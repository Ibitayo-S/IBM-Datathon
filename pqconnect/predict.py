"""CLI and Python interface for next-exchange latency prediction."""
import argparse
import json
from pathlib import Path
import joblib
import numpy as np
from environment_check import compatibility_error
from features import NUMERIC, inference_features


def predict(payload, artifacts=None):
    artifacts = Path(artifacts or Path(__file__).parent / 'artifacts')
    version_error = compatibility_error(artifacts / 'metadata.json')
    if version_error:
        raise RuntimeError(version_error)
    metadata = json.loads((artifacts / 'metadata.json').read_text(encoding='utf-8'))
    catalog = json.loads((artifacts / 'configurations.json').read_text(encoding='utf-8'))
    config_id = payload['configuration_id']
    if payload.get('history_configuration_id') != config_id:
        raise ValueError('History must use the requested configuration. Algorithm-switch predictions are not validated.')
    config = next((x for x in catalog if x['configuration_id'] == config_id), None)
    if config is None or config['training_rows'] == 0:
        raise ValueError('Configuration is not supported by the trained model.')
    features = inference_features(payload['history'], config)
    warnings = []
    for name in NUMERIC:
        bounds = metadata['numeric_training_ranges'][name]
        if not bounds['min'] <= float(features[name].iloc[0]) <= bounds['max']:
            warnings.append(f'{name} is outside its training range.')
    if config['test_rows'] == 0:
        warnings.append('This configuration has no held-out test records.')
    # Load only trusted local model artifacts: joblib uses pickle internally.
    model = joblib.load(artifacts / 'latency_model.joblib')
    value = max(0., float(model.predict(features)[0]))
    threshold = float(payload.get('latency_target_ms', 500))
    if not np.isfinite(threshold) or threshold <= 0:
        raise ValueError('latency_target_ms must be finite and positive.')
    return {'predicted_authentication_exchange_delay_ms': round(value, 3),
            'latency_target_ms': threshold, 'predicted_within_target': value <= threshold,
            'configuration_id': config_id, 'model': metadata['selected_model'],
            'scope': 'Simulated next exchange, with unchanged cryptographic configuration; not full login time.',
            'warnings': warnings}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    print(json.dumps(predict(json.loads(args.input.read_text(encoding='utf-8')), args.artifacts), indent=2))
