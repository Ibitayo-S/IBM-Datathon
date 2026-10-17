"""Cached trained-model inference with recorded, configuration-matched history."""
import json
import math
from pathlib import Path
from threading import RLock

import joblib
import numpy as np
import pandas as pd
from pqconnect.features import FEATURES, MEASUREMENTS, NUMERIC, inference_features

ROOT = Path(__file__).resolve().parent
SCOPE = 'Predicted authentication-exchange delay in the source simulation, not full login time.'
COMPARISON_NOTE = ('Each configuration uses its own recorded history. These forecasts are not a '
                   'controlled comparison of switching algorithms on your current network.')
PROFILES = [{'id': p, 'label': label} for p, label in
            [('early', 'Early recorded exchanges'), ('middle', 'Middle recorded exchanges'),
             ('late', 'Late recorded exchanges')]]


def category(algorithm):
    if algorithm in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'):
        return {'ML-DSA-44': 2, 'ML-DSA-65': 3, 'ML-DSA-87': 5}[algorithm]
    if algorithm.startswith(('SLH-DSA-SHA2-', 'SLH-DSA-SHAKE-')):
        return {'128': 1, '192': 3, '256': 5}[algorithm.split('-')[-1][:3]]
    raise ValueError('Unknown algorithm.')


def number(value, name, low=0., high=600000.):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f'{name} must be a number.')
    try:
        value = float(value)
    except OverflowError:
        raise ValueError(f'{name} is outside the supported range.') from None
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError(f'{name} must be between {low:g} and {high:g}.')
    return value


class ModelUnavailable(RuntimeError):
    pass


class ModelService:
    def __init__(self, directory=None):
        self.directory = Path(directory or ROOT / 'pqconnect/artifacts')
        self.model = None
        self.error = None
        self.catalog = {}
        self.metadata = {}
        self.metrics = {}
        self.replays = {}
        self.baseline = {}
        self._cache = {}
        self._lock = RLock()
        try:
            self.metadata = self.read('metadata.json')
            self.metrics = self.read('metrics.json')
            for row in self.read('configurations.json'):
                if row['training_rows']:
                    row['category'] = min(category(row['end_entity_algorithm']), category(row['ca_algorithm']))
                    self.catalog[row['configuration_id']] = row
            self.replays = self.read('network_states.json')
            self.baseline = self.read('classical_reference.json')
            self.model = joblib.load(self.directory / 'latency_model.joblib')
            if list(self.model.feature_names_in_) != FEATURES:
                raise ValueError('Model feature schema differs from the shared feature pipeline.')
        except Exception as error:
            self.model = None
            self.error = f'Model assets could not be loaded ({type(error).__name__}). Check the server log.'
            import logging
            logging.getLogger(__name__).exception('Unable to load model assets')

    def read(self, name):
        return json.loads((self.directory / name).read_text(encoding='utf-8'))

    def require(self):
        if self.model is None:
            raise ModelUnavailable(self.error or 'The trained model is unavailable.')

    def info(self):
        return {'loaded': self.model is not None,
                'model': self.metadata.get('selected_model', 'unavailable'),
                'trained_rows': self.metadata.get('split', {}).get('train', {}).get('rows', 0),
                'metrics': self.metrics.get('test', {}).get(self.metadata.get('selected_model'), {}),
                'baseline_metrics': self.metrics.get('test', {}).get('previous_exchange', {}),
                'limitations': self.metadata.get('limitations', []), 'scope': SCOPE,
                'error': self.error}

    def configuration(self, config_id):
        if not isinstance(config_id, str) or config_id not in self.catalog:
            raise ValueError('Choose a configuration supported by the trained model.')
        return self.catalog[config_id]

    def validate_history(self, history):
        if not isinstance(history, list) or not 5 <= len(history) <= 100:
            raise ValueError('Provide 5 to 100 consecutive completed exchanges from one device.')
        if not all(isinstance(row, dict) for row in history):
            raise ValueError('Each history record must be an object.')
        for row in history:
            for field in MEASUREMENTS:
                number(row.get(field), field, 1e-9 if field == 'handshake_delay_ms' else 0,
                       1 if field == 'phy_frame_drop_rate' else 1e12)
        for field in ('node_id', 'configuration_id'):
            supplied = [row.get(field) for row in history]
            if any(x is not None for x in supplied) and (any(x is None for x in supplied) or
                    any(x != supplied[0] for x in supplied)):
                raise ValueError(f'History must have a single consistent {field}.')
        indices = [row.get('handshake_index') for row in history]
        if any(x is not None for x in indices):
            if any(type(x) is not int or x < 0 for x in indices) or any(b != a + 1 for a,b in zip(indices, indices[1:])):
                raise ValueError('History indices must be consecutive and chronological.')
        return history

    def warnings(self, frame, config):
        warnings = []
        for name in NUMERIC:
            limits = self.metadata['numeric_training_ranges'][name]
            if not limits['min'] <= float(frame[name].iloc[0]) <= limits['max']:
                warnings.append(f'{name} is outside the training range.')
        if not config['test_rows']:
            warnings.append('This configuration has no held-out test records.')
        return warnings

    def predict(self, body):
        self.require()
        config = self.configuration(body.get('configuration_id'))
        if body.get('history_configuration_id') != config['configuration_id']:
            raise ValueError('History must match the requested configuration; algorithm-switch predictions are not validated.')
        history = self.validate_history(body.get('history'))
        if any('configuration_id' in row and row['configuration_id'] != config['configuration_id'] for row in history):
            raise ValueError('History configuration does not match the requested configuration.')
        threshold = number(body.get('latency_target_ms', 500), 'latency_target_ms', 1, 600000)
        frame = inference_features(history, config)
        with self._lock:
            result = float(self.model.predict(frame)[0])
        result = max(0., result)
        return {'predicted_authentication_exchange_delay_ms': round(result, 3),
                'latency_target_ms': threshold, 'predicted_within_target': result <= threshold,
                'configuration_id': config['configuration_id'], 'model': self.metadata['selected_model'],
                'scope': SCOPE, 'warnings': self.warnings(frame, config)}

    def replay_predictions(self, profile):
        self.require()
        if profile not in [p['id'] for p in PROFILES]:
            raise ValueError('profile must be early, middle or late.')
        with self._lock:
            if profile in self._cache:
                return self._cache[profile]
            rows, frames = [], []
            for config_id, config in self.catalog.items():
                replay = self.replays.get(config_id, {}).get(profile)
                if replay is None:
                    continue
                history = self.validate_history(replay['history'])
                if any(row.get('configuration_id') != config_id for row in history):
                    raise ModelUnavailable('Recorded history configuration does not match the model catalog.')
                frame = inference_features(history, config)
                frames.append(frame)
                rows.append({'configuration_id': config_id, 'ee_alg': config['end_entity_algorithm'],
                             'ca_alg': config['ca_algorithm'], 'category': config['category'],
                             'test_rows': config['test_rows'],
                             'certificate_message_bytes': config['server_cert_msg_bytes'] + config['client_cert_msg_bytes'],
                             'history': history, 'history_mean_ms': float(frame.handshake_delay_ms_mean5.iloc[0]),
                             'observed_ms': replay['observed_ms'], 'provenance': replay['provenance'],
                             'warnings': self.warnings(frame, config)})
            if not frames:
                raise ModelUnavailable('No replay histories are available for this profile.')
            predictions = self.model.predict(pd.concat(frames, ignore_index=True))
            for row, result in zip(rows, predictions):
                row['predicted_ms'] = max(0., float(result))
            self._cache[profile] = rows
            return rows

    def analyze(self, body):
        self.require()
        min_cat = body.get('min_category', 3)
        if type(min_cat) is not int or min_cat not in (1, 2, 3, 5):
            raise ValueError('Minimum category must be 1, 2, 3 or 5.')
        target = number(body.get('target_ms', 500), 'target_ms', 1, 600000)
        profile = body.get('profile', 'middle')
        requested = body.get('configuration_id')
        if requested is not None:
            self.configuration(requested)
        network = body.get('network')
        if network is not None:
            if not isinstance(network, dict):
                raise ValueError('network must be an object or null.')
            network = {'rtt_ms': number(network.get('rtt_ms'), 'rtt_ms', 0, 60000),
                       'download_mbps': number(network.get('download_mbps'), 'download_mbps', 1e-9, 100000)}
        allowed = body.get('allowed_algs')
        if allowed is not None and (not isinstance(allowed, list) or not allowed or
                any(not isinstance(a, str) or a not in self.algorithms() for a in allowed)):
            raise ValueError('allowed_algs must contain known algorithm names.')
        results = []
        for original in self.replay_predictions(profile):
            if original['category'] < min_cat or (allowed is not None and
                    (original['ee_alg'] not in allowed or original['ca_alg'] not in allowed)):
                continue
            row = dict(original)
            row['meets_target'] = row['predicted_ms'] <= target
            row['target_headroom_ms'] = target - row['predicted_ms']
            extra_bytes = max(0., row['certificate_message_bytes'] - self.baseline['certificate_message_bytes'])
            row['extra_certificate_bytes'] = extra_bytes
            row['network_extra_transfer_ms'] = extra_bytes * 8 / (network['download_mbps'] * 1000) if network else None
            results.append(row)
        results.sort(key=lambda row: row['predicted_ms'])
        selected = next((r for r in results if r['configuration_id'] == requested), results[0] if results else None)
        return {'results': results, 'selected': selected,
                'summary': {'configurations': len(results), 'within_target': sum(r['meets_target'] for r in results),
                            'lowest_predicted_ms': results[0]['predicted_ms'] if results else None,
                            'median_predicted_ms': float(np.median([r['predicted_ms'] for r in results])) if results else None},
                'model': self.info(), 'network': network, 'target_ms': target, 'min_category': min_cat,
                'profile': profile, 'scope': SCOPE, 'comparison_note': COMPARISON_NOTE, 'baseline': self.baseline,
                'network_estimate_note': 'Extra certificate-message bytes / measured download rate. Uses that rate in both directions; excludes CPU, loss, round trips and protocol overhead. Not an end-to-end migration forecast.'}

    def algorithms(self):
        return sorted({row[key] for row in self.catalog.values() for key in ('end_entity_algorithm', 'ca_algorithm')})
