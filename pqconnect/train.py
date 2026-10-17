"""Train and evaluate PQConnect; run from any working directory."""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import shutil

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.linear_model import Ridge
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from features import TARGET, MEASUREMENTS, CATEGORIES, SIZES, NUMERIC, FEATURES, engineer


def metrics(y, prediction):
    p = np.maximum(0, np.asarray(prediction))
    y = np.asarray(y)
    error = np.abs(y - p)
    return {'rows': len(y), 'mae_ms': float(mean_absolute_error(y, p)),
            'rmse_ms': float(mean_squared_error(y, p) ** .5), 'r2': float(r2_score(y, p)),
            'within_100ms_percent': float(100 * np.mean(error <= 100)),
            'p95_absolute_error_ms': float(np.quantile(error, .95)),
            'over_500ms_accuracy_percent': float(100 * np.mean((y > 500) == (p > 500))),
            'over_500ms_confusion_matrix_actual_rows_predicted_columns':
                confusion_matrix(y > 500, p > 500, labels=[False, True]).tolist()}


def pipeline(estimator):
    prep = ColumnTransformer([
        ('algorithms', OneHotEncoder(handle_unknown='error', sparse_output=False), CATEGORIES),
        ('numbers', StandardScaler(), NUMERIC)])
    return Pipeline([('features', prep), ('regressor', estimator)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', type=Path, required=True, help='Directory containing s2_*.csv')
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).parent / 'artifacts')
    args = parser.parse_args()
    out = args.output_dir.resolve(); out.mkdir(parents=True, exist_ok=True)
    frames, audit, digest = [], [], hashlib.sha256()
    for path in sorted(args.data_dir.glob('s2_*.csv')):
        content = path.read_bytes(); digest.update(path.name.encode()); digest.update(content)
        frame = pd.read_csv(path)
        audit.append({'file': path.name, 'rows': len(frame), 'sha256': hashlib.sha256(content).hexdigest()})
        if frame.empty:
            continue
        label = path.stem.removeprefix('s2_')
        ee, ca = label.split('_signed-by_')
        if not frame['sta_cert_algo'].eq(label).all() or not frame['ap_cert_algo'].eq(label).all():
            raise ValueError(f'Unexpected asymmetric configuration: {path}')
        frame['run_id'] = path.stem
        frame[CATEGORIES[0]] = ee; frame[CATEGORIES[1]] = ca
        frames.append(frame)
    if not frames:
        raise ValueError('No nonempty s2 CSV files found.')
    raw = pd.concat(frames, ignore_index=True)
    if raw.duplicated(['run_id', 'node_id', 'handshake_index']).any():
        raise ValueError('Duplicate exchange indices.')
    numeric = MEASUREMENTS + SIZES
    valid = np.isfinite(raw[numeric]).all(axis=1) & raw[numeric].ge(0).all(axis=1)
    valid &= raw[TARGET].gt(0) & raw['phy_frame_drop_rate'].le(1)
    invalid_rows = int((~valid).sum()); raw = raw.loc[valid].copy()
    config_sizes = raw.groupby(CATEGORIES)[SIZES].nunique()
    if config_sizes.gt(1).any().any():
        raise ValueError('Message sizes vary within configurations; revise metadata handling.')
    data = engineer(raw)
    train = data.loc[data.handshake_index < 60]
    val = data.loc[data.handshake_index.between(60, 79)]
    test = data.loc[data.handshake_index >= 80]
    if any(x.empty for x in [train, val, test]):
        raise ValueError('Insufficient data for the predefined temporal split.')
    # Test history can contain earlier held-out observations: one-step online evaluation.
    assert train.handshake_index.max() < val.handshake_index.min()
    assert val.handshake_index.max() < test.handshake_index.min()
    train_means = train.groupby('run_id')[TARGET].mean()
    scores = {'validation': {}, 'test': {}}
    baseline_predictions = {}
    for split_name, split in [('validation', val), ('test', test)]:
        baseline_predictions[split_name] = {
            'configuration_mean': split.run_id.map(train_means).to_numpy(),
            'previous_exchange': split[f'{TARGET}_previous'].to_numpy(),
            'recent_mean5': split[f'{TARGET}_mean5'].to_numpy()}
        for name, p in baseline_predictions[split_name].items():
            scores[split_name][name] = metrics(split[TARGET], p)
    candidates = {f'ridge_alpha_{a:g}': pipeline(Ridge(alpha=a)) for a in [0.1, 10., 1000.]}
    candidates['hist_gradient_boosting'] = pipeline(HistGradientBoostingRegressor(
        max_iter=180, max_leaf_nodes=15, min_samples_leaf=40,
        l2_regularization=10., learning_rate=.08, early_stopping=False, random_state=42))
    for name, model in candidates.items():
        print(f'Training {name} on {len(train):,} rows...', flush=True)
        model.fit(train[FEATURES], train[TARGET])
        scores['validation'][name] = metrics(val[TARGET], model.predict(val[FEATURES]))
        print(json.dumps(scores['validation'][name]), flush=True)
    chosen = min(candidates, key=lambda n: scores['validation'][n]['mae_ms'])
    best = candidates[chosen]
    best_ridge = min((n for n in candidates if n.startswith('ridge')), key=lambda n: scores['validation'][n]['mae_ms'])
    for name in dict.fromkeys([chosen, best_ridge]):
        scores['test'][name] = metrics(test[TARGET], candidates[name].predict(test[FEATURES]))
    prediction = np.maximum(0, best.predict(test[FEATURES]))
    records = test[['run_id', 'node_id', 'handshake_index', TARGET]].copy()
    records['prediction_ms'] = prediction
    for name, p in baseline_predictions['test'].items(): records[name + '_ms'] = p
    records.to_csv(out / 'test_predictions.csv', index=False)
    per_config = []
    for name, subset in records.groupby('run_id'):
        item = {'configuration': name, **metrics(subset[TARGET], subset.prediction_ms)}
        item['persistence_mae_ms'] = float(mean_absolute_error(subset[TARGET], subset.previous_exchange_ms))
        per_config.append(item)
    pd.DataFrame(per_config).to_csv(out / 'test_metrics_by_configuration.csv', index=False)
    # Save the actual evaluated model. Do not silently refit using held-out rows.
    joblib.dump(best, out / 'latency_model.joblib')
    joblib.dump(candidates[best_ridge], out / 'ridge_model.joblib')
    config_catalog = raw.groupby(CATEGORIES, as_index=False)[SIZES].first()
    train_configs = set(train.run_id); val_configs = set(val.run_id); test_configs = set(test.run_id)
    config_catalog['configuration_id'] = config_catalog[CATEGORIES[0]] + '_signed-by_' + config_catalog[CATEGORIES[1]]
    config_catalog['training_rows'] = config_catalog.configuration_id.map(train.groupby('run_id').size().rename(index=lambda s: s.removeprefix('s2_'))).fillna(0).astype(int)
    config_catalog['test_rows'] = config_catalog.configuration_id.map(test.groupby('run_id').size().rename(index=lambda s: s.removeprefix('s2_'))).fillna(0).astype(int)
    config_catalog.to_json(out / 'configurations.json', orient='records', indent=2)
    metadata = {'target': TARGET, 'target_description': 'Simulation time from connection setup start to client final-certificate-message send; excludes final server acceptance.',
        'selected_model': chosen, 'selection_rule': 'Minimum validation MAE among learned models; test not used for selection.',
        'best_ridge': best_ridge, 'features': FEATURES, 'history_window': 5,
        'dataset_url': 'https://github.com/samettonyali29/x-layer_performance_evaluation_of_PQ_X.509',
        'dataset_content_sha256': digest.hexdigest(), 'csv_files': len(audit), 'raw_pq_rows': sum(a['rows'] for a in audit),
        'empty_files': sum(a['rows'] == 0 for a in audit), 'partial_nonempty_files': sum(0 < a['rows'] < 800 for a in audit),
        'invalid_rows_removed': invalid_rows, 'usable_feature_rows': len(data),
        'split': {n: {'rows': len(d), 'configurations': int(d.run_id.nunique()), 'index_min': int(d.handshake_index.min()), 'index_max': int(d.handshake_index.max())} for n,d in [('train', train), ('validation', val), ('test', test)]},
        'training_configurations_without_test': sorted(train_configs-test_configs),
        'numeric_training_ranges': {f: {'min': float(train[f].min()), 'max': float(train[f].max())} for f in NUMERIC},
        'versions': {'python': platform.python_version(), 'numpy': np.__version__, 'pandas': pd.__version__, 'scikit_learn': sklearn.__version__, 'joblib': joblib.__version__},
        'limitations': ['Single simulated Wi-Fi setting and x86 cryptographic timings; not LinuxONE latency measurements.',
            'Partial files and completion-conditioned data can bias results; missing exchanges are not imputed.',
            'Temporal holdout is by per-device handshake index, not shared wall-clock time; devices share one simulated network.',
            'Online one-step evaluation uses actual earlier observations, including earlier validation/test exchanges.',
            'No independent network/seed, unseen-configuration, or algorithm-switch validation.',
            'History and requested configuration must match; cross-configuration recommendations are not validated.',
            'Minimum security category and delay target are policy inputs, not latency-model features.']}
    (out / 'metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    (out / 'metrics.json').write_text(json.dumps(scores, indent=2), encoding='utf-8')
    (out / 'dataset_manifest.json').write_text(json.dumps(audit, indent=2), encoding='utf-8')
    row = test.iloc[0]
    past = raw.loc[(raw.run_id == row.run_id) & (raw.node_id == row.node_id) & (raw.handshake_index < row.handshake_index)].sort_values('handshake_index').tail(5)
    example = {'configuration_id': row.run_id.removeprefix('s2_'), 'history_configuration_id': row.run_id.removeprefix('s2_'),
               'history': past[MEASUREMENTS].to_dict(orient='records'), 'latency_target_ms': 500}
    (out.parent / 'example_input.json').write_text(json.dumps(example, indent=2), encoding='utf-8')
    print(json.dumps({'selected_model': chosen, 'splits': metadata['split'], 'test': scores['test']}, indent=2), flush=True)


if __name__ == '__main__': main()
