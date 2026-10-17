"""Shared, strictly historical features for training and inference."""
import numpy as np
import pandas as pd

TARGET = 'handshake_delay_ms'
WINDOW = 5
MEASUREMENTS = [TARGET, 'mac_retry_rate', 'phy_frame_drop_rate',
                'throughput_kbps', 'tx_delay_us']
CATEGORIES = ['end_entity_algorithm', 'ca_algorithm']
SIZES = ['server_cert_msg_bytes', 'client_cert_msg_bytes']
NUMERIC = SIZES + [f'{m}_{stat}' for m in MEASUREMENTS for stat in ('previous', 'mean5')]
FEATURES = CATEGORIES + NUMERIC


def engineer(raw):
    """Never cross run/device boundaries; all rolling windows exclude target row."""
    data = raw.sort_values(['run_id', 'node_id', 'handshake_index']).copy()
    group = data.groupby(['run_id', 'node_id'], sort=False)
    for name in MEASUREMENTS:
        data[f'{name}_previous'] = group[name].shift(1)
        data[f'{name}_mean5'] = group[name].transform(
            lambda x: x.shift(1).rolling(WINDOW, min_periods=WINDOW).mean())
    # Require contiguous history, including the step to the target exchange.
    data['history_start_index'] = group['handshake_index'].shift(WINDOW)
    valid = data['handshake_index'] - data['history_start_index'] == WINDOW
    return data.loc[valid].dropna(subset=FEATURES + [TARGET]).copy()


def inference_features(history, configuration):
    """History must be chronological, from one device and an unchanged configuration."""
    if len(history) < WINDOW:
        raise ValueError('At least five completed exchanges are required.')
    history = history[-WINDOW:]
    rows = pd.DataFrame(history)
    missing = set(MEASUREMENTS) - set(rows.columns)
    if missing:
        raise ValueError(f'Missing telemetry: {sorted(missing)}')
    values = rows[MEASUREMENTS].to_numpy(dtype=float)
    if not np.isfinite(values).all() or (values < 0).any():
        raise ValueError('Telemetry must be finite and nonnegative.')
    if (rows[TARGET] <= 0).any() or (rows['phy_frame_drop_rate'] > 1).any():
        raise ValueError('Delay must be positive; PHY drop indicator must be in [0, 1].')
    result = {name: configuration[name] for name in CATEGORIES + SIZES}
    for name in MEASUREMENTS:
        result[f'{name}_previous'] = float(rows[name].iloc[-1])
        result[f'{name}_mean5'] = float(rows[name].mean())
    return pd.DataFrame([result], columns=FEATURES)
