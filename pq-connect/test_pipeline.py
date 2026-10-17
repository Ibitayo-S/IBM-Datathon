"""Checks that matter for deployment: no future leakage and offline/online parity."""
import copy
import json
from pathlib import Path
import unittest
import numpy as np
import pandas as pd
from features import CATEGORIES, FEATURES, MEASUREMENTS, SIZES, engineer, inference_features
from predict import predict


class FeatureTests(unittest.TestCase):
    def sample(self):
        rows = []
        for node in [1, 2]:
            for index in range(8):
                row = {'run_id': 'run', 'node_id': node, 'handshake_index': index,
                       CATEGORIES[0]: 'ML-DSA-44', CATEGORIES[1]: 'ML-DSA-65',
                       SIZES[0]: 3000, SIZES[1]: 3001}
                row.update({name: float(node * 100 + index) for name in MEASUREMENTS})
                row['phy_frame_drop_rate'] = index / 100
                rows.append(row)
        return pd.DataFrame(rows)

    def test_current_and_future_measurements_cannot_change_current_features(self):
        raw = self.sample()
        before = engineer(raw)
        changed = raw.copy()
        changed.loc[(changed.node_id == 1) & (changed.handshake_index >= 5), MEASUREMENTS] = 999
        after = engineer(changed)
        mask = (before.node_id == 1) & (before.handshake_index == 5)
        pd.testing.assert_frame_equal(before.loc[mask, FEATURES], after.loc[mask, FEATURES])

    def test_devices_do_not_share_history_and_inference_matches_training(self):
        raw = self.sample()
        batch = engineer(raw)
        row = batch.loc[(batch.node_id == 2) & (batch.handshake_index == 5)].iloc[0]
        history = raw.loc[(raw.node_id == 2) & (raw.handshake_index < 5), MEASUREMENTS].to_dict('records')
        online = inference_features(history, row.to_dict())
        pd.testing.assert_frame_equal(online, pd.DataFrame([row[FEATURES].to_dict()]), check_dtype=False)
        self.assertEqual(online['handshake_delay_ms_previous'].iloc[0], 204)

    def test_missing_history_not_silently_bridged(self):
        raw = self.sample()
        raw = raw.loc[~((raw.node_id == 1) & (raw.handshake_index == 3))]
        self.assertFalse((engineer(raw).node_id == 1).any())

    def test_invalid_telemetry_rejected(self):
        row = self.sample().iloc[0].to_dict()
        with self.assertRaises(ValueError): inference_features([row] * 4, row)
        bad = copy.deepcopy(row); bad['throughput_kbps'] = float('nan')
        with self.assertRaises(ValueError): inference_features([bad] * 5, row)


class ArtifactTests(unittest.TestCase):
    def test_saved_model_predicts_recorded_held_out_example(self):
        root = Path(__file__).parent
        payload = json.loads((root / 'example_input.json').read_text())
        answer = predict(payload)
        first = pd.read_csv(root / 'artifacts/test_predictions.csv', nrows=1).iloc[0]
        self.assertAlmostEqual(answer['predicted_authentication_exchange_delay_ms'], first.prediction_ms, places=2)
        payload['history_configuration_id'] = 'different'
        with self.assertRaises(ValueError): predict(payload)


if __name__ == '__main__': unittest.main()
