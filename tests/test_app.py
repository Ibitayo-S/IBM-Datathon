"""HTTP integration checks against the real bundled model and recorded data.

Run from the repository root: python -m unittest discover -s tests -v
"""
import copy
import csv
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import create_app

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "pqconnect" / "artifacts"
MEASUREMENTS = ("handshake_delay_ms", "mac_retry_rate", "phy_frame_drop_rate",
                "throughput_kbps", "tx_delay_us")


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = tempfile.TemporaryDirectory(prefix="pqconnect-tests-")
        cls.app = create_app({
            "TESTING": True, "PQCONNECT_DEMO": True, "SECRET_KEY": "integration-test-only",
            "INSTANCE_PATH": cls.instance.name, "MODEL_DIR": str(MODEL_DIR),
        })
        cls.example = json.loads((ROOT / "pqconnect/example_input.json").read_text())
        with (MODEL_DIR / "test_predictions.csv").open(newline="") as handle:
            cls.heldout = next(csv.DictReader(handle))

    @classmethod
    def tearDownClass(cls):
        cls.instance.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        response = self.client.get("/api/session")
        self.assertEqual(response.status_code, 200)
        session = response.get_json()
        self.assertTrue(session["authenticated"])
        self.assertTrue(session["demo"])
        self.headers = {"X-CSRF-Token": session["csrf"]}

    def post(self, route, payload):
        return self.client.post(route, json=payload, headers=self.headers)

    def analyze(self, **overrides):
        payload = {"min_category": 3, "target_ms": 500, "profile": "middle"}
        payload.update(overrides)
        response = self.post("/api/analyze", payload)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def assert_bad_request(self, route, payload):
        response = self.post(route, payload)
        self.assertEqual(response.status_code, 400, response.get_data(as_text=True))
        self.assertTrue(response.get_json().get("error"))

    def test_dashboard_assets_and_health_are_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)
        self.assertIn("PQConnect", response.get_data(as_text=True))
        response.close()
        for route in ("/static/app.js", "/static/style.css"):
            with self.subTest(route=route):
                asset = self.client.get(route)
                self.assertEqual(asset.status_code, 200)
                self.assertGreater(len(asset.data), 0)
                asset.close()
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.get_json()["model_loaded"])

    def test_data_model_and_instance_files_are_not_public_assets(self):
        for route in (
            "/pqconnect/artifacts/latency_model.joblib",
            "/pqconnect/data/s2_ML-DSA-44_signed-by_ML-DSA-44.csv",
            "/static/../app.py", "/static/latency_model.joblib",
            "/instance/secret_key", "/app.py",
        ):
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 404)

    def test_metadata_matches_the_real_configuration_catalog(self):
        response = self.client.get("/api/meta")
        self.assertEqual(response.status_code, 200)
        meta = response.get_json()
        self.assertTrue(meta["model"]["loaded"])
        catalog = json.loads((MODEL_DIR / "configurations.json").read_text())
        expected = {row["configuration_id"] for row in catalog if row["training_rows"] > 0}
        self.assertEqual({row["configuration_id"] for row in meta["configurations"]}, expected)
        self.assertIn(meta["default_configuration"], expected)

    def test_prediction_matches_saved_heldout_result(self):
        response = self.post("/api/predict", self.example)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        predicted = response.get_json()["predicted_authentication_exchange_delay_ms"]
        self.assertAlmostEqual(predicted, float(self.heldout["prediction_ms"]), places=2)

    def test_extremely_large_numbers_are_client_errors(self):
        self.assert_bad_request('/api/analyze', {'target_ms': 10**400})
        payload = copy.deepcopy(self.example)
        payload['history'][0]['throughput_kbps'] = 10**400
        self.assert_bad_request('/api/predict', payload)

    def test_malformed_csrf_and_nonlocal_demo_hosts_are_rejected(self):
        response = self.client.post('/api/analyze', json={}, headers={'X-CSRF-Token': 'é'})
        self.assertEqual(response.status_code, 403)
        for base_url in ('http://untrusted.example:5000', 'http://evil.localhost.example'):
            response = self.client.get('/api/session', base_url=base_url)
            self.assertEqual(response.status_code, 403)
        response = self.client.get('/api/session', environ_overrides={'REMOTE_ADDR': '192.168.0.10'})
        self.assertEqual(response.status_code, 403)

    def test_target_changes_decision_without_changing_prediction(self):
        low, high = copy.deepcopy(self.example), copy.deepcopy(self.example)
        low["latency_target_ms"], high["latency_target_ms"] = 1, 100000
        low_response, high_response = self.post("/api/predict", low), self.post("/api/predict", high)
        self.assertEqual(low_response.status_code, 200)
        self.assertEqual(high_response.status_code, 200)
        low_result, high_result = low_response.get_json(), high_response.get_json()
        key = "predicted_authentication_exchange_delay_ms"
        self.assertEqual(low_result[key], high_result[key])
        self.assertFalse(low_result["predicted_within_target"])
        self.assertTrue(high_result["predicted_within_target"])

    def test_cross_configuration_history_and_unknown_configuration_rejected(self):
        payload = copy.deepcopy(self.example)
        payload["history_configuration_id"] = "ML-DSA-65_signed-by_ML-DSA-65"
        self.assert_bad_request("/api/predict", payload)
        payload["configuration_id"] = payload["history_configuration_id"] = "unknown"
        self.assert_bad_request("/api/predict", payload)

    def test_invalid_history_rejected(self):
        invalid = []
        short = copy.deepcopy(self.example)
        short["history"] = short["history"][:4]
        invalid.append(short)
        missing = copy.deepcopy(self.example)
        del missing["history"][0]["throughput_kbps"]
        invalid.append(missing)
        for field, value in (
            ("handshake_delay_ms", 0), ("handshake_delay_ms", -1),
            ("throughput_kbps", float("nan")), ("tx_delay_us", float("inf")),
            ("mac_retry_rate", -1), ("phy_frame_drop_rate", 1.01),
            ("throughput_kbps", "invalid"),
        ):
            payload = copy.deepcopy(self.example)
            payload["history"][0][field] = value
            invalid.append(payload)
        for index, payload in enumerate(invalid):
            with self.subTest(case=index):
                self.assert_bad_request("/api/predict", payload)

    def test_history_identity_and_order_are_checked_when_provided(self):
        complete = copy.deepcopy(self.example)
        for index, row in enumerate(complete["history"]):
            row.update(node_id=1, handshake_index=index, configuration_id=complete["configuration_id"])
        self.assertEqual(self.post("/api/predict", complete).status_code, 200)
        for field, value in (("node_id", 2), ("handshake_index", 99), ("configuration_id", "different")):
            with self.subTest(field=field):
                payload = copy.deepcopy(complete)
                payload["history"][2][field] = value
                self.assert_bad_request("/api/predict", payload)

    def test_malformed_request_bodies_are_client_errors(self):
        for route in ("/api/predict", "/api/analyze"):
            for payload in ([], "invalid", 7):
                with self.subTest(route=route, payload=payload):
                    self.assert_bad_request(route, payload)
            response = self.client.post(route, data="{broken", content_type="application/json", headers=self.headers)
            self.assertEqual(response.status_code, 400)

    def test_policy_and_profile_validation(self):
        for value in (0, 4, 6, 3.5, True, "invalid", float("nan"), float("inf")):
            with self.subTest(category=value):
                self.assert_bad_request("/api/analyze", {"min_category": value})
        for value in (0, -1, "invalid", float("nan"), float("inf")):
            with self.subTest(target=value):
                self.assert_bad_request("/api/analyze", {"target_ms": value})
                self.assert_bad_request("/api/predict", {**self.example, "latency_target_ms": value})
        self.assert_bad_request("/api/analyze", {"profile": "unknown"})
        self.assert_bad_request("/api/analyze", {"configuration_id": "unknown"})

    def test_security_filter_applies_to_endpoint_and_ca(self):
        meta = self.client.get("/api/meta").get_json()
        categories = {row["name"]: row["category"] for row in meta["algorithms"]}
        analysis = self.analyze(min_category=5)
        self.assertGreater(len(analysis["results"]), 0)
        for row in analysis["results"]:
            with self.subTest(configuration=row["configuration_id"]):
                self.assertGreaterEqual(categories[row["ee_alg"]], 5)
                self.assertGreaterEqual(categories[row["ca_alg"]], 5)
                self.assertEqual(row["category"], min(categories[row["ee_alg"]], categories[row["ca_alg"]]))
                self.assertTrue(math.isfinite(row["predicted_ms"]))
                self.assertGreaterEqual(row["predicted_ms"], 0)
        self.assertEqual(analysis["summary"]["configurations"], len(analysis["results"]))
        self.assertEqual(analysis["summary"]["within_target"], sum(row["meets_target"] for row in analysis["results"]))

    def test_incompatible_policy_has_no_fabricated_result(self):
        analysis = self.analyze(min_category=5, allowed_algs=["ML-DSA-44"])
        self.assertEqual(analysis["results"], [])
        self.assertIsNone(analysis["selected"])
        self.assertEqual(analysis["summary"]["configurations"], 0)
        self.assertIsNone(analysis["summary"]["lowest_predicted_ms"])

    def test_configuration_without_test_coverage_keeps_warning(self):
        analysis = self.analyze(configuration_id="SLH-DSA-SHA2-192s_signed-by_ML-DSA-65")
        selected = analysis["selected"]
        self.assertEqual(selected["configuration_id"], "SLH-DSA-SHA2-192s_signed-by_ML-DSA-65")
        self.assertEqual(selected["test_rows"], 0)
        self.assertTrue(any("held-out" in warning for warning in selected["warnings"]))

    def test_each_configuration_uses_its_own_consecutive_recorded_history(self):
        analysis = self.analyze(min_category=5)
        for result in analysis["results"]:
            configuration_id = result["configuration_id"]
            with self.subTest(configuration=configuration_id):
                history, provenance = result["history"], result["provenance"]
                self.assertEqual(provenance["source"], "dataset replay")
                self.assertEqual(len(history), 5)
                target_index = int(provenance["handshake_index"])
                self.assertEqual([int(row["handshake_index"]) for row in history], list(range(target_index - 5, target_index)))
                path = ROOT / "pqconnect" / "data" / f"s2_{configuration_id}.csv"
                with path.open(newline="") as handle:
                    recorded = {
                        int(row["handshake_index"]): row for row in csv.DictReader(handle)
                        if int(row["node_id"]) == int(provenance["node_id"])
                    }
                for row in history:
                    original = recorded[int(row["handshake_index"])]
                    self.assertEqual(original["sta_cert_algo"], configuration_id)
                    for field in MEASUREMENTS:
                        self.assertAlmostEqual(float(row[field]), float(original[field]), places=7)
                self.assertAlmostEqual(result["observed_ms"], float(recorded[target_index]["handshake_delay_ms"]), places=3)

    def test_selected_replay_roundtrips_through_prediction_api(self):
        analysis = self.analyze(configuration_id="ML-DSA-65_signed-by_ML-DSA-65")
        selected = analysis["selected"]
        self.assertEqual(selected["configuration_id"], "ML-DSA-65_signed-by_ML-DSA-65")
        response = self.post("/api/predict", {
            "configuration_id": selected["configuration_id"],
            "history_configuration_id": selected["configuration_id"],
            "history": selected["history"], "latency_target_ms": analysis["target_ms"],
        })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertAlmostEqual(response.get_json()["predicted_authentication_exchange_delay_ms"], selected["predicted_ms"], places=3)

    def test_browser_network_measurements_do_not_replace_model_telemetry(self):
        without = self.analyze(min_category=5, network=None)
        with_network = self.analyze(min_category=5, network={"rtt_ms": 45, "download_mbps": 20})
        self.assertEqual(
            {row["configuration_id"]: row["predicted_ms"] for row in without["results"]},
            {row["configuration_id"]: row["predicted_ms"] for row in with_network["results"]},
        )
        self.assertTrue(all(row["network_extra_transfer_ms"] is None for row in without["results"]))
        self.assertTrue(all(math.isfinite(row["network_extra_transfer_ms"]) for row in with_network["results"]))

    def test_invalid_network_measurements_rejected(self):
        for network in (
            {"rtt_ms": -1, "download_mbps": 20},
            {"rtt_ms": float("inf"), "download_mbps": 20},
            {"rtt_ms": 10, "download_mbps": 0},
            {"rtt_ms": 10, "download_mbps": float("nan")},
            {"rtt_ms": 10, "download_mbps": "invalid"},
        ):
            with self.subTest(network=network):
                self.assert_bad_request("/api/analyze", {"network": network})

    def test_post_requires_csrf_but_get_probes_do_not(self):
        for headers in ({}, {"X-CSRF-Token": "wrong-token"}):
            response = self.client.post("/api/predict", json=self.example, headers=headers)
            self.assertEqual(response.status_code, 403)
        ping = self.client.get("/api/probe/ping")
        self.assertEqual(ping.status_code, 204)
        self.assertEqual(len(ping.data), 0)
        payload = self.client.get("/api/probe/download?bytes=1024")
        self.assertEqual(payload.status_code, 200)
        self.assertEqual(len(payload.data), 1024)
        self.assertIn("no-store", payload.headers.get("Cache-Control", ""))

    def test_probe_payload_rejects_invalid_or_excessive_sizes(self):
        for value in ("0", "-1", "1023", "8388609", "huge", "1.5"):
            with self.subTest(bytes=value):
                self.assertEqual(self.client.get(f"/api/probe/download?bytes={value}").status_code, 400)
        response = self.client.get("/api/probe/download?bytes=8388608")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 8388608)


class MissingModelTests(unittest.TestCase):
    def test_missing_model_returns_unavailable_instead_of_mock_prediction(self):
        with tempfile.TemporaryDirectory(prefix="pqconnect-missing-") as folder:
            app = create_app({
                "TESTING": True, "PQCONNECT_DEMO": True, "SECRET_KEY": "integration-test-only",
                "INSTANCE_PATH": folder, "MODEL_DIR": str(Path(folder) / "no-model-here"),
            })
            client = app.test_client()
            token = client.get("/api/session").get_json()["csrf"]
            health = client.get("/api/health")
            self.assertEqual(health.status_code, 503)
            self.assertFalse(health.get_json()["model_loaded"])
            for route in ("/api/analyze", "/api/predict"):
                response = client.post(route, json={}, headers={"X-CSRF-Token": token})
                self.assertEqual(response.status_code, 503, response.get_data(as_text=True))
                self.assertTrue(response.get_json().get("error"))
                self.assertNotIn("predicted_authentication_exchange_delay_ms", response.get_json())
            response = client.post('/api/analyze', json={'configuration_id':'ML-DSA-65_signed-by_ML-DSA-65'}, headers={'X-CSRF-Token':token})
            self.assertEqual(response.status_code, 503)


class EnvironmentCompatibilityTests(unittest.TestCase):
    def test_model_refuses_inconsistent_runtime_versions(self):
        from model_service import ModelService
        with patch('model_service.compatibility_error', return_value='version mismatch'):
            service = ModelService(MODEL_DIR)
        self.assertIsNone(service.model)
        self.assertIn('version mismatch', service.error)


class AuthenticatedTests(unittest.TestCase):
    def test_sign_in_rotation_and_logout(self):
        from werkzeug.security import generate_password_hash
        with tempfile.TemporaryDirectory(prefix='pqconnect-auth-') as folder:
            Path(folder, 'users.json').write_text(json.dumps({'tester':generate_password_hash('test-only-password-123')}))
            application = create_app({'TESTING':True, 'PQCONNECT_DEMO':False, 'DEV_HTTP':True,
                                      'SECRET_KEY':'test-only', 'INSTANCE_PATH':folder,
                                      'SESSION_COOKIE_SECURE':False, 'MODEL_DIR':str(MODEL_DIR)})
            client = application.test_client()
            self.assertEqual(client.get('/api/meta').status_code, 401)
            token = client.get('/api/session').get_json()['csrf']
            wrong = client.post('/api/login', json={'username':'tester','password':'wrong'}, headers={'X-CSRF-Token':token})
            self.assertEqual(wrong.status_code, 401)
            login = client.post('/api/login', json={'username':'tester','password':'test-only-password-123'}, headers={'X-CSRF-Token':token})
            self.assertEqual(login.status_code, 200)
            new_token = login.get_json()['csrf']
            self.assertNotEqual(new_token, token)
            self.assertEqual(client.get('/api/meta').status_code, 200)
            self.assertEqual(client.post('/api/analyze', json={}, headers={'X-CSRF-Token':token}).status_code, 403)
            self.assertEqual(client.post('/api/logout', json={}, headers={'X-CSRF-Token':new_token}).status_code, 200)
            self.assertEqual(client.get('/api/meta').status_code, 401)


if __name__ == "__main__":
    unittest.main()
