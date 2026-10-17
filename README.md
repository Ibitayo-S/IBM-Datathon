# PQConnect — runnable post-quantum latency dashboard

One application connects the frontend, recorded network/authentication state, and the trained model. It also measures the browser-to-server path and estimates the transfer time attributable to larger PQ certificate messages.

## Run on this Windows machine

From PowerShell in this repository:

```powershell
.\.venv\Scripts\python.exe app.py --demo
```

Open **http://127.0.0.1:5000**. Stop the server with **Ctrl+C**. The local demo opens directly without an account and is restricted to loopback. To use another port, add `--port 5050`.

Alternatively, `powershell -ExecutionPolicy Bypass -File .\run.ps1` creates a local virtual environment and installs missing dependencies before starting the demo. This bypass applies only to that launcher process.

## Fresh setup / LinuxONE

Use Python 3.11 or newer (training used Python 3.13). In a fresh checkout:

On Linux, use the provided setup script. It installs the exact versions used to
serialize the bundled model and checks them before startup:

```sh
chmod +x setup-linux.sh
./setup-linux.sh
.venv/bin/python app.py --demo
```

The explicit `.venv/bin/python` matters: it prevents a system Python or a stale
environment from loading the model. You can also run `python environment_check.py`
inside an activated environment to see installed and required versions.

On LinuxONE, keep the service on loopback and use an SSH tunnel from your laptop:

```sh
ssh -L 5000:127.0.0.1:5000 your-user@your-linuxone-host
```

Then open http://127.0.0.1:5000 locally. A network probe over this tunnel measures the tunnel path, not the source simulation's Wi-Fi network. Exact dependency availability on s390x must be checked on the provided machine. If compatible pinned libraries cannot be installed, the setup script stops and prints the retraining commands. Do not suppress or ignore an `InconsistentVersionWarning`: use the exact environment or retrain and regenerate the artifacts on LinuxONE. This integration has been tested locally on Windows, not on LinuxONE.

### Fixing version warnings

If you already created an environment manually, first confirm which interpreter
you are actually using:

```sh
which python
python environment_check.py
python -m pip check
```

The bundled model requires scikit-learn 1.8.0, NumPy 2.4.4, pandas 3.0.2 and
joblib 1.5.3. Recreate the environment with `./setup-linux.sh` when any version
differs. PQConnect now refuses to load a mismatched serialized model instead of
continuing after a warning and producing potentially unreliable results.

## Dashboard workflow

1. The dashboard automatically loads a recorded telemetry analysis.
2. Choose a minimum NIST category, a certificate configuration, a latency budget and an early/middle/late recorded window. Click **Analyze configurations**.
3. Inspect predicted exchange delay, budget status, recent history, actual next recorded delay, test coverage and configuration comparisons.
4. Click **Run network test** to measure five request durations and a 1 MiB download. The independent extra-transfer estimate then appears.
5. Export the analysis to CSV or JSON.

Security eligibility requires both endpoint and CA signature categories to meet the selected minimum. Categories use the existing FIPS 204/205 mappings; this filter does not certify a deployment's security or validate its certificates.

## Two distinct outputs

**ML authentication-exchange prediction:** the actual saved gradient-boosting model uses the previous five completed exchanges from the same device and unchanged certificate configuration. The same feature code as training supplies 14 fields: two algorithm labels, two certificate-message sizes, and the previous value plus previous-five mean for delay, retry indicator, drop indicator, throughput and PHY transmission duration. Model and metadata load once; inference is batched and cached per recorded window. No mock formula or placeholder telemetry is used.

Every row in the comparison uses its own configuration's recorded experiment. These are absolute next-exchange forecasts, not a controlled estimate of switching algorithms under an identical network state. The recorded next exchange is displayed for inspection, but never fed into its prediction. Early and middle demo windows may overlap training data; late windows may be held out only where enough records exist. Dashboard examples are not additional test-accuracy evidence.

**Extra certificate-transfer estimate:**

```text
extra milliseconds = max(PQ certificate-message bytes − classical reference bytes, 0)
                     × 8 / (measured download Mbps × 1000)
```

The classical reference is 2,582 bytes: the median combined server/client certificate-message size in the bundled ECDSA P-256/SHA-256 reference run. The estimate assumes the download rate applies in both directions. It excludes CPU cost, packet loss, round trips and protocol overhead. Request duration is shown as context and is not fed into the model or added to this formula. On localhost, the probe measures your own computer's loopback path, not internet/Wi-Fi bandwidth.

Browser ping/download values are not interchangeable with the model's authentication history or MAC/PHY measurements. A real organisation needs a collector supplying equivalent authentication telemetry and local calibration. Therefore this dashboard does not claim to measure the full extra login time caused by a PQ migration.

## API

All POSTs require the `X-CSRF-Token` from `GET /api/session`. Authenticated mode additionally requires sign-in; the local demo establishes its session automatically.

| Route | Purpose |
|---|---|
| `GET /api/health` | 200 when assets load; 503 when unavailable |
| `GET /api/session` | Session state and CSRF token |
| `POST /api/login`, `/api/logout` | Account sessions |
| `GET /api/meta` | Model quality, supported configurations, profiles and runtime |
| `POST /api/analyze` | Policy-filtered recorded forecasts and optional network transfer estimates |
| `POST /api/predict` | Predict from supplied authentic history (same schema as `pqconnect/example_input.json`) |
| `GET /api/probe/ping` | Small no-cache request probe |
| `GET /api/probe/download?bytes=1048576` | Bounded, noncompressible test download |

Example analysis body:

```json
{"min_category":3,"target_ms":500,"profile":"middle","configuration_id":"ML-DSA-65_signed-by_ML-DSA-65","network":null}
```

Optional `network` contains numeric `rtt_ms` and `download_mbps`. It changes only the independent transfer estimate. Optional `allowed_algs` restricts both endpoint and CA choices. Profiles are `early`, `middle`, `late`.

`/api/recommend` is an alias of `/api/analyze`; it does not return a validated migration recommendation. Old flat-telemetry requests are rejected clearly. `/api/estimate-telemetry` returns 422 rather than inventing MAC/PHY values from browser speed tests. The old `ibm_datathon/app.py` entry point now starts this same server.

`/api/predict` requires at least five consecutive, chronological records from the same device and configuration. The service checks numeric fields and any provided `node_id`, `configuration_id` and `handshake_index` metadata. If identity/order metadata is omitted, the caller remains responsible for those properties.

## Validation and reproducibility

```sh
python -m unittest discover -s tests -v
python -m unittest discover -s pqconnect -p test_pipeline.py -v
python build_replay.py --classical-csv pqconnect/reference_data/s1_ECDSA-SHA256_signed-by_ECDSA-SHA256.csv
```

To retrain, run `python pqconnect/train.py --data-dir pqconnect/data`, then regenerate replay assets with the command above and restart the server. Original metrics, hashes and per-configuration coverage remain in `pqconnect/artifacts/`. See `pqconnect/REPORT.md` for training results and limitations. Selected-model held-out MAE is 42.35 ms; the previous-delay baseline achieved 40.11 ms MAE. Do not claim ML wins on every metric.

## Authenticated/shared deployment

Create accounts with `python manage_users.py add <username>` (interactive password entry). For local authenticated testing, use `python app.py --http`. For the existing built-in HTTPS mode, supply `instance/tls/cert.pem` and `key.pem`, then run `python app.py --host <bind-address>`; Flask's built-in server is suitable for demonstration, not production.

For an administered deployment, `wsgi:app` is the authenticated application factory output for a WSGI server behind an HTTPS reverse proxy. Keep `PQCONNECT_DEMO` and `PQCONNECT_DEV_HTTP` unset. Sessions use a secret in ignored `instance/secret_key` unless `PQCONNECT_SECRET_KEY` is provided. Cookies are HttpOnly/SameSite=Strict and Secure in HTTPS mode; POSTs require CSRF. Demo mode checks both loopback peer and host name. Model/CSV files, credentials and source files are not public static assets. No GitHub upload or deployment is performed by the launcher.

## Data attribution

Original data and experiments: **Samet Tonyalı**, *A Cross-Layer Performance Evaluation of Post-Quantum X.509 Authentication over Wi-Fi* (2026).

- [Original dataset](https://github.com/samettonyali29/x-layer_performance_evaluation_of_PQ_X.509)
- [Attribution notice](pqconnect/DATA_ATTRIBUTION.md)
- [Original MIT licence](pqconnect/DATA_LICENSE.txt)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)

The bundled 225 PQ CSVs contain 147,271 records, including partial and empty files. The additional classical reference CSV supplies message sizes only. Preserve the attribution and licence when redistributing.
