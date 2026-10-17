# PQConnect: authentication-exchange delay prediction

Predict the next exchange's measured delay from five completed exchanges from the
same device, using an unchanged certificate configuration. This is a trained
proof of concept using the homogeneous post-quantum subset of the published
Wi-Fi simulation dataset. It is not a full login-time predictor.

## Run a prediction

Use Python 3.11 or newer. The supplied model was trained with Python 3.13.13 and
the library versions pinned in `requirements.txt`.

```sh
python -m pip install -r requirements.txt
python predict.py --input example_input.json
```

The JSON input contains a `configuration_id`, matching `history_configuration_id`,
five chronological records from one device, and an optional `latency_target_ms`.
Each historical record contains:

| Field | Unit / interpretation |
|---|---|
| `handshake_delay_ms` | Recorded exchange delay in milliseconds |
| `mac_retry_rate` | MAC failure events per observed frame; can exceed 1 |
| `phy_frame_drop_rate` | Dataset's AP reception-drop indicator, 0–1 |
| `throughput_kbps` | PHY-observed bytes per exchange duration, kbit/s; not link capacity |
| `tx_delay_us` | Mean PHY transmission duration in microseconds; excludes backoff |

The input contract requires consecutive completed exchanges, chronological order,
one device, and the same configuration. The caller must enforce those properties;
the minimal JSON telemetry records have no device IDs or timestamps to verify them.
The predictor rejects missing, nonfinite, or invalid telemetry and unsupported
configurations. Global out-of-range warnings are a basic diagnostic, not a complete
out-of-distribution detector. Never load untrusted joblib/pickle model files.

Certificate-message sizes and endpoint/CA algorithm identities are loaded from
the bundled configuration catalog. The user does not type these measurements.
The numerical features are each measurement's previous value and previous-five
mean, plus the two message sizes. Algorithm names are one-hot encoded. The exact
same feature definitions are used during training and inference.

## Reproduce training and verification

```sh
python train.py --data-dir data
python -m unittest -v test_pipeline.py
```

`data/` contains the 225 original homogeneous PQ CSVs, including empty files so
the dataset audit remains reproducible. Their source license is preserved in
`DATA_LICENSE.txt`. `artifacts/dataset_manifest.json` records individual SHA-256
hashes; metadata also records a deterministic hash over names and contents.

Training uses exchange indices 5–59, validation 60–79, and testing 80–99 within
each run/device. The first five exchanges supply initial history. Lagged features
never cross experiment or device boundaries. Gaps and invalid histories are
excluded. No random row split is used. Because indices are per-device rather than
global timestamps, this is a within-run sequence holdout, not an independent
network experiment or a strict shared-wall-clock cutoff across devices.

The evaluation predicts one exchange at a time using already observed history.
Later test predictions can use actual earlier test exchanges. This matches an
online next-exchange service, not a multi-step forecast with no new observations.

Three Ridge regularization strengths and a histogram gradient-boosting regressor
are compared using validation MAE. Baselines are the training-set configuration
mean, previous-exchange delay, and previous-five mean. Test results are computed
only after selecting the learned model. The saved model is exactly the evaluated
training-only model: it is not silently refitted on validation or test records.

See `REPORT.md` for results, `artifacts/metrics.json` for numerical metrics,
`test_metrics_by_configuration.csv` for coverage/error per tested configuration,
and `test_predictions.csv` for individual held-out predictions (both in artifacts).

## Scope and limitations

- The target is elapsed simulated time from connection setup start to the client's
  final certificate-message send, as implemented by `RecordHandshake()`. It does
  not include final server acceptance, a complete TLS exchange, or a user login.
- Only homogeneous PQ configurations are trained. Heterogeneous and classical
  experiments are excluded. There is no independent hardware/network/seed test.
- The dataset is incomplete and records completed exchanges; estimates may
  underrepresent slow or unfinished cases. Missing exchanges are not fabricated.
- Historical throughput and delay also depend on the cryptographic configuration.
  This model does not validate switching algorithms while holding history fixed.
  The predictor therefore requires matching historical and requested configurations.
- Minimum security category is a separate policy filter, not an ML feature.
  This package does not certify security or implement configuration recommendations.
- Ridge is additive unless explicit interaction terms are added; the tree model
  can learn nonlinear interactions. Validation decides which is saved as primary.
- Training was performed locally on the supplied simulation data. The source
  cryptographic measurements were collected on x86 hardware. Hosting inference
  on LinuxONE does not make these predictions measurements of LinuxONE latency.
- For a real deployment, collect matching local telemetry and recalibrate/evaluate
  on the organisation's actual protocol, hardware, certificates, and network.

## LinuxONE

Copy this directory to the provided environment. Create a Python environment,
install compatible dependencies, and run the commands above. Package availability
on s390x must be checked there; it has not been tested in this workspace. If exact
versions are unavailable, install supported versions and retrain locally rather
than assuming the serialized model is compatible across scikit-learn versions.

Dataset: https://github.com/samettonyali29/x-layer_performance_evaluation_of_PQ_X.509
