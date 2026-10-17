# PQConnect — trained model and evaluation

The deliverable predicts the next **authentication-exchange delay in milliseconds**
from historical measurements and an unchanged cryptographic configuration.

## Result

The selected histogram gradient-boosting model achieved **42.35 ms mean absolute
error** on **21,891 held-out exchanges** from **157 configurations**. Selection
used validation MAE, not test performance. Ridge regression is also supplied.

| Predictor | Validation MAE (ms) | Test MAE (ms) | Test RMSE (ms) | Test R² | Test within 100 ms |
|---|---:|---:|---:|---:|---:|
| Training configuration mean | 51.08 | 65.34 | 187.93 | 0.9539 | 79.51% |
| Previous exchange | 46.72 | **40.11** | 247.70 | 0.9200 | **96.63%** |
| Previous-five mean | 45.26 | 40.61 | 193.98 | 0.9509 | 94.12% |
| Ridge, alpha 10 | 45.67 | 44.45 | 181.73 | 0.9569 | 93.38% |
| **Selected gradient boosting** | **41.81** | 42.35 | **176.63** | **0.9593** | 92.33% |

The learned model improves on a configuration-average lookup and reduces RMSE
relative to the other evaluated predictors. It does **not** outperform simply
reusing the previous delay on held-out MAE or the percentage within 100 ms.
Consequently, these results do not establish that ML is uniformly better than
simple forecasting. Persistence should remain a production baseline. No model
was retuned after inspecting the test results.

For the selected model, the 95th percentile absolute error is **119.48 ms**.
The much larger RMSE indicates occasional large errors; the MAE is not a bound
or a confidence interval for an individual prediction.

At a 500 ms delay threshold, test classification accuracy is **98.75%**:

| Actual / predicted | At most 500 ms | Over 500 ms |
|---|---:|---:|
| Actual at most 500 ms | 15,507 | 78 |
| Actual over 500 ms | 195 | 6,111 |

The 195 missed slow exchanges show why this must not be presented as a guarantee
that a particular authentication will meet a latency target.

## Data and split

- 225 homogeneous PQ CSV files, with 147,271 recorded exchanges.
- 110 complete files, 107 partial nonempty files, and 8 empty files.
- 217 nonempty configurations available for training.
- No invalid numeric rows were removed.
- Five historical exchanges required per prediction; 138,598 usable feature rows.
- Training: indices 5–59, 91,921 rows across 217 configurations.
- Validation: indices 60–79, 24,786 rows across 157 configurations.
- Test: indices 80–99, 21,891 rows across 157 configurations.
- 60 training configurations have no test coverage because their records stop
  earlier. Their predictions are explicitly flagged by the inference interface.

Features are computed separately within each CSV/device sequence. Rolling means
are shifted before calculation. A target exchange's measured duration, throughput,
verification time, or retries are never inputs for predicting that same exchange.
There is no random train/test row mixing. The shared simulated network and lack of
independent runs nevertheless limit what this evaluation establishes.

## Inputs and output

Four configuration fields: endpoint algorithm, CA algorithm, server certificate
message bytes, and client certificate message bytes.

Ten historical numeric fields: previous value and mean of the previous five
values for exchange delay, MAC retry indicator, PHY-drop indicator, observed
throughput, and mean PHY transmission duration.

Output: predicted delay in milliseconds, plus whether the point prediction is
within an optional user-specified delay target. Negative model outputs are clipped
to zero consistently in evaluation and inference.

The minimum security requirement belongs in a separate eligibility layer. It is
not an input to this regression model. This package does not automatically change
algorithms, select cryptographic policies, or compare unsupported configurations.

## Interpretation

This is a **within-environment, one-step forecasting proof of concept**. It does
not validate performance on unseen networks, hardware, independent random seeds,
or after changing cryptographic configurations. The records use a simplified
authentication protocol and exclude final server acceptance from the measured
target. The dataset's missing and incomplete exchanges can bias evaluation toward
shorter/successfully recorded exchanges.

Historical delay and throughput depend on the previous configuration as well as
network conditions. Cross-configuration ranking requires additional experiments,
ideally with independently measured network conditions and controlled configuration
changes. The shipped predictor requires history from the requested configuration
to avoid silently presenting that unvalidated capability as established.

The model was trained and checked locally. It is packaged for transfer to
LinuxONE, but has not been deployed or tested there. Inference hosting does not
change the hardware conditions represented by the source data.

## Files

- `artifacts/latency_model.joblib`: evaluated gradient-boosting pipeline.
- `artifacts/ridge_model.joblib`: evaluated Ridge pipeline.
- `features.py`: shared feature definitions and historical processing.
- `train.py`: data audit, training, selection, evaluation, and artifact generation.
- `predict.py`: Python/JSON prediction interface.
- `example_input.json`: real held-out example's five preceding exchanges.
- `test_pipeline.py`: leakage, grouping, missing-history, invalid-input, and
  saved-model prediction-parity checks.
- `artifacts/metrics.json`: full validation/test metrics and threshold matrices.
- `artifacts/test_predictions.csv`: held-out predictions and baselines.
- `artifacts/test_metrics_by_configuration.csv`: configuration-specific errors.
- `artifacts/metadata.json`: versions, inputs, coverage, and limitations.
- `artifacts/dataset_manifest.json`: original file counts and checksums.
- `data/`: source PQ CSVs; `DATA_LICENSE.txt`: original dataset license.

Source: https://github.com/samettonyali29/x-layer_performance_evaluation_of_PQ_X.509
