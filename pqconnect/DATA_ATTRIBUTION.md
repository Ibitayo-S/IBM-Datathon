# Third-party dataset attribution and reuse notice

## Original author and copyright

The authentication-performance data in `data/` was created and published by
Samet Tonyalı (GitHub: `samettonyali29`). It was not collected or created by the
PQConnect project.

The original copyright notice is:

Copyright (c) 2026 samettonyali29

Original repository:
https://github.com/samettonyali29/x-layer_performance_evaluation_of_PQ_X.509

Associated work:
Samet Tonyalı, *A Cross-Layer Performance Evaluation of Post-Quantum X.509
Authentication over Wi-Fi* (2026).

## Licence and redistribution

The source repository is distributed under the MIT License. The original
copyright notice and complete licence text are preserved in `DATA_LICENSE.txt`.
Retain that file with any redistribution of this dataset or substantial portions
of it. This attribution notice supplements the original licence; it does not
replace it, change its terms, or claim new ownership of the source data.

The MIT License permits use, modification, and redistribution, including in
private and commercial projects, subject to its terms. The data is provided
without warranty as stated in the original licence.

## What this project redistributes

The `data/` directory contains the 225 homogeneous post-quantum CSV files
(`s2_*.csv`) copied from the original repository snapshot inspected for this
project. They contain 147,271 recorded exchanges in total:

- 110 files contain all 800 expected records.
- 107 files contain some, but fewer than 800, records.
- 8 files contain only a header.

The copied CSV contents are unmodified. This is a selected subset, not the full
dataset or the complete set of exchanges reported in the associated research.
Classical and heterogeneous experiment files are not included in this directory.
Original file names and content hashes are recorded in
`artifacts/dataset_manifest.json`.

The integrated dashboard additionally includes one unmodified, 800-record
classical reference file in `reference_data/`:
`s1_ECDSA-SHA256_signed-by_ECDSA-SHA256.csv`. Its median combined certificate-message
size is used only as a reference for the independent network byte-transfer estimate.
Its source hash is preserved in `artifacts/classical_reference.json`. It is not used
as a measured classical login-time baseline. The same original MIT licence applies.
`artifacts/network_states.json` contains derived selections of recorded PQ history
for the dashboard; original CSV data is retained unchanged.

## Nature and limitations of the data

The data describes controlled, simulated Wi-Fi certificate-authentication
experiments incorporating measured cryptographic operations. It is not a
collection of real university users' login histories. Node identifiers describe
simulation stations.

The source snapshot contains incomplete experiments, and the recorded exchanges
do not establish performance across all networks, hardware, or authentication
protocols. Missing and unfinished exchanges may bias performance estimates.
The measured authentication-exchange delay must not be presented as complete
user login time or a guarantee of production performance.

## PQConnect's contribution

PQConnect uses these third-party measurements to develop feature-processing,
model-training, evaluation, and prediction code. That work is separate from the
original dataset and experiments. Credit for the original data remains with its
author. This notice does not set the licence for PQConnect's own code or imply
that the original author endorses PQConnect or its results.

If you modify the CSVs later, update this notice to describe those changes and
retain the original attribution and licence.
