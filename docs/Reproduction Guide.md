# Reproduction Guide

## A. Independent-round statistics (fully reproducible in this package)

Requirements:
- Python 3
- NumPy
- pandas

Run from the artifact root:

    REPRODUCE_REPEATABILITY.cmd

The command calls:

    python repeatability/analyze_independent_rounds.py \
        --root repeatability \
        --bootstrap-reps 50000

Input layout:
- `repeatability/config/`
- `repeatability/stats_results/raw/`
- `repeatability/stats_results/environment/`

The formal targeted design is:
- 10 independently restarted process rounds
- 19 formal cases
- 100 online measurements per case and round
- 19,000 targeted online measurements total
- all observations retained
- inference unit: independent-round median
- bootstrap: 50,000 resamples

The original processed outputs are stored in:
`repeatability/stats_results/processed/`.

## B. Stage 13C main benchmark protocol

The complete recovered main-benchmark evidence is under
`main_benchmark_raw/results/`.

Primary formal raw files:
- `stage13c_h32_lattice_raw_latest.csv` — 6,500 rows
- `stage13c_h64_lattice_raw_latest.csv` — 8,500 rows
- `stage13c_mldsa_online_raw_latest.csv` — 13,000 rows

Total: 28,000 formal online measurements.

The three raw CSVs exactly match the SHA-256 values previously recorded in the
Stage 13C Formal Audit. `main_benchmark_raw/STAGE13C_RECOVERY_VALIDATION.md`
documents this recovery.

To re-run the deterministic Stage 13C analysis over the recovered raw files:

    python code/runner/analyze_stage13c.py main_benchmark_raw/results

The resulting theory-vs-measurement CSV is byte-identical to the archived
output; the text reports are semantically identical modulo line endings.

The C++17 sources/configuration needed to repeat the benchmark on a compatible
Windows/MSVC host are in `code/` and `main_benchmark_protocol/`.

## C. Security estimator

The original Stage 13B estimator runner/configuration and outputs have now been
recovered and are included under:

- `security_estimator/stage13b_runner_config/`
- `security_estimator/original_stage13b_evidence/`

The supplied Stage 13B launcher checks out-of-band that the lattice-estimator
repository HEAD equals:

`3e48ef421ec256afddb3e7d2249a77eab6e9ba12`

and then runs the recovered candidate-estimator script under SageMath.
The recovered result CSV, JSON, and log were verified byte-for-byte against
the copies already retained in this artifact.

## D. Integrity

Run:

    python validate_artifact.py

The script validates the package SHA-256 ledger, the 190 independent-round
online raw artifacts and their original ledger, the 10x19 case grid, 100
online rows per targeted file, and required processed outputs.
