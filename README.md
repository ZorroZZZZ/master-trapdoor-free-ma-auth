# Master-Trapdoor-Free Post-Quantum Multi-Authority Authentication

Reproducibility repository for the manuscript:

**Master-Trapdoor-Free Post-Quantum Multi-Authority Authentication via User-Local Lattice Capability Aggregation**

Authors: Jinhong Chen, Xueguang Zhou, and Wei Fu.

## Scope

This repository provides reviewer-facing source code, experiment configurations,
analysis scripts, compact validation outputs, security-estimator outputs, and
figures used in the manuscript.

The evaluation contains two complementary measurement sets:

- **28,000 main benchmark measurements** for the Hmax=32 reference profile,
  Hmax=64 primary profile, and same-machine ML-DSA reference architectures.
- **19,000 targeted independent-round measurements** collected over ten
  independently restarted process rounds.

The complete frozen raw-data and reproducibility bundle is distributed as a
GitHub Release asset rather than committed directly to Git history.

## Recommended release asset

Upload the following file to the repository's first GitHub Release:

`Reviewer Reproducibility Artifact v1.3 FINAL FROZEN.zip`

SHA-256:

`9ebe373a9c0d852c82110686f81aec143ace3da42e3d7c712129c090e5ccf7af`

The release bundle contains the complete raw CSVs, environment captures,
estimator runner/configuration, source pins, integrity manifests, and
independent-round data.

## Repository structure

- `code/` — C++17 proposed-scheme and ML-DSA reference implementations.
- `scripts/` — Windows/MSVC experiment launchers.
- `config/` — formal benchmark and repeatability case configurations.
- `analysis/` — main benchmark and independent-round analysis scripts.
- `results/` — compact audited summaries used to cross-check manuscript claims.
- `security estimator/` — pinned estimator revision and reported estimator outputs.
- `figures/` — manuscript evaluation figures.
- `docs/` — reproduction guide, result crosswalk, and validation report.

## Main reproduction path

The recorded benchmark environment is Windows x64 with MSVC/C++17. Start with:

`docs/Reproduction Guide.md`

For the formal Stage 13C benchmark, use:

`RUN_STAGE13C_FORMAL.cmd`

For the independent-round statistics, use:

`analysis/analyze_independent_rounds.py`

The complete frozen release asset should be downloaded when inspecting or
reanalyzing all raw measurements.

## Integrity

The final frozen supplementary artifact passed the recorded integrity checks:

- 28,000 main benchmark measurements recovered and validated.
- 19,000 independent-round measurements validated.
- Stage 13B estimator runner/configuration recovered and validated.
- 190/190 targeted raw artifacts matched the recorded SHA-256 ledger.

## Paper status

This repository accompanies Electronics manuscript electronics-4597245.

The v1.0-review release preserves the earlier manuscript and experimental
snapshot. Materials supporting the revised manuscript dated 9 October 2026
are available at:

https://github.com/ZorroZZZZ/lattices-abs

The earlier IEEE Access submission label is superseded by this notice.
## Citation

If the manuscript is accepted, the bibliographic citation and DOI will be
added here. Until then, please cite the manuscript title and authors above.
