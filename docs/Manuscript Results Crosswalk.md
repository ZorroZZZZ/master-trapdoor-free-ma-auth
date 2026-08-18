# Manuscript Results Crosswalk

## Main benchmark — fully recovered and included

The artifact contains the authenticated raw data behind the manuscript's
28,000-measurement main evaluation:
- 6,500 Hmax=32 lattice measurements;
- 8,500 Hmax=64 lattice measurements;
- 13,000 same-machine ML-DSA reference measurements.

The three formal raw CSVs exactly match the SHA-256 values in the Stage 13C
Formal Audit. The recovered raw-data status is therefore PASS rather than a
summary-only crosswalk.

Recorded primary-profile main-run endpoints:
- cold sign at k=64: 382.934 ms
- prepared online sign at k=64: about 134.039 ms
- cold verify at k=64: 74.950 ms
- prepared online verify at k=64: about 14.001 ms
- max observed ||e||/beta in the main Hmax=64 benchmark: 0.407092
- peak RSS, Hmax=64: about 397.5 MiB

## Independent-round repeatability — fully included

The package contains all raw data and the analysis behind the manuscript's
independent-round claims.

Witness-size proposed sign medians (ms):
k=1: 135.150
k=8: 133.139
k=16: 131.992
k=32: 129.532
k=33: 129.622
k=48: 129.664
k=64: 134.932

Within-round normalized proposed ratios:
1.000, 0.987, 0.977, 0.959, 0.959, 0.959, 0.999

Safe manuscript conclusion:
no monotonic witness-size-dependent growth in the prepared online lattice path.

Fixed |S|=64 issuer-partition endpoint:
- J=1 sign median 134.962 ms
- J=64 sign median 135.176 ms
- paired change +0.196%
- bootstrap 95% CI [-0.512%, +0.474%]

Hence the manuscript reports no distinguishable endpoint growth within
round-to-round measurement variability.

## Communication

Proposed Hmax=64 fresh manifest-backed token: 78,408 B.
Per-attribute ML-DSA model: 40 + 2420 k bytes.

- k=33: 78,408 B vs 79,900 B
- k=64: 78,408 B vs 154,920 B
- saving at k=64: 76,512 B = 49.39%

## k=64 computational context from independent rounds

- proposed sign: 134.932 ms
- per-attribute ML-DSA sign: 20.362 ms
- proposed verify: 13.921 ms
- per-attribute ML-DSA verify: 5.696 ms

The body of the manuscript reports the corresponding computational overhead,
while the abstract does not foreground these ratios.

## Security-estimator diagnostics

Pinned commit:
3e48ef421ec256afddb3e7d2249a77eab6e9ba12

Primary Hmax=64:
- normal-form Module-LWE quantum effective diagnostic: 141.096 bits
- homogeneous Module-SIS quantum effective diagnostic: 168.635 bits
- 2 beta / q ≈ 0.6851

These are attack-cost diagnostics for the stated estimator model, not a
bit-exact end-to-end security proof.
