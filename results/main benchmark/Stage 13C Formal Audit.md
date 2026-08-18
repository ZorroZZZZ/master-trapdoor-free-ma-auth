# Stage 13C Formal Audit v1.0

## Verdict

**STAGE13C_OVERALL = PASS**

The formal run is internally consistent and suitable as the evidence base for a redesigned online/offline evaluation section.

- H32: 6,500 formal online trials, all sign/verify checks passed.
- H64: 8,500 formal online trials, all sign/verify checks passed.
- ML-DSA deletion baselines: 13,000 formal online trials, all normal and tamper checks passed.
- Total formal online trials: 28,000.
- Theory-versus-serialization byte formulas: PASS for every measured point.

## Main quantitative findings

### 1. Online/offline split materially reduces request-path work

At H32, k=32:
- cold sign median: 308.220 ms
- prepared online sign median: 132.423 ms
- reduction: 57.04%

- cold verify median: 45.083 ms
- prepared online verify median: 13.938 ms
- reduction: 69.08%

At H64, k=64:
- cold sign median: 382.934 ms
- prepared online sign median: 134.039 ms
- reduction: 65.00%

- cold verify median: 74.950 ms
- prepared online verify median: 14.001 ms
- reduction: 81.32%

### 2. Prepared online lattice cost is essentially witness-size independent inside each supported profile

H64 online sign remains roughly 131--136 ms from k=1 through k=64, and online verification stays about 14 ms.
The k-dependent additive aggregation has been moved into offline preparation.

### 3. Thin-token communication crossover is now strong at H64

- H32 k=32: lattice 76,104 B vs per-attribute ML-DSA 77,480 B; lattice is 1.78% smaller.
- H64 k=33: lattice 78,408 B vs per-attribute ML-DSA 79,900 B; lattice is 1.87% smaller.
- H64 k=64: lattice 78,408 B vs per-attribute ML-DSA 154,920 B; lattice is 49.39% smaller.

This is a **fresh online possession/presentation** result, not a claim that static registry storage or portable self-contained state is smaller.

### 4. Latency disadvantage remains, but the gap narrows as k grows

At H64 k=64:
- lattice online sign: 134.039 ms
- per-attribute ML-DSA online sign: 20.357 ms
- slowdown: 6.58x

- lattice online verify: 14.001 ms
- per-attribute ML-DSA online verify: 5.704 ms
- slowdown: 2.45x

Therefore the paper should not claim a latency crossover within H<=64.

### 5. Authority-partition invariance is especially clean after preparation

For fixed |S|=64, moving from 1 AA to 64 AAs changes:
- online sign by +0.121%
- online verify by -0.000%
- SamplePre by +0.150%

The issuer partition is pushed almost entirely into offline credential/root authentication.

## Security / implementation status

H64 has now passed both:
1. the Stage 13B pinned numeric estimator gate; and
2. the Stage 13C end-to-end implementation gate.

It should still be described as an **estimator-qualified, implementation-validated candidate profile**, not as a strict bit-exact end-to-end 128-bit theorem.

Observed maximum norm ratios:
- H32: 0.406084
- H64: 0.407092

Peak RSS:
- H32: 208.1 MiB
- H64: 397.5 MiB

The H64 memory increase should remain a disclosed implementation trade-off.

## Recommended manuscript direction

1. Make **registry-backed prepared online authentication** the primary deployment profile.
2. Treat portable/self-contained transmission as a fallback profile and report its static-state cost separately.
3. Use H64 as the main scalability experiment, with H32 as a lower-memory/legacy profile.
4. Add an analytical cost model before the measurements.
5. Main figures should emphasize:
   - thin-token communication scaling and the k=33 / k=64 crossover;
   - prepared online latency stability versus witness size;
   - fixed-witness authority-partition invariance;
   - cold/prepared decomposition.
6. Keep absolute ML-DSA latency in a compact table and state the remaining slowdown explicitly.
7. Do not claim latency superiority within the supported H<=64 profile.

## Important benchmark-scope note

The Stage 13C serializer is benchmark-faithful rather than a production-literal network protocol. The final manuscript definition of `wid` should explicitly bind the canonical policy/witness identifiers, credential identifiers/digests, issuer/root versions, `(pid,tau)`, and the aggregate public-root digest, even if the benchmark represents some of these fields through fixed case metadata.

