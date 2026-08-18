# Analytical Cost and Break-Even Model

## 1. Why separate static and fresh costs
The proposed lattice construction has large period-stable public capability objects `B_a`, while the fresh request proof is `e` plus `r_sig`. A per-attribute ML-DSA architecture likewise has static per-attribute public keys/certificates, but it must generate a fresh request signature for each selected attribute. A fair online comparison therefore separates:

1. static credential/registry storage;
2. offline preparation/cache refresh;
3. fresh online request payload;
4. fresh online signing/verification computation.

The portable self-contained profile remains separately reported.

## 2. H32 fresh possession payload
Current proof dimension:

\[
D_e=18{,}432.
\]

Current 33-bit centered packing gives

\[
|e|=\left\lceil 18{,}432\cdot33/8\right\rceil=76{,}032\;\text{B}.
\]

With 32-byte `r_sig`, the fresh cryptographic core is

\[
C_L^{fresh}=76{,}032+32=\boxed{76{,}064\;\text{B}}.
\]

A 32-byte manifest ID yields the minimal manifest-backed core

\[
C_L^{thin}=\boxed{76{,}096\;\text{B}}
\]

before small wire-format framing.

## 3. Per-attribute ML-DSA fresh payload
The measured/standardized ML-DSA-44 signature used by the baseline occupies 2,420 B. For `k` selected attributes:

\[
C_{PA}^{fresh}(k)=2{,}420k.
\]

A common manifest/reference header can be used by both architectures and cancels in the break-even equation. Thus

\[
2{,}420k\ge 76{,}064
\]

gives

\[
\boxed{k^*_{H32}=32}.
\]

At `k=32`, fresh ML-DSA signatures occupy 77,440 B versus 76,064 B for `(r_sig,e)`, a 1,376 B fresh-possession advantage before common headers.

## 4. Static public capability cost
`B_a` has `d*w*N = 8*56*256 = 114,688` coefficients. Since `q < 2^34`, a direct 34-bit packed representation requires

\[
C_B=114{,}688\cdot34/8=\boxed{487{,}424\;\text{B}}
\]

per attribute, before serialization metadata. This explains why portable presentations are large and why the primary deployment profile should use authenticated registry resolution.

The existing implementation uses approximately 487,680 B of portable increment per selected `B_a`, consistent with the theoretical coefficient payload plus metadata.

## 5. Offline/online time model
For the lattice signer, a cold request can be decomposed as

\[
T_L^{cold}(k)=T_{policy}+T_{agg}(k)+T_{prep}+T_{rng}+T_{Hmsg}+T_{SamplePre}.
\]

With a prepared witness state,

\[
\boxed{T_L^{online}\approx T_{rng}+T_{Hmsg}^{thin}+T_{SamplePre}}.
\]

For the verifier,

\[
T_V^{cold}=T_{DUR/AA/Merkle}+T_{pub-agg}(k)+T_{Hmsg}+T_{lattice-eq}+T_{freshness}.
\]

With a current prevalidated manifest,

\[
\boxed{T_V^{online}\approx T_{manifest-current}+T_{Hmsg}^{thin}+T_{lattice-eq}}.
\]

The registry-current check is not assumed to be zero; the redesigned benchmark must measure it.

## 6. Projection from existing component timings (not a new benchmark)
Stage 12E D32 medians provide a conservative component projection:
- measured total signing: 255.480 ms;
- aggregation: 33.399 ms;
- trapdoor transform/Schur precompute: 66.958 ms;
- `r_sig` RNG: 0.0037 ms;
- current large-context `H_msg`: 4.193 ms;
- SamplePre: 128.503 ms.

Moving only aggregation and deterministic precompute offline leaves

\[
0.0037+4.193+128.503\approx\boxed{132.70\;\text{ms}}
\]

as a **projection from old components**, not a measured Stage 13 result. The thin `wid` hash context may reduce `H_msg`, but no numerical gain is claimed before remeasurement.

For D32 verification, current `H_msg` plus lattice equation medians sum to about

\[
4.207+14.156\approx\boxed{18.36\;\text{ms}}.
\]

Again this is only a core projection; manifest-current lookup/freshness must be measured in the new implementation.

## 7. H64/H128 exploratory size profiles
The current H32 `zeta` cannot support H64 unchanged. Stage 13B therefore computes exploratory retunes with a 5% margin over the same conservative sampling formula.

- H64: candidate `zeta≈4.3346e7`, `beta≈5.8849e9`, `2beta/q≈0.6851`, 34-bit proof packing, `|e|=78,336 B`.
- H128: candidate `zeta≈6.1301e7`, `beta≈8.3225e9`, `2beta/q≈0.9689`, 34-bit proof packing, `|e|=78,336 B`.

The fresh `(e,r_sig)` core would be 78,368 B for both exploratory profiles, moving the ML-DSA break-even to `k=33`.

If H64 passes the fresh SIS estimator and implementation validation, then at `k=64`:

\[
C_L^{fresh}=78{,}368\;\text{B},\qquad C_{PA}^{fresh}=154{,}880\;\text{B},
\]

so the lattice fresh proof would be about 49.4% smaller.

If H128 passes all gates, at `k=128` the comparison would be 78,368 B versus 309,760 B, about 74.7% smaller.

**These H64/H128 numbers are projections only. They are not security claims.** H64/H128 require a fresh homogeneous-SIS estimator run because `beta` changes. H128 also has very little `2beta<q` headroom and is therefore exploratory rather than a preferred immediate profile.
