# Stage 13B Protocol Freeze — Online/Offline Split

## 1. Design goal
Move period-stable credential evidence and witness-dependent deterministic work out of the per-request critical path without changing the lattice possession relation.

The lattice core remains

\[
B_a=A_0R_a+G,\qquad
R_S=\sum_{a\in S}R_a,\qquad
B_S=\sum_{a\in S}B_a-(|S|-1)G,
\]
\[
C_S=[A_0\mid B_S],\quad T_S=-R_S,\quad C_S[T_S;I]=G,
\]
\[
e\leftarrow \mathsf{ModuleSamplePre}(C_S,T_S,u_M;\zeta),\qquad C_Se=u_M\pmod q.
\]

No multiplication-based credential evaluation is reintroduced.

## 2. Component roles

### DUR
The DUR remains a registration/pseudonym component. It binds one registered user to `pid_{U,tau}` and the active period. It MUST NOT become a universal attribute issuer or a trusted lattice trapdoor holder.

### Independent AAs
Each AA independently issues and authenticates user/attribute/period credential state. AA signatures remain the root of issuer authenticity.

### Authenticated Credential Registry / Directory
The registry is a distribution/cache layer, not a new issuer. It stores or indexes DUR/AA-authenticated state, including public `B_a`, credential identifiers, root/version/status metadata, and AA evidence. A verifier may prevalidate and cache this evidence. A registry entry is acceptable only if the underlying DUR/AA evidence has been validated under the current trust policy.

This preserves the no-system-wide-lattice-master-trapdoor property and avoids turning the DUR into a central attribute authority.

## 3. Canonical witness manifest
For a canonical witness `S`, define a canonical manifest

\[
\mathsf{Man}_S=\mathsf{Encode}(sid,paramID,pid_{U,\tau},\tau,policyID,S,
\{cid_a,issuer_a,rootVer_a,statusVer_a\}_{a\in S},H(B_S),t_{exp}).
\]

Define the manifest identifier

\[
wid=H_{man}(\mathsf{Man}_S)\in\{0,1\}^{256}.
\]

`wid` commits to the exact user/period, canonical witness, issuer/version state, and aggregate public root. Any change of those fields creates a different manifest identifier except on a hash collision.

The registry may create manifests on demand and cache only actually used canonical witnesses. The design does not require pre-enumerating all satisfying subsets.

## 4. Signer offline preparation
`Signer.PrepareOffline(S)` performs work reusable for the lifetime of the manifest:

1. Resolve and locally validate the selected credential statements.
2. Check one common `(pid,tau)` and credential freshness.
3. Check `WitnessOK(f,S)=1` and canonical ordering.
4. Compute `R_S=sum R_a`.
5. Compute/check `B_S=sum B_a-(|S|-1)G`.
6. Construct `C_S=[A_0|B_S]` and `T_S=-R_S`.
7. Compute reusable trapdoor transforms / Schur data required by the reference ModuleSamplePre implementation.
8. Construct `Man_S` and `wid`; cache `SState=(wid,R_S,B_S,C_S,T_S,precompute,expiry,versions)`.

Invalidation occurs on period change, selected credential rotation, root/status version change, revocation, policy/witness change, or parameter-set change.

## 5. Signer online path
For a fresh request/session supplied externally by the verifier/PDP:

1. Require a non-expired current `SState`.
2. Sample independent `r_sig <- {0,1}^{256}`.
3. Compute

\[
u_M=H_{msg}(sid,paramID,wid,req,verifierNonce,sessionID,r_{sig}).
\]

4. Run `ModuleSamplePre` using cached `(C_S,T_S,precompute)`.
5. Return the thin online token

\[
\boxed{\Sigma_{thin}=(wid,r_{sig},e)}.
\]

The request/message need not be duplicated inside the token when already supplied by the session layer; it remains cryptographically bound through `H_msg`.

A self-describing wire format may add codec/version bytes. Those bytes are implementation metadata, not part of the cryptographic core-size formula.

## 6. Verifier offline preparation
`Verifier.PrepareOffline(wid)`:

1. Resolve `Man_S` and all referenced credential state.
2. Verify the DUR registration evidence and current period/status.
3. Verify AA verification keys/namespaces and AA root/direct signatures.
4. Verify Merkle membership where used.
5. Verify the same `(pid,tau)`, canonical witness, policy satisfaction, versions, expiry, and status.
6. Reconstruct `B_S` from authenticated `B_a` and check `H(B_S)` against the manifest.
7. Construct `C_S=[A_0|B_S]`.
8. Cache `VState=(wid,C_S,expiry,versions,statusSnapshot)`.

The expensive DUR/AA/Merkle checks therefore need not be repeated for every request while the cached state remains current.

## 7. Verifier online path
For a fresh request and token `(wid,r_sig,e)`:

1. Parse canonical encodings and check request/session replay state.
2. Resolve a current non-expired `VState` for `wid`; fail closed if currentness cannot be established.
3. Compute the same `u_M` from `wid`, request/session context and `r_sig`.
4. Check `||e|| <= beta_sig`.
5. Check `C_S e = u_M (mod q)`.
6. Accept only if all checks pass.

## 8. Profiles

### Primary: manifest-backed thin online profile
Per request, transmit only `wid`, `r_sig`, and `e` (plus minimal codec framing). Static credential evidence stays in the authenticated registry/cache.

### Fallback: reference-list profile
Transmit small credential identifiers/references but not `B_a`, AA signatures, roots or Merkle paths. The verifier resolves the evidence.

### Audit/fallback: portable self-contained profile
Transmit the public credential material and authentication evidence. This remains useful for disconnected verification but is not the performance-oriented deployment profile.

## 9. Security-critical non-negotiables
- `r_sig` remains fresh and independent for every request.
- `H_msg` binds `wid` and the fresh verifier/session context.
- `wid` binds the exact canonical witness and credential/root/status versions.
- Cached state must be invalidated on revocation/rotation/version changes.
- Registry distribution does not authorize credentials by itself; underlying DUR/AA authenticity remains required.
- Failure to establish current registry state is a verification failure, not a reason to accept stale cached evidence.
