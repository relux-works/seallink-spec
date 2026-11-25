# SealLink Open Questions and Provisional Parameters

- **Version:** `1.0.0-draft.10`
- **Purpose:** Authoritative registry of every unresolved design item, provisional numeric constant, deferred extension, and unprofiled standard service type. Per `SPEC-00 §5.1`, readers MUST fail closed on any unprofiled `open` construct.

---

## 1. Open Normative Profiles and Protocols

| ID | Owning Spec | Status | Topic | Current Safe Fallback / Blocking Scope |
| --- | --- | :-: | --- | --- |
| `OQ-001` | `SPEC-04 §4` (`SL-ORIG-010`) | `open` | **Trusted calendar time-interval oracle** for human majority boundary `T` (`[t_low, t_high]`). | Fail closed (`GUARDIAN_TIME_BOUNDARY`) whenever credible UTC bounds cannot be established or straddle `T`. Candidate profiles: multi-source Roughtime / signed NTS quorum + chain MTP floor. |
| `OQ-002` | `SPEC-02 §1.1` (`SL-LDGR-002`) | `open` | **Tier 2 light / proof-bundle verifier profile** (`k >= 2` independent UTXO/name proof servers or future authenticated UTXO commitments). | Tier 1 full-node verifier is required for all effect executors. Tier 2 is deferred to post-v1.0. |
| `OQ-003` | `SPEC-06 §6` (`SL-GRNT-014`) | `open` | **External CAS witness wire protocol** (`advance(journal_id, token, pos, from_commit, to_commit)`). | State machine and fencing invariants are `decided`; interoperable wire transport (e.g., HTTP CAS / Raft / consensus-backed service) remains operator-local until profiled. |
| `OQ-004` | `SPEC-03 §4` (`SL-IDEN-009`) | `open` | **HTTPS `.well-known` domain-binding verification** (Channel 2 pairing between `id/<label>` and `d/<label>` or DNSSEC/NIP-05). | Channel 0 (inline) and Channel 1 (local cache / configured mirrors) work unconditionally; Channel 2 is optional and hash-pinned only. |
| `OQ-005` | `SPEC-01 §4.1` (`SL-WIRE-012`) | `open` | **Additional hardware device algorithms** (`fido2-es256`, `fido2-eddsa`, `ssh-ed25519` WebAuthn/SSH wrappers). | v1.0 closes `DeviceList.alg` to `bip340`, `p256`, and `ed25519`. Hardware wrapper formats will be proposed via SLIPs with exact canonical challenge framing. |
| `OQ-006` | `SPEC-02 §6.3` (`SL-LDGR-013`) | `open` | **Production propagation qualification for TRUC v3 / `P2A` (`51024e73`) CPFP revocation.** | Two-node Namecoin Core `nc28.0` regtest 1p1c `submitpackage` + P2P propagation + confirmation is verified both standalone (`conformance/p2a-regtest/`) and end-to-end inside live `Tier1Verifier` Trace 03 (`conformance/traces-regtest/`, covering `minrelaytxfee = 0.001 NMC/1000 vB` and `240`-sat `P2A` dust floor). Independent operator administration, fee competition, and mainnet propagation remain open before `chain-tested` maturity. |
| `OQ-007` | `SPEC-02 §3.1` (`SL-LDGR-004`) | `open` *(non-blocking)* | **Optional threshold-ECDSA MPC qualification for single-key `P2WPKH` outputs.** | **Resolved for institutional branch roles in `v1.0.0-draft.7`:** `BranchKeySpec` natively supports BOTH single `CompressedPubkey66` AND compact native `P2WSH` `m-of-n` (`2 <= n <= 5`) multisig via offline PSBT for `disposer_pk`, `arbiter_pk`, `challenger_pk`, and `arbiter_or_both.arbiter` (verified live on `nc28.0` alongside `P2WSH` `namepsbt` name outputs). Optional external threshold-ECDSA MPC signing for single-key `P2WPKH` outputs remains an independent deployment option outside the v1.0 wire freeze. |

---

## 2. Provisional Numeric Constants (Subject to Empirical Calibration Before Freeze)

| ID | Owning Spec | Constant | Provisional Value | Calibration Basis |
| --- | --- | --- | --- | --- |
| `OQ-010` | `SPEC-02 §4` (`SL-LDGR-008`) | `LAG` (reading-node header lag bound) | `1` block | Verifier-owned config (never overridable by `ChainViewSnapshot`, `SL-LDGR-015`); Namecoin block propagation telemetry. |
| `OQ-011` | `SPEC-02 §4` (`SL-LDGR-008`) | `S` (block header future-timestamp bound) | `600` seconds | Verifier-owned config (never overridable by `ChainViewSnapshot`, `SL-LDGR-015`); Namecoin consensus vs clock skew tolerances. |
| `OQ-012` | `SPEC-02 §4` (`SL-LDGR-008`) | `K` (grant `recent_block` recency ceiling) | **`432` blocks (~72 h) — `decided`** | Frozen in `v1.0.0-draft.7`: balances offline signing ceremonies against bounded replay/history walks. |
| `OQ-013` | `SPEC-02 §4` (`SL-LDGR-008`) | Risk Class 1 / Class 2 `tip_age` cutoffs | `3600s` / `5400s` | Namecoin block-interval tail distribution (9.88 min mean). |
| `OQ-014` | `SPEC-03 §6` (`SL-IDEN-012`) | Host trust-root admin override delay `D` | `1008` blocks (~7 d) | Incident response window for human owners. |
| `OQ-015` | `SPEC-04 §6` (`SL-ORIG-013`) | Dual-party `name_recovery` minimum delay | `144` blocks min (`1008` recommended) | Live-owner liveness & cancellation window. |

---

## 3. Unprofiled Standard Service Types (`registry/service-types.json`)

The following standard `service_type` names are reserved with `status = "open"` pending dedicated SLIP profiles meeting the `SPEC-07 §4.1` checklist:

| `service_type` | Planned Profile | Notes |
| --- | --- | --- |
| `xmpp` | `PROFILE-xmpp-v1.md` | Sovereign XMPP hosting bound via `manifest.providers[]`. |
| `blob` | `PROFILE-blob-v1.md` | Grant-aware content-addressed blob store (Blossom BUD-01/02/04). |
| `wallet` | `PROFILE-wallet-v1.md` | `seallink/coins` spend & budget execution (concrete executor, UTXO seal, no bearer sessions). |
| `names` | `PROFILE-names-v1.md` | Delegated update-only ledger name operations. |
| `compute` | `PROFILE-compute-v1.md` | Metered LLM/compute proxy (`seallink/cost`, `seallink/tokens`, root `window_only`, bearer sessions). |
| `rental` | `PROFILE-rental-v1.md` | Contract-bound physical/digital asset lease (`requires_contract = true`, arbiter seal). |

---

## 4. Institutional and Scope Boundaries Explicitly Outside v1.0

- **Reversible adult legal capacity (conservatorship):** v1.0 enforces strictly one-way `ward -> autonomous`. Reversible capacity requires a future SLIP addressing judicial contestation and revocation of autonomy.
- **Cross-chain bridge semantics:** v1.0 binds one `network` + `genesis` per object and verification session.
