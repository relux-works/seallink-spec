# PROFILE-artifact-v1: Decentralized Artifact Notarization, Release Verification & Tier-2 SPV Gatekeeper

- **Version:** `1.0.0-draft.11`
- **Status:** `draft` (optional conformance module `artifact-notarization`, `decided`)
- **Evidence / Maturity:** `vectors` (`vectors/security-conformance.json`, `vectors/refusal-coverage-matrix.json`, `conformance/traces-regtest/`)
- **Optional Module Tag (`CONFORMANCE.md §1.1`):** `artifact-notarization`
- **Registries:** `registry/object-types.json`, `registry/opreturn-actions.json`, `registry/key-roles.json`, `registry/artifact-schemes.json`, `registry/refusal-codes.json`
- **Schemas:** `schemas/log.schema.json`, `schemas/profile-artifact.schema.json`, `schemas/credential.schema.json`

---

## 1. Scope and Module Boundary

`PROFILE-artifact-v1` builds an optional, self-contained **Artifact Gatekeeper & Tier-2 SPV Verification Profile** on top of SealLink Core's `0x14 LOG_CHECKPOINT` transparency/denial logs (`SPEC-05 §6`, `SL-CONT-012`) and `seallink-release/1` records (`SPEC-05 §7`, `SL-CONT-013`).

- **Optional module gate (`SL-ARTF-001`, `decided`):** Implementations that do **NOT** declare `artifact-notarization` MUST refuse `seallink-ticket/1` and `seallink-tier2-name-history/1` at wire ingress Step 7b (`SPEC-01 §7`) with **`ACTION_UNSUPPORTED`** and zero journal writes.
- **Canonical artifact identity (`SL-ARTF-002`, `decided`):** Every `seallink-ticket/1`, `seallink-release/1`, and `artifact-notarization` `seallink-notary/1` MUST carry `target_sha256 == H_tag("seallink-artifact-id/1", JCS({"digest", "scheme"}))` strictly excluding `params` (`registry/artifact-schemes.json`). Under `scheme = "fsverity-sha256"`, `params` MUST equal `{"version": 1, "hash_alg": "sha256", "block_size": 4096, "salt_hex": ""}` (non-empty `salt_hex` refused `WIRE_MEMBER`; ticket mismatch refused **`TICKET_PROOF_INVALID`**).

---

## 2. Artifact Tickets (`seallink-ticket/1`) and Gatekeeper Policy (`SL-ARTF-003`, `decided`)

`seallink-ticket/1` (`schemas/profile-artifact.schema.json#/$defs/ArtifactTicket`) bundles an `artifact_identity`, canonical `target_sha256`, optional `release` (`seallink-release/1`, REQUIRED whenever `notarizations` is empty), `notarizations[0..32]`, and optional `absent_notary_proofs[]`.

A Gatekeeper evaluates a ticket against a closed `GatekeeperPolicy` (`mode ∈ {"standard", "hardened"}`, `trusted_notaries[]`, `quorum_m`, `required_claims[]`, optional `trusted_release_issuers[]`, `require_release`, `release_floor`, `allow_reinstatement`, optional `bootstrap_expires_at`):

1. **Hardened bootstrap ban & expiry:** `bootstrap_expires_at` is FORBIDDEN when `mode == "hardened"` (`WIRE_MEMBER`). When present in `standard` mode, if `now >= bootstrap_expires_at`, refuse **`ARTIFACT_POLICY_DENIED`**.
2. **Provisional gossip deny-wins:** Any wire-valid `seallink-log-revocation/1` signed by a trusted notary's or release issuer's live `link.<role>` targeting `target:<target_id>|*`, `target:<target_id>|cap:<req_claim>`, or `rel:<release_id>|*` MUST immediately refuse **`ARTIFACT_POLICY_DENIED`** without mutating durable `FencedJournal.log-head`.
3. **Release verification & `release_floor`:** When `release` is present (or `require_release == true`), verify `release.target_sha256 == target_id` (`TICKET_PROOF_INVALID`), issuer `NamePin` + `allowed_product_prefixes[]` + `log_id` (`ARTIFACT_POLICY_DENIED`), monotonic `release_seq >= release_floor[product_id]` (`ARTIFACT_POLICY_DENIED`), and `verify_release` (`0x09` eternal or `0x14` `log_tracked`, propagating `NOTARY_LOG_COMPROMISED` unconditionally).
4. **Present notarizations, `verdict ∈ {"pass", "fail", "inconclusive"}`, and `target:` SMT veto (`SL-ARTF-004`, `decided`):**
   - Duplicate entries for the same trusted notary refuse **`TICKET_PROOF_INVALID`**. Untrusted third-party notarizations in a multi-notary ticket are ignored.
   - Each trusted `log_tracked` notarization MUST verify `0x14` batch inclusion, ancestor chain, durable log closure (`NOTARY_LOG_COMPROMISED`), heartbeat freshness (`heartbeat_max_blocks` unless `terminal == true`), `act:<act_id>|*` SMT proof, AND **`target:<target_id>|*` SMT proof** against `head_checkpoint.denials_root`.
   - Claim verdicts: `"pass"` counts toward `quorum_m`; **`"fail"`** is an immediate deny-wins veto (**`ARTIFACT_POLICY_DENIED`**) and notaries emitting `"fail"` MUST publish a companion `target:<target_id>|*` (or `|cap:<claim_id>`) revocation in the same checkpoint; **`"inconclusive"`** abstains (neither counts toward `quorum_m` nor triggers a veto).
   - For every trusted notary with a pinned `log_id` absent from `notarizations[]`: in **`hardened`** mode, an `absent_notary_proof` proving `target:<target_id>|*` is not revoked in that notary's fresh `head_checkpoint` is **MANDATORY** (`TICKET_PROOF_INVALID` if omitted, `ARTIFACT_POLICY_DENIED` if revoked, `NOTARY_LOG_COMPROMISED` if the log is closed).
   - Every `claim_id` in `required_claims[]` MUST achieve `>= quorum_m` distinct trusted `"pass"` votes (`ARTIFACT_POLICY_DENIED` otherwise).

---

## 3. Tier-2 Consensus-Exact `SegWitNameUpdateProof` and Namecoin AuxPoW (`SL-ARTF-005`, `decided`)

For lightweight Gatekeepers verifying Namecoin `OP_NAME_UPDATE` / `OP_NAME_FIRSTUPDATE` histories via paginated `seallink-tier2-name-history/1` pages (`schemas/profile-artifact.schema.json#/$defs/Tier2NameHistoryPage`), every `SegWitNameUpdateProof` MUST pass **all 7 consensus-exact Namecoin Core `nc28.0` checks** (any failure refuses **`TICKET_PROOF_INVALID`**):

1. **Anti-64-byte leaf forgery & `nVersion`:** Non-witness serialized byte lengths of `coinbase_tx`, `tx`, and `prevout_tx`, plus full serialized length of `tx`, MUST ALL be strictly **`!= 64` bytes**; `tx` MUST carry SegWit marker/flag `00 01` and `nVersion == 0x7100`.
2. **Coinbase structure & exact depth `D_tree`:** `len(coinbase_tx.vin) == 1` with null prevout `(00*32, 0xffffffff)`; `coinbase_merkle_branch` folds `txid(coinbase_tx)` at `index == 0` into `block_header.hashMerkleRoot`, fixing exact block Merkle depth `D_tree = len(coinbase_merkle_branch) >= 1`.
3. **Strict depth & `CVE-2012-2459` guard:** `tx_index >= 1`, `len(txid_branch) == len(wtxid_branch) == len(wtxid_coinbase_branch) == D_tree`, rejecting odd-position duplicate siblings; `txid_branch` proves `txid(tx)` at `tx_index` in `hashMerkleRoot`.
4. **BIP-141 witness commitment:** Extract commitment `[6:38]` from the **LAST** `coinbase_tx.vout[]` matching prefix `6a24aa21a9ed` (`len >= 38`); `coinbase_tx.vin[0].witness` MUST hold exactly one 32-byte `witness_reserved_value`.
5. **Witness tree binding:** `wtxid(tx)` at the same `tx_index` via `wtxid_branch` produces `wtxid_root`; `wtxid_coinbase_branch` folds `00*32` at `index == 0` into the same `wtxid_root`; `SHA256d(wtxid_root || witness_reserved_value) == witness_commitment`.
6. **Stripped BIP-143 `scriptCode` with CompactSize prefix:** `prevout_tx` matches the spent name input; strip Namecoin prefix (`OP_NAME_FIRSTUPDATE` / `OP_NAME_UPDATE ... OP_2DROP OP_DROP`) and match trailing script to `compile(expected_owner_policy)`; compute BIP-143 sighash including `varint(len(scriptCode)) || scriptCode` (`76a914<20B>88ac` for `P2WPKH`, `witnessScript` for `P2WSH`).
7. **Consensus-exact BIP-66 DER + `SIGHASH_ALL` (accepting high-S):** Every ECDSA signature in the name input witness MUST be canonical BIP-66 DER with trailing `0x01` (`SIGHASH_ALL`) and verify over the BIP-143 sighash. **Tier-2 verifiers MUST NOT reject consensus-valid high-S (`S > N/2`) signatures** already mined into Namecoin blocks (signers SHOULD emit low-S per `GUIDE-01 §2` to satisfy standard relay policy).

### 3.1 Namecoin AuxPoW (`CAuxPow::check`) and Difficulty Retarget (`SL-ARTF-006`, `decided`)

When validating 80-byte Namecoin block header chains (`BlockHeaderProof`):
- **AuxPoW (`nVersion & 0x00000100 != 0`):** Verify `chain_id = (nVersion >> 16) == 0x0001`, `parent_header` PoW `<= target(nBits)`, `coinbase_branch` at `index == 0` into `parent_header.hashMerkleRoot`, merged-mining magic `fabe6d6d` immediately preceding `aux_merkle_root` (or omitted iff `aux_merkle_root` starts within the first 20 bytes of `parent_coinbase.vin[0].scriptSig`, matching Namecoin Core `CAuxPow::check`, where synthetic regtest parent coinbases MAY carry empty `vout`), `merkle_size`, `merkle_nonce`, expected slot `GetExpectedIndex(merkle_nonce, chain_id, merkle_size)`, and `chain_branch` for `block_hash`.
- **Difficulty retarget (`H % 2016 == 0`):** Clamp `actual_timespan = block[H - 1].nTime - block[H - 2016].nTime` strictly to `[302400, 4838400]`, compute `new_target = min(powLimit, (old_target * actual_timespan) // 1209600)`, and enforce `fPowNoRetargeting = true` on `regtest`. Header checkpoints SHOULD anchor at `H_cp % 2016 == 0` (or pin explicit `epoch_start_time`).

---

## 4. Curator Integration (`CIP-0007` / `CIP-0008` / `CIP-0034`)

- Canonical signing (`CIP-0008`) maps directly to SealLink Restricted JCS + BIP-340 (`SPEC-01`).
- Curator content digests use `scheme = "works.relux.curator/content-v2"` (`registry/artifact-schemes.json`); revocations (`CIP-0007`) map to `act:<act_id>|*` and `target:<target_id>|*` inside `0x14` logs.
- Phase-1 bootstrap Gatekeeper deployments MUST set `bootstrap_expires_at <= now + 90 days` in `standard` mode and transition to `hardened` mode (without `bootstrap_expires_at`) once multi-notary quorum is operational.

---

## 5. Security Considerations

- **Unified 100% `CLOSE` on log fraud:** A verified `seallink-log-fraud/1` durably records `NOTARY_LOG_COMPROMISED` and blocks 100% of acts and releases from that `log_id` in both `standard` and `hardened` Gatekeeper modes.
- **Tier-2 source diversity:** Production Tier-2 Gatekeepers SHOULD cross-check headers and `seallink-tier2-name-history/1` pages across `k >= 2` independent header/RPC providers (`OPEN-QUESTIONS.md` `OQ-002`).
- **HSM role separation:** `link.notary` and `link.release` keys require dedicated BIP-340 signers; `log_seal` (ECDSA) MAY reside in standard KMS/HSM custody (`GUIDE-01 §1`).

---

## 6. References

- **Normative:** [RFC8785], [RFC9162], [BIP-66], [BIP-141], [BIP-143], [BIP-340], [JSON-SCHEMA-2020-12].
- **Informative:** [NC28].
