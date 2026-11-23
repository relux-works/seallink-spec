# Namecoin Core 28 — Live Four-Trace Regtest Conformance Proof for SealLink

End-to-end live Namecoin Core `v28.0.0` regtest execution of all four SealLink protocol traces (`trace-01` through `trace-04`) under strict standard transaction policy (`-acceptnonstdtxn=0`, `-txindex=1`), with every `ChainView` extracted directly from an independent read-only peer node (`node B`) and verified live through the Reference Verifier Core (`tools/seallink_verifier.py` with `Tier1Verifier(pinned_network="regtest", require_jsonschema=True)`).

## Measured Configuration

- **Nodes:** Two fresh upstream Namecoin Core `v28.0.0` (`nc28.0`) regtest daemons running on separate temporary data directories, standard policy (`-acceptnonstdtxn=0`), transaction index enabled (`-txindex=1`), connected strictly over a single loopback link (`127.0.0.1`), with no other peers.
  - **Node A (writer):** Broadcasts raw signed transactions, builds `createpsbt` + `namepsbt` `P2WSH` name updates, submits TRUC v3 `P2A` CPFP revocation packages via `submitpackage`, and mines regtest blocks.
  - **Node B (independent read-only verifier peer, `-disablewallet=1`):** Receives zero RPC submissions; observes all transactions over P2P (mempool and confirmed blocks) and supplies 100% of `ChainView` data (`getblockchaininfo`, `getblockheader`, `getrawtransaction`, `getrawmempool`, `name_show`) to `Tier1Verifier`, cross-checked against Node A as the comparison peer.
- **Cryptography & Transactions:** Zero external crypto pip dependencies — pure-Python RFC 6979 low-S DER secp256k1 ECDSA + BIP-143 SegWit v0 signing paired with repository `tools/seallink_ref.py` (`compile_script_policy`, `encode_name_output`, `encode_opreturn`) and `tools/seallink_verifier.py`.

## Scenarios Verified on Live `nc28.0` Regtest

| Trace | Live On-Chain & Mempool Operations Verified | Live `Tier1Verifier` & `nc28.0` Consensus Results |
| --- | --- | --- |
| **Trace 01** (`mail`) | Live `NAME_NEW` -> 12-block maturity -> `NAME_FIRSTUPDATE` -> owner-authored `SIGHASH_ALL` `OP_NAME_UPDATE` (canonical JCS `<= 520 B`), P2WPKH seal + `0x01` `OP_RETURN` issuance, real mempool seal revocation observed on Node B **before mining** | Initial invocation -> `ADMIT`; mempool revocation on Node B -> `REFUSE / SEAL_SPENT`; post-closure invocation -> `REFUSE / GRANT_CLOSED` |
| **Trace 02** (`origin` & `guardianship`) | Live `0x09` origin anchor + `0x0c` name binding; **real `P2WSH` 2-of-3 multisig ward name (`id/t2-child-leo`) updated via `createpsbt` + `namepsbt` + BIP-143 P2WSH witness** (`decodepsbt` script matches `sl.encode_name_output` byte-for-byte); `0x12` initial activation (`both_of_2` -> `either_of_2`), active halt spend, `0x0f` roster transition, `0x0d` `guardian_slot_pending` CSV P2WSH output (**negative control:** premature `0x0e` rejected by `nc28.0` with `non-BIP68-final`; **positive:** exact same `0x0e` accepted & confirmed after `delay_blocks`), plus live `0x0c` recovery attempt cancelled by `P2WSH` 2-of-3 `OP_NAME_UPDATE` with `0x10 RECOVERY_CANCEL` | Ward self-assent -> `REFUSE / WARD_AUTONOMOUS_FORBIDDEN`; halted guardian -> `REFUSE / GUARDIAN_INACTIVE`; CSV-activated successor -> `ADMIT`; recovery outcome -> `cancelled_restored` |
| **Trace 03** (`single_use` & `P2A`) | Real `single_use_1_of_2` P2WSH spends via **branch 0** (grantee + `0x11` `OP_RETURN`) and **branch 1** (issuer revoke); plus **TRUC v3 zero-fee `P2A` (`0x51024e73`) CPFP revocation package** (**negative control:** standalone parent rejected with `min relay fee not met`; **positive:** `submitpackage` -> both parent & child observed in Node B's mempool **before mining**, then confirmed on Node B) | Branch-0 first -> `ADMIT`; branch-0 new-nonce replay -> `REFUSE / INVOKE_REPLAY`; branch-1 revoke -> `REFUSE / SEAL_SPENT` -> `GRANT_CLOSED`; P2A mempool revocation on Node B -> `REFUSE / SEAL_SPENT` |
| **Trace 04** (`agent` ward intake) | Live anchored ward origin (`0x09` + `0x0c`) with two `0x12`-activated `either_of_2` guardians and `0x01` `agent/guardian-message` grants (`strict_drop`, `effect_grant`) | Downgraded 1-of-2 `routine_read` -> `REFUSE / GUARDIAN_QUORUM_UNMET`; full 2-of-2 `effect_grant` -> `ADMIT` |

## Reproduce

Requires Python 3.11+ with `jsonschema>=4.23` and official Namecoin Core `v28.0.0` (`nc28.0`) binaries (`namecoind` and `namecoin-cli`).

```sh
python3 conformance/traces-regtest/run_traces_regtest.py \
  --bin-dir /absolute/path/to/namecoin-28.0/bin \
  --output-json /tmp/observed-traces.json
```

All raw transaction hexes, txids, witnessScripts, negative-control rejection reasons, peer observation flags, and `Tier1Verifier` verdicts from our reference run are recorded in [`observed-traces.json`](observed-traces.json) and integrity-pinned in [`SHA256SUMS`](SHA256SUMS). Both regtest daemons are stopped cleanly and all temporary data directories are removed on exit.

*(Note: `conformance/p2a-regtest/` remains untouched as the original standalone two-node `P2A` package-relay control artifact.)*
