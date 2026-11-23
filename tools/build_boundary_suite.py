#!/usr/bin/env python3
"""
Boundary, Restart-Recovery, Historical Re-Registration, and Compound-Logic Suite.

Appends executable conformance cases to `vectors/security-conformance.json` closing:
  1. Historical eternal credential verification after issuer expiry & re-registration
     by a new owner (same ChainView resolving current new owner AND historical diploma).
  2. Full executor restart state reconstruction via `FencedJournal.replay_persisted_entries`
     (restoring monotonic `seconds:*` clock watermarks AND content-addressed cached receipts).
  3. Exact numeric boundary endpoints (`<` vs `<=`, `>` vs `>=`) across SPEC-01..SPEC-07
     so two independent implementations cannot diverge on any off-by-one boundary.
  4. Isolated clauses of compound boolean (`and`/`or`) guards.
"""

from __future__ import annotations

import copy
from typing import Any, Callable

import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = rm.GENESIS_MAIN
GENESIS_REGTEST = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-bnd-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"bnd:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def add_boundary_and_recovery_cases(add: Callable[..., None]) -> None:
    """Append historical re-registration, restart recovery, boundary, and logic cases."""
    fx0 = rm._base_invocation_fixture()

    # =========================================================================
    # 1. Historical Eternal Credential Across Expiry & Lawful Re-Registration
    # =========================================================================
    sch1_own, sch1_cred = _kp("hr-sch1-own"), _kp("hr-sch1-cred")
    sch2_own, sch2_cred = _kp("hr-sch2-own"), _kp("hr-sch2-cred")
    subj_k = _kp("hr-subj")
    sch1_pol = {"kind": "key", "pk": sch1_own["comp"]}
    sch2_pol = {"kind": "key", "pk": sch2_own["comp"]}
    reg1 = {"txid": _h32("hr-reg1-fu"), "vout": 0}
    reg2 = {"txid": _h32("hr-reg2-fu"), "vout": 0}
    lin1 = sv.make_name_history(
        "id/school-hist", reg1, sch1_pol, {"link": {"cred": sch1_cred["xonly"]}},
        first_height=150, update_height=151,
    )
    lin2 = sv.make_name_history(
        "id/school-hist", reg2, sch2_pol, {"link": {"cred": sch2_cred["xonly"]}},
        first_height=200, update_height=201,
    )
    dip_ok_p = {
        "claims": {"degree": "BSc Computer Science", "graduated": 2026},
        "credential_kind": "education/diploma",
        "genesis": GENESIS_REGTEST,
        "issued_at": 1795220000,
        "issuer": {"name": "id/school-hist", "owner_policy": sch1_pol, "registration": reg1, "role_policy": {"m": 1, "pks": [sch1_cred["xonly"]]}},
        "lifecycle": "eternal",
        "network": "regtest",
        "not_before_height": 157,
        "subject": {"key": subj_k["xonly"], "mode": "key"},
        "type": "seallink-credential/1",
    }
    dip_ok = sl.sign_envelope(dip_ok_p, [sch1_cred["sk"]])
    dip_ok_tx = _h32("hr-dip-ok-tx")
    # Second diploma anchored AFTER reg1 expired (151 + 30 = 181 on regtest -> height 181 MUST refuse NAME_EXPIRED!)
    dip_exp_p = {**dip_ok_p, "claims": {"degree": "Post-Expiry Forgery", "graduated": 2026}, "not_before_height": 181}
    dip_exp = sl.sign_envelope(dip_exp_p, [sch1_cred["sk"]])
    dip_exp_tx = _h32("hr-dip-exp-tx")

    ch_hr = {
        "best_header_height": 204,
        "blocks": {},
        "clock_watermark": 1795219900,
        "comparison_peers": [{"hash_at_tip": _h32("hr-tip"), "healthy": True, "height": 204, "id": "peer-a"}],
        "future_bound_s": 600,
        "genesis": GENESIS_REGTEST,
        "in_ibd": False,
        "lag_limit": 1,
        "manifests": {},
        "name_registrations": {"id/school-hist": [lin1, lin2]},
        "names": {"id/school-hist": lin2},
        "network": "regtest",
        "node_reachable": True,
        "now": 1795220010,
        "tip_first_sight": 1795220000,
        "tip_hash": _h32("hr-tip"),
        "tip_header_time": 1795220000,
        "tip_height": 204,
        "txindex": True,
        "txs": {
            dip_ok_tx: {"confirmed_height": 157, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(dip_ok)).hex(), "outputs": {}},
            dip_exp_tx: {"confirmed_height": 181, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(dip_exp)).hex(), "outputs": {}},
        },
    }
    add(
        "accept-historical-eternal-credential-survives-expiry-and-reregistration",
        ["SL-LDGR-002", "SL-CONT-010"],
        "historical_rereg",
        {
            "pinned_network": "regtest",
            "pinned_genesis": GENESIS_REGTEST,
            "name": "id/school-hist",
            "old_owner_policy": sch1_pol,
            "old_registration": reg1,
            "new_owner_policy": sch2_pol,
            "new_registration": reg2,
            "old_credential": dip_ok,
            "old_anchor_txid": dip_ok_tx,
            "post_expiry_credential": dip_exp,
            "post_expiry_anchor_txid": dip_exp_tx,
            "chain": ch_hr,
        },
        "ADMIT",
        None,
        "From one ChainView after expiry and re-registration, current lookup resolves to the new owner, historical eternal diploma anchored while reg #1 was live returns ADMIT, and a post-expiry anchor returns NAME_EXPIRED.",
    )

    # =========================================================================
    # 2. Full Executor Restart Recovery (quota_watermarks + receipt_store)
    # =========================================================================
    fx_rr = rm._base_invocation_fixture()
    exec_wire_rr = fx_rr["invocation"]["payload"]["executor"]
    # Build a seconds:3600 quota grant (mail/read) AND a single_use grant on the same executor!
    gp_sec = copy.deepcopy(fx_rr["bundle"]["grants"][0]["payload"])
    gp_sec["capabilities"] = [
        {
            "action": "mail/read",
            "quotas": [{"kind": "count", "max": "5", "resource": "mail/read", "unit": "calls", "window": "seconds:3600"}],
            "target": "mailbox:id/alice:work",
            "where": {},
        }
    ]
    g_sec = sl.sign_envelope(gp_sec, [fx_rr["_keys"]["alice_gr"]["sk"]])
    gid_sec = sl.object_id(gp_sec)
    itx_sec = _h32("rr-itx-sec")
    orig_itx_h = fx_rr["chain"]["txs"][fx_rr["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["confirmed_height"]
    fx_rr["chain"]["txs"][itx_sec] = {
        "confirmed_height": orig_itx_h,
        "inputs": [sv.make_segwit_input(gp_sec["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_sec), "grant_id": gid_sec, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_sec_1 = sl.sign_envelope(
        {
            "action": "mail/read",
            "arguments": {"folder": "INBOX", "message_id": "m-rr-1"},
            "executor": exec_wire_rr,
            "exp": 1795221000,
            "genesis": GENESIS_MAIN,
            "iat": 1795220000,
            "network": "main",
            "nonce": _h32("rr-sec-n1"),
            "proof_path": [{"grant_id": gid_sec, "issuance_txid": itx_sec}],
            "target": "mailbox:id/alice:work",
            "type": "seallink-invocation/1",
        },
        [fx_rr["_keys"]["agent_req"]["sk"]],
    )
    rcpt_sec_1 = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": fx_rr["executor_cfg"]["name"],
            "genesis": GENESIS_MAIN,
            "grant_id": gid_sec,
            "invocation_id": sl.object_id(inv_sec_1["payload"]),
            "network": "main",
            "outcome": "executed",
            "recorded_at": 1795220010,
            "settlements": [{"account": "own", "kind": "count", "released": "0", "reserved": "1", "resource": "mail/read", "settled": "1", "unit": "calls", "window": "seconds:3600"}],
            "tip_hash": fx_rr["chain"]["tip_hash"],
            "tip_height": fx_rr["chain"]["tip_height"],
            "type": "seallink-receipt/1",
        },
        [fx_rr["_keys"]["host_rcpt"]["sk"]],
    )
    # Single-use grant for cached receipt recovery after restart!
    su_iss_k, su_gr_k = _kp("rr-su-iss"), _kp("rr-su-gr")
    su_pol = {"kind": "branch", "template": "single_use_1_of_2", "keys": {"grantee": su_gr_k["comp"], "issuer": su_iss_k["comp"]}}
    su_spk, su_ws = sl.compile_script_policy(su_pol)
    assert su_ws is not None
    su_seal_tx = _h32("rr-su-seal-tx")
    gp_su = copy.deepcopy(gp_sec)
    gp_su["revocation"] = {"construction": "W", "kind": "single_use", "mode": "seal", "seal": {"script_policy": su_pol, "txid": su_seal_tx, "vout": 0}}
    g_su = sl.sign_envelope(gp_su, [fx_rr["_keys"]["alice_gr"]["sk"]])
    gid_su = sl.object_id(gp_su)
    itx_su = _h32("rr-itx-su")
    inv_su_1 = sl.sign_envelope(
        {**inv_sec_1["payload"], "nonce": _h32("rr-su-n1"), "proof_path": [{"grant_id": gid_su, "issuance_txid": itx_su}]},
        [fx_rr["_keys"]["agent_req"]["sk"]],
    )
    inv_su_new_nonce = sl.sign_envelope(
        {**inv_sec_1["payload"], "nonce": _h32("rr-su-n2"), "proof_path": [{"grant_id": gid_su, "issuance_txid": itx_su}]},
        [fx_rr["_keys"]["agent_req"]["sk"]],
    )
    use_su_tx = _h32("rr-su-use-tx")
    fx_rr["chain"]["txs"][su_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": su_spk.hex(), "spent_by_txid": use_su_tx}}}
    fx_rr["chain"]["txs"][itx_su] = {
        "confirmed_height": orig_itx_h,
        "inputs": [sv.make_segwit_input(gp_sec["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_su), "grant_id": gid_su, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    fx_rr["chain"]["txs"][use_su_tx] = {
        "confirmed_height": 749999,
        "inputs": [{"prev_txid": su_seal_tx, "prev_vout": 0, "script_sig_hex": "", "witness": ["3044" + ("02" * 68) + "01", "", su_ws.hex()]}],
        "opreturn_hex": sl.encode_opreturn(0x11, sl.content_addr(inv_su_1)).hex(),
        "outputs": {},
    }
    rcpt_su_1 = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": fx_rr["executor_cfg"]["name"],
            "genesis": GENESIS_MAIN,
            "grant_id": gid_su,
            "invocation_id": sl.object_id(inv_su_1["payload"]),
            "network": "main",
            "outcome": "executed",
            "recorded_at": 1795220010,
            "settlements": [{"account": "own", "kind": "count", "released": "0", "reserved": "1", "resource": "mail/read", "settled": "1", "unit": "calls", "window": "seconds:3600"}],
            "tip_hash": fx_rr["chain"]["tip_hash"],
            "tip_height": fx_rr["chain"]["tip_height"],
            "type": "seallink-receipt/1",
        },
        [fx_rr["_keys"]["host_rcpt"]["sk"]],
    )

    ch_t10 = copy.deepcopy(fx_rr["chain"])
    ch_t10["now"] = 1795220010
    ch_t10["clock_watermark"] = 1795220000
    ch_t10["tip_header_time"] = 1795220000
    ch_t10["tip_first_sight"] = 1795220000
    ch_t09 = copy.deepcopy(ch_t10)
    ch_t09["now"] = 1795220009
    inv_sec_back = sl.sign_envelope({**inv_sec_1["payload"], "nonce": _h32("rr-sec-back")}, [fx_rr["_keys"]["agent_req"]["sk"]])
    inv_sec_eq = sl.sign_envelope({**inv_sec_1["payload"], "nonce": _h32("rr-sec-eq")}, [fx_rr["_keys"]["agent_req"]["sk"]])

    add(
        "accept-restart-recovery-restores-watermarks-and-cached-receipts",
        ["SL-GRNT-004", "SL-GRNT-014"],
        "restart_recovery",
        {
            "journal_id": _h32("rr-jid"),
            "executor_cfg": fx_rr["executor_cfg"],
            "pre_restart_steps": [
                {"label": "pre-sec-mail-read", "chain": ch_t10, "invocation": inv_sec_1, "bundle": {**fx_rr["bundle"], "grants": [g_sec]}, "receipt_env": rcpt_sec_1, "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "pre-single-use", "chain": ch_t10, "invocation": inv_su_1, "bundle": {**fx_rr["bundle"], "grants": [g_su]}, "use_txid": use_su_tx, "receipt_env": rcpt_su_1, "want_verdict": "ADMIT", "want_refusal": None},
            ],
            "post_restart_steps": [
                {"label": "post-clock-regression", "chain": ch_t09, "invocation": inv_sec_back, "bundle": {**fx_rr["bundle"], "grants": [g_sec]}, "want_verdict": "REFUSE", "want_refusal": "QUOTA_CLOCK_REGRESSION", "expect_zero_writes": True},
                {"label": "post-clock-eq-watermark", "chain": ch_t10, "invocation": inv_sec_eq, "bundle": {**fx_rr["bundle"], "grants": [g_sec]}, "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "post-cached-mail-receipt", "chain": ch_t10, "invocation": inv_sec_1, "bundle": {**fx_rr["bundle"], "grants": [g_sec]}, "want_verdict": "ADMIT", "want_refusal": None, "expect_zero_writes": True, "expect_cached_receipt_ca": sl.content_addr(rcpt_sec_1)},
                {"label": "post-cached-su-receipt", "chain": ch_t10, "invocation": inv_su_1, "bundle": {**fx_rr["bundle"], "grants": [g_su]}, "use_txid": use_su_tx, "want_verdict": "ADMIT", "want_refusal": None, "expect_zero_writes": True, "expect_cached_receipt_ca": sl.content_addr(rcpt_su_1)},
                {"label": "post-su-new-nonce-replay", "chain": ch_t10, "invocation": inv_su_new_nonce, "bundle": {**fx_rr["bundle"], "grants": [g_su]}, "use_txid": use_su_tx, "want_verdict": "REFUSE", "want_refusal": "INVOKE_REPLAY", "expect_zero_writes": True},
            ],
        },
        "ADMIT",
        None,
        "After serialized journal + receipt_store replay into a fresh FencedJournal, monotonic seconds:* clock watermarks survive (blocking clock rollback with QUOTA_CLOCK_REGRESSION while admitting == watermark), idempotent retries return identical cached signed receipts with 0 writes, and consumed single-use new-nonce calls refuse INVOKE_REPLAY.",
    )

    # =========================================================================
    # 3. Exact Numeric Boundaries (< vs <=, > vs >=) across SPEC-01..SPEC-07
    # =========================================================================

    # 3a. Exact type_max wire size (16384 B seallink-card/1) -> ADMIT (kills L622 > -> >=)
    card_base = {
        "contact": [],
        "display": {"name": "X"},
        "kind": "person",
        "name": "id/alice",
        "network": "main",
        "relays": [],
        "replaces": None,
        "role": "issuer",
        "seq": 1,
        "transports": [],
        "type": "seallink-card/1",
    }
    # Pad `display.bio`? Let's pad `display.name`? Card display.name maxLength=256; use `relays` URLs to reach EXACT 16384 bytes!
    # Wait: check card schema limits -> relays maxItems=16, let's check what allows large text or use `seallink-name-binding/1`? No, card has max_bytes=16384! Let's use `seallink-grant/1` (`terms_text` up to 8192) or `seallink-auth-challenge/1` (max_bytes=2048)?
    # Even cleaner: `seallink-name-binding/1` has max_bytes=4096, or `seallink-card/1`? Let's compute exact length with `raw_bytes_utf8` using `seallink-auth-challenge/1`? No, `auth-challenge` has fixed fields. Use `seallink-card/1` with `display.summary` or `seallink-manifest/1`? Wait — use `raw_wire` with `max_bytes_override`? No, L622 tests `type_max = reg[obj_type]["max_bytes"]`!
    # `seallink-name-binding/1` has max_bytes=4096; `seallink-card/1` has `contact` array (maxItems=32, value maxLength=512 -> 32*512 = 16384!!)! Let's check exact byte length cleanly!
    # Use `seallink-statement/1` (max_bytes=4096, body freeform? Let's use `seallink-grant/1`? Grant max_bytes=65536).
    # `seallink-card/1` has `max_bytes=16384` and `contact` / `relays` / `transports`. Let's use `seallink-contract/1`? Contract max_bytes=65536.
    # Actually `seallink-card/1` `contact` items `{kind, value}` with 31*500 + exact filler hits EXACT 16384 bytes!
    # Wait: `seallink-card/1` schema has `maxItems: 16` or `32`? Let's check using `seallink-grant/1`? No, let's build a valid `seallink-statement/1`? Even simpler: `seallink-migration/1`? No, check `seallink-receipt/1`? No, `seallink-card/1`! Wait: check `seallink-device-list/1` (`max_bytes=16384`) or `seallink-manifest/1` (`max_bytes=16384`, `providers` maxItems=64 -> each provider ~260 bytes -> 60 providers = ~16384B)! Let's pad `manifest.service.endpoint` (maxLength=1024) + `providers` to hit EXACT 16384 bytes!
    man_exact = {
        "network": "main",
        "owner": "id/alice",
        "providers": [
            {
                "label": f"p{i:02d}",
                "provider": {"name": f"id/prov-{i:02d}", "owner_policy": fx0["_host_owner_pol"], "registration": {"txid": _h32(f"mp-{i}"), "vout": 0}},
                "service_type": "mail",
            }
            for i in range(60)
        ],
        "seq": 1,
        "service": {"actions": ["mail/read"], "endpoint": "https://m.example/", "receipt_key": fx0["_keys"]["host_rcpt"]["xonly"], "service_type": "mail"},
        "type": "seallink-manifest/1",
    }
    cur_len = len(sl.jcs_encode(man_exact))
    # Adjust providers count so 16384 - cur_len is between 20 and 900, then pad endpoint URL to EXACT 16384 bytes!
    while cur_len > 16350:
        man_exact["providers"].pop()
        cur_len = len(sl.jcs_encode(man_exact))
    pad_n = 16384 - cur_len
    assert 0 <= pad_n <= 980, f"Unexpected pad_n={pad_n}"
    man_exact["service"]["endpoint"] = "https://m.example/" + ("a" * pad_n)
    assert len(sl.jcs_encode(man_exact)) == 16384
    add("bnd-wire-exact-type-max-bytes-admit", ["SL-WIRE-001"], "raw_wire",
        {"object": man_exact}, "ADMIT", None,
        "Manifest encoding to exact type_max (16384 bytes) MUST be admitted (strictly > type_max refuses WIRE_SIZE).")

    # 3b. Exact MAX_UINT64 quota string ("18446744073709551615") -> ADMIT (kills L702 > -> >=)
    gp_u64 = copy.deepcopy(fx0["bundle"]["grants"][0]["payload"])
    gp_u64["capabilities"][0]["quotas"] = [{"kind": "count", "max": str(sl.MAX_UINT64), "resource": "mail/read", "unit": "calls", "window": "term"}]
    g_u64 = sl.sign_envelope(gp_u64, [fx0["_keys"]["alice_gr"]["sk"]])
    add("bnd-quota-exact-max-uint64-admit", ["SL-WIRE-004"], "raw_wire",
        {"object": g_u64}, "ADMIT", None,
        "Quota max equal to exact MAX_UINT64 (2^64-1) MUST be admitted.")

    # 3c. Chain observation & rebracket exact boundaries (L768, L782, L786, L791, L806)
    ch_lag_eq = copy.deepcopy(fx0["chain"])
    ch_lag_eq["best_header_height"] = ch_lag_eq["tip_height"] + 1
    ch_lag_eq["lag_limit"] = 1
    add("bnd-chain-obs-lag-eq-limit-admit", ["SL-LDGR-008"], "chain_obs",
        {"chain": ch_lag_eq, "risk_class": 1}, "ADMIT", None,
        "best_header_height - tip_height == lag_limit MUST admit.")

    ch_wm_eq = copy.deepcopy(fx0["chain"])
    ch_wm_eq["clock_watermark"] = ch_wm_eq["now"]
    add("bnd-chain-obs-now-eq-watermark-admit", ["SL-LDGR-008"], "chain_obs",
        {"chain": ch_wm_eq, "risk_class": 1}, "ADMIT", None,
        "now == clock_watermark MUST admit (only now < watermark refuses CHAIN_CLOCK_ERROR).")

    ch_fut_eq = copy.deepcopy(fx0["chain"])
    ch_fut_eq["tip_header_time"] = ch_fut_eq["now"] + 600
    ch_fut_eq["tip_first_sight"] = ch_fut_eq["now"]
    ch_fut_eq["future_bound_s"] = 600
    add("bnd-chain-obs-header-eq-future-bound-admit", ["SL-LDGR-008"], "chain_obs",
        {"chain": ch_fut_eq, "risk_class": 1}, "ADMIT", None,
        "tip_header_time - now == future_bound_s (600s) MUST admit.")

    for rc, cut in [(1, 3600), (2, 5400)]:
        ch_age_ok = copy.deepcopy(fx0["chain"])
        ch_age_ok["tip_header_time"] = ch_age_ok["now"] - cut
        ch_age_ok["tip_first_sight"] = ch_age_ok["now"] - cut
        add(f"bnd-chain-obs-rc{rc}-tip-age-exact-{cut}-admit", ["SL-LDGR-008"], "chain_obs",
            {"chain": ch_age_ok, "risk_class": rc}, "ADMIT", None,
            f"Risk Class {rc} tip_age == {cut}s MUST admit.")
        ch_age_bad = copy.deepcopy(ch_age_ok)
        ch_age_bad["tip_header_time"] = ch_age_bad["now"] - (cut + 1)
        ch_age_bad["tip_first_sight"] = ch_age_bad["now"] - (cut + 1)
        add(f"bnd-chain-obs-rc{rc}-tip-age-{cut+1}-refuse", ["SL-LDGR-008"], "chain_obs",
            {"chain": ch_age_bad, "risk_class": rc}, "REFUSE", "CHAIN_TIP_STALE",
            f"Risk Class {rc} tip_age == {cut+1}s MUST refuse CHAIN_TIP_STALE.")
        ch_rb_ok = copy.deepcopy(fx0["chain"])
        ch_rb_ok["rebracket_tip"] = {"hash": ch_rb_ok["tip_hash"], "header_time": ch_rb_ok["now"] - cut, "first_sight": ch_rb_ok["now"] - cut, "height": ch_rb_ok["tip_height"], "now": ch_rb_ok["now"]}
        add(f"bnd-rebracket-rc{rc}-tip-age-exact-{cut}-admit", ["SL-LDGR-008"], "chain_obs",
            {"chain": ch_rb_ok, "rebracket": True, "risk_class": rc}, "ADMIT", None,
            f"Rebracket Risk Class {rc} tip_age == {cut}s MUST admit.")

    # 3d. Seal confirmation depth exact boundary (L906 depth == required_depth)
    s_pol_b = {"kind": "key", "pk": _kp("bnd-seal-k")["comp"]}
    s_tx_b = _h32("bnd-seal-tx")
    ch_sd = copy.deepcopy(fx0["chain"])
    ch_sd["txs"][s_tx_b] = {"confirmed_height": ch_sd["tip_height"] - 2, "outputs": {"0": {"script_pubkey_hex": _spk_hex(s_pol_b)}}}
    add("bnd-seal-depth-exact-required-admit", ["SL-LDGR-010"], "seal",
        {"seal": {"script_policy": s_pol_b, "txid": s_tx_b, "vout": 0}, "required_depth": 3, "chain": ch_sd},
        "ADMIT", None, "Seal at exact confirmation depth == required_depth (3) MUST admit.")

    # 3e. Name history exact max_history_steps & exact at_height == update height & exact recent_block_height (L1041, L1065, L1150)
    add("bnd-name-history-exact-max-steps-admit", ["SL-LDGR-006"], "name_resolve",
        {"name": "id/alice", "max_history_steps": 2, "chain": fx0["chain"]},
        "ADMIT", None, "Name history with len(updates) == max_history_steps MUST admit.")
    alice_u1_h = fx0["chain"]["names"]["id/alice"]["updates"][-1]["confirmed_height"]
    add("bnd-name-resolve-exact-at-height-admit", ["SL-LDGR-006"], "name_resolve",
        {"name": "id/alice", "at_height": alice_u1_h, "chain": fx0["chain"]},
        "ADMIT", None, "Historical resolve_name at exact at_height == update.confirmed_height MUST admit.")
    add("bnd-role-policy-exact-recent-block-height-admit", ["SL-IDEN-003"], "name_resolve",
        {"name": "id/alice", "check_role": "grant", "presented_role_policy": {"m": 1, "pks": [fx0["_keys"]["alice_gr"]["xonly"]]},
         "recent_block_height": alice_u1_h, "chain": fx0["chain"]},
        "ADMIT", None, "resolve_role_policy at exact recent_block_height == update.confirmed_height MUST admit.")

    # 3f. 0x0b break exact h_c == inclusion_height, anchor_height == min_hc, multi-break min(h_c) (L1194, L1206, L1208)
    cb_own, cb_a = _kp("bnd-0b-own"), _kp("bnd-0b-a")
    cb_pol = {"kind": "key", "pk": cb_own["comp"]}
    cb_reg = {"txid": _h32("bnd-0b-reg"), "vout": 0}
    cb_hist = sv.make_name_history("id/bnd-0b", cb_reg, cb_pol, {"link": {"cred": cb_a["xonly"]}}, first_height=748000, update_height=748500)
    prev_0b = cb_hist["updates"][-1]
    pol_a_0b = {"m": 1, "pks": [cb_a["xonly"]]}
    iss_pin_0b = {"name": "id/bnd-0b", "owner_policy": cb_pol, "registration": cb_reg, "role_policy": pol_a_0b}
    # First 0x0b break: h_c == inclusion_height == 749600 (exact boundary L1194!)
    brk1 = {"compromised_policy": pol_a_0b, "genesis": GENESIS_MAIN, "h_c": 749600, "issuer": {"name": "id/bnd-0b", "owner_policy": cb_pol, "registration": cb_reg}, "name_input": {"txid": prev_0b["txid"], "vout": prev_0b["vout"]}, "role": "cred", "type": "seallink-credential-break/1"}
    u_brk1_tx = _h32("bnd-0b-u1")
    cb_hist["updates"].append({
        "confirmed_height": 749600, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk1).hex(), h_c=749600).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(cb_pol)[0], name=b"id/bnd-0b", value=sl.jcs_encode({"link": {"cred": cb_a["xonly"]}})).hex(),
        "owner_policy": cb_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": prev_0b["txid"], "vout": prev_0b["vout"], "witness_policy": cb_pol},
        "txid": u_brk1_tx, "vout": 0,
    })
    # Second 0x0b break with LOWER h_c = 749500 (narrows min_hc! Kills L1206!)
    brk2 = {**brk1, "h_c": 749500, "name_input": {"txid": u_brk1_tx, "vout": 0}}
    u_brk2_tx = _h32("bnd-0b-u2")
    cb_hist["updates"].append({
        "confirmed_height": 749650, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk2).hex(), h_c=749500).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(cb_pol)[0], name=b"id/bnd-0b", value=sl.jcs_encode({"link": {"cred": cb_a["xonly"]}})).hex(),
        "owner_policy": cb_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": u_brk1_tx, "vout": 0, "witness_policy": cb_pol},
        "txid": u_brk2_tx, "vout": 0,
    })
    ch_0b = copy.deepcopy(fx0["chain"])
    ch_0b["names"]["id/bnd-0b"] = cb_hist
    env_0b = sl.sign_envelope({"claims": {"ok": True}, "credential_kind": "test/bnd", "genesis": GENESIS_MAIN, "issued_at": 1795220000, "issuer": iss_pin_0b, "lifecycle": "eternal", "network": "main", "not_before_height": 749000, "subject": {"key": _kp("bnd-0b-s")["xonly"], "mode": "key"}, "type": "seallink-credential/1"}, [cb_a["sk"]])
    add("bnd-0b-hc-eq-inclusion-and-anchor-eq-min-hc-refuse", ["SL-CONT-009"], "issuer_role",
        {"issuer_pin": iss_pin_0b, "envelope": env_0b, "role": "cred", "anchor_height": 749500, "chain": ch_0b},
        "REFUSE", "CRED_ISSUER_CLOSED",
        "0x0b break with h_c <= inclusion_height narrows to min(h_c) and refuses CRED_ISSUER_CLOSED at exact anchor_height == min_hc.")
    # Also test single break with exact h_c == inclusion_height (749600) & anchor_height == 749600 (kills L1194 > -> >= directly!)
    ch_0b_eq = copy.deepcopy(fx0["chain"])
    ch_0b_eq["names"]["id/bnd-0b"] = {"registration": cb_reg, "updates": cb_hist["updates"][:-1]}
    add("bnd-0b-single-hc-eq-inclusion-refuse", ["SL-CONT-009"], "issuer_role",
        {"issuer_pin": iss_pin_0b, "envelope": env_0b, "role": "cred", "anchor_height": 749600, "chain": ch_0b_eq},
        "REFUSE", "CRED_ISSUER_CLOSED",
        "Single 0x0b break with exact h_c == inclusion_height MUST take effect and refuse CRED_ISSUER_CLOSED at anchor_height == h_c.")

    # 3g. Manifest head exact seq == prev["seq"] with SAME sha256 -> ADMIT (kills L1274 < -> <=)
    alice_man_ca = sl.content_addr(fx0["_alice_man"])
    add("bnd-manifest-seq-eq-prev-same-sha-admit", ["SL-IDEN-006"], "name_resolve",
        {"name": "id/alice", "check_manifest": True, "manifests": {alice_man_ca: fx0["_alice_man"]},
         "journal": {"journal_id": _h32("bnd-mh-j"), "manifest_heads": [{"name": "id/alice", "reg_key": f"{fx0['_alice_reg']['txid']}:0", "seq": fx0["_alice_man"]["seq"], "sha256": alice_man_ca}]},
         "chain": fx0["chain"]},
        "ADMIT", None, "Observing identical manifest (seq == prev.seq and sha256 == prev.sha256) MUST admit.")

    # 3h. AuthChallenge exact boundaries (L1290: ttl == 120 ADMIT, exp == iat REFUSE, now == exp REFUSE) + L1318 or->and
    ac_k = _kp("bnd-ac-k")
    ac_ttl120 = sl.sign_envelope({"auth_pubkey": ac_k["xonly"], "expires_at": 1795220120, "issued_at": 1795220000, "nonce": _h32("bnd-ac-120"), "service_id": "svc.example", "type": "seallink-auth-challenge/1"}, [ac_k["sk"]])
    ch_ac120 = copy.deepcopy(fx0["chain"])
    ch_ac120["now"] = 1795220050
    add("bnd-auth-challenge-ttl-exact-120-admit", ["SL-IDEN-010"], "auth_challenge",
        {"challenge": ac_ttl120, "service_id": "svc.example", "journal": {"journal_id": _h32("bnd-acj1"), "auth_nonces": {_h32("bnd-ac-120"): {"service_id": "svc.example", "used": False}}}, "chain": ch_ac120},
        "ADMIT", None, "AuthChallenge with exact 120s TTL MUST admit.")
    ac_eq_iat = sl.sign_envelope({"auth_pubkey": ac_k["xonly"], "expires_at": 1795220060, "issued_at": 1795220060, "nonce": _h32("bnd-ac-eqiat"), "service_id": "svc.example", "type": "seallink-auth-challenge/1"}, [ac_k["sk"]])
    add("bnd-auth-challenge-exp-eq-iat-refuse", ["SL-IDEN-010"], "auth_challenge",
        {"challenge": ac_eq_iat, "service_id": "svc.example", "journal": {"journal_id": _h32("bnd-acj2"), "auth_nonces": {_h32("bnd-ac-eqiat"): {"service_id": "svc.example", "used": False}}}, "chain": ch_ac120},
        "REFUSE", "AUTH_CHALLENGE_EXPIRED", "AuthChallenge with expires_at == issued_at MUST refuse AUTH_CHALLENGE_EXPIRED.")
    ch_ac_exp = copy.deepcopy(fx0["chain"])
    ch_ac_exp["now"] = 1795220120
    add("bnd-auth-challenge-now-eq-exp-refuse", ["SL-IDEN-010"], "auth_challenge",
        {"challenge": ac_ttl120, "service_id": "svc.example", "journal": {"journal_id": _h32("bnd-acj3"), "auth_nonces": {_h32("bnd-ac-120"): {"service_id": "svc.example", "used": False}}}, "chain": ch_ac_exp},
        "REFUSE", "AUTH_CHALLENGE_EXPIRED", "AuthChallenge at exact now == expires_at MUST refuse AUTH_CHALLENGE_EXPIRED.")
    # L1318 compound `or`: named auth challenge with valid auth_seal present in manifest, ONLY auth_key mismatched!
    ac_seal_pol = {"kind": "key", "pk": _kp("bnd-ac-seal")["comp"]}
    ac_seal_tx = _h32("bnd-ac-seal-tx")
    man_ac_wrong = copy.deepcopy(fx0["_alice_man"])
    man_ac_wrong["auth_key"] = _kp("bnd-other-auth")["xonly"]
    man_ac_wrong["auth_seal"] = {"script_policy": ac_seal_pol, "txid": ac_seal_tx, "vout": 0}
    ch_ac_named = copy.deepcopy(ch_ac120)
    ch_ac_named["txs"][ac_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(ac_seal_pol)}}}
    ch_ac_named["names"]["id/alice"] = sv.make_name_history("id/alice", fx0["_alice_reg"], fx0["_alice_owner_pol"], {"link": {"grant": fx0["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(man_ac_wrong), "s": 1}}, first_height=748000, update_height=749000)
    ac_named = sl.sign_envelope({"auth_pubkey": ac_k["xonly"], "expires_at": 1795220120, "issued_at": 1795220000, "name": "id/alice", "nonce": _h32("bnd-ac-named"), "service_id": "svc.example", "type": "seallink-auth-challenge/1"}, [ac_k["sk"]])
    add("bnd-auth-named-wrong-key-with-valid-seal-refuse", ["SL-IDEN-010"], "auth_challenge",
        {"challenge": ac_named, "service_id": "svc.example", "manifests": {sl.content_addr(man_ac_wrong): man_ac_wrong},
         "journal": {"journal_id": _h32("bnd-acj4"), "auth_nonces": {_h32("bnd-ac-named"): {"service_id": "svc.example", "used": False}}}, "chain": ch_ac_named},
        "REFUSE", "AUTH_KEY_UNPINNED", "Named auth challenge with valid auth_seal present but mismatched auth_key MUST refuse AUTH_KEY_UNPINNED.")

    # 3i. OwnerCommand exact iat == now (ADMIT) and exp == now (REFUSE) (kills L1344 both shifts!)
    oc_dev = _kp("bnd-oc-dev")
    oc_seal_pol = {"kind": "key", "pk": _kp("bnd-oc-seal")["comp"]}
    oc_seal_tx = _h32("bnd-oc-seal-tx")
    ch_oc_b = copy.deepcopy(fx0["chain"])
    ch_oc_b["txs"][oc_seal_tx] = {"confirmed_height": 749990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(oc_seal_pol)}}}
    dlist_b = {"devices": [{"alg": "bip340", "ceiling": 1, "key": oc_dev["xonly"], "label": "d1", "presence": False, "seal": {"script_policy": oc_seal_pol, "txid": oc_seal_tx, "vout": 0}}], "network": "main", "owner": "id/alice", "seq": 1, "type": "seallink-device-list/1"}
    oc_now_iat = sl.sign_envelope({"arguments": {"brief_sha256": _h32("b"), "run_id": "r1"}, "command": "agent-dispatch", "exp": ch_oc_b["now"] + 60, "genesis": GENESIS_MAIN, "iat": ch_oc_b["now"], "level": 1, "network": "main", "nonce": _h32("bnd-oc-iat"), "owner": "id/alice", "target_executor": "id/st", "type": "seallink-owner-command/1"}, [oc_dev["sk"]])
    add("bnd-owner-cmd-now-eq-iat-admit", ["SL-IDEN-011"], "owner_command",
        {"command": oc_now_iat, "device_list": dlist_b, "is_foreign_service": False, "chain": ch_oc_b}, "ADMIT", None,
        "Owner command at exact now == iat MUST admit.")
    oc_now_exp = sl.sign_envelope({"arguments": {"brief_sha256": _h32("b"), "run_id": "r2"}, "command": "agent-dispatch", "exp": ch_oc_b["now"], "genesis": GENESIS_MAIN, "iat": ch_oc_b["now"] - 60, "level": 1, "network": "main", "nonce": _h32("bnd-oc-exp"), "owner": "id/alice", "target_executor": "id/st", "type": "seallink-owner-command/1"}, [oc_dev["sk"]])
    add("bnd-owner-cmd-now-eq-exp-refuse", ["SL-IDEN-011"], "owner_command",
        {"command": oc_now_exp, "device_list": dlist_b, "is_foreign_service": False, "chain": ch_oc_b}, "REFUSE", "INVOKE_TIME_INVALID",
        "Owner command at exact now == exp MUST refuse INVOKE_TIME_INVALID.")

    # 3j. Assent exact TTL == 259200 (72h ADMIT), expires_at == issued_at (REFUSE), now == expires_at (REFUSE) (kills all 3 shifts on L2123!)
    p1k, p2k = _kp("bnd-cp1"), _kp("bnd-cp2")
    c_bnd = {
        "clause_commitments": [sl.clause_commit(_h32("bc0"), {"t": "ok"})],
        "contract_salt": _h32("bcsalt"), "genesis": GENESIS_MAIN, "network": "main",
        "parties": [{"party_id": "p1", "role": "buyer", "signing_policy": {"m": 1, "pks": [p1k["xonly"]]}}, {"party_id": "p2", "role": "seller", "signing_policy": {"m": 1, "pks": [p2k["xonly"]]}}],
        "profile": "test-v1", "type": "seallink-contract/1", "window": {"not_after_height": 760000, "not_before_height": 749000},
    }
    cid_bnd = sl.object_id(c_bnd)
    now_a = fx0["chain"]["now"]
    a_72h = sl.sign_envelope({"expires_at": now_a + 259200, "genesis": GENESIS_MAIN, "issued_at": now_a, "network": "main", "nonce": _h32("ba-72h"), "party_id": "p1", "party_role": "buyer", "target_id": cid_bnd, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [p1k["sk"]])
    add("bnd-assent-exact-72h-ttl-admit", ["SL-CONT-004"], "assent",
        {"assent": a_72h, "contract": c_bnd, "origin_bundle": None, "chain": fx0["chain"]}, "ADMIT", None,
        "Assent with exact 72h (259200s) TTL MUST admit.")
    a_eq_iat = sl.sign_envelope({"expires_at": now_a + 100, "genesis": GENESIS_MAIN, "issued_at": now_a + 100, "network": "main", "nonce": _h32("ba-eqi"), "party_id": "p1", "party_role": "buyer", "target_id": cid_bnd, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [p1k["sk"]])
    add("bnd-assent-exp-eq-iat-refuse", ["SL-CONT-004"], "assent",
        {"assent": a_eq_iat, "contract": c_bnd, "origin_bundle": None, "chain": fx0["chain"]}, "REFUSE", "CONTRACT_ASSENT_INVALID",
        "Assent with expires_at == issued_at MUST refuse CONTRACT_ASSENT_INVALID.")
    a_now_exp = sl.sign_envelope({"expires_at": now_a, "genesis": GENESIS_MAIN, "issued_at": now_a - 100, "network": "main", "nonce": _h32("ba-nexp"), "party_id": "p1", "party_role": "buyer", "target_id": cid_bnd, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [p1k["sk"]])
    add("bnd-assent-now-eq-exp-refuse", ["SL-CONT-004"], "assent",
        {"assent": a_now_exp, "contract": c_bnd, "origin_bundle": None, "chain": fx0["chain"]}, "REFUSE", "CONTRACT_ASSENT_INVALID",
        "Assent at exact now == expires_at MUST refuse CONTRACT_ASSENT_INVALID.")

    # 3k. Origin, Majority UTC interval (L1676, L1678), Recovery deadline (L1593, L1604), Incoming guardian assent exp==iat (L1396),
    #     Guardian calendar term exact boundaries (L2059), Pending CSV exact delay (L1871), Roster exact effective_delay (L1957)!
    of_maj = rm._base_origin_fixture()
    maj_u = of_maj["origin_bundle"]["opened_majority_unix"]
    # t_low < maj_u == t_high -> GUARDIAN_TIME_BOUNDARY (kills L1676 <= -> <!)
    of_maj_hi = copy.deepcopy(of_maj)
    of_maj_hi["chain"]["credible_utc_interval"] = [maj_u - 10, maj_u]
    add("bnd-majority-interval-t-high-eq-T-refuse", ["SL-ORIG-010"], "origin_status",
        {"origin_bundle": of_maj_hi["origin_bundle"], "chain": of_maj_hi["chain"], "trusted_origin_issuers": of_maj_hi["trusted_origin_issuers"]},
        "REFUSE", "GUARDIAN_TIME_BOUNDARY", "Credible UTC interval with t_high == T MUST refuse GUARDIAN_TIME_BOUNDARY.")
    # t_low == maj_u (with handover!) -> ADMIT_AUTONOMOUS (kills L1676 < -> <= AND L1678 >= -> >!)
    of_maj_eq = copy.deepcopy(of_maj)
    of_maj_eq["chain"]["credible_utc_interval"] = [maj_u, maj_u + 10]
    leo_u = of_maj_eq["chain"]["names"]["id/child-leo"]["updates"]
    prev_l = leo_u[-1]
    ad_pol = {"kind": "key", "pk": _kp("bnd-leo-ad")["comp"]}
    ad_spk, _ = sl.compile_script_policy(ad_pol)
    l_val = sl.jcs_encode({"link": {"grant": of_maj["_keys"]["ward_gr"]["xonly"], "origin": of_maj["_origin_id"]}})
    leo_u.append({"confirmed_height": 749900, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", ad_spk, name=b"id/child-leo", value=l_val).hex(), "owner_policy": ad_pol, "prev_input": {"sighash_bytes": [0x01], "txid": prev_l["txid"], "vout": prev_l["vout"], "witness_policy": prev_l["owner_policy"]}, "txid": _h32("bnd-leo-ho1"), "vout": 0})
    leo_u.append({"confirmed_height": 749910, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", ad_spk, name=b"id/child-leo", value=l_val).hex(), "owner_policy": ad_pol, "prev_input": {"sighash_bytes": [0x01], "txid": _h32("bnd-leo-ho1"), "vout": 0, "witness_policy": ad_pol}, "txid": _h32("bnd-leo-ho2"), "vout": 0})
    add("bnd-majority-interval-t-low-eq-T-autonomous", ["SL-ORIG-010", "SL-ORIG-011"], "origin_status",
        {"origin_bundle": of_maj_eq["origin_bundle"], "chain": of_maj_eq["chain"], "trusted_origin_issuers": of_maj_eq["trusted_origin_issuers"]},
        "ADMIT_AUTONOMOUS", None, "Credible UTC interval with t_low == T after handover MUST admit autonomous capacity.")

    # Recovery deadline exact boundary: cancel at confirmed_height == deadline fails cancel -> tip == deadline promotes B_2 (kills L1593 & L1604!)
    of_rec = rm._base_origin_fixture()
    rec_pol = of_rec["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["script_policy"]
    rec_tx_id = of_rec["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"]
    cand_b2 = {
        "genesis": GENESIS_MAIN, "name": "id/child-leo-rec2", "network": "main",
        "next_recovery_policy": rec_pol, "next_recovery_vout": 0, "origin_id": of_rec["_origin_id"],
        "owner_policy": of_rec["origin_bundle"]["name_binding"]["owner_policy"],
        "registration": {"txid": _h32("bnd-rec2-reg"), "vout": 0}, "seq": 2,
        "supersedes_binding_id": sl.object_id(of_rec["origin_bundle"]["name_binding"]), "type": "seallink-name-binding/1",
    }
    cand_b2_id = sl.object_id(cand_b2)
    rspend_tx = _h32("bnd-rspend")
    h_rec_start = 749800
    delay_r = of_rec["origin_bundle"]["origin"]["payload"]["name_recovery"]["delay_blocks"]  # 144
    deadline_r = h_rec_start + delay_r
    of_rec["chain"]["txs"][rec_tx_id]["outputs"]["0"]["spent_by_txid"] = rspend_tx
    of_rec["chain"]["txs"][rspend_tx] = {"confirmed_height": h_rec_start, "opreturn_hex": sl.encode_opreturn(0x0C, cand_b2_id).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_pol)}}}
    # Put 0x10 cancel at EXACT deadline_r (NOT < deadline_r -> MUST NOT cancel!) and set tip_height == deadline_r!
    leo_u_r = of_rec["chain"]["names"]["id/child-leo"]["updates"]
    prev_lr = leo_u_r[-1]
    leo_u_r.append({
        "confirmed_height": deadline_r, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, cand_b2_id).hex(),
        "output_script_hex": prev_lr["output_script_hex"], "owner_policy": prev_lr["owner_policy"],
        "prev_input": {"sighash_bytes": [0x01], "txid": prev_lr["txid"], "vout": prev_lr["vout"], "witness_policy": prev_lr["owner_policy"]},
        "txid": _h32("bnd-late-0x10"), "vout": 0,
    })
    of_rec["chain"]["tip_height"] = deadline_r
    of_rec["chain"]["best_header_height"] = deadline_r
    of_rec["chain"]["comparison_peers"][0]["height"] = deadline_r
    of_rec["origin_bundle"]["recovery_bindings"] = [cand_b2]
    # Assert B_2 IS promoted (would refuse RECOVERY_FORBIDDEN if L1593 cancelled at == deadline OR if L1604 rejected tip == deadline!)
    add("bnd-recovery-cancel-at-exact-deadline-not-cancelled-and-tip-eq-deadline-promotes", ["SL-ORIG-013"], "origin_status",
        {"origin_bundle": of_rec["origin_bundle"], "chain": of_rec["chain"], "trusted_origin_issuers": of_rec["trusted_origin_issuers"], "assert_binding_id": cand_b2_id},
        "ADMIT_WARD", None, "0x10 cancel at exact height == deadline is too late, and tip_height == deadline promotes successor binding B_2.")

    # Guardian incoming assent expires_at == issued_at -> slot fails (kills L1396 <= -> <!)
    of_ga_eq = rm._base_origin_fixture()
    op_1of2_b = copy.deepcopy(of_ga_eq["origin_bundle"]["origin"]["payload"])
    op_1of2_b["guardian_policy"]["quorums"]["contract_assent"] = {"den": 2, "min": 1, "num": 1}
    o_1of2_b = sl.sign_envelope(op_1of2_b, [of_ga_eq["_keys"]["reg_cred"]["sk"]])
    oid_1of2_b = sl.object_id(op_1of2_b)
    of_ga_eq["origin_bundle"]["origin"] = o_1of2_b
    of_ga_eq["origin_bundle"]["name_binding"]["origin_id"] = oid_1of2_b
    grec_1p_b = {**of_ga_eq["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_1of2_b}
    grec_1_b = sl.sign_envelope(grec_1p_b, [of_ga_eq["_keys"]["reg_cred"]["sk"]])
    of_ga_eq["origin_bundle"]["guardian_records"] = [grec_1_b]
    bad_ga = sl.sign_envelope({**of_ga_eq["origin_bundle"]["guardian_assents"][0]["payload"], "expires_at": 1795220000, "issued_at": 1795220000, "target_id": sl.object_id(grec_1p_b)}, [of_ga_eq["_keys"]["g1_gr"]["sk"]])
    of_ga_eq["origin_bundle"]["guardian_assents"] = [bad_ga]
    of_ga_eq["chain"]["txs"][of_ga_eq["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_1of2_b)).hex()
    of_ga_eq["chain"]["txs"][of_ga_eq["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_ga_eq["origin_bundle"]["name_binding"])).hex()
    of_ga_eq["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(grec_1_b)).hex()
    c_1of2_b = copy.deepcopy(of_ga_eq["contract"])
    c_1of2_b["parties"][0]["ward_origin_id"] = oid_1of2_b
    wa_1of2_b = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": oid_1of2_b, "revision": 1, "ward_name": "id/child-leo"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("bnd-wa-gaeq"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
         "target_id": sl.object_id(c_1of2_b), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [of_ga_eq["_keys"]["g1_gr"]["sk"]]}],
    )
    add("bnd-guardian-incoming-assent-exp-eq-iat-refuse", ["SL-ORIG-007"], "assent",
        {"assent": wa_1of2_b, "contract": c_1of2_b, "origin_bundle": of_ga_eq["origin_bundle"], "chain": of_ga_eq["chain"], "trusted_origin_issuers": of_ga_eq["trusted_origin_issuers"]},
        "REFUSE", "GUARDIAN_INACTIVE", "Incoming guardian assent with expires_at == issued_at MUST prevent slot activation.")

    # Guardian calendar term exact boundaries (L2059: tip == ceiling_height AND now == not_after_unix!)
    for tag_t, ceil_h, na_u in [("ceil", 750000, 1795900000), ("unix", 760000, 1795220010)]:
        of_cal = copy.deepcopy(of_ga_eq)
        grec_cal_p = {**grec_1p_b, "term": {"ceiling_height": ceil_h, "mode": "calendar", "not_after_unix": na_u}}
        grec_cal = sl.sign_envelope(grec_cal_p, [of_ga_eq["_keys"]["reg_cred"]["sk"]])
        of_cal["origin_bundle"]["guardian_records"] = [grec_cal]
        of_cal["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**of_ga_eq["origin_bundle"]["guardian_assents"][0]["payload"], "expires_at": 1795400000, "issued_at": 1795220000, "target_id": sl.object_id(grec_cal_p)}, [of_ga_eq["_keys"]["g1_gr"]["sk"]])]
        of_cal["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(grec_cal)).hex()
        of_cal["chain"]["tip_height"] = 750000
        of_cal["chain"]["best_header_height"] = 750000
        of_cal["chain"]["comparison_peers"][0]["height"] = 750000
        of_cal["chain"]["now"] = 1795220010
        of_cal["chain"]["tip_header_time"] = 1795220000
        of_cal["chain"]["tip_first_sight"] = 1795220000
        add(f"bnd-guardian-calendar-term-exact-{tag_t}-refuse", ["SL-ORIG-005"], "assent",
            {"assent": wa_1of2_b, "contract": c_1of2_b, "origin_bundle": of_cal["origin_bundle"], "chain": of_cal["chain"], "trusted_origin_issuers": of_cal["trusted_origin_issuers"]},
            "REFUSE", "GUARDIAN_INACTIVE", f"Calendar guardian term at exact {tag_t} boundary MUST refuse GUARDIAN_INACTIVE.")

    # Pending CSV exact delay_blocks (L1920) & Roster exact effective_delay_blocks (L2006)!
    of_pr = rm._base_origin_fixture()
    tip_pr = of_pr["chain"]["tip_height"]  # 750010
    gp_orig_pr = of_pr["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    vac_pol_pr = gp_orig_pr["roster_seal"]["script_policy"]
    delay_pr = gp_orig_pr["appointment_delay_blocks"]  # 144
    g1_pin_pr = of_pr["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]
    pend_pol_pr = {"delay_blocks": delay_pr, "keys": {"challenger": gp_orig_pr["challenger_pk"], "disposer": gp_orig_pr["disposer_pk"], "guardian": _kp("bnd-pr-g")["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
    act_pol_pr = {"keys": {"a": gp_orig_pr["disposer_pk"], "b": _kp("bnd-pr-g")["comp"]}, "kind": "branch", "template": "either_of_2"}
    quorums_1 = {k: {"den": 1, "min": 1, "num": 1} for k in gp_orig_pr["quorums"]}
    rost_p_pr = {
        "arbiter_pk": gp_orig_pr["arbiter_pk"], "challenger_pk": gp_orig_pr["challenger_pk"], "disposer_pk": gp_orig_pr["disposer_pk"],
        "effective_delay_blocks": 10, "genesis": GENESIS_MAIN, "issuer": of_pr["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main", "next_roster_policy": vac_pol_pr, "next_roster_vout": 0, "origin_id": of_pr["_origin_id"],
        "prev_revision": 1, "prev_roster_outpoint": {"txid": gp_orig_pr["roster_seal"]["txid"], "vout": 0},
        "quorums": quorums_1,
        "revision": 2, "revision_size": 1,
        "slots": [{"action": "new_vacant", "new_vacant_policy": vac_pol_pr, "new_vacant_vout": 1, "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    rost_pr = sl.sign_envelope(rost_p_pr, [of_pr["_keys"]["reg_cred"]["sk"]])
    rtx_pr = _h32("bnd-pr-rtx")
    dtx_pr = _h32("bnd-pr-dtx")
    etx_pr = _h32("bnd-pr-etx")
    g2_pr_p = {
        "activation_mode": "appointed", "active_policy": act_pol_pr, "effective_delay_blocks": delay_pr,
        "genesis": GENESIS_MAIN, "guardian": g1_pin_pr, "issuer": of_pr["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main", "origin_id": of_pr["_origin_id"], "pending_policy": pend_pol_pr, "pending_vout": 0,
        "prev_outpoint": {"txid": rtx_pr, "vout": 1}, "revision": 2, "slot": 1, "term": {"mode": "indefinite"}, "type": "seallink-guardian/1",
    }
    g2_pr = sl.sign_envelope(g2_pr_p, [of_pr["_keys"]["reg_cred"]["sk"]])
    g2_ass_pr = sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("bnd-pr-ga"), "party_id": "g-pr", "party_name": "id/parent-a", "party_role": "guardian", "target_id": sl.object_id(g2_pr_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"}, [of_pr["_keys"]["g1_gr"]["sk"]])
    of_pr["chain"]["txs"][gp_orig_pr["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_pr
    of_pr["chain"]["txs"][rtx_pr] = {"confirmed_height": tip_pr - 200, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_pr)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pol_pr)}, "1": {"script_pubkey_hex": _spk_hex(vac_pol_pr), "spent_by_txid": dtx_pr}}}
    of_pr["chain"]["txs"][dtx_pr] = {"confirmed_height": tip_pr - delay_pr, "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g2_pr)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_pol_pr), "spent_by_txid": etx_pr}}}
    of_pr["chain"]["txs"][etx_pr] = {"confirmed_height": tip_pr, "opreturn_hex": sl.encode_opreturn(0x0E, sl.object_id(g2_pr_p)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_pol_pr)}}}
    of_pr["origin_bundle"]["roster_records"] = [rost_pr]
    of_pr["origin_bundle"]["guardian_records"].append(g2_pr)
    of_pr["origin_bundle"]["guardian_assents"].append(g2_ass_pr)
    wa_pr = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": of_pr["_origin_id"], "revision": 2, "ward_name": "id/child-leo"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("bnd-pr-wa"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
         "target_id": sl.object_id(of_pr["contract"]), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"slot": 1, "revision": 2, "guardian_name": "id/parent-a", "signers": [of_pr["_keys"]["g1_gr"]["sk"]]}],
    )
    add("bnd-guardian-pending-exact-csv-delay-admit", ["SL-ORIG-008"], "assent",
        {"assent": wa_pr, "contract": of_pr["contract"], "origin_bundle": of_pr["origin_bundle"], "chain": of_pr["chain"], "trusted_origin_issuers": of_pr["trusted_origin_issuers"]},
        "ADMIT", None, "Stage-2 0x0e activation at exact confirmed_height == pending_height + delay_blocks MUST activate guardian.")

    # Exact roster effective_delay_blocks (rtx at tip - 10, delay=10, tip == rtx + delay, retain_active slot 1 -> rev 2 active at exact tip == rtx + delay!)
    of_re = rm._base_origin_fixture()
    tip_re = of_re["chain"]["tip_height"]  # 750010
    gp_re = of_re["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    g1_id_re = sl.object_id(of_re["origin_bundle"]["guardian_records"][0]["payload"])
    rost_re_p = {
        **rost_p_pr,
        "origin_id": of_re["_origin_id"],
        "prev_roster_outpoint": {"txid": gp_re["roster_seal"]["txid"], "vout": 0},
        "slots": [{"action": "retain_active", "active_outpoint": {"txid": rm._h32("og1-init-0x12"), "vout": 0}, "guardian_id": g1_id_re, "slot": 1}],
    }
    rost_re = sl.sign_envelope(rost_re_p, [of_re["_keys"]["reg_cred"]["sk"]])
    rtx_re = _h32("bnd-re-rtx")
    of_re["chain"]["txs"][gp_re["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_re
    of_re["chain"]["txs"][rtx_re] = {"confirmed_height": tip_re - 10, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_re)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(gp_re["roster_seal"]["script_policy"])}}}
    of_re["origin_bundle"]["roster_records"] = [rost_re]
    wa_re = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": of_re["_origin_id"], "revision": 2, "ward_name": "id/child-leo"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("bnd-re-wa"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
         "target_id": sl.object_id(of_re["contract"]), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"slot": 1, "revision": 2, "guardian_name": "id/parent-a", "signers": [of_re["_keys"]["g1_gr"]["sk"]]}],
    )
    add("bnd-roster-exact-effective-delay-admit", ["SL-ORIG-015"], "assent",
        {"assent": wa_re, "contract": of_re["contract"], "origin_bundle": of_re["origin_bundle"], "chain": of_re["chain"], "trusted_origin_issuers": of_re["trusted_origin_issuers"]},
        "ADMIT", None, "Roster transition at exact tip_height == rtx_height + effective_delay_blocks MUST activate new revision.")

    # 3l. Credential exact operator_min_depth (L2221) & exact not_before_height == tip_height (L2231)
    cr_own, cr_key, cr_subj = _kp("bnd-cr-own"), _kp("bnd-cr-key"), _kp("bnd-cr-subj")
    cr_pol = {"kind": "key", "pk": cr_own["comp"]}
    cr_reg = {"txid": _h32("bnd-cr-reg"), "vout": 0}
    tip_fx0 = fx0["chain"]["tip_height"]  # 750010
    cr_p = {
        "claims": {"v": 1}, "credential_kind": "test/bnd", "genesis": GENESIS_MAIN, "issued_at": 1795220000,
        "issuer": {"name": "id/bnd-cr", "owner_policy": cr_pol, "registration": cr_reg, "role_policy": {"m": 1, "pks": [cr_key["xonly"]]}},
        "lifecycle": "eternal", "network": "main", "not_before_height": tip_fx0,
        "subject": {"key": cr_subj["xonly"], "mode": "key"}, "type": "seallink-credential/1",
    }
    cr_env = sl.sign_envelope(cr_p, [cr_key["sk"]])
    cr_tx = _h32("bnd-cr-tx")
    ch_cr = copy.deepcopy(fx0["chain"])
    ch_cr["names"]["id/bnd-cr"] = sv.make_name_history("id/bnd-cr", cr_reg, cr_pol, {"link": {"cred": cr_key["xonly"]}}, first_height=748000, update_height=748500)
    ch_cr["txs"][cr_tx] = {"confirmed_height": tip_fx0 - 5, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_env)).hex(), "outputs": {}}
    add("bnd-cred-exact-min-depth-and-not-before-eq-tip-admit", ["SL-CONT-010"], "credential",
        {"credential": cr_env, "anchor_txid": cr_tx, "operator_min_depth": 6, "chain": ch_cr}, "ADMIT", None,
        "Credential at exact depth == operator_min_depth (6) and exact not_before_height == tip_height MUST admit.")

    # 3m. Invocation exact iat == now (ADMIT) & exp == now (REFUSE) (L2284), Grant exact not_before == tip & not_after == tip (L2601),
    #     Issuance recency R < A <= R + K exact endpoints (L2638) & exact req_depth (L2644), settle == 0 & settle == reserve (L353)!
    fx_inv_b = rm._base_invocation_fixture()
    now_i = fx_inv_b["chain"]["now"]
    inv_eq_iat = sl.sign_envelope({**fx_inv_b["invocation"]["payload"], "iat": now_i, "nonce": _h32("bi-iat")}, [fx_inv_b["_keys"]["agent_req"]["sk"]])
    add("bnd-inv-now-eq-iat-and-settle-eq-0-admit", ["SL-GRNT-004", "SL-GRNT-007"], "invocation",
        {"invocation": inv_eq_iat, "bundle": fx_inv_b["bundle"], "chain": fx_inv_b["chain"], "journal": {"journal_id": _h32("bi-j1")}, "executor_cfg": fx_inv_b["executor_cfg"],
         "actual_quota_usage": {"count|mail/read|calls|term": 0}},
        "ADMIT", None, "Invocation at exact now == iat with settle == 0 (full release) MUST admit.")
    inv_eq_exp = sl.sign_envelope({**fx_inv_b["invocation"]["payload"], "exp": now_i, "iat": now_i - 60, "nonce": _h32("bi-exp")}, [fx_inv_b["_keys"]["agent_req"]["sk"]])
    add("bnd-inv-now-eq-exp-refuse", ["SL-GRNT-007"], "invocation",
        {"invocation": inv_eq_exp, "bundle": fx_inv_b["bundle"], "chain": fx_inv_b["chain"], "journal": {"journal_id": _h32("bi-j2")}, "executor_cfg": fx_inv_b["executor_cfg"]},
        "REFUSE", "INVOKE_TIME_INVALID", "Invocation at exact now == exp MUST refuse INVOKE_TIME_INVALID.")

    # Grant exact not_before == tip_height, exact R + K (432) recency, exact depth == req_depth (3), AND contract window exact bounds (L2484, L2485, L2601, L2638, L2644)!
    fx_gb = rm._base_invocation_fixture()
    tip_gb = fx_gb["chain"]["tip_height"]  # 750010
    c_gb_seal_pol = {"kind": "key", "pk": _kp("bnd-cgb-s")["comp"]}
    c_gb_seal_tx = _h32("bnd-cgb-stx")
    c_gb = {
        "clause_commitments": [sl.clause_commit(_h32("cgb0"), {"t": "ok"})], "contract_salt": _h32("cgb-salt"),
        "genesis": GENESIS_MAIN, "network": "main",
        "parties": [{"party_id": "p1", "role": "issuer", "signing_policy": {"m": 1, "pks": [fx_gb["_keys"]["alice_gr"]["xonly"]]}},
                    {"party_id": "p2", "role": "counterparty", "signing_policy": {"m": 1, "pks": [fx_gb["_keys"]["agent_req"]["xonly"]]}}],
        "profile": "test-v1", "seal": {"script_policy": c_gb_seal_pol, "txid": c_gb_seal_tx, "vout": 0},
        "type": "seallink-contract/1", "window": {"not_after_height": 760000, "not_before_height": tip_gb},
    }
    cid_gb = sl.object_id(c_gb)
    ac_gb1 = sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("acgb1"), "party_id": "p1", "party_role": "issuer", "target_id": cid_gb, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_gb["_keys"]["alice_gr"]["sk"]])
    ac_gb2 = sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("acgb2"), "party_id": "p2", "party_role": "counterparty", "target_id": cid_gb, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_gb["_keys"]["agent_req"]["sk"]])
    gp_gb = copy.deepcopy(fx_gb["bundle"]["grants"][0]["payload"])
    r_blk_gb = _h32("bnd-rblk-432")
    gp_gb["recent_block"] = r_blk_gb
    gp_gb["not_before_height"] = tip_gb  # == tip_height AND == contract.window.not_before_height!
    gp_gb["not_after_height"] = 760000   # == contract.window.not_after_height!
    gp_gb["contract_id"] = cid_gb
    g_gb = sl.sign_envelope(gp_gb, [fx_gb["_keys"]["alice_gr"]["sk"]])
    gid_gb = sl.object_id(gp_gb)
    itx_gb = _h32("bnd-itx-gb")
    # a_height = tip_gb - 2 (depth == 3 == operator_min_depth!), r_height = a_height - 432 (exact R + K!)
    a_h_gb = tip_gb - 2
    fx_gb["chain"]["blocks"][r_blk_gb] = a_h_gb - 432
    fx_gb["chain"]["txs"][c_gb_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(c_gb_seal_pol)}}}
    fx_gb["chain"]["txs"][itx_gb] = {
        "confirmed_height": a_h_gb,
        "inputs": [sv.make_segwit_input(gp_gb["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"contract_id": cid_gb, "genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_gb), "grant_id": gid_gb, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_gb = sl.sign_envelope({**fx_gb["invocation"]["payload"], "nonce": _h32("bi-gb"), "proof_path": [{"grant_id": gid_gb, "issuance_txid": itx_gb}]}, [fx_gb["_keys"]["agent_req"]["sk"]])
    add("bnd-grant-exact-window-recency-rk-depth-admit", ["SL-GRNT-003", "SL-LDGR-008", "SL-CONT-005"], "invocation",
        {"invocation": inv_gb, "bundle": {**fx_gb["bundle"], "grants": [g_gb], "contract": c_gb, "contract_assents": [ac_gb1, ac_gb2]},
         "chain": fx_gb["chain"], "journal": {"journal_id": _h32("bi-jgb")}, "executor_cfg": fx_gb["executor_cfg"], "operator_min_depth": 3},
        "ADMIT", None,
        "Grant at exact not_before==tip, exact contract window endpoints, exact recency A==R+432, and exact issuance depth==3 MUST admit.")

    # Grant recency A == R -> MUST refuse CHAIN_RECENCY_INVALID (kills L2638 < -> <=!)
    fx_gb_r = copy.deepcopy(fx_gb)
    fx_gb_r["chain"]["blocks"][r_blk_gb] = a_h_gb  # == a_height!
    add("bnd-grant-recency-a-eq-r-refuse", ["SL-LDGR-008"], "invocation",
        {"invocation": inv_gb, "bundle": {**fx_gb["bundle"], "grants": [g_gb], "contract": c_gb, "contract_assents": [ac_gb1, ac_gb2]},
         "chain": fx_gb_r["chain"], "journal": {"journal_id": _h32("bi-jgbr")}, "executor_cfg": fx_gb["executor_cfg"]},
        "REFUSE", "CHAIN_RECENCY_INVALID", "Grant issuance at exact a_height == r_height MUST refuse CHAIN_RECENCY_INVALID.")

    # Grant exact tip_height == not_after_height -> GRANT_WINDOW_CLOSED (kills L2601 < -> <=!)
    fx_gb_na = rm._base_invocation_fixture()
    gp_na = copy.deepcopy(fx_gb_na["bundle"]["grants"][0]["payload"])
    gp_na["not_after_height"] = fx_gb_na["chain"]["tip_height"]  # == tip_height!
    g_na = sl.sign_envelope(gp_na, [fx_gb_na["_keys"]["alice_gr"]["sk"]])
    gid_na = sl.object_id(gp_na)
    itx_na = _h32("bnd-itx-na")
    fx_gb_na["chain"]["txs"][itx_na] = {
        "confirmed_height": orig_itx_h,
        "inputs": [sv.make_segwit_input(gp_na["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_na), "grant_id": gid_na, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_na = sl.sign_envelope({**fx_gb_na["invocation"]["payload"], "nonce": _h32("bi-na"), "proof_path": [{"grant_id": gid_na, "issuance_txid": itx_na}]}, [fx_gb_na["_keys"]["agent_req"]["sk"]])
    add("bnd-grant-tip-eq-not-after-refuse", ["SL-GRNT-003"], "invocation",
        {"invocation": inv_na, "bundle": {**fx_gb_na["bundle"], "grants": [g_na]}, "chain": fx_gb_na["chain"], "journal": {"journal_id": _h32("bi-jna")}, "executor_cfg": fx_gb_na["executor_cfg"]},
        "REFUSE", "GRANT_WINDOW_CLOSED", "Grant at exact tip_height == not_after_height MUST refuse GRANT_WINDOW_CLOSED.")

    # 3n. Depth-2 delegation exact boundaries: ordinal == cur_ord + count (L2519), child not_before == root.not_before & not_after == root.not_after (L2562, L2563),
    #     AND compound `or` child action matches with DIFFERENT target (L2577)!
    fx_d = rm._base_invocation_fixture()
    exec_wire_d = fx_d["invocation"]["payload"]["executor"]
    del_k, cseal_k, row_k, child_rcpt = _kp("bd-del"), _kp("bd-cseal"), _kp("bd-row"), _kp("bd-crcpt")
    row_pol = {"kind": "key", "pk": row_k["comp"]}
    cseal_pol = {"kind": "key", "pk": cseal_k["comp"]}
    row_tx = _h32("bd-row-tx")
    cseal_tx = _h32("bd-cseal-tx")
    pg_p = copy.deepcopy(fx_d["bundle"]["grants"][0]["payload"])
    pg_p["not_before_height"] = 749000
    pg_p["not_after_height"] = 760000
    pg_p["delegate"] = {
        "child_seal_key": cseal_k["comp"],
        "groups": [{
            "ranges": [{"count": 2, "first": 0, "script_policy": row_pol, "txid": row_tx}],
            "template": {
                "capabilities": [{"action": "mail/read", "quotas": [{"kind": "count", "max": "5", "resource": "mail/read", "unit": "calls", "window": "term"}], "target": "mailbox:id/alice:work", "where": {}}],
                "executor": exec_wire_d, "notary_mode": "none", "recipient_rule": {"key": child_rcpt["xonly"], "mode": "exact_key"},
            },
        }],
        "key": del_k["xonly"],
        "pools": [{"kind": "count", "max": "10", "resource": "mail/read", "unit": "calls", "window": "term"}],
    }
    pg_env = sl.sign_envelope(pg_p, [fx_d["_keys"]["alice_gr"]["sk"]])
    pg_id = sl.object_id(pg_p)
    pitx = _h32("bd-pitx")
    cg_p = {
        "capabilities": [{"action": "mail/read", "quotas": [{"kind": "count", "max": "5", "resource": "mail/read", "unit": "calls", "window": "term"}], "target": "mailbox:id/alice:work", "where": {}}],
        "executor": exec_wire_d, "genesis": GENESIS_MAIN, "network": "main",
        "not_after_height": 760000,   # == root.not_after_height!
        "not_before_height": 749000,  # == root.not_before_height!
        "parent": {"grant_id": pg_id, "ordinal": 2},  # == cur_ord + count (upper endpoint of range)!
        "recent_block": pg_p["recent_block"],
        "recipient": {"key": child_rcpt["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": cseal_pol, "txid": cseal_tx, "vout": 0}},
        "type": "seallink-grant/1",
    }
    cg_env = sl.sign_envelope(cg_p, [del_k["sk"]])
    cg_id = sl.object_id(cg_p)
    citx = _h32("bd-citx")
    fx_d["chain"]["txs"][row_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(row_pol)}, "1": {"script_pubkey_hex": _spk_hex(row_pol), "spent_by_txid": citx}}}
    fx_d["chain"]["txs"][cseal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(cseal_pol)}}}
    fx_d["chain"]["txs"][pitx] = {"confirmed_height": orig_itx_h, "inputs": [sv.make_segwit_input(pg_p["revocation"]["seal"]["txid"], 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(pg_env), "grant_id": pg_id, "type": "seallink-issuance/1"}).hex()).hex(), "outputs": {}}
    fx_d["chain"]["txs"][citx] = {"confirmed_height": orig_itx_h, "inputs": [sv.make_segwit_input(row_tx, 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(cg_env), "grant_id": cg_id, "type": "seallink-issuance/1"}).hex()).hex(), "outputs": {}}
    inv_d = sl.sign_envelope({**fx_d["invocation"]["payload"], "nonce": _h32("bd-inv"), "proof_path": [{"grant_id": pg_id, "issuance_txid": pitx}, {"grant_id": cg_id, "issuance_txid": citx}]}, [child_rcpt["sk"]])
    add("bnd-delegation-exact-ordinal-upper-and-window-bounds-admit", ["SL-GRNT-005", "SL-GRNT-006"], "invocation",
        {"invocation": inv_d, "bundle": {**fx_d["bundle"], "grants": [pg_env, cg_env]}, "chain": fx_d["chain"], "journal": {"journal_id": _h32("bd-j")}, "executor_cfg": fx_d["executor_cfg"]},
        "ADMIT", None, "Depth-2 child grant at exact upper ordinal (cur_ord + count) and exact root not_before/not_after bounds MUST admit.")

    # Compound L2577: child action == parent action BUT child target != parent target -> GRANT_DELEGATION_INVALID!
    cg_bad_t = copy.deepcopy(cg_p)
    cg_bad_t["capabilities"][0]["target"] = "mailbox:id/alice:other"
    cg_bt_env = sl.sign_envelope(cg_bad_t, [del_k["sk"]])
    cg_bt_id = sl.object_id(cg_bad_t)
    citx_bt = _h32("bd-citx-bt")
    ch_d_bt = copy.deepcopy(fx_d["chain"])
    ch_d_bt["txs"][row_tx]["outputs"]["1"]["spent_by_txid"] = citx_bt
    ch_d_bt["txs"][citx_bt] = {"confirmed_height": orig_itx_h, "inputs": [sv.make_segwit_input(row_tx, 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(cg_bt_env), "grant_id": cg_bt_id, "type": "seallink-issuance/1"}).hex()).hex(), "outputs": {}}
    inv_bt = sl.sign_envelope({**fx_d["invocation"]["payload"], "nonce": _h32("bd-inv-bt"), "proof_path": [{"grant_id": pg_id, "issuance_txid": pitx}, {"grant_id": cg_bt_id, "issuance_txid": citx_bt}], "target": "mailbox:id/alice:other"}, [child_rcpt["sk"]])
    add("bnd-delegation-same-action-wrong-target-refuse", ["SL-GRNT-006"], "invocation",
        {"invocation": inv_bt, "bundle": {**fx_d["bundle"], "grants": [pg_env, cg_bt_env]}, "chain": ch_d_bt, "journal": {"journal_id": _h32("bd-jbt")}, "executor_cfg": fx_d["executor_cfg"]},
        "REFUSE", "GRANT_CHILD_WIDER", "Child grant matching parent template action but mismatching target MUST refuse GRANT_CHILD_WIDER.")

    # 3o. Bearer session exact now == exp -> SESSION_INVALID (kills L2953 >= -> >!)
    tok_eq = "sl_tok_exact_exp"
    add("bnd-bearer-session-now-eq-exp-refuse", ["SL-GRNT-013"], "bearer_session",
        {"token": tok_eq, "slot_binding": "slot:1", "chain": fx0["chain"],
         "journal": {"journal_id": _h32("bsj-eq"), "sessions": {sl.sha256(tok_eq.encode()).hex(): {"closed": False, "exp": fx0["chain"]["now"], "grant_id": _h32("bg-eq"), "slot_binding": "slot:1"}}}},
        "REFUSE", "SESSION_INVALID", "Bearer session at exact now == exp MUST refuse SESSION_INVALID.")

    # 3p. Compound boolean isolations:
    #     - L2605: allow_window_only=True on require_seal=True action (mail/send) -> GRANT_SEAL_REQUIRED!
    fx_wo = rm._base_invocation_fixture()
    exec_wire_wo = fx_wo["invocation"]["payload"]["executor"]
    gp_wo = copy.deepcopy(fx_wo["bundle"]["grants"][0]["payload"])
    gp_wo["capabilities"] = [{"action": "mail/send", "target": "mailbox:id/alice:work", "where": {}}]
    gp_wo["not_before_height"] = fx_wo["chain"]["tip_height"] - 5
    gp_wo["not_after_height"] = fx_wo["chain"]["tip_height"] + 5  # <= 12 blocks!
    gp_wo["revocation"] = {"mode": "window_only"}
    g_wo = sl.sign_envelope(gp_wo, [fx_wo["_keys"]["alice_gr"]["sk"]])
    gid_wo = sl.object_id(gp_wo)
    itx_wo = _h32("bnd-itx-wo")
    fx_wo["chain"]["txs"][itx_wo] = {"confirmed_height": orig_itx_h, "inputs": [sv.make_segwit_input(fx_wo["bundle"]["grants"][0]["payload"]["revocation"]["seal"]["txid"], 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_wo), "grant_id": gid_wo, "type": "seallink-issuance/1"}).hex()).hex(), "outputs": {}}
    inv_wo = sl.sign_envelope(
        {"action": "mail/send", "arguments": {"body_sha256": _h32("wo-b"), "size_bytes": "12", "subject": "hi", "to": "b@ex.com"},
         "executor": exec_wire_wo, "exp": 1795221000, "genesis": GENESIS_MAIN, "iat": 1795220000, "network": "main",
         "nonce": _h32("bnd-n-wo"), "proof_path": [{"grant_id": gid_wo, "issuance_txid": itx_wo}], "target": "mailbox:id/alice:work", "type": "seallink-invocation/1"},
        [fx_wo["_keys"]["agent_req"]["sk"]],
    )
    add("bnd-window-only-forbidden-on-require-seal-action-even-when-allowed", ["SL-GRNT-003"], "invocation",
        {"invocation": inv_wo, "bundle": {**fx_wo["bundle"], "grants": [g_wo]}, "chain": fx_wo["chain"], "journal": {"journal_id": _h32("j-wo")}, "executor_cfg": fx_wo["executor_cfg"], "allow_window_only": True},
        "REFUSE", "GRANT_SEAL_REQUIRED", "Even when executor sets allow_window_only=True, an action with require_seal=True (mail/send) MUST refuse GRANT_SEAL_REQUIRED.")

    #     - L3043: federation screening from TRUSTED peer with ZERO-quota grant -> FEDERATION_POLICY_DENIED!
    gp_noq = copy.deepcopy(fx0["bundle"]["grants"][0]["payload"])
    gp_noq["capabilities"][0].pop("quotas", None)
    g_noq = sl.sign_envelope(gp_noq, [fx0["_keys"]["alice_gr"]["sk"]])
    add("bnd-fed-screening-trusted-peer-zero-quota-refuse", ["SL-SERV-004"], "federation",
        {"policy": {"trusted_peers": ["id/peer-good"]}, "peer_ctx": {"phase": "screening", "peer_id": "id/peer-good"}, "grant": g_noq, "chain": fx0["chain"]},
        "REFUSE", "FEDERATION_POLICY_DENIED", "Federation screening from a trusted peer whose grant lacks quotas MUST refuse FEDERATION_POLICY_DENIED.")

    # 3q. EndRecord and CapacityRecord signed by 0x0b-compromised civil registry cred key -> CRED_ISSUER_CLOSED!
    for rec_kind in ("end", "capacity"):
        of_bk = rm._base_origin_fixture()
        reg_hist = of_bk["chain"]["names"]["id/civil-registry"]
        reg_prev = reg_hist["updates"][-1]
        reg_iss = of_bk["origin_bundle"]["origin"]["payload"]["issuer"]
        reg_pol = reg_iss["owner_policy"]
        reg_brk = {
            "compromised_policy": reg_iss["role_policy"], "genesis": GENESIS_MAIN, "h_c": 749800,
            "issuer": {"name": reg_iss["name"], "owner_policy": reg_pol, "registration": reg_iss["registration"]},
            "name_input": {"txid": reg_prev["txid"], "vout": reg_prev["vout"]}, "role": "cred", "type": "seallink-credential-break/1",
        }
        reg_brk_tx = _h32(f"bnd-reg-brk-{rec_kind}")
        reg_hist["updates"].append({
            "confirmed_height": 749900, "op": "NAME_UPDATE",
            "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(reg_brk).hex(), h_c=749800).hex(),
            "output_script_hex": reg_prev["output_script_hex"], "owner_policy": reg_pol,
            "prev_input": {"sighash_bytes": [0x01], "txid": reg_prev["txid"], "vout": reg_prev["vout"], "witness_policy": reg_pol},
            "txid": reg_brk_tx, "vout": 0,
        })
        stat_seal = of_bk["origin_bundle"]["origin"]["payload"]["status_seal"]
        spend_stx = _h32(f"bnd-stat-spend-{rec_kind}")
        of_bk["chain"]["txs"][stat_seal["txid"]]["outputs"]["0"]["spent_by_txid"] = spend_stx
        if rec_kind == "end":
            erec = sl.sign_envelope(
                {"basis_sha256": _h32("e-basis"), "genesis": GENESIS_MAIN, "issued_at": 1795220000, "issuer": reg_iss,
                 "network": "main", "origin_id": of_bk["_origin_id"], "reason": "death",
                 "status_prev_outpoint": {"txid": stat_seal["txid"], "vout": 0}, "type": "seallink-end/1"},
                [of_bk["_keys"]["reg_cred"]["sk"]],
            )
            of_bk["origin_bundle"]["end_record"] = erec
            of_bk["chain"]["txs"][spend_stx] = {"confirmed_height": 749950, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(erec)).hex(), "outputs": {}}
        else:
            crec = sl.sign_envelope(
                {"basis_sha256": _h32("c-basis"), "genesis": GENESIS_MAIN, "issued_at": 1795220000, "issuer": reg_iss,
                 "network": "main", "next_status_policy": stat_seal["script_policy"], "next_status_vout": 0,
                 "origin_id": of_bk["_origin_id"], "status_prev_outpoint": {"txid": stat_seal["txid"], "vout": 0},
                 "subject_new_owner_policy": {"kind": "key", "pk": _kp("bnd-em-new")["comp"]}, "type": "seallink-capacity/1"},
                [of_bk["_keys"]["reg_cred"]["sk"]],
            )
            of_bk["origin_bundle"]["capacity_record"] = crec
            of_bk["chain"]["txs"][spend_stx] = {"confirmed_height": 749950, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(crec)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_seal["script_policy"])}}}
        add(f"bnd-origin-{rec_kind}-record-issuer-0x0b-closed-refuse", ["SL-ORIG-012", "SL-CONT-009"], "origin_status",
            {"origin_bundle": of_bk["origin_bundle"], "chain": of_bk["chain"], "trusted_origin_issuers": of_bk["trusted_origin_issuers"]},
            "REFUSE", "CRED_ISSUER_CLOSED",
            f"A {rec_kind} record anchored at h >= h_c under a 0x0b-compromised registry key MUST refuse CRED_ISSUER_CLOSED.")

    # 3r. Remaining exact boundary & isolated compound-logic pins:
    #     - L353 (`settle < 0`): max="1" grant where call 1 settles 0 (full release) so call 2 succeeds!
    fx_s0 = rm._base_invocation_fixture()
    gp_s0 = copy.deepcopy(fx_s0["bundle"]["grants"][0]["payload"])
    gp_s0["capabilities"][0]["quotas"] = [{"kind": "count", "max": "1", "resource": "mail/read", "unit": "calls", "window": "term"}]
    g_s0 = sl.sign_envelope(gp_s0, [fx_s0["_keys"]["alice_gr"]["sk"]])
    gid_s0 = sl.object_id(gp_s0)
    itx_s0 = _h32("bnd-s0-itx")
    fx_s0["chain"]["txs"][itx_s0] = {
        "confirmed_height": orig_itx_h,
        "inputs": [sv.make_segwit_input(gp_s0["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_s0), "grant_id": gid_s0, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_s0_1 = sl.sign_envelope({**fx_s0["invocation"]["payload"], "nonce": _h32("s0-n1"), "proof_path": [{"grant_id": gid_s0, "issuance_txid": itx_s0}]}, [fx_s0["_keys"]["agent_req"]["sk"]])
    inv_s0_2 = sl.sign_envelope({**fx_s0["invocation"]["payload"], "nonce": _h32("s0-n2"), "proof_path": [{"grant_id": gid_s0, "issuance_txid": itx_s0}]}, [fx_s0["_keys"]["agent_req"]["sk"]])
    add("bnd-quota-settle-zero-releases-full-reservation-admit", ["SL-GRNT-004"], "restart_recovery",
        {
            "journal_id": _h32("s0-jid"),
            "executor_cfg": fx_s0["executor_cfg"],
            "pre_restart_steps": [
                {"label": "call1-settle-zero", "chain": fx_s0["chain"], "invocation": inv_s0_1, "bundle": {**fx_s0["bundle"], "grants": [g_s0]}, "actual_quota_usage": {"count|mail/read|calls|term": 0}, "want_verdict": "ADMIT", "want_refusal": None},
            ],
            "post_restart_steps": [
                {"label": "call2-after-full-release", "chain": fx_s0["chain"], "invocation": inv_s0_2, "bundle": {**fx_s0["bundle"], "grants": [g_s0]}, "want_verdict": "ADMIT", "want_refusal": None},
            ],
        },
        "ADMIT", None,
        "Settling exact 0 on a max=1 quota MUST release the entire reservation (not clamp to reserve), admitting a subsequent call after replay.")

    #     - L1200 (`uh <= recent_block_height`): role rotated at exact uh == recent_block_height and unchanged thereafter -> ADMIT!
    #       (If `<=` mutates to `<`, baseline stays at u[0] and u[1] falsely triggers NAME_ROLE_CHANGED!)
    ch_rbh = copy.deepcopy(fx0["chain"])
    al_u = ch_rbh["names"]["id/alice"]["updates"]
    al_prev = al_u[-1]
    new_gr_k = _kp("bnd-rot-gr")
    u_rot_h = al_prev["confirmed_height"] + 5
    u_rot_tx = _h32("bnd-al-rot-1")
    al_u.append({
        "confirmed_height": u_rot_h,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(al_prev["owner_policy"])[0], name=b"id/alice", value=sl.jcs_encode({"link": {"grant": new_gr_k["xonly"]}})).hex(),
        "owner_policy": al_prev["owner_policy"],
        "prev_input": {"sighash_bytes": [0x01], "txid": al_prev["txid"], "vout": al_prev["vout"], "witness_policy": al_prev["owner_policy"]},
        "txid": u_rot_tx,
        "vout": 0,
    })
    al_u.append({
        "confirmed_height": u_rot_h + 5,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(al_prev["owner_policy"])[0], name=b"id/alice", value=sl.jcs_encode({"link": {"grant": new_gr_k["xonly"]}})).hex(),
        "owner_policy": al_prev["owner_policy"],
        "prev_input": {"sighash_bytes": [0x01], "txid": u_rot_tx, "vout": 0, "witness_policy": al_prev["owner_policy"]},
        "txid": _h32("bnd-al-rot-2"),
        "vout": 0,
    })
    add("bnd-role-policy-rotation-at-exact-recent-block-height-admit", ["SL-IDEN-003"], "name_resolve",
        {"name": "id/alice", "check_role": "grant", "presented_role_policy": {"m": 1, "pks": [new_gr_k["xonly"]]},
         "recent_block_height": u_rot_h, "chain": ch_rbh},
        "ADMIT", None,
        "A role rotation confirmed at exact confirmed_height == recent_block_height with no subsequent change MUST admit.")

    #     - L1480 (`len(updates) < 3`): emancipation handover in exact 3 updates (FIRSTUPDATE + transfer + subject update) -> ADMIT_AUTONOMOUS!
    of_3u = rm._base_origin_fixture()
    of_3u["chain"]["credible_utc_interval"] = [of_3u["origin_bundle"]["opened_majority_unix"], of_3u["origin_bundle"]["opened_majority_unix"] + 10]
    u0_3 = copy.deepcopy(of_3u["chain"]["names"]["id/child-leo"]["updates"][0])
    ad3_pol = {"kind": "key", "pk": _kp("bnd-leo-3u")["comp"]}
    ad3_spk, _ = sl.compile_script_policy(ad3_pol)
    l3_val = sl.jcs_encode({"link": {"grant": of_3u["_keys"]["ward_gr"]["xonly"], "origin": of_3u["_origin_id"]}})
    u1_3 = {"confirmed_height": 749900, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", ad3_spk, name=b"id/child-leo", value=l3_val).hex(), "owner_policy": ad3_pol, "prev_input": {"sighash_bytes": [0x01], "txid": u0_3["txid"], "vout": u0_3["vout"], "witness_policy": u0_3["owner_policy"]}, "txid": _h32("bnd-3u-1"), "vout": 0}
    u2_3 = {"confirmed_height": 749910, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", ad3_spk, name=b"id/child-leo", value=l3_val).hex(), "owner_policy": ad3_pol, "prev_input": {"sighash_bytes": [0x01], "txid": u1_3["txid"], "vout": 0, "witness_policy": ad3_pol}, "txid": _h32("bnd-3u-2"), "vout": 0}
    of_3u["chain"]["names"]["id/child-leo"]["updates"] = [u0_3, u1_3, u2_3]
    add("bnd-emancipation-exact-3-updates-handover-autonomous", ["SL-ORIG-011"], "origin_status",
        {"origin_bundle": of_3u["origin_bundle"], "chain": of_3u["chain"], "trusted_origin_issuers": of_3u["trusted_origin_issuers"]},
        "ADMIT_AUTONOMOUS", None,
        "Emancipation handover completing in exact minimum 3 name updates (FIRSTUPDATE, transfer, subject update) MUST admit autonomous capacity.")

    #     - L3015 isolated bearer session refusals (`closed` only, wrong `slot_binding` only)
    tok_cl = "sl_tok_closed_only"
    add("bnd-bearer-session-closed-only-refuse", ["SL-GRNT-013"], "bearer_session",
        {"token": tok_cl, "slot_binding": "slot:1", "chain": fx0["chain"],
         "journal": {"journal_id": _h32("bsj-cl"), "sessions": {sl.sha256(tok_cl.encode()).hex(): {"closed": True, "exp": fx0["chain"]["now"] + 600, "grant_id": _h32("bg-cl"), "slot_binding": "slot:1"}}}},
        "REFUSE", "SESSION_INVALID", "Closed bearer session with valid slot_binding and unexpired exp MUST refuse SESSION_INVALID.")
    tok_sl = "sl_tok_wrong_slot_only"
    add("bnd-bearer-session-wrong-slot-only-refuse", ["SL-GRNT-013"], "bearer_session",
        {"token": tok_sl, "slot_binding": "slot:2", "chain": fx0["chain"],
         "journal": {"journal_id": _h32("bsj-sl"), "sessions": {sl.sha256(tok_sl.encode()).hex(): {"closed": False, "exp": fx0["chain"]["now"] + 600, "grant_id": _h32("bg-sl"), "slot_binding": "slot:1"}}}},
        "REFUSE", "SESSION_INVALID", "Open unexpired bearer session presented on mismatched slot_binding MUST refuse SESSION_INVALID.")

    #     - L2618 isolated delegation child `not_before_height < root.not_before_height` -> GRANT_CHILD_WIDER!
    cg_nb = copy.deepcopy(cg_p)
    cg_nb["not_before_height"] = pg_p["not_before_height"] - 1
    cg_nb_env = sl.sign_envelope(cg_nb, [del_k["sk"]])
    cg_nb_id = sl.object_id(cg_nb)
    citx_nb = _h32("bd-citx-nb")
    ch_d_nb = copy.deepcopy(fx_d["chain"])
    ch_d_nb["txs"][row_tx]["outputs"]["1"]["spent_by_txid"] = citx_nb
    ch_d_nb["txs"][citx_nb] = {"confirmed_height": orig_itx_h, "inputs": [sv.make_segwit_input(row_tx, 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(cg_nb_env), "grant_id": cg_nb_id, "type": "seallink-issuance/1"}).hex()).hex(), "outputs": {}}
    inv_nb = sl.sign_envelope({**fx_d["invocation"]["payload"], "nonce": _h32("bd-inv-nb"), "proof_path": [{"grant_id": pg_id, "issuance_txid": pitx}, {"grant_id": cg_nb_id, "issuance_txid": citx_nb}]}, [child_rcpt["sk"]])
    add("bnd-delegation-child-not-before-earlier-than-root-refuse", ["SL-GRNT-006"], "invocation",
        {"invocation": inv_nb, "bundle": {**fx_d["bundle"], "grants": [pg_env, cg_nb_env]}, "chain": ch_d_nb, "journal": {"journal_id": _h32("bd-jnb")}, "executor_cfg": fx_d["executor_cfg"]},
        "REFUSE", "GRANT_CHILD_WIDER", "Child grant with not_before_height < root.not_before_height MUST refuse GRANT_CHILD_WIDER.")

    #     - L2759 isolated direct grant same executor.name with wrong executor.key -> GRANT_EXECUTOR_MISMATCH!
    fx_ek = rm._base_invocation_fixture()
    gp_ek = copy.deepcopy(fx_ek["bundle"]["grants"][0]["payload"])
    gp_ek["executor"] = {"key": _kp("bnd-wrong-ek")["xonly"], "name": fx_ek["executor_cfg"]["name"]}
    g_ek = sl.sign_envelope(gp_ek, [fx_ek["_keys"]["alice_gr"]["sk"]])
    gid_ek = sl.object_id(gp_ek)
    itx_ek = _h32("bnd-ek-itx")
    fx_ek["chain"]["txs"][itx_ek] = {"confirmed_height": orig_itx_h, "inputs": [sv.make_segwit_input(gp_ek["revocation"]["seal"]["txid"], 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_ek), "grant_id": gid_ek, "type": "seallink-issuance/1"}).hex()).hex(), "outputs": {}}
    inv_ek = sl.sign_envelope({**fx_ek["invocation"]["payload"], "nonce": _h32("bnd-ek-n"), "proof_path": [{"grant_id": gid_ek, "issuance_txid": itx_ek}]}, [fx_ek["_keys"]["agent_req"]["sk"]])
    add("bnd-direct-grant-same-executor-name-wrong-key-refuse", ["SL-GRNT-003"], "invocation",
        {"invocation": inv_ek, "bundle": {**fx_ek["bundle"], "grants": [g_ek]}, "chain": fx_ek["chain"], "journal": {"journal_id": _h32("bnd-jek")}, "executor_cfg": fx_ek["executor_cfg"]},
        "REFUSE", "GRANT_EXECUTOR_MISMATCH", "Direct grant matching executor.name but mismatching executor.key MUST refuse GRANT_EXECUTOR_MISMATCH.")
