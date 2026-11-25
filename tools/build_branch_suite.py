#!/usr/bin/env python3
"""
Acceptance & Exhaustive Refusal-Branch Conformance Cases for SealLink v1.0.

Provides:
  Part A: Mandatory v1.0.0-draft.8 acceptance tests:
    1. Policy-scoped 0x0b compromise cutoff (4 outcomes: retired key A before h_c,
       retired key A at/after h_c, rotated successor key B surviving break on A,
       distinct role 'notary' unaffected).
    2. Sibling-row row_ordinal quota accounting isolation across one executor
       plus fresh FencedJournal.replay_persisted_entries reconstruction.
    3. Maximum-capacity 32-quota / 64-settlement Receipt with explicit window &
       row_ordinal fields (plus boundary refusals: 65 lines, missing row_ordinal,
       unexpected own row_ordinal, missing window).
  Part B: Independent single-condition refusal-branch tests targeting every
    remaining refusal return site in `tools/seallink_verifier.py` so exhaustive
    mutation testing catches removed checks.
"""

from __future__ import annotations

import copy
from typing import Any, Callable

import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = rm.GENESIS_MAIN


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-branch-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"branch:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def _build_delegation_base(
    *,
    pool_calls: int = 10,
    row_cap_calls: int = 2,
    c1_max_calls: int = 1,
    c2_max_calls: int = 2,
    c1_kind: str = "revocable",
) -> dict[str, Any]:
    """Reusable clean depth-2 delegation fixture with sibling rows 1 and 2 on one executor."""
    org_own = _kp("del-org-own")
    org_gr = _kp("del-org-gr")
    del_k = _kp("del-key")
    cseal_k = _kp("del-cseal-k")
    exec_k = _kp("del-exec-rcpt")
    w1_k = _kp("del-w1")
    w2_k = _kp("del-w2")
    w1_seal = _kp("del-w1-seal")
    org_owner_pol = {"kind": "key", "pk": org_own["comp"]}
    org_reg = {"txid": _h32("del-org-reg"), "vout": 0}
    p_seal_pol = {"kind": "key", "pk": _kp("del-pseal")["comp"]}
    p_seal_tx = _h32("del-pseal-tx")
    rows_tx = _h32("del-rows-tx")
    recent_blk = _h32("del-recent-blk")

    row_coin_pol = {"kind": "key", "pk": _kp("del-row-coin")["comp"]}
    p_payload = {
        "capabilities": [
            {
                "action": "agent/tool",
                "quotas": [{"kind": "seallink/count", "max": str(pool_calls), "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}],
                "target": "station:id/station-a:tools",
                "where": {"tool_name": {"in": ["lint", "pytest"]}},
            }
        ],
        "delegate": {
            "child_seal_key": cseal_k["comp"],
            "groups": [
                {
                    "ranges": [{"count": 3, "first": 0, "script_policy": row_coin_pol, "txid": rows_tx}],
                    "template": {
                        "capabilities": [
                            {
                                "action": "agent/tool",
                                "quotas": [{"kind": "seallink/count", "max": str(row_cap_calls), "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}],
                                "target": "station:id/station-a:tools",
                                "where": {"tool_name": {"in": ["lint", "pytest"]}},
                            }
                        ],
                        "executor": {"key": exec_k["xonly"], "name": "id/station-a"},
                        "notary_mode": "none",
                        "recipient_rule": {"key": w1_k["xonly"], "mode": "exact_key"},
                    },
                }
            ],
            "key": del_k["xonly"],
            "pools": [{"kind": "seallink/count", "max": str(pool_calls), "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}],
        },
        "executor": {"key": exec_k["xonly"], "name": "id/station-a"},
        "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/org-treasury", "owner_policy": org_owner_pol, "registration": org_reg, "role_policy": {"m": 1, "pks": [org_gr["xonly"]]}},
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 750000,
        "recent_block": recent_blk,
        "recipient": {"key": _kp("del-orch")["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": p_seal_pol, "txid": p_seal_tx, "vout": 0}},
        "type": "seallink-grant/1",
    }
    p_env = sl.sign_envelope(p_payload, [org_gr["sk"]])
    p_id = sl.object_id(p_payload)
    p_iss_tx = _h32("del-p-iss-tx")
    p_iss_opret = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_env), "grant_id": p_id, "type": "seallink-issuance/1"}).hex()
    ).hex()

    def make_child(ordinal: int, max_calls: int, rec_k: dict[str, Any], kind: str) -> tuple[dict[str, Any], str, str, str, dict[str, Any]]:
        if kind == "single_use":
            spol = {"keys": {"grantee": w1_seal["comp"], "issuer": cseal_k["comp"]}, "kind": "branch", "template": "single_use_1_of_2"}
        else:
            spol = {"kind": "key", "pk": cseal_k["comp"]}
        stx = _h32(f"del-c{ordinal}-seal-tx")
        cp = {
            "capabilities": [
                {
                    "action": "agent/tool",
                    "quotas": [{"kind": "seallink/count", "max": str(max_calls), "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}],
                    "target": "station:id/station-a:tools",
                    "where": {"tool_name": {"eq": "pytest"}},
                }
            ],
            "executor": {"key": exec_k["xonly"], "name": "id/station-a"},
            "genesis": GENESIS_MAIN,
            "network": "main",
            "not_after_height": 755000,
            "not_before_height": 750100,
            "parent": {"grant_id": p_id, "ordinal": ordinal},
            "recent_block": recent_blk,
            "recipient": {"key": rec_k["xonly"], "mode": "key"},
            "revocation": {"construction": "W", "kind": kind, "mode": "seal", "seal": {"script_policy": spol, "txid": stx, "vout": 0}},
            "type": "seallink-grant/1",
        }
        cenv = sl.sign_envelope(cp, [del_k["sk"]])
        cid = sl.object_id(cp)
        itx = _h32(f"del-c{ordinal}-iss-tx")
        return cenv, cid, itx, stx, spol

    c1_env, c1_id, c1_itx, c1_stx, c1_spol = make_child(1, c1_max_calls, w1_k, c1_kind)
    c2_env, c2_id, c2_itx, c2_stx, c2_spol = make_child(2, c2_max_calls, w1_k, "revocable")

    def make_inv(cid: str, itx: str, rec_k: dict[str, Any], nonce_lbl: str) -> dict[str, Any]:
        return sl.sign_envelope(
            {
                "action": "agent/tool",
                "arguments": {"input_sha256": _h32(f"args-{nonce_lbl}"), "max_output_bytes": "1024", "tool_name": "pytest"},
                "executor": {"key": exec_k["xonly"], "name": "id/station-a"},
                "exp": 1795221000,
                "genesis": GENESIS_MAIN,
                "iat": 1795220000,
                "network": "main",
                "nonce": _h32(f"nonce-{nonce_lbl}"),
                "proof_path": [{"grant_id": p_id, "issuance_txid": p_iss_tx}, {"grant_id": cid, "issuance_txid": itx}],
                "target": "station:id/station-a:tools",
                "type": "seallink-invocation/1",
            },
            [rec_k["sk"]],
        )

    c1_iss_opret = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c1_env), "grant_id": c1_id, "type": "seallink-issuance/1"}).hex()
    ).hex()
    c2_iss_opret = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c2_env), "grant_id": c2_id, "type": "seallink-issuance/1"}).hex()
    ).hex()

    chain = rm.sync_chain_tip({
        "network": "main",
        "genesis": GENESIS_MAIN,
        "tip_height": 750110,
        "tip_hash": _h32("del-tip"),
        "tip_header_time": 1795220040,
        "tip_first_sight": 1795220045,
        "now": 1795220050,
        "blocks": {recent_blk: 750000},
        "names": {
            "id/org-treasury": sv.make_name_history(
                "id/org-treasury", org_reg, org_owner_pol, {"link": {"grant": org_gr["xonly"]}}, first_height=748000, update_height=749000
            )
        },
        "txs": {
            p_seal_tx: {"confirmed_height": 750002, "inputs": [sv.make_segwit_input(_h32("pf"), 0)], "outputs": {"0": {"script_pubkey_hex": _spk_hex(p_seal_pol)}, "1": {"script_pubkey_hex": _spk_hex(org_owner_pol)}}},
            p_iss_tx: {"confirmed_height": 750005, "inputs": [sv.make_segwit_input(p_seal_tx, 1)], "opreturn_hex": p_iss_opret, "outputs": {}},
            c1_stx: {"confirmed_height": 750101, "inputs": [sv.make_segwit_input(_h32("c1f"), 0)], "outputs": {"0": {"script_pubkey_hex": _spk_hex(c1_spol)}, "1": {"script_pubkey_hex": _spk_hex(org_owner_pol)}}},
            c1_itx: {"confirmed_height": 750102, "inputs": [sv.make_segwit_input(rows_tx, 0), sv.make_segwit_input(c1_stx, 1)], "opreturn_hex": c1_iss_opret, "outputs": {}},
            c2_stx: {"confirmed_height": 750101, "inputs": [sv.make_segwit_input(_h32("c2f"), 0)], "outputs": {"0": {"script_pubkey_hex": _spk_hex(c2_spol)}, "1": {"script_pubkey_hex": _spk_hex(org_owner_pol)}}},
            c2_itx: {"confirmed_height": 750102, "inputs": [sv.make_segwit_input(rows_tx, 1), sv.make_segwit_input(c2_stx, 1)], "opreturn_hex": c2_iss_opret, "outputs": {}},
        },
    })
    return {
        "parent_env": p_env,
        "parent_id": p_id,
        "parent_iss_tx": p_iss_tx,
        "c1_env": c1_env,
        "c1_id": c1_id,
        "c1_itx": c1_itx,
        "c1_stx": c1_stx,
        "c1_spol": c1_spol,
        "c2_env": c2_env,
        "c2_id": c2_id,
        "c2_itx": c2_itx,
        "c2_stx": c2_stx,
        "c2_spol": c2_spol,
        "make_inv": make_inv,
        "chain": chain,
        "executor_cfg": {
            "key": exec_k["xonly"],
            "name": "id/station-a",
            "station_slot_bindings": {"station:id/station-a:tools": [{"name": "id/org-treasury", "owner_policy": org_owner_pol, "registration": org_reg}]},
        },
        "journal": {"journal_id": _h32("del-jid")},
        "keys": {"org_gr": org_gr, "del_k": del_k, "cseal_k": cseal_k, "exec_k": exec_k, "w1_k": w1_k, "w2_k": w2_k},
        "rows_tx": rows_tx,
        "recent_blk": recent_blk,
    }


def add_acceptance_and_branch_cases(add: Callable[..., None]) -> None:
    """Append all v1.0.0-draft.8 acceptance tests and exhaustive refusal-branch cases."""

    # ========================================================================
    # PART A — MANDATORY ACCEPTANCE TESTS (Review 2 §1.1, §1.2, §2)
    # ========================================================================

    # --- A1. Policy-scoped 0x0b compromise cutoff (4 required outcomes) ---
    iss_own = _kp("0x0b-iss-own")
    key_a = _kp("0x0b-cred-key-A")
    key_b = _kp("0x0b-cred-key-B")
    key_notary = _kp("0x0b-notary-key")
    iss_owner_pol = {"kind": "key", "pk": iss_own["comp"]}
    iss_reg = {"txid": _h32("0x0b-iss-reg"), "vout": 0}
    hist_pre = sv.make_name_history(
        "id/issuer-rot", iss_reg, iss_owner_pol,
        {"link": {"cred": key_a["xonly"], "notary": key_notary["xonly"]}},
        first_height=748000, update_height=749000,
    )
    prev_u = hist_pre["updates"][-1]
    brk_a_obj = {
        "compromised_policy": {"m": 1, "pks": [key_a["xonly"]]},
        "genesis": GENESIS_MAIN,
        "h_c": 749400,
        "issuer": {"name": "id/issuer-rot", "owner_policy": iss_owner_pol, "registration": iss_reg},
        "name_input": {"txid": prev_u["txid"], "vout": prev_u["vout"]},
        "role": "cred",
        "type": "seallink-credential-break/1",
    }
    hist_with_break_and_rot = sv.make_name_history(
        "id/issuer-rot", iss_reg, iss_owner_pol,
        {"link": {"cred": key_a["xonly"], "notary": key_notary["xonly"]}},
        first_height=748000, update_height=749000,
        extra_updates=[{
            "txid": _h32("0x0b-break-a-install-b-tx"),
            "confirmed_height": 749600,
            "value": {"link": {"cred": key_b["xonly"], "notary": key_notary["xonly"]}},
            "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_a_obj).hex(), 0x00, h_c=749400).hex(),
        }],
    )

    def _make_cred_and_chain(signer_kp: dict[str, Any], anchor_h: int, lbl: str) -> dict[str, Any]:
        cp = {
            "claims": {"degree": "MSc"},
            "credential_kind": "education/diploma",
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": {
                "name": "id/issuer-rot",
                "owner_policy": iss_owner_pol,
                "registration": iss_reg,
                "role_policy": {"m": 1, "pks": [signer_kp["xonly"]]},
            },
            "lifecycle": "eternal",
            "network": "main",
            "not_before_height": 749000,
            "not_after_height": 760000,
            "subject": {"key": _kp("0x0b-subj")["xonly"], "mode": "key"},
            "type": "seallink-credential/1",
        }
        cenv = sl.sign_envelope(cp, [signer_kp["sk"]])
        atx = _h32(f"0x0b-atx-{lbl}")
        chain = rm.sync_chain_tip({
            "network": "main",
            "genesis": GENESIS_MAIN,
            "tip_height": 750010,
            "tip_hash": _h32("0x0b-tip"),
            "tip_header_time": 1795220000,
            "tip_first_sight": 1795220005,
            "now": 1795220010,
            "blocks": {},
            "names": {"id/issuer-rot": copy.deepcopy(hist_with_break_and_rot)},
            "txs": {atx: {"confirmed_height": anchor_h, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cenv)).hex(), "outputs": {}}},
        })
        return {"credential": cenv, "anchor_txid": atx, "chain": chain}

    add(
        "accept-0x0b-retired-key-a-before-cutoff-admit",
        ["SL-CONT-009", "SL-CONT-010"],
        "credential",
        _make_cred_and_chain(key_a, 749300, "a-pre"),
        "ADMIT",
        None,
        "Credential signed by compromised key A anchored strictly BEFORE h_c (749300 < 749400) MUST survive.",
    )
    add(
        "accept-0x0b-retired-key-a-at-cutoff-refuse",
        ["SL-CONT-009", "SL-CONT-010"],
        "credential",
        _make_cred_and_chain(key_a, 749500, "a-post"),
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "Credential signed by compromised key A anchored at/after h_c (749500 >= 749400) MUST refuse CRED_ISSUER_CLOSED.",
    )
    add(
        "accept-0x0b-successor-key-b-survives-break-a",
        ["SL-CONT-009", "SL-CONT-010"],
        "credential",
        _make_cred_and_chain(key_b, 749900, "b-post-rot"),
        "ADMIT",
        None,
        "Credential signed by rotated successor key B (installed at 749600, anchored at 749900) MUST survive a 0x0b break scoped strictly to retired key A.",
    )
    notary_env = sl.sign_envelope(
        {
            "act_kind": "fact-attestation",
            "attested_at": 1795220000,
            "details": {"fact_schema": "seallink/example", "fact_sha256": _h32("not-fact"), "kind": "fact-attestation"},
            "genesis": GENESIS_MAIN,
            "lifecycle": "eternal",
            "network": "main",
            "notary": {"name": "id/issuer-rot", "owner_policy": iss_owner_pol, "registration": iss_reg, "role_policy": {"m": 1, "pks": [key_notary["xonly"]]}},
            "target_sha256": _h32("not-tgt"),
            "tip_hash": _h32("0x0b-tip"),
            "tip_height": 749500,
            "type": "seallink-notary/1",
        },
        [key_notary["sk"]],
    )
    add(
        "accept-0x0b-other-role-notary-unaffected",
        ["SL-CONT-009", "SL-CONT-011"],
        "issuer_role",
        {
            "issuer_pin": notary_env["payload"]["notary"],
            "envelope": notary_env,
            "role": "notary",
            "anchor_height": 749500,
            "chain": _make_cred_and_chain(key_b, 749900, "notary-ctx")["chain"],
        },
        "ADMIT",
        None,
        "0x0b compromise break targeting role='cred' policy A MUST NOT close records signed under distinct role='notary'.",
    )

    # --- A2. Sibling-row row_ordinal quota accounting isolation + journal replay ---
    db = _build_delegation_base(pool_calls=10, row_cap_calls=2, c1_max_calls=1, c2_max_calls=2, c1_kind="revocable")
    inv_r1_1 = db["make_inv"](db["c1_id"], db["c1_itx"], db["keys"]["w1_k"], "sib-r1-1")
    inv_r2_1 = db["make_inv"](db["c2_id"], db["c2_itx"], db["keys"]["w1_k"], "sib-r2-1")
    inv_r2_2 = db["make_inv"](db["c2_id"], db["c2_itx"], db["keys"]["w1_k"], "sib-r2-2")
    inv_r2_3 = db["make_inv"](db["c2_id"], db["c2_itx"], db["keys"]["w1_k"], "sib-r2-3")
    q_calls_k = "seallink/count|station:id/station-a:tools|calls|term"
    add(
        "accept-sibling-rows-isolated-accounting-and-replay",
        ["SL-GRNT-007", "SL-GRNT-009", "SL-GRNT-014"],
        "sibling_rows_replay",
        {
            "chain": db["chain"],
            "journal": db["journal"],
            "executor_cfg": db["executor_cfg"],
            "steps": [
                {"label": "row1-call1", "invocation": inv_r1_1, "bundle": {"grants": [db["parent_env"], db["c1_env"]]}, "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "row2-call1", "invocation": inv_r2_1, "bundle": {"grants": [db["parent_env"], db["c2_env"]]}, "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "row2-call2", "invocation": inv_r2_2, "bundle": {"grants": [db["parent_env"], db["c2_env"]]}, "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "row2-call3-exceed", "invocation": inv_r2_3, "bundle": {"grants": [db["parent_env"], db["c2_env"]]}, "want_verdict": "REFUSE", "want_refusal": "QUOTA_EXCEEDED"},
            ],
            "check_balances": [
                {"scope": f"own:{db['c1_id']}", "qkey": q_calls_k, "bucket_id": "term", "expected": 1},
                {"scope": f"row:{db['parent_id']}:1", "qkey": q_calls_k, "bucket_id": "term", "expected": 1},
                {"scope": f"own:{db['c2_id']}", "qkey": q_calls_k, "bucket_id": "term", "expected": 2},
                {"scope": f"row:{db['parent_id']}:2", "qkey": q_calls_k, "bucket_id": "term", "expected": 2},
            ],
        },
        "ADMIT",
        None,
        "Sibling rows (ordinal 1 and ordinal 2) at one executor MUST track independent row accounts in live execution and persisted journal replay.",
    )

    # --- A3. Maximum-capacity Receipt (32 quotas x 2 accounts = 64 lines with window + row_ordinal) ---
    rcpt_signer = _kp("max-rcpt-signer")
    max_settlements: list[dict[str, Any]] = []
    for idx in range(32):
        win = "term" if idx == 0 else (f"blocks:{idx * 10}" if idx <= 16 else f"seconds:{idx * 60}")
        max_settlements.append({
            "account": "own",
            "kind": "seallink/count",
            "released": "0",
            "reserved": "1",
            "resource": "station:id/station-a:tools",
            "settled": "1",
            "unit": "calls",
            "window": win,
        })
        max_settlements.append({
            "account": "row",
            "kind": "seallink/count",
            "released": "0",
            "reserved": "1",
            "resource": "station:id/station-a:tools",
            "row_ordinal": 1,
            "settled": "1",
            "unit": "calls",
            "window": win,
        })
    max_rcpt_p = {
        "action": "agent/tool",
        "executor_name": "id/station-a",
        "genesis": GENESIS_MAIN,
        "grant_id": db["c1_id"],
        "invocation_id": _h32("max-rcpt-inv"),
        "network": "main",
        "outcome": "executed",
        "recorded_at": 1795220050,
        "result_sha256": _h32("max-rcpt-res"),
        "settlements": max_settlements,
        "tip_hash": _h32("del-tip"),
        "tip_height": 750110,
        "type": "seallink-receipt/1",
    }
    max_rcpt = sl.sign_envelope(max_rcpt_p, [rcpt_signer["sk"]])
    assert len(sl.jcs_encode(max_rcpt)) <= 65536
    add(
        "accept-receipt-max-32-quotas-64-settlements-admit",
        ["SL-GRNT-007", "SL-GRNT-008"],
        "raw_wire",
        {"object": max_rcpt, "expected_type": "seallink-receipt/1", "max_wire_bytes": 65536},
        "ADMIT",
        None,
        "Maximum-capacity receipt with 32 distinct-window quotas x 2 accounts (64 lines with account, row_ordinal, window) MUST pass Draft 2020-12 schema and fit well under 65536 B.",
    )
    rcpt_65 = sl.sign_envelope({**max_rcpt_p, "settlements": max_settlements + [max_settlements[0]]}, [rcpt_signer["sk"]])
    add(
        "accept-receipt-65-settlements-refused",
        ["SL-GRNT-008", "SL-WIRE-010"],
        "raw_wire",
        {"object": rcpt_65, "expected_type": "seallink-receipt/1"},
        "REFUSE",
        "WIRE_MEMBER",
        "Receipt exceeding 64 settlement lines MUST refuse WIRE_MEMBER under closed Draft 2020-12 schema.",
    )
    bad_row_no_ord = copy.deepcopy(max_settlements[1])
    del bad_row_no_ord["row_ordinal"]
    add(
        "accept-receipt-row-missing-ordinal-refused",
        ["SL-GRNT-007", "SL-GRNT-008"],
        "raw_wire",
        {"object": sl.sign_envelope({**max_rcpt_p, "settlements": [bad_row_no_ord]}, [rcpt_signer["sk"]]), "expected_type": "seallink-receipt/1"},
        "REFUSE",
        "WIRE_MEMBER",
        "Receipt settlement line with account='row' omitting row_ordinal MUST refuse WIRE_MEMBER.",
    )
    bad_own_ord = {**max_settlements[0], "row_ordinal": 1}
    add(
        "accept-receipt-own-unexpected-ordinal-refused",
        ["SL-GRNT-007", "SL-GRNT-008"],
        "raw_wire",
        {"object": sl.sign_envelope({**max_rcpt_p, "settlements": [bad_own_ord]}, [rcpt_signer["sk"]]), "expected_type": "seallink-receipt/1"},
        "REFUSE",
        "WIRE_MEMBER",
        "Receipt settlement line with account='own' carrying row_ordinal MUST refuse WIRE_MEMBER.",
    )
    bad_no_win = copy.deepcopy(max_settlements[0])
    del bad_no_win["window"]
    add(
        "accept-receipt-missing-window-refused",
        ["SL-GRNT-008"],
        "raw_wire",
        {"object": sl.sign_envelope({**max_rcpt_p, "settlements": [bad_no_win]}, [rcpt_signer["sk"]]), "expected_type": "seallink-receipt/1"},
        "REFUSE",
        "WIRE_MEMBER",
        "Receipt settlement line omitting mandatory window field MUST refuse WIRE_MEMBER.",
    )

    # ========================================================================
    # PART B — EXHAUSTIVE REFUSAL-BRANCH COVERAGE (Killing remaining mutants)
    # ========================================================================

    # --- Group 1: Journal continuity ---
    add("branch-continuity-witness-journal-id-mismatch", ["SL-GRNT-014"], "continuity",
        {"journal": {"journal_id": _h32("j1"), "witness_journal_id": _h32("j2")}}, "REFUSE", "JOURNAL_LOST",
        "Witness journal_id mismatch MUST refuse JOURNAL_LOST.")
    add("branch-continuity-pos-gap", ["SL-GRNT-014"], "continuity",
        {"journal": {"journal_id": _h32("j3"), "pos": 5, "witness_pos": 2}}, "REFUSE", "JOURNAL_LOST",
        "Journal position gap > 1 relative to external witness MUST refuse JOURNAL_LOST.")

    # --- Group 2: Wire bytes, object wire, wire semantics ---
    add("branch-wire-payload-not-dict", ["SL-WIRE-010"], "raw_wire",
        {"raw_bytes_utf8": '{"payload":1,"signatures":{}}'}, "REFUSE", "WIRE_MEMBER",
        "Non-object payload member MUST refuse WIRE_MEMBER.")
    add("branch-wire-missing-type-with-signatures", ["SL-WIRE-010"], "raw_wire",
        {"raw_bytes_utf8": '{"signatures":{}}'}, "REFUSE", "WIRE_TYPE",
        "Envelope with signatures but missing type MUST refuse WIRE_TYPE (W-9).")
    big_card = {"bio": "x" * 17000, "display_name": "Big", "kind": "person", "type": "seallink-card/1"}
    add("branch-wire-exceeds-type-max-bytes", ["SL-WIRE-001"], "raw_wire",
        {"raw_bytes_utf8": sl.jcs_encode(big_card).decode("utf-8")}, "REFUSE", "WIRE_SIZE",
        "Document exceeding registered per-type max_bytes (16384 B for card/1) MUST refuse WIRE_SIZE.")
    add("branch-wire-non-dict-object", ["SL-WIRE-002"], "raw_wire",
        {"object": [1, 2, 3]}, "REFUSE", "WIRE_JSON",
        "Non-object value passed to _verify_object_wire MUST refuse WIRE_JSON.")
    small_card = {
        "contact": "alice@example.org", "display": "Alice", "kind": "person", "name": "id/alice",
        "network": "main", "relays": [], "replaces": 0, "role": "owner", "seq": 1, "transports": [],
        "type": "seallink-card/1",
    }
    add("branch-wire-expected-type-mismatch", ["SL-WIRE-010"], "raw_wire",
        {"object": small_card, "expected_type": "seallink-manifest/1"}, "REFUSE", "WIRE_TYPE",
        "Object whose type differs from caller expected_type MUST refuse WIRE_TYPE.")

    fx0 = rm._base_invocation_fixture()
    g_base = copy.deepcopy(fx0["bundle"]["grants"][0])
    gp_nb = copy.deepcopy(g_base["payload"])
    gp_nb["not_before_height"] = gp_nb["not_after_height"]
    add("branch-wire-grant-nb-ge-na", ["SL-WIRE-007", "SL-GRNT-004"], "raw_wire",
        {"object": sl.sign_envelope(gp_nb, [fx0["_keys"]["alice_gr"]["sk"]])}, "REFUSE", "WIRE_INTEGER",
        "Grant with not_before_height >= not_after_height MUST refuse WIRE_INTEGER.")
    gp_ext = copy.deepcopy(g_base["payload"])
    gp_ext["capabilities"][0]["extensions"] = {"x": 1}
    add("branch-wire-grant-cap-extensions", ["SL-WIRE-015"], "raw_wire",
        {"object": sl.sign_envelope(gp_ext, [fx0["_keys"]["alice_gr"]["sk"]])}, "REFUSE", "WIRE_CONSTRAINT",
        "Grant capability with populated extensions MUST refuse WIRE_CONSTRAINT.")
    gp_qmax = copy.deepcopy(g_base["payload"])
    gp_qmax["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "99999999999999999999", "resource": "r", "unit": "u", "window": "term"}]
    add("branch-wire-grant-quota-max-overflow", ["SL-WIRE-008"], "raw_wire",
        {"object": sl.sign_envelope(gp_qmax, [fx0["_keys"]["alice_gr"]["sk"]])}, "REFUSE", "WIRE_INTEGER",
        "Grant quota max exceeding 2^64-1 MUST refuse WIRE_INTEGER.")
    dp_ext = copy.deepcopy(db["parent_env"]["payload"])
    dp_ext["delegate"]["groups"][0]["template"]["capabilities"][0]["extensions"] = {"x": 1}
    add("branch-wire-delegate-template-extensions", ["SL-WIRE-015"], "raw_wire",
        {"object": sl.sign_envelope(dp_ext, [db["keys"]["org_gr"]["sk"]])}, "REFUSE", "WIRE_CONSTRAINT",
        "Delegate template capability with extensions MUST refuse WIRE_CONSTRAINT.")
    dp_pred = copy.deepcopy(db["parent_env"]["payload"])
    dp_pred["delegate"]["groups"][0]["template"]["capabilities"][0]["where"] = {"tool_name": {"unknown_op": "x"}}
    add("branch-wire-delegate-template-bad-pred", ["SL-WIRE-016"], "raw_wire",
        {"object": sl.sign_envelope(dp_pred, [db["keys"]["org_gr"]["sk"]])}, "REFUSE", "WIRE_CONSTRAINT",
        "Delegate template capability with unknown predicate operator MUST refuse WIRE_CONSTRAINT.")
    of_dup = rm._base_origin_fixture()
    dup_c = copy.deepcopy(of_dup["contract"])
    dup_c["parties"].append(copy.deepcopy(dup_c["parties"][0]))
    add("branch-wire-contract-dup-party-id", ["SL-CONT-002"], "raw_wire",
        {"object": dup_c}, "REFUSE", "WIRE_MEMBER",
        "Contract with duplicate party_id MUST refuse WIRE_MEMBER.")

    # --- Group 3: Chain observation & rebracket (including split paired CHAIN_NODE_DISAGREEMENT!) ---
    ch_obs = copy.deepcopy(fx0["chain"])
    ch_obs["best_header_height"] = ch_obs["tip_height"] + 5
    add("branch-obs-header-lag", ["SL-LDGR-008"], "chain_obs", {"chain": ch_obs}, "REFUSE", "CHAIN_UNHEALTHY",
        "Node lagging behind best_header_height by > lag_limit MUST refuse CHAIN_UNHEALTHY.")
    ch_obs = copy.deepcopy(fx0["chain"])
    ch_obs["comparison_peers"] = [{"id": "peer-1", "healthy": True, "height": ch_obs["tip_height"] + 1, "hash_at_tip": ch_obs["tip_hash"]}]
    add("branch-obs-peer-higher-same-hash", ["SL-LDGR-008"], "chain_obs", {"chain": ch_obs}, "REFUSE", "CHAIN_NODE_DISAGREEMENT",
        "Comparison peer strictly ahead of local tip (even with same tip hash) MUST refuse CHAIN_NODE_DISAGREEMENT.")
    ch_obs = copy.deepcopy(fx0["chain"])
    ch_obs["comparison_peers"] = [{"id": "peer-1", "healthy": True, "height": ch_obs["tip_height"], "hash_at_tip": _h32("fork-hash")}]
    add("branch-obs-peer-same-height-diff-hash", ["SL-LDGR-008"], "chain_obs", {"chain": ch_obs}, "REFUSE", "CHAIN_NODE_DISAGREEMENT",
        "Comparison peer at identical height with divergent tip hash MUST refuse CHAIN_NODE_DISAGREEMENT.")
    ch_obs = copy.deepcopy(fx0["chain"])
    ch_obs["tip_header_time"] = ch_obs["now"] + 10000
    add("branch-obs-future-header-time", ["SL-LDGR-008"], "chain_obs", {"chain": ch_obs}, "REFUSE", "CHAIN_CLOCK_ERROR",
        "Block header timestamp further ahead than allowed skew MUST refuse CHAIN_CLOCK_ERROR.")
    ch_obs = copy.deepcopy(fx0["chain"])
    ch_obs["rebracket_tip"] = {"height": ch_obs["tip_height"], "hash": ch_obs["tip_hash"], "now": ch_obs["tip_first_sight"] + 10000}
    add("branch-rebracket-tip-stale", ["SL-LDGR-008"], "chain_obs", {"chain": ch_obs, "rebracket": True}, "REFUSE", "CHAIN_TIP_STALE",
        "Rebracket snapshot whose tip age exceeds freshness cutoff MUST refuse CHAIN_TIP_STALE.")

    # --- Group 4: Seals (standard & single-use) ---
    bad_pol = {"kind": "bad_kind", "pk": "00"}
    add("branch-seal-unsupported-script", ["SL-LDGR-004"], "seal",
        {"seal": {"script_policy": bad_pol, "txid": _h32("s1"), "vout": 0}, "chain": fx0["chain"]}, "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED",
        "Standard seal with unsupported ScriptPolicy template MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")
    good_seal = fx0["bundle"]["grants"][0]["payload"]["revocation"]["seal"]
    add("branch-seal-depth-insufficient", ["SL-LDGR-011"], "seal",
        {"seal": good_seal, "chain": fx0["chain"], "required_depth": 999}, "REFUSE", "SEAL_UNAVAILABLE",
        "Standard seal with confirmation depth < required_depth MUST refuse SEAL_UNAVAILABLE.")
    add("branch-su-seal-bad-script", ["SL-LDGR-004"], "single_use_seal",
        {"seal": {"script_policy": bad_pol, "txid": _h32("s2"), "vout": 0}, "invocation_content_addr": _h32("ic"), "chain": fx0["chain"]},
        "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED", "Single-use seal with invalid ScriptPolicy MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")
    add("branch-su-seal-wrong-template", ["SL-LDGR-004"], "single_use_seal",
        {"seal": good_seal, "invocation_content_addr": _h32("ic"), "chain": fx0["chain"]},
        "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED", "Single-use seal with non-single_use_1_of_2 template MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")
    su_db = _build_delegation_base(c1_kind="single_use")
    su_seal = su_db["c1_env"]["payload"]["revocation"]["seal"]
    ch_su = copy.deepcopy(su_db["chain"])
    del ch_su["txs"][su_seal["txid"]]
    add("branch-su-seal-missing-tx", ["SL-LDGR-011"], "single_use_seal",
        {"seal": su_seal, "invocation_content_addr": _h32("ic"), "chain": ch_su},
        "REFUSE", "SEAL_UNAVAILABLE", "Single-use seal whose funding tx is unknown MUST refuse SEAL_UNAVAILABLE.")
    add("branch-su-seal-unspent-awaiting", ["SL-LDGR-012"], "single_use_seal",
        {"seal": su_seal, "invocation_content_addr": _h32("ic"), "chain": su_db["chain"]},
        "REFUSE", "SEAL_UNAVAILABLE", "Unspent single-use seal awaiting grantee 0x11 spend MUST refuse SEAL_UNAVAILABLE.")
    ch_su2 = copy.deepcopy(su_db["chain"])
    su_spend = _h32("su-spend-wrong-use")
    ch_su2["txs"][su_seal["txid"]]["outputs"]["0"]["spent_by_txid"] = su_spend
    ch_su2["txs"][su_spend] = {
        "confirmed_height": 750105,
        "inputs": [sv.make_single_use_spend_input(su_seal, branch=0)],
        "opreturn_hex": sl.encode_opreturn(0x11, _h32("other-ic")).hex(),
        "outputs": {},
    }
    add("branch-su-seal-wrong-use-txid-or-commit", ["SL-LDGR-012"], "single_use_seal",
        {"seal": su_seal, "use_txid": _h32("expected-use"), "invocation_content_addr": _h32("ic"), "chain": ch_su2},
        "REFUSE", "SEAL_SPENT", "Single-use branch-0 spend with wrong use_txid or 0x11 commitment MUST refuse SEAL_SPENT.")

    # --- Group 5: Name parsing, history, role policies, issuer lookup & manifests ---
    def _name_chain(upd_override: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        c = copy.deepcopy(fx0["chain"])
        upd_override(c["names"]["id/alice"])
        return c

    add("branch-name-non-str-script", ["SL-LDGR-005"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n["updates"][-1].__setitem__("output_script_hex", 123))},
        "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED", "Non-string output_script_hex MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")
    add("branch-name-bad-hex-script", ["SL-LDGR-005"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n["updates"][-1].__setitem__("output_script_hex", "zzzz"))},
        "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED", "Malformed output_script_hex MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")
    wrong_name_scr = sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(fx0["_alice_owner_pol"])[0], name=b"id/other", value=b"{}").hex()
    add("branch-name-script-wrong-name", ["SL-LDGR-005"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n["updates"][-1].__setitem__("output_script_hex", wrong_name_scr))},
        "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED", "Name output script carrying different name than queried MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")
    big_val_scr = sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(fx0["_alice_owner_pol"])[0], name=b"id/alice", value=(b'{"x":"' + b"a" * 520 + b'"}')).hex()
    add("branch-name-value-over-520b", ["SL-IDEN-001"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n["updates"][-1].__setitem__("output_script_hex", big_val_scr))},
        "REFUSE", "NAME_VALUE_INVALID", "Name value exceeding 520 bytes MUST refuse NAME_VALUE_INVALID.")
    bad_jcs_scr = sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(fx0["_alice_owner_pol"])[0], name=b"id/alice", value=b"{ invalid").hex()
    add("branch-name-value-bad-jcs", ["SL-IDEN-001"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n["updates"][-1].__setitem__("output_script_hex", bad_jcs_scr))},
        "REFUSE", "NAME_VALUE_INVALID", "Non-canonical/invalid JSON in name value MUST refuse NAME_VALUE_INVALID.")
    dup_rk = fx0["_keys"]["alice_gr"]["xonly"]
    dup_rk_scr = sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(fx0["_alice_owner_pol"])[0], name=b"id/alice", value=sl.jcs_encode({"link": {"cred": dup_rk, "grant": dup_rk}})).hex()
    add("branch-name-duplicate-role-key", ["SL-IDEN-003"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n["updates"][-1].__setitem__("output_script_hex", dup_rk_scr))},
        "REFUSE", "NAME_VALUE_INVALID", "Reusing the same key across link.grant and link.cred MUST refuse NAME_VALUE_INVALID.")
    add("branch-name-wrong-registration", ["SL-IDEN-004"], "name_resolve",
        {"name": "id/alice", "expected_registration": {"txid": _h32("wrong-reg"), "vout": 0}, "chain": fx0["chain"]},
        "REFUSE", "NAME_OWNER_MISMATCH", "Name registration mismatch MUST refuse NAME_OWNER_MISMATCH.")
    add("branch-name-empty-updates", ["SL-IDEN-004"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n.__setitem__("updates", []))},
        "REFUSE", "NAME_HISTORY_UNAVAILABLE", "Empty updates list MUST refuse NAME_HISTORY_UNAVAILABLE.")
    add("branch-name-first-update-reg-mismatch", ["SL-IDEN-004"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n["updates"][0].__setitem__("txid", _h32("bad-first")))},
        "REFUSE", "NAME_HISTORY_UNAVAILABLE", "updates[0] not matching registration outpoint MUST refuse NAME_HISTORY_UNAVAILABLE.")
    add("branch-name-broken-update-chain", ["SL-IDEN-004"], "name_resolve",
        {"name": "id/alice", "chain": _name_chain(lambda n: n["updates"][1]["prev_input"].__setitem__("txid", _h32("broken-link")))},
        "REFUSE", "NAME_HISTORY_UNAVAILABLE", "Broken prev_input chain between name updates MUST refuse NAME_HISTORY_UNAVAILABLE.")
    add("branch-name-at-height-before-first", ["SL-IDEN-004"], "name_resolve",
        {"name": "id/alice", "at_height": 100, "chain": fx0["chain"]},
        "REFUSE", "NAME_HISTORY_UNAVAILABLE", "Historical lookup before first name confirmation MUST refuse NAME_HISTORY_UNAVAILABLE.")
    add("branch-name-bad-expected-owner-policy", ["SL-LDGR-004"], "name_resolve",
        {"name": "id/alice", "expected_owner_policy": bad_pol, "chain": fx0["chain"]},
        "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED", "Invalid expected_owner_policy MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")

    # Role policy branches
    ch_rp_bad = _name_chain(lambda n: n["updates"][0].__setitem__("output_script_hex", bad_jcs_scr))
    add("branch-role-bad-history-value", ["SL-IDEN-004"], "name_resolve",
        {"name": "id/alice", "check_role": "grant", "recent_block_height": 749000, "chain": ch_rp_bad},
        "REFUSE", "NAME_VALUE_INVALID", "Corrupted update value encountered during role continuity walk MUST refuse NAME_VALUE_INVALID.")
    add("branch-role-missing-entry", ["SL-IDEN-003"], "name_resolve",
        {"name": "id/alice", "check_role": "notary", "chain": fx0["chain"]},
        "REFUSE", "NAME_ROLE_CHANGED", "Absent link.<role> entry MUST refuse NAME_ROLE_CHANGED.")
    kp_pol = {"m": 1, "pks": [fx0["_keys"]["alice_gr"]["xonly"]]}
    kp_hash = sl.sha256(sl.jcs_encode(kp_pol)).hex()
    ch_kp = copy.deepcopy(fx0["chain"])
    ch_kp["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx0["_alice_reg"], fx0["_alice_owner_pol"], {"link": {"grant": {"p": kp_hash}}}, first_height=748000, update_height=749000
    )
    add("branch-role-kp-missing-presented", ["SL-IDEN-003"], "name_resolve",
        {"name": "id/alice", "check_role": "grant", "chain": ch_kp},
        "REFUSE", "WIRE_SIGNATURE", "Hash-pinned role policy without presented_role_policy MUST refuse WIRE_SIGNATURE.")
    add("branch-role-kp-wrong-presented", ["SL-IDEN-003"], "name_resolve",
        {"name": "id/alice", "check_role": "grant", "presented_role_policy": {"m": 1, "pks": [_kp("wrong-kp")["xonly"]]}, "chain": ch_kp},
        "REFUSE", "WIRE_SIGNATURE", "Hash-pinned role policy with mismatched presented_role_policy MUST refuse WIRE_SIGNATURE.")
    ch_bad_re = copy.deepcopy(fx0["chain"])
    ch_bad_re["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx0["_alice_reg"], fx0["_alice_owner_pol"], {"link": {"grant": 42}}, first_height=748000, update_height=749000
    )
    add("branch-role-malformed-entry", ["SL-IDEN-003"], "name_resolve",
        {"name": "id/alice", "check_role": "grant", "chain": ch_bad_re},
        "REFUSE", "NAME_VALUE_INVALID", "Malformed non-string/non-pin link.<role> MUST refuse NAME_VALUE_INVALID.")
    add("branch-role-presented-mismatch-plain", ["SL-IDEN-003"], "name_resolve",
        {"name": "id/alice", "check_role": "grant", "presented_role_policy": {"m": 1, "pks": [_kp("wrong-plain")["xonly"]]}, "chain": fx0["chain"]},
        "REFUSE", "WIRE_SIGNATURE", "Presented role policy differing from plain on-chain role key MUST refuse WIRE_SIGNATURE.")
    add("branch-issuer-role-missing-name", ["SL-ORIG-002"], "issuer_role",
        {"issuer_pin": {"name": "id/ghost-issuer", "owner_policy": iss_owner_pol, "registration": iss_reg, "role_policy": {"m": 1, "pks": [key_a["xonly"]]}},
         "envelope": notary_env, "role": "cred", "anchor_height": 749500, "chain": fx0["chain"]},
        "REFUSE", "NAME_NOT_FOUND", "verify_issuer_role_at_height with missing issuer name MUST refuse NAME_NOT_FOUND.")

    # Manifest branches (split hash-mismatch vs owner/seq-mismatch!)
    ch_no_m = copy.deepcopy(fx0["chain"])
    ch_no_m["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx0["_alice_reg"], fx0["_alice_owner_pol"], {"link": {"grant": fx0["_keys"]["alice_gr"]["xonly"]}}, first_height=748000, update_height=749000
    )
    add("branch-manifest-missing-pin", ["SL-IDEN-006"], "name_resolve",
        {"name": "id/alice", "check_manifest": True, "chain": ch_no_m},
        "REFUSE", "MANIFEST_UNAVAILABLE", "Name value omitting m pin MUST refuse MANIFEST_UNAVAILABLE.")
    man_tampered = copy.deepcopy(fx0["_alice_man"])
    man_tampered["providers"][0]["label"] = "tampered"  # same owner/network/seq, different content_addr!
    add("branch-manifest-hash-mismatch-only", ["SL-IDEN-006"], "name_resolve",
        {"name": "id/alice", "check_manifest": True, "manifests": {"id/alice": man_tampered}, "chain": fx0["chain"]},
        "REFUSE", "MANIFEST_MISMATCH", "Manifest with matching owner/seq but wrong content_addr MUST refuse MANIFEST_MISMATCH.")
    man_wrong_seq = copy.deepcopy(fx0["_alice_man"])
    man_wrong_seq["seq"] = 99
    ch_ws = copy.deepcopy(fx0["chain"])
    ch_ws["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx0["_alice_reg"], fx0["_alice_owner_pol"],
        {"link": {"grant": fx0["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(man_wrong_seq), "s": 1}},
        first_height=748000, update_height=749000,
    )
    add("branch-manifest-seq-mismatch-only", ["SL-IDEN-006"], "name_resolve",
        {"name": "id/alice", "check_manifest": True, "manifests": {sl.content_addr(man_wrong_seq): man_wrong_seq}, "chain": ch_ws},
        "REFUSE", "MANIFEST_MISMATCH", "Manifest with matching content_addr but seq != m.s MUST refuse MANIFEST_MISMATCH.")

    # --- Group 6: Auth challenge & Owner commands ---
    auth_k = _kp("auth-br-k")
    chlg = sl.sign_envelope(
        {"auth_pubkey": auth_k["xonly"], "expires_at": 1795220100, "issued_at": 1795220000, "nonce": _h32("ac-n"), "service_id": "mail.example", "type": "seallink-auth-challenge/1"},
        [auth_k["sk"]],
    )
    add("branch-auth-challenge-wrong-service-id", ["SL-IDEN-010"], "auth_challenge",
        {"challenge": chlg, "service_id": "other.example", "journal": {"journal_id": _h32("ac-j"), "auth_nonces": {_h32("ac-n"): {"service_id": "other.example", "used": False, "issued_at": 1795220000, "expires_at": 1795220100}}}, "chain": fx0["chain"]},
        "REFUSE", "AUTH_CHALLENGE_INVALID", "Auth challenge bound to different service_id MUST refuse AUTH_CHALLENGE_INVALID.")

    dev1 = _kp("oc-dev1")
    dev2 = _kp("oc-dev2")
    dseal_pol = {"kind": "key", "pk": _kp("oc-dseal")["comp"]}
    dseal_tx = _h32("oc-dseal-tx")
    ch_oc = copy.deepcopy(fx0["chain"])
    ch_oc["txs"][dseal_tx] = {"confirmed_height": 749990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(dseal_pol)}}}
    dev_list_br = {
        "devices": [
            {"alg": "bip340", "ceiling": 1, "key": dev1["xonly"], "label": "dev1", "presence": False, "seal": {"script_policy": dseal_pol, "txid": dseal_tx, "vout": 0}},
            {"alg": "bip340", "ceiling": 2, "key": dev2["xonly"], "label": "dev2", "presence": False, "seal": {"script_policy": dseal_pol, "txid": dseal_tx, "vout": 0}},
        ],
        "network": "main",
        "owner": "id/alice",
        "seq": 1,
        "type": "seallink-device-list/1",
    }
    oc_base = {
        "arguments": {"brief_sha256": _h32("oc-brf"), "run_id": "run-1"}, "command": "agent-dispatch", "exp": 1795220300, "genesis": GENESIS_MAIN,
        "iat": 1795220000, "level": 0, "network": "main", "nonce": _h32("oc-1"),
        "owner": "id/alice", "target_executor": "id/station-a", "type": "seallink-owner-command/1",
    }
    add("branch-oc-foreign-service-refused", ["SL-IDEN-011"], "owner_command",
        {"command": sl.sign_envelope(oc_base, [dev1["sk"]]), "device_list": dev_list_br, "is_foreign_service": True, "chain": ch_oc},
        "REFUSE", "DEVICE_UNAUTHORIZED", "Valid L0 owner command presented to foreign service MUST refuse DEVICE_UNAUTHORIZED.")
    add("branch-oc-chain-mismatch", ["SL-IDEN-011"], "owner_command",
        {"command": sl.sign_envelope({**oc_base, "genesis": _h32("wrong-gen")}, [dev1["sk"]]), "device_list": dev_list_br, "is_foreign_service": False, "chain": ch_oc},
        "REFUSE", "CHAIN_MISMATCH", "Owner command for wrong genesis MUST refuse CHAIN_MISMATCH.")
    add("branch-oc-expired", ["SL-IDEN-011"], "owner_command",
        {"command": sl.sign_envelope({**oc_base, "iat": 1795210000, "exp": 1795210100}, [dev1["sk"]]), "device_list": dev_list_br, "is_foreign_service": False, "chain": ch_oc},
        "REFUSE", "INVOKE_TIME_INVALID", "Expired owner command MUST refuse INVOKE_TIME_INVALID.")
    add("branch-oc-multisig-disallowed", ["SL-IDEN-011"], "owner_command",
        {"command": sl.sign_envelope(oc_base, [dev1["sk"], dev2["sk"]], m=2), "device_list": dev_list_br, "is_foreign_service": False, "chain": ch_oc},
        "REFUSE", "DEVICE_UNAUTHORIZED", "Owner command signed by 2-of-2 instead of 1 enrolled device key MUST refuse DEVICE_UNAUTHORIZED.")
    add("branch-oc-unknown-device", ["SL-IDEN-011"], "owner_command",
        {"command": sl.sign_envelope(oc_base, [_kp("oc-stranger")["sk"]]), "device_list": dev_list_br, "is_foreign_service": False, "chain": ch_oc},
        "REFUSE", "DEVICE_UNAUTHORIZED", "Owner command from unenrolled device key MUST refuse DEVICE_UNAUTHORIZED.")
    add("branch-oc-level-exceeds-ceiling", ["SL-IDEN-011"], "owner_command",
        {"command": sl.sign_envelope({**oc_base, "level": 2}, [dev1["sk"]]), "device_list": dev_list_br, "is_foreign_service": False, "chain": ch_oc},
        "REFUSE", "DEVICE_UNAUTHORIZED", "Owner command level exceeding device ceiling MUST refuse DEVICE_UNAUTHORIZED.")
    oc_l2_nopres = {**oc_base, "command": "policy-apply", "level": 2, "arguments": {"config_sha256": _h32("c"), "statement_id": _h32("s")}}
    add("branch-oc-policy-apply-requires-presence", ["SL-IDEN-011"], "owner_command",
        {"command": sl.sign_envelope(oc_l2_nopres, [dev2["sk"]]), "device_list": dev_list_br, "is_foreign_service": False, "chain": ch_oc},
        "REFUSE", "DEVICE_UNAUTHORIZED", "L2 policy-apply from device without user-presence verification MUST refuse DEVICE_UNAUTHORIZED.")

    # --- Group 7: Origin, Recovery, Status, Roster & Ward Approvals ---
    of = rm._base_origin_fixture()
    add("branch-origin-missing-envelope", ["SL-ORIG-002"], "origin_status",
        {"origin_bundle": {}, "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Missing origin envelope MUST refuse ORIGIN_UNVERIFIED.")
    of_gen = rm._base_origin_fixture()
    of_gen["origin_bundle"]["origin"] = sl.sign_envelope({**of_gen["origin_bundle"]["origin"]["payload"], "genesis": _h32("bad-og")}, [of_gen["_keys"]["reg_cred"]["sk"]])
    add("branch-origin-chain-mismatch", ["SL-ORIG-002"], "origin_status",
        {"origin_bundle": of_gen["origin_bundle"], "chain": of_gen["chain"], "trusted_origin_issuer_pins": of_gen["trusted_origin_issuer_pins"]},
        "REFUSE", "CHAIN_MISMATCH", "Origin with wrong genesis MUST refuse CHAIN_MISMATCH.")
    of_cd = rm._base_origin_fixture()
    of_cd["origin_bundle"]["card"] = {
        "contact": "org@example.org", "display": "Wrong", "kind": "organization", "name": "id/child-leo",
        "network": "main", "relays": [], "replaces": 0, "role": "ward", "seq": 1, "transports": [],
        "type": "seallink-card/1",
    }
    add("branch-origin-card-kind-mismatch", ["SL-ORIG-002"], "origin_status",
        {"origin_bundle": of_cd["origin_bundle"], "chain": of_cd["chain"], "trusted_origin_issuer_pins": of_cd["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Entity card kind mismatching origin_class MUST refuse ORIGIN_UNVERIFIED.")
    of_anc = rm._base_origin_fixture()
    of_anc["chain"]["txs"][of_anc["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, _h32("wrong-orig-ca")).hex()
    add("branch-origin-bad-0x09-anchor", ["SL-ORIG-002"], "origin_status",
        {"origin_bundle": of_anc["origin_bundle"], "chain": of_anc["chain"], "trusted_origin_issuer_pins": of_anc["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Origin 0x09 commitment mismatch MUST refuse ORIGIN_UNVERIFIED.")
    of_noi = rm._base_origin_fixture()
    del of_noi["chain"]["names"]["id/civil-registry"]
    add("branch-origin-missing-issuer-name", ["SL-ORIG-002"], "origin_status",
        {"origin_bundle": of_noi["origin_bundle"], "chain": of_noi["chain"], "trusted_origin_issuer_pins": of_noi["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Origin whose issuer name is missing on chain MUST refuse ORIGIN_UNVERIFIED.")
    of_nb = rm._base_origin_fixture()
    del of_nb["origin_bundle"]["name_binding"]
    add("branch-origin-missing-binding", ["SL-ORIG-003"], "origin_status",
        {"origin_bundle": of_nb["origin_bundle"], "chain": of_nb["chain"], "trusted_origin_issuer_pins": of_nb["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_BINDING_INVALID", "Missing name_binding MUST refuse ORIGIN_BINDING_INVALID.")
    of_seq2 = rm._base_origin_fixture()
    nr_s2 = of_seq2["origin_bundle"]["origin"]["payload"]["name_recovery"]
    of_seq2["origin_bundle"]["name_binding"].update({
        "binding_mode": "recovery",
        "next_recovery_policy": {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(nr_s2["disposer_pk"], nr_s2["arbiter_pk"])},
        "next_recovery_vout": 0,
        "seq": 2,
        "supersedes_binding_id": _h32("fake-prev-binding"),
    })
    add("branch-origin-initial-binding-seq-not-1", ["SL-ORIG-003"], "origin_status",
        {"origin_bundle": of_seq2["origin_bundle"], "chain": of_seq2["chain"], "trusted_origin_issuer_pins": of_seq2["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_BINDING_INVALID", "Initial name_binding with seq != 1 MUST refuse ORIGIN_BINDING_INVALID.")
    of_beh = rm._base_origin_fixture()
    of_beh["chain"]["txs"][of_beh["origin_bundle"]["name_binding_txid"]]["confirmed_height"] = 749000  # <= h_origin 749000!
    add("branch-origin-binding-before-origin", ["SL-ORIG-003"], "origin_status",
        {"origin_bundle": of_beh["origin_bundle"], "chain": of_beh["chain"], "trusted_origin_issuer_pins": of_beh["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_BINDING_INVALID", "Initial name_binding confirmed <= h_origin MUST refuse ORIGIN_BINDING_INVALID.")

    # Recovery branches
    of_rnone = rm._base_origin_fixture()
    op_none = copy.deepcopy(of_rnone["origin_bundle"]["origin"]["payload"])
    op_none.pop("guardian_policy", None)
    op_none["claims"].pop("majority_commitment", None)
    op_none["name_recovery"] = {"mode": "none"}
    o_none = sl.sign_envelope(op_none, [of_rnone["_keys"]["reg_cred"]["sk"]])
    oid_none = sl.object_id(op_none)
    of_rnone["origin_bundle"]["origin"] = o_none
    of_rnone["origin_bundle"].pop("guardian_records", None)
    of_rnone["origin_bundle"].pop("guardian_assents", None)
    of_rnone["origin_bundle"].pop("initial_guardian_disclosures", None)
    of_rnone["origin_bundle"].pop("opened_majority_unix", None)
    of_rnone["origin_bundle"]["name_binding"]["origin_id"] = oid_none
    of_rnone["chain"]["txs"][of_rnone["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_none)).hex()
    of_rnone["chain"]["txs"][of_rnone["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_rnone["origin_bundle"]["name_binding"])).hex()
    of_rnone["origin_bundle"]["recovery_bindings"] = [copy.deepcopy(of_rnone["origin_bundle"]["name_binding"])]
    add("branch-recovery-forbidden-under-mode-none", ["SL-ORIG-013"], "origin_status",
        {"origin_bundle": of_rnone["origin_bundle"], "chain": of_rnone["chain"], "trusted_origin_issuer_pins": of_rnone["trusted_origin_issuer_pins"]},
        "REFUSE", "RECOVERY_FORBIDDEN", "Presenting recovery_bindings under autonomous name_recovery.mode='none' MUST refuse RECOVERY_FORBIDDEN.")

    of_rs = rm._base_origin_fixture()
    op_rs = copy.deepcopy(of_rs["origin_bundle"]["origin"]["payload"])
    op_rs["name_recovery"]["recovery_seal"]["script_policy"] = {"kind": "key", "pk": of_rs["_keys"]["disp"]["comp"]}
    o_rs = sl.sign_envelope(op_rs, [of_rs["_keys"]["reg_cred"]["sk"]])
    of_rs["origin_bundle"]["origin"] = o_rs
    of_rs["origin_bundle"]["name_binding"]["origin_id"] = sl.object_id(op_rs)
    of_rs["chain"]["txs"][of_rs["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_rs)).hex()
    of_rs["chain"]["txs"][of_rs["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_rs["origin_bundle"]["name_binding"])).hex()
    add("branch-recovery-seal-script-mismatch", ["SL-ORIG-014"], "origin_status",
        {"origin_bundle": of_rs["origin_bundle"], "chain": of_rs["chain"], "trusted_origin_issuer_pins": of_rs["trusted_origin_issuer_pins"]},
        "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED", "Recovery seal script not matching both_of_2(disposer, arbiter) MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")

    of_rmiss = rm._base_origin_fixture()
    del of_rmiss["chain"]["txs"][of_rmiss["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"]]
    add("branch-recovery-missing-outpoint", ["SL-ORIG-014"], "origin_status",
        {"origin_bundle": of_rmiss["origin_bundle"], "chain": of_rmiss["chain"], "trusted_origin_issuer_pins": of_rmiss["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Missing recovery_seal outpoint MUST refuse ORIGIN_STATUS_INCOMPLETE.")

    def _rec_spend_fixture(*, bad_opret: bool = False, bad_seq: bool = False, miss_next_out: bool = False, tip_h: int = 750010) -> dict[str, Any]:
        o2 = rm._base_origin_fixture()
        nr = o2["origin_bundle"]["origin"]["payload"]["name_recovery"]
        rec_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(nr["disposer_pk"], nr["arbiter_pk"])}
        cand = {
            **copy.deepcopy(o2["origin_bundle"]["name_binding"]),
            "binding_mode": "recovery",
            "name": "id/child-leo-rec",
            "seq": 3 if bad_seq else 2,
            "supersedes_binding_id": sl.object_id(o2["origin_bundle"]["name_binding"]),
            "next_recovery_vout": 0,
            "next_recovery_policy": rec_pol,
            "registration": {"txid": _h32("rec-new-reg"), "vout": 0},
        }
        rtx_id = _h32("br-rec-spend-tx")
        o2["chain"]["txs"][o2["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_id
        o2["chain"]["txs"][rtx_id] = {
            "confirmed_height": 750000,
            "opreturn_hex": sl.encode_opreturn(0x09, sl.object_id(cand)).hex() if bad_opret else sl.encode_opreturn(0x0C, sl.object_id(cand)).hex(),
            "outputs": {} if miss_next_out else {"0": {"script_pubkey_hex": _spk_hex(rec_pol)}},
        }
        o2["chain"]["tip_height"] = tip_h
        o2["chain"]["comparison_peers"] = [{"id": "peer-1", "healthy": True, "height": tip_h, "hash_at_tip": o2["chain"]["tip_hash"]}]
        o2["origin_bundle"]["recovery_bindings"] = [cand]
        return o2

    # Decision D-1: malformed recovery_seal spend burns ONLY the recovery line (`recovery_burned=True`)
    # while preserving confirmed binding B_k; asserting the malformed candidate itself refuses RECOVERY_FORBIDDEN.
    for cid_r, kw_r, note_r in [
        ("branch-recovery-bad-0x0c-tx", {"bad_opret": True}, "Malformed recovery spend without 0x0c OP_RETURN burns recovery line while preserving active binding B_1 (D-1)."),
        ("branch-recovery-bad-candidate-seq", {"bad_seq": True}, "Recovery candidate with non-increasing seq burns recovery line while preserving active binding B_1 (D-1)."),
        ("branch-recovery-missing-next-seal", {"miss_next_out": True}, "Recovery spend missing continuation output burns recovery line while preserving active binding B_1 (D-1)."),
    ]:
        orf = _rec_spend_fixture(**kw_r)
        b1_id = sl.object_id(orf["origin_bundle"]["name_binding"])
        add(cid_r, ["SL-ORIG-014"], "origin_status",
            {"origin_bundle": orf["origin_bundle"], "chain": orf["chain"], "trusted_origin_issuer_pins": orf["trusted_origin_issuer_pins"],
             "assert_binding_id": b1_id, "expect_recovery_burned": True},
            "ADMIT_WARD", None, note_r)
    orf_del = _rec_spend_fixture(tip_h=750010)
    add("branch-recovery-delay-not-elapsed", ["SL-ORIG-014"], "origin_status",
        {"origin_bundle": orf_del["origin_bundle"], "chain": orf_del["chain"], "trusted_origin_issuer_pins": orf_del["trusted_origin_issuer_pins"]},
        "REFUSE", "RECOVERY_FORBIDDEN", "Un-cancelled recovery before h_rec + delay_blocks MUST refuse RECOVERY_FORBIDDEN.")

    # Status spine branches
    of_sm = rm._base_origin_fixture()
    del of_sm["chain"]["txs"][of_sm["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]
    add("branch-status-missing-seal-out", ["SL-ORIG-002"], "origin_status",
        {"origin_bundle": of_sm["origin_bundle"], "chain": of_sm["chain"], "trusted_origin_issuer_pins": of_sm["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Missing status_seal outpoint MUST refuse ORIGIN_STATUS_INCOMPLETE.")
    of_sbad = rm._base_origin_fixture()
    end_for_bad = sl.sign_envelope(
        {
            "basis_sha256": _h32("end-basis-bad"),
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": of_sbad["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "origin_id": of_sbad["_origin_id"],
            "reason": "dissolution",
            "status_prev_outpoint": {"txid": of_sbad["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": 0},
            "type": "seallink-end/1",
        },
        [of_sbad["_keys"]["reg_cred"]["sk"]],
    )
    stx_b = _h32("stx-bad-opret")
    of_sbad["chain"]["txs"][of_sbad["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = stx_b
    of_sbad["chain"]["txs"][stx_b] = {"confirmed_height": 749600, "opreturn_hex": sl.encode_opreturn(0x0C, sl.content_addr(end_for_bad)).hex(), "outputs": {}}
    of_sbad["origin_bundle"]["end_record"] = end_for_bad
    add("branch-status-bad-0x09-spend", ["SL-ORIG-002"], "origin_status",
        {"origin_bundle": of_sbad["origin_bundle"], "chain": of_sbad["chain"], "trusted_origin_issuer_pins": of_sbad["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Status seal spend without 0x09 OP_RETURN MUST refuse ORIGIN_STATUS_INCOMPLETE.")

    of_end_oid = rm._base_origin_fixture()
    end_bad = sl.sign_envelope(
        {
            "basis_sha256": _h32("end-basis-oid"),
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": of_end_oid["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "origin_id": _h32("other-oid"),
            "reason": "dissolution",
            "status_prev_outpoint": {"txid": of_end_oid["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": 0},
            "type": "seallink-end/1",
        },
        [of_end_oid["_keys"]["reg_cred"]["sk"]],
    )
    stx_e = _h32("stx-end-oid")
    of_end_oid["chain"]["txs"][of_end_oid["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = stx_e
    of_end_oid["chain"]["txs"][stx_e] = {"confirmed_height": 749600, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(end_bad)).hex(), "outputs": {}}
    of_end_oid["origin_bundle"]["end_record"] = end_bad
    add("branch-status-end-wrong-origin-id", ["SL-ORIG-012"], "origin_status",
        {"origin_bundle": of_end_oid["origin_bundle"], "chain": of_end_oid["chain"], "trusted_origin_issuer_pins": of_end_oid["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "seallink-end/1 with mismatched origin_id MUST refuse ORIGIN_STATUS_INCOMPLETE.")

    def _cap_fixture(*, wrong_oid: bool = False, wrong_auth: bool = False, miss_nxt: bool = False) -> dict[str, Any]:
        oc = rm._base_origin_fixture()
        other_iss = _kp("cap-other-auth")
        if wrong_auth:
            op2 = copy.deepcopy(oc["origin_bundle"]["origin"]["payload"])
            op2["capacity_authority"] = {"name": "id/court-auth", "owner_policy": op2["issuer"]["owner_policy"], "registration": {"txid": _h32("court-reg"), "vout": 0}}
            o2 = sl.sign_envelope(op2, [oc["_keys"]["reg_cred"]["sk"]])
            oc["origin_bundle"]["origin"] = o2
            oc["_origin_id"] = sl.object_id(op2)
            oc["origin_bundle"]["name_binding"]["origin_id"] = oc["_origin_id"]
            oc["chain"]["txs"][oc["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o2)).hex()
            oc["chain"]["txs"][oc["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(oc["origin_bundle"]["name_binding"])).hex()
        nxt_pol = {"kind": "key", "pk": other_iss["comp"]}
        cp = {
            "basis_sha256": _h32("cap-basis"),
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": oc["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "next_status_policy": nxt_pol,
            "next_status_vout": 0,
            "origin_id": _h32("wrong-cap-oid") if wrong_oid else oc["_origin_id"],
            "status_prev_outpoint": {"txid": oc["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": 0},
            "subject_new_owner_policy": {"kind": "key", "pk": _kp("emanc-subj")["comp"]},
            "type": "seallink-capacity/1",
        }
        crec = sl.sign_envelope(cp, [oc["_keys"]["reg_cred"]["sk"]])
        stx_c = _h32(f"stx-cap-{wrong_oid}-{wrong_auth}-{miss_nxt}")
        oc["chain"]["txs"][oc["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = stx_c
        wrong_ns_spk = _spk_hex({"kind": "key", "pk": _kp("wrong-ns-pk")["comp"]})
        oc["chain"]["txs"][stx_c] = {
            "confirmed_height": 749600,
            "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(crec)).hex(),
            "outputs": {"0": {"script_pubkey_hex": wrong_ns_spk}} if miss_nxt else {"0": {"script_pubkey_hex": _spk_hex(nxt_pol)}},
        }
        oc["origin_bundle"]["capacity_record"] = crec
        return oc

    for cid_c, kw_c, note_c in [
        ("branch-status-cap-wrong-origin-id", {"wrong_oid": True}, "seallink-capacity/1 with wrong origin_id MUST refuse ORIGIN_STATUS_INCOMPLETE."),
        ("branch-status-cap-wrong-authority", {"wrong_auth": True}, "seallink-capacity/1 issued by name != capacity_authority MUST refuse ORIGIN_STATUS_INCOMPLETE."),
        ("branch-status-cap-missing-next-seal", {"miss_nxt": True}, "seallink-capacity/1 spend omitting next_status_vout output MUST refuse ORIGIN_STATUS_INCOMPLETE."),
    ]:
        ocf = _cap_fixture(**kw_c)
        add(cid_c, ["SL-ORIG-002", "SL-ORIG-009"], "origin_status",
            {"origin_bundle": ocf["origin_bundle"], "chain": ocf["chain"], "trusted_origin_issuer_pins": ocf["trusted_origin_issuer_pins"]},
            "REFUSE", "ORIGIN_STATUS_INCOMPLETE", note_c)

    of_maj = rm._base_origin_fixture()
    of_maj["origin_bundle"]["opened_majority_unix"] = 1900000000
    of_maj["origin_bundle"]["majority_salt_hex"] = _h32("wrong-maj-salt")
    add("branch-origin-bad-majority-salt", ["SL-ORIG-009"], "origin_status",
        {"origin_bundle": of_maj["origin_bundle"], "chain": of_maj["chain"], "trusted_origin_issuer_pins": of_maj["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Opened majority_unix failing salted commitment MUST refuse ORIGIN_UNVERIFIED.")
    of_m2 = rm._base_origin_fixture()
    of_m2["chain"].pop("credible_utc_interval", None)
    add("branch-origin-missing-utc-oracle", ["SL-ORIG-010"], "origin_status",
        {"origin_bundle": of_m2["origin_bundle"], "chain": of_m2["chain"], "trusted_origin_issuer_pins": of_m2["trusted_origin_issuer_pins"]},
        "REFUSE", "GUARDIAN_TIME_BOUNDARY", "Missing credible_utc_interval when evaluating majority boundary MUST refuse GUARDIAN_TIME_BOUNDARY.")

    # Roster spine branches (0x0f)
    def _roster_fixture(*, miss_rout: bool = False, bad_opret: bool = False, miss_rec: bool = False, bad_prev: bool = False, miss_iss_name: bool = False, miss_nxt: bool = False) -> dict[str, Any]:
        or0 = rm._base_origin_fixture()
        disp, arb = or0["_keys"]["disp"], or0["_keys"]["arb"]
        vac = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["comp"], arb["comp"])}
        if miss_rout:
            del or0["chain"]["txs"][or0["origin_bundle"]["origin"]["payload"]["guardian_policy"]["roster_seal"]["txid"]]
            return or0
        rp = {
            "arbiter_pk": arb["comp"],
            "challenger_pk": or0["origin_bundle"]["origin"]["payload"]["guardian_policy"]["challenger_pk"],
            "disposer_pk": disp["comp"],
            "effective_delay_blocks": 144,
            "genesis": GENESIS_MAIN,
            "issuer": or0["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "next_roster_policy": vac,
            "next_roster_vout": 0,
            "origin_id": or0["_origin_id"],
            "prev_revision": 99 if bad_prev else 1,
            "prev_roster_outpoint": {"txid": or0["origin_bundle"]["origin"]["payload"]["guardian_policy"]["roster_seal"]["txid"], "vout": 0},
            "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in ("routine_read", "effect_grant", "contract_assent", "custody_change")},
            "revision": 2,
            "revision_size": 1,
            "slots": [{"action": "new_vacant", "new_vacant_policy": vac, "new_vacant_vout": 1, "slot": 1}],
            "type": "seallink-guardian-roster/1",
        }
        rrec = sl.sign_envelope(rp, [or0["_keys"]["reg_cred"]["sk"]])
        rtx_id = _h32(f"br-rtx-{bad_opret}-{miss_rec}-{bad_prev}-{miss_iss_name}-{miss_nxt}")
        or0["chain"]["txs"][or0["origin_bundle"]["origin"]["payload"]["guardian_policy"]["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_id
        wrong_nr_spk = _spk_hex({"kind": "key", "pk": _kp("wrong-nr-pk")["comp"]})
        or0["chain"]["txs"][rtx_id] = {
            "confirmed_height": 749500,
            "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(rrec)).hex() if bad_opret else sl.encode_opreturn(0x0F, sl.content_addr(rrec)).hex(),
            "outputs": {"0": {"script_pubkey_hex": wrong_nr_spk}, "1": {"script_pubkey_hex": _spk_hex(vac)}} if miss_nxt else {"0": {"script_pubkey_hex": _spk_hex(vac)}, "1": {"script_pubkey_hex": _spk_hex(vac)}},
        }
        if not miss_rec:
            or0["origin_bundle"]["roster_records"] = [rrec]
        if miss_iss_name:
            # Remove civil-registry only at 749500? Use a fresh issuer name in rp so origin still passes!
            rp2 = {**rp, "issuer": {**rp["issuer"], "name": "id/missing-roster-issuer"}}
            rrec2 = sl.sign_envelope(rp2, [or0["_keys"]["reg_cred"]["sk"]])
            or0["chain"]["txs"][rtx_id]["opreturn_hex"] = sl.encode_opreturn(0x0F, sl.content_addr(rrec2)).hex()
            or0["origin_bundle"]["roster_records"] = [rrec2]
        return or0

    for cid_ro, kw_ro, note_ro in [
        ("branch-roster-missing-outpoint", {"miss_rout": True}, "Missing roster_seal output MUST refuse ORIGIN_STATUS_INCOMPLETE."),
        ("branch-roster-bad-0x0f-tx", {"bad_opret": True}, "Roster spend without 0x0f OP_RETURN MUST refuse ORIGIN_STATUS_INCOMPLETE."),
        ("branch-roster-missing-record", {"miss_rec": True}, "Roster spend without presented guardian-roster/1 MUST refuse ORIGIN_STATUS_INCOMPLETE."),
        ("branch-roster-bad-prev-revision", {"bad_prev": True}, "Roster transition with prev_revision != active revision MUST refuse ORIGIN_STATUS_INCOMPLETE."),
        ("branch-roster-missing-issuer-name", {"miss_iss_name": True}, "Roster transition with unknown issuer name MUST refuse ORIGIN_STATUS_INCOMPLETE."),
        ("branch-roster-missing-next-seal", {"miss_nxt": True}, "Roster spend omitting next_roster_vout output MUST refuse ORIGIN_STATUS_INCOMPLETE."),
    ]:
        orf = _roster_fixture(**kw_ro)
        add(cid_ro, ["SL-ORIG-015"], "origin_status",
            {"origin_bundle": orf["origin_bundle"], "chain": orf["chain"], "trusted_origin_issuer_pins": orf["trusted_origin_issuer_pins"]},
            "REFUSE", "ORIGIN_STATUS_INCOMPLETE", note_ro)

    # Ward approvals branches (including fail-safe halt on roster revision change!)
    def _ward_assent_fx(
        *,
        gc_override: dict[str, Any] | None = None,
        approvals_override: list[dict[str, Any]] | None = None,
        mutate_of: Callable[[dict[str, Any]], None] | None = None,
        make_slot2: bool = False,
    ) -> dict[str, Any]:
        ow = rm._base_origin_fixture()
        if make_slot2:
            # Activate slot 2 with guardian g2 (or same guardian reg for duplicate test)
            g2_gr = _kp("br-g2-gr")
            g2_own = _kp("br-g2-own")
            g2_opol = {"kind": "key", "pk": g2_own["comp"]}
            g2_reg = {"txid": _h32("br-g2-reg"), "vout": 0}
            ow["_g2"] = {"gr": g2_gr, "reg": g2_reg}
            ow["chain"]["names"]["id/parent-b"] = sv.make_name_history(
                "id/parent-b", g2_reg, g2_opol, {"link": {"grant": g2_gr["xonly"]}}, first_height=748000, update_height=749000
            )
            g2_act_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(g2_own["comp"], ow["_keys"]["disp"]["comp"])}
            g2_rec_p = copy.deepcopy(ow["origin_bundle"]["guardian_records"][0]["payload"])
            g2_rec_p.update({
                "slot": 2,
                "active_policy": g2_act_pol,
                "guardian": {"name": "id/parent-b", "owner_policy": g2_opol, "registration": g2_reg},
                "prev_outpoint": copy.deepcopy(ow["origin_bundle"]["origin"]["payload"]["guardian_policy"]["slots"][1]["vacant_utxo"]),
            })
            g2_rec = sl.sign_envelope(g2_rec_p, [ow["_keys"]["reg_cred"]["sk"]])
            g2_assent = sl.sign_envelope(
                {**ow["origin_bundle"]["guardian_assents"][0]["payload"], "party_id": "guardian-slot-2", "party_name": "id/parent-b", "target_id": sl.object_id(g2_rec_p)},
                [g2_gr["sk"]],
            )
            s2_tx = _h32("br-g2-init-0x12")
            ow["chain"]["txs"][ow["origin_bundle"]["origin"]["payload"]["guardian_policy"]["slots"][1]["vacant_utxo"]["txid"]]["outputs"]["0"]["spent_by_txid"] = s2_tx
            ow["chain"]["txs"][s2_tx] = {
                "confirmed_height": 749100,
                "opreturn_hex": sl.encode_opreturn(0x12, sl.content_addr(g2_rec)).hex(),
                "outputs": {"0": {"script_pubkey_hex": _spk_hex(g2_act_pol)}},
            }
            ow["origin_bundle"]["guardian_records"].append(g2_rec)
            ow["origin_bundle"]["guardian_assents"].append(g2_assent)
            g2_pin = {"name": "id/parent-b", "owner_policy": g2_opol, "registration": g2_reg}
            ow["origin_bundle"]["initial_guardian_disclosures"]["2"] = {
                "name_pin": g2_pin,
                "salt_hex": ow["origin_bundle"]["initial_guardian_disclosures"]["1"]["salt_hex"],
            }
            # Re-sign origin with slot 2 commitment matching g2_pin
            op_m = copy.deepcopy(ow["origin_bundle"]["origin"]["payload"])
            op_m["guardian_policy"]["slots"][1]["initial_guardian_commitment"] = sl.clause_commit(
                ow["origin_bundle"]["initial_guardian_disclosures"]["2"]["salt_hex"], g2_pin
            )
            o_m = sl.sign_envelope(op_m, [ow["_keys"]["reg_cred"]["sk"]])
            oid_m = sl.object_id(op_m)
            ow["_origin_id"] = oid_m
            ow["origin_bundle"]["origin"] = o_m
            ow["origin_bundle"]["name_binding"]["origin_id"] = oid_m
            ow["contract"]["parties"][0]["ward_origin_id"] = oid_m
            for gr_idx in range(len(ow["origin_bundle"]["guardian_records"])):
                gp_x = {**ow["origin_bundle"]["guardian_records"][gr_idx]["payload"], "origin_id": oid_m}
                grec_x = sl.sign_envelope(gp_x, [ow["_keys"]["reg_cred"]["sk"]])
                ow["origin_bundle"]["guardian_records"][gr_idx] = grec_x
                sk_x = ow["_keys"]["g1_gr"]["sk"] if gr_idx == 0 else g2_gr["sk"]
                ow["origin_bundle"]["guardian_assents"][gr_idx] = sl.sign_envelope(
                    {**ow["origin_bundle"]["guardian_assents"][gr_idx]["payload"], "target_id": sl.object_id(gp_x)}, [sk_x]
                )
            ow["chain"]["txs"][ow["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_m)).hex()
            ow["chain"]["txs"][ow["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(ow["origin_bundle"]["name_binding"])).hex()
            ow["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(ow["origin_bundle"]["guardian_records"][0])).hex()
            ow["chain"]["txs"][s2_tx]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(ow["origin_bundle"]["guardian_records"][1])).hex()
        if mutate_of:
            mutate_of(ow)
        gc = {"event_class": "contract_assent", "origin_id": ow["_origin_id"], "revision": 1, "ward_name": "id/child-leo"}
        if gc_override:
            gc.update(gc_override)
        ap = {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": gc,
            "issued_at": 1795220000, "network": "main", "nonce": _h32("wa-n"),
            "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
            "target_id": sl.object_id(ow["contract"]), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        }
        apps = approvals_override if approvals_override is not None else [
            {"slot": 1, "revision": gc["revision"], "guardian_name": "id/parent-a", "signers": [ow["_keys"]["g1_gr"]["sk"]]}
        ]
        if make_slot2 and approvals_override is None:
            apps.append({"slot": 2, "revision": gc["revision"], "guardian_name": "id/parent-b", "signers": [ow["_g2"]["gr"]["sk"]]})
        ass = sl.sign_guardian_envelope(ap, apps)
        return {"assent": ass, "contract": ow["contract"], "origin_bundle": ow["origin_bundle"], "chain": ow["chain"], "trusted_origin_issuer_pins": ow["trusted_origin_issuer_pins"]}

    add("branch-ward-gc-wrong-ward-name", ["SL-ORIG-006"], "assent",
        _ward_assent_fx(gc_override={"ward_name": "id/other-ward"}),
        "REFUSE", "ORIGIN_UNVERIFIED", "guardian_context.ward_name mismatching active binding MUST refuse ORIGIN_UNVERIFIED.")
    # Intentional fail-safe halt of old revision ward grant/assent after 0x0f roster transition!
    def _advance_roster_to_rev2(ow: dict[str, Any]) -> None:
        disp, arb = ow["_keys"]["disp"], ow["_keys"]["arb"]
        vac = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["comp"], arb["comp"])}
        rp = {
            "arbiter_pk": arb["comp"],
            "challenger_pk": ow["origin_bundle"]["origin"]["payload"]["guardian_policy"]["challenger_pk"],
            "disposer_pk": disp["comp"],
            "effective_delay_blocks": 144,
            "genesis": GENESIS_MAIN,
            "issuer": ow["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "next_roster_policy": vac,
            "next_roster_vout": 0,
            "origin_id": ow["_origin_id"],
            "prev_revision": 1,
            "prev_roster_outpoint": {"txid": ow["origin_bundle"]["origin"]["payload"]["guardian_policy"]["roster_seal"]["txid"], "vout": 0},
            "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in ("routine_read", "effect_grant", "contract_assent", "custody_change")},
            "revision": 2,
            "revision_size": 1,
            "slots": [{"action": "retain_active", "active_outpoint": {"txid": rm._h32("og1-init-0x12"), "vout": 0}, "guardian_id": sl.object_id(ow["origin_bundle"]["guardian_records"][0]["payload"]), "slot": 1}],
            "type": "seallink-guardian-roster/1",
        }
        rrec = sl.sign_envelope(rp, [ow["_keys"]["reg_cred"]["sk"]])
        rtx = _h32("br-rev2-halt-tx")
        ow["chain"]["txs"][ow["origin_bundle"]["origin"]["payload"]["guardian_policy"]["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx
        ow["chain"]["txs"][rtx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rrec)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac)}}}
        ow["origin_bundle"]["roster_records"] = [rrec]
    add("branch-ward-old-revision-halted-after-roster-transition", ["SL-ORIG-006", "SL-ORIG-015"], "assent",
        _ward_assent_fx(mutate_of=_advance_roster_to_rev2),
        "REFUSE", "GUARDIAN_QUORUM_UNMET", "Pre-transition revision=1 ward approval MUST fail closed with GUARDIAN_QUORUM_UNMET once revision=2 roster takes effect.")
    # Unsorted guardian_approvals[] (slot 2 before slot 1) -> WIRE_SIGNATURE
    wa_unsorted = _ward_assent_fx(make_slot2=True)
    wa_unsorted["assent"]["guardian_approvals"] = list(reversed(wa_unsorted["assent"]["guardian_approvals"]))
    add("branch-ward-unsorted-guardian-approvals", ["SL-ORIG-006", "SL-WIRE-013"], "assent", wa_unsorted,
        "REFUSE", "WIRE_SIGNATURE", "guardian_approvals[] not strictly ascending by slot MUST refuse WIRE_SIGNATURE.")
    # Approval item revision != guardian_context.revision -> GUARDIAN_QUORUM_UNMET
    wa_irev = _ward_assent_fx()
    wa_irev["assent"]["guardian_approvals"][0]["revision"] = 2
    add("branch-ward-approval-item-revision-mismatch", ["SL-ORIG-006"], "assent", wa_irev,
        "REFUSE", "GUARDIAN_QUORUM_UNMET", "Approval item revision mismatching guardian_context.revision MUST refuse GUARDIAN_QUORUM_UNMET.")
    # Guardian calendar term > opened_majority_unix -> GUARDIAN_INACTIVE
    def _set_cal_over_maj(ow: dict[str, Any]) -> None:
        gp = copy.deepcopy(ow["origin_bundle"]["guardian_records"][0]["payload"])
        gp["term"] = {"ceiling_height": 800000, "mode": "calendar", "not_after_unix": 2050000000}
        grec = sl.sign_envelope(gp, [ow["_keys"]["reg_cred"]["sk"]])
        ow["origin_bundle"]["guardian_records"][0] = grec
        ow["origin_bundle"]["guardian_assents"][0] = sl.sign_envelope(
            {**ow["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(gp)}, [ow["_keys"]["g1_gr"]["sk"]]
        )
        ow["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(grec)).hex()
        ow["chain"]["credible_utc_interval"] = [1795220000, 1795220100]
    add("branch-ward-guardian-term-exceeds-majority", ["SL-ORIG-009"], "assent",
        _ward_assent_fx(mutate_of=_set_cal_over_maj),
        "REFUSE", "GUARDIAN_INACTIVE", "Guardian calendar term not_after_unix > opened majority_unix MUST refuse GUARDIAN_INACTIVE.")
    # Guardian calendar term expired by height -> GUARDIAN_INACTIVE
    def _set_cal_expired(ow: dict[str, Any]) -> None:
        gp = copy.deepcopy(ow["origin_bundle"]["guardian_records"][0]["payload"])
        gp["term"] = {"ceiling_height": 749900, "mode": "calendar", "not_after_unix": 1900000000}
        grec = sl.sign_envelope(gp, [ow["_keys"]["reg_cred"]["sk"]])
        ow["origin_bundle"]["guardian_records"][0] = grec
        ow["origin_bundle"]["guardian_assents"][0] = sl.sign_envelope(
            {**ow["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(gp)}, [ow["_keys"]["g1_gr"]["sk"]]
        )
        ow["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(grec)).hex()
    add("branch-ward-guardian-term-expired", ["SL-ORIG-009"], "assent",
        _ward_assent_fx(mutate_of=_set_cal_expired),
        "REFUSE", "GUARDIAN_INACTIVE", "Guardian whose calendar ceiling_height has passed MUST refuse GUARDIAN_INACTIVE.")
    # Duplicate guardian registration across two slots -> GUARDIAN_INACTIVE
    def _dup_guardian_reg(ow: dict[str, Any]) -> None:
        g1_reg = ow["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]["registration"]
        gp2 = copy.deepcopy(ow["origin_bundle"]["guardian_records"][1]["payload"])
        gp2["guardian"]["registration"] = copy.deepcopy(g1_reg)
        g2rec = sl.sign_envelope(gp2, [ow["_keys"]["reg_cred"]["sk"]])
        ow["origin_bundle"]["guardian_records"][1] = g2rec
        ow["origin_bundle"]["guardian_assents"][1] = sl.sign_envelope(
            {**ow["origin_bundle"]["guardian_assents"][1]["payload"], "target_id": sl.object_id(gp2)}, [ow["_g2"]["gr"]["sk"]]
        )
        ow["chain"]["names"]["id/parent-b"]["registration"] = copy.deepcopy(g1_reg)
        ow["chain"]["names"]["id/parent-b"]["updates"][0]["txid"] = g1_reg["txid"]
        ow["chain"]["names"]["id/parent-b"]["updates"][1]["prev_input"]["txid"] = g1_reg["txid"]
        ow["origin_bundle"]["initial_guardian_disclosures"]["2"]["name_pin"]["registration"] = copy.deepcopy(g1_reg)
        op_m = copy.deepcopy(ow["origin_bundle"]["origin"]["payload"])
        op_m["guardian_policy"]["slots"][1]["initial_guardian_commitment"] = sl.clause_commit(
            ow["origin_bundle"]["initial_guardian_disclosures"]["2"]["salt_hex"], gp2["guardian"]
        )
        o_m = sl.sign_envelope(op_m, [ow["_keys"]["reg_cred"]["sk"]])
        oid_m = sl.object_id(op_m)
        ow["_origin_id"] = oid_m
        ow["origin_bundle"]["origin"] = o_m
        ow["origin_bundle"]["name_binding"]["origin_id"] = oid_m
        ow["contract"]["parties"][0]["ward_origin_id"] = oid_m
        for gr_idx in range(2):
            gp_x = {**ow["origin_bundle"]["guardian_records"][gr_idx]["payload"], "origin_id": oid_m}
            grec_x = sl.sign_envelope(gp_x, [ow["_keys"]["reg_cred"]["sk"]])
            ow["origin_bundle"]["guardian_records"][gr_idx] = grec_x
            sk_x = ow["_keys"]["g1_gr"]["sk"] if gr_idx == 0 else ow["_g2"]["gr"]["sk"]
            ow["origin_bundle"]["guardian_assents"][gr_idx] = sl.sign_envelope(
                {**ow["origin_bundle"]["guardian_assents"][gr_idx]["payload"], "target_id": sl.object_id(gp_x)}, [sk_x]
            )
        ow["chain"]["txs"][ow["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_m)).hex()
        ow["chain"]["txs"][ow["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(ow["origin_bundle"]["name_binding"])).hex()
        ow["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(ow["origin_bundle"]["guardian_records"][0])).hex()
        ow["chain"]["txs"][_h32("br-g2-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(ow["origin_bundle"]["guardian_records"][1])).hex()
    add("branch-ward-duplicate-guardian-registration", ["SL-ORIG-006"], "assent",
        _ward_assent_fx(make_slot2=True, mutate_of=_dup_guardian_reg),
        "REFUSE", "GUARDIAN_INACTIVE", "Same guardian registration appearing in two slots MUST refuse GUARDIAN_INACTIVE.")

    # Guardian name deleted at tip (after 0x12 verified using tip? Wait: resolve_name for guardian at verify_ward_approvals)
    # Wait: if id/parent-a is missing, _verify_guardian_incoming_assent also fails -> GUARDIAN_INACTIVE! To hit L2080 specifically, guardian is active at 749100 (verified via assent at tip?) Wait: both check tip, so to hit L2080 we check guardian whose link.grant is removed AFTER activation or whose name has expired! Even simpler: guardian_assent is checked at tip during trace_slot, wait — let's check if guardian name missing hits L2080 or trace_slot!
    # Look: in verify_ward_approvals, L2080 calls resolve_name(gn, chain, expected_owner_policy=st["guardian_owner_policy"], expected_registration=st["guardian_reg"]), whereas _verify_guardian_incoming_assent checks `expected_owner_policy=grec["payload"]["guardian"]["owner_policy"]`! If guardian's name has `expected_registration` intact during 0x12? Wait — both read the SAME chain! Wait: in _verify_guardian_incoming_assent, `require_writer=True, require_history=False` whereas verify_ward_approvals calls `require_writer=True, require_history=True`!
    # GENIUS!! If id/parent-a has `history_truncated: True`, `_verify_guardian_incoming_assent` (require_history=False) SUCCEEDS, slot becomes ACTIVE, and THEN `verify_ward_approvals` L2080 (`require_history=True`) catches it and refuses `GUARDIAN_INACTIVE`!!
    add("branch-ward-guardian-history-unavailable", ["SL-ORIG-006"], "assent",
        _ward_assent_fx(mutate_of=lambda ow: ow["chain"]["names"]["id/parent-a"].__setitem__("history_truncated", True)),
        "REFUSE", "GUARDIAN_INACTIVE", "Active guardian whose name history is unavailable during approval check MUST refuse GUARDIAN_INACTIVE.")
    # And for L2083 (rerr -> WIRE_SIGNATURE in verify_ward_approvals):
    # During trace_slot, _verify_guardian_incoming_assent verifies against current link.grant, while verify_ward_approvals passes `presented_role_policy=item["signatures"]["policy"]`! If item is signed by WRONG key (not link.grant), `resolve_role_policy` returns `WIRE_SIGNATURE` at L2083!
    wa_wrong_gk = _ward_assent_fx(approvals_override=[{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [_kp("wrong-g1-signer")["sk"]]}])
    add("branch-ward-guardian-wrong-grant-key", ["SL-ORIG-006", "SL-WIRE-013"], "assent", wa_wrong_gk,
        "REFUSE", "WIRE_SIGNATURE", "Guardian approval signed by key != guardian link.grant MUST refuse WIRE_SIGNATURE.")
    # Split paired check L2094: gc["event_class"] != derived_class WITH full valid 2-of-2 quorum so ONLY L2094 refuses!
    add("branch-ward-event-class-downgrade-with-full-quorum", ["SL-ORIG-005"], "assent",
        _ward_assent_fx(make_slot2=True, gc_override={"event_class": "routine_read"}),
        "REFUSE", "GUARDIAN_QUORUM_UNMET", "Ward contract assent declaring event_class='routine_read' (even with full 2-of-2 signatures!) MUST refuse GUARDIAN_QUORUM_UNMET.")

    # --- Group 8: Contracts, Assents & Credentials ---
    p1_k, p2_k = _kp("ca-p1"), _kp("ca-p2")
    c_two = {
        "clause_commitments": [sl.clause_commit(_h32("ca-s0"), {"idx": 0})],
        "config_sha256": _h32("ca-cfg"),
        "contract_salt": _h32("ca-csalt"),
        "genesis": GENESIS_MAIN,
        "machine_clause_indices": [0],
        "network": "main",
        "parties": [
            {"party_id": "p1", "role": "buyer", "signing_policy": {"m": 1, "pks": [p1_k["xonly"]]}},
            {"party_id": "p2", "role": "seller", "signing_policy": {"m": 1, "pks": [p2_k["xonly"]]}},
        ],
        "profile": "seallink/generic-v1",
        "seal": {"script_policy": {"kind": "key", "pk": p1_k["comp"]}, "txid": _h32("ca-seal"), "vout": 0},
        "type": "seallink-contract/1",
        "window": {"not_before_height": 749000, "not_after_height": 760000},
    }
    def _mk_assent(pid: str, role: str, sk: bytes, **ov: Any) -> dict[str, Any]:
        ap = {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
            "nonce": _h32(f"ca-n-{pid}-{ov}"), "party_id": pid, "party_role": role,
            "target_id": sl.object_id(c_two), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        }
        ap.update(ov)
        return sl.sign_envelope(ap, [sk])

    a_p1 = _mk_assent("p1", "buyer", p1_k["sk"])
    a_p2 = _mk_assent("p2", "seller", p2_k["sk"])
    add("branch-assent-wrong-target-id", ["SL-CONT-004"], "assent",
        {"assent": _mk_assent("p1", "buyer", p1_k["sk"], target_id=_h32("other-contract")), "contract": c_two, "chain": fx0["chain"]},
        "REFUSE", "CONTRACT_ASSENT_INVALID", "Assent targeting different contract_id MUST refuse CONTRACT_ASSENT_INVALID.")
    add("branch-assent-expired", ["SL-CONT-004"], "assent",
        {"assent": _mk_assent("p1", "buyer", p1_k["sk"], issued_at=1795000000, expires_at=1795100000), "contract": c_two, "chain": fx0["chain"]},
        "REFUSE", "CONTRACT_ASSENT_INVALID", "Expired contract assent MUST refuse CONTRACT_ASSENT_INVALID.")
    add("branch-assent-wrong-party-role", ["SL-CONT-004"], "assent",
        {"assent": _mk_assent("p1", "seller", p1_k["sk"]), "contract": c_two, "chain": fx0["chain"]},
        "REFUSE", "CONTRACT_ASSENT_INVALID", "Assent party_role disagreeing with Contract.parties[party_id].role MUST refuse CONTRACT_ASSENT_INVALID.")
    of_wa = rm._base_origin_fixture()
    wa_ok = _ward_assent_fx()
    add("branch-assent-ward-missing-origin-bundle", ["SL-ORIG-006"], "assent",
        {"assent": wa_ok["assent"], "contract": wa_ok["contract"], "origin_bundle": None, "chain": wa_ok["chain"], "trusted_origin_issuer_pins": of_wa["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Ward contract assent without origin_bundle MUST refuse ORIGIN_UNVERIFIED.")
    add("branch-assent-ward-bad-origin-bundle", ["SL-ORIG-006"], "assent",
        {"assent": wa_ok["assent"], "contract": wa_ok["contract"], "origin_bundle": {}, "chain": wa_ok["chain"], "trusted_origin_issuer_pins": of_wa["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Ward contract assent with invalid origin_bundle MUST refuse ORIGIN_UNVERIFIED.")
    c_ward_other = copy.deepcopy(wa_ok["contract"])
    c_ward_other["parties"][0]["ward_origin_id"] = _h32("different-ward-oid")
    wa_other_c = sl.sign_guardian_envelope(
        {**wa_ok["assent"]["payload"], "target_id": sl.object_id(c_ward_other)},
        [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [of_wa["_keys"]["g1_gr"]["sk"]]}],
    )
    add("branch-assent-ward-origin-id-mismatch", ["SL-CONT-002"], "assent",
        {"assent": wa_other_c, "contract": c_ward_other, "origin_bundle": wa_ok["origin_bundle"], "chain": wa_ok["chain"], "trusted_origin_issuer_pins": of_wa["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Verified origin_id mismatching Contract.parties[].ward_origin_id MUST refuse ORIGIN_UNVERIFIED.")
    add("branch-contract-assents-invalid-member", ["SL-CONT-004"], "contract_assents",
        {"contract": c_two, "assents": [a_p1, _mk_assent("p2", "seller", p1_k["sk"])], "chain": fx0["chain"]},
        "REFUSE", "CONTRACT_ASSENT_INVALID", "Contract assent set containing an invalid signature MUST refuse CONTRACT_ASSENT_INVALID.")
    a_p2 = _mk_assent("p2", "seller", p2_k["sk"])
    add("branch-contract-assents-duplicate-party", ["SL-CONT-004"], "contract_assents",
        {"contract": c_two, "assents": [a_p1, _mk_assent("p1", "buyer", p1_k["sk"], nonce=_h32("dup-p1")), a_p2], "chain": fx0["chain"]},
        "REFUSE", "CONTRACT_ASSENT_INVALID", "Contract assent set covering same party_id twice MUST refuse CONTRACT_ASSENT_INVALID.")
    add("branch-contract-assents-missing-party", ["SL-CONT-004"], "contract_assents",
        {"contract": c_two, "assents": [a_p1], "chain": fx0["chain"]},
        "REFUSE", "CONTRACT_ASSENT_INVALID", "Contract assent set omitting required party_id MUST refuse CONTRACT_ASSENT_INVALID.")

    # Credential branches
    cr_ok = _make_cred_and_chain(key_b, 749900, "br-cr")
    add("branch-cred-unsupported-kind", ["SL-CONT-010"], "credential",
        {**cr_ok, "supported_kinds": ["other/kind"]}, "REFUSE", "WIRE_TYPE",
        "Credential whose credential_kind is not in supported_kinds MUST refuse WIRE_TYPE.")
    cr_gen = copy.deepcopy(cr_ok)
    cr_gen["credential"] = sl.sign_envelope({**cr_ok["credential"]["payload"], "genesis": _h32("bad-cgen")}, [key_b["sk"]])
    add("branch-cred-chain-mismatch", ["SL-CONT-010"], "credential", cr_gen, "REFUSE", "CHAIN_MISMATCH",
        "Credential for wrong genesis MUST refuse CHAIN_MISMATCH.")
    add("branch-cred-anchor-depth-insufficient", ["SL-CONT-010"], "credential",
        {**cr_ok, "operator_min_depth": 500}, "REFUSE", "CHAIN_DEPTH_INSUFFICIENT",
        "Credential anchor depth < operator_min_depth MUST refuse CHAIN_DEPTH_INSUFFICIENT.")
    cr_early = copy.deepcopy(cr_ok)
    cr_early["credential"] = sl.sign_envelope({**cr_ok["credential"]["payload"], "not_before_height": 755000}, [key_b["sk"]])
    cr_early["chain"]["txs"][cr_early["anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(cr_early["credential"])).hex()
    add("branch-cred-before-not-before-height", ["SL-CONT-010"], "credential", cr_early, "REFUSE", "CRED_WINDOW_CLOSED",
        "Credential evaluated prior to not_before_height MUST refuse CRED_WINDOW_CLOSED.")

    # --- Group 9: Invocation pipeline, closures, framework contracts, re-delegation, anchors, executor_ref, guardian-message, sessions, migration, federation ---
    # Split Step 2 (inv_p.executor mismatch) vs Step 10d (leaf_gp.executor mismatch)
    fx_e1 = rm._base_invocation_fixture()
    fx_e1["invocation"] = sl.sign_envelope(
        {**fx_e1["invocation"]["payload"], "executor": {"key": fx_e1["executor_cfg"]["key"], "name": "id/other-exec"}},
        [fx_e1["_keys"]["agent_req"]["sk"]],
    )
    add("branch-inv-step2-executor-mismatch", ["SL-GRNT-012"], "invocation", fx_e1, "REFUSE", "GRANT_EXECUTOR_MISMATCH",
        "Invocation.executor mismatching executor_cfg (Step 2) MUST refuse GRANT_EXECUTOR_MISMATCH.")
    fx_e2 = rm._base_invocation_fixture()
    gp_em = copy.deepcopy(fx_e2["bundle"]["grants"][0]["payload"])
    gp_em["executor"] = {"key": _kp("wrong-exec-k")["xonly"], "name": "id/other-exec"}
    g_em = sl.sign_envelope(gp_em, [fx_e2["_keys"]["alice_gr"]["sk"]])
    gid_em = sl.object_id(gp_em)
    fx_e2["bundle"]["grants"] = [g_em]
    fx_e2["invocation"] = sl.sign_envelope(
        {**fx_e2["invocation"]["payload"], "proof_path": [{"grant_id": gid_em, "issuance_txid": fx_e2["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}]},
        [fx_e2["_keys"]["agent_req"]["sk"]],
    )
    fx_e2["chain"]["txs"][fx_e2["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_em), "grant_id": gid_em, "type": "seallink-issuance/1"}).hex()
    ).hex()
    add("branch-inv-step10d-grant-executor-mismatch", ["SL-GRNT-003", "SL-GRNT-012"], "invocation", fx_e2, "REFUSE", "GRANT_EXECUTOR_MISMATCH",
        "Grant.executor mismatching executor_cfg while Invocation.executor matches (Step 10d) MUST refuse GRANT_EXECUTOR_MISMATCH.")

    fx_mg = rm._base_invocation_fixture()
    fx_mg["bundle"]["grants"] = []
    add("branch-inv-missing-grant-in-bundle", ["SL-GRNT-012"], "invocation", fx_mg, "REFUSE", "WIRE_MEMBER",
        "Invocation referencing grant_id absent from presented bundle MUST refuse WIRE_MEMBER.")

    # Journal pre-recorded closure re-refusals (GRANT_ROW_STOPPED, NAME_ROLE_CHANGED, SEAL_SPENT)
    db_cl = _build_delegation_base()
    inv_cl = db_cl["make_inv"](db_cl["c1_id"], db_cl["c1_itx"], db_cl["keys"]["w1_k"], "cl-row")
    add("branch-inv-journal-row-stopped-closure", ["SL-GRNT-011", "SL-GRNT-014"], "invocation",
        {"invocation": inv_cl, "bundle": {"grants": [db_cl["parent_env"], db_cl["c1_env"]]}, "chain": db_cl["chain"],
         "journal": {"journal_id": _h32("jcl1"), "closures": {f"{db_cl['parent_id']}:1": {"cause": "GRANT_ROW_STOPPED"}}}, "executor_cfg": db_cl["executor_cfg"]},
        "REFUSE", "GRANT_ROW_STOPPED", "Durable journal row-stop closure MUST immediately refuse GRANT_ROW_STOPPED.")
    fx_rc = rm._base_invocation_fixture()
    rc_subj = {
        "name": "id/alice",
        "policy_sha256": sv._policy_sha256({"m": 1, "pks": [fx_rc["_keys"]["alice_gr"]["xonly"]]}),
        "registration": fx_rc["_alice_reg"],
        "role": "grant",
        "subject_kind": "role",
    }
    fx_rc["journal"]["closures"] = {sv._closure_subject_key(rc_subj): {"cause": "NAME_ROLE_CHANGED", "subject": rc_subj}}
    add("branch-inv-journal-role-changed-closure", ["SL-IDEN-004", "SL-GRNT-014"], "invocation", fx_rc, "REFUSE", "NAME_ROLE_CHANGED",
        "Durable journal policy-scoped issuer-role closure MUST immediately refuse NAME_ROLE_CHANGED.")
    fx_sc = rm._base_invocation_fixture()
    s0 = fx_sc["bundle"]["grants"][0]["payload"]["revocation"]["seal"]
    fx_sc["journal"]["closures"] = {f"{s0['txid']}:{s0['vout']}": {"cause": "SEAL_SPENT"}}
    add("branch-inv-journal-seal-spent-closure", ["SL-LDGR-011", "SL-GRNT-014"], "invocation", fx_sc, "REFUSE", "SEAL_SPENT",
        "Durable journal seal-spend closure MUST immediately refuse SEAL_SPENT.")

    # Ward grant missing / bad origin_bundle in verify_invocation
    fx_wo = rm._base_invocation_fixture()
    fx_wo["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_wo["_alice_reg"], fx_wo["_alice_owner_pol"],
        {"link": {"grant": fx_wo["_keys"]["alice_gr"]["xonly"], "origin": _h32("ward-orig-pin")}, "m": {"h": sl.content_addr(fx_wo["_alice_man"]), "s": 1}},
        first_height=748000, update_height=749000,
    )
    add("branch-inv-ward-missing-origin-bundle", ["SL-ORIG-006"], "invocation", fx_wo, "REFUSE", "ORIGIN_UNVERIFIED",
        "Name with link.origin pin invoked without origin_bundle MUST refuse ORIGIN_UNVERIFIED.")
    fx_wo2 = copy.deepcopy(fx_wo)
    fx_wo2["bundle"]["origin_bundle"] = {}
    add("branch-inv-ward-bad-origin-bundle", ["SL-ORIG-006"], "invocation", fx_wo2, "REFUSE", "ORIGIN_UNVERIFIED",
        "Name with link.origin pin invoked with invalid origin_bundle MUST refuse ORIGIN_UNVERIFIED.")

    # Framework contract checks (ALL 6 branches!)
    def _fw_contract_fx(*, omit_fw: bool = False, wrong_fw_id: bool = False, nested_fw: bool = False, no_fw_seal: bool = False, spent_fw_seal: bool = False, grant_outside_cw: bool = False) -> dict[str, Any]:
        fx = rm._base_invocation_fixture()
        fw_seal_pol = {"kind": "key", "pk": p1_k["comp"]}
        fw_seal_tx = _h32(f"fw-stx-{spent_fw_seal}")
        fw_obj: dict[str, Any] = {
            "clause_commitments": [sl.clause_commit(_h32("fw-s0"), {"idx": 0})],
            "contract_salt": _h32("fw-csalt"),
            "genesis": GENESIS_MAIN,
            "machine_clause_indices": [],
            "network": "main",
            "parties": [
                {"party_id": "p1", "role": "buyer", "signing_policy": {"m": 1, "pks": [p1_k["xonly"]]}},
                {"party_id": "p2", "role": "seller", "signing_policy": {"m": 1, "pks": [p2_k["xonly"]]}},
            ],
            "profile": "seallink/framework-v1",
            "type": "seallink-contract/1",
            "window": {"not_before_height": 749000, "not_after_height": 760000},
        }
        if not no_fw_seal:
            fw_obj["seal"] = {"script_policy": fw_seal_pol, "txid": fw_seal_tx, "vout": 0}
        if nested_fw:
            fw_obj["framework_id"] = _h32("grandparent-fw")
        c_seal_pol = {"kind": "key", "pk": p2_k["comp"]}
        c_seal_tx = _h32("child-c-stx")
        c_sub = {
            "clause_commitments": [sl.clause_commit(_h32("cs-s0"), {"idx": 0})],
            "contract_salt": _h32("cs-csalt"),
            "framework_id": _h32("wrong-fw-ref") if wrong_fw_id else sl.object_id(fw_obj),
            "genesis": GENESIS_MAIN,
            "machine_clause_indices": [0],
            "network": "main",
            "parties": [
                {"party_id": "p1", "role": "buyer", "signing_policy": {"m": 1, "pks": [p1_k["xonly"]]}},
                {"party_id": "p2", "role": "seller", "signing_policy": {"m": 1, "pks": [p2_k["xonly"]]}},
            ],
            "profile": "seallink/sub-v1",
            "seal": {"script_policy": c_seal_pol, "txid": c_seal_tx, "vout": 0},
            "type": "seallink-contract/1",
            "window": {"not_before_height": 750050 if grant_outside_cw else 749000, "not_after_height": 760000},
        }
        cid_sub = sl.object_id(c_sub)
        a1 = sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("fwa1"), "party_id": "p1", "party_role": "buyer", "target_id": cid_sub, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [p1_k["sk"]])
        a2 = sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("fwa2"), "party_id": "p2", "party_role": "seller", "target_id": cid_sub, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [p2_k["sk"]])
        gp = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
        gp["contract_id"] = cid_sub
        g_new = sl.sign_envelope(gp, [fx["_keys"]["alice_gr"]["sk"]])
        gid_new = sl.object_id(gp)
        fx["bundle"]["grants"] = [g_new]
        fx["bundle"]["contract"] = c_sub
        fx["bundle"]["contract_assents"] = [a1, a2]
        fx["bundle"]["disclosed_clauses"] = {"0": {"clause": {"idx": 0}, "salt_hex": _h32("cs-s0")}}
        if not omit_fw:
            fx["bundle"]["framework_contract"] = fw_obj
        fx["invocation"] = sl.sign_envelope(
            {**fx["invocation"]["payload"], "proof_path": [{"grant_id": gid_new, "issuance_txid": fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}]},
            [fx["_keys"]["agent_req"]["sk"]],
        )
        fx["chain"]["txs"][fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(
            0x01, sl.signing_digest({"contract_id": cid_sub, "genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_new), "grant_id": gid_new, "type": "seallink-issuance/1"}).hex()
        ).hex()
        fx["chain"]["txs"][c_seal_tx] = {"confirmed_height": 749500, "outputs": {"0": {"script_pubkey_hex": _spk_hex(c_seal_pol)}}}
        fx["chain"]["txs"][fw_seal_tx] = {"confirmed_height": 749500, "outputs": {"0": {"script_pubkey_hex": _spk_hex(fw_seal_pol), **({"spent_by_txid": _h32("fw-spent")} if spent_fw_seal else {})}}}
        return fx

    for cid_fw, kw_fw, want_fw, note_fw in [
        ("branch-fw-contract-not-presented", {"omit_fw": True}, "CONTRACT_NOT_PRESENTED", "Child contract naming framework_id without framework_contract in bundle MUST refuse CONTRACT_NOT_PRESENTED."),
        ("branch-fw-contract-id-mismatch", {"wrong_fw_id": True}, "CONTRACT_ID_MISMATCH", "Framework contract object_id mismatching child.framework_id MUST refuse CONTRACT_ID_MISMATCH."),
        ("branch-fw-contract-depth-gt-1", {"nested_fw": True}, "CONTRACT_TERMS_MISMATCH", "Framework contract itself naming a framework_id (depth > 1) MUST refuse CONTRACT_TERMS_MISMATCH."),
        ("branch-fw-contract-missing-seal", {"no_fw_seal": True}, "CONTRACT_SEAL_MISSING", "Framework contract omitting seal MUST refuse CONTRACT_SEAL_MISSING."),
        ("branch-fw-contract-spent-seal", {"spent_fw_seal": True}, "SEAL_SPENT", "Framework contract with spent seal MUST refuse SEAL_SPENT."),
        ("branch-contract-grant-window-outside", {"grant_outside_cw": True}, "CONTRACT_TERMS_MISMATCH", "Grant validity window starting before contract.window.not_before_height MUST refuse CONTRACT_TERMS_MISMATCH."),
    ]:
        add(cid_fw, ["SL-CONT-003", "SL-CONT-005"], "invocation", _fw_contract_fx(**kw_fw), "REFUSE", want_fw, note_fw)

    # Re-delegation inside verify_invocation (R8.5, R8.6, wrong parent, ordinal OOR, window widened, window_only child, wrong child_seal_key!)
    def _del_bad_fx(mode: str) -> dict[str, Any]:
        d = _build_delegation_base(pool_calls=10, row_cap_calls=2, c1_max_calls=1, c1_kind="single_use" if mode == "su_cseal" else "revocable")
        p_pl = copy.deepcopy(d["parent_env"]["payload"])
        c_pl = copy.deepcopy(d["c1_env"]["payload"])
        if mode == "wrong_parent":
            c_pl["parent"]["grant_id"] = _h32("other-parent")
        elif mode == "r85":
            p_pl["delegate"]["pools"][0]["max"] = "5"  # 3 rows * 2 = 6 > 5!
        elif mode == "r86":
            p_pl["delegate"]["groups"][0]["ranges"].append({"count": 1, "first": 0, "script_policy": p_pl["delegate"]["groups"][0]["ranges"][0]["script_policy"], "txid": d["rows_tx"]})  # overlaps vout 0!
        elif mode == "ord_oor":
            c_pl["parent"]["ordinal"] = 99
        elif mode == "win_wide":
            c_pl["not_after_height"] = p_pl["not_after_height"] + 10
        elif mode == "win_only":
            c_pl["revocation"] = {"mode": "window_only"}
            c_pl["not_after_height"] = c_pl["not_before_height"] + 5
        elif mode == "p2wpkh_cseal":
            c_pl["revocation"]["seal"]["script_policy"] = {"kind": "key", "pk": _kp("wrong-cs")["comp"]}
        elif mode == "su_cseal":
            c_pl["revocation"]["seal"]["script_policy"]["keys"]["issuer"] = _kp("wrong-cs2")["comp"]
        p_new = sl.sign_envelope(p_pl, [d["keys"]["org_gr"]["sk"]])
        pid_new = sl.object_id(p_pl)
        if mode != "wrong_parent":
            c_pl["parent"]["grant_id"] = pid_new
        c_new = sl.sign_envelope(c_pl, [d["keys"]["del_k"]["sk"]])
        cid_new = sl.object_id(c_pl)
        inv = d["make_inv"](cid_new, d["c1_itx"], d["keys"]["w1_k"], f"del-{mode}")
        inv = sl.sign_envelope({**inv["payload"], "proof_path": [{"grant_id": pid_new, "issuance_txid": d["parent_iss_tx"]}, {"grant_id": cid_new, "issuance_txid": d["c1_itx"]}]}, [d["keys"]["w1_k"]["sk"]])
        d["chain"]["txs"][d["parent_iss_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_new), "grant_id": pid_new, "type": "seallink-issuance/1"}).hex()).hex()
        d["chain"]["txs"][d["c1_itx"]]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_new), "grant_id": cid_new, "type": "seallink-issuance/1"}).hex()).hex()
        return {"invocation": inv, "bundle": {"grants": [p_new, c_new]}, "chain": d["chain"], "journal": d["journal"], "executor_cfg": d["executor_cfg"]}

    for m_d, want_d, note_d in [
        ("wrong_parent", "GRANT_NOT_DELEGABLE", "Child grant.parent.grant_id mismatching root grant in proof_path MUST refuse GRANT_NOT_DELEGABLE."),
        ("r85", "GRANT_CHILD_WIDER", "Whole-parent aggregate R8.5 budget overflow inside verify_invocation MUST refuse GRANT_CHILD_WIDER."),
        ("r86", "GRANT_ROW_INVALID", "Overlapping R8.6 row coin ranges inside verify_invocation MUST refuse GRANT_ROW_INVALID."),
        ("ord_oor", "GRANT_ROW_INVALID", "Child ordinal outside parent group ranges MUST refuse GRANT_ROW_INVALID."),
        ("win_wide", "GRANT_CHILD_WIDER", "Child validity window extending past parent MUST refuse GRANT_CHILD_WIDER."),
        ("win_only", "WIRE_MEMBER", "Child grant using revocation.mode='window_only' MUST refuse WIRE_MEMBER under closed ChildGrant schema."),
        ("p2wpkh_cseal", "GRANT_CHILD_WIDER", "Child P2WPKH seal key != parent.delegate.child_seal_key MUST refuse GRANT_CHILD_WIDER."),
        ("su_cseal", "GRANT_CHILD_WIDER", "Child single_use issuer key != parent.delegate.child_seal_key MUST refuse GRANT_CHILD_WIDER."),
    ]:
        add(f"branch-delegation-{m_d}", ["SL-GRNT-009", "SL-GRNT-010"], "invocation", _del_bad_fx(m_d), "REFUSE", want_d, note_d)

    # Issuance anchors (0x01/0x02/unknown/missing) & recency (unknown recent_block)
    fx_a = rm._base_invocation_fixture()
    del fx_a["chain"]["txs"][fx_a["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]
    add("branch-issuance-missing-tx", ["SL-LDGR-010"], "invocation", fx_a, "REFUSE", "CHAIN_FRAME_INVALID",
        "Missing issuance anchor tx MUST refuse CHAIN_FRAME_INVALID.")
    fx_a2 = rm._base_invocation_fixture()
    fx_a2["chain"]["txs"][fx_a2["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x01, _h32("wrong-iss-commit")).hex()
    add("branch-issuance-0x01-wrong-commitment", ["SL-LDGR-010"], "invocation", fx_a2, "REFUSE", "CHAIN_FRAME_INVALID",
        "0x01 issuance frame with mismatched typed_digest MUST refuse CHAIN_FRAME_INVALID.")
    fx_a3 = rm._base_invocation_fixture()
    fx_a3["chain"]["txs"][fx_a3["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x02, _h32("batch-root")).hex()
    add("branch-issuance-0x02-missing-batch-proof", ["SL-LDGR-014"], "invocation", fx_a3, "REFUSE", "CHAIN_FRAME_INVALID",
        "0x02 batch anchor without valid Merkle batch_proof MUST refuse CHAIN_FRAME_INVALID.")
    fx_a4 = rm._base_invocation_fixture()
    fx_a4["chain"]["txs"][fx_a4["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x07, _h32("wrong-action")).hex()
    add("branch-issuance-wrong-action-byte", ["SL-LDGR-010"], "invocation", fx_a4, "REFUSE", "CHAIN_FRAME_INVALID",
        "Issuance tx carrying non-0x01/0x02 action byte MUST refuse CHAIN_FRAME_INVALID.")
    fx_a5 = rm._base_invocation_fixture()
    fx_a5["chain"]["blocks"] = {}
    add("branch-issuance-unknown-recent-block", ["SL-LDGR-008"], "invocation", fx_a5, "REFUSE", "CHAIN_RECENCY_INVALID",
        "Grant naming unknown recent_block hash MUST refuse CHAIN_RECENCY_INVALID.")

    # executor_ref & name recipient branches
    def _exec_ref_fx(*, single_use: bool = False, drop_holder: bool = False, drop_prov: bool = False, drop_prov_man: bool = False, bad_prov_key: bool = False) -> dict[str, Any]:
        fx = rm._base_invocation_fixture()
        gp = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
        del gp["executor"]
        gp["executor_ref"] = {"label": "work", "provider_of": "id/alice", "service_type": "mail"}
        if single_use:
            su_pol = {"keys": {"grantee": _kp("er-g")["comp"], "issuer": _kp("er-i")["comp"]}, "kind": "branch", "template": "single_use_1_of_2"}
            gp["revocation"]["kind"] = "single_use"
            gp["revocation"]["seal"]["script_policy"] = su_pol
            su_tx = _h32("er-su-use")
            fx["chain"]["txs"][gp["revocation"]["seal"]["txid"]]["outputs"]["0"] = {"script_pubkey_hex": _spk_hex(su_pol), "spent_by_txid": su_tx}
        g_new = sl.sign_envelope(gp, [fx["_keys"]["alice_gr"]["sk"]])
        gid_new = sl.object_id(gp)
        fx["bundle"]["grants"] = [g_new]
        inv_new = sl.sign_envelope({**fx["invocation"]["payload"], "proof_path": [{"grant_id": gid_new, "issuance_txid": fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}]}, [fx["_keys"]["agent_req"]["sk"]])
        fx["invocation"] = inv_new
        if single_use:
            fx["use_txid"] = _h32("er-su-use")
            fx["chain"]["txs"][_h32("er-su-use")] = {"confirmed_height": 750006, "inputs": [sv.make_single_use_spend_input(gp["revocation"]["seal"], 0)], "opreturn_hex": sl.encode_opreturn(0x11, sl.content_addr(inv_new)).hex(), "outputs": {}}
        fx["chain"]["txs"][fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_new), "grant_id": gid_new, "type": "seallink-issuance/1"}).hex()).hex()
        if drop_holder:
            # Use a distinct holder name so issuer id/alice still resolves!
            gp["executor_ref"]["provider_of"] = "id/missing-holder"
            g_new = sl.sign_envelope(gp, [fx["_keys"]["alice_gr"]["sk"]])
            gid_new = sl.object_id(gp)
            fx["bundle"]["grants"] = [g_new]
            fx["invocation"] = sl.sign_envelope({**fx["invocation"]["payload"], "proof_path": [{"grant_id": gid_new, "issuance_txid": fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}]}, [fx["_keys"]["agent_req"]["sk"]])
            fx["chain"]["txs"][fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_new), "grant_id": gid_new, "type": "seallink-issuance/1"}).hex()).hex()
        if drop_prov:
            del fx["chain"]["names"]["id/mail-host-a"]
        if drop_prov_man:
            fx["bundle"]["manifests"] = {k: v for k, v in fx["bundle"]["manifests"].items() if v.get("owner") != "id/mail-host-a"}
            fx["chain"]["manifests"] = {}
        if bad_prov_key:
            pm = copy.deepcopy(fx["_host_man"])
            pm["service"]["receipt_key"] = _kp("other-prov-rcpt")["xonly"]
            fx["chain"]["names"]["id/mail-host-a"] = sv.make_name_history(
                "id/mail-host-a", fx["_host_reg"], fx["_host_owner_pol"],
                {"m": {"h": sl.content_addr(pm), "s": 1}}, first_height=748000, update_height=749000,
            )
            fx["bundle"]["manifests"][sl.content_addr(pm)] = pm
            fx["bundle"]["manifests"]["id/mail-host-a"] = pm
        return fx

    for cid_er, kw_er, want_er, note_er in [
        ("branch-exec-ref-single-use-forbidden", {"single_use": True}, "WIRE_MEMBER", "executor_ref on single_use grant MUST refuse WIRE_MEMBER under closed Grant schema."),
        ("branch-exec-ref-missing-holder-name", {"drop_holder": True}, "GRANT_TARGET_UNAUTHORIZED", "G7-17: executor_ref naming provider_of != root.issuer.name MUST refuse GRANT_TARGET_UNAUTHORIZED."),
        ("branch-exec-ref-missing-provider-name", {"drop_prov": True}, "NAME_NOT_FOUND", "executor_ref pointing to missing provider name MUST refuse NAME_NOT_FOUND."),
        ("branch-exec-ref-missing-provider-manifest", {"drop_prov_man": True}, "MANIFEST_UNAVAILABLE", "executor_ref whose provider manifest is unavailable MUST refuse MANIFEST_UNAVAILABLE."),
        ("branch-exec-ref-provider-key-mismatch", {"bad_prov_key": True}, "GRANT_EXECUTOR_MISMATCH", "executor_ref provider manifest receipt_key mismatching executor_cfg MUST refuse GRANT_EXECUTOR_MISMATCH."),
    ]:
        add(cid_er, ["SL-GRNT-003", "SL-SERV-001"], "invocation", _exec_ref_fx(**kw_er), "REFUSE", want_er, note_er)

    # Name recipient missing name & missing link.request
    fx_nr = rm._base_invocation_fixture()
    gp_nr = copy.deepcopy(fx_nr["bundle"]["grants"][0]["payload"])
    bob_own = _kp("nr-bob-own")
    bob_opol = {"kind": "key", "pk": bob_own["comp"]}
    bob_reg = {"txid": _h32("nr-bob-reg"), "vout": 0}
    gp_nr["recipient"] = {"mode": "name", "name": "id/bob-rcpt", "owner_policy": bob_opol, "registration": bob_reg}
    g_nr = sl.sign_envelope(gp_nr, [fx_nr["_keys"]["alice_gr"]["sk"]])
    gid_nr = sl.object_id(gp_nr)
    fx_nr["bundle"]["grants"] = [g_nr]
    fx_nr["invocation"] = sl.sign_envelope({**fx_nr["invocation"]["payload"], "proof_path": [{"grant_id": gid_nr, "issuance_txid": fx_nr["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}]}, [fx_nr["_keys"]["agent_req"]["sk"]])
    fx_nr["chain"]["txs"][fx_nr["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_nr), "grant_id": gid_nr, "type": "seallink-issuance/1"}).hex()).hex()
    add("branch-recipient-name-missing", ["SL-GRNT-002"], "invocation", fx_nr, "REFUSE", "NAME_NOT_FOUND",
        "Name-mode recipient whose ledger name is absent MUST refuse NAME_NOT_FOUND.")
    fx_nr2 = copy.deepcopy(fx_nr)
    fx_nr2["chain"]["names"]["id/bob-rcpt"] = sv.make_name_history("id/bob-rcpt", bob_reg, bob_opol, {"link": {"grant": _kp("nr-gr-only")["xonly"]}}, first_height=748000, update_height=749000)
    add("branch-recipient-name-missing-request-key", ["SL-GRNT-002"], "invocation", fx_nr2, "REFUSE", "WIRE_SIGNATURE",
        "Name-mode recipient lacking link.request key MUST refuse WIRE_SIGNATURE.")

    # Action not supported by executor_cfg["actions"]
    fx_act = rm._base_invocation_fixture()
    fx_act["executor_cfg"]["actions"] = ["mail/list"]
    add("branch-executor-unsupported-action", ["SL-GRNT-012"], "invocation", fx_act, "REFUSE", "INVOKE_ACTION_DENIED",
        "Action absent from executor_cfg.actions MUST refuse INVOKE_ACTION_DENIED.")

    # agent/guardian-message branches (wrong ward target, wrong args.revision, wrong raw_message_bytes hash!)
    def _agm_fx(*, wrong_target: bool = False, wrong_rev: bool = False, wrong_raw_msg: bool = False) -> dict[str, Any]:
        ow = rm._base_origin_fixture()
        oid = ow["_origin_id"]
        exec_k = _kp("agm-exec")
        rcpt_k = _kp("agm-rcpt")
        gseal_pol = {"kind": "key", "pk": ow["_keys"]["disp"]["comp"]}
        gseal_tx = _h32("agm-gseal")
        recent_blk = _h32("agm-recent")
        raw_msg = b"hello guardian"
        msg_sha = sl.sha256(raw_msg).hex()
        tgt = f"ward:{_h32('other-ward')}" if wrong_target else f"ward:{oid}"
        gp = {
            "capabilities": [{"action": "agent/guardian-message", "target": tgt, "where": {}}],
            "executor": {"key": exec_k["xonly"], "name": "id/agent-host"},
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "effect_grant", "origin_id": oid, "revision": 1, "ward_name": "id/child-leo"},
            "issuer": {"name": "id/child-leo", "owner_policy": ow["origin_bundle"]["name_binding"]["owner_policy"], "registration": ow["origin_bundle"]["name_binding"]["registration"]},
            "network": "main",
            "not_after_height": 760000,
            "not_before_height": 749000,
            "recent_block": recent_blk,
            "recipient": {"key": rcpt_k["xonly"], "mode": "key"},
            "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": gseal_pol, "txid": gseal_tx, "vout": 0}},
            "type": "seallink-grant/1",
        }
        # Re-sign origin with 1-of-2 effect_grant quorum so single active slot 1 satisfies effect_grant!
        op_q = copy.deepcopy(ow["origin_bundle"]["origin"]["payload"])
        op_q["guardian_policy"]["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 1}
        o_q = sl.sign_envelope(op_q, [ow["_keys"]["reg_cred"]["sk"]])
        oid_q = sl.object_id(op_q)
        ow["origin_bundle"]["origin"] = o_q
        ow["origin_bundle"]["name_binding"]["origin_id"] = oid_q
        grec_p = {**ow["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_q}
        grec_q = sl.sign_envelope(grec_p, [ow["_keys"]["reg_cred"]["sk"]])
        ow["origin_bundle"]["guardian_records"] = [grec_q]
        ow["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**ow["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(grec_p)}, [ow["_keys"]["g1_gr"]["sk"]])]
        ow["chain"]["txs"][ow["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_q)).hex()
        ow["chain"]["txs"][ow["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(ow["origin_bundle"]["name_binding"])).hex()
        ow["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(grec_q)).hex()
        ow["chain"]["names"]["id/child-leo"] = sv.make_name_history(
            "id/child-leo", ow["origin_bundle"]["name_binding"]["registration"], ow["origin_bundle"]["name_binding"]["owner_policy"],
            {"link": {"grant": ow["_keys"]["g1_gr"]["xonly"], "origin": oid_q}}, first_height=749005, update_height=749010,
        )
        tgt_q = f"ward:{_h32('other-ward')}" if wrong_target else f"ward:{oid_q}"
        gp["capabilities"][0]["target"] = tgt_q
        gp["guardian_context"]["origin_id"] = oid_q
        g_env = sl.sign_guardian_envelope(gp, [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [ow["_keys"]["g1_gr"]["sk"]]}])
        gid = sl.object_id(gp)
        itx = _h32(f"agm-itx-{wrong_target}-{wrong_rev}-{wrong_raw_msg}")
        ow["chain"]["blocks"] = {recent_blk: 749900}
        ow["chain"]["txs"][gseal_tx] = {"confirmed_height": 749902, "inputs": [sv.make_segwit_input(_h32("agm-f"), 0)], "outputs": {"0": {"script_pubkey_hex": _spk_hex(gseal_pol)}, "1": {"script_pubkey_hex": _spk_hex(gseal_pol)}}}
        ow["chain"]["txs"][itx] = {"confirmed_height": 749905, "inputs": [sv.make_segwit_input(gseal_tx, 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_env), "grant_id": gid, "type": "seallink-issuance/1"}).hex()).hex(), "outputs": {}}
        inv = sl.sign_envelope(
            {
                "action": "agent/guardian-message",
                "arguments": {
                    "channel": "direct",
                    "delivery_mode": "strict_drop",
                    "message_sha256": msg_sha,
                    "origin_id": oid_q,
                    "revision": 2 if wrong_rev else 1,
                    "subject_ward_name": "id/child-leo",
                },
                "executor": {"key": exec_k["xonly"], "name": "id/agent-host"},
                "exp": 1795221000,
                "genesis": GENESIS_MAIN,
                "iat": 1795220000,
                "network": "main",
                "nonce": _h32(f"agm-n-{wrong_target}-{wrong_rev}-{wrong_raw_msg}"),
                "proof_path": [{"grant_id": gid, "issuance_txid": itx}],
                "target": tgt_q,
                "type": "seallink-invocation/1",
            },
            [rcpt_k["sk"]],
        )
        out = {
            "invocation": inv,
            "bundle": {"grants": [g_env], "origin_bundle": ow["origin_bundle"]},
            "chain": ow["chain"],
            "journal": {"journal_id": _h32("agm-jid")},
            "executor_cfg": {"key": exec_k["xonly"], "name": "id/agent-host", "pinned_ward_origin_id": oid_q},
            "trusted_origin_issuer_pins": ow["trusted_origin_issuer_pins"],
        }
        if wrong_raw_msg:
            out["raw_message_hex"] = b"tampered bytes".hex()
        return out

    add("branch-agm-wrong-ward-target", ["SL-AGNT-004"], "invocation", _agm_fx(wrong_target=True), "REFUSE", "GRANT_TARGET_UNAUTHORIZED",
        "agent/guardian-message target mismatching pinned ward origin MUST refuse GRANT_TARGET_UNAUTHORIZED (B-3).")
    add("branch-agm-wrong-args-revision", ["SL-AGNT-004"], "invocation", _agm_fx(wrong_rev=True), "REFUSE", "GUARDIAN_QUORUM_UNMET",
        "agent/guardian-message args.revision mismatching verified roster revision MUST refuse GUARDIAN_QUORUM_UNMET.")
    add("branch-agm-raw-message-hash-mismatch", ["SL-AGNT-004"], "invocation", _agm_fx(wrong_raw_msg=True), "REFUSE", "INVOKE_CONSTRAINT_FAILED",
        "agent/guardian-message raw bytes not matching args.message_sha256 MUST refuse INVOKE_CONSTRAINT_FAILED.")

    # Bearer session closed grant in journal
    tok = "sl_tok_closed_grant"
    add("branch-bearer-session-grant-closed", ["SL-GRNT-013"], "bearer_session",
        {"token": tok, "slot_binding": "slot:1", "chain": fx0["chain"],
         "journal": {"journal_id": _h32("bsj"), "closures": {_h32("closed-g"): {"cause": "SEAL_SPENT"}},
                     "sessions": {sl.sha256(tok.encode()).hex(): {"closed": False, "exp": 1795229999, "grant_id": _h32("closed-g"), "slot_binding": "slot:1"}}}},
        "REFUSE", "SESSION_INVALID", "Bearer session whose backing grant is closed in journal MUST refuse SESSION_INVALID.")

    # Migration branches (all remaining! H-14 closed MigrationExportBundle + M-14 local_executor_pin!)
    def _mig_fx(*, wrong_gen: bool = False, no_chain: bool = False, miss_src_name: bool = False, miss_src_man: bool = False, no_rcpt_key: bool = False, bad_files_type: bool = False, wrong_inv_sha: bool = False, unfenced: bool = False, dup_mid: bool = False) -> dict[str, Any]:
        fx = rm._base_invocation_fixture()
        src_rcpt = fx["_keys"]["host_rcpt"]
        mid = _h32(f"mig-id-{dup_mid}")
        inv_obj: Any = {
            "holder_name": "id/alice",
            "items": [{"media_type": "message/rfc822", "path": "mail/m1.eml", "sha256": _h32("m1"), "size_bytes": "128"}],
            "migration_id": mid,
            "service_type": "mail",
        }
        inv_sha = _h32("wrong-inv-sha") if wrong_inv_sha else sl.sha256(sl.jcs_encode(inv_obj)).hex()
        dest_pin = {"name": "id/mail-svc-2", "owner_policy": fx["_host_owner_pol"], "registration": {"txid": _h32("dst-reg"), "vout": 0}}
        src_pin = {"name": "id/mail-host-a", "owner_policy": fx["_host_owner_pol"], "registration": fx["_host_reg"]}
        holder_pin = {"name": "id/alice", "owner_policy": fx["_alice_owner_pol"], "registration": fx["_alice_reg"]}
        mp = {
            "dest_executor": dest_pin,
            "genesis": _h32("bad-mgen") if wrong_gen else GENESIS_MAIN,
            "holder": holder_pin,
            "inventory_sha256": inv_sha,
            "issued_at": 1795220000,
            "journal_commitment": _h32("mig-jc"),
            "journal_pos": 10,
            "migration_id": mid,
            "network": "main",
            "outstanding_exposure": [],
            "service_type": "mail",
            "source_executor": src_pin,
            "type": "seallink-migration/1",
        }
        menv = sl.sign_envelope(mp, [src_rcpt["sk"]])
        ch_m: dict[str, Any] | None = copy.deepcopy(fx["chain"])
        mans = copy.deepcopy(fx["bundle"]["manifests"])
        if no_chain:
            ch_m = None
        elif miss_src_name:
            del ch_m["names"]["id/mail-host-a"]
        elif miss_src_man:
            mans = {}
            ch_m["manifests"] = {}
        elif no_rcpt_key:
            sm_no = copy.deepcopy(fx["_host_man"])
            sm_no.pop("service", None)
            ch_m["names"]["id/mail-host-a"] = sv.make_name_history("id/mail-host-a", fx["_host_reg"], fx["_host_owner_pol"], {"m": {"h": sl.content_addr(sm_no), "s": 1}}, first_height=748000, update_height=749000)
            mans = {sl.content_addr(sm_no): sm_no}
        eb: dict[str, Any] = {
            "inventory": "not-an-object" if bad_files_type else inv_obj,
            "source_journal_pos": 10,
            "source_journal_commitment": _h32("mig-jc"),
        }
        if not unfenced and not bad_files_type:
            f_stmt = sl.sign_envelope(
                {
                    "genesis": GENESIS_MAIN,
                    "issuer": src_pin,
                    "network": "main",
                    "not_after": 1795221000,
                    "not_before": 1795219000,
                    "seq": 1,
                    "statement_kind": "migration-fence",
                    "subject": {
                        "dest_executor": dest_pin,
                        "holder": holder_pin,
                        "inventory_sha256": inv_sha,
                        "migration_id": mid,
                        "predecessor_grant_seals": [],
                        "source_journal_commitment": _h32("mig-jc"),
                        "source_journal_pos": 10,
                    },
                    "type": "seallink-statement/1",
                },
                [src_rcpt["sk"]],
            )
            eb["fencing_statement"] = f_stmt
        j = {"journal_id": _h32("mig-j"), "migrations_applied": [mid] if dup_mid else []}
        return {"migration": menv, "export_bundle": eb, "journal": j, "chain": ch_m, "manifests": mans, "local_executor_pin": dest_pin}

    for cid_m, kw_m, want_m, note_m in [
        ("branch-mig-chain-mismatch", {"wrong_gen": True}, "CHAIN_MISMATCH", "Migration manifest with wrong genesis MUST refuse CHAIN_MISMATCH."),
        ("branch-mig-no-chain", {"no_chain": True}, "SERVICE_MIGRATION_INVALID", "Migration without chain view MUST refuse SERVICE_MIGRATION_INVALID."),
        ("branch-mig-missing-source-name", {"miss_src_name": True}, "NAME_NOT_FOUND", "Migration whose source_executor name is missing MUST refuse NAME_NOT_FOUND."),
        ("branch-mig-missing-source-manifest", {"miss_src_man": True}, "MANIFEST_UNAVAILABLE", "Migration whose source_executor manifest is unavailable MUST refuse MANIFEST_UNAVAILABLE."),
        ("branch-mig-source-no-receipt-key", {"no_rcpt_key": True}, "SERVICE_MIGRATION_INVALID", "Migration whose source manifest lacks service.receipt_key MUST refuse SERVICE_MIGRATION_INVALID."),
        ("branch-mig-bad-files-type", {"bad_files_type": True}, "SERVICE_MIGRATION_INVALID", "Migration with non-list export files MUST refuse SERVICE_MIGRATION_INVALID."),
        ("branch-mig-inventory-sha-mismatch", {"wrong_inv_sha": True}, "SERVICE_MIGRATION_INVALID", "Migration with mismatched inventory_sha256 MUST refuse SERVICE_MIGRATION_INVALID."),
        ("branch-mig-source-journal-unfenced", {"unfenced": True}, "SERVICE_MIGRATION_INVALID", "Migration with unfenced source journal MUST refuse SERVICE_MIGRATION_INVALID."),
        ("branch-mig-duplicate-migration-id", {"dup_mid": True}, "SERVICE_MIGRATION_INVALID", "Replaying an already-applied migration_id MUST refuse SERVICE_MIGRATION_INVALID."),
    ]:
        add(cid_m, ["SL-SERV-002", "SL-SERV-003"], "migration", _mig_fx(**kw_m), "REFUSE", want_m, note_m)

    # Federation disclosure branches (all remaining!)
    l1_cmd = sl.sign_envelope(
        {"arguments": {"brief_sha256": _h32("fed-brf"), "run_id": "run-fed"}, "command": "agent-dispatch", "exp": 1795220300, "genesis": GENESIS_MAIN, "iat": 1795220000, "level": 1, "network": "main", "nonce": _h32("fed-l1"), "owner": "id/alice", "target_executor": "id/station-a", "type": "seallink-owner-command/1"},
        [dev1["sk"]],
    )
    add("branch-fed-screening-untrusted-peer", ["SL-SERV-004"], "federation",
        {"policy": {"trusted_peers": ["id/peer-good"]}, "peer_ctx": {"phase": "screening", "peer_id": "id/peer-untrusted"}, "grant": fx0["bundle"]["grants"][0], "chain": fx0["chain"]},
        "REFUSE", "FEDERATION_POLICY_DENIED", "Screening phase from untrusted peer or zero-quota grant MUST refuse FEDERATION_POLICY_DENIED.")
    add("branch-fed-pii-missing-approval-cmd", ["SL-SERV-004"], "federation",
        {"policy": {"trusted_peers": ["id/peer-good"]}, "peer_ctx": {"phase": "pii_disclosure", "route_hops": [{"actor": "id/peer-good", "role": "counterparty"}]}, "grant": fx0["bundle"]["grants"][0], "chain": fx0["chain"]},
        "REFUSE", "FEDERATION_POLICY_DENIED", "Contour A PII disclosure without L2 approval_command MUST refuse FEDERATION_POLICY_DENIED.")
    al_man_fed_br = {**copy.deepcopy(fx0["_alice_man"]), "sets": {"devices": {"seq": 1, "sha256": sl.content_addr(dev_list_br)}}}
    al_man_fed_br_h = sl.content_addr(al_man_fed_br)
    ch_oc_fed = copy.deepcopy(ch_oc)
    ch_oc_fed["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx0["_alice_reg"], fx0["_alice_owner_pol"],
        {"link": {"grant": fx0["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al_man_fed_br_h, "s": 1}},
        first_height=748000, update_height=749000,
    )
    add("branch-fed-pii-level1-approval-rejected", ["SL-SERV-004"], "federation",
        {"policy": {"trusted_peers": ["id/peer-good"]}, "peer_ctx": {"phase": "pii_disclosure", "route_hops": [{"actor": "id/peer-good", "role": "counterparty"}], "approval_command": l1_cmd, "device_list": dev_list_br, "manifests": {al_man_fed_br_h: al_man_fed_br}}, "grant": fx0["bundle"]["grants"][0], "chain": ch_oc_fed},
        "REFUSE", "FEDERATION_POLICY_DENIED", "Contour A PII disclosure with level=1 instead of level=2 owner command MUST refuse FEDERATION_POLICY_DENIED.")
    add("branch-fed-unknown-phase", ["SL-SERV-004"], "federation",
        {"policy": {"trusted_peers": ["id/peer-good"]}, "peer_ctx": {"phase": "unknown_phase"}, "grant": fx0["bundle"]["grants"][0], "chain": fx0["chain"]},
        "REFUSE", "FEDERATION_POLICY_DENIED", "Federation request with unrecognized phase MUST refuse FEDERATION_POLICY_DENIED.")

    # --- Final 10 razor-sharp refusal branch tests targeting 100% verifier mutation kill rate ---
    # 1. Bare envelope missing `payload` and `type` (verify_wire_bytes)
    add("branch-wire-bare-signatures-no-payload", ["SL-WIRE-002"], "raw_wire",
        {"object": {"signatures": {}}}, "REFUSE", "WIRE_TYPE",
        "Object carrying signatures without payload or type MUST refuse WIRE_TYPE (W-9).")

    # 2. Uncompilable script_policy on evaluate_single_use_seal
    add("branch-single-use-bad-script-policy", ["SL-LDGR-011"], "single_use_seal",
        {"seal": {"script_policy": {"kind": "invalid_kind"}, "txid": _h32("su-bad-sp"), "vout": 0},
         "use_txid": _h32("su-bad-u"), "invocation_content_addr": _h32("su-bad-ca"), "chain": fx0["chain"]},
        "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED",
        "single_use_1_of_2 seal with uncompilable script_policy MUST refuse CHAIN_SCRIPT_UNSUPPORTED.")

    # 3. Name registration outpoint disagrees with updates[0]
    ch_reg_mis = copy.deepcopy(fx0["chain"])
    ch_reg_mis["names"]["id/alice"]["registration"] = {"txid": _h32("wrong-reg-u0"), "vout": 0}
    add("branch-name-registration-mismatch-u0", ["SL-LDGR-006"], "name_resolve",
        {"name": "id/alice", "chain": ch_reg_mis}, "REFUSE", "NAME_HISTORY_UNAVAILABLE",
        "Name history whose updates[0] does not match rec.registration MUST refuse NAME_HISTORY_UNAVAILABLE.")

    # 4. Origin bundle missing name_binding
    of_nob = rm._base_origin_fixture()
    del of_nob["origin_bundle"]["name_binding"]
    add("branch-origin-missing-name-binding", ["SL-ORIG-003"], "origin_status",
        {"origin_bundle": of_nob["origin_bundle"], "chain": of_nob["chain"], "trusted_origin_issuer_pins": of_nob["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_BINDING_INVALID",
        "Origin bundle omitting name_binding MUST refuse ORIGIN_BINDING_INVALID.")

    # 5. Origin name_binding with mismatched origin_id committed in 0x0c OP_RETURN
    of_boid = rm._base_origin_fixture()
    of_boid["origin_bundle"]["name_binding"]["origin_id"] = _h32("wrong-nb-origin")
    of_boid["chain"]["txs"][of_boid["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(
        0x0C, sl.object_id(of_boid["origin_bundle"]["name_binding"])
    ).hex()
    add("branch-origin-binding-wrong-origin-id", ["SL-ORIG-003"], "origin_status",
        {"origin_bundle": of_boid["origin_bundle"], "chain": of_boid["chain"], "trusted_origin_issuer_pins": of_boid["trusted_origin_issuer_pins"]},
        "REFUSE", "ORIGIN_BINDING_INVALID",
        "0x0c name-binding whose origin_id disagrees with verified origin MUST refuse ORIGIN_BINDING_INVALID.")

    # 6. Guardian approval item revision disagrees with guardian_context.revision (with 1-of-2 quorum so ONLY item.revision refuses!)
    wa_item_rev = rm._base_origin_fixture()
    op_1of2 = copy.deepcopy(wa_item_rev["origin_bundle"]["origin"]["payload"])
    op_1of2["guardian_policy"]["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 1}
    op_1of2["guardian_policy"]["quorums"]["contract_assent"] = {"den": 2, "min": 1, "num": 1}
    o_1of2 = sl.sign_envelope(op_1of2, [wa_item_rev["_keys"]["reg_cred"]["sk"]])
    oid_1of2 = sl.object_id(op_1of2)
    wa_item_rev["origin_bundle"]["origin"] = o_1of2
    wa_item_rev["origin_bundle"]["name_binding"]["origin_id"] = oid_1of2
    grec_1p = {**wa_item_rev["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_1of2}
    grec_1 = sl.sign_envelope(grec_1p, [wa_item_rev["_keys"]["reg_cred"]["sk"]])
    wa_item_rev["origin_bundle"]["guardian_records"] = [grec_1]
    wa_item_rev["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**wa_item_rev["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(grec_1p)}, [wa_item_rev["_keys"]["g1_gr"]["sk"]])]
    wa_item_rev["chain"]["txs"][wa_item_rev["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_1of2)).hex()
    wa_item_rev["chain"]["txs"][wa_item_rev["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(wa_item_rev["origin_bundle"]["name_binding"])).hex()
    wa_item_rev["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(grec_1)).hex()
    c_1of2 = copy.deepcopy(wa_item_rev["contract"])
    c_1of2["parties"][0]["ward_origin_id"] = oid_1of2
    assent_item_rev = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": oid_1of2, "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000, "network": "main", "nonce": _h32("br-item-rev-mis"),
            "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
            "target_id": sl.object_id(c_1of2), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        },
        [{"slot": 1, "revision": 2, "guardian_name": "id/parent-a", "signers": [wa_item_rev["_keys"]["g1_gr"]["sk"]]}],
    )
    add("branch-ward-approval-item-revision-mismatch-1of2", ["SL-ORIG-005"], "assent",
        {"assent": assent_item_rev, "contract": c_1of2, "origin_bundle": wa_item_rev["origin_bundle"],
         "chain": wa_item_rev["chain"], "trusted_origin_issuer_pins": wa_item_rev["trusted_origin_issuer_pins"]},
        "REFUSE", "GUARDIAN_QUORUM_UNMET",
        "guardian_approvals[].revision mismatching guardian_context.revision MUST refuse GUARDIAN_QUORUM_UNMET.")

    # 7. Active guardian rotates owner_policy after activation -> resolve_name at tip refuses NAME_OWNER_MISMATCH
    wa_gmiss = copy.deepcopy(wa_ok)
    g1_hist = wa_gmiss["chain"]["names"]["id/parent-a"]["updates"]
    new_g1_own_pol = {"kind": "key", "pk": _kp("g1-new-owner-after-act")["comp"]}
    prev_u = g1_hist[-1]
    val_b_g1 = sl.jcs_encode({"link": {"grant": of_wa["_keys"]["g1_gr"]["xonly"]}})
    new_g1_spk, _ = sl.compile_script_policy(new_g1_own_pol)
    g1_hist.append({
        "confirmed_height": 749500,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", new_g1_spk, name=b"id/parent-a", value=val_b_g1).hex(),
        "owner_policy": new_g1_own_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": prev_u["txid"], "vout": prev_u["vout"], "witness_policy": prev_u["owner_policy"]},
        "txid": _h32("g1-xfer-tx"),
        "vout": 0,
    })
    add("branch-ward-approval-guardian-owner-changed-at-tip", ["SL-ORIG-005", "SL-ORIG-006"], "assent",
        {"assent": wa_gmiss["assent"], "contract": wa_gmiss["contract"], "origin_bundle": wa_gmiss["origin_bundle"],
         "chain": wa_gmiss["chain"], "trusted_origin_issuer_pins": of_wa["trusted_origin_issuer_pins"]},
        "REFUSE", "GUARDIAN_INACTIVE",
        "Active guardian whose Namecoin owner_policy changed after activation MUST refuse GUARDIAN_INACTIVE at tip (SL-ORIG-006 / H-35).")

    # 8. Post-majority adult (after majority handover NAME_UPDATE) assenting a ward-only contract party lacking signing_policy
    wa_adult = copy.deepcopy(wa_ok)
    wa_adult["chain"]["now"] = wa_adult["origin_bundle"]["opened_majority_unix"] + 100
    wa_adult["chain"]["tip_header_time"] = wa_adult["chain"]["now"] - 60
    wa_adult["chain"]["tip_first_sight"] = wa_adult["chain"]["now"] - 60
    wa_adult["chain"]["credible_utc_interval"] = [wa_adult["chain"]["now"] - 50, wa_adult["chain"]["now"] + 50]
    leo_hist = wa_adult["chain"]["names"]["id/child-leo"]["updates"]
    prev_leo = leo_hist[-1]
    adult_own_pol = {"kind": "key", "pk": _kp("leo-adult-owner")["comp"]}
    adult_spk, _ = sl.compile_script_policy(adult_own_pol)
    leo_val_b = sl.jcs_encode({"link": {"grant": of_wa["_keys"]["ward_gr"]["xonly"], "origin": of_wa["_origin_id"]}})
    # Decision 1B: Transition to State 4 (autonomous) via confirmed seallink-capacity/1 + handover transfer + self-update
    cap_adult_p = {
        "basis_sha256": _h32("leo-adult-basis"),
        "genesis": GENESIS_MAIN,
        "issued_at": wa_adult["chain"]["now"] - 500,
        "issuer": wa_adult["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "next_status_policy": wa_adult["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"],
        "next_status_vout": 0,
        "origin_id": of_wa["_origin_id"],
        "status_prev_outpoint": {"txid": wa_adult["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": wa_adult["origin_bundle"]["origin"]["payload"]["status_seal"]["vout"]},
        "subject_new_owner_policy": adult_own_pol,
        "type": "seallink-capacity/1",
    }
    cap_adult_env = sl.sign_envelope(cap_adult_p, [of_wa["_keys"]["reg_cred"]["sk"]])
    cap_adult_tx = _h32("leo-adult-cap-tx")
    wa_adult["chain"]["txs"][wa_adult["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_adult_tx
    wa_adult["chain"]["txs"][cap_adult_tx] = {
        "confirmed_height": 749890,
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_adult_env)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(cap_adult_p["next_status_policy"])}},
    }
    wa_adult["origin_bundle"]["capacity_record"] = cap_adult_env
    wa_adult["contract"]["parties"][0]["name_pin"]["owner_policy"] = adult_own_pol
    leo_hist.append({
        "confirmed_height": 749900,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", adult_spk, name=b"id/child-leo", value=leo_val_b).hex(),
        "owner_policy": adult_own_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": prev_leo["txid"], "vout": prev_leo["vout"], "witness_policy": prev_leo["owner_policy"]},
        "txid": _h32("leo-majority-handover"),
        "vout": 0,
    })
    leo_hist.append({
        "confirmed_height": 749910,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", adult_spk, name=b"id/child-leo", value=leo_val_b).hex(),
        "owner_policy": adult_own_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": _h32("leo-majority-handover"), "vout": 0, "witness_policy": adult_own_pol},
        "txid": _h32("leo-majority-confirm"),
        "vout": 0,
    })
    adult_assent = sl.sign_envelope(
        {
            "expires_at": wa_adult["chain"]["now"] + 100000,
            "genesis": GENESIS_MAIN,
            "issued_at": wa_adult["chain"]["now"] - 100,
            "network": "main",
            "nonce": _h32("adult-no-sp-nonce"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": sl.object_id(wa_adult["contract"]),
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [of_wa["_keys"]["ward_gr"]["sk"]],
    )
    add("branch-assent-adult-missing-signing-policy", ["SL-CONT-002"], "assent",
        {"assent": adult_assent, "contract": wa_adult["contract"], "origin_bundle": wa_adult["origin_bundle"],
         "chain": wa_adult["chain"], "trusted_origin_issuer_pins": of_wa["trusted_origin_issuer_pins"]},
        "REFUSE", "CONTRACT_ASSENT_INVALID",
        "Adult capacity assent against a ward-mode contract party without signing_policy MUST refuse CONTRACT_ASSENT_INVALID.")

    # 9. Contract-bound invocation whose contract seal is spent
    fx_cs = rm._base_invocation_fixture()
    c_seal_pol = {"kind": "key", "pk": _kp("cseal-br")["comp"]}
    c_seal_tx = _h32("cseal-br-tx")
    c_seal_spend = _h32("cseal-br-spend")
    c_br = {
        "clause_commitments": [sl.clause_commit(_h32("cbr-s"), {"text": "Lease"})],
        "contract_salt": _h32("cbr-salt"),
        "genesis": GENESIS_MAIN,
        "network": "main",
        "parties": [
            {"party_id": "p1", "role": "issuer", "signing_policy": {"m": 1, "pks": [fx_cs["_keys"]["alice_gr"]["xonly"]]}},
            {"party_id": "p2", "role": "counterparty", "signing_policy": {"m": 1, "pks": [fx_cs["_keys"]["agent_req"]["xonly"]]}},
        ],
        "profile": "lease-v1",
        "seal": {"script_policy": c_seal_pol, "txid": c_seal_tx, "vout": 0},
        "type": "seallink-contract/1",
        "window": {"not_after_height": 760000, "not_before_height": 749000},
    }
    cid_br = sl.object_id(c_br)
    a_c1 = sl.sign_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("ac1-cs"), "party_id": "p1", "party_role": "issuer", "target_id": cid_br, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [fx_cs["_keys"]["alice_gr"]["sk"]],
    )
    a_c2 = sl.sign_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("ac2-cs"), "party_id": "p2", "party_role": "counterparty", "target_id": cid_br, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [fx_cs["_keys"]["agent_req"]["sk"]],
    )
    gp_cs = copy.deepcopy(fx_cs["bundle"]["grants"][0]["payload"])
    gp_cs["contract_id"] = cid_br
    g_cs = sl.sign_envelope(gp_cs, [fx_cs["_keys"]["alice_gr"]["sk"]])
    gid_cs = sl.object_id(gp_cs)
    itx_cs = _h32("itx-cseal-spent")
    fx_cs["chain"]["txs"][c_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(c_seal_pol), "spent_by_txid": c_seal_spend}}}
    fx_cs["chain"]["txs"][c_seal_spend] = {"confirmed_height": 749950, "outputs": {}}
    fx_cs["chain"]["txs"][itx_cs] = {
        "confirmed_height": 749905,
        "inputs": [sv.make_segwit_input(gp_cs["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"assent_content_addrs": sorted([sl.content_addr(a_c1), sl.content_addr(a_c2)]), "contract_id": cid_br, "genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_cs), "grant_id": gid_cs, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_cs = sl.sign_envelope(
        {**fx_cs["invocation"]["payload"], "nonce": _h32("n-cseal-sp"), "proof_path": [{"grant_id": gid_cs, "issuance_txid": itx_cs}]},
        [fx_cs["_keys"]["agent_req"]["sk"]],
    )
    add("branch-inv-contract-seal-spent", ["SL-CONT-005"], "invocation",
        {"invocation": inv_cs, "bundle": {**fx_cs["bundle"], "grants": [g_cs], "contract": c_br, "contract_assents": [a_c1, a_c2]}, "chain": fx_cs["chain"], "journal": {"journal_id": _h32("j-cseal-sp")}, "executor_cfg": fx_cs["executor_cfg"]},
        "REFUSE", "SEAL_SPENT",
        "Contract-bound invocation whose contract seal is spent MUST refuse SEAL_SPENT.")

    # 10. Recipient mode=name whose Namecoin record lacks `nostr` key
    fx_nn = rm._base_invocation_fixture()
    bob_own = _kp("bob-nonostr-own")
    bob_pol = {"kind": "key", "pk": bob_own["comp"]}
    bob_reg = {"txid": _h32("bob-nonostr-reg"), "vout": 0}
    fx_nn["chain"]["names"]["id/bob-no-nostr"] = sv.make_name_history(
        "id/bob-no-nostr", bob_reg, bob_pol, {"link": {"grant": _kp("bob-nonostr-gr")["xonly"]}}, first_height=748000, update_height=749000
    )
    gp_nn = copy.deepcopy(fx_nn["bundle"]["grants"][0]["payload"])
    gp_nn["recipient"] = {"mode": "name", "name": "id/bob-no-nostr", "owner_policy": bob_pol, "registration": bob_reg}
    g_nn = sl.sign_envelope(gp_nn, [fx_nn["_keys"]["alice_gr"]["sk"]])
    gid_nn = sl.object_id(gp_nn)
    itx_nn = _h32("itx-rcpt-nonostr")
    orig_itx_h = fx_nn["chain"]["txs"][fx_nn["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["confirmed_height"]
    fx_nn["chain"]["txs"][itx_nn] = {
        "confirmed_height": orig_itx_h,
        "inputs": [sv.make_segwit_input(gp_nn["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_nn), "grant_id": gid_nn, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_nn = sl.sign_envelope(
        {**fx_nn["invocation"]["payload"], "nonce": _h32("n-rcpt-nonostr"), "proof_path": [{"grant_id": gid_nn, "issuance_txid": itx_nn}]},
        [fx_nn["_keys"]["agent_req"]["sk"]],
    )
    add("branch-inv-recipient-name-no-nostr", ["SL-GRNT-003"], "invocation",
        {"invocation": inv_nn, "bundle": {**fx_nn["bundle"], "grants": [g_nn]}, "chain": fx_nn["chain"], "journal": {"journal_id": _h32("j-rcpt-nonostr")}, "executor_cfg": fx_nn["executor_cfg"]},
        "REFUSE", "WIRE_SIGNATURE",
        "Invocation for recipient.mode=name whose Namecoin value omits nostr pubkey MUST refuse WIRE_SIGNATURE.")
