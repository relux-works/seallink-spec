#!/usr/bin/env python3
"""
Draft.9 Clean-Core Closure Conformance Suite (`D8-B1..B5`, `D8-M1..M9`).

Executable golden vectors covering every review blocker & major resolved in v1.0.0-draft.9:
  - D8-B1: 0x0b CredentialBreak with role='grant' schema validation + exact h_c-1 / h_c / h_c+1 truth table + successor key survival
  - D8-B2: Crossed-order receipt settlements[] golden JournalEntry commitment + uncertain 0-write idempotent retry, conflict INVOKE_REPLAY, refund ban, & uncertain -> executed reconciliation
  - D8-B3: Core-only verifier (enabled_modules=['core']) refusing all 3 optional modules with ACTION_UNSUPPORTED and 0 writes
  - D8-B4: 32-quota / 96-debit-line delegated session-use JournalEntry golden vector + restart replay
  - D8-M1: Canonical SPEC-02 §2.2 observation_bracket without redundant rebracket_tip (ADMIT, start!=end VOID, tip mismatch VOID)
  - D8-M3: Self-contained single_use 3-process restart recovery strictly from persisted JournalEntry[] + action mismatch + missing/mismatched use_txid refusals
  - D8-M5: Eternal subject.mode='origin' credential between h_origin and h_binding, historical pending_delay RECOVERY_FORBIDDEN, 0x10 missing block_time fail-closed lockout, capacity/1 temporal order & K1->K2 recovery
  - D8-M7: Bearer session open returning bearer_token (golden 00..1f SHA256 check), issuer-signed close, mandatory depth-2 parent_grant_env, live vs spent contract_seal recheck
  - D8-M8: Migration mode='stage' BEFORE source fencing (0 writes ADMIT) + mode='activate' mandatory local_executor_pin & source fencing
  - D8-M9: Contour A PII disclosure mandatory recipient.mode='name' & mandatory fields_sha256
"""

from __future__ import annotations

import copy
from typing import Any, Callable

import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = rm.GENESIS_MAIN


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-d9:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"d9:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def _reanchor(fx: dict[str, Any], gp: dict[str, Any], signer_sk: bytes | None = None) -> tuple[dict[str, Any], str]:
    sk = signer_sk or fx["_keys"]["alice_gr"]["sk"]
    g_env = sl.sign_envelope(gp, [sk])
    gid = sl.object_id(gp)
    iss_txid = fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    iss_prep: dict[str, Any] = {
        "genesis": gp["genesis"],
        "grant_content_addr": sl.content_addr(g_env),
        "grant_id": gid,
        "type": "seallink-issuance/1",
    }
    if "contract_id" in gp:
        iss_prep["contract_id"] = gp["contract_id"]
    fx["chain"]["txs"][iss_txid]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest(iss_prep).hex(), 0x00).hex()
    fx["bundle"]["grants"] = [g_env]
    inv_p = copy.deepcopy(fx["invocation"]["payload"])
    inv_p["proof_path"] = [{"grant_id": gid, "issuance_txid": iss_txid}]
    fx["invocation"] = sl.sign_envelope(inv_p, [fx["_keys"]["agent_req"]["sk"]])
    return g_env, gid


def _make_0x0b_update(
    name: str,
    prev_u: dict[str, Any],
    reg: dict[str, Any],
    owner_pol: dict[str, Any],
    role: str,
    compromised_pol: dict[str, Any],
    new_val: dict[str, Any],
    h_c: int,
    h_update: int,
    label: str,
) -> dict[str, Any]:
    cb = {
        "compromised_policy": compromised_pol,
        "genesis": GENESIS_MAIN,
        "h_c": h_c,
        "issuer": {"name": name, "registration": reg},
        "name_input": {"txid": prev_u["txid"], "vout": prev_u["vout"]},
        "role": role,
        "type": "seallink-credential-break/1",
    }
    ospk, _ = sl.compile_script_policy(owner_pol)
    return {
        "block_time": 1795215000,
        "confirmed_height": h_update,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(cb).hex(), h_c=h_c).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", ospk, name=name.encode("utf-8"), value=sl.jcs_encode(new_val)).hex(),
        "owner_policy": owner_pol,
        "prev_input": {"sighash_bytes": [1], "txid": prev_u["txid"], "vout": prev_u["vout"], "witness_policy": owner_pol},
        "txid": _h32(f"0b-upd-{label}"),
        "vout": 0,
    }


def add_draft9_conformance_cases(add: Callable[..., None]) -> None:
    """Register all v1.0.0-draft.9 clean-core closure conformance vectors."""

    # =========================================================================
    # 1. D8-B1: 0x0b CredentialBreak with role='grant' + exact h_c-1 / h_c / h_c+1 truth table
    # =========================================================================
    of_b1 = rm._base_origin_fixture()
    g1_rec = of_b1["chain"]["names"]["id/parent-a"]
    g1_reg = g1_rec["registration"]
    g1_prev = g1_rec["updates"][-1]
    g1_opol = g1_prev["owner_policy"]
    g1_old_pk = of_b1["_keys"]["g1_gr"]["xonly"]
    g1_new_k = _kp("b1-g1-succ")
    cb_grant = {
        "compromised_policy": {"m": 1, "pks": [g1_old_pk]},
        "genesis": GENESIS_MAIN,
        "h_c": 749500,
        "issuer": {"name": "id/parent-a", "registration": g1_reg},
        "name_input": {"txid": g1_prev["txid"], "vout": g1_prev["vout"]},
        "role": "grant",
        "type": "seallink-credential-break/1",
    }
    add(
        "d9-b1-credential-break-role-grant-schema-admit",
        ["SL-CONT-009", "SL-ORIG-006"],
        "raw_wire",
        {"expected_type": "seallink-credential-break/1", "object": cb_grant},
        "ADMIT",
        None,
        "D8-B1: Reconstructed seallink-credential-break/1 with role='grant' MUST validate against schemas/credential.schema.json.",
    )

    # Reduce contract_assent quorum to 1-of-2 so guardian slot 1 alone tests exact h_c boundary cleanly!
    op_b1 = copy.deepcopy(of_b1["origin_bundle"]["origin"]["payload"])
    op_b1["guardian_policy"]["quorums"] = {k: {"den": 2, "min": 1, "num": 1} for k in op_b1["guardian_policy"]["quorums"]}
    o_b1 = sl.sign_envelope(op_b1, [of_b1["_keys"]["reg_cred"]["sk"]])
    oid_b1 = sl.object_id(op_b1)
    of_b1["origin_bundle"]["origin"] = o_b1
    of_b1["origin_bundle"]["name_binding"]["origin_id"] = oid_b1
    rm.sync_ward_origin_link(of_b1, oid_b1)
    g1_b1_p = {**of_b1["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_b1}
    g1_b1 = sl.sign_envelope(g1_b1_p, [of_b1["_keys"]["reg_cred"]["sk"]])
    of_b1["origin_bundle"]["guardian_records"] = [g1_b1]
    of_b1["origin_bundle"]["guardian_assents"] = [
        sl.sign_envelope({**of_b1["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(g1_b1_p)}, [of_b1["_keys"]["g1_gr"]["sk"]])
    ]
    of_b1["chain"]["txs"][of_b1["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_b1)).hex()
    of_b1["chain"]["txs"][of_b1["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_b1["origin_bundle"]["name_binding"])).hex()
    of_b1["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_b1)).hex()
    of_b1["chain"]["names"]["id/parent-a"]["updates"].append(
        _make_0x0b_update(
            "id/parent-a",
            g1_prev,
            g1_reg,
            g1_opol,
            "grant",
            {"m": 1, "pks": [g1_old_pk]},
            {"link": {"grant": g1_new_k["xonly"]}},
            h_c=749500,
            h_update=749505,
            label="d9-b1-g1",
        )
    )
    c_b1 = copy.deepcopy(of_b1["contract"])
    c_b1["parties"][0]["ward_origin_id"] = oid_b1
    wa_b1_old = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": oid_b1, "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000, "network": "main", "nonce": _h32("d9-b1-wa-old"),
            "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
            "target_id": sl.object_id(c_b1), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        },
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_b1["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    wa_b1_new = sl.sign_guardian_envelope(
        {**wa_b1_old["payload"], "nonce": _h32("d9-b1-wa-new")},
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [g1_new_k["sk"]], "slot": 1}],
    )
    for label_h, h_a, assent_obj, want_v, want_c, note_h in [
        ("hc-minus-1-admit", 749499, wa_b1_old, "ADMIT", None, "D8-B1: Historical ward assent at h_anchor = h_c - 1 survives guardian 0x0b role='grant' break."),
        ("hc-exact-refuse", 749500, wa_b1_old, "REFUSE", "CRED_ISSUER_CLOSED", "D8-B1: Historical ward assent at h_anchor == h_c refuses CRED_ISSUER_CLOSED under guardian 0x0b role='grant' break."),
        ("hc-plus-1-refuse", 749501, wa_b1_old, "REFUSE", "CRED_ISSUER_CLOSED", "D8-B1: Historical ward assent at h_anchor = h_c + 1 (retroactive break before key rotation at 749505) refuses CRED_ISSUER_CLOSED."),
        ("successor-key-admit", 749505, wa_b1_new, "ADMIT", None, "D8-B1: Historical ward assent signed by unaffected successor link.grant key B after rotation admits cleanly."),
    ]:
        add(
            f"d9-b1-ward-assent-0x0b-grant-{label_h}",
            ["SL-CONT-009", "SL-ORIG-006", "SL-CONT-004"],
            "assent",
            {
                "anchor_height": h_a,
                "anchor_time": 1795220010,
                "assent": assent_obj,
                "chain": of_b1["chain"],
                "contract": c_b1,
                "origin_bundle": of_b1["origin_bundle"],
                "trusted_origin_issuer_pins": of_b1["trusted_origin_issuer_pins"],
            },
            want_v,
            want_c,
            note_h,
        )

    # =========================================================================
    # 2. D8-B2: Crossed-order settlements[] golden JournalEntry hash + uncertain idempotency/reconcile/refund-ban
    # =========================================================================
    fx_co = rm._delegation_fx()
    # Add a 2nd quota to BOTH parent template & child grant so Phase 1 creates 4 lines (own q1, row q1, own q2, row q2)
    q1 = {"kind": "seallink/count", "max": "10", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}
    q2 = {"kind": "seallink/bytes", "max": "4096", "resource": "station:id/station-a:tools", "unit": "bytes", "window": "term"}
    p_co = copy.deepcopy(fx_co["bundle"]["grants"][0]["payload"])
    c_co = copy.deepcopy(fx_co["bundle"]["grants"][1]["payload"])
    p_co["delegate"]["pools"] = [
        {"kind": "seallink/count", "max": "20", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"},
        {"kind": "seallink/bytes", "max": "8192", "resource": "station:id/station-a:tools", "unit": "bytes", "window": "term"},
    ]
    p_co["capabilities"][0]["quotas"] = copy.deepcopy(p_co["delegate"]["pools"])
    p_co["delegate"]["groups"][0]["template"]["capabilities"][0]["quotas"] = [q1, q2]
    p_co_env = sl.sign_envelope(p_co, [fx_co["_keys"]["alice_gr"]["sk"]])
    pid_co = sl.object_id(p_co)
    c_co["parent"]["grant_id"] = pid_co
    c_co["capabilities"][0]["quotas"] = [q1, q2]
    c_co_env = sl.sign_envelope(c_co, [fx_co["_del_k"]["sk"]])
    cid_co = sl.object_id(c_co)
    p_itx_co = fx_co["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    c_itx_co = fx_co["invocation"]["payload"]["proof_path"][1]["issuance_txid"]
    fx_co["chain"]["txs"][p_itx_co]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_co_env), "grant_id": pid_co, "type": "seallink-issuance/1"}).hex()
    ).hex()
    fx_co["chain"]["txs"][c_itx_co]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_co_env), "grant_id": cid_co, "type": "seallink-issuance/1"}).hex()
    ).hex()
    fx_co["bundle"]["grants"] = [p_co_env, c_co_env]
    inv_co_p = copy.deepcopy(fx_co["invocation"]["payload"])
    inv_co_p["proof_path"] = [{"grant_id": pid_co, "issuance_txid": p_itx_co}, {"grant_id": cid_co, "issuance_txid": c_itx_co}]
    fx_co["invocation"] = sl.sign_envelope(inv_co_p, [fx_co["_keys"]["agent_req"]["sk"]])
    inv_co_id = sl.object_id(inv_co_p)
    # Crossed/permuted order in signed receipt: row:q2, own:q1, row:q1, own:q2!
    crossed_settlements = [
        {"account": "row", "kind": "seallink/bytes", "released": "512", "reserved": "1024", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "512", "unit": "bytes", "window": "term"},
        {"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "settled": "1", "unit": "calls", "window": "term"},
        {"account": "row", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "1", "unit": "calls", "window": "term"},
        {"account": "own", "kind": "seallink/bytes", "released": "512", "reserved": "1024", "resource": "station:id/station-a:tools", "settled": "512", "unit": "bytes", "window": "term"},
    ]
    rcpt_co = sl.sign_envelope(
        {
            "action": "agent/tool", "executor_name": "id/station-a", "genesis": GENESIS_MAIN, "grant_id": cid_co,
            "invocation_id": inv_co_id, "network": "main", "outcome": "executed", "recorded_at": fx_co["chain"]["now"],
            "result_sha256": _h32("d9-co-res"), "settlements": crossed_settlements,
            "tip_hash": fx_co["chain"]["tip_hash"], "tip_height": fx_co["chain"]["tip_height"], "type": "seallink-receipt/1",
        },
        [fx_co["_keys"]["host_rcpt"]["sk"]],
    )
    # Pre-compute golden journal commitment by running reference verifier once cleanly
    _v_tmp = sv.Tier1Verifier(require_jsonschema=True)
    _j_tmp = sv.FencedJournal(_h32("d9-co-j"))
    _p1_tmp = _v_tmp.admit_and_reserve(fx_co["invocation"], fx_co["bundle"], sv.ChainView(fx_co["chain"]), _j_tmp, fx_co["executor_cfg"])
    assert _p1_tmp.verdict == "ADMIT", _p1_tmp
    _p2_tmp = _v_tmp.commit_result(rcpt_co, _j_tmp, fx_co["executor_cfg"], invocation_id=inv_co_id, grant_id=cid_co)
    assert _p2_tmp.verdict == "ADMIT", _p2_tmp
    golden_co_commit = _j_tmp.commitment
    add(
        "d9-b2-crossed-order-settlements-golden-order-admit",
        ["SL-GRNT-007", "SL-GRNT-008"],
        "commit_edge",
        {
            "bundle": fx_co["bundle"],
            "chain": fx_co["chain"],
            "executor_cfg": fx_co["executor_cfg"],
            "expect_head_commitment": golden_co_commit,
            "expect_settlement_order": [
                "row:1:seallink/bytes:bytes",
                "own::seallink/count:calls",
                "row:1:seallink/count:calls",
                "own::seallink/bytes:bytes",
            ],
            "expect_total_entries": 2,
            "invocation": fx_co["invocation"],
            "journal_id": _h32("d9-co-j"),
            "receipt_env": rcpt_co,
        },
        "ADMIT",
        None,
        "D8-B2: Journal settlement entry MUST preserve signed receipt.payload.settlements[] order (exact golden hash commitment verified across crossed 4-line order).",
    )

    # D8-B2: uncertain 0-write idempotent retry (pos 2->2), conflicting uncertain INVOKE_REPLAY, & uncertain -> executed reconciliation releasing reserve!
    rcpt_unc1 = sl.sign_envelope(
        {
            "action": "agent/tool", "executor_name": "id/station-a", "genesis": GENESIS_MAIN, "grant_id": cid_co,
            "invocation_id": inv_co_id, "network": "main", "outcome": "uncertain", "recorded_at": fx_co["chain"]["now"],
            "settlements": [
                {"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "settled": "1", "unit": "calls", "window": "term"},
                {"account": "row", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "1", "unit": "calls", "window": "term"},
                {"account": "own", "kind": "seallink/bytes", "released": "0", "reserved": "1024", "resource": "station:id/station-a:tools", "settled": "1024", "unit": "bytes", "window": "term"},
                {"account": "row", "kind": "seallink/bytes", "released": "0", "reserved": "1024", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "1024", "unit": "bytes", "window": "term"},
            ],
            "tip_hash": fx_co["chain"]["tip_hash"], "tip_height": fx_co["chain"]["tip_height"], "type": "seallink-receipt/1",
        },
        [fx_co["_keys"]["host_rcpt"]["sk"]],
    )
    rcpt_unc_conflict = sl.sign_envelope(
        {**rcpt_unc1["payload"], "recorded_at": fx_co["chain"]["now"] + 5},
        [fx_co["_keys"]["host_rcpt"]["sk"]],
    )
    rcpt_unc_refund = sl.sign_envelope(
        {**rcpt_co["payload"], "outcome": "uncertain"},
        [fx_co["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d9-b2-uncertain-idempotent-retry-conflict-and-reconcile",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "commit_edge",
        {
            "bundle": fx_co["bundle"],
            "chain": fx_co["chain"],
            "executor_cfg": fx_co["executor_cfg"],
            "expect_total_entries": 2,
            "extra_commits": [
                {
                    "check_balances": [{"bucket_id": "term", "expected": 1024, "qkey": "seallink/bytes|station:id/station-a:tools|bytes|term", "scope": f"own:{cid_co}"}],
                    "expect_pos": 2,
                    "expect_zero_writes": True,
                    "label": "repeat-identical-uncertain-zero-writes",
                    "receipt_env": rcpt_unc1,
                    "want_refusal": None,
                    "want_verdict": "ADMIT",
                },
                {
                    "expect_pos": 2,
                    "expect_zero_writes": True,
                    "label": "conflicting-uncertain-refuse-replay",
                    "receipt_env": rcpt_unc_conflict,
                    "want_refusal": "INVOKE_REPLAY",
                    "want_verdict": "REFUSE",
                },
                {
                    "check_balances": [
                        {"bucket_id": "term", "expected": 512, "qkey": "seallink/bytes|station:id/station-a:tools|bytes|term", "scope": f"own:{cid_co}"},
                        {"bucket_id": "term", "expected": 512, "qkey": "seallink/bytes|station:id/station-a:tools|bytes|term", "scope": f"row:{pid_co}:1"},
                    ],
                    "expect_pos": 3,
                    "label": "reconcile-uncertain-to-executed-releases-reserve",
                    "receipt_env": rcpt_co,
                    "want_refusal": None,
                    "want_verdict": "ADMIT",
                },
            ],
            "invocation": fx_co["invocation"],
            "journal_id": _h32("d9-unc-j"),
            "receipt_env": rcpt_unc1,
        },
        "ADMIT",
        None,
        "D8-B2: Repeating identical signed uncertain receipt is 0-write idempotent (pos 2->2); conflicting uncertain refuses INVOKE_REPLAY; later executed receipt reconciles & releases 512 bytes.",
    )
    add(
        "d9-b2-uncertain-refund-forbidden-refuse",
        ["SL-GRNT-007"],
        "commit_edge",
        {
            "bundle": fx_co["bundle"],
            "chain": fx_co["chain"],
            "executor_cfg": fx_co["executor_cfg"],
            "invocation": fx_co["invocation"],
            "journal_id": _h32("d9-unc-ref-j"),
            "receipt_env": rcpt_unc_refund,
        },
        "REFUSE",
        "WIRE_MEMBER",
        "D8-B2: Uncertain receipt MUST retain full reserve (released > 0 refuses WIRE_MEMBER).",
    )

    # =========================================================================
    # 3. D8-B3: Core-only verifier refusing all 3 optional modules with ACTION_UNSUPPORTED (0 writes!)
    # =========================================================================
    fx_b3 = rm._base_invocation_fixture()
    gid_b3 = sl.object_id(fx_b3["bundle"]["grants"][0]["payload"])
    so_b3 = sl.sign_envelope(
        {
            "executor": fx_b3["bundle"]["grants"][0]["payload"]["executor"],
            "exp": fx_b3["chain"]["now"] + 600,
            "genesis": GENESIS_MAIN,
            "iat": fx_b3["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d9-b3-so-n"),
            "op": "open",
            "proof_path": fx_b3["invocation"]["payload"]["proof_path"],
            "quotas": [],
            "slot_binding": "slot-1",
            "type": "seallink-session-open/1",
        },
        [fx_b3["_keys"]["agent_req"]["sk"]],
    )
    add(
        "d9-b3-core-only-session-open-action-unsupported",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "enabled_modules": ["core"],
            "executor_cfg": fx_b3["executor_cfg"],
            "journal": {"journal_id": _h32("d9-b3-j1")},
            "steps": [{"bundle": fx_b3["bundle"], "chain": fx_b3["chain"], "expect_zero_writes": True, "kind": "session_open", "label": "open-disabled", "session_open": so_b3, "want_refusal": "ACTION_UNSUPPORTED", "want_verdict": "REFUSE"}],
        },
        "ADMIT",
        None,
        "D8-B3: Core-only verifier with bearer-sessions disabled refuses seallink-session-open/1 with ACTION_UNSUPPORTED and zero journal writes.",
        module="core",
    )
    add(
        "d9-b3-core-only-bearer-session-action-unsupported",
        ["SL-GRNT-013"],
        "bearer_session",
        {
            "chain": fx_b3["chain"],
            "enabled_modules": ["core"],
            "expect_zero_writes": True,
            "grant_env": fx_b3["bundle"]["grants"][0],
            "journal": {"journal_id": _h32("d9-b3-j2")},
            "slot_binding": "slot-1",
            "token": _h32("d9-b3-tok"),
        },
        "REFUSE",
        "ACTION_UNSUPPORTED",
        "D8-B3: Core-only verifier with bearer-sessions disabled refuses verify_bearer_session with ACTION_UNSUPPORTED and zero journal writes.",
        module="core",
    )
    mig_b3_inv = {"holder_name": "id/alice", "items": [], "migration_id": _h32("d9-b3-mid"), "service_type": "mail"}
    mig_b3_env = sl.sign_envelope(
        {
            "dest_executor": {"name": "id/mail-host-b", "owner_policy": {"kind": "key", "pk": _kp("d9-b3-do")["comp"]}, "registration": {"txid": _h32("d9-b3-dr"), "vout": 0}},
            "genesis": GENESIS_MAIN,
            "holder": {"name": "id/alice", "owner_policy": fx_b3["_alice_owner_pol"], "registration": fx_b3["_alice_reg"]},
            "inventory_sha256": sl.sha256(sl.jcs_encode(mig_b3_inv)).hex(),
            "issued_at": fx_b3["chain"]["now"],
            "journal_commitment": _h32("d9-b3-jc"),
            "journal_pos": 1,
            "migration_id": _h32("d9-b3-mid"),
            "network": "main",
            "outstanding_exposure": [],
            "service_type": "mail",
            "source_executor": {"name": "id/mail-host-a", "owner_policy": fx_b3["_host_owner_pol"], "registration": fx_b3["_host_reg"]},
            "type": "seallink-migration/1",
        },
        [fx_b3["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d9-b3-core-only-migration-action-unsupported",
        ["SL-SERV-003"],
        "migration",
        {
            "chain": fx_b3["chain"],
            "enabled_modules": ["core"],
            "expect_zero_writes": True,
            "export_bundle": {"inventory": mig_b3_inv, "source_journal_commitment": _h32("d9-b3-jc"), "source_journal_pos": 1},
            "journal": {"journal_id": _h32("d9-b3-j3")},
            "manifests": fx_b3["bundle"]["manifests"],
            "migration": mig_b3_env,
        },
        "REFUSE",
        "ACTION_UNSUPPORTED",
        "D8-B3: Core-only verifier with service-migration disabled refuses verify_migration with ACTION_UNSUPPORTED and zero journal writes.",
        module="core",
    )
    add(
        "d9-b3-core-only-federation-action-unsupported",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_b3["chain"],
            "enabled_modules": ["core"],
            "grant": fx_b3["bundle"]["grants"][0],
            "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"},
            "policy": {"trusted_peers": ["id/peer-b"]},
        },
        "REFUSE",
        "ACTION_UNSUPPORTED",
        "D8-B3: Core-only verifier with federated-screening disabled refuses verify_federation_disclosure with ACTION_UNSUPPORTED.",
        module="core",
    )

    # =========================================================================
    # 4. D8-B4: 32-quota / 96-debit-line delegated session-use golden vector
    # =========================================================================
    fx_96 = rm._delegation_fx()
    quotas_32 = [
        {
            "kind": "seallink/count",
            "max": "10",
            "resource": "station:id/station-a:tools" if i == 0 else f"station:id/station-a:tools:r{i:02d}",
            "unit": "calls",
            "window": "term",
        }
        for i in range(32)
    ]
    pools_32 = [{**q, "max": "20"} for q in quotas_32]
    p96 = copy.deepcopy(fx_96["bundle"]["grants"][0]["payload"])
    c96 = copy.deepcopy(fx_96["bundle"]["grants"][1]["payload"])
    p96["capabilities"][0]["quotas"] = copy.deepcopy(pools_32)
    p96["delegate"]["groups"][0]["template"]["capabilities"][0]["quotas"] = quotas_32
    p96["delegate"]["pools"] = pools_32
    p96_env = sl.sign_envelope(p96, [fx_96["_keys"]["alice_gr"]["sk"]])
    pid96 = sl.object_id(p96)
    c96["parent"]["grant_id"] = pid96
    c96["capabilities"][0]["quotas"] = quotas_32
    c96_env = sl.sign_envelope(c96, [fx_96["_del_k"]["sk"]])
    cid96 = sl.object_id(c96)
    p96_itx = fx_96["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    c96_itx = fx_96["invocation"]["payload"]["proof_path"][1]["issuance_txid"]
    fx_96["chain"]["txs"][p96_itx]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p96_env), "grant_id": pid96, "type": "seallink-issuance/1"}).hex()
    ).hex()
    fx_96["chain"]["txs"][c96_itx]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c96_env), "grant_id": cid96, "type": "seallink-issuance/1"}).hex()
    ).hex()
    fx_96["bundle"]["grants"] = [p96_env, c96_env]
    so96 = sl.sign_envelope(
        {
            "executor": c96["executor"],
            "exp": fx_96["chain"]["now"] + 1800,
            "genesis": GENESIS_MAIN,
            "iat": fx_96["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d9-96-open"),
            "op": "open",
            "proof_path": [{"grant_id": pid96, "issuance_txid": p96_itx}, {"grant_id": cid96, "issuance_txid": c96_itx}],
            "quotas": quotas_32,
            "slot_binding": "slot-96",
            "type": "seallink-session-open/1",
        },
        [fx_96["_keys"]["agent_req"]["sk"]],
    )
    tok96 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    assert sl.sha256(tok96.encode("utf-8")).hex() == "6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b"
    add(
        "d9-b4-session-use-32-quotas-96-debits-admit",
        ["SL-GRNT-013", "SL-GRNT-007"],
        "session_lifecycle",
        {
            "executor_cfg": fx_96["executor_cfg"],
            "journal": {"journal_id": _h32("d9-96-j")},
            "steps": [
                {"bearer_token": tok96, "bundle": fx_96["bundle"], "chain": fx_96["chain"], "expect_bearer_token": True, "kind": "session_open", "label": "open-32q", "session_open": so96, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/tool", "arguments": {"input_sha256": _h32("in96"), "max_output_bytes": "128", "tool_name": "pytest"}, "chain": fx_96["chain"], "expect_debit_count": 96, "grant_env": c96_env, "kind": "bearer_session", "label": "use-96-debits", "parent_grant_env": p96_env, "slot_binding": "slot-96", "target": "station:id/station-a:tools", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
                {"kind": "replay_restart", "label": "restart-96-debits"},
                {"action": "agent/tool", "arguments": {"input_sha256": _h32("in96b"), "max_output_bytes": "128", "tool_name": "pytest"}, "chain": fx_96["chain"], "expect_debit_count": 96, "grant_env": c96_env, "kind": "bearer_session", "label": "post-restart-use", "parent_grant_env": p96_env, "slot_binding": "slot-96", "target": "station:id/station-a:tools", "token": tok96, "want_refusal": None, "want_verdict": "ADMIT"},
            ],
        },
        "ADMIT",
        None,
        "D8-B4: Depth-2 bearer session with 32 capability quotas atomically writes a schema-valid 96-debit session-use JournalEntry (32 session + 32 own + 32 row) and survives restart replay.",
        module="bearer-sessions",
    )

    # =========================================================================
    # 5. D8-M1: Canonical SPEC-02 §2.2 ChainView observation_bracket without rebracket_tip
    # =========================================================================
    ch_m1 = copy.deepcopy(fx_b3["chain"])
    ch_m1.pop("rebracket_tip", None)
    ch_m1["observation_bracket"] = {
        "consistent": True,
        "end": {"hash": ch_m1["tip_hash"], "height": ch_m1["tip_height"]},
        "start": {"hash": ch_m1["tip_hash"], "height": ch_m1["tip_height"]},
    }
    add(
        "d9-m1-canonical-observation-bracket-no-rebracket-tip-admit",
        ["SL-LDGR-015", "SL-LDGR-008"],
        "chain_obs",
        {"chain": ch_m1, "require_observation_bracket": True},
        "ADMIT",
        None,
        "D8-M1: Canonical SPEC-02 §2.2 observation_bracket {consistent:true, start==end==tip} admits under require_observation_bracket=True even without redundant rebracket_tip.",
    )
    ch_m1_se = copy.deepcopy(ch_m1)
    ch_m1_se["observation_bracket"]["end"] = {"hash": _h32("m1-other-end"), "height": ch_m1["tip_height"] + 1}
    add(
        "d9-m1-canonical-observation-bracket-start-end-mismatch-refuse",
        ["SL-LDGR-015", "SL-LDGR-008"],
        "chain_obs",
        {"chain": ch_m1_se, "require_observation_bracket": True},
        "REFUSE",
        "CHAIN_OBSERVATION_VOID",
        "D8-M1: observation_bracket with start != end refuses CHAIN_OBSERVATION_VOID even if consistent=True is spoofed.",
    )
    ch_m1_tip = copy.deepcopy(ch_m1)
    ch_m1_tip["observation_bracket"]["start"] = {"hash": _h32("m1-wrong-tip"), "height": ch_m1["tip_height"]}
    ch_m1_tip["observation_bracket"]["end"] = {"hash": _h32("m1-wrong-tip"), "height": ch_m1["tip_height"]}
    add(
        "d9-m1-canonical-observation-bracket-tip-mismatch-refuse",
        ["SL-LDGR-015", "SL-LDGR-008"],
        "chain_obs",
        {"chain": ch_m1_tip, "require_observation_bracket": True},
        "REFUSE",
        "CHAIN_OBSERVATION_VOID",
        "D8-M1: observation_bracket with start == end != (tip_hash, tip_height) refuses CHAIN_OBSERVATION_VOID.",
    )

    # =========================================================================
    # 6. D8-M3: Self-contained single_use 3-process restart recovery & commit_result guards
    # =========================================================================
    fx_su = rm._base_invocation_fixture()
    su_pol = {"kind": "branch", "template": "single_use_1_of_2", "keys": {"grantee": fx_su["_keys"]["agent_own"]["comp"], "issuer": fx_su["_keys"]["alice_seal"]["comp"]}}
    su_spk, su_ws = sl.compile_script_policy(su_pol)
    assert su_ws is not None
    su_seal_tx = _h32("d9-m3-su-seal")
    gp_su = copy.deepcopy(fx_su["bundle"]["grants"][0]["payload"])
    gp_su["revocation"] = {"construction": "W", "kind": "single_use", "mode": "seal", "seal": {"script_policy": su_pol, "txid": su_seal_tx, "vout": 0}}
    g_su_env, gid_su = _reanchor(fx_su, gp_su)
    fx_su["chain"]["txs"][su_seal_tx] = {
        "confirmed_height": 749995,
        "inputs": [sv.make_segwit_input(_h32("d9-m3-fund"), 0)],
        "outputs": {"0": {"script_pubkey_hex": su_spk.hex()}, "1": {"script_pubkey_hex": _spk_hex(fx_su["_alice_owner_pol"])}},
    }
    su_itx = fx_su["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx_su["chain"]["txs"][su_itx]["inputs"] = [sv.make_segwit_input(su_seal_tx, 1)]
    su_use_tx = _h32("d9-m3-use-tx")
    fx_su["chain"]["txs"][su_seal_tx]["outputs"]["0"]["spent_by_txid"] = su_use_tx
    fx_su["chain"]["txs"][su_use_tx] = {
        "confirmed_height": 750002,
        "inputs": [{"prev_txid": su_seal_tx, "prev_vout": 0, "script_sig_hex": "", "witness": ["3044" + ("02" * 68) + "01", "", su_ws.hex()]}],
        "opreturn_hex": sl.encode_opreturn(0x11, sl.content_addr(fx_su["invocation"])).hex(),
        "outputs": {},
    }
    rcpt_su = sl.sign_envelope(
        {
            "action": "mail/read", "executor_name": "id/mail-host-a", "genesis": GENESIS_MAIN, "grant_id": gid_su,
            "invocation_id": sl.object_id(fx_su["invocation"]["payload"]), "network": "main", "outcome": "executed",
            "recorded_at": fx_su["chain"]["now"], "result_sha256": _h32("d9-m3-res"), "settlements": [],
            "tip_hash": fx_su["chain"]["tip_hash"], "tip_height": fx_su["chain"]["tip_height"], "type": "seallink-receipt/1",
        },
        [fx_su["_keys"]["host_rcpt"]["sk"]],
    )
    inv_su_new = sl.sign_envelope({**fx_su["invocation"]["payload"], "nonce": _h32("d9-m3-n2")}, [fx_su["_keys"]["agent_req"]["sk"]])
    add(
        "d9-m3-single-use-self-contained-restart-commit-admit",
        ["SL-GRNT-006", "SL-GRNT-007", "SL-GRNT-014"],
        "commit_edge",
        {
            "actual_message_meta": {"folder": "Invoices"},
            "bundle": fx_su["bundle"],
            "chain": fx_su["chain"],
            "executor_cfg": fx_su["executor_cfg"],
            "expect_total_entries": 2,
            "invocation": fx_su["invocation"],
            "journal_id": _h32("d9-m3-j1"),
            "post_restart_new_invocation": inv_su_new,
            "receipt_env": rcpt_su,
            "self_contained_restart": True,
            "use_txid": su_use_tx,
        },
        "REFUSE",
        "INVOKE_REPLAY",
        "D8-M3: After Phase-1 restart strictly from JournalEntry[] + witness, commit_result auto-recovers single_use & use_txid from reservation, writes SINGLE_USE_CONSUMED closure, and refuses a second new-nonce invocation with INVOKE_REPLAY.",
    )
    rcpt_wrong_act = sl.sign_envelope({**rcpt_su["payload"], "action": "mail/list"}, [fx_su["_keys"]["host_rcpt"]["sk"]])
    add(
        "d9-m3-commit-action-mismatch-from-reservation-refuse",
        ["SL-GRNT-007"],
        "commit_edge",
        {
            "actual_message_meta": {"folder": "Invoices"},
            "bundle": fx_su["bundle"],
            "chain": fx_su["chain"],
            "executor_cfg": fx_su["executor_cfg"],
            "invocation": fx_su["invocation"],
            "journal_id": _h32("d9-m3-j2"),
            "receipt_env": rcpt_wrong_act,
            "self_contained_restart": True,
            "use_txid": su_use_tx,
        },
        "REFUSE",
        "WIRE_MEMBER",
        "D8-M3: commit_result enforces rp['action'] == reservation['action'] persisted in Phase-1 JournalEntry without caller expected_action.",
    )
    add(
        "d9-m3-single-use-auto-derived-use-txid-admit",
        ["SL-GRNT-006", "SL-GRNT-007", "SL-GRNT-014"],
        "commit_edge",
        {
            "actual_message_meta": {"folder": "Invoices"},
            "bundle": fx_su["bundle"],
            "chain": fx_su["chain"],
            "executor_cfg": fx_su["executor_cfg"],
            "expect_total_entries": 2,
            "invocation": fx_su["invocation"],
            "journal_id": _h32("d9-m3-j3"),
            "post_restart_new_invocation": inv_su_new,
            "receipt_env": rcpt_su,
            "self_contained_restart": True,
        },
        "REFUSE",
        "INVOKE_REPLAY",
        "D10-M3/H-7: Single-use admit_and_reserve with use_txid omitted auto-derives spent_by_txid from verified branch-0 seal spend, persists it in reservation, commits SINGLE_USE_CONSUMED after restart, and refuses replay with INVOKE_REPLAY.",
    )
    fx_ord_su = rm._base_invocation_fixture()
    gid_ord = sl.object_id(fx_ord_su["bundle"]["grants"][0]["payload"])
    rcpt_ord = sl.sign_envelope(
        {
            "action": "mail/read", "executor_name": "id/mail-host-a", "genesis": GENESIS_MAIN, "grant_id": gid_ord,
            "invocation_id": sl.object_id(fx_ord_su["invocation"]["payload"]), "network": "main", "outcome": "executed",
            "recorded_at": fx_ord_su["chain"]["now"], "result_sha256": _h32("d9-m3-ord-res"), "settlements": [],
            "tip_hash": fx_ord_su["chain"]["tip_hash"], "tip_height": fx_ord_su["chain"]["tip_height"], "type": "seallink-receipt/1",
        },
        [fx_ord_su["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d9-m3-commit-mismatched-grant-id-refuse",
        ["SL-GRNT-007"],
        "commit_edge",
        {
            "actual_message_meta": {"folder": "Invoices"},
            "bundle": fx_ord_su["bundle"],
            "chain": fx_ord_su["chain"],
            "executor_cfg": fx_ord_su["executor_cfg"],
            "invocation": fx_ord_su["invocation"],
            "journal_id": _h32("d9-m3-j4"),
            "override_grant_id": _h32("d9-m3-wrong-gid"),
            "receipt_env": rcpt_ord,
        },
        "REFUSE",
        "WIRE_MEMBER",
        "D8-M3: commit_result with caller grant_id disagreeing with receipt & durable reservation refuses WIRE_MEMBER.",
    )

    # =========================================================================
    # 7. D8-M5: Eternal origin cred before 0x0c, historical pending_delay, 0x10 missing block_time, capacity/1 0x0c temporal order & K1->K2
    # =========================================================================
    of_e5 = rm._base_origin_fixture()
    # Origin confirmed at 749000; push initial 0x0c binding confirmation to 749200; issue eternal credential at h_anchor = 749050!
    of_e5["chain"]["txs"][of_e5["origin_bundle"]["name_binding_txid"]]["confirmed_height"] = 749200
    cr_pre_bind_p = {
        "claims": {"birth_cert": "ok"},
        "credential_kind": "identity/birth-attestation-v1",
        "genesis": GENESIS_MAIN,
        "issued_at": 1795200000,
        "issuer": of_e5["origin_bundle"]["origin"]["payload"]["issuer"],
        "lifecycle": "eternal",
        "network": "main",
        "not_before_height": 749000,
        "subject": {"mode": "origin", "origin_id": of_e5["_origin_id"]},
        "type": "seallink-credential/1",
    }
    cr_pre_bind = sl.sign_envelope(cr_pre_bind_p, [of_e5["_keys"]["reg_cred"]["sk"]])
    cr_anc_ok = _h32("d9-m5-cr-anc-ok")
    cr_anc_early = _h32("d9-m5-cr-anc-early")
    of_e5["chain"]["txs"][cr_anc_ok] = {"confirmed_height": 749050, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_pre_bind)).hex(), "outputs": {}}
    of_e5["chain"]["txs"][cr_anc_early] = {"confirmed_height": 748999, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_pre_bind)).hex(), "outputs": {}}
    add(
        "d9-m5-eternal-origin-cred-between-h-origin-and-h-binding-admit",
        ["SL-CONT-008", "SL-CONT-010", "SL-ORIG-002"],
        "credential",
        {
            "anchor_txid": cr_anc_ok,
            "chain": of_e5["chain"],
            "credential": cr_pre_bind,
            "origin_bundle": of_e5["origin_bundle"],
            "trusted_origin_issuer_pins": of_e5["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "D8-M5: Eternal credential with subject.mode='origin' anchored at h_origin <= h_anchor < h_binding admits without requiring initial 0x0c binding at h_anchor.",
    )
    add(
        "d9-m5-eternal-origin-cred-before-h-origin-refuse",
        ["SL-CONT-008", "SL-CONT-010", "SL-ORIG-002"],
        "credential",
        {
            "anchor_txid": cr_anc_early,
            "chain": of_e5["chain"],
            "credential": cr_pre_bind,
            "origin_bundle": of_e5["origin_bundle"],
            "trusted_origin_issuer_pins": of_e5["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "D8-M5: Eternal credential with subject.mode='origin' anchored strictly before h_origin refuses ORIGIN_UNVERIFIED.",
    )

    # Helper to construct a confirmed 0x0c recovery on a base origin fixture
    def _setup_recovery(of_base: dict[str, Any], h_rec: int, k_new: dict[str, Any], label: str) -> tuple[dict[str, Any], str, dict[str, Any], dict[str, Any]]:
        of_x = copy.deepcopy(of_base)
        b1 = of_x["origin_bundle"]["name_binding"]
        new_pol = {"kind": "key", "pk": k_new["comp"]}
        new_reg = {"txid": _h32(f"d9-rec-reg-{label}"), "vout": 0}
        rec_pol = of_x["_rec_pol"]
        rec_spk = _spk_hex(rec_pol)
        b2 = {
            "binding_mode": "recovery",
            "genesis": GENESIS_MAIN,
            "name": "id/child-leo-recovered",
            "network": "main",
            "next_recovery_policy": rec_pol,
            "next_recovery_vout": 0,
            "origin_id": of_x["_origin_id"],
            "owner_policy": new_pol,
            "registration": new_reg,
            "seq": 2,
            "supersedes_binding_id": sl.object_id(b1),
            "type": "seallink-name-binding/1",
        }
        rtx = _h32(f"d9-rec-0x0c-{label}")
        rs_op = of_x["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
        of_x["chain"]["txs"][rs_op["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx
        of_x["chain"]["txs"][rtx] = {
            "confirmed_height": h_rec,
            "inputs": [sv.make_segwit_input(rs_op["txid"], rs_op["vout"])],
            "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(b2)).hex(),
            "outputs": {"0": {"script_pubkey_hex": rec_spk}},
        }
        of_x["origin_bundle"]["recovery_bindings"] = [b2]
        # Register new name with subject-authored SIGHASH_ALL self-update
        of_x["chain"]["names"]["id/child-leo-recovered"] = sv.make_name_history(
            "id/child-leo-recovered", new_reg, new_pol, {"link": {"origin": of_x["_origin_id"]}}, first_height=h_rec - 10, update_height=h_rec + 2
        )
        return of_x, rtx, b2, new_pol

    # Historical pending_delay at at_height refuses RECOVERY_FORBIDDEN!
    of_pd, _rtx_pd, _b2_pd, _pol_pd = _setup_recovery(rm._base_origin_fixture(), 749500, _kp("d9-m5-pd-k"), "pd")
    add(
        "d9-m5-historical-pending-delay-refuses-recovery-forbidden",
        ["SL-ORIG-014"],
        "origin_status",
        {
            "at_height": 749550,  # inside [749500, 749500 + 144)!
            "chain": of_pd["chain"],
            "origin_bundle": of_pd["origin_bundle"],
            "trusted_origin_issuer_pins": of_pd["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "RECOVERY_FORBIDDEN",
        "D8-M5: Historical evaluation during [h_rec, h_rec + delay_blocks) without valid 0x10 MUST refuse RECOVERY_FORBIDDEN consistently with live tip evaluation.",
    )

    # Former-guardian 0x10 missing block_time on minor origin fails closed as locked out -> 0x0c promotes!
    of_nbt, _rtx_nbt, b2_nbt, _pol_nbt = _setup_recovery(rm._base_origin_fixture(), 749500, _kp("d9-m5-nbt-k"), "nbt")
    b1_updates = of_nbt["chain"]["names"]["id/child-leo"]["updates"]
    prev_b1 = b1_updates[-1]
    w_opol = prev_b1["owner_policy"]
    w_ospk, _ = sl.compile_script_policy(w_opol)
    cancel_u = {
        "confirmed_height": 749510,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, sl.object_id(b2_nbt)).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", w_ospk, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_nbt["_origin_id"]}})).hex(),
        "owner_policy": w_opol,
        "prev_input": {"sighash_bytes": [1], "txid": prev_b1["txid"], "vout": prev_b1["vout"], "witness_policy": w_opol},
        "txid": _h32("d9-m5-cancel-no-bt"),
        "vout": 0,
    }  # Intentionally omits block_time!
    b1_updates.append(cancel_u)
    add(
        "d9-m5-0x10-missing-block-time-locked-out-promotes",
        ["SL-ORIG-014", "SL-ORIG-011"],
        "origin_status",
        {
            "chain": of_nbt["chain"],
            "expect_recovery_outcome": "promoted",
            "origin_bundle": of_nbt["origin_bundle"],
            "trusted_origin_issuer_pins": of_nbt["trusted_origin_issuer_pins"],
        },
        "ADMIT_WARD",
        None,
        "D8-M5: Former-guardian 0x10 update omitting block_time when majority_commitment is opened MUST fail closed as locked out so 0x0c promotes cleanly.",
    )

    # Exact boundary (kills L2971 >= -> >): 0x10 WITH valid block_time < opened_majority at EXACT h_cancel == deadline (h_rec + 144) is TOO LATE -> promotes!
    of_dl, _rtx_dl, b2_dl, _pol_dl = _setup_recovery(rm._base_origin_fixture(), 749500, _kp("d9-m5-dl-k"), "dl")
    b1_dl_u = of_dl["chain"]["names"]["id/child-leo"]["updates"]
    prev_dl = b1_dl_u[-1]
    w_dl_pol = prev_dl["owner_policy"]
    w_dl_spk, _ = sl.compile_script_policy(w_dl_pol)
    b1_dl_u.append({
        "block_time": 1795215000,  # Strictly < opened_majority!
        "confirmed_height": 749500 + 144,  # EXACT deadline -> too late!
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, sl.object_id(b2_dl)).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", w_dl_spk, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_dl["_origin_id"]}})).hex(),
        "owner_policy": w_dl_pol,
        "prev_input": {"sighash_bytes": [1], "txid": prev_dl["txid"], "vout": prev_dl["vout"], "witness_policy": w_dl_pol},
        "txid": _h32("d9-m5-cancel-exact-deadline"),
        "vout": 0,
    })
    add(
        "d9-m5-0x10-at-exact-deadline-with-block-time-too-late-promotes",
        ["SL-ORIG-014"],
        "origin_status",
        {
            "chain": of_dl["chain"],
            "expect_recovery_outcome": "promoted",
            "origin_bundle": of_dl["origin_bundle"],
            "trusted_origin_issuer_pins": of_dl["trusted_origin_issuer_pins"],
        },
        "ADMIT_WARD",
        None,
        "D8-M5 exact boundary: valid-timestamped 0x10 at h_cancel == h_rec + delay_blocks is too late so 0x0c promotes (kills >= -> >).",
    )

    # Helper to attach confirmed seallink-capacity/1 spending status_seal at h_cap naming k1_pol
    def _attach_capacity(of_x: dict[str, Any], h_cap: int, k1_pol: dict[str, Any], label: str) -> None:
        st_s = of_x["origin_bundle"]["origin"]["payload"]["status_seal"]
        nxt_stat_pol = {"kind": "key", "pk": _kp(f"d9-nxt-stat-{label}")["comp"]}
        cap_p = {
            "basis_sha256": _h32(f"d9-cap-basis-{label}"),
            "genesis": GENESIS_MAIN,
            "issued_at": of_x["chain"]["now"] - 100,
            "issuer": of_x["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "next_status_policy": nxt_stat_pol,
            "next_status_vout": 0,
            "origin_id": of_x["_origin_id"],
            "status_prev_outpoint": {"txid": st_s["txid"], "vout": st_s["vout"]},
            "subject_new_owner_policy": k1_pol,
            "type": "seallink-capacity/1",
        }
        cap_env = sl.sign_envelope(cap_p, [of_x["_keys"]["reg_cred"]["sk"]])
        cap_tx = _h32(f"d9-cap-tx-{label}")
        of_x["chain"]["txs"][st_s["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_tx
        of_x["chain"]["txs"][cap_tx] = {
            "confirmed_height": h_cap,
            "inputs": [sv.make_segwit_input(st_s["txid"], st_s["vout"])],
            "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_env)).hex(),
            "outputs": {"0": {"script_pubkey_hex": _spk_hex(nxt_stat_pol)}},
        }
        of_x["origin_bundle"]["capacity_record"] = cap_env

    k1_pol = {"kind": "key", "pk": _kp("d9-m5-k1-lost")["comp"]}
    # Pre-capacity 0x0c promoted at 749400 + 144 = 749544 < h_cap = 749700 -> MUST stay GUARDIAN_TRANSFER_PENDING!
    of_pre_cap, _, _, _ = _setup_recovery(rm._base_origin_fixture(), 749400, _kp("d9-m5-precap-k"), "precap")
    _attach_capacity(of_pre_cap, 749700, k1_pol, "precap")
    add(
        "d9-m5-capacity-prior-0x0c-before-cap-height-stays-pending",
        ["SL-ORIG-011", "SL-ORIG-014"],
        "origin_status",
        {
            "chain": of_pre_cap["chain"],
            "origin_bundle": of_pre_cap["origin_bundle"],
            "trusted_origin_issuer_pins": of_pre_cap["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "GUARDIAN_TRANSFER_PENDING",
        "D8-M5: A 0x0c recovery promoted strictly before seallink-capacity/1 anchor height (h_promo < h_cap) MUST NOT bypass State 3 handover and remains GUARDIAN_TRANSFER_PENDING.",
    )
    # Post-capacity 0x0c recovering K1 -> K2 promoting at EXACT h_promo == h_cap (749600 + 144 == 749744) -> ADMIT_AUTONOMOUS (kills L2459 >= -> >)!
    of_k2, _, _, _ = _setup_recovery(rm._base_origin_fixture(), 749600, _kp("d9-m5-k2-rec"), "k2")
    _attach_capacity(of_k2, 749744, k1_pol, "k2")
    add(
        "d9-m5-capacity-followed-by-0x0c-k1-to-k2-recovery-autonomous",
        ["SL-ORIG-011", "SL-ORIG-014"],
        "origin_status",
        {
            "chain": of_k2["chain"],
            "origin_bundle": of_k2["origin_bundle"],
            "trusted_origin_issuer_pins": of_k2["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "D8-M5 exact boundary: After seallink-capacity/1 names K1 at h_cap, a governed 0x0c recovery promoting at h_promo == h_cap to a fresh K2 != K1 with subject self-update advances cleanly to State 4 ADMIT_AUTONOMOUS (kills >= -> >).",
    )

    # =========================================================================
    # 8. D8-M7: Bearer session issuer-signed close, auto bearer_token, mandatory depth-2 parent, live/spent contract_seal
    # =========================================================================
    fx_m7 = rm._base_invocation_fixture()
    gp_m7 = copy.deepcopy(fx_m7["bundle"]["grants"][0]["payload"])
    gp_m7["capabilities"] = [{"action": "mail/read", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "calls", "window": "term"}], "target": "mailbox:id/alice:work"}]
    g_m7_env, gid_m7 = _reanchor(fx_m7, gp_m7)
    m7_itx = fx_m7["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    so_m7_open = sl.sign_envelope(
        {
            "executor": gp_m7["executor"], "exp": fx_m7["chain"]["now"] + 600, "genesis": GENESIS_MAIN,
            "iat": fx_m7["chain"]["now"] - 10, "network": "main", "nonce": _h32("d9-m7-op"), "op": "open",
            "proof_path": [{"grant_id": gid_m7, "issuance_txid": m7_itx}], "quotas": gp_m7["capabilities"][0]["quotas"],
            "slot_binding": "slot-m7", "type": "seallink-session-open/1",
        },
        [fx_m7["_keys"]["agent_req"]["sk"]],
    )
    sid_m7 = sl.object_id(so_m7_open["payload"])
    # Root grant ISSUER (alice_gr, NOT recipient agent_req!) signs op='close' -> MUST ADMIT!
    so_m7_close_iss = sl.sign_envelope(
        {
            "executor": gp_m7["executor"], "exp": fx_m7["chain"]["now"] + 600, "genesis": GENESIS_MAIN,
            "iat": fx_m7["chain"]["now"] - 10, "network": "main", "nonce": _h32("d9-m7-cl"), "op": "close",
            "proof_path": [{"grant_id": gid_m7, "issuance_txid": m7_itx}], "quotas": [], "session_id": sid_m7,
            "slot_binding": "slot-m7", "type": "seallink-session-open/1",
        },
        [fx_m7["_keys"]["alice_gr"]["sk"]],
    )
    add(
        "d9-m7-bearer-session-close-by-issuer-and-auto-token-admit",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_m7["executor_cfg"],
            "journal": {"journal_id": _h32("d9-m7-j1")},
            "steps": [
                {"bundle": fx_m7["bundle"], "chain": fx_m7["chain"], "expect_bearer_token": True, "kind": "session_open", "label": "open-auto-tok", "session_open": so_m7_open, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "arguments": {"folder": "Inbox", "message_id": "m1"}, "chain": fx_m7["chain"], "grant_env": g_m7_env, "kind": "bearer_session", "label": "use-auto-tok", "slot_binding": "slot-m7", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
                {"bundle": fx_m7["bundle"], "chain": fx_m7["chain"], "kind": "session_open", "label": "issuer-close", "session_open": so_m7_close_iss, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "arguments": {"folder": "Inbox", "message_id": "m2"}, "chain": fx_m7["chain"], "grant_env": g_m7_env, "kind": "bearer_session", "label": "post-close-refuse", "slot_binding": "slot-m7", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "D8-M7: Bearer session open mints & returns 64-hex CSPRNG bearer_token once; root grant issuer (link.grant) can close the session, invalidating subsequent uses.",
        module="bearer-sessions",
    )
    # Depth-2 bearer session omitting parent_grant_env -> SESSION_INVALID!
    add(
        "d9-m7-bearer-session-depth2-missing-parent-refuse",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_96["executor_cfg"],
            "journal": {"journal_id": _h32("d9-m7-j2")},
            "steps": [
                {"bearer_token": tok96, "bundle": fx_96["bundle"], "chain": fx_96["chain"], "kind": "session_open", "label": "open-d2", "session_open": so96, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/tool", "arguments": {"input_sha256": _h32("in96c"), "max_output_bytes": "128", "tool_name": "pytest"}, "chain": fx_96["chain"], "grant_env": c96_env, "kind": "bearer_session", "label": "use-no-parent", "slot_binding": "slot-96", "target": "station:id/station-a:tools", "token": tok96, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "D8-M7: Depth-2 bearer session use omitting parent_grant_env MUST fail closed with SESSION_INVALID.",
        module="bearer-sessions",
    )
    # Contract-bound bearer session: live contract_seal -> ADMIT, spent contract_seal -> SESSION_INVALID!
    fx_mc = rm._contract_fx()
    c_env_m7 = fx_mc["bundle"]["contract"]
    g_mc_env = fx_mc["bundle"]["grants"][0]
    gid_mc = sl.object_id(g_mc_env["payload"])
    so_mc = sl.sign_envelope(
        {
            "executor": g_mc_env["payload"]["executor"], "exp": fx_mc["chain"]["now"] + 600, "genesis": GENESIS_MAIN,
            "iat": fx_mc["chain"]["now"] - 10, "network": "main", "nonce": _h32("d9-m7-mc-op"), "op": "open",
            "proof_path": fx_mc["invocation"]["payload"]["proof_path"], "quotas": g_mc_env["payload"]["capabilities"][0]["quotas"],
            "slot_binding": "slot-mc", "type": "seallink-session-open/1",
        },
        [fx_mc["_keys"]["agent_req"]["sk"]],
    )
    ch_mc_spent = copy.deepcopy(fx_mc["chain"])
    c_seal_tx = c_env_m7["seal"]["txid"]
    ch_mc_spent["txs"][c_seal_tx]["outputs"]["0"]["spent_by_txid"] = _h32("d9-m7-cseal-spend")
    ch_mc_spent["txs"][_h32("d9-m7-cseal-spend")] = {"confirmed_height": 750009, "inputs": [sv.make_segwit_input(c_seal_tx, 0)], "outputs": {}}
    add(
        "d9-m7-bearer-session-contract-seal-live-then-spent",
        ["SL-GRNT-013", "SL-CONT-005"],
        "session_lifecycle",
        {
            "executor_cfg": fx_mc["executor_cfg"],
            "journal": {"journal_id": _h32("d9-m7-j3")},
            "steps": [
                {"bundle": fx_mc["bundle"], "chain": fx_mc["chain"], "expect_bearer_token": True, "kind": "session_open", "label": "open-mc", "session_open": so_mc, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/session", "arguments": {"config_sha256": c_env_m7["config_sha256"], "op": "start", "session_slot": "slot1"}, "chain": fx_mc["chain"], "contract_env": c_env_m7, "grant_env": g_mc_env, "kind": "bearer_session", "label": "live-contract-seal-admit", "slot_binding": "slot-mc", "target": "station:id/station-a:slot1", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/session", "arguments": {"config_sha256": c_env_m7["config_sha256"], "op": "start", "session_slot": "slot1"}, "chain": ch_mc_spent, "contract_env": c_env_m7, "grant_env": g_mc_env, "kind": "bearer_session", "label": "spent-contract-seal-refuse", "slot_binding": "slot-mc", "target": "station:id/station-a:slot1", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "D8-M7: Contract-bound bearer session verifies live contract_env seal on use (ADMIT) and fails closed SESSION_INVALID immediately when contract seal is spent.",
        module="bearer-sessions",
    )

    # =========================================================================
    # 9. D8-M8: Migration stage BEFORE fencing (0 writes) + activate mandatory local_executor_pin & fencing
    # =========================================================================
    add(
        "d9-m8-migration-stage-before-fencing-admit",
        ["SL-SERV-003"],
        "migration",
        {
            "chain": fx_b3["chain"],
            "expect_zero_writes": True,
            "export_bundle": {
                "inventory": mig_b3_inv,
                "source_journal_commitment": _h32("d9-b3-jc"),
                "source_journal_pos": 1,
            },
            "journal": {"journal_id": _h32("d9-m8-j1")},
            "manifests": fx_b3["bundle"]["manifests"],
            "migration": mig_b3_env,
            "mode": "stage",
        },
        "ADMIT",
        None,
        "D8-M8: Migration mode='stage' runs BEFORE source fencing & predecessor closure with zero journal writes.",
        module="service-migration",
    )
    add(
        "d9-m8-migration-activate-missing-local-pin-refuse",
        ["SL-SERV-003"],
        "migration",
        {
            "chain": fx_b3["chain"],
            "export_bundle": {
                "inventory": mig_b3_inv,
                "source_journal_commitment": _h32("d9-b3-jc"),
                "source_journal_pos": 1,
            },
            "journal": {"journal_id": _h32("d9-m8-j2")},
            "manifests": fx_b3["bundle"]["manifests"],
            "migration": mig_b3_env,
            "mode": "activate",
        },
        "REFUSE",
        "GRANT_EXECUTOR_MISMATCH",
        "D8-M8: Migration mode='activate' omitting local_executor_pin MUST fail closed with GRANT_EXECUTOR_MISMATCH.",
        module="service-migration",
    )
    # Single-defect unfenced activate (ALL 4 downstream proofs valid; ONLY source_write_token_fenced=False -> kills L6080!)
    fx_m8u = copy.deepcopy(fx_b3)
    d8_own, d8_rcpt = _kp("d9-m8u-do"), _kp("d9-m8u-dr")
    d8_pol = {"kind": "key", "pk": d8_own["comp"]}
    d8_reg = {"txid": _h32("d9-m8u-drg"), "vout": 0}
    d8_pin = {"name": "id/mail-host-b", "owner_policy": d8_pol, "registration": d8_reg}
    d8_man = {"network": "main", "owner": "id/mail-host-b", "seq": 1, "service": {"actions": ["mail/read"], "endpoint": "https://mail-b.example.org", "receipt_key": d8_rcpt["xonly"], "service_type": "mail"}, "type": "seallink-manifest/1"}
    d8_man_h = sl.content_addr(d8_man)
    al8_man = {**copy.deepcopy(fx_m8u["_alice_man"]), "providers": [{"label": "work", "provider": d8_pin, "service_type": "mail"}], "seq": 2}
    al8_man_h = sl.content_addr(al8_man)
    fx_m8u["chain"]["manifests"][d8_man_h] = d8_man
    fx_m8u["chain"]["manifests"][al8_man_h] = al8_man
    fx_m8u["bundle"]["manifests"][d8_man_h] = d8_man
    fx_m8u["bundle"]["manifests"][al8_man_h] = al8_man
    fx_m8u["chain"]["names"]["id/mail-host-b"] = sv.make_name_history("id/mail-host-b", d8_reg, d8_pol, {"m": {"h": d8_man_h, "s": 1}}, first_height=748000, update_height=749000)
    fx_m8u["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_m8u["_alice_reg"], fx_m8u["_alice_owner_pol"], {"link": {"grant": fx_m8u["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al8_man_h, "s": 2}}, first_height=748000, update_height=749000)
    m8u_mid = _h32("d9-m8u-mid")
    m8u_inv = {"holder_name": "id/alice", "items": [], "migration_id": m8u_mid, "service_type": "mail"}
    m8u_sha = sl.sha256(sl.jcs_encode(m8u_inv)).hex()
    h8_pin = {"name": "id/alice", "owner_policy": fx_m8u["_alice_owner_pol"], "registration": fx_m8u["_alice_reg"]}
    s8_pin = {"name": "id/mail-host-a", "owner_policy": fx_m8u["_host_owner_pol"], "registration": fx_m8u["_host_reg"]}
    m8u_p = {"dest_executor": d8_pin, "genesis": GENESIS_MAIN, "holder": h8_pin, "inventory_sha256": m8u_sha, "issued_at": fx_m8u["chain"]["now"], "journal_commitment": _h32("d9-m8u-jc"), "journal_pos": 1, "migration_id": m8u_mid, "network": "main", "outstanding_exposure": [], "service_type": "mail", "source_executor": s8_pin, "type": "seallink-migration/1"}
    m8u_env = sl.sign_envelope(m8u_p, [fx_m8u["_keys"]["host_rcpt"]["sk"]])
    m8u_ha = sl.sign_envelope({"expires_at": fx_m8u["chain"]["now"] + 3600, "genesis": GENESIS_MAIN, "issued_at": fx_m8u["chain"]["now"] - 10, "network": "main", "nonce": _h32("d9-m8u-ha"), "party_id": "h", "party_name": "id/alice", "party_role": "holder", "target_id": sl.object_id(m8u_p), "target_type": "seallink-migration/1", "type": "seallink-assent/1"}, [fx_m8u["_keys"]["alice_gr"]["sk"]])
    m8u_acc = sl.sign_envelope({"genesis": GENESIS_MAIN, "issuer": d8_pin, "network": "main", "not_after": fx_m8u["chain"]["now"] + 3600, "not_before": fx_m8u["chain"]["now"] - 10, "seq": 1, "statement_kind": "migration-accept", "subject": {"holder": h8_pin, "inventory_sha256": m8u_sha, "migration_id": m8u_mid, "source_executor": s8_pin}, "type": "seallink-statement/1"}, [d8_rcpt["sk"]])
    add(
        "d9-m8-migration-activate-unfenced-source-refuse",
        ["SL-SERV-003"],
        "migration",
        {
            "chain": fx_m8u["chain"],
            "dest_accept_stmt": m8u_acc,
            "export_bundle": {
                "inventory": m8u_inv,
                "source_journal_commitment": _h32("d9-m8u-jc"),
                "source_journal_pos": 1,
            },
            "holder_assent": m8u_ha,
            "journal": {"journal_id": _h32("d9-m8-j3")},
            "local_executor_pin": d8_pin,
            "manifests": fx_m8u["bundle"]["manifests"],
            "migration": m8u_env,
            "mode": "activate",
        },
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "D8-M8 single-defect: Migration mode='activate' with all 4 downstream proofs valid but unfenced source journal refuses SERVICE_MIGRATION_INVALID.",
        module="service-migration",
    )

    # =========================================================================
    # 10. D8-M9: Contour A Federation strict recipient.mode='name' & mandatory fields_sha256
    # =========================================================================
    fx_f9 = rm._base_invocation_fixture()
    p256_f9_sk = sl.deterministic_p256_privkey("d9-m9-p256")
    p256_f9_pk = sl.p256_compressed_pubkey(p256_f9_sk)
    ds_f9_pol = {"kind": "key", "pk": _kp("d9-m9-ds")["comp"]}
    ds_f9_tx = _h32("d9-m9-ds-tx")
    fx_f9["chain"]["txs"][ds_f9_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(ds_f9_pol)}}}
    dh_f9, dp_f9 = rm.make_salted_device_set(
        "id/alice",
        [{"alg": "p256", "ceiling": 2, "key": p256_f9_pk, "label": "l2-f9", "presence": True, "seal": {"script_policy": ds_f9_pol, "txid": ds_f9_tx, "vout": 0}}],
    )
    am_f9 = {**copy.deepcopy(fx_f9["_alice_man"]), "sets": {"devices": {"seq": 1, "sha256": sl.content_addr(dh_f9)}}}
    am_f9_h = sl.content_addr(am_f9)
    fx_f9["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_f9["_alice_reg"], fx_f9["_alice_owner_pol"], {"link": {"grant": fx_f9["_keys"]["alice_gr"]["xonly"]}, "m": {"h": am_f9_h, "s": 1}}, first_height=748000, update_height=749000)

    # Grant 1: bare key recipient (MUST refuse FEDERATION_POLICY_DENIED!)
    g_bare = fx_f9["bundle"]["grants"][0]
    cmd_bare = sl.sign_envelope(
        {
            "arguments": {"fields_sha256": _h32("d9-m9-f"), "grant_id": sl.object_id(g_bare["payload"]), "recipient_name": "id/peer-b", "route_mode": "direct"},
            "command": "approve-pii-disclosure", "exp": fx_f9["chain"]["now"] + 600, "genesis": GENESIS_MAIN,
            "iat": fx_f9["chain"]["now"] - 10, "level": 2, "network": "main", "nonce": _h32("d9-m9-n1"),
            "owner": "id/alice", "target_executor": "id/station-a", "type": "seallink-owner-command/1",
        },
        [p256_f9_sk],
        alg="p256",
    )
    add(
        "d9-m9-federation-bare-key-recipient-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_f9["chain"],
            "grant": g_bare,
            "journal": {"journal_id": _h32("d9-m9-j1")},
            "peer_ctx": {
                "approval_command": cmd_bare,
                "device_proof": dp_f9[0],
                "fields_sha256": _h32("d9-m9-f"),
                "manifests": {am_f9_h: am_f9},
                "phase": "pii_disclosure",
                "route_hops": [{"actor": "id/peer-b", "role": "counterparty"}],
            },
            "policy": {"require_contour_a": True, "trusted_peers": ["id/peer-b"]},
        },
        "REFUSE",
        "FEDERATION_POLICY_DENIED",
        "D8-M9: Contour A PII disclosure MUST require grant.recipient.mode == 'name' (bare key recipient refuses FEDERATION_POLICY_DENIED).",
        module="federated-screening",
    )

    # Grant 2: named recipient id/peer-b, omitting fields_sha256 in peer_ctx -> FEDERATION_POLICY_DENIED!
    g_named_p = copy.deepcopy(g_bare["payload"])
    g_named_p["recipient"] = {"mode": "name", "name": "id/peer-b", "owner_policy": {"kind": "key", "pk": _kp("d9-m9-pb")["comp"]}, "registration": {"txid": _h32("d9-m9-pbr"), "vout": 0}}
    g_named = sl.sign_envelope(g_named_p, [fx_f9["_keys"]["alice_gr"]["sk"]])
    cmd_named = sl.sign_envelope(
        {
            "arguments": {"fields_sha256": _h32("d9-m9-f"), "grant_id": sl.object_id(g_named_p), "recipient_name": "id/peer-b", "route_mode": "direct"},
            "command": "approve-pii-disclosure", "exp": fx_f9["chain"]["now"] + 600, "genesis": GENESIS_MAIN,
            "iat": fx_f9["chain"]["now"] - 10, "level": 2, "network": "main", "nonce": _h32("d9-m9-n2"),
            "owner": "id/alice", "target_executor": "id/station-a", "type": "seallink-owner-command/1",
        },
        [p256_f9_sk],
        alg="p256",
    )
    add(
        "d9-m9-federation-missing-fields-sha256-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_f9["chain"],
            "grant": g_named,
            "journal": {"journal_id": _h32("d9-m9-j2")},
            "peer_ctx": {
                "approval_command": cmd_named,
                "device_proof": dp_f9[0],
                "manifests": {am_f9_h: am_f9},
                "phase": "pii_disclosure",
                "route_hops": [{"actor": "id/peer-b", "role": "counterparty"}],
            },
            "policy": {"require_contour_a": True, "trusted_peers": ["id/peer-b"]},
        },
        "REFUSE",
        "FEDERATION_POLICY_DENIED",
        "D8-M9: Contour A PII disclosure omitting fields_sha256 from peer_ctx MUST fail closed with FEDERATION_POLICY_DENIED.",
        module="federated-screening",
    )
    cmd_wrong_rcpt = sl.sign_envelope(
        {
            **cmd_named["payload"],
            "arguments": {**cmd_named["payload"]["arguments"], "recipient_name": "id/other-peer"},
            "nonce": _h32("d9-m9-n3"),
        },
        [p256_f9_sk],
        alg="p256",
    )
    add(
        "d9-m9-federation-mismatched-recipient-name-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_f9["chain"],
            "grant": g_named,
            "journal": {"journal_id": _h32("d9-m9-j3")},
            "peer_ctx": {
                "approval_command": cmd_wrong_rcpt,
                "device_proof": dp_f9[0],
                "fields_sha256": _h32("d9-m9-f"),
                "manifests": {am_f9_h: am_f9},
                "phase": "pii_disclosure",
                "route_hops": [{"actor": "id/peer-b", "role": "counterparty"}],
            },
            "policy": {"require_contour_a": True, "trusted_peers": ["id/peer-b"]},
        },
        "REFUSE",
        "FEDERATION_POLICY_DENIED",
        "D8-M9: Contour A PII disclosure where approval.arguments.recipient_name != grant.recipient.name MUST refuse FEDERATION_POLICY_DENIED.",
        module="federated-screening",
    )
