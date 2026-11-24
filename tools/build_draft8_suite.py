#!/usr/bin/env python3
"""
SealLink v1.0.0-draft.8 — Second-Round Triple-Audit Closure Suite (R1, R2, R3).

Covers every architectural decision, blocker closure, false-admit regression,
optional-module hardening (2A), unified Decision 1B emancipation, historical ward
contract survival (R1 #1), signed-receipt reconciliation & single atomic terminal
(R1 #2/#3, R3 Blockers #2/#3), 3-way R2G-01 recovery semantics, canonical
ScriptPolicy pair ordering (Decision 4), and cross-language wire invariants.
"""

from __future__ import annotations

import copy
from typing import Any, Callable

import build_branch_suite as bbs
import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = rm.GENESIS_MAIN


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-d8-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"d8:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def _reanchor(fx: dict[str, Any], new_gp: dict[str, Any], signer_sk: bytes | None = None) -> tuple[dict[str, Any], str]:
    sk = signer_sk or fx["_keys"]["alice_gr"]["sk"]
    g_env = sl.sign_envelope(new_gp, [sk])
    gid = sl.object_id(new_gp)
    itx = fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    prep: dict[str, Any] = {
        "genesis": new_gp["genesis"],
        "grant_content_addr": sl.content_addr(g_env),
        "grant_id": gid,
        "type": "seallink-issuance/1",
    }
    if "contract_id" in new_gp:
        prep["contract_id"] = new_gp["contract_id"]
    fx["chain"]["txs"][itx]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest(prep).hex(), 0x00).hex()
    fx["bundle"]["grants"] = [g_env]
    inv_p = copy.deepcopy(fx["invocation"]["payload"])
    inv_p["proof_path"] = [{"grant_id": gid, "issuance_txid": itx}]
    fx["invocation"] = sl.sign_envelope(inv_p, [fx["_keys"]["agent_req"]["sk"]])
    return g_env, gid


def add_draft8_conformance_cases(add: Callable[..., None]) -> None:
    """Append all v1.0.0-draft.8 regression, closure, optional-module, and coverage cases."""

    # =========================================================================
    # 1. R1 #1 / R2-04 / H-32: Historical Ward Contract Survival & Retroactive 0x0b
    # =========================================================================
    of_hist = rm._base_origin_fixture()
    # Set quorums monotonically (routine_read <= effect_grant <= contract_assent <= custody_change) so 1-of-2 admits at rev=1
    op_h = copy.deepcopy(of_hist["origin_bundle"]["origin"]["payload"])
    op_h["guardian_policy"]["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 1}
    op_h["guardian_policy"]["quorums"]["contract_assent"] = {"den": 2, "min": 1, "num": 1}
    op_h["guardian_policy"]["quorums"]["custody_change"] = {"den": 2, "min": 1, "num": 1}
    o_env_h = sl.sign_envelope(op_h, [of_hist["_keys"]["reg_cred"]["sk"]])
    oid_h = sl.object_id(op_h)
    of_hist["origin_bundle"]["origin"] = o_env_h
    of_hist["origin_bundle"]["name_binding"]["origin_id"] = oid_h
    g1_h_p = {**of_hist["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_h}
    g1_h = sl.sign_envelope(g1_h_p, [of_hist["_keys"]["reg_cred"]["sk"]])
    g1_h_id = sl.object_id(g1_h_p)
    of_hist["origin_bundle"]["guardian_records"] = [g1_h]
    of_hist["origin_bundle"]["guardian_assents"] = [
        sl.sign_envelope({**of_hist["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": g1_h_id}, [of_hist["_keys"]["g1_gr"]["sk"]])
    ]
    of_hist["chain"]["txs"][of_hist["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_env_h)).hex()
    of_hist["chain"]["txs"][of_hist["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_hist["origin_bundle"]["name_binding"])).hex()
    of_hist["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_h)).hex()
    of_hist["chain"]["names"]["id/child-leo"] = sv.make_name_history(
        "id/child-leo",
        of_hist["origin_bundle"]["name_binding"]["registration"],
        of_hist["origin_bundle"]["name_binding"]["owner_policy"],
        {"link": {"origin": oid_h}},
        first_height=749005,
        update_height=749015,
    )
    of_hist["contract"]["parties"][0]["ward_origin_id"] = oid_h
    cid_h = sl.object_id(of_hist["contract"])
    h_anchor = 749500
    t_anchor = 1795220000
    wa_h = sl.sign_guardian_envelope(
        {
            "expires_at": t_anchor + 100000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": oid_h, "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": t_anchor - 100,
            "network": "main",
            "nonce": _h32("d8-r1-1-wa"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": cid_h,
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_hist["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    # AFTER h_anchor (749500): (a) 0x0f roster transitions to rev=2 at 749600 (effective 749744 <= tip 750100),
    # AND (b) id/parent-a rotates link.grant K1 -> K2 at 749800!
    gp_h = op_h["guardian_policy"]
    vac_h = gp_h["roster_seal"]["script_policy"]
    rost_h_p = {
        "arbiter_pk": gp_h["arbiter_pk"],
        "challenger_pk": gp_h["challenger_pk"],
        "disposer_pk": gp_h["disposer_pk"],
        "effective_delay_blocks": 144,
        "genesis": GENESIS_MAIN,
        "issuer": op_h["issuer"],
        "network": "main",
        "next_roster_policy": vac_h,
        "next_roster_vout": 0,
        "origin_id": oid_h,
        "prev_revision": 1,
        "prev_roster_outpoint": {"txid": gp_h["roster_seal"]["txid"], "vout": 0},
        "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in gp_h["quorums"]},
        "revision": 2,
        "revision_size": 1,
        "slots": [{"action": "retain_active", "active_outpoint": {"txid": rm._h32("og1-init-0x12"), "vout": 0}, "guardian_id": g1_h_id, "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    rost_h = sl.sign_envelope(rost_h_p, [of_hist["_keys"]["reg_cred"]["sk"]])
    rtx_h = _h32("d8-r1-1-roster-tx")
    of_hist["chain"]["txs"][gp_h["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_h
    of_hist["chain"]["txs"][rtx_h] = {
        "confirmed_height": 749600,
        "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_h)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_h)}},
    }
    of_hist["origin_bundle"]["roster_records"] = [rost_h]
    g1_new_gr = _kp("d8-r1-1-g1-rot")
    g1_pin_h = of_hist["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]
    of_hist["chain"]["names"]["id/parent-a"] = sv.make_name_history(
        "id/parent-a",
        g1_pin_h["registration"],
        g1_pin_h["owner_policy"],
        {"link": {"grant": of_hist["_keys"]["g1_gr"]["xonly"]}},
        first_height=748000,
        update_height=748600,
        extra_updates=[{"txid": _h32("d8-r1-1-g1-rot-tx"), "confirmed_height": 749800, "value": {"link": {"grant": g1_new_gr["xonly"]}}}],
    )
    add(
        "d8-r1-1-historical-ward-contract-survives-0x0f-and-guardian-key-rot-admit",
        ["SL-CONT-004", "SL-ORIG-006"],
        "assent",
        {
            "anchor_height": h_anchor,
            "anchor_time": t_anchor,
            "assent": wa_h,
            "chain": of_hist["chain"],
            "contract": of_hist["contract"],
            "origin_bundle": of_hist["origin_bundle"],
            "trusted_origin_issuers": of_hist["trusted_origin_issuers"],
        },
        "ADMIT",
        None,
        "R1 #1 / R2-04: Concluded ward contract anchored at h_anchor MUST survive later 0x0f roster transitions and guardian link.grant key rotation.",
    )

    # Retroactive 0x0b break on guardian K1 with h_c <= h_anchor -> CRED_ISSUER_CLOSED; with h_c > h_anchor -> ADMIT!
    def _make_hist_0x0b(hc_val: int, lbl: str) -> dict[str, Any]:
        of_b = copy.deepcopy(of_hist)
        base_g1_hist = sv.make_name_history(
            "id/parent-a", g1_pin_h["registration"], g1_pin_h["owner_policy"],
            {"link": {"grant": of_hist["_keys"]["g1_gr"]["xonly"]}}, first_height=748000, update_height=748600,
        )
        prev_g1_u = base_g1_hist["updates"][-1]
        brk_obj = {
            "compromised_policy": {"m": 1, "pks": [of_hist["_keys"]["g1_gr"]["xonly"]]},
            "genesis": GENESIS_MAIN,
            "h_c": hc_val,
            "issuer": {"name": "id/parent-a", "owner_policy": g1_pin_h["owner_policy"], "registration": g1_pin_h["registration"]},
            "name_input": {"txid": prev_g1_u["txid"], "vout": prev_g1_u["vout"]},
            "role": "grant",
            "type": "seallink-credential-break/1",
        }
        of_b["chain"]["names"]["id/parent-a"] = sv.make_name_history(
            "id/parent-a", g1_pin_h["registration"], g1_pin_h["owner_policy"],
            {"link": {"grant": of_hist["_keys"]["g1_gr"]["xonly"]}}, first_height=748000, update_height=748600,
            extra_updates=[{
                "txid": _h32(f"d8-r1-1-0x0b-{lbl}"),
                "confirmed_height": 749800,
                "value": {"link": {"grant": g1_new_gr["xonly"]}},
                "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_obj).hex(), 0x00, h_c=hc_val).hex(),
            }],
        )
        return {
            "anchor_height": h_anchor,
            "anchor_time": t_anchor,
            "assent": wa_h,
            "chain": of_b["chain"],
            "contract": of_b["contract"],
            "origin_bundle": of_b["origin_bundle"],
            "trusted_origin_issuers": of_b["trusted_origin_issuers"],
        }

    add(
        "d8-r1-1-historical-ward-contract-retroactive-0x0b-at-anchor-refuse",
        ["SL-CONT-004", "SL-CONT-009"],
        "assent",
        _make_hist_0x0b(h_anchor, "at"),
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "R1 #1 / R2-04: Retroactive 0x0b compromise break on guardian link.grant with h_c <= h_anchor MUST invalidate the historical ward contract assent (CRED_ISSUER_CLOSED).",
    )
    add(
        "d8-r1-1-historical-ward-contract-0x0b-after-anchor-admit",
        ["SL-CONT-004", "SL-CONT-009"],
        "assent",
        _make_hist_0x0b(h_anchor + 1, "after"),
        "ADMIT",
        None,
        "R1 #1 / R2-04: 0x0b compromise break on guardian link.grant with h_c > h_anchor MUST preserve earlier anchored ward contract assent.",
    )

    # H-32: Ward assent with wrong party_name -> CONTRACT_ASSENT_INVALID
    wa_wrong_pn = sl.sign_guardian_envelope(
        {**wa_h["payload"], "nonce": _h32("d8-h32-wpn"), "party_name": "id/wrong-ward-name"},
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_hist["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add(
        "d8-h32-ward-contract-assent-wrong-party-name-refuse",
        ["SL-CONT-004"],
        "assent",
        {
            "anchor_height": h_anchor,
            "anchor_time": t_anchor,
            "assent": wa_wrong_pn,
            "chain": of_hist["chain"],
            "contract": of_hist["contract"],
            "origin_bundle": of_hist["origin_bundle"],
            "trusted_origin_issuers": of_hist["trusted_origin_issuers"],
        },
        "REFUSE",
        "CONTRACT_ASSENT_INVALID",
        "H-32: Ward contract assent whose party_name mismatches the ward binding name MUST refuse CONTRACT_ASSENT_INVALID.",
    )

    # =========================================================================
    # 2. R1 #2 / R1 #3 / R3 Blockers #2 & #3 / G7-07 / G7-11:
    #    Signed-Receipt Reconciliation, Idempotency, 1-Entry Single-Use, 65536B Journal, CAS Fence
    # =========================================================================
    fx_ce = rm._base_invocation_fixture()
    gp_ce = copy.deepcopy(fx_ce["bundle"]["grants"][0]["payload"])
    gp_ce["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    _, gid_ce = _reanchor(fx_ce, gp_ce)
    inv_id_ce = sl.object_id(fx_ce["invocation"]["payload"])
    rcpt_ce_1 = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": fx_ce["executor_cfg"]["name"],
            "genesis": GENESIS_MAIN,
            "grant_id": gid_ce,
            "invocation_id": inv_id_ce,
            "network": "main",
            "outcome": "executed",
            "recorded_at": fx_ce["chain"]["now"],
            "result_sha256": _h32("d8-ce-res1"),
            "settlements": [{"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/alice:work", "settled": "1", "unit": "reads", "window": "term"}],
            "tip_hash": fx_ce["chain"]["tip_hash"],
            "tip_height": fx_ce["chain"]["tip_height"],
            "type": "seallink-receipt/1",
        },
        [fx_ce["_keys"]["host_rcpt"]["sk"]],
    )
    rcpt_ce_2_conflict = sl.sign_envelope(
        {**rcpt_ce_1["payload"], "result_sha256": _h32("d8-ce-res2-conflict")},
        [fx_ce["_keys"]["host_rcpt"]["sk"]],
    )
    rcpt_ce_bad_res = sl.sign_envelope(
        {
            **rcpt_ce_1["payload"],
            "settlements": [{"account": "own", "kind": "seallink/count", "released": "0", "reserved": "2", "resource": "mailbox:id/alice:work", "settled": "2", "unit": "reads", "window": "term"}],
        },
        [fx_ce["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d8-r1-2-commit-result-idempotent-same-receipt-zero-writes-admit",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "commit_edge",
        {
            "bundle": fx_ce["bundle"],
            "chain": fx_ce["chain"],
            "executor_cfg": fx_ce["executor_cfg"],
            "invocation": fx_ce["invocation"],
            "journal_id": _h32("d8-ce-j1"),
            "receipt_env": rcpt_ce_1,
            "second_receipt_env": rcpt_ce_1,
        },
        "ADMIT",
        None,
        "R1 #2 / R3 Blocker #3: Retrying commit_result with the identical signed receipt MUST succeed idempotently with zero extra journal writes.",
    )
    add(
        "d8-r1-2-commit-result-conflicting-receipt-refuse",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "commit_edge",
        {
            "bundle": fx_ce["bundle"],
            "chain": fx_ce["chain"],
            "executor_cfg": fx_ce["executor_cfg"],
            "invocation": fx_ce["invocation"],
            "journal_id": _h32("d8-ce-j2"),
            "receipt_env": rcpt_ce_1,
            "second_receipt_env": rcpt_ce_2_conflict,
        },
        "REFUSE",
        "INVOKE_REPLAY",
        "R1 #2 / R3 Blocker #3: Calling commit_result with a conflicting second receipt for an already-settled invocation_id MUST refuse INVOKE_REPLAY.",
    )
    add(
        "d8-r1-2-commit-result-without-reservation-refuse",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "commit_edge",
        {
            "chain": fx_ce["chain"],
            "executor_cfg": fx_ce["executor_cfg"],
            "journal_id": _h32("d8-ce-j3"),
            "receipt_env": rcpt_ce_1,
            "skip_phase1": True,
        },
        "REFUSE",
        "INVOKE_REPLAY",
        "R1 #2: Calling commit_result without a prior durable Phase-1 reservation MUST refuse INVOKE_REPLAY.",
    )
    add(
        "d8-r1-2-commit-result-receipt-reserved-mismatch-refuse",
        ["SL-GRNT-007", "SL-GRNT-008"],
        "commit_edge",
        {
            "bundle": fx_ce["bundle"],
            "chain": fx_ce["chain"],
            "executor_cfg": fx_ce["executor_cfg"],
            "invocation": fx_ce["invocation"],
            "journal_id": _h32("d8-ce-j4"),
            "receipt_env": rcpt_ce_bad_res,
        },
        "REFUSE",
        "QUOTA_EXCEEDED",
        "R1 #2 / R3 Blocker #3: commit_result MUST reconcile signed receipt.settlements[] 1-to-1 against durable reservation and refuse reserved mismatch (QUOTA_EXCEEDED).",
    )

    # R3 Blocker #2: Single-use commits in ONE atomic terminal settlement entry (2 total entries: reservation + settlement) and blocks new invocation after restart!
    fx_su = rm._base_invocation_fixture()
    su_iss_k = _kp("d8-su-iss")
    su_gr_k = _kp("d8-su-gr")
    su_pol = {"keys": {"grantee": su_gr_k["comp"], "issuer": su_iss_k["comp"]}, "kind": "branch", "template": "single_use_1_of_2"}
    gp_su = copy.deepcopy(fx_su["bundle"]["grants"][0]["payload"])
    gp_su["revocation"]["kind"] = "single_use"
    gp_su["revocation"]["seal"]["script_policy"] = su_pol
    g_su, gid_su = _reanchor(fx_su, gp_su)
    inv_su = fx_su["invocation"]
    inv_su_id = sl.object_id(inv_su["payload"])
    su_use_tx = _h32("d8-su-use-tx")
    fx_su["chain"]["txs"][gp_su["revocation"]["seal"]["txid"]]["outputs"]["0"] = {"script_pubkey_hex": _spk_hex(su_pol), "spent_by_txid": su_use_tx}
    fx_su["chain"]["txs"][su_use_tx] = {
        "confirmed_height": 750006,
        "inputs": [sv.make_single_use_spend_input(gp_su["revocation"]["seal"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x11, sl.content_addr(inv_su)).hex(),
        "outputs": {},
    }
    rcpt_su = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": fx_su["executor_cfg"]["name"],
            "genesis": GENESIS_MAIN,
            "grant_id": gid_su,
            "invocation_id": inv_su_id,
            "network": "main",
            "outcome": "executed",
            "recorded_at": fx_su["chain"]["now"],
            "result_sha256": _h32("d8-su-res"),
            "settlements": [],
            "tip_hash": fx_su["chain"]["tip_hash"],
            "tip_height": fx_su["chain"]["tip_height"],
            "type": "seallink-receipt/1",
        },
        [fx_su["_keys"]["host_rcpt"]["sk"]],
    )
    inv_su_new_nonce = sl.sign_envelope({**inv_su["payload"], "nonce": _h32("d8-su-inv-second")}, [fx_su["_keys"]["agent_req"]["sk"]])
    add(
        "d8-r3-b2-single-use-unified-one-entry-terminal-and-restart-replay",
        ["SL-LDGR-012", "SL-GRNT-007", "SL-GRNT-014"],
        "commit_edge",
        {
            "bundle": fx_su["bundle"],
            "chain": fx_su["chain"],
            "executor_cfg": fx_su["executor_cfg"],
            "expect_total_entries": 2,
            "invocation": inv_su,
            "journal_id": _h32("d8-su-j1"),
            "post_restart_new_invocation": inv_su_new_nonce,
            "receipt_env": rcpt_su,
            "use_txid": su_use_tx,
        },
        "REFUSE",
        "INVOKE_REPLAY",
        "R3 Blocker #2: Single-use grant commits atomically in 1 terminal settlement entry (2 total journal entries) and blocks a new-nonce invocation after witness-verified restart replay (INVOKE_REPLAY).",
    )

    # R1 #3: Maximal 32-quota / 64-line JournalEntry exceeds old 16384B cap and succeeds within 65536B!
    lines_64 = []
    for i in range(32):
        res_name = f"station:id/station-a:workspace-slot-quota-{i:02d}-long-resource-identifier-padding"
        lines_64.append({"account": "own", "amount": "1000", "bucket_id": "term", "grant_id": _h32("d8-j64-g"), "quota_kind": "seallink/bytes", "resource": res_name, "unit": "bytes", "window": "term"})
        lines_64.append({"account": "row", "amount": "1000", "bucket_id": "term", "grant_id": _h32("d8-j64-p"), "quota_kind": "seallink/bytes", "resource": res_name, "row_ordinal": 1, "unit": "bytes", "window": "term"})
    add(
        "d8-r1-3-journal-entry-64-lines-within-65536b-admit",
        ["SL-WIRE-001", "SL-GRNT-014"],
        "journal_entry_wire",
        {
            "body": {
                "expires_at": 1795221000,
                "grant_id": _h32("d8-j64-g"),
                "invocation_id": _h32("d8-j64-inv"),
                "nonce": _h32("d8-j64-n"),
                "recorded_at": 1795220050,
                "reservations": lines_64,
            },
            "expect_gt_16384": True,
            "journal_id": _h32("d8-j64-jid"),
            "kind": "reservation",
        },
        "ADMIT",
        None,
        "R1 #3: Maximal 32-quota / 64-line reservation JournalEntry (> 16384B, <= 65536B) MUST pass wire, Draft 2020-12 schema, and FencedJournal.append().",
    )

    # G7-11: Replay without witness head fails closed with JOURNAL_LOST; CAS concurrent writer fails with JOURNAL_FENCED!
    j_nw = sv.FencedJournal(_h32("d8-nw-jid"))
    j_nw.append("recovery", {"fenced_at": 1795220000, "new_write_token": 2, "prev_write_token": 1})
    add(
        "d8-g7-11-replay-without-witness-fails-closed-journal-lost",
        ["SL-GRNT-014"],
        "replay_journal_tamper",
        {"entries": copy.deepcopy(j_nw.entries), "journal_id": j_nw.journal_id, "require_witness": True},
        "REFUSE",
        "JOURNAL_LOST",
        "G7-11: FencedJournal.replay_persisted_entries with require_witness=True (default) MUST fail closed with JOURNAL_LOST when witness head is omitted.",
    )
    add(
        "d8-g7-11-concurrent-writer-cas-fenced-journal-fenced",
        ["SL-GRNT-014"],
        "journal_cas_fence",
        {"journal_id": _h32("d8-cas-jid")},
        "REFUSE",
        "JOURNAL_FENCED",
        "G7-11: Stale replica appending to a shared external CAS witness after write_token advancement MUST fail closed with JOURNAL_FENCED.",
    )

    # =========================================================================
    # 3. R2G-01: Three-Way recovery_seal Spend Semantics
    # =========================================================================
    of_r1 = rm._base_origin_fixture()
    rec_s1 = of_r1["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
    unconf_rec_tx = _h32("d8-r2g01-unconf")
    of_r1["chain"]["txs"][rec_s1["txid"]]["outputs"]["0"]["spent_by_txid"] = unconf_rec_tx
    of_r1["chain"]["txs"][unconf_rec_tx] = {"confirmed_height": None, "mempool": True, "outputs": {"0": {"script_pubkey_hex": "0014" + "aa" * 20}}}
    add(
        "d8-r2g01-unconfirmed-recovery-spend-incomplete-refuse",
        ["SL-ORIG-013"],
        "origin_status",
        {"chain": of_r1["chain"], "origin_bundle": of_r1["origin_bundle"], "trusted_origin_issuers": of_r1["trusted_origin_issuers"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "R2G-01: Unconfirmed mempool spend of recovery_seal MUST return ORIGIN_STATUS_INCOMPLETE (never permanently burning recovery).",
    )

    of_r2 = rm._base_origin_fixture()
    rec_s2 = of_r2["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
    withheld_rec_tx = _h32("d8-r2g01-withheld")
    of_r2["chain"]["txs"][rec_s2["txid"]]["outputs"]["0"]["spent_by_txid"] = withheld_rec_tx
    of_r2["chain"]["txs"][withheld_rec_tx] = {
        "confirmed_height": 749600,
        "opreturn_hex": sl.encode_opreturn(0x0C, _h32("d8-r2g01-withheld-b2")).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_s2["script_policy"])}},
    }
    add(
        "d8-r2g01-confirmed-0x0c-withheld-candidate-incomplete-refuse",
        ["SL-ORIG-013"],
        "origin_status",
        {"chain": of_r2["chain"], "origin_bundle": of_r2["origin_bundle"], "trusted_origin_issuers": of_r2["trusted_origin_issuers"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "R2G-01: Confirmed valid 0x0c + continuation spend where presenter withholds the candidate NameBinding MUST return ORIGIN_STATUS_INCOMPLETE (never reverting to B_1).",
    )

    of_r3 = rm._base_origin_fixture()
    rec_s3 = of_r3["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
    mal_rec_tx3 = _h32("d8-r2g01-malformed")
    of_r3["chain"]["txs"][rec_s3["txid"]]["outputs"]["0"]["spent_by_txid"] = mal_rec_tx3
    of_r3["chain"]["txs"][mal_rec_tx3] = {"confirmed_height": 749600, "outputs": {"0": {"script_pubkey_hex": "0014" + "bb" * 20}}}
    add(
        "d8-r2g01-confirmed-malformed-recovery-spend-burns-b1-survives",
        ["SL-ORIG-013"],
        "origin_status",
        {"chain": of_r3["chain"], "expect_recovery_burned": True, "origin_bundle": of_r3["origin_bundle"], "trusted_origin_issuers": of_r3["trusted_origin_issuers"]},
        "ADMIT_WARD",
        None,
        "R2G-01: Confirmed provably malformed recovery_seal spend sets recovery_burned=True while preserving live binding B_1.",
    )

    of_r4 = rm._base_origin_fixture()
    rec_s4 = of_r4["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
    bad_b2 = {
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo-badseq",
        "network": "main",
        "next_recovery_policy": rec_s4["script_policy"],
        "next_recovery_vout": 0,
        "origin_id": of_r4["_origin_id"],
        "owner_policy": of_r4["origin_bundle"]["name_binding"]["owner_policy"],
        "registration": {"txid": _h32("d8-r2g01-badseq-reg"), "vout": 0},
        "seq": 9,  # invalid seq != prev.seq + 1
        "supersedes_binding_id": sl.object_id(of_r4["origin_bundle"]["name_binding"]),
        "type": "seallink-name-binding/1",
    }
    bad_rec_tx4 = _h32("d8-r2g01-badpreimage")
    of_r4["chain"]["txs"][rec_s4["txid"]]["outputs"]["0"]["spent_by_txid"] = bad_rec_tx4
    of_r4["chain"]["txs"][bad_rec_tx4] = {
        "confirmed_height": 749600,
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(bad_b2)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_s4["script_policy"])}},
    }
    of_r4["origin_bundle"]["recovery_bindings"] = [bad_b2]
    add(
        "d8-r2g01-confirmed-0x0c-invalid-preimage-seq-burns-b1-survives",
        ["SL-ORIG-013"],
        "origin_status",
        {"chain": of_r4["chain"], "expect_recovery_burned": True, "origin_bundle": of_r4["origin_bundle"], "trusted_origin_issuers": of_r4["trusted_origin_issuers"]},
        "ADMIT_WARD",
        None,
        "R2G-01: Confirmed 0x0c spend whose verified preimage violates seq == prev.seq + 1 burns recovery while preserving B_1.",
    )

    # =========================================================================
    # 4. Decision 1B, R2G-02..07, H-29, H-31, G-5, R2-L-02, R2-05
    # =========================================================================
    # R2G-02: At t_low >= T without capacity/1, custodian self-transfer A->B->B still refuses GUARDIAN_TRANSFER_PENDING!
    of_rt = rm._base_origin_fixture()
    maj_rt = of_rt["_maj_unix"]
    of_rt["chain"]["credible_utc_interval"] = [maj_rt + 100, maj_rt + 200]
    of_rt["chain"]["tip_median_time_past"] = maj_rt + 50
    fake_b_pol = {"kind": "key", "pk": _kp("d8-r2g02-fake-b")["comp"]}
    fake_b_spk, _ = sl.compile_script_policy(fake_b_pol)
    leo_u_rt = of_rt["chain"]["names"]["id/child-leo"]["updates"]
    prev_rt = leo_u_rt[-1]
    val_rt = sl.jcs_encode({"link": {"origin": of_rt["_origin_id"]}})
    leo_u_rt.append({"confirmed_height": 749900, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", fake_b_spk, name=b"id/child-leo", value=val_rt).hex(), "owner_policy": fake_b_pol, "prev_input": {"sighash_bytes": [0x01], "txid": prev_rt["txid"], "vout": prev_rt["vout"], "witness_policy": prev_rt["owner_policy"]}, "txid": _h32("d8-rt-1"), "vout": 0})
    leo_u_rt.append({"confirmed_height": 749910, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", fake_b_spk, name=b"id/child-leo", value=val_rt).hex(), "owner_policy": fake_b_pol, "prev_input": {"sighash_bytes": [0x01], "txid": _h32("d8-rt-1"), "vout": 0, "witness_policy": fake_b_pol}, "txid": _h32("d8-rt-2"), "vout": 0})
    add(
        "d8-1b-person-majority-custodian-transfer-without-capacity-refuse",
        ["SL-ORIG-011"],
        "origin_status",
        {"chain": of_rt["chain"], "origin_bundle": of_rt["origin_bundle"], "trusted_origin_issuers": of_rt["trusted_origin_issuers"]},
        "REFUSE",
        "GUARDIAN_TRANSFER_PENDING",
        "Decision 1B / R2G-02: Calendar majority T alone without capacity/1 or 0x0c recovery NEVER admits State 4 even if custodians transfer the name.",
    )

    # R2G-04: Full E2E State-4 emancipated subject issues autonomous mail/read grant (and rotates owner_policy S -> S2!) -> ADMIT!
    def _build_state4_e2e(*, rotate_owner: bool = False) -> dict[str, Any]:
        fx_s4 = rm._base_invocation_fixture()
        of_s4 = rm._base_origin_fixture()
        subj_own_1 = _kp("d8-s4-subj-own1")
        subj_own_2 = _kp("d8-s4-subj-own2")
        subj_gr = _kp("d8-s4-subj-gr")
        subj_pol_1 = {"kind": "key", "pk": subj_own_1["comp"]}
        subj_pol_2 = {"kind": "key", "pk": subj_own_2["comp"]}
        active_pol = subj_pol_2 if rotate_owner else subj_pol_1
        # Confirmed seallink-capacity/1 spending status_seal naming subj_pol_1
        cap_s4_p = {
            "basis_sha256": _h32("d8-s4-basis"),
            "genesis": GENESIS_MAIN,
            "issued_at": of_s4["chain"]["now"] - 500,
            "issuer": of_s4["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "next_status_policy": of_s4["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"],
            "next_status_vout": 0,
            "origin_id": of_s4["_origin_id"],
            "status_prev_outpoint": {"txid": of_s4["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": of_s4["origin_bundle"]["origin"]["payload"]["status_seal"]["vout"]},
            "subject_new_owner_policy": subj_pol_1,
            "type": "seallink-capacity/1",
        }
        cap_s4 = sl.sign_envelope(cap_s4_p, [of_s4["_keys"]["reg_cred"]["sk"]])
        cap_s4_tx = _h32("d8-s4-cap-tx")
        of_s4["chain"]["txs"][of_s4["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_s4_tx
        of_s4["chain"]["txs"][cap_s4_tx] = {
            "confirmed_height": 749100,
            "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_s4)).hex(),
            "outputs": {"0": {"script_pubkey_hex": _spk_hex(cap_s4_p["next_status_policy"])}},
        }
        of_s4["origin_bundle"]["capacity_record"] = cap_s4

        leo_man = {
            "network": "main",
            "owner": "id/child-leo",
            "providers": [
                {
                    "label": "work",
                    "provider": {"name": "id/mail-host-a", "owner_policy": fx_s4["_host_owner_pol"], "registration": fx_s4["_host_reg"]},
                    "service_type": "mail",
                }
            ],
            "seq": 1,
            "type": "seallink-manifest/1",
        }
        leo_man_h = sl.content_addr(leo_man)
        leo_val = sl.jcs_encode({"link": {"grant": subj_gr["xonly"], "origin": of_s4["_origin_id"]}, "m": {"h": leo_man_h, "s": 1}})
        s1_spk, _ = sl.compile_script_policy(subj_pol_1)
        s2_spk, _ = sl.compile_script_policy(subj_pol_2)
        lu = of_s4["chain"]["names"]["id/child-leo"]["updates"]
        p_u = lu[-1]
        lu.append({"confirmed_height": 749200, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", s1_spk, name=b"id/child-leo", value=leo_val).hex(), "owner_policy": subj_pol_1, "prev_input": {"sighash_bytes": [0x01], "txid": p_u["txid"], "vout": p_u["vout"], "witness_policy": p_u["owner_policy"]}, "txid": _h32("d8-s4-u1"), "vout": 0})
        lu.append({"confirmed_height": 749210, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", s1_spk, name=b"id/child-leo", value=leo_val).hex(), "owner_policy": subj_pol_1, "prev_input": {"sighash_bytes": [0x01], "txid": _h32("d8-s4-u1"), "vout": 0, "witness_policy": subj_pol_1}, "txid": _h32("d8-s4-u2"), "vout": 0})
        if rotate_owner:
            lu.append({"confirmed_height": 749220, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", s2_spk, name=b"id/child-leo", value=leo_val).hex(), "owner_policy": subj_pol_2, "prev_input": {"sighash_bytes": [0x01], "txid": _h32("d8-s4-u2"), "vout": 0, "witness_policy": subj_pol_1}, "txid": _h32("d8-s4-u3"), "vout": 0})
            lu.append({"confirmed_height": 749230, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", s2_spk, name=b"id/child-leo", value=leo_val).hex(), "owner_policy": subj_pol_2, "prev_input": {"sighash_bytes": [0x01], "txid": _h32("d8-s4-u3"), "vout": 0, "witness_policy": subj_pol_2}, "txid": _h32("d8-s4-u4"), "vout": 0})

        fx_s4["chain"]["names"].update(of_s4["chain"]["names"])
        fx_s4["chain"]["txs"].update(of_s4["chain"]["txs"])
        fx_s4["chain"]["tip_height"] = of_s4["chain"]["tip_height"]
        fx_s4["chain"]["best_header_height"] = of_s4["chain"]["tip_height"]
        fx_s4["chain"]["tip_hash"] = of_s4["chain"]["tip_hash"]
        fx_s4["chain"]["comparison_peers"] = of_s4["chain"]["comparison_peers"]
        fx_s4["chain"]["credible_utc_interval"] = of_s4["chain"]["credible_utc_interval"]
        fx_s4["chain"]["tip_median_time_past"] = of_s4["chain"]["tip_median_time_past"]
        fx_s4["chain"]["manifests"][leo_man_h] = leo_man
        fx_s4["bundle"]["manifests"][leo_man_h] = leo_man
        fx_s4["bundle"]["origin_bundle"] = of_s4["origin_bundle"]
        fx_s4["trusted_origin_issuers"] = of_s4["trusted_origin_issuers"]

        gp_s4 = copy.deepcopy(fx_s4["bundle"]["grants"][0]["payload"])
        gp_s4["issuer"] = {
            "name": "id/child-leo",
            "owner_policy": active_pol,
            "registration": of_s4["origin_bundle"]["name_binding"]["registration"],
            "role_policy": {"m": 1, "pks": [subj_gr["xonly"]]},
        }
        gp_s4["capabilities"] = [{"action": "mail/read", "target": "mailbox:id/child-leo:work", "where": {"folder": {"in": ["Invoices"]}}}]
        _reanchor(fx_s4, gp_s4, signer_sk=subj_gr["sk"])
        inv_s4_p = copy.deepcopy(fx_s4["invocation"]["payload"])
        inv_s4_p["target"] = "mailbox:id/child-leo:work"
        fx_s4["invocation"] = sl.sign_envelope(inv_s4_p, [fx_s4["_keys"]["agent_req"]["sk"]])
        return fx_s4

    add(
        "d8-1b-state4-emancipated-subject-e2e-grant-admit",
        ["SL-ORIG-011", "SL-GRNT-012"],
        "invocation",
        _build_state4_e2e(rotate_owner=False),
        "ADMIT",
        None,
        "Decision 1B / R2G-04: Emancipated State-4 subject (capacity/1 + handover + self-update) issues an autonomous mail/read grant under effective_binding and admits.",
    )
    add(
        "d8-1b-state4-emancipated-subject-routine-owner-rotation-admit",
        ["SL-ORIG-011", "SL-GRNT-012"],
        "invocation",
        _build_state4_e2e(rotate_owner=True),
        "ADMIT",
        None,
        "Decision 1B / R2G-04: State-4 emancipated subject rotating owner_policy S -> S2 via self-authored SIGHASH_ALL update continues admitting autonomous grants.",
    )

    # R2G-07: Agent origin carrying majority_commitment MUST refuse WIRE_MEMBER!
    of_ag_m = rm._base_origin_fixture()
    op_ag_m = copy.deepcopy(of_ag_m["origin_bundle"]["origin"]["payload"])
    op_ag_m["origin_class"] = "agent"
    env_ag_m = sl.sign_envelope(op_ag_m, [of_ag_m["_keys"]["reg_cred"]["sk"]])
    add(
        "d8-1b-agent-majority-commitment-forbidden-refuse",
        ["SL-ORIG-002", "SL-WIRE-010"],
        "raw_wire",
        {"expected_type": "seallink-origin/1", "raw_bytes_hex": sl.jcs_encode(env_ag_m).hex()},
        "REFUSE",
        "WIRE_MEMBER",
        "Decision 1B / R2G-07: seallink-origin/1 with origin_class='agent' carrying claims.majority_commitment MUST refuse WIRE_MEMBER.",
    )

    # R2G-03: Mismatched majority_commitment opening -> ORIGIN_UNVERIFIED (distinct from omitted -> ORIGIN_STATUS_INCOMPLETE!)
    of_mm = rm._base_origin_fixture()
    of_mm["origin_bundle"]["opened_majority_unix"] = of_mm["_maj_unix"] + 1
    add(
        "d8-r2g03-majority-commitment-mismatched-opening-origin-unverified",
        ["SL-ORIG-002"],
        "origin_status",
        {"chain": of_mm["chain"], "origin_bundle": of_mm["origin_bundle"], "trusted_origin_issuers": of_mm["trusted_origin_issuers"]},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "R2G-03: Presented majority_commitment opening that mismatches the hash MUST refuse ORIGIN_UNVERIFIED.",
    )

    # R2G-05 & H-29: Non-retroactive 0x10 confirmed BEFORE T survives AFTER T, AND survives later owner rotation!
    of_nr10 = rm._base_origin_fixture()
    maj_nr10 = of_nr10["_maj_unix"]
    rec_nr10 = of_nr10["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
    b2_nr10 = {
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo-rec-nr10",
        "network": "main",
        "next_recovery_policy": rec_nr10["script_policy"],
        "next_recovery_vout": 0,
        "origin_id": of_nr10["_origin_id"],
        "owner_policy": {"kind": "key", "pk": _kp("d8-nr10-b2")["comp"]},
        "registration": {"txid": _h32("d8-nr10-b2-reg"), "vout": 0},
        "seq": 2,
        "supersedes_binding_id": sl.object_id(of_nr10["origin_bundle"]["name_binding"]),
        "type": "seallink-name-binding/1",
    }
    b2_nr10_id = sl.object_id(b2_nr10)
    t_rec_nr10 = _h32("d8-nr10-trec")
    of_nr10["chain"]["txs"][rec_nr10["txid"]]["outputs"]["0"]["spent_by_txid"] = t_rec_nr10
    of_nr10["chain"]["txs"][t_rec_nr10] = {
        "confirmed_height": 749100,
        "opreturn_hex": sl.encode_opreturn(0x0C, b2_nr10_id).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_nr10["script_policy"])}},
    }
    lu_nr10 = of_nr10["chain"]["names"]["id/child-leo"]["updates"]
    prev_nr10 = lu_nr10[-1]
    w_pol_nr10 = of_nr10["origin_bundle"]["name_binding"]["owner_policy"]
    w_spk_nr10, _ = sl.compile_script_policy(w_pol_nr10)
    lu_nr10.append({
        "block_time": maj_nr10 - 10000,  # STRICTLY before majority T!
        "confirmed_height": 749200,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, b2_nr10_id).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", w_spk_nr10, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_nr10["_origin_id"]}})).hex(),
        "owner_policy": w_pol_nr10,
        "prev_input": {"sighash_bytes": [0x01], "txid": prev_nr10["txid"], "vout": prev_nr10["vout"], "witness_policy": prev_nr10["owner_policy"]},
        "txid": _h32("d8-nr10-0x10-tx"),
        "vout": 0,
    })
    of_nr10["origin_bundle"]["recovery_bindings"] = [b2_nr10]
    # Now advance tip past delay (749100 + 1008 = 750108 -> tip = 750500) AND past T -> B2 MUST stay cancelled (assert_binding_id=b2 -> RECOVERY_FORBIDDEN)!
    of_nr10_after_t = copy.deepcopy(of_nr10)
    of_nr10_after_t["chain"]["tip_height"] = 750500
    of_nr10_after_t["chain"]["best_header_height"] = 750500
    of_nr10_after_t["chain"]["comparison_peers"] = [{"hash_at_tip": of_nr10["chain"]["tip_hash"], "healthy": True, "height": 750500}]
    of_nr10_after_t["chain"]["credible_utc_interval"] = [maj_nr10 + 100, maj_nr10 + 200]
    of_nr10_after_t["chain"]["tip_median_time_past"] = maj_nr10 + 50
    add(
        "d8-r2g05-non-retroactive-0x10-before-t-stays-cancelled-after-t",
        ["SL-ORIG-014"],
        "origin_status",
        {"assert_binding_id": b2_nr10_id, "chain": of_nr10_after_t["chain"], "origin_bundle": of_nr10_after_t["origin_bundle"], "trusted_origin_issuers": of_nr10_after_t["trusted_origin_issuers"]},
        "REFUSE",
        "RECOVERY_FORBIDDEN",
        "R2G-05: A valid 0x10 cancel confirmed at block_time < T MUST NOT be retroactively invalidated after T (cancelled B_2 stays RECOVERY_FORBIDDEN).",
    )
    # H-29: Same 0x10 cancel survives even after a subsequent routine owner update before T!
    of_h29 = copy.deepcopy(of_nr10)
    of_h29["chain"]["tip_height"] = 750500
    of_h29["chain"]["best_header_height"] = 750500
    of_h29["chain"]["comparison_peers"] = [{"hash_at_tip": of_nr10["chain"]["tip_hash"], "healthy": True, "height": 750500}]
    of_h29["chain"]["names"]["id/child-leo"]["updates"].append({
        "block_time": 1795219500,
        "confirmed_height": 750200,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", w_spk_nr10, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_nr10["_origin_id"]}})).hex(),
        "owner_policy": w_pol_nr10,
        "prev_input": {"sighash_bytes": [0x01], "txid": _h32("d8-nr10-0x10-tx"), "vout": 0, "witness_policy": w_pol_nr10},
        "txid": _h32("d8-h29-later-upd"),
        "vout": 0,
    })
    add(
        "d8-h29-full-history-0x10-survives-later-update-admit-ward",
        ["SL-ORIG-014"],
        "origin_status",
        {"chain": of_h29["chain"], "origin_bundle": of_h29["origin_bundle"], "trusted_origin_issuers": of_h29["trusted_origin_issuers"]},
        "ADMIT_WARD",
        None,
        "H-29: Full-history 0x10 scan preserves a valid cancel confirmed during [h_rec, h_rec+delay) even after subsequent name updates.",
    )

    # R2G-06: Missing tip_median_time_past on ward with majority_commitment -> GUARDIAN_TIME_BOUNDARY
    of_nomtp = rm._base_origin_fixture()
    of_nomtp["chain"].pop("tip_median_time_past", None)
    add(
        "d8-r2g06-missing-tip-mtp-fails-closed-refuse",
        ["SL-ORIG-010"],
        "origin_status",
        {"chain": of_nomtp["chain"], "origin_bundle": of_nomtp["origin_bundle"], "trusted_origin_issuers": of_nomtp["trusted_origin_issuers"]},
        "REFUSE",
        "GUARDIAN_TIME_BOUNDARY",
        "R2G-06: Omitting tip_median_time_past when evaluating a ward origin with majority_commitment MUST fail closed with GUARDIAN_TIME_BOUNDARY.",
    )

    # H-31: seallink-capacity/1 with mismatched status_prev_outpoint -> ORIGIN_STATUS_INCOMPLETE
    of_h31 = rm._base_origin_fixture()
    cap_h31_p = {
        "basis_sha256": _h32("d8-h31-b"),
        "genesis": GENESIS_MAIN,
        "issued_at": of_h31["chain"]["now"] - 100,
        "issuer": of_h31["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "next_status_policy": of_h31["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"],
        "next_status_vout": 0,
        "origin_id": of_h31["_origin_id"],
        "status_prev_outpoint": {"txid": _h32("d8-h31-wrong-prev"), "vout": 0},
        "subject_new_owner_policy": {"kind": "key", "pk": _kp("d8-h31-s")["comp"]},
        "type": "seallink-capacity/1",
    }
    cap_h31 = sl.sign_envelope(cap_h31_p, [of_h31["_keys"]["reg_cred"]["sk"]])
    cap_h31_tx = _h32("d8-h31-cap-tx")
    of_h31["chain"]["txs"][of_h31["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_h31_tx
    of_h31["chain"]["txs"][cap_h31_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_h31)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(cap_h31_p["next_status_policy"])}}}
    of_h31["origin_bundle"]["capacity_record"] = cap_h31
    add(
        "d8-h31-capacity-wrong-status-prev-outpoint-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"chain": of_h31["chain"], "origin_bundle": of_h31["origin_bundle"], "trusted_origin_issuers": of_h31["trusted_origin_issuers"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "H-31: seallink-capacity/1 whose status_prev_outpoint mismatches the spent status_seal outpoint MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )

    # R2-L-02: 0x0e activation with truthy witness selector (spoofing disposer/challenger branch even with sequence=delay) -> GUARDIAN_INACTIVE!
    of_l02 = rm._base_origin_fixture()
    gp_l02 = of_l02["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    dly_l02 = gp_l02["appointment_delay_blocks"]
    vac_l02 = gp_l02["roster_seal"]["script_policy"]
    g_l02_k = _kp("d8-l02-g")
    pend_l02 = {"delay_blocks": dly_l02, "keys": {"challenger": gp_l02["challenger_pk"], "disposer": gp_l02["disposer_pk"], "guardian": g_l02_k["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
    act_l02 = {"keys": sl.canonical_branch_pair(gp_l02["disposer_pk"], g_l02_k["comp"]), "kind": "branch", "template": "either_of_2"}
    rost_l02_p = {
        "arbiter_pk": gp_l02["arbiter_pk"], "challenger_pk": gp_l02["challenger_pk"], "disposer_pk": gp_l02["disposer_pk"],
        "effective_delay_blocks": dly_l02, "genesis": GENESIS_MAIN, "issuer": of_l02["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main", "next_roster_policy": vac_l02, "next_roster_vout": 0, "origin_id": of_l02["_origin_id"],
        "prev_revision": 1, "prev_roster_outpoint": {"txid": gp_l02["roster_seal"]["txid"], "vout": 0},
        "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in gp_l02["quorums"]}, "revision": 2, "revision_size": 1,
        "slots": [{"action": "new_vacant", "new_vacant_policy": vac_l02, "new_vacant_vout": 1, "slot": 1}], "type": "seallink-guardian-roster/1",
    }
    rost_l02 = sl.sign_envelope(rost_l02_p, [of_l02["_keys"]["reg_cred"]["sk"]])
    rtx_l02, dtx_l02, etx_l02 = _h32("d8-l02-r"), _h32("d8-l02-d"), _h32("d8-l02-e")
    g2_l02_p = {
        "activation_mode": "appointed", "active_policy": act_l02, "effective_delay_blocks": dly_l02,
        "genesis": GENESIS_MAIN, "guardian": of_l02["origin_bundle"]["guardian_records"][0]["payload"]["guardian"],
        "issuer": of_l02["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main", "origin_id": of_l02["_origin_id"],
        "pending_policy": pend_l02, "pending_vout": 0, "prev_outpoint": {"txid": rtx_l02, "vout": 1}, "revision": 2, "slot": 1,
        "term": {"mode": "indefinite"}, "type": "seallink-guardian/1",
    }
    g2_l02 = sl.sign_envelope(g2_l02_p, [of_l02["_keys"]["reg_cred"]["sk"]])
    g2_l02_ass = sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-l02-ga"), "party_id": "g-l02", "party_name": "id/parent-a", "party_role": "guardian", "target_id": sl.object_id(g2_l02_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"}, [of_l02["_keys"]["g1_gr"]["sk"]])
    tip_l02 = of_l02["chain"]["tip_height"]
    of_l02["chain"]["txs"][gp_l02["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_l02
    of_l02["chain"]["txs"][rtx_l02] = {"confirmed_height": tip_l02 - 2 * dly_l02 - 10, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_l02)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_l02)}, "1": {"script_pubkey_hex": _spk_hex(vac_l02), "spent_by_txid": dtx_l02}}}
    of_l02["chain"]["txs"][dtx_l02] = {"confirmed_height": tip_l02 - dly_l02, "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g2_l02)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_l02), "spent_by_txid": etx_l02}}}
    bad_csv_inp = sv.make_guardian_csv_input(dtx_l02, 0, pend_l02, sequence=dly_l02)
    bad_csv_inp["witness"][2] = "01"  # Outer selector TRUE (disposer veto spoof!)
    of_l02["chain"]["txs"][etx_l02] = {"confirmed_height": tip_l02, "inputs": [bad_csv_inp], "opreturn_hex": sl.encode_opreturn(0x0E, sl.object_id(g2_l02_p)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_l02)}}}
    of_l02["origin_bundle"]["roster_records"] = [rost_l02]
    of_l02["origin_bundle"]["guardian_records"].append(g2_l02)
    of_l02["origin_bundle"]["guardian_assents"].append(g2_l02_ass)
    wa_l02 = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": of_l02["_origin_id"], "revision": 2, "ward_name": "id/child-leo"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-l02-wa"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
         "target_id": sl.object_id(of_l02["contract"]), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"guardian_name": "id/parent-a", "revision": 2, "signers": [of_l02["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add(
        "d8-r2l02-0x0e-spoofed-truthy-selector-refuse",
        ["SL-ORIG-007", "SL-LDGR-004"],
        "assent",
        {"assent": wa_l02, "chain": of_l02["chain"], "contract": of_l02["contract"], "origin_bundle": of_l02["origin_bundle"], "trusted_origin_issuers": of_l02["trusted_origin_issuers"]},
        "REFUSE",
        "GUARDIAN_INACTIVE",
        "R2-L-02: 0x0e activation with truthy P2WSH branch selector (disposer/challenger branch spoof) MUST fail closed as GUARDIAN_INACTIVE.",
    )

    # R2-05: trusted_origin_issuer_pins rejects same name with different registration!
    of_pin = rm._base_origin_fixture()
    wrong_reg_pin = {
        "name": "id/civil-registry",
        "owner_policy": of_pin["origin_bundle"]["origin"]["payload"]["issuer"]["owner_policy"],
        "registration": {"txid": _h32("d8-r2-05-other-reg"), "vout": 0},
    }
    add(
        "d8-r2-05-trusted-origin-issuer-pin-wrong-registration-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"chain": of_pin["chain"], "origin_bundle": of_pin["origin_bundle"], "trusted_origin_issuer_pins": [wrong_reg_pin], "trusted_origin_issuers": []},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "R2-05: trusted_origin_issuer_pins MUST match full NamePin (name, registration, owner_policy) and refuse a re-registered name string with ORIGIN_UNVERIFIED.",
    )

    # =========================================================================
    # 5. G7-01, G7-02, G7-05, G7-06, G7-08, M-3, R3 Blockers #1/#4, R3 High #2, W-13, S-7, S-13, R2-01..03, D-6, H-19, R2-10
    # =========================================================================
    # G7-01: station: default fail-closed for foreign issuer, AND self-owner ADMIT!
    fx_st_bad = rm._contract_fx()
    fx_st_bad["executor_cfg"].pop("station_slot_bindings", None)  # default fail-closed!
    add(
        "d8-g7-01-station-default-fail-closed-foreign-issuer-refuse",
        ["SL-GRNT-012", "SL-AGNT-002"],
        "invocation",
        fx_st_bad,
        "REFUSE",
        "GRANT_TARGET_UNAUTHORIZED",
        "G7-01: station:<host>:<slot> without explicit station_slot_bindings MUST refuse any foreign issuer (id/alice != id/station-a) with GRANT_TARGET_UNAUTHORIZED.",
    )
    fx_st_own = rm._contract_fx()
    fx_st_own["executor_cfg"].pop("station_slot_bindings", None)
    # Station owner id/station-a itself issues the grant -> ADMIT without needing station_slot_bindings!
    st_own_k = _kp("d8-g7-01-st-own")
    st_gr_k = _kp("d8-g7-01-st-gr")
    st_own_pol = {"kind": "key", "pk": st_own_k["comp"]}
    st_reg = {"txid": _h32("d8-g7-01-st-reg"), "vout": 0}
    fx_st_own["chain"]["names"]["id/station-a"] = sv.make_name_history("id/station-a", st_reg, st_own_pol, {"link": {"grant": st_gr_k["xonly"]}}, first_height=748000, update_height=749000)
    fx_st_own["bundle"]["contract"]["parties"][0]["signing_policy"] = {"m": 1, "pks": [st_gr_k["xonly"]]}
    cid_sto = sl.object_id(fx_st_own["bundle"]["contract"])
    fx_st_own["bundle"]["contract_assents"] = [
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-sto-a1"), "party_id": "client-1", "party_role": "client", "target_id": cid_sto, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [st_gr_k["sk"]]),
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-sto-a2"), "party_id": "worker-1", "party_role": "worker", "target_id": cid_sto, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_st_own["_keys"]["agent_req"]["sk"]]),
    ]
    gp_sto = copy.deepcopy(fx_st_own["bundle"]["grants"][0]["payload"])
    gp_sto["contract_id"] = cid_sto
    gp_sto["issuer"] = {"name": "id/station-a", "owner_policy": st_own_pol, "registration": st_reg, "role_policy": {"m": 1, "pks": [st_gr_k["xonly"]]}}
    _reanchor(fx_st_own, gp_sto, signer_sk=st_gr_k["sk"])
    add(
        "d8-g7-01-station-owner-self-issuer-admit",
        ["SL-GRNT-012", "SL-AGNT-002"],
        "invocation",
        fx_st_own,
        "ADMIT",
        None,
        "G7-01: station:<host>:<slot> with issuer == verified <host> owner admits cleanly without extra station_slot_bindings.",
    )

    # G7-02: Required quota resource != target -> QUOTA_EXCEEDED
    fx_qres = rm._contract_fx()
    bad_cap_q = {"action": "agent/session", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "station:id/station-a:wrong-slot", "unit": "starts", "window": "term"}], "target": "station:id/station-a:slot1"}
    c0_q = {"machine_terms": {"capabilities": [bad_cap_q]}, "text": "Wrong quota resource"}
    s0_q = _h32("d8-g7-02-s0")
    fx_qres["bundle"]["contract"]["clause_commitments"] = [sl.clause_commit(s0_q, c0_q)]
    cid_qr = sl.object_id(fx_qres["bundle"]["contract"])
    fx_qres["bundle"]["disclosed_clauses"] = {"0": {"clause": c0_q, "salt_hex": s0_q}}
    fx_qres["bundle"]["contract_assents"] = [
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-qr-a1"), "party_id": "client-1", "party_role": "client", "target_id": cid_qr, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_qres["_keys"]["alice_gr"]["sk"]]),
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-qr-a2"), "party_id": "worker-1", "party_role": "worker", "target_id": cid_qr, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_qres["_keys"]["agent_req"]["sk"]]),
    ]
    gp_qr = copy.deepcopy(fx_qres["bundle"]["grants"][0]["payload"])
    gp_qr["contract_id"] = cid_qr
    gp_qr["capabilities"] = [bad_cap_q]
    _reanchor(fx_qres, gp_qr)
    add(
        "d8-g7-02-required-quota-wrong-resource-refuse",
        ["SL-GRNT-007", "SL-AGNT-005"],
        "invocation",
        fx_qres,
        "REFUSE",
        "QUOTA_EXCEEDED",
        "G7-02: Required profile quota whose resource != target MUST refuse QUOTA_EXCEEDED.",
    )

    # G7-05: Foreign 0x11 does NOT close a live single_use grant -> legitimate invocation still ADMITs!
    fx_ados = copy.deepcopy(fx_su)
    inv_foreign = sl.sign_envelope({**inv_su["payload"], "nonce": _h32("d8-g7-05-foreign")}, [fx_su["_keys"]["agent_req"]["sk"]])
    add(
        "d8-g7-05-foreign-0x11-does-not-close-single-use-grant",
        ["SL-LDGR-012"],
        "single_use_anti_dos",
        {
            "bundle": fx_ados["bundle"],
            "chain": fx_ados["chain"],
            "executor_cfg": fx_ados["executor_cfg"],
            "foreign_invocation": inv_foreign,
            "foreign_use_txid": su_use_tx,
            "good_invocation": inv_su,
            "good_use_txid": su_use_tx,
            "journal_id": _h32("d8-g7-05-j"),
        },
        "ADMIT",
        None,
        "G7-05 anti-DoS: Presenting a foreign invocation against a legitimate 0x11 spend refuses SEAL_SPENT without closing grant_id, so the legitimate invocation still ADMITs.",
    )

    # G7-06 / H-4: Persisted contract closure in journal blocks invocation even when chain seal looks unspent!
    fx_ccl = rm._contract_fx()
    cid_ccl = sl.object_id(fx_ccl["bundle"]["contract"])
    fx_ccl["journal"]["closures"] = {f"contract:{cid_ccl}": {"reason": "SEAL_SPENT", "subject": {"subject_id": cid_ccl, "subject_kind": "contract"}}}
    add(
        "d8-g7-06-persisted-contract-closure-blocks-invocation",
        ["SL-CONT-005", "SL-GRNT-012"],
        "invocation",
        fx_ccl,
        "REFUSE",
        "SEAL_SPENT",
        "G7-06 / H-4: Persisted ClosureSubject(subject_kind='contract') in local journal MUST block invocation with SEAL_SPENT even if chain UTXO appears unspent.",
    )

    # G7-08: Concrete executor mail/read without confirmed holder manifest -> SERVICE_PROVIDER_UNBOUND!
    fx_g708 = rm._base_invocation_fixture()
    fx_g708["bundle"]["manifests"] = {k: v for k, v in fx_g708["bundle"]["manifests"].items() if v.get("owner") != "id/alice"}
    fx_g708["chain"]["manifests"] = {}
    add(
        "d8-g7-08-concrete-mail-missing-holder-manifest-refuse",
        ["SL-MAIL-003", "SL-SERV-001"],
        "invocation",
        fx_g708,
        "REFUSE",
        "SERVICE_PROVIDER_UNBOUND",
        "G7-08: Concrete-executor mail/read grant lacking confirmed holder manifest pinning this provider MUST fail closed with SERVICE_PROVIDER_UNBOUND.",
    )

    # M-3: Declared stop_txid missing from ChainView -> fail closed SEAL_UNAVAILABLE!
    fx_m3 = rm._delegation_fx(notary_mode="optional_stop", with_stop=True)
    fx_m3["chain"]["txs"].pop(rm._h32("stop-tx"), None)
    add(
        "d8-m3-missing-stop-coin-tx-fails-closed-refuse",
        ["SL-GRNT-011"],
        "invocation",
        fx_m3,
        "REFUSE",
        "SEAL_UNAVAILABLE",
        "M-3: Depth-2 grant declaring a stop coin whose creation tx is unavailable on chain MUST fail closed with SEAL_UNAVAILABLE.",
    )

    # R3 Blocker #1: Depth-2 child 0x01 anchor missing (child_seal_txid, child_seal_vout + 1) linkage -> CHAIN_TX_CONSTRUCTION!
    db_r3 = bbs._build_delegation_base(pool_calls=10, row_cap_calls=2, c1_max_calls=1, c2_max_calls=2, c1_kind="revocable")
    db_r3["chain"]["txs"][db_r3["c1_itx"]]["inputs"] = [sv.make_segwit_input(db_r3["rows_tx"], 0)]  # missing (c1_stx, 1)!
    add(
        "d8-r3-b1-child-0x01-missing-seal-linkage-refuse",
        ["SL-LDGR-009", "SL-GRNT-009"],
        "invocation",
        {
            "bundle": {"grants": [db_r3["parent_env"], db_r3["c1_env"]]},
            "chain": db_r3["chain"],
            "executor_cfg": db_r3["executor_cfg"],
            "invocation": db_r3["make_inv"](db_r3["c1_id"], db_r3["c1_itx"], db_r3["keys"]["w1_k"], "d8-r3b1"),
            "journal": db_r3["journal"],
        },
        "REFUSE",
        "CHAIN_TX_CONSTRUCTION",
        "R3 Blocker #1: Depth-2 child 0x01 anchor spending row_coin WITHOUT (child_seal_txid, child_seal_vout + 1) MUST refuse CHAIN_TX_CONSTRUCTION.",
    )

    # R3 Blocker #4 (Decision 4): Unsorted both_of_2 (a > b) & shared x-coord across roles -> CHAIN_SCRIPT_UNSUPPORTED!
    ka4, kb4 = _kp("d8-b4-a"), _kp("d8-b4-b")
    lo4, hi4 = (ka4["comp"], kb4["comp"]) if ka4["comp"] < kb4["comp"] else (kb4["comp"], ka4["comp"])
    fx_u4 = rm._base_invocation_fixture()
    gp_u4 = copy.deepcopy(fx_u4["bundle"]["grants"][0]["payload"])
    gp_u4["revocation"]["seal"]["script_policy"] = {"keys": {"a": hi4, "b": lo4}, "kind": "branch", "template": "both_of_2"}
    add(
        "d8-r3-b4-unsorted-both-of-2-refuse",
        ["SL-LDGR-004"],
        "raw_wire",
        {"expected_type": "seallink-grant/1", "raw_bytes_hex": sl.jcs_encode(sl.sign_envelope(gp_u4, [fx_u4["_keys"]["alice_gr"]["sk"]])).hex()},
        "REFUSE",
        "CHAIN_SCRIPT_UNSUPPORTED",
        "Decision 4 / R3 Blocker #4: both_of_2 with unsorted input order a > b MUST refuse CHAIN_SCRIPT_UNSUPPORTED.",
    )
    gp_sx = copy.deepcopy(fx_u4["bundle"]["grants"][0]["payload"])
    kc4 = _kp("d8-b4-c")
    gp_sx["revocation"]["seal"]["script_policy"] = {
        "keys": {**sl.canonical_branch_pair(lo4, hi4), "arbiter": {"m": 1, "pks": sorted([lo4, kc4["comp"]])}},
        "kind": "branch",
        "template": "arbiter_or_both",
    }
    add(
        "d8-r3-b4-shared-xcoord-across-roles-refuse",
        ["SL-LDGR-004"],
        "raw_wire",
        {"expected_type": "seallink-grant/1", "raw_bytes_hex": sl.jcs_encode(sl.sign_envelope(gp_sx, [fx_u4["_keys"]["alice_gr"]["sk"]])).hex()},
        "REFUSE",
        "CHAIN_SCRIPT_UNSUPPORTED",
        "Decision 4 / R3 Blocker #4: Reusing a key x-coordinate across distinct roles in arbiter_or_both MUST refuse CHAIN_SCRIPT_UNSUPPORTED.",
    )

    # R3 High #2, W-13, S-7, S-13: Wire-stage semantic checks!
    gp_wop = copy.deepcopy(fx_u4["bundle"]["grants"][0]["payload"])
    gp_wop["capabilities"][0]["where"] = {"folder": {"suffix": ".pdf"}}  # suffix disallowed on mail/read folder!
    add(
        "d8-r3-h2-disallowed-where-op-for-standard-action-refuse",
        ["SL-WIRE-015", "SL-MAIL-004"],
        "raw_wire",
        {"expected_type": "seallink-grant/1", "raw_bytes_hex": sl.jcs_encode(sl.sign_envelope(gp_wop, [fx_u4["_keys"]["alice_gr"]["sk"]])).hex()},
        "REFUSE",
        "WIRE_CONSTRAINT",
        "R3 High #2: Using a where predicate operator not listed in registry/actions.json allowed_where_predicates MUST refuse WIRE_CONSTRAINT.",
    )
    gp_dq = copy.deepcopy(fx_u4["bundle"]["grants"][0]["payload"])
    q_dup = {"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}
    gp_dq["capabilities"][0]["quotas"] = [q_dup, copy.deepcopy(q_dup)]
    add(
        "d8-w13-duplicate-capability-quota-tuple-refuse",
        ["SL-WIRE-015"],
        "raw_wire",
        {"expected_type": "seallink-grant/1", "raw_bytes_hex": sl.jcs_encode(sl.sign_envelope(gp_dq, [fx_u4["_keys"]["alice_gr"]["sk"]])).hex()},
        "REFUSE",
        "WIRE_CONSTRAINT",
        "W-13: Duplicate (kind, resource, unit, window) entries within Capability.quotas[] MUST refuse WIRE_CONSTRAINT.",
    )
    fx_s7 = rm._contract_fx()
    bad_c_s7 = copy.deepcopy(fx_s7["bundle"]["contract"])
    bad_c_s7["parties"][0]["signing_policy"] = {"m": 2, "pks": [fx_s7["_keys"]["alice_gr"]["xonly"]]}
    add(
        "d8-s7-embedded-threshold-policy-m-gt-n-refuse",
        ["SL-WIRE-013", "SL-WIRE-018"],
        "raw_wire",
        {"expected_type": "seallink-contract/1", "raw_bytes_hex": sl.jcs_encode(bad_c_s7).hex()},
        "REFUSE",
        "WIRE_SIGNATURE",
        "S-7 / W-8: Embedded ThresholdPolicy with m > len(pks) inside a contract party MUST fail at wire stage with WIRE_SIGNATURE.",
    )
    rcpt_s13_bad = sl.sign_envelope(
        {
            **rcpt_ce_1["payload"],
            "settlements": [{"account": "own", "kind": "seallink/count", "released": "1", "reserved": "1", "resource": "mailbox:id/alice:work", "settled": "1", "unit": "reads", "window": "term"}],
        },
        [fx_ce["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d8-s13-receipt-reserved-ne-settled-plus-released-refuse",
        ["SL-WIRE-009", "SL-GRNT-008"],
        "raw_wire",
        {"expected_type": "seallink-receipt/1", "raw_bytes_hex": sl.jcs_encode(rcpt_s13_bad).hex()},
        "REFUSE",
        "WIRE_INTEGER",
        "S-13: seallink-receipt/1 settlement line violating reserved == settled + released MUST refuse WIRE_INTEGER.",
    )

    # R2-01: MachineClauseTerms.config_sha256 != contract.config_sha256 -> CONTRACT_TERMS_MISMATCH
    fx_mc = rm._contract_fx()
    c0_mc = copy.deepcopy(fx_mc["bundle"]["disclosed_clauses"]["0"]["clause"])
    c0_mc["machine_terms"]["config_sha256"] = _h32("d8-r2-01-wrong-cfg")
    s0_mc = _h32("d8-r2-01-s0")
    fx_mc["bundle"]["contract"]["clause_commitments"] = [sl.clause_commit(s0_mc, c0_mc)]
    cid_mc = sl.object_id(fx_mc["bundle"]["contract"])
    fx_mc["bundle"]["disclosed_clauses"] = {"0": {"clause": c0_mc, "salt_hex": s0_mc}}
    fx_mc["bundle"]["contract_assents"] = [
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-mc-a1"), "party_id": "client-1", "party_role": "client", "target_id": cid_mc, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_mc["_keys"]["alice_gr"]["sk"]]),
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-mc-a2"), "party_id": "worker-1", "party_role": "worker", "target_id": cid_mc, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_mc["_keys"]["agent_req"]["sk"]]),
    ]
    gp_mc = copy.deepcopy(fx_mc["bundle"]["grants"][0]["payload"])
    gp_mc["contract_id"] = cid_mc
    _reanchor(fx_mc, gp_mc)
    add(
        "d8-r2-01-machine-clause-config-sha256-mismatch-refuse",
        ["SL-CONT-002", "SL-CONT-003"],
        "invocation",
        fx_mc,
        "REFUSE",
        "CONTRACT_CONFIG_MISMATCH",
        "R2-01: Disclosed MachineClauseTerms.config_sha256 mismatching contract.config_sha256 MUST refuse CONTRACT_CONFIG_MISMATCH.",
    )

    # R2-02: 0x07 contract anchor missing block_time -> fail closed CHAIN_FRAME_INVALID (no silent wall-clock fallback!)
    fx_r202 = rm._contract_fx()
    c_anch_tx = _h32("d8-r2-02-0x07-no-bt")
    fx_r202["bundle"]["contract_anchor_txid"] = c_anch_tx
    fx_r202["chain"]["txs"][c_anch_tx] = {
        "confirmed_height": 749995,
        "opreturn_hex": sl.encode_opreturn(0x07, sl.object_id(fx_r202["bundle"]["contract"])).hex(),
        "outputs": {},
        # intentionally omits block_time!
    }
    add(
        "d8-r2-02-contract-anchor-missing-block-time-refuse",
        ["SL-CONT-004"],
        "invocation",
        fx_r202,
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "R2-02: Confirmed 0x07 contract anchor missing block_time MUST fail closed with CHAIN_FRAME_INVALID (never falling back to wall-clock now).",
    )

    # R2-03 & D-6: subject.mode='origin' missing origin_bundle -> ORIGIN_UNVERIFIED; eternal survives later seallink-end/1 -> ADMIT!
    of_cred = rm._base_origin_fixture()
    cred_iss_own = _kp("d8-cred-iss-own")
    cred_iss_k = _kp("d8-cred-iss-k")
    cred_iss_pol = {"kind": "key", "pk": cred_iss_own["comp"]}
    cred_iss_reg = {"txid": _h32("d8-cred-iss-reg"), "vout": 0}
    cred_orig_p = {
        "claims": {"degree": "BA", "pk": "not-a-hex-key-allowed-in-open-claims"},  # also exercises R2-10!
        "credential_kind": "education/diploma",
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "issuer": {"name": "id/uni", "owner_policy": cred_iss_pol, "registration": cred_iss_reg, "role_policy": {"m": 1, "pks": [cred_iss_k["xonly"]]}},
        "lifecycle": "eternal",
        "network": "main",
        "not_before_height": 749000,
        "subject": {"mode": "origin", "origin_id": of_cred["_origin_id"]},
        "type": "seallink-credential/1",
    }
    cred_orig_env = sl.sign_envelope(cred_orig_p, [cred_iss_k["sk"]])
    cred_atx = _h32("d8-cred-atx")
    ch_cred = copy.deepcopy(of_cred["chain"])
    ch_cred["names"]["id/uni"] = sv.make_name_history("id/uni", cred_iss_reg, cred_iss_pol, {"link": {"cred": cred_iss_k["xonly"]}}, first_height=748000, update_height=748500)
    ch_cred["txs"][cred_atx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cred_orig_env)).hex(), "outputs": {}}
    add(
        "d8-r2-03-credential-origin-mode-missing-bundle-refuse",
        ["SL-CONT-008", "SL-CONT-010"],
        "credential",
        {"anchor_txid": cred_atx, "chain": ch_cred, "credential": cred_orig_env, "trusted_origin_issuers": of_cred["trusted_origin_issuers"]},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "R2-03: seallink-credential/1 with subject.mode='origin' lacking origin_bundle MUST fail closed with ORIGIN_UNVERIFIED.",
    )
    # D-6 + R2-10: Now spend status_seal with terminal seallink-end/1 AFTER credential anchor; eternal credential STILL admits!
    end_d6_p = {
        "basis_sha256": _h32("d8-d6-end-basis"),
        "genesis": GENESIS_MAIN,
        "issued_at": ch_cred["now"] - 10,
        "issuer": of_cred["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "origin_id": of_cred["_origin_id"],
        "reason": "death",
        "status_prev_outpoint": {"txid": of_cred["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": of_cred["origin_bundle"]["origin"]["payload"]["status_seal"]["vout"]},
        "type": "seallink-end/1",
    }
    end_d6 = sl.sign_envelope(end_d6_p, [of_cred["_keys"]["reg_cred"]["sk"]])
    end_d6_tx = _h32("d8-d6-end-tx")
    ch_cred_end = copy.deepcopy(ch_cred)
    ch_cred_end["txs"][of_cred["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = end_d6_tx
    ch_cred_end["txs"][end_d6_tx] = {"confirmed_height": 749900, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(end_d6)).hex(), "outputs": {}}
    ob_cred_end = {**copy.deepcopy(of_cred["origin_bundle"]), "end_record": end_d6}
    add(
        "d8-d6-eternal-origin-credential-survives-subject-end-and-open-claims-admit",
        ["SL-CONT-008", "SL-CONT-010", "SL-WIRE-012"],
        "credential",
        {"anchor_txid": cred_atx, "chain": ch_cred_end, "credential": cred_orig_env, "origin_bundle": ob_cred_end, "trusted_origin_issuers": of_cred["trusted_origin_issuers"]},
        "ADMIT",
        None,
        "D-6 / R2-10: Eternal credential with subject.mode='origin' (and open claims key named 'pk') survives later seallink-end/1 by verifying historical origin existence at h_origin <= h_anchor.",
    )

    # H-19: Cross-role duplicate policy-hash pin -> NAME_VALUE_INVALID; case-fold alias "Link" -> WIRE_DUPLICATE!
    fx_h19 = rm._base_invocation_fixture()
    dup_ph = _h32("d8-h19-shared-ph")
    fx_h19["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_h19["_alice_reg"], fx_h19["_alice_owner_pol"],
        {"link": {"cred": {"p": dup_ph}, "grant": {"p": dup_ph}}}, first_height=748000, update_height=749000,
    )
    add(
        "d8-h19-cross-role-duplicate-policy-hash-refuse",
        ["SL-IDEN-003"],
        "name_resolve",
        {"chain": fx_h19["chain"], "name": "id/alice"},
        "REFUSE",
        "NAME_VALUE_INVALID",
        "H-19: Sharing identical on-chain policy-hash pin {'p': H} across link.grant and link.cred MUST refuse NAME_VALUE_INVALID.",
    )
    fx_alias = rm._base_invocation_fixture()
    fx_alias["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_alias["_alice_reg"], fx_alias["_alice_owner_pol"],
        {"Link": {"grant": fx_alias["_keys"]["alice_gr"]["xonly"]}}, first_height=748000, update_height=749000,
    )
    add(
        "d8-h19-casefold-alias-name-value-wire-duplicate",
        ["SL-IDEN-002"],
        "name_resolve",
        {"chain": fx_alias["chain"], "name": "id/alice"},
        "REFUSE",
        "WIRE_DUPLICATE",
        "H-19: Top-level Unicode case-fold alias ('Link') in 520-byte name value MUST refuse WIRE_DUPLICATE.",
    )

    # Coverage gap closers: txindex=False -> CHAIN_UNHEALTHY, multi-output opreturns[], blocks:N quota window
    fx_txi = rm._base_invocation_fixture()
    fx_txi["chain"]["txindex"] = False
    add(
        "d8-cov-txindex-false-chain-unhealthy",
        ["SL-LDGR-002", "SL-LDGR-008"],
        "invocation",
        fx_txi,
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "Tier 1 observer reporting txindex=False MUST refuse CHAIN_UNHEALTHY.",
    )
    fx_mop = rm._base_invocation_fixture()
    iss_op_hex = fx_mop["chain"]["txs"][fx_mop["invocation"]["payload"]["proof_path"][0]["issuance_txid"]].pop("opreturn_hex")
    fx_mop["chain"]["txs"][fx_mop["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturns"] = [iss_op_hex, iss_op_hex]
    add(
        "d8-cov-duplicate-opreturn-outputs-refuse",
        ["SL-LDGR-010"],
        "invocation",
        fx_mop,
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "Transaction carrying two SLNK OP_RETURN outputs in opreturns[] MUST refuse CHAIN_FRAME_INVALID.",
    )

    # =========================================================================
    # 6. Decision 2A: Hardened Optional-Declaration Modules (CONFORMANCE.md §1.1)
    # =========================================================================
    # 6a. Bearer Sessions (module="bearer-sessions")
    fx_bs = rm._base_invocation_fixture()
    gp_bs = copy.deepcopy(fx_bs["bundle"]["grants"][0]["payload"])
    gp_bs["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "2", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    g_bs, gid_bs = _reanchor(fx_bs, gp_bs)
    itx_bs = fx_bs["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    now_bs = fx_bs["chain"]["now"]
    so_bs_p = {
        "executor": fx_bs["invocation"]["payload"]["executor"],
        "exp": now_bs + 1200,
        "genesis": GENESIS_MAIN,
        "iat": now_bs - 10,
        "network": "main",
        "nonce": _h32("d8-2a-bs-n1"),
        "op": "open",
        "proof_path": [{"grant_id": gid_bs, "issuance_txid": itx_bs}],
        "quotas": [{"kind": "seallink/count", "max": "2", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}],
        "slot_binding": "tls-d8-bs",
        "type": "seallink-session-open/1",
    }
    so_bs_open = sl.sign_envelope(so_bs_p, [fx_bs["_keys"]["agent_req"]["sk"]])
    sid_bs = sl.object_id(so_bs_p)
    tok_bs = "d8-2a-durable-bearer-tok"
    # Forged backing grant (signed by stranger) -> verify_session_open MUST run full §4 admission and refuse WIRE_SIGNATURE!
    stranger_bs = _kp("d8-2a-bs-stranger")
    forged_g_bs = sl.sign_envelope(gp_bs, [stranger_bs["sk"]])
    add(
        "d8-2a-session-open-forged-backing-grant-refuse",
        ["SL-GRNT-013", "SL-GRNT-012"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs["executor_cfg"],
            "journal": {"journal_id": _h32("d8-2a-bs-jf")},
            "steps": [
                {"bundle": {**fx_bs["bundle"], "grants": [forged_g_bs]}, "chain": fx_bs["chain"], "kind": "session_open", "label": "forged-grant", "session_open": so_bs_open, "want_refusal": "WIRE_SIGNATURE", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "Decision 2A: verify_session_open runs full §4 backing-grant chain verification and refuses forged issuer signatures (WIRE_SIGNATURE).",
    )
    # Non-widening extend + durable session-use debits across witness-verified replay_restart + missing grant_env refusal!
    so_bs_widen = sl.sign_envelope(
        {**so_bs_p, "exp": now_bs + 2400, "nonce": _h32("d8-2a-bs-nw"), "op": "extend", "quotas": [{"kind": "seallink/count", "max": "3", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}], "session_id": sid_bs},
        [fx_bs["_keys"]["agent_req"]["sk"]],
    )
    add(
        "d8-2a-session-use-durable-restart-and-non-widening-extend",
        ["SL-GRNT-013", "SL-GRNT-014"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs["executor_cfg"],
            "journal": {"journal_id": _h32("d8-2a-bs-jr")},
            "steps": [
                {"bearer_token": tok_bs, "bundle": fx_bs["bundle"], "chain": fx_bs["chain"], "kind": "session_open", "label": "open", "session_open": so_bs_open, "want_refusal": None, "want_verdict": "ADMIT"},
                {"bundle": fx_bs["bundle"], "chain": fx_bs["chain"], "kind": "session_open", "label": "extend-widen-refuse", "session_open": so_bs_widen, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": fx_bs["chain"], "grant_env": g_bs, "kind": "bearer_session", "label": "use-1-pre-restart", "slot_binding": "tls-d8-bs", "token": tok_bs, "want_refusal": None, "want_verdict": "ADMIT"},
                {"kind": "replay_restart", "label": "restart"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m2"}, "chain": fx_bs["chain"], "grant_env": None, "kind": "bearer_session", "label": "use-no-grant-env", "slot_binding": "tls-d8-bs", "token": tok_bs, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m2"}, "chain": fx_bs["chain"], "grant_env": g_bs, "kind": "bearer_session", "label": "use-2-post-restart", "slot_binding": "tls-d8-bs", "token": tok_bs, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m3"}, "chain": fx_bs["chain"], "grant_env": g_bs, "kind": "bearer_session", "label": "use-3-exceed-post-restart", "slot_binding": "tls-d8-bs", "token": tok_bs, "want_refusal": "QUOTA_EXCEEDED", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "Decision 2A: Bearer session open persists token_sha256, forbids widening extend, requires live grant_env on use, and persists atomic session-use debits across witness-verified restart.",
    )

    # 6b. Service Migration (module="service-migration"): stage vs mandatory-proof activate & legacy inventory ban
    fx_mg = rm._base_invocation_fixture()
    dest_own = _kp("d8-mg-dest-own")
    dest_rcpt = _kp("d8-mg-dest-rcpt")
    dest_gr = _kp("d8-mg-dest-gr")
    dest_own_pol = {"kind": "key", "pk": dest_own["comp"]}
    dest_reg = {"txid": _h32("d8-mg-dest-reg"), "vout": 0}
    dest_pin = {"name": "id/mail-host-b", "owner_policy": dest_own_pol, "registration": dest_reg}
    src_pin = {"name": "id/mail-host-a", "owner_policy": fx_mg["_host_owner_pol"], "registration": fx_mg["_host_reg"]}
    holder_pin = {"name": "id/alice", "owner_policy": fx_mg["_alice_owner_pol"], "registration": fx_mg["_alice_reg"]}
    dest_man = {
        "network": "main",
        "owner": "id/mail-host-b",
        "seq": 1,
        "service": {
            "actions": ["mail/read"],
            "endpoint": "https://host-b.example",
            "receipt_key": dest_rcpt["xonly"],
            "service_type": "mail",
            "tls_spki_sha256": _h32("d8-mg-dest-tls"),
        },
        "type": "seallink-manifest/1",
    }
    alice_man_b = {
        "network": "main",
        "owner": "id/alice",
        "providers": [{"label": "work", "provider": dest_pin, "service_type": "mail"}],
        "seq": 2,
        "type": "seallink-manifest/1",
    }
    dest_man_h = sl.content_addr(dest_man)
    alice_man_b_h = sl.content_addr(alice_man_b)
    fx_mg["chain"]["names"]["id/mail-host-b"] = sv.make_name_history("id/mail-host-b", dest_reg, dest_own_pol, {"link": {"grant": dest_gr["xonly"]}, "m": {"h": dest_man_h, "s": 1}}, first_height=748000, update_height=749000)
    fx_mg["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_mg["_alice_reg"], fx_mg["_alice_owner_pol"], {"link": {"grant": fx_mg["_keys"]["alice_gr"]["xonly"]}, "m": {"h": alice_man_b_h, "s": 2}}, first_height=748000, update_height=749000)
    mg_id = _h32("d8-mg-id")
    inv_obj = {"holder_name": "id/alice", "items": [{"media_type": "message/rfc822", "path": "Invoices/msg1.eml", "sha256": _h32("d8-mg-m1"), "size_bytes": "128"}], "migration_id": mg_id, "service_type": "mail"}
    inv_h = sl.sha256(sl.jcs_encode(inv_obj)).hex()
    mg_export = {
        "inventory": inv_obj,
        "open_predecessor_grants": [],
        "source_journal_commitment": _h32("d8-mg-jc"),
        "source_journal_pos": 5,
        "source_write_token_fenced": True,
    }
    mg_p = {
        "dest_executor": dest_pin,
        "genesis": GENESIS_MAIN,
        "holder": holder_pin,
        "inventory_sha256": inv_h,
        "issued_at": fx_mg["chain"]["now"] - 10,
        "journal_commitment": _h32("d8-mg-jc"),
        "journal_pos": 5,
        "migration_id": mg_id,
        "network": "main",
        "outstanding_exposure": [],
        "service_type": "mail",
        "source_executor": src_pin,
        "type": "seallink-migration/1",
    }
    mg_env = sl.sign_envelope(mg_p, [fx_mg["_keys"]["host_rcpt"]["sk"]])
    mg_obj_id = sl.object_id(mg_p)
    mg_assent = sl.sign_envelope(
        {"expires_at": fx_mg["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "issued_at": fx_mg["chain"]["now"] - 10, "network": "main", "nonce": _h32("d8-mg-an"), "party_id": "holder-1", "party_name": "id/alice", "party_role": "holder", "target_id": mg_obj_id, "target_type": "seallink-migration/1", "type": "seallink-assent/1"},
        [fx_mg["_keys"]["alice_gr"]["sk"]],
    )
    mg_accept = sl.sign_envelope(
        {"genesis": GENESIS_MAIN, "issuer": dest_pin, "network": "main", "not_after": fx_mg["chain"]["now"] + 600, "not_before": fx_mg["chain"]["now"] - 10, "seq": 1, "statement_kind": "migration-accept", "subject": {"holder": holder_pin, "inventory_sha256": inv_h, "migration_id": mg_id, "source_executor": src_pin}, "type": "seallink-statement/1"},
        [dest_rcpt["sk"]],
    )
    mg_mans = {sl.content_addr(fx_mg["_host_man"]): fx_mg["_host_man"], dest_man_h: dest_man, alice_man_b_h: alice_man_b}
    add(
        "d8-2a-migration-stage-zero-writes-admit",
        ["SL-SERV-002", "SL-SERV-003"],
        "migration",
        {"chain": fx_mg["chain"], "expect_zero_writes": True, "export_bundle": mg_export, "journal": {"journal_id": _h32("d8-mg-j1")}, "manifests": mg_mans, "migration": mg_env, "mode": "stage"},
        "ADMIT",
        None,
        "Decision 2A: Migration mode='stage' validates source signature and canonical MigrationInventory with zero journal writes.",
    )
    add(
        "d8-2a-migration-activate-full-proofs-admit",
        ["SL-SERV-002", "SL-SERV-003"],
        "migration",
        {"chain": fx_mg["chain"], "dest_accept_stmt": mg_accept, "export_bundle": mg_export, "holder_assent": mg_assent, "journal": {"journal_id": _h32("d8-mg-j2")}, "local_executor_pin": dest_pin, "manifests": mg_mans, "migration": mg_env, "mode": "activate"},
        "ADMIT",
        None,
        "Decision 2A: Migration mode='activate' admits when all 4 normative proofs (local_executor_pin, holder_assent, confirmed provider manifest, dest migration-accept) verify.",
    )
    add(
        "d8-2a-migration-activate-missing-holder-assent-refuse",
        ["SL-SERV-003"],
        "migration",
        {"chain": fx_mg["chain"], "dest_accept_stmt": mg_accept, "export_bundle": mg_export, "journal": {"journal_id": _h32("d8-mg-j3")}, "local_executor_pin": dest_pin, "manifests": mg_mans, "migration": mg_env, "mode": "activate"},
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "Decision 2A: Migration mode='activate' missing holder_assent MUST fail closed with SERVICE_MIGRATION_INVALID.",
    )
    add(
        "d8-2a-migration-activate-missing-dest-accept-refuse",
        ["SL-SERV-003"],
        "migration",
        {"chain": fx_mg["chain"], "export_bundle": mg_export, "holder_assent": mg_assent, "journal": {"journal_id": _h32("d8-mg-j4")}, "local_executor_pin": dest_pin, "manifests": mg_mans, "migration": mg_env, "mode": "activate"},
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "Decision 2A: Migration mode='activate' missing dest_accept_stmt MUST fail closed with SERVICE_MIGRATION_INVALID.",
    )
    add(
        "d8-2a-migration-activate-wrong-local-executor-refuse",
        ["SL-SERV-003"],
        "migration",
        {"chain": fx_mg["chain"], "dest_accept_stmt": mg_accept, "export_bundle": mg_export, "holder_assent": mg_assent, "journal": {"journal_id": _h32("d8-mg-j5")}, "local_executor_pin": src_pin, "manifests": mg_mans, "migration": mg_env, "mode": "activate"},
        "REFUSE",
        "GRANT_EXECUTOR_MISMATCH",
        "Decision 2A: Migration mode='activate' where dest_executor != local_executor_pin MUST refuse GRANT_EXECUTOR_MISMATCH.",
    )
    legacy_inv = {"files": [{"name": "a.eml", "sha256": _h32("d8-mg-leg")}]}
    mg_leg = sl.sign_envelope({**mg_p, "inventory_sha256": sl.sha256(sl.jcs_encode(legacy_inv)).hex()}, [fx_mg["_keys"]["host_rcpt"]["sk"]])
    add(
        "d8-2a-migration-legacy-files-inventory-refuse",
        ["SL-SERV-002"],
        "migration",
        {"chain": fx_mg["chain"], "export_bundle": {**mg_export, "inventory": legacy_inv}, "journal": {"journal_id": _h32("d8-mg-j6")}, "manifests": mg_mans, "migration": mg_leg, "mode": "stage"},
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "Decision 2A: Legacy non-canonical {'files':[...]} migration inventory MUST refuse SERVICE_MIGRATION_INVALID.",
    )

    # 6c. Federated Screening & PII Disclosure (module="federated-screening"): mandatory holder manifest + strict direct hop!
    fx_fd = rm._base_invocation_fixture()
    p256_fd_sk = sl.deterministic_p256_privkey("d8-fed-p256-l2")
    p256_fd_pk = sl.p256_compressed_pubkey(p256_fd_sk)
    dseal_fd_pol = {"kind": "key", "pk": _kp("d8-fed-dseal")["comp"]}
    dseal_fd_tx = _h32("d8-fed-dseal-tx")
    fx_fd["chain"]["txs"][dseal_fd_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(dseal_fd_pol)}}}
    dev_list_fd = {"devices": [{"alg": "p256", "ceiling": 2, "key": p256_fd_pk, "label": "l2-enclave", "presence": True, "seal": {"script_policy": dseal_fd_pol, "txid": dseal_fd_tx, "vout": 0}}], "network": "main", "owner": "id/alice", "seq": 1, "type": "seallink-device-list/1"}
    al_man_fd = {**copy.deepcopy(fx_fd["_alice_man"]), "sets": {"devices": {"seq": 1, "sha256": sl.content_addr(dev_list_fd)}}}
    al_man_fd_h = sl.content_addr(al_man_fd)
    fx_fd["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_fd["_alice_reg"], fx_fd["_alice_owner_pol"], {"link": {"grant": fx_fd["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al_man_fd_h, "s": 1}}, first_height=748000, update_height=749000)
    l2_fd_cmd = sl.sign_envelope(
        {
            "arguments": {"fields_sha256": _h32("d8-fed-f"), "grant_id": sl.object_id(fx_fd["bundle"]["grants"][0]["payload"]), "recipient_name": "id/agent-1", "route_mode": "direct"},
            "command": "approve-pii-disclosure",
            "exp": fx_fd["chain"]["now"] + 600,
            "genesis": GENESIS_MAIN,
            "iat": fx_fd["chain"]["now"] - 10,
            "level": 2,
            "network": "main",
            "nonce": _h32("d8-fed-n"),
            "owner": "id/alice",
            "target_executor": "id/station-a",
            "type": "seallink-owner-command/1",
        },
        [p256_fd_sk],
        alg="p256",
    )
    add(
        "d8-2a-federation-missing-holder-manifest-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_fd["chain"],
            "grant": fx_fd["bundle"]["grants"][0],
            "peer_ctx": {
                "approval_command": l2_fd_cmd,
                "device_list": dev_list_fd,
                "fields_sha256": _h32("d8-fed-f"),
                "manifests": {},  # MISSING holder manifest!
                "phase": "pii_disclosure",
                "route_hops": [{"actor": "id/agent-1", "role": "counterparty"}],
            },
            "policy": {"require_contour_a": True, "trusted_peers": ["id/agent-1"]},
        },
        "REFUSE",
        "MANIFEST_UNAVAILABLE",
        "Decision 2A: Phase-2 Contour A disclosure lacking verified holder manifest pinning sets.devices MUST fail closed with MANIFEST_UNAVAILABLE.",
    )
    add(
        "d8-2a-federation-multi-hop-relay-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_fd["chain"],
            "grant": fx_fd["bundle"]["grants"][0],
            "peer_ctx": {
                "approval_command": l2_fd_cmd,
                "device_list": dev_list_fd,
                "fields_sha256": _h32("d8-fed-f"),
                "manifests": {al_man_fd_h: al_man_fd},
                "phase": "pii_disclosure",
                "route_hops": [{"actor": "id/hub-1", "role": "hub"}, {"actor": "id/agent-1", "role": "counterparty"}],
            },
            "policy": {"require_contour_a": True, "trusted_peers": ["id/agent-1"]},
        },
        "REFUSE",
        "FEDERATION_POLICY_DENIED",
        "Decision 2A: Contour A disclosure routing through a hub/multi-hop path MUST refuse FEDERATION_POLICY_DENIED.",
    )
    add(
        "d8-2a-federation-direct-hop-with-manifest-admit",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_fd["chain"],
            "grant": fx_fd["bundle"]["grants"][0],
            "peer_ctx": {
                "approval_command": l2_fd_cmd,
                "device_list": dev_list_fd,
                "fields_sha256": _h32("d8-fed-f"),
                "manifests": {al_man_fd_h: al_man_fd},
                "phase": "pii_disclosure",
                "route_hops": [{"actor": "id/agent-1", "role": "counterparty"}],
            },
            "policy": {"require_contour_a": True, "trusted_peers": ["id/agent-1"]},
        },
        "ADMIT",
        None,
        "Decision 2A: Phase-2 Contour A direct single-hop PII disclosure with verified holder manifest pinning sets.devices and L2 P-256 presence command MUST admit.",
    )
    fx_fd_nod = copy.deepcopy(fx_fd)
    al_man_nod_h = sl.content_addr(fx_fd["_alice_man"])
    fx_fd_nod["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_fd["_alice_reg"], fx_fd["_alice_owner_pol"], {"link": {"grant": fx_fd["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al_man_nod_h, "s": 1}}, first_height=748000, update_height=749000)
    add(
        "d8-2a-federation-manifest-missing-devices-set-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_fd_nod["chain"],
            "grant": fx_fd_nod["bundle"]["grants"][0],
            "peer_ctx": {
                "approval_command": l2_fd_cmd,
                "device_list": dev_list_fd,
                "fields_sha256": _h32("d8-fed-f"),
                "manifests": {al_man_nod_h: fx_fd["_alice_man"]},
                "phase": "pii_disclosure",
                "route_hops": [{"actor": "id/agent-1", "role": "counterparty"}],
            },
            "policy": {"require_contour_a": True, "trusted_peers": ["id/agent-1"]},
        },
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "Decision 2A: Phase-2 Contour A disclosure whose holder manifest omits sets.devices MUST fail closed with DEVICE_UNAUTHORIZED.",
    )
    _add_draft8_mutation_kill_cases(add)


def _add_draft8_mutation_kill_cases(add: Callable[..., None]) -> None:
    """Targeted exact-boundary and refusal-branch micro-vectors closing 100.0% across all 3 mutation operators."""
    # =========================================================================
    # A. Journal CAS Fencing / Loss, Exact 65536B Boundary, Wire & Name History
    # =========================================================================
    fx_jf = rm._base_invocation_fixture()
    jid_jf = _h32("d8-mk-jf")
    fx_jf["journal"] = {"journal_id": jid_jf}
    fx_jf["external_witness"] = {"active_write_token": 2, "commitment": sl.journal_commit_init(jid_jf), "journal_id": jid_jf, "pos": 0}
    fx_jf["write_token"] = 1
    add("d8-mk-append-journal-fenced", ["SL-GRNT-014"], "invocation", fx_jf, "REFUSE", "JOURNAL_FENCED",
        "Stale write_token against external CAS witness during admit_and_reserve MUST refuse JOURNAL_FENCED.")

    fx_jl = rm._base_invocation_fixture()
    jid_jl = _h32("d8-mk-jl")
    fx_jl["journal"] = {"journal_id": jid_jl}
    fx_jl["external_witness"] = {"active_write_token": 1, "commitment": sl.journal_commit_init(jid_jl), "journal_id": _h32("wrong-jid-jl"), "pos": 0}
    fx_jl["write_token"] = 1
    add("d8-mk-append-journal-lost", ["SL-GRNT-014"], "invocation", fx_jl, "REFUSE", "JOURNAL_LOST",
        "External CAS witness journal_id mismatch during admit_and_reserve MUST refuse JOURNAL_LOST.")

    # Exact 65536B vs 65537B boundary in FencedJournal.append (kills len(raw_entry) > max_b -> >=!)
    jid_sz = _h32("d8-mk-sz")
    base_sz_body = {
        "expires_at": 1795221000,
        "grant_id": _h32("d8-sz-g"),
        "invocation_id": _h32("d8-sz-inv"),
        "nonce": _h32("d8-sz-n"),
        "recorded_at": 1795220050,
        "reservations": [{"account": "own", "amount": "1", "bucket_id": "term", "grant_id": _h32("d8-sz-g"), "quota_kind": "seallink/count", "resource": "X", "unit": "reads", "window": "term"}],
    }
    probe_sz_entry = {"body": base_sz_body, "journal_id": jid_sz, "kind": "reservation", "pos": 1, "prev_commitment": sl.journal_commit_init(jid_sz), "type": "seallink-journal-entry/1"}
    pad_exact = 65536 - len(sl.jcs_encode(probe_sz_entry)) + 1
    body_65536 = copy.deepcopy(base_sz_body)
    body_65536["reservations"][0]["resource"] = "X" * pad_exact
    body_65537 = copy.deepcopy(base_sz_body)
    body_65537["reservations"][0]["resource"] = "X" * (pad_exact + 1)
    add("d8-mk-journal-append-exact-65536-not-wire-size", ["SL-WIRE-001", "SL-GRNT-014"], "journal_entry_wire",
        {"body": body_65536, "journal_id": jid_sz, "kind": "reservation"}, "REFUSE", "WIRE_MEMBER",
        "Exact 65536-byte JournalEntry passes WIRE_SIZE limit and proceeds to Draft 2020-12 schema validation (WIRE_MEMBER).")
    add("d8-mk-journal-append-65537-wire-size", ["SL-WIRE-001", "SL-GRNT-014"], "journal_entry_wire",
        {"body": body_65537, "journal_id": jid_sz, "kind": "reservation"}, "REFUSE", "WIRE_SIZE",
        "65537-byte JournalEntry exceeds max_bytes=65536 and fails closed with WIRE_SIZE.")

    # _check_wire_semantics: session-open duplicate quota tuple (WIRE_CONSTRAINT) & receipt unknown refusal_code (WIRE_MEMBER)
    fx_w0 = rm._base_invocation_fixture()
    exec_pin_w0 = {"key": fx_w0["executor_cfg"]["key"], "name": fx_w0["executor_cfg"]["name"]}
    q_dup = {"kind": "seallink/count", "max": "1", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}
    so_dup_env = sl.sign_envelope(
        {"executor": exec_pin_w0, "exp": fx_w0["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "iat": fx_w0["chain"]["now"] - 10, "network": "main", "nonce": _h32("d8-mk-sodup"), "op": "open", "proof_path": fx_w0["invocation"]["payload"]["proof_path"], "quotas": [q_dup, copy.deepcopy(q_dup)], "slot_binding": "tls-dup", "type": "seallink-session-open/1"},
        [fx_w0["_keys"]["agent_req"]["sk"]],
    )
    add("d8-mk-session-open-dup-quota-wire-constraint", ["SL-WIRE-010", "SL-GRNT-013"], "raw_wire",
        {"expected_type": "seallink-session-open/1", "raw_bytes_hex": sl.jcs_encode(so_dup_env).hex()}, "REFUSE", "WIRE_CONSTRAINT",
        "seallink-session-open/1 with duplicate (kind, resource, unit, window) quota tuple MUST refuse WIRE_CONSTRAINT.")

    rcpt_bad_rc = sl.sign_envelope(
        {"action": "mail/read", "executor_name": fx_w0["executor_cfg"]["name"], "genesis": GENESIS_MAIN, "grant_id": _h32("g"), "invocation_id": _h32("i"), "network": "main", "outcome": "refused", "recorded_at": fx_w0["chain"]["now"], "refusal_code": "FAKE_UNREGISTERED_CODE", "tip_hash": fx_w0["chain"]["tip_hash"], "tip_height": fx_w0["chain"]["tip_height"], "type": "seallink-receipt/1"},
        [fx_w0["_keys"]["host_rcpt"]["sk"]],
    )
    add("d8-mk-receipt-unregistered-refusal-code-wire-member", ["SL-WIRE-009", "SL-GRNT-008"], "raw_wire",
        {"expected_type": "seallink-receipt/1", "raw_bytes_hex": sl.jcs_encode(rcpt_bad_rc).hex()}, "REFUSE", "WIRE_MEMBER",
        "seallink-receipt/1 with unregistered refusal_code MUST refuse WIRE_MEMBER.")

    # _parse_update_value WIRE_DUPLICATE + resolve_name missing-reg / corrupt-history script & JSON
    ch_nv = copy.deepcopy(fx_w0["chain"])
    al_spk_nv = sl.compile_script_policy(fx_w0["_alice_owner_pol"])[0]
    ch_nv["names"]["id/alice"]["updates"][-1]["output_script_hex"] = sl.encode_name_output("NAME_UPDATE", al_spk_nv, name=b"id/alice", value=b'{"link":{},"link":{}}').hex()
    add("d8-mk-name-value-exact-dup-key-wire-duplicate", ["SL-WIRE-002", "SL-IDEN-001"], "name_resolve",
        {"chain": ch_nv, "name": "id/alice"}, "REFUSE", "WIRE_DUPLICATE",
        "Namecoin value carrying duplicate JSON keys MUST refuse WIRE_DUPLICATE.")

    add("d8-mk-resolve-name-missing-reg-existing-name", ["SL-LDGR-003"], "name_resolve",
        {"chain": fx_w0["chain"], "expected_registration": {"txid": _h32("d8-mk-other-reg"), "vout": 0}, "name": "id/alice"}, "REFUSE", "NAME_OWNER_MISMATCH",
        "Live resolve_name for an existing name whose registration mismatches expected_registration MUST refuse NAME_OWNER_MISMATCH.")

    ch_hs = copy.deepcopy(fx_w0["chain"])
    ch_hs["names"]["id/alice"]["updates"][0]["output_script_hex"] = "00"
    add("d8-mk-resolve-name-corrupt-hist-script", ["SL-LDGR-003"], "name_resolve",
        {"chain": ch_hs, "name": "id/alice", "require_writer": False}, "REFUSE", "NAME_HISTORY_UNAVAILABLE",
        "Historical update with unparseable output_script_hex MUST refuse NAME_HISTORY_UNAVAILABLE.")

    ch_hj = copy.deepcopy(fx_w0["chain"])
    ch_hj["names"]["id/alice"]["updates"][0]["output_script_hex"] = sl.encode_name_output("NAME_FIRSTUPDATE", al_spk_nv, name=b"id/alice", rand=b"\x01" * 20, value=b"{bad").hex()
    add("d8-mk-resolve-name-corrupt-hist-json", ["SL-LDGR-003"], "name_resolve",
        {"chain": ch_hj, "name": "id/alice", "require_writer": False}, "REFUSE", "NAME_VALUE_INVALID",
        "Historical update with non-canonical/malformed JSON value MUST refuse NAME_VALUE_INVALID.")

    # =========================================================================
    # B. Origin, Guardianship, Recovery, Historical & Slot Exact Boundaries
    # =========================================================================
    of0 = rm._base_origin_fixture()
    add("d8-mk-origin-card-non-dict", ["SL-ORIG-002"], "origin_status",
        {"chain": of0["chain"], "origin_bundle": {**copy.deepcopy(of0["origin_bundle"]), "card": "not-a-dict"}, "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Non-dict card in origin_bundle MUST refuse ORIGIN_UNVERIFIED.")

    bad_card = {"contact": "", "display": "Wrong Name", "kind": "person", "name": "id/wrong-name", "network": "main", "relays": [], "replaces": 0, "role": "", "seq": 1, "transports": [], "type": "seallink-card/1"}
    add("d8-mk-origin-card-name-mismatch", ["SL-ORIG-002"], "origin_status",
        {"chain": of0["chain"], "origin_bundle": {**copy.deepcopy(of0["origin_bundle"]), "card": bad_card}, "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Presented seallink-card/1 whose name mismatches active_binding.name MUST refuse ORIGIN_UNVERIFIED.")

    h_orig_0 = of0["chain"]["txs"][of0["origin_bundle"]["origin_anchor_txid"]]["confirmed_height"]
    h_bind_0 = of0["chain"]["txs"][of0["origin_bundle"]["name_binding_txid"]]["confirmed_height"]
    add("d8-mk-origin-after-eval-h", ["SL-ORIG-002"], "origin_status",
        {"at_height": h_orig_0 - 1, "chain": of0["chain"], "origin_bundle": of0["origin_bundle"], "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_UNVERIFIED", "Origin anchored strictly after historical eval_h MUST refuse ORIGIN_UNVERIFIED.")

    add("d8-mk-origin-binding-after-eval-h", ["SL-ORIG-003"], "origin_status",
        {"at_height": h_bind_0 - 1, "chain": of0["chain"], "origin_bundle": of0["origin_bundle"], "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_BINDING_INVALID", "Initial NameBinding anchored strictly after historical eval_h MUST refuse ORIGIN_BINDING_INVALID.")

    j_ocl = sv.FencedJournal(_h32("d8-mk-ocl"))
    j_ocl.record_closure({"subject_id": of0["_origin_id"], "subject_kind": "origin"}, "SUBJECT_ENDED", observed_at=of0["chain"]["now"], observed_height=of0["chain"]["tip_height"])
    add("d8-mk-origin-persisted-closure", ["SL-ORIG-012"], "origin_status",
        {"chain": of0["chain"], "journal": {"closures": j_ocl.closures, "journal_id": j_ocl.journal_id}, "origin_bundle": of0["origin_bundle"], "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "SUBJECT_ENDED", "Persisted durable origin closure in FencedJournal MUST refuse SUBJECT_ENDED.")

    ch_nb = copy.deepcopy(of0["chain"])
    del ch_nb["names"]["id/child-leo"]
    add("d8-mk-origin-binding-name-missing", ["SL-ORIG-003"], "origin_status",
        {"chain": ch_nb, "origin_bundle": of0["origin_bundle"], "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_BINDING_INVALID", "Missing ward name record for initial NameBinding MUST refuse ORIGIN_BINDING_INVALID.")

    add("d8-mk-origin-recovery-bindings-non-list", ["SL-ORIG-013"], "origin_status",
        {"chain": of0["chain"], "origin_bundle": {**copy.deepcopy(of0["origin_bundle"]), "recovery_bindings": "bad"}, "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Malformed non-list recovery_bindings MUST refuse ORIGIN_STATUS_INCOMPLETE.")

    ch_rabs = copy.deepcopy(of0["chain"])
    rec_s0 = of0["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
    ch_rabs["txs"][rec_s0["txid"]]["outputs"][str(rec_s0["vout"])]["absent_from_utxo"] = True
    add("d8-mk-origin-recovery-seal-absent-from-utxo", ["SL-ORIG-013"], "origin_status",
        {"chain": ch_rabs, "origin_bundle": of0["origin_bundle"], "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "recovery_seal absent_from_utxo without spending tx MUST refuse ORIGIN_STATUS_INCOMPLETE.")

    add("d8-mk-origin-roster-records-non-list", ["SL-ORIG-006"], "origin_status",
        {"chain": of0["chain"], "origin_bundle": {**copy.deepcopy(of0["origin_bundle"]), "roster_records": "bad"}, "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Malformed non-list roster_records MUST refuse ORIGIN_STATUS_INCOMPLETE.")

    # Point credible_utc_interval [t, t] (kills interval[0] > interval[1] -> >=) & mtp=0 (kills mtp < 0 -> <=)
    ch_pt = copy.deepcopy(of0["chain"])
    ch_pt["credible_utc_interval"] = [0, 0]
    ch_pt["tip_median_time_past"] = 0
    add("d8-mk-origin-point-interval-and-mtp-zero-admit", ["SL-ORIG-010"], "origin_status",
        {"chain": ch_pt, "origin_bundle": of0["origin_bundle"], "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "ADMIT_WARD", None, "Exact point interval [0, 0] with tip_median_time_past == 0 (< majority_unix) MUST admit ward.")

    # Historical at_time == opened_majority -> GUARDIAN_TRANSFER_PENDING (kills eval_t >= opened_majority -> >!)
    add("d8-mk-origin-at-time-eq-majority-pending", ["SL-ORIG-011"], "origin_status",
        {"at_height": of0["chain"]["tip_height"], "at_time": of0["_maj_unix"], "chain": of0["chain"], "origin_bundle": of0["origin_bundle"], "trusted_origin_issuers": of0["trusted_origin_issuers"]},
        "REFUSE", "GUARDIAN_TRANSFER_PENDING", "Historical at_time == opened_majority enters State 3 GUARDIAN_TRANSFER_PENDING.")

    # Historical at_height == exact creation/spend heights (kills L2692, L2708, L2854, L2872, L3102, L3119, L3338, L3379!)
    of_eq = rm._base_origin_fixture()
    eval_eq = 749100
    # Place status_seal, recovery_seal, roster_seal, slot 1 vacant tx creation height AT exact eval_eq, plus 0x12 at eval_eq!
    op_eq = of_eq["origin_bundle"]["origin"]["payload"]
    of_eq["chain"]["txs"][op_eq["status_seal"]["txid"]]["confirmed_height"] = eval_eq
    of_eq["chain"]["txs"][op_eq["name_recovery"]["recovery_seal"]["txid"]]["confirmed_height"] = eval_eq
    of_eq["chain"]["txs"][op_eq["guardian_policy"]["roster_seal"]["txid"]]["confirmed_height"] = eval_eq
    of_eq["chain"]["txs"][op_eq["guardian_policy"]["slots"][0]["vacant_utxo"]["txid"]]["confirmed_height"] = eval_eq
    of_eq["chain"]["txs"][rm._h32("og1-init-0x12")]["confirmed_height"] = eval_eq
    add("d8-mk-origin-hist-seals-created-at-exact-eval-h-admit", ["SL-ORIG-002", "SL-ORIG-006"], "origin_status",
        {"at_height": eval_eq, "chain": of_eq["chain"], "origin_bundle": of_eq["origin_bundle"], "trusted_origin_issuers": of_eq["trusted_origin_issuers"]},
        "ADMIT_WARD", None, "Seals and 0x12 initial slot activation confirmed at exact historical eval_h MUST admit.")

    # Status spend (seallink-end/1) at exact eval_h -> SUBJECT_ENDED (kills L2708 stx["confirmed_height"] > eval_h -> >=!)
    of_end_eq = copy.deepcopy(of_eq)
    end_eq_p = {"basis_sha256": _h32("d8-mk-eb"), "genesis": GENESIS_MAIN, "issued_at": of_end_eq["chain"]["now"] - 10, "issuer": op_eq["issuer"], "network": "main", "origin_id": of_end_eq["_origin_id"], "reason": "death", "status_prev_outpoint": {"txid": op_eq["status_seal"]["txid"], "vout": op_eq["status_seal"]["vout"]}, "type": "seallink-end/1"}
    end_eq = sl.sign_envelope(end_eq_p, [of_end_eq["_keys"]["reg_cred"]["sk"]])
    end_eq_tx = _h32("d8-mk-end-eq-tx")
    of_end_eq["chain"]["txs"][op_eq["status_seal"]["txid"]]["outputs"][str(op_eq["status_seal"]["vout"])]["spent_by_txid"] = end_eq_tx
    of_end_eq["chain"]["txs"][end_eq_tx] = {"confirmed_height": eval_eq, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(end_eq)).hex(), "outputs": {}}
    of_end_eq["origin_bundle"]["end_record"] = end_eq
    add("d8-mk-origin-hist-end-at-exact-eval-h-refuse", ["SL-ORIG-012"], "origin_status",
        {"at_height": eval_eq, "chain": of_end_eq["chain"], "origin_bundle": of_end_eq["origin_bundle"], "trusted_origin_issuers": of_end_eq["trusted_origin_issuers"]},
        "REFUSE", "SUBJECT_ENDED", "seallink-end/1 confirmed at exact historical eval_h MUST take effect (SUBJECT_ENDED).")

    # Malformed recovery spend at exact eval_h -> recovery_burned=True (kills L2872 rtx["confirmed_height"] > eval_h -> >=!)
    of_rb_eq = copy.deepcopy(of_eq)
    rb_eq_tx = _h32("d8-mk-rb-eq-tx")
    of_rb_eq["chain"]["txs"][op_eq["name_recovery"]["recovery_seal"]["txid"]]["outputs"][str(op_eq["name_recovery"]["recovery_seal"]["vout"])]["spent_by_txid"] = rb_eq_tx
    of_rb_eq["chain"]["txs"][rb_eq_tx] = {"confirmed_height": eval_eq, "outputs": {"0": {"script_pubkey_hex": _spk_hex({"kind": "key", "pk": _kp("d8-mk-rb-sink")["comp"]})}}}
    add("d8-mk-origin-hist-recovery-burn-at-exact-eval-h", ["SL-ORIG-013"], "origin_status",
        {"at_height": eval_eq, "chain": of_rb_eq["chain"], "expect_recovery_burned": True, "origin_bundle": of_rb_eq["origin_bundle"], "trusted_origin_issuers": of_rb_eq["trusted_origin_issuers"]},
        "ADMIT_WARD", None, "Malformed recovery spend confirmed at exact historical eval_h MUST set recovery_burned=True.")

    # Slot 0x12 active at exact eval_h via verify_assent (kills L3119 h_stx > eval_h -> >=) + 0x0f roster spend at exact eval_h (kills L3338 & L3379!)
    of_r_eq = copy.deepcopy(of_eq)
    gp_req = of_r_eq["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    vac_req = gp_req["roster_seal"]["script_policy"]
    rost_req_p = {
        "arbiter_pk": gp_req["arbiter_pk"], "challenger_pk": gp_req["challenger_pk"], "disposer_pk": gp_req["disposer_pk"],
        "effective_delay_blocks": 144, "genesis": GENESIS_MAIN, "issuer": op_eq["issuer"], "network": "main",
        "next_roster_policy": vac_req, "next_roster_vout": 0, "origin_id": of_r_eq["_origin_id"],
        "prev_revision": 1, "prev_roster_outpoint": {"txid": gp_req["roster_seal"]["txid"], "vout": 0},
        "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in gp_req["quorums"]},
        "revision": 2, "revision_size": 1,
        "slots": [{"action": "retain_active", "active_outpoint": {"txid": rm._h32("og1-init-0x12"), "vout": 0}, "guardian_id": sl.object_id(of_r_eq["origin_bundle"]["guardian_records"][0]["payload"]), "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    rost_req = sl.sign_envelope(rost_req_p, [of_r_eq["_keys"]["reg_cred"]["sk"]])
    rtx_req = _h32("d8-mk-rtx-req")
    of_r_eq["chain"]["txs"][gp_req["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_req
    of_r_eq["chain"]["txs"][rtx_req] = {"confirmed_height": eval_eq, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_req)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_req)}}}
    of_r_eq["origin_bundle"]["roster_records"] = [rost_req]
    # Note: at eval_eq with 0x0f confirmed AT eval_eq, rev 2 becomes effective at eval_eq + 144, so rev 1 is still active;
    # to kill L3338 (stx["confirmed_height"] > eval_h -> >=), set a MALFORMED 0x0f at exact eval_eq -> ORIGIN_STATUS_INCOMPLETE!
    of_r_bad_eq = copy.deepcopy(of_r_eq)
    of_r_bad_eq["chain"]["txs"][rtx_req] = {"confirmed_height": eval_eq, "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_req)}}}
    of_r_bad_eq["origin_bundle"]["roster_records"] = []
    add("d8-mk-origin-hist-roster-spend-at-exact-eval-h", ["SL-ORIG-006"], "origin_status",
        {"at_height": eval_eq, "chain": of_r_bad_eq["chain"], "origin_bundle": of_r_bad_eq["origin_bundle"], "trusted_origin_issuers": of_r_bad_eq["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Malformed roster_seal spend confirmed at exact historical eval_h MUST be observed (ORIGIN_STATUS_INCOMPLETE).")

    # Slot 0x12 active at exact eval_eq tested via verify_assent -> kills L3119 (h_stx > eval_h -> >=)!
    of_sl_eq = copy.deepcopy(of_eq)
    op_sl = copy.deepcopy(of_sl_eq["origin_bundle"]["origin"]["payload"])
    op_sl["guardian_policy"]["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 1}
    op_sl["guardian_policy"]["quorums"]["contract_assent"] = {"den": 2, "min": 1, "num": 1}
    op_sl["guardian_policy"]["quorums"]["custody_change"] = {"den": 2, "min": 1, "num": 1}
    o_sl = sl.sign_envelope(op_sl, [of_sl_eq["_keys"]["reg_cred"]["sk"]])
    oid_sl = sl.object_id(op_sl)
    of_sl_eq["origin_bundle"]["origin"] = o_sl
    of_sl_eq["origin_bundle"]["name_binding"]["origin_id"] = oid_sl
    g1_sl_p = {**of_sl_eq["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_sl}
    g1_sl = sl.sign_envelope(g1_sl_p, [of_sl_eq["_keys"]["reg_cred"]["sk"]])
    of_sl_eq["origin_bundle"]["guardian_records"] = [g1_sl]
    of_sl_eq["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**of_sl_eq["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(g1_sl_p)}, [of_sl_eq["_keys"]["g1_gr"]["sk"]])]
    of_sl_eq["chain"]["txs"][of_sl_eq["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_sl)).hex()
    of_sl_eq["chain"]["txs"][of_sl_eq["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_sl_eq["origin_bundle"]["name_binding"])).hex()
    of_sl_eq["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_sl)).hex()
    of_sl_eq["chain"]["names"]["id/child-leo"] = sv.make_name_history("id/child-leo", of_sl_eq["origin_bundle"]["name_binding"]["registration"], of_sl_eq["origin_bundle"]["name_binding"]["owner_policy"], {"link": {"origin": oid_sl}}, first_height=749005, update_height=749015)
    of_sl_eq["contract"]["parties"][0]["ward_origin_id"] = oid_sl
    wa_sl = sl.sign_guardian_envelope(
        {"expires_at": of_sl_eq["chain"]["now"] + 10000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": oid_sl, "revision": 1, "ward_name": "id/child-leo"}, "issued_at": of_sl_eq["chain"]["now"] - 10, "network": "main", "nonce": _h32("d8-mk-wasl"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward", "target_id": sl.object_id(of_sl_eq["contract"]), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_sl_eq["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add("d8-mk-assent-hist-slot-0x12-at-exact-eval-h-admit", ["SL-ORIG-006", "SL-CONT-004"], "assent",
        {"anchor_height": eval_eq, "anchor_time": of_sl_eq["chain"]["now"], "assent": wa_sl, "chain": of_sl_eq["chain"], "contract": of_sl_eq["contract"], "origin_bundle": of_sl_eq["origin_bundle"], "trusted_origin_issuers": of_sl_eq["trusted_origin_issuers"]},
        "ADMIT", None, "0x12 guardian activation confirmed at exact historical anchor_height MUST count as active.")

    # Path B emancipation handover self-update at exact at_height (kills L2413 confirmed_height <= eval_h -> <!)
    of_ho_eq = rm._base_origin_fixture()
    s_own_he = _kp("d8-mk-he-s")
    s_pol_he = {"kind": "key", "pk": s_own_he["comp"]}
    cap_he_p = {"basis_sha256": _h32("d8-mk-he-b"), "genesis": GENESIS_MAIN, "issued_at": of_ho_eq["chain"]["now"] - 500, "issuer": of_ho_eq["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main", "next_status_policy": of_ho_eq["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"], "next_status_vout": 0, "origin_id": of_ho_eq["_origin_id"], "status_prev_outpoint": {"txid": of_ho_eq["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": 0}, "subject_new_owner_policy": s_pol_he, "type": "seallink-capacity/1"}
    cap_he = sl.sign_envelope(cap_he_p, [of_ho_eq["_keys"]["reg_cred"]["sk"]])
    cap_he_tx = _h32("d8-mk-he-cap-tx")
    of_ho_eq["chain"]["txs"][of_ho_eq["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_he_tx
    of_ho_eq["chain"]["txs"][cap_he_tx] = {"confirmed_height": 749100, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_he)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(cap_he_p["next_status_policy"])}}}
    of_ho_eq["origin_bundle"]["capacity_record"] = cap_he
    s_spk_he = sl.compile_script_policy(s_pol_he)[0]
    lu_he = of_ho_eq["chain"]["names"]["id/child-leo"]["updates"]
    p_he = lu_he[-1]
    val_he = sl.jcs_encode({"link": {"origin": of_ho_eq["_origin_id"]}})
    lu_he.append({"confirmed_height": 749150, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", s_spk_he, name=b"id/child-leo", value=val_he).hex(), "owner_policy": s_pol_he, "prev_input": {"sighash_bytes": [0x01], "txid": p_he["txid"], "vout": p_he["vout"], "witness_policy": p_he["owner_policy"]}, "txid": _h32("d8-mk-he-u1"), "vout": 0})
    lu_he.append({"confirmed_height": 749200, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", s_spk_he, name=b"id/child-leo", value=val_he).hex(), "owner_policy": s_pol_he, "prev_input": {"sighash_bytes": [0x01], "txid": _h32("d8-mk-he-u1"), "vout": 0, "witness_policy": s_pol_he}, "txid": _h32("d8-mk-he-u2"), "vout": 0})
    add("d8-mk-emancipation-handover-at-exact-eval-h-admit", ["SL-ORIG-011"], "origin_status",
        {"at_height": 749200, "chain": of_ho_eq["chain"], "origin_bundle": of_ho_eq["origin_bundle"], "trusted_origin_issuers": of_ho_eq["trusted_origin_issuers"]},
        "ADMIT_AUTONOMOUS", None, "Subject self-update confirming handover at exact historical eval_h MUST admit State 4 autonomous.")

    # Exact 0x10 cancel boundaries (kills L2928, L2934 x2, L2953, L2957!)
    def _mk_rec_cancel_fx(h_rec: int, h_cancel: int, *, cancel_bt: int | None = None, cap_h: int | None = None, trunc_old: bool = False) -> dict[str, Any]:
        of_rc = rm._base_origin_fixture()
        rec_s = of_rc["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
        b2 = {
            "genesis": GENESIS_MAIN, "name": "id/child-leo-rec-mk", "network": "main",
            "next_recovery_policy": rec_s["script_policy"], "next_recovery_vout": 0,
            "origin_id": of_rc["_origin_id"], "owner_policy": {"kind": "key", "pk": _kp("d8-mk-rc-b2")["comp"]},
            "registration": {"txid": _h32("d8-mk-rc-b2-reg"), "vout": 0}, "seq": 2,
            "supersedes_binding_id": sl.object_id(of_rc["origin_bundle"]["name_binding"]), "type": "seallink-name-binding/1",
        }
        b2_id = sl.object_id(b2)
        t_rc = _h32(f"d8-mk-trc-{h_rec}-{h_cancel}-{cancel_bt}-{cap_h}-{trunc_old}")
        of_rc["chain"]["txs"][rec_s["txid"]]["outputs"]["0"]["spent_by_txid"] = t_rc
        of_rc["chain"]["txs"][t_rc] = {"confirmed_height": h_rec, "opreturn_hex": sl.encode_opreturn(0x0C, b2_id).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_s["script_policy"])}}}
        of_rc["origin_bundle"]["recovery_bindings"] = [b2]
        if cap_h is not None:
            s_pol_c = {"kind": "key", "pk": _kp("d8-mk-rc-cap-s")["comp"]}
            cap_p = {"basis_sha256": _h32("d8-mk-rc-cb"), "genesis": GENESIS_MAIN, "issued_at": of_rc["chain"]["now"] - 500, "issuer": of_rc["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main", "next_status_policy": of_rc["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"], "next_status_vout": 0, "origin_id": of_rc["_origin_id"], "status_prev_outpoint": {"txid": of_rc["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": 0}, "subject_new_owner_policy": s_pol_c, "type": "seallink-capacity/1"}
            cap_e = sl.sign_envelope(cap_p, [of_rc["_keys"]["reg_cred"]["sk"]])
            cap_tx = _h32(f"d8-mk-rc-captx-{cap_h}")
            of_rc["chain"]["txs"][of_rc["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_tx
            of_rc["chain"]["txs"][cap_tx] = {"confirmed_height": cap_h, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_e)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(cap_p["next_status_policy"])}}}
            of_rc["origin_bundle"]["capacity_record"] = cap_e
            of_rc["chain"]["names"]["id/child-leo-rec-mk"] = sv.make_name_history("id/child-leo-rec-mk", b2["registration"], b2["owner_policy"], {"link": {"origin": of_rc["_origin_id"]}}, first_height=h_rec + 5, update_height=h_rec + 10)
            s_spk_c = sl.compile_script_policy(s_pol_c)[0]
            lu_b2 = of_rc["chain"]["names"]["id/child-leo-rec-mk"]["updates"]
            lu_b2.append({"confirmed_height": h_rec + 200, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", s_spk_c, name=b"id/child-leo-rec-mk", value=sl.jcs_encode({"link": {"origin": of_rc["_origin_id"]}})).hex(), "owner_policy": s_pol_c, "prev_input": {"sighash_bytes": [0x01], "txid": lu_b2[-1]["txid"], "vout": 0, "witness_policy": lu_b2[-1]["owner_policy"]}, "txid": _h32("d8-mk-rc-b2-ho"), "vout": 0})
            lu_b2.append({"confirmed_height": h_rec + 210, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", s_spk_c, name=b"id/child-leo-rec-mk", value=sl.jcs_encode({"link": {"origin": of_rc["_origin_id"]}})).hex(), "owner_policy": s_pol_c, "prev_input": {"sighash_bytes": [0x01], "txid": _h32("d8-mk-rc-b2-ho"), "vout": 0, "witness_policy": s_pol_c}, "txid": _h32("d8-mk-rc-b2-self"), "vout": 0})
        lu_old = of_rc["chain"]["names"]["id/child-leo"]["updates"]
        p_o = lu_old[-1]
        o_spk = sl.compile_script_policy(p_o["owner_policy"])[0]
        u_can: dict[str, Any] = {
            "confirmed_height": h_cancel, "op": "NAME_UPDATE",
            "opreturn_hex": sl.encode_opreturn(0x10, b2_id).hex(),
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", o_spk, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_rc["_origin_id"]}})).hex(),
            "owner_policy": p_o["owner_policy"],
            "prev_input": {"sighash_bytes": [0x01], "txid": p_o["txid"], "vout": p_o["vout"], "witness_policy": p_o["owner_policy"]},
            "txid": _h32(f"d8-mk-rc-u-{h_cancel}"), "vout": 0,
        }
        if cancel_bt is not None:
            u_can["block_time"] = cancel_bt
        lu_old.append(u_can)
        if trunc_old:
            of_rc["chain"]["names"]["id/child-leo"]["history_truncated"] = True
        return of_rc

    of_rc_tr = _mk_rec_cancel_fx(749100, 749110, trunc_old=True)
    add("d8-mk-0x10-truncated-old-name-incomplete", ["SL-ORIG-013"], "origin_status",
        {"chain": of_rc_tr["chain"], "origin_bundle": of_rc_tr["origin_bundle"], "trusted_origin_issuers": of_rc_tr["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Truncated history on active_binding during 0x10 scan MUST refuse ORIGIN_STATUS_INCOMPLETE.")

    of_rc_eq = _mk_rec_cancel_fx(749100, 749100, cancel_bt=of0["_maj_unix"] - 100)
    add("d8-mk-0x10-exact-h-cancel-eq-h-rec-and-eval-h", ["SL-ORIG-013"], "origin_status",
        {"at_height": 749100, "chain": of_rc_eq["chain"], "expect_recovery_outcome": "cancelled_restored", "origin_bundle": of_rc_eq["origin_bundle"], "trusted_origin_issuers": of_rc_eq["trusted_origin_issuers"]},
        "ADMIT_WARD", None, "0x10 cancel confirmed at exact h_cancel == h_rec == eval_h MUST cancel recovery (cancelled_restored).")

    of_rc_cap = _mk_rec_cancel_fx(749100, 749110, cancel_bt=of0["_maj_unix"] - 100, cap_h=749110)
    add("d8-mk-0x10-exact-h-cancel-eq-cap-h-locked-out", ["SL-ORIG-013"], "origin_status",
        {"chain": of_rc_cap["chain"], "expect_recovery_outcome": "promoted", "origin_bundle": of_rc_cap["origin_bundle"], "trusted_origin_issuers": of_rc_cap["trusted_origin_issuers"]},
        "ADMIT_AUTONOMOUS", None, "Former-guardian 0x10 confirmed at exact h_cancel == cap_confirmed_height MUST be locked out so B2 promotes.")

    of_rc_maj = _mk_rec_cancel_fx(749100, 749110, cancel_bt=of0["_maj_unix"])
    add("d8-mk-0x10-exact-cancel-bt-eq-majority-locked-out", ["SL-ORIG-013"], "origin_status",
        {"chain": of_rc_maj["chain"], "expect_recovery_outcome": "promoted", "origin_bundle": of_rc_maj["origin_bundle"], "trusted_origin_issuers": of_rc_maj["trusted_origin_issuers"]},
        "ADMIT_WARD", None, "Former-guardian 0x10 with exact block_time == opened_majority MUST be locked out so B2 promotes.")

    # trace_slot _walk_exhausted (initial slot & post-0x0f roster slot via 2-tx vacant<->pending cycle -> ORIGIN_STATUS_INCOMPLETE, kills L3363 & L3498!)
    def _attach_slot_cycle(of_cy: dict[str, Any], start_tx: str, start_vout: int, rev_num: int, h_base: int, tag: str) -> None:
        gp_cy = of_cy["origin_bundle"]["origin"]["payload"]["guardian_policy"]
        vac_cy = gp_cy["roster_seal"]["script_policy"]
        g_pin_cy = of_cy["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]
        g_seal_cy = _kp(f"d8-mk-cy-gs-{tag}")
        pend_cy_pol = {"delay_blocks": gp_cy["appointment_delay_blocks"], "keys": {"challenger": gp_cy["challenger_pk"], "disposer": gp_cy["disposer_pk"], "guardian": g_seal_cy["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
        act_cy_pol = {"keys": sl.canonical_branch_pair(gp_cy["disposer_pk"], g_seal_cy["comp"]), "kind": "branch", "template": "either_of_2"}
        halt_tx = _h32(f"d8-mk-cy-halt-{tag}")
        pend_tx = _h32(f"d8-mk-cy-pend-{tag}")
        # Create valid appointed guardian record whose prev_outpoint is halt_tx:0 (and start_tx spends to halt_tx via initial active->halt!)
        g_app_p = {
            "activation_mode": "appointed", "active_policy": act_cy_pol, "effective_delay_blocks": gp_cy["appointment_delay_blocks"],
            "genesis": GENESIS_MAIN, "guardian": g_pin_cy, "issuer": of_cy["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main", "origin_id": of_cy["_origin_id"], "pending_policy": pend_cy_pol, "pending_vout": 0,
            "prev_outpoint": {"txid": halt_tx, "vout": 0}, "revision": rev_num, "slot": 1, "term": {"mode": "indefinite"}, "type": "seallink-guardian/1",
        }
        g_app = sl.sign_envelope(g_app_p, [of_cy["_keys"]["reg_cred"]["sk"]])
        g_app_ass = sl.sign_envelope(
            {"expires_at": of_cy["chain"]["now"] + 100000, "genesis": GENESIS_MAIN, "issued_at": of_cy["chain"]["now"] - 100, "network": "main", "nonce": _h32(f"d8-mk-cy-ga-{tag}"), "party_id": f"g-cy-{tag}", "party_name": g_pin_cy["name"], "party_role": "guardian", "target_id": sl.object_id(g_app_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"},
            [of_cy["_keys"]["g1_gr"]["sk"]],
        )
        of_cy["origin_bundle"]["guardian_records"].append(g_app)
        of_cy["origin_bundle"]["guardian_assents"].append(g_app_ass)
        # Enter cycle: start_tx:start_vout -> halt_tx:0 (vacant) -> pend_tx:0 (0x0d pending) -> halt_tx:0 (vacant) ...
        of_cy["chain"]["txs"][start_tx]["outputs"][str(start_vout)]["spent_by_txid"] = halt_tx
        of_cy["chain"]["txs"][halt_tx] = {"confirmed_height": h_base, "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_cy), "spent_by_txid": pend_tx}}}
        of_cy["chain"]["txs"][pend_tx] = {"confirmed_height": h_base + 1, "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g_app)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_cy_pol), "spent_by_txid": halt_tx}}}

    of_cy1 = rm._base_origin_fixture()
    # Initial slot 1 is already active at og1-init-0x12:0; halting it enters halt_tx:0 <-> pend_tx:0!
    _attach_slot_cycle(of_cy1, rm._h32("og1-init-0x12"), 0, 1, 749060, "init")
    add("d8-mk-slot-walk-exhausted-initial", ["SL-ORIG-006"], "origin_status",
        {"chain": of_cy1["chain"], "origin_bundle": of_cy1["origin_bundle"], "trusted_origin_issuers": of_cy1["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Cyclic initial slot UTXO spend MUST exhaust trace_slot and refuse ORIGIN_STATUS_INCOMPLETE.")

    of_cy2 = rm._base_origin_fixture()
    gp_cy2 = of_cy2["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    vac_cy2 = gp_cy2["roster_seal"]["script_policy"]
    rost_cy2_p = {
        "arbiter_pk": gp_cy2["arbiter_pk"], "challenger_pk": gp_cy2["challenger_pk"], "disposer_pk": gp_cy2["disposer_pk"],
        "effective_delay_blocks": 144, "genesis": GENESIS_MAIN, "issuer": of_cy2["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main",
        "next_roster_policy": vac_cy2, "next_roster_vout": 0, "origin_id": of_cy2["_origin_id"],
        "prev_revision": 1, "prev_roster_outpoint": {"txid": gp_cy2["roster_seal"]["txid"], "vout": 0},
        "quorums": gp_cy2["quorums"], "revision": 2, "revision_size": 2,
        "slots": [
            {"action": "new_vacant", "new_vacant_policy": vac_cy2, "new_vacant_vout": 1, "slot": 1},
            {"action": "new_vacant", "new_vacant_policy": vac_cy2, "new_vacant_vout": 2, "slot": 2},
        ],
        "type": "seallink-guardian-roster/1",
    }
    rost_cy2 = sl.sign_envelope(rost_cy2_p, [of_cy2["_keys"]["reg_cred"]["sk"]])
    rtx_cy2 = _h32("d8-mk-rtx-cy2")
    of_cy2["chain"]["txs"][gp_cy2["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_cy2
    of_cy2["origin_bundle"]["roster_records"] = [rost_cy2]
    of_cy2["chain"]["txs"][rtx_cy2] = {"confirmed_height": 749100, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_cy2)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_cy2)}, "1": {"script_pubkey_hex": _spk_hex(vac_cy2)}, "2": {"script_pubkey_hex": _spk_hex(vac_cy2)}}}
    # Put a 2-step pending<->halt cycle starting at rtx_cy2:1 (at height 749300 >= 749244):
    g_pin_cy2 = of_cy2["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]
    g_seal_cy2 = _kp("d8-mk-cy-gs-r2")
    pend_cy2_pol = {"delay_blocks": gp_cy2["appointment_delay_blocks"], "keys": {"challenger": gp_cy2["challenger_pk"], "disposer": gp_cy2["disposer_pk"], "guardian": g_seal_cy2["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
    act_cy2_pol = {"keys": sl.canonical_branch_pair(gp_cy2["disposer_pk"], g_seal_cy2["comp"]), "kind": "branch", "template": "either_of_2"}
    p2_a = _h32("d8-mk-cy2-pa")
    h2_a = _h32("d8-mk-cy2-ha")
    p2_b = _h32("d8-mk-cy2-pb")
    g_app_2a_p = {"activation_mode": "appointed", "active_policy": act_cy2_pol, "effective_delay_blocks": gp_cy2["appointment_delay_blocks"], "genesis": GENESIS_MAIN, "guardian": g_pin_cy2, "issuer": of_cy2["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main", "origin_id": of_cy2["_origin_id"], "pending_policy": pend_cy2_pol, "pending_vout": 0, "prev_outpoint": {"txid": rtx_cy2, "vout": 1}, "revision": 2, "slot": 1, "term": {"mode": "indefinite"}, "type": "seallink-guardian/1"}
    g_app_2b_p = {**g_app_2a_p, "prev_outpoint": {"txid": h2_a, "vout": 0}}
    g_app_2a = sl.sign_envelope(g_app_2a_p, [of_cy2["_keys"]["reg_cred"]["sk"]])
    g_app_2b = sl.sign_envelope(g_app_2b_p, [of_cy2["_keys"]["reg_cred"]["sk"]])
    of_cy2["origin_bundle"]["guardian_records"].extend([g_app_2a, g_app_2b])
    of_cy2["origin_bundle"]["guardian_assents"].extend([
        sl.sign_envelope({"expires_at": of_cy2["chain"]["now"] + 100000, "genesis": GENESIS_MAIN, "issued_at": of_cy2["chain"]["now"] - 100, "network": "main", "nonce": _h32("d8-mk-cy2-gaa"), "party_id": "g-cy2-a", "party_name": g_pin_cy2["name"], "party_role": "guardian", "target_id": sl.object_id(g_app_2a_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"}, [of_cy2["_keys"]["g1_gr"]["sk"]]),
        sl.sign_envelope({"expires_at": of_cy2["chain"]["now"] + 100000, "genesis": GENESIS_MAIN, "issued_at": of_cy2["chain"]["now"] - 100, "network": "main", "nonce": _h32("d8-mk-cy2-gab"), "party_id": "g-cy2-b", "party_name": g_pin_cy2["name"], "party_role": "guardian", "target_id": sl.object_id(g_app_2b_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"}, [of_cy2["_keys"]["g1_gr"]["sk"]]),
    ])
    of_cy2["chain"]["txs"][rtx_cy2]["outputs"]["1"]["spent_by_txid"] = p2_a
    of_cy2["chain"]["txs"][p2_a] = {"confirmed_height": 749300, "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g_app_2a)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_cy2_pol), "spent_by_txid": h2_a}}}
    of_cy2["chain"]["txs"][h2_a] = {"confirmed_height": 749301, "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_cy2), "spent_by_txid": p2_b}}}
    of_cy2["chain"]["txs"][p2_b] = {"confirmed_height": 749302, "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g_app_2b)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_cy2_pol), "spent_by_txid": h2_a}}}
    add("d8-mk-slot-walk-exhausted-post-0x0f", ["SL-ORIG-006"], "origin_status",
        {"chain": of_cy2["chain"], "origin_bundle": of_cy2["origin_bundle"], "trusted_origin_issuers": of_cy2["trusted_origin_issuers"]},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Cyclic post-0x0f new_vacant slot spend MUST exhaust trace_slot and refuse ORIGIN_STATUS_INCOMPLETE.")

    # verify_ward_approvals: persisted guardian_slot closure & guardian missing link.grant (kills L3567, L3593!)
    j_gcl = sv.FencedJournal(_h32("d8-mk-gcl"))
    j_gcl.record_closure({"origin_id": oid_sl, "outpoint": {"txid": rm._h32("og1-init-0x12"), "vout": 0}, "slot": 1, "subject_kind": "guardian_slot"}, "SEAL_SPENT", observed_at=of_sl_eq["chain"]["now"], observed_height=of_sl_eq["chain"]["tip_height"])
    add("d8-mk-ward-approvals-persisted-slot-closure", ["SL-ORIG-006"], "assent",
        {"assent": wa_sl, "chain": of_sl_eq["chain"], "contract": of_sl_eq["contract"], "journal": {"closures": j_gcl.closures, "journal_id": j_gcl.journal_id}, "origin_bundle": of_sl_eq["origin_bundle"], "trusted_origin_issuers": of_sl_eq["trusted_origin_issuers"]},
        "REFUSE", "GUARDIAN_INACTIVE", "Persisted guardian_slot closure in FencedJournal MUST refuse GUARDIAN_INACTIVE.")

    of_nogr = copy.deepcopy(of_sl_eq)
    g1_pin_nogr = of_nogr["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]
    # Keep valid link.grant at 748600 (so 0x12 at 749100 succeeds), then drop link.grant at 749500 (keeping valid link.cred) so live verify_ward_approvals hits L3586!
    of_nogr["chain"]["names"]["id/parent-a"] = sv.make_name_history(
        "id/parent-a", g1_pin_nogr["registration"], g1_pin_nogr["owner_policy"],
        {"link": {"grant": of_nogr["_keys"]["g1_gr"]["xonly"]}}, first_height=748000, update_height=748600,
        extra_updates=[{"confirmed_height": 749500, "txid": _h32("d8-mk-nogr-drop"), "value": {"link": {"cred": _kp("d8-mk-nogr-cred")["xonly"]}}}],
    )
    add("d8-mk-ward-approvals-guardian-missing-grant-role", ["SL-ORIG-006"], "assent",
        {"assent": wa_sl, "chain": of_nogr["chain"], "contract": of_nogr["contract"], "origin_bundle": of_nogr["origin_bundle"], "trusted_origin_issuers": of_nogr["trusted_origin_issuers"]},
        "REFUSE", "GUARDIAN_INACTIVE", "Active guardian whose name later removes link.grant MUST refuse GUARDIAN_INACTIVE.")

    # Slot active spend (halt) confirmed at EXACT eval_h -> slot halted at eval_h -> GUARDIAN_INACTIVE (kills trace_slot L3334 > -> >=!)
    of_shalt = copy.deepcopy(of_sl_eq)
    shalt_h = 749600
    shalt_tx = _h32("d8-mk-shalt-eq")
    of_shalt["chain"]["txs"][rm._h32("og1-init-0x12")]["outputs"]["0"]["spent_by_txid"] = shalt_tx
    of_shalt["chain"]["txs"][shalt_tx] = {"confirmed_height": shalt_h, "outputs": {"0": {"script_pubkey_hex": _spk_hex(of_shalt["origin_bundle"]["origin"]["payload"]["guardian_policy"]["roster_seal"]["script_policy"])}}}
    add("d8-mk-slot-spend-at-exact-eval-h", ["SL-ORIG-006"], "assent",
        {"anchor_height": shalt_h, "anchor_time": of_shalt["chain"]["now"], "assent": wa_sl, "chain": of_shalt["chain"], "contract": of_shalt["contract"], "origin_bundle": of_shalt["origin_bundle"], "trusted_origin_issuers": of_shalt["trusted_origin_issuers"]},
        "REFUSE", "GUARDIAN_INACTIVE", "Active guardian slot halt confirmed at exact historical anchor_height MUST render slot inactive.")

    # verify_assent: autonomous party_name mismatch (L3732) & retroactive 0x0b on anchored autonomous party (L3759)
    fx_aa = rm._contract_fx()
    c_aa = copy.deepcopy(fx_aa["bundle"]["contract"])
    c_aa["parties"][0]["name_pin"] = {"name": "id/alice", "owner_policy": fx_aa["_alice_owner_pol"], "registration": fx_aa["_alice_reg"]}
    cid_aa = sl.object_id(c_aa)
    a_bad_pn = sl.sign_envelope(
        {"expires_at": fx_aa["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "issued_at": fx_aa["chain"]["now"] - 10, "network": "main", "nonce": _h32("d8-mk-abpn"), "party_id": "client-1", "party_name": "id/wrong-client", "party_role": "client", "target_id": cid_aa, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [fx_aa["_keys"]["alice_gr"]["sk"]],
    )
    add("d8-mk-assent-autonomous-party-name-mismatch", ["SL-CONT-004"], "assent",
        {"assent": a_bad_pn, "chain": fx_aa["chain"], "contract": c_aa}, "REFUSE", "CONTRACT_ASSENT_INVALID",
        "Autonomous assent whose party_name mismatches party.name_pin.name MUST refuse CONTRACT_ASSENT_INVALID.")

    ch_aa_0b = copy.deepcopy(fx_aa["chain"])
    al_prev_u = ch_aa_0b["names"]["id/alice"]["updates"][-1]
    brk_aa = {"compromised_policy": {"m": 1, "pks": [fx_aa["_keys"]["alice_gr"]["xonly"]]}, "genesis": GENESIS_MAIN, "h_c": 749500, "issuer": {"name": "id/alice", "owner_policy": fx_aa["_alice_owner_pol"], "registration": fx_aa["_alice_reg"]}, "name_input": {"txid": al_prev_u["txid"], "vout": al_prev_u["vout"]}, "role": "grant", "type": "seallink-credential-break/1"}
    ch_aa_0b["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_aa["_alice_reg"], fx_aa["_alice_owner_pol"],
        {"link": {"grant": fx_aa["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_aa["_alice_man"]), "s": 1}},
        first_height=748000, update_height=749000,
        extra_updates=[{"confirmed_height": 749800, "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_aa).hex(), 0x00, h_c=749500).hex(), "txid": _h32("d8-mk-aa-0b"), "value": {"link": {"grant": _kp("d8-mk-aa-new")["xonly"]}, "m": {"h": sl.content_addr(fx_aa["_alice_man"]), "s": 1}}}],
    )
    a_ok_aa = sl.sign_envelope(
        {"expires_at": fx_aa["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "issued_at": fx_aa["chain"]["now"] - 10, "network": "main", "nonce": _h32("d8-mk-aok"), "party_id": "client-1", "party_name": "id/alice", "party_role": "client", "target_id": cid_aa, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [fx_aa["_keys"]["alice_gr"]["sk"]],
    )
    add("d8-mk-assent-autonomous-retroactive-0x0b-refuse", ["SL-CONT-004", "SL-CONT-009"], "assent",
        {"anchor_height": 749500, "anchor_time": fx_aa["chain"]["now"], "assent": a_ok_aa, "chain": ch_aa_0b, "contract": c_aa}, "REFUSE", "CRED_ISSUER_CLOSED",
        "Anchored autonomous party assent with retroactive 0x0b break h_c <= anchor_height MUST refuse CRED_ISSUER_CLOSED.")

    # Persisted closures on verify_credential (L3848) & verify_notary_act (L3953)
    c_iss_k = _kp("d8-mk-cr-iss")
    c_iss_pol = {"kind": "key", "pk": c_iss_k["comp"]}
    c_iss_reg = {"txid": _h32("d8-mk-cr-reg"), "vout": 0}
    cr_p = {"claims": {"k": "v"}, "credential_kind": "test/cert", "genesis": GENESIS_MAIN, "issued_at": 1795220000, "issuer": {"name": "id/uni-mk", "owner_policy": c_iss_pol, "registration": c_iss_reg, "role_policy": {"m": 1, "pks": [c_iss_k["xonly"]]}}, "lifecycle": "eternal", "network": "main", "not_before_height": 749000, "subject": {"key": _kp("d8-mk-cr-s")["xonly"], "mode": "key"}, "type": "seallink-credential/1"}
    cr_env = sl.sign_envelope(cr_p, [c_iss_k["sk"]])
    cr_id = sl.object_id(cr_p)
    j_crcl = sv.FencedJournal(_h32("d8-mk-crcl"))
    j_crcl.record_closure({"subject_id": cr_id, "subject_kind": "credential"}, "CRED_REVOKED_FOR_CAUSE", observed_at=fx_w0["chain"]["now"], observed_height=fx_w0["chain"]["tip_height"])
    add("d8-mk-credential-persisted-closure", ["SL-CONT-008"], "credential",
        {"anchor_txid": _h32("d8-mk-cr-atx"), "chain": fx_w0["chain"], "credential": cr_env, "journal": {"closures": j_crcl.closures, "journal_id": j_crcl.journal_id}},
        "REFUSE", "CRED_REVOKED_FOR_CAUSE", "Persisted credential closure in FencedJournal MUST refuse CRED_REVOKED_FOR_CAUSE.")

    not_p = {
        "act_kind": "fact-attestation",
        "attested_at": fx_w0["chain"]["now"],
        "details": {"fact_schema": "test/v1", "fact_sha256": _h32("d8-mk-not-f"), "kind": "fact-attestation"},
        "genesis": GENESIS_MAIN,
        "lifecycle": "eternal",
        "network": "main",
        "notary": {"name": "id/notary-mk", "owner_policy": c_iss_pol, "registration": c_iss_reg, "role_policy": {"m": 1, "pks": [c_iss_k["xonly"]]}},
        "target_sha256": _h32("d8-mk-not-s"),
        "tip_hash": fx_w0["chain"]["tip_hash"],
        "tip_height": fx_w0["chain"]["tip_height"],
        "type": "seallink-notary/1",
    }
    not_env = sl.sign_envelope(not_p, [c_iss_k["sk"]])
    not_id = sl.object_id(not_p)
    j_ncl = sv.FencedJournal(_h32("d8-mk-ncl"))
    j_ncl.record_closure({"subject_id": not_id, "subject_kind": "credential"}, "CRED_REVOKED_FOR_CAUSE", observed_at=fx_w0["chain"]["now"], observed_height=fx_w0["chain"]["tip_height"])
    add("d8-mk-notary-persisted-closure", ["SL-CONT-011"], "notary_act",
        {"anchor_txid": _h32("d8-mk-not-atx"), "chain": fx_w0["chain"], "journal": {"closures": j_ncl.closures, "journal_id": j_ncl.journal_id}, "notary": not_env},
        "REFUSE", "CRED_REVOKED_FOR_CAUSE", "Persisted notary act closure in FencedJournal MUST refuse CRED_REVOKED_FOR_CAUSE.")

    # =========================================================================
    # C. Target Authority, Backing Grant Chain, commit_result, & 2A Modules
    # =========================================================================
    fx_bt = rm._base_invocation_fixture()
    gp_bt = copy.deepcopy(fx_bt["bundle"]["grants"][0]["payload"])
    gp_bt["capabilities"][0]["target"] = "mailbox:badformat"
    _reanchor(fx_bt, gp_bt)
    inv_bt_p = {**fx_bt["invocation"]["payload"], "target": "mailbox:badformat"}
    fx_bt["invocation"] = sl.sign_envelope(inv_bt_p, [fx_bt["_keys"]["agent_req"]["sk"]])
    add("d8-mk-target-regex-mismatch-unauthorized", ["SL-GRNT-003"], "invocation", fx_bt, "REFUSE", "GRANT_TARGET_UNAUTHORIZED",
        "Target string failing action target_pattern regex MUST refuse GRANT_TARGET_UNAUTHORIZED.")

    # Persisted framework_contract closure (L4884)
    fx_fwcl = rm._contract_fx()
    fw_id_cl = _h32("d8-mk-fwcl-id")
    fx_fwcl["bundle"]["contract"]["framework_id"] = fw_id_cl
    cid_fwcl = sl.object_id(fx_fwcl["bundle"]["contract"])
    fx_fwcl["bundle"]["contract_assents"] = [
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-fwcl-a1"), "party_id": "client-1", "party_role": "client", "target_id": cid_fwcl, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_fwcl["_keys"]["alice_gr"]["sk"]]),
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d8-fwcl-a2"), "party_id": "worker-1", "party_role": "worker", "target_id": cid_fwcl, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [fx_fwcl["_keys"]["agent_req"]["sk"]]),
    ]
    gp_fwcl = {**copy.deepcopy(fx_fwcl["bundle"]["grants"][0]["payload"]), "contract_id": cid_fwcl}
    _reanchor(fx_fwcl, gp_fwcl)
    j_fw = sv.FencedJournal(_h32("d8-mk-jfw"))
    j_fw.record_closure({"subject_id": fw_id_cl, "subject_kind": "contract"}, "SEAL_SPENT", observed_at=fx_fwcl["chain"]["now"], observed_height=fx_fwcl["chain"]["tip_height"])
    fx_fwcl["journal"] = {"closures": j_fw.closures, "journal_id": j_fw.journal_id}
    add("d8-mk-framework-persisted-closure", ["SL-CONT-005"], "invocation", fx_fwcl, "REFUSE", "SEAL_SPENT",
        "Persisted closure on framework_contract MUST refuse SEAL_SPENT.")

    # H-6 funding input exact boundaries: linkage ph_i == a_height (ADMIT), linkage ph_i == a_height + 1 (REFUSE), non-linkage ph_i == a_height (REFUSE)
    def _mk_h6_fx(*, link_delta: int = 0, extra_fund_delta: int | None = None) -> dict[str, Any]:
        fx_h6 = rm._base_invocation_fixture()
        itx_h6 = fx_h6["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
        a_h = fx_h6["chain"]["txs"][itx_h6]["confirmed_height"]
        seal_txid_h6 = fx_h6["bundle"]["grants"][0]["payload"]["revocation"]["seal"]["txid"]
        fx_h6["chain"]["txs"][seal_txid_h6]["confirmed_height"] = a_h + link_delta
        if extra_fund_delta is not None:
            ftx_id = _h32(f"d8-mk-h6-fund-{extra_fund_delta}")
            fx_h6["chain"]["txs"][ftx_id] = {"confirmed_height": a_h + extra_fund_delta, "outputs": {"0": {"script_pubkey_hex": "0014" + ("aa" * 20)}}}
            fx_h6["chain"]["txs"][itx_h6]["inputs"].append(sv.make_segwit_input(ftx_id, 0))
        return fx_h6

    add("d8-mk-h6-linkage-same-block-admit", ["SL-LDGR-009"], "invocation", _mk_h6_fx(link_delta=0), "ADMIT", None,
        "H-6: Companion linkage input (seal_txid, seal_vout + 1) confirming in the SAME block as 0x01 issuance (ph_i == a_height) MUST admit.")
    add("d8-mk-h6-linkage-future-block-refuse", ["SL-LDGR-009"], "invocation", _mk_h6_fx(link_delta=1), "REFUSE", "CHAIN_TX_CONSTRUCTION",
        "H-6: Companion linkage input confirming strictly AFTER 0x01 issuance (ph_i > a_height) MUST refuse CHAIN_TX_CONSTRUCTION.")
    add("d8-mk-h6-non-linkage-same-block-refuse", ["SL-LDGR-009"], "invocation", _mk_h6_fx(link_delta=-1, extra_fund_delta=0), "REFUSE", "CHAIN_TX_CONSTRUCTION",
        "H-6: Non-linkage funding input confirming in the SAME block as 0x01 issuance (ph_i == a_height) MUST refuse CHAIN_TX_CONSTRUCTION.")

    # commit_result refusal & boundary kill suite (L5365, L5367, L5371, L5407, L5413, L5425, L5433, L5441)
    fx_cm = rm._base_invocation_fixture()
    gp_cm = copy.deepcopy(fx_cm["bundle"]["grants"][0]["payload"])
    gp_cm["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    _, gid_cm = _reanchor(fx_cm, gp_cm)
    inv_id_cm = sl.object_id(fx_cm["invocation"]["payload"])
    rcpt_cm_base = {
        "action": "mail/read", "executor_name": fx_cm["executor_cfg"]["name"], "genesis": GENESIS_MAIN, "grant_id": gid_cm,
        "invocation_id": inv_id_cm, "network": "main", "outcome": "executed", "recorded_at": fx_cm["chain"]["now"],
        "result_sha256": _h32("d8-mk-cm-res"),
        "settlements": [{"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/alice:work", "settled": "1", "unit": "reads", "window": "term"}],
        "tip_hash": fx_cm["chain"]["tip_hash"], "tip_height": fx_cm["chain"]["tip_height"], "type": "seallink-receipt/1",
    }
    def _cm_inp(rp_patch: dict[str, Any], *, jtag: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        rp = {**copy.deepcopy(rcpt_cm_base), **rp_patch}
        r_env = sl.sign_envelope(rp, [fx_cm["_keys"]["host_rcpt"]["sk"]])
        return {"bundle": fx_cm["bundle"], "chain": fx_cm["chain"], "executor_cfg": fx_cm["executor_cfg"], "invocation": fx_cm["invocation"], "journal_id": _h32(f"d8-mk-cm-{jtag}"), "receipt_env": r_env, **(extra or {})}

    add("d8-mk-commit-wrong-network", ["SL-GRNT-008"], "commit_edge", _cm_inp({"network": "regtest"}, jtag="net"), "REFUSE", "CHAIN_MISMATCH", "commit_result with wrong receipt network MUST refuse CHAIN_MISMATCH.")
    add("d8-mk-commit-wrong-executor", ["SL-GRNT-008"], "commit_edge", _cm_inp({"executor_name": "id/wrong-host"}, jtag="ex"), "REFUSE", "GRANT_EXECUTOR_MISMATCH", "commit_result with wrong receipt executor_name MUST refuse GRANT_EXECUTOR_MISMATCH.")
    add("d8-mk-commit-wrong-action", ["SL-GRNT-008"], "commit_edge", _cm_inp({}, jtag="act", extra={"expected_action": "mail/send"}), "REFUSE", "WIRE_MEMBER", "commit_result with expected_action mismatch MUST refuse WIRE_MEMBER.")
    add("d8-mk-commit-wrong-grant-id", ["SL-GRNT-008"], "commit_edge", _cm_inp({"grant_id": _h32("wrong-g")}, jtag="gid", extra={"override_grant_id": _h32("wrong-g")}), "REFUSE", "WIRE_MEMBER", "commit_result whose grant_id disagrees with durable reservation MUST refuse WIRE_MEMBER.")
    add("d8-mk-commit-wrong-settlement-len", ["SL-GRNT-008"], "commit_edge", _cm_inp({"settlements": []}, jtag="slen"), "REFUSE", "WIRE_MEMBER", "commit_result with wrong settlements[] length MUST refuse WIRE_MEMBER.")
    add("d8-mk-commit-unknown-settlement-key", ["SL-GRNT-008"], "commit_edge", _cm_inp({"settlements": [{"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/alice:other", "settled": "1", "unit": "reads", "window": "term"}]}, jtag="skey"), "REFUSE", "WIRE_MEMBER", "commit_result with settlement key absent from reservation MUST refuse WIRE_MEMBER.")
    add("d8-mk-commit-reserved-mismatch-settled-eq-res", ["SL-GRNT-008"], "commit_edge", _cm_inp({"settlements": [{"account": "own", "kind": "seallink/count", "released": "1", "reserved": "2", "resource": "mailbox:id/alice:work", "settled": "1", "unit": "reads", "window": "term"}]}, jtag="rmis"), "REFUSE", "WIRE_MEMBER", "commit_result with reserved=2 != res_amt=1 while settled=1 == res_amt MUST refuse WIRE_MEMBER (kills set_amt > res_amt -> >=).")
    add("d8-mk-commit-actual-usage-mismatch", ["SL-GRNT-008"], "commit_edge", _cm_inp({}, jtag="actu", extra={"actual_quota_usage": {"seallink/count|mailbox:id/alice:work|reads|term": 0}}), "REFUSE", "WIRE_MEMBER", "commit_result whose receipt settled disagrees with actual_quota_usage MUST refuse WIRE_MEMBER.")

    # Decision 2A: Bearer Sessions open/use refusal & exact-boundary suite (kills L5187, L5608..5652, L5799, L5843, L5876, L5891, L5939!)
    fx_bs2 = rm._base_invocation_fixture()
    gp_bs2 = copy.deepcopy(fx_bs2["bundle"]["grants"][0]["payload"])
    gp_bs2["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "2", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "seconds:3600"}]
    g_bs2, gid_bs2 = _reanchor(fx_bs2, gp_bs2)
    now_bs2 = fx_bs2["chain"]["now"]
    so_bs2_p = {"executor": {"key": fx_bs2["executor_cfg"]["key"], "name": fx_bs2["executor_cfg"]["name"]}, "exp": now_bs2 + 600, "genesis": GENESIS_MAIN, "iat": now_bs2 - 10, "network": "main", "nonce": _h32("d8-mk-bs2-n"), "op": "open", "proof_path": [{"grant_id": gid_bs2, "issuance_txid": fx_bs2["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}], "quotas": [{"kind": "seallink/count", "max": "2", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "seconds:3600"}], "slot_binding": "tls-mk-bs2", "type": "seallink-session-open/1"}
    so_bs2_open = sl.sign_envelope(so_bs2_p, [fx_bs2["_keys"]["agent_req"]["sk"]])
    tok_bs2 = _h32("d8-mk-bs2-tok")

    # 1. Single-use backing grant on session_open -> SESSION_INVALID (L5187)
    fx_bssu = rm._base_invocation_fixture()
    gp_bssu = copy.deepcopy(fx_bssu["bundle"]["grants"][0]["payload"])
    su_gr_k = _kp("d8-mk-bssu-gr")
    su_pol_bs = {"kind": "branch", "template": "single_use_1_of_2", "keys": {"grantee": su_gr_k["comp"], "issuer": fx_bssu["_keys"]["alice_seal"]["comp"]}}
    gp_bssu["revocation"] = {"construction": "W", "kind": "single_use", "mode": "seal", "seal": {"script_policy": su_pol_bs, "txid": gp_bssu["revocation"]["seal"]["txid"], "vout": 0}}
    fx_bssu["chain"]["txs"][gp_bssu["revocation"]["seal"]["txid"]]["outputs"]["0"]["script_pubkey_hex"] = _spk_hex(su_pol_bs)
    _, gid_bssu = _reanchor(fx_bssu, gp_bssu)
    so_bssu = sl.sign_envelope({**so_bs2_p, "nonce": _h32("d8-mk-bssu-n"), "proof_path": [{"grant_id": gid_bssu, "issuance_txid": fx_bssu["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}]}, [fx_bssu["_keys"]["agent_req"]["sk"]])
    add("d8-mk-2a-session-open-single-use-grant-refuse", ["SL-GRNT-013"], "session_lifecycle",
        {"executor_cfg": fx_bssu["executor_cfg"], "journal": {"journal_id": _h32("d8-mk-bssu-j")}, "steps": [{"bundle": fx_bssu["bundle"], "chain": fx_bssu["chain"], "kind": "session_open", "label": "su-refuse", "session_open": so_bssu, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"}]},
        "ADMIT", None, "verify_session_open MUST refuse single_use backing grant with SESSION_INVALID.")

    # 2. session_open wrong-network grant (L5608), missing grant (L5614), child-as-root missing issuer (L5618), disallowed action (L5646), non-bearer mail/send (L5648), requires_contract (L5650), mechanical terms_text (L5652)
    g_wnet = sl.sign_envelope({**gp_bs2, "network": "regtest"}, [fx_bs2["_keys"]["alice_gr"]["sk"]])
    add("d8-mk-2a-session-open-wrong-net-grant", ["SL-GRNT-013"], "session_lifecycle",
        {"executor_cfg": fx_bs2["executor_cfg"], "journal": {"journal_id": _h32("d8-mk-swn-j")}, "steps": [{"bundle": {**fx_bs2["bundle"], "grants": [g_wnet]}, "chain": fx_bs2["chain"], "kind": "session_open", "label": "wnet", "session_open": so_bs2_open, "want_refusal": "CHAIN_MISMATCH", "want_verdict": "REFUSE"}]},
        "ADMIT", None, "verify_session_open with wrong-network grant MUST refuse CHAIN_MISMATCH.")

    add("d8-mk-2a-session-open-missing-grant", ["SL-GRNT-013"], "session_lifecycle",
        {"executor_cfg": fx_bs2["executor_cfg"], "journal": {"journal_id": _h32("d8-mk-smg-j")}, "steps": [{"bundle": {**fx_bs2["bundle"], "grants": []}, "chain": fx_bs2["chain"], "kind": "session_open", "label": "missing", "session_open": so_bs2_open, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"}]},
        "ADMIT", None, "verify_session_open with missing proof_path grant MUST refuse SESSION_INVALID.")

    fx_del_bs = rm._delegation_fx()
    c_only_g = fx_del_bs["bundle"]["grants"][1]
    c_only_id = sl.object_id(c_only_g["payload"])
    so_croot = sl.sign_envelope({**so_bs2_p, "executor": {"key": fx_del_bs["executor_cfg"]["key"], "name": fx_del_bs["executor_cfg"]["name"]}, "nonce": _h32("d8-mk-croot"), "proof_path": [{"grant_id": c_only_id, "issuance_txid": fx_del_bs["invocation"]["payload"]["proof_path"][1]["issuance_txid"]}], "quotas": []}, [fx_del_bs["_keys"]["agent_req"]["sk"]])
    add("d8-mk-2a-session-open-child-at-root", ["SL-GRNT-013"], "session_lifecycle",
        {"executor_cfg": fx_del_bs["executor_cfg"], "journal": {"journal_id": _h32("d8-mk-scr-j")}, "steps": [{"bundle": {"grants": [c_only_g], "manifests": fx_del_bs["bundle"]["manifests"]}, "chain": fx_del_bs["chain"], "kind": "session_open", "label": "croot", "session_open": so_croot, "want_refusal": "GRANT_NOT_DELEGABLE", "want_verdict": "REFUSE"}]},
        "ADMIT", None, "verify_session_open placing a child grant (lacking issuer) at proof_path[0] MUST refuse GRANT_NOT_DELEGABLE.")

    add("d8-mk-2a-session-open-disallowed-action", ["SL-GRNT-013"], "session_lifecycle",
        {"executor_cfg": {**fx_bs2["executor_cfg"], "actions": ["mail/list"]}, "journal": {"journal_id": _h32("d8-mk-sda-j")}, "steps": [{"bundle": fx_bs2["bundle"], "chain": fx_bs2["chain"], "kind": "session_open", "label": "disact", "session_open": so_bs2_open, "want_refusal": "INVOKE_ACTION_DENIED", "want_verdict": "REFUSE"}]},
        "ADMIT", None, "verify_session_open for an action disallowed by executor_cfg.actions MUST refuse INVOKE_ACTION_DENIED.")

    fx_ms = rm._base_invocation_fixture()
    gp_ms = copy.deepcopy(fx_ms["bundle"]["grants"][0]["payload"])
    gp_ms["capabilities"] = [{"action": "com.example/non-bearer", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "messages", "window": "term"}], "target": "mailbox:id/alice:work", "where": {}}]
    _, gid_ms = _reanchor(fx_ms, gp_ms)
    so_ms = sl.sign_envelope({**so_bs2_p, "nonce": _h32("d8-mk-sms"), "proof_path": [{"grant_id": gid_ms, "issuance_txid": fx_ms["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}], "quotas": []}, [fx_ms["_keys"]["agent_req"]["sk"]])
    ecfg_ms = {**fx_ms["executor_cfg"], "action_profiles": {"com.example/non-bearer": {"allows_bearer_session": False, "mechanical": True, "requires_contract": False, "target_authority": "mailbox_owner"}}, "actions": [*fx_ms["executor_cfg"].get("actions", []), "com.example/non-bearer"]}
    add("d8-mk-2a-session-open-non-bearer-action", ["SL-GRNT-013"], "session_lifecycle",
        {"executor_cfg": ecfg_ms, "journal": {"journal_id": _h32("d8-mk-sms-j")}, "steps": [{"bundle": fx_ms["bundle"], "chain": fx_ms["chain"], "kind": "session_open", "label": "nonbearer", "session_open": so_ms, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"}]},
        "ADMIT", None, "verify_session_open for an action with allows_bearer_session=false MUST refuse SESSION_INVALID.")

    # Mechanical terms_text & requires_contract on session_open (use custom local action_profiles so allows_bearer_session=True + requires_contract=True!)
    fx_stxt = rm._base_invocation_fixture()
    gp_stxt = copy.deepcopy(fx_stxt["bundle"]["grants"][0]["payload"])
    gp_stxt["terms_text"] = "freeform text forbidden on mechanical mail/read"
    _, gid_stxt = _reanchor(fx_stxt, gp_stxt)
    so_stxt = sl.sign_envelope({**so_bs2_p, "nonce": _h32("d8-mk-stxt"), "proof_path": [{"grant_id": gid_stxt, "issuance_txid": fx_stxt["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}], "quotas": []}, [fx_stxt["_keys"]["agent_req"]["sk"]])
    add("d8-mk-2a-session-open-mechanical-terms-text", ["SL-GRNT-013"], "session_lifecycle",
        {"executor_cfg": fx_stxt["executor_cfg"], "journal": {"journal_id": _h32("d8-mk-stxt-j")}, "steps": [{"bundle": fx_stxt["bundle"], "chain": fx_stxt["chain"], "kind": "session_open", "label": "termstext", "session_open": so_stxt, "want_refusal": "GRANT_TEXT_FORBIDDEN", "want_verdict": "REFUSE"}]},
        "ADMIT", None, "verify_session_open with mechanical grant carrying terms_text MUST refuse GRANT_TEXT_FORBIDDEN.")

    fx_scont = rm._base_invocation_fixture()
    gp_scont = copy.deepcopy(fx_scont["bundle"]["grants"][0]["payload"])
    gp_scont["capabilities"] = [{"action": "com.example/session-read", "target": "mailbox:id/alice:work", "where": {}}]
    _, gid_scont = _reanchor(fx_scont, gp_scont)
    so_scont = sl.sign_envelope({**so_bs2_p, "nonce": _h32("d8-mk-scont"), "proof_path": [{"grant_id": gid_scont, "issuance_txid": fx_scont["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}], "quotas": []}, [fx_scont["_keys"]["agent_req"]["sk"]])
    ecfg_scont = {**fx_scont["executor_cfg"], "action_profiles": {"com.example/session-read": {"allows_bearer_session": True, "mechanical": True, "requires_contract": True, "target_authority": "mailbox_owner"}}, "actions": [*fx_scont["executor_cfg"].get("actions", []), "com.example/session-read"]}
    add("d8-mk-2a-session-open-requires-contract", ["SL-GRNT-013"], "session_lifecycle",
        {"executor_cfg": ecfg_scont, "journal": {"journal_id": _h32("d8-mk-scont-j")}, "steps": [{"bundle": fx_scont["bundle"], "chain": fx_scont["chain"], "kind": "session_open", "label": "reqcont", "session_open": so_scont, "want_refusal": "GRANT_CONTRACT_REQUIRED", "want_verdict": "REFUSE"}]},
        "ADMIT", None, "verify_session_open for an action with requires_contract=True lacking contract_id MUST refuse GRANT_CONTRACT_REQUIRED.")

    # 3. Bearer session use: where-mismatch (INVOKE_CONSTRAINT_FAILED), exact now == watermark (ADMIT) & now == watermark - 1 (QUOTA_CLOCK_REGRESSION), exact now == exp (SESSION_INVALID), & depth-2 parent boundaries!
    ch_bs2_wm = copy.deepcopy(fx_bs2["chain"])
    ch_bs2_back = copy.deepcopy(fx_bs2["chain"])
    ch_bs2_back["now"] = now_bs2 - 1
    ch_bs2_exp = copy.deepcopy(fx_bs2["chain"])
    ch_bs2_exp["now"] = now_bs2 + 600  # exact == sess.exp!
    add("d8-mk-2a-bearer-session-boundaries-and-clock", ["SL-GRNT-013"], "session_lifecycle",
        {
            "executor_cfg": fx_bs2["executor_cfg"],
            "journal": {"journal_id": _h32("d8-mk-bs2-j")},
            "steps": [
                {"bearer_token": tok_bs2, "bundle": fx_bs2["bundle"], "chain": fx_bs2["chain"], "kind": "session_open", "label": "open", "session_open": so_bs2_open, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "arguments": {"folder": "Forbidden", "message_id": "m0"}, "chain": fx_bs2["chain"], "grant_env": g_bs2, "kind": "bearer_session", "label": "where-fail", "slot_binding": "tls-mk-bs2", "token": tok_bs2, "want_refusal": "INVOKE_CONSTRAINT_FAILED", "want_verdict": "REFUSE"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": fx_bs2["chain"], "grant_env": g_bs2, "kind": "bearer_session", "label": "use-1-set-wm", "slot_binding": "tls-mk-bs2", "token": tok_bs2, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m2"}, "chain": ch_bs2_back, "grant_env": g_bs2, "kind": "bearer_session", "label": "clock-back", "slot_binding": "tls-mk-bs2", "token": tok_bs2, "want_refusal": "QUOTA_CLOCK_REGRESSION", "want_verdict": "REFUSE"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m2"}, "chain": ch_bs2_wm, "grant_env": g_bs2, "kind": "bearer_session", "label": "clock-eq-wm-max", "slot_binding": "tls-mk-bs2", "token": tok_bs2, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m3"}, "chain": ch_bs2_exp, "grant_env": g_bs2, "kind": "bearer_session", "label": "exact-exp", "slot_binding": "tls-mk-bs2", "token": tok_bs2, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT", None, "Bearer session use enforces where-constraints, exact now == watermark ADMIT vs watermark-1 QUOTA_CLOCK_REGRESSION, exact used==max ADMIT, and exact now==exp SESSION_INVALID.")

    # Depth-2 bearer session parent window exact boundaries (tip_height == parent.not_before_height ADMIT & == parent.not_after_height SESSION_INVALID!)
    fx_d2bs = rm._delegation_fx()
    p_d2bs, c_d2bs = fx_d2bs["bundle"]["grants"][0], fx_d2bs["bundle"]["grants"][1]
    p_nb_h, p_na_h = p_d2bs["payload"]["not_before_height"], p_d2bs["payload"]["not_after_height"]
    ecfg_d2bs = {**fx_d2bs["executor_cfg"], "action_profiles": {"agent/tool": {**sv.ACTION_PROFILES["agent/tool"], "allows_bearer_session": True}}}
    so_d2bs_p = {"executor": {"key": fx_d2bs["executor_cfg"]["key"], "name": fx_d2bs["executor_cfg"]["name"]}, "exp": fx_d2bs["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "iat": fx_d2bs["chain"]["now"] - 10, "network": "main", "nonce": _h32("d8-mk-d2bs-n"), "op": "open", "proof_path": fx_d2bs["invocation"]["payload"]["proof_path"], "quotas": [], "slot_binding": "tls-d2bs", "type": "seallink-session-open/1"}
    so_d2bs_open = sl.sign_envelope(so_d2bs_p, [fx_d2bs["_keys"]["agent_req"]["sk"]])
    tok_d2bs = _h32("d8-mk-d2bs-tok")
    ch_d2_nb = copy.deepcopy(fx_d2bs["chain"])
    ch_d2_nb["tip_height"] = p_nb_h
    ch_d2_nb["best_header_height"] = p_nb_h
    ch_d2_nb["comparison_peers"] = [{"hash_at_tip": ch_d2_nb["tip_hash"], "healthy": True, "height": p_nb_h}]
    ch_d2_na = copy.deepcopy(fx_d2bs["chain"])
    ch_d2_na["tip_height"] = p_na_h
    ch_d2_na["best_header_height"] = p_na_h
    ch_d2_na["comparison_peers"] = [{"hash_at_tip": ch_d2_na["tip_hash"], "healthy": True, "height": p_na_h}]
    add("d8-mk-2a-bearer-session-depth2-parent-boundaries", ["SL-GRNT-013"], "session_lifecycle",
        {
            "executor_cfg": ecfg_d2bs,
            "journal": {"journal_id": _h32("d8-mk-d2bs-j")},
            "steps": [
                {"bearer_token": tok_d2bs, "bundle": fx_d2bs["bundle"], "chain": fx_d2bs["chain"], "kind": "session_open", "label": "open", "session_open": so_d2bs_open, "want_refusal": None, "want_verdict": "ADMIT"},
                {"chain": ch_d2_nb, "grant_env": c_d2bs, "kind": "bearer_session", "label": "parent-nb-eq-admit", "parent_grant_env": p_d2bs, "slot_binding": "tls-d2bs", "token": tok_d2bs, "want_refusal": None, "want_verdict": "ADMIT"},
                {"chain": ch_d2_na, "grant_env": c_d2bs, "kind": "bearer_session", "label": "parent-na-eq-refuse", "parent_grant_env": p_d2bs, "slot_binding": "tls-d2bs", "token": tok_d2bs, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT", None, "Depth-2 bearer session enforces parent grant exact window bounds [not_before_height, not_after_height).")

    # Decision 2A: Migration unknown mode + assent exact issued_at / expires_at boundaries + stale holder manifest (kills L5999, L6100, L6101, h_merr!)
    fx_mg2 = rm._base_invocation_fixture()
    d2_own, d2_rcpt, d2_gr = _kp("d8-mk-mg2-do"), _kp("d8-mk-mg2-dr"), _kp("d8-mk-mg2-dg")
    d2_pol = {"kind": "key", "pk": d2_own["comp"]}
    d2_reg = {"txid": _h32("d8-mk-mg2-reg"), "vout": 0}
    d2_pin = {"name": "id/mail-host-b", "owner_policy": d2_pol, "registration": d2_reg}
    s2_pin = {"name": "id/mail-host-a", "owner_policy": fx_mg2["_host_owner_pol"], "registration": fx_mg2["_host_reg"]}
    h2_pin = {"name": "id/alice", "owner_policy": fx_mg2["_alice_owner_pol"], "registration": fx_mg2["_alice_reg"]}
    d2_man = {"network": "main", "owner": "id/mail-host-b", "seq": 1, "service": {"actions": ["mail/read"], "endpoint": "https://hb.example", "receipt_key": d2_rcpt["xonly"], "service_type": "mail", "tls_spki_sha256": _h32("d8-mk-mg2-tls")}, "type": "seallink-manifest/1"}
    a2_man = {"network": "main", "owner": "id/alice", "providers": [{"label": "work", "provider": d2_pin, "service_type": "mail"}], "seq": 2, "type": "seallink-manifest/1"}
    d2_mh, a2_mh = sl.content_addr(d2_man), sl.content_addr(a2_man)
    fx_mg2["chain"]["names"]["id/mail-host-b"] = sv.make_name_history("id/mail-host-b", d2_reg, d2_pol, {"link": {"grant": d2_gr["xonly"]}, "m": {"h": d2_mh, "s": 1}}, first_height=748000, update_height=749000)
    fx_mg2["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_mg2["_alice_reg"], fx_mg2["_alice_owner_pol"], {"link": {"grant": fx_mg2["_keys"]["alice_gr"]["xonly"]}, "m": {"h": a2_mh, "s": 2}}, first_height=748000, update_height=749000)
    mid2 = _h32("d8-mk-mg2-id")
    inv2 = {"holder_name": "id/alice", "items": [{"media_type": "message/rfc822", "path": "Invoices/m.eml", "sha256": _h32("d8-mk-mg2-m"), "size_bytes": "12"}], "migration_id": mid2, "service_type": "mail"}
    inv2_h = sl.sha256(sl.jcs_encode(inv2)).hex()
    exp2 = {"inventory": inv2, "open_predecessor_grants": [], "source_journal_commitment": _h32("d8-mk-mg2-jc"), "source_journal_pos": 5, "source_write_token_fenced": True}
    mg2_p = {"dest_executor": d2_pin, "genesis": GENESIS_MAIN, "holder": h2_pin, "inventory_sha256": inv2_h, "issued_at": fx_mg2["chain"]["now"] - 10, "journal_commitment": _h32("d8-mk-mg2-jc"), "journal_pos": 5, "migration_id": mid2, "network": "main", "outstanding_exposure": [], "service_type": "mail", "source_executor": s2_pin, "type": "seallink-migration/1"}
    mg2_env = sl.sign_envelope(mg2_p, [fx_mg2["_keys"]["host_rcpt"]["sk"]])
    mg2_oid = sl.object_id(mg2_p)
    mg2_acc = sl.sign_envelope({"genesis": GENESIS_MAIN, "issuer": d2_pin, "network": "main", "not_after": fx_mg2["chain"]["now"] + 600, "not_before": fx_mg2["chain"]["now"] - 10, "seq": 1, "statement_kind": "migration-accept", "subject": {"holder": h2_pin, "inventory_sha256": inv2_h, "migration_id": mid2, "source_executor": s2_pin}, "type": "seallink-statement/1"}, [d2_rcpt["sk"]])
    mg2_mans = {sl.content_addr(fx_mg2["_host_man"]): fx_mg2["_host_man"], d2_mh: d2_man, a2_mh: a2_man}
    # Holder assent exact issued_at == now (ADMIT) & expires_at == now (REFUSE)
    ha_eq_iat = sl.sign_envelope({"expires_at": fx_mg2["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "issued_at": fx_mg2["chain"]["now"], "network": "main", "nonce": _h32("d8-mk-ha-iat"), "party_id": "holder-1", "party_name": "id/alice", "party_role": "holder", "target_id": mg2_oid, "target_type": "seallink-migration/1", "type": "seallink-assent/1"}, [fx_mg2["_keys"]["alice_gr"]["sk"]])
    ha_eq_exp = sl.sign_envelope({"expires_at": fx_mg2["chain"]["now"], "genesis": GENESIS_MAIN, "issued_at": fx_mg2["chain"]["now"] - 10, "network": "main", "nonce": _h32("d8-mk-ha-exp"), "party_id": "holder-1", "party_name": "id/alice", "party_role": "holder", "target_id": mg2_oid, "target_type": "seallink-migration/1", "type": "seallink-assent/1"}, [fx_mg2["_keys"]["alice_gr"]["sk"]])
    # Unknown mode (all activate proofs valid, ONLY mode="bogus" invalid -> deleting L5912 causes ADMIT!)
    add("d8-mk-2a-migration-unknown-mode-refuse", ["SL-SERV-003"], "migration",
        {"chain": fx_mg2["chain"], "dest_accept_stmt": mg2_acc, "export_bundle": exp2, "holder_assent": ha_eq_iat, "journal": {"journal_id": _h32("d8-mk-mg2-j0")}, "local_executor_pin": d2_pin, "manifests": mg2_mans, "migration": mg2_env, "mode": "bogus"},
        "REFUSE", "SERVICE_MIGRATION_INVALID", "Unknown migration mode MUST refuse SERVICE_MIGRATION_INVALID even when all activate proofs are valid.")
    add("d8-mk-2a-migration-assent-exact-iat-admit", ["SL-SERV-003"], "migration",
        {"chain": fx_mg2["chain"], "dest_accept_stmt": mg2_acc, "export_bundle": exp2, "holder_assent": ha_eq_iat, "journal": {"journal_id": _h32("d8-mk-mg2-j1")}, "local_executor_pin": d2_pin, "manifests": mg2_mans, "migration": mg2_env, "mode": "activate"},
        "ADMIT", None, "Migration holder_assent at exact chain.now == issued_at MUST admit.")
    add("d8-mk-2a-migration-assent-exact-exp-refuse", ["SL-SERV-003"], "migration",
        {"chain": fx_mg2["chain"], "dest_accept_stmt": mg2_acc, "export_bundle": exp2, "holder_assent": ha_eq_exp, "journal": {"journal_id": _h32("d8-mk-mg2-j2")}, "local_executor_pin": d2_pin, "manifests": mg2_mans, "migration": mg2_env, "mode": "activate"},
        "REFUSE", "SERVICE_MIGRATION_INVALID", "Migration holder_assent at exact chain.now == expires_at MUST refuse SERVICE_MIGRATION_INVALID.")
    # Holder manifest rollback (journal saw seq=3 while chain pins seq=2 -> MANIFEST_ROLLBACK!)
    add("d8-mk-2a-migration-holder-manifest-rollback", ["SL-SERV-003"], "migration",
        {"chain": fx_mg2["chain"], "dest_accept_stmt": mg2_acc, "export_bundle": exp2, "holder_assent": ha_eq_iat, "journal": {"journal_id": _h32("d8-mk-mg2-j3"), "manifest_heads": [{"anchoring_txid_active": True, "name": "id/alice", "reg_key": sv._outpoint_key(fx_mg2["_alice_reg"]), "seq": 3, "sha256": _h32("d8-mk-mrb-h")}]}, "local_executor_pin": d2_pin, "manifests": mg2_mans, "migration": mg2_env, "mode": "activate"},
        "REFUSE", "MANIFEST_ROLLBACK", "Migration activate MUST propagate MANIFEST_ROLLBACK when holder manifest regresses.")

    # Decision 2A: Federation wrong network (CHAIN_MISMATCH), persisted closure (GRANT_CLOSED), & screening exact window boundaries!
    fx_fd2 = rm._base_invocation_fixture()
    gp_fd2 = copy.deepcopy(fx_fd2["bundle"]["grants"][0]["payload"])
    gp_fd2["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    g_fd2, gid_fd2 = _reanchor(fx_fd2, gp_fd2)
    g_fd2_wnet = sl.sign_envelope({**gp_fd2, "network": "regtest"}, [fx_fd2["_keys"]["alice_gr"]["sk"]])
    add("d8-mk-2a-federation-wrong-network", ["SL-SERV-004"], "federation",
        {"chain": fx_fd2["chain"], "grant": g_fd2_wnet, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": {"trusted_peers": ["id/peer-b"]}},
        "REFUSE", "CHAIN_MISMATCH", "Federation disclosure with wrong-network grant MUST refuse CHAIN_MISMATCH.")

    j_fdcl = sv.FencedJournal(_h32("d8-mk-fdcl"))
    j_fdcl.record_closure({"subject_id": gid_fd2, "subject_kind": "grant"}, "GRANT_CLOSED", observed_at=fx_fd2["chain"]["now"], observed_height=fx_fd2["chain"]["tip_height"])
    add("d8-mk-2a-federation-persisted-grant-closure", ["SL-SERV-004"], "federation",
        {"chain": fx_fd2["chain"], "grant": g_fd2, "journal": {"closures": j_fdcl.closures, "journal_id": j_fdcl.journal_id}, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": {"trusted_peers": ["id/peer-b"]}},
        "REFUSE", "GRANT_CLOSED", "Federation disclosure with persisted grant closure MUST refuse GRANT_CLOSED.")

    ch_fd_nb = copy.deepcopy(fx_fd2["chain"])
    ch_fd_nb["tip_height"] = gp_fd2["not_before_height"]
    ch_fd_nb["best_header_height"] = gp_fd2["not_before_height"]
    ch_fd_nb["comparison_peers"] = [{"hash_at_tip": ch_fd_nb["tip_hash"], "healthy": True, "height": gp_fd2["not_before_height"]}]
    ch_fd_na = copy.deepcopy(fx_fd2["chain"])
    ch_fd_na["tip_height"] = gp_fd2["not_after_height"]
    ch_fd_na["best_header_height"] = gp_fd2["not_after_height"]
    ch_fd_na["comparison_peers"] = [{"hash_at_tip": ch_fd_na["tip_hash"], "healthy": True, "height": gp_fd2["not_after_height"]}]
    add("d8-mk-2a-federation-screening-exact-nb-admit", ["SL-SERV-004"], "federation",
        {"chain": ch_fd_nb, "grant": g_fd2, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": {"trusted_peers": ["id/peer-b"]}},
        "ADMIT", None, "Federation screening at exact tip_height == not_before_height MUST admit.")
    add("d8-mk-2a-federation-screening-exact-na-refuse", ["SL-SERV-004"], "federation",
        {"chain": ch_fd_na, "grant": g_fd2, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": {"trusted_peers": ["id/peer-b"]}},
        "REFUSE", "FEDERATION_POLICY_DENIED", "Federation screening at exact tip_height == not_after_height MUST refuse FEDERATION_POLICY_DENIED.")

    # Schema leaf validator=='type' branches (kills _map_schema_error_to_refusal L302 on BOTH refusal-return & wrong-code!)
    g_wt_base = copy.deepcopy(fx_w0["bundle"]["grants"][0])
    g_wt_cons = copy.deepcopy(g_wt_base)
    g_wt_cons["payload"]["capabilities"][0]["where"] = {"folder": {"in": "not-an-array"}}
    add("d8-mk-wire-type-mismatch-in-constraint", ["SL-WIRE-007"], "raw_wire",
        {"expected_type": "seallink-grant/1", "object": g_wt_cons}, "REFUSE", "WIRE_CONSTRAINT",
        "Wrong JSON type inside ConstraintPredicate (in: string) MUST map validator=='type' to WIRE_CONSTRAINT.")

    g_wt_uint = copy.deepcopy(g_wt_base)
    g_wt_uint["payload"]["not_before_height"] = "not-an-int"
    add("d8-mk-wire-type-mismatch-on-uint53", ["SL-WIRE-007"], "raw_wire",
        {"expected_type": "seallink-grant/1", "object": g_wt_uint}, "REFUSE", "WIRE_MEMBER",
        "Wrong JSON type on a Uint53 field (string instead of integer) MUST map validator=='type' to WIRE_MEMBER rather than WIRE_INTEGER.")

    # Mid-operation write-time CAS race & validation fallback through _append_journal_checked (kills L1091, L1093, L1096 on BOTH refusal-return & wrong-code!)
    for r_mode, r_code, r_id, r_note in (
        ("fence", "JOURNAL_FENCED", "d8-mk-write-race-cas-fenced", "Concurrent CAS write_token fence between check_continuity and append MUST refuse JOURNAL_FENCED."),
        ("drift", "JOURNAL_LOST", "d8-mk-write-race-cas-lost", "Concurrent CAS witness head drift between check_continuity and append MUST refuse JOURNAL_LOST."),
        ("value_err", "WIRE_SIZE", "d8-mk-write-race-value-error-wire-size", "Unregistered ValueError raised during journal.append MUST map fail-closed to WIRE_SIZE."),
    ):
        fx_wr = rm._base_invocation_fixture()
        j_wr_id = _h32(f"d8-mk-wr-{r_mode}")
        j_wr_0 = sv.FencedJournal(j_wr_id)
        fx_wr["journal"] = {"journal_id": j_wr_id}
        fx_wr["external_witness"] = {"active_write_token": 1, "commitment": j_wr_0.commitment, "journal_id": j_wr_id, "pos": 0}
        fx_wr["write_token"] = 1
        fx_wr["write_race"] = r_mode
        add(r_id, ["SL-GRNT-010"], "invocation", fx_wr, "REFUSE", r_code, r_note)

    # Depth-2 bearer session defense-in-depth parent exact not_after_height boundary (kills _validate_session_backing_grant L5751 < -> <=!)
    fx_pna = rm._delegation_fx()
    p_pna = copy.deepcopy(fx_pna["bundle"]["grants"][0])
    c_pna_p = copy.deepcopy(fx_pna["bundle"]["grants"][1]["payload"])
    p_pna_na = p_pna["payload"]["not_after_height"]
    c_pna_p["not_after_height"] = p_pna_na + 10  # child still open at tip == parent.not_after_height so L5751 is the sole gate!
    c_pna = sl.sign_envelope(c_pna_p, [fx_pna["_keys"]["agent_req"]["sk"]])
    c_pna_id = sl.object_id(c_pna_p)
    tok_pna = _h32("d8-mk-pna-tok")
    th_pna = sl.sha256(tok_pna.encode("utf-8")).hex()
    ch_pna = copy.deepcopy(fx_pna["chain"])
    ch_pna["tip_height"] = p_pna_na
    ch_pna["best_header_height"] = p_pna_na
    ch_pna["comparison_peers"] = [{"hash_at_tip": ch_pna["tip_hash"], "healthy": True, "height": p_pna_na}]
    add("d8-mk-2a-bearer-session-parent-na-exact-boundary", ["SL-GRNT-013"], "bearer_session",
        {
            "chain": ch_pna,
            "grant_env": c_pna,
            "journal": {"journal_id": _h32("d8-mk-pna-j"), "sessions": {th_pna: {"closed": False, "exp": ch_pna["now"] + 600, "grant_id": c_pna_id, "quotas": [], "session_id": _h32("d8-mk-pna-sid"), "slot_binding": "tls-pna", "token_sha256": th_pna}}},
            "parent_grant_env": p_pna,
            "slot_binding": "tls-pna",
            "token": tok_pna,
        },
        "REFUSE", "SESSION_INVALID", "Bearer session defense-in-depth MUST refuse SESSION_INVALID at exact tip_height == parent.not_after_height.")
