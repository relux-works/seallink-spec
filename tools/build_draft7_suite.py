#!/usr/bin/env python3
"""
SealLink v1.0.0-draft.7 — Triple-Audit Regression, PR #1 Graduation, and 30/30 Object-Type Suite.

Graduates all 15 blocker families from Reviewer #2's draft PR #1 (`B-1..B-15`, controls + closed
witnesses + resolved design decisions) together with Reviewer #1 (`R1-A`, `R1-B`, `R1-C`),
Reviewer #3 (`R3-B1..B6`, `R3-H1/H4/H8`), Decision 6A (native P2WSH m-of-n `BranchKeySpec`),
Decisions D-1/D-2/D-6, and Decision 6B / H-24 full executable positive + negative coverage across
all 30 registered object types (`registry/object-types.json`).
"""

from __future__ import annotations

import copy
from typing import Any, Callable

import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = rm.GENESIS_MAIN
_h32 = rm._h32
_kp = rm._kp
_spk_hex = rm._spk_hex


def _reanchor(fx: dict[str, Any], gp: dict[str, Any], *, signer_sk: bytes | None = None, rcpt_sk: bytes | None = None) -> tuple[dict[str, Any], str]:
    """Re-sign grant payload, update 0x01 issuance tx & invocation proof_path."""
    sk = signer_sk if signer_sk is not None else fx["_keys"]["alice_gr"]["sk"]
    g_env = sl.sign_envelope(gp, [sk])
    gid = sl.object_id(gp)
    itx = fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx["bundle"]["grants"] = [g_env]
    fx["chain"]["txs"][itx]["opreturn_hex"] = sl.encode_opreturn(
        0x01,
        sl.signing_digest({
            "genesis": GENESIS_MAIN,
            "grant_content_addr": sl.content_addr(g_env),
            "grant_id": gid,
            "type": "seallink-issuance/1",
        }).hex(),
    ).hex()
    inv_p = copy.deepcopy(fx["invocation"]["payload"])
    inv_p["proof_path"] = [{"grant_id": gid, "issuance_txid": itx}]
    fx["invocation"] = sl.sign_envelope(inv_p, [rcpt_sk if rcpt_sk is not None else fx["_keys"]["agent_req"]["sk"]])
    return g_env, gid


def add_draft7_conformance_cases(add: Callable[..., None]) -> None:
    """Append all v1.0.0-draft.7 regression, PR #1 graduated, and 30/30 object-type vectors."""

    # =========================================================================
    # B-1: Target Authority Binding (Mailbox Owner & Station Host)
    # =========================================================================
    fx_b1_ctrl = rm._base_invocation_fixture()
    add(
        "d7-b01-control-owner-mailbox-admit",
        ["SL-MAIL-003", "SL-GRNT-012"],
        "invocation",
        fx_b1_ctrl,
        "ADMIT",
        None,
        "Control: grant issued by id/alice targeting mailbox:id/alice:work admits cleanly.",
    )

    fx_b1_for = rm._base_invocation_fixture()
    mal_own, mal_gr = _kp("d7-b1-mal-own"), _kp("d7-b1-mal-gr")
    mal_opol = {"kind": "key", "pk": mal_own["comp"]}
    mal_reg = {"txid": _h32("d7-b1-mal-reg"), "vout": 0}
    fx_b1_for["chain"]["names"]["id/mallory"] = sv.make_name_history(
        "id/mallory", mal_reg, mal_opol, {"link": {"grant": mal_gr["xonly"]}}, first_height=748000, update_height=749000
    )
    gp_b1 = copy.deepcopy(fx_b1_for["bundle"]["grants"][0]["payload"])
    gp_b1["issuer"] = {"name": "id/mallory", "owner_policy": mal_opol, "registration": mal_reg, "role_policy": {"m": 1, "pks": [mal_gr["xonly"]]}}
    _reanchor(fx_b1_for, gp_b1, signer_sk=mal_gr["sk"])
    add(
        "d7-b01-foreign-issuer-concrete-executor-refuse",
        ["SL-MAIL-003", "SL-GRNT-012"],
        "invocation",
        fx_b1_for,
        "REFUSE",
        "GRANT_TARGET_UNAUTHORIZED",
        "PR #1 B-1 closed: foreign issuer id/mallory issuing grant targeting mailbox:id/alice:work MUST refuse GRANT_TARGET_UNAUTHORIZED.",
    )

    # Foreign issuer using executor_ref pointing at victim's provider
    fx_b1_eref = rm._base_invocation_fixture()
    fx_b1_eref["chain"]["names"]["id/mallory"] = sv.make_name_history(
        "id/mallory", mal_reg, mal_opol, {"link": {"grant": mal_gr["xonly"]}}, first_height=748000, update_height=749000
    )
    gp_b1e = copy.deepcopy(fx_b1_eref["bundle"]["grants"][0]["payload"])
    gp_b1e.pop("executor", None)
    gp_b1e["executor_ref"] = {"label": "work", "provider_of": "id/alice", "service_type": "mail"}
    gp_b1e["issuer"] = {"name": "id/mallory", "owner_policy": mal_opol, "registration": mal_reg, "role_policy": {"m": 1, "pks": [mal_gr["xonly"]]}}
    _reanchor(fx_b1_eref, gp_b1e, signer_sk=mal_gr["sk"])
    add(
        "d7-b01-foreign-issuer-executor-ref-refuse",
        ["SL-MAIL-003", "SL-GRNT-003"],
        "invocation",
        fx_b1_eref,
        "REFUSE",
        "GRANT_TARGET_UNAUTHORIZED",
        "PR #1 B-1 closed: foreign issuer using executor_ref.provider_of=id/alice for mailbox:id/alice:work MUST refuse GRANT_TARGET_UNAUTHORIZED.",
    )

    # Foreign station target mismatching executor_cfg.name -> GRANT_TARGET_UNAUTHORIZED
    fx_b1_st = rm._delegation_fx()
    gp_b1s = copy.deepcopy(fx_b1_st["bundle"]["grants"][0]["payload"])
    gp_b1s["capabilities"][0]["target"] = "station:id/station-other:tools"
    gp_b1s["delegate"]["groups"][0]["template"]["capabilities"][0]["target"] = "station:id/station-other:tools"
    p_env_s = sl.sign_envelope(gp_b1s, [fx_b1_st["_keys"]["alice_gr"]["sk"]])
    pid_s = sl.object_id(gp_b1s)
    fx_b1_st["chain"]["txs"][_h32("p-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_env_s), "grant_id": pid_s, "type": "seallink-issuance/1"}).hex()
    ).hex()
    cg_b1s = copy.deepcopy(fx_b1_st["bundle"]["grants"][1]["payload"])
    cg_b1s["parent"]["grant_id"] = pid_s
    cg_b1s["capabilities"][0]["target"] = "station:id/station-other:tools"
    c_env_s = sl.sign_envelope(cg_b1s, [fx_b1_st["_del_k"]["sk"]])
    cid_s = sl.object_id(cg_b1s)
    fx_b1_st["chain"]["txs"][_h32("c-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_env_s), "grant_id": cid_s, "type": "seallink-issuance/1"}).hex()
    ).hex()
    fx_b1_st["bundle"]["grants"] = [p_env_s, c_env_s]
    inv_b1s = copy.deepcopy(fx_b1_st["invocation"]["payload"])
    inv_b1s["target"] = "station:id/station-other:tools"
    inv_b1s["proof_path"] = [{"grant_id": pid_s, "issuance_txid": _h32("p-iss-tx")}, {"grant_id": cid_s, "issuance_txid": _h32("c-iss-tx")}]
    fx_b1_st["invocation"] = sl.sign_envelope(inv_b1s, [fx_b1_st["_keys"]["agent_req"]["sk"]])
    add(
        "d7-b01-foreign-station-host-target-refuse",
        ["SL-AGNT-001", "SL-GRNT-012"],
        "invocation",
        fx_b1_st,
        "REFUSE",
        "GRANT_TARGET_UNAUTHORIZED",
        "B-1: station:<host>:<slot> target whose host != executor.name MUST refuse GRANT_TARGET_UNAUTHORIZED.",
    )

    # =========================================================================
    # B-2: Autonomous Issuer Impersonation via Foreign Ward origin_bundle
    # =========================================================================
    fx_b2 = rm._base_invocation_fixture()
    of_b2 = rm._base_origin_fixture()
    # Merge ward origin tx/name data into fx_b2 chain, attach foreign ward bundle, and sign Alice's grant with wrong key
    fx_b2["chain"]["names"].update(of_b2["chain"]["names"])
    fx_b2["chain"]["txs"].update(of_b2["chain"]["txs"])
    fx_b2["bundle"]["origin_bundle"] = of_b2["origin_bundle"]
    fx_b2["trusted_origin_issuer_pins"] = of_b2["trusted_origin_issuer_pins"]
    gp_b2 = copy.deepcopy(fx_b2["bundle"]["grants"][0]["payload"])
    gp_b2["guardian_context"] = {"event_class": "routine_read", "origin_id": of_b2["_origin_id"], "revision": 1, "ward_name": "id/child-leo"}
    gp_b2["issuer"].pop("role_policy", None)
    g_b2 = sl.sign_guardian_envelope(gp_b2, [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [of_b2["_keys"]["g1_gr"]["sk"]]}])
    gid_b2 = sl.object_id(gp_b2)
    itx_b2 = fx_b2["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx_b2["bundle"]["grants"] = [g_b2]
    fx_b2["chain"]["txs"][itx_b2]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_b2), "grant_id": gid_b2, "type": "seallink-issuance/1"}).hex()
    ).hex()
    inv_b2 = copy.deepcopy(fx_b2["invocation"]["payload"])
    inv_b2["proof_path"] = [{"grant_id": gid_b2, "issuance_txid": itx_b2}]
    fx_b2["invocation"] = sl.sign_envelope(inv_b2, [fx_b2["_keys"]["agent_req"]["sk"]])
    add(
        "d7-b02-autonomous-issuer-foreign-ward-bundle-refuse",
        ["SL-ORIG-005", "SL-WIRE-013"],
        "invocation",
        fx_b2,
        "REFUSE",
        "WIRE_SIGNATURE",
        "PR #1 B-2 closed: attaching a foreign ward's origin_bundle and guardian_approvals to an autonomous issuer (no link.origin) MUST refuse WIRE_SIGNATURE.",
    )

    # =========================================================================
    # B-3: Cross-Ward & Autonomous agent/guardian-message Defenses
    # =========================================================================
    of_b3 = rm._base_origin_fixture()
    gm_st = _kp("d7-b3-station")
    gm_br = _kp("d7-b3-bridge")
    gm_sl_k = _kp("d7-b3-seal")
    gm_sl_pol = {"kind": "key", "pk": gm_sl_k["comp"]}
    gm_sl_tx = _h32("d7-b3-seal-tx")
    gm_itx = _h32("d7-b3-itx")
    gm_rblk = _h32("d7-b3-rblk")
    of_b3["chain"].setdefault("blocks", {})[gm_rblk] = 749950
    of_b3["chain"]["txs"][gm_sl_tx] = {"confirmed_height": 749960, "outputs": {"0": {"script_pubkey_hex": _spk_hex(gm_sl_pol)}, "1": {"script_pubkey_hex": _spk_hex(gm_sl_pol)}}}
    raw_m_b3 = b"Ward instruction"
    # Autonomous single-guardian plain grant with NO guardian_context for agent/guardian-message -> WARD_AUTONOMOUS_FORBIDDEN
    gp_b3_auto = {
        "capabilities": [{"action": "agent/guardian-message", "target": f"ward:{of_b3['_origin_id']}", "where": {}}],
        "executor": {"key": gm_st["xonly"], "name": "id/station-b3"},
        "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/child-leo", "owner_policy": of_b3["origin_bundle"]["name_binding"]["owner_policy"], "registration": of_b3["origin_bundle"]["name_binding"]["registration"], "role_policy": {"m": 1, "pks": [of_b3["_keys"]["ward_gr"]["xonly"]]}},
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 749900,
        "recent_block": gm_rblk,
        "recipient": {"key": gm_br["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": gm_sl_pol, "txid": gm_sl_tx, "vout": 0}},
        "type": "seallink-grant/1",
    }
    g_b3_auto = sl.sign_envelope(gp_b3_auto, [of_b3["_keys"]["ward_gr"]["sk"]])
    gid_b3_auto = sl.object_id(gp_b3_auto)
    of_b3["chain"]["txs"][gm_itx] = {
        "confirmed_height": 749970,
        "inputs": [sv.make_segwit_input(gm_sl_tx, 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_b3_auto), "grant_id": gid_b3_auto, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_b3_auto = sl.sign_envelope(
        {
            "action": "agent/guardian-message",
            "arguments": {"channel": "direct", "delivery_mode": "strict_drop", "message_sha256": sl.sha256(raw_m_b3).hex(), "origin_id": of_b3["_origin_id"], "revision": 1, "subject_ward_name": "id/child-leo"},
            "executor": {"key": gm_st["xonly"], "name": "id/station-b3"},
            "exp": of_b3["chain"]["now"] + 600,
            "genesis": GENESIS_MAIN,
            "iat": of_b3["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d7-b3-auto-n"),
            "proof_path": [{"grant_id": gid_b3_auto, "issuance_txid": gm_itx}],
            "target": f"ward:{of_b3['_origin_id']}",
            "type": "seallink-invocation/1",
        },
        [gm_br["sk"]],
    )
    add(
        "d7-b03-ward-plain-grant-no-guardian-context-refuse",
        ["SL-ORIG-005", "SL-AGNT-003"],
        "invocation",
        {
            "invocation": inv_b3_auto,
            "bundle": {"grants": [g_b3_auto], "origin_bundle": of_b3["origin_bundle"]},
            "chain": of_b3["chain"],
            "journal": {"journal_id": _h32("d7-b3-j1")},
            "executor_cfg": {"key": gm_st["xonly"], "name": "id/station-b3", "pinned_ward_origin_id": of_b3["_origin_id"]},
            "trusted_origin_issuer_pins": of_b3["trusted_origin_issuer_pins"],
            "raw_message_hex": raw_m_b3.hex(),
        },
        "REFUSE",
        "WARD_AUTONOMOUS_FORBIDDEN",
        "PR #1 B-3 closed: plain autonomous grant without guardian_context/guardian_approvals on ward origin MUST refuse WARD_AUTONOMOUS_FORBIDDEN.",
    )

    # Guardians of ward X trying to authorize message into pinned ward Y -> GRANT_TARGET_UNAUTHORIZED
    of_b3_xy = copy.deepcopy(of_b3)
    op_xy = copy.deepcopy(of_b3_xy["origin_bundle"]["origin"]["payload"])
    op_xy["guardian_policy"]["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 1}
    o_xy = sl.sign_envelope(op_xy, [of_b3_xy["_keys"]["reg_cred"]["sk"]])
    oid_x = sl.object_id(op_xy)
    oid_y = _h32("d7-b3-ward-y")
    of_b3_xy["origin_bundle"]["origin"] = o_xy
    of_b3_xy["origin_bundle"]["name_binding"]["origin_id"] = oid_x
    g1_xy_p = {**of_b3_xy["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_x}
    g1_xy = sl.sign_envelope(g1_xy_p, [of_b3_xy["_keys"]["reg_cred"]["sk"]])
    of_b3_xy["origin_bundle"]["guardian_records"] = [g1_xy]
    of_b3_xy["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**of_b3_xy["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(g1_xy_p)}, [of_b3_xy["_keys"]["g1_gr"]["sk"]])]
    of_b3_xy["chain"]["txs"][of_b3_xy["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_xy)).hex()
    of_b3_xy["chain"]["txs"][of_b3_xy["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_b3_xy["origin_bundle"]["name_binding"])).hex()
    of_b3_xy["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_xy)).hex()
    of_b3_xy["chain"]["names"]["id/child-leo"] = sv.make_name_history(
        "id/child-leo", of_b3_xy["origin_bundle"]["name_binding"]["registration"], of_b3_xy["origin_bundle"]["name_binding"]["owner_policy"],
        {"link": {"grant": of_b3_xy["_keys"]["g1_gr"]["xonly"], "origin": oid_x}}, first_height=749005, update_height=749010,
    )
    gp_xy = {
        "capabilities": [{"action": "agent/guardian-message", "target": f"ward:{oid_y}", "where": {}}],
        "executor": {"key": gm_st["xonly"], "name": "id/station-b3"},
        "genesis": GENESIS_MAIN,
        "guardian_context": {"event_class": "effect_grant", "origin_id": oid_x, "revision": 1, "ward_name": "id/child-leo"},
        "issuer": {"name": "id/child-leo", "owner_policy": of_b3_xy["origin_bundle"]["name_binding"]["owner_policy"], "registration": of_b3_xy["origin_bundle"]["name_binding"]["registration"]},
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 749900,
        "recent_block": gm_rblk,
        "recipient": {"key": gm_br["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": gm_sl_pol, "txid": gm_sl_tx, "vout": 0}},
        "type": "seallink-grant/1",
    }
    g_xy = sl.sign_guardian_envelope(gp_xy, [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [of_b3_xy["_keys"]["g1_gr"]["sk"]]}])
    gid_xy = sl.object_id(gp_xy)
    itx_xy = _h32("d7-b3-xy-itx")
    of_b3_xy["chain"]["txs"][itx_xy] = {
        "confirmed_height": 749970,
        "inputs": [sv.make_segwit_input(gm_sl_tx, 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_xy), "grant_id": gid_xy, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_xy = sl.sign_envelope(
        {
            "action": "agent/guardian-message",
            "arguments": {"channel": "direct", "delivery_mode": "strict_drop", "message_sha256": sl.sha256(raw_m_b3).hex(), "origin_id": oid_y, "revision": 1, "subject_ward_name": "id/child-leo"},
            "executor": {"key": gm_st["xonly"], "name": "id/station-b3"},
            "exp": of_b3_xy["chain"]["now"] + 600,
            "genesis": GENESIS_MAIN,
            "iat": of_b3_xy["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d7-b3-xy-n"),
            "proof_path": [{"grant_id": gid_xy, "issuance_txid": itx_xy}],
            "target": f"ward:{oid_y}",
            "type": "seallink-invocation/1",
        },
        [gm_br["sk"]],
    )
    add(
        "d7-b03-guardians-of-ward-x-into-pinned-ward-y-refuse",
        ["SL-ORIG-005", "SL-AGNT-003"],
        "invocation",
        {
            "invocation": inv_xy,
            "bundle": {"grants": [g_xy], "origin_bundle": of_b3_xy["origin_bundle"]},
            "chain": of_b3_xy["chain"],
            "journal": {"journal_id": _h32("d7-b3-j2")},
            "executor_cfg": {"key": gm_st["xonly"], "name": "id/station-b3", "pinned_ward_origin_id": oid_y},
            "trusted_origin_issuer_pins": of_b3_xy["trusted_origin_issuer_pins"],
            "raw_message_hex": raw_m_b3.hex(),
        },
        "REFUSE",
        "GRANT_TARGET_UNAUTHORIZED",
        "PR #1 B-3 closed: guardians of ward X MUST NOT authorize agent/guardian-message into pinned ward Y.",
    )

    # =========================================================================
    # B-4: Cryptographic seallink-notary/1 Verification on required_act
    # =========================================================================
    def _notary_delegation_fx(*, notary_act_mode: str = "valid") -> dict[str, Any]:
        fx_n = rm._delegation_fx(notary_mode="required_act")
        not_own, not_k = _kp("d7-not-own"), _kp("d7-not-role")
        not_opol = {"kind": "key", "pk": not_own["comp"]}
        not_reg = {"txid": _h32("d7-not-reg"), "vout": 0}
        not_pin = {"name": "id/notary-a", "owner_policy": not_opol, "registration": not_reg}
        fx_n["chain"]["names"]["id/notary-a"] = sv.make_name_history(
            "id/notary-a", not_reg, not_opol, {"link": {"notary": not_k["xonly"]}}, first_height=748000, update_height=749000
        )
        # Update parent delegate.notaries and template.notary_name to real pinned id/notary-a
        pp = copy.deepcopy(fx_n["bundle"]["grants"][0]["payload"])
        pp["delegate"]["notaries"] = [not_pin]
        pp["delegate"]["groups"][0]["template"]["notary_name"] = "id/notary-a"
        p_env = sl.sign_envelope(pp, [fx_n["_keys"]["alice_gr"]["sk"]])
        pid = sl.object_id(pp)
        fx_n["chain"]["txs"][_h32("p-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(
            0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_env), "grant_id": pid, "type": "seallink-issuance/1"}).hex()
        ).hex()
        cp = copy.deepcopy(fx_n["bundle"]["grants"][1]["payload"])
        cp["parent"]["grant_id"] = pid
        c_env = sl.sign_envelope(cp, [fx_n["_del_k"]["sk"]])
        cid = sl.object_id(cp)
        fx_n["chain"]["txs"][_h32("c-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(
            0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_env), "grant_id": cid, "type": "seallink-issuance/1"}).hex()
        ).hex()
        fx_n["bundle"]["grants"] = [p_env, c_env]
        inv_p = copy.deepcopy(fx_n["invocation"]["payload"])
        inv_p["proof_path"] = [{"grant_id": pid, "issuance_txid": _h32("p-iss-tx")}, {"grant_id": cid, "issuance_txid": _h32("c-iss-tx")}]
        fx_n["invocation"] = sl.sign_envelope(inv_p, [fx_n["_keys"]["agent_req"]["sk"]])

        if notary_act_mode == "junk":
            fx_n["bundle"]["notary_act"] = {"garbage": True}
            return fx_n
        if notary_act_mode == "string":
            fx_n["bundle"]["notary_act"] = "not-an-object"
            return fx_n
        target_cid = _h32("wrong-child-id") if notary_act_mode == "wrong_child" else cid
        n_seal_pol = {"kind": "key", "pk": _kp("d7-not-seal")["comp"]}
        n_seal_tx = _h32("d7-not-seal-tx")
        n_act_p: dict[str, Any] = {
            "act_kind": "child-within-parent",
            "attested_at": 1795220000,
            "details": {"child_grant_id": target_cid, "kind": "child-within-parent", "ordinal": 1, "parent_grant_id": pid},
            "genesis": GENESIS_MAIN,
            "lifecycle": "revocable" if notary_act_mode == "revoked" else "eternal",
            "network": "main",
            "notary": {**not_pin, "role_policy": {"m": 1, "pks": [not_k["xonly"]]}},
            "target_sha256": sl.content_addr(c_env),
            "tip_hash": fx_n["chain"]["tip_hash"],
            "tip_height": 749980,
            "type": "seallink-notary/1",
        }
        if notary_act_mode == "revoked":
            n_act_p["notary_seal"] = {"script_policy": n_seal_pol, "txid": n_seal_tx, "vout": 0}
        n_act = sl.sign_envelope(n_act_p, [not_k["sk"]])
        n_tx = _h32(f"d7-not-0x04-{notary_act_mode}")
        fx_n["chain"]["txs"][n_tx] = {
            "confirmed_height": 749985,
            "opreturn_hex": sl.encode_opreturn(0x04, sl.content_addr(n_act)).hex(),
            "outputs": {},
        }
        if notary_act_mode == "revoked":
            rev_tx = _h32("d7-not-0x05-rev")
            fx_n["chain"]["txs"][n_seal_tx] = {"confirmed_height": 749980, "outputs": {"0": {"script_pubkey_hex": _spk_hex(n_seal_pol), "spent_by_txid": rev_tx}}}
            fx_n["chain"]["txs"][rev_tx] = {"confirmed_height": 749995, "opreturn_hex": sl.encode_opreturn(0x05, sl.object_id(n_act_p)).hex(), "outputs": {}}
        fx_n["bundle"]["notary_act"] = n_act
        fx_n["bundle"]["notary_anchor_txid"] = n_tx
        return fx_n

    add(
        "d7-b04-valid-notary-act-child-within-parent-admit",
        ["SL-GRNT-011", "SL-CONT-011"],
        "invocation",
        _notary_delegation_fx(notary_act_mode="valid"),
        "ADMIT",
        None,
        "PR #1 B-4 positive: anchored seallink-notary/1 (0x04) signed by pinned delegate.notaries key for exact (parent_grant_id, child_grant_id, ordinal) admits.",
    )
    add(
        "d7-b04-required-act-junk-object-refuse",
        ["SL-GRNT-011"],
        "invocation",
        _notary_delegation_fx(notary_act_mode="junk"),
        "REFUSE",
        "NOTARY_REQUIRED",
        "PR #1 B-4 closed: junk notary_act object MUST NOT satisfy required_act.",
    )
    add(
        "d7-b04-required-act-string-refuse",
        ["SL-GRNT-011"],
        "invocation",
        _notary_delegation_fx(notary_act_mode="string"),
        "REFUSE",
        "NOTARY_REQUIRED",
        "PR #1 B-4 closed: non-object string notary_act MUST NOT satisfy required_act.",
    )
    add(
        "d7-b04-required-act-wrong-child-refuse",
        ["SL-GRNT-011", "SL-CONT-011"],
        "invocation",
        _notary_delegation_fx(notary_act_mode="wrong_child"),
        "REFUSE",
        "NOTARY_REQUIRED",
        "PR #1 B-4 closed: genuine anchored seallink-notary/1 attesting a DIFFERENT child_grant_id MUST refuse NOTARY_REQUIRED.",
    )
    add(
        "d7-b04-revoked-notary-act-0x05-refuse",
        ["SL-CONT-011"],
        "invocation",
        _notary_delegation_fx(notary_act_mode="revoked"),
        "REFUSE",
        "CRED_REVOKED_FOR_CAUSE",
        "H-24 / SPEC-05 §5: revocable notary_act whose notary_seal was spent with 0x05 MUST refuse CRED_REVOKED_FOR_CAUSE.",
    )

    # Standalone notary_act runner (fact-attestation)
    fx_n_sa = _notary_delegation_fx(notary_act_mode="valid")
    add(
        "d7-obj-notary-standalone-admit",
        ["SL-CONT-011"],
        "notary_act",
        {"notary": fx_n_sa["bundle"]["notary_act"], "anchor_txid": fx_n_sa["bundle"]["notary_anchor_txid"], "chain": fx_n_sa["chain"]},
        "ADMIT",
        None,
        "H-24: standalone verify_notary_act() verifies 0x04 anchor and notary link.notary role.",
    )

    # =========================================================================
    # B-5 & R3-B3: binding_seal Spend + h_origin < h_firstupdate
    # =========================================================================
    of_b5_unspent = rm._base_origin_fixture()
    bseal_txid = of_b5_unspent["origin_bundle"]["origin"]["payload"]["binding_seal"]["txid"]
    of_b5_unspent["chain"]["txs"][bseal_txid]["outputs"]["0"].pop("spent_by_txid", None)
    of_b5_unspent["chain"]["txs"][of_b5_unspent["origin_bundle"]["name_binding_txid"]]["inputs"] = [sv.make_segwit_input(_h32("random-attacker-utxo"), 0)]
    add(
        "d7-b05-unspent-binding-seal-forged-0x0c-refuse",
        ["SL-ORIG-003"],
        "origin_status",
        {"origin_bundle": of_b5_unspent["origin_bundle"], "chain": of_b5_unspent["chain"], "trusted_origin_issuer_pins": of_b5_unspent["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "PR #1 B-5 closed: initial 0x0c name-binding anchored WITHOUT spending origin.binding_seal MUST refuse ORIGIN_BINDING_INVALID.",
    )

    of_b5_pre = rm._base_origin_fixture()
    of_b5_pre["chain"]["names"]["id/child-leo"]["updates"][0]["confirmed_height"] = 748999  # < h_origin 749000!
    add(
        "d7-r3b3-firstupdate-before-origin-refuse",
        ["SL-ORIG-003"],
        "origin_status",
        {"origin_bundle": of_b5_pre["origin_bundle"], "chain": of_b5_pre["chain"], "trusted_origin_issuer_pins": of_b5_pre["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "R3-B3 closed: ward name FIRSTUPDATE height <= h_origin MUST refuse ORIGIN_BINDING_INVALID.",
    )

    # =========================================================================
    # B-6 & H-24: recipient_rule (exact_key, exact_name, member_class + seallink-members-list/1)
    # =========================================================================
    fx_b6_ek = rm._delegation_fx()
    pp_ek = copy.deepcopy(fx_b6_ek["bundle"]["grants"][0]["payload"])
    pp_ek["delegate"]["groups"][0]["template"]["recipient_rule"] = {"key": _kp("d7-b6-other-key")["xonly"], "mode": "exact_key"}
    p_ek = sl.sign_envelope(pp_ek, [fx_b6_ek["_keys"]["alice_gr"]["sk"]])
    pid_ek = sl.object_id(pp_ek)
    fx_b6_ek["chain"]["txs"][_h32("p-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_ek), "grant_id": pid_ek, "type": "seallink-issuance/1"}).hex()
    ).hex()
    cp_ek = copy.deepcopy(fx_b6_ek["bundle"]["grants"][1]["payload"])
    cp_ek["parent"]["grant_id"] = pid_ek
    c_ek = sl.sign_envelope(cp_ek, [fx_b6_ek["_del_k"]["sk"]])
    cid_ek = sl.object_id(cp_ek)
    fx_b6_ek["chain"]["txs"][_h32("c-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(
        0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_ek), "grant_id": cid_ek, "type": "seallink-issuance/1"}).hex()
    ).hex()
    fx_b6_ek["bundle"]["grants"] = [p_ek, c_ek]
    inv_ek = copy.deepcopy(fx_b6_ek["invocation"]["payload"])
    inv_ek["proof_path"] = [{"grant_id": pid_ek, "issuance_txid": _h32("p-iss-tx")}, {"grant_id": cid_ek, "issuance_txid": _h32("c-iss-tx")}]
    fx_b6_ek["invocation"] = sl.sign_envelope(inv_ek, [fx_b6_ek["_keys"]["agent_req"]["sk"]])
    add(
        "d7-b06-exact-key-mismatch-refuse",
        ["SL-GRNT-010"],
        "invocation",
        fx_b6_ek,
        "REFUSE",
        "GRANT_CHILD_WIDER",
        "PR #1 B-6 closed: child recipient key mismatching template.recipient_rule.exact_key MUST refuse GRANT_CHILD_WIDER.",
    )

    # member_class positive + negative (exercises seallink-members-list/1!)
    def _member_class_fx(*, include_bob: bool = True) -> dict[str, Any]:
        fx_mc = rm._delegation_fx()
        bob_own, bob_req = _kp("d7-mc-bob-own"), _kp("d7-mc-bob-req")
        bob_opol = {"kind": "key", "pk": bob_own["comp"]}
        bob_reg = {"txid": _h32("d7-mc-bob-reg"), "vout": 0}
        bob_seal_pol = {"kind": "key", "pk": _kp("d7-mc-bob-seal")["comp"]}
        bob_seal_tx = _h32("d7-mc-bob-seal-tx")
        fx_mc["chain"]["txs"][bob_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(bob_seal_pol)}}}
        fx_mc["chain"]["names"]["id/bob-member"] = sv.make_name_history(
            "id/bob-member", bob_reg, bob_opol, {"nostr": bob_req["xonly"]}, first_height=748000, update_height=749000
        )
        entries = []
        if include_bob:
            entries.append({"name": "id/bob-member", "owner_policy": bob_opol, "registration": bob_reg, "seal": {"script_policy": bob_seal_pol, "txid": bob_seal_tx, "vout": 0}})
        mlist = {"entries": entries, "network": "main", "owner": "id/alice", "seq": 1, "type": "seallink-members-list/1"}
        al_man = copy.deepcopy(fx_mc["_alice_man"])
        al_man["sets"] = {"members": {"seq": 1, "sha256": sl.content_addr(mlist)}}
        al_man_h = sl.content_addr(al_man)
        fx_mc["chain"]["manifests"][al_man_h] = al_man
        fx_mc["bundle"]["manifests"][al_man_h] = al_man
        fx_mc["bundle"]["members_lists"] = {sl.content_addr(mlist): mlist}
        fx_mc["chain"]["names"]["id/alice"] = sv.make_name_history(
            "id/alice", fx_mc["_alice_reg"], fx_mc["_alice_owner_pol"],
            {"link": {"grant": fx_mc["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al_man_h, "s": 1}},
        )
        pp_mc = copy.deepcopy(fx_mc["bundle"]["grants"][0]["payload"])
        pp_mc["delegate"]["groups"][0]["template"]["recipient_rule"] = {
            "mode": "member_class",
            "operators": [{"name": "id/alice", "owner_policy": fx_mc["_alice_owner_pol"], "registration": fx_mc["_alice_reg"]}],
        }
        p_mc = sl.sign_envelope(pp_mc, [fx_mc["_keys"]["alice_gr"]["sk"]])
        pid_mc = sl.object_id(pp_mc)
        fx_mc["chain"]["txs"][_h32("p-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(
            0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_mc), "grant_id": pid_mc, "type": "seallink-issuance/1"}).hex()
        ).hex()
        cp_mc = copy.deepcopy(fx_mc["bundle"]["grants"][1]["payload"])
        cp_mc["parent"]["grant_id"] = pid_mc
        cp_mc["recipient"] = {"mode": "name", "name": "id/bob-member", "owner_policy": bob_opol, "registration": bob_reg}
        c_mc = sl.sign_envelope(cp_mc, [fx_mc["_del_k"]["sk"]])
        cid_mc = sl.object_id(cp_mc)
        fx_mc["chain"]["txs"][_h32("c-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(
            0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_mc), "grant_id": cid_mc, "type": "seallink-issuance/1"}).hex()
        ).hex()
        fx_mc["bundle"]["grants"] = [p_mc, c_mc]
        inv_mc = copy.deepcopy(fx_mc["invocation"]["payload"])
        inv_mc["proof_path"] = [{"grant_id": pid_mc, "issuance_txid": _h32("p-iss-tx")}, {"grant_id": cid_mc, "issuance_txid": _h32("c-iss-tx")}]
        fx_mc["invocation"] = sl.sign_envelope(inv_mc, [bob_req["sk"]])
        return fx_mc

    add(
        "d7-b06-member-class-valid-members-list-admit",
        ["SL-GRNT-010", "SL-IDEN-006"],
        "invocation",
        _member_class_fx(include_bob=True),
        "ADMIT",
        None,
        "B-6 & H-24: child grant under recipient_rule.member_class backed by manifest-pinned seallink-members-list/1 with unspent entry seal admits.",
    )
    add(
        "d7-b06-member-class-absent-member-refuse",
        ["SL-GRNT-010", "SL-IDEN-006"],
        "invocation",
        _member_class_fx(include_bob=False),
        "REFUSE",
        "GRANT_CHILD_WIDER",
        "B-6: child recipient absent from manifest-pinned seallink-members-list/1 MUST refuse GRANT_CHILD_WIDER.",
    )

    # =========================================================================
    # B-7, R1-A, H-8: Two-Phase Atomic Journal, Late Real Receipt, Witness-Verified Replay
    # =========================================================================
    fx_tp = rm._base_invocation_fixture()
    inv_tp_id = sl.object_id(fx_tp["invocation"]["payload"])
    gid_tp = sl.object_id(fx_tp["bundle"]["grants"][0]["payload"])
    rcpt_tp = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": fx_tp["executor_cfg"]["name"],
            "genesis": GENESIS_MAIN,
            "grant_id": gid_tp,
            "invocation_id": inv_tp_id,
            "network": "main",
            "outcome": "executed",
            "recorded_at": fx_tp["chain"]["now"],
            "result_sha256": _h32("d7-tp-real-result"),
            "tip_hash": fx_tp["chain"]["tip_hash"],
            "tip_height": fx_tp["chain"]["tip_height"],
            "type": "seallink-receipt/1",
        },
        [fx_tp["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d7-r1a-two-phase-late-receipt-restart-idempotent-admit",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "two_phase_commit",
        {
            "journal_id": _h32("d7-tp-j1"),
            "chain": fx_tp["chain"],
            "invocation": fx_tp["invocation"],
            "bundle": fx_tp["bundle"],
            "executor_cfg": fx_tp["executor_cfg"],
            "actual_message_meta": {"folder": "Invoices"},
            "receipt_env": rcpt_tp,
            "expect_cached_receipt_ca": sl.content_addr(rcpt_tp),
        },
        "ADMIT",
        None,
        "R1-A closed: admit_and_reserve() -> execute -> commit_result(real_receipt) -> witness-verified restart returns exact content_addr(real_receipt) with 0 writes.",
    )
    add(
        "d7-r1a-retry-while-unsettled-returns-uncertain",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "two_phase_commit",
        {
            "journal_id": _h32("d7-tp-j2"),
            "chain": fx_tp["chain"],
            "invocation": fx_tp["invocation"],
            "bundle": fx_tp["bundle"],
            "executor_cfg": fx_tp["executor_cfg"],
            "actual_message_meta": {"folder": "Invoices"},
            "retry_before_commit": True,
        },
        "UNCERTAIN",
        None,
        "R1-A: retrying an invocation after admit_and_reserve() before commit_result() MUST return UNCERTAIN with 0 writes (never double-execute).",
    )
    add(
        "d7-b07-missing-receipt-blob-on-restart-refuses-replay",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "two_phase_commit",
        {
            "journal_id": _h32("d7-tp-j3"),
            "chain": fx_tp["chain"],
            "invocation": fx_tp["invocation"],
            "bundle": fx_tp["bundle"],
            "executor_cfg": fx_tp["executor_cfg"],
            "actual_message_meta": {"folder": "Invoices"},
            "receipt_env": rcpt_tp,
            "drop_receipt_blob_on_restart": True,
        },
        "REFUSE",
        "INVOKE_REPLAY",
        "PR #1 B-7 closed: terminal settlement whose receipt blob is missing from receipt_store after restart MUST refuse INVOKE_REPLAY (never re-execute).",
    )
    # Forged receipt signed by wrong key in commit_result -> WIRE_SIGNATURE
    rcpt_forged = sl.sign_envelope(rcpt_tp["payload"], [_kp("d7-forged-rcpt")["sk"]])
    add(
        "d7-r1a-commit-result-wrong-receipt-key-refuse",
        ["SL-GRNT-014", "SL-WIRE-013"],
        "two_phase_commit",
        {
            "journal_id": _h32("d7-tp-j4"),
            "chain": fx_tp["chain"],
            "invocation": fx_tp["invocation"],
            "bundle": fx_tp["bundle"],
            "executor_cfg": fx_tp["executor_cfg"],
            "actual_message_meta": {"folder": "Invoices"},
            "receipt_env": rcpt_forged,
        },
        "REFUSE",
        "WIRE_SIGNATURE",
        "R1-A: commit_result() MUST verify receipt_env signature against executor.key before persisting or appending settlement.",
    )
    # Nonce reuse on quota-bearing path with distinct invocation payload -> INVOKE_REPLAY
    fx_qnr = rm._base_invocation_fixture()
    gp_qnr = copy.deepcopy(fx_qnr["bundle"]["grants"][0]["payload"])
    gp_qnr["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "10", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    _reanchor(fx_qnr, gp_qnr)
    inv_qnr_1 = fx_qnr["invocation"]
    inv_qnr_2 = sl.sign_envelope({**inv_qnr_1["payload"], "arguments": {"folder": "Invoices", "message_id": "msg-different"}}, [fx_qnr["_keys"]["agent_req"]["sk"]])
    add(
        "d7-b07-nonce-reuse-on-quota-path-refuse",
        ["SL-GRNT-007"],
        "sibling_rows_replay",
        {
            "chain": fx_qnr["chain"],
            "journal": {"journal_id": _h32("d7-qnr-j")},
            "executor_cfg": fx_qnr["executor_cfg"],
            "steps": [
                {"label": "first-quota-call", "invocation": inv_qnr_1, "bundle": fx_qnr["bundle"], "actual_message_meta": {"folder": "Invoices"}, "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "reused-nonce-diff-inv", "invocation": inv_qnr_2, "bundle": fx_qnr["bundle"], "actual_message_meta": {"folder": "Invoices"}, "want_verdict": "REFUSE", "want_refusal": "INVOKE_REPLAY"},
            ],
            "check_balances": [],
        },
        "ADMIT",
        None,
        "PR #1 B-7 closed: reusing a nonce across two distinct invocations on a quota-bearing grant MUST refuse INVOKE_REPLAY.",
    )
    # H-8: Witness-verified replay refuses tampered log (JOURNAL_LOST) and fenced write token (JOURNAL_FENCED) without AssertionError!
    j_tmp = sv.FencedJournal(_h32("d7-h8-j"))
    j_tmp.append("nonce", {"expires_at": 1795220300, "invocation_id": _h32("i1"), "nonce": _h32("n1"), "scope": "invocation"})
    tampered_entries = copy.deepcopy(j_tmp.entries)
    tampered_entries[0]["prev_commitment"] = _h32("corrupted-prev")
    add(
        "d7-h08-replay-tampered-journal-refuses-journal-lost",
        ["SL-GRNT-014"],
        "replay_journal_tamper",
        {"journal_id": j_tmp.journal_id, "entries": tampered_entries, "witness_pos": j_tmp.witness_pos, "witness_commitment": j_tmp.witness_commitment},
        "REFUSE",
        "JOURNAL_LOST",
        "H-8: witness-verified replay_persisted_entries_checked() refuses broken hash-chain links with JOURNAL_LOST (zero assert crashes).",
    )
    add(
        "d7-h08-replay-fenced-write-token-refuses-journal-fenced",
        ["SL-GRNT-014"],
        "replay_journal_tamper",
        {"journal_id": j_tmp.journal_id, "entries": copy.deepcopy(j_tmp.entries), "witness_pos": j_tmp.witness_pos, "witness_commitment": j_tmp.witness_commitment, "write_token_active": False},
        "REFUSE",
        "JOURNAL_FENCED",
        "H-8: witness-verified replay with superseded write_token MUST refuse JOURNAL_FENCED.",
    )

    # =========================================================================
    # B-8: Mandatory Action Quotas (mail/send requires messages quota)
    # =========================================================================
    fx_b8 = rm._base_invocation_fixture()
    gp_b8 = copy.deepcopy(fx_b8["bundle"]["grants"][0]["payload"])
    gp_b8["capabilities"] = [{"action": "mail/send", "target": "mailbox:id/alice:work"}]
    _reanchor(fx_b8, gp_b8)
    inv_b8 = copy.deepcopy(fx_b8["invocation"]["payload"])
    inv_b8["action"] = "mail/send"
    inv_b8["arguments"] = {"body_sha256": _h32("b8-body"), "size_bytes": "12", "subject": "hi", "to": "bob@example.org"}
    fx_b8["invocation"] = sl.sign_envelope(inv_b8, [fx_b8["_keys"]["agent_req"]["sk"]])
    add(
        "d7-b08-quota-consuming-action-missing-required-quota-refuse",
        ["SL-MAIL-001", "SL-GRNT-007"],
        "invocation",
        fx_b8,
        "REFUSE",
        "QUOTA_EXCEEDED",
        "PR #1 B-8 closed: mail/send grant lacking mandatory seallink/count|messages quota MUST refuse QUOTA_EXCEEDED.",
    )

    # =========================================================================
    # B-9: Transfer-Written Value Refusal (NAME_WRITER_UNVERIFIED) on Name, Issuer & Named Recipient
    # =========================================================================
    fx_b9 = rm._base_invocation_fixture()
    new_al_own = _kp("d7-b9-new-al-own")
    new_al_pol = {"kind": "key", "pk": new_al_own["comp"]}
    new_al_spk, _ = sl.compile_script_policy(new_al_pol)
    prev_al_u = fx_b9["chain"]["names"]["id/alice"]["updates"][-1]
    # Transfer from old owner -> new owner, signed by outgoing old owner while writing a fresh grant key!
    xfer_gr = _kp("d7-b9-xfer-gr")
    xfer_val = sl.jcs_encode({"link": {"grant": xfer_gr["xonly"]}})
    fx_b9["chain"]["names"]["id/alice"]["updates"].append({
        "confirmed_height": 749500,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", new_al_spk, name=b"id/alice", value=xfer_val).hex(),
        "owner_policy": new_al_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": prev_al_u["txid"], "vout": prev_al_u["vout"], "witness_policy": prev_al_u["owner_policy"]},
        "txid": _h32("d7-b9-xfer-tx"),
        "vout": 0,
    })
    add(
        "d7-b09-transfer-written-value-refuses-writer-unverified",
        ["SL-LDGR-005", "SL-IDEN-002"],
        "name_resolve",
        {"name": "id/alice", "expected_owner_policy": new_al_pol, "expected_registration": fx_b9["_alice_reg"], "chain": fx_b9["chain"]},
        "REFUSE",
        "NAME_WRITER_UNVERIFIED",
        "PR #1 B-9 closed: name value written by departing outgoing owner in a transfer tx MUST refuse NAME_WRITER_UNVERIFIED.",
    )

    # =========================================================================
    # B-10, R3-B5, D-5, R1-C: Contracts, IssuancePrep, MachineClauseTerms, Anchor-Time Freshness, Multi-Ward
    # =========================================================================
    fx_b10 = rm._contract_fx()
    add(
        "d7-b10-issuance-prep-without-assent-addrs-admit",
        ["SL-CONT-002", "SL-CONT-003"],
        "invocation",
        fx_b10,
        "ADMIT",
        None,
        "PR #1 B-10 decision: IssuancePrep without dead assent_content_addrs commits cleanly to 0x07 and admits.",
    )
    # R3-B5: Grant capability wider than disclosed MachineClauseTerms -> CONTRACT_TERMS_MISMATCH
    fx_b5_w = rm._contract_fx()
    fx_b5_w["bundle"]["disclosed_clauses"]["0"]["clause"]["machine_terms"]["capabilities"] = [
        {"action": "agent/session", "target": "station:id/station-a:other-slot", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "station:id/station-a:other-slot", "unit": "starts", "window": "term"}]}
    ]
    c_w = copy.deepcopy(fx_b5_w["bundle"]["contract"])
    c_w["clause_commitments"][0] = sl.clause_commit(fx_b5_w["bundle"]["disclosed_clauses"]["0"]["salt_hex"], fx_b5_w["bundle"]["disclosed_clauses"]["0"]["clause"])
    cid_w = sl.object_id(c_w)
    fx_b5_w["bundle"]["contract"] = c_w
    a1_w = sl.sign_envelope({**fx_b5_w["bundle"]["contract_assents"][0]["payload"], "target_id": cid_w}, [fx_b5_w["_keys"]["alice_gr"]["sk"]])
    a2_w = sl.sign_envelope({**fx_b5_w["bundle"]["contract_assents"][1]["payload"], "target_id": cid_w}, [fx_b5_w["_keys"]["agent_req"]["sk"]])
    fx_b5_w["bundle"]["contract_assents"] = [a1_w, a2_w]
    gp_w = copy.deepcopy(fx_b5_w["bundle"]["grants"][0]["payload"])
    gp_w["contract_id"] = cid_w
    rm._reanchor_grant(fx_b5_w, gp_w)
    add(
        "d7-r3b5-grant-wider-than-machine-clause-terms-refuse",
        ["SL-CONT-004"],
        "invocation",
        fx_b5_w,
        "REFUSE",
        "CONTRACT_TERMS_MISMATCH",
        "R3-B5 closed: grant capability not narrowed from disclosed ClauseObject.machine_terms MUST refuse CONTRACT_TERMS_MISMATCH.",
    )

    # R1-C: Multi-ward contract with TWO distinct ward origins resolved via origin_bundles_by_oid!
    of_w1 = rm._base_origin_fixture()
    of_w2 = rm._base_origin_fixture()
    # Give ward 2 a distinct origin_id & name id/child-mia (by varying claims.note + name + keys)
    op_w1 = copy.deepcopy(of_w1["origin_bundle"]["origin"]["payload"])
    op_w1["guardian_policy"]["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 1}
    op_w1["guardian_policy"]["quorums"]["contract_assent"] = {"den": 2, "min": 1, "num": 1}
    o_w1 = sl.sign_envelope(op_w1, [of_w1["_keys"]["reg_cred"]["sk"]])
    oid_w1 = sl.object_id(op_w1)
    of_w1["origin_bundle"]["origin"] = o_w1
    of_w1["origin_bundle"]["name_binding"]["origin_id"] = oid_w1
    g1_w1_p = {**of_w1["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_w1}
    g1_w1 = sl.sign_envelope(g1_w1_p, [of_w1["_keys"]["reg_cred"]["sk"]])
    of_w1["origin_bundle"]["guardian_records"] = [g1_w1]
    of_w1["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**of_w1["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(g1_w1_p)}, [of_w1["_keys"]["g1_gr"]["sk"]])]
    of_w1["chain"]["txs"][of_w1["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_w1)).hex()
    of_w1["chain"]["txs"][of_w1["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_w1["origin_bundle"]["name_binding"])).hex()
    of_w1["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_w1)).hex()
    of_w1["chain"]["names"]["id/child-leo"] = sv.make_name_history(
        "id/child-leo", of_w1["origin_bundle"]["name_binding"]["registration"], of_w1["origin_bundle"]["name_binding"]["owner_policy"],
        {"link": {"grant": of_w1["_keys"]["ward_gr"]["xonly"], "origin": oid_w1}}, first_height=749005, update_height=749010,
    )

    # Distinct ward 2 (id/child-mia) on fresh txids!
    w2_bseal_tx, w2_sseal_tx, w2_rseal_tx, w2_rost_tx, w2_v1_tx, w2_v2_tx = (_h32(f"mw2-{k}") for k in ("bs", "ss", "rs", "ros", "v1", "v2"))
    w2_o_tx, w2_nb_tx, w2_g1_tx = _h32("mw2-otx"), _h32("mw2-nbtx"), _h32("mw2-g1tx")
    w2_reg = {"txid": _h32("mw2-reg"), "vout": 0}
    op_w2 = copy.deepcopy(op_w1)
    op_w2["claims"]["intended_name"] = "id/child-mia"
    op_w2["binding_seal"]["txid"] = w2_bseal_tx
    op_w2["status_seal"]["txid"] = w2_sseal_tx
    op_w2["name_recovery"]["recovery_seal"]["txid"] = w2_rseal_tx
    op_w2["guardian_policy"]["roster_seal"]["txid"] = w2_rost_tx
    op_w2["guardian_policy"]["slots"][0]["vacant_utxo"]["txid"] = w2_v1_tx
    op_w2["guardian_policy"]["slots"][1]["vacant_utxo"]["txid"] = w2_v2_tx
    o_w2 = sl.sign_envelope(op_w2, [of_w1["_keys"]["reg_cred"]["sk"]])
    oid_w2 = sl.object_id(op_w2)
    nb_w2 = {**copy.deepcopy(of_w1["origin_bundle"]["name_binding"]), "name": "id/child-mia", "origin_id": oid_w2, "registration": w2_reg}
    g1_w2_p = {**copy.deepcopy(g1_w1_p), "origin_id": oid_w2, "prev_outpoint": {"txid": w2_v1_tx, "vout": 0}}
    g1_w2 = sl.sign_envelope(g1_w2_p, [of_w1["_keys"]["reg_cred"]["sk"]])
    ga1_w2 = sl.sign_envelope({**of_w1["origin_bundle"]["guardian_assents"][0]["payload"], "nonce": _h32("mw2-ga1"), "target_id": sl.object_id(g1_w2_p)}, [of_w1["_keys"]["g1_gr"]["sk"]])
    ch_mw = copy.deepcopy(of_w1["chain"])
    ch_mw["names"]["id/child-mia"] = sv.make_name_history(
        "id/child-mia", w2_reg, nb_w2["owner_policy"],
        {"link": {"grant": _kp("mw2-ward-gr")["xonly"], "origin": oid_w2}}, first_height=749005, update_height=749010,
    )
    ch_mw["txs"][w2_bseal_tx] = {"confirmed_height": 748990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(op_w2["binding_seal"]["script_policy"]), "spent_by_txid": w2_nb_tx}}}
    ch_mw["txs"][w2_sseal_tx] = {"confirmed_height": 748990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(op_w2["status_seal"]["script_policy"])}}}
    ch_mw["txs"][w2_rseal_tx] = {"confirmed_height": 748990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(op_w2["name_recovery"]["recovery_seal"]["script_policy"])}}}
    ch_mw["txs"][w2_rost_tx] = {"confirmed_height": 748990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(op_w2["guardian_policy"]["roster_seal"]["script_policy"])}}}
    ch_mw["txs"][w2_v1_tx] = {"confirmed_height": 748990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(op_w2["guardian_policy"]["roster_seal"]["script_policy"]), "spent_by_txid": w2_g1_tx}}}
    ch_mw["txs"][w2_v2_tx] = {"confirmed_height": 748990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(op_w2["guardian_policy"]["roster_seal"]["script_policy"])}}}
    ch_mw["txs"][w2_o_tx] = {"confirmed_height": 749000, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(o_w2)).hex(), "outputs": {}}
    ch_mw["txs"][w2_nb_tx] = {"confirmed_height": 749010, "inputs": [sv.make_segwit_input(w2_bseal_tx, 0)], "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(nb_w2)).hex(), "outputs": {}}
    ch_mw["txs"][w2_g1_tx] = {"confirmed_height": 749100, "inputs": [sv.make_segwit_input(w2_v1_tx, 0)], "opreturn_hex": sl.encode_opreturn(0x12, sl.content_addr(g1_w2)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(g1_w2_p["active_policy"])}}}
    ob_w2 = {
        "guardian_assents": [ga1_w2],
        "guardian_records": [g1_w2],
        "initial_guardian_disclosures": copy.deepcopy(of_w1["origin_bundle"]["initial_guardian_disclosures"]),
        "name_binding": nb_w2,
        "name_binding_txid": w2_nb_tx,
        "opened_majority_unix": of_w1["origin_bundle"]["opened_majority_unix"],
        "majority_salt_hex": of_w1["origin_bundle"]["majority_salt_hex"],
        "origin": o_w2,
        "origin_anchor_txid": w2_o_tx,
    }
    c_mw = copy.deepcopy(of_w1["contract"])
    c_mw["parties"] = [
        {"name_pin": {"name": "id/child-leo", "owner_policy": of_w1["origin_bundle"]["name_binding"]["owner_policy"], "registration": of_w1["origin_bundle"]["name_binding"]["registration"]}, "party_id": "ward-1", "role": "participant_a", "ward_origin_id": oid_w1},
        {"name_pin": {"name": "id/child-mia", "owner_policy": nb_w2["owner_policy"], "registration": w2_reg}, "party_id": "ward-2", "role": "participant_b", "ward_origin_id": oid_w2},
    ]
    cid_mw = sl.object_id(c_mw)
    ass_w1 = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": oid_w1, "revision": 1, "ward_name": "id/child-leo"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("mw-a1"), "party_id": "ward-1", "party_name": "id/child-leo", "party_role": "participant_a",
         "target_id": cid_mw, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [of_w1["_keys"]["g1_gr"]["sk"]]}],
    )
    ass_w2 = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": oid_w2, "revision": 1, "ward_name": "id/child-mia"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("mw-a2"), "party_id": "ward-2", "party_name": "id/child-mia", "party_role": "participant_b",
         "target_id": cid_mw, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [of_w1["_keys"]["g1_gr"]["sk"]]}],
    )
    add(
        "d7-r1c-multi-ward-contract-assents-admit",
        ["SL-CONT-002", "SL-ORIG-005"],
        "contract_assents",
        {
            "contract": c_mw,
            "assents": [ass_w1, ass_w2],
            "origin_bundles_by_oid": {oid_w1: of_w1["origin_bundle"], oid_w2: ob_w2},
            "chain": ch_mw,
            "trusted_origin_issuer_pins": of_w1["trusted_origin_issuer_pins"],
            "anchor_time": 1795220100,
        },
        "ADMIT",
        None,
        "R1-C closed: verify_contract_assents() resolves distinct ward parties via origin_bundles_by_oid and admits.",
    )
    add(
        "d7-r1c-multi-ward-missing-second-bundle-refuse",
        ["SL-CONT-002", "SL-ORIG-005"],
        "contract_assents",
        {
            "contract": c_mw,
            "assents": [ass_w1, ass_w2],
            "origin_bundles_by_oid": {oid_w1: of_w1["origin_bundle"]},
            "chain": ch_mw,
            "trusted_origin_issuer_pins": of_w1["trusted_origin_issuer_pins"],
            "anchor_time": 1795220100,
        },
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "R1-C: multi-ward contract missing the second ward's origin_bundle MUST refuse ORIGIN_UNVERIFIED.",
    )
    add(
        "d7-b10-assent-freshness-past-72h-at-anchor-time-refuse",
        ["SL-CONT-002"],
        "contract_assents",
        {
            "contract": c_mw,
            "assents": [ass_w1, ass_w2],
            "origin_bundles_by_oid": {oid_w1: of_w1["origin_bundle"], oid_w2: ob_w2},
            "chain": ch_mw,
            "trusted_origin_issuer_pins": of_w1["trusted_origin_issuer_pins"],
            "anchor_time": 1795220000 + 259201,  # > 72h after issued_at!
        },
        "REFUSE",
        "CONTRACT_ASSENT_INVALID",
        "B-10: assent issued > 72 hours (259200s) before 0x07 anchor_time MUST refuse CONTRACT_ASSENT_INVALID.",
    )

    # =========================================================================
    # B-11 & R3-B6: Deterministic x-seallink-refusal Precedence & Cofactorless Ed25519
    # =========================================================================
    gp_b11_md = copy.deepcopy(fx_b1_ctrl["bundle"]["grants"][0]["payload"])
    gp_b11_md["min_depth"] = 145
    add(
        "d7-b11-min-depth-145-refuses-wire-integer",
        ["SL-WIRE-008"],
        "raw_wire",
        {"object": sl.sign_envelope(gp_b11_md, [fx_b1_ctrl["_keys"]["alice_gr"]["sk"]])},
        "REFUSE",
        "WIRE_INTEGER",
        "PR #1 B-11 closed: RootGrant with min_depth=145 (> 144) MUST refuse WIRE_INTEGER (not WIRE_MEMBER).",
    )
    gp_b11_rk = copy.deepcopy(fx_b1_ctrl["bundle"]["grants"][0]["payload"])
    gp_b11_rk["recipient"] = {"key": "ff" * 32, "mode": "key"}
    add(
        "d7-b11-off-curve-recipient-key-refuses-wire-key",
        ["SL-WIRE-011"],
        "raw_wire",
        {"object": sl.sign_envelope(gp_b11_rk, [fx_b1_ctrl["_keys"]["alice_gr"]["sk"]])},
        "REFUSE",
        "WIRE_KEY",
        "PR #1 B-11 closed: off-curve secp256k1 recipient.key MUST refuse WIRE_KEY at wire layer.",
    )
    # R3-B6: Small-order Ed25519 public key (identity point 0100..00) in DeviceList -> WIRE_KEY
    dl_small_ord = {
        "devices": [{
            "alg": "ed25519",
            "ceiling": 1,
            "key": "01" + ("00" * 31),
            "label": "bad-small-order",
            "presence": True,
            "seal": {"script_policy": {"kind": "key", "pk": fx_b1_ctrl["_keys"]["alice_own"]["comp"]}, "txid": _h32("so-seal"), "vout": 0},
        }],
        "network": "main",
        "owner": "id/alice",
        "seq": 1,
        "type": "seallink-device-list/1",
    }
    add(
        "d7-r3b6-ed25519-small-order-point-refuses-wire-key",
        ["SL-WIRE-011", "SL-WIRE-012"],
        "raw_wire",
        {"object": dl_small_ord},
        "REFUSE",
        "WIRE_KEY",
        "R3-B6 closed: Ed25519 identity/small-order public key in DeviceList MUST refuse WIRE_KEY.",
    )

    # =========================================================================
    # B-12: Stripped link.origin Still Detected from Name History
    # =========================================================================
    fx_b12 = rm._base_invocation_fixture()
    al_u = fx_b12["chain"]["names"]["id/alice"]["updates"]
    # First update carried link.origin, second update stripped it!
    al_u[1]["output_script_hex"] = sl.encode_name_output(
        "NAME_UPDATE",
        sl.compile_script_policy(fx_b12["_alice_owner_pol"])[0],
        name=b"id/alice",
        value=sl.jcs_encode({"link": {"grant": fx_b12["_keys"]["alice_gr"]["xonly"], "origin": _h32("d7-b12-ward-oid")}}),
    ).hex()
    al_u.append({
        "confirmed_height": 749500,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output(
            "NAME_UPDATE",
            sl.compile_script_policy(fx_b12["_alice_owner_pol"])[0],
            name=b"id/alice",
            value=sl.jcs_encode({"link": {"grant": fx_b12["_keys"]["alice_gr"]["xonly"]}}),
        ).hex(),
        "owner_policy": fx_b12["_alice_owner_pol"],
        "prev_input": {"sighash_bytes": [0x01], "txid": al_u[1]["txid"], "vout": 0, "witness_policy": fx_b12["_alice_owner_pol"]},
        "txid": _h32("d7-b12-strip-tx"),
        "vout": 0,
    })
    add(
        "d7-b12-stripped-link-origin-detected-in-history-refuse",
        ["SL-ORIG-005", "SL-IDEN-002"],
        "invocation",
        fx_b12,
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "PR #1 B-12 closed: stripping link.origin in a later NAME_UPDATE MUST NOT turn a ward into an autonomous issuer.",
    )

    # =========================================================================
    # B-13 & D-2: Unsalted opened_majority_unix Ignored, Path A/B Emancipation, Former Guardian Lockout
    # =========================================================================
    of_b13_ag = rm._base_origin_fixture()
    op_ag = copy.deepcopy(of_b13_ag["origin_bundle"]["origin"]["payload"])
    op_ag["origin_class"] = "agent"
    op_ag["claims"].pop("majority_commitment", None)
    o_ag = sl.sign_envelope(op_ag, [of_b13_ag["_keys"]["reg_cred"]["sk"]])
    oid_ag = sl.object_id(op_ag)
    of_b13_ag["origin_bundle"]["origin"] = o_ag
    of_b13_ag["origin_bundle"]["name_binding"]["origin_id"] = oid_ag
    of_b13_ag["origin_bundle"]["opened_majority_unix"] = 1700000000  # Unauthenticated attacker-injected value in past!
    of_b13_ag["origin_bundle"].pop("majority_salt_hex", None)
    of_b13_ag["chain"]["txs"][of_b13_ag["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_ag)).hex()
    of_b13_ag["chain"]["txs"][of_b13_ag["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_b13_ag["origin_bundle"]["name_binding"])).hex()
    add(
        "d7-b13-unsalted-opened-majority-on-agent-ignored-stays-ward",
        ["SL-ORIG-011"],
        "origin_status",
        {"origin_bundle": of_b13_ag["origin_bundle"], "chain": of_b13_ag["chain"], "trusted_origin_issuer_pins": of_b13_ag["trusted_origin_issuer_pins"]},
        "ADMIT_WARD",
        None,
        "PR #1 B-13 closed: presenter-injected opened_majority_unix on agent origin without majority_commitment MUST be ignored (remains ward).",
    )

    # D-2: name_recovery.mode='none' forbidden when guardian_policy is present -> WIRE_MEMBER
    op_d2_bad = copy.deepcopy(of_b13_ag["origin_bundle"]["origin"]["payload"])
    op_d2_bad["name_recovery"] = {"mode": "none"}
    add(
        "d7-d2-guardian-policy-forbids-recovery-mode-none",
        ["SL-ORIG-013"],
        "raw_wire",
        {"object": sl.sign_envelope(op_d2_bad, [of_b13_ag["_keys"]["reg_cred"]["sk"]])},
        "REFUSE",
        "WIRE_MEMBER",
        "Decision D-2: origin/1 carrying guardian_policy MUST NOT set name_recovery.mode='none'.",
    )

    # =========================================================================
    # B-14 & B-15: Exact Authority Pinning & Roster Delay Hardening
    # =========================================================================
    of_b14 = rm._base_origin_fixture()
    rogue_own, rogue_cred = _kp("d7-b14-rogue-own"), _kp("d7-b14-rogue-cred")
    rogue_opol = {"kind": "key", "pk": rogue_own["comp"]}
    rogue_reg = {"txid": _h32("d7-b14-rogue-reg"), "vout": 0}
    of_b14["chain"]["names"]["id/rogue-registry"] = sv.make_name_history(
        "id/rogue-registry", rogue_reg, rogue_opol, {"link": {"cred": rogue_cred["xonly"]}}, first_height=748000, update_height=748500
    )
    stat_seal = of_b14["origin_bundle"]["origin"]["payload"]["status_seal"]
    end_rogue = sl.sign_envelope(
        {
            "basis_sha256": _h32("b14-basis"),
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": {"name": "id/rogue-registry", "owner_policy": rogue_opol, "registration": rogue_reg, "role_policy": {"m": 1, "pks": [rogue_cred["xonly"]]}},
            "network": "main",
            "origin_id": of_b14["_origin_id"],
            "reason": "death",
            "status_prev_outpoint": {"txid": stat_seal["txid"], "vout": 0},
            "type": "seallink-end/1",
        },
        [rogue_cred["sk"]],
    )
    end_rtx = _h32("d7-b14-end-tx")
    of_b14["chain"]["txs"][stat_seal["txid"]]["outputs"]["0"]["spent_by_txid"] = end_rtx
    of_b14["chain"]["txs"][end_rtx] = {"confirmed_height": 749950, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(end_rogue)).hex(), "outputs": {}}
    of_b14["origin_bundle"]["end_record"] = end_rogue
    add(
        "d7-b14-end-record-by-unrelated-issuer-refuse",
        ["SL-ORIG-012"],
        "origin_status",
        {
            "origin_bundle": of_b14["origin_bundle"],
            "chain": of_b14["chain"],
            "trusted_origin_issuer_pins": of_b14["trusted_origin_issuer_pins"] + [{"name": "id/rogue-registry", "owner_policy": rogue_opol, "registration": rogue_reg}],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "PR #1 B-14 closed: end/1 signed by unrelated trusted issuer (not origin.issuer) MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )

    # B-15: Roster with effective_delay_blocks < appointment_delay_blocks -> ORIGIN_STATUS_INCOMPLETE
    of_b15 = rm._base_origin_fixture()
    gp_b15 = of_b15["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    rost_short_p = {
        "arbiter_pk": gp_b15["arbiter_pk"],
        "challenger_pk": gp_b15["challenger_pk"],
        "disposer_pk": gp_b15["disposer_pk"],
        "effective_delay_blocks": 10,  # < appointment_delay_blocks (144)!
        "genesis": GENESIS_MAIN,
        "issuer": of_b15["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "next_roster_policy": gp_b15["roster_seal"]["script_policy"],
        "next_roster_vout": 0,
        "origin_id": of_b15["_origin_id"],
        "prev_revision": 1,
        "prev_roster_outpoint": {"txid": gp_b15["roster_seal"]["txid"], "vout": 0},
        "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in gp_b15["quorums"]},
        "revision": 2,
        "revision_size": 1,
        "slots": [{"action": "retain_active", "active_outpoint": {"txid": rm._h32("og1-init-0x12"), "vout": 0}, "guardian_id": sl.object_id(of_b15["origin_bundle"]["guardian_records"][0]["payload"]), "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    rost_short = sl.sign_envelope(rost_short_p, [of_b15["_keys"]["reg_cred"]["sk"]])
    rtx_short = _h32("d7-b15-rtx-short")
    of_b15["chain"]["txs"][gp_b15["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_short
    of_b15["chain"]["txs"][rtx_short] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_short)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(gp_b15["roster_seal"]["script_policy"])}}}
    of_b15["origin_bundle"]["roster_records"] = [rost_short]
    add(
        "d7-b15-roster-effective-delay-below-appointment-delay-refuse",
        ["SL-ORIG-015"],
        "origin_status",
        {"origin_bundle": of_b15["origin_bundle"], "chain": of_b15["chain"], "trusted_origin_issuer_pins": of_b15["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "PR #1 B-15 closed: guardian-roster/1 with effective_delay_blocks < appointment_delay_blocks MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )

    # =========================================================================
    # R3-B1: 0x02 Merkle Batch Root-Only (Forbidden on Depth-2 Child Grants)
    # =========================================================================
    fx_mb = rm._delegation_fx()
    c_env_mb = fx_mb["bundle"]["grants"][1]
    cid_mb = sl.object_id(c_env_mb["payload"])
    leaf_mb = sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_env_mb), "grant_id": cid_mb, "type": "seallink-issuance/1"}).hex()
    mroot_mb, mproofs_mb = sl.build_merkle_tree([leaf_mb])
    bp_mb = mproofs_mb[leaf_mb]
    fx_mb["chain"]["txs"][_h32("c-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(0x02, mroot_mb).hex()
    inv_mb_p = copy.deepcopy(fx_mb["invocation"]["payload"])
    inv_mb_p["proof_path"][1]["batch_proof"] = bp_mb
    fx_mb["invocation"] = sl.sign_envelope(inv_mb_p, [fx_mb["_keys"]["agent_req"]["sk"]])
    add(
        "d7-r3b1-merkle-batch-0x02-forbidden-on-child-grant-refuse",
        ["SL-GRNT-004", "SL-GRNT-009"],
        "invocation",
        fx_mb,
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "R3-B1 closed: 0x02 Merkle batch issuance (even with a cryptographically valid batch_proof) is root-grant-only and MUST refuse CHAIN_FRAME_INVALID on depth-2 child grants.",
    )

    # =========================================================================
    # Decision 6A (OQ-007): Native P2WSH m-of-n BranchKeySpec on Origin + Guardian
    # =========================================================================
    of_6a = rm._base_origin_fixture()
    d1, d2, d3 = _kp("6a-d1"), _kp("6a-d2"), _kp("6a-d3")
    a1, a2, a3 = _kp("6a-a1"), _kp("6a-a2"), _kp("6a-a3")
    c1, c2 = _kp("6a-c1"), _kp("6a-c2")
    disp_spec = {"m": 2, "pks": sorted([d1["comp"], d2["comp"], d3["comp"]])}
    arb_spec = {"m": 2, "pks": sorted([a1["comp"], a2["comp"], a3["comp"]])}
    chal_spec = {"m": 1, "pks": sorted([c1["comp"], c2["comp"]])}
    vac_6a = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp_spec, arb_spec)}
    rec_6a = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp_spec, arb_spec)}
    act_6a = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp_spec, _kp("6a-g1-seal")["comp"])}
    op_6a = copy.deepcopy(of_6a["origin_bundle"]["origin"]["payload"])
    op_6a["name_recovery"]["disposer_pk"] = disp_spec
    op_6a["name_recovery"]["arbiter_pk"] = arb_spec
    op_6a["name_recovery"]["recovery_seal"]["script_policy"] = rec_6a
    op_6a["guardian_policy"]["disposer_pk"] = disp_spec
    op_6a["guardian_policy"]["arbiter_pk"] = arb_spec
    op_6a["guardian_policy"]["challenger_pk"] = chal_spec
    op_6a["guardian_policy"]["roster_seal"]["script_policy"] = vac_6a
    o_6a = sl.sign_envelope(op_6a, [of_6a["_keys"]["reg_cred"]["sk"]])
    oid_6a = sl.object_id(op_6a)
    of_6a["origin_bundle"]["origin"] = o_6a
    of_6a["origin_bundle"]["name_binding"]["origin_id"] = oid_6a
    g1_6a_p = {**of_6a["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_6a, "active_policy": act_6a}
    g1_6a = sl.sign_envelope(g1_6a_p, [of_6a["_keys"]["reg_cred"]["sk"]])
    of_6a["origin_bundle"]["guardian_records"] = [g1_6a]
    of_6a["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**of_6a["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(g1_6a_p)}, [of_6a["_keys"]["g1_gr"]["sk"]])]
    of_6a["chain"]["txs"][op_6a["name_recovery"]["recovery_seal"]["txid"]]["outputs"]["0"]["script_pubkey_hex"] = _spk_hex(rec_6a)
    of_6a["chain"]["txs"][op_6a["guardian_policy"]["roster_seal"]["txid"]]["outputs"]["0"]["script_pubkey_hex"] = _spk_hex(vac_6a)
    for sl_s in op_6a["guardian_policy"]["slots"]:
        of_6a["chain"]["txs"][sl_s["vacant_utxo"]["txid"]]["outputs"]["0"]["script_pubkey_hex"] = _spk_hex(vac_6a)
    of_6a["chain"]["txs"][of_6a["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_6a)).hex()
    of_6a["chain"]["txs"][of_6a["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_6a["origin_bundle"]["name_binding"])).hex()
    of_6a["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_6a)).hex()
    of_6a["chain"]["txs"][rm._h32("og1-init-0x12")]["outputs"]["0"]["script_pubkey_hex"] = _spk_hex(act_6a)
    add(
        "d7-6a-branch-key-spec-native-p2wsh-2of3-admit",
        ["SL-LDGR-011", "SL-ORIG-005"],
        "origin_status",
        {"origin_bundle": of_6a["origin_bundle"], "chain": of_6a["chain"], "trusted_origin_issuer_pins": of_6a["trusted_origin_issuer_pins"]},
        "ADMIT_WARD",
        None,
        "Decision 6A (OQ-007): institutional 2-of-3 native P2WSH BranchKeySpec for disposer_pk/arbiter_pk/challenger_pk compiles and verifies end-to-end.",
    )

    # =========================================================================
    # Decision D-6 & R3-H8: Eternal Subject at h_anchor, subject.mode=origin, not_after_unix, 0x0a Withdrawal
    # =========================================================================
    cr_iss_own, cr_iss_k = _kp("d7-cr-iss-own"), _kp("d7-cr-iss-k")
    cr_iss_pol = {"kind": "key", "pk": cr_iss_own["comp"]}
    cr_iss_reg = {"txid": _h32("d7-cr-iss-reg"), "vout": 0}
    cr_sub_own = _kp("d7-cr-sub-own")
    cr_sub_pol = {"kind": "key", "pk": cr_sub_own["comp"]}
    cr_sub_reg = {"txid": _h32("d7-cr-sub-reg"), "vout": 0}
    ch_d6 = copy.deepcopy(fx_b1_ctrl["chain"])
    rm.sync_chain_tip(ch_d6, height=800000)
    ch_d6["names"]["id/uni-d6"] = sv.make_name_history("id/uni-d6", cr_iss_reg, cr_iss_pol, {"link": {"cred": cr_iss_k["xonly"]}}, first_height=740000, update_height=741000)
    # Subject id/grad-d6 was live at h_anchor=745000 (expires at 741000+36000=777000 < tip 800000!), expired by tip!
    ch_d6["names"]["id/grad-d6"] = sv.make_name_history("id/grad-d6", cr_sub_reg, cr_sub_pol, {"link": {"grant": _kp("d7-grad-gr")["xonly"]}}, first_height=740000, update_height=741000)
    ch_d6["names"]["id/grad-d6"]["expired"] = True
    ch_d6["names"]["id/grad-d6"]["expires_at_height"] = 777000
    cr_et_p = {
        "claims": {"degree": "MSc"},
        "credential_kind": "education/diploma-v1",
        "genesis": GENESIS_MAIN,
        "issued_at": 1795200000,
        "issuer": {"name": "id/uni-d6", "owner_policy": cr_iss_pol, "registration": cr_iss_reg, "role_policy": {"m": 1, "pks": [cr_iss_k["xonly"]]}},
        "lifecycle": "eternal",
        "network": "main",
        "not_before_height": 745000,
        "subject": {"mode": "name", "name_pin": {"name": "id/grad-d6", "owner_policy": cr_sub_pol, "registration": cr_sub_reg}},
        "type": "seallink-credential/1",
    }
    cr_et = sl.sign_envelope(cr_et_p, [cr_iss_k["sk"]])
    cr_et_tx = _h32("d7-d6-et-tx")
    ch_d6["txs"][cr_et_tx] = {"confirmed_height": 745000, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_et)).hex(), "outputs": {}}
    add(
        "d7-d6-eternal-credential-subject-name-pin-at-h-anchor-admit",
        ["SL-CONT-010"],
        "credential",
        {"credential": cr_et, "anchor_txid": cr_et_tx, "chain": ch_d6},
        "ADMIT",
        None,
        "Decision D-6: eternal credential subject.name_pin verified at h_anchor (745000) survives subsequent subject name expiry at tip (800000).",
    )

    # D-6: subject.mode="origin" verified against origin_bundle
    of_d6o = rm._base_origin_fixture()
    cr_orig_p = {
        "claims": {"status": "enrolled"},
        "credential_kind": "education/enrollment-v1",
        "genesis": GENESIS_MAIN,
        "issued_at": 1795200000,
        "issuer": of_d6o["origin_bundle"]["origin"]["payload"]["issuer"],
        "lifecycle": "eternal",
        "network": "main",
        "not_before_height": 749000,
        "subject": {"mode": "origin", "origin_id": of_d6o["_origin_id"]},
        "type": "seallink-credential/1",
    }
    cr_orig = sl.sign_envelope(cr_orig_p, [of_d6o["_keys"]["reg_cred"]["sk"]])
    cr_orig_tx = _h32("d7-d6-orig-tx")
    of_d6o["chain"]["txs"][cr_orig_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_orig)).hex(), "outputs": {}}
    add(
        "d7-d6-credential-subject-origin-mode-admit",
        ["SL-CONT-010", "SL-ORIG-002"],
        "credential",
        {"credential": cr_orig, "anchor_txid": cr_orig_tx, "chain": of_d6o["chain"], "origin_bundle": of_d6o["origin_bundle"], "trusted_origin_issuer_pins": of_d6o["trusted_origin_issuer_pins"]},
        "ADMIT",
        None,
        "Decision D-6: credential with subject.mode='origin' verifies against origin_bundle and admits.",
    )

    # R3-H8: not_after_unix expiry + 0x0a seallink-credential-withdrawal/1
    cr_uexp_p = {**cr_orig_p, "not_after_unix": of_d6o["chain"]["now"] - 1}
    cr_uexp = sl.sign_envelope(cr_uexp_p, [of_d6o["_keys"]["reg_cred"]["sk"]])
    cr_uexp_tx = _h32("d7-h8-uexp-tx")
    of_d6o["chain"]["txs"][cr_uexp_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_uexp)).hex(), "outputs": {}}
    add(
        "d7-r3h8-credential-not-after-unix-expired-refuse",
        ["SL-CONT-010"],
        "credential",
        {"credential": cr_uexp, "anchor_txid": cr_uexp_tx, "chain": of_d6o["chain"], "origin_bundle": of_d6o["origin_bundle"], "trusted_origin_issuer_pins": of_d6o["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CRED_WINDOW_CLOSED",
        "R3-H8: credential past not_after_unix MUST refuse CRED_WINDOW_CLOSED.",
    )

    # 0x0a seallink-credential-withdrawal/1
    w_seal_pol = {"kind": "key", "pk": _kp("d7-w-seal")["comp"]}
    w_seal_tx = _h32("d7-w-seal-tx")
    cr_rev_p = {
        **cr_orig_p,
        "lifecycle": "revocable",
        "revocation_seal": {"script_policy": w_seal_pol, "txid": w_seal_tx, "vout": 0},
    }
    cr_rev = sl.sign_envelope(cr_rev_p, [of_d6o["_keys"]["reg_cred"]["sk"]])
    cr_rev_tx = _h32("d7-w-0x09-tx")
    w_doc = {"cause_sha256": _h32("d7-w-cause"), "credential_id": sl.object_id(cr_rev_p), "genesis": GENESIS_MAIN, "type": "seallink-credential-withdrawal/1"}
    w_spend_tx = _h32("d7-w-0x0a-tx")
    ch_w = copy.deepcopy(of_d6o["chain"])
    ch_w["txs"][cr_rev_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_rev)).hex(), "outputs": {}}
    ch_w["txs"][w_seal_tx] = {"confirmed_height": 749490, "outputs": {"0": {"script_pubkey_hex": _spk_hex(w_seal_pol), "spent_by_txid": w_spend_tx}}}
    ch_w["txs"][w_spend_tx] = {"confirmed_height": 749900, "opreturn_hex": sl.encode_opreturn(0x0A, sl.signing_digest(w_doc).hex()).hex(), "outputs": {}}
    add(
        "d7-obj-credential-withdrawal-0x0a-refuse",
        ["SL-CONT-010"],
        "credential",
        {"credential": cr_rev, "anchor_txid": cr_rev_tx, "chain": ch_w, "withdrawal_doc": w_doc, "origin_bundle": of_d6o["origin_bundle"], "trusted_origin_issuer_pins": of_d6o["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CRED_REVOKED_FOR_CAUSE",
        "H-24 / R3-H8: revocable credential withdrawn via 0x0a seallink-credential-withdrawal/1 MUST refuse CRED_REVOKED_FOR_CAUSE.",
    )

    # =========================================================================
    # Decision 6B & H-24: Remaining 30/30 Object Types (Positive + Negative)
    #   seallink-auth-upgrade/1, seallink-session-open/1, seallink-verdict/1,
    #   seallink-termination/1, seallink-certset-head/1, seallink-statement/1,
    #   seallink-migration/1 (full 4-step with MigrationInventory + assent + accept stmt),
    #   seallink-card/1
    # =========================================================================

    # 1. seallink-auth-upgrade/1 (positive + wrong firstupdate_txid)
    fx_au = rm._base_invocation_fixture()
    au_key = _kp("d7-au-key")
    au_seal_pol = {"kind": "key", "pk": _kp("d7-au-seal")["comp"]}
    au_seal_tx = _h32("d7-au-seal-tx")
    fx_au["chain"]["txs"][au_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(au_seal_pol)}}}
    au_man = copy.deepcopy(fx_au["_alice_man"])
    au_man["auth_key"] = au_key["xonly"]
    au_man["auth_seal"] = {"script_policy": au_seal_pol, "txid": au_seal_tx, "vout": 0}
    au_man_h = sl.content_addr(au_man)
    fx_au["chain"]["manifests"][au_man_h] = au_man
    fx_au["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_au["_alice_reg"], fx_au["_alice_owner_pol"],
        {"link": {"grant": fx_au["_keys"]["alice_gr"]["xonly"]}, "m": {"h": au_man_h, "s": 1}},
    )
    au_env = sl.sign_envelope(
        {
            "account_id": "prov-cell-42",
            "auth_pubkey": au_key["xonly"],
            "expires_at": fx_au["chain"]["now"] + 60,
            "firstupdate_txid": fx_au["_alice_reg"]["txid"],
            "issued_at": fx_au["chain"]["now"] - 10,
            "name": "id/alice",
            "nonce": _h32("d7-au-n1"),
            "service_id": "mail.example.org",
            "type": "seallink-auth-upgrade/1",
        },
        [au_key["sk"]],
    )
    add(
        "d7-obj-auth-upgrade-valid-admit",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"upgrade": au_env, "expected_service_id": "mail.example.org", "expected_provisional_auth_pubkey": au_key["xonly"], "chain": fx_au["chain"], "manifests": {au_man_h: au_man}},
        "ADMIT",
        None,
        "H-24: seallink-auth-upgrade/1 atomically upgrades provisional cell when firstupdate_txid, auth_key, and unspent auth_seal verify.",
    )
    au_bad_reg = sl.sign_envelope({**au_env["payload"], "firstupdate_txid": _h32("wrong-firstupd"), "nonce": _h32("d7-au-n2")}, [au_key["sk"]])
    add(
        "d7-obj-auth-upgrade-wrong-firstupdate-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"upgrade": au_bad_reg, "expected_service_id": "mail.example.org", "expected_provisional_auth_pubkey": au_key["xonly"], "chain": fx_au["chain"], "manifests": {au_man_h: au_man}},
        "REFUSE",
        "NAME_REREGISTERED",
        "H-24: seallink-auth-upgrade/1 with mismatched firstupdate_txid MUST refuse NAME_REREGISTERED.",
    )

    # 2. seallink-session-open/1 full lifecycle (open -> bearer verify -> extend -> close -> post-close refuse)
    fx_so = rm._base_invocation_fixture()
    gp_so = copy.deepcopy(fx_so["bundle"]["grants"][0]["payload"])
    gp_so["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "10", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    g_so, gid_so = _reanchor(fx_so, gp_so)
    so_itx = fx_so["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    so_open_p = {
        "executor": fx_so["invocation"]["payload"]["executor"],
        "exp": fx_so["chain"]["now"] + 1200,
        "genesis": GENESIS_MAIN,
        "iat": fx_so["chain"]["now"] - 10,
        "network": "main",
        "nonce": _h32("d7-so-n1"),
        "op": "open",
        "proof_path": [{"grant_id": gid_so, "issuance_txid": so_itx}],
        "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}],
        "slot_binding": "tls-slot-a",
        "type": "seallink-session-open/1",
    }
    so_open = sl.sign_envelope(so_open_p, [fx_so["_keys"]["agent_req"]["sk"]])
    sid_so = sl.object_id(so_open_p)
    so_ext = sl.sign_envelope({**so_open_p, "exp": fx_so["chain"]["now"] + 2400, "nonce": _h32("d7-so-n2"), "op": "extend", "session_id": sid_so}, [fx_so["_keys"]["agent_req"]["sk"]])
    so_cls = sl.sign_envelope({**so_open_p, "nonce": _h32("d7-so-n3"), "op": "close", "session_id": sid_so}, [fx_so["_keys"]["agent_req"]["sk"]])
    so_over = sl.sign_envelope({**so_open_p, "nonce": _h32("d7-so-n4"), "quotas": [{"kind": "seallink/count", "max": "11", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]}, [fx_so["_keys"]["agent_req"]["sk"]])
    tok_so = _h32("d7-bearer-session-tok-1")
    add(
        "d7-obj-session-open-full-lifecycle-admit",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_so["executor_cfg"],
            "journal": {"journal_id": _h32("d7-so-j")},
            "steps": [
                {"label": "over-quota-refuse", "kind": "session_open", "chain": fx_so["chain"], "session_open": so_over, "bundle": fx_so["bundle"], "want_verdict": "REFUSE", "want_refusal": "SESSION_INVALID"},
                {"label": "open", "kind": "session_open", "chain": fx_so["chain"], "session_open": so_open, "bundle": fx_so["bundle"], "bearer_token": tok_so, "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "use-open", "kind": "bearer_session", "action": "mail/read", "target": "mailbox:id/alice:work", "arguments": {"folder": "Invoices", "message_id": "m1"}, "actual_message_meta": {"folder": "Invoices"}, "chain": fx_so["chain"], "grant_env": g_so, "token": tok_so, "slot_binding": "tls-slot-a", "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "extend", "kind": "session_open", "chain": fx_so["chain"], "session_open": so_ext, "bundle": fx_so["bundle"], "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "close", "kind": "session_open", "chain": fx_so["chain"], "session_open": so_cls, "bundle": fx_so["bundle"], "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "use-after-close", "kind": "bearer_session", "action": "mail/read", "target": "mailbox:id/alice:work", "arguments": {"folder": "Invoices", "message_id": "m2"}, "actual_message_meta": {"folder": "Invoices"}, "chain": fx_so["chain"], "token": tok_so, "slot_binding": "tls-slot-a", "want_verdict": "REFUSE", "want_refusal": "SESSION_INVALID"},
            ],
        },
        "ADMIT",
        None,
        "Decision 6B / H-12: seallink-session-open/1 enforces quota narrowing, open -> bearer use -> extend -> close, and refuses post-close tokens.",
    )

    # 3. seallink-verdict/1 (ordinal 1 + chained ordinal 2 + 0x03 frame, plus bad prev_verdict_id)
    fx_vt = rm._contract_fx()
    mod_k = _kp("d7-mod-key")
    c_mod = copy.deepcopy(fx_vt["bundle"]["contract"])
    c_mod["moderation"] = {"moderator_key": mod_k["xonly"], "moderator_kind": "agent", "rules_sha256": _h32("d7-mod-rules")}
    cid_mod = sl.object_id(c_mod)
    v1_p = {
        "contract_id": cid_mod,
        "genesis": GENESIS_MAIN,
        "grant_id": sl.object_id(fx_vt["bundle"]["grants"][0]["payload"]),
        "network": "main",
        "ordinal": 1,
        "request_salted_sha256": _h32("v1-req"),
        "response_salted_sha256": _h32("v1-resp"),
        "rules_sha256": _h32("d7-mod-rules"),
        "tip_height": 750000,
        "type": "seallink-verdict/1",
        "violated_rule": "rule-no-pii",
    }
    v1_env = sl.sign_envelope(v1_p, [mod_k["sk"]])
    v1_tx = _h32("d7-v1-0x03-tx")
    fx_vt["chain"]["txs"][v1_tx] = {"confirmed_height": 750005, "opreturn_hex": sl.encode_opreturn(0x03, sl.signing_digest(v1_p).hex()).hex(), "outputs": {}}
    v2_p = {**v1_p, "ordinal": 2, "prev_verdict_id": sl.object_id(v1_p)}
    v2_env = sl.sign_envelope(v2_p, [mod_k["sk"]])
    v2_bad = sl.sign_envelope({**v2_p, "prev_verdict_id": _h32("wrong-prev-v")}, [mod_k["sk"]])
    add(
        "d7-obj-verdict-ordinal1-0x03-admit",
        ["SL-CONT-006"],
        "verdict",
        {"verdict": v1_env, "contract": c_mod, "chain": fx_vt["chain"], "anchor_txid": v1_tx},
        "ADMIT",
        None,
        "H-24: seallink-verdict/1 signed by contract.moderation.moderator_key with matching 0x03 anchor admits.",
    )
    add(
        "d7-obj-verdict-ordinal2-chained-admit",
        ["SL-CONT-006"],
        "verdict",
        {"verdict": v2_env, "prev_verdict": v1_env, "contract": c_mod, "chain": fx_vt["chain"]},
        "ADMIT",
        None,
        "H-24: chained seallink-verdict/1 ordinal=2 matching prev_verdict_id admits.",
    )
    add(
        "d7-obj-verdict-ordinal2-broken-chain-refuse",
        ["SL-CONT-006"],
        "verdict",
        {"verdict": v2_bad, "prev_verdict": v1_env, "contract": c_mod, "chain": fx_vt["chain"]},
        "REFUSE",
        "CONTRACT_TERMS_MISMATCH",
        "H-24: seallink-verdict/1 ordinal=2 with mismatched prev_verdict_id MUST refuse CONTRACT_TERMS_MISMATCH.",
    )

    # 4. seallink-termination/1 (party-signed with 0x08 spend frame + non-party refuse)
    term_p = {
        "contract_id": cid_mod,
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "network": "main",
        "reason": "Mutually concluded.",
        "termination_branch": "either_party",
        "type": "seallink-termination/1",
    }
    term_ok = sl.sign_envelope(term_p, [fx_vt["_keys"]["alice_gr"]["sk"]])
    term_tx = _h32("d7-term-0x08-tx")
    fx_vt["chain"]["txs"][term_tx] = {"confirmed_height": 750008, "opreturn_hex": sl.encode_opreturn(0x08, sl.signing_digest(term_p).hex()).hex(), "outputs": {}}
    term_bad = sl.sign_envelope(term_p, [_kp("d7-stranger-term")["sk"]])
    add(
        "d7-obj-termination-party-signed-0x08-admit",
        ["SL-CONT-005"],
        "termination",
        {"termination": term_ok, "contract": c_mod, "chain": fx_vt["chain"], "spend_txid": term_tx},
        "ADMIT",
        None,
        "H-24: seallink-termination/1 signed by contract party with matching 0x08 frame admits.",
    )
    add(
        "d7-obj-termination-stranger-signer-refuse",
        ["SL-CONT-005"],
        "termination",
        {"termination": term_bad, "contract": c_mod, "chain": fx_vt["chain"]},
        "REFUSE",
        "WIRE_SIGNATURE",
        "H-24: seallink-termination/1 signed by non-party key MUST refuse WIRE_SIGNATURE.",
    )

    # 5. seallink-statement/1 & seallink-certset-head/1 (positive + negative)
    fx_st = rm._base_invocation_fixture()
    stmt_ok = sl.sign_envelope(
        {
            "genesis": GENESIS_MAIN,
            "issuer": {"name": "id/alice", "owner_policy": fx_st["_alice_owner_pol"], "registration": fx_st["_alice_reg"]},
            "network": "main",
            "not_after": fx_st["chain"]["now"] + 3600,
            "not_before": fx_st["chain"]["now"] - 60,
            "seq": 1,
            "statement_kind": "transport-binding",
            "subject": {"endpoint": "https://mail.example.org", "key_alg": "sha256-spki", "key_hex": _h32("tls-spki"), "transport": "https-tls-spki"},
            "type": "seallink-statement/1",
        },
        [fx_st["_keys"]["alice_gr"]["sk"]],
    )
    stmt_exp = sl.sign_envelope({**stmt_ok["payload"], "not_after": fx_st["chain"]["now"]}, [fx_st["_keys"]["alice_gr"]["sk"]])
    set_sha = sl.sha256(sl._jcs_serialize([sl.content_addr(stmt_ok)], None, (), 0).encode("utf-8")).hex()
    csh_ok = {"count": 1, "issuer_name": "id/alice", "network": "main", "seq": 1, "set_sha256": set_sha, "type": "seallink-certset-head/1"}
    al_man_cs = {**copy.deepcopy(fx_st["_alice_man"]), "sets": {"certs": {"seq": 1, "sha256": sl.content_addr(csh_ok)}}}
    add(
        "d7-obj-statement-transport-binding-admit",
        ["SL-IDEN-006"],
        "statement",
        {"statement": stmt_ok, "chain": fx_st["chain"]},
        "ADMIT",
        None,
        "H-24: seallink-statement/1 signed by issuer's live link.grant policy within validity window admits.",
    )
    add(
        "d7-obj-statement-expired-refuse",
        ["SL-IDEN-006"],
        "statement",
        {"statement": stmt_exp, "chain": fx_st["chain"]},
        "REFUSE",
        "INVOKE_TIME_INVALID",
        "H-24: expired seallink-statement/1 (now >= not_after) MUST refuse INVOKE_TIME_INVALID.",
    )
    add(
        "d7-obj-certset-head-valid-admit",
        ["SL-IDEN-006"],
        "certset_head",
        {"head": csh_ok, "statements": [stmt_ok], "owner_manifest": al_man_cs},
        "ADMIT",
        None,
        "H-24 / S-19: seallink-certset-head/1 matching manifest sets.certs pin and SHA256(JCS(sorted_statement_caddrs)) admits.",
    )
    add(
        "d7-obj-certset-head-tampered-set-refuse",
        ["SL-IDEN-006"],
        "certset_head",
        {"head": csh_ok, "statements": [], "owner_manifest": al_man_cs},
        "REFUSE",
        "MANIFEST_MISMATCH",
        "H-24 / S-19: seallink-certset-head/1 with missing/tampered statements MUST refuse MANIFEST_MISMATCH.",
    )

    # 6. seallink-migration/1 full 4-step cut-over (MigrationInventory + holder assent + holder manifest + dest migration-accept statement)
    fx_m4 = rm._base_invocation_fixture()
    dest_own, dest_rcpt = _kp("d7-m4-dest-own"), _kp("d7-m4-dest-rcpt")
    dest_opol = {"kind": "key", "pk": dest_own["comp"]}
    dest_reg = {"txid": _h32("d7-m4-dest-reg"), "vout": 0}
    dest_pin = {"name": "id/mail-host-b", "owner_policy": dest_opol, "registration": dest_reg}
    dest_man = {
        "network": "main",
        "owner": "id/mail-host-b",
        "seq": 1,
        "service": {"actions": ["mail/read", "mail/send"], "endpoint": "https://mail-b.example.org", "receipt_key": dest_rcpt["xonly"], "service_type": "mail"},
        "type": "seallink-manifest/1",
    }
    dest_man_h = sl.content_addr(dest_man)
    fx_m4["chain"]["manifests"][dest_man_h] = dest_man
    fx_m4["bundle"]["manifests"][dest_man_h] = dest_man
    fx_m4["chain"]["names"]["id/mail-host-b"] = sv.make_name_history(
        "id/mail-host-b", dest_reg, dest_opol, {"m": {"h": dest_man_h, "s": 1}}, first_height=748000, update_height=749000
    )
    # Alice's confirmed manifest now binds dest_executor id/mail-host-b!
    al_man_m4 = {
        "network": "main",
        "owner": "id/alice",
        "providers": [{"label": "work", "provider": dest_pin, "service_type": "mail"}],
        "seq": 2,
        "type": "seallink-manifest/1",
    }
    al_man_m4_h = sl.content_addr(al_man_m4)
    fx_m4["chain"]["manifests"][al_man_m4_h] = al_man_m4
    fx_m4["bundle"]["manifests"][al_man_m4_h] = al_man_m4
    fx_m4["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_m4["_alice_reg"], fx_m4["_alice_owner_pol"],
        {"link": {"grant": fx_m4["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al_man_m4_h, "s": 2}},
    )
    mig_id = _h32("d7-m4-mig-id")
    mig_inv = {
        "holder_name": "id/alice",
        "items": [{"media_type": "message/rfc822", "path": "mail/2026/msg1.eml", "sha256": _h32("eml1"), "size_bytes": "512"}],
        "migration_id": mig_id,
        "service_type": "mail",
    }
    mig_inv_sha = sl.sha256(sl.jcs_encode(mig_inv)).hex()
    holder_pin = {"name": "id/alice", "owner_policy": fx_m4["_alice_owner_pol"], "registration": fx_m4["_alice_reg"]}
    src_pin = {"name": "id/mail-host-a", "owner_policy": fx_m4["_host_owner_pol"], "registration": fx_m4["_host_reg"]}
    mig_p = {
        "dest_executor": dest_pin,
        "genesis": GENESIS_MAIN,
        "holder": holder_pin,
        "inventory_sha256": mig_inv_sha,
        "issued_at": fx_m4["chain"]["now"],
        "journal_commitment": _h32("d7-m4-jc"),
        "journal_pos": 42,
        "migration_id": mig_id,
        "network": "main",
        "outstanding_exposure": [],
        "service_type": "mail",
        "source_executor": src_pin,
        "type": "seallink-migration/1",
    }
    mig_env = sl.sign_envelope(mig_p, [fx_m4["_keys"]["host_rcpt"]["sk"]])
    h_assent = sl.sign_envelope(
        {
            "expires_at": fx_m4["chain"]["now"] + 3600,
            "genesis": GENESIS_MAIN,
            "issued_at": fx_m4["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d7-m4-ha-n"),
            "party_id": "holder",
            "party_name": "id/alice",
            "party_role": "holder",
            "target_id": sl.object_id(mig_p),
            "target_type": "seallink-migration/1",
            "type": "seallink-assent/1",
        },
        [fx_m4["_keys"]["alice_gr"]["sk"]],
    )
    d_accept = sl.sign_envelope(
        {
            "genesis": GENESIS_MAIN,
            "issuer": dest_pin,
            "network": "main",
            "not_after": fx_m4["chain"]["now"] + 3600,
            "not_before": fx_m4["chain"]["now"] - 10,
            "seq": 1,
            "statement_kind": "migration-accept",
            "subject": {"holder": holder_pin, "inventory_sha256": mig_inv_sha, "migration_id": mig_id, "source_executor": src_pin},
            "type": "seallink-statement/1",
        },
        [dest_rcpt["sk"]],
    )
    f_stmt_m4 = sl.sign_envelope(
        {
            "genesis": GENESIS_MAIN,
            "issuer": src_pin,
            "network": "main",
            "not_after": fx_m4["chain"]["now"] + 3600,
            "not_before": fx_m4["chain"]["now"] - 10,
            "seq": 1,
            "statement_kind": "migration-fence",
            "subject": {
                "dest_executor": dest_pin,
                "holder": holder_pin,
                "inventory_sha256": mig_inv_sha,
                "migration_id": mig_id,
                "predecessor_grant_seals": [],
                "source_journal_commitment": _h32("d7-m4-jc"),
                "source_journal_pos": 42,
            },
            "type": "seallink-statement/1",
        },
        [fx_m4["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d7-obj-migration-4step-cutover-admit",
        ["SL-SERV-002"],
        "migration",
        {
            "migration": mig_env,
            "export_bundle": {
                "fencing_statement": f_stmt_m4,
                "inventory": mig_inv,
                "source_journal_commitment": _h32("d7-m4-jc"),
                "source_journal_pos": 42,
            },
            "holder_assent": h_assent,
            "dest_accept_stmt": d_accept,
            "local_executor_pin": dest_pin,
            "chain": fx_m4["chain"],
            "manifests": fx_m4["bundle"]["manifests"],
            "journal": {"journal_id": _h32("d7-m4-j")},
        },
        "ADMIT",
        None,
        "Decision 6B / H-14: full 4-step exclusive migration cut-over with signed migration-fence Statement, MigrationInventory, holder assent, holder manifest provider cut-over, and destination migration-accept statement admits.",
    )
    # Path traversal item in MigrationInventory -> SERVICE_MIGRATION_INVALID
    bad_mig_inv = copy.deepcopy(mig_inv)
    bad_mig_inv["items"][0]["path"] = "../secrets/key.pem"
    bad_mig_p = {**mig_p, "inventory_sha256": sl.sha256(sl.jcs_encode(bad_mig_inv)).hex()}
    add(
        "d7-obj-migration-inventory-path-traversal-refuse",
        ["SL-SERV-002"],
        "migration",
        {
            "migration": sl.sign_envelope(bad_mig_p, [fx_m4["_keys"]["host_rcpt"]["sk"]]),
            "local_executor_pin": dest_pin,
            "export_bundle": {
                "inventory": bad_mig_inv,
                "source_journal_commitment": _h32("d7-m4-jc"),
                "source_journal_pos": 42,
            },
            "chain": fx_m4["chain"],
            "manifests": fx_m4["bundle"]["manifests"],
            "journal": {"journal_id": _h32("d7-m4-j2")},
        },
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "Decision 6B / H-14: MigrationInventory path containing '..' traversal MUST refuse SERVICE_MIGRATION_INVALID.",
    )

    # 7. seallink-card/1 positive wire admission
    card_ok = {
        "contact": "alice@example.org",
        "display": "Alice",
        "kind": "person",
        "name": "id/alice",
        "network": "main",
        "relays": ["wss://relay.example.org"],
        "replaces": 0,
        "role": "issuer",
        "seq": 1,
        "transports": [{"address": "https://mail.example.org", "transport": "https"}],
        "type": "seallink-card/1",
    }
    add(
        "d7-obj-card-valid-admit",
        ["SL-IDEN-006"],
        "raw_wire",
        {"object": card_ok},
        "ADMIT",
        None,
        "H-24: canonical seallink-card/1 validates cleanly against Draft 2020-12 schema.",
    )

    # 8. seallink-credential-break/1 positive wire admission (completes 30/30 registered object types!)
    cb_ok = {
        "compromised_policy": {"m": 1, "pks": [_kp("d7-cb-comp")["xonly"]]},
        "genesis": GENESIS_MAIN,
        "h_c": 749400,
        "issuer": {"name": "id/alice", "owner_policy": fx_b1_ctrl["_alice_owner_pol"], "registration": fx_b1_ctrl["_alice_reg"]},
        "name_input": {"txid": _h32("d7-cb-name-in"), "vout": 0},
        "role": "cred",
        "type": "seallink-credential-break/1",
    }
    add(
        "d7-obj-credential-break-valid-admit",
        ["SL-CONT-009"],
        "raw_wire",
        {"object": cb_ok},
        "ADMIT",
        None,
        "H-24: canonical seallink-credential-break/1 validates cleanly against Draft 2020-12 schema (30/30 object types).",
    )

    # =========================================================================
    # R1-B, B-13 Path B, B-15 Pre-Effective 0x0d, R3-H4 0x0e CSV Veto, B-8 Zero-Debit
    # =========================================================================

    # R1-B: Closed-bracket rebracket_tip advancing past invocation exp -> INVOKE_TIME_INVALID
    fx_r1b = rm._base_invocation_fixture()
    fx_r1b["require_observation_bracket"] = True
    fx_r1b["chain"]["rebracket_tip"] = {
        "first_sight": fx_r1b["chain"]["tip_first_sight"],
        "hash": fx_r1b["chain"]["tip_hash"],
        "header_time": fx_r1b["chain"]["tip_header_time"],
        "height": fx_r1b["chain"]["tip_height"],
        "now": fx_r1b["invocation"]["payload"]["exp"],  # Unified clock advanced at close of bracket!
    }
    add(
        "d7-r1b-closed-bracket-unified-clock-advances-past-exp-refuse",
        ["SL-LDGR-008", "SL-GRNT-006"],
        "invocation",
        fx_r1b,
        "REFUSE",
        "INVOKE_TIME_INVALID",
        "R1-B closed: closed-bracket rebracket_tip advancing unified clock to >= invocation.exp MUST refuse INVOKE_TIME_INVALID.",
    )

    # B-13 Path B: Confirmed capacity/1 + handover to exact subject_new_owner_policy -> ADMIT_AUTONOMOUS vs wrong owner -> GUARDIAN_TRANSFER_PENDING
    def _path_b_fx(*, match_policy: bool = True) -> dict[str, Any]:
        of_pb = rm._base_origin_fixture()
        stat_s = of_pb["origin_bundle"]["origin"]["payload"]["status_seal"]
        target_pol = {"kind": "key", "pk": _kp("d7-pb-target-own")["comp"]}
        actual_pol = target_pol if match_policy else {"kind": "key", "pk": _kp("d7-pb-wrong-own")["comp"]}
        cap_p = {
            "basis_sha256": _h32("d7-pb-basis"),
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": of_pb["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "next_status_policy": stat_s["script_policy"],
            "next_status_vout": 0,
            "origin_id": of_pb["_origin_id"],
            "status_prev_outpoint": {"txid": stat_s["txid"], "vout": 0},
            "subject_new_owner_policy": target_pol,
            "type": "seallink-capacity/1",
        }
        cap_rec = sl.sign_envelope(cap_p, [of_pb["_keys"]["reg_cred"]["sk"]])
        cap_tx = _h32(f"d7-pb-cap-{match_policy}")
        of_pb["chain"]["txs"][stat_s["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_tx
        of_pb["chain"]["txs"][cap_tx] = {
            "confirmed_height": 749900,
            "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_rec)).hex(),
            "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_s["script_policy"])}},
        }
        of_pb["origin_bundle"]["capacity_record"] = cap_rec
        leo_u = of_pb["chain"]["names"]["id/child-leo"]["updates"]
        prev_u = leo_u[-1]
        act_spk, _ = sl.compile_script_policy(actual_pol)
        val_b = sl.jcs_encode({"link": {"grant": of_pb["_keys"]["ward_gr"]["xonly"], "origin": of_pb["_origin_id"]}})
        tx1 = _h32(f"d7-pb-ho1-{match_policy}")
        leo_u.append({
            "confirmed_height": 749920,
            "op": "NAME_UPDATE",
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", act_spk, name=b"id/child-leo", value=val_b).hex(),
            "owner_policy": actual_pol,
            "prev_input": {"sighash_bytes": [0x01], "txid": prev_u["txid"], "vout": 0, "witness_policy": prev_u["owner_policy"]},
            "txid": tx1,
            "vout": 0,
        })
        leo_u.append({
            "confirmed_height": 749930,
            "op": "NAME_UPDATE",
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", act_spk, name=b"id/child-leo", value=val_b).hex(),
            "owner_policy": actual_pol,
            "prev_input": {"sighash_bytes": [0x01], "txid": tx1, "vout": 0, "witness_policy": actual_pol},
            "txid": _h32(f"d7-pb-ho2-{match_policy}"),
            "vout": 0,
        })
        return of_pb

    of_pb_ok = _path_b_fx(match_policy=True)
    add(
        "d7-b13-path-b-capacity-handover-exact-policy-autonomous",
        ["SL-ORIG-011"],
        "origin_status",
        {"origin_bundle": of_pb_ok["origin_bundle"], "chain": of_pb_ok["chain"], "trusted_origin_issuer_pins": of_pb_ok["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "B-13 Path B: confirmed capacity/1 + handover to exact subject_new_owner_policy admits autonomous capacity.",
    )
    of_pb_bad = _path_b_fx(match_policy=False)
    add(
        "d7-b13-path-b-capacity-handover-wrong-policy-pending",
        ["SL-ORIG-011"],
        "origin_status",
        {"origin_bundle": of_pb_bad["origin_bundle"], "chain": of_pb_bad["chain"], "trusted_origin_issuer_pins": of_pb_bad["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_TRANSFER_PENDING",
        "B-13 Path B: confirmed capacity/1 with handover to a policy != subject_new_owner_policy MUST refuse GUARDIAN_TRANSFER_PENDING.",
    )

    # B-15: Pre-effective 0x0d on new_vacant (h_0x0d < h_0x0f + effective_delay_blocks) burns slot -> GUARDIAN_INACTIVE
    of_pe = rm._base_origin_fixture()
    tip_pe = of_pe["chain"]["tip_height"]  # 750010
    gp_pe = of_pe["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    delay_pe = gp_pe["appointment_delay_blocks"]  # 144
    vac_pe = gp_pe["roster_seal"]["script_policy"]
    g_pe_k = _kp("d7-pe-g")
    pend_pe = {"delay_blocks": delay_pe, "keys": {"challenger": gp_pe["challenger_pk"], "disposer": gp_pe["disposer_pk"], "guardian": g_pe_k["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
    act_pe = {"keys": sl.canonical_branch_pair(gp_pe["disposer_pk"], g_pe_k["comp"]), "kind": "branch", "template": "either_of_2"}
    rost_pe_p = {
        "arbiter_pk": gp_pe["arbiter_pk"], "challenger_pk": gp_pe["challenger_pk"], "disposer_pk": gp_pe["disposer_pk"],
        "effective_delay_blocks": delay_pe, "genesis": GENESIS_MAIN, "issuer": of_pe["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main", "next_roster_policy": vac_pe, "next_roster_vout": 0, "origin_id": of_pe["_origin_id"],
        "prev_revision": 1, "prev_roster_outpoint": {"txid": gp_pe["roster_seal"]["txid"], "vout": 0},
        "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in gp_pe["quorums"]},
        "revision": 2, "revision_size": 1,
        "slots": [{"action": "new_vacant", "new_vacant_policy": vac_pe, "new_vacant_vout": 1, "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    rost_pe = sl.sign_envelope(rost_pe_p, [of_pe["_keys"]["reg_cred"]["sk"]])
    rtx_pe, dtx_pe, etx_pe = _h32("d7-pe-rtx"), _h32("d7-pe-dtx"), _h32("d7-pe-etx")
    g2_pe_p = {
        "activation_mode": "appointed", "active_policy": act_pe, "effective_delay_blocks": delay_pe,
        "genesis": GENESIS_MAIN, "guardian": of_pe["origin_bundle"]["guardian_records"][0]["payload"]["guardian"],
        "issuer": of_pe["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main", "origin_id": of_pe["_origin_id"],
        "pending_policy": pend_pe, "pending_vout": 0, "prev_outpoint": {"txid": rtx_pe, "vout": 1}, "revision": 2, "slot": 1,
        "term": {"mode": "indefinite"}, "type": "seallink-guardian/1",
    }
    g2_pe = sl.sign_envelope(g2_pe_p, [of_pe["_keys"]["reg_cred"]["sk"]])
    g2_pe_ass = sl.sign_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d7-pe-ga"),
         "party_id": "g-pe", "party_name": "id/parent-a", "party_role": "guardian", "target_id": sl.object_id(g2_pe_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"},
        [of_pe["_keys"]["g1_gr"]["sk"]],
    )
    of_pe["chain"]["txs"][gp_pe["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_pe
    # rtx at tip - 200; roster becomes effective at tip - 56; dtx at tip - 144 is BEFORE roster effective (tip - 144 < tip - 56)!
    of_pe["chain"]["txs"][rtx_pe] = {"confirmed_height": tip_pe - 200, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_pe)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pe)}, "1": {"script_pubkey_hex": _spk_hex(vac_pe), "spent_by_txid": dtx_pe}}}
    of_pe["chain"]["txs"][dtx_pe] = {"confirmed_height": tip_pe - delay_pe, "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g2_pe)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_pe), "spent_by_txid": etx_pe}}}
    of_pe["chain"]["txs"][etx_pe] = {"confirmed_height": tip_pe, "opreturn_hex": sl.encode_opreturn(0x0E, sl.object_id(g2_pe_p)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_pe)}}}
    of_pe["origin_bundle"]["roster_records"] = [rost_pe]
    of_pe["origin_bundle"]["guardian_records"].append(g2_pe)
    of_pe["origin_bundle"]["guardian_assents"].append(g2_pe_ass)
    wa_pe = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": of_pe["_origin_id"], "revision": 2, "ward_name": "id/child-leo"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("d7-pe-wa"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
         "target_id": sl.object_id(of_pe["contract"]), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"slot": 1, "revision": 2, "guardian_name": "id/parent-a", "signers": [of_pe["_keys"]["g1_gr"]["sk"]]}],
    )
    add(
        "d7-b15-pre-effective-0x0d-on-new-vacant-burns-slot",
        ["SL-ORIG-015"],
        "assent",
        {"assent": wa_pe, "contract": of_pe["contract"], "origin_bundle": of_pe["origin_bundle"], "chain": of_pe["chain"], "trusted_origin_issuer_pins": of_pe["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_INACTIVE",
        "B-15: 0x0d appointment spending new_vacant BEFORE roster effective_delay_blocks elapses burns the slot (GUARDIAN_INACTIVE).",
    )

    # R3-H4: 0x0e activation with input sequence < delay_blocks (non-CSV veto branch spoof!) -> GUARDIAN_INACTIVE
    of_h4 = copy.deepcopy(of_pe)
    of_h4["chain"]["txs"][rtx_pe]["confirmed_height"] = tip_pe - (2 * delay_pe + 20)  # roster IS effective before dtx!
    of_h4["chain"]["txs"][etx_pe]["inputs"] = [{**sv.make_segwit_input(dtx_pe, 0), "sequence": 0xFFFFFFFF}]  # BIP-68 CSV NOT active!
    add(
        "d7-r3h4-0x0e-without-bip68-csv-sequence-refuse",
        ["SL-ORIG-008"],
        "assent",
        {"assent": wa_pe, "contract": of_h4["contract"], "origin_bundle": of_h4["origin_bundle"], "chain": of_h4["chain"], "trusted_origin_issuer_pins": of_h4["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_INACTIVE",
        "R3-H4: 0x0e activation tx lacking valid BIP-68 CSV sequence >= delay_blocks (veto-branch spoof) MUST refuse GUARDIAN_INACTIVE.",
    )

    # B-8: agent/session op=checkpoint is 0-debit (admits even when starts quota is fully exhausted!)
    fx_b8_cp = rm._contract_fx()
    gid_cp = sl.object_id(fx_b8_cp["bundle"]["grants"][0]["payload"])
    fx_b8_cp["journal"]["quotas_used"] = [{
        "bucket_id": "term",
        "quota_key": "seallink/count|station:id/station-a:slot1|starts|term",
        "scope": f"own:{gid_cp}",
        "used": 5,  # max == 5 -> starts exhausted!
    }]
    inv_cp = sl.sign_envelope(
        {**fx_b8_cp["invocation"]["payload"], "arguments": {"config_sha256": _h32("cfg-agreed"), "op": "checkpoint", "session_slot": "slot1"}, "nonce": _h32("d7-b8-cp-n")},
        [fx_b8_cp["_keys"]["agent_req"]["sk"]],
    )
    fx_b8_cp["invocation"] = inv_cp
    add(
        "d7-b08-agent-session-checkpoint-zero-debit-admit",
        ["SL-AGNT-002", "SL-GRNT-007"],
        "invocation",
        fx_b8_cp,
        "ADMIT",
        None,
        "B-8: agent/session op='checkpoint' debits 0 starts and MUST admit even when starts quota is already at max.",
    )

    _add_draft7_mutation_and_boundary_cases(add)


def _add_draft7_mutation_and_boundary_cases(add: Callable[..., None]) -> None:
    """Comprehensive negative & exact-boundary regression vectors across all v1.0.0-draft.7 rules and 30/30 objects."""

    # --- Batch 1: Wire, Curve Keys, Semantics, max_bytes exact boundary, Chain Observation ---
    # 1a. Exact max_bytes boundary on seallink-credential/1 (ADMIT at len == max_bytes; kills > -> >=)
    fx_sz = rm._base_invocation_fixture()
    cred_max = sv.registered_types()["seallink-credential/1"]["max_bytes"]
    cred_pad_p = {
        "claims": {},
        "credential_kind": "education/diploma",
        "genesis": GENESIS_MAIN,
        "issued_at": fx_sz["chain"]["now"],
        "issuer": {"name": "id/alice", "owner_policy": fx_sz["_alice_owner_pol"], "registration": fx_sz["_alice_reg"], "role_policy": {"m": 1, "pks": [fx_sz["_keys"]["alice_gr"]["xonly"]]}},
        "lifecycle": "eternal",
        "network": "main",
        "not_before_height": 749000,
        "subject": {"key": fx_sz["_keys"]["agent_req"]["xonly"], "mode": "key"},
        "type": "seallink-credential/1",
    }
    i_pad = 0
    while True:
        cur_len = len(sl.jcs_encode(sl.sign_envelope(cred_pad_p, [fx_sz["_keys"]["alice_gr"]["sk"]])))
        rem = cred_max - cur_len
        if rem == 0:
            break
        k_pad = f"p{i_pad:02d}"
        i_pad += 1
        # Adding one key adds `,"pXX":"..."` (or `"pXX":"..."` for first key)
        overhead = len(f'"{k_pad}":""') + (1 if cred_pad_p["claims"] else 0)
        chunk = min(1024, rem - overhead)
        cred_pad_p["claims"][k_pad] = "a" * chunk
    cred_exact = sl.sign_envelope(cred_pad_p, [fx_sz["_keys"]["alice_gr"]["sk"]])
    assert len(sl.jcs_encode(cred_exact)) == cred_max
    add(
        "d7-bnd-wire-exact-max-bytes-admit",
        ["SL-WIRE-001", "SL-WIRE-020"],
        "raw_wire",
        {"object": cred_exact},
        "ADMIT",
        None,
        "Exact boundary: object byte length == type max_bytes MUST admit (kills > -> >=).",
    )

    # 1b. Invalid ScriptPolicy multisig (m > len(pks)) -> CHAIN_SCRIPT_UNSUPPORTED
    fx_bks = rm._base_invocation_fixture()
    k1, k2 = _kp("d7-bks-1"), _kp("d7-bks-2")
    gp_bks = copy.deepcopy(fx_bks["bundle"]["grants"][0]["payload"])
    gp_bks["issuer"]["owner_policy"] = {"kind": "multisig", "m": 3, "pks": sorted([k1["comp"], k2["comp"]])}
    add(
        "d7-wire-branch-key-spec-invalid-m-refuse",
        ["SL-LDGR-004"],
        "raw_wire",
        {"object": sl.sign_envelope(gp_bks, [fx_bks["_keys"]["alice_gr"]["sk"]])},
        "REFUSE",
        "CHAIN_SCRIPT_UNSUPPORTED",
        "ScriptPolicy multisig with m > len(pks) MUST refuse CHAIN_SCRIPT_UNSUPPORTED.",
    )

    # 1c. Quota max == MAX_UINT64 + 1 -> WIRE_INTEGER
    fx_u64 = rm._base_invocation_fixture()
    gp_u64 = copy.deepcopy(fx_u64["bundle"]["grants"][0]["payload"])
    gp_u64["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": str(sl.MAX_UINT64 + 1), "resource": "mailbox:id/alice:work", "unit": "calls", "window": "term"}]
    add(
        "d7-wire-quota-max-overflow-uint64-refuse",
        ["SL-WIRE-006"],
        "raw_wire",
        {"object": sl.sign_envelope(gp_u64, [fx_u64["_keys"]["alice_gr"]["sk"]])},
        "REFUSE",
        "WIRE_INTEGER",
        "Quota max > 2^64-1 MUST refuse WIRE_INTEGER.",
    )

    # 1d. Origin duplicate seal outpoint (G-9) -> ORIGIN_UNVERIFIED; mismatched recovery_seal script -> CHAIN_SCRIPT_UNSUPPORTED
    of_dup = rm._base_origin_fixture()
    op_dup = copy.deepcopy(of_dup["origin_bundle"]["origin"]["payload"])
    op_dup["status_seal"]["txid"] = op_dup["binding_seal"]["txid"]
    op_dup["status_seal"]["vout"] = op_dup["binding_seal"]["vout"]
    add(
        "d7-g09-origin-duplicate-seal-outpoint-refuse",
        ["SL-ORIG-002"],
        "raw_wire",
        {"object": sl.sign_envelope(op_dup, [of_dup["_keys"]["reg_cred"]["sk"]])},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "G-9: seallink-origin/1 reusing the same outpoint across binding_seal and status_seal MUST refuse ORIGIN_UNVERIFIED.",
    )
    op_bad_rs = copy.deepcopy(of_dup["origin_bundle"]["origin"]["payload"])
    op_bad_rs["name_recovery"]["recovery_seal"]["script_policy"] = {"kind": "key", "pk": _kp("d7-wrong-rs")["comp"]}
    add(
        "d7-g09-origin-recovery-seal-script-mismatch-refuse",
        ["SL-ORIG-013"],
        "raw_wire",
        {"object": sl.sign_envelope(op_bad_rs, [of_dup["_keys"]["reg_cred"]["sk"]])},
        "REFUSE",
        "CHAIN_SCRIPT_UNSUPPORTED",
        "G-9: dual_party_delayed recovery_seal.script_policy not matching both_of_2(disposer_pk, arbiter_pk) MUST refuse CHAIN_SCRIPT_UNSUPPORTED.",
    )

    # 1e. Contract machine_clause_indices exact boundary: [len(cc)] -> WIRE_INTEGER vs [len(cc) - 1] -> ADMIT
    fx_mci = rm._contract_fx()
    c_mci = copy.deepcopy(fx_mci["bundle"]["contract"])
    c_mci_bad = {**c_mci, "machine_clause_indices": [len(c_mci["clause_commitments"])]}
    c_mci_ok = {**c_mci, "machine_clause_indices": [len(c_mci["clause_commitments"]) - 1]}
    add(
        "d7-bnd-contract-machine-clause-index-eq-len-refuse",
        ["SL-CONT-002"],
        "raw_wire",
        {"object": c_mci_bad},
        "REFUSE",
        "WIRE_INTEGER",
        "Exact boundary: machine_clause_indices containing index == len(clause_commitments) MUST refuse WIRE_INTEGER (kills >= -> >).",
    )
    add(
        "d7-bnd-contract-machine-clause-index-last-admit",
        ["SL-CONT-002"],
        "raw_wire",
        {"object": c_mci_ok},
        "ADMIT",
        None,
        "Exact boundary: machine_clause_indices containing index == len(clause_commitments) - 1 admits.",
    )

    # 1f. Chain observation: regtest_deterministic clock_source forbidden on main (A-9) + bracket missing rebracket_tip
    ch_a9 = copy.deepcopy(fx_sz["chain"])
    ch_a9["clock_source"] = "regtest_deterministic"
    add(
        "d7-a09-regtest-clock-source-on-main-refuse",
        ["SL-LDGR-008"],
        "chain_obs",
        {"chain": ch_a9},
        "REFUSE",
        "CHAIN_CLOCK_ERROR",
        "A-9: regtest_deterministic clock_source on main network MUST refuse CHAIN_CLOCK_ERROR.",
    )
    ch_br = copy.deepcopy(fx_sz["chain"])
    ch_br.pop("rebracket_tip", None)
    ch_br.pop("observation_bracket", None)
    add(
        "d7-r1b-rebracket-missing-with-require-bracket-refuse",
        ["SL-LDGR-008"],
        "chain_obs",
        {"chain": ch_br, "rebracket": True, "require_observation_bracket": True},
        "REFUSE",
        "CHAIN_OBSERVATION_VOID",
        "R1-B: check_rebracket with require_observation_bracket=True and missing rebracket_tip MUST refuse CHAIN_OBSERVATION_VOID.",
    )

    # --- Batch 2: Name Value, History Origins, Role/Mempool Continuity, Manifest Disjointness, Auth Challenge/Upgrade, Owner Command ---
    # 2a. Name history containing two distinct link.origin values -> ORIGIN_UNVERIFIED
    fx_n2o = rm._base_invocation_fixture()
    n2o_reg = {"txid": _h32("d7-n2o-reg"), "vout": 0}
    n2o_pol = fx_n2o["_alice_owner_pol"]
    n2o_spk, _ = sl.compile_script_policy(n2o_pol)
    n2o_hist = sv.make_name_history(
        "id/two-origins", n2o_reg, n2o_pol, {"link": {"grant": fx_n2o["_keys"]["alice_gr"]["xonly"], "origin": _h32("oid-1")}},
        first_height=748000, update_height=749000,
    )
    prev_n2o = n2o_hist["updates"][-1]
    val2 = sl.jcs_encode({"link": {"grant": fx_n2o["_keys"]["alice_gr"]["xonly"], "origin": _h32("oid-2")}})
    n2o_hist["updates"].append({
        "confirmed_height": 749100,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", n2o_spk, name=b"id/two-origins", value=val2).hex(),
        "owner_policy": n2o_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": prev_n2o["txid"], "vout": 0, "witness_policy": n2o_pol},
        "txid": _h32("d7-n2o-u2"),
        "vout": 0,
    })
    fx_n2o["chain"]["names"]["id/two-origins"] = n2o_hist
    add(
        "d7-b12-multiple-distinct-origins-in-history-refuse",
        ["SL-ORIG-002", "SL-IDEN-002"],
        "name_resolve",
        {"chain": fx_n2o["chain"], "name": "id/two-origins"},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "B-12: name registration history carrying two distinct link.origin IDs MUST refuse ORIGIN_UNVERIFIED.",
    )

    # 2b. Confirmed owner_policy change after recent_block_height -> NAME_OWNER_MISMATCH; mempool role change -> NAME_ROLE_CHANGED
    fx_rc = rm._base_invocation_fixture()
    rc_reg = {"txid": _h32("d7-rc-reg"), "vout": 0}
    rc_pol1 = {"kind": "key", "pk": _kp("d7-rc-own1")["comp"]}
    rc_pol2 = {"kind": "key", "pk": _kp("d7-rc-own2")["comp"]}
    rc_spk2, _ = sl.compile_script_policy(rc_pol2)
    rc_gr = _kp("d7-rc-gr")
    rc_hist = sv.make_name_history("id/rc-owner", rc_reg, rc_pol1, {"link": {"grant": rc_gr["xonly"]}}, first_height=748000, update_height=749000)
    u1_rc = rc_hist["updates"][-1]
    val_rc = sl.jcs_encode({"link": {"grant": rc_gr["xonly"]}})
    tx_rc_x = _h32("d7-rc-xfer")
    rc_hist["updates"].append({
        "confirmed_height": 749500, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", rc_spk2, name=b"id/rc-owner", value=val_rc).hex(),
        "owner_policy": rc_pol2, "prev_input": {"sighash_bytes": [0x01], "txid": u1_rc["txid"], "vout": 0, "witness_policy": rc_pol1},
        "txid": tx_rc_x, "vout": 0,
    })
    rc_hist["updates"].append({
        "confirmed_height": 749600, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", rc_spk2, name=b"id/rc-owner", value=val_rc).hex(),
        "owner_policy": rc_pol2, "prev_input": {"sighash_bytes": [0x01], "txid": tx_rc_x, "vout": 0, "witness_policy": rc_pol2},
        "txid": _h32("d7-rc-self"), "vout": 0,
    })
    fx_rc["chain"]["names"]["id/rc-owner"] = rc_hist
    add(
        "d7-b09-owner-changed-since-recent-block-refuse",
        ["SL-IDEN-002", "SL-GRNT-004"],
        "name_resolve",
        {"chain": fx_rc["chain"], "check_role": "grant", "name": "id/rc-owner", "recent_block_height": 749100},
        "REFUSE",
        "NAME_OWNER_MISMATCH",
        "B-9: confirmed owner_policy transfer after recent_block_height MUST refuse NAME_OWNER_MISMATCH.",
    )

    # Mempool OP_NAME_UPDATE changing link.grant (A-5), malformed script, and bad JSON
    fx_mp = rm._base_invocation_fixture()
    al_u_last = fx_mp["chain"]["names"]["id/alice"]["updates"][-1]
    al_spk, _ = sl.compile_script_policy(fx_mp["_alice_owner_pol"])
    mp_new_gr = _kp("d7-mp-new-gr")["xonly"]
    fx_mp["chain"]["names"]["id/alice"]["mempool_updates"] = [{
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", al_spk, name=b"id/alice", value=sl.jcs_encode({"link": {"grant": mp_new_gr}})).hex(),
        "owner_policy": fx_mp["_alice_owner_pol"],
        "prev_input": {"sighash_bytes": [0x01], "txid": al_u_last["txid"], "vout": 0, "witness_policy": fx_mp["_alice_owner_pol"]},
        "txid": _h32("d7-mp-role"),
    }]
    add(
        "d7-a05-mempool-role-change-refuse",
        ["SL-LDGR-007", "SL-IDEN-003"],
        "name_resolve",
        {"chain": fx_mp["chain"], "check_role": "grant", "name": "id/alice", "recent_block_height": 749900},
        "REFUSE",
        "NAME_ROLE_CHANGED",
        "A-5: owner-authored mempool OP_NAME_UPDATE rotating link.grant MUST refuse NAME_ROLE_CHANGED.",
    )
    fx_mp_bad_scr = copy.deepcopy(fx_mp)
    fx_mp_bad_scr["chain"]["names"]["id/alice"]["mempool_updates"][0]["output_script_hex"] = "00"
    add(
        "d7-a05-mempool-bad-script-refuse",
        ["SL-LDGR-004"],
        "name_resolve",
        {"chain": fx_mp_bad_scr["chain"], "check_role": "grant", "name": "id/alice", "recent_block_height": 749900},
        "REFUSE",
        "CHAIN_SCRIPT_UNSUPPORTED",
        "A-5: owner-authored mempool update with unparseable script MUST refuse CHAIN_SCRIPT_UNSUPPORTED.",
    )
    fx_mp_wrong_name = copy.deepcopy(fx_mp)
    fx_mp_wrong_name["chain"]["names"]["id/alice"]["mempool_updates"][0]["output_script_hex"] = sl.encode_name_output("NAME_UPDATE", al_spk, name=b"id/other", value=b"{}").hex()
    add(
        "d7-a05-mempool-wrong-name-refuse",
        ["SL-LDGR-004"],
        "name_resolve",
        {"chain": fx_mp_wrong_name["chain"], "check_role": "grant", "name": "id/alice", "recent_block_height": 749900},
        "REFUSE",
        "CHAIN_SCRIPT_UNSUPPORTED",
        "A-5: owner-authored mempool update naming a different name MUST refuse CHAIN_SCRIPT_UNSUPPORTED.",
    )
    fx_mp_bad_jcs = copy.deepcopy(fx_mp)
    fx_mp_bad_jcs["chain"]["names"]["id/alice"]["mempool_updates"][0]["output_script_hex"] = sl.encode_name_output("NAME_UPDATE", al_spk, name=b"id/alice", value=b"{bad json").hex()
    add(
        "d7-a05-mempool-bad-value-refuse",
        ["SL-IDEN-002"],
        "name_resolve",
        {"chain": fx_mp_bad_jcs["chain"], "check_role": "grant", "name": "id/alice", "recent_block_height": 749900},
        "REFUSE",
        "NAME_VALUE_INVALID",
        "A-5: owner-authored mempool update with non-canonical JSON value MUST refuse NAME_VALUE_INVALID.",
    )

    # 2c. Manifest auth_key colliding with link.grant (H-19) -> NAME_VALUE_INVALID
    fx_mk = rm._base_invocation_fixture()
    mk_seal_tx = _h32("d7-mk-seal")
    mk_seal_pol = {"kind": "key", "pk": _kp("d7-mk-s")["comp"]}
    fx_mk["chain"]["txs"][mk_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(mk_seal_pol)}}}
    bad_man = copy.deepcopy(fx_mk["_alice_man"])
    bad_man["auth_key"] = fx_mk["_keys"]["alice_gr"]["xonly"]  # Collides with link.grant!
    bad_man["auth_seal"] = {"script_policy": mk_seal_pol, "txid": mk_seal_tx, "vout": 0}
    bad_man_h = sl.content_addr(bad_man)
    fx_mk["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_mk["_alice_reg"], fx_mk["_alice_owner_pol"],
        {"link": {"grant": fx_mk["_keys"]["alice_gr"]["xonly"]}, "m": {"h": bad_man_h, "s": 1}},
    )
    add(
        "d7-h19-manifest-auth-key-collides-with-grant-role-refuse",
        ["SL-IDEN-003", "SL-IDEN-005"],
        "name_resolve",
        {"chain": fx_mk["chain"], "check_manifest": True, "manifests": {bad_man_h: bad_man}, "name": "id/alice"},
        "REFUSE",
        "NAME_VALUE_INVALID",
        "H-19: manifest auth_key reusing link.grant key MUST refuse NAME_VALUE_INVALID.",
    )

    # 2d. verify_auth_challenge exact boundaries (expires_at == issued_at -> EXPIRED; now == issued_at -> ADMIT)
    fx_ac = rm._base_invocation_fixture()
    ac_k = _kp("d7-ac-k")
    now_ac = fx_ac["chain"]["now"]
    ac_eq_p = {"auth_pubkey": ac_k["xonly"], "expires_at": now_ac, "issued_at": now_ac, "nonce": _h32("d7-ac-n1"), "service_id": "mail.example.org", "type": "seallink-auth-challenge/1"}
    add(
        "d7-bnd-auth-challenge-exp-eq-iat-refuse",
        ["SL-IDEN-010"],
        "auth_challenge",
        {"chain": fx_ac["chain"], "challenge": sl.sign_envelope(ac_eq_p, [ac_k["sk"]]), "journal": {"auth_nonces": {ac_eq_p["nonce"]: {"expires_at": now_ac, "issued_at": now_ac, "service_id": "mail.example.org", "used": False}}, "journal_id": _h32("d7-ac-j1")}, "service_id": "mail.example.org"},
        "REFUSE",
        "AUTH_CHALLENGE_EXPIRED",
        "Exact boundary: auth challenge with expires_at == issued_at MUST refuse AUTH_CHALLENGE_EXPIRED (kills <= -> <).",
    )
    ac_ok_p = {**ac_eq_p, "expires_at": now_ac + 120, "nonce": _h32("d7-ac-n2")}
    add(
        "d7-bnd-auth-challenge-now-eq-iat-admit",
        ["SL-IDEN-010"],
        "auth_challenge",
        {"chain": fx_ac["chain"], "challenge": sl.sign_envelope(ac_ok_p, [ac_k["sk"]]), "journal": {"auth_nonces": {ac_ok_p["nonce"]: {"expires_at": now_ac + 120, "issued_at": now_ac, "service_id": "mail.example.org", "used": False}}, "journal_id": _h32("d7-ac-j2")}, "service_id": "mail.example.org"},
        "ADMIT",
        None,
        "Exact boundary: auth challenge at chain.now == issued_at admits (kills < -> <=).",
    )

    # 2e. verify_auth_upgrade all refusal branches & exact boundaries
    fx_au2 = rm._base_invocation_fixture()
    au2_k = _kp("d7-au2-k")
    au2_spol = {"kind": "key", "pk": _kp("d7-au2-s")["comp"]}
    au2_stx = _h32("d7-au2-stx")
    fx_au2["chain"]["txs"][au2_stx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(au2_spol)}}}
    au2_man = {**copy.deepcopy(fx_au2["_alice_man"]), "auth_key": au2_k["xonly"], "auth_seal": {"script_policy": au2_spol, "txid": au2_stx, "vout": 0}}
    au2_man_h = sl.content_addr(au2_man)
    fx_au2["chain"]["manifests"][au2_man_h] = au2_man
    fx_au2["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_au2["_alice_reg"], fx_au2["_alice_owner_pol"], {"link": {"grant": fx_au2["_keys"]["alice_gr"]["xonly"]}, "m": {"h": au2_man_h, "s": 1}})
    now_au = fx_au2["chain"]["now"]
    au2_base = {"account_id": "prov-2", "auth_pubkey": au2_k["xonly"], "expires_at": now_au + 120, "firstupdate_txid": fx_au2["_alice_reg"]["txid"], "issued_at": now_au, "name": "id/alice", "nonce": _h32("d7-au2-n1"), "service_id": "mail.example.org", "type": "seallink-auth-upgrade/1"}
    add(
        "d7-bnd-auth-upgrade-exact-120s-now-eq-iat-admit",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"chain": fx_au2["chain"], "expected_provisional_auth_pubkey": au2_k["xonly"], "expected_service_id": "mail.example.org", "manifests": {au2_man_h: au2_man}, "upgrade": sl.sign_envelope(au2_base, [au2_k["sk"]])},
        "ADMIT",
        None,
        "Exact boundary: auth-upgrade with expires_at - issued_at == 120 and now == issued_at admits (kills > 120 -> >= and now < iat -> <=).",
    )
    add(
        "d7-bnd-auth-upgrade-exp-eq-iat-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"chain": fx_au2["chain"], "expected_provisional_auth_pubkey": au2_k["xonly"], "expected_service_id": "mail.example.org", "manifests": {au2_man_h: au2_man}, "upgrade": sl.sign_envelope({**au2_base, "expires_at": now_au, "nonce": _h32("d7-au2-n2")}, [au2_k["sk"]])},
        "REFUSE",
        "AUTH_CHALLENGE_INVALID",
        "Exact boundary: auth-upgrade with expires_at == issued_at refuses AUTH_CHALLENGE_INVALID (kills <= -> <).",
    )
    add(
        "d7-bnd-auth-upgrade-now-eq-exp-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"chain": fx_au2["chain"], "expected_provisional_auth_pubkey": au2_k["xonly"], "expected_service_id": "mail.example.org", "manifests": {au2_man_h: au2_man}, "upgrade": sl.sign_envelope({**au2_base, "expires_at": now_au, "issued_at": now_au - 60, "nonce": _h32("d7-au2-n3")}, [au2_k["sk"]])},
        "REFUSE",
        "AUTH_CHALLENGE_EXPIRED",
        "Exact boundary: auth-upgrade at now == expires_at refuses AUTH_CHALLENGE_EXPIRED (kills >= -> >).",
    )
    other_au_k = _kp("d7-au2-other")
    add(
        "d7-obj-auth-upgrade-wrong-provisional-key-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"chain": fx_au2["chain"], "expected_provisional_auth_pubkey": other_au_k["xonly"], "expected_service_id": "mail.example.org", "manifests": {au2_man_h: au2_man}, "upgrade": sl.sign_envelope({**au2_base, "nonce": _h32("d7-au2-n4")}, [au2_k["sk"]])},
        "REFUSE",
        "AUTH_KEY_UNPINNED",
        "auth-upgrade with auth_pubkey != expected_provisional_auth_pubkey refuses AUTH_KEY_UNPINNED.",
    )
    au2_man_noauth = copy.deepcopy(fx_au2["_alice_man"])
    au2_man_nh = sl.content_addr(au2_man_noauth)
    ch_au_no = copy.deepcopy(fx_au2["chain"])
    ch_au_no["manifests"][au2_man_nh] = au2_man_noauth
    ch_au_no["names"]["id/alice"] = sv.make_name_history("id/alice", fx_au2["_alice_reg"], fx_au2["_alice_owner_pol"], {"link": {"grant": fx_au2["_keys"]["alice_gr"]["xonly"]}, "m": {"h": au2_man_nh, "s": 1}})
    add(
        "d7-obj-auth-upgrade-manifest-unpinned-auth-key-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"chain": ch_au_no, "expected_provisional_auth_pubkey": au2_k["xonly"], "expected_service_id": "mail.example.org", "manifests": {au2_man_nh: au2_man_noauth}, "upgrade": sl.sign_envelope({**au2_base, "nonce": _h32("d7-au2-n5")}, [au2_k["sk"]])},
        "REFUSE",
        "AUTH_KEY_UNPINNED",
        "auth-upgrade when confirmed manifest lacks matching auth_key/auth_seal refuses AUTH_KEY_UNPINNED.",
    )

    # 2f. verify_owner_command: wrong device_list.owner -> DEVICE_UNAUTHORIZED; unpinned owner_manifest -> MANIFEST_MISMATCH
    p256_s2 = sl.deterministic_p256_privkey("d7-oc-p256")
    p256_p2 = sl.p256_compressed_pubkey(p256_s2)
    dl_ok = {"devices": [{"alg": "p256", "ceiling": 2, "key": p256_p2, "label": "enclave", "presence": True, "seal": {"script_policy": au2_spol, "txid": au2_stx, "vout": 0}}], "network": "main", "owner": "id/alice", "seq": 1, "type": "seallink-device-list/1"}
    oc_env = sl.sign_envelope({"arguments": {"scope": "all"}, "command": "keyholder-halt", "exp": now_au + 300, "genesis": GENESIS_MAIN, "iat": now_au, "level": 2, "network": "main", "nonce": _h32("d7-oc-n1"), "owner": "id/alice", "target_executor": "id/station-a", "type": "seallink-owner-command/1"}, [p256_s2], alg="p256")
    add(
        "d7-oc-wrong-device-list-owner-refuse",
        ["SL-IDEN-011"],
        "owner_command",
        {"chain": fx_au2["chain"], "command": oc_env, "device_list": {**dl_ok, "owner": "id/bob"}, "is_foreign_service": False},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "owner-command whose device_list.owner != command.owner refuses DEVICE_UNAUTHORIZED.",
    )
    add(
        "d7-oc-unpinned-owner-manifest-refuse",
        ["SL-IDEN-011"],
        "owner_command",
        {"chain": fx_au2["chain"], "command": oc_env, "device_list": dl_ok, "is_foreign_service": False, "owner_manifest": fx_au2["_alice_man"]},
        "REFUSE",
        "MANIFEST_MISMATCH",
        "owner-command when owner_manifest lacks matching sets.devices pin refuses MANIFEST_MISMATCH.",
    )

    # --- Batch 3: Origin, operator_min_depth boundaries, Majority MTP, D-1/B-15/emancipation handover ---
    # 3a. operator_min_depth = 2 exact boundaries on origin, binding, status_spend, roster_spend, slot spend, and notary_act!
    of_md = rm._base_origin_fixture()
    tip_md = of_md["chain"]["tip_height"]  # 750010
    # Origin at tip_height (depth 1 < 2 -> CHAIN_DEPTH_INSUFFICIENT)
    of_md_o = copy.deepcopy(of_md)
    of_md_o["chain"]["txs"][of_md_o["origin_bundle"]["origin_anchor_txid"]]["confirmed_height"] = tip_md
    add(
        "d7-bnd-origin-min-depth-1-lt-2-refuse",
        ["SL-ORIG-002", "SL-LDGR-008"],
        "origin_status",
        {"chain": of_md_o["chain"], "operator_min_depth": 2, "origin_bundle": of_md_o["origin_bundle"], "trusted_origin_issuer_pins": of_md_o["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_DEPTH_INSUFFICIENT",
        "Exact boundary: origin anchor at depth 1 with operator_min_depth=2 refuses CHAIN_DEPTH_INSUFFICIENT.",
    )
    # Origin at tip - 1 (depth 2 == 2 -> ADMIT_WARD) — wait binding must be > h_origin, so set tip = h_origin + 1 for origin, and test binding at tip (depth 1 < 2) vs tip - 1 (depth 2 == 2)!
    of_md_b = copy.deepcopy(of_md)
    of_md_b["chain"]["txs"][of_md_b["origin_bundle"]["name_binding_txid"]]["confirmed_height"] = tip_md
    add(
        "d7-bnd-binding-min-depth-1-lt-2-refuse",
        ["SL-ORIG-002", "SL-LDGR-008"],
        "origin_status",
        {"chain": of_md_b["chain"], "operator_min_depth": 2, "origin_bundle": of_md_b["origin_bundle"], "trusted_origin_issuer_pins": of_md_b["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_DEPTH_INSUFFICIENT",
        "Exact boundary: name-binding 0x0c at depth 1 with operator_min_depth=2 refuses CHAIN_DEPTH_INSUFFICIENT.",
    )
    # Exact depth == 2 on origin (h_origin = tip - 1? need bind > h_origin, so set h_origin = tip - 2, h_fu = tip - 1, h_bind = tip - 1 -> depth 2 == 2 ADMIT_WARD AND kills h_fu <= h_origin & bind < h_fu!)
    of_md_exact = copy.deepcopy(of_md)
    h_o_ex = tip_md - 2
    of_md_exact["chain"]["txs"][of_md_exact["origin_bundle"]["origin_anchor_txid"]]["confirmed_height"] = h_o_ex
    of_md_exact["chain"]["names"]["id/child-leo"]["updates"][0]["confirmed_height"] = h_o_ex + 1
    of_md_exact["chain"]["names"]["id/child-leo"]["updates"][1]["confirmed_height"] = h_o_ex + 1
    of_md_exact["chain"]["txs"][of_md_exact["origin_bundle"]["name_binding_txid"]]["confirmed_height"] = h_o_ex + 1
    # Also test operator_min_depth=3 with h_origin = tip - 2 (depth == 3) -> ADMIT_WARD? No: bind is at tip - 1 -> depth 2!
    # So with operator_min_depth = 2: origin depth = 3, bind depth = 2 (exact == 2!), AND h_fu == h_origin + 1, bind_h == h_fu (exact == h_fu!)
    add(
        "d7-bnd-binding-exact-min-depth-2-and-eq-h-fu-admit",
        ["SL-ORIG-002", "SL-LDGR-008"],
        "origin_status",
        {"chain": of_md_exact["chain"], "operator_min_depth": 2, "origin_bundle": of_md_exact["origin_bundle"], "trusted_origin_issuer_pins": of_md_exact["trusted_origin_issuer_pins"]},
        "ADMIT_WARD",
        None,
        "Exact boundary: bind_tx at depth == operator_min_depth (2) and bind_h == h_fu == h_origin + 1 admits (kills < -> <=).",
    )
    # Exact origin depth == operator_min_depth (set operator_min_depth=3, h_origin=tip-2, bind=tip-2? No, bind > h_origin so bind depth < origin depth!
    # Wait: if operator_min_depth = 2 and h_origin = tip - 1 is impossible if bind > h_origin AND bind <= tip. What if bind is at tip - 1? Then h_origin <= tip - 2 so depth(origin) >= 3!
    # Wait: h_origin CAN have depth == operator_min_depth ONLY IF bind_h == h_origin + 1 AND tip == bind_h - 1 (impossible) UNLESS operator_min_depth is checked at h_origin == tip - 1 (depth 2) BEFORE binding check (which then fails bind_h <= h_origin or depth 1)!
    # Aha! If operator_min_depth = 2, h_origin = tip - 1 (depth 2!), bind_tx at tip (depth 1 -> CHAIN_DEPTH_INSUFFICIENT? No, both return CHAIN_DEPTH_INSUFFICIENT!),
    # whereas if bind_tx is at tip - 1 (same height as h_origin -> ORIGIN_BINDING_INVALID!):
    # With < operator_min_depth (2): depth(origin) = 2 passes L2198 -> reaches L2169 bind_h <= h_origin -> returns ORIGIN_BINDING_INVALID!
    # If L2198 mutated < to <=: depth(origin) = 2 <= 2 -> returns CHAIN_DEPTH_INSUFFICIENT instead of ORIGIN_BINDING_INVALID -> KILLED!!
    of_md_o2 = copy.deepcopy(of_md)
    of_md_o2["chain"]["txs"][of_md_o2["origin_bundle"]["origin_anchor_txid"]]["confirmed_height"] = tip_md - 1
    of_md_o2["chain"]["txs"][of_md_o2["origin_bundle"]["name_binding_txid"]]["confirmed_height"] = tip_md - 1
    of_md_o2["chain"]["names"].pop("id/child-leo", None)
    add(
        "d7-bnd-origin-depth-eq-2-then-bind-eq-origin-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"chain": of_md_o2["chain"], "operator_min_depth": 2, "origin_bundle": of_md_o2["origin_bundle"], "trusted_origin_issuer_pins": of_md_o2["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "Exact boundary: origin at depth == operator_min_depth (2) passes depth check and refuses ORIGIN_BINDING_INVALID when bind_h == h_origin (kills both < -> <= and <= -> <).",
    )
    # h_fu == h_origin (exact <= -> < boundary!)
    of_fu_eq = copy.deepcopy(of_md)
    h_o_fu = of_fu_eq["chain"]["txs"][of_fu_eq["origin_bundle"]["origin_anchor_txid"]]["confirmed_height"]
    of_fu_eq["chain"]["names"]["id/child-leo"]["updates"][0]["confirmed_height"] = h_o_fu
    add(
        "d7-bnd-firstupdate-eq-origin-height-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"chain": of_fu_eq["chain"], "origin_bundle": of_fu_eq["origin_bundle"], "trusted_origin_issuer_pins": of_fu_eq["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "Exact boundary: h_firstupdate == h_origin refuses ORIGIN_BINDING_INVALID (kills <= -> <).",
    )

    # 3b. Status spend (end/1) & roster spend (0x0f) exact depth == 1 vs 2 + CHAIN_MISMATCH on binding/end/capacity + absent_from_utxo
    of_end_d = rm._base_origin_fixture()
    st_s = of_end_d["origin_bundle"]["origin"]["payload"]["status_seal"]
    end_p_d = {"basis_sha256": _h32("d7-end-basis"), "genesis": GENESIS_MAIN, "issued_at": 1795220000, "issuer": of_end_d["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main", "origin_id": of_end_d["_origin_id"], "reason": "dematerialization", "status_prev_outpoint": {"txid": st_s["txid"], "vout": 0}, "type": "seallink-end/1"}
    end_env_d = sl.sign_envelope(end_p_d, [of_end_d["_keys"]["reg_cred"]["sk"]])
    end_tx_d = _h32("d7-end-depth-tx")
    of_end_d["chain"]["txs"][st_s["txid"]]["outputs"]["0"]["spent_by_txid"] = end_tx_d
    of_end_d["chain"]["txs"][end_tx_d] = {"confirmed_height": tip_md, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(end_env_d)).hex(), "outputs": {}}
    of_end_d["origin_bundle"]["end_record"] = end_env_d
    add(
        "d7-bnd-status-spend-depth-1-lt-2-refuse",
        ["SL-ORIG-002", "SL-LDGR-008"],
        "origin_status",
        {"chain": of_end_d["chain"], "operator_min_depth": 2, "origin_bundle": of_end_d["origin_bundle"], "trusted_origin_issuer_pins": of_end_d["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_DEPTH_INSUFFICIENT",
        "Exact boundary: status_seal spend at depth 1 with operator_min_depth=2 refuses CHAIN_DEPTH_INSUFFICIENT.",
    )
    of_end_d2 = copy.deepcopy(of_end_d)
    of_end_d2["chain"]["txs"][end_tx_d]["confirmed_height"] = tip_md - 1  # depth == 2 -> SUBJECT_ENDED!
    add(
        "d7-bnd-status-spend-depth-eq-2-subject-ended",
        ["SL-ORIG-002", "SL-ORIG-012"],
        "origin_status",
        {"chain": of_end_d2["chain"], "operator_min_depth": 2, "origin_bundle": of_end_d2["origin_bundle"], "trusted_origin_issuer_pins": of_end_d2["trusted_origin_issuer_pins"]},
        "REFUSE",
        "SUBJECT_ENDED",
        "Exact boundary: status_seal spend at depth == operator_min_depth (2) reaches SUBJECT_ENDED (kills < -> <=).",
    )
    # end/1 CHAIN_MISMATCH
    of_end_cm = rm._base_origin_fixture()
    end_cm = sl.sign_envelope({**end_p_d, "genesis": _h32("wrong-gen-end")}, [of_end_cm["_keys"]["reg_cred"]["sk"]])
    end_cm_tx = _h32("d7-end-cm-tx")
    of_end_cm["chain"]["txs"][st_s["txid"]]["outputs"]["0"]["spent_by_txid"] = end_cm_tx
    of_end_cm["chain"]["txs"][end_cm_tx] = {"confirmed_height": tip_md - 5, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(end_cm)).hex(), "outputs": {}}
    of_end_cm["origin_bundle"]["end_record"] = end_cm
    add(
        "d7-end-record-chain-mismatch-refuse",
        ["SL-ORIG-012"],
        "origin_status",
        {"chain": of_end_cm["chain"], "origin_bundle": of_end_cm["origin_bundle"], "trusted_origin_issuer_pins": of_end_cm["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_MISMATCH",
        "seallink-end/1 with wrong genesis refuses CHAIN_MISMATCH.",
    )
    # capacity/1 CHAIN_MISMATCH
    of_cap_cm = rm._base_origin_fixture()
    cap_cm = sl.sign_envelope({"basis_sha256": _h32("cap-cm-b"), "genesis": _h32("wrong-gen-cap"), "issued_at": 1795220000, "issuer": of_cap_cm["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main", "next_status_policy": st_s["script_policy"], "next_status_vout": 0, "origin_id": of_cap_cm["_origin_id"], "status_prev_outpoint": {"txid": st_s["txid"], "vout": 0}, "subject_new_owner_policy": {"kind": "key", "pk": _kp("d7-cm-new")["comp"]}, "type": "seallink-capacity/1"}, [of_cap_cm["_keys"]["reg_cred"]["sk"]])
    cap_cm_tx = _h32("d7-cap-cm-tx")
    of_cap_cm["chain"]["txs"][st_s["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_cm_tx
    of_cap_cm["chain"]["txs"][cap_cm_tx] = {"confirmed_height": tip_md - 5, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_cm)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(st_s["script_policy"])}}}
    of_cap_cm["origin_bundle"]["capacity_record"] = cap_cm
    add(
        "d7-capacity-record-chain-mismatch-refuse",
        ["SL-ORIG-011"],
        "origin_status",
        {"chain": of_cap_cm["chain"], "origin_bundle": of_cap_cm["origin_bundle"], "trusted_origin_issuer_pins": of_cap_cm["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_MISMATCH",
        "seallink-capacity/1 with wrong genesis refuses CHAIN_MISMATCH.",
    )
    # binding CHAIN_MISMATCH
    of_bnd_cm = rm._base_origin_fixture()
    of_bnd_cm["origin_bundle"]["name_binding"]["genesis"] = _h32("wrong-gen-bnd")
    add(
        "d7-binding-chain-mismatch-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"chain": of_bnd_cm["chain"], "origin_bundle": of_bnd_cm["origin_bundle"], "trusted_origin_issuer_pins": of_bnd_cm["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_MISMATCH",
        "seallink-name-binding/1 with wrong genesis refuses CHAIN_MISMATCH.",
    )
    # status_seal absent_from_utxo & roster_seal absent_from_utxo
    of_abs_s = rm._base_origin_fixture()
    of_abs_s["chain"]["txs"][st_s["txid"]]["outputs"]["0"]["absent_from_utxo"] = True
    add(
        "d7-status-seal-absent-from-utxo-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"chain": of_abs_s["chain"], "origin_bundle": of_abs_s["origin_bundle"], "trusted_origin_issuer_pins": of_abs_s["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "Unattributed missing status_seal (absent_from_utxo=True) refuses ORIGIN_STATUS_INCOMPLETE.",
    )
    of_abs_r = rm._base_origin_fixture()
    rs_o = of_abs_r["origin_bundle"]["origin"]["payload"]["guardian_policy"]["roster_seal"]
    of_abs_r["chain"]["txs"][rs_o["txid"]]["outputs"]["0"]["absent_from_utxo"] = True
    add(
        "d7-roster-seal-absent-from-utxo-refuse",
        ["SL-ORIG-015"],
        "origin_status",
        {"chain": of_abs_r["chain"], "origin_bundle": of_abs_r["origin_bundle"], "trusted_origin_issuer_pins": of_abs_r["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "Unattributed missing roster_seal (absent_from_utxo=True) refuses ORIGIN_STATUS_INCOMPLETE.",
    )

    # 3c. Majority commitment omitted disclosure (B-13) + exact MTP == T vs T-1 boundary + D-1 recovery_burned assert_binding_id
    of_mj_miss = rm._base_origin_fixture()
    of_mj_miss["origin_bundle"].pop("opened_majority_unix", None)
    add(
        "d7-b13-majority-commitment-omitted-disclosure-refuse",
        ["SL-ORIG-010"],
        "origin_status",
        {"chain": of_mj_miss["chain"], "origin_bundle": of_mj_miss["origin_bundle"], "trusted_origin_issuer_pins": of_mj_miss["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "B-13: omitting opened_majority_unix when origin.claims.majority_commitment is present refuses ORIGIN_STATUS_INCOMPLETE.",
    )
    of_mtp_eq = rm._base_origin_fixture()
    t_maj = of_mtp_eq["_maj_unix"]
    of_mtp_eq["chain"]["credible_utc_interval"] = [t_maj - 10, t_maj - 1]
    of_mtp_eq["chain"]["tip_median_time_past"] = t_maj  # Exact MTP == T -> GUARDIAN_TIME_BOUNDARY!
    add(
        "d7-bnd-majority-mtp-eq-t-refuse",
        ["SL-ORIG-010"],
        "origin_status",
        {"chain": of_mtp_eq["chain"], "origin_bundle": of_mtp_eq["origin_bundle"], "trusted_origin_issuer_pins": of_mtp_eq["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_TIME_BOUNDARY",
        "B-13 exact boundary: tip_median_time_past == T while t_low < T refuses GUARDIAN_TIME_BOUNDARY (kills >= -> >).",
    )
    of_mtp_lt = copy.deepcopy(of_mtp_eq)
    of_mtp_lt["chain"]["tip_median_time_past"] = t_maj - 1  # MTP == T - 1 -> ADMIT_WARD!
    add(
        "d7-bnd-majority-mtp-lt-t-admit-ward",
        ["SL-ORIG-010"],
        "origin_status",
        {"chain": of_mtp_lt["chain"], "origin_bundle": of_mtp_lt["origin_bundle"], "trusted_origin_issuer_pins": of_mtp_lt["trusted_origin_issuer_pins"]},
        "ADMIT_WARD",
        None,
        "B-13 exact boundary: t_low < T and tip_median_time_past == T - 1 admits ward capacity.",
    )
    of_d1_ab = rm._base_origin_fixture()
    rec_s = of_d1_ab["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
    mal_rec_tx = _h32("d7-d01-malformed-rec-spend")
    of_d1_ab["chain"]["txs"][rec_s["txid"]]["outputs"]["0"]["spent_by_txid"] = mal_rec_tx
    of_d1_ab["chain"]["txs"][mal_rec_tx] = {"confirmed_height": 749500, "outputs": {"0": {"script_pubkey_hex": "0014" + "99" * 20}}}
    add(
        "d7-d01-recovery-burned-assert-wrong-binding-refuse",
        ["SL-ORIG-013"],
        "origin_status",
        {"assert_binding_id": _h32("wrong-binding"), "chain": of_d1_ab["chain"], "origin_bundle": of_d1_ab["origin_bundle"], "trusted_origin_issuer_pins": of_d1_ab["trusted_origin_issuer_pins"]},
        "REFUSE",
        "RECOVERY_FORBIDDEN",
        "Decision D-1 / R2G-01: when recovery_seal is provably burned by a confirmed malformed spend and assert_binding_id != active B_k, refuse RECOVERY_FORBIDDEN.",
    )

    # 3d. Roster 0x0f depth boundary (1 vs 2) & B-15 exact h_0x0d == roster_eff_h ADMIT + slot depth boundary (1 vs 2)
    of_r_d = rm._base_origin_fixture()
    gp_rd = of_r_d["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    dly_rd = gp_rd["appointment_delay_blocks"]  # 144
    vac_rd = gp_rd["roster_seal"]["script_policy"]
    g_rd_k = _kp("d7-rd-g")
    pend_rd = {"delay_blocks": dly_rd, "keys": {"challenger": gp_rd["challenger_pk"], "disposer": gp_rd["disposer_pk"], "guardian": g_rd_k["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
    act_rd = {"keys": sl.canonical_branch_pair(gp_rd["disposer_pk"], g_rd_k["comp"]), "kind": "branch", "template": "either_of_2"}
    rost_rd_p = {
        "arbiter_pk": gp_rd["arbiter_pk"], "challenger_pk": gp_rd["challenger_pk"], "disposer_pk": gp_rd["disposer_pk"],
        "effective_delay_blocks": dly_rd, "genesis": GENESIS_MAIN, "issuer": of_r_d["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main", "next_roster_policy": vac_rd, "next_roster_vout": 0, "origin_id": of_r_d["_origin_id"],
        "prev_revision": 1, "prev_roster_outpoint": {"txid": gp_rd["roster_seal"]["txid"], "vout": 0},
        "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in gp_rd["quorums"]},
        "revision": 2, "revision_size": 1,
        "slots": [{"action": "new_vacant", "new_vacant_policy": vac_rd, "new_vacant_vout": 1, "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    rost_rd = sl.sign_envelope(rost_rd_p, [of_r_d["_keys"]["reg_cred"]["sk"]])
    rtx_rd, dtx_rd, etx_rd = _h32("d7-rd-rtx"), _h32("d7-rd-dtx"), _h32("d7-rd-etx")
    g2_rd_p = {
        "activation_mode": "appointed", "active_policy": act_rd, "effective_delay_blocks": dly_rd,
        "genesis": GENESIS_MAIN, "guardian": of_r_d["origin_bundle"]["guardian_records"][0]["payload"]["guardian"],
        "issuer": of_r_d["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main", "origin_id": of_r_d["_origin_id"],
        "pending_policy": pend_rd, "pending_vout": 0, "prev_outpoint": {"txid": rtx_rd, "vout": 1}, "revision": 2, "slot": 1,
        "term": {"mode": "indefinite"}, "type": "seallink-guardian/1",
    }
    g2_rd = sl.sign_envelope(g2_rd_p, [of_r_d["_keys"]["reg_cred"]["sk"]])
    g2_rd_ass = sl.sign_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d7-rd-ga"),
         "party_id": "g-rd", "party_name": "id/parent-a", "party_role": "guardian", "target_id": sl.object_id(g2_rd_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"},
        [of_r_d["_keys"]["g1_gr"]["sk"]],
    )
    of_r_d["chain"]["txs"][gp_rd["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_rd
    of_r_d["chain"]["txs"][rtx_rd] = {"confirmed_height": tip_md, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_rd)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_rd)}, "1": {"script_pubkey_hex": _spk_hex(vac_rd)}}}
    of_r_d["origin_bundle"]["roster_records"] = [rost_rd]
    add(
        "d7-bnd-roster-spend-depth-1-lt-2-refuse",
        ["SL-ORIG-015", "SL-LDGR-008"],
        "origin_status",
        {"chain": of_r_d["chain"], "operator_min_depth": 2, "origin_bundle": of_r_d["origin_bundle"], "trusted_origin_issuer_pins": of_r_d["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_DEPTH_INSUFFICIENT",
        "Exact boundary: roster 0x0f spend at depth 1 with operator_min_depth=2 refuses CHAIN_DEPTH_INSUFFICIENT.",
    )
    of_r_d2 = copy.deepcopy(of_r_d)
    of_r_d2["chain"]["txs"][rtx_rd]["confirmed_height"] = tip_md - 1  # depth == 2 (not yet effective -> ADMIT_WARD!)
    add(
        "d7-bnd-roster-spend-depth-eq-2-admit",
        ["SL-ORIG-015", "SL-LDGR-008"],
        "origin_status",
        {"chain": of_r_d2["chain"], "operator_min_depth": 2, "origin_bundle": of_r_d2["origin_bundle"], "trusted_origin_issuer_pins": of_r_d2["trusted_origin_issuer_pins"]},
        "ADMIT_WARD",
        None,
        "Exact boundary: roster 0x0f spend at depth == operator_min_depth (2) admits (kills < -> <=).",
    )
    # B-15 exact h_0x0d == roster_eff_h (min_appoint_height) -> ADMIT, and slot 0x0e at depth 1 vs 2 with operator_min_depth=2!
    of_pe_ok = copy.deepcopy(of_r_d)
    h_r_ok = tip_md - (2 * dly_rd + 1)
    h_d_ok = h_r_ok + dly_rd  # EXACT == min_appoint_height!
    h_e_ok = h_d_ok + dly_rd  # == tip_md - 1 -> depth == 2!
    of_pe_ok["chain"]["txs"][rtx_rd] = {"confirmed_height": h_r_ok, "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_rd)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_rd)}, "1": {"script_pubkey_hex": _spk_hex(vac_rd), "spent_by_txid": dtx_rd}}}
    of_pe_ok["chain"]["txs"][dtx_rd] = {"confirmed_height": h_d_ok, "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g2_rd)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_rd), "spent_by_txid": etx_rd}}}
    of_pe_ok["chain"]["txs"][etx_rd] = {"confirmed_height": h_e_ok, "inputs": [sv.make_guardian_csv_input(dtx_rd, 0, pend_rd, sequence=dly_rd)], "opreturn_hex": sl.encode_opreturn(0x0E, sl.object_id(g2_rd_p)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_rd)}}}
    of_pe_ok["origin_bundle"]["guardian_records"].append(g2_rd)
    of_pe_ok["origin_bundle"]["guardian_assents"].append(g2_rd_ass)
    wa_rd = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": of_r_d["_origin_id"], "revision": 2, "ward_name": "id/child-leo"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("d7-rd-wa"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
         "target_id": sl.object_id(of_r_d["contract"]), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"slot": 1, "revision": 2, "guardian_name": "id/parent-a", "signers": [of_r_d["_keys"]["g1_gr"]["sk"]]}],
    )
    add(
        "d7-bnd-b15-exact-min-appoint-height-and-slot-depth-2-admit",
        ["SL-ORIG-015", "SL-ORIG-008"],
        "assent",
        {"assent": wa_rd, "chain": of_pe_ok["chain"], "contract": of_pe_ok["contract"], "operator_min_depth": 2, "origin_bundle": of_pe_ok["origin_bundle"], "trusted_origin_issuer_pins": of_pe_ok["trusted_origin_issuer_pins"]},
        "ADMIT",
        None,
        "B-15 exact boundary: 0x0d at h == roster_eff_h and 0x0e at depth == operator_min_depth (2) admits (kills both < -> <=).",
    )
    of_pe_d1 = copy.deepcopy(of_pe_ok)
    of_pe_d1["chain"]["txs"][etx_rd]["confirmed_height"] = tip_md  # depth 1 < 2 -> stays pending -> GUARDIAN_INACTIVE!
    add(
        "d7-bnd-slot-0x0e-depth-1-lt-2-inactive",
        ["SL-ORIG-008", "SL-LDGR-008"],
        "assent",
        {"assent": wa_rd, "chain": of_pe_d1["chain"], "contract": of_pe_d1["contract"], "operator_min_depth": 2, "origin_bundle": of_pe_d1["origin_bundle"], "trusted_origin_issuer_pins": of_pe_d1["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_INACTIVE",
        "Exact boundary: slot 0x0e at depth 1 with operator_min_depth=2 remains pending (GUARDIAN_INACTIVE).",
    )

    # 3e. Emancipation handover via promoted seq==2 recovery binding with exactly 2 updates (kills BOTH >= 2 in _check_emancipation_handover!)
    of_eh2 = rm._base_origin_fixture()
    new_reg_eh = {"txid": _h32("d7-eh2-reg"), "vout": 0}
    new_pol_eh = {"kind": "key", "pk": _kp("d7-eh2-own")["comp"]}
    rec_s_eh = of_eh2["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
    cand_eh = {
        "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": "id/leo-adult", "network": "main",
        "next_recovery_policy": rec_s_eh["script_policy"], "next_recovery_vout": 0,
        "origin_id": of_eh2["_origin_id"], "owner_policy": new_pol_eh, "registration": new_reg_eh,
        "seq": 2, "supersedes_binding_id": sl.object_id(of_eh2["origin_bundle"]["name_binding"]),
        "type": "seallink-name-binding/1",
    }
    rec_tx_eh = _h32("d7-eh2-rec-tx")
    of_eh2["chain"]["txs"][rec_s_eh["txid"]]["outputs"]["0"]["spent_by_txid"] = rec_tx_eh
    of_eh2["chain"]["txs"][rec_tx_eh] = {"confirmed_height": tip_md - 200, "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(cand_eh)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_s_eh["script_policy"])}}}
    of_eh2["chain"].setdefault("block_times", {})[str((tip_md - 200) + 144)] = of_eh2["_maj_unix"] + 10
    of_eh2["origin_bundle"]["recovery_bindings"] = [cand_eh]
    of_eh2["chain"]["credible_utc_interval"] = [of_eh2["_maj_unix"] + 100, of_eh2["_maj_unix"] + 200]
    of_eh2["chain"]["names"]["id/leo-adult"] = sv.make_name_history("id/leo-adult", new_reg_eh, new_pol_eh, {"link": {"grant": of_eh2["_keys"]["ward_gr"]["xonly"], "origin": of_eh2["_origin_id"]}}, first_height=749700, update_height=749850)
    add(
        "d7-bnd-emancipation-handover-seq2-2-updates-autonomous",
        ["SL-ORIG-011", "SL-ORIG-013"],
        "origin_status",
        {"chain": of_eh2["chain"], "origin_bundle": of_eh2["origin_bundle"], "trusted_origin_issuer_pins": of_eh2["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "Exact boundary: emancipated handover via seq==2 promoted recovery binding with len(updates)==2 admits autonomous (kills both >= 2 -> > 2).",
    )

    # --- Batch 4: Assent, Credential, Notary, Verdict, Termination, Certset-Head, Statement ---
    # 4a. verify_assent: CHAIN_MISMATCH, expires_at == issued_at, ward name_pin mismatch, autonomous masquerading as ward, autonomous bad signing_policy
    of_as = rm._base_origin_fixture()
    c_as = copy.deepcopy(of_as["contract"])
    a_sch_base = {"expires_at": 1795220500, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d7-as-n1"), "party_id": "school-1", "party_name": "id/school", "party_role": "school", "target_id": sl.object_id(c_as), "target_type": "seallink-contract/1", "type": "seallink-assent/1"}
    add(
        "d7-assent-chain-mismatch-refuse",
        ["SL-CONT-004"],
        "assent",
        {"assent": sl.sign_envelope({**a_sch_base, "genesis": _h32("wrong-as-gen")}, [of_as["_keys"]["sch_gr"]["sk"]]), "chain": of_as["chain"], "contract": c_as, "origin_bundle": of_as["origin_bundle"], "trusted_origin_issuer_pins": of_as["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_MISMATCH",
        "seallink-assent/1 with wrong genesis refuses CHAIN_MISMATCH.",
    )
    add(
        "d7-bnd-assent-exp-eq-iat-refuse",
        ["SL-CONT-004"],
        "assent",
        {"assent": sl.sign_envelope({**a_sch_base, "expires_at": 1795220000, "nonce": _h32("d7-as-n2")}, [of_as["_keys"]["sch_gr"]["sk"]]), "chain": of_as["chain"], "contract": c_as, "origin_bundle": of_as["origin_bundle"], "trusted_origin_issuer_pins": of_as["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CONTRACT_ASSENT_INVALID",
        "Exact boundary: assent with expires_at == issued_at refuses CONTRACT_ASSENT_INVALID (kills <= -> <).",
    )
    c_as_wnp = copy.deepcopy(c_as)
    c_as_wnp["parties"][0]["name_pin"] = {"name": "id/wrong-ward", "owner_policy": of_as["origin_bundle"]["name_binding"]["owner_policy"], "registration": of_as["origin_bundle"]["name_binding"]["registration"]}
    a_wnp = sl.sign_guardian_envelope(
        {"expires_at": 1795220500, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": of_as["_origin_id"], "revision": 1, "ward_name": "id/child-leo"}, "issued_at": 1795220000, "network": "main", "nonce": _h32("d7-as-n3"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward", "target_id": sl.object_id(c_as_wnp), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_as["_keys"]["g1_gr"]["sk"]], "slot": 1}, {"guardian_name": "id/parent-b", "revision": 1, "signers": [of_as["_keys"]["g2_gr"]["sk"]], "slot": 2}],
    )
    add(
        "d7-assent-ward-party-name-pin-mismatch-refuse",
        ["SL-CONT-004", "SL-ORIG-002"],
        "assent",
        {"assent": a_wnp, "chain": of_as["chain"], "contract": c_as_wnp, "origin_bundle": of_as["origin_bundle"], "trusted_origin_issuer_pins": of_as["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "Contract ward party whose name_pin disagrees with verified origin binding refuses ORIGIN_BINDING_INVALID.",
    )
    # Autonomous party masquerading as ward (has name_pin pointing to id/child-leo WITHOUT ward_origin_id!)
    c_masq = copy.deepcopy(c_as)
    c_masq["parties"][1] = {"name_pin": {"name": "id/child-leo", "owner_policy": of_as["origin_bundle"]["name_binding"]["owner_policy"], "registration": of_as["origin_bundle"]["name_binding"]["registration"]}, "party_id": "masq-1", "role": "school", "signing_policy": {"m": 1, "pks": [of_as["_keys"]["ward_gr"]["xonly"]]}}
    a_masq = sl.sign_envelope({**a_sch_base, "nonce": _h32("d7-as-n4"), "party_id": "masq-1", "party_name": "id/child-leo", "target_id": sl.object_id(c_masq)}, [of_as["_keys"]["ward_gr"]["sk"]])
    add(
        "d7-h32-autonomous-party-ward-missing-origin-bundle-refuse",
        ["SL-CONT-004", "SL-ORIG-006"],
        "assent",
        {"assent": a_masq, "chain": of_as["chain"], "contract": c_masq, "trusted_origin_issuer_pins": of_as["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "H-32: autonomous contract party whose name has historical link.origin with omitted origin_bundle refuses ORIGIN_UNVERIFIED.",
    )
    add(
        "d7-h32-autonomous-party-masquerading-as-ward-refuse",
        ["SL-CONT-004", "SL-ORIG-006"],
        "assent",
        {"assent": a_masq, "chain": of_as["chain"], "contract": c_masq, "origin_bundle": of_as["origin_bundle"], "trusted_origin_issuer_pins": of_as["trusted_origin_issuer_pins"]},
        "REFUSE",
        "WARD_AUTONOMOUS_FORBIDDEN",
        "H-32: ward name listed as autonomous party without ward_origin_id refuses WARD_AUTONOMOUS_FORBIDDEN.",
    )
    # Autonomous party with name_pin whose signing_policy != link.grant -> CONTRACT_ASSENT_INVALID
    fx_apb = rm._contract_fx()
    c_apb = copy.deepcopy(fx_apb["bundle"]["contract"])
    other_sp = _kp("d7-apb-other")
    c_apb["parties"][0] = {"name_pin": {"name": "id/alice", "owner_policy": fx_apb["_alice_owner_pol"], "registration": fx_apb["_alice_reg"]}, "party_id": "p-alice", "role": "client", "signing_policy": {"m": 1, "pks": [other_sp["xonly"]]}}
    a_apb = sl.sign_envelope({"expires_at": fx_apb["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "issued_at": fx_apb["chain"]["now"] - 10, "network": "main", "nonce": _h32("d7-apb-n"), "party_id": "p-alice", "party_name": "id/alice", "party_role": "client", "target_id": sl.object_id(c_apb), "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [other_sp["sk"]])
    add(
        "d7-h32-autonomous-party-signing-policy-mismatch-refuse",
        ["SL-CONT-004"],
        "assent",
        {"assent": a_apb, "chain": fx_apb["chain"], "contract": c_apb},
        "REFUSE",
        "CONTRACT_ASSENT_INVALID",
        "H-32: autonomous party whose signing_policy does not match name_pin's live link.grant refuses CONTRACT_ASSENT_INVALID.",
    )

    # 4b. verify_credential: subject.origin mismatch, not_after_unix == now vs now+1, tampered withdrawal_doc
    of_cr = rm._base_origin_fixture()
    cr_base_p = {"claims": {"status": "ok"}, "credential_kind": "education/enrollment-v1", "genesis": GENESIS_MAIN, "issued_at": 1795200000, "issuer": of_cr["origin_bundle"]["origin"]["payload"]["issuer"], "lifecycle": "eternal", "network": "main", "not_before_height": 749000, "subject": {"mode": "origin", "origin_id": _h32("wrong-subj-oid")}, "type": "seallink-credential/1"}
    cr_bad_o = sl.sign_envelope(cr_base_p, [of_cr["_keys"]["reg_cred"]["sk"]])
    cr_bad_o_tx = _h32("d7-cr-bo-tx")
    of_cr["chain"]["txs"][cr_bad_o_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_bad_o)).hex(), "outputs": {}}
    add(
        "d7-d6-credential-subject-origin-mismatch-refuse",
        ["SL-CONT-010"],
        "credential",
        {"anchor_txid": cr_bad_o_tx, "chain": of_cr["chain"], "credential": cr_bad_o, "origin_bundle": of_cr["origin_bundle"], "trusted_origin_issuer_pins": of_cr["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "D-6: credential subject.origin_id disagreeing with verified origin_bundle refuses ORIGIN_UNVERIFIED.",
    )
    cr_nu_eq = sl.sign_envelope({**cr_base_p, "not_after_unix": of_cr["chain"]["now"], "subject": {"mode": "origin", "origin_id": of_cr["_origin_id"]}}, [of_cr["_keys"]["reg_cred"]["sk"]])
    cr_nu_eq_tx = _h32("d7-cr-nueq-tx")
    of_cr["chain"]["txs"][cr_nu_eq_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_nu_eq)).hex(), "outputs": {}}
    add(
        "d7-bnd-credential-not-after-unix-eq-now-refuse",
        ["SL-CONT-010"],
        "credential",
        {"anchor_txid": cr_nu_eq_tx, "chain": of_cr["chain"], "credential": cr_nu_eq, "origin_bundle": of_cr["origin_bundle"], "trusted_origin_issuer_pins": of_cr["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CRED_WINDOW_CLOSED",
        "Exact boundary: credential not_after_unix == chain.now refuses CRED_WINDOW_CLOSED (kills >= -> >).",
    )
    w_s_pol2 = {"kind": "key", "pk": _kp("d7-w2-s")["comp"]}
    w_s_tx2, w_sp_tx2, cr_w2_tx = _h32("d7-w2-stx"), _h32("d7-w2-sptx"), _h32("d7-w2-0x09")
    cr_w2_p = {**cr_base_p, "lifecycle": "revocable", "revocation_seal": {"script_policy": w_s_pol2, "txid": w_s_tx2, "vout": 0}, "subject": {"mode": "origin", "origin_id": of_cr["_origin_id"]}}
    cr_w2 = sl.sign_envelope(cr_w2_p, [of_cr["_keys"]["reg_cred"]["sk"]])
    w_doc_bad = {"cause_sha256": _h32("w2-c"), "credential_id": _h32("wrong-cid"), "genesis": GENESIS_MAIN, "type": "seallink-credential-withdrawal/1"}
    of_cr["chain"]["txs"][cr_w2_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_w2)).hex(), "outputs": {}}
    of_cr["chain"]["txs"][w_s_tx2] = {"confirmed_height": 749490, "outputs": {"0": {"script_pubkey_hex": _spk_hex(w_s_pol2), "spent_by_txid": w_sp_tx2}}}
    of_cr["chain"]["txs"][w_sp_tx2] = {"confirmed_height": 749900, "opreturn_hex": sl.encode_opreturn(0x0A, sl.signing_digest(w_doc_bad).hex()).hex(), "outputs": {}}
    add(
        "d7-r3h8-credential-withdrawal-mismatched-doc-refuse",
        ["SL-CONT-010"],
        "credential",
        {"anchor_txid": cr_w2_tx, "chain": of_cr["chain"], "credential": cr_w2, "origin_bundle": of_cr["origin_bundle"], "trusted_origin_issuer_pins": of_cr["trusted_origin_issuer_pins"], "withdrawal_doc": w_doc_bad},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "R3-H8: 0x0a withdrawal_doc with mismatched credential_id refuses CHAIN_FRAME_INVALID.",
    )

    # 4c. verify_notary_act: CHAIN_MISMATCH, CRED_ANCHOR_MISSING, operator_min_depth (1 vs 2), expected_notary_name, allowed_notaries
    fx_na = rm._base_invocation_fixture()
    not_own, not_k = _kp("d7-na-own"), _kp("d7-na-k")
    not_pol = {"kind": "key", "pk": not_own["comp"]}
    not_reg = {"txid": _h32("d7-na-reg"), "vout": 0}
    not_pin = {"name": "id/notary-x", "owner_policy": not_pol, "registration": not_reg, "role_policy": {"m": 1, "pks": [not_k["xonly"]]}}
    fx_na["chain"]["names"]["id/notary-x"] = sv.make_name_history("id/notary-x", not_reg, not_pol, {"link": {"notary": not_k["xonly"]}}, first_height=748000, update_height=749000)
    na_p = {"act_kind": "fact-attestation", "attested_at": 1795220000, "details": {"fact_schema": "seallink/test-v1", "fact_sha256": _h32("na-f"), "kind": "fact-attestation"}, "genesis": GENESIS_MAIN, "lifecycle": "eternal", "network": "main", "notary": not_pin, "target_sha256": _h32("na-s"), "tip_hash": fx_na["chain"]["tip_hash"], "tip_height": fx_na["chain"]["tip_height"], "type": "seallink-notary/1"}
    na_ok = sl.sign_envelope(na_p, [not_k["sk"]])
    na_tx = _h32("d7-na-tx")
    tip_na = fx_na["chain"]["tip_height"]
    fx_na["chain"]["txs"][na_tx] = {"confirmed_height": tip_na - 1, "opreturn_hex": sl.encode_opreturn(0x04, sl.content_addr(na_ok)).hex(), "outputs": {}}
    add("d7-na-chain-mismatch-refuse", ["SL-CONT-011"], "notary_act", {"anchor_txid": na_tx, "chain": fx_na["chain"], "notary": sl.sign_envelope({**na_p, "genesis": _h32("bad-na-gen")}, [not_k["sk"]])}, "REFUSE", "CHAIN_MISMATCH", "notary/1 with wrong genesis refuses CHAIN_MISMATCH.")
    add("d7-na-missing-anchor-refuse", ["SL-CONT-011"], "notary_act", {"anchor_txid": None, "chain": fx_na["chain"], "notary": na_ok}, "REFUSE", "CRED_ANCHOR_MISSING", "notary/1 without confirmed 0x04 anchor refuses CRED_ANCHOR_MISSING.")
    add("d7-bnd-na-depth-eq-2-admit", ["SL-CONT-011", "SL-LDGR-008"], "notary_act", {"anchor_txid": na_tx, "chain": fx_na["chain"], "notary": na_ok, "operator_min_depth": 2}, "ADMIT", None, "Exact boundary: notary/1 at depth == operator_min_depth (2) admits (kills < -> <=).")
    ch_na1 = copy.deepcopy(fx_na["chain"])
    ch_na1["txs"][na_tx]["confirmed_height"] = tip_na
    add("d7-bnd-na-depth-1-lt-2-refuse", ["SL-CONT-011", "SL-LDGR-008"], "notary_act", {"anchor_txid": na_tx, "chain": ch_na1, "notary": na_ok, "operator_min_depth": 2}, "REFUSE", "CHAIN_DEPTH_INSUFFICIENT", "Exact boundary: notary/1 at depth 1 with operator_min_depth=2 refuses CHAIN_DEPTH_INSUFFICIENT.")
    add("d7-na-wrong-expected-name-refuse", ["SL-CONT-011"], "notary_act", {"anchor_txid": na_tx, "chain": fx_na["chain"], "expected_notary_name": "id/notary-other", "notary": na_ok}, "REFUSE", "NOTARY_REQUIRED", "notary/1 with wrong expected_notary_name refuses NOTARY_REQUIRED.")
    add("d7-na-disallowed-notary-refuse", ["SL-CONT-011"], "notary_act", {"allowed_notaries": [{"name": "id/notary-other", "owner_policy": not_pol, "registration": not_reg}], "anchor_txid": na_tx, "chain": fx_na["chain"], "notary": na_ok}, "REFUSE", "NOTARY_REQUIRED", "notary/1 not in allowed_notaries refuses NOTARY_REQUIRED.")

    # 4d. verify_verdict, verify_termination, verify_certset_head, verify_statement (all missing refusal + boundary branches)
    fx_vt2 = rm._contract_fx()
    mk2 = _kp("d7-vt2-mk")
    c_vt2 = {**copy.deepcopy(fx_vt2["bundle"]["contract"]), "moderation": {"moderator_key": mk2["xonly"], "moderator_kind": "agent", "rules_sha256": _h32("vt2-rules")}}
    v_p2 = {"contract_id": sl.object_id(c_vt2), "genesis": GENESIS_MAIN, "grant_id": sl.object_id(fx_vt2["bundle"]["grants"][0]["payload"]), "network": "main", "ordinal": 1, "request_salted_sha256": _h32("v2-r"), "response_salted_sha256": _h32("v2-s"), "rules_sha256": _h32("vt2-rules"), "tip_height": 750000, "type": "seallink-verdict/1", "violated_rule": "r1"}
    add("d7-vt-chain-mismatch-refuse", ["SL-CONT-006"], "verdict", {"chain": fx_vt2["chain"], "contract": c_vt2, "verdict": sl.sign_envelope({**v_p2, "genesis": _h32("bad-vg")}, [mk2["sk"]])}, "REFUSE", "CHAIN_MISMATCH", "verdict/1 with wrong genesis refuses CHAIN_MISMATCH.")
    add("d7-vt-rules-mismatch-refuse", ["SL-CONT-006"], "verdict", {"chain": fx_vt2["chain"], "contract": c_vt2, "verdict": sl.sign_envelope({**v_p2, "rules_sha256": _h32("wrong-r")}, [mk2["sk"]])}, "REFUSE", "CONTRACT_TERMS_MISMATCH", "verdict/1 with wrong rules_sha256 refuses CONTRACT_TERMS_MISMATCH.")
    add("d7-vt-bad-0x03-anchor-refuse", ["SL-CONT-006"], "verdict", {"anchor_txid": _h32("missing-0x03"), "chain": fx_vt2["chain"], "contract": c_vt2, "verdict": sl.sign_envelope(v_p2, [mk2["sk"]])}, "REFUSE", "CHAIN_FRAME_INVALID", "verdict/1 with missing 0x03 anchor refuses CHAIN_FRAME_INVALID.")

    tm_p2 = {"contract_id": sl.object_id(c_vt2), "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "reason": "done", "termination_branch": "either_party", "type": "seallink-termination/1"}
    add("d7-tm-chain-mismatch-refuse", ["SL-CONT-005"], "termination", {"chain": fx_vt2["chain"], "contract": c_vt2, "termination": sl.sign_envelope({**tm_p2, "genesis": _h32("bad-tg")}, [fx_vt2["_keys"]["alice_gr"]["sk"]])}, "REFUSE", "CHAIN_MISMATCH", "termination/1 with wrong genesis refuses CHAIN_MISMATCH.")
    add("d7-tm-contract-id-mismatch-refuse", ["SL-CONT-005"], "termination", {"chain": fx_vt2["chain"], "contract": c_vt2, "termination": sl.sign_envelope({**tm_p2, "contract_id": _h32("wrong-cid")}, [fx_vt2["_keys"]["alice_gr"]["sk"]])}, "REFUSE", "CONTRACT_ID_MISMATCH", "termination/1 with wrong contract_id refuses CONTRACT_ID_MISMATCH.")
    add("d7-tm-bad-0x08-spend-refuse", ["SL-CONT-005"], "termination", {"chain": fx_vt2["chain"], "contract": c_vt2, "spend_txid": _h32("missing-0x08"), "termination": sl.sign_envelope(tm_p2, [fx_vt2["_keys"]["alice_gr"]["sk"]])}, "REFUSE", "CHAIN_FRAME_INVALID", "termination/1 with missing 0x08 spend refuses CHAIN_FRAME_INVALID.")

    # certset_head missing sets.certs pin
    csh2 = {"count": 0, "issuer_name": "id/alice", "network": "main", "seq": 1, "set_sha256": sl.sha256(b"[]").hex(), "type": "seallink-certset-head/1"}
    add("d7-csh-missing-manifest-pin-refuse", ["SL-IDEN-006"], "certset_head", {"head": csh2, "owner_manifest": fx_au2["_alice_man"], "statements": []}, "REFUSE", "MANIFEST_MISMATCH", "certset-head/1 not pinned in owner_manifest.sets.certs refuses MANIFEST_MISMATCH.")

    # statement: CHAIN_MISMATCH, not_after == not_before, not_before == now ADMIT, device_list P-256 ADMIT & unauthorized REFUSE
    st_p2 = {"body_sha256": _h32("d7-stmt-body"), "genesis": GENESIS_MAIN, "issuer": {"name": "id/alice", "owner_policy": fx_au2["_alice_owner_pol"], "registration": fx_au2["_alice_reg"]}, "network": "main", "not_after": now_au + 60, "not_before": now_au, "seq": 1, "statement_kind": "config-section", "subject": {"host_id": "id/station-a", "section": "runtime"}, "type": "seallink-statement/1"}
    add("d7-stmt-chain-mismatch-refuse", ["SL-IDEN-006"], "statement", {"chain": fx_au2["chain"], "statement": sl.sign_envelope({**st_p2, "genesis": _h32("bad-sg")}, [fx_au2["_keys"]["alice_gr"]["sk"]])}, "REFUSE", "CHAIN_MISMATCH", "statement/1 with wrong genesis refuses CHAIN_MISMATCH.")
    add("d7-bnd-stmt-not-before-eq-now-admit", ["SL-IDEN-006"], "statement", {"chain": fx_au2["chain"], "statement": sl.sign_envelope(st_p2, [fx_au2["_keys"]["alice_gr"]["sk"]])}, "ADMIT", None, "Exact boundary: statement at not_before == chain.now admits (kills <= -> <).")
    add("d7-bnd-stmt-not-after-eq-not-before-refuse", ["SL-IDEN-006"], "statement", {"chain": fx_au2["chain"], "statement": sl.sign_envelope({**st_p2, "not_after": now_au - 10, "not_before": now_au - 10}, [fx_au2["_keys"]["alice_gr"]["sk"]])}, "REFUSE", "INVOKE_TIME_INVALID", "Exact boundary: statement with not_after == not_before refuses INVOKE_TIME_INVALID (kills <= -> <).")
    stmt_dev_ok = sl.sign_envelope(st_p2, [p256_s2], alg="p256")
    add("d7-stmt-device-list-p256-admit", ["SL-IDEN-006", "SL-WIRE-012"], "statement", {"chain": fx_au2["chain"], "device_list": dl_ok, "statement": stmt_dev_ok}, "ADMIT", None, "config-section statement signed by enrolled P-256 device admits.")
    add("d7-stmt-device-list-unregistered-refuse", ["SL-IDEN-006"], "statement", {"chain": fx_au2["chain"], "device_list": {**dl_ok, "owner": "id/bob"}, "statement": stmt_dev_ok}, "REFUSE", "DEVICE_UNAUTHORIZED", "statement signed by device whose device_list owner mismatches refuses DEVICE_UNAUTHORIZED.")

    # --- Batch 5: Invocation (admit_and_reserve), commit_result, & Decision 6B Optional Modules ---
    # 5a. Invocation CHAIN_MISMATCH, iat == now ADMIT, grant CHAIN_MISMATCH, root_gp is child grant -> GRANT_NOT_DELEGABLE
    fx_i5 = rm._base_invocation_fixture()
    inv_cm = sl.sign_envelope({**fx_i5["invocation"]["payload"], "genesis": _h32("bad-inv-g")}, [fx_i5["_keys"]["agent_req"]["sk"]])
    add("d7-inv-chain-mismatch-refuse", ["SL-GRNT-006"], "invocation", {**fx_i5, "invocation": inv_cm}, "REFUSE", "CHAIN_MISMATCH", "invocation/1 with wrong genesis refuses CHAIN_MISMATCH.")
    inv_iat_eq = sl.sign_envelope({**fx_i5["invocation"]["payload"], "iat": fx_i5["chain"]["now"]}, [fx_i5["_keys"]["agent_req"]["sk"]])
    add("d7-bnd-inv-iat-eq-now-admit", ["SL-GRNT-006"], "invocation", {**fx_i5, "invocation": inv_iat_eq}, "ADMIT", None, "Exact boundary: invocation at iat == chain.now admits (kills <= -> <).")
    fx_gcm = rm._base_invocation_fixture()
    gp_gcm = {**copy.deepcopy(fx_gcm["bundle"]["grants"][0]["payload"]), "genesis": _h32("bad-g-gen")}
    g_gcm = sl.sign_envelope(gp_gcm, [fx_gcm["_keys"]["alice_gr"]["sk"]])
    fx_gcm["bundle"]["grants"] = [g_gcm]
    add("d7-grant-chain-mismatch-refuse", ["SL-GRNT-001"], "invocation", fx_gcm, "REFUSE", "CHAIN_MISMATCH", "grant/1 with wrong genesis refuses CHAIN_MISMATCH.")
    fx_ch_root = rm._delegation_fx()
    child_only = fx_ch_root["bundle"]["grants"][1]
    cid_only = sl.object_id(child_only["payload"])
    inv_co = sl.sign_envelope({**fx_ch_root["invocation"]["payload"], "proof_path": [{"grant_id": cid_only, "issuance_txid": _h32("c-iss-tx")}]}, [fx_ch_root["_keys"]["agent_req"]["sk"]])
    add("d7-root-grant-missing-issuer-refuse", ["SL-GRNT-009"], "invocation", {**fx_ch_root, "bundle": {**fx_ch_root["bundle"], "grants": [child_only]}, "invocation": inv_co}, "REFUSE", "GRANT_NOT_DELEGABLE", "Child grant presented as proof_path[0] root refuses GRANT_NOT_DELEGABLE.")

    # 5b. Issuer origin binding mismatch -> ORIGIN_BINDING_INVALID
    of_ib = rm._base_origin_fixture()
    fx_ib = rm._base_invocation_fixture()
    # Attach Leo's origin_id to id/alice's history (binding says id/child-leo, issuer says id/alice -> ORIGIN_BINDING_INVALID!)
    fx_ib["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_ib["_alice_reg"], fx_ib["_alice_owner_pol"], {"link": {"grant": fx_ib["_keys"]["alice_gr"]["xonly"], "origin": of_ib["_origin_id"]}, "m": {"h": sl.content_addr(fx_ib["_alice_man"]), "s": 1}})
    fx_ib["chain"]["names"].update(of_ib["chain"]["names"])
    fx_ib["chain"]["txs"].update(of_ib["chain"]["txs"])
    fx_ib["chain"]["credible_utc_interval"] = of_ib["chain"]["credible_utc_interval"]
    fx_ib["bundle"]["origin_bundle"] = of_ib["origin_bundle"]
    fx_ib["trusted_origin_issuer_pins"] = of_ib["trusted_origin_issuer_pins"]
    add("d7-b02-issuer-origin-binding-name-mismatch-refuse", ["SL-ORIG-002", "SL-GRNT-001"], "invocation", fx_ib, "REFUSE", "ORIGIN_BINDING_INVALID", "B-2: origin_bundle whose active_binding disagrees with root grant issuer refuses ORIGIN_BINDING_INVALID.")

    # 5c. Contract & framework checks: CHAIN_MISMATCH, nested framework_id, window boundaries, not_after_unix boundaries, 0x07 bad anchor, D-5 party mismatch, MachineClauseTerms boundaries, missing config_sha256
    fx_c5 = rm._contract_fx()
    now_c5 = fx_c5["chain"]["now"]
    # Contract CHAIN_MISMATCH
    fx_c5_cm = copy.deepcopy(fx_c5)
    c_cm = {**fx_c5_cm["bundle"]["contract"], "genesis": _h32("bad-c-gen")}
    fx_c5_cm["bundle"]["contract"] = c_cm
    gp_c5 = {**fx_c5_cm["bundle"]["grants"][0]["payload"], "contract_id": sl.object_id(c_cm)}
    _reanchor(fx_c5_cm, gp_c5)
    add("d7-contract-chain-mismatch-refuse", ["SL-CONT-002"], "invocation", fx_c5_cm, "REFUSE", "CHAIN_MISMATCH", "contract/1 with wrong genesis refuses CHAIN_MISMATCH.")

    # Framework nesting + exact window & not_after_unix boundaries + nested framework_id + framework CHAIN_MISMATCH
    def _fw_fx(*, fw_gen: str = GENESIS_MAIN, fw_nested: bool = False, fw_nb: int = 749000, fw_na: int = 755000, fw_nau: int | None = None, c_nau: int | None = None) -> dict[str, Any]:
        fx_f = rm._contract_fx()
        fw_spol = {"kind": "key", "pk": _kp("d7-fw-s")["comp"]}
        fw_stx = _h32("d7-fw-stx")
        fx_f["chain"]["txs"][fw_stx] = {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(fw_spol)}}}
        fw_w: dict[str, Any] = {"not_before_height": fw_nb, "not_after_height": fw_na}
        if fw_nau is not None:
            fw_w["not_after_unix"] = fw_nau
        fw_obj: dict[str, Any] = {**copy.deepcopy(fx_f["bundle"]["contract"]), "genesis": fw_gen, "seal": {"script_policy": fw_spol, "txid": fw_stx, "vout": 0}, "window": fw_w}
        if fw_nested:
            fw_obj["framework_id"] = _h32("grandparent-fw")
        fw_id = sl.object_id(fw_obj)
        c_sub = copy.deepcopy(fx_f["bundle"]["contract"])
        c_sub["framework_id"] = fw_id
        if c_nau is not None:
            c_sub["window"]["not_after_unix"] = c_nau
        c_sub_id = sl.object_id(c_sub)
        fx_f["bundle"]["framework_contract"] = fw_obj
        fx_f["bundle"]["contract"] = c_sub
        # Re-sign contract assents for c_sub_id!
        new_ass = []
        for a in fx_f["bundle"]["contract_assents"]:
            ap = {**a["payload"], "target_id": c_sub_id}
            sk_a = fx_f["_keys"]["alice_gr"]["sk"] if ap["party_id"] == "client-1" else fx_f["_keys"]["agent_req"]["sk"]
            new_ass.append(sl.sign_envelope(ap, [sk_a]))
        fx_f["bundle"]["contract_assents"] = new_ass
        gp_f = {**fx_f["bundle"]["grants"][0]["payload"], "contract_id": c_sub_id}
        g_f = sl.sign_envelope(gp_f, [fx_f["_keys"]["alice_gr"]["sk"]])
        gid_f = sl.object_id(gp_f)
        itx_f = fx_f["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
        fx_f["bundle"]["grants"] = [g_f]
        fx_f["chain"]["txs"][itx_f]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"contract_id": c_sub_id, "genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_f), "grant_id": gid_f, "type": "seallink-issuance/1"}).hex()).hex()
        fx_f["invocation"] = sl.sign_envelope({**fx_f["invocation"]["payload"], "proof_path": [{"grant_id": gid_f, "issuance_txid": itx_f}]}, [fx_f["_keys"]["agent_req"]["sk"]])
        return fx_f

    c_w_nb = fx_c5["bundle"]["contract"]["window"]["not_before_height"]
    c_w_na = fx_c5["bundle"]["contract"]["window"]["not_after_height"]
    add("d7-bnd-framework-exact-window-and-unix-admit", ["SL-CONT-003"], "invocation", _fw_fx(fw_nb=c_w_nb, fw_na=c_w_na, fw_nau=now_c5 + 1, c_nau=now_c5 + 1), "ADMIT", None, "Exact boundary: framework window == contract window and not_after_unix == now + 1 admits (kills < -> <= and > -> >=).")
    add("d7-fw-chain-mismatch-refuse", ["SL-CONT-003"], "invocation", _fw_fx(fw_gen=_h32("bad-fw-g")), "REFUSE", "CHAIN_MISMATCH", "framework_contract with wrong genesis refuses CHAIN_MISMATCH.")
    add("d7-fw-nested-framework-refuse", ["SL-CONT-003"], "invocation", _fw_fx(fw_nested=True, fw_nb=c_w_nb, fw_na=c_w_na), "REFUSE", "CONTRACT_TERMS_MISMATCH", "Framework contract nesting another framework_id refuses CONTRACT_TERMS_MISMATCH.")
    add("d7-h18-fw-window-narrower-than-contract-refuse", ["SL-CONT-003"], "invocation", _fw_fx(fw_nb=c_w_nb + 1, fw_na=c_w_na), "REFUSE", "CONTRACT_TERMS_MISMATCH", "H-18: contract window starting before framework window refuses CONTRACT_TERMS_MISMATCH.")
    add("d7-bnd-fw-not-after-unix-eq-now-refuse", ["SL-CONT-003"], "invocation", _fw_fx(fw_nb=c_w_nb, fw_na=c_w_na, fw_nau=now_c5), "REFUSE", "GRANT_WINDOW_CLOSED", "H-18 exact boundary: framework not_after_unix == now refuses GRANT_WINDOW_CLOSED (kills >= -> >).")
    add("d7-bnd-contract-not-after-unix-eq-now-refuse", ["SL-CONT-003"], "invocation", _fw_fx(fw_nb=c_w_nb, fw_na=c_w_na, c_nau=now_c5), "REFUSE", "GRANT_WINDOW_CLOSED", "Exact boundary: contract not_after_unix == now refuses GRANT_WINDOW_CLOSED (kills >= -> >).")

    # Bad 0x07 contract_anchor_txid -> CHAIN_FRAME_INVALID
    fx_c07 = rm._contract_fx()
    fx_c07["bundle"]["contract_anchor_txid"] = _h32("missing-0x07")
    add("d7-contract-bad-0x07-anchor-refuse", ["SL-CONT-004"], "invocation", fx_c07, "REFUSE", "CHAIN_FRAME_INVALID", "Invalid contract_anchor_txid refuses CHAIN_FRAME_INVALID.")

    # Grant window wider than contract window -> CONTRACT_TERMS_MISMATCH
    fx_gwc = rm._contract_fx()
    gp_gwc = {**fx_gwc["bundle"]["grants"][0]["payload"], "not_after_height": fx_gwc["bundle"]["contract"]["window"]["not_after_height"] + 1}
    g_gwc = sl.sign_envelope(gp_gwc, [fx_gwc["_keys"]["alice_gr"]["sk"]])
    gid_gwc = sl.object_id(gp_gwc)
    itx_gwc = fx_gwc["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx_gwc["bundle"]["grants"] = [g_gwc]
    fx_gwc["chain"]["txs"][itx_gwc]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"contract_id": gp_gwc["contract_id"], "genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_gwc), "grant_id": gid_gwc, "type": "seallink-issuance/1"}).hex()).hex()
    fx_gwc["invocation"] = sl.sign_envelope({**fx_gwc["invocation"]["payload"], "proof_path": [{"grant_id": gid_gwc, "issuance_txid": itx_gwc}]}, [fx_gwc["_keys"]["agent_req"]["sk"]])
    add("d7-grant-window-wider-than-contract-refuse", ["SL-CONT-003"], "invocation", fx_gwc, "REFUSE", "CONTRACT_TERMS_MISMATCH", "Grant exceeding bound contract window refuses CONTRACT_TERMS_MISMATCH.")

    # D-5: Grant recipient is NOT a contract party -> CONTRACT_TERMS_MISMATCH
    fx_d5 = rm._contract_fx()
    stranger_r = _kp("d7-d5-stranger")
    gp_d5 = {**fx_d5["bundle"]["grants"][0]["payload"], "recipient": {"key": stranger_r["xonly"], "mode": "key"}}
    g_d5 = sl.sign_envelope(gp_d5, [fx_d5["_keys"]["alice_gr"]["sk"]])
    gid_d5 = sl.object_id(gp_d5)
    itx_d5 = fx_d5["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx_d5["bundle"]["grants"] = [g_d5]
    fx_d5["chain"]["txs"][itx_d5]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"contract_id": gp_d5["contract_id"], "genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_d5), "grant_id": gid_d5, "type": "seallink-issuance/1"}).hex()).hex()
    fx_d5["invocation"] = sl.sign_envelope({**fx_d5["invocation"]["payload"], "proof_path": [{"grant_id": gid_d5, "issuance_txid": itx_d5}]}, [stranger_r["sk"]])
    add("d7-d05-grant-recipient-not-contract-party-refuse", ["SL-CONT-004", "SL-GRNT-001"], "invocation", fx_d5, "REFUSE", "CONTRACT_TERMS_MISMATCH", "D-5: grant recipient not matching a distinct contract party refuses CONTRACT_TERMS_MISMATCH.")

    # R3-B5 MachineClauseTerms exact boundaries (not_before_height & not_after_height == leaf grant ADMIT!) + agent/session missing config_sha256
    fx_mt = rm._contract_fx()
    gp_mt0 = fx_mt["bundle"]["grants"][0]["payload"]
    mt_salt = _h32("d7-mt-salt")
    mt_clause = {"machine_terms": {"capabilities": copy.deepcopy(gp_mt0["capabilities"]), "not_after_height": gp_mt0["not_after_height"], "not_before_height": gp_mt0["not_before_height"]}, "text": "Exact window machine terms."}
    c_mt = copy.deepcopy(fx_mt["bundle"]["contract"])
    c_mt["clause_commitments"] = [sl.clause_commit(mt_salt, mt_clause)]
    c_mt["machine_clause_indices"] = [0]
    c_mt_id = sl.object_id(c_mt)
    fx_mt["bundle"]["contract"] = c_mt
    fx_mt["bundle"]["disclosed_clauses"] = {"0": {"clause": mt_clause, "salt_hex": mt_salt}}
    fx_mt["bundle"]["contract_assents"] = [
        sl.sign_envelope({**a["payload"], "target_id": c_mt_id}, [fx_mt["_keys"]["alice_gr"]["sk"] if a["payload"]["party_id"] == "client-1" else fx_mt["_keys"]["agent_req"]["sk"]])
        for a in fx_mt["bundle"]["contract_assents"]
    ]
    gp_mt = {**gp_mt0, "contract_id": c_mt_id}
    g_mt = sl.sign_envelope(gp_mt, [fx_mt["_keys"]["alice_gr"]["sk"]])
    gid_mt = sl.object_id(gp_mt)
    itx_mt = fx_mt["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx_mt["bundle"]["grants"] = [g_mt]
    fx_mt["chain"]["txs"][itx_mt]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"contract_id": c_mt_id, "genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_mt), "grant_id": gid_mt, "type": "seallink-issuance/1"}).hex()).hex()
    fx_mt["invocation"] = sl.sign_envelope({**fx_mt["invocation"]["payload"], "proof_path": [{"grant_id": gid_mt, "issuance_txid": itx_mt}]}, [fx_mt["_keys"]["agent_req"]["sk"]])
    add("d7-bnd-r3b5-machine-clause-exact-window-admit", ["SL-CONT-002"], "invocation", fx_mt, "ADMIT", None, "R3-B5 exact boundary: grant window == MachineClauseTerms not_before_height/not_after_height admits (kills < -> <= and > -> >=).")

    fx_nocfg = rm._contract_fx()
    c_nc = copy.deepcopy(fx_nocfg["bundle"]["contract"])
    c_nc.pop("config_sha256", None)
    c_nc_id = sl.object_id(c_nc)
    fx_nocfg["bundle"]["contract"] = c_nc
    fx_nocfg["bundle"]["contract_assents"] = [
        sl.sign_envelope({**a["payload"], "target_id": c_nc_id}, [fx_nocfg["_keys"]["alice_gr"]["sk"] if a["payload"]["party_id"] == "client-1" else fx_nocfg["_keys"]["agent_req"]["sk"]])
        for a in fx_nocfg["bundle"]["contract_assents"]
    ]
    gp_nc = {**fx_nocfg["bundle"]["grants"][0]["payload"], "contract_id": c_nc_id}
    g_nc = sl.sign_envelope(gp_nc, [fx_nocfg["_keys"]["alice_gr"]["sk"]])
    gid_nc = sl.object_id(gp_nc)
    itx_nc = fx_nocfg["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx_nocfg["bundle"]["grants"] = [g_nc]
    fx_nocfg["chain"]["txs"][itx_nc]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"contract_id": c_nc_id, "genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_nc), "grant_id": gid_nc, "type": "seallink-issuance/1"}).hex()).hex()
    fx_nocfg["invocation"] = sl.sign_envelope({**fx_nocfg["invocation"]["payload"], "proof_path": [{"grant_id": gid_nc, "issuance_txid": itx_nc}]}, [fx_nocfg["_keys"]["agent_req"]["sk"]])
    add("d7-agent-session-start-missing-contract-config-refuse", ["SL-AGNT-002", "SL-CONT-007"], "invocation", fx_nocfg, "REFUSE", "CONTRACT_CONFIG_MISMATCH", "agent/session op='start' when bound contract omits config_sha256 refuses CONTRACT_CONFIG_MISMATCH.")

    # 5d. Delegation row creation height boundary (== root_recent_h ADMIT vs +1 GRANT_ROW_INVALID) & missing notary_act -> NOTARY_REQUIRED
    fx_dr = rm._delegation_fx()
    root_rb = fx_dr["bundle"]["grants"][0]["payload"]["recent_block"]
    root_rh = fx_dr["chain"]["blocks"][root_rb]
    row_txid = fx_dr["bundle"]["grants"][0]["payload"]["delegate"]["groups"][0]["ranges"][0]["txid"]
    row_spol = fx_dr["bundle"]["grants"][0]["payload"]["delegate"]["groups"][0]["ranges"][0]["script_policy"]
    fx_dr["chain"]["txs"][row_txid] = {"confirmed_height": root_rh, "outputs": {"0": {"script_pubkey_hex": _spk_hex(row_spol)}}}
    add("d7-bnd-delegation-row-created-eq-recent-block-admit", ["SL-GRNT-009"], "invocation", fx_dr, "ADMIT", None, "Exact boundary: row coin creation tx confirmed at height == parent.recent_block admits (kills > -> >=).")
    fx_dr_late = copy.deepcopy(fx_dr)
    fx_dr_late["chain"]["txs"][row_txid]["confirmed_height"] = root_rh + 1
    add("d7-bnd-delegation-row-created-after-recent-block-refuse", ["SL-GRNT-009"], "invocation", fx_dr_late, "REFUSE", "GRANT_ROW_INVALID", "Row coin created after parent.recent_block refuses GRANT_ROW_INVALID.")

    # Missing notary_act when notary_mode == required_act -> NOTARY_REQUIRED
    fx_mn = rm._delegation_fx()
    gp_mn_p = copy.deepcopy(fx_mn["bundle"]["grants"][0]["payload"])
    gp_mn_p["delegate"]["groups"][0]["template"]["notary_mode"] = "required_act"
    gp_mn_p["delegate"]["groups"][0]["template"]["notary_name"] = "id/notary-x"
    gp_mn_p["delegate"]["notaries"] = [{"name": "id/notary-x", "owner_policy": not_pol, "registration": not_reg}]
    g_mn_p = sl.sign_envelope(gp_mn_p, [fx_mn["_keys"]["alice_gr"]["sk"]])
    pid_mn = sl.object_id(gp_mn_p)
    gp_mn_c = copy.deepcopy(fx_mn["bundle"]["grants"][1]["payload"])
    gp_mn_c["parent"]["grant_id"] = pid_mn
    g_mn_c = sl.sign_envelope(gp_mn_c, [fx_mn["_del_k"]["sk"]])
    cid_mn = sl.object_id(gp_mn_c)
    p_itx_mn = fx_mn["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    c_itx_mn = fx_mn["invocation"]["payload"]["proof_path"][1]["issuance_txid"]
    fx_mn["bundle"]["grants"] = [g_mn_p, g_mn_c]
    fx_mn["chain"]["txs"][p_itx_mn]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_mn_p), "grant_id": pid_mn, "type": "seallink-issuance/1"}).hex()).hex()
    fx_mn["chain"]["txs"][c_itx_mn]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_mn_c), "grant_id": cid_mn, "type": "seallink-issuance/1"}).hex()).hex()
    fx_mn["invocation"] = sl.sign_envelope({**fx_mn["invocation"]["payload"], "proof_path": [{"grant_id": pid_mn, "issuance_txid": p_itx_mn}, {"grant_id": cid_mn, "issuance_txid": c_itx_mn}]}, [fx_mn["_keys"]["agent_req"]["sk"]])
    add("d7-b04-required-act-missing-notary-act-refuse", ["SL-GRNT-009", "SL-CONT-011"], "invocation", fx_mn, "REFUSE", "NOTARY_REQUIRED", "B-4: required_act delegation omitting notary_act refuses NOTARY_REQUIRED.")

    # 5e. SL-GRNT-004 issuer_name_expiry_at_issuance exact boundary (not_after == iss_exp ADMIT vs +1 GRANT_WINDOW_CLOSED, with u.confirmed_height == a_height!)
    fx_ie = rm._base_invocation_fixture()
    itx_ie = fx_ie["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    a_h_ie = fx_ie["chain"]["txs"][itx_ie]["confirmed_height"]  # 749995
    # Set Alice's latest confirmed update to exact a_height -> iss_exp_at_iss = a_h_ie + 36000!
    fx_ie["chain"]["names"]["id/alice"]["updates"][-1]["confirmed_height"] = a_h_ie
    iss_exp_ie = a_h_ie + 36000
    gp_ie_ok = {**copy.deepcopy(fx_ie["bundle"]["grants"][0]["payload"]), "not_after_height": iss_exp_ie}
    _reanchor(fx_ie, gp_ie_ok)
    add("d7-bnd-b09-grant-not-after-eq-issuer-expiry-at-issuance-admit", ["SL-GRNT-004"], "invocation", fx_ie, "ADMIT", None, "B-9 exact boundary: grant not_after_height == issuer_name_expiry_at_issuance (with update at height == a_height) admits (kills <= -> < and > -> >=).")
    fx_ie_bad = copy.deepcopy(fx_ie)
    gp_ie_bad = {**copy.deepcopy(fx_ie_bad["bundle"]["grants"][0]["payload"]), "not_after_height": iss_exp_ie + 1}
    _reanchor(fx_ie_bad, gp_ie_bad)
    add("d7-bnd-b09-grant-not-after-gt-issuer-expiry-at-issuance-refuse", ["SL-GRNT-004"], "invocation", fx_ie_bad, "REFUSE", "GRANT_WINDOW_CLOSED", "B-9 exact boundary: grant not_after_height > issuer_name_expiry_at_issuance refuses GRANT_WINDOW_CLOSED.")

    # 5f. B-1 concrete executor unbound in holder manifest -> SERVICE_PROVIDER_UNBOUND; B-3 agent/guardian-message missing pinned_ward / autonomous / wrong args.origin_id
    fx_unb = rm._base_invocation_fixture()
    al_man_unb = {**copy.deepcopy(fx_unb["_alice_man"]), "providers": []}
    al_man_unb_h = sl.content_addr(al_man_unb)
    fx_unb["chain"]["manifests"][al_man_unb_h] = al_man_unb
    fx_unb["bundle"]["manifests"][al_man_unb_h] = al_man_unb
    fx_unb["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_unb["_alice_reg"], fx_unb["_alice_owner_pol"], {"link": {"grant": fx_unb["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al_man_unb_h, "s": 1}})
    add("d7-b01-concrete-executor-unbound-in-manifest-refuse", ["SL-MAIL-003", "SL-SERV-001"], "invocation", fx_unb, "REFUSE", "SERVICE_PROVIDER_UNBOUND", "B-1: concrete-executor mailbox grant whose holder manifest does not bind that provider refuses SERVICE_PROVIDER_UNBOUND.")

    # B-3 agent/guardian-message: missing pinned_ward_origin_id -> ORIGIN_UNVERIFIED; autonomous issuer -> WARD_AUTONOMOUS_FORBIDDEN; wrong args.origin_id -> INVOKE_CONSTRAINT_FAILED
    fx_gm = rm._base_invocation_fixture()
    of_gm = rm._base_origin_fixture()
    gm_oid = of_gm["_origin_id"]
    gm_seal_pol = {"kind": "key", "pk": fx_gm["_keys"]["alice_seal"]["comp"]}
    gm_seal_tx, gm_itx = _h32("d7-gm-stx"), _h32("d7-gm-itx")
    fx_gm["chain"]["txs"].update(of_gm["chain"]["txs"])
    fx_gm["chain"]["names"].update(of_gm["chain"]["names"])
    fx_gm["chain"]["credible_utc_interval"] = of_gm["chain"]["credible_utc_interval"]
    fx_gm["chain"]["txs"][gm_seal_tx] = {"confirmed_height": 749990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(gm_seal_pol)}, "1": {"script_pubkey_hex": _spk_hex(gm_seal_pol)}}}
    gm_gp_auto = {
        "capabilities": [{"action": "agent/guardian-message", "target": f"ward:{gm_oid}", "where": {}}],
        "executor": fx_gm["invocation"]["payload"]["executor"],
        "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_gm["_alice_owner_pol"], "registration": fx_gm["_alice_reg"], "role_policy": {"m": 1, "pks": [fx_gm["_keys"]["alice_gr"]["xonly"]]}},
        "network": "main", "not_after_height": 755000, "not_before_height": 749000,
        "recent_block": fx_gm["bundle"]["grants"][0]["payload"]["recent_block"],
        "recipient": {"key": fx_gm["_keys"]["agent_req"]["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": gm_seal_pol, "txid": gm_seal_tx, "vout": 0}},
        "type": "seallink-grant/1",
    }
    gm_g_auto = sl.sign_envelope(gm_gp_auto, [fx_gm["_keys"]["alice_gr"]["sk"]])
    gm_gid_auto = sl.object_id(gm_gp_auto)
    fx_gm["chain"]["txs"][gm_itx] = {"confirmed_height": 749995, "inputs": [sv.make_segwit_input(gm_seal_tx, 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(gm_g_auto), "grant_id": gm_gid_auto, "type": "seallink-issuance/1"}).hex()).hex(), "outputs": {}}
    gm_inv_p = {"action": "agent/guardian-message", "arguments": {"channel": "nostr", "delivery_mode": "strict_drop", "message_sha256": _h32("gm-m"), "origin_id": gm_oid, "revision": 1, "subject_ward_name": "id/child-leo"}, "executor": fx_gm["invocation"]["payload"]["executor"], "exp": fx_gm["chain"]["now"] + 300, "genesis": GENESIS_MAIN, "iat": fx_gm["chain"]["now"] - 10, "network": "main", "nonce": _h32("d7-gm-n1"), "proof_path": [{"grant_id": gm_gid_auto, "issuance_txid": gm_itx}], "target": f"ward:{gm_oid}", "type": "seallink-invocation/1"}
    fx_gm["bundle"]["grants"] = [gm_g_auto]
    fx_gm["invocation"] = sl.sign_envelope(gm_inv_p, [fx_gm["_keys"]["agent_req"]["sk"]])
    fx_gm["executor_cfg"] = {**fx_gm["executor_cfg"], "actions": ["agent/guardian-message"]}
    add("d7-b03-guardian-msg-missing-pinned-ward-refuse", ["SL-AGNT-003"], "invocation", fx_gm, "REFUSE", "ORIGIN_UNVERIFIED", "B-3: agent/guardian-message executor without pinned_ward_origin_id refuses ORIGIN_UNVERIFIED.")
    fx_gm_auto = copy.deepcopy(fx_gm)
    fx_gm_auto["executor_cfg"]["pinned_ward_origin_id"] = gm_oid
    add("d7-b03-guardian-msg-autonomous-issuer-refuse", ["SL-AGNT-003"], "invocation", fx_gm_auto, "REFUSE", "WARD_AUTONOMOUS_FORBIDDEN", "B-3: autonomous actor invoking agent/guardian-message refuses WARD_AUTONOMOUS_FORBIDDEN.")

    # Ward guardian-message with mismatched args.origin_id -> INVOKE_CONSTRAINT_FAILED
    of_gm2 = rm._base_origin_fixture()
    op_gm2 = copy.deepcopy(of_gm2["origin_bundle"]["origin"]["payload"])
    op_gm2["guardian_policy"]["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 1}
    o_gm2 = sl.sign_envelope(op_gm2, [of_gm2["_keys"]["reg_cred"]["sk"]])
    gm2_oid = sl.object_id(op_gm2)
    of_gm2["origin_bundle"]["origin"] = o_gm2
    of_gm2["origin_bundle"]["name_binding"]["origin_id"] = gm2_oid
    g1_gm2_p = {**of_gm2["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": gm2_oid}
    g1_gm2 = sl.sign_envelope(g1_gm2_p, [of_gm2["_keys"]["reg_cred"]["sk"]])
    of_gm2["origin_bundle"]["guardian_records"] = [g1_gm2]
    of_gm2["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**of_gm2["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(g1_gm2_p)}, [of_gm2["_keys"]["g1_gr"]["sk"]])]
    of_gm2["chain"]["txs"][of_gm2["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_gm2)).hex()
    of_gm2["chain"]["txs"][of_gm2["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_gm2["origin_bundle"]["name_binding"])).hex()
    of_gm2["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_gm2)).hex()
    of_gm2["chain"]["names"]["id/child-leo"] = sv.make_name_history("id/child-leo", of_gm2["origin_bundle"]["name_binding"]["registration"], of_gm2["origin_bundle"]["name_binding"]["owner_policy"], {"link": {"grant": of_gm2["_keys"]["ward_gr"]["xonly"], "origin": gm2_oid}}, first_height=749005, update_height=749010)
    fx_gm_w = copy.deepcopy(fx_gm_auto)
    fx_gm_w["chain"]["names"].update(of_gm2["chain"]["names"])
    fx_gm_w["chain"]["txs"].update(of_gm2["chain"]["txs"])
    rm.sync_chain_tip(fx_gm_w["chain"], height=of_gm2["chain"]["tip_height"], tip_hash=of_gm2["chain"]["tip_hash"])
    fx_gm_w["chain"]["now"] = of_gm2["chain"]["now"]
    fx_gm_w["executor_cfg"]["pinned_ward_origin_id"] = gm2_oid
    gm_gp_w = {
        **gm_gp_auto,
        "capabilities": [{"action": "agent/guardian-message", "target": f"ward:{gm2_oid}", "where": {}}],
        "guardian_context": {"event_class": "effect_grant", "origin_id": gm2_oid, "revision": 1, "ward_name": "id/child-leo"},
        "issuer": {"name": "id/child-leo", "owner_policy": of_gm2["origin_bundle"]["name_binding"]["owner_policy"], "registration": of_gm2["origin_bundle"]["name_binding"]["registration"]},
    }
    gm_g_w = sl.sign_guardian_envelope(gm_gp_w, [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_gm2["_keys"]["g1_gr"]["sk"]], "slot": 1}])
    gm_gid_w = sl.object_id(gm_gp_w)
    fx_gm_w["chain"]["txs"][gm_itx]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(gm_g_w), "grant_id": gm_gid_w, "type": "seallink-issuance/1"}).hex()).hex()
    fx_gm_w["bundle"]["grants"] = [gm_g_w]
    fx_gm_w["bundle"]["origin_bundle"] = of_gm2["origin_bundle"]
    fx_gm_w["trusted_origin_issuer_pins"] = of_gm2["trusted_origin_issuer_pins"]
    raw_gm_b = b"guardian-mismatch-msg"
    gm_inv_bad_arg = {**gm_inv_p, "arguments": {**gm_inv_p["arguments"], "message_sha256": sl.sha256(raw_gm_b).hex(), "origin_id": _h32("wrong-arg-oid")}, "exp": of_gm2["chain"]["now"] + 300, "iat": of_gm2["chain"]["now"] - 10, "nonce": _h32("d7-gm-n2"), "proof_path": [{"grant_id": gm_gid_w, "issuance_txid": gm_itx}], "target": f"ward:{gm2_oid}"}
    fx_gm_w["invocation"] = sl.sign_envelope(gm_inv_bad_arg, [fx_gm["_keys"]["agent_req"]["sk"]])
    fx_gm_w["raw_message_hex"] = raw_gm_b.hex()
    add("d7-b03-guardian-msg-args-origin-mismatch-refuse", ["SL-AGNT-003"], "invocation", fx_gm_w, "REFUSE", "INVOKE_CONSTRAINT_FAILED", "B-3: agent/guardian-message arguments.origin_id != pinned_ward_origin_id refuses INVOKE_CONSTRAINT_FAILED.")

    # 5g. commit_result: mismatched grant_id -> WIRE_MEMBER; actual_quota_usage == reserve ADMIT & > reserve QUOTA_EXCEEDED
    fx_cr2 = rm._base_invocation_fixture()
    gp_cr2 = copy.deepcopy(fx_cr2["bundle"]["grants"][0]["payload"])
    gp_cr2["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    _, gid_cr2 = _reanchor(fx_cr2, gp_cr2)
    inv_id_cr2 = sl.object_id(fx_cr2["invocation"]["payload"])
    rcpt_cr2_ok = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": fx_cr2["executor_cfg"]["name"],
            "genesis": GENESIS_MAIN,
            "grant_id": gid_cr2,
            "invocation_id": inv_id_cr2,
            "network": "main",
            "outcome": "executed",
            "recorded_at": fx_cr2["chain"]["now"],
            "result_sha256": _h32("cr2-res"),
            "settlements": [{"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/alice:work", "settled": "1", "unit": "reads", "window": "term"}],
            "tip_hash": fx_cr2["chain"]["tip_hash"],
            "tip_height": fx_cr2["chain"]["tip_height"],
            "type": "seallink-receipt/1",
        },
        [fx_cr2["_keys"]["host_rcpt"]["sk"]],
    )
    rcpt_cr2_bad = sl.sign_envelope({**rcpt_cr2_ok["payload"], "grant_id": _h32("wrong-gid")}, [fx_cr2["_keys"]["host_rcpt"]["sk"]])
    add("d7-r1a-commit-result-wrong-grant-id-refuse", ["SL-GRNT-014"], "two_phase_commit", {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_cr2["bundle"], "chain": fx_cr2["chain"], "executor_cfg": fx_cr2["executor_cfg"], "invocation": fx_cr2["invocation"], "journal_id": _h32("d7-cr2-j1"), "receipt_env": rcpt_cr2_bad}, "REFUSE", "WIRE_MEMBER", "R1-A: commit_result with receipt grant_id mismatch refuses WIRE_MEMBER.")
    add("d7-bnd-commit-result-actual-eq-reserve-admit", ["SL-GRNT-007", "SL-GRNT-014"], "two_phase_commit", {"actual_message_meta": {"folder": "Invoices"}, "actual_quota_usage": {"seallink/count|mailbox:id/alice:work|reads|term": 1}, "bundle": fx_cr2["bundle"], "chain": fx_cr2["chain"], "executor_cfg": fx_cr2["executor_cfg"], "invocation": fx_cr2["invocation"], "journal_id": _h32("d7-cr2-j2"), "receipt_env": rcpt_cr2_ok}, "ADMIT", None, "Exact boundary: commit_result with actual_quota_usage == reserve admits (kills > -> >=).")
    add("d7-bnd-commit-result-actual-gt-reserve-refuse", ["SL-GRNT-007", "SL-GRNT-014"], "two_phase_commit", {"actual_message_meta": {"folder": "Invoices"}, "actual_quota_usage": {"seallink/count|mailbox:id/alice:work|reads|term": 2}, "bundle": fx_cr2["bundle"], "chain": fx_cr2["chain"], "executor_cfg": fx_cr2["executor_cfg"], "invocation": fx_cr2["invocation"], "journal_id": _h32("d7-cr2-j3"), "receipt_env": rcpt_cr2_ok}, "REFUSE", "QUOTA_EXCEEDED", "Exact boundary: commit_result with actual_quota_usage > reserve refuses QUOTA_EXCEEDED.")

    # 5h. Decision 6B: verify_session_open & verify_bearer_session exhaustive boundaries + refusals
    fx_s6 = rm._base_invocation_fixture()
    gp_s6 = copy.deepcopy(fx_s6["bundle"]["grants"][0]["payload"])
    gp_s6["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "2", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    g_s6, gid_s6 = _reanchor(fx_s6, gp_s6)
    itx_s6 = fx_s6["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    now_s6 = fx_s6["chain"]["now"]
    nb_s6, na_s6 = gp_s6["not_before_height"], gp_s6["not_after_height"]
    so6_p = {"executor": fx_s6["invocation"]["payload"]["executor"], "exp": now_s6 + 3600, "genesis": GENESIS_MAIN, "iat": now_s6, "network": "main", "nonce": _h32("d7-s6-n1"), "op": "open", "proof_path": [{"grant_id": gid_s6, "issuance_txid": itx_s6}], "quotas": [{"kind": "seallink/count", "max": "2", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}], "slot_binding": "tls-6", "type": "seallink-session-open/1"}
    so6_ok = sl.sign_envelope(so6_p, [fx_s6["_keys"]["agent_req"]["sk"]])
    ch_s6_nb = rm.sync_chain_tip(copy.deepcopy(fx_s6["chain"]), height=nb_s6)
    ch_s6_na1 = rm.sync_chain_tip(copy.deepcopy(fx_s6["chain"]), height=na_s6 - 1)
    ch_s6_na = rm.sync_chain_tip(copy.deepcopy(fx_s6["chain"]), height=na_s6)
    # Ensure seal is confirmed <= nb_s6 so evaluate_seal succeeds at nb_s6!
    seal_tx_s6 = gp_s6["revocation"]["seal"]["txid"]
    ch_s6_nb["txs"][seal_tx_s6]["confirmed_height"] = nb_s6 - 5
    ch_s6_na1["txs"][seal_tx_s6]["confirmed_height"] = nb_s6 - 5
    ch_s6_na["txs"][seal_tx_s6]["confirmed_height"] = nb_s6 - 5
    tok_s6 = _h32("d7-s6-tok")
    add(
        "d7-bnd-6b-session-open-and-bearer-all-boundaries-admit",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_s6["executor_cfg"],
            "journal": {"journal_id": _h32("d7-s6-j")},
            "steps": [
                # CHAIN_MISMATCH
                {"bundle": fx_s6["bundle"], "chain": ch_s6_nb, "kind": "session_open", "label": "cm", "session_open": sl.sign_envelope({**so6_p, "genesis": _h32("bad-s6-g"), "nonce": _h32("d7-s6-ncm")}, [fx_s6["_keys"]["agent_req"]["sk"]]), "want_refusal": "CHAIN_MISMATCH", "want_verdict": "REFUSE"},
                # GRANT_EXECUTOR_MISMATCH
                {"bundle": fx_s6["bundle"], "chain": ch_s6_nb, "kind": "session_open", "label": "exm", "session_open": sl.sign_envelope({**so6_p, "executor": {**fx_s6["invocation"]["payload"]["executor"], "name": "id/wrong-host"}, "nonce": _h32("d7-s6-nex")}, [fx_s6["_keys"]["agent_req"]["sk"]]), "want_refusal": "GRANT_EXECUTOR_MISMATCH", "want_verdict": "REFUSE"},
                # exp == now (kills <= -> <) & exp == now + 3601 (kills > 3600 -> >=)
                {"bundle": fx_s6["bundle"], "chain": ch_s6_nb, "kind": "session_open", "label": "exp-eq-now", "session_open": sl.sign_envelope({**so6_p, "exp": now_s6, "nonce": _h32("d7-s6-nexp0")}, [fx_s6["_keys"]["agent_req"]["sk"]]), "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"bundle": fx_s6["bundle"], "chain": ch_s6_nb, "kind": "session_open", "label": "exp-3601", "session_open": sl.sign_envelope({**so6_p, "exp": now_s6 + 3601, "nonce": _h32("d7-s6-nexp1")}, [fx_s6["_keys"]["agent_req"]["sk"]]), "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                # GRANT_WINDOW_CLOSED at tip == not_after_height (kills < -> <=)
                {"bundle": fx_s6["bundle"], "chain": ch_s6_na, "kind": "session_open", "label": "win-closed", "session_open": sl.sign_envelope({**so6_p, "nonce": _h32("d7-s6-nwc")}, [fx_s6["_keys"]["agent_req"]["sk"]]), "want_refusal": "GRANT_WINDOW_CLOSED", "want_verdict": "REFUSE"},
                # Exact open ADMIT at tip == not_before_height, iat == now, exp == now + 3600, sq.max == grant_max (2)!
                {"bearer_token": tok_s6, "bundle": fx_s6["bundle"], "chain": ch_s6_nb, "kind": "session_open", "label": "open-exact", "session_open": so6_ok, "want_refusal": None, "want_verdict": "ADMIT"},
                # Replayed identical open -> INVOKE_REPLAY!
                {"bundle": fx_s6["bundle"], "chain": ch_s6_nb, "kind": "session_open", "label": "replay-open", "session_open": so6_ok, "want_refusal": "INVOKE_REPLAY", "want_verdict": "REFUSE"},
                # Bearer use #1 at tip == not_before_height with live grant_env + quota (used 1 <= 2 -> ADMIT)
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": ch_s6_nb, "grant_env": g_s6, "kind": "bearer_session", "label": "use-1-nb", "slot_binding": "tls-6", "target": "mailbox:id/alice:work", "token": tok_s6, "want_refusal": None, "want_verdict": "ADMIT"},
                # Bearer use #2 at tip == not_after_height - 1 with live grant_env + quota (used 2 == max 2 -> ADMIT; kills > -> >= and < -> <=!)
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m2"}, "chain": ch_s6_na1, "grant_env": g_s6, "kind": "bearer_session", "label": "use-2-na1", "slot_binding": "tls-6", "target": "mailbox:id/alice:work", "token": tok_s6, "want_refusal": None, "want_verdict": "ADMIT"},
                # Bearer use #3 exceeds session quota (used 3 > 2 -> QUOTA_EXCEEDED!)
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m3"}, "chain": ch_s6_na1, "grant_env": g_s6, "kind": "bearer_session", "label": "use-3-over", "slot_binding": "tls-6", "target": "mailbox:id/alice:work", "token": tok_s6, "want_refusal": "QUOTA_EXCEEDED", "want_verdict": "REFUSE"},
                # Bearer use at tip == not_after_height with live grant_env -> SESSION_INVALID!
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m4"}, "chain": ch_s6_na, "grant_env": g_s6, "kind": "bearer_session", "label": "use-win-closed", "slot_binding": "tls-6", "target": "mailbox:id/alice:work", "token": tok_s6, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "Decision 6B: exhaustive boundary and refusal coverage across verify_session_open and verify_bearer_session.",
    )
    # session_open on closed grant -> GRANT_CLOSED; named recipient missing name -> NAME_NOT_FOUND
    add(
        "d7-6b-session-open-closed-grant-refuse",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_s6["executor_cfg"],
            "journal": {"closures": {gid_s6: {"reason": "SEAL_SPENT"}}, "journal_id": _h32("d7-s6-jc")},
            "steps": [{"bundle": fx_s6["bundle"], "chain": ch_s6_nb, "kind": "session_open", "label": "closed", "session_open": so6_ok, "want_refusal": "GRANT_CLOSED", "want_verdict": "REFUSE"}],
        },
        "ADMIT",
        None,
        "Decision 6B: session-open against locally closed grant refuses GRANT_CLOSED.",
    )
    fx_s6n = rm._base_invocation_fixture()
    gp_s6n = {**copy.deepcopy(fx_s6n["bundle"]["grants"][0]["payload"]), "recipient": {"mode": "name", "name": "id/ghost-rcpt", "owner_policy": fx_s6n["_alice_owner_pol"], "registration": fx_s6n["_alice_reg"]}}
    _, gid_s6n = _reanchor(fx_s6n, gp_s6n)
    so6n = sl.sign_envelope({**so6_p, "nonce": _h32("d7-s6-nghost"), "proof_path": [{"grant_id": gid_s6n, "issuance_txid": fx_s6n["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}], "quotas": []}, [fx_s6n["_keys"]["agent_req"]["sk"]])
    add(
        "d7-6b-session-open-named-recipient-missing-refuse",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_s6n["executor_cfg"],
            "journal": {"journal_id": _h32("d7-s6-jn")},
            "steps": [{"bundle": fx_s6n["bundle"], "chain": fx_s6n["chain"], "kind": "session_open", "label": "ghost", "session_open": so6n, "want_refusal": "NAME_NOT_FOUND", "want_verdict": "REFUSE"}],
        },
        "ADMIT",
        None,
        "Decision 6B: session-open with missing named recipient refuses NAME_NOT_FOUND.",
    )

    # 5i. Decision 6B: verify_migration remaining refusal branches (holder manifest unbound -> SERVICE_PROVIDER_UNBOUND, ward missing origin_bundle -> ORIGIN_UNVERIFIED, bad dest_accept_stmt -> SERVICE_MIGRATION_INVALID)
    fx_m5 = rm._base_invocation_fixture()
    dest_own5, dest_rcpt5 = _kp("d7-m5-do"), _kp("d7-m5-dr")
    dest_pol5 = {"kind": "key", "pk": dest_own5["comp"]}
    dest_reg5 = {"txid": _h32("d7-m5-drg"), "vout": 0}
    dest_pin5 = {"name": "id/mail-host-c", "owner_policy": dest_pol5, "registration": dest_reg5}
    dest_man5 = {"network": "main", "owner": "id/mail-host-c", "seq": 1, "service": {"actions": ["mail/read"], "endpoint": "https://mail-c.example.org", "receipt_key": dest_rcpt5["xonly"], "service_type": "mail"}, "type": "seallink-manifest/1"}
    dest_man5_h = sl.content_addr(dest_man5)
    fx_m5["chain"]["manifests"][dest_man5_h] = dest_man5
    fx_m5["bundle"]["manifests"][dest_man5_h] = dest_man5
    fx_m5["chain"]["names"]["id/mail-host-c"] = sv.make_name_history("id/mail-host-c", dest_reg5, dest_pol5, {"m": {"h": dest_man5_h, "s": 1}}, first_height=748000, update_height=749000)
    mig5_id = _h32("d7-m5-id")
    mig5_inv = {"holder_name": "id/alice", "items": [], "migration_id": mig5_id, "service_type": "mail"}
    mig5_sha = sl.sha256(sl.jcs_encode(mig5_inv)).hex()
    h_pin5 = {"name": "id/alice", "owner_policy": fx_m5["_alice_owner_pol"], "registration": fx_m5["_alice_reg"]}
    s_pin5 = {"name": "id/mail-host-a", "owner_policy": fx_m5["_host_owner_pol"], "registration": fx_m5["_host_reg"]}
    mig5_p = {"dest_executor": dest_pin5, "genesis": GENESIS_MAIN, "holder": h_pin5, "inventory_sha256": mig5_sha, "issued_at": fx_m5["chain"]["now"], "journal_commitment": _h32("d7-m5-jc"), "journal_pos": 10, "migration_id": mig5_id, "network": "main", "outstanding_exposure": [], "service_type": "mail", "source_executor": s_pin5, "type": "seallink-migration/1"}
    mig5_env = sl.sign_envelope(mig5_p, [fx_m5["_keys"]["host_rcpt"]["sk"]])
    ha5_ok = sl.sign_envelope({"expires_at": fx_m5["chain"]["now"] + 3600, "genesis": GENESIS_MAIN, "issued_at": fx_m5["chain"]["now"] - 10, "network": "main", "nonce": _h32("d7-m5-ha"), "party_id": "h", "party_name": "id/alice", "party_role": "holder", "target_id": sl.object_id(mig5_p), "target_type": "seallink-migration/1", "type": "seallink-assent/1"}, [fx_m5["_keys"]["alice_gr"]["sk"]])
    f_stmt5 = sl.sign_envelope(
        {
            "genesis": GENESIS_MAIN,
            "issuer": s_pin5,
            "network": "main",
            "not_after": fx_m5["chain"]["now"] + 3600,
            "not_before": fx_m5["chain"]["now"] - 10,
            "seq": 1,
            "statement_kind": "migration-fence",
            "subject": {
                "dest_executor": dest_pin5,
                "holder": h_pin5,
                "inventory_sha256": mig5_sha,
                "migration_id": mig5_id,
                "predecessor_grant_seals": [],
                "source_journal_commitment": _h32("d7-m5-jc"),
                "source_journal_pos": 10,
            },
            "type": "seallink-statement/1",
        },
        [fx_m5["_keys"]["host_rcpt"]["sk"]],
    )
    eb5 = {"fencing_statement": f_stmt5, "inventory": mig5_inv, "source_journal_commitment": _h32("d7-m5-jc"), "source_journal_pos": 10}
    # Alice's manifest still points to id/mail-host-a, NOT dest id/mail-host-c -> SERVICE_PROVIDER_UNBOUND!
    add("d7-6b-migration-holder-manifest-unbound-dest-refuse", ["SL-SERV-002"], "migration", {"chain": fx_m5["chain"], "export_bundle": eb5, "holder_assent": ha5_ok, "journal": {"journal_id": _h32("d7-m5-j1")}, "local_executor_pin": dest_pin5, "manifests": fx_m5["bundle"]["manifests"], "migration": mig5_env}, "REFUSE", "SERVICE_PROVIDER_UNBOUND", "Decision 6B: migration when holder manifest does not bind dest_executor refuses SERVICE_PROVIDER_UNBOUND.")
    # Bad holder assent signer -> SERVICE_MIGRATION_INVALID
    ha5_bad = sl.sign_envelope(ha5_ok["payload"], [_kp("d7-m5-stranger")["sk"]])
    add("d7-6b-migration-bad-holder-assent-refuse", ["SL-SERV-002"], "migration", {"chain": fx_m5["chain"], "export_bundle": eb5, "holder_assent": ha5_bad, "journal": {"journal_id": _h32("d7-m5-j2")}, "local_executor_pin": dest_pin5, "manifests": fx_m5["bundle"]["manifests"], "migration": mig5_env}, "REFUSE", "SERVICE_MIGRATION_INVALID", "Decision 6B: migration with holder assent signed by wrong key refuses SERVICE_MIGRATION_INVALID.")
    # Holder has historical origin_id with missing origin_bundle -> ORIGIN_UNVERIFIED
    ch_m5_o = copy.deepcopy(fx_m5["chain"])
    ch_m5_o["names"]["id/alice"] = sv.make_name_history("id/alice", fx_m5["_alice_reg"], fx_m5["_alice_owner_pol"], {"link": {"grant": fx_m5["_keys"]["alice_gr"]["xonly"], "origin": _h32("m5-oid")}})
    add("d7-6b-migration-origin-holder-missing-bundle-refuse", ["SL-SERV-002", "SL-ORIG-002"], "migration", {"chain": ch_m5_o, "export_bundle": eb5, "holder_assent": ha5_ok, "journal": {"journal_id": _h32("d7-m5-j3")}, "local_executor_pin": dest_pin5, "manifests": fx_m5["bundle"]["manifests"], "migration": mig5_env}, "REFUSE", "ORIGIN_UNVERIFIED", "Decision 6B: migration for origin-bearing holder without origin_bundle refuses ORIGIN_UNVERIFIED.")
    # Bad dest_accept_stmt -> SERVICE_MIGRATION_INVALID
    da5_bad = sl.sign_envelope({"genesis": GENESIS_MAIN, "issuer": dest_pin5, "network": "main", "not_after": fx_m5["chain"]["now"] + 3600, "not_before": fx_m5["chain"]["now"] - 10, "seq": 1, "statement_kind": "migration-accept", "subject": {"holder": h_pin5, "inventory_sha256": _h32("wrong-inv"), "migration_id": mig5_id, "source_executor": s_pin5}, "type": "seallink-statement/1"}, [dest_rcpt5["sk"]])
    add("d7-6b-migration-bad-dest-accept-refuse", ["SL-SERV-002"], "migration", {"chain": fx_m5["chain"], "dest_accept_stmt": da5_bad, "export_bundle": eb5, "journal": {"journal_id": _h32("d7-m5-j4")}, "local_executor_pin": dest_pin5, "manifests": fx_m5["bundle"]["manifests"], "migration": mig5_env}, "REFUSE", "SERVICE_MIGRATION_INVALID", "Decision 6B: migration with mismatched dest migration-accept statement refuses SERVICE_MIGRATION_INVALID.")

    # --- Final 8 Precision Precedence & Boundary Kill Vectors ---
    # F1 (L1110): Observation bracket void MUST precede peer disagreement (SPEC-02 §4 Step 4a before 4d)
    ch_br_peer = copy.deepcopy(fx_sz["chain"])
    ch_br_peer["rebracket_tip"] = {"hash": _h32("other-tip"), "height": ch_br_peer["tip_height"] + 1}
    ch_br_peer["comparison_peers"] = [{"hash_at_tip": _h32("peer-fork"), "healthy": True, "height": ch_br_peer["tip_height"] + 5, "id": "p-disagree"}]
    add("d7-r1b-bracket-void-precedes-peer-disagreement-refuse", ["SL-LDGR-008"], "chain_obs", {"chain": ch_br_peer, "require_observation_bracket": True}, "REFUSE", "CHAIN_OBSERVATION_VOID", "SPEC-02 §4: Step 4a CHAIN_OBSERVATION_VOID MUST precede Step 4d CHAIN_NODE_DISAGREEMENT.")

    # F2 (L1454): Target update carrying unsupported ScriptPolicy in resolve_name -> CHAIN_SCRIPT_UNSUPPORTED
    fx_prev_unsup = rm._base_invocation_fixture()
    fx_prev_unsup["chain"]["names"]["id/alice"]["updates"][1]["owner_policy"] = {"kind": "unsupported_script"}
    add("d7-resolve-name-target-update-unsupported-script-refuse", ["SL-LDGR-004", "SL-LDGR-007"], "name_resolve", {"chain": fx_prev_unsup["chain"], "name": "id/alice"}, "REFUSE", "CHAIN_SCRIPT_UNSUPPORTED", "Target name update with unsupported ScriptPolicy refuses CHAIN_SCRIPT_UNSUPPORTED.")

    # F3 (L2264): status_seal spent by confirmed 0x09 tx with unknown commitment -> ORIGIN_STATUS_INCOMPLETE
    of_st_unk = rm._base_origin_fixture()
    st_unk_tx = _h32("d7-st-unk-tx")
    of_st_unk["chain"]["txs"][st_s["txid"]]["outputs"]["0"]["spent_by_txid"] = st_unk_tx
    of_st_unk["chain"]["txs"][st_unk_tx] = {"confirmed_height": tip_md - 5, "opreturn_hex": sl.encode_opreturn(0x09, _h32("unknown-status-commit")).hex(), "outputs": {}}
    add("d7-status-seal-unknown-0x09-commitment-refuse", ["SL-ORIG-002"], "origin_status", {"chain": of_st_unk["chain"], "origin_bundle": of_st_unk["origin_bundle"], "trusted_origin_issuer_pins": of_st_unk["trusted_origin_issuer_pins"]}, "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Confirmed 0x09 status_seal spend whose commitment matches neither end/1 nor capacity/1 refuses ORIGIN_STATUS_INCOMPLETE.")

    # F4 (L2283): Exact t_low == opened_majority AND tip_median_time_past == opened_majority -> emancipated (GUARDIAN_TRANSFER_PENDING, NOT GUARDIAN_TIME_BOUNDARY!)
    of_tlow_eq = rm._base_origin_fixture()
    of_tlow_eq["chain"]["credible_utc_interval"] = [t_maj, t_maj + 10]
    of_tlow_eq["chain"]["tip_median_time_past"] = t_maj
    add("d7-bnd-majority-tlow-eq-t-with-mtp-eq-t-emancipates", ["SL-ORIG-010", "SL-ORIG-011"], "origin_status", {"chain": of_tlow_eq["chain"], "origin_bundle": of_tlow_eq["origin_bundle"], "trusted_origin_issuer_pins": of_tlow_eq["trusted_origin_issuer_pins"]}, "REFUSE", "GUARDIAN_TRANSFER_PENDING", "Exact boundary: t_low == T with tip_median_time_past == T emancipates into handover check rather than GUARDIAN_TIME_BOUNDARY (kills t_low < T -> <=).")

    # F5 (L2505): trace_slot 0x12 initial activation exact operator_min_depth == 2 (ADMIT at tip-1 vs GUARDIAN_INACTIVE at tip)
    of_s12 = rm._base_origin_fixture()
    init12_txid = rm._h32("og1-init-0x12")
    of_s12["chain"]["txs"][init12_txid]["confirmed_height"] = tip_md - 1  # depth == 2!
    op_s12 = copy.deepcopy(of_s12["origin_bundle"]["origin"]["payload"])
    op_s12["guardian_policy"]["quorums"] = {k: {"den": 2, "min": 1, "num": 1} for k in op_s12["guardian_policy"]["quorums"]}
    o_s12 = sl.sign_envelope(op_s12, [of_s12["_keys"]["reg_cred"]["sk"]])
    oid_s12 = sl.object_id(op_s12)
    of_s12["origin_bundle"]["origin"] = o_s12
    of_s12["origin_bundle"]["name_binding"]["origin_id"] = oid_s12
    g1_s12_p = {**of_s12["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_s12}
    g1_s12 = sl.sign_envelope(g1_s12_p, [of_s12["_keys"]["reg_cred"]["sk"]])
    of_s12["origin_bundle"]["guardian_records"] = [g1_s12]
    of_s12["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**of_s12["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(g1_s12_p)}, [of_s12["_keys"]["g1_gr"]["sk"]])]
    of_s12["chain"]["txs"][of_s12["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_s12)).hex()
    of_s12["chain"]["txs"][of_s12["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_s12["origin_bundle"]["name_binding"])).hex()
    of_s12["chain"]["txs"][init12_txid]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_s12)).hex()
    c_s12 = copy.deepcopy(of_s12["contract"])
    c_s12["parties"][0]["ward_origin_id"] = oid_s12
    wa_s12 = sl.sign_guardian_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "guardian_context": {"event_class": "contract_assent", "origin_id": oid_s12, "revision": 1, "ward_name": "id/child-leo"},
         "issued_at": 1795220000, "network": "main", "nonce": _h32("d7-s12-wa"), "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
         "target_id": sl.object_id(c_s12), "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_s12["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add("d7-bnd-slot-0x12-depth-eq-2-admit", ["SL-ORIG-008", "SL-LDGR-008"], "assent", {"assent": wa_s12, "chain": of_s12["chain"], "contract": c_s12, "operator_min_depth": 2, "origin_bundle": of_s12["origin_bundle"], "trusted_origin_issuer_pins": of_s12["trusted_origin_issuer_pins"]}, "ADMIT", None, "Exact boundary: 0x12 initial activation at depth == operator_min_depth (2) admits (kills < -> <=).")
    of_s12_d1 = copy.deepcopy(of_s12)
    of_s12_d1["chain"]["txs"][init12_txid]["confirmed_height"] = tip_md  # depth 1 < 2 -> GUARDIAN_INACTIVE!
    add("d7-bnd-slot-0x12-depth-1-lt-2-inactive", ["SL-ORIG-008", "SL-LDGR-008"], "assent", {"assent": wa_s12, "chain": of_s12_d1["chain"], "contract": c_s12, "operator_min_depth": 2, "origin_bundle": of_s12_d1["origin_bundle"], "trusted_origin_issuer_pins": of_s12_d1["trusted_origin_issuer_pins"]}, "REFUSE", "GUARDIAN_INACTIVE", "Exact boundary: 0x12 initial activation at depth 1 with operator_min_depth=2 remains inactive.")

    # F6 (L2764): roster 0x0f next_roster_vout wrong script -> ORIGIN_STATUS_INCOMPLETE
    of_r_badnxt = copy.deepcopy(of_r_d2)
    of_r_badnxt["chain"]["txs"][rtx_rd]["outputs"]["0"]["script_pubkey_hex"] = "0014" + "00" * 20
    add("d7-roster-0x0f-wrong-next-roster-script-refuse", ["SL-ORIG-015"], "origin_status", {"chain": of_r_badnxt["chain"], "origin_bundle": of_r_badnxt["origin_bundle"], "trusted_origin_issuer_pins": of_r_badnxt["trusted_origin_issuer_pins"]}, "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "Roster 0x0f spend whose next_roster_vout script disagrees with next_roster_policy refuses ORIGIN_STATUS_INCOMPLETE.")

    # F7 (L3488/L3489): Step 2 invocation time window MUST precede Step 4 CHAIN_UNHEALTHY (both refusal & exact iat == now boundary!)
    fx_t2_exp = rm._base_invocation_fixture()
    fx_t2_exp["chain"]["in_ibd"] = True
    fx_t2_exp["invocation"] = sl.sign_envelope({**fx_t2_exp["invocation"]["payload"], "exp": fx_t2_exp["chain"]["now"]}, [fx_t2_exp["_keys"]["agent_req"]["sk"]])
    add("d7-step2-inv-time-invalid-precedes-chain-unhealthy-refuse", ["SL-GRNT-006", "SL-GRNT-012"], "invocation", fx_t2_exp, "REFUSE", "INVOKE_TIME_INVALID", "SPEC-06 §4: Step 2 INVOKE_TIME_INVALID MUST precede Step 4 CHAIN_UNHEALTHY.")
    fx_t2_iat = rm._base_invocation_fixture()
    fx_t2_iat["chain"]["in_ibd"] = True
    fx_t2_iat["invocation"] = sl.sign_envelope({**fx_t2_iat["invocation"]["payload"], "iat": fx_t2_iat["chain"]["now"]}, [fx_t2_iat["_keys"]["agent_req"]["sk"]])
    add("d7-bnd-step2-inv-iat-eq-now-reaches-chain-unhealthy", ["SL-GRNT-006", "SL-GRNT-012"], "invocation", fx_t2_iat, "REFUSE", "CHAIN_UNHEALTHY", "Exact boundary: Step 2 passes at iat == now and reaches Step 4 CHAIN_UNHEALTHY (kills <= -> <).")

    # F8 (L4848): migration holder_assent targeting wrong target_id -> SERVICE_MIGRATION_INVALID
    ha5_wrong_tid = sl.sign_envelope({**ha5_ok["payload"], "target_id": _h32("wrong-mig-tid")}, [fx_m5["_keys"]["alice_gr"]["sk"]])
    add("d7-6b-migration-holder-assent-wrong-target-id-refuse", ["SL-SERV-002"], "migration", {"chain": fx_m5["chain"], "export_bundle": eb5, "holder_assent": ha5_wrong_tid, "journal": {"journal_id": _h32("d7-m5-j5")}, "local_executor_pin": dest_pin5, "manifests": fx_m5["bundle"]["manifests"], "migration": mig5_env}, "REFUSE", "SERVICE_MIGRATION_INVALID", "Decision 6B: migration holder_assent with wrong target_id refuses SERVICE_MIGRATION_INVALID.")

    # F9 (L2749 wrong-code): 0x0f roster record signed by issuer with active 0x0b compromise break -> CRED_ISSUER_CLOSED
    of_r_0b = copy.deepcopy(of_r_d2)
    reg_name = of_r_0b["origin_bundle"]["origin"]["payload"]["issuer"]["name"]
    reg_u = of_r_0b["chain"]["names"][reg_name]["updates"]
    reg_prev = reg_u[-1]
    reg_opol = reg_prev["owner_policy"]
    reg_ospk, _ = sl.compile_script_policy(reg_opol)
    new_reg_cred = _kp("d7-reg-cred-post0b")["xonly"]
    cb_r = {
        "compromised_policy": {"m": 1, "pks": [of_r_0b["_keys"]["reg_cred"]["xonly"]]},
        "genesis": GENESIS_MAIN,
        "h_c": of_r_0b["chain"]["txs"][rtx_rd]["confirmed_height"],  # Compromises roster 0x0f (NOT origin at 749000)!
        "issuer": {"name": reg_name, "owner_policy": reg_opol, "registration": of_r_0b["chain"]["names"][reg_name]["registration"]},
        "name_input": {"txid": reg_prev["txid"], "vout": reg_prev["vout"]},
        "role": "cred",
        "type": "seallink-credential-break/1",
    }
    reg_u.append({
        "confirmed_height": tip_md,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(cb_r).hex(), h_c=cb_r["h_c"]).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", reg_ospk, name=reg_name.encode("utf-8"), value=sl.jcs_encode({"link": {"cred": new_reg_cred}})).hex(),
        "owner_policy": reg_opol,
        "prev_input": {"sighash_bytes": [0x01], "txid": reg_prev["txid"], "vout": reg_prev["vout"], "witness_policy": reg_opol},
        "txid": _h32("d7-reg-0x0b-tx"),
        "vout": 0,
    })
    add("d7-roster-0x0f-issuer-0x0b-compromised-refuse", ["SL-ORIG-015", "SL-CONT-009"], "origin_status", {"chain": of_r_0b["chain"], "origin_bundle": of_r_0b["origin_bundle"], "trusted_origin_issuer_pins": of_r_0b["trusted_origin_issuer_pins"]}, "REFUSE", "CRED_ISSUER_CLOSED", "SL-CONT-009: roster 0x0f record signed by cred policy compromised at h_c <= h_0x0f refuses CRED_ISSUER_CLOSED.")

    # F10 (L3247 wrong-code): standalone verify_notary_act with expected_child_binding mismatch -> NOTARY_REQUIRED
    add("d7-na-standalone-wrong-child-binding-refuse", ["SL-CONT-011"], "notary_act", {"anchor_txid": na_tx, "chain": fx_na["chain"], "expected_child_binding": {"child_grant_id": _h32("c-x"), "ordinal": 1, "parent_grant_id": _h32("p-x")}, "notary": na_ok}, "REFUSE", "NOTARY_REQUIRED", "Standalone verify_notary_act with expected_child_binding mismatch refuses NOTARY_REQUIRED.")
