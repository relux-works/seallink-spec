#!/usr/bin/env python3
"""
Draft.10 Hardened-Core Closure Conformance Suite (`B-1..B-2`, `H-1..H-15`, `M-1..M-16`, `L-4..L-13`, `F3`).

Executable golden & adversarial vectors closing 100% of independent verification review findings:
  1. B-1: Strict NamePin-only trusted_origin_issuer_pins (re-registered same-spelling issuer refuses ORIGIN_UNVERIFIED)
  2. B-2 / H-9 / H-10 / M-10 / M-16 / L-6: Bearer sessions — live root grant rotation, 0x0b break, depth-2 stop_outpoint spend,
     mandatory contract_env & framework_contract_env & contract window, mandatory action/target/arguments + profile args_schema +
     mail/read actual_message_meta, strict 64-lowercase-hex token, & multi-capability per-cap quota isolation
  3. H-1 / H-2 / H-3 / F3 / L-8: Fail-closed ChainView health/clock/bracket fields, canonical SL-LDGR-015 comparison_peers ABI,
     node_reachable=False on owner_command & statement, SLNK name-history framing (0x06/malformed/bad loc_type/h_c>h_inc -> CHAIN_FRAME_INVALID,
     critical reserved 0x13/0x14 -> ORIGIN_STATUS_INCOMPLETE, well-formed advisory 0x20 -> ADMIT)
  4. H-4 / D9-B1 / M-1: Authenticate grant signature BEFORE writing policy-scoped NAME_ROLE_CHANGED closure (0 closures on forged grant;
     legitimate successor key B admits in same journal & after restart), two-anchor 0x09 cred (h_late>=h_c then h_early<h_c) + idempotent closure,
     notary 0x0b compromise exact h_c-1 vs h_c boundary
  5. H-5 / H-6 / M-6 / M-7 / M-8 / M-9 / A-17: Childhood 0x0c does NOT auto-emancipate at T; post-T 0x0c DOES; rotated former guardian W1->W2
     still locked out from 0x10 in State 3 while State-4 adult cancels rogue 0x0c; emancipation pubkey disjointness; Pass-1 GUARDIAN_INACTIVE
     beats Pass-2 CRED_ISSUER_CLOSED; live ward grant 0x0b refusal; historical_existence_only seal checks; strict NamePin executor_cfg.pin
  6. H-8 / M-2 / M-3 / M-4 / M-5 / L-9 / L-11 / L-12: Global 2-pass precedence (QUOTA_EXCEEDED beats WIRE_MEMBER), extra actual_quota_usage key,
     own-vs-row settled equality, uncertain -> admit_and_reserve -> UNCERTAIN -> reconcile, single_use+uncertain->executed writes SINGLE_USE_CONSUMED
     once, tampered uncertain released!=0 replay -> JOURNAL_LOST, settlement.recorded_at == receipt.payload.recorded_at, blk:/sec: golden buckets
  7. H-11 / H-12 / H-13 / H-14 / H-15 / M-11..M-15: Contour A hop actor == recipient.name, pii_disclosure grant window & live seal,
     DEVICE_UNAUTHORIZED preservation, mandatory journal on federation, closed MigrationExportBundle + source-signed migration-fence + on-chain
     predecessor_grant_seals[] spend, uniform core-only ACTION_UNSUPPORTED across verify_wire_bytes/owner_command/statement/assent,
     and strict actual_message_meta enforcement across mail/read folder/sender_domain/max_bytes.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Callable

import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = rm.GENESIS_MAIN


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-d10:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"d10:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def _raw_slnk_frame(action_byte: int, payload: bytes) -> str:
    """Build raw OP_RETURN SLNK frame: 6a 05 'SLNK' <action> <push(payload)>."""
    if len(payload) <= 75:
        push = bytes([len(payload)]) + payload
    else:
        push = bytes([0x4C, len(payload)]) + payload
    return (bytes([0x6A, 0x05]) + b"SLNK" + bytes([action_byte]) + push).hex()


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


def add_draft10_conformance_cases(add: Callable[..., None]) -> None:
    """Register all v1.0.0-draft.10 hardened-core closure conformance vectors."""

    # =========================================================================
    # 1. B-1: Strict NamePin-only trusted_origin_issuer_pins
    # =========================================================================
    of_b1 = rm._base_origin_fixture()
    alt_reg_pin = {
        "name": "id/civil-registry",
        "owner_policy": {"kind": "key", "pk": _kp("b1-re-reg-own")["comp"]},
        "registration": {"txid": _h32("b1-re-reg-tx"), "vout": 0},
    }
    add(
        "d10-b1-reregistered-origin-issuer-same-spelling-refuse",
        ["SL-ORIG-001", "SL-IDTY-002"],
        "origin_status",
        {
            "chain": of_b1["chain"],
            "origin_bundle": of_b1["origin_bundle"],
            "trusted_origin_issuer_pins": [alt_reg_pin],
        },
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "B-1: Same-spelling origin issuer with different registration/owner_policy MUST refuse ORIGIN_UNVERIFIED.",
    )
    add(
        "d10-b1-empty-trusted-origin-issuer-pins-refuse",
        ["SL-ORIG-001"],
        "origin_status",
        {
            "chain": of_b1["chain"],
            "origin_bundle": of_b1["origin_bundle"],
            "trusted_origin_issuer_pins": [],
        },
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "B-1: Empty trusted_origin_issuer_pins MUST refuse ORIGIN_UNVERIFIED.",
    )

    # =========================================================================
    # 2. B-2 / H-9 / H-10 / M-10 / M-16 / L-6: Bearer sessions live re-validation & quota isolation
    # =========================================================================
    fx_bs = rm._base_invocation_fixture()
    gp_bs = copy.deepcopy(fx_bs["bundle"]["grants"][0]["payload"])
    gp_bs["capabilities"] = [
        {
            "action": "mail/read",
            "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}],
            "target": "mailbox:id/alice:work",
            "where": {"folder": {"eq": "Invoices"}, "max_bytes": {"range": ["0", "1024"]}, "sender_domain": {"eq": "vendor.example"}},
        },
        {
            "action": "mail/list",
            "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "lists", "window": "term"}],
            "target": "mailbox:id/alice:work",
        },
    ]
    g_bs_env, gid_bs = _reanchor(fx_bs, gp_bs)
    bs_itx = fx_bs["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    so_bs = sl.sign_envelope(
        {
            "executor": gp_bs["executor"],
            "exp": fx_bs["chain"]["now"] + 600,
            "genesis": GENESIS_MAIN,
            "iat": fx_bs["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d10-bs-op"),
            "op": "open",
            "proof_path": [{"grant_id": gid_bs, "issuance_txid": bs_itx}],
            "quotas": [
                gp_bs["capabilities"][0]["quotas"][0],
                gp_bs["capabilities"][1]["quotas"][0],
            ],
            "slot_binding": "slot-d10",
            "type": "seallink-session-open/1",
        },
        [fx_bs["_keys"]["agent_req"]["sk"]],
    )
    tok_bs = _h32("d10-bs-tok-64hex")
    sid_bs = sl.object_id(so_bs["payload"])

    # M-10 / L-6: Multi-cap session debits ONLY matched capability's quota (leaves mail/list quota at 0!)
    add(
        "d10-m10-bearer-multi-cap-debits-only-matched-cap-admit",
        ["SL-GRNT-013", "SL-GRNT-007"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs["executor_cfg"],
            "journal": {"journal_id": _h32("d10-bs-j1")},
            "steps": [
                {"bearer_token": tok_bs, "bundle": fx_bs["bundle"], "chain": fx_bs["chain"], "kind": "session_open", "label": "open-2cap", "session_open": so_bs, "want_refusal": None, "want_verdict": "ADMIT"},
                {
                    "action": "mail/read",
                    "actual_message_meta": {"folder": "Invoices", "sender_domain": "vendor.example", "size_bytes": "512"},
                    "arguments": {"folder": "Invoices", "message_id": "m1"},
                    "chain": fx_bs["chain"],
                    "check_balances": [
                        {"bucket_id": "term", "expected": 1, "qkey": "seallink/count|mailbox:id/alice:work|reads|term", "scope": f"session:{sid_bs}"},
                        {"bucket_id": "term", "expected": 1, "qkey": "seallink/count|mailbox:id/alice:work|reads|term", "scope": f"own:{gid_bs}"},
                        {"bucket_id": "term", "expected": 0, "qkey": "seallink/count|mailbox:id/alice:work|lists|term", "scope": f"session:{sid_bs}"},
                        {"bucket_id": "term", "expected": 0, "qkey": "seallink/count|mailbox:id/alice:work|lists|term", "scope": f"own:{gid_bs}"},
                    ],
                    "expect_debit_count": 2,
                    "grant_env": g_bs_env,
                    "kind": "bearer_session",
                    "label": "use-read-only",
                    "slot_binding": "slot-d10",
                    "target": "mailbox:id/alice:work",
                    "token": tok_bs,
                    "want_refusal": None,
                    "want_verdict": "ADMIT",
                },
            ],
        },
        "ADMIT",
        None,
        "M-10/L-6: Multi-capability bearer session debits ONLY quotas of the matched capability (mail/read), leaving unrelated capability quota (mail/list) at 0.",
        module="bearer-sessions",
    )

    # H-9: Bearer mail/read missing actual_message_meta or violating size_bytes/sender_domain/action omitted
    add(
        "d10-h9-bearer-mail-read-missing-and-bad-meta-refuse",
        ["SL-GRNT-013", "SL-PROF-001"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs["executor_cfg"],
            "journal": {"journal_id": _h32("d10-bs-j2")},
            "steps": [
                {"bearer_token": tok_bs, "bundle": fx_bs["bundle"], "chain": fx_bs["chain"], "kind": "session_open", "label": "open", "session_open": so_bs, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": fx_bs["chain"], "expect_zero_writes": True, "grant_env": g_bs_env, "kind": "bearer_session", "label": "missing-meta", "slot_binding": "slot-d10", "target": "mailbox:id/alice:work", "token": tok_bs, "want_refusal": "INVOKE_CONSTRAINT_FAILED", "want_verdict": "REFUSE"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices", "sender_domain": "vendor.example", "size_bytes": "1025"}, "arguments": {"folder": "Invoices", "message_id": "m2"}, "chain": fx_bs["chain"], "expect_zero_writes": True, "grant_env": g_bs_env, "kind": "bearer_session", "label": "oversize-meta", "slot_binding": "slot-d10", "target": "mailbox:id/alice:work", "token": tok_bs, "want_refusal": "INVOKE_CONSTRAINT_FAILED", "want_verdict": "REFUSE"},
                {"chain": fx_bs["chain"], "expect_zero_writes": True, "grant_env": g_bs_env, "kind": "bearer_session", "label": "missing-action-args", "slot_binding": "slot-d10", "token": tok_bs, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "H-9: Bearer session use MUST require action/target/arguments and enforce mail/read actual_message_meta constraints.",
        module="bearer-sessions",
    )

    # B-2: Bearer session refuses SESSION_INVALID after live root link.grant rotation!
    ch_bs_rot = copy.deepcopy(fx_bs["chain"])
    al_prev = ch_bs_rot["names"]["id/alice"]["updates"][-1]
    al_new_gr = _kp("d10-bs-al-new-gr")
    al_ospk, _ = sl.compile_script_policy(fx_bs["_alice_owner_pol"])
    ch_bs_rot["names"]["id/alice"]["updates"].append({
        "block_time": 1795220020,
        "confirmed_height": 750003,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", al_ospk, name=b"id/alice", value=sl.jcs_encode({"link": {"grant": al_new_gr["xonly"]}, "m": {"h": sl.content_addr(fx_bs["_alice_man"]), "s": 1}})).hex(),
        "owner_policy": fx_bs["_alice_owner_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": al_prev["txid"], "vout": al_prev["vout"], "witness_policy": fx_bs["_alice_owner_pol"]},
        "txid": _h32("d10-bs-al-rot-tx"),
        "vout": 0,
    })
    rm.sync_chain_tip(ch_bs_rot, height=750004)
    add(
        "d10-b2-bearer-after-grant-rotation-refuse",
        ["SL-GRNT-013", "SL-CONT-009"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs["executor_cfg"],
            "journal": {"journal_id": _h32("d10-bs-j3")},
            "steps": [
                {"bearer_token": tok_bs, "bundle": fx_bs["bundle"], "chain": fx_bs["chain"], "kind": "session_open", "label": "open", "session_open": so_bs, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/list", "arguments": {"folder": "Invoices", "page": 0}, "chain": ch_bs_rot, "grant_env": g_bs_env, "kind": "bearer_session", "label": "after-rotation", "slot_binding": "slot-d10", "target": "mailbox:id/alice:work", "token": tok_bs, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "B-2: Bearer session use re-validates root issuer link.grant live and refuses SESSION_INVALID after rotation.",
        module="bearer-sessions",
    )

    # B-2: Bearer session refuses SESSION_INVALID on exact-boundary live 0x0b (tip == h_c) AND persisted role closure (without 0x0b on chain)!
    ch_bs_0b = copy.deepcopy(fx_bs["chain"])
    ch_bs_0b["names"]["id/alice"]["updates"].append(
        _make_0x0b_update(
            "id/alice",
            ch_bs_0b["names"]["id/alice"]["updates"][-1],
            fx_bs["_alice_reg"],
            fx_bs["_alice_owner_pol"],
            "grant",
            {"m": 1, "pks": [fx_bs["_keys"]["alice_gr"]["xonly"]]},
            {"link": {"grant": fx_bs["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_bs["_alice_man"]), "s": 1}},
            h_c=750004,
            h_update=750004,
            label="d10-bs-0b",
        )
    )
    rm.sync_chain_tip(ch_bs_0b, height=750004)
    ch_bs_no_0b = copy.deepcopy(fx_bs["chain"])
    rm.sync_chain_tip(ch_bs_no_0b, height=750004)
    add(
        "d10-b2-bearer-0x0b-exact-hc-live-and-persisted-refuse",
        ["SL-GRNT-013", "SL-CONT-009"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs["executor_cfg"],
            "journal": {"journal_id": _h32("d10-bs-j3b")},
            "steps": [
                {"bearer_token": tok_bs, "bundle": fx_bs["bundle"], "chain": fx_bs["chain"], "kind": "session_open", "label": "open", "session_open": so_bs, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/list", "arguments": {"folder": "Invoices", "page": 0}, "chain": ch_bs_0b, "grant_env": g_bs_env, "kind": "bearer_session", "label": "live-0x0b-at-exact-hc", "slot_binding": "slot-d10", "target": "mailbox:id/alice:work", "token": tok_bs, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"action": "mail/list", "arguments": {"folder": "Invoices", "page": 0}, "chain": ch_bs_no_0b, "expect_zero_writes": True, "grant_env": g_bs_env, "kind": "bearer_session", "label": "persisted-0x0b-at-exact-hc", "slot_binding": "slot-d10", "target": "mailbox:id/alice:work", "token": tok_bs, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "B-2: Bearer session refuses SESSION_INVALID on live 0x0b at exact tip_height==h_c and persists cutoff closure blocking repeat use even without 0x0b on chain.",
        module="bearer-sessions",
    )

    # B-2: Depth-2 bearer session admits at exact range upper bound (row_ord==count==1) then refuses SESSION_INVALID after parent stop_outpoint spend!
    fx_d2 = rm._delegation_fx(notary_mode="optional_stop", with_stop=True)
    p_d2_p = copy.deepcopy(fx_d2["bundle"]["grants"][0]["payload"])
    p_d2_p["delegate"]["groups"][0]["ranges"][0]["count"] = 1
    p_d2 = sl.sign_envelope(p_d2_p, [fx_d2["_keys"]["alice_gr"]["sk"]])
    pid_d2 = sl.object_id(p_d2_p)
    c_d2_p = copy.deepcopy(fx_d2["bundle"]["grants"][1]["payload"])
    c_d2_p["parent"]["grant_id"] = pid_d2
    c_d2 = sl.sign_envelope(c_d2_p, [fx_d2["_del_k"]["sk"]])
    cid_d2 = sl.object_id(c_d2_p)
    p_itx_d2, c_itx_d2 = fx_d2["invocation"]["payload"]["proof_path"][0]["issuance_txid"], fx_d2["invocation"]["payload"]["proof_path"][1]["issuance_txid"]
    fx_d2["chain"]["txs"][p_itx_d2]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_d2), "grant_id": pid_d2, "type": "seallink-issuance/1"}).hex()).hex()
    fx_d2["chain"]["txs"][c_itx_d2]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_d2), "grant_id": cid_d2, "type": "seallink-issuance/1"}).hex()).hex()
    fx_d2["bundle"]["grants"] = [p_d2, c_d2]
    so_d2 = sl.sign_envelope(
        {
            "executor": c_d2["payload"]["executor"],
            "exp": fx_d2["chain"]["now"] + 600,
            "genesis": GENESIS_MAIN,
            "iat": fx_d2["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d10-d2-op"),
            "op": "open",
            "proof_path": [{"grant_id": pid_d2, "issuance_txid": p_itx_d2}, {"grant_id": cid_d2, "issuance_txid": c_itx_d2}],
            "quotas": c_d2["payload"]["capabilities"][0]["quotas"],
            "slot_binding": "slot-d2",
            "type": "seallink-session-open/1",
        },
        [fx_d2["_keys"]["agent_req"]["sk"]],
    )
    tok_d2 = _h32("d10-d2-tok")
    ch_d2_stop = copy.deepcopy(fx_d2["chain"])
    rng_d2 = p_d2["payload"]["delegate"]["groups"][0]["ranges"][0]
    stop_txid, stop_vout = rng_d2["stop_txid"], rng_d2["stop_first"]
    ch_d2_stop["txs"][stop_txid]["outputs"][str(stop_vout)]["spent_by_txid"] = _h32("d10-d2-stop-spend")
    ch_d2_stop["txs"][_h32("d10-d2-stop-spend")] = {"confirmed_height": 750004, "inputs": [sv.make_segwit_input(stop_txid, stop_vout)], "outputs": {}}
    rm.sync_chain_tip(ch_d2_stop, height=750005)
    add(
        "d10-b2-bearer-depth2-stop-coin-spent-refuse",
        ["SL-GRNT-013", "SL-GRNT-012"],
        "session_lifecycle",
        {
            "executor_cfg": fx_d2["executor_cfg"],
            "journal": {"journal_id": _h32("d10-d2-j")},
            "steps": [
                {"bearer_token": tok_d2, "bundle": fx_d2["bundle"], "chain": fx_d2["chain"], "kind": "session_open", "label": "open-d2", "session_open": so_d2, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/tool", "arguments": {"input_sha256": _h32("in-d2-ok"), "max_output_bytes": "128", "tool_name": "pytest"}, "chain": fx_d2["chain"], "grant_env": c_d2, "kind": "bearer_session", "label": "unspent-stop-admit", "parent_grant_env": p_d2, "slot_binding": "slot-d2", "target": "station:id/station-a:tools", "token": tok_d2, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/tool", "arguments": {"input_sha256": _h32("in-d2"), "max_output_bytes": "128", "tool_name": "pytest"}, "chain": ch_d2_stop, "grant_env": c_d2, "kind": "bearer_session", "label": "stop-spent", "parent_grant_env": p_d2, "slot_binding": "slot-d2", "target": "station:id/station-a:tools", "token": tok_d2, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "B-2: Depth-2 bearer session admits at exact range boundary (row_ord==count==1) while stop_outpoint is unspent and refuses SESSION_INVALID once spent.",
        module="bearer-sessions",
    )

    # H-10: Contract-bound bearer session omitting contract_env AND exact contract window boundaries (not_before_height, not_after_height, not_after_unix)!
    fx_ct = rm._contract_fx()
    c_ct = copy.deepcopy(fx_ct["bundle"]["contract"])
    c_ct["window"]["not_before_height"] = 750002
    c_ct["window"]["not_after_height"] = 750050
    c_ct["window"]["not_after_unix"] = fx_ct["chain"]["now"] + 500
    cid_ct_new = sl.object_id(c_ct)
    fx_ct["bundle"]["contract"] = c_ct
    fx_ct["bundle"]["contract_assents"] = [
        sl.sign_envelope({**a["payload"], "target_id": cid_ct_new}, [fx_ct["_keys"]["alice_gr"]["sk"] if a["payload"]["party_id"] == "client-1" else fx_ct["_keys"]["agent_req"]["sk"]])
        for a in fx_ct["bundle"]["contract_assents"]
    ]
    gp_ct_new = copy.deepcopy(fx_ct["bundle"]["grants"][0]["payload"])
    gp_ct_new["contract_id"] = cid_ct_new
    gp_ct_new["not_before_height"] = 750002
    gp_ct_new["not_after_height"] = 750050
    g_ct, gid_ct = _reanchor(fx_ct, gp_ct_new)
    so_ct = sl.sign_envelope(
        {
            "executor": g_ct["payload"]["executor"],
            "exp": fx_ct["chain"]["now"] + 1200,
            "genesis": GENESIS_MAIN,
            "iat": fx_ct["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d10-ct-op"),
            "op": "open",
            "proof_path": fx_ct["invocation"]["payload"]["proof_path"],
            "quotas": g_ct["payload"]["capabilities"][0]["quotas"],
            "slot_binding": "slot-ct",
            "type": "seallink-session-open/1",
        },
        [fx_ct["_keys"]["agent_req"]["sk"]],
    )
    tok_ct = _h32("d10-ct-tok")
    ch_ct_nb = copy.deepcopy(fx_ct["chain"])
    rm.sync_chain_tip(ch_ct_nb, height=750002)
    ch_ct_exp_h = copy.deepcopy(fx_ct["chain"])
    rm.sync_chain_tip(ch_ct_exp_h, height=750050)
    ch_ct_exp_t = copy.deepcopy(fx_ct["chain"])
    ch_ct_exp_t["now"] = c_ct["window"]["not_after_unix"]
    ch_ct_exp_t["clock_watermark"] = ch_ct_exp_t["now"]
    ch_ct_exp_t["tip_header_time"] = ch_ct_exp_t["now"] - 60
    ch_ct_exp_t["tip_first_sight"] = ch_ct_exp_t["now"] - 60
    add(
        "d10-h10-bearer-missing-contract-and-expired-window-refuse",
        ["SL-GRNT-013", "SL-CONT-005"],
        "session_lifecycle",
        {
            "executor_cfg": fx_ct["executor_cfg"],
            "journal": {"journal_id": _h32("d10-ct-j")},
            "steps": [
                {"bearer_token": tok_ct, "bundle": fx_ct["bundle"], "chain": ch_ct_nb, "kind": "session_open", "label": "open-ct", "session_open": so_ct, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/session", "arguments": {"config_sha256": c_ct["config_sha256"], "op": "start", "session_slot": "slot1"}, "chain": ch_ct_nb, "contract_env": c_ct, "grant_env": g_ct, "kind": "bearer_session", "label": "exact-not-before-admit", "slot_binding": "slot-ct", "target": "station:id/station-a:slot1", "token": tok_ct, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/session", "arguments": {"config_sha256": c_ct["config_sha256"], "op": "start", "session_slot": "slot1"}, "chain": ch_ct_nb, "expect_zero_writes": True, "grant_env": g_ct, "kind": "bearer_session", "label": "missing-contract-env", "slot_binding": "slot-ct", "target": "station:id/station-a:slot1", "token": tok_ct, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"action": "agent/session", "arguments": {"config_sha256": c_ct["config_sha256"], "op": "start", "session_slot": "slot1"}, "chain": ch_ct_exp_t, "contract_env": c_ct, "expect_zero_writes": True, "grant_env": g_ct, "kind": "bearer_session", "label": "exact-not-after-unix-refuse", "slot_binding": "slot-ct", "target": "station:id/station-a:slot1", "token": tok_ct, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "H-10: Contract-bound bearer session admits at exact not_before_height and refuses SESSION_INVALID on omitted contract_env and exact not_after_unix.",
        module="bearer-sessions",
    )
    # Direct bearer_session check with wider grant window (not_after=750100) vs contract not_after_height=750050 at exact tip==750050!
    gp_ct_wide = {**copy.deepcopy(gp_ct_new), "not_after_height": 750100}
    g_ct_wide = sl.sign_envelope(gp_ct_wide, [fx_ct["_keys"]["alice_gr"]["sk"]])
    gid_ct_wide = sl.object_id(gp_ct_wide)
    j_ct_wide_dict = {
        "journal_id": _h32("d10-ct-wide-j"),
        "sessions": {
            sl.sha256(tok_ct.encode("utf-8")).hex(): {
                "closed": False,
                "exp": fx_ct["chain"]["now"] + 1200,
                "grant_id": gid_ct_wide,
                "session_id": _h32("d10-ct-wide-sid"),
                "slot_binding": "slot-ct",
            }
        },
    }
    add(
        "d10-h10-bearer-contract-exact-not-after-height-refuse",
        ["SL-GRNT-013", "SL-CONT-005"],
        "bearer_session",
        {
            "action": "agent/session",
            "arguments": {"config_sha256": c_ct["config_sha256"], "op": "start", "session_slot": "slot1"},
            "chain": ch_ct_exp_h,
            "contract_env": c_ct,
            "expect_zero_writes": True,
            "grant_env": g_ct_wide,
            "journal": j_ct_wide_dict,
            "slot_binding": "slot-ct",
            "target": "station:id/station-a:slot1",
            "token": tok_ct,
        },
        "REFUSE",
        "SESSION_INVALID",
        "H-10: Bearer session MUST enforce contract window not_after_height independently of grant window at exact tip_height == contract.window.not_after_height.",
        module="bearer-sessions",
    )

    # H-9 / M-10: Bearer session non-dict args, bad args_schema, and seconds: window clock regression!
    fx_bsec = rm._base_invocation_fixture()
    gp_bsec = copy.deepcopy(fx_bsec["bundle"]["grants"][0]["payload"])
    gp_bsec["capabilities"] = [
        {"action": "mail/list", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "lists", "window": "seconds:3600"}], "target": "mailbox:id/alice:work"}
    ]
    g_bsec, gid_bsec = _reanchor(fx_bsec, gp_bsec)
    so_bsec = sl.sign_envelope(
        {
            "executor": gp_bsec["executor"],
            "exp": fx_bsec["chain"]["now"] + 600,
            "genesis": GENESIS_MAIN,
            "iat": fx_bsec["chain"]["now"] - 10,
            "network": "main",
            "nonce": _h32("d10-bsec-op"),
            "op": "open",
            "proof_path": [{"grant_id": gid_bsec, "issuance_txid": fx_bsec["invocation"]["payload"]["proof_path"][0]["issuance_txid"]}],
            "quotas": gp_bsec["capabilities"][0]["quotas"],
            "slot_binding": "slot-bsec",
            "type": "seallink-session-open/1",
        },
        [fx_bsec["_keys"]["agent_req"]["sk"]],
    )
    tok_bsec = _h32("d10-bsec-tok")
    ch_bsec_reg = copy.deepcopy(fx_bsec["chain"])
    ch_bsec_reg["now"] = fx_bsec["chain"]["now"] - 1
    ch_bsec_reg["clock_watermark"] = ch_bsec_reg["now"]
    ch_bsec_reg["tip_header_time"] = ch_bsec_reg["now"] - 60
    ch_bsec_reg["tip_first_sight"] = ch_bsec_reg["now"] - 60
    add(
        "d10-h9-bearer-args-schema-and-seconds-clock-regression-refuse",
        ["SL-GRNT-013", "SL-GRNT-007"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bsec["executor_cfg"],
            "journal": {"journal_id": _h32("d10-bsec-j")},
            "steps": [
                {"bearer_token": tok_bsec, "bundle": fx_bsec["bundle"], "chain": fx_bsec["chain"], "kind": "session_open", "label": "open-sec", "session_open": so_bsec, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/list", "arguments": "not-a-dict", "chain": fx_bsec["chain"], "expect_zero_writes": True, "grant_env": g_bsec, "kind": "bearer_session", "label": "non-dict-args", "slot_binding": "slot-bsec", "target": "mailbox:id/alice:work", "token": tok_bsec, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"action": "mail/list", "arguments": {"folder": "Invoices", "page": -1, "unexpected": True}, "chain": fx_bsec["chain"], "expect_zero_writes": True, "grant_env": g_bsec, "kind": "bearer_session", "label": "bad-args-schema", "slot_binding": "slot-bsec", "target": "mailbox:id/alice:work", "token": tok_bsec, "want_refusal": "WIRE_MEMBER", "want_verdict": "REFUSE"},
                {"action": "mail/list", "arguments": {"folder": "Invoices", "page": 0}, "chain": fx_bsec["chain"], "grant_env": g_bsec, "kind": "bearer_session", "label": "first-sec-use-admit", "slot_binding": "slot-bsec", "target": "mailbox:id/alice:work", "token": tok_bsec, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/list", "arguments": {"folder": "Invoices", "page": 0}, "chain": ch_bsec_reg, "expect_zero_writes": True, "grant_env": g_bsec, "kind": "bearer_session", "label": "sec-clock-regression", "slot_binding": "slot-bsec", "target": "mailbox:id/alice:work", "token": tok_bsec, "want_refusal": "QUOTA_CLOCK_REGRESSION", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "H-9/M-10: Bearer session refuses non-dict arguments (INVOKE_CONSTRAINT_FAILED), invalid profile args_schema (WIRE_MEMBER), and seconds: window clock regression (QUOTA_CLOCK_REGRESSION).",
        module="bearer-sessions",
    )

    # M-16: Non-64-lowercase-hex bearer token refused in both session_open and bearer_session!
    add(
        "d10-m16-bearer-non-64hex-token-refuse",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs["executor_cfg"],
            "journal": {"journal_id": _h32("d10-tok-j")},
            "steps": [
                {"bearer_token": "not-64-hex", "bundle": fx_bs["bundle"], "chain": fx_bs["chain"], "expect_zero_writes": True, "kind": "session_open", "label": "open-bad-tok", "session_open": so_bs, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"action": "mail/list", "arguments": {"folder": "Invoices", "page": 0}, "chain": fx_bs["chain"], "expect_zero_writes": True, "grant_env": g_bs_env, "kind": "bearer_session", "label": "use-upper-tok", "slot_binding": "slot-d10", "target": "mailbox:id/alice:work", "token": "A" * 64, "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "M-16: Bearer tokens MUST be strictly 64 lowercase hex characters in both open and use.",
        module="bearer-sessions",
    )
    add(
        "d10-m16-bearer-preseeded-uppercase-token-still-refuse",
        ["SL-GRNT-013"],
        "bearer_session",
        {
            "action": "mail/list",
            "arguments": {"folder": "Invoices", "page": 0},
            "chain": fx_bs["chain"],
            "expect_zero_writes": True,
            "grant_env": g_bs_env,
            "journal": {
                "journal_id": _h32("d10-tok-pre-j"),
                "sessions": {
                    sl.sha256(("A" * 64).encode("utf-8")).hex(): {
                        "closed": False,
                        "exp": fx_bs["chain"]["now"] + 600,
                        "grant_id": gid_bs,
                        "session_id": _h32("d10-tok-pre-sid"),
                        "slot_binding": "slot-d10",
                    }
                },
            },
            "slot_binding": "slot-d10",
            "target": "mailbox:id/alice:work",
            "token": "A" * 64,
        },
        "REFUSE",
        "SESSION_INVALID",
        "M-16: Even if a non-64-lowercase-hex token hash existed in journal.sessions, format gate MUST refuse SESSION_INVALID.",
        module="bearer-sessions",
    )

    # =========================================================================
    # 3. H-1 / H-2 / H-3 / F3 / L-8: Chain health fail-closed, comparison_peers ABI, SLNK criticality
    # =========================================================================
    base_ch = copy.deepcopy(fx_bs["chain"])
    for missing_field, want_code in [
        ("txindex", "CHAIN_UNHEALTHY"),
        ("in_ibd", "CHAIN_UNHEALTHY"),
        ("node_reachable", "CHAIN_UNHEALTHY"),
        ("best_header_height", "CHAIN_UNHEALTHY"),
        ("clock_watermark", "CHAIN_CLOCK_ERROR"),
        ("observation_bracket", "CHAIN_OBSERVATION_VOID"),
    ]:
        ch_m = copy.deepcopy(base_ch)
        ch_m.pop(missing_field, None)
        add(
            f"d10-h1-omitted-{missing_field.replace('_', '-')}-refuse",
            ["SL-LDGR-001", "SL-LDGR-015"],
            "chain_obs",
            {"chain": ch_m},
            "REFUSE",
            want_code,
            f"H-1: Omitting required ChainViewSnapshot field '{missing_field}' MUST fail closed with {want_code}.",
        )
    ch_peer_mal = copy.deepcopy(base_ch)
    ch_peer_mal["comparison_peers"] = [{"healthy": True, "height": ch_peer_mal["tip_height"], "id": "observer-bad"}]
    add(
        "d10-h1-comparison-peer-missing-hash-at-tip-refuse",
        ["SL-LDGR-002", "SL-LDGR-015"],
        "chain_obs",
        {"chain": ch_peer_mal},
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "H-1: Healthy comparison_peers entry omitting mandatory hash_at_tip MUST fail closed with CHAIN_UNHEALTHY.",
    )
    ch_peer = copy.deepcopy(base_ch)
    ch_peer["comparison_peers"] = [{"hash_at_tip": _h32("divergent-tip"), "healthy": True, "height": ch_peer["tip_height"], "id": "observer-b"}]
    add(
        "d10-h1-divergent-comparison-peer-canonical-abi-refuse",
        ["SL-LDGR-002", "SL-LDGR-015"],
        "chain_obs",
        {"chain": ch_peer},
        "REFUSE",
        "CHAIN_NODE_DISAGREEMENT",
        "H-1: Divergent comparison_peers entry using canonical SL-LDGR-015 ChainViewSnapshot ABI MUST refuse CHAIN_NODE_DISAGREEMENT.",
    )

    # H-2: node_reachable=False in verify_owner_command & verify_statement -> CHAIN_UNHEALTHY
    fx_oc = rm._base_invocation_fixture()
    p256_sk = sl.deterministic_p256_privkey("d10-h2-p256")
    p256_pk = sl.p256_compressed_pubkey(p256_sk)
    ds_pol = {"kind": "key", "pk": _kp("d10-h2-ds")["comp"]}
    ds_tx = _h32("d10-h2-ds-tx")
    fx_oc["chain"]["txs"][ds_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(ds_pol)}}}
    _, dp_h2 = rm.make_salted_device_set(
        "id/alice",
        [{"alg": "p256", "ceiling": 1, "key": p256_pk, "label": "l1", "presence": True, "seal": {"script_policy": ds_pol, "txid": ds_tx, "vout": 0}}],
    )
    oc_env = sl.sign_envelope(
        {"arguments": {"brief_sha256": _h32("d10-h2-brf"), "run_id": "run-h2"}, "command": "agent-dispatch", "exp": fx_oc["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "iat": fx_oc["chain"]["now"] - 10, "level": 0, "network": "main", "nonce": _h32("d10-h2-n"), "owner": "id/alice", "target_executor": "id/mail-host-a", "type": "seallink-owner-command/1"},
        [p256_sk],
        alg="p256",
    )
    ch_unreach = copy.deepcopy(fx_oc["chain"])
    ch_unreach["node_reachable"] = False
    add(
        "d10-h2-owner-command-node-unreachable-chain-unhealthy",
        ["SL-LDGR-001", "SL-IDTY-010"],
        "owner_command",
        {"chain": ch_unreach, "command": oc_env, "device_proof": dp_h2[0], "is_foreign_service": False},
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "H-2: verify_owner_command on node_reachable=False MUST fail closed with CHAIN_UNHEALTHY.",
    )
    st_h2 = sl.sign_envelope(
        {"genesis": GENESIS_MAIN, "issuer": {"name": "id/alice", "owner_policy": fx_oc["_alice_owner_pol"], "registration": fx_oc["_alice_reg"]}, "network": "main", "not_after": fx_oc["chain"]["now"] + 600, "not_before": fx_oc["chain"]["now"] - 10, "seq": 1, "statement_kind": "transport-binding", "subject": {"endpoint": "https://alice.example.org", "key_alg": "bip340", "key_hex": _h32("d10-h2-tk"), "transport": "https-tls-spki"}, "type": "seallink-statement/1"},
        [fx_oc["_keys"]["alice_gr"]["sk"]],
    )
    add(
        "d10-h2-statement-node-unreachable-chain-unhealthy",
        ["SL-LDGR-001"],
        "statement",
        {"chain": ch_unreach, "statement": st_h2},
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "H-2: verify_statement on node_reachable=False MUST fail closed with CHAIN_UNHEALTHY.",
    )
    add(
        "d10-h2-evaluate-seal-node-unreachable-chain-unhealthy",
        ["SL-LDGR-001", "SL-LDGR-013"],
        "seal",
        {"chain": ch_unreach, "seal": fx_oc["bundle"]["grants"][0]["payload"]["revocation"]["seal"]},
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "H-2: evaluate_seal on node_reachable=False MUST fail closed with CHAIN_UNHEALTHY.",
    )
    add(
        "d10-h2-evaluate-single-use-seal-node-unreachable-chain-unhealthy",
        ["SL-LDGR-001", "SL-LDGR-013"],
        "single_use_seal",
        {
            "chain": ch_unreach,
            "invocation_content_addr": sl.content_addr(fx_oc["invocation"]),
            "seal": fx_oc["bundle"]["grants"][0]["payload"]["revocation"]["seal"],
        },
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "H-2: evaluate_single_use_seal on node_reachable=False MUST fail closed with CHAIN_UNHEALTHY.",
    )
    ch_st_0b = copy.deepcopy(fx_oc["chain"])
    ch_st_0b["names"]["id/alice"]["updates"].append(
        _make_0x0b_update(
            "id/alice",
            ch_st_0b["names"]["id/alice"]["updates"][-1],
            fx_oc["_alice_reg"],
            fx_oc["_alice_owner_pol"],
            "grant",
            {"m": 1, "pks": [fx_oc["_keys"]["alice_gr"]["xonly"]]},
            {"link": {"grant": fx_oc["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_oc["_alice_man"]), "s": 1}},
            h_c=749900,
            h_update=749905,
            label="d10-st-0b",
        )
    )
    add(
        "d10-m1-statement-0x0b-compromised-refuse",
        ["SL-CONT-009"],
        "statement",
        {"chain": ch_st_0b, "statement": st_h2},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "M-1: verify_statement signed by a 0x0b-compromised link.grant key MUST refuse CRED_ISSUER_CLOSED.",
    )

    # H-3 / F3 / L-8: SLNK OP_RETURN framing & criticality in name history
    def _name_hist_with_opret(opret_hex: str, label: str, h_u: int = 749010) -> dict[str, Any]:
        ch_x = copy.deepcopy(base_ch)
        prev_u = ch_x["names"]["id/alice"]["updates"][-1]
        ospk, _ = sl.compile_script_policy(fx_bs["_alice_owner_pol"])
        ch_x["names"]["id/alice"]["updates"].append({
            "block_time": 1795215010,
            "confirmed_height": h_u,
            "op": "NAME_UPDATE",
            "opreturn_hex": opret_hex,
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", ospk, name=b"id/alice", value=sl.jcs_encode({"link": {"grant": fx_bs["_keys"]["alice_gr"]["xonly"]}})).hex(),
            "owner_policy": fx_bs["_alice_owner_pol"],
            "prev_input": {"sighash_bytes": [1], "txid": prev_u["txid"], "vout": prev_u["vout"], "witness_policy": fx_bs["_alice_owner_pol"]},
            "txid": _h32(f"nh-{label}"),
            "vout": 0,
        })
        return ch_x

    valid_34b_payload = b"\x01" + bytes.fromhex(_h32("slnk-comm")) + b"\x00"
    for case_id, opret_hex, want_v, want_c, desc in [
        ("d10-h3-name-history-0x06-frame-invalid", _raw_slnk_frame(0x06, valid_34b_payload), "REFUSE", "CHAIN_FRAME_INVALID", "H-3: Reserved action 0x06 in name history MUST refuse CHAIN_FRAME_INVALID."),
        ("d10-h3-name-history-malformed-0x0b-frame-invalid", _raw_slnk_frame(0x0B, b"\x01" + b"\x00" * 10), "REFUSE", "CHAIN_FRAME_INVALID", "H-3: Truncated/malformed 0x0b in name history MUST refuse CHAIN_FRAME_INVALID."),
        ("d10-h3-name-history-bad-loc-type-frame-invalid", _raw_slnk_frame(0x07, b"\x01" + bytes.fromhex(_h32("c07")) + b"\x09"), "REFUSE", "CHAIN_FRAME_INVALID", "H-3: Invalid loc_type in name history SLNK frame MUST refuse CHAIN_FRAME_INVALID."),
        ("d10-l8-name-history-0x0b-hc-gt-inclusion-height-frame-invalid", sl.encode_opreturn(0x0B, _h32("cb-fut"), h_c=749011).hex(), "REFUSE", "CHAIN_FRAME_INVALID", "L-8: 0x0b with h_c > inclusion_height MUST refuse CHAIN_FRAME_INVALID."),
        ("d10-f3-name-history-0x13-critical-reserved-incomplete", _raw_slnk_frame(0x13, valid_34b_payload), "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "F3/H-3: Unresolved 0x13 VOLUNTARY_REBIND in name history MUST fail closed ORIGIN_STATUS_INCOMPLETE without origin_bundle."),
        ("d10-f3-name-history-0x15-critical-reserved-incomplete", _raw_slnk_frame(0x15, valid_34b_payload), "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "F3/H-3: Critical reserved 0x15 in name history MUST fail closed ORIGIN_STATUS_INCOMPLETE on v1.0 readers."),
        ("d10-f3-name-history-0x20-advisory-ignorable-admit", _raw_slnk_frame(0x20, valid_34b_payload), "ADMIT", None, "F3/H-3: Well-formed advisory 0x20 in name history MUST be safely ignored by v1.0 readers (ADMIT)."),
        ("d10-f3-name-history-0x20-malformed-frame-invalid", _raw_slnk_frame(0x20, b"\x01" + b"\x00" * 16), "REFUSE", "CHAIN_FRAME_INVALID", "F3/H-3: Malformed advisory 0x20 in name history MUST refuse CHAIN_FRAME_INVALID."),
    ]:
        add(
            case_id,
            ["SL-LDGR-010", "SL-IDTY-001"],
            "name_resolve",
            {"chain": _name_hist_with_opret(opret_hex, case_id), "name": "id/alice"},
            want_v,
            want_c,
            desc,
        )

    # L-8 / F3: opreturns[] list with exactly 1 zero-value advisory SLNK (ADMIT, kills len > 1 boundary) vs 2 SLNK frames (CHAIN_FRAME_INVALID)!
    def _name_hist_with_opreturns_list(opreturns: list[dict[str, Any]], label: str) -> dict[str, Any]:
        ch_x = copy.deepcopy(base_ch)
        prev_u = ch_x["names"]["id/alice"]["updates"][-1]
        ospk, _ = sl.compile_script_policy(fx_bs["_alice_owner_pol"])
        ch_x["names"]["id/alice"]["updates"].append({
            "block_time": 1795215010,
            "confirmed_height": 749010,
            "op": "NAME_UPDATE",
            "opreturns": opreturns,
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", ospk, name=b"id/alice", value=sl.jcs_encode({"link": {"grant": fx_bs["_keys"]["alice_gr"]["xonly"]}})).hex(),
            "owner_policy": fx_bs["_alice_owner_pol"],
            "prev_input": {"sighash_bytes": [1], "txid": prev_u["txid"], "vout": prev_u["vout"], "witness_policy": fx_bs["_alice_owner_pol"]},
            "txid": _h32(f"nh-list-{label}"),
            "vout": 0,
        })
        return ch_x

    add(
        "d10-f3-name-history-opreturns-single-advisory-0x20-admit",
        ["SL-LDGR-010", "SL-IDTY-001"],
        "name_resolve",
        {
            "chain": _name_hist_with_opreturns_list(
                [{"script_pubkey_hex": _raw_slnk_frame(0x20, valid_34b_payload), "value_sat": 0}],
                "single-0x20",
            ),
            "name": "id/alice",
        },
        "ADMIT",
        None,
        "F3/L-8: Structured opreturns[] with exactly 1 zero-value well-formed advisory 0x20 SLNK frame MUST admit.",
    )
    add(
        "d10-l8-name-history-opreturns-two-slnk-frame-invalid",
        ["SL-LDGR-010", "SL-IDTY-001"],
        "name_resolve",
        {
            "chain": _name_hist_with_opreturns_list(
                [
                    {"script_pubkey_hex": _raw_slnk_frame(0x20, valid_34b_payload), "value_sat": 0},
                    {"script_pubkey_hex": _raw_slnk_frame(0x21, valid_34b_payload), "value_sat": 0},
                ],
                "two-slnk",
            ),
            "name": "id/alice",
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "L-8: Structured opreturns[] carrying > 1 SLNK OP_RETURN frame MUST refuse CHAIN_FRAME_INVALID.",
    )

    # =========================================================================
    # 4. H-4 / D9-B1 / M-1: Authenticate before policy-scoped NAME_ROLE_CHANGED + two-anchor 0x09 + notary 0x0b
    # =========================================================================
    fx_h4 = rm._base_invocation_fixture()
    al_k_init = _kp("d10-h4-al-init")
    al_k_old = fx_h4["_keys"]["alice_gr"]
    al_k_new = _kp("d10-h4-al-new")
    # 3-step update history: init key at 748000 -> al_k_old at EXACT 749900 (== rb_old_h!) -> al_k_new at 749998!
    al_ospk_h4, _ = sl.compile_script_policy(fx_h4["_alice_owner_pol"])
    fx_h4["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_h4["_alice_reg"],
        fx_h4["_alice_owner_pol"],
        {"link": {"grant": al_k_init["xonly"]}, "m": {"h": sl.content_addr(fx_h4["_alice_man"]), "s": 1}},
        first_height=748000,
        update_height=749000,
    )
    al_u0_h4 = fx_h4["chain"]["names"]["id/alice"]["updates"][-1]
    u_pol_a_h4 = {
        "block_time": 1795219000,
        "confirmed_height": 749900,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", al_ospk_h4, name=b"id/alice", value=sl.jcs_encode({"link": {"grant": al_k_old["xonly"]}, "m": {"h": sl.content_addr(fx_h4["_alice_man"]), "s": 1}})).hex(),
        "owner_policy": fx_h4["_alice_owner_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": al_u0_h4["txid"], "vout": al_u0_h4["vout"], "witness_policy": fx_h4["_alice_owner_pol"]},
        "txid": _h32("d10-h4-pol-a"),
        "vout": 0,
    }
    fx_h4["chain"]["names"]["id/alice"]["updates"].append(u_pol_a_h4)
    fx_h4["chain"]["names"]["id/alice"]["updates"].append({
        "block_time": 1795219900,
        "confirmed_height": 749998,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", al_ospk_h4, name=b"id/alice", value=sl.jcs_encode({"link": {"grant": al_k_new["xonly"]}, "m": {"h": sl.content_addr(fx_h4["_alice_man"]), "s": 1}})).hex(),
        "owner_policy": fx_h4["_alice_owner_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": u_pol_a_h4["txid"], "vout": 0, "witness_policy": fx_h4["_alice_owner_pol"]},
        "txid": _h32("d10-h4-rot"),
        "vout": 0,
    })
    # Register recent_block hashes in chain.blocks for H-4 grants!
    rb_old_h, rb_new_h = _h32("rb-749900"), _h32("rb-749999")
    fx_h4["chain"]["blocks"][rb_old_h] = 749900
    fx_h4["chain"]["blocks"][rb_new_h] = 749999
    # Grant 1: FORGED signature (random attacker key) with old recent_block=749900 -> MUST refuse WIRE_SIGNATURE with 0 closures!
    gp_forged = copy.deepcopy(fx_h4["bundle"]["grants"][0]["payload"])
    gp_forged["recent_block"] = rb_old_h
    g_forged = sl.sign_envelope(gp_forged, [_kp("d10-h4-attacker")["sk"]])
    gid_forged = sl.object_id(gp_forged)
    itx_forged = _h32("d10-h4-itx-forged")
    fx_h4["chain"]["txs"][itx_forged] = {
        "confirmed_height": 749999,
        "inputs": [sv.make_segwit_input(gp_forged["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_forged), "grant_id": gid_forged, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_forged = sl.sign_envelope({**fx_h4["invocation"]["payload"], "nonce": _h32("d10-h4-n1"), "proof_path": [{"grant_id": gid_forged, "issuance_txid": itx_forged}]}, [fx_h4["_keys"]["agent_req"]["sk"]])

    # Grant 2: AUTHENTIC old grant signed by retired al_k_old with recent_block=749900 -> refuses NAME_ROLE_CHANGED writing 1 policy-scoped closure!
    gp_old = copy.deepcopy(gp_forged)
    gp_old["not_before_height"] = 749899
    g_old = sl.sign_envelope(gp_old, [al_k_old["sk"]])
    gid_old = sl.object_id(gp_old)
    itx_old = _h32("d10-h4-itx-old")
    fx_h4["chain"]["txs"][itx_old] = {
        "confirmed_height": 749999,
        "inputs": [sv.make_segwit_input(gp_old["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_old), "grant_id": gid_old, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_old = sl.sign_envelope({**fx_h4["invocation"]["payload"], "nonce": _h32("d10-h4-n2"), "proof_path": [{"grant_id": gid_old, "issuance_txid": itx_old}]}, [fx_h4["_keys"]["agent_req"]["sk"]])

    # Grant 3: AUTHENTIC NEW grant signed by successor al_k_new with recent_block=749999 -> MUST ADMIT in SAME journal & after restart!
    gp_new = copy.deepcopy(fx_h4["bundle"]["grants"][0]["payload"])
    gp_new["issuer"]["role_policy"] = {"m": 1, "pks": [al_k_new["xonly"]]}
    gp_new["recent_block"] = rb_new_h
    g_new = sl.sign_envelope(gp_new, [al_k_new["sk"]])
    gid_new = sl.object_id(gp_new)
    itx_new = _h32("d10-h4-itx-new")
    fx_h4["chain"]["txs"][itx_new] = {
        "confirmed_height": 750000,
        "inputs": [sv.make_segwit_input(gp_new["revocation"]["seal"]["txid"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_new), "grant_id": gid_new, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    inv_new_1 = sl.sign_envelope({**fx_h4["invocation"]["payload"], "nonce": _h32("d10-h4-n3"), "proof_path": [{"grant_id": gid_new, "issuance_txid": itx_new}]}, [fx_h4["_keys"]["agent_req"]["sk"]])
    inv_new_2 = sl.sign_envelope({**fx_h4["invocation"]["payload"], "nonce": _h32("d10-h4-n4"), "proof_path": [{"grant_id": gid_new, "issuance_txid": itx_new}]}, [fx_h4["_keys"]["agent_req"]["sk"]])
    add(
        "d10-h4-auth-before-close-and-policy-scoped-successor-survival",
        ["SL-GRNT-003", "SL-CONT-009"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("d10-h4-j")},
            "steps": [
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": {**fx_h4["bundle"], "grants": [g_forged]}, "chain": fx_h4["chain"], "executor_cfg": fx_h4["executor_cfg"], "expect_closures_delta": 0, "expect_entries_delta": 0, "invocation": inv_forged, "kind": "invocation", "label": "forged-zero-closures", "want_refusal": "WIRE_SIGNATURE", "want_verdict": "REFUSE"},
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": {**fx_h4["bundle"], "grants": [g_old]}, "chain": fx_h4["chain"], "executor_cfg": fx_h4["executor_cfg"], "expect_closures_delta": 1, "invocation": inv_old, "kind": "invocation", "label": "authentic-old-closes-policy-a", "want_refusal": "NAME_ROLE_CHANGED", "want_verdict": "REFUSE"},
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": {**fx_h4["bundle"], "grants": [g_old]}, "chain": fx_h4["chain"], "executor_cfg": fx_h4["executor_cfg"], "expect_closures_delta": 0, "expect_entries_delta": 0, "invocation": inv_old, "kind": "invocation", "label": "repeat-old-hits-persisted-closure", "want_refusal": "NAME_ROLE_CHANGED", "want_verdict": "REFUSE"},
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": {**fx_h4["bundle"], "grants": [g_new]}, "chain": fx_h4["chain"], "executor_cfg": fx_h4["executor_cfg"], "expect_closures_delta": 0, "invocation": inv_new_1, "kind": "invocation", "label": "successor-b-admits-same-journal", "want_refusal": None, "want_verdict": "ADMIT"},
                {"kind": "replay_restart", "label": "restart"},
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": {**fx_h4["bundle"], "grants": [g_new]}, "chain": fx_h4["chain"], "executor_cfg": fx_h4["executor_cfg"], "expect_closures_delta": 0, "invocation": inv_new_2, "kind": "invocation", "label": "successor-b-admits-after-restart", "want_refusal": None, "want_verdict": "ADMIT"},
            ],
        },
        "ADMIT",
        None,
        "H-4/D9-B1: Forged grant with old recent_block writes 0 closures (WIRE_SIGNATURE); authentic retired grant writes policy-scoped closure for key A; successor key B admits in same journal and after restart.",
    )
    # H-4: Issuer name value that lacks link.grant entirely -> NAME_ROLE_CHANGED (not WIRE_SIGNATURE)!
    fx_nolg = rm._base_invocation_fixture()
    fx_nolg["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_nolg["_alice_reg"],
        fx_nolg["_alice_owner_pol"],
        {"m": {"h": sl.content_addr(fx_nolg["_alice_man"]), "s": 1}},
        first_height=748000,
        update_height=749000,
    )
    add(
        "d10-h4-grant-issuer-lacks-link-grant-role-changed",
        ["SL-GRNT-003", "SL-IDTY-001"],
        "invocation",
        {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_nolg["bundle"], "chain": fx_nolg["chain"], "executor_cfg": fx_nolg["executor_cfg"], "invocation": fx_nolg["invocation"], "journal": {"journal_id": _h32("d10-nolg-j")}},
        "REFUSE",
        "NAME_ROLE_CHANGED",
        "H-4: Root grant whose issuer name carries no link.grant entry at all MUST refuse NAME_ROLE_CHANGED.",
    )

    # M-1: Two-anchor 0x09 credential (h_late >= h_c -> CRED_ISSUER_CLOSED +1 closure; repeat -> 0 dup closures; h_early < h_c -> ADMIT!)
    of_m1 = rm._base_origin_fixture()
    reg_rec = of_m1["chain"]["names"]["id/civil-registry"]
    reg_prev = reg_rec["updates"][-1]
    reg_opol = reg_prev["owner_policy"]
    reg_old_pk = of_m1["_keys"]["reg_cred"]["xonly"]
    reg_new_k = _kp("d10-m1-reg-succ")
    reg_rec["updates"].append(
        _make_0x0b_update(
            "id/civil-registry",
            reg_prev,
            reg_rec["registration"],
            reg_opol,
            "cred",
            {"m": 1, "pks": [reg_old_pk]},
            {"link": {"cred": reg_new_k["xonly"]}},
            h_c=749500,
            h_update=749505,
            label="d10-m1-reg",
        )
    )
    cr_m1 = sl.sign_envelope(
        {
            "claims": {"diploma": "BSc"},
            "credential_kind": "education/degree-v1",
            "genesis": GENESIS_MAIN,
            "issued_at": 1795210000,
            "issuer": of_m1["origin_bundle"]["origin"]["payload"]["issuer"],
            "lifecycle": "eternal",
            "network": "main",
            "not_before_height": 749000,
            "subject": {"mode": "origin", "origin_id": of_m1["_origin_id"]},
            "type": "seallink-credential/1",
        },
        [of_m1["_keys"]["reg_cred"]["sk"]],
    )
    anc_late, anc_early = _h32("d10-m1-late"), _h32("d10-m1-early")
    of_m1["chain"]["txs"][anc_late] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_m1)).hex(), "outputs": {}}
    of_m1["chain"]["txs"][anc_early] = {"confirmed_height": 749499, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cr_m1)).hex(), "outputs": {}}
    ch_m1_no_0b = copy.deepcopy(of_m1["chain"])
    ch_m1_no_0b["names"]["id/civil-registry"]["updates"].pop()
    add(
        "d10-m1-two-anchor-cred-cutoff-scoped-and-idempotent-closure",
        ["SL-CONT-009", "SL-CONT-010"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("d10-m1-j")},
            "steps": [
                {"anchor_txid": anc_late, "chain": of_m1["chain"], "credential": cr_m1, "expect_closures_delta": 1, "kind": "credential", "label": "late-at-hc", "origin_bundle": of_m1["origin_bundle"], "want_refusal": "CRED_ISSUER_CLOSED", "want_verdict": "REFUSE"},
                {"anchor_txid": anc_late, "chain": ch_m1_no_0b, "credential": cr_m1, "expect_closures_delta": 0, "expect_entries_delta": 0, "kind": "credential", "label": "repeat-late-persisted-no-0x0b", "origin_bundle": of_m1["origin_bundle"], "want_refusal": "CRED_ISSUER_CLOSED", "want_verdict": "REFUSE"},
                {"anchor_txid": anc_early, "chain": of_m1["chain"], "credential": cr_m1, "expect_closures_delta": 0, "kind": "credential", "label": "early-before-hc-survives", "origin_bundle": of_m1["origin_bundle"], "want_refusal": None, "want_verdict": "ADMIT"},
            ],
            "trusted_origin_issuer_pins": of_m1["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "M-1: Cutoff-scoped role closure blocks h_late==h_c persistently (even if 0x0b absent from chain view, 0 dup writes) while allowing earlier anchor h_early=h_c-1 of same credential in same journal.",
    )

    # M-1: Live grant 0x0b break at EXACT tip_height == h_c -> CRED_ISSUER_CLOSED + persisted role closure (blocks repeat even without 0x0b on chain)!
    fx_g0b = rm._base_invocation_fixture()
    ch_g0b_live = copy.deepcopy(fx_g0b["chain"])
    ch_g0b_live["names"]["id/alice"]["updates"].append(
        _make_0x0b_update(
            "id/alice",
            ch_g0b_live["names"]["id/alice"]["updates"][-1],
            fx_g0b["_alice_reg"],
            fx_g0b["_alice_owner_pol"],
            "grant",
            {"m": 1, "pks": [fx_g0b["_keys"]["alice_gr"]["xonly"]]},
            {"link": {"grant": fx_g0b["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_g0b["_alice_man"]), "s": 1}},
            h_c=fx_g0b["chain"]["tip_height"],
            h_update=fx_g0b["chain"]["tip_height"],
            label="d10-g0b-exact",
        )
    )
    add(
        "d10-m1-grant-0x0b-exact-hc-live-and-persisted-refuse",
        ["SL-CONT-009", "SL-GRNT-003"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("d10-g0b-j")},
            "steps": [
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_g0b["bundle"], "chain": ch_g0b_live, "executor_cfg": fx_g0b["executor_cfg"], "expect_closures_delta": 1, "invocation": fx_g0b["invocation"], "kind": "invocation", "label": "live-grant-0x0b-at-exact-hc", "want_refusal": "CRED_ISSUER_CLOSED", "want_verdict": "REFUSE"},
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_g0b["bundle"], "chain": fx_g0b["chain"], "executor_cfg": fx_g0b["executor_cfg"], "expect_closures_delta": 0, "expect_entries_delta": 0, "invocation": fx_g0b["invocation"], "kind": "invocation", "label": "persisted-grant-0x0b-at-exact-hc", "want_refusal": "CRED_ISSUER_CLOSED", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "M-1: Root grant issuer 0x0b break at exact tip_height==h_c refuses CRED_ISSUER_CLOSED and persists role closure blocking repeat invocation even without 0x0b on chain.",
    )

    # M-1: Notary role 0x0b break exact h_c-1 admit vs h_c refuse
    fx_not = rm._base_invocation_fixture()
    nk_old, nk_new, n_own = _kp("d10-not-old"), _kp("d10-not-new"), _kp("d10-not-own")
    n_pol = {"kind": "key", "pk": n_own["comp"]}
    n_reg = {"txid": _h32("d10-not-reg"), "vout": 0}
    n_pin = {"name": "id/notary-x", "owner_policy": n_pol, "registration": n_reg}
    fx_not["chain"]["names"]["id/notary-x"] = sv.make_name_history("id/notary-x", n_reg, n_pol, {"link": {"notary": nk_old["xonly"]}}, first_height=748000, update_height=749000)
    fx_not["chain"]["names"]["id/notary-x"]["updates"].append(
        _make_0x0b_update("id/notary-x", fx_not["chain"]["names"]["id/notary-x"]["updates"][-1], n_reg, n_pol, "notary", {"m": 1, "pks": [nk_old["xonly"]]}, {"link": {"notary": nk_new["xonly"]}}, h_c=749500, h_update=749505, label="d10-not")
    )
    na_env = sl.sign_envelope(
        {
            "act_kind": "fact-attestation",
            "attested_at": 1795210000,
            "details": {"fact_schema": "seallink/example", "fact_sha256": _h32("d10-not-fact"), "kind": "fact-attestation"},
            "genesis": GENESIS_MAIN,
            "lifecycle": "eternal",
            "network": "main",
            "notary": {**n_pin, "role_policy": {"m": 1, "pks": [nk_old["xonly"]]}},
            "target_sha256": _h32("d10-not-sub"),
            "tip_hash": fx_not["chain"]["tip_hash"],
            "tip_height": 749499,
            "type": "seallink-notary/1",
        },
        [nk_old["sk"]],
    )
    na_ok_tx, na_bad_tx = _h32("d10-na-ok"), _h32("d10-na-bad")
    fx_not["chain"]["txs"][na_ok_tx] = {"confirmed_height": 749499, "opreturn_hex": sl.encode_opreturn(0x04, sl.content_addr(na_env)).hex(), "outputs": {}}
    fx_not["chain"]["txs"][na_bad_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x04, sl.content_addr(na_env)).hex(), "outputs": {}}
    add("d10-m1-notary-0x0b-before-hc-admit", ["SL-CONT-009"], "notary_act", {"anchor_txid": na_ok_tx, "chain": fx_not["chain"], "notary": na_env}, "ADMIT", None, "M-1: Notary act anchored at h_c-1 survives 0x0b role='notary' break.")
    add("d10-m1-notary-0x0b-at-hc-refuse", ["SL-CONT-009"], "notary_act", {"anchor_txid": na_bad_tx, "chain": fx_not["chain"], "notary": na_env}, "REFUSE", "CRED_ISSUER_CLOSED", "M-1: Notary act anchored at h_c refuses CRED_ISSUER_CLOSED under 0x0b role='notary' break.")

    # =========================================================================
    # 5. H-5 / H-6 / M-6 / M-7 / M-8 / M-9 / A-17: Origin, Guardianship, Emancipation & NamePin
    # =========================================================================
    def _setup_rec(of_base: dict[str, Any], h_rec: int, k_pol: dict[str, Any], label: str, name_new: str = "id/child-leo-rec") -> tuple[dict[str, Any], str, dict[str, Any]]:
        of_x = copy.deepcopy(of_base)
        b1 = of_x["origin_bundle"]["name_binding"]
        new_reg = {"txid": _h32(f"d10-rec-reg-{label}"), "vout": 0}
        rec_pol = of_x["_rec_pol"]
        b2 = {
            "binding_mode": "recovery",
            "genesis": GENESIS_MAIN,
            "name": name_new,
            "network": "main",
            "next_recovery_policy": rec_pol,
            "next_recovery_vout": 0,
            "origin_id": of_x["_origin_id"],
            "owner_policy": k_pol,
            "registration": new_reg,
            "seq": 2,
            "supersedes_binding_id": sl.object_id(b1),
            "type": "seallink-name-binding/1",
        }
        rtx = _h32(f"d10-rec-tx-{label}")
        rs_op = of_x["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]
        of_x["chain"]["txs"][rs_op["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx
        of_x["chain"]["txs"][rtx] = {
            "confirmed_height": h_rec,
            "inputs": [sv.make_segwit_input(rs_op["txid"], rs_op["vout"])],
            "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(b2)).hex(),
            "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_pol)}},
        }
        of_x["origin_bundle"]["recovery_bindings"] = [b2]
        of_x["chain"]["names"][name_new] = sv.make_name_history(name_new, new_reg, k_pol, {"link": {"origin": of_x["_origin_id"]}}, first_height=h_rec - 10, update_height=h_rec + 2)
        return of_x, rtx, b2

    # H-5: Childhood 0x0c promoted BEFORE opened_majority MUST stay GUARDIAN_TRANSFER_PENDING after T!
    of_h5_pre, _, _ = _setup_rec(rm._base_origin_fixture(), 749500, {"kind": "key", "pk": _kp("d10-h5-child-rec")["comp"]}, "h5-pre")
    maj_t = of_h5_pre["origin_bundle"]["opened_majority_unix"]
    of_h5_pre["chain"]["block_times"] = {str(749500 + 144): maj_t - 3600}  # promoted 1h BEFORE T!
    of_h5_pre["chain"]["credible_utc_interval"] = [maj_t + 600, maj_t + 660]
    of_h5_pre["chain"]["tip_median_time_past"] = maj_t + 600
    add(
        "d10-h5-childhood-0x0c-before-majority-no-auto-emancipation",
        ["SL-ORIG-011", "SL-ORIG-014"],
        "origin_status",
        {"chain": of_h5_pre["chain"], "origin_bundle": of_h5_pre["origin_bundle"], "trusted_origin_issuer_pins": of_h5_pre["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_TRANSFER_PENDING",
        "H-5: Childhood 0x0c promoted before majority T MUST NOT auto-emancipate at T (stays GUARDIAN_TRANSFER_PENDING).",
    )

    # H-5: Post-majority 0x0c promoted at EXACT block_time == T to disjoint K_adult (+ b1 update at EXACT block_time == T) -> ADMIT_AUTONOMOUS!
    k_h5_adult = {"kind": "key", "pk": _kp("d10-h5-adult-k")["comp"]}
    of_h5_post, _, _ = _setup_rec(rm._base_origin_fixture(), 749600, k_h5_adult, "h5-post")
    of_h5_post["chain"]["block_times"] = {str(749600 + 144): maj_t}  # EXACT promo_time == opened_majority!
    of_h5_post["chain"]["credible_utc_interval"] = [maj_t + 600, maj_t + 660]
    of_h5_post["chain"]["tip_median_time_past"] = maj_t + 600
    # Also record an update on b1 (id/child-leo) at EXACT block_time == maj_t using k_h5_adult:
    # before_maj MUST be False (bu_bt < opened_majority), so k_h5_adult MUST NOT be tainted into pre_trigger_pks!
    b1_h5_u = of_h5_post["chain"]["names"]["id/child-leo"]["updates"]
    b1_h5_prev = b1_h5_u[-1]
    b1_h5_u.append({
        "block_time": maj_t,
        "confirmed_height": 749744,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", sl.compile_script_policy(k_h5_adult)[0], name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_h5_post["_origin_id"]}})).hex(),
        "owner_policy": k_h5_adult,
        "prev_input": {"sighash_bytes": [1], "txid": b1_h5_prev["txid"], "vout": b1_h5_prev["vout"], "witness_policy": b1_h5_prev["owner_policy"]},
        "txid": _h32("d10-h5-b1-at-exact-maj"),
        "vout": 0,
    })
    add(
        "d10-h5-post-majority-0x0c-handover-admits-autonomous",
        ["SL-ORIG-011", "SL-ORIG-014"],
        "origin_status",
        {"chain": of_h5_post["chain"], "origin_bundle": of_h5_post["origin_bundle"], "trusted_origin_issuer_pins": of_h5_post["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "H-5: Post-majority 0x0c promoted at exact block_time == T to disjoint adult owner_policy with self-update advances to ADMIT_AUTONOMOUS.",
    )

    # M-9: Case-2 capacity handover at EXACT confirmed_height == h_cap (before majority T) admits ADMIT_AUTONOMOUS!
    of_cap_eq = rm._base_origin_fixture()
    maj_cap_eq = of_cap_eq["origin_bundle"]["opened_majority_unix"]
    subj_cap_pol = {"kind": "key", "pk": _kp("d10-m9-cap-eq-subj")["comp"]}
    subj_cap_spk, _ = sl.compile_script_policy(subj_cap_pol)
    h_cap_eq = 749600
    cap_eq_p = {
        "basis_sha256": _h32("d10-cap-eq-basis"),
        "genesis": GENESIS_MAIN,
        "issued_at": of_cap_eq["chain"]["now"] - 500,
        "issuer": of_cap_eq["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "next_status_policy": of_cap_eq["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"],
        "next_status_vout": 0,
        "origin_id": of_cap_eq["_origin_id"],
        "status_prev_outpoint": {
            "txid": of_cap_eq["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"],
            "vout": of_cap_eq["origin_bundle"]["origin"]["payload"]["status_seal"]["vout"],
        },
        "subject_new_owner_policy": subj_cap_pol,
        "type": "seallink-capacity/1",
    }
    cap_eq_env = sl.sign_envelope(cap_eq_p, [of_cap_eq["_keys"]["reg_cred"]["sk"]])
    cap_eq_tx = _h32("d10-cap-eq-tx")
    ss_op_eq = of_cap_eq["origin_bundle"]["origin"]["payload"]["status_seal"]
    of_cap_eq["chain"]["txs"][ss_op_eq["txid"]]["outputs"]["0"]["spent_by_txid"] = cap_eq_tx
    of_cap_eq["chain"]["txs"][cap_eq_tx] = {
        "confirmed_height": h_cap_eq,
        "inputs": [sv.make_segwit_input(ss_op_eq["txid"], ss_op_eq["vout"])],
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_eq_env)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(cap_eq_p["next_status_policy"])}},
    }
    of_cap_eq["origin_bundle"]["capacity_record"] = cap_eq_env
    # Transfer at EXACT confirmed_height == h_cap_eq (with block_time < opened_majority!) + self-update at h_cap_eq + 1
    ce_u = of_cap_eq["chain"]["names"]["id/child-leo"]["updates"]
    ce_prev = ce_u[-1]
    u_ce_xfer = {
        "block_time": maj_cap_eq - 200,
        "confirmed_height": h_cap_eq,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", subj_cap_spk, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_cap_eq["_origin_id"]}})).hex(),
        "owner_policy": subj_cap_pol,
        "prev_input": {"sighash_bytes": [1], "txid": ce_prev["txid"], "vout": ce_prev["vout"], "witness_policy": ce_prev["owner_policy"]},
        "txid": _h32("d10-ce-xfer"),
        "vout": 0,
    }
    u_ce_self = {
        "block_time": maj_cap_eq - 100,
        "confirmed_height": h_cap_eq + 1,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", subj_cap_spk, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_cap_eq["_origin_id"]}})).hex(),
        "owner_policy": subj_cap_pol,
        "prev_input": {"sighash_bytes": [1], "txid": u_ce_xfer["txid"], "vout": 0, "witness_policy": subj_cap_pol},
        "txid": _h32("d10-ce-self"),
        "vout": 0,
    }
    ce_u.extend([u_ce_xfer, u_ce_self])
    add(
        "d10-m9-emancipation-same-block-capacity-handover-admit",
        ["SL-ORIG-011"],
        "origin_status",
        {"chain": of_cap_eq["chain"], "origin_bundle": of_cap_eq["origin_bundle"], "trusted_origin_issuer_pins": of_cap_eq["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "M-9: Capacity handover transfer confirmed at exact confirmed_height == h_cap (before majority T) followed by subject self-update advances to ADMIT_AUTONOMOUS.",
    )

    # H-6: Rotated former guardian W1 -> W2 BEFORE T is STILL locked out from 0x10 in State 3!
    of_h6_rot, _, b2_h6 = _setup_rec(rm._base_origin_fixture(), 749600, {"kind": "key", "pk": _kp("d10-h6-adult-k")["comp"]}, "h6-rot")
    maj_h6 = of_h6_rot["origin_bundle"]["opened_majority_unix"]
    of_h6_rot["chain"]["block_times"] = {str(749600 + 144): maj_h6 + 100}
    of_h6_rot["chain"]["credible_utc_interval"] = [maj_h6 + 600, maj_h6 + 660]
    of_h6_rot["chain"]["tip_median_time_past"] = maj_h6 + 600
    w2_pol = {"kind": "key", "pk": _kp("d10-h6-guardian-w2")["comp"]}
    w2_spk, _ = sl.compile_script_policy(w2_pol)
    b1_u = of_h6_rot["chain"]["names"]["id/child-leo"]["updates"]
    prev_w1 = b1_u[-1]
    # Guardian rotates W1 -> W2 at height 749500 (BEFORE T!)
    u_rot = {
        "block_time": maj_h6 - 1000,
        "confirmed_height": 749500,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", w2_spk, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_h6_rot["_origin_id"]}})).hex(),
        "owner_policy": w2_pol,
        "prev_input": {"sighash_bytes": [1], "txid": prev_w1["txid"], "vout": prev_w1["vout"], "witness_policy": prev_w1["owner_policy"]},
        "txid": _h32("d10-h6-w1-to-w2"),
        "vout": 0,
    }
    # Guardian tries 0x10 using W2 at height 749610 (AFTER T, State 3!) -> MUST STILL BE LOCKED OUT!
    u_cancel = {
        "block_time": maj_h6 + 50,
        "confirmed_height": 749610,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, sl.object_id(b2_h6)).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", w2_spk, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": of_h6_rot["_origin_id"]}})).hex(),
        "owner_policy": w2_pol,
        "prev_input": {"sighash_bytes": [1], "txid": u_rot["txid"], "vout": 0, "witness_policy": w2_pol},
        "txid": _h32("d10-h6-w2-0x10"),
        "vout": 0,
    }
    b1_u.extend([u_rot, u_cancel])
    add(
        "d10-h6-rotated-former-guardian-w1-to-w2-still-locked-out-0x10",
        ["SL-ORIG-011", "SL-ORIG-014"],
        "origin_status",
        {"chain": of_h6_rot["chain"], "expect_recovery_outcome": "promoted", "origin_bundle": of_h6_rot["origin_bundle"], "trusted_origin_issuer_pins": of_h6_rot["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "H-6: Rotating guardian key W1->W2 before majority T MUST NOT bypass State-3 0x10 lockout; adult 0x0c promotes to ADMIT_AUTONOMOUS.",
    )

    # H-6 positive: State-4 adult (already emancipated!) CAN cancel a subsequent rogue 0x0c via 0x10!
    of_h6_s4 = copy.deepcopy(of_h5_post)
    b2_adult = of_h6_s4["origin_bundle"]["recovery_bindings"][0]
    b2_rtx = of_h6_s4["chain"]["txs"][of_h6_s4["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"]
    b3_rogue = {
        "binding_mode": "recovery",
        "genesis": GENESIS_MAIN,
        "name": "id/rogue-takeover",
        "network": "main",
        "next_recovery_policy": of_h6_s4["_rec_pol"],
        "next_recovery_vout": 0,
        "origin_id": of_h6_s4["_origin_id"],
        "owner_policy": {"kind": "key", "pk": _kp("d10-h6-rogue")["comp"]},
        "registration": {"txid": _h32("d10-h6-rogue-reg"), "vout": 0},
        "seq": 3,
        "supersedes_binding_id": sl.object_id(b2_adult),
        "type": "seallink-name-binding/1",
    }
    rtx_rogue = _h32("d10-h6-rogue-0x0c")
    of_h6_s4["chain"]["txs"][b2_rtx]["outputs"]["0"]["spent_by_txid"] = rtx_rogue
    of_h6_s4["chain"]["txs"][rtx_rogue] = {
        "confirmed_height": 749800,
        "inputs": [sv.make_segwit_input(b2_rtx, 0)],
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(b3_rogue)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(of_h6_s4["_rec_pol"])}},
    }
    of_h6_s4["origin_bundle"]["recovery_bindings"].append(b3_rogue)
    ad_u = of_h6_s4["chain"]["names"][b2_adult["name"]]["updates"]
    ad_prev = ad_u[-1]
    ad_pol = ad_prev["owner_policy"]
    ad_spk, _ = sl.compile_script_policy(ad_pol)
    ad_u.append({
        "block_time": maj_t + 300,
        "confirmed_height": 749810,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, sl.object_id(b3_rogue)).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", ad_spk, name=b2_adult["name"].encode("utf-8"), value=sl.jcs_encode({"link": {"origin": of_h6_s4["_origin_id"]}})).hex(),
        "owner_policy": ad_pol,
        "prev_input": {"sighash_bytes": [1], "txid": ad_prev["txid"], "vout": ad_prev["vout"], "witness_policy": ad_pol},
        "txid": _h32("d10-h6-adult-0x10"),
        "vout": 0,
    })
    add(
        "d10-h6-state4-adult-can-cancel-rogue-0x0c",
        ["SL-ORIG-011", "SL-ORIG-014"],
        "origin_status",
        {"assert_binding_id": sl.object_id(b2_adult), "chain": of_h6_s4["chain"], "expect_recovery_outcome": "cancelled_restored", "origin_bundle": of_h6_s4["origin_bundle"], "trusted_origin_issuer_pins": of_h6_s4["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "H-6: Already-emancipated State-4 adult owner CAN cancel a subsequent rogue 0x0c via 0x10 and keep their active binding.",
    )

    # M-9: Post-majority 0x0c targeting owner_policy sharing pubkey with initial_owner_policy stays GUARDIAN_TRANSFER_PENDING!
    of_m9_base = rm._base_origin_fixture()
    guard_pk = of_m9_base["origin_bundle"]["origin"]["payload"]["claims"]["intended_owner_policy"]["pks"][0]
    overlap_pol = {"kind": "multisig", "m": 1, "pks": sorted([guard_pk, _kp("d10-m9-extra")["comp"]])}
    of_m9, _, _ = _setup_rec(of_m9_base, 749600, overlap_pol, "m9-ov", name_new="id/child-leo-ov")
    maj_m9 = of_m9["origin_bundle"]["opened_majority_unix"]
    of_m9["chain"]["block_times"] = {str(749600 + 144): maj_m9 + 10}
    of_m9["chain"]["credible_utc_interval"] = [maj_m9 + 600, maj_m9 + 660]
    of_m9["chain"]["tip_median_time_past"] = maj_m9 + 600
    add(
        "d10-m9-emancipation-0x0c-overlapping-guardian-pubkey-refuse",
        ["SL-ORIG-011"],
        "origin_status",
        {"chain": of_m9["chain"], "origin_bundle": of_m9["origin_bundle"], "trusted_origin_issuer_pins": of_m9["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_TRANSFER_PENDING",
        "M-9: Emancipated owner_policy sharing any pubkey with pre-trigger guardian policy (e.g. 1-of-2 with guardian key) MUST stay GUARDIAN_TRANSFER_PENDING.",
    )

    # M-6 / A-17: Pass-1 GUARDIAN_INACTIVE beats Pass-2 0x0b CRED_ISSUER_CLOSED; live ward grant with 0x0b guardian refuses CRED_ISSUER_CLOSED!
    of_m6 = rm._base_origin_fixture()
    g1_m6_rec = of_m6["chain"]["names"]["id/parent-a"]
    g1_m6_prev = g1_m6_rec["updates"][-1]
    g1_m6_rec["updates"].append(
        _make_0x0b_update(
            "id/parent-a",
            g1_m6_prev,
            g1_m6_rec["registration"],
            g1_m6_prev["owner_policy"],
            "grant",
            {"m": 1, "pks": [of_m6["_keys"]["g1_gr"]["xonly"]]},
            {"link": {"grant": _kp("d10-m6-g1-new")["xonly"]}},
            h_c=749500,
            h_update=749505,
            label="d10-m6-g1",
        )
    )
    # Slot 1 (id/parent-a) is active & 0x0b-compromised (Pass 2), while slot 2 (id/parent-b) is NOT active (Pass 1)!
    wa_m6_both = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": of_m6["_origin_id"], "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000, "network": "main", "nonce": _h32("d10-m6-n"),
            "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
            "target_id": sl.object_id(of_m6["contract"]), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        },
        [
            {"guardian_name": "id/parent-a", "revision": 1, "signers": [of_m6["_keys"]["g1_gr"]["sk"]], "slot": 1},
            {"guardian_name": "id/parent-b", "revision": 1, "signers": [_kp("d10-m6-g2-unact")["sk"]], "slot": 2},
        ],
    )
    add(
        "d10-m6-ward-approvals-pass1-inactive-beats-pass2-0x0b",
        ["SL-ORIG-006", "SL-CONT-009"],
        "assent",
        {"assent": wa_m6_both, "chain": of_m6["chain"], "contract": of_m6["contract"], "origin_bundle": of_m6["origin_bundle"], "trusted_origin_issuer_pins": of_m6["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_INACTIVE",
        "M-6: Pass-1 GUARDIAN_INACTIVE on slot 2 MUST take precedence over Pass-2 0x0b CRED_ISSUER_CLOSED on slot 1.",
    )
    # A-17: Live tip ward assent (1-of-2 quorum, slot 1 active & 0x0b-compromised) -> CRED_ISSUER_CLOSED!
    of_a17 = rm._base_origin_fixture()
    op_a17 = copy.deepcopy(of_a17["origin_bundle"]["origin"]["payload"])
    op_a17["guardian_policy"]["quorums"] = {k: {"den": 2, "min": 1, "num": 1} for k in op_a17["guardian_policy"]["quorums"]}
    o_a17 = sl.sign_envelope(op_a17, [of_a17["_keys"]["reg_cred"]["sk"]])
    oid_a17 = sl.object_id(op_a17)
    of_a17["origin_bundle"]["origin"] = o_a17
    of_a17["origin_bundle"]["name_binding"]["origin_id"] = oid_a17
    rm.sync_ward_origin_link(of_a17, oid_a17)
    g1_a17_p = {**of_a17["origin_bundle"]["guardian_records"][0]["payload"], "origin_id": oid_a17}
    g1_a17 = sl.sign_envelope(g1_a17_p, [of_a17["_keys"]["reg_cred"]["sk"]])
    of_a17["origin_bundle"]["guardian_records"] = [g1_a17]
    of_a17["origin_bundle"]["guardian_assents"] = [sl.sign_envelope({**of_a17["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(g1_a17_p)}, [of_a17["_keys"]["g1_gr"]["sk"]])]
    of_a17["chain"]["txs"][of_a17["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(o_a17)).hex()
    of_a17["chain"]["txs"][of_a17["origin_bundle"]["name_binding_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x0C, sl.object_id(of_a17["origin_bundle"]["name_binding"])).hex()
    of_a17["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(g1_a17)).hex()
    g1_a17_rec = of_a17["chain"]["names"]["id/parent-a"]
    g1_a17_prev = g1_a17_rec["updates"][-1]
    g1_a17_rec["updates"].append(
        _make_0x0b_update(
            "id/parent-a",
            g1_a17_prev,
            g1_a17_rec["registration"],
            g1_a17_prev["owner_policy"],
            "grant",
            {"m": 1, "pks": [of_a17["_keys"]["g1_gr"]["xonly"]]},
            {"link": {"grant": of_a17["_keys"]["g1_gr"]["xonly"]}},
            h_c=749500,
            h_update=749505,
            label="d10-a17-g1",
        )
    )
    c_a17 = copy.deepcopy(of_a17["contract"])
    c_a17["parties"][0]["ward_origin_id"] = oid_a17
    wa_a17 = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": oid_a17, "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000, "network": "main", "nonce": _h32("d10-a17-n"),
            "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
            "target_id": sl.object_id(c_a17), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        },
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_a17["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add(
        "d10-a17-live-ward-assent-0x0b-compromised-refuse",
        ["SL-ORIG-006", "SL-CONT-009"],
        "assent",
        {"assent": wa_a17, "chain": of_a17["chain"], "contract": c_a17, "origin_bundle": of_a17["origin_bundle"], "trusted_origin_issuer_pins": of_a17["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "A-17: Live tip ward approval signed by a 0x0b-compromised guardian link.grant key MUST refuse CRED_ISSUER_CLOSED.",
    )

    # M-8: historical_existence_only=True exact boundary (binding_seal & status_seal confirmed_height == eval_h -> ADMIT) + negative binding_seal, status_seal, & bad name_binding!
    of_m8_ok = rm._base_origin_fixture()
    bs_s_tx = of_m8_ok["origin_bundle"]["origin"]["payload"]["binding_seal"]["txid"]
    st_s_tx = of_m8_ok["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]
    of_m8_ok["chain"]["txs"][bs_s_tx]["confirmed_height"] = 749010
    of_m8_ok["chain"]["txs"][st_s_tx]["confirmed_height"] = 749010
    add(
        "d10-m8-historical-existence-exact-eval-height-seals-admit",
        ["SL-ORIG-002"],
        "origin_status",
        {"at_height": 749010, "chain": of_m8_ok["chain"], "historical_existence_only": True, "origin_bundle": of_m8_ok["origin_bundle"], "trusted_origin_issuer_pins": of_m8_ok["trusted_origin_issuer_pins"]},
        "ADMIT_WARD",
        None,
        "M-8: historical_existence_only=True admits when binding_seal & status_seal are confirmed at exact confirmed_height == eval_h.",
    )
    of_m8_bs = copy.deepcopy(of_m8_ok)
    of_m8_bs["chain"]["txs"][bs_s_tx]["confirmed_height"] = 749050
    add(
        "d10-m8-historical-existence-unconfirmed-binding-seal-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"at_height": 749010, "chain": of_m8_bs["chain"], "historical_existence_only": True, "origin_bundle": of_m8_bs["origin_bundle"], "trusted_origin_issuer_pins": of_m8_bs["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "M-8: historical_existence_only=True MUST refuse ORIGIN_BINDING_INVALID if binding_seal is confirmed after eval_h.",
    )
    of_m8_nb = copy.deepcopy(of_m8_ok)
    of_m8_nb["origin_bundle"]["name_binding"]["name"] = "id/wrong-name"
    add(
        "d10-m8-historical-existence-bad-name-binding-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"at_height": 749010, "chain": of_m8_nb["chain"], "historical_existence_only": True, "origin_bundle": of_m8_nb["origin_bundle"], "trusted_origin_issuer_pins": of_m8_nb["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "M-8: historical_existence_only=True MUST refuse ORIGIN_BINDING_INVALID if optional name_binding mismatches origin intended_name.",
    )
    of_m8 = rm._base_origin_fixture()
    of_m8["chain"]["txs"][st_s_tx]["confirmed_height"] = 749050
    add(
        "d10-m8-historical-existence-unconfirmed-status-seal-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {"at_height": 749010, "chain": of_m8["chain"], "historical_existence_only": True, "origin_bundle": of_m8["origin_bundle"], "trusted_origin_issuer_pins": of_m8["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "M-8: historical_existence_only=True MUST verify confirmed status_seal & binding_seal UTXOs at <= eval_h.",
    )

    # M-7: Concrete mailbox target omitting executor_cfg.pin (and not self_hosted) refuses GRANT_TARGET_UNAUTHORIZED!
    fx_m7 = rm._base_invocation_fixture()
    ecfg_no_pin = {k: v for k, v in fx_m7["executor_cfg"].items() if k != "pin"}
    add(
        "d10-m7-mailbox-missing-executor-pin-refuse",
        ["SL-GRNT-004", "SL-PROF-001"],
        "invocation",
        {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_m7["bundle"], "chain": fx_m7["chain"], "executor_cfg": ecfg_no_pin, "invocation": fx_m7["invocation"], "journal": {"journal_id": _h32("d10-m7-j")}},
        "REFUSE",
        "SERVICE_PROVIDER_UNBOUND",
        "M-7: Concrete mailbox target MUST require structured NamePin in executor_cfg.pin (no bare string fallback).",
    )

    # =========================================================================
    # 6. H-8 / M-2 / M-4 / M-5 / L-9 / L-11 / L-12: Commit precedence, uncertain replay, single_use, golden buckets
    # =========================================================================
    fx_m2 = rm._delegation_fx()
    q_c = {"kind": "seallink/count", "max": "10", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}
    q_b = {"kind": "seallink/bytes", "max": "4096", "resource": "station:id/station-a:tools", "unit": "bytes", "window": "term"}
    p_m2 = copy.deepcopy(fx_m2["bundle"]["grants"][0]["payload"])
    c_m2 = copy.deepcopy(fx_m2["bundle"]["grants"][1]["payload"])
    p_m2["delegate"]["pools"] = [{**q_c, "max": "20"}, {**q_b, "max": "8192"}]
    p_m2["capabilities"][0]["quotas"] = copy.deepcopy(p_m2["delegate"]["pools"])
    p_m2["delegate"]["groups"][0]["template"]["capabilities"][0]["quotas"] = [q_c, q_b]
    p_m2_env = sl.sign_envelope(p_m2, [fx_m2["_keys"]["alice_gr"]["sk"]])
    pid_m2 = sl.object_id(p_m2)
    c_m2["parent"]["grant_id"] = pid_m2
    c_m2["capabilities"][0]["quotas"] = [q_c, q_b]
    c_m2_env = sl.sign_envelope(c_m2, [fx_m2["_del_k"]["sk"]])
    cid_m2 = sl.object_id(c_m2)
    p_itx_m2, c_itx_m2 = fx_m2["invocation"]["payload"]["proof_path"][0]["issuance_txid"], fx_m2["invocation"]["payload"]["proof_path"][1]["issuance_txid"]
    fx_m2["chain"]["txs"][p_itx_m2]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_m2_env), "grant_id": pid_m2, "type": "seallink-issuance/1"}).hex()).hex()
    fx_m2["chain"]["txs"][c_itx_m2]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_m2_env), "grant_id": cid_m2, "type": "seallink-issuance/1"}).hex()).hex()
    fx_m2["bundle"]["grants"] = [p_m2_env, c_m2_env]
    inv_m2_p = copy.deepcopy(fx_m2["invocation"]["payload"])
    inv_m2_p["proof_path"] = [{"grant_id": pid_m2, "issuance_txid": p_itx_m2}, {"grant_id": cid_m2, "issuance_txid": c_itx_m2}]
    fx_m2["invocation"] = sl.sign_envelope(inv_m2_p, [fx_m2["_keys"]["agent_req"]["sk"]])
    inv_m2_id = sl.object_id(inv_m2_p)

    rcpt_m2_ok = sl.sign_envelope(
        {
            "action": "agent/tool", "executor_name": "id/station-a", "genesis": GENESIS_MAIN, "grant_id": cid_m2,
            "invocation_id": inv_m2_id, "network": "main", "outcome": "executed", "recorded_at": fx_m2["chain"]["now"] + 7,
            "result_sha256": _h32("d10-m2-ok-res"),
            "settlements": [
                {"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "settled": "1", "unit": "calls", "window": "term"},
                {"account": "row", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "1", "unit": "calls", "window": "term"},
                {"account": "own", "kind": "seallink/bytes", "released": "512", "reserved": "1024", "resource": "station:id/station-a:tools", "settled": "512", "unit": "bytes", "window": "term"},
                {"account": "row", "kind": "seallink/bytes", "released": "512", "reserved": "1024", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "512", "unit": "bytes", "window": "term"},
            ],
            "tip_hash": fx_m2["chain"]["tip_hash"], "tip_height": fx_m2["chain"]["tip_height"], "type": "seallink-receipt/1",
        },
        [fx_m2["_keys"]["host_rcpt"]["sk"]],
    )
    # M-2: Mixed-defect receipt (line 1 meter mismatch 0!=1 + line 2 overrun 1025>1024) -> QUOTA_EXCEEDED wins!
    add(
        "d10-m2-mixed-defect-receipt-overrun-beats-wire-member",
        ["SL-GRNT-007"],
        "commit_edge",
        {
            "actual_quota_usage": {
                "seallink/count|station:id/station-a:tools|calls|term": 0,      # line 1 meter mismatch (WIRE_MEMBER)
                "seallink/bytes|station:id/station-a:tools|bytes|term": 1025,  # line 2 overrun > reserved 1024 (QUOTA_EXCEEDED!)
            },
            "bundle": fx_m2["bundle"],
            "chain": fx_m2["chain"],
            "executor_cfg": fx_m2["executor_cfg"],
            "invocation": fx_m2["invocation"],
            "journal_id": _h32("d10-m2-j1"),
            "receipt_env": rcpt_m2_ok,
        },
        "REFUSE",
        "QUOTA_EXCEEDED",
        "M-2: Global 2-pass precedence ensures QUOTA_EXCEEDED on line 2 beats meter-mismatch WIRE_MEMBER on line 1.",
    )

    # L-12: Extra unknown key in actual_quota_usage -> WIRE_MEMBER; own-vs-row different settled -> WIRE_MEMBER!
    add(
        "d10-l12-extra-actual-quota-usage-key-wire-member",
        ["SL-GRNT-007"],
        "commit_edge",
        {
            "actual_quota_usage": {"seallink/bogus|station:id/station-a:tools|x|term": 1},
            "bundle": fx_m2["bundle"],
            "chain": fx_m2["chain"],
            "executor_cfg": fx_m2["executor_cfg"],
            "invocation": fx_m2["invocation"],
            "journal_id": _h32("d10-l12-j1"),
            "receipt_env": rcpt_m2_ok,
        },
        "REFUSE",
        "WIRE_MEMBER",
        "L-12: Unknown/extra key in actual_quota_usage MUST refuse WIRE_MEMBER.",
    )
    rcpt_m2_skew = sl.sign_envelope(
        {
            **rcpt_m2_ok["payload"],
            "settlements": [
                {"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "settled": "1", "unit": "calls", "window": "term"},
                {"account": "row", "kind": "seallink/count", "released": "1", "reserved": "1", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "0", "unit": "calls", "window": "term"},
                {"account": "own", "kind": "seallink/bytes", "released": "512", "reserved": "1024", "resource": "station:id/station-a:tools", "settled": "512", "unit": "bytes", "window": "term"},
                {"account": "row", "kind": "seallink/bytes", "released": "512", "reserved": "1024", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "512", "unit": "bytes", "window": "term"},
            ],
        },
        [fx_m2["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d10-l12-own-vs-row-different-settled-wire-member",
        ["SL-GRNT-007"],
        "commit_edge",
        {"bundle": fx_m2["bundle"], "chain": fx_m2["chain"], "executor_cfg": fx_m2["executor_cfg"], "invocation": fx_m2["invocation"], "journal_id": _h32("d10-l12-j2"), "receipt_env": rcpt_m2_skew},
        "REFUSE",
        "WIRE_MEMBER",
        "L-12: Delegated receipt with own.settled != row.settled for the same quota MUST refuse WIRE_MEMBER.",
    )

    # M-5: Settlement journal entry recorded_at MUST equal receipt.payload.recorded_at!
    add(
        "d10-m5-settlement-recorded-at-equals-receipt-recorded-at",
        ["SL-GRNT-007", "SL-GRNT-008"],
        "commit_edge",
        {
            "bundle": fx_m2["bundle"],
            "chain": fx_m2["chain"],
            "executor_cfg": fx_m2["executor_cfg"],
            "expect_settlement_recorded_at": fx_m2["chain"]["now"] + 7,
            "invocation": fx_m2["invocation"],
            "journal_id": _h32("d10-m5-j"),
            "receipt_env": rcpt_m2_ok,
        },
        "ADMIT",
        None,
        "M-5: Persisted JournalEntry.settlement.recorded_at MUST deterministically equal signed receipt.payload.recorded_at.",
    )

    # M-4: After commit_result(uncertain), admit_and_reserve(same inv) MUST return UNCERTAIN (NOT false ADMIT!), then restart & reconcile!
    rcpt_m4_unc = sl.sign_envelope(
        {
            "action": "agent/tool", "executor_name": "id/station-a", "genesis": GENESIS_MAIN, "grant_id": cid_m2,
            "invocation_id": inv_m2_id, "network": "main", "outcome": "uncertain", "recorded_at": fx_m2["chain"]["now"],
            "settlements": [
                {"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "settled": "1", "unit": "calls", "window": "term"},
                {"account": "row", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "1", "unit": "calls", "window": "term"},
                {"account": "own", "kind": "seallink/bytes", "released": "0", "reserved": "1024", "resource": "station:id/station-a:tools", "settled": "1024", "unit": "bytes", "window": "term"},
                {"account": "row", "kind": "seallink/bytes", "released": "0", "reserved": "1024", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "1024", "unit": "bytes", "window": "term"},
            ],
            "tip_hash": fx_m2["chain"]["tip_hash"], "tip_height": fx_m2["chain"]["tip_height"], "type": "seallink-receipt/1",
        },
        [fx_m2["_keys"]["host_rcpt"]["sk"]],
    )
    add(
        "d10-m4-uncertain-admit-replay-returns-uncertain-then-reconciles",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "commit_edge",
        {
            "admit_replay_after_p2": {"want_refusal": None, "want_verdict": "UNCERTAIN"},
            "bundle": fx_m2["bundle"],
            "chain": fx_m2["chain"],
            "executor_cfg": fx_m2["executor_cfg"],
            "extra_commits": [{"label": "post-restart-reconcile", "receipt_env": rcpt_m2_ok, "restart_before": True, "want_refusal": None, "want_verdict": "ADMIT"}],
            "invocation": fx_m2["invocation"],
            "journal_id": _h32("d10-m4-j"),
            "receipt_env": rcpt_m4_unc,
        },
        "ADMIT",
        None,
        "M-4: After committing uncertain outcome, re-calling admit_and_reserve with the same invocation MUST return UNCERTAIN (not false ADMIT), and survives restart to reconcile into executed.",
    )

    # L-11: single_use + uncertain -> executed writes SINGLE_USE_CONSUMED closure EXACTLY ONCE!
    fx_l11 = rm._base_invocation_fixture()
    su_pol = {"kind": "branch", "template": "single_use_1_of_2", "keys": {"grantee": fx_l11["_keys"]["agent_own"]["comp"], "issuer": fx_l11["_keys"]["alice_seal"]["comp"]}}
    su_spk, su_ws = sl.compile_script_policy(su_pol)
    assert su_ws is not None
    su_tx = _h32("d10-l11-su-seal")
    gp_l11 = copy.deepcopy(fx_l11["bundle"]["grants"][0]["payload"])
    gp_l11["revocation"] = {"construction": "W", "kind": "single_use", "mode": "seal", "seal": {"script_policy": su_pol, "txid": su_tx, "vout": 0}}
    _, gid_l11 = _reanchor(fx_l11, gp_l11)
    fx_l11["chain"]["txs"][su_tx] = {"confirmed_height": 749995, "inputs": [sv.make_segwit_input(_h32("d10-l11-f"), 0)], "outputs": {"0": {"script_pubkey_hex": su_spk.hex()}, "1": {"script_pubkey_hex": _spk_hex(fx_l11["_alice_owner_pol"])}}}
    fx_l11["chain"]["txs"][fx_l11["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["inputs"] = [sv.make_segwit_input(su_tx, 1)]
    su_use = _h32("d10-l11-use")
    fx_l11["chain"]["txs"][su_tx]["outputs"]["0"]["spent_by_txid"] = su_use
    fx_l11["chain"]["txs"][su_use] = {"confirmed_height": 750002, "inputs": [{"prev_txid": su_tx, "prev_vout": 0, "script_sig_hex": "", "witness": ["3044" + ("02" * 68) + "01", "", su_ws.hex()]}], "opreturn_hex": sl.encode_opreturn(0x11, sl.content_addr(fx_l11["invocation"])).hex(), "outputs": {}}
    rcpt_l11_unc = sl.sign_envelope({"action": "mail/read", "executor_name": "id/mail-host-a", "genesis": GENESIS_MAIN, "grant_id": gid_l11, "invocation_id": sl.object_id(fx_l11["invocation"]["payload"]), "network": "main", "outcome": "uncertain", "recorded_at": fx_l11["chain"]["now"], "settlements": [], "tip_hash": fx_l11["chain"]["tip_hash"], "tip_height": fx_l11["chain"]["tip_height"], "type": "seallink-receipt/1"}, [fx_l11["_keys"]["host_rcpt"]["sk"]])
    rcpt_l11_exe = sl.sign_envelope({**rcpt_l11_unc["payload"], "outcome": "executed", "result_sha256": _h32("d10-l11-res")}, [fx_l11["_keys"]["host_rcpt"]["sk"]])
    add(
        "d10-l11-single-use-uncertain-then-executed-single-closure",
        ["SL-GRNT-006", "SL-GRNT-007"],
        "commit_edge",
        {
            "actual_message_meta": {"folder": "Invoices"},
            "bundle": fx_l11["bundle"],
            "chain": fx_l11["chain"],
            "executor_cfg": fx_l11["executor_cfg"],
            "expect_single_use_closure_count": 1,
            "extra_commits": [{"label": "reconcile-executed", "receipt_env": rcpt_l11_exe, "restart_before": True, "want_refusal": None, "want_verdict": "ADMIT"}],
            "invocation": fx_l11["invocation"],
            "journal_id": _h32("d10-l11-j"),
            "receipt_env": rcpt_l11_unc,
        },
        "ADMIT",
        None,
        "L-11: Single-use grant transitioning uncertain -> restart -> executed MUST record SINGLE_USE_CONSUMED closure exactly once.",
    )

    # L-9: Replay journal with tampered uncertain settlement having released != "0" -> JOURNAL_LOST!
    j_l9 = sv.FencedJournal(_h32("d10-l9-j"))
    j_l9.append(
        "reservation",
        {
            "action": "mail/read",
            "expires_at": 1795220300,
            "grant_id": gid_l11,
            "invocation_id": _h32("d10-l9-inv"),
            "nonce": _h32("d10-l9-n"),
            "recorded_at": 1795220000,
            "reservations": [
                {
                    "account": "own",
                    "amount": "1",
                    "bucket_id": "term",
                    "grant_id": gid_l11,
                    "quota_kind": "seallink/count",
                    "resource": "mailbox:id/alice:work",
                    "unit": "calls",
                    "window": "term",
                }
            ],
        },
    )
    # Construct valid hash-chained tampered entry with uncertain outcome and released="1"
    tampered_body = {
        "grant_id": gid_l11,
        "invocation_id": _h32("d10-l9-inv"),
        "outcome": "uncertain",
        "receipt_content_addr": _h32("d10-l9-rcpt"),
        "recorded_at": 1795220000,
        "settlements": [
            {
                "account": "own",
                "bucket_id": "term",
                "grant_id": gid_l11,
                "quota_kind": "seallink/count",
                "released": "1",
                "resource": "mailbox:id/alice:work",
                "settled": "0",
                "unit": "calls",
                "window": "term",
            }
        ],
    }
    e2_l9 = {"body": tampered_body, "kind": "settlement", "pos": 2, "prev_commitment": j_l9.commitment}
    c2_l9 = sl.journal_commit_step(j_l9.commitment, e2_l9)
    add(
        "d10-l9-replay-tampered-uncertain-nonzero-released-refuse",
        ["SL-GRNT-007", "SL-GRNT-014"],
        "replay_journal_tamper",
        {"entries": j_l9.entries + [e2_l9], "journal_id": j_l9.journal_id, "witness_commitment": c2_l9, "witness_pos": 2},
        "REFUSE",
        "JOURNAL_LOST",
        "L-9: Replay of persisted uncertain settlement with non-zero released amount MUST fail closed with JOURNAL_LOST.",
    )

    # H-8: Golden blk: and sec: bucket_id journal commitments!
    fx_h8 = rm._base_invocation_fixture()
    gp_h8 = copy.deepcopy(fx_h8["bundle"]["grants"][0]["payload"])
    gp_h8["capabilities"][0]["quotas"] = [
        {"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "blocks:10"},
        {"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "seconds:3600"},
    ]
    _, gid_h8 = _reanchor(fx_h8, gp_h8)
    _v_h8 = sv.Tier1Verifier(require_jsonschema=True)
    _j_h8 = sv.FencedJournal(_h32("d10-h8-j"))
    _r_h8 = _v_h8.verify_invocation(fx_h8["invocation"], fx_h8["bundle"], sv.ChainView(fx_h8["chain"]), _j_h8, fx_h8["executor_cfg"], actual_message_meta={"folder": "Invoices"})
    assert _r_h8.verdict == "ADMIT", _r_h8
    assert _j_h8.entries[0]["body"]["reservations"][0]["bucket_id"] == f"blk:{(fx_h8['chain']['tip_height'] // 10) * 10}"
    assert _j_h8.entries[0]["body"]["reservations"][1]["bucket_id"] == f"sec:{(fx_h8['chain']['now'] // 3600) * 3600}"
    add(
        "d10-h8-window-blk-and-sec-golden-bucket-commitments",
        ["SL-GRNT-007", "SL-GRNT-008"],
        "multi_step_journal",
        {
            "expect_head_commitment": _j_h8.commitment,
            "journal": {"journal_id": _h32("d10-h8-j")},
            "steps": [{"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_h8["bundle"], "chain": fx_h8["chain"], "executor_cfg": fx_h8["executor_cfg"], "invocation": fx_h8["invocation"], "kind": "invocation", "label": "blk-sec-buckets", "want_refusal": None, "want_verdict": "ADMIT"}],
        },
        "ADMIT",
        None,
        "H-8: Golden JournalEntry commitment verifying canonical 'blk:<floor>' and 'sec:<floor>' bucket_id formatting for 10b and 3600s quota windows.",
    )

    # =========================================================================
    # 7. H-11..H-15 / M-11..M-15: Federation, Migration, Core-Only Uniformity, & mail/read meta
    # =========================================================================
    fx_f10 = rm._base_invocation_fixture()
    p256_f10_sk = sl.deterministic_p256_privkey("d10-fed-p256")
    p256_f10_pk = sl.p256_compressed_pubkey(p256_f10_sk)
    ds_f10_pol = {"kind": "key", "pk": _kp("d10-fed-ds")["comp"]}
    ds_f10_tx = _h32("d10-fed-ds-tx")
    fx_f10["chain"]["txs"][ds_f10_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(ds_f10_pol)}}}
    dh_f10, dp_f10 = rm.make_salted_device_set(
        "id/alice",
        [{"alg": "p256", "ceiling": 2, "key": p256_f10_pk, "label": "l2-f10", "presence": True, "seal": {"script_policy": ds_f10_pol, "txid": ds_f10_tx, "vout": 0}}],
    )
    am_f10 = {**copy.deepcopy(fx_f10["_alice_man"]), "sets": {"devices": {"seq": 1, "sha256": sl.content_addr(dh_f10)}}}
    am_f10_h = sl.content_addr(am_f10)
    fx_f10["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_f10["_alice_reg"], fx_f10["_alice_owner_pol"], {"link": {"grant": fx_f10["_keys"]["alice_gr"]["xonly"]}, "m": {"h": am_f10_h, "s": 1}}, first_height=748000, update_height=749000)
    gf_p = copy.deepcopy(fx_f10["bundle"]["grants"][0]["payload"])
    gf_p["recipient"] = {"mode": "name", "name": "id/peer-b", "owner_policy": {"kind": "key", "pk": _kp("d10-fed-pb")["comp"]}, "registration": {"txid": _h32("d10-fed-pbr"), "vout": 0}}
    gf_env = sl.sign_envelope(gf_p, [fx_f10["_keys"]["alice_gr"]["sk"]])
    cmd_f10 = sl.sign_envelope({"arguments": {"fields_sha256": _h32("d10-fed-f"), "grant_id": sl.object_id(gf_p), "recipient_name": "id/peer-b", "route_mode": "direct"}, "command": "approve-pii-disclosure", "exp": fx_f10["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "iat": fx_f10["chain"]["now"] - 10, "level": 2, "network": "main", "nonce": _h32("d10-fed-n"), "owner": "id/alice", "target_executor": "id/station-a", "type": "seallink-owner-command/1"}, [p256_f10_sk], alg="p256")
    base_fed_ctx = {"approval_command": cmd_f10, "device_proof": dp_f10[0], "fields_sha256": _h32("d10-fed-f"), "manifests": {am_f10_h: am_f10}, "phase": "pii_disclosure", "route_hops": [{"actor": "id/peer-b", "role": "counterparty"}]}
    base_fed_pol = {"require_contour_a": True, "trusted_peers": ["id/peer-b", "id/wrong-peer"]}

    add("d10-h11-federation-wrong-hop-actor-refuse", ["SL-SERV-004"], "federation", {"chain": fx_f10["chain"], "grant": gf_env, "journal": {"journal_id": _h32("d10-f-j1")}, "peer_ctx": {**base_fed_ctx, "route_hops": [{"actor": "id/wrong-peer", "role": "counterparty"}]}, "policy": base_fed_pol}, "REFUSE", "FEDERATION_POLICY_DENIED", "H-11: Contour A direct route hop actor MUST equal grant.recipient.name.", module="federated-screening")
    ch_f_exp = copy.deepcopy(fx_f10["chain"])
    rm.sync_chain_tip(ch_f_exp, height=gf_p["not_after_height"] + 1)
    add("d10-h12-federation-pii-expired-grant-window-closed", ["SL-SERV-004"], "federation", {"chain": ch_f_exp, "grant": gf_env, "journal": {"journal_id": _h32("d10-f-j2")}, "peer_ctx": base_fed_ctx, "policy": base_fed_pol}, "REFUSE", "GRANT_WINDOW_CLOSED", "H-12: Federation pii_disclosure MUST enforce grant height window (GRANT_WINDOW_CLOSED).", module="federated-screening")
    ch_f_sp = copy.deepcopy(fx_f10["chain"])
    gs_tx = gf_p["revocation"]["seal"]["txid"]
    ch_f_sp["txs"][gs_tx]["outputs"]["0"]["spent_by_txid"] = _h32("d10-f-sp")
    ch_f_sp["txs"][_h32("d10-f-sp")] = {"confirmed_height": 750003, "inputs": [sv.make_segwit_input(gs_tx, 0)], "outputs": {}}
    add("d10-h12-federation-pii-spent-seal-refuse", ["SL-SERV-004"], "federation", {"chain": ch_f_sp, "grant": gf_env, "journal": {"journal_id": _h32("d10-f-j3")}, "peer_ctx": base_fed_ctx, "policy": base_fed_pol}, "REFUSE", "SEAL_SPENT", "H-12: Federation pii_disclosure MUST enforce live grant revocation seal (SEAL_SPENT).", module="federated-screening")
    add("d10-m13-federation-pii-missing-device-list-device-unauthorized", ["SL-SERV-004", "SL-IDTY-010"], "federation", {"chain": fx_f10["chain"], "grant": gf_env, "journal": {"journal_id": _h32("d10-f-j4")}, "peer_ctx": {k: v for k, v in base_fed_ctx.items() if k != "device_proof"}, "policy": base_fed_pol}, "REFUSE", "DEVICE_UNAUTHORIZED", "M-13: Federation pii_disclosure omitting device_proof MUST preserve DEVICE_UNAUTHORIZED.", module="federated-screening")
    add("d10-m15-federation-missing-journal-refuse", ["SL-SERV-004"], "federation", {"chain": fx_f10["chain"], "grant": gf_env, "peer_ctx": base_fed_ctx, "policy": base_fed_pol}, "REFUSE", "FEDERATION_POLICY_DENIED", "M-15: Federation verification omitting mandatory journal MUST fail closed.", module="federated-screening")
    add("d10-m15-federation-corrupt-journal-lost", ["SL-SERV-004"], "federation", {"chain": fx_f10["chain"], "grant": gf_env, "journal": {"journal_id": _h32("d10-f-j5"), "witness_readable": False}, "peer_ctx": base_fed_ctx, "policy": base_fed_pol}, "REFUSE", "JOURNAL_LOST", "M-15: Federation verification with corrupt journal continuity MUST refuse JOURNAL_LOST.", module="federated-screening")
    gf_wo_p = {**copy.deepcopy(gf_p), "not_after_height": fx_f10["chain"]["tip_height"] + 8, "not_before_height": fx_f10["chain"]["tip_height"] - 2, "revocation": {"mode": "window_only"}}
    gf_wo_env = sl.sign_envelope(gf_wo_p, [fx_f10["_keys"]["alice_gr"]["sk"]])
    cmd_f10_wo = sl.sign_envelope({**cmd_f10["payload"], "arguments": {**cmd_f10["payload"]["arguments"], "grant_id": sl.object_id(gf_wo_p)}}, [p256_f10_sk], alg="p256")
    add("d10-h12-federation-pii-window-only-refuse", ["SL-SERV-004"], "federation", {"chain": fx_f10["chain"], "grant": gf_wo_env, "journal": {"journal_id": _h32("d10-f-j6")}, "peer_ctx": {**base_fed_ctx, "approval_command": cmd_f10_wo}, "policy": base_fed_pol}, "REFUSE", "FEDERATION_POLICY_DENIED", "H-12: Federation pii_disclosure with window_only grant (even with matching L2 approval command) MUST refuse FEDERATION_POLICY_DENIED.", module="federated-screening")
    add("d10-h12-federation-unknown-phase-refuse", ["SL-SERV-004"], "federation", {"chain": fx_f10["chain"], "grant": gf_env, "journal": {"journal_id": _h32("d10-f-j7")}, "peer_ctx": {**base_fed_ctx, "phase": "unknown"}, "policy": base_fed_pol}, "REFUSE", "FEDERATION_POLICY_DENIED", "H-12: Federation with unknown phase MUST fail closed with FEDERATION_POLICY_DENIED.", module="federated-screening")
    ch_f_noname = copy.deepcopy(fx_f10["chain"])
    ch_f_noname["names"] = {}
    add("d10-h12-federation-pii-issuer-name-missing-refuse", ["SL-SERV-004"], "federation", {"chain": ch_f_noname, "grant": gf_env, "journal": {"journal_id": _h32("d10-f-j8")}, "peer_ctx": base_fed_ctx, "policy": base_fed_pol}, "REFUSE", "NAME_NOT_FOUND", "H-12: Federation pii_disclosure when grant issuer name cannot be resolved MUST refuse NAME_NOT_FOUND.", module="federated-screening")

    # H-14: Closed MigrationExportBundle + source-signed migration-fence + on-chain predecessor_grant_seals[] spend!
    fx_mig = rm._base_invocation_fixture()
    d_own, d_rcpt = _kp("d10-mig-do"), _kp("d10-mig-dr")
    d_pol, d_reg = {"kind": "key", "pk": d_own["comp"]}, {"txid": _h32("d10-mig-drg"), "vout": 0}
    d_pin = {"name": "id/mail-host-b", "owner_policy": d_pol, "registration": d_reg}
    h_pin = {"name": "id/alice", "owner_policy": fx_mig["_alice_owner_pol"], "registration": fx_mig["_alice_reg"]}
    s_pin = {"name": "id/mail-host-a", "owner_policy": fx_mig["_host_owner_pol"], "registration": fx_mig["_host_reg"]}
    d_man = {"network": "main", "owner": "id/mail-host-b", "seq": 1, "service": {"actions": ["mail/read"], "endpoint": "https://mail-b.example.org", "receipt_key": d_rcpt["xonly"], "service_type": "mail"}, "type": "seallink-manifest/1"}
    d_man_h = sl.content_addr(d_man)
    al_m_man = {**copy.deepcopy(fx_mig["_alice_man"]), "providers": [{"label": "work", "provider": d_pin, "service_type": "mail"}], "seq": 2}
    al_m_man_h = sl.content_addr(al_m_man)
    fx_mig["bundle"]["manifests"][d_man_h] = d_man
    fx_mig["bundle"]["manifests"][al_m_man_h] = al_m_man
    fx_mig["chain"]["names"]["id/mail-host-b"] = sv.make_name_history("id/mail-host-b", d_reg, d_pol, {"m": {"h": d_man_h, "s": 1}}, first_height=748000, update_height=749000)
    fx_mig["chain"]["names"]["id/alice"] = sv.make_name_history("id/alice", fx_mig["_alice_reg"], fx_mig["_alice_owner_pol"], {"link": {"grant": fx_mig["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al_m_man_h, "s": 2}}, first_height=748000, update_height=749000)
    mid_10 = _h32("d10-mig-id")
    m_inv = {"holder_name": "id/alice", "items": [], "migration_id": mid_10, "service_type": "mail"}
    m_sha = sl.sha256(sl.jcs_encode(m_inv)).hex()
    m_jc = _h32("d10-mig-jc")
    m_p = {"dest_executor": d_pin, "genesis": GENESIS_MAIN, "holder": h_pin, "inventory_sha256": m_sha, "issued_at": fx_mig["chain"]["now"], "journal_commitment": m_jc, "journal_pos": 1, "migration_id": mid_10, "network": "main", "outstanding_exposure": [], "service_type": "mail", "source_executor": s_pin, "type": "seallink-migration/1"}
    m_env = sl.sign_envelope(m_p, [fx_mig["_keys"]["host_rcpt"]["sk"]])
    m_ha = sl.sign_envelope({"expires_at": fx_mig["chain"]["now"] + 3600, "genesis": GENESIS_MAIN, "issued_at": fx_mig["chain"]["now"] - 10, "network": "main", "nonce": _h32("d10-mig-ha"), "party_id": "h", "party_name": "id/alice", "party_role": "holder", "target_id": sl.object_id(m_p), "target_type": "seallink-migration/1", "type": "seallink-assent/1"}, [fx_mig["_keys"]["alice_gr"]["sk"]])
    m_acc = sl.sign_envelope({"genesis": GENESIS_MAIN, "issuer": d_pin, "network": "main", "not_after": fx_mig["chain"]["now"] + 3600, "not_before": fx_mig["chain"]["now"] - 10, "seq": 1, "statement_kind": "migration-accept", "subject": {"holder": h_pin, "inventory_sha256": m_sha, "migration_id": mid_10, "source_executor": s_pin}, "type": "seallink-statement/1"}, [d_rcpt["sk"]])
    pred_seal = fx_mig["bundle"]["grants"][0]["payload"]["revocation"]["seal"]
    m_fence = sl.sign_envelope({"genesis": GENESIS_MAIN, "issuer": s_pin, "network": "main", "not_after": fx_mig["chain"]["now"] + 3600, "not_before": fx_mig["chain"]["now"] - 10, "seq": 1, "statement_kind": "migration-fence", "subject": {"dest_executor": d_pin, "holder": h_pin, "inventory_sha256": m_sha, "migration_id": mid_10, "predecessor_grant_seals": [pred_seal], "source_journal_commitment": m_jc, "source_journal_pos": 1}, "type": "seallink-statement/1"}, [fx_mig["_keys"]["host_rcpt"]["sk"]])
    eb_10 = {"fencing_statement": m_fence, "inventory": m_inv, "source_journal_commitment": m_jc, "source_journal_pos": 1}

    add("d10-h14-migration-unspent-predecessor-seal-refuse", ["SL-SERV-003"], "migration", {"chain": fx_mig["chain"], "dest_accept_stmt": m_acc, "export_bundle": eb_10, "holder_assent": m_ha, "journal": {"journal_id": _h32("d10-mig-j1")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate"}, "REFUSE", "SERVICE_MIGRATION_INVALID", "H-14: Migration activate with valid migration-fence naming an UNSPENT predecessor_grant_seals[0] MUST refuse SERVICE_MIGRATION_INVALID.", module="service-migration")
    ch_mig_ok = copy.deepcopy(fx_mig["chain"])
    ch_mig_ok["txs"][pred_seal["txid"]]["outputs"]["0"]["spent_by_txid"] = _h32("d10-mig-pred-sp")
    ch_mig_ok["txs"][_h32("d10-mig-pred-sp")] = {"confirmed_height": 750002, "inputs": [sv.make_segwit_input(pred_seal["txid"], 0)], "outputs": {}}
    add("d10-h14-migration-spent-predecessor-seal-and-fence-admit", ["SL-SERV-003"], "migration", {"chain": ch_mig_ok, "dest_accept_stmt": m_acc, "export_bundle": eb_10, "holder_assent": m_ha, "journal": {"journal_id": _h32("d10-mig-j2")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate"}, "ADMIT", None, "H-14: Migration activate with valid source-signed migration-fence and confirmed on-chain spend of predecessor_grant_seals[0] admits cleanly.", module="service-migration")
    add("d10-h14-migration-legacy-boolean-keys-refuse", ["SL-SERV-003"], "migration", {"chain": ch_mig_ok, "dest_accept_stmt": m_acc, "export_bundle": {**eb_10, "source_write_token_fenced": True}, "holder_assent": m_ha, "journal": {"journal_id": _h32("d10-mig-j3")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate"}, "REFUSE", "SERVICE_MIGRATION_INVALID", "H-14: Closed MigrationExportBundle schema rejects legacy self-asserted source_write_token_fenced boolean.", module="service-migration")
    add("d10-h14-migration-duplicate-migration-id-refuse", ["SL-SERV-003"], "migration", {"chain": ch_mig_ok, "dest_accept_stmt": m_acc, "export_bundle": eb_10, "holder_assent": m_ha, "journal": {"journal_id": _h32("d10-mig-j4"), "migrations_applied": [mid_10]}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate"}, "REFUSE", "SERVICE_MIGRATION_INVALID", "H-14: Replaying an already-applied migration_id with valid fencing_statement and spent predecessor seal MUST refuse SERVICE_MIGRATION_INVALID.", module="service-migration")
    m_inv_bad = {"holder_name": "id/alice", "items": [{"media_type": "application/octet-stream", "path": "secrets/private_key.pem", "sha256": _h32("d10-mig-sec"), "size_bytes": "32"}], "migration_id": mid_10, "service_type": "mail"}
    m_p_bad = {**m_p, "inventory_sha256": sl.sha256(sl.jcs_encode(m_inv_bad)).hex()}
    m_env_bad = sl.sign_envelope(m_p_bad, [fx_mig["_keys"]["host_rcpt"]["sk"]])
    add("d10-h14-migration-stage-forbidden-export-item-refuse", ["SL-SERV-003"], "migration", {"chain": fx_mig["chain"], "export_bundle": {"inventory": m_inv_bad, "source_journal_commitment": _h32("d10-mig-stage-jc"), "source_journal_pos": 0}, "journal": {"journal_id": _h32("d10-mig-j5")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env_bad, "mode": "stage"}, "REFUSE", "SERVICE_MIGRATION_INVALID", "H-14/L-13: Migration stage mode MUST reject forbidden execution-secret export items (SERVICE_MIGRATION_INVALID).", module="service-migration")

    # H-13 / M-11: Core-only uniform ACTION_UNSUPPORTED across wire bytes, owner_command, statement, & assent!
    add("d10-h13-core-only-wire-bytes-session-open-action-unsupported", ["SL-WIRE-007", "SL-GRNT-013"], "raw_wire", {"enabled_modules": ["core"], "raw_bytes_utf8": sl.jcs_encode(so_bs).decode("utf-8")}, "REFUSE", "ACTION_UNSUPPORTED", "H-13: Core-only verify_wire_bytes MUST refuse seallink-session-open/1 with ACTION_UNSUPPORTED.", module="core")
    add("d10-h13-core-only-wire-bytes-migration-action-unsupported", ["SL-WIRE-007", "SL-SERV-003"], "raw_wire", {"enabled_modules": ["core"], "raw_bytes_utf8": sl.jcs_encode(m_env).decode("utf-8")}, "REFUSE", "ACTION_UNSUPPORTED", "H-13: Core-only verify_wire_bytes MUST refuse seallink-migration/1 with ACTION_UNSUPPORTED.", module="core")
    add("d10-h13-core-only-owner-command-pii-action-unsupported", ["SL-SERV-004"], "owner_command", {"chain": fx_f10["chain"], "command": cmd_f10, "device_proof": dp_f10[0], "enabled_modules": ["core"], "is_foreign_service": False}, "REFUSE", "ACTION_UNSUPPORTED", "H-13: Core-only verify_owner_command MUST refuse approve-pii-disclosure with ACTION_UNSUPPORTED.", module="core")
    add("d10-h13-core-only-statement-migration-accept-action-unsupported", ["SL-SERV-003"], "statement", {"chain": fx_mig["chain"], "enabled_modules": ["core"], "statement": m_acc}, "REFUSE", "ACTION_UNSUPPORTED", "H-13: Core-only verify_statement MUST refuse migration-accept with ACTION_UNSUPPORTED.", module="core")
    add("d10-h13-core-only-statement-migration-fence-action-unsupported", ["SL-SERV-003"], "statement", {"chain": fx_mig["chain"], "enabled_modules": ["core"], "statement": m_fence}, "REFUSE", "ACTION_UNSUPPORTED", "H-13: Core-only verify_statement MUST refuse migration-fence with ACTION_UNSUPPORTED.", module="core")
    add("d10-h13-core-only-assent-migration-target-action-unsupported", ["SL-SERV-003"], "assent", {"assent": m_ha, "chain": fx_mig["chain"], "contract": of_b1["contract"], "enabled_modules": ["core"]}, "REFUSE", "ACTION_UNSUPPORTED", "H-13: Core-only verify_assent MUST refuse target_type='seallink-migration/1' with ACTION_UNSUPPORTED.", module="core")

    # H-15: mail/read actual_message_meta enforcement across folder, sender_domain, and max_bytes!
    fx_h15 = rm._base_invocation_fixture()
    gp_h15 = copy.deepcopy(fx_h15["bundle"]["grants"][0]["payload"])
    gp_h15["capabilities"][0]["where"] = {"folder": {"eq": "Invoices"}, "max_bytes": {"range": ["0", "1024"]}, "sender_domain": {"eq": "vendor.example"}}
    _reanchor(fx_h15, gp_h15)
    for label_m, meta_val, want_v, want_c, desc_m in [
        ("missing-meta-refuse", None, "REFUSE", "INVOKE_CONSTRAINT_FAILED", "H-15: mail/read where.folder/sender_domain/max_bytes omitting actual_message_meta refuses INVOKE_CONSTRAINT_FAILED."),
        ("wrong-folder-refuse", {"folder": "Spam", "sender_domain": "vendor.example", "size_bytes": "512"}, "REFUSE", "INVOKE_CONSTRAINT_FAILED", "H-15: mail/read actual_message_meta.folder != where.folder refuses INVOKE_CONSTRAINT_FAILED (even when inv.arguments.folder matches!)."),
        ("wrong-domain-refuse", {"folder": "Invoices", "sender_domain": "evil.example", "size_bytes": "512"}, "REFUSE", "INVOKE_CONSTRAINT_FAILED", "H-15: mail/read actual_message_meta.sender_domain mismatch refuses INVOKE_CONSTRAINT_FAILED."),
        ("over-max-bytes-refuse", {"folder": "Invoices", "sender_domain": "vendor.example", "size_bytes": "1025"}, "REFUSE", "INVOKE_CONSTRAINT_FAILED", "H-15: mail/read actual_message_meta.size_bytes == max_bytes + 1 refuses INVOKE_CONSTRAINT_FAILED."),
        ("exact-max-bytes-admit", {"folder": "Invoices", "sender_domain": "vendor.example", "size_bytes": "1024"}, "ADMIT", None, "H-15: mail/read with matching folder/sender_domain and exact size_bytes == max_bytes admits."),
    ]:
        inp_m: dict[str, Any] = {"bundle": fx_h15["bundle"], "chain": fx_h15["chain"], "executor_cfg": fx_h15["executor_cfg"], "invocation": fx_h15["invocation"], "journal": {"journal_id": _h32(f"d10-h15-{label_m}")}}
        if meta_val is not None:
            inp_m["actual_message_meta"] = meta_val
        add(f"d10-h15-mail-read-{label_m}", ["SL-PROF-001", "SL-GRNT-004"], "invocation", inp_m, want_v, want_c, desc_m)

    # =========================================================================
    # 13. Layer 1 Verification Hardening (Post-draft.10 Audit Closures)
    # =========================================================================

    # L1-1: Tier1Verifier.__init__ validates trusted_origin_issuer_pins against NamePin schema (fail closed!)
    fx_orig_l1 = rm._base_origin_fixture()
    bad_pin = copy.deepcopy(fx_orig_l1["trusted_origin_issuer_pins"][0])
    bad_pin["unexpected_typo"] = "boom"
    add(
        "d10-l1-init-bad-origin-issuer-pin-refuse",
        ["SL-ORIG-002"],
        "init_verifier",
        {"trusted_origin_issuer_pins": [bad_pin]},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "L1: Tier1Verifier.__init__ MUST validate every trusted_origin_issuer_pins entry against closed NamePin schema.",
    )

    # L1-2: SPEC-01 §7 Step 7 WIRE_SIZE runs BEFORE Step 7b optional-module ACTION_UNSUPPORTED!
    big_mig_payload = {
        "dest_executor": fx_mig["executor_cfg"]["pin"],
        "genesis": GENESIS_MAIN,
        "holder": fx_mig["bundle"]["grants"][0]["payload"]["issuer"],
        "inventory_sha256": _h32("l1-big-inv"),
        "issued_at": 1795220000,
        "journal_commitment": _h32("l1-big-jc"),
        "journal_pos": 1,
        "migration_id": _h32("l1-big-mid"),
        "network": "main",
        "outstanding_exposure": [
            {"kind": "seallink/count", "max": "1", "resource": ("r" * 240) + f"-{i:02d}", "unit": "calls", "window": "term"}
            for i in range(64)
        ],
        "source_executor": fx_mig["executor_cfg"]["pin"],
        "type": "seallink-migration/1",
    }
    big_mig_env = sl.sign_envelope(big_mig_payload, [fx_mig["_keys"]["host_rcpt"]["sk"]])
    big_mig_raw = sl.jcs_encode(big_mig_env).decode("utf-8")
    # Pad inside a valid UTF-8 JSON object exceeding 65536B (or using max_bytes_override? No, make raw > 65536B via extra field before Step 8!)
    big_mig_over = json.dumps({**big_mig_env, "pad": "x" * 66000}, separators=(",", ":"), sort_keys=True)
    add(
        "d10-l1-wire-size-before-action-unsupported-refuse",
        ["SL-WIRE-001", "SL-SERV-003"],
        "raw_wire",
        {"enabled_modules": ["core"], "raw_bytes_utf8": big_mig_over},
        "REFUSE",
        "WIRE_SIZE",
        "L1 (SPEC-01 §7): Oversized disabled-module object (> type max_bytes) MUST refuse WIRE_SIZE before optional-module ACTION_UNSUPPORTED.",
    )

    # L1-3: _is_bracket_consistent MUST NOT let rebracket_tip alone bypass missing/invalid observation_bracket!
    ch_no_ob_with_rb = copy.deepcopy(fx_h15["chain"])
    ch_no_ob_with_rb.pop("observation_bracket", None)
    ch_no_ob_with_rb["rebracket_tip"] = {
        "first_sight": ch_no_ob_with_rb["tip_first_sight"],
        "hash": ch_no_ob_with_rb["tip_hash"],
        "header_time": ch_no_ob_with_rb["tip_header_time"],
        "height": ch_no_ob_with_rb["tip_height"],
        "now": ch_no_ob_with_rb["now"],
    }
    add(
        "d10-l1-missing-ob-with-rebracket-tip-void",
        ["SL-LDGR-008"],
        "chain_obs",
        {"chain": ch_no_ob_with_rb, "require_observation_bracket": True, "risk_class": 1},
        "REFUSE",
        "CHAIN_OBSERVATION_VOID",
        "L1: rebracket_tip alone MUST NOT bypass missing observation_bracket when require_observation_bracket=True.",
    )
    ch_nondict_ob = copy.deepcopy(ch_no_ob_with_rb)
    ch_nondict_ob["observation_bracket"] = "invalid"
    add(
        "d10-l1-nondict-ob-with-rebracket-tip-void",
        ["SL-LDGR-008"],
        "chain_obs",
        {"chain": ch_nondict_ob, "require_observation_bracket": True, "risk_class": 1},
        "REFUSE",
        "CHAIN_OBSERVATION_VOID",
        "L1: Non-dict observation_bracket MUST refuse CHAIN_OBSERVATION_VOID even if rebracket_tip matches.",
    )

    # L1-4: SPEC-02 §5.2 200-year SLNK outer-before-semantic + critical_forward_only (0x13..0x1a) vs critical_retroactive (0x1b..0x1f)
    sl_own, sl_cred, sl_subj = _kp("l1-sl-own"), _kp("l1-sl-cred"), _kp("l1-sl-subj")
    sl_pol = {"kind": "key", "pk": sl_own["comp"]}
    sl_reg = {"txid": _h32("l1-sl-reg"), "vout": 0}
    sl_val = {"link": {"cred": sl_cred["xonly"]}}
    sl_cred_p = {
        "claims": {"degree": "MSc"},
        "credential_kind": "education/diploma",
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "issuer": {"name": "id/slnk-uni", "owner_policy": sl_pol, "registration": sl_reg, "role_policy": {"m": 1, "pks": [sl_cred["xonly"]]}},
        "lifecycle": "eternal",
        "network": "main",
        "not_before_height": 749500,
        "subject": {"key": sl_subj["xonly"], "mode": "key"},
        "type": "seallink-credential/1",
    }
    sl_cred_env = sl.sign_envelope(sl_cred_p, [sl_cred["sk"]])
    sl_atx_before = _h32("l1-sl-atx-749999")
    sl_atx_at = _h32("l1-sl-atx-750000")
    frame_0x13_ok = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x15, 0x22, 0x01]) + (b"\xaa" * 32) + bytes([0x00])).hex()
    frame_0x13_bad_outer = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x15, 0x05, 0x01, 0x02])).hex()
    frame_0x1b_ok = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x1B, 0x22, 0x01]) + (b"\xbb" * 32) + bytes([0x00])).hex()
    frame_0x0b_bad_hc = sl.encode_opreturn(0x0B, _h32("l1-0b-bad"), 0x00, h_c=750050).hex()

    def _slnk_chain(opret_hex: str, *, sighash: int = 0x01) -> dict[str, Any]:
        ch_s = copy.deepcopy(fx_h15["chain"])
        ch_s["names"]["id/slnk-uni"] = sv.make_name_history(
            "id/slnk-uni",
            sl_reg,
            sl_pol,
            sl_val,
            first_height=748000,
            update_height=749000,
            extra_updates=[{"confirmed_height": 750000, "opreturn_hex": opret_hex, "sighash_bytes": [sighash], "txid": _h32(f"l1-sl-u-{opret_hex[:8]}-{sighash}"), "value": sl_val}],
        )
        ch_s["txs"][sl_atx_before] = {"confirmed_height": 749999, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(sl_cred_env)).hex(), "outputs": {}}
        ch_s["txs"][sl_atx_at] = {"confirmed_height": 750000, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(sl_cred_env)).hex(), "outputs": {}}
        return ch_s

    add("d10-l1-slnk-0x13-forward-only-before-hframe-admit", ["SL-LDGR-010", "SL-CONT-008"], "credential",
        {"anchor_txid": sl_atx_before, "chain": _slnk_chain(frame_0x13_ok), "credential": sl_cred_env},
        "ADMIT", None, "L1 (SPEC-02 §5.2): Future critical_forward_only 0x13 frame at h_frame=750000 MUST NOT break historical eternal credential at at_height=749999 < h_frame.")
    add("d10-l1-slnk-0x13-forward-only-at-hframe-refuse", ["SL-LDGR-010", "SL-CONT-008"], "credential",
        {"anchor_txid": sl_atx_at, "chain": _slnk_chain(frame_0x13_ok), "credential": sl_cred_env},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "L1 (SPEC-02 §5.2): Future critical_forward_only 0x13 frame at h_frame=750000 MUST refuse ORIGIN_STATUS_INCOMPLETE at at_height == h_frame.")
    add("d10-l1-slnk-0x1b-retroactive-before-hframe-refuse", ["SL-LDGR-010", "SL-CONT-008"], "credential",
        {"anchor_txid": sl_atx_before, "chain": _slnk_chain(frame_0x1b_ok), "credential": sl_cred_env},
        "REFUSE", "ORIGIN_STATUS_INCOMPLETE", "L1 (SPEC-02 §5.2): Future critical_retroactive 0x1b frame at h_frame=750000 MUST fail closed ORIGIN_STATUS_INCOMPLETE even at historical at_height=749999 < h_frame.")
    add("d10-l1-slnk-0x13-malformed-outer-frame-invalid", ["SL-LDGR-010"], "credential",
        {"anchor_txid": sl_atx_before, "chain": _slnk_chain(frame_0x13_bad_outer), "credential": sl_cred_env},
        "REFUSE", "CHAIN_FRAME_INVALID", "L1 (SPEC-02 §5.2): Truncated outer push on 0x13 MUST refuse CHAIN_FRAME_INVALID before range criticality.")
    add("d10-l1-slnk-non-sighash-all-0x1b-inert-admit", ["SL-LDGR-010"], "credential",
        {"anchor_txid": sl_atx_before, "chain": _slnk_chain(frame_0x1b_ok, sighash=0x81), "credential": sl_cred_env},
        "ADMIT", None, "H-10 / R12-M3 (SPEC-02 §5.2): Non-SIGHASH_ALL update carrying 0x1b is strictly inert and MUST NOT poison historical eternal credentials.")
    add("d10-l1-slnk-non-sighash-all-0x0b-bad-hc-inert-admit", ["SL-LDGR-010"], "credential",
        {"anchor_txid": sl_atx_before, "chain": _slnk_chain(frame_0x0b_bad_hc, sighash=0x81), "credential": sl_cred_env},
        "ADMIT", None, "H-10 / R12-M3 (SPEC-02 §5.2): Non-SIGHASH_ALL update carrying malformed/bad-hc 0x0b is strictly inert.")
    add("d10-l1-slnk-sighash-all-0x0b-bad-hc-frame-invalid", ["SL-LDGR-010"], "credential",
        {"anchor_txid": sl_atx_before, "chain": _slnk_chain(frame_0x0b_bad_hc, sighash=0x01), "credential": sl_cred_env},
        "REFUSE", "CHAIN_FRAME_INVALID", "SPEC-02 §5.2: Owner-authored SIGHASH_ALL confirmed update carrying 0x0b with h_c > inclusion_height MUST refuse CHAIN_FRAME_INVALID.")

    # L1-5: A -> B -> A role rotation consistency (retired_before_height) + cause-keyed role closures (NAME_ROLE_CHANGED vs 0x0b CRED_ISSUER_CLOSED)
    fx_aba = rm._base_invocation_fixture()
    k_a = fx_aba["_keys"]["alice_gr"]
    k_b = _kp("l1-aba-key-b")
    alice_val_a = {"link": {"grant": k_a["xonly"]}, "m": {"h": sl.content_addr(fx_aba["_alice_man"]), "s": 1}}
    alice_val_b = {"link": {"grant": k_b["xonly"]}, "m": {"h": sl.content_addr(fx_aba["_alice_man"]), "s": 1}}
    # Old grant G_old issued at recent_block=749990 (BEFORE A->B rotation at 749995)
    g_aba_old = fx_aba["bundle"]["grants"][0]
    inv_aba_old = fx_aba["invocation"]
    # New grant G_new issued by restored key A at recent_block=750002 (AFTER B->A restoration at 750000!)
    blk_750002 = _h32("l1-aba-blk-750002")
    seal_tx_new = _h32("l1-aba-seal-new")
    iss_tx_new = _h32("l1-aba-iss-new")
    seal_pol_aba = g_aba_old["payload"]["revocation"]["seal"]["script_policy"]
    gp_aba_new = copy.deepcopy(g_aba_old["payload"])
    gp_aba_new["recent_block"] = blk_750002
    gp_aba_new["revocation"] = {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": seal_pol_aba, "txid": seal_tx_new, "vout": 0}}
    g_aba_new = sl.sign_envelope(gp_aba_new, [k_a["sk"]])
    gid_aba_new = sl.object_id(gp_aba_new)
    iss_prep_new = {"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_aba_new), "grant_id": gid_aba_new, "type": "seallink-issuance/1"}
    inv_aba_new = sl.sign_envelope(
        {**inv_aba_old["payload"], "nonce": _h32("l1-aba-n-new"), "proof_path": [{"grant_id": gid_aba_new, "issuance_txid": iss_tx_new}]},
        [fx_aba["_keys"]["agent_req"]["sk"]],
    )
    bundle_aba_new = {**fx_aba["bundle"], "grants": [g_aba_new]}
    ch_aba = copy.deepcopy(fx_aba["chain"])
    ch_aba["blocks"][blk_750002] = 750002
    ch_aba["txs"][seal_tx_new] = {
        "confirmed_height": 750003,
        "inputs": [sv.make_segwit_input(_h32("l1-aba-fund"), 0)],
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(seal_pol_aba)}, "1": {"script_pubkey_hex": _spk_hex(fx_aba["_alice_owner_pol"])}},
    }
    ch_aba["txs"][iss_tx_new] = {
        "confirmed_height": 750004,
        "inputs": [sv.make_segwit_input(seal_tx_new, 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest(iss_prep_new).hex(), 0x00).hex(),
        "outputs": {},
    }
    u_rot_b_tx = _h32("l1-aba-rot-b")
    u_rot_a2_tx = _h32("l1-aba-rot-a2")
    ch_aba["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_aba["_alice_reg"],
        fx_aba["_alice_owner_pol"],
        alice_val_a,
        first_height=748000,
        update_height=749000,
        extra_updates=[
            {"confirmed_height": 749995, "txid": u_rot_b_tx, "value": alice_val_b},
            {"confirmed_height": 750000, "txid": u_rot_a2_tx, "value": alice_val_a},
        ],
    )
    # Also build post-0x0b chain where key A is later compromised at h_c = 750001 (on update at 750006)!
    brk_aba = {
        "compromised_policy": {"m": 1, "pks": [k_a["xonly"]]},
        "genesis": GENESIS_MAIN,
        "h_c": 750001,
        "issuer": {"name": "id/alice", "registration": fx_aba["_alice_reg"]},
        "name_input": {"txid": u_rot_a2_tx, "vout": 0},
        "role": "grant",
        "type": "seallink-credential-break/1",
    }
    ch_aba_0b = copy.deepcopy(ch_aba)
    ch_aba_0b["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_aba["_alice_reg"],
        fx_aba["_alice_owner_pol"],
        alice_val_a,
        first_height=748000,
        update_height=749000,
        extra_updates=[
            {"confirmed_height": 749995, "txid": u_rot_b_tx, "value": alice_val_b},
            {"confirmed_height": 750000, "txid": u_rot_a2_tx, "value": alice_val_a},
            {"confirmed_height": 750006, "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_aba).hex(), 0x00, h_c=750001).hex(), "txid": _h32("l1-aba-0b"), "value": alice_val_a},
        ],
    )
    add(
        "d10-l1-aba-rotation-epoch-and-cause-keyed-role-closures",
        ["SL-IDEN-004", "SL-CONT-009", "SL-GRNT-014"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("l1-aba-j")},
            "steps": [
                # 1. Old grant from before A->B rotation at 749995 refuses NAME_ROLE_CHANGED & writes retired_before_height=749995
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_aba["bundle"], "chain": ch_aba, "executor_cfg": fx_aba["executor_cfg"], "expect_closures_delta": 1, "invocation": inv_aba_old, "kind": "invocation", "label": "old-pre-rot-refuse", "want_refusal": "NAME_ROLE_CHANGED", "want_verdict": "REFUSE"},
                # 2. Re-presenting old grant hits persisted NAME_ROLE_CHANGED idempotently (0 new writes!)
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_aba["bundle"], "chain": ch_aba, "executor_cfg": fx_aba["executor_cfg"], "expect_entries_delta": 0, "invocation": inv_aba_old, "kind": "invocation", "label": "old-pre-rot-cached", "want_refusal": "NAME_ROLE_CHANGED", "want_verdict": "REFUSE"},
                # 3. New grant from restored epoch (recent_block=750002 >= 749995) ADMITS identically on stateful & fresh server!
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": bundle_aba_new, "chain": ch_aba, "executor_cfg": fx_aba["executor_cfg"], "invocation": inv_aba_new, "kind": "invocation", "label": "new-post-restore-admit", "want_refusal": None, "want_verdict": "ADMIT"},
                # 4. Restart journal cleanly preserving retired_before_height!
                {"kind": "replay_restart", "label": "restart"},
                # 5. Later 0x0b compromise of key A records separate CRED_ISSUER_CLOSED closure without overwriting NAME_ROLE_CHANGED!
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": bundle_aba_new, "chain": ch_aba_0b, "executor_cfg": fx_aba["executor_cfg"], "expect_closures_delta": 1, "invocation": sl.sign_envelope({**inv_aba_new["payload"], "nonce": _h32("l1-aba-n-new2")}, [fx_aba["_keys"]["agent_req"]["sk"]]), "kind": "invocation", "label": "post-0x0b-cred-issuer-closed", "want_refusal": "CRED_ISSUER_CLOSED", "want_verdict": "REFUSE"},
                # 6. Both closures coexist: persisted CRED_ISSUER_CLOSED refuses on replay with 0 extra entries!
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": bundle_aba_new, "chain": ch_aba_0b, "executor_cfg": fx_aba["executor_cfg"], "expect_entries_delta": 0, "invocation": sl.sign_envelope({**inv_aba_new["payload"], "nonce": _h32("l1-aba-n-new3")}, [fx_aba["_keys"]["agent_req"]["sk"]]), "kind": "invocation", "label": "post-0x0b-cached", "want_refusal": "CRED_ISSUER_CLOSED", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "L1: A->B->A role rotation uses retired_before_height for stateful/fresh consistency, and cause-keyed role closures separate NAME_ROLE_CHANGED from 0x0b CRED_ISSUER_CLOSED.",
    )
    # Also test mempool role change -> retired_before_height = tip_height + 1 (kills _first_role_change_height mempool return!)
    ch_mem_rot = copy.deepcopy(fx_aba["chain"])
    mem_rot_spk, _ = sl.compile_script_policy(fx_aba["_alice_owner_pol"])
    mem_rot_out = sl.encode_name_output("NAME_UPDATE", mem_rot_spk, name=b"id/alice", value=sl.jcs_encode(alice_val_b))
    last_u_a = ch_mem_rot["names"]["id/alice"]["updates"][-1]
    ch_mem_rot["names"]["id/alice"]["mempool_updates"] = [{
        "op": "NAME_UPDATE",
        "output_script_hex": mem_rot_out.hex(),
        "owner_policy": fx_aba["_alice_owner_pol"],
        "prev_input": {"sighash_bytes": [0x01], "txid": last_u_a["txid"], "vout": last_u_a["vout"], "witness_policy": fx_aba["_alice_owner_pol"]},
        "txid": _h32("l1-mem-rot-tx"),
        "vout": 0,
    }]
    add(
        "d10-l1-mempool-role-rotation-refuse",
        ["SL-IDEN-004"],
        "invocation",
        {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_aba["bundle"], "chain": ch_mem_rot, "executor_cfg": fx_aba["executor_cfg"], "invocation": inv_aba_old, "journal": {"journal_id": _h32("l1-memrot-j")}},
        "REFUSE",
        "NAME_ROLE_CHANGED",
        "L1: Mempool OP_NAME_UPDATE rotating link.grant refuses NAME_ROLE_CHANGED and records retired_before_height = tip_height + 1.",
    )

    # L1-6: Emancipation x-coordinate negated pubkey (02X vs 03X) & missing block_time (bu_bt is None) fail closed!
    of_neg = rm._base_origin_fixture()
    init_comp = of_neg["origin_bundle"]["origin"]["payload"]["claims"]["intended_owner_policy"]["pks"][0]
    neg_comp = ("03" if init_comp.startswith("02") else "02") + init_comp[2:]
    neg_pol = {"kind": "key", "pk": neg_comp}
    of_neg_cap_tx = _h32("l1-neg-cap-tx")
    op_neg = of_neg["origin_bundle"]["origin"]["payload"]
    cap_neg_p = {
        "basis_sha256": _h32("l1-neg-basis"),
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "issuer": op_neg["issuer"],
        "network": "main",
        "next_status_policy": op_neg["status_seal"]["script_policy"],
        "next_status_vout": 0,
        "origin_id": sl.object_id(op_neg),
        "status_prev_outpoint": {"txid": op_neg["status_seal"]["txid"], "vout": op_neg["status_seal"]["vout"]},
        "subject_new_owner_policy": neg_pol,
        "type": "seallink-capacity/1",
    }
    cap_neg = sl.sign_envelope(cap_neg_p, [of_neg["_keys"]["reg_cred"]["sk"]])
    of_neg["origin_bundle"]["capacity_record"] = cap_neg
    of_neg["chain"]["txs"][op_neg["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = of_neg_cap_tx
    of_neg["chain"]["txs"][of_neg_cap_tx] = {
        "confirmed_height": 750050,
        "inputs": [sv.make_segwit_input(op_neg["status_seal"]["txid"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_neg)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(op_neg["status_seal"]["script_policy"])}},
    }
    of_neg["chain"]["names"]["id/child-leo"] = sv.make_name_history(
        "id/child-leo",
        of_neg["origin_bundle"]["name_binding"]["registration"],
        op_neg["claims"]["intended_owner_policy"],
        {"link": {"origin": sl.object_id(op_neg)}},
        first_height=749005,
        update_height=749015,
        extra_updates=[
            {"confirmed_height": 750060, "owner_policy": neg_pol, "txid": _h32("l1-neg-xfer"), "value": {"link": {"origin": sl.object_id(op_neg)}}},
            {"confirmed_height": 750070, "owner_policy": neg_pol, "txid": _h32("l1-neg-self"), "value": {"link": {"origin": sl.object_id(op_neg)}}},
        ],
    )
    add(
        "d10-l1-emancipation-negated-xcoord-pubkey-refuse",
        ["SL-ORIG-014", "SL-LDGR-004"],
        "origin_status",
        {"chain": of_neg["chain"], "origin_bundle": of_neg["origin_bundle"], "trusted_origin_issuer_pins": of_neg["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_TRANSFER_PENDING",
        "L1: Emancipation handover to negated secp256k1 point (03X vs 02X, identical x-coordinate) MUST fail closed GUARDIAN_TRANSFER_PENDING.",
    )

    # Missing block_time on ward name update -> conservatively treated as pre-majority (fail closed!)
    of_nobt = rm._base_origin_fixture()
    op_nb = of_nobt["origin_bundle"]["origin"]["payload"]
    k_mid_guard = _kp("l1-nobt-mid-guard")
    pol_mid_guard = {"kind": "key", "pk": k_mid_guard["comp"]}
    cap_nb_p = {
        "basis_sha256": _h32("l1-nobt-basis"),
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "issuer": op_nb["issuer"],
        "network": "main",
        "next_status_policy": op_nb["status_seal"]["script_policy"],
        "next_status_vout": 0,
        "origin_id": sl.object_id(op_nb),
        "status_prev_outpoint": {"txid": op_nb["status_seal"]["txid"], "vout": op_nb["status_seal"]["vout"]},
        "subject_new_owner_policy": pol_mid_guard,
        "type": "seallink-capacity/1",
    }
    cap_nb = sl.sign_envelope(cap_nb_p, [of_nobt["_keys"]["reg_cred"]["sk"]])
    nb_cap_tx = _h32("l1-nobt-cap-tx")
    of_nobt["origin_bundle"]["capacity_record"] = cap_nb
    of_nobt["chain"]["txs"][op_nb["status_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = nb_cap_tx
    of_nobt["chain"]["txs"][nb_cap_tx] = {
        "confirmed_height": 750050,
        "inputs": [sv.make_segwit_input(op_nb["status_seal"]["txid"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_nb)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(op_nb["status_seal"]["script_policy"])}},
    }
    # Update at 750040 (< h_cap) has NO block_time -> MUST be added to pre_trigger_pks (blocking reuse of pol_mid_guard at 750060!)
    of_nobt["chain"]["names"]["id/child-leo"] = sv.make_name_history(
        "id/child-leo",
        of_nobt["origin_bundle"]["name_binding"]["registration"],
        op_nb["claims"]["intended_owner_policy"],
        {"link": {"origin": sl.object_id(op_nb)}},
        first_height=749005,
        update_height=749015,
        extra_updates=[
            {"confirmed_height": 750040, "owner_policy": pol_mid_guard, "txid": _h32("l1-nobt-pre"), "value": {"link": {"origin": sl.object_id(op_nb)}}},
            {"confirmed_height": 750060, "owner_policy": pol_mid_guard, "txid": _h32("l1-nobt-post"), "value": {"link": {"origin": sl.object_id(op_nb)}}},
            {"confirmed_height": 750070, "owner_policy": pol_mid_guard, "txid": _h32("l1-nobt-self"), "value": {"link": {"origin": sl.object_id(op_nb)}}},
        ],
    )
    add(
        "d10-l1-emancipation-missing-block-time-fail-closed",
        ["SL-ORIG-014"],
        "origin_status",
        {"chain": of_nobt["chain"], "origin_bundle": of_nobt["origin_bundle"], "trusted_origin_issuer_pins": of_nobt["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_TRANSFER_PENDING",
        "L1: Confirmed ward update with omitted block_time MUST conservatively join pre_trigger_pks (fail closed GUARDIAN_TRANSFER_PENDING).",
    )

    # L1-7: SPEC-05 §4.2 & §5 anchor check runs BEFORE persisted journal closure!
    j_cr_l1 = sv.FencedJournal(_h32("l1-cr-j"))
    j_cr_l1.record_closure({"subject_id": sl.object_id(sl_cred_p), "subject_kind": "credential"}, "CRED_REVOKED_FOR_CAUSE", observed_at=fx_h15["chain"]["now"], observed_height=fx_h15["chain"]["tip_height"])
    add(
        "d10-l1-credential-missing-anchor-before-persisted-closure",
        ["SL-CONT-010"],
        "credential",
        {"anchor_txid": _h32("l1-missing-anchor"), "chain": fx_h15["chain"], "credential": sl_cred_env, "journal": {"closures": j_cr_l1.closures, "journal_id": j_cr_l1.journal_id}},
        "REFUSE",
        "CRED_ANCHOR_MISSING",
        "L1 (SPEC-05 §4.2): Missing 0x09 anchor MUST refuse CRED_ANCHOR_MISSING (Step 4) before persisted credential closure (Step 8).",
    )

    # L1-8: Bearer sessions hardening (Class-1 risk_class freshness, reorged proof_path anchor, 0x02 batch anchor, missing target)
    fx_bs_l1 = rm._base_invocation_fixture()
    gp_bs_l1 = copy.deepcopy(fx_bs_l1["bundle"]["grants"][0]["payload"])
    gp_bs_l1["capabilities"] = [{"action": "mail/read", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}], "target": "mailbox:id/alice:work"}]
    g_bs_l1, gid_bs_l1 = _reanchor(fx_bs_l1, gp_bs_l1)
    itx_bs_l1 = fx_bs_l1["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    so_bs_l1 = sl.sign_envelope(
        {"executor": fx_bs_l1["invocation"]["payload"]["executor"], "exp": fx_bs_l1["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "iat": fx_bs_l1["chain"]["now"], "network": "main", "nonce": _h32("l1-bs-n1"), "op": "open", "proof_path": [{"grant_id": gid_bs_l1, "issuance_txid": itx_bs_l1}], "quotas": [], "slot_binding": "slot-bs-l1", "type": "seallink-session-open/1"},
        [fx_bs_l1["_keys"]["agent_req"]["sk"]],
    )
    ch_bs_reorg = copy.deepcopy(fx_bs_l1["chain"])
    ch_bs_reorg["txs"].pop(itx_bs_l1, None)
    ch_bs_4000s = copy.deepcopy(fx_bs_l1["chain"])
    ch_bs_4000s["tip_header_time"] = ch_bs_4000s["now"] - 4000
    ch_bs_4000s["tip_first_sight"] = ch_bs_4000s["now"] - 4000
    add(
        "d10-l1-bearer-reorged-anchor-and-missing-target-refuse",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs_l1["executor_cfg"],
            "journal": {"journal_id": _h32("l1-bs-j1")},
            "steps": [
                {"bundle": fx_bs_l1["bundle"], "chain": fx_bs_l1["chain"], "kind": "session_open", "label": "open", "session_open": so_bs_l1, "want_refusal": None, "want_verdict": "ADMIT"},
                {"kind": "replay_restart", "label": "restart-preserves-proof-path"},
                # mail/read is risk_class=2 (5400s cutoff) -> 4000s tip age ADMITS!
                {"action": "mail/read", "arguments": {"folder": "Inbox", "message_id": "m1"}, "chain": ch_bs_4000s, "grant_env": g_bs_l1, "kind": "bearer_session", "label": "class2-4000s-admit", "slot_binding": "slot-bs-l1", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
                # Reorged-out issuance_txid in persisted proof_path -> SESSION_INVALID!
                {"action": "mail/read", "arguments": {"folder": "Inbox", "message_id": "m2"}, "chain": ch_bs_reorg, "expect_zero_writes": True, "grant_env": g_bs_l1, "kind": "bearer_session", "label": "reorged-anchor-refuse", "slot_binding": "slot-bs-l1", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                # Missing target -> SESSION_INVALID!
                {"action": "mail/read", "arguments": {"folder": "Inbox", "message_id": "m3"}, "chain": fx_bs_l1["chain"], "expect_zero_writes": True, "grant_env": g_bs_l1, "kind": "bearer_session", "label": "missing-target-refuse", "slot_binding": "slot-bs-l1", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "L1 (SPEC-06 §5): Bearer session persists proof_path across restart, re-verifies active-chain anchor against reorgs, allows Class-2 4000s freshness, and refuses missing target with SESSION_INVALID.",
        module="bearer-sessions",
    )
    # Class-1 bearer session (agent/session) at 4000s tip age -> MUST refuse CHAIN_TIP_STALE (> 3600s)!
    add(
        "d10-l1-bearer-class1-action-4000s-tip-stale",
        ["SL-GRNT-013", "SL-LDGR-008"],
        "bearer_session",
        {"action": "agent/session", "arguments": {"config_sha256": _h32("cfg"), "op": "start", "session_slot": "s1"}, "chain": ch_bs_4000s, "journal": {"journal_id": _h32("l1-bs-j2")}, "slot_binding": "slot-bs-l1", "target": "station:id/s:s1", "token": _h32("l1-tok-c1")},
        "REFUSE",
        "CHAIN_TIP_STALE",
        "L1 (SPEC-06 §5): Bearer session for Class-1 action (agent/session) MUST enforce 3600s Class-1 chain freshness (refusing CHAIN_TIP_STALE at 4000s).",
        module="bearer-sessions",
    )
    # 0x02 batch-anchored root grant bearer session (kills _verify_issuance_anchor_live 0x02 branch!)
    fx_bs02 = rm._base_invocation_fixture()
    g_bs02 = fx_bs02["bundle"]["grants"][0]
    gp_bs02 = g_bs02["payload"]
    gid_bs02 = sl.object_id(gp_bs02)
    iss_dig_02 = sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_bs02), "grant_id": gid_bs02, "type": "seallink-issuance/1"}).hex()
    mroot_02, mproofs_02 = sl.build_merkle_tree([iss_dig_02, _h32("l1-bs02-other")])
    itx_02 = fx_bs02["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx_bs02["chain"]["txs"][itx_02]["opreturn_hex"] = sl.encode_opreturn(0x02, mroot_02, 0x00).hex()
    so_bs02 = sl.sign_envelope(
        {"executor": fx_bs02["invocation"]["payload"]["executor"], "exp": fx_bs02["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "iat": fx_bs02["chain"]["now"], "network": "main", "nonce": _h32("l1-bs02-n"), "op": "open", "proof_path": [{"batch_proof": mproofs_02[iss_dig_02], "grant_id": gid_bs02, "issuance_txid": itx_02}], "quotas": [], "slot_binding": "slot-bs02", "type": "seallink-session-open/1"},
        [fx_bs02["_keys"]["agent_req"]["sk"]],
    )
    ch_bs02_bad = copy.deepcopy(fx_bs02["chain"])
    ch_bs02_bad["txs"][itx_02]["opreturn_hex"] = sl.encode_opreturn(0x02, _h32("l1-bs02-wrong-root"), 0x00).hex()
    ch_bs02_wrong_act = copy.deepcopy(fx_bs02["chain"])
    ch_bs02_wrong_act["txs"][itx_02]["opreturn_hex"] = sl.encode_opreturn(0x09, mroot_02, 0x00).hex()
    add(
        "d10-l1-bearer-0x02-batch-anchor-recheck",
        ["SL-GRNT-013", "SL-LDGR-014"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs02["executor_cfg"],
            "journal": {"journal_id": _h32("l1-bs02-j")},
            "steps": [
                {"bundle": fx_bs02["bundle"], "chain": fx_bs02["chain"], "kind": "session_open", "label": "open-0x02", "session_open": so_bs02, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": fx_bs02["chain"], "grant_env": g_bs02, "kind": "bearer_session", "label": "use-0x02-admit", "slot_binding": "slot-bs02", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m2"}, "chain": ch_bs02_bad, "expect_zero_writes": True, "grant_env": g_bs02, "kind": "bearer_session", "label": "use-0x02-wrong-root", "slot_binding": "slot-bs02", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m3"}, "chain": ch_bs02_wrong_act, "expect_zero_writes": True, "grant_env": g_bs02, "kind": "bearer_session", "label": "use-wrong-opret-action", "slot_binding": "slot-bs02", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "L1 (SPEC-06 §5): Bearer session re-verifies 0x02 batch-anchored root grant proof_path on live use and refuses corrupted root or wrong action byte.",
        module="bearer-sessions",
    )

    # L1-9: Service migration hardening (D10-2 + benign prose filename + confirmed predecessor spend + dest_accept_stmt issuer)
    m_inv_prose = {"holder_name": "id/alice", "items": [{"media_type": "text/markdown", "path": "notes/history-of-private-keys.md", "sha256": _h32("l1-prose"), "size_bytes": "512"}], "migration_id": mid_10, "service_type": "mail"}
    m_p_prose = {**m_p, "inventory_sha256": sl.sha256(sl.jcs_encode(m_inv_prose)).hex()}
    m_env_prose = sl.sign_envelope(m_p_prose, [fx_mig["_keys"]["host_rcpt"]["sk"]])
    add(
        "d10-l1-migration-benign-prose-filename-stage-admit",
        ["SL-SERV-003"],
        "migration",
        {"chain": ch_mig_ok, "export_bundle": {"inventory": m_inv_prose, "source_journal_commitment": m_jc, "source_journal_pos": 1}, "journal": {"journal_id": _h32("l1-mig-j0")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env_prose, "mode": "stage"},
        "ADMIT",
        None,
        "L1 (SPEC-07 §2.1): Structured secret blocklist MUST permit benign user prose like notes/history-of-private-keys.md (text/markdown).",
        module="service-migration",
    )
    m_inv_pem_mt = {"holder_name": "id/alice", "items": [{"media_type": "application/x-pem-file", "path": "docs/readme.txt", "sha256": _h32("l1-pem-mt"), "size_bytes": "64"}], "migration_id": mid_10, "service_type": "mail"}
    m_p_pem_mt = {**m_p, "inventory_sha256": sl.sha256(sl.jcs_encode(m_inv_pem_mt)).hex()}
    m_env_pem_mt = sl.sign_envelope(m_p_pem_mt, [fx_mig["_keys"]["host_rcpt"]["sk"]])
    add(
        "d10-l1-migration-forbidden-pem-media-type-refuse",
        ["SL-SERV-003"],
        "migration",
        {"chain": ch_mig_ok, "export_bundle": {"inventory": m_inv_pem_mt, "source_journal_commitment": m_jc, "source_journal_pos": 1}, "journal": {"journal_id": _h32("l1-mig-j1")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env_pem_mt, "mode": "stage"},
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "L1 (SPEC-07 §2.1): Forbidden execution-credential media_type (application/x-pem-file) MUST refuse SERVICE_MIGRATION_INVALID even on a benign path.",
        module="service-migration",
    )
    # Mempool-only predecessor seal spend (unconfirmed!) MUST refuse SERVICE_MIGRATION_INVALID on activate!
    ch_mig_mem = copy.deepcopy(ch_mig_ok)
    ch_mig_mem["txs"][_h32("d10-mig-pred-sp")]["confirmed_height"] = None
    add(
        "d10-l1-migration-mempool-only-predecessor-spend-refuse",
        ["SL-SERV-003"],
        "migration",
        {"chain": ch_mig_mem, "dest_accept_stmt": m_acc, "export_bundle": eb_10, "holder_assent": m_ha, "journal": {"journal_id": _h32("l1-mig-j2")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate"},
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "L1 (SPEC-07 §2.2): Mempool-only (unconfirmed) predecessor_grant_seals spend MUST NOT satisfy activate postcondition (refuses SERVICE_MIGRATION_INVALID).",
        module="service-migration",
    )
    # Insufficient depth on predecessor seal spend (operator_min_depth=20 > depth=9) MUST refuse SERVICE_MIGRATION_INVALID!
    add(
        "d10-l1-migration-shallow-predecessor-spend-refuse",
        ["SL-SERV-003"],
        "migration",
        {"chain": ch_mig_ok, "dest_accept_stmt": m_acc, "export_bundle": eb_10, "holder_assent": m_ha, "journal": {"journal_id": _h32("l1-mig-j2b")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate", "operator_min_depth": 20},
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "L1 (SPEC-07 §2.2): Predecessor grant seal spend below operator_min_depth MUST refuse SERVICE_MIGRATION_INVALID.",
        module="service-migration",
    )
    # Unrelated origin_bundle presented for migration holder -> ORIGIN_BINDING_INVALID (D10-2!)
    add(
        "d10-l1-migration-unrelated-origin-bundle-refuse",
        ["SL-SERV-003", "SL-ORIG-002"],
        "migration",
        {"chain": {**ch_mig_ok, "names": {**ch_mig_ok["names"], **fx_orig_l1["chain"]["names"]}, "txs": {**ch_mig_ok["txs"], **fx_orig_l1["chain"]["txs"]}, "credible_utc_interval": fx_orig_l1["chain"]["credible_utc_interval"], "tip_median_time_past": fx_orig_l1["chain"]["tip_median_time_past"]}, "dest_accept_stmt": m_acc, "export_bundle": eb_10, "holder_assent": m_ha, "journal": {"journal_id": _h32("l1-mig-j3")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate", "origin_bundle": fx_orig_l1["origin_bundle"], "trusted_origin_issuer_pins": fx_orig_l1["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "L1 (D10-2): Migration with origin_bundle whose effective_binding != holder NamePin MUST refuse ORIGIN_BINDING_INVALID.",
        module="service-migration",
    )
    # dest_accept_stmt with mismatched issuer NamePin (still signed by d_rkey) -> SERVICE_MIGRATION_INVALID!
    m_acc_bad_iss = sl.sign_envelope({**m_acc["payload"], "issuer": fx_mig["executor_cfg"]["pin"]}, [d_rcpt["sk"]])
    add(
        "d10-l1-migration-dest-accept-wrong-issuer-refuse",
        ["SL-SERV-003"],
        "migration",
        {"chain": ch_mig_ok, "dest_accept_stmt": m_acc_bad_iss, "export_bundle": eb_10, "holder_assent": m_ha, "journal": {"journal_id": _h32("l1-mig-j4")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate"},
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "L1: migration-accept statement whose issuer NamePin != dest_executor MUST refuse SERVICE_MIGRATION_INVALID.",
        module="service-migration",
    )

    # L1-10: Federated screening & PII disclosure hardening (D10-1: sealed in both phases, issuer auth, 0x0b, recipient match, optional issuance_txid, ward deferral, L2 nonce anti-replay!)
    add(
        "d10-l1-federation-screening-window-only-refuse",
        ["SL-SERV-004"],
        "federation",
        {"chain": fx_f10["chain"], "grant": gf_wo_env, "journal": {"journal_id": _h32("l1-fed-j1")}, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": base_fed_pol},
        "REFUSE",
        "FEDERATION_POLICY_DENIED",
        "L1 (D10-1 / SPEC-07 §3): Federated screening MUST require a revocable UTXO seal (window_only refuses FEDERATION_POLICY_DENIED).",
        module="federated-screening",
    )
    attacker_fed = _kp("l1-fed-attacker")
    gf_forged = sl.sign_envelope(gf_p, [attacker_fed["sk"]])
    add(
        "d10-l1-federation-screening-forged-grant-sig-refuse",
        ["SL-SERV-004", "SL-IDEN-003"],
        "federation",
        {"chain": fx_f10["chain"], "grant": gf_forged, "journal": {"journal_id": _h32("l1-fed-j2")}, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": base_fed_pol},
        "REFUSE",
        "WIRE_SIGNATURE",
        "L1 (D10-1): Federated screening with attacker-signed grant not matching issuer's confirmed link.grant MUST refuse WIRE_SIGNATURE.",
        module="federated-screening",
    )
    add(
        "d10-l1-federation-screening-wrong-named-peer-refuse",
        ["SL-SERV-004"],
        "federation",
        {"chain": fx_f10["chain"], "grant": gf_env, "journal": {"journal_id": _h32("l1-fed-j3")}, "peer_ctx": {"peer_id": "id/peer-other", "phase": "screening"}, "policy": {"trusted_peers": ["id/peer-b", "id/peer-other"]}},
        "REFUSE",
        "FEDERATION_POLICY_DENIED",
        "L1 (D10-1): Federated screening with named recipient MUST match peer_id == recipient.name (even if peer-other is in trusted_peers).",
        module="federated-screening",
    )
    # Screening with rotated link.grant -> NAME_ROLE_CHANGED; with 0x0b break -> CRED_ISSUER_CLOSED!
    ch_f10_rot = copy.deepcopy(fx_f10["chain"])
    k_frot = _kp("l1-fed-rot-k")
    ch_f10_rot["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_f10["_alice_reg"],
        fx_f10["_alice_owner_pol"],
        {"link": {"grant": fx_f10["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_f10["_alice_man"]), "s": 1}},
        first_height=748000,
        update_height=749000,
        extra_updates=[{"confirmed_height": 750002, "txid": _h32("l1-fed-rot-u"), "value": {"link": {"grant": k_frot["xonly"]}, "m": {"h": sl.content_addr(fx_f10["_alice_man"]), "s": 1}}}],
    )
    add(
        "d10-l1-federation-screening-rotated-role-refuse",
        ["SL-SERV-004", "SL-IDEN-004"],
        "federation",
        {"chain": ch_f10_rot, "grant": gf_env, "journal": {"journal_id": _h32("l1-fed-j4")}, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": base_fed_pol},
        "REFUSE",
        "NAME_ROLE_CHANGED",
        "L1 (D10-1): Federated screening MUST refuse NAME_ROLE_CHANGED when issuer rotated link.grant after grant.recent_block.",
        module="federated-screening",
    )
    ch_f10_0b = copy.deepcopy(fx_f10["chain"])
    u_prev_f10 = ch_f10_0b["names"]["id/alice"]["updates"][-1]
    brk_f10 = {
        "compromised_policy": {"m": 1, "pks": [fx_f10["_keys"]["alice_gr"]["xonly"]]},
        "genesis": GENESIS_MAIN,
        "h_c": 750001,
        "issuer": {"name": "id/alice", "registration": fx_f10["_alice_reg"]},
        "name_input": {"txid": u_prev_f10["txid"], "vout": u_prev_f10["vout"]},
        "role": "grant",
        "type": "seallink-credential-break/1",
    }
    ch_f10_0b["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_f10["_alice_reg"],
        fx_f10["_alice_owner_pol"],
        {"link": {"grant": fx_f10["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_f10["_alice_man"]), "s": 1}},
        first_height=748000,
        update_height=749000,
        extra_updates=[{"confirmed_height": 750005, "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_f10).hex(), 0x00, h_c=750001).hex(), "txid": _h32("l1-fed-0b-u"), "value": {"link": {"grant": fx_f10["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_f10["_alice_man"]), "s": 1}}}],
    )
    add(
        "d10-l1-federation-screening-0x0b-compromised-refuse",
        ["SL-SERV-004", "SL-CONT-009"],
        "federation",
        {"chain": ch_f10_0b, "grant": gf_env, "journal": {"journal_id": _h32("l1-fed-j5")}, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": base_fed_pol},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "L1 (D10-1): Federated screening MUST refuse CRED_ISSUER_CLOSED when issuer link.grant has a confirmed 0x0b compromise break <= tip_height.",
        module="federated-screening",
    )
    # Screening with issuance_txid anchor present (invalid anchor -> CHAIN_FRAME_INVALID!)
    add(
        "d10-l1-federation-screening-bad-issuance-anchor-refuse",
        ["SL-SERV-004"],
        "federation",
        {"chain": fx_f10["chain"], "grant": gf_env, "journal": {"journal_id": _h32("l1-fed-j6")}, "peer_ctx": {"issuance_txid": _h32("l1-fed-missing-itx"), "peer_id": "id/peer-b", "phase": "screening"}, "policy": base_fed_pol},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "L1 (D10-1): Federated screening supplying an unanchored/missing issuance_txid MUST refuse CHAIN_FRAME_INVALID.",
        module="federated-screening",
    )
    # L2 PII disclosure single-use nonce anti-replay in multi_step_journal: 1st call ADMIT (writes nonce), 2nd call -> INVOKE_REPLAY!
    add(
        "d10-l1-federation-pii-nonce-replay-refuse",
        ["SL-SERV-004"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("l1-fed-j7")},
            "steps": [
                {"chain": fx_f10["chain"], "expect_entries_delta": 1, "grant": gf_env, "kind": "federation", "label": "first-pii-admit", "peer_ctx": base_fed_ctx, "policy": base_fed_pol, "want_refusal": None, "want_verdict": "ADMIT"},
                {"chain": fx_f10["chain"], "expect_entries_delta": 0, "grant": gf_env, "kind": "federation", "label": "replay-pii-refuse", "peer_ctx": base_fed_ctx, "policy": base_fed_pol, "want_refusal": "INVOKE_REPLAY", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "L1 (D10-1 / SPEC-07 §3): Contour A PII disclosure durably records approval_command.nonce in FencedJournal and refuses replay with INVOKE_REPLAY.",
        module="federated-screening",
    )
    # Ward origin in federation: activate slot 2 for 2-of-2 effect_grant quorum -> screening ADMITs, pii_disclosure refuses WARD_AUTONOMOUS_FORBIDDEN (post-v1.0 SLIP)!
    of_wfed = rm._base_origin_fixture()
    w_op_f = of_wfed["origin_bundle"]["origin"]["payload"]
    w_oid_f = sl.object_id(w_op_f)
    g2_own_f, g2_seal_f = rm._kp("o-g2-own"), _kp("l1-wfed-g2-seal")
    g2_pin_f = {"name": "id/parent-b", "owner_policy": {"kind": "key", "pk": g2_own_f["comp"]}, "registration": {"txid": rm._h32("g2-reg"), "vout": 0}}
    act_pol_2f = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(of_wfed["_keys"]["disp"]["comp"], g2_seal_f["comp"])}
    g2_rec_pf = {
        "active_policy": act_pol_2f,
        "active_vout": 0,
        "activation_mode": "initial",
        "genesis": GENESIS_MAIN,
        "guardian": g2_pin_f,
        "issuer": w_op_f["issuer"],
        "network": "main",
        "origin_id": w_oid_f,
        "prev_outpoint": {"txid": rm._h32("os2-vac"), "vout": 0},
        "revision": 1,
        "slot": 2,
        "term": {"ceiling_height": 1750000, "mode": "calendar", "not_after_unix": of_wfed["_maj_unix"]},
        "type": "seallink-guardian/1",
    }
    g2_rec_f = sl.sign_envelope(g2_rec_pf, [of_wfed["_keys"]["reg_cred"]["sk"]])
    g2_assent_f = sl.sign_envelope(
        {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("l1-wfed-g2a"), "party_id": "slot-2", "party_name": "id/parent-b", "party_role": "guardian", "target_id": sl.object_id(g2_rec_pf), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"},
        [of_wfed["_keys"]["g2_gr"]["sk"]],
    )
    g2_init_txf = _h32("l1-wfed-g2-0x12")
    of_wfed["chain"]["names"]["id/parent-b"] = sv.make_name_history("id/parent-b", g2_pin_f["registration"], g2_pin_f["owner_policy"], {"link": {"grant": of_wfed["_keys"]["g2_gr"]["xonly"]}}, first_height=748000, update_height=748600)
    of_wfed["chain"]["txs"][rm._h32("os2-vac")]["outputs"]["0"]["spent_by_txid"] = g2_init_txf
    of_wfed["chain"]["txs"][g2_init_txf] = {"confirmed_height": 749020, "opreturn_hex": sl.encode_opreturn(0x12, sl.content_addr(g2_rec_f)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_pol_2f)}}}
    of_wfed["origin_bundle"]["guardian_records"].append(g2_rec_f)
    of_wfed["origin_bundle"]["guardian_assents"].append(g2_assent_f)
    of_wfed["origin_bundle"]["initial_guardian_disclosures"]["2"] = {"name_pin": g2_pin_f, "salt_hex": rm._h32("salt-g2")}

    w_seal_k = _kp("l1-wfed-seal")
    w_seal_pol = {"kind": "key", "pk": w_seal_k["comp"]}
    w_seal_tx = _h32("l1-wfed-stx")
    w_recent_blk = _h32("l1-wfed-rblk")
    of_wfed["chain"]["blocks"][w_recent_blk] = 750090
    of_wfed["chain"]["txs"][w_seal_tx] = {"confirmed_height": 750095, "outputs": {"0": {"script_pubkey_hex": _spk_hex(w_seal_pol)}}}
    w_fed_gp = {
        "capabilities": [{"action": "mail/list", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/child-leo:inbox", "unit": "lists", "window": "term"}], "target": "mailbox:id/child-leo:inbox"}],
        "executor": {"key": fx_f10["_keys"]["host_rcpt"]["xonly"], "name": "id/mail-host-a"},
        "genesis": GENESIS_MAIN,
        "guardian_context": {"event_class": "effect_grant", "origin_id": w_oid_f, "revision": 1, "ward_name": "id/child-leo"},
        "issuer": {"name": "id/child-leo", "owner_policy": w_op_f["claims"]["intended_owner_policy"], "registration": of_wfed["origin_bundle"]["name_binding"]["registration"]},
        "min_depth": 1,
        "network": "main",
        "not_after_height": 751000,
        "not_before_height": 750000,
        "recent_block": w_recent_blk,
        "recipient": {"mode": "name", "name": "id/peer-b", "owner_policy": fx_f10["_host_owner_pol"], "registration": fx_f10["_host_reg"]},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": w_seal_pol, "txid": w_seal_tx, "vout": 0}},
        "type": "seallink-grant/1",
    }
    w_fed_env = {
        "guardian_approvals": [
            {"guardian_name": "id/parent-a", "revision": 1, "signatures": sl.sign_envelope(w_fed_gp, [of_wfed["_keys"]["g1_gr"]["sk"]])["signatures"], "slot": 1},
            {"guardian_name": "id/parent-b", "revision": 1, "signatures": sl.sign_envelope(w_fed_gp, [of_wfed["_keys"]["g2_gr"]["sk"]])["signatures"], "slot": 2},
        ],
        "payload": w_fed_gp,
    }
    add(
        "d10-l1-federation-ward-screening-admit",
        ["SL-SERV-004", "SL-ORIG-006"],
        "federation",
        {"chain": of_wfed["chain"], "grant": w_fed_env, "journal": {"journal_id": _h32("l1-wfed-j1")}, "peer_ctx": {"origin_bundle": of_wfed["origin_bundle"], "peer_id": "id/peer-b", "phase": "screening"}, "policy": base_fed_pol, "trusted_origin_issuer_pins": of_wfed["trusted_origin_issuer_pins"]},
        "ADMIT",
        None,
        "L1 (D10-1): Ward-origin federated screening with valid guardian_approvals and active origin_bundle admits cleanly.",
        module="federated-screening",
    )
    add(
        "d10-l1-federation-ward-pii-deferred-refuse",
        ["SL-SERV-004", "SL-ORIG-006"],
        "federation",
        {"chain": of_wfed["chain"], "grant": w_fed_env, "journal": {"journal_id": _h32("l1-wfed-j2")}, "peer_ctx": {"fields_sha256": _h32("wf"), "origin_bundle": of_wfed["origin_bundle"], "phase": "pii_disclosure", "route_hops": [{"actor": "id/peer-b", "role": "recipient"}]}, "policy": base_fed_pol, "trusted_origin_issuer_pins": of_wfed["trusted_origin_issuer_pins"]},
        "REFUSE",
        "WARD_AUTONOMOUS_FORBIDDEN",
        "L1 (SPEC-07 §3): Ward-only pii_disclosure is deferred to a post-v1.0 SLIP and MUST refuse WARD_AUTONOMOUS_FORBIDDEN in v1.0.",
        module="federated-screening",
    )
    add(
        "d10-l1-federation-ward-missing-origin-bundle-refuse",
        ["SL-SERV-004", "SL-ORIG-002"],
        "federation",
        {"chain": of_wfed["chain"], "grant": w_fed_env, "journal": {"journal_id": _h32("l1-wfed-j3")}, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": base_fed_pol, "trusted_origin_issuer_pins": of_wfed["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "L1 (D10-1): Origin-certified issuer in federation omitting origin_bundle MUST refuse ORIGIN_UNVERIFIED.",
        module="federated-screening",
    )

    # L1-11: Exact boundary & branch-coverage regressions (100% 3-operator mutation kill across Layer 1)
    # 1. FencedJournal.record_closure idempotency & monotonic tightening (kills boundary L932 & L937)
    rc_base_subj = {
        "name": "id/alice",
        "policy_sha256": sv._policy_sha256({"m": 1, "pks": [k_a["xonly"]]}),
        "registration": fx_aba["_alice_reg"],
        "role": "grant",
        "subject_kind": "role",
    }
    add(
        "d10-l1-role-closure-idempotency-and-monotonic-tightening",
        ["SL-CONT-009", "SL-IDEN-004", "SL-GRNT-014"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("l1-rc-idem-j")},
            "steps": [
                {"cause": "CRED_ISSUER_CLOSED", "expect_entries_delta": 1, "kind": "record_closure", "label": "hc-init", "observed_at": 1795220000, "observed_height": 750010, "subject": {**rc_base_subj, "cutoff_height": 749400}},
                {"cause": "CRED_ISSUER_CLOSED", "expect_entries_delta": 0, "kind": "record_closure", "label": "hc-same-idem", "observed_at": 1795220001, "observed_height": 750010, "subject": {**rc_base_subj, "cutoff_height": 749400}},
                {"cause": "CRED_ISSUER_CLOSED", "expect_entries_delta": 1, "kind": "record_closure", "label": "hc-earlier-tighten", "observed_at": 1795220002, "observed_height": 750010, "subject": {**rc_base_subj, "cutoff_height": 749300}},
                {"cause": "NAME_ROLE_CHANGED", "expect_entries_delta": 1, "kind": "record_closure", "label": "rbh-init", "observed_at": 1795220003, "observed_height": 750010, "subject": {**rc_base_subj, "retired_before_height": 749995}},
                {"cause": "NAME_ROLE_CHANGED", "expect_entries_delta": 0, "kind": "record_closure", "label": "rbh-same-idem", "observed_at": 1795220004, "observed_height": 750010, "subject": {**rc_base_subj, "retired_before_height": 749995}},
                {"cause": "NAME_ROLE_CHANGED", "expect_entries_delta": 1, "kind": "record_closure", "label": "rbh-later-tighten", "observed_at": 1795220005, "observed_height": 750010, "subject": {**rc_base_subj, "retired_before_height": 750000}},
            ],
        },
        "ADMIT",
        None,
        "L1: FencedJournal.record_closure is idempotent on equal cutoff_height / retired_before_height (0 writes) and tightens monotonically.",
    )

    # 2. _first_role_change_height baseline at exact uh == recent_block_height (kills boundary L2208)
    blk_749995 = _h32("l1-b-749995")
    blk_749996 = _h32("l1-b-749996")
    ch_b_exact = copy.deepcopy(fx_aba["chain"])
    ch_b_exact["blocks"][blk_749995] = 749995
    ch_b_exact["blocks"][blk_749996] = 749996
    ch_b_exact["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_aba["_alice_reg"],
        fx_aba["_alice_owner_pol"],
        alice_val_a,
        first_height=748000,
        update_height=749000,
        extra_updates=[
            {"confirmed_height": 749995, "txid": _h32("l1-bex-u1"), "value": alice_val_b},
            {"confirmed_height": 749998, "txid": _h32("l1-bex-u2"), "value": alice_val_a},
        ],
    )
    gp_b1 = copy.deepcopy(g_aba_old["payload"])
    gp_b1["recent_block"] = blk_749995
    gp_b1["issuer"]["role_policy"] = {"m": 1, "pks": [k_b["xonly"]]}
    g_b1 = sl.sign_envelope(gp_b1, [k_b["sk"]])
    gid_b1 = sl.object_id(gp_b1)
    inv_b1 = sl.sign_envelope({**inv_aba_old["payload"], "nonce": _h32("l1-bex-n1"), "proof_path": [{"grant_id": gid_b1, "issuance_txid": _h32("l1-bex-itx1")}]}, [fx_aba["_keys"]["agent_req"]["sk"]])
    gp_b2 = copy.deepcopy(g_aba_old["payload"])
    gp_b2["recent_block"] = blk_749996
    gp_b2["issuer"]["role_policy"] = {"m": 1, "pks": [k_b["xonly"]]}
    g_b2 = sl.sign_envelope(gp_b2, [k_b["sk"]])
    gid_b2 = sl.object_id(gp_b2)
    inv_b2 = sl.sign_envelope({**inv_aba_old["payload"], "nonce": _h32("l1-bex-n2"), "proof_path": [{"grant_id": gid_b2, "issuance_txid": _h32("l1-bex-itx2")}]}, [fx_aba["_keys"]["agent_req"]["sk"]])
    add(
        "d10-l1-role-change-baseline-at-exact-recent-block",
        ["SL-IDEN-004"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("l1-bex-j")},
            "steps": [
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": {**fx_aba["bundle"], "grants": [g_b1]}, "chain": ch_b_exact, "executor_cfg": fx_aba["executor_cfg"], "expect_entries_delta": 1, "invocation": inv_b1, "kind": "invocation", "label": "b-at-749995-records-749998", "want_refusal": "NAME_ROLE_CHANGED", "want_verdict": "REFUSE"},
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": {**fx_aba["bundle"], "grants": [g_b2]}, "chain": ch_b_exact, "executor_cfg": fx_aba["executor_cfg"], "expect_entries_delta": 0, "invocation": inv_b2, "kind": "invocation", "label": "b-at-749996-hits-persisted-749998", "want_refusal": "NAME_ROLE_CHANGED", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "L1: _first_role_change_height treats uh == recent_block_height as baseline so rotation at 749998 (not 749995) is recorded as retired_before_height.",
    )

    # 3 & 4. Same-block A->B->A at 749995 with root_recent_h == retired_before_height == 749995 (kills L5199 & L6498)
    ch_aba_sb = copy.deepcopy(fx_aba["chain"])
    ch_aba_sb["blocks"][blk_749995] = 749995
    sb_seal_tx = _h32("l1-sb-seal")
    sb_iss_tx = _h32("l1-sb-iss")
    gp_aba_sb = copy.deepcopy(g_aba_old["payload"])
    gp_aba_sb["recent_block"] = blk_749995
    gp_aba_sb["revocation"] = {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": seal_pol_aba, "txid": sb_seal_tx, "vout": 0}}
    g_aba_sb = sl.sign_envelope(gp_aba_sb, [k_a["sk"]])
    gid_aba_sb = sl.object_id(gp_aba_sb)
    iss_prep_sb = {"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_aba_sb), "grant_id": gid_aba_sb, "type": "seallink-issuance/1"}
    inv_aba_sb = sl.sign_envelope({**inv_aba_old["payload"], "nonce": _h32("l1-sb-n"), "proof_path": [{"grant_id": gid_aba_sb, "issuance_txid": sb_iss_tx}]}, [fx_aba["_keys"]["agent_req"]["sk"]])
    ch_aba_sb["txs"][sb_seal_tx] = {"confirmed_height": 749996, "inputs": [sv.make_segwit_input(_h32("l1-sb-fund"), 0)], "outputs": {"0": {"script_pubkey_hex": _spk_hex(seal_pol_aba)}, "1": {"script_pubkey_hex": _spk_hex(fx_aba["_alice_owner_pol"])}}}
    ch_aba_sb["txs"][sb_iss_tx] = {"confirmed_height": 749997, "inputs": [sv.make_segwit_input(sb_seal_tx, 1)], "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest(iss_prep_sb).hex(), 0x00).hex(), "outputs": {}}
    ch_aba_sb["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_aba["_alice_reg"],
        fx_aba["_alice_owner_pol"],
        alice_val_a,
        first_height=748000,
        update_height=749000,
        extra_updates=[
            {"confirmed_height": 749995, "txid": _h32("l1-sb-rot-b"), "value": alice_val_b},
            {"confirmed_height": 749995, "txid": _h32("l1-sb-rot-a2"), "value": alice_val_a},
        ],
    )
    add(
        "d10-l1-aba-same-block-restore-exact-rbh-admit",
        ["SL-IDEN-004", "SL-GRNT-014"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("l1-sb-j")},
            "steps": [
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": fx_aba["bundle"], "chain": ch_aba_sb, "executor_cfg": fx_aba["executor_cfg"], "expect_closures_delta": 1, "invocation": inv_aba_old, "kind": "invocation", "label": "old-records-749995", "want_refusal": "NAME_ROLE_CHANGED", "want_verdict": "REFUSE"},
                {"actual_message_meta": {"folder": "Invoices"}, "bundle": {**fx_aba["bundle"], "grants": [g_aba_sb]}, "chain": ch_aba_sb, "executor_cfg": fx_aba["executor_cfg"], "invocation": inv_aba_sb, "kind": "invocation", "label": "new-at-exact-749995-admits", "want_refusal": None, "want_verdict": "ADMIT"},
            ],
        },
        "ADMIT",
        None,
        "L1: Same-block A->B->A at height 749995 admits new-epoch grant at exact recent_block_height == retired_before_height == 749995.",
    )
    j_sb_bs = sv.FencedJournal(_h32("l1-sb-bs-j"))
    j_sb_bs.record_closure({**rc_base_subj, "retired_before_height": 749995}, "NAME_ROLE_CHANGED", observed_at=ch_aba_sb["now"], observed_height=ch_aba_sb["tip_height"])
    so_aba_sb = sl.sign_envelope(
        {"executor": inv_aba_sb["payload"]["executor"], "exp": ch_aba_sb["now"] + 600, "genesis": GENESIS_MAIN, "iat": ch_aba_sb["now"], "network": "main", "nonce": _h32("l1-sb-so-n"), "op": "open", "proof_path": [{"grant_id": gid_aba_sb, "issuance_txid": sb_iss_tx}], "quotas": [], "slot_binding": "slot-sb-bs", "type": "seallink-session-open/1"},
        [fx_aba["_keys"]["agent_req"]["sk"]],
    )
    add(
        "d10-l1-bearer-same-block-aba-exact-rbh-admit",
        ["SL-GRNT-013", "SL-IDEN-004"],
        "session_lifecycle",
        {
            "executor_cfg": fx_aba["executor_cfg"],
            "journal": {"closures": j_sb_bs.closures, "journal_id": j_sb_bs.journal_id},
            "steps": [
                {"bundle": {**fx_aba["bundle"], "grants": [g_aba_sb]}, "chain": ch_aba_sb, "kind": "session_open", "label": "open-at-exact-rbh", "session_open": so_aba_sb, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": ch_aba_sb, "grant_env": g_aba_sb, "kind": "bearer_session", "label": "use-at-exact-rbh-admits", "slot_binding": "slot-sb-bs", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
            ],
        },
        "ADMIT",
        None,
        "L1: Bearer session live recheck admits new-epoch grant at exact recent_block_height == retired_before_height == 749995.",
        module="bearer-sessions",
    )

    # 5. _verify_issuance_anchor_live exact boundary regressions (kills all 3 L6333 operators: <, <=, >=)
    fx_bs_b = rm._base_invocation_fixture()
    gp_bs_b = copy.deepcopy(fx_bs_b["bundle"]["grants"][0]["payload"])
    gp_bs_b["min_depth"] = 3
    g_bs_b, gid_bs_b = _reanchor(fx_bs_b, gp_bs_b)
    itx_bs_b = fx_bs_b["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    so_bs_b = sl.sign_envelope(
        {"executor": fx_bs_b["invocation"]["payload"]["executor"], "exp": fx_bs_b["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "iat": fx_bs_b["chain"]["now"], "network": "main", "nonce": _h32("l1-bsb-n"), "op": "open", "proof_path": [{"grant_id": gid_bs_b, "issuance_txid": itx_bs_b}], "quotas": [], "slot_binding": "slot-bsb", "type": "seallink-session-open/1"},
        [fx_bs_b["_keys"]["agent_req"]["sk"]],
    )
    a_h_bsb = fx_bs_b["chain"]["txs"][itx_bs_b]["confirmed_height"]
    ch_bsb_eq_rh = copy.deepcopy(fx_bs_b["chain"])
    ch_bsb_eq_rh["txs"][itx_bs_b]["confirmed_height"] = 749990  # a_h == r_h -> REFUSE
    ch_bsb_max_k = copy.deepcopy(fx_bs_b["chain"])
    ch_bsb_max_k["txs"][itx_bs_b]["confirmed_height"] = 749990 + 432  # exact a_h == r_h + 432 (consistent with root_recent_height=749990) -> ADMIT
    rm.sync_chain_tip(ch_bsb_max_k, height=749990 + 432 + 5)
    ch_bsb_min_d = copy.deepcopy(fx_bs_b["chain"])
    rm.sync_chain_tip(ch_bsb_min_d, height=a_h_bsb + 2)  # exact (tip - a_h + 1) == 3 == min_depth -> ADMIT
    add(
        "d10-l1-bearer-anchor-exact-boundaries",
        ["SL-GRNT-013", "SL-LDGR-008"],
        "session_lifecycle",
        {
            "executor_cfg": fx_bs_b["executor_cfg"],
            "journal": {"journal_id": _h32("l1-bsb-j")},
            "steps": [
                {"bundle": fx_bs_b["bundle"], "chain": fx_bs_b["chain"], "kind": "session_open", "label": "open-d3", "session_open": so_bs_b, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": ch_bsb_eq_rh, "expect_zero_writes": True, "grant_env": g_bs_b, "kind": "bearer_session", "label": "ah-eq-rh-refuse", "slot_binding": "slot-bsb", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m2"}, "chain": ch_bsb_max_k, "grant_env": g_bs_b, "kind": "bearer_session", "label": "ah-eq-rh-plus-432-admit", "slot_binding": "slot-bsb", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m3"}, "chain": ch_bsb_min_d, "grant_env": g_bs_b, "kind": "bearer_session", "label": "depth-eq-min-depth-admit", "slot_binding": "slot-bsb", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
            ],
        },
        "ADMIT",
        None,
        "L1: Bearer session _verify_issuance_anchor_live enforces exact (r_h, r_h + 432] recency and depth >= max(min_depth, operator_min_depth).",
        module="bearer-sessions",
    )

    # 6 & 7. Migration bad predecessor ScriptPolicy (kills L6894) & exact operator_min_depth == 9 admit (kills L6907)
    m_fence_badsp_p = copy.deepcopy(m_fence["payload"])
    m_fence_badsp_p["subject"]["predecessor_grant_seals"][0]["script_policy"] = {"kind": "multisig", "m": 2, "pks": [fx_mig["_keys"]["alice_seal"]["comp"]]}
    m_fence_badsp = sl.sign_envelope(m_fence_badsp_p, [fx_mig["_keys"]["host_rcpt"]["sk"]])
    add(
        "d10-l1-migration-bad-predecessor-script-policy-refuse",
        ["SL-SERV-003"],
        "migration",
        {"chain": ch_mig_ok, "dest_accept_stmt": m_acc, "export_bundle": {**eb_10, "fencing_statement": m_fence_badsp}, "holder_assent": m_ha, "journal": {"journal_id": _h32("l1-mig-j5")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate"},
        "REFUSE",
        "SERVICE_MIGRATION_INVALID",
        "L1: migration-fence listing a predecessor_grant_seal with uncompilable ScriptPolicy (m=2 > len(pks)=1) MUST refuse SERVICE_MIGRATION_INVALID.",
        module="service-migration",
    )
    add(
        "d10-l1-migration-exact-depth-predecessor-spend-admit",
        ["SL-SERV-003"],
        "migration",
        {"chain": ch_mig_ok, "dest_accept_stmt": m_acc, "export_bundle": eb_10, "holder_assent": m_ha, "journal": {"journal_id": _h32("l1-mig-j6")}, "local_executor_pin": d_pin, "manifests": fx_mig["bundle"]["manifests"], "migration": m_env, "mode": "activate", "operator_min_depth": 9},
        "ADMIT",
        None,
        "L1: Predecessor grant seal spend at exact depth == operator_min_depth (750010 - 750002 + 1 == 9) admits cleanly.",
        module="service-migration",
    )

    # 8 & 9. Federation unrelated origin_bundle (kills L7088) & exact tip_height == h_c 0x0b break (kills L7103)
    add(
        "d10-l1-federation-unrelated-origin-bundle-refuse",
        ["SL-SERV-004", "SL-ORIG-002"],
        "federation",
        {
            "chain": {**fx_f10["chain"], "credible_utc_interval": fx_orig_l1["chain"]["credible_utc_interval"], "names": {**fx_f10["chain"]["names"], **fx_orig_l1["chain"]["names"]}, "tip_median_time_past": fx_orig_l1["chain"]["tip_median_time_past"], "txs": {**fx_f10["chain"]["txs"], **fx_orig_l1["chain"]["txs"]}},
            "grant": gf_env,
            "journal": {"journal_id": _h32("l1-fed-j8")},
            "peer_ctx": {"origin_bundle": fx_orig_l1["origin_bundle"], "peer_id": "id/peer-b", "phase": "screening"},
            "policy": base_fed_pol,
            "trusted_origin_issuer_pins": fx_orig_l1["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "L1 (D10-1): Federation presented with an unrelated origin_bundle whose effective_binding != grant.issuer MUST refuse ORIGIN_BINDING_INVALID.",
        module="federated-screening",
    )
    ch_f10_0b_tip = copy.deepcopy(fx_f10["chain"])
    u_prev_f10_t = ch_f10_0b_tip["names"]["id/alice"]["updates"][-1]
    brk_f10_tip = {
        "compromised_policy": {"m": 1, "pks": [fx_f10["_keys"]["alice_gr"]["xonly"]]},
        "genesis": GENESIS_MAIN,
        "h_c": 750010,
        "issuer": {"name": "id/alice", "registration": fx_f10["_alice_reg"]},
        "name_input": {"txid": u_prev_f10_t["txid"], "vout": u_prev_f10_t["vout"]},
        "role": "grant",
        "type": "seallink-credential-break/1",
    }
    ch_f10_0b_tip["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_f10["_alice_reg"],
        fx_f10["_alice_owner_pol"],
        {"link": {"grant": fx_f10["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_f10["_alice_man"]), "s": 1}},
        first_height=748000,
        update_height=749000,
        extra_updates=[{"confirmed_height": 750010, "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_f10_tip).hex(), 0x00, h_c=750010).hex(), "txid": _h32("l1-fed-0b-tip-u"), "value": {"link": {"grant": fx_f10["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_f10["_alice_man"]), "s": 1}}}],
    )
    add(
        "d10-l1-federation-0x0b-exact-tip-height-refuse",
        ["SL-SERV-004", "SL-CONT-009"],
        "federation",
        {"chain": ch_f10_0b_tip, "grant": gf_env, "journal": {"journal_id": _h32("l1-fed-j9")}, "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"}, "policy": base_fed_pol},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "L1 (D10-1): Federated screening MUST refuse CRED_ISSUER_CLOSED at exact tip_height == h_c (750010 == 750010).",
        module="federated-screening",
    )
