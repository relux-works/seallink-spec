#!/usr/bin/env python3
"""
Executable 85/85 Refusal Code Coverage Matrix Builder for SealLink v1.0.

Builds `vectors/refusal-coverage-matrix.json`, where every single one of the 85
registered refusal codes in `registry/refusal-codes.json` has a concrete,
self-contained, Draft 2020-12 schema-valid (for all non-WIRE_* cases) executable
test case driven through `tools/seallink_verifier.py` and `tools/seallink_ref.py`
using derived ChainView history, witness inputs, and authoritative key binding.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import seallink_ref as sl
import seallink_verifier as sv

ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.0.0-draft.9"
GENESIS_MAIN = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-matrix-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"matrix:{label}")
    return {
        "sk": sk,
        "xonly": sl.xonly_pubkey(sk),
        "comp": sl.compressed_pubkey(sk),
    }


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


_CACHED_INV_FX: dict[str, Any] | None = None
_CACHED_ORIG_FX: dict[str, Any] | None = None


def _base_invocation_fixture() -> dict[str, Any]:
    global _CACHED_INV_FX
    if _CACHED_INV_FX is None:
        _CACHED_INV_FX = _build_base_invocation_fixture()
    return copy.deepcopy(_CACHED_INV_FX)


def _build_base_invocation_fixture() -> dict[str, Any]:
    """Build a valid, self-contained invocation fixture with derived history/witnesses returning ADMIT."""
    alice_own = _kp("alice-owner")
    alice_gr = _kp("alice-grant")
    alice_seal = _kp("alice-seal")
    host_own = _kp("host-owner")
    host_rcpt = _kp("host-receipt")
    agent_req = _kp("agent-req")
    agent_own = _kp("agent-owner")

    alice_owner_pol = {"kind": "key", "pk": alice_own["comp"]}
    host_owner_pol = {"kind": "key", "pk": host_own["comp"]}
    agent_owner_pol = {"kind": "key", "pk": agent_own["comp"]}
    seal_pol = {"kind": "key", "pk": alice_seal["comp"]}

    alice_reg = {"txid": _h32("alice-reg"), "vout": 0}
    host_reg = {"txid": _h32("host-reg"), "vout": 0}
    agent_reg = {"txid": _h32("agent-reg"), "vout": 0}

    host_man = {
        "network": "main",
        "owner": "id/mail-host-a",
        "seq": 1,
        "service": {
            "actions": ["mail/list", "mail/read", "mail/send"],
            "endpoint": "https://mail-a.example/seallink/v1",
            "receipt_key": host_rcpt["xonly"],
            "service_type": "mail",
            "tls_spki_sha256": _h32("host-spki"),
        },
        "type": "seallink-manifest/1",
    }
    alice_man = {
        "network": "main",
        "owner": "id/alice",
        "providers": [
            {
                "label": "work",
                "provider": {
                    "name": "id/mail-host-a",
                    "owner_policy": host_owner_pol,
                    "registration": host_reg,
                },
                "service_type": "mail",
            }
        ],
        "seq": 1,
        "type": "seallink-manifest/1",
    }

    alice_val_obj = {"link": {"grant": alice_gr["xonly"]}, "m": {"h": sl.content_addr(alice_man), "s": 1}}
    host_val_obj = {"m": {"h": sl.content_addr(host_man), "s": 1}}
    agent_val_obj = {"nostr": agent_req["xonly"]}

    seal_txid = _h32("alice-seal-tx")
    iss_txid = _h32("alice-iss-tx")
    recent_blk = _h32("recent-blk-749990")

    grant_payload = {
        "capabilities": [
            {
                "action": "mail/read",
                "target": "mailbox:id/alice:work",
                "where": {"folder": {"in": ["Invoices"]}},
            }
        ],
        "executor": {"key": host_rcpt["xonly"], "name": "id/mail-host-a"},
        "genesis": GENESIS_MAIN,
        "issuer": {
            "name": "id/alice",
            "owner_policy": alice_owner_pol,
            "registration": alice_reg,
            "role_policy": {"m": 1, "pks": [alice_gr["xonly"]]},
        },
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 750000,
        "recent_block": recent_blk,
        "recipient": {"key": agent_req["xonly"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "revocable",
            "mode": "seal",
            "seal": {"script_policy": seal_pol, "txid": seal_txid, "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    grant_env = sl.sign_envelope(grant_payload, [alice_gr["sk"]])
    grant_id = sl.object_id(grant_payload)
    iss_prep = {
        "genesis": GENESIS_MAIN,
        "grant_content_addr": sl.content_addr(grant_env),
        "grant_id": grant_id,
        "type": "seallink-issuance/1",
    }
    iss_opret = sl.encode_opreturn(0x01, sl.signing_digest(iss_prep).hex(), 0x00).hex()

    inv_payload = {
        "action": "mail/read",
        "arguments": {"folder": "Invoices", "message_id": "msg-1"},
        "executor": {"key": host_rcpt["xonly"], "name": "id/mail-host-a"},
        "exp": 1795220300,
        "genesis": GENESIS_MAIN,
        "iat": 1795220000,
        "network": "main",
        "nonce": _h32("inv-nonce-1"),
        "proof_path": [{"grant_id": grant_id, "issuance_txid": iss_txid}],
        "target": "mailbox:id/alice:work",
        "type": "seallink-invocation/1",
    }
    inv_env = sl.sign_envelope(inv_payload, [agent_req["sk"]])

    chain_state = {
        "network": "main",
        "genesis": GENESIS_MAIN,
        "tip_height": 750010,
        "tip_hash": _h32("tip-750010"),
        "tip_header_time": 1795220000,
        "tip_median_time_past": 1795219900,
        "tip_first_sight": 1795220005,
        "now": 1795220010,
        "clock_watermark": 1795219000,
        "in_ibd": False,
        "txindex": True,
        "node_reachable": True,
        "best_header_height": 750010,
        "comparison_peers": [{"healthy": True, "height": 750010, "hash_at_tip": _h32("tip-750010")}],
        "blocks": {recent_blk: 749990},
        "names": {
            "id/alice": sv.make_name_history("id/alice", alice_reg, alice_owner_pol, alice_val_obj, first_height=748000, update_height=749000),
            "id/mail-host-a": sv.make_name_history("id/mail-host-a", host_reg, host_owner_pol, host_val_obj, first_height=748000, update_height=749000),
            "id/alice-acct-agent": sv.make_name_history("id/alice-acct-agent", agent_reg, agent_owner_pol, agent_val_obj, first_height=748000, update_height=749000),
        },
        "txs": {
            seal_txid: {
                "confirmed_height": 749995,
                "inputs": [sv.make_segwit_input(_h32("alice-fund-tx"), 0)],
                "outputs": {
                    "0": {"script_pubkey_hex": _spk_hex(seal_pol)},
                    "1": {"script_pubkey_hex": _spk_hex(alice_owner_pol)},
                },
            },
            iss_txid: {
                "confirmed_height": 749998,
                "inputs": [sv.make_segwit_input(seal_txid, 1)],
                "opreturn_hex": iss_opret,
                "outputs": {},
            },
        },
        "manifests": {
            sl.content_addr(alice_man): alice_man,
            sl.content_addr(host_man): host_man,
        },
    }
    journal_state = {"journal_id": _h32("matrix-journal")}
    executor_cfg = {
        "name": "id/mail-host-a",
        "key": host_rcpt["xonly"],
        "pin": {"name": "id/mail-host-a", "owner_policy": host_owner_pol, "registration": host_reg},
        "actions": ["mail/list", "mail/read", "mail/send", "agent/tool", "agent/session", "agent/brief", "agent/guardian-message"],
    }
    bundle = {
        "grants": [grant_env],
        "manifests": {
            sl.content_addr(alice_man): alice_man,
            sl.content_addr(host_man): host_man,
        },
    }
    keys = {
        "alice_own": alice_own,
        "alice_gr": alice_gr,
        "alice_seal": alice_seal,
        "host_own": host_own,
        "host_rcpt": host_rcpt,
        "agent_req": agent_req,
        "agent_own": agent_own,
    }
    return {
        "invocation": inv_env,
        "bundle": bundle,
        "chain": chain_state,
        "journal": journal_state,
        "executor_cfg": executor_cfg,
        "_keys": keys,
        "_alice_man": alice_man,
        "_host_man": host_man,
        "_alice_reg": alice_reg,
        "_host_reg": host_reg,
        "_alice_owner_pol": alice_owner_pol,
        "_host_owner_pol": host_owner_pol,
    }


def _reanchor_grant(fx: dict[str, Any], new_grant_payload: dict[str, Any], signer_sk: bytes | None = None) -> None:
    """Re-sign root grant and update issuance tx + invocation proof_path cleanly."""
    sk = signer_sk or fx["_keys"]["alice_gr"]["sk"]
    g_env = sl.sign_envelope(new_grant_payload, [sk])
    gid = sl.object_id(new_grant_payload)
    iss_txid = _h32("alice-iss-tx")
    iss_prep = {
        "genesis": new_grant_payload["genesis"],
        "grant_content_addr": sl.content_addr(g_env),
        "grant_id": gid,
        "type": "seallink-issuance/1",
    }
    if "contract_id" in new_grant_payload:
        iss_prep["contract_id"] = new_grant_payload["contract_id"]
    fx["chain"]["txs"][iss_txid]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest(iss_prep).hex(), 0x00).hex()
    fx["bundle"]["grants"] = [g_env]
    inv_p = copy.deepcopy(fx["invocation"]["payload"])
    inv_p["proof_path"] = [{"grant_id": gid, "issuance_txid": iss_txid}]
    fx["invocation"] = sl.sign_envelope(inv_p, [fx["_keys"]["agent_req"]["sk"]])


def _base_origin_fixture() -> dict[str, Any]:
    global _CACHED_ORIG_FX
    if _CACHED_ORIG_FX is None:
        _CACHED_ORIG_FX = _build_base_origin_fixture()
    return copy.deepcopy(_CACHED_ORIG_FX)


def _build_base_origin_fixture() -> dict[str, Any]:
    """Build a valid ward origin bundle + authoritative chain state (including civil-registry + guardian assent)."""
    reg_own = _kp("o-reg-own")
    reg_cred = _kp("o-reg-cred")
    disp = _kp("o-disp")
    arb = _kp("o-arb")
    chal = _kp("o-chal")
    ward_init = _kp("o-ward-init")
    ward_gr = _kp("o-ward-gr")
    bind_seal = _kp("o-bind")
    stat_cap = _kp("o-scap")
    stat_end = _kp("o-send")
    rec_disp = _kp("o-rdisp")
    rec_arb = _kp("o-rarb")
    g1_own = _kp("o-g1-own")
    g1_gr = _kp("o-g1-gr")
    g1_seal = _kp("o-g1-seal")
    g2_own = _kp("o-g2-own")
    g2_gr = _kp("o-g2-gr")
    sch_own = _kp("o-sch-own")
    sch_gr = _kp("o-sch-gr")

    reg_owner_pol = {"kind": "key", "pk": reg_own["comp"]}
    reg_outpoint = {"txid": _h32("oreg-tx"), "vout": 0}
    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["comp"], arb["comp"])}
    stat_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(stat_cap["comp"], stat_end["comp"])}
    rec_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(rec_disp["comp"], rec_arb["comp"])}
    ward_owner_pol = {"kind": "multisig", "m": 2, "pks": sorted([g1_own["comp"], g2_own["comp"], reg_own["comp"]])}
    g1_pin = {"name": "id/parent-a", "owner_policy": {"kind": "key", "pk": g1_own["comp"]}, "registration": {"txid": _h32("g1-reg"), "vout": 0}}
    g2_pin = {"name": "id/parent-b", "owner_policy": {"kind": "key", "pk": g2_own["comp"]}, "registration": {"txid": _h32("g2-reg"), "vout": 0}}

    salt_maj = _h32("salt-maj")
    salt_g1 = _h32("salt-g1")
    salt_g2 = _h32("salt-g2")
    maj_unix = 2000000000

    quorums = {
        "contract_assent": {"den": 1, "min": 2, "num": 1},
        "custody_change": {"den": 1, "min": 2, "num": 1},
        "effect_grant": {"den": 1, "min": 1, "num": 1},
        "routine_read": {"den": 2, "min": 1, "num": 1},
    }
    origin_p = {
        "binding_seal": {"script_policy": {"kind": "key", "pk": bind_seal["comp"]}, "txid": _h32("obind-tx"), "vout": 0},
        "capacity_authority": {"name": "id/civil-registry", "owner_policy": reg_owner_pol, "registration": reg_outpoint},
        "claims": {
            "intended_name": "id/child-leo",
            "intended_owner_policy": ward_owner_pol,
            "majority_commitment": sl.clause_commit(salt_maj, {"majority_unix": maj_unix}),
        },
        "genesis": GENESIS_MAIN,
        "guardian_policy": {
            "appointment_delay_blocks": 144,
            "arbiter_pk": arb["comp"],
            "challenger_pk": chal["comp"],
            "disposer_pk": disp["comp"],
            "quorums": quorums,
            "revision": 1,
            "revision_size": 2,
            "roster_seal": {"script_policy": vac_pol, "txid": _h32("oroster-tx"), "vout": 0},
            "slots": [
                {"initial_guardian_commitment": sl.clause_commit(salt_g1, g1_pin), "slot": 1, "vacant_utxo": {"txid": _h32("os1-vac"), "vout": 0}},
                {"initial_guardian_commitment": sl.clause_commit(salt_g2, g2_pin), "slot": 2, "vacant_utxo": {"txid": _h32("os2-vac"), "vout": 0}},
            ],
        },
        "issuer": {"name": "id/civil-registry", "owner_policy": reg_owner_pol, "registration": reg_outpoint, "role_policy": {"m": 1, "pks": [reg_cred["xonly"]]}},
        "name_recovery": {
            "arbiter_pk": rec_arb["comp"],
            "delay_blocks": 144,
            "disposer_pk": rec_disp["comp"],
            "mode": "dual_party_delayed",
            "recovery_seal": {"script_policy": rec_pol, "txid": _h32("orecov-tx"), "vout": 0},
        },
        "network": "main",
        "origin_class": "person",
        "request_sha256": _h32("obirth-req"),
        "status_seal": {"script_policy": stat_pol, "txid": _h32("ostat-tx"), "vout": 0},
        "subject_initial_key": ward_init["xonly"],
        "type": "seallink-origin/1",
    }
    origin_env = sl.sign_envelope(origin_p, [reg_cred["sk"]])
    origin_id = sl.object_id(origin_p)

    binding = {
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo",
        "network": "main",
        "origin_id": origin_id,
        "owner_policy": ward_owner_pol,
        "registration": {"txid": _h32("oleo-reg"), "vout": 0},
        "seq": 1,
        "type": "seallink-name-binding/1",
    }

    act_pol_1 = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp["comp"], g1_seal["comp"])}
    g1_rec_p = {
        "active_policy": act_pol_1,
        "active_vout": 0,
        "activation_mode": "initial",
        "genesis": GENESIS_MAIN,
        "guardian": g1_pin,
        "issuer": origin_p["issuer"],
        "network": "main",
        "origin_id": origin_id,
        "prev_outpoint": {"txid": _h32("os1-vac"), "vout": 0},
        "revision": 1,
        "slot": 1,
        "term": {"ceiling_height": 1750000, "mode": "calendar", "not_after_unix": maj_unix},
        "type": "seallink-guardian/1",
    }
    g1_rec = sl.sign_envelope(g1_rec_p, [reg_cred["sk"]])
    g1_assent = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "network": "main",
            "nonce": _h32("og1-assent-nonce"),
            "party_id": "slot-1",
            "party_name": "id/parent-a",
            "party_role": "guardian",
            "target_id": sl.object_id(g1_rec_p),
            "target_type": "seallink-guardian/1",
            "type": "seallink-assent/1",
        },
        [g1_gr["sk"]],
    )
    g1_init_txid = _h32("og1-init-0x12")

    contract = {
        "clause_commitments": [sl.clause_commit(_h32("c0-s"), {"text": "Enrollment"})],
        "contract_salt": _h32("csalt"),
        "genesis": GENESIS_MAIN,
        "machine_clause_indices": [0],
        "network": "main",
        "parties": [
            {"name_pin": {"name": "id/child-leo", "owner_policy": ward_owner_pol, "registration": binding["registration"]}, "party_id": "student-1", "role": "student_ward", "ward_origin_id": origin_id},
            {"name_pin": {"name": "id/school", "owner_policy": {"kind": "key", "pk": sch_own["comp"]}, "registration": {"txid": _h32("sch-reg"), "vout": 0}}, "party_id": "school-1", "role": "school", "signing_policy": {"m": 1, "pks": [sch_gr["xonly"]]}},
        ],
        "profile": "org.seallink/enrollment-v1",
        "seal": {"script_policy": {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp["comp"], sch_own["comp"])}, "txid": _h32("ocseal-tx"), "vout": 0},
        "type": "seallink-contract/1",
        "window": {"not_after_height": 790000, "not_before_height": 750000},
    }

    origin_txid = _h32("oanchor-tx")
    bind_txid = _h32("obind-spend-tx")

    chain = {
        "network": "main",
        "genesis": GENESIS_MAIN,
        "tip_height": 750100,
        "tip_hash": _h32("otip-750100"),
        "tip_header_time": 1795220000,
        "tip_median_time_past": 1795219900,
        "tip_first_sight": 1795220005,
        "now": 1795220010,
        "credible_utc_interval": [1795220000, 1795220020],
        "comparison_peers": [{"healthy": True, "height": 750100, "hash_at_tip": _h32("otip-750100")}],
        "names": {
            "id/civil-registry": sv.make_name_history(
                "id/civil-registry", reg_outpoint, reg_owner_pol, {"link": {"cred": reg_cred["xonly"]}}, first_height=748000, update_height=748500
            ),
            "id/parent-a": sv.make_name_history(
                "id/parent-a", g1_pin["registration"], g1_pin["owner_policy"], {"link": {"grant": g1_gr["xonly"]}}, first_height=748000, update_height=748600
            ),
            "id/child-leo": sv.make_name_history(
                "id/child-leo", binding["registration"], ward_owner_pol, {"link": {"origin": origin_id}}, first_height=749005, update_height=749015
            ),
        },
        "txs": {
            origin_txid: {"confirmed_height": 749000, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(origin_env)).hex(), "outputs": {}},
            _h32("obind-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex({"kind": "key", "pk": bind_seal["comp"]}), "spent_by_txid": bind_txid}}},
            bind_txid: {"confirmed_height": 749010, "inputs": [sv.make_segwit_input(_h32("obind-tx"), 0)], "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(binding)).hex(), "outputs": {}},
            _h32("ostat-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_pol)}}},
            _h32("oroster-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pol)}}},
            _h32("orecov-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_pol)}}},
            _h32("os1-vac"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pol), "spent_by_txid": g1_init_txid}}},
            _h32("os2-vac"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pol)}}},
            g1_init_txid: {
                "confirmed_height": 749020,
                "opreturn_hex": sl.encode_opreturn(0x12, sl.content_addr(g1_rec)).hex(),
                "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_pol_1)}},
            },
        },
    }
    origin_bundle = {
        "origin": origin_env,
        "origin_anchor_txid": origin_txid,
        "name_binding": binding,
        "name_binding_txid": bind_txid,
        "guardian_records": [g1_rec],
        "guardian_assents": [g1_assent],
        "roster_records": [],
        "initial_guardian_disclosures": {"1": {"salt_hex": salt_g1, "name_pin": g1_pin}},
        "opened_majority_unix": maj_unix,
        "majority_salt_hex": salt_maj,
    }
    return {
        "origin_bundle": origin_bundle,
        "contract": contract,
        "chain": chain,
        "trusted_origin_issuers": ["id/civil-registry"],
        "trusted_origin_issuer_pins": [{"name": "id/civil-registry", "owner_policy": reg_owner_pol, "registration": reg_outpoint}],
        "_keys": {
            "reg_own": reg_own, "reg_cred": reg_cred, "disp": disp, "arb": arb,
            "ward_gr": ward_gr, "g1_gr": g1_gr, "g2_gr": g2_gr, "sch_gr": sch_gr,
            "stat_cap": stat_cap, "stat_end": stat_end,
        },
        "_origin_id": origin_id,
        "_maj_unix": maj_unix,
        "_rec_pol": rec_pol,
    }


def _contract_fx() -> dict[str, Any]:
    f = _base_invocation_fixture()
    f["executor_cfg"]["name"] = "id/station-a"
    f["executor_cfg"].pop("pin", None)
    f["executor_cfg"]["station_slot_bindings"] = {
        "station:id/station-a:slot1": [{"name": "id/alice", "owner_policy": f["_alice_owner_pol"], "registration": f["_alice_reg"]}]
    }
    c_salt = _h32("c0-salt")
    sess_cap = {"action": "agent/session", "target": "station:id/station-a:slot1", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "station:id/station-a:slot1", "unit": "starts", "window": "term"}]}
    c0 = {"machine_terms": {"capabilities": [sess_cap]}, "text": "Isolated session terms"}
    cseal_a = _kp("cseal-a")
    cseal_b = _kp("cseal-b")
    cseal_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(cseal_a["comp"], cseal_b["comp"])}
    c_obj = {
        "clause_commitments": [sl.clause_commit(c_salt, c0)],
        "config_sha256": _h32("cfg-agreed"),
        "contract_salt": _h32("cs-root"),
        "genesis": GENESIS_MAIN,
        "machine_clause_indices": [0],
        "network": "main",
        "parties": [
            {"party_id": "client-1", "role": "client", "signing_policy": {"m": 1, "pks": [f["_keys"]["alice_gr"]["xonly"]]}},
            {"party_id": "worker-1", "role": "worker", "signing_policy": {"m": 1, "pks": [f["_keys"]["agent_req"]["xonly"]]}},
        ],
        "profile": "org.seallink/agent-session-v1",
        "seal": {"script_policy": cseal_pol, "txid": _h32("cseal-tx"), "vout": 0},
        "type": "seallink-contract/1",
        "window": {"not_after_height": 770000, "not_before_height": 749000},
    }
    cid = sl.object_id(c_obj)
    a1 = sl.sign_envelope({
        "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
        "nonce": _h32("ca-1"), "party_id": "client-1", "party_role": "client", "target_id": cid, "target_type": "seallink-contract/1", "type": "seallink-assent/1",
    }, [f["_keys"]["alice_gr"]["sk"]])
    a2 = sl.sign_envelope({
        "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
        "nonce": _h32("ca-2"), "party_id": "worker-1", "party_role": "worker", "target_id": cid, "target_type": "seallink-contract/1", "type": "seallink-assent/1",
    }, [f["_keys"]["agent_req"]["sk"]])
    gp = copy.deepcopy(f["bundle"]["grants"][0]["payload"])
    gp["executor"] = {"key": f["_keys"]["host_rcpt"]["xonly"], "name": "id/station-a"}
    gp["contract_id"] = cid
    gp["capabilities"] = [sess_cap]
    _reanchor_grant(f, gp)
    inv_p = copy.deepcopy(f["invocation"]["payload"])
    inv_p["action"] = "agent/session"
    inv_p["executor"] = gp["executor"]
    inv_p["target"] = "station:id/station-a:slot1"
    inv_p["arguments"] = {"config_sha256": _h32("cfg-agreed"), "op": "start", "session_slot": "slot1"}
    f["invocation"] = sl.sign_envelope(inv_p, [f["_keys"]["agent_req"]["sk"]])
    f["bundle"]["contract"] = c_obj
    f["bundle"]["contract_assents"] = [a1, a2]
    f["bundle"]["disclosed_clauses"] = {"0": {"salt_hex": c_salt, "clause": c0}}
    f["chain"]["txs"][_h32("cseal-tx")] = {"confirmed_height": 749500, "outputs": {"0": {"script_pubkey_hex": _spk_hex(cseal_pol)}}}
    f["executor_cfg"]["runtime_config_sha256"] = _h32("cfg-agreed")
    return f


def _delegation_fx(notary_mode: str = "none", with_stop: bool = False) -> dict[str, Any]:
    f = _base_invocation_fixture()
    f["executor_cfg"]["name"] = "id/station-a"
    f["executor_cfg"]["station_slot_bindings"] = {
        "station:id/station-a:tools": [{"name": "id/alice", "owner_policy": f["_alice_owner_pol"], "registration": f["_alice_reg"]}]
    }
    del_k = _kp("del-key")
    cseal_iss = _kp("cseal-iss")
    row_k = _kp("row-coin")
    stop_k = _kp("stop-coin")
    pool_q = {"kind": "seallink/count", "max": "10", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}
    row_q = {"kind": "seallink/count", "max": "2", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}
    rng: dict[str, Any] = {"count": 2, "first": 0, "script_policy": {"kind": "key", "pk": row_k["comp"]}, "txid": _h32("row-tx")}
    if with_stop:
        rng["stop_txid"] = _h32("stop-tx")
        rng["stop_first"] = 0
        rng["stop_script_policy"] = {"kind": "key", "pk": stop_k["comp"]}
    parent_p = copy.deepcopy(f["bundle"]["grants"][0]["payload"])
    parent_p["executor"] = {"key": f["_keys"]["host_rcpt"]["xonly"], "name": "id/station-a"}
    parent_p["capabilities"] = [{"action": "agent/tool", "quotas": [pool_q], "target": "station:id/station-a:tools"}]
    tpl_obj: dict[str, Any] = {
        "capabilities": [{"action": "agent/tool", "quotas": [row_q], "target": "station:id/station-a:tools", "where": {"tool_name": {"in": ["pytest"]}}}],
        "executor": parent_p["executor"],
        "notary_mode": notary_mode,
        "recipient_rule": {"key": f["_keys"]["agent_req"]["xonly"], "mode": "exact_key"},
    }
    del_obj: dict[str, Any] = {
        "child_seal_key": cseal_iss["comp"],
        "groups": [{
            "ranges": [rng],
            "template": tpl_obj,
        }],
        "key": del_k["xonly"],
        "pools": [pool_q],
    }
    if notary_mode in ("optional_stop", "required_act"):
        not_own = _kp("notary-own")
        tpl_obj["notary_name"] = "id/notary-1"
        del_obj["notaries"] = [{
            "name": "id/notary-1",
            "owner_policy": {"kind": "key", "pk": not_own["comp"]},
            "registration": {"txid": _h32("notary-reg"), "vout": 0},
        }]
    parent_p["delegate"] = del_obj
    parent_env = sl.sign_envelope(parent_p, [f["_keys"]["alice_gr"]["sk"]])
    pid = sl.object_id(parent_p)
    cseal_pol = {"kind": "key", "pk": cseal_iss["comp"]}
    child_p = {
        "capabilities": [{"action": "agent/tool", "quotas": [row_q], "target": "station:id/station-a:tools", "where": {"tool_name": {"eq": "pytest"}}}],
        "executor": parent_p["executor"],
        "genesis": GENESIS_MAIN,
        "network": "main",
        "not_after_height": 755000,
        "not_before_height": 750000,
        "parent": {"grant_id": pid, "ordinal": 1},
        "recent_block": parent_p["recent_block"],
        "recipient": {"key": f["_keys"]["agent_req"]["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": cseal_pol, "txid": _h32("child-seal-tx"), "vout": 0}},
        "type": "seallink-grant/1",
    }
    child_env = sl.sign_envelope(child_p, [del_k["sk"]])
    cid = sl.object_id(child_p)
    p_itx = _h32("p-iss-tx")
    c_itx = _h32("c-iss-tx")
    f["chain"]["txs"][p_itx] = {
        "confirmed_height": 749998,
        "inputs": [sv.make_segwit_input(_h32("alice-seal-tx"), 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(parent_env), "grant_id": pid, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    f["chain"]["txs"][c_itx] = {
        "confirmed_height": 749999,
        "inputs": [sv.make_segwit_input(_h32("row-tx"), 0), sv.make_segwit_input(_h32("child-seal-tx"), 1)],
        "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(child_env), "grant_id": cid, "type": "seallink-issuance/1"}).hex()).hex(),
        "outputs": {},
    }
    f["chain"]["txs"][_h32("child-seal-tx")] = {
        "confirmed_height": 749995,
        "inputs": [sv.make_segwit_input(_h32("cseal-fund"), 0)],
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(cseal_pol)}, "1": {"script_pubkey_hex": _spk_hex(cseal_pol)}},
    }
    if with_stop:
        f["chain"]["txs"][_h32("stop-tx")] = {"confirmed_height": 749990, "outputs": {"0": {"script_pubkey_hex": _spk_hex({"kind": "key", "pk": stop_k["comp"]})}}}
    inv_p = copy.deepcopy(f["invocation"]["payload"])
    inv_p["action"] = "agent/tool"
    inv_p["executor"] = parent_p["executor"]
    inv_p["target"] = "station:id/station-a:tools"
    inv_p["arguments"] = {"input_sha256": _h32("in1"), "max_output_bytes": "1024", "tool_name": "pytest"}
    inv_p["proof_path"] = [{"grant_id": pid, "issuance_txid": p_itx}, {"grant_id": cid, "issuance_txid": c_itx}]
    f["invocation"] = sl.sign_envelope(inv_p, [f["_keys"]["agent_req"]["sk"]])
    f["bundle"]["grants"] = [parent_env, child_env]
    f["_del_k"] = del_k
    return f


def _strip_private(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_private(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_private(v) for v in obj]
    return obj


def execute_matrix_case(case: dict[str, Any], *, require_jsonschema: bool = True) -> str | None:
    """Execute one refusal-coverage-matrix case using ONLY seallink_verifier / seallink_ref.
    Returns the computed refusal code (or None if admitted). NEVER reads case['expected_refusal'].
    """
    runner = case["runner"]
    inp = case["inputs"]
    v = sv.Tier1Verifier(
        pinned_network=inp.get("pinned_network", "main"),
        pinned_genesis=inp.get("pinned_genesis", GENESIS_MAIN),
        operator_min_depth=inp.get("operator_min_depth", 1),
        allow_window_only=inp.get("allow_window_only", False),
        trusted_origin_issuers=inp.get("trusted_origin_issuers"),
        trusted_origin_issuer_pins=inp.get("trusted_origin_issuer_pins"),
        enforce_schemas=True,
        require_jsonschema=require_jsonschema,
        enabled_modules=inp.get("enabled_modules"),
    )

    if runner == "wire_raw":
        ok, res = v.verify_wire_bytes(bytes.fromhex(inp["raw_hex"]), max_bytes_override=inp.get("max_bytes"))
        return None if ok else res
    if runner == "script_parse":
        try:
            sl.parse_name_output(bytes.fromhex(inp["script_hex"]))
            return None
        except ValueError as exc:
            return str(exc)
    if runner == "opreturn_decode":
        try:
            sl.decode_opreturn(bytes.fromhex(inp["script_hex"]))
            return None
        except ValueError as exc:
            return str(exc)
    if runner == "invocation":
        chain = sv.ChainView(inp["chain"])
        journal = sv.FencedJournal.from_dict(inp["journal"])
        res = v.verify_invocation(
            inp["invocation"],
            inp["bundle"],
            chain,
            journal,
            inp["executor_cfg"],
            use_txid=inp.get("use_txid"),
        )
        return res.refusal_code
    if runner == "assent":
        chain = sv.ChainView(inp["chain"])
        res = v.verify_assent(inp["assent"], inp["contract"], inp.get("origin_bundle"), chain)
        return res.refusal_code
    if runner == "origin_status":
        chain = sv.ChainView(inp["chain"])
        _, err = v.verify_origin_and_status(inp["origin_bundle"], chain, assert_binding_id=inp.get("assert_binding_id"))
        return err
    if runner == "credential":
        chain = sv.ChainView(inp["chain"])
        res = v.verify_credential(inp["credential"], inp.get("anchor_txid"), chain)
        return res.refusal_code
    if runner == "auth_challenge":
        chain = sv.ChainView(inp["chain"])
        journal = sv.FencedJournal.from_dict(inp["journal"])
        res = v.verify_auth_challenge(inp["challenge"], chain, journal, inp["service_id"], inp.get("manifests"))
        return res.refusal_code
    if runner == "owner_command":
        chain = sv.ChainView(inp["chain"])
        res = v.verify_owner_command(inp["command"], inp["device_list"], inp["is_foreign_service"], chain)
        return res.refusal_code
    if runner == "bearer_session":
        chain = sv.ChainView(inp["chain"])
        journal = sv.FencedJournal.from_dict(inp["journal"])
        res = v.verify_bearer_session(inp["token"], inp["slot_binding"], chain, journal)
        return res.refusal_code
    if runner == "migration":
        chain = sv.ChainView(inp["chain"])
        journal = sv.FencedJournal.from_dict(inp["journal"])
        res = v.verify_migration(inp["migration"], inp["export_bundle"], journal, chain, inp.get("manifests"))
        return res.refusal_code
    if runner == "federation":
        chain = sv.ChainView(inp["chain"]) if "chain" in inp else None
        res = v.verify_federation_disclosure(inp["policy"], inp["peer_ctx"], inp["grant"], chain=chain)
        return res.refusal_code
    raise ValueError(f"Unknown matrix runner: {runner}")


def build_refusal_coverage_matrix() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    MODULE_BY_CODE = {
        "SESSION_INVALID": "bearer-sessions",
        "SERVICE_MIGRATION_INVALID": "service-migration",
        "FEDERATION_POLICY_DENIED": "federated-screening",
    }

    def add(code: str, rule: str, runner: str, inputs: dict[str, Any], *, module: str | None = None) -> None:
        clean_inputs = _strip_private(inputs)
        mod = module if module is not None else MODULE_BY_CODE.get(code, "core")
        case = {"code": code, "module": mod, "rule": rule, "runner": runner, "inputs": clean_inputs, "expected_refusal": code}
        got = execute_matrix_case(case)
        assert got == code, f"Matrix case {code} failed self-check: got {got!r}"
        cases.append(case)

    # ---- 1. WIRE_* (13 codes) ----
    add("WIRE_SIZE", "SL-WIRE-001", "wire_raw", {"raw_hex": b'{"a":"01234567890123456789"}'.hex(), "max_bytes": 16})
    add("WIRE_JSON", "SL-WIRE-002", "wire_raw", {"raw_hex": (b"\xef\xbb\xbf" + b'{"a":1}').hex()})
    add("WIRE_DUPLICATE", "SL-WIRE-003", "wire_raw", {"raw_hex": b'{"a":1,"a":2}'.hex()})
    add("WIRE_VALUE", "SL-WIRE-004", "wire_raw", {"raw_hex": b'{"a":null}'.hex()})
    add("WIRE_NUMBER", "SL-WIRE-007", "wire_raw", {"raw_hex": b'{"a":1.5}'.hex()})
    # WIRE_INTEGER: window_only > 12 blocks
    fx_wi = _base_invocation_fixture()
    gp_wi = copy.deepcopy(fx_wi["bundle"]["grants"][0]["payload"])
    gp_wi["revocation"] = {"mode": "window_only"}
    gp_wi["not_after_height"] = 750100
    g_wi = sl.sign_envelope(gp_wi, [fx_wi["_keys"]["alice_gr"]["sk"]])
    add("WIRE_INTEGER", "SL-WIRE-008", "wire_raw", {"raw_hex": sl.jcs_encode(g_wi).hex()})
    add("WIRE_STRING", "SL-WIRE-005", "wire_raw", {"raw_hex": b'{"a":"bad\x7fstr"}'.hex()})
    add("WIRE_NOT_CANONICAL", "SL-WIRE-006", "wire_raw", {"raw_hex": b'{"b":1,"a":2}'.hex()})
    add("WIRE_TYPE", "SL-WIRE-010", "wire_raw", {"raw_hex": b'{"type":"seallink-unknown/99"}'.hex()})
    # WIRE_MEMBER: single-defect unknown member on valid typed object (W-9: missing type is WIRE_TYPE)
    fx_wm = _base_invocation_fixture()
    gp_wm = copy.deepcopy(fx_wm["bundle"]["grants"][0]["payload"])
    gp_wm["unknown_field"] = 1
    g_wm = sl.sign_envelope(gp_wm, [fx_wm["_keys"]["alice_gr"]["sk"]])
    add("WIRE_MEMBER", "SL-WIRE-010", "wire_raw", {"raw_hex": sl.jcs_encode(g_wm).hex()})
    # WIRE_KEY: invalid x-only pubkey (not on secp256k1)
    bad_pk = None
    for cand in range(1, 200):
        hx = f"{cand:064x}"
        if not sl.is_valid_xonly_pubkey(hx):
            bad_pk = hx
            break
    assert bad_pk is not None
    fx_wk = _base_invocation_fixture()
    g_wk = copy.deepcopy(fx_wk["bundle"]["grants"][0])
    g_wk["signatures"]["policy"]["pks"] = [bad_pk]
    add("WIRE_KEY", "SL-WIRE-012", "wire_raw", {"raw_hex": sl.jcs_encode(g_wk).hex()})
    # WIRE_SIGNATURE: tampered signature byte
    fx_ws = _base_invocation_fixture()
    g_ws = copy.deepcopy(fx_ws["bundle"]["grants"][0])
    s0 = g_ws["signatures"]["sigs"][0]["sig"]
    g_ws["signatures"]["sigs"][0]["sig"] = ("0" if s0[0] != "0" else "1") + s0[1:]
    add("WIRE_SIGNATURE", "SL-WIRE-013", "wire_raw", {"raw_hex": sl.jcs_encode(g_ws).hex()})
    # WIRE_CONSTRAINT: unsorted `in` array
    fx_wc = _base_invocation_fixture()
    gp_wc = copy.deepcopy(fx_wc["bundle"]["grants"][0]["payload"])
    gp_wc["capabilities"][0]["where"] = {"folder": {"in": ["Zeta", "Alpha"]}}
    g_wc = sl.sign_envelope(gp_wc, [fx_wc["_keys"]["alice_gr"]["sk"]])
    add("WIRE_CONSTRAINT", "SL-WIRE-016", "wire_raw", {"raw_hex": sl.jcs_encode(g_wc).hex()})

    # ---- 2. CHAIN_* & SEAL_* (13 codes) ----
    fx = _base_invocation_fixture()
    fx["chain"]["genesis"] = _h32("wrong-genesis")
    add("CHAIN_MISMATCH", "SL-LDGR-003", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["in_ibd"] = True
    add("CHAIN_UNHEALTHY", "SL-LDGR-008", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["comparison_peers"] = [{"healthy": True, "height": 750011, "hash_at_tip": _h32("peer-ahead")}]
    add("CHAIN_NODE_DISAGREEMENT", "SL-LDGR-008", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["clock_watermark"] = fx["chain"]["now"] + 100
    add("CHAIN_CLOCK_ERROR", "SL-LDGR-008", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["tip_header_time"] = fx["chain"]["now"] - 6000
    add("CHAIN_TIP_STALE", "SL-LDGR-008", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["rebracket_tip"] = {"height": 750011, "hash": _h32("tip-changed")}
    add("CHAIN_OBSERVATION_VOID", "SL-LDGR-008", "invocation", fx)

    legacy_tail = bytes.fromhex("76a914" + "11" * 20 + "88ac")
    bad_name_script = sl.encode_name_output("NAME_UPDATE", legacy_tail, name=b"id/alice", value=b"{}")
    add("CHAIN_SCRIPT_UNSUPPORTED", "SL-LDGR-005", "script_parse", {"script_hex": bad_name_script.hex()})

    fx = _base_invocation_fixture()
    # Non-empty scriptSig on issuance tx input -> violates Witness Profile W!
    fx["chain"]["txs"][_h32("alice-iss-tx")]["inputs"][0]["script_sig_hex"] = "483045"
    add("CHAIN_TX_CONSTRUCTION", "SL-LDGR-009", "invocation", fx)

    reserved_06 = bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x06, 0x22, 0x01]) + bytes.fromhex(_h32("r06")) + bytes([0x00])
    add("CHAIN_FRAME_INVALID", "SL-LDGR-010", "opreturn_decode", {"script_hex": reserved_06.hex()})

    fx = _base_invocation_fixture()
    fx["chain"]["txs"][_h32("alice-iss-tx")]["confirmed_height"] = 750010
    fx["operator_min_depth"] = 6
    add("CHAIN_DEPTH_INSUFFICIENT", "SL-LDGR-008", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["blocks"] = {_h32("recent-blk-749990"): 749000}
    add("CHAIN_RECENCY_INVALID", "SL-LDGR-008", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["txs"][_h32("alice-seal-tx")]["confirmed_height"] = None
    add("SEAL_UNAVAILABLE", "SL-LDGR-011", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["txs"][_h32("alice-seal-tx")]["outputs"]["0"]["spent_by_txid"] = _h32("revoke-tx")
    add("SEAL_SPENT", "SL-LDGR-011", "invocation", fx)

    # ---- 3. NAME_*, MANIFEST_*, AUTH_*, DEVICE_* (14 codes — ALL derived from history/scripts!) ----
    fx = _base_invocation_fixture()
    del fx["chain"]["names"]["id/alice"]
    add("NAME_NOT_FOUND", "SL-IDEN-004", "invocation", fx)

    fx = _base_invocation_fixture()
    # Last update at 714010 + D(36000) == 750010 == tip_height -> derived NAME_EXPIRED!
    fx["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx["_alice_reg"],
        fx["_alice_owner_pol"],
        {"link": {"grant": fx["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx["_alice_man"]), "s": 1}},
        first_height=710000,
        update_height=714010,
    )
    add("NAME_EXPIRED", "SL-LDGR-003", "invocation", fx)

    fx = _base_invocation_fixture()
    other_k = _kp("hijacker")
    fx["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx["_alice_reg"],
        {"kind": "key", "pk": other_k["comp"]},
        {"link": {"grant": fx["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx["_alice_man"]), "s": 1}},
    )
    add("NAME_OWNER_MISMATCH", "SL-IDEN-004", "invocation", fx)

    fx = _base_invocation_fixture()
    # Funding-wallet FIRSTUPDATE with no owner-authored SIGHASH_ALL NAME_UPDATE -> derived NAME_WRITER_UNVERIFIED!
    fx["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx["_alice_reg"],
        fx["_alice_owner_pol"],
        {"link": {"grant": fx["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx["_alice_man"]), "s": 1}},
        first_height=749000,
        first_only=True,
    )
    add("NAME_WRITER_UNVERIFIED", "SL-LDGR-007", "invocation", fx)

    fx = _base_invocation_fixture()
    # Truncated history chain -> derived NAME_HISTORY_UNAVAILABLE!
    fx["chain"]["names"]["id/alice"]["history_truncated"] = True
    add("NAME_HISTORY_UNAVAILABLE", "SL-IDEN-004", "invocation", fx)

    fx = _base_invocation_fixture()
    # Role key reused across grant and nostr inside encoded NAME_UPDATE script -> derived NAME_VALUE_INVALID!
    dup_pk = fx["_keys"]["alice_gr"]["xonly"]
    fx["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx["_alice_reg"],
        fx["_alice_owner_pol"],
        {"link": {"grant": dup_pk}, "nostr": dup_pk},
    )
    add("NAME_VALUE_INVALID", "SL-IDEN-003", "invocation", fx)

    fx = _base_invocation_fixture()
    # Name update AFTER recent_block (749990) rotates link.grant -> derived NAME_ROLE_CHANGED!
    rot_gr = _kp("alice-grant-rotated")
    fx["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx["_alice_reg"],
        fx["_alice_owner_pol"],
        {"link": {"grant": fx["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx["_alice_man"]), "s": 1}},
        first_height=748000,
        update_height=749000,
        extra_updates=[{
            "txid": _h32("alice-role-rot-upd"),
            "confirmed_height": 749995,
            "value": {"link": {"grant": rot_gr["xonly"]}, "m": {"h": sl.content_addr(fx["_alice_man"]), "s": 1}},
        }],
    )
    add("NAME_ROLE_CHANGED", "SL-IDEN-003", "invocation", fx)

    # MANIFEST_* via executor_ref
    def _eref_fx() -> dict[str, Any]:
        f = _base_invocation_fixture()
        gp = copy.deepcopy(f["bundle"]["grants"][0]["payload"])
        del gp["executor"]
        gp["executor_ref"] = {"label": "work", "provider_of": "id/alice", "service_type": "mail"}
        _reanchor_grant(f, gp)
        return f

    fx = _eref_fx()
    fx["bundle"]["manifests"] = {}
    fx["chain"]["manifests"] = {}
    add("MANIFEST_UNAVAILABLE", "SL-IDEN-009", "invocation", fx)

    fx = _eref_fx()
    bad_man = copy.deepcopy(fx["_alice_man"])
    bad_man["seq"] = 99
    fx["bundle"]["manifests"] = {"id/alice": bad_man}
    fx["chain"]["manifests"] = {}
    add("MANIFEST_MISMATCH", "SL-IDEN-009", "invocation", fx)

    fx = _eref_fx()
    fx["journal"]["manifest_heads"] = [{
        "name": "id/alice",
        "reg_key": f"{_h32('alice-reg')}:0",
        "seq": 5,
        "sha256": _h32("newer-man"),
        "anchoring_txid_active": True,
    }]
    add("MANIFEST_ROLLBACK", "SL-IDEN-008", "invocation", fx)

    # AUTH_* (3 codes — strictly Draft 2020-12 schema-valid AuthChallenge: NO network/genesis!)
    auth_k = _kp("auth-key")
    auth_seal_k = _kp("auth-seal")
    auth_chal_p = {
        "auth_pubkey": auth_k["xonly"],
        "expires_at": 1795220005,
        "issued_at": 1795219950,
        "name": "id/alice",
        "nonce": _h32("auth-n1"),
        "service_id": "id/mail-host-a",
        "type": "seallink-auth-challenge/1",
    }
    auth_chal = sl.sign_envelope(auth_chal_p, [auth_k["sk"]])
    fx_a = _base_invocation_fixture()
    add("AUTH_CHALLENGE_EXPIRED", "SL-IDEN-010", "auth_challenge", {
        "challenge": auth_chal,
        "chain": fx_a["chain"],
        "journal": {"journal_id": _h32("aj"), "auth_nonces": {_h32("auth-n1"): {"used": False, "service_id": "id/mail-host-a", "issued_at": 1795219950, "expires_at": 1795220005}}},
        "service_id": "id/mail-host-a",
        "manifests": fx_a["bundle"]["manifests"],
    })

    auth_chal_p2 = {**auth_chal_p, "issued_at": 1795220000, "expires_at": 1795220100}
    auth_chal2 = sl.sign_envelope(auth_chal_p2, [auth_k["sk"]])
    add("AUTH_CHALLENGE_INVALID", "SL-IDEN-010", "auth_challenge", {
        "challenge": auth_chal2,
        "chain": fx_a["chain"],
        "journal": {"journal_id": _h32("aj2"), "auth_nonces": {_h32("auth-n1"): {"used": True, "service_id": "id/mail-host-a", "issued_at": 1795220000, "expires_at": 1795220100}}},
        "service_id": "id/mail-host-a",
        "manifests": fx_a["bundle"]["manifests"],
    })

    add("AUTH_KEY_UNPINNED", "SL-IDEN-010", "auth_challenge", {
        "challenge": auth_chal2,
        "chain": fx_a["chain"],
        "journal": {"journal_id": _h32("aj3"), "auth_nonces": {_h32("auth-n1"): {"used": False, "service_id": "id/mail-host-a", "issued_at": 1795220000, "expires_at": 1795220100}}},
        "service_id": "id/mail-host-a",
        "manifests": fx_a["bundle"]["manifests"],
    })

    # DEVICE_UNAUTHORIZED (strictly Draft 2020-12 schema-valid OwnerCommand!)
    dev_k = _kp("dev-l1")
    cmd_p = {
        "arguments": {"scope": "all"},
        "command": "keyholder-halt",
        "exp": 1795220300,
        "genesis": GENESIS_MAIN,
        "iat": 1795220000,
        "level": 2,
        "network": "main",
        "nonce": _h32("cmd-n1"),
        "owner": "id/alice",
        "target_executor": "id/station-a",
        "type": "seallink-owner-command/1",
    }
    cmd_env = sl.sign_envelope(cmd_p, [dev_k["sk"]])
    dev_list = {
        "devices": [{
            "alg": "bip340",
            "ceiling": 1,
            "key": dev_k["xonly"],
            "label": "laptop",
            "presence": False,
            "seal": {"script_policy": {"kind": "key", "pk": auth_seal_k["comp"]}, "txid": _h32("dseal"), "vout": 0},
        }],
        "network": "main",
        "owner": "id/alice",
        "seq": 1,
        "type": "seallink-device-list/1",
    }
    add("DEVICE_UNAUTHORIZED", "SL-IDEN-011", "owner_command", {
        "command": cmd_env,
        "device_list": dev_list,
        "is_foreign_service": True,
        "chain": fx_a["chain"],
    })

    # ---- 4. ORIGIN_*, WARD_*, GUARDIAN_*, SUBJECT_*, RECOVERY_* (10 codes) ----
    of = _base_origin_fixture()
    add("ORIGIN_UNVERIFIED", "SL-ORIG-002", "origin_status", {
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": ["id/other-trusted-registry"],
    })

    of = _base_origin_fixture()
    of["chain"]["registered_bindings"] = {f"{_h32('oleo-reg')}:0": _h32("other-origin")}
    add("ORIGIN_BINDING_INVALID", "SL-ORIG-003", "origin_status", {
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
    })

    of = _base_origin_fixture()
    of["chain"]["txs"][_h32("ostat-tx")]["outputs"]["0"]["spent_by_txid"] = _h32("unpresented-status-spend")
    of["chain"]["txs"][_h32("unpresented-status-spend")] = {"confirmed_height": 750050, "opreturn_hex": sl.encode_opreturn(0x09, _h32("unknown-doc")).hex(), "outputs": {}}
    add("ORIGIN_STATUS_INCOMPLETE", "SL-ORIG-002", "origin_status", {
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
    })

    of = _base_origin_fixture()
    assent_alone = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "network": "main",
            "nonce": _h32("wa-1"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": sl.object_id(of["contract"]),
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [of["_keys"]["ward_gr"]["sk"]],
    )
    add("WARD_AUTONOMOUS_FORBIDDEN", "SL-ORIG-006", "assent", {
        "assent": assent_alone,
        "contract": of["contract"],
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
    })

    of = _base_origin_fixture()
    assent_inactive = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": of["_origin_id"], "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000,
            "network": "main",
            "nonce": _h32("wi-2"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": sl.object_id(of["contract"]),
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [{"slot": 2, "revision": 1, "guardian_name": "id/parent-b", "signers": [of["_keys"]["g2_gr"]["sk"]]}],
    )
    add("GUARDIAN_INACTIVE", "SL-ORIG-007", "assent", {
        "assent": assent_inactive,
        "contract": of["contract"],
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
    })

    of = _base_origin_fixture()
    assent_1of2 = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": of["_origin_id"], "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000,
            "network": "main",
            "nonce": _h32("wq-1"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": sl.object_id(of["contract"]),
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [of["_keys"]["g1_gr"]["sk"]]}],
    )
    add("GUARDIAN_QUORUM_UNMET", "SL-ORIG-005", "assent", {
        "assent": assent_1of2,
        "contract": of["contract"],
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
    })

    of = _base_origin_fixture()
    # Majority reached (t_low >= maj_unix), but ward name.updates[] has NOT transferred to fresh subject owner_policy!
    of["chain"]["credible_utc_interval"] = [of["_maj_unix"] + 100, of["_maj_unix"] + 200]
    add("GUARDIAN_TRANSFER_PENDING", "SL-ORIG-011", "origin_status", {
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
    })

    of = _base_origin_fixture()
    of["chain"]["credible_utc_interval"] = [of["_maj_unix"] - 10, of["_maj_unix"] + 10]
    add("GUARDIAN_TIME_BOUNDARY", "SL-ORIG-010", "origin_status", {
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
    })

    of = _base_origin_fixture()
    end_env = sl.sign_envelope(
        {
            "basis_sha256": _h32("end-basis"),
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": of["origin_bundle"]["origin"]["payload"]["issuer"],
            "network": "main",
            "origin_id": of["_origin_id"],
            "reason": "dematerialization",
            "status_prev_outpoint": {"txid": _h32("ostat-tx"), "vout": 0},
            "type": "seallink-end/1",
        },
        [of["_keys"]["reg_cred"]["sk"]],
    )
    end_txid = _h32("end-spend-tx")
    of["chain"]["txs"][_h32("ostat-tx")]["outputs"]["0"]["spent_by_txid"] = end_txid
    of["chain"]["txs"][end_txid] = {"confirmed_height": 750050, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(end_env)).hex(), "outputs": {}}
    of["origin_bundle"]["end_record"] = end_env
    add("SUBJECT_ENDED", "SL-ORIG-012", "origin_status", {
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
    })

    of = _base_origin_fixture()
    rec_binding = {
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo-recovered",
        "network": "main",
        "next_recovery_policy": of["_rec_pol"],
        "next_recovery_vout": 0,
        "origin_id": of["_origin_id"],
        "owner_policy": of["origin_bundle"]["name_binding"]["owner_policy"],
        "registration": {"txid": _h32("oleo-new-reg"), "vout": 0},
        "seq": 2,
        "supersedes_binding_id": sl.object_id(of["origin_bundle"]["name_binding"]),
        "type": "seallink-name-binding/1",
    }
    rec_txid = _h32("orec-0x0c-tx")
    rec_id = sl.object_id(rec_binding)
    of["chain"]["txs"][_h32("orecov-tx")]["outputs"]["0"]["spent_by_txid"] = rec_txid
    of["chain"]["txs"][rec_txid] = {
        "confirmed_height": 750050,
        "opreturn_hex": sl.encode_opreturn(0x0C, rec_id).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(of["_rec_pol"])}},
    }
    # Live owner broadcasts owner-authored SIGHASH_ALL NAME_UPDATE with OP_RETURN 0x10 RECOVERY_CANCEL!
    leo_upds = of["chain"]["names"]["id/child-leo"]["updates"]
    prev_leo = leo_upds[-1]
    cancel_spk, _ = sl.compile_script_policy(prev_leo["owner_policy"])
    cancel_val = sl.jcs_encode({"link": {"origin": of["_origin_id"]}})
    leo_upds.append({
        "op": "NAME_UPDATE",
        "txid": _h32("leo-0x10-cancel-tx"),
        "vout": 0,
        "confirmed_height": 750060,
        "owner_policy": prev_leo["owner_policy"],
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", cancel_spk, name=b"id/child-leo", value=cancel_val).hex(),
        "prev_input": {"txid": prev_leo["txid"], "vout": prev_leo["vout"], "witness_policy": prev_leo["owner_policy"], "sighash_bytes": [0x01]},
        "opreturn_hex": sl.encode_opreturn(0x10, rec_id).hex(),
    })
    of["origin_bundle"]["recovery_bindings"] = [rec_binding]
    add("RECOVERY_FORBIDDEN", "SL-ORIG-014", "origin_status", {
        "origin_bundle": of["origin_bundle"],
        "chain": of["chain"],
        "trusted_origin_issuers": of["trusted_origin_issuers"],
        "assert_binding_id": rec_id,
    })

    # ---- 5. CONTRACT_*, CRED_*, NOTARY_* (11 codes) ----
    def _contract_fx() -> dict[str, Any]:
        f = _base_invocation_fixture()
        f["executor_cfg"]["name"] = "id/station-a"
        c_salt = _h32("c0-salt")
        sess_cap = {"action": "agent/session", "target": "station:id/station-a:slot1", "quotas": [{"kind": "seallink/count", "max": "5", "resource": "station:id/station-a:slot1", "unit": "starts", "window": "term"}]}
        c0 = {"machine_terms": {"capabilities": [sess_cap]}, "text": "Isolated session terms"}
        cseal_a = _kp("cseal-a")
        cseal_b = _kp("cseal-b")
        cseal_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(cseal_a["comp"], cseal_b["comp"])}
        c_obj = {
            "clause_commitments": [sl.clause_commit(c_salt, c0)],
            "config_sha256": _h32("cfg-agreed"),
            "contract_salt": _h32("cs-root"),
            "genesis": GENESIS_MAIN,
            "machine_clause_indices": [0],
            "network": "main",
            "parties": [
                {"party_id": "client-1", "role": "client", "signing_policy": {"m": 1, "pks": [f["_keys"]["alice_gr"]["xonly"]]}},
                {"party_id": "worker-1", "role": "worker", "signing_policy": {"m": 1, "pks": [f["_keys"]["agent_req"]["xonly"]]}},
            ],
            "profile": "org.seallink/agent-session-v1",
            "seal": {"script_policy": cseal_pol, "txid": _h32("cseal-tx"), "vout": 0},
            "type": "seallink-contract/1",
            "window": {"not_after_height": 770000, "not_before_height": 749000},
        }
        cid = sl.object_id(c_obj)
        a1 = sl.sign_envelope({
            "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
            "nonce": _h32("ca-1"), "party_id": "client-1", "party_role": "client", "target_id": cid, "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        }, [f["_keys"]["alice_gr"]["sk"]])
        a2 = sl.sign_envelope({
            "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
            "nonce": _h32("ca-2"), "party_id": "worker-1", "party_role": "worker", "target_id": cid, "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        }, [f["_keys"]["agent_req"]["sk"]])
        gp = copy.deepcopy(f["bundle"]["grants"][0]["payload"])
        gp["executor"] = {"key": f["_keys"]["host_rcpt"]["xonly"], "name": "id/station-a"}
        gp["contract_id"] = cid
        gp["capabilities"] = [sess_cap]
        _reanchor_grant(f, gp)
        inv_p = copy.deepcopy(f["invocation"]["payload"])
        inv_p["action"] = "agent/session"
        inv_p["executor"] = gp["executor"]
        inv_p["target"] = "station:id/station-a:slot1"
        inv_p["arguments"] = {"config_sha256": _h32("cfg-agreed"), "op": "start", "session_slot": "slot1"}
        f["invocation"] = sl.sign_envelope(inv_p, [f["_keys"]["agent_req"]["sk"]])
        f["bundle"]["contract"] = c_obj
        f["bundle"]["contract_assents"] = [a1, a2]
        f["bundle"]["disclosed_clauses"] = {"0": {"salt_hex": c_salt, "clause": c0}}
        f["chain"]["txs"][_h32("cseal-tx")] = {"confirmed_height": 749500, "outputs": {"0": {"script_pubkey_hex": _spk_hex(cseal_pol)}}}
        f["executor_cfg"]["runtime_config_sha256"] = _h32("cfg-agreed")
        return f

    fx = _contract_fx()
    del fx["bundle"]["contract"]
    add("CONTRACT_NOT_PRESENTED", "SL-CONT-002", "invocation", fx)

    fx = _contract_fx()
    fx["bundle"]["contract"]["contract_salt"] = _h32("wrong-salt")
    add("CONTRACT_ID_MISMATCH", "SL-CONT-002", "invocation", fx)

    fx = _contract_fx()
    fx["bundle"]["contract_assents"] = fx["bundle"]["contract_assents"][:1]
    add("CONTRACT_ASSENT_INVALID", "SL-CONT-004", "invocation", fx)

    fx = _contract_fx()
    del fx["bundle"]["contract"]["seal"]
    new_cid = sl.object_id(fx["bundle"]["contract"])
    gp_cs = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    gp_cs["contract_id"] = new_cid
    _reanchor_grant(fx, gp_cs)
    fx["bundle"]["contract_assents"] = [
        sl.sign_envelope({**a["payload"], "target_id": new_cid}, [sk])
        for a, sk in zip(fx["bundle"]["contract_assents"], [fx["_keys"]["alice_gr"]["sk"], fx["_keys"]["agent_req"]["sk"]])
    ]
    add("CONTRACT_SEAL_MISSING", "SL-CONT-005", "invocation", fx)

    fx = _contract_fx()
    fx["bundle"]["disclosed_clauses"] = {}
    add("CONTRACT_TERMS_MISMATCH", "SL-CONT-002", "invocation", fx)

    fx = _contract_fx()
    fx["executor_cfg"]["runtime_config_sha256"] = _h32("different-runtime-config")
    add("CONTRACT_CONFIG_MISMATCH", "SL-CONT-006", "invocation", fx)

    # CRED_* (4 codes — strictly Draft 2020-12 schema-valid Credential with claims & issued_at!)
    def _cred_fx(lifecycle: str = "revocable", break_h_c: int | None = None) -> dict[str, Any]:
        iss_own = _kp("cred-iss-own")
        iss_cr = _kp("cred-iss-cr")
        cseal_k = _kp("cred-seal")
        cseal_pol = {"kind": "key", "pk": cseal_k["comp"]}
        iss_owner_pol = {"kind": "key", "pk": iss_own["comp"]}
        iss_reg = {"txid": _h32("ciss-reg"), "vout": 0}
        cp: dict[str, Any] = {
            "claim_commitments": {"verified": sl.clause_commit(_h32("cs1"), {"verified": True})},
            "claims": {"verified": True},
            "credential_kind": "subject-claim",
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": {
                "name": "id/issuer-a",
                "owner_policy": iss_owner_pol,
                "registration": iss_reg,
                "role_policy": {"m": 1, "pks": [iss_cr["xonly"]]},
            },
            "lifecycle": lifecycle,
            "network": "main",
            "not_before_height": 749000,
            "not_after_height": 760000,
            "subject": {"key": _kp("subj")["xonly"], "mode": "key"},
            "type": "seallink-credential/1",
        }
        if lifecycle == "revocable":
            cp["revocation_seal"] = {"script_policy": cseal_pol, "txid": _h32("cr-seal-tx"), "vout": 0}
        c_env = sl.sign_envelope(cp, [iss_cr["sk"]])
        atx = _h32("cr-anchor-tx")
        base_hist = sv.make_name_history(
            "id/issuer-a", iss_reg, iss_owner_pol, {"link": {"cred": iss_cr["xonly"]}},
            first_height=748000, update_height=749000,
        )
        prev_u = base_hist["updates"][-1]
        extra_upds = None
        if break_h_c is not None:
            brk_obj = {
                "compromised_policy": {"m": 1, "pks": [iss_cr["xonly"]]},
                "genesis": GENESIS_MAIN,
                "h_c": break_h_c,
                "issuer": {"name": "id/issuer-a", "owner_policy": iss_owner_pol, "registration": iss_reg},
                "name_input": {"txid": prev_u["txid"], "vout": prev_u["vout"]},
                "role": "cred",
                "type": "seallink-credential-break/1",
            }
            extra_upds = [{
                "txid": _h32("ciss-0x0b-break-tx"),
                "confirmed_height": 749600,
                "value": {"link": {"cred": _kp("cred-iss-cr-new")["xonly"]}},
                "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_obj).hex(), 0x00, h_c=break_h_c).hex(),
            }]
        chain = {
            "network": "main",
            "genesis": GENESIS_MAIN,
            "tip_height": 750010,
            "tip_hash": _h32("ctip"),
            "tip_header_time": 1795220000,
            "tip_first_sight": 1795220005,
            "now": 1795220010,
            "comparison_peers": [{"healthy": True, "height": 750010, "hash_at_tip": _h32("ctip")}],
            "names": {
                "id/issuer-a": sv.make_name_history(
                    "id/issuer-a", iss_reg, iss_owner_pol, {"link": {"cred": iss_cr["xonly"]}},
                    first_height=748000, update_height=749000, extra_updates=extra_upds,
                ),
            },
            "txs": {
                atx: {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(c_env)).hex(), "outputs": {}},
                _h32("cr-seal-tx"): {"confirmed_height": 749400, "outputs": {"0": {"script_pubkey_hex": _spk_hex(cseal_pol)}}},
            },
        }
        return {"credential": c_env, "anchor_txid": atx, "chain": chain}

    cf = _cred_fx()
    cf["anchor_txid"] = None
    add("CRED_ANCHOR_MISSING", "SL-CONT-008", "credential", cf)

    cf = _cred_fx("eternal", break_h_c=749400)  # anchor 749500 >= h_c 749400 -> derived 0x0b CRED_ISSUER_CLOSED!
    add("CRED_ISSUER_CLOSED", "SL-CONT-009", "credential", cf)

    cf = _cred_fx()
    cf["chain"]["tip_height"] = 760000
    cf["chain"]["comparison_peers"] = [{"healthy": True, "height": 760000, "hash_at_tip": _h32("ctip")}]
    add("CRED_WINDOW_CLOSED", "SL-CONT-010", "credential", cf)

    cf = _cred_fx("revocable")
    cause_tx = _h32("cause-spend")
    cf["chain"]["txs"][_h32("cr-seal-tx")]["outputs"]["0"]["spent_by_txid"] = cause_tx
    wdr_obj = {
        "cause_sha256": _h32("cause-reason"),
        "credential_id": sl.object_id(cf["credential"]["payload"]),
        "genesis": GENESIS_MAIN,
        "type": "seallink-credential-withdrawal/1",
    }
    cf["chain"]["txs"][cause_tx] = {
        "confirmed_height": 750005,
        "opreturn_hex": sl.encode_opreturn(0x0A, sl.signing_digest(wdr_obj).hex()).hex(),
        "outputs": {},
    }
    add("CRED_REVOKED_FOR_CAUSE", "SL-CONT-010", "credential", cf)

    # ---- 6. GRANT_*, INVOKE_*, QUOTA_*, SESSION_*, JOURNAL_* (20 codes) + NOTARY_REQUIRED ----
    # Fix _delegation_fx executor_cfg to match target station:id/station-a:tools!
    def _delegation_fx(notary_mode: str = "none", with_stop: bool = False) -> dict[str, Any]:
        f = _base_invocation_fixture()
        f["executor_cfg"]["name"] = "id/station-a"
        del_k = _kp("del-key")
        cseal_iss = _kp("cseal-iss")
        row_k = _kp("row-coin")
        stop_k = _kp("stop-coin")
        pool_q = {"kind": "seallink/count", "max": "10", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}
        row_q = {"kind": "seallink/count", "max": "2", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}
        rng: dict[str, Any] = {"count": 2, "first": 0, "script_policy": {"kind": "key", "pk": row_k["comp"]}, "txid": _h32("row-tx")}
        if with_stop:
            rng["stop_txid"] = _h32("stop-tx")
            rng["stop_first"] = 0
            rng["stop_script_policy"] = {"kind": "key", "pk": stop_k["comp"]}
        parent_p = copy.deepcopy(f["bundle"]["grants"][0]["payload"])
        parent_p["executor"] = {"key": f["_keys"]["host_rcpt"]["xonly"], "name": "id/station-a"}
        parent_p["capabilities"] = [{"action": "agent/tool", "quotas": [pool_q], "target": "station:id/station-a:tools"}]
        tpl_obj: dict[str, Any] = {
            "capabilities": [{"action": "agent/tool", "quotas": [row_q], "target": "station:id/station-a:tools", "where": {"tool_name": {"in": ["pytest"]}}}],
            "executor": parent_p["executor"],
            "notary_mode": notary_mode,
            "recipient_rule": {"key": f["_keys"]["agent_req"]["xonly"], "mode": "exact_key"},
        }
        del_obj: dict[str, Any] = {
            "child_seal_key": cseal_iss["comp"],
            "groups": [{
                "ranges": [rng],
                "template": tpl_obj,
            }],
            "key": del_k["xonly"],
            "pools": [pool_q],
        }
        if notary_mode in ("optional_stop", "required_act"):
            not_own = _kp("notary-own")
            tpl_obj["notary_name"] = "id/notary-1"
            del_obj["notaries"] = [{
                "name": "id/notary-1",
                "owner_policy": {"kind": "key", "pk": not_own["comp"]},
                "registration": {"txid": _h32("notary-reg"), "vout": 0},
            }]
        parent_p["delegate"] = del_obj
        parent_env = sl.sign_envelope(parent_p, [f["_keys"]["alice_gr"]["sk"]])
        pid = sl.object_id(parent_p)
        cseal_pol = {"kind": "key", "pk": cseal_iss["comp"]}
        child_p = {
            "capabilities": [{"action": "agent/tool", "quotas": [row_q], "target": "station:id/station-a:tools", "where": {"tool_name": {"eq": "pytest"}}}],
            "executor": parent_p["executor"],
            "genesis": GENESIS_MAIN,
            "network": "main",
            "not_after_height": 755000,
            "not_before_height": 750000,
            "parent": {"grant_id": pid, "ordinal": 1},
            "recent_block": parent_p["recent_block"],
            "recipient": {"key": f["_keys"]["agent_req"]["xonly"], "mode": "key"},
            "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": cseal_pol, "txid": _h32("child-seal-tx"), "vout": 0}},
            "type": "seallink-grant/1",
        }
        child_env = sl.sign_envelope(child_p, [del_k["sk"]])
        cid = sl.object_id(child_p)
        p_itx = _h32("p-iss-tx")
        c_itx = _h32("c-iss-tx")
        f["chain"]["txs"][p_itx] = {
            "confirmed_height": 749998,
            "inputs": [sv.make_segwit_input(_h32("alice-seal-tx"), 1)],
            "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(parent_env), "grant_id": pid, "type": "seallink-issuance/1"}).hex()).hex(),
            "outputs": {},
        }
        f["chain"]["txs"][c_itx] = {
            "confirmed_height": 749999,
            "inputs": [sv.make_segwit_input(_h32("row-tx"), 0), sv.make_segwit_input(_h32("child-seal-tx"), 1)],
            "opreturn_hex": sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(child_env), "grant_id": cid, "type": "seallink-issuance/1"}).hex()).hex(),
            "outputs": {},
        }
        f["chain"]["txs"][_h32("child-seal-tx")] = {
            "confirmed_height": 749995,
            "inputs": [sv.make_segwit_input(_h32("cseal-fund"), 0)],
            "outputs": {"0": {"script_pubkey_hex": _spk_hex(cseal_pol)}, "1": {"script_pubkey_hex": _spk_hex(cseal_pol)}},
        }
        if with_stop:
            f["chain"]["txs"][_h32("stop-tx")] = {"confirmed_height": 749990, "outputs": {"0": {"script_pubkey_hex": _spk_hex({"kind": "key", "pk": stop_k["comp"]})}}}
        inv_p = copy.deepcopy(f["invocation"]["payload"])
        inv_p["action"] = "agent/tool"
        inv_p["executor"] = parent_p["executor"]
        inv_p["target"] = "station:id/station-a:tools"
        inv_p["arguments"] = {"input_sha256": _h32("in1"), "max_output_bytes": "1024", "tool_name": "pytest"}
        inv_p["proof_path"] = [{"grant_id": pid, "issuance_txid": p_itx}, {"grant_id": cid, "issuance_txid": c_itx}]
        f["invocation"] = sl.sign_envelope(inv_p, [f["_keys"]["agent_req"]["sk"]])
        f["bundle"]["grants"] = [parent_env, child_env]
        f["_del_k"] = del_k
        return f

    fx = _delegation_fx(notary_mode="required_act")
    add("NOTARY_REQUIRED", "SL-GRNT-011", "invocation", fx)

    fx = _base_invocation_fixture()
    gid_0 = sl.object_id(fx["bundle"]["grants"][0]["payload"])
    fx["journal"]["closures"] = {gid_0: {"cause": "SEAL_SPENT", "subject_id": gid_0, "subject_kind": "grant"}}
    add("GRANT_CLOSED", "SL-GRNT-012", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["tip_height"] = 760000
    fx["chain"]["comparison_peers"] = [{"healthy": True, "height": 760000, "hash_at_tip": _h32("tip-750010")}]
    add("GRANT_WINDOW_CLOSED", "SL-GRNT-004", "invocation", fx)

    fx = _base_invocation_fixture()
    gp_wo = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    gp_wo["revocation"] = {"mode": "window_only"}
    gp_wo["not_after_height"] = 750012
    _reanchor_grant(fx, gp_wo)
    add("GRANT_SEAL_REQUIRED", "SL-GRNT-004", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["executor_cfg"]["name"] = "id/different-executor"
    add("GRANT_EXECUTOR_MISMATCH", "SL-GRNT-012", "invocation", fx)

    fx = _base_invocation_fixture()
    gp_erf = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    del gp_erf["executor"]
    gp_erf["executor_ref"] = {"label": "work", "provider_of": "id/alice", "service_type": "mail"}
    gp_erf["capabilities"] = [{"action": "mail/send", "target": "mailbox:id/alice:work"}]
    _reanchor_grant(fx, gp_erf)
    inv_p_erf = copy.deepcopy(fx["invocation"]["payload"])
    inv_p_erf["action"] = "mail/send"
    inv_p_erf["arguments"] = {"body_sha256": _h32("b"), "size_bytes": "10", "subject": "hi", "to": "b@example.org"}
    fx["invocation"] = sl.sign_envelope(inv_p_erf, [fx["_keys"]["agent_req"]["sk"]])
    add("GRANT_EXECUTOR_REF_FORBIDDEN", "SL-GRNT-003", "invocation", fx)

    fx = _base_invocation_fixture()
    gp_cr = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    gp_cr["capabilities"] = [{
        "action": "agent/session",
        "quotas": [{"kind": "seallink/count", "max": "1", "resource": "station:id/mail-host-a:s1", "unit": "starts", "window": "term"}],
        "target": "station:id/mail-host-a:s1",
    }]
    _reanchor_grant(fx, gp_cr)
    inv_p_cr = copy.deepcopy(fx["invocation"]["payload"])
    inv_p_cr["action"] = "agent/session"
    inv_p_cr["target"] = "station:id/mail-host-a:s1"
    inv_p_cr["arguments"] = {"config_sha256": _h32("c"), "op": "start", "session_slot": "s1"}
    fx["invocation"] = sl.sign_envelope(inv_p_cr, [fx["_keys"]["agent_req"]["sk"]])
    add("GRANT_CONTRACT_REQUIRED", "SL-CONT-001", "invocation", fx)

    fx = _base_invocation_fixture()
    gp_tf = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    gp_tf["terms_text"] = "Read politely."
    _reanchor_grant(fx, gp_tf)
    add("GRANT_TEXT_FORBIDDEN", "SL-GRNT-005", "invocation", fx)

    # GRANT_TARGET_UNAUTHORIZED (B-1): foreign issuer id/mallory issuing a grant targeting mailbox:id/alice:work!
    fx = _base_invocation_fixture()
    mal_own = _kp("mallory-own")
    mal_gr = _kp("mallory-gr")
    mal_opol = {"kind": "key", "pk": mal_own["comp"]}
    mal_reg = {"txid": _h32("mallory-reg"), "vout": 0}
    fx["chain"]["names"]["id/mallory"] = sv.make_name_history(
        "id/mallory", mal_reg, mal_opol, {"link": {"grant": mal_gr["xonly"]}}, first_height=748000, update_height=749000
    )
    gp_tu = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    gp_tu["issuer"] = {"name": "id/mallory", "owner_policy": mal_opol, "registration": mal_reg, "role_policy": {"m": 1, "pks": [mal_gr["xonly"]]}}
    _reanchor_grant(fx, gp_tu, signer_sk=mal_gr["sk"])
    add("GRANT_TARGET_UNAUTHORIZED", "SL-MAIL-003", "invocation", fx)

    fx = _delegation_fx()
    p_nodel = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    del p_nodel["delegate"]
    p_env_nd = sl.sign_envelope(p_nodel, [fx["_keys"]["alice_gr"]["sk"]])
    pid_nd = sl.object_id(p_nodel)
    fx["chain"]["txs"][_h32("p-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(p_env_nd), "grant_id": pid_nd, "type": "seallink-issuance/1"}).hex()).hex()
    c_p_nd = copy.deepcopy(fx["bundle"]["grants"][1]["payload"])
    c_p_nd["parent"]["grant_id"] = pid_nd
    c_env_nd = sl.sign_envelope(c_p_nd, [fx["_del_k"]["sk"]])
    cid_nd = sl.object_id(c_p_nd)
    fx["bundle"]["grants"] = [p_env_nd, c_env_nd]
    inv_nd = copy.deepcopy(fx["invocation"]["payload"])
    inv_nd["proof_path"] = [{"grant_id": pid_nd, "issuance_txid": _h32("p-iss-tx")}, {"grant_id": cid_nd, "issuance_txid": _h32("c-iss-tx")}]
    fx["invocation"] = sl.sign_envelope(inv_nd, [fx["_keys"]["agent_req"]["sk"]])
    add("GRANT_NOT_DELEGABLE", "SL-GRNT-009", "invocation", fx)

    fx = _delegation_fx()
    c_wide = copy.deepcopy(fx["bundle"]["grants"][1]["payload"])
    c_wide["capabilities"][0]["where"] = {"tool_name": {"eq": "rm-rf"}}
    c_env_w = sl.sign_envelope(c_wide, [fx["_del_k"]["sk"]])
    cid_w = sl.object_id(c_wide)
    fx["chain"]["txs"][_h32("c-iss-tx")]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c_env_w), "grant_id": cid_w, "type": "seallink-issuance/1"}).hex()).hex()
    fx["bundle"]["grants"][1] = c_env_w
    inv_w = copy.deepcopy(fx["invocation"]["payload"])
    inv_w["proof_path"][1]["grant_id"] = cid_w
    fx["invocation"] = sl.sign_envelope(inv_w, [fx["_keys"]["agent_req"]["sk"]])
    add("GRANT_CHILD_WIDER", "SL-GRNT-010", "invocation", fx)

    fx = _delegation_fx()
    # Child issuance tx inputs[] omit the ordinal row coin -> derived GRANT_ROW_INVALID!
    fx["chain"]["txs"][_h32("c-iss-tx")]["inputs"] = [sv.make_segwit_input(_h32("child-seal-tx"), 1)]
    add("GRANT_ROW_INVALID", "SL-GRNT-009", "invocation", fx)

    fx = _delegation_fx(with_stop=True)
    fx["chain"]["txs"][_h32("stop-tx")]["outputs"]["0"]["spent_by_txid"] = _h32("notary-stop-spend")
    add("GRANT_ROW_STOPPED", "SL-GRNT-011", "invocation", fx)

    fx = _base_invocation_fixture()
    inv_ad = copy.deepcopy(fx["invocation"]["payload"])
    inv_ad["action"] = "mail/list"
    inv_ad["arguments"] = {"folder": "Invoices", "page": 0}  # Schema-valid MailListArgs!
    fx["invocation"] = sl.sign_envelope(inv_ad, [fx["_keys"]["agent_req"]["sk"]])
    add("INVOKE_ACTION_DENIED", "SL-GRNT-012", "invocation", fx)

    fx = _base_invocation_fixture()
    inv_cf = copy.deepcopy(fx["invocation"]["payload"])
    inv_cf["arguments"]["folder"] = "Personal"
    fx["invocation"] = sl.sign_envelope(inv_cf, [fx["_keys"]["agent_req"]["sk"]])
    add("INVOKE_CONSTRAINT_FAILED", "SL-WIRE-016", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["chain"]["now"] = fx["invocation"]["payload"]["exp"]
    add("INVOKE_TIME_INVALID", "SL-GRNT-006", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["journal"]["nonces"] = {fx["invocation"]["payload"]["nonce"]: _h32("different-inv-id")}
    add("INVOKE_REPLAY", "SL-GRNT-007", "invocation", fx)

    fx = _base_invocation_fixture()
    gp_qe = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    gp_qe["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "1", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "term"}]
    _reanchor_grant(fx, gp_qe)
    gid_qe = sl.object_id(gp_qe)
    fx["journal"]["quotas_used"] = [{
        "scope": f"own:{gid_qe}",
        "quota_key": "seallink/count|mailbox:id/alice:work|reads|term",
        "bucket_id": "term",
        "used": 1,
    }]
    add("QUOTA_EXCEEDED", "SL-GRNT-007", "invocation", fx)

    fx = _base_invocation_fixture()
    gp_qr = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    gp_qr["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "reads", "window": "seconds:3600"}]
    _reanchor_grant(fx, gp_qr)
    fx["journal"]["quota_watermarks"] = {"seallink/count|mailbox:id/alice:work|reads|seconds:3600": fx["chain"]["now"] + 60}
    add("QUOTA_CLOCK_REGRESSION", "SL-GRNT-007", "invocation", fx)

    add("SESSION_INVALID", "SL-GRNT-013", "bearer_session", {
        "token": "secret-bearer-token-xyz",
        "slot_binding": "slot-1",
        "chain": fx["chain"],
        "journal": {
            "journal_id": _h32("sj"),
            "sessions": {
                sl.sha256(b"secret-bearer-token-xyz").hex(): {"grant_id": _h32("g"), "slot_binding": "slot-1", "exp": 1795219000, "closed": False}
            },
        },
    })

    fx = _base_invocation_fixture()
    fx["journal"]["witness_readable"] = False
    add("JOURNAL_LOST", "SL-GRNT-014", "invocation", fx)

    fx = _base_invocation_fixture()
    fx["journal"]["write_token_active"] = False
    add("JOURNAL_FENCED", "SL-GRNT-014", "invocation", fx)

    # ---- 7. SERVICE_*, FEDERATION_* (3 codes — ALL schema-valid & derived!) ----
    fx = _eref_fx()
    empty_man = copy.deepcopy(fx["_alice_man"])
    empty_man["providers"] = []
    em_h = sl.content_addr(empty_man)
    fx["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx["_alice_reg"],
        fx["_alice_owner_pol"],
        {"link": {"grant": fx["_keys"]["alice_gr"]["xonly"]}, "m": {"h": em_h, "s": 1}},
    )
    fx["bundle"]["manifests"][em_h] = empty_man
    fx["chain"]["manifests"][em_h] = empty_man
    add("SERVICE_PROVIDER_UNBOUND", "SL-SERV-001", "invocation", fx)

    # SERVICE_MIGRATION_INVALID: Draft 2020-12 schema-valid MigrationManifest signed by real source_executor receipt_key,
    # with derived export files[] leaking a forbidden dkim_key!
    fx_mig = _base_invocation_fixture()
    dest_own = _kp("mail-host-b-own")
    export_files = [
        {"content_sha256": _h32("msg-blob-1"), "kind": "mail_blob", "media_type": "message/rfc822", "path": "mail/msg-1.eml"},
        {"content_sha256": _h32("leaked-dkim"), "kind": "dkim_key", "media_type": "application/x-pem-file", "path": "secrets/dkim.pem"},
    ]
    inv_sha = sl.sha256(sl.jcs_encode({"files": export_files})).hex()
    mig_env = sl.sign_envelope(
        {
            "dest_executor": {"name": "id/mail-host-b", "owner_policy": {"kind": "key", "pk": dest_own["comp"]}, "registration": {"txid": _h32("host-b-reg"), "vout": 0}},
            "genesis": GENESIS_MAIN,
            "holder": {"name": "id/alice", "owner_policy": fx_mig["_alice_owner_pol"], "registration": fx_mig["_alice_reg"]},
            "inventory_sha256": inv_sha,
            "issued_at": 1795220000,
            "journal_commitment": _h32("jc"),
            "journal_pos": 10,
            "migration_id": _h32("mig-id-1"),
            "network": "main",
            "outstanding_exposure": [],
            "service_type": "mail",
            "source_executor": {"name": "id/mail-host-a", "owner_policy": fx_mig["_host_owner_pol"], "registration": fx_mig["_host_reg"]},
            "type": "seallink-migration/1",
        },
        [fx_mig["_keys"]["host_rcpt"]["sk"]],
    )
    add("SERVICE_MIGRATION_INVALID", "SL-SERV-002", "migration", {
        "migration": mig_env,
        "export_bundle": {
            "files": export_files,
            "open_predecessor_grants": [],
            "source_journal_commitment": _h32("jc"),
            "source_journal_pos": 10,
            "source_write_token_fenced": True,
        },
        "chain": fx_mig["chain"],
        "manifests": fx_mig["bundle"]["manifests"],
        "journal": {"journal_id": _h32("mj")},
    })

    # FEDERATION_POLICY_DENIED: valid L2 OwnerCommand + route_hops passing through screening_agent!
    fx_fed = _base_invocation_fixture()
    l2_dev = _kp("fed-l2-dev")
    l2_seal_k = _kp("fed-l2-seal")
    l2_seal_pol = {"kind": "key", "pk": l2_seal_k["comp"]}
    fx_fed["chain"]["txs"][_h32("fed-l2-seal-tx")] = {
        "confirmed_height": 749990,
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(l2_seal_pol)}},
    }
    l2_cmd = sl.sign_envelope(
        {
            "arguments": {
                "fields_sha256": _h32("pii-fields"),
                "grant_id": sl.object_id(fx_fed["bundle"]["grants"][0]["payload"]),
                "recipient_name": "id/peer-b",
                "route_mode": "direct",
            },
            "command": "approve-pii-disclosure",
            "exp": 1795220300,
            "genesis": GENESIS_MAIN,
            "iat": 1795220000,
            "level": 2,
            "network": "main",
            "nonce": _h32("fed-l2-nonce"),
            "owner": "id/alice",
            "target_executor": "id/station-a",
            "type": "seallink-owner-command/1",
        },
        [l2_dev["sk"]],
    )
    l2_dev_list = {
        "devices": [{
            "alg": "bip340",
            "ceiling": 2,
            "key": l2_dev["xonly"],
            "label": "yubikey-l2",
            "presence": True,
            "seal": {"script_policy": l2_seal_pol, "txid": _h32("fed-l2-seal-tx"), "vout": 0},
        }],
        "network": "main",
        "owner": "id/alice",
        "seq": 1,
        "type": "seallink-device-list/1",
    }
    add("FEDERATION_POLICY_DENIED", "SL-SERV-004", "federation", {
        "policy": {"require_contour_a": True, "trusted_peers": ["id/peer-b"]},
        "peer_ctx": {
            "phase": "pii_disclosure",
            "route_hops": [
                {"actor": "id/screener-bot", "role": "screening_agent"},
                {"actor": "id/peer-b", "role": "counterparty"},
            ],
            "approval_command": l2_cmd,
            "device_list": l2_dev_list,
        },
        "grant": fx_fed["bundle"]["grants"][0],
        "chain": fx_fed["chain"],
    })

    # ACTION_UNSUPPORTED: core-only verifier (optional modules disabled) MUST refuse optional module requests fail-closed (D8-B3)
    fx_au = _base_invocation_fixture()
    add("ACTION_UNSUPPORTED", "SL-GRNT-013", "bearer_session", {
        "enabled_modules": ["core"],
        "token": _h32("disabled-mod-tok"),
        "slot_binding": "slot-1",
        "chain": fx_au["chain"],
        "journal": {"journal_id": _h32("au-j")},
    }, module="core")

    # Verify 100% coverage against registry/refusal-codes.json
    reg_codes = {e["code"] for e in json.loads((ROOT / "registry" / "refusal-codes.json").read_text(encoding="utf-8"))["codes"]}
    built_codes = {c["code"] for c in cases}
    missing = sorted(reg_codes - built_codes)
    extra = sorted(built_codes - reg_codes)
    assert not missing and not extra, f"Refusal matrix coverage mismatch: missing={missing}, extra={extra}"

    return {
        "suite": "refusal-coverage-matrix",
        "version": VERSION,
        "description": "Executable 86/86 refusal-code conformance matrix with Draft 2020-12 schema-validated semantic fixtures, explicit module selection tags, and derived ChainView evidence.",
        "total_registered_codes": len(reg_codes),
        "total_covered_codes": len(built_codes),
        "cases": sorted(cases, key=lambda c: c["code"]),
    }
