#!/usr/bin/env python3
"""
SealLink v1.0.0-draft.13 Audit Closure Conformance Suite (Commit 1):
Comprehensive positive, negative, and exact-boundary regressions covering all 33 confirmed
defects from the 8-reviewer v1.0.0-draft.12 audit (BLK-1..8, H-1..11, M-1..14).
"""

from __future__ import annotations

import copy
import struct
from typing import Any, Callable

import build_draft11_suite as bd11
import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = rm.GENESIS_MAIN


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-d13-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"d13:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def _mk_chain(tip_height: int = 750010) -> dict[str, Any]:
    ch = copy.deepcopy(rm._base_invocation_fixture()["chain"])
    ch["names"] = {}
    ch["txs"] = {}
    rm.sync_chain_tip(ch, height=tip_height)
    return ch


def _mk_upd(
    name: str,
    owner_pol: dict[str, Any],
    val_bytes: bytes,
    txid: str,
    height: int,
    prev_txid: str,
    prev_pol: dict[str, Any],
    *,
    prev_vout: int = 0,
    sighash_bytes: list[int] | None = None,
    opreturn_hex: str | None = None,
    inputs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    u: dict[str, Any] = {
        "confirmed_height": height,
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(owner_pol)), name=name.encode("utf-8"), value=val_bytes).hex(),
        "owner_policy": owner_pol,
        "prev_input": {"sighash_bytes": [1] if sighash_bytes is None else sighash_bytes, "txid": prev_txid, "vout": prev_vout, "witness_policy": prev_pol},
        "txid": txid,
        "vout": 0,
    }
    if opreturn_hex is not None:
        u["opreturn_hex"] = opreturn_hex
    if inputs is not None:
        u["inputs"] = inputs
    return u


def _mk_0b_opret(name: str, reg: dict[str, Any], role: str, comp_pol: dict[str, Any], name_in_txid: str, h_c: int) -> str:
    brk = {
        "compromised_policy": comp_pol,
        "genesis": GENESIS_MAIN,
        "h_c": h_c,
        "issuer": {"name": name, "registration": reg},
        "name_input": {"txid": name_in_txid, "vout": 0},
        "role": role,
        "type": "seallink-credential-break/1",
    }
    return sl.encode_opreturn(0x0B, sl.signing_digest(brk).hex(), h_c=h_c).hex()


def _mine_regtest_hdr(ver: int, prev_le: bytes, merkle_le: bytes, ntime: int, nbits: int = 0x207FFFFF) -> bytes:
    tgt = sl.bits_to_target(nbits)
    for nonce in range(100000):
        cand = struct.pack("<I", ver) + prev_le + merkle_le + struct.pack("<III", ntime, nbits, nonce)
        if int.from_bytes(sl.dsha256(cand), "little") <= tgt:
            return cand
    raise RuntimeError("failed to mine synthetic regtest header")


def _mk_t2_page(
    nm: str,
    upds: list[dict[str, Any]],
    *,
    limit: int = 10,
    registration: dict[str, Any] | None = None,
    headers: list[dict[str, Any]] | None = None,
    network: str = "regtest",
    cursor_height: int | None = None,
    cursor_txid: str | None = None,
    cursor_vout: int | None = None,
    cursor_owner_policy: dict[str, Any] | None = None,
    next_cursor: dict[str, Any] | None = None,
    has_more: bool = False,
) -> dict[str, Any]:
    reg = registration
    if reg is None:
        if upds:
            t0 = sl.parse_raw_tx(bytes.fromhex(upds[0]["tx_hex"]))
            p0 = sl.parse_raw_tx(bytes.fromhex(upds[0]["prevout_tx_hex"]))
            n_op = None
            for vo in t0["vout"]:
                try:
                    pn = sl.parse_name_output(vo["script_pubkey"])
                    if pn.get("name") == nm:
                        n_op = pn.get("op")
                        break
                except ValueError:
                    pass
            reg = {"txid": t0["txid"] if n_op == "NAME_FIRSTUPDATE" else p0["txid"], "vout": 0}
        else:
            reg = {"txid": _h32(f"t2-reg-{nm}"), "vout": 0}
    if headers is None:
        hdrs_by_h: dict[int, str] = {}
        for u_it in upds:
            hdrs_by_h.setdefault(int(u_it["block_height"]), u_it["block_header_hex"])
        headers = [{"header_hex": hdrs_by_h[h_k], "height": h_k} for h_k in sorted(hdrs_by_h)]
    pg: dict[str, Any] = {
        "genesis": GENESIS_MAIN,
        "has_more": has_more,
        "headers": headers,
        "limit": limit,
        "name": nm,
        "network": network,
        "registration": reg,
        "type": "seallink-tier2-name-history/1",
        "updates": upds,
    }
    if cursor_height is not None:
        pg["cursor_height"] = cursor_height
    if cursor_txid is not None:
        pg["cursor_txid"] = cursor_txid
    if cursor_vout is not None:
        pg["cursor_vout"] = cursor_vout
    if cursor_owner_policy is not None:
        pg["cursor_owner_policy"] = cursor_owner_policy
    if next_cursor is not None:
        pg["next_cursor"] = next_cursor
    return pg


def add_draft13_conformance_cases(add: Callable[..., None]) -> None:
    # ========================================================================
    # BLK-1: illegal_reversion (no free kill-switch via bad rec_b_inclusion or non-adjacent rotation)
    # ========================================================================
    eco_b1 = bd11._build_log_ecosystem("d13-blk1", role="notary", with_4_checkpoints=True)
    # 1a. Honest cp3 -> cp4 transition, attacker supplies forged/corrupt rec_b_inclusion -> REFUSE CHAIN_FRAME_INVALID (0 writes/closures)
    bad_rec_b_inc = {
        "batch_proof": {"leaf_digest": _h32("blk1-wrong-leaf"), "root": _h32("blk1-wrong-root"), "steps": [{"hash": _h32("blk1-corrupt-hash"), "side": "R"}]},
        "checkpoint": eco_b1["cp4_env"],
        "checkpoint_txid": eco_b1["cp4_tx"],
    }
    fp_bad_inc = {
        "checkpoints_proof": sl.rfc9162_inclusion_proof(eco_b1["leaves_3"], 2),
        "cp_a": eco_b1["cp3_env"],
        "cp_a_txid": eco_b1["cp3_tx"],
        "cp_b": eco_b1["cp4_env"],
        "cp_b_txid": eco_b1["cp4_tx"],
        "fraud_mode": "illegal_reversion",
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": eco_b1["gen_op"],
        "log_id": eco_b1["log_id"],
        "network": "main",
        "rec_a": eco_b1["rev1_env"],
        "rec_b": eco_b1["reinst2_env"],
        "rec_b_inclusion": bad_rec_b_inc,
        "role": "notary",
        "smt_proof_a": sl.smt_prove(eco_b1["kv3"], eco_b1["denial_key"]),
        "smt_proof_b": sl.smt_prove(eco_b1["kv4"], eco_b1["denial_key"]),
        "type": "seallink-log-fraud/1",
    }
    add(
        "d13-blk1-invalid-rec-b-inclusion-refuse-zero-writes",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": eco_b1["chain"],
            "expect_zero_closures": True,
            "expect_zero_writes": True,
            "fraud": fp_bad_inc,
            "journal": {"journal_id": _h32("d13-blk1-j1")},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013 BLK-1: Invalid rec_b_inclusion in illegal_reversion MUST refuse CHAIN_FRAME_INVALID with 0 journal writes/closures (no free kill-switch).",
    )

    # 1b. Honest role-key rotation K1 -> K2 between cp4 (h=749998) and cp5 (h=750000):
    # rec_b (reinst2, signed by K1 at cp4) is carried into cp5 (signed by K2).
    # Attacker submits (cp_a=cp3, cp_b=cp5) WITHOUT rec_b_inclusion -> MUST refuse CHAIN_FRAME_INVALID (0 closures)!
    k2_b1 = _kp("d13-blk1-k2")
    k2_pin = {
        "name": eco_b1["iss_name"],
        "owner_policy": eco_b1["iss_pol"],
        "registration": eco_b1["iss_reg"],
        "role_policy": {"m": 1, "pks": [k2_b1["xonly"]]},
    }
    ch_rot_b1 = copy.deepcopy(eco_b1["chain"])
    rm.sync_chain_tip(ch_rot_b1, height=750004)
    # Re-open cp4 as non-terminal so cp5 can follow after K1 -> K2 rotation
    cp4_nt_p = copy.deepcopy(eco_b1["cp4_env"]["payload"])
    cp4_nt_p["terminal"] = False
    cp4_nt_p["next_log_policy"] = eco_b1["seal_pol"]
    cp4_nt_p["next_log_vout"] = 1
    cp4_nt_env = sl.sign_envelope(cp4_nt_p, [eco_b1["iss_role"]["sk"]])
    cp4_nt_ca = sl.content_addr(cp4_nt_env)
    cp5_tx_b1 = _h32("d13-blk1-cp5-tx")
    leaves_4_b1 = eco_b1["leaves_3"] + [sl.ckpt_leaf(4, cp4_nt_ca)]
    cp5_p_b1 = {
        "batch_count": 0,
        "batch_root": sl.EMPTY_BATCH_ROOT,
        "checkpoints_root": sl.rfc9162_mth(leaves_4_b1).hex(),
        "cumulative_entries_count": 3,
        "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": cp4_nt_p["denials_root"],
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": eco_b1["gen_op"],
        "issuer": k2_pin,
        "log_id": eco_b1["log_id"],
        "network": "main",
        "prev_checkpoint_id": cp4_nt_ca,
        "prev_log_outpoint": {"txid": eco_b1["cp4_tx"], "vout": 1},
        "role": "notary",
        "seq": 5,
        "terminal": True,
        "type": "seallink-log-checkpoint/1",
    }
    cp5_env_b1 = sl.sign_envelope(cp5_p_b1, [k2_b1["sk"]])
    cp5_ca_b1 = sl.content_addr(cp5_env_b1)
    ch_rot_b1["txs"][eco_b1["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, cp4_nt_ca).hex()
    ch_rot_b1["txs"][eco_b1["cp4_tx"]]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(eco_b1["seal_pol"]), "spent_by_txid": cp5_tx_b1}}
    ch_rot_b1["txs"][cp5_tx_b1] = {
        "block_hash": _h32("d13-blk1-blk-cp5"),
        "confirmed_height": 750000,
        "inputs": [sv.make_segwit_input(eco_b1["cp4_tx"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, cp5_ca_b1).hex(),
        "outputs": {},
    }
    # Add K1 -> K2 name update at height 749999 (after cp4 at 749998, before cp5 at 750000)
    prev_b1_u = ch_rot_b1["names"][eco_b1["iss_name"]]["updates"][-1]
    ch_rot_b1["names"][eco_b1["iss_name"]]["updates"].append(
        _mk_upd(eco_b1["iss_name"], eco_b1["iss_pol"], sl.jcs_encode({"link": {"notary": k2_b1["xonly"]}}), _h32("d13-blk1-rot-k2"), 749999, prev_b1_u["txid"], eco_b1["iss_pol"])
    )
    fp_nonadj_no_inc = {
        "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_4_b1, 2),
        "cp_a": eco_b1["cp3_env"],
        "cp_a_txid": eco_b1["cp3_tx"],
        "cp_b": cp5_env_b1,
        "cp_b_txid": cp5_tx_b1,
        "fraud_mode": "illegal_reversion",
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": eco_b1["gen_op"],
        "log_id": eco_b1["log_id"],
        "network": "main",
        "rec_a": eco_b1["rev1_env"],
        "rec_b": eco_b1["reinst2_env"],
        "role": "notary",
        "smt_proof_a": sl.smt_prove(eco_b1["kv3"], eco_b1["denial_key"]),
        "smt_proof_b": sl.smt_prove(eco_b1["kv4"], eco_b1["denial_key"]),
        "type": "seallink-log-fraud/1",
    }
    add(
        "d13-blk1-non-adjacent-rotated-key-without-rec-b-inclusion-refuse",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": ch_rot_b1,
            "expect_zero_closures": True,
            "expect_zero_writes": True,
            "fraud": fp_nonadj_no_inc,
            "journal": {"journal_id": _h32("d13-blk1-j2")},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013 BLK-1: Non-adjacent (seq_b > seq_a + 1) illegal_reversion after routine K1->K2 rotation without rec_b_inclusion MUST refuse CHAIN_FRAME_INVALID with 0 closures.",
    )

    # 1c. Genuine forged rec_b at adjacent seq_b == seq_a + 1 (bad signature by stranger) -> ADMIT fraud + CLOSE
    stranger_b1 = _kp("d13-blk1-stranger")
    bad_reinst_p = copy.deepcopy(eco_b1["reinst2_env"]["payload"])
    bad_reinst_env = sl.sign_envelope(bad_reinst_p, [stranger_b1["sk"]])
    bad_reinst_ca = sl.content_addr(bad_reinst_env)
    kv4_bad = {eco_b1["denial_key"]: bad_reinst_ca}
    e_bad_re = sl.log_entry_digest(0x03, bad_reinst_ca)
    b4_bad_root, b4_bad_proofs = sl.build_log_batch_root([e_bad_re])
    cp4_bad_p = {
        **eco_b1["cp4_env"]["payload"],
        "batch_root": b4_bad_root,
        "denials_delta_root": b4_bad_root,
        "denials_root": sl.smt_root(kv4_bad),
    }
    cp4_bad_env = sl.sign_envelope(cp4_bad_p, [eco_b1["iss_role"]["sk"]])
    cp4_bad_ca = sl.content_addr(cp4_bad_env)
    ch_adj_bad = copy.deepcopy(eco_b1["chain"])
    ch_adj_bad["txs"][eco_b1["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, cp4_bad_ca).hex()
    fp_adj_bad = {
        "checkpoints_proof": sl.rfc9162_inclusion_proof(eco_b1["leaves_3"], 2),
        "cp_a": eco_b1["cp3_env"],
        "cp_a_txid": eco_b1["cp3_tx"],
        "cp_b": cp4_bad_env,
        "cp_b_txid": eco_b1["cp4_tx"],
        "fraud_mode": "illegal_reversion",
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": eco_b1["gen_op"],
        "log_id": eco_b1["log_id"],
        "network": "main",
        "rec_a": eco_b1["rev1_env"],
        "rec_b": bad_reinst_env,
        "role": "notary",
        "smt_proof_a": sl.smt_prove(eco_b1["kv3"], eco_b1["denial_key"]),
        "smt_proof_b": sl.smt_prove(kv4_bad, eco_b1["denial_key"]),
        "type": "seallink-log-fraud/1",
    }
    add(
        "d13-blk1-adjacent-forged-rec-b-admit-fraud",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": ch_adj_bad,
            "fraud": fp_adj_bad,
            "journal": {"journal_id": _h32("d13-blk1-j3")},
        },
        "ADMIT",
        None,
        "SL-CONT-013 BLK-1: Genuinely forged rec_b introduced at adjacent seq_b == seq_a + 1 proves illegal_reversion without rec_b_inclusion and closes log.",
    )

    # 1d. Non-adjacent forged rec_b introduced at seq_intro=4, verified against cp_a=3, cp_b=5 WITH valid rec_b_inclusion -> ADMIT fraud
    cp4_bad_nt_p = {**cp4_bad_p, "next_log_policy": eco_b1["seal_pol"], "next_log_vout": 1, "terminal": False}
    cp4_bad_nt_env = sl.sign_envelope(cp4_bad_nt_p, [eco_b1["iss_role"]["sk"]])
    cp4_bad_nt_ca = sl.content_addr(cp4_bad_nt_env)
    leaves_4_bad = eco_b1["leaves_3"] + [sl.ckpt_leaf(4, cp4_bad_nt_ca)]
    cp5_bad_tx = _h32("d13-blk1-cp5-bad-tx")
    cp5_bad_p = {
        "batch_count": 0,
        "batch_root": sl.EMPTY_BATCH_ROOT,
        "checkpoints_root": sl.rfc9162_mth(leaves_4_bad).hex(),
        "cumulative_entries_count": 3,
        "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": sl.smt_root(kv4_bad),
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": eco_b1["gen_op"],
        "issuer": eco_b1["iss_role_pin"],
        "log_id": eco_b1["log_id"],
        "network": "main",
        "prev_checkpoint_id": cp4_bad_nt_ca,
        "prev_log_outpoint": {"txid": eco_b1["cp4_tx"], "vout": 1},
        "role": "notary",
        "seq": 5,
        "terminal": True,
        "type": "seallink-log-checkpoint/1",
    }
    cp5_bad_env = sl.sign_envelope(cp5_bad_p, [eco_b1["iss_role"]["sk"]])
    cp5_bad_ca = sl.content_addr(cp5_bad_env)
    ch_nonadj_bad = copy.deepcopy(eco_b1["chain"])
    rm.sync_chain_tip(ch_nonadj_bad, height=750004)
    ch_nonadj_bad["txs"][eco_b1["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, cp4_bad_nt_ca).hex()
    ch_nonadj_bad["txs"][eco_b1["cp4_tx"]]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(eco_b1["seal_pol"]), "spent_by_txid": cp5_bad_tx}}
    ch_nonadj_bad["txs"][cp5_bad_tx] = {
        "block_hash": _h32("d13-blk1-blk-cp5-bad"),
        "confirmed_height": 750000,
        "inputs": [sv.make_segwit_input(eco_b1["cp4_tx"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, cp5_bad_ca).hex(),
        "outputs": {},
    }
    fp_nonadj_with_inc = {
        "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_4_bad, 2),
        "cp_a": eco_b1["cp3_env"],
        "cp_a_txid": eco_b1["cp3_tx"],
        "cp_b": cp5_bad_env,
        "cp_b_txid": cp5_bad_tx,
        "fraud_mode": "illegal_reversion",
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": eco_b1["gen_op"],
        "log_id": eco_b1["log_id"],
        "network": "main",
        "rec_a": eco_b1["rev1_env"],
        "rec_b": bad_reinst_env,
        "rec_b_inclusion": {
            "batch_proof": b4_bad_proofs[e_bad_re],
            "checkpoint": cp4_bad_nt_env,
            "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_4_bad, 3),
            "checkpoint_txid": eco_b1["cp4_tx"],
        },
        "role": "notary",
        "smt_proof_a": sl.smt_prove(eco_b1["kv3"], eco_b1["denial_key"]),
        "smt_proof_b": sl.smt_prove(kv4_bad, eco_b1["denial_key"]),
        "type": "seallink-log-fraud/1",
    }
    add(
        "d13-blk1-non-adjacent-forged-rec-b-with-valid-inclusion-admit-fraud",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": ch_nonadj_bad,
            "fraud": fp_nonadj_with_inc,
            "journal": {"journal_id": _h32("d13-blk1-j4")},
        },
        "ADMIT",
        None,
        "SL-CONT-013 BLK-1: Non-adjacent forged rec_b proven via valid rec_b_inclusion at seq_intro=4 admits illegal_reversion and closes log.",
    )

    # ========================================================================
    # BLK-2: Canonical 0x14 single-use-seal layout (vout=1 non-terminal, len(vout)==1 terminal, >16 hops)
    # ========================================================================
    ch_term_v1 = copy.deepcopy(eco_b1["chain"])
    ch_term_v1["txs"][eco_b1["cp4_tx"]]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(eco_b1["seal_pol"])}}
    add(
        "d13-blk2-terminal-with-vout1-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_term_v1, "checkpoint": eco_b1["cp4_env"], "checkpoint_txid": eco_b1["cp4_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 BLK-2: Terminal 0x14 checkpoint carrying a vout=1 output on-chain violates single-use-seal destruction and MUST refuse CHAIN_FRAME_INVALID.",
    )

    cp2_v2_p = copy.deepcopy(eco_b1["cp2_env"]["payload"])
    cp2_v2_p["next_log_vout"] = 2
    cp2_v2_env = sl.sign_envelope(cp2_v2_p, [eco_b1["iss_role"]["sk"]])
    add(
        "d13-blk2-non-terminal-next-log-vout-2-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": eco_b1["chain_at_cp2"], "checkpoint": cp2_v2_env, "checkpoint_txid": eco_b1["cp2_tx"]},
        "REFUSE",
        "WIRE_INTEGER",
        "SL-CONT-012 BLK-2: Non-terminal 0x14 checkpoint with next_log_vout != 1 MUST refuse WIRE_INTEGER at Step 8 schema check.",
    )

    # 20-hop 0x14 chain (> 16 hops!) strictly along canonical vout=1 -> ADMIT
    ch_20 = copy.deepcopy(eco_b1["chain_at_cp1"])
    rm.sync_chain_tip(ch_20, height=750050)
    prev_tx_20 = eco_b1["cp1_tx"]
    prev_ca_20 = eco_b1["cp1_ca"]
    leaves_20 = [sl.ckpt_leaf(1, prev_ca_20)]
    cur_dr_20 = eco_b1["cp1_env"]["payload"]["denials_root"]
    cur_cnt_20 = eco_b1["cp1_env"]["payload"]["cumulative_entries_count"]
    last_cp_20 = eco_b1["cp1_env"]
    last_tx_20 = prev_tx_20
    for seq_i in range(2, 21):
        is_term_20 = seq_i == 20
        tx_i = _h32(f"d13-blk2-20hop-tx-{seq_i}")
        cp_i_p: dict[str, Any] = {
            "batch_count": 0,
            "batch_root": sl.EMPTY_BATCH_ROOT,
            "checkpoints_root": sl.rfc9162_mth(leaves_20).hex(),
            "cumulative_entries_count": cur_cnt_20,
            "denials_delta_root": sl.EMPTY_BATCH_ROOT,
            "denials_root": cur_dr_20,
            "genesis": GENESIS_MAIN,
            "genesis_seal_outpoint": eco_b1["gen_op"],
            "issuer": eco_b1["iss_role_pin"],
            "log_id": eco_b1["log_id"],
            "network": "main",
            "prev_checkpoint_id": prev_ca_20,
            "prev_log_outpoint": {"txid": prev_tx_20, "vout": 1},
            "role": "notary",
            "seq": seq_i,
            "terminal": is_term_20,
            "type": "seallink-log-checkpoint/1",
        }
        if not is_term_20:
            cp_i_p["next_log_policy"] = eco_b1["seal_pol"]
            cp_i_p["next_log_vout"] = 1
        cp_i_env = sl.sign_envelope(cp_i_p, [eco_b1["iss_role"]["sk"]])
        cp_i_ca = sl.content_addr(cp_i_env)
        ch_20["txs"][prev_tx_20]["outputs"]["1"]["spent_by_txid"] = tx_i
        ch_20["txs"][tx_i] = {
            "block_hash": _h32(f"d13-blk2-20hop-blk-{seq_i}"),
            "confirmed_height": 749985 + seq_i,
            "inputs": [sv.make_segwit_input(prev_tx_20, 1)],
            "opreturn_hex": sl.encode_opreturn(0x14, cp_i_ca).hex(),
            "outputs": {} if is_term_20 else {"1": {"script_pubkey_hex": _spk_hex(eco_b1["seal_pol"])}},
        }
        leaves_20.append(sl.ckpt_leaf(seq_i, cp_i_ca))
        prev_tx_20, prev_ca_20 = tx_i, cp_i_ca
        last_cp_20, last_tx_20 = cp_i_env, tx_i
    add(
        "d13-blk2-deep-20-hop-0x14-chain-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_20, "checkpoint": last_cp_20, "checkpoint_txid": last_tx_20},
        "ADMIT",
        None,
        "SL-CONT-012 BLK-2: 20-checkpoint (>16-hop) 0x14 single-use-seal chain along canonical vout=1 admits cleanly.",
    )

    # Shadow branch spending vout=2 fee-change at intermediate step -> REFUSE CHAIN_FRAME_INVALID
    ch_shadow = copy.deepcopy(eco_b1["chain"])
    ch_shadow["txs"][eco_b1["cp2_tx"]]["outputs"]["2"] = {"script_pubkey_hex": _spk_hex(eco_b1["seal_pol"]), "spent_by_txid": eco_b1["cp3_tx"]}
    ch_shadow["txs"][eco_b1["cp2_tx"]]["outputs"]["1"].pop("spent_by_txid", None)
    ch_shadow["txs"][eco_b1["cp3_tx"]]["inputs"] = [sv.make_segwit_input(eco_b1["cp2_tx"], 2)]
    add(
        "d13-blk2-shadow-branch-via-vout2-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_shadow, "checkpoint": eco_b1["cp4_env"], "checkpoint_txid": eco_b1["cp4_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 BLK-2: Intermediate 0x14 step spending vout=2 (change/P2A) instead of canonical vout=1 MUST refuse CHAIN_FRAME_INVALID.",
    )

    # ========================================================================
    # BLK-3: 0x13 unknown_preimage capped at H + min_d (prevents late 0x10 split-brain resurrection)
    # ========================================================================
    fx_b3_late = bd11._build_autonomous_origin_rebind_fixture(
        "d13-blk3-late", h_offer=749450, h_13=749500, h_act=None, tip_h=749644,
    )
    fx_b3_late["origin_bundle"].pop("voluntary_rebind_bindings", None)
    b1_b3_late_n = fx_b3_late["_b1"]["name"]
    b1_b3_late_pol = fx_b3_late["_b1_pol"]
    b1_b3_late_u = fx_b3_late["chain"]["names"][b1_b3_late_n]["updates"][-1]
    fx_b3_late["chain"]["names"][b1_b3_late_n]["updates"].append(
        _mk_upd(b1_b3_late_n, b1_b3_late_pol, b"{}", _h32("d13-blk3-late-0x10"), 749644, b1_b3_late_u["txid"], b1_b3_late_pol, prev_vout=b1_b3_late_u["vout"], opreturn_hex=sl.encode_opreturn(0x10, fx_b3_late["_b2_id"]).hex())
    )
    add(
        "d13-blk3-unknown-preimage-late-0x10-at-h13-plus-mind-incomplete",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": fx_b3_late["chain"],
            "origin_bundle": fx_b3_late["origin_bundle"],
            "trusted_origin_issuer_pins": fx_b3_late["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017 BLK-3: Unknown 0x13 preimage stalls at H == h_13 + min_d (144); a late 0x10 cancel at h_13 + 144 MUST NOT resurrect B_1.",
    )

    fx_b3_timely = bd11._build_autonomous_origin_rebind_fixture(
        "d13-blk3-timely", h_offer=749450, h_13=749500, h_act=None, tip_h=749644,
    )
    fx_b3_timely["origin_bundle"].pop("voluntary_rebind_bindings", None)
    b1_b3_t_n = fx_b3_timely["_b1"]["name"]
    b1_b3_t_pol = fx_b3_timely["_b1_pol"]
    b1_b3_t_u = fx_b3_timely["chain"]["names"][b1_b3_t_n]["updates"][-1]
    fx_b3_timely["chain"]["names"][b1_b3_t_n]["updates"].append(
        _mk_upd(b1_b3_t_n, b1_b3_t_pol, b"{}", _h32("d13-blk3-timely-0x10"), 749643, b1_b3_t_u["txid"], b1_b3_t_pol, prev_vout=b1_b3_t_u["vout"], opreturn_hex=sl.encode_opreturn(0x10, fx_b3_timely["_b2_id"]).hex())
    )
    add(
        "d13-blk3-unknown-preimage-timely-0x10-before-mind-cancels",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": fx_b3_timely["chain"],
            "expect_active_name": b1_b3_t_n,
            "expect_rebind_outcome": "cancelled_restored",
            "origin_bundle": fx_b3_timely["origin_bundle"],
            "trusted_origin_issuer_pins": fx_b3_timely["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 BLK-3: Unknown 0x13 preimage canceled strictly before h_13 + min_d (at h_13 + 143) cancels cleanly and preserves B_1.",
    )

    # ========================================================================
    # BLK-4: manifest/1 canonical notary & release sections (SPEC-03 §3.1 == manifest.schema.json)
    # ========================================================================
    man_ok = {
        "network": "main",
        "notary": {
            "log": {
                "genesis_seal": eco_b1["gen_seal"],
                "heartbeat_max_blocks": 144,
                "log_id": eco_b1["log_id"],
                "predecessor_logs": [_h32("d13-man-nlog-pred")],
            },
            "supported_claim_ids": ["org.seallink.audit/build-reproducible"],
            "supported_schemes": ["fsverity-sha256", "sha256"],
        },
        "owner": "id/notary-d13",
        "release": {
            "allowed_product_prefixes": ["works.relux/"],
            "log": {
                "genesis_seal": eco_b1["gen_seal"],
                "heartbeat_max_blocks": 1008,
                "log_id": _h32("d13-man-rlog"),
                "predecessor_logs": [_h32("d13-man-rlog-pred")],
            },
            "supported_schemes": ["fsverity-sha256"],
        },
        "seq": 1,
        "type": "seallink-manifest/1",
    }
    add(
        "d13-blk4-manifest-notary-release-valid-admit",
        ["SL-IDEN-005"],
        "raw_wire",
        {"expected_type": "seallink-manifest/1", "object": man_ok},
        "ADMIT",
        None,
        "SL-IDEN-005 BLK-4: Canonical seallink-manifest/1 with notary & release objects (log, predecessor_logs, supported_*) validates cleanly.",
    )
    man_legacy_bad = {
        "network": "main",
        "notary": {"notary_log": {"genesis_seal": eco_b1["gen_seal"], "heartbeat_max_blocks": 144, "log_id": eco_b1["log_id"]}},
        "owner": "id/notary-d13",
        "seq": 1,
        "type": "seallink-manifest/1",
    }
    add(
        "d13-blk4-manifest-legacy-notary-log-refuse",
        ["SL-IDEN-005"],
        "raw_wire",
        {"expected_type": "seallink-manifest/1", "object": man_legacy_bad},
        "REFUSE",
        "WIRE_MEMBER",
        "SL-IDEN-005 BLK-4: Legacy notary_log member name inside manifest.notary MUST refuse WIRE_MEMBER.",
    )

    # ========================================================================
    # BLK-5: O(1) Log Handover (compute_log_id folds predecessor_log_id, predecessor_chain, inherited SMT denial, cross-issuer hijack)
    # ========================================================================
    # Build log_2 handing over from eco_b1 (terminal cp4) with an inherited log_1 revocation at kv3!
    eco_ho = bd11._build_log_ecosystem("d13-blk5", role="notary", with_4_checkpoints=True)
    # Make cp3 terminal so its denials_root still has active rev1 (signed under log_1!)
    ho_term_p = copy.deepcopy(eco_ho["cp3_env"]["payload"])
    ho_term_p["terminal"] = True
    ho_term_p.pop("next_log_policy", None)
    ho_term_p.pop("next_log_vout", None)
    ho_term_env = sl.sign_envelope(ho_term_p, [eco_ho["iss_role"]["sk"]])
    ho_term_ca = sl.content_addr(ho_term_env)
    ch_b5 = copy.deepcopy(eco_ho["chain_at_cp3"])
    rm.sync_chain_tip(ch_b5, height=750004)
    ch_b5["txs"][eco_ho["cp3_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, ho_term_ca).hex()
    ch_b5["txs"][eco_ho["cp3_tx"]]["outputs"] = {}

    gen2_op = {"txid": _h32("d13-blk5-gen2"), "vout": 0}
    log2_id = sl.compute_log_id("main", GENESIS_MAIN, "notary", eco_ho["iss_name"], eco_ho["iss_reg"], gen2_op, predecessor_log_id=eco_ho["log_id"])
    cp2_1_tx = _h32("d13-blk5-log2-cp1")
    cp2_1_p = {
        "batch_count": 0,
        "batch_root": sl.EMPTY_BATCH_ROOT,
        "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 0,
        "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": ho_term_p["denials_root"],
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": gen2_op,
        "issuer": eco_ho["iss_role_pin"],
        "log_id": log2_id,
        "network": "main",
        "next_log_policy": eco_ho["seal_pol"],
        "next_log_vout": 1,
        "predecessor_log_id": eco_ho["log_id"],
        "predecessor_terminal_denials_root": ho_term_p["denials_root"],
        "prev_log_outpoint": gen2_op,
        "role": "notary",
        "seq": 1,
        "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }
    cp2_1_env = sl.sign_envelope(cp2_1_p, [eco_ho["iss_role"]["sk"]])
    cp2_1_ca = sl.content_addr(cp2_1_env)
    ch_b5["txs"][gen2_op["txid"]] = {
        "confirmed_height": 749995,
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(eco_ho["seal_pol"]), "spent_by_txid": cp2_1_tx}},
    }
    ch_b5["txs"][cp2_1_tx] = {
        "block_hash": _h32("d13-blk5-blk-log2-cp1"),
        "confirmed_height": 749999,
        "inputs": [sv.make_segwit_input(gen2_op["txid"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x14, cp2_1_ca).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco_ho["seal_pol"])}},
    }
    # Mint a fresh notary act in log_2 seq=2 (while log_1's denial for eco_ho's act_id is still carried in denials_root!)
    # Check eco_ho's original act_env against log_2 cp2_1 via predecessor_chain -> inherited log_1 revocation MUST refuse CRED_REVOKED_FOR_CAUSE!
    pred_chain_b5 = [{"checkpoint": ho_term_env, "checkpoint_txid": eco_ho["cp3_tx"]}]
    add(
        "d13-blk5-handover-inherited-smt-revocation-refuse",
        ["SL-CONT-012"],
        "notary_act",
        {
            "chain": ch_b5,
            "log_ctx": {
                "batch_proof": eco_ho["b1_proof"],
                "checkpoint": eco_ho["cp1_env"],
                "checkpoint_txid": eco_ho["cp1_tx"],
                "checkpoints_proof": sl.rfc9162_inclusion_proof(eco_ho["leaves_2"], 0),
                "head_checkpoint": cp2_1_env,
                "head_checkpoint_txid": cp2_1_tx,
                "predecessor_chain": pred_chain_b5,
                "smt_proof": sl.smt_prove(eco_ho["kv3"], eco_ho["denial_key"]),
                "state_record": eco_ho["rev1_env"],
                "state_record_inclusion": {
                    "batch_proof": eco_ho["b3_proof"],
                    "checkpoint": ho_term_env,
                    "checkpoint_txid": eco_ho["cp3_tx"],
                },
            },
            "notary": eco_ho["item_env"],
        },
        "REFUSE",
        "CRED_REVOKED_FOR_CAUSE",
        "SL-CONT-012 BLK-5: Inherited log_1 revocation in log_2.denials_root (payload.log_id == log_1 != log_2) is authenticated via predecessor_chain and refuses CRED_REVOKED_FOR_CAUSE.",
    )

    # Handover checkpoint at seq=2 omitting predecessor_log_id from log_id computation -> REFUSE CHAIN_FRAME_INVALID
    bad_log2_id = sl.compute_log_id("main", GENESIS_MAIN, "notary", eco_ho["iss_name"], eco_ho["iss_reg"], gen2_op)
    cp2_bad_lid_env = sl.sign_envelope({**cp2_1_p, "log_id": bad_log2_id}, [eco_ho["iss_role"]["sk"]])
    ch_b5_bad = copy.deepcopy(ch_b5)
    ch_b5_bad["txs"][cp2_1_tx]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp2_bad_lid_env)).hex()
    add(
        "d13-blk5-handover-log-id-omitting-predecessor-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_b5_bad,
            "checkpoint": cp2_bad_lid_env,
            "checkpoint_txid": cp2_1_tx,
            "predecessor_chain": pred_chain_b5,
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 BLK-5: Handover checkpoint whose log_id omits predecessor_log_id MUST refuse CHAIN_FRAME_INVALID.",
    )

    # Cross-issuer hijack via persisted journal log-head: id/eve tries to hand over from id/alice's persisted terminal log-head!
    eve_o = _kp("d13-blk5-eve-o")
    eve_r = _kp("d13-blk5-eve-r")
    eve_o_pol = {"kind": "key", "pk": eve_o["comp"]}
    eve_reg = {"txid": _h32("d13-blk5-eve-reg"), "vout": 0}
    eve_pin = {"name": "id/eve-d13", "owner_policy": eve_o_pol, "registration": eve_reg, "role_policy": {"m": 1, "pks": [eve_r["xonly"]]}}
    eve_lid = sl.compute_log_id("main", GENESIS_MAIN, "notary", "id/eve-d13", eve_reg, gen2_op, predecessor_log_id=eco_ho["log_id"])
    eve_cp1_p = {
        **cp2_1_p,
        "issuer": eve_pin,
        "log_id": eve_lid,
    }
    eve_cp1_env = sl.sign_envelope(eve_cp1_p, [eve_r["sk"]])
    ch_eve_hj = copy.deepcopy(ch_b5)
    ch_eve_hj["names"]["id/eve-d13"] = sv.make_name_history("id/eve-d13", eve_reg, eve_o_pol, {"link": {"notary": eve_r["xonly"]}}, update_height=749990)
    ch_eve_hj["txs"][cp2_1_tx]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(eve_cp1_env)).hex()
    j_alice_term = {
        "journal_id": _h32("d13-blk5-j-alice"),
        "initial_entries": [{
            "body": {
                "block_hash": ch_b5["txs"][eco_ho["cp3_tx"]]["block_hash"],
                "checkpoint_id": ho_term_ca,
                "checkpoint_object_id": sl.object_id(ho_term_p),
                "checkpoint_txid": eco_ho["cp3_tx"],
                "checkpoints_root": ho_term_p["checkpoints_root"],
                "confirmed_height": 749994,
                "denials_root": ho_term_p["denials_root"],
                "issuer_name": eco_ho["iss_name"],
                "issuer_registration": eco_ho["iss_reg"],
                "log_id": eco_ho["log_id"],
                "max_seq": 3,
                "role": "notary",
                "terminal": True,
            },
            "kind": "log-head",
        }],
    }
    add(
        "d13-blk5-log-head-cross-issuer-hijack-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_eve_hj,
            "checkpoint": eve_cp1_env,
            "checkpoint_txid": cp2_1_tx,
            "journal": j_alice_term,
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 BLK-5: id/eve claiming predecessor_log_id of id/alice's persisted log-head MUST refuse CHAIN_FRAME_INVALID (issuer_name/registration pinned in log-head).",
    )

    # ========================================================================
    # BLK-6: 0x0b KEY_COMPROMISE_BREAK survives cold owner_policy rotation P1 -> P2
    # ========================================================================
    p1_b6 = _kp("d13-blk6-p1")
    p2_b6 = _kp("d13-blk6-p2")
    k1_b6 = _kp("d13-blk6-k1")
    p1_pol = {"kind": "key", "pk": p1_b6["comp"]}
    p2_pol = {"kind": "key", "pk": p2_b6["comp"]}
    b6_reg = {"txid": _h32("d13-blk6-reg"), "vout": 0}
    b6_iss_pin_p1 = {"name": "id/iss-b6", "owner_policy": p1_pol, "registration": b6_reg, "role_policy": {"m": 1, "pks": [k1_b6["xonly"]]}}
    b6_subj = _kp("d13-blk6-subj")
    b6_cred_p = {
        "claims": {"verified": True},
        "credential_kind": "org.seallink.test/kyc",
        "genesis": GENESIS_MAIN,
        "issued_at": 1795219000,
        "issuer": b6_iss_pin_p1,
        "lifecycle": "eternal",
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 749900,
        "subject": {"key": b6_subj["xonly"], "mode": "key"},
        "type": "seallink-credential/1",
    }
    b6_cred_env = sl.sign_envelope(b6_cred_p, [k1_b6["sk"]])
    b6_anc_tx = _h32("d13-blk6-anc")
    b6_ch = _mk_chain(tip_height=750010)
    b6_ch["txs"][b6_anc_tx] = {
        "confirmed_height": 749995,
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(b6_cred_env)).hex(),
        "outputs": {},
    }
    # Updates: 0=FIRSTUPDATE(P1), 1=UPDATE(P1 sets link.cred=K1), 2=UPDATE(P1->P2 transfer), 3=UPDATE(P2 self-update + 0x0b break of K1 at h_c=749990 <= h_anchor=749995!)
    b6_u1 = _h32("d13-blk6-u1")
    b6_u2 = _h32("d13-blk6-u2-rot")
    b6_u3 = _h32("d13-blk6-u3-0b")
    b6_val = sl.jcs_encode({"link": {"cred": k1_b6["xonly"]}})
    b6_ch["names"]["id/iss-b6"] = {
        "registration": b6_reg,
        "updates": [
            {
                "confirmed_height": 749900,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(p1_pol)), name=b"id/iss-b6", rand=b"\x01" * 20, value=b"{}").hex(),
                "owner_policy": p1_pol,
                "txid": b6_reg["txid"],
                "vout": 0,
            },
            _mk_upd("id/iss-b6", p1_pol, b6_val, b6_u1, 749910, b6_reg["txid"], p1_pol),
            _mk_upd("id/iss-b6", p2_pol, b6_val, b6_u2, 749998, b6_u1, p1_pol),
            _mk_upd(
                "id/iss-b6", p2_pol, b6_val, b6_u3, 750000, b6_u2, p2_pol,
                opreturn_hex=_mk_0b_opret("id/iss-b6", b6_reg, "cred", {"m": 1, "pks": [k1_b6["xonly"]]}, b6_u2, 749990),
            ),
        ],
    }
    add(
        "d13-blk6-0x0b-after-cold-rotation-p1-to-p2-refuse-cred-issuer-closed",
        ["SL-CONT-009", "SL-LDGR-010"],
        "credential",
        {"anchor_txid": b6_anc_tx, "chain": b6_ch, "credential": b6_cred_env},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "SL-CONT-009 BLK-6: 0x0b KEY_COMPROMISE_BREAK published by rotated cold owner P2 (same registration) MUST revoke K1 credentials issued under P1.",
    )

    # ========================================================================
    # BLK-7: 0x0c ward OP_NAME_FIRSTUPDATE MUST commit link.origin (cold observer discovery)
    # ========================================================================
    fx_b7 = rm._base_origin_fixture()
    # Remove link.origin from updates[0] (OP_NAME_FIRSTUPDATE) while keeping it in updates[1]
    ward_n_b7 = fx_b7["origin_bundle"]["name_binding"]["name"]
    ward_pol_b7 = fx_b7["origin_bundle"]["name_binding"]["owner_policy"]
    ch_b7_miss = copy.deepcopy(fx_b7["chain"])
    ch_b7_miss["names"][ward_n_b7]["updates"][0]["output_script_hex"] = sl.encode_name_output(
        "NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(ward_pol_b7)), name=ward_n_b7.encode("utf-8"), rand=b"\x01" * 20, value=b"{}"
    ).hex()
    add(
        "d13-blk7-0x0c-ward-missing-firstupdate-link-origin-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {
            "chain": ch_b7_miss,
            "origin_bundle": fx_b7["origin_bundle"],
            "trusted_origin_issuer_pins": fx_b7["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-002 BLK-7: 0x0c-bound ward whose OP_NAME_FIRSTUPDATE (updates[0]) omits link.origin MUST refuse ORIGIN_BINDING_INVALID.",
    )

    ch_b7_wrong = copy.deepcopy(fx_b7["chain"])
    ch_b7_wrong["names"][ward_n_b7]["updates"][0]["output_script_hex"] = sl.encode_name_output(
        "NAME_FIRSTUPDATE",
        bytes.fromhex(_spk_hex(ward_pol_b7)),
        name=ward_n_b7.encode("utf-8"),
        rand=b"\x01" * 20,
        value=sl.jcs_encode({"link": {"origin": _h32("wrong-origin-id")}}),
    ).hex()
    add(
        "d13-blk7-0x0c-ward-wrong-firstupdate-link-origin-refuse",
        ["SL-ORIG-002"],
        "origin_status",
        {
            "chain": ch_b7_wrong,
            "origin_bundle": fx_b7["origin_bundle"],
            "trusted_origin_issuer_pins": fx_b7["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-002 BLK-7: 0x0c-bound ward whose OP_NAME_FIRSTUPDATE commits a mismatched link.origin MUST refuse ORIGIN_BINDING_INVALID.",
    )

    # ========================================================================
    # BLK-8: Tier-2 SPV (P2WSH rotation + 2-page pagination, empty page 1, name-value schema, MTP11, +2h, 0x13, CAuxPow)
    # ========================================================================
    t2_k1 = _kp("d13-t2-k1")
    t2_k2 = _kp("d13-t2-k2")
    t2_k3 = _kp("d13-t2-k3")
    t2_p1 = {"kind": "key", "pk": t2_k1["comp"]}
    t2_p2_pks = sorted([t2_k2["comp"], t2_k3["comp"]])
    t2_p2_sks = [t2_k2["sk"], t2_k3["sk"]] if t2_p2_pks[0] == t2_k2["comp"] else [t2_k3["sk"], t2_k2["sk"]]
    t2_p2 = {"kind": "multisig", "m": 2, "pks": t2_p2_pks}

    pr_rot1, hdr_rot1 = bd11._build_synthetic_spv_proof(
        "d13-p2wsh-rot1", t2_p1, [t2_k1["sk"]], "id/t2-p2wsh-rot", "{}",
        block_height=750010, block_time=1795220000, new_owner_pol=t2_p2,
    )
    pr_rot2, hdr_rot2 = bd11._build_synthetic_spv_proof(
        "d13-p2wsh-rot2", t2_p2, t2_p2_sks, "id/t2-p2wsh-rot", f'{{"link":{{"notary":"{t2_k2["xonly"]}"}}}}',
        block_height=750011, prev_raw_override=bytes.fromhex(pr_rot1["tx_hex"]),
        prev_block_hash_le=sl.dsha256(hdr_rot1), block_time=1795220060,
    )
    pr_rot1_txid = sl.parse_raw_tx(bytes.fromhex(pr_rot1["tx_hex"]))["txid"]
    pr_rot2_txid = sl.parse_raw_tx(bytes.fromhex(pr_rot2["tx_hex"]))["txid"]
    pr_rot_reg = {"txid": sl.parse_raw_tx(bytes.fromhex(pr_rot1["prevout_tx_hex"]))["txid"], "vout": 0}
    add(
        "d13-blk8-tier2-p2wsh-cold-rotation-page1-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expect_next_cursor_owner_policy": t2_p2,
            "expect_owner_authored": [False, True],
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page(
                "id/t2-p2wsh-rot",
                [pr_rot1, pr_rot2],
                limit=2,
                registration=pr_rot_reg,
                headers=[
                    {"header_hex": hdr_rot1.hex(), "height": 750010},
                    {"header_hex": hdr_rot2.hex(), "height": 750011},
                ],
                next_cursor={"height": 750011, "owner_policy": t2_p2, "txid": pr_rot2_txid, "vout": 0},
                has_more=True,
            ),
            "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "SL-ARTF-005 BLK-8: Tier-2 P2WPKH -> P2WSH 2-of-2 cold rotation tracks owner_authored=[False, True] and emits next_cursor.owner_policy=P2WSH.",
        module="artifact-notarization",
    )
    add(
        "d13-blk8-tier2-p2wsh-cold-rotation-page1-ends-on-transfer-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expect_next_cursor_owner_policy": t2_p2,
            "expect_owner_authored": [False],
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page(
                "id/t2-p2wsh-rot",
                [pr_rot1],
                limit=1,
                registration=pr_rot_reg,
                headers=[{"header_hex": hdr_rot1.hex(), "height": 750010}],
                next_cursor={"height": 750010, "owner_policy": t2_p2, "txid": pr_rot1_txid, "vout": 0},
                has_more=True,
            ),
            "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "SL-ARTF-005 BLK-8: Tier-2 page 1 ending on a P2WPKH -> P2WSH 2-of-2 transfer verifies next_cursor.owner_policy against new_trailing_script_pubkey and emits final_owner_policy=P2WSH.",
        module="artifact-notarization",
    )
    add(
        "d13-blk8-tier2-p2wsh-cold-rotation-page2-cursor-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expect_owner_authored": [True],
            "expected_owner_policy": t2_p2,
            "page": _mk_t2_page(
                "id/t2-p2wsh-rot",
                [pr_rot2],
                limit=2,
                registration=pr_rot_reg,
                headers=[{"header_hex": hdr_rot2.hex(), "height": 750011}],
                cursor_height=750010,
                cursor_txid=pr_rot1_txid,
                cursor_vout=0,
                cursor_owner_policy=t2_p2,
            ),
            "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "SL-ARTF-005 BLK-8: Tier-2 page 2 resumes cleanly from cursor_owner_policy=P2WSH 2-of-2 after cold rotation.",
        module="artifact-notarization",
    )

    add(
        "d13-blk8-tier2-empty-page1-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page("id/t2-empty", [], headers=[{"header_hex": hdr_rot1.hex(), "height": 750010}]),
            "pinned_network": "regtest",
        },
        "REFUSE",
        "WIRE_MEMBER",
        "SL-ARTF-005 BLK-8: Page 1 (no cursor_txid) with empty updates[] MUST refuse WIRE_MEMBER at Step 8 schema check.",
        module="artifact-notarization",
    )

    pr_casefold, _ = bd11._build_synthetic_spv_proof(
        "d13-t2-casefold", t2_p1, [t2_k1["sk"]], "id/t2-cf", '{"LINK":1}', block_height=750010,
    )
    add(
        "d13-blk8-tier2-name-value-schema-casefold-LINK-refuse",
        ["SL-ARTF-005", "SL-IDEN-002"],
        "tier2_name_history",
        {"expected_owner_policy": t2_p1, "page": _mk_t2_page("id/t2-cf", [pr_casefold]), "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005 BLK-8: Tier-2 update carrying valid JCS {\"LINK\":1} violating name-value.schema.json MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # MTP(11) & +2h future timestamp boundary checks (nc28.0 ContextualCheckBlockHeader)
    nmc_v4 = (0x0001 << 16) | 4
    mtp_hdrs: list[dict[str, Any]] = []
    cur_prev_mtp = b"\x33" * 32
    base_t_mtp = 1795220000
    for i_m in range(11):
        hm = _mine_regtest_hdr(nmc_v4, cur_prev_mtp, sl.sha256(f"mtp-{i_m}".encode()), base_t_mtp + i_m * 60, 0x207FFFFF)
        mtp_hdrs.append({"header_hex": hm.hex(), "height": 100 + i_m})
        cur_prev_mtp = sl.dsha256(hm)
    # Median of [0, 60, 120, 180, 240, 300, 360, 420, 480, 540, 600] is base + 300!
    hm_bad_mtp = _mine_regtest_hdr(nmc_v4, cur_prev_mtp, sl.sha256(b"mtp-bad-11"), base_t_mtp + 300, 0x207FFFFF)
    add(
        "d13-blk8-tier2-header-mtp11-violation-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page(
                "id/t2-mtp", [], cursor_height=100, cursor_txid=_h32("t2-mtp-c"), cursor_vout=0,
                headers=mtp_hdrs + [{"header_hex": hm_bad_mtp.hex(), "height": 111}],
            ),
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 BLK-8: Header timestamp == MTP(11) violates nc28.0 ContextualCheckBlockHeader (ntime > MTP11) and MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    add(
        "d13-blk8-tier2-header-future-2h-plus1-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "current_time": 1795220000 - 7201,
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page("id/t2-p2wsh-rot", [pr_rot1], headers=[{"header_hex": hdr_rot1.hex(), "height": 750010}]),
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 BLK-8: Header timestamp == current_time + 7201 (> +2h) MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d13-blk8-tier2-header-future-2h-exact-admit",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "current_time": 1795220000 - 7200,
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page("id/t2-p2wsh-rot", [pr_rot1], headers=[{"header_hex": hdr_rot1.hex(), "height": 750010}]),
            "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "SL-ARTF-006 BLK-8: Header timestamp == exact current_time + 7200 (+2h boundary) admits.",
        module="artifact-notarization",
    )

    pr_0x13, _ = bd11._build_synthetic_spv_proof(
        "d13-t2-0x13", t2_p1, [t2_k1["sk"]], "id/t2-rebind", "{}",
        block_height=750010, opreturns=[sl.encode_opreturn(0x13, _h32("d13-t2-rebind-oid"))],
    )
    add(
        "d13-blk8-tier2-0x13-surfaced-refuse-incomplete",
        ["SL-ARTF-005", "SL-ORIG-017"],
        "tier2_name_history",
        {"expected_owner_policy": t2_p1, "page": _mk_t2_page("id/t2-rebind", [pr_0x13]), "pinned_network": "regtest"},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ARTF-005 BLK-8: Tier-2 update carrying 0x13 VOLUNTARY_REBIND without allow_unresolved_voluntary_rebind MUST refuse ORIGIN_STATUS_INCOMPLETE.",
        module="artifact-notarization",
    )

    # CAuxPow: chain_merkle_size=16, len(chain_branch)=4, BIP-9/ASICBoost nVersion, non-empty vout -> ADMIT; empty vin -> REFUSE
    aux_ver_d13 = (0x0001 << 16) | 0x00000100 | 4
    aux_hdr_d13 = struct.pack("<I", aux_ver_d13) + (b"\x44" * 32) + (b"\x55" * 32) + struct.pack("<III", 1795220100, 0x207FFFFF, 0)
    aux_bhash_le = sl.dsha256(aux_hdr_d13)
    chain_nonce_16 = 7
    slot_idx_16 = sl.auxpow_expected_index(chain_nonce_16, 1, 16)
    leaves_16 = [sl.sha256(f"d13-aux-slot-{i}".encode()) for i in range(16)]
    leaves_16[slot_idx_16] = aux_bhash_le
    c_root_16_le, c_branches_16 = bd11._btc_merkle_root_and_branches(leaves_16)
    aux_tag_16 = b"\xfa\xbe\x6d\x6d" + c_root_16_le[::-1] + struct.pack("<II", 16, chain_nonce_16)
    par_cb_16 = bd11._encode_raw_tx(
        2,
        [{"prev_txid": "00" * 32, "prev_vout": 0xFFFFFFFF, "script_sig": b"\x03\x01\x02\x03" + aux_tag_16}],
        [(5_000_000_000, b"\x00\x14" + (b"\x66" * 20))],
    )
    par_cb_p16 = sl.parse_raw_tx(par_cb_16)
    par_mr_16, par_cb_br_16 = bd11._btc_merkle_root_and_branches([par_cb_p16["txid_le"], sl.sha256(b"d13-par-tx1")])
    # BIP-9 + ASICBoost parent version 0x20800000
    par_hdr_16 = _mine_regtest_hdr(0x20800000, b"\x77" * 32, par_mr_16, 1795220100, 0x207FFFFF)
    aux_proof_16 = {
        "chain_branch": c_branches_16[slot_idx_16],
        "chain_merkle_nonce": chain_nonce_16,
        "chain_merkle_size": 16,
        "coinbase_branch": par_cb_br_16[0],
        "parent_coinbase_hex": par_cb_16.hex(),
        "parent_header_hex": par_hdr_16.hex(),
    }
    add(
        "d13-blk8-cauxpow-msz16-bip9-nonempty-vout-admit",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page(
                "id/t2-aux16", [], cursor_height=200, cursor_txid=_h32("t2-aux16-c"), cursor_vout=0,
                headers=[{"auxpow": aux_proof_16, "header_hex": aux_hdr_d13.hex(), "height": 201}],
            ),
            "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "SL-ARTF-006 BLK-8: CAuxPow with chain_merkle_size=16, len(chain_branch)=4, BIP-9/ASICBoost parent nVersion, and non-empty vout admits.",
        module="artifact-notarization",
    )
    # Empty vin in parent coinbase (>= 60 bytes so schema minLength passes and CAuxPow::check !vin.empty() rejects!) -> REFUSE TICKET_PROOF_INVALID
    par_cb_empty_vin = bd11._encode_raw_tx(
        2,
        [],
        [(5_000_000_000, b"\x00\x14" + (b"\x66" * 20)), (0, b"\x6a\x28" + (b"\xaa" * 40))],
    )
    add(
        "d13-blk8-cauxpow-empty-vin-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page(
                "id/t2-aux-ev", [], cursor_height=200, cursor_txid=_h32("t2-aux-ev-c"), cursor_vout=0,
                headers=[{"auxpow": {**aux_proof_16, "parent_coinbase_hex": par_cb_empty_vin.hex()}, "header_hex": aux_hdr_d13.hex(), "height": 201}],
            ),
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 BLK-8: CAuxPow parent coinbase with empty vin MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # ========================================================================
    # H-1: 3 VOLUNTARY_REBIND regressions (canceled 0x13 eternal notary, repeated 0x13 after B_2 pre-offer rotation, B_2 history_truncated at exact deadline)
    # ========================================================================
    # H-1a: Eternal notary act anchored BEFORE a canceled 0x13 on notary's name + origin_bundle -> ADMIT!
    fx_h1a = bd11._build_autonomous_origin_rebind_fixture("d13-h1a", h_offer=749450, h_13=749500, h_act=None, tip_h=750000)
    not_k_h1a = _kp("d13-h1a-not")
    b1_h1a_name = fx_h1a["_b1"]["name"]
    b1_h1a_pol = fx_h1a["_b1_pol"]
    b1_h1a_reg = fx_h1a["_b1"]["registration"]
    ch_h1a = copy.deepcopy(fx_h1a["chain"])
    # Add notary role key to b1's updates at h=749100 (after u1 at 749015, before h_anchor=749200 and before h_13=749500), and cancel 0x13 at h=749520!
    b1_u_h1a = ch_h1a["names"][b1_h1a_name]["updates"]
    h1a_set_tx = _h32("d13-h1a-set-notary")
    b1_u_h1a.insert(2, _mk_upd(b1_h1a_name, b1_h1a_pol, sl.jcs_encode({"link": {"grant": fx_h1a["_b1_gr"]["xonly"], "notary": not_k_h1a["xonly"]}}), h1a_set_tx, 749100, b1_u_h1a[1]["txid"], b1_h1a_pol))
    if len(b1_u_h1a) > 3 and "prev_input" in b1_u_h1a[3]:
        b1_u_h1a[3]["prev_input"]["txid"] = h1a_set_tx
    b1_last_h1a = b1_u_h1a[-1]
    b1_u_h1a.append(
        _mk_upd(b1_h1a_name, b1_h1a_pol, sl.jcs_encode({"link": {"grant": fx_h1a["_b1_gr"]["xonly"], "notary": not_k_h1a["xonly"]}}), _h32("d13-h1a-cancel-0x10"), 749520, b1_last_h1a["txid"], b1_h1a_pol, prev_vout=b1_last_h1a["vout"], opreturn_hex=sl.encode_opreturn(0x10, fx_h1a["_b2_id"]).hex())
    )
    art_h1a = {"digest": _h32("d13-h1a-art"), "scheme": "sha256"}
    not_act_h1a_p = {
        "act_kind": "artifact-notarization",
        "attested_at": 1795210000,
        "details": {"artifact_identity": art_h1a, "claims": [{"claim_id": "org.seallink.audit/build-reproducible", "verdict": "pass"}], "kind": "artifact-notarization"},
        "genesis": GENESIS_MAIN,
        "lifecycle": "eternal",
        "network": "main",
        "notary": {"name": b1_h1a_name, "owner_policy": b1_h1a_pol, "registration": b1_h1a_reg, "role_policy": {"m": 1, "pks": [not_k_h1a["xonly"]]}},
        "target_sha256": sl.artifact_target_id(art_h1a),
        "tip_hash": ch_h1a["tip_hash"],
        "tip_height": 749199,
        "type": "seallink-notary/1",
    }
    not_act_h1a = sl.sign_envelope(not_act_h1a_p, [not_k_h1a["sk"]])
    not_anc_h1a = _h32("d13-h1a-not-anc")
    ch_h1a["txs"][not_anc_h1a] = {
        "confirmed_height": 749200,
        "opreturn_hex": sl.encode_opreturn(0x04, sl.content_addr(not_act_h1a)).hex(),
        "outputs": {},
    }
    add(
        "d13-h1a-canceled-0x13-eternal-notary-act-with-origin-bundle-admit",
        ["SL-ORIG-017", "SL-CONT-011"],
        "notary_act",
        {
            "anchor_txid": not_anc_h1a,
            "chain": ch_h1a,
            "notary": not_act_h1a,
            "origin_bundle": fx_h1a["origin_bundle"],
            "trusted_origin_issuer_pins": fx_h1a["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "SL-ORIG-017 H-1a: Eternal notary act anchored before a canceled 0x13 rebind admits when origin_bundle is supplied (previously permanently blocked).",
    )

    # H-1b: Repeated 0x13 (B_1 -> B_2 -> B_3) after B_2 performed a valid pre-offer cold owner rotation!
    fx_h1b = bd11._build_autonomous_origin_rebind_fixture(
        "d13-h1b", h_offer=749450, h_13=749500, h_act=749644, tip_h=750100,
    )
    b2_old_k_h1b = _kp("d13-h1b-b2-old-o")
    b2_old_pol_h1b = {"kind": "key", "pk": b2_old_k_h1b["comp"]}
    b3_k_h1b = _kp("d13-h1b-b3-o")
    b3_pol_h1b = {"kind": "key", "pk": b3_k_h1b["comp"]}
    b3_reg_h1b = {"txid": _h32("d13-h1b-b3-reg"), "vout": 0}
    b3_off_tx = _h32("d13-h1b-b3-off")
    b3_reb_tx = _h32("d13-h1b-b3-reb")
    b2_name_h1b = fx_h1b["_b2"]["name"]
    b2_pol_h1b = fx_h1b["_b2_pol"]
    b2_b_h1b = fx_h1b["_b2"]
    b3_bind_h1b = {
        "binding_mode": "voluntary",
        "consent_outpoint": {"txid": b3_off_tx, "vout": 1},
        "delay_blocks": 144,
        "genesis": GENESIS_MAIN,
        "name": "id/d13-h1b-v3",
        "network": "main",
        "origin_id": fx_h1b["_oid"],
        "owner_policy": b3_pol_h1b,
        "registration": b3_reg_h1b,
        "seq": 3,
        "supersedes_binding_id": sl.object_id(b2_b_h1b),
        "type": "seallink-name-binding/1",
    }
    ch_h1b = copy.deepcopy(fx_h1b["chain"])
    # Pre-offer cold rotation on B_2: updates[0] (NAME_FIRSTUPDATE) started with b2_old_pol_h1b, then rotated to b2_pol_h1b BEFORE T_offer!
    b2_u_h1b = ch_h1b["names"][b2_name_h1b]["updates"]
    b2_u_h1b[0]["owner_policy"] = b2_old_pol_h1b
    b2_u_h1b[0]["output_script_hex"] = sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(b2_old_pol_h1b)), name=b2_name_h1b.encode("utf-8"), rand=b"\x07" * 20, value=b"{}").hex()
    rot_b2_tx = _h32("d13-h1b-b2-preoffer-rot")
    b2_u_h1b.insert(1, _mk_upd(b2_name_h1b, b2_pol_h1b, b"{}", rot_b2_tx, 749410, b2_u_h1b[0]["txid"], b2_old_pol_h1b))
    if len(b2_u_h1b) > 2 and "prev_input" in b2_u_h1b[2]:
        b2_u_h1b[2]["prev_input"]["txid"] = rot_b2_tx
    # B_2 spends its name UTXO in b3_reb_tx at h=749800 (well after B_2 activated at 749644) together with B_3's T_offer
    b2_last_u = b2_u_h1b[-1]
    b2_u_h1b.append(
        _mk_upd(
            b2_name_h1b, b2_pol_h1b, b"{}", b3_reb_tx, 749800, b2_last_u["txid"], b2_pol_h1b,
            prev_vout=b2_last_u["vout"],
            opreturn_hex=sl.encode_opreturn(0x13, sl.object_id(b3_bind_h1b)).hex(),
        )
    )
    ch_h1b["names"]["id/d13-h1b-v3"] = {
        "registration": b3_reg_h1b,
        "updates": [
            {
                "confirmed_height": 749700,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(b3_pol_h1b)), name=b"id/d13-h1b-v3", rand=b"\x02" * 20, value=b"{}").hex(),
                "owner_policy": b3_pol_h1b,
                "txid": b3_reg_h1b["txid"],
                "vout": 0,
            },
            _mk_upd("id/d13-h1b-v3", b3_pol_h1b, b"", b3_off_tx, 749750, b3_reg_h1b["txid"], b3_pol_h1b),
            _mk_upd("id/d13-h1b-v3", b3_pol_h1b, sl.jcs_encode({"link": {"origin": fx_h1b["_oid"]}}), _h32("d13-h1b-b3-act"), 749944, b3_off_tx, b3_pol_h1b),
        ],
    }
    ch_h1b["txs"][b3_off_tx] = {"confirmed_height": 749750, "outputs": {"1": {"script_pubkey_hex": _spk_hex(b3_pol_h1b), "spent_by_txid": b3_reb_tx}}, "version": 0x7100}
    ch_h1b["txs"][b3_reb_tx] = {
        "confirmed_height": 749800,
        "inputs": [sv.make_segwit_input(b2_last_u["txid"], b2_last_u["vout"]), sv.make_segwit_input(b3_off_tx, 1)],
        "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_bind_h1b)).hex(),
        "outputs": {},
        "version": 0x7100,
    }
    ob_h1b = copy.deepcopy(fx_h1b["origin_bundle"])
    ob_h1b["voluntary_rebind_bindings"].append(b3_bind_h1b)
    add(
        "d13-h1b-repeated-0x13-after-b2-pre-offer-rotation-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": ch_h1b,
            "expect_active_name": "id/d13-h1b-v3",
            "origin_bundle": ob_h1b,
            "trusted_origin_issuer_pins": fx_h1b["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 H-1b: Repeated 0x13 (B_1 -> B_2 -> B_3) after B_2 performed an allowed pre-offer cold rotation admits cleanly on B_3.",
    )

    # H-1c: B_2 history_truncated=True at exact H == deadline MUST refuse ORIGIN_STATUS_INCOMPLETE (not fall back to B_1!)
    fx_h1c = bd11._build_autonomous_origin_rebind_fixture("d13-h1c", h_offer=749450, h_13=749500, h_act=None, tip_h=749644)
    ch_h1c = copy.deepcopy(fx_h1c["chain"])
    ch_h1c["names"][fx_h1c["_b2"]["name"]]["history_truncated"] = True
    ch_h1c["names"][fx_h1c["_b2"]["name"]]["first_error_height"] = 749644
    add(
        "d13-h1c-b2-history-truncated-at-exact-deadline-incomplete",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": ch_h1c,
            "origin_bundle": fx_h1c["origin_bundle"],
            "trusted_origin_issuer_pins": fx_h1c["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017 H-1c: Truncated B_2 history at exact H == deadline MUST fail closed ORIGIN_STATUS_INCOMPLETE (never revert to B_1).",
    )
    ch_h1c_h13 = copy.deepcopy(fx_h1c["chain"])
    ch_h1c_h13["names"][fx_h1c["_b2"]["name"]]["history_truncated"] = True
    add(
        "d13-mk-b2-history-truncated-at-h13-incomplete",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": ch_h1c_h13,
            "origin_bundle": fx_h1c["origin_bundle"],
            "trusted_origin_issuer_pins": fx_h1c["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017 H-1c: Truncated B_2 history already truncated at H == h_13 MUST fail closed ORIGIN_STATUS_INCOMPLETE.",
    )

    # ========================================================================
    # H-2: 0x0f Guardian Roster Revision carried-over slot mutated AFTER roster_eff_h -> NOT contested_burned!
    # ========================================================================
    fx_h2 = rm._base_origin_fixture()
    tip_h2 = fx_h2["chain"]["tip_height"]  # 750010
    gp_h2 = fx_h2["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    vac_pol_h2 = gp_h2["roster_seal"]["script_policy"]
    delay_h2 = gp_h2["appointment_delay_blocks"]  # 144
    g1_id_h2 = sl.object_id(fx_h2["origin_bundle"]["guardian_records"][0]["payload"])
    g2_pin_h2 = fx_h2["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]
    # Appoint g2 in slot 2 (new_vacant) while retaining g1 in slot 1 (retain_active); then spend g1's slot 1 AFTER roster_eff_h!
    pend_pol_h2 = {"delay_blocks": delay_h2, "keys": {"challenger": gp_h2["challenger_pk"], "disposer": gp_h2["disposer_pk"], "guardian": _kp("d13-h2-g2")["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
    act_pol_h2 = {"keys": sl.canonical_branch_pair(gp_h2["disposer_pk"], _kp("d13-h2-g2")["comp"]), "kind": "branch", "template": "either_of_2"}
    quorums_h2 = {k: {"den": 2, "min": 1, "num": 1} for k in gp_h2["quorums"]}
    rost_h2_p = {
        "arbiter_pk": gp_h2["arbiter_pk"],
        "challenger_pk": gp_h2["challenger_pk"],
        "disposer_pk": gp_h2["disposer_pk"],
        "effective_delay_blocks": delay_h2,
        "genesis": GENESIS_MAIN,
        "issuer": fx_h2["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "next_roster_policy": vac_pol_h2,
        "next_roster_vout": 0,
        "origin_id": fx_h2["_origin_id"],
        "prev_revision": 1,
        "prev_roster_outpoint": {"txid": gp_h2["roster_seal"]["txid"], "vout": 0},
        "quorums": quorums_h2,
        "revision": 2,
        "revision_size": 2,
        "slots": [
            {"action": "retain_active", "active_outpoint": {"txid": rm._h32("og1-init-0x12"), "vout": 0}, "guardian_id": g1_id_h2, "slot": 1},
            {"action": "new_vacant", "new_vacant_policy": vac_pol_h2, "new_vacant_vout": 1, "slot": 2},
        ],
        "type": "seallink-guardian-roster/1",
    }
    rost_h2 = sl.sign_envelope(rost_h2_p, [fx_h2["_keys"]["reg_cred"]["sk"]])
    rtx_h2 = _h32("d13-h2-0x0f-rtx")
    dtx_h2 = _h32("d13-h2-g2-0x0d")
    etx_h2 = _h32("d13-h2-g2-0x0e")
    g2_rec_h2_p = {
        "activation_mode": "appointed",
        "active_policy": act_pol_h2,
        "effective_delay_blocks": delay_h2,
        "genesis": GENESIS_MAIN,
        "guardian": g2_pin_h2,
        "issuer": fx_h2["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "origin_id": fx_h2["_origin_id"],
        "pending_policy": pend_pol_h2,
        "pending_vout": 0,
        "prev_outpoint": {"txid": rtx_h2, "vout": 1},
        "revision": 2,
        "slot": 2,
        "term": {"mode": "indefinite"},
        "type": "seallink-guardian/1",
    }
    g2_rec_h2 = sl.sign_envelope(g2_rec_h2_p, [fx_h2["_keys"]["reg_cred"]["sk"]])
    g2_ass_h2 = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "network": "main",
            "nonce": _h32("d13-h2-g2-ass"),
            "party_id": "g-h2",
            "party_name": "id/parent-a",
            "party_role": "guardian",
            "target_id": sl.object_id(g2_rec_h2_p),
            "target_type": "seallink-guardian/1",
            "type": "seallink-assent/1",
        },
        [fx_h2["_keys"]["g1_gr"]["sk"]],
    )
    # 0x0f confirmed at tip - 2*delay - 20 -> roster_eff_h = tip - delay - 20!
    rtx_h2_height = tip_h2 - (2 * delay_h2 + 20)
    roster_eff_h2 = rtx_h2_height + delay_h2
    fx_h2["chain"]["txs"][gp_h2["roster_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = rtx_h2
    fx_h2["chain"]["txs"][rtx_h2] = {
        "confirmed_height": rtx_h2_height,
        "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rost_h2)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pol_h2)}, "1": {"script_pubkey_hex": _spk_hex(vac_pol_h2), "spent_by_txid": dtx_h2}},
    }
    fx_h2["chain"]["txs"][dtx_h2] = {
        "confirmed_height": tip_h2 - delay_h2,
        "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g2_rec_h2)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_pol_h2), "spent_by_txid": etx_h2}},
    }
    fx_h2["chain"]["txs"][etx_h2] = {
        "confirmed_height": tip_h2,
        "inputs": [sv.make_guardian_csv_input(dtx_h2, 0, pend_pol_h2, sequence=delay_h2)],
        "opreturn_hex": sl.encode_opreturn(0x0E, sl.object_id(g2_rec_h2_p)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_pol_h2)}},
    }
    # AFTER roster_eff_h2, slot 1's carried-over active_outpoint is spent cleanly at roster_eff_h2 + 5!
    # With H-2 fix, rev 1 traces slot 1 ONLY up to roster_eff_h2 (still active!), rev 2 activates cleanly, and slot 2's g2 satisfies 1-of-2 quorum!
    g1_rem_tx_h2 = _h32("d13-h2-g1-rem-post-eff")
    fx_h2["chain"]["txs"][rm._h32("og1-init-0x12")]["outputs"]["0"]["spent_by_txid"] = g1_rem_tx_h2
    fx_h2["chain"]["txs"][g1_rem_tx_h2] = {
        "confirmed_height": roster_eff_h2 + 5,
        "inputs": [sv.make_segwit_input(rm._h32("og1-init-0x12"), 0)],
        "outputs": {},
    }
    fx_h2["origin_bundle"]["roster_records"] = [rost_h2]
    fx_h2["origin_bundle"]["guardian_records"].append(g2_rec_h2)
    fx_h2["origin_bundle"]["guardian_assents"].append(g2_ass_h2)
    wa_h2 = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": fx_h2["_origin_id"], "revision": 2, "ward_name": "id/child-leo"},
            "issued_at": 1795220000,
            "network": "main",
            "nonce": _h32("d13-h2-wa"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": sl.object_id(fx_h2["contract"]),
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [{"guardian_name": "id/parent-a", "revision": 2, "signers": [fx_h2["_keys"]["g1_gr"]["sk"]], "slot": 2}],
    )
    add(
        "d13-h2-0x0f-roster-revision-carried-over-slot-mutated-after-eff-h-admit",
        ["SL-ORIG-014", "SL-ORIG-015"],
        "assent",
        {
            "assent": wa_h2,
            "chain": fx_h2["chain"],
            "contract": fx_h2["contract"],
            "origin_bundle": fx_h2["origin_bundle"],
            "trusted_origin_issuer_pins": fx_h2["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "SL-ORIG-014 H-2: Carried-over slot 1 spent AFTER 0x0f roster_eff_h MUST trace revision 1 only to roster_eff_h so revision 2 activates and slot 2 admits.",
    )

    # ========================================================================
    # H-3: Bearer sessions enforce required_quotas & config_sha256
    # ========================================================================
    fx_h3 = rm._base_invocation_fixture()
    gp_h3 = copy.deepcopy(fx_h3["bundle"]["grants"][0]["payload"])
    gp_h3["capabilities"] = [{"action": "mail/send", "target": "mailbox:id/alice:work"}]
    rm._reanchor_grant(fx_h3, gp_h3)
    so_h3_p = {
        "executor": gp_h3["executor"],
        "exp": fx_h3["chain"]["now"] + 600,
        "genesis": GENESIS_MAIN,
        "iat": fx_h3["chain"]["now"] - 10,
        "network": "main",
        "nonce": _h32("d13-h3-so-nonce"),
        "op": "open",
        "proof_path": fx_h3["invocation"]["payload"]["proof_path"],
        "quotas": [],
        "slot_binding": "slot-h3-send",
        "type": "seallink-session-open/1",
    }
    so_h3 = sl.sign_envelope(so_h3_p, [fx_h3["_keys"]["agent_req"]["sk"]])
    add(
        "d13-h3-session-open-mail-send-missing-required-quota-refuse",
        ["SL-GRNT-015"],
        "session_lifecycle",
        {
            "executor_cfg": fx_h3["executor_cfg"],
            "steps": [{
                "bundle": fx_h3["bundle"],
                "chain": fx_h3["chain"],
                "kind": "session_open",
                "label": "open-missing-quota",
                "session_open": so_h3,
                "want_refusal": "QUOTA_EXCEEDED",
                "want_verdict": "REFUSE",
            }],
        },
        "ADMIT",
        None,
        "SL-GRNT-015 H-3: verify_session_open MUST enforce act_meta.required_quotas (mail/send without messages_per_day refuses QUOTA_EXCEEDED).",
        module="bearer-sessions",
    )

    # Bearer session with contract config_sha256 mismatch -> REFUSE CONFIG_MISMATCH!
    fx_h3c = rm._base_invocation_fixture()
    gp_h3c = copy.deepcopy(fx_h3c["bundle"]["grants"][0]["payload"])
    c_h3c_seal_k = _kp("d13-h3c-cseal")
    c_h3c_seal_pol = {"kind": "key", "pk": c_h3c_seal_k["comp"]}
    c_h3c_seal_tx = _h32("d13-h3c-cseal-tx")
    fx_h3c["chain"]["txs"][c_h3c_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(c_h3c_seal_pol)}}}
    c_h3c_salt = _h32("d13-h3c-salt")
    c_h3c_clause = {"text": "cfg"}
    c_h3c_obj = {
        "clause_commitments": [sl.clause_commit(c_h3c_salt, c_h3c_clause)],
        "config_sha256": _h32("d13-h3-expected-cfg"),
        "contract_salt": _h32("d13-h3c-csalt"),
        "genesis": GENESIS_MAIN,
        "machine_clause_indices": [],
        "network": "main",
        "parties": [
            {"name_pin": {"name": "id/alice", "owner_policy": gp_h3c["issuer"]["owner_policy"], "registration": gp_h3c["issuer"]["registration"]}, "party_id": "p-alice", "role": "principal", "signing_policy": gp_h3c["issuer"]["role_policy"]},
            {"party_id": "p-agent", "role": "agent", "signing_policy": {"m": 1, "pks": [fx_h3c["_keys"]["agent_req"]["xonly"]]}},
        ],
        "profile": "org.seallink/mail-v1",
        "seal": {"script_policy": c_h3c_seal_pol, "txid": c_h3c_seal_tx, "vout": 0},
        "type": "seallink-contract/1",
        "window": {"not_after_height": 790000, "not_before_height": 749000},
    }
    gp_h3c["contract_id"] = sl.object_id(c_h3c_obj)
    rm._reanchor_grant(fx_h3c, gp_h3c)
    fx_h3c["bundle"]["contract"] = c_h3c_obj
    c_h3c_id = sl.object_id(c_h3c_obj)
    fx_h3c["bundle"]["contract_assents"] = [
        sl.sign_envelope(
            {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d13-h3c-a1"), "party_id": "p-alice", "party_name": "id/alice", "party_role": "principal", "target_id": c_h3c_id, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
            [fx_h3c["_keys"]["alice_gr"]["sk"]],
        ),
        sl.sign_envelope(
            {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d13-h3c-a2"), "party_id": "p-agent", "party_role": "agent", "target_id": c_h3c_id, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
            [fx_h3c["_keys"]["agent_req"]["sk"]],
        ),
    ]
    slot_h3c = "slot-h3-cfg"
    so_h3c_p = {
        "executor": gp_h3c["executor"],
        "exp": fx_h3c["chain"]["now"] + 600,
        "genesis": GENESIS_MAIN,
        "iat": fx_h3c["chain"]["now"] - 10,
        "network": "main",
        "nonce": _h32("d13-h3c-so-nonce"),
        "op": "open",
        "proof_path": fx_h3c["invocation"]["payload"]["proof_path"],
        "quotas": [],
        "slot_binding": slot_h3c,
        "type": "seallink-session-open/1",
    }
    so_h3c = sl.sign_envelope(so_h3c_p, [fx_h3c["_keys"]["agent_req"]["sk"]])
    good_cfg_h3c = {**fx_h3c["executor_cfg"], "runtime_config_sha256": _h32("d13-h3-expected-cfg")}
    bad_cfg_h3c = {**fx_h3c["executor_cfg"], "runtime_config_sha256": _h32("d13-h3-wrong-cfg")}
    add(
        "d13-h3-bearer-session-config-sha256-mismatch-refuse",
        ["SL-GRNT-015"],
        "session_lifecycle",
        {
            "executor_cfg": good_cfg_h3c,
            "steps": [
                {
                    "bundle": fx_h3c["bundle"],
                    "chain": fx_h3c["chain"],
                    "expect_bearer_token": True,
                    "kind": "session_open",
                    "label": "open-with-good-cfg",
                    "session_open": so_h3c,
                    "want_verdict": "ADMIT",
                },
                {
                    "action": "mail/read",
                    "actual_message_meta": {"folder": "Invoices"},
                    "arguments": {"folder": "Invoices", "message_id": _h32("d13-h3-msg")},
                    "chain": fx_h3c["chain"],
                    "contract_env": c_h3c_obj,
                    "executor_cfg": bad_cfg_h3c,
                    "grant_env": fx_h3c["bundle"]["grants"][0],
                    "kind": "bearer_session",
                    "label": "use-after-cfg-drift",
                    "slot_binding": slot_h3c,
                    "target": "mailbox:id/alice:work",
                    "token": "__FROM_OPEN__",
                    "want_refusal": "CONTRACT_CONFIG_MISMATCH",
                    "want_verdict": "REFUSE",
                },
            ],
        },
        "ADMIT",
        None,
        "SL-GRNT-015 H-3: verify_bearer_session MUST verify executor_cfg.runtime_config_sha256 against contract.config_sha256 and refuse CONTRACT_CONFIG_MISMATCH.",
        module="bearer-sessions",
    )

    # ========================================================================
    # H-5: Live verify_assent(..., anchor_height=None) MUST enforce 0x0b CRED_ISSUER_CLOSED
    # ========================================================================
    fx_h5 = rm._base_invocation_fixture()
    al_o_h5 = fx_h5["_keys"]["alice_own"]
    al_c_h5 = _kp("d13-h5-alice-cred")
    al_o_pol_h5 = {"kind": "key", "pk": al_o_h5["comp"]}
    al_reg_h5 = fx_h5["chain"]["names"]["id/alice"]["registration"]
    c_h5_seal_tx = _h32("d13-h5-cseal")
    c_h5_obj = {
        "clause_commitments": [sl.clause_commit(_h32("h5-salt"), {"text": "agree"})],
        "contract_salt": _h32("d13-h5-csalt"),
        "genesis": GENESIS_MAIN,
        "machine_clause_indices": [],
        "network": "main",
        "parties": [
            {"name_pin": {"name": "id/alice", "owner_policy": al_o_pol_h5, "registration": al_reg_h5}, "party_id": "buyer-1", "role": "buyer", "signing_policy": {"m": 1, "pks": [al_c_h5["xonly"]]}},
            {"name_pin": {"name": "id/mail-host-a", "owner_policy": {"kind": "key", "pk": fx_h5["_keys"]["host_own"]["comp"]}, "registration": fx_h5["chain"]["names"]["id/mail-host-a"]["registration"]}, "party_id": "seller-1", "role": "seller", "signing_policy": {"m": 1, "pks": [fx_h5["_keys"]["host_rcpt"]["xonly"]]}},
        ],
        "profile": "org.seallink/sale-v1",
        "seal": {"script_policy": al_o_pol_h5, "txid": c_h5_seal_tx, "vout": 0},
        "type": "seallink-contract/1",
        "window": {"not_after_height": 790000, "not_before_height": 749900},
    }
    a_h5_p = {
        "expires_at": 1795400000,
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "network": "main",
        "nonce": _h32("d13-h5-anonce"),
        "party_id": "buyer-1",
        "party_name": "id/alice",
        "party_role": "buyer",
        "target_id": sl.object_id(c_h5_obj),
        "target_type": "seallink-contract/1",
        "type": "seallink-assent/1",
    }
    a_h5_env = sl.sign_envelope(a_h5_p, [al_c_h5["sk"]])
    ch_h5 = copy.deepcopy(fx_h5["chain"])
    ch_h5["txs"][c_h5_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(al_o_pol_h5)}}}
    h5_u1 = _h32("d13-h5-u1")
    h5_val = sl.jcs_encode({"link": {"grant": al_c_h5["xonly"]}})
    ch_h5["names"]["id/alice"] = {
        "registration": al_reg_h5,
        "updates": [
            {
                "confirmed_height": 749900,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(al_o_pol_h5)), name=b"id/alice", rand=b"\x01" * 20, value=b"{}").hex(),
                "owner_policy": al_o_pol_h5,
                "txid": al_reg_h5["txid"],
                "vout": 0,
            },
            _mk_upd("id/alice", al_o_pol_h5, h5_val, h5_u1, 749910, al_reg_h5["txid"], al_o_pol_h5),
            _mk_upd(
                "id/alice", al_o_pol_h5, h5_val, _h32("d13-h5-u2-0b"), 749995, h5_u1, al_o_pol_h5,
                opreturn_hex=_mk_0b_opret("id/alice", al_reg_h5, "grant", {"m": 1, "pks": [al_c_h5["xonly"]]}, h5_u1, 749905),
            ),
        ],
    }
    add(
        "d13-h5-live-assent-anchor-height-none-0x0b-refuse",
        ["SL-CONT-005", "SL-CONT-009"],
        "assent",
        {"assent": a_h5_env, "chain": ch_h5, "contract": c_h5_obj},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "SL-CONT-005 H-5: Live verify_assent (anchor_height=None) MUST enforce 0x0b KEY_COMPROMISE_BREAK and refuse CRED_ISSUER_CLOSED.",
    )

    # ========================================================================
    # H-6: verify_owner_command & device-signed verify_statement MUST bind owner_manifest to m.h
    # ========================================================================
    fx_h6 = rm._base_invocation_fixture()
    ed_seed_h6 = sl.deterministic_ed25519_seed("d13-h6-ed")
    ed_pk_h6 = sl.ed25519_pubkey(ed_seed_h6)
    dev_seal_k_h6 = _kp("d13-h6-dseal")
    dev_seal_pol_h6 = {"kind": "key", "pk": dev_seal_k_h6["comp"]}
    dev_seal_tx_h6 = _h32("d13-h6-dseal-tx")
    fx_h6["chain"]["txs"][dev_seal_tx_h6] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(dev_seal_pol_h6)}}}
    dh_h6, dp_h6 = rm.make_salted_device_set(
        "id/alice",
        [{
            "alg": "ed25519",
            "ceiling": 2,
            "key": ed_pk_h6,
            "label": "phone-h6",
            "presence": True,
            "seal": {"script_policy": dev_seal_pol_h6, "txid": dev_seal_tx_h6, "vout": 0},
        }],
    )
    cmd_h6 = sl.sign_envelope(
        {
            "arguments": {"scope": "all"},
            "command": "keyholder-halt",
            "exp": 1795220300,
            "genesis": GENESIS_MAIN,
            "iat": 1795220000,
            "level": 2,
            "network": "main",
            "nonce": _h32("d13-h6-nonce"),
            "owner": "id/alice",
            "target_executor": "id/station-a",
            "type": "seallink-owner-command/1",
        },
        [ed_seed_h6],
        alg="ed25519",
    )
    add(
        "d13-h6-owner-command-missing-owner-manifest-refuse",
        ["SL-IDEN-008"],
        "owner_command",
        {"chain": fx_h6["chain"], "command": cmd_h6, "device_proof": dp_h6[0], "is_foreign_service": False},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "SL-IDEN-008 H-6: verify_owner_command when confirmed owner manifest omits sets.devices MUST refuse DEVICE_UNAUTHORIZED.",
    )

    al_o_pol_h6 = {"kind": "key", "pk": fx_h6["_keys"]["alice_own"]["comp"]}
    al_reg_h6 = fx_h6["chain"]["names"]["id/alice"]["registration"]
    st_h6 = sl.sign_envelope(
        {
            "genesis": GENESIS_MAIN,
            "issuer": {"name": "id/alice", "owner_policy": al_o_pol_h6, "registration": al_reg_h6},
            "network": "main",
            "not_after": 1795400000,
            "not_before": 1795200000,
            "seq": 1,
            "statement_kind": "transport-binding",
            "subject": {
                "endpoint": "wss://relay.example.org",
                "key_alg": "bip340",
                "key_hex": fx_h6["_keys"]["alice_gr"]["xonly"],
                "transport": "nostr",
            },
            "type": "seallink-statement/1",
        },
        [ed_seed_h6],
        alg="ed25519",
    )
    ch_h6_man = copy.deepcopy(fx_h6["chain"])
    man_h6_real = rm.bind_sets_manifest(ch_h6_man, "id/alice", al_o_pol_h6, al_reg_h6, device_head=dh_h6)
    man_h6_tampered = copy.deepcopy(man_h6_real)
    man_h6_tampered["seq"] = 99
    add(
        "d13-h6-statement-device-tampered-manifest-refuse",
        ["SL-IDEN-008"],
        "statement",
        {"chain": ch_h6_man, "device_proof": dp_h6[0], "owner_manifest": man_h6_tampered, "statement": st_h6},
        "REFUSE",
        "MANIFEST_MISMATCH",
        "SL-IDEN-008 H-6: Device-signed verify_statement with owner_manifest mismatching on-chain m.h MUST refuse MANIFEST_MISMATCH.",
    )

    # ========================================================================
    # H-7: log-head equivocation writes durable closure + reorg self-healing
    # ========================================================================
    j_h7a = {
        "journal_id": _h32("d13-h7a-j"),
        "initial_entries": [{
            "body": {
                "block_hash": eco_b1["chain_at_cp2"]["txs"][eco_b1["cp2_tx"]]["block_hash"],
                "checkpoint_id": eco_b1["cp2_ca"],
                "checkpoint_object_id": eco_b1["cp2_oid"],
                "checkpoint_txid": eco_b1["cp2_tx"],
                "checkpoints_root": eco_b1["cp2_env"]["payload"]["checkpoints_root"],
                "confirmed_height": 749990,
                "denials_root": eco_b1["cp2_env"]["payload"]["denials_root"],
                "issuer_name": eco_b1["iss_name"],
                "issuer_registration": eco_b1["iss_reg"],
                "log_id": eco_b1["log_id"],
                "max_seq": 2,
                "next_log_outpoint": {"txid": eco_b1["cp2_tx"], "vout": 1},
                "next_log_policy": eco_b1["seal_pol"],
                "role": "notary",
                "terminal": False,
            },
            "kind": "log-head",
        }],
    }
    cp2_eq_h7a = sl.sign_envelope({**eco_b1["cp2_env"]["payload"], "denials_root": _h32("d13-h7a-eq-dr")}, [eco_b1["iss_role"]["sk"]])
    ch_h7a = copy.deepcopy(eco_b1["chain_at_cp2"])
    ch_h7a["txs"][eco_b1["cp2_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp2_eq_h7a)).hex()
    add(
        "d13-h7a-log-head-equivocation-writes-durable-closure",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_h7a,
            "checkpoint": cp2_eq_h7a,
            "checkpoint_txid": eco_b1["cp2_tx"],
            "expect_closure_written": True,
            "journal": j_h7a,
        },
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-CONT-012 H-7a: Same-seq equivocation on verify_log_checkpoint MUST durably persist NOTARY_LOG_COMPROMISED closure in FencedJournal.",
    )

    # H-7b: Reorg orphans cp2's block; identical cp2_env re-confirms in new txid cp2_tx_reorg -> ADMIT & update log-head!
    cp2_tx_reorg = _h32("d13-h7b-cp2-reorg-tx")
    blk_reorg = _h32("d13-h7b-cp2-reorg-blk")
    ch_h7b = copy.deepcopy(eco_b1["chain_at_cp2"])
    ch_h7b["txs"].pop(eco_b1["cp2_tx"])
    ch_h7b["txs"][eco_b1["cp1_tx"]]["outputs"]["1"]["spent_by_txid"] = cp2_tx_reorg
    ch_h7b["txs"][cp2_tx_reorg] = {
        "block_hash": blk_reorg,
        "confirmed_height": 749991,
        "inputs": [sv.make_segwit_input(eco_b1["cp1_tx"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, eco_b1["cp2_ca"]).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco_b1["seal_pol"])}},
    }
    ch_h7b["blocks"] = {blk_reorg: 749991}
    add(
        "d13-h7b-log-head-reorg-same-payload-new-txid-updates-head",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_h7b,
            "checkpoint": eco_b1["cp2_env"],
            "checkpoint_txid": cp2_tx_reorg,
            "expect_journal_writes": 1,
            "expect_log_head_txid": cp2_tx_reorg,
            "journal": j_h7a,
            "replay_restart_check": True,
        },
        "ADMIT",
        None,
        "SL-CONT-012 H-7b: Orphaned log-head whose exact checkpoint_object_id re-confirms in a new txid updates persisted log-head atomically.",
    )

    # ========================================================================
    # H-8: admit_and_reserve fail-closed when delegation row_cre_tx is absent from ChainView
    # ========================================================================
    import build_branch_suite as bbs
    d_h8 = bbs._build_delegation_base()
    # Deliberately OMIT rows_tx from chain["txs"]!
    ch_h8 = copy.deepcopy(d_h8["chain"])
    ch_h8["txs"].pop(d_h8["rows_tx"], None)
    add(
        "d13-h8-delegation-missing-row-cre-tx-fail-closed",
        ["SL-GRNT-010"],
        "invocation",
        {
            "bundle": {"grants": [d_h8["parent_env"], d_h8["c1_env"]]},
            "chain": ch_h8,
            "executor_cfg": d_h8["executor_cfg"],
            "invocation": d_h8["make_inv"](d_h8["c1_id"], d_h8["c1_itx"], d_h8["keys"]["w1_k"], "h8-inv"),
            "journal": d_h8["journal"],
        },
        "REFUSE",
        "GRANT_ROW_INVALID",
        "SL-GRNT-010 H-8: Missing row_cre_tx in ChainView MUST fail closed with GRANT_ROW_INVALID (never skip row_coin output script verification).",
    )

    # ========================================================================
    # H-9: resolve_manifest enforces pairwise key disjointness including link.release
    # ========================================================================
    fx_h9 = rm._base_invocation_fixture()
    al_g_h9 = fx_h9["_keys"]["alice_gr"]["xonly"]
    al_o_pol_h9 = {"kind": "key", "pk": fx_h9["_keys"]["alice_own"]["comp"]}
    ch_h9 = copy.deepcopy(fx_h9["chain"])
    man_h9 = {"network": "main", "owner": "id/alice", "seq": 1, "type": "seallink-manifest/1"}
    man_h9_h = sl.content_addr(man_h9)
    ch_h9["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_h9["chain"]["names"]["id/alice"]["registration"], al_o_pol_h9,
        {"link": {"grant": al_g_h9, "release": al_g_h9}, "m": {"h": man_h9_h, "s": 1}},
    )
    add(
        "d13-h9-manifest-release-key-collides-with-grant-key-refuse",
        ["SL-IDEN-003"],
        "name_resolve",
        {"chain": ch_h9, "check_manifest": True, "manifests": {man_h9_h: man_h9}, "name": "id/alice"},
        "REFUSE",
        "NAME_VALUE_INVALID",
        "SL-IDEN-003 H-9: Reusing the same pubkey in link.release and link.grant MUST refuse NAME_VALUE_INVALID.",
    )

    # ========================================================================
    # H-10 & H-11: Clean SIGHASH_ALL self-update restores writer_verified (non-ALL SLNK inert) + self-funded FIRSTUPDATE
    # ========================================================================
    k_h10_o = _kp("d13-h10-o")
    k_h10_g = _kp("d13-h10-g")
    pol_h10 = {"kind": "key", "pk": k_h10_o["comp"]}
    reg_h10 = {"txid": _h32("d13-h10-reg"), "vout": 0}
    ch_h10 = _mk_chain(tip_height=750010)
    h10_u1 = _h32("d13-h10-u1-nonall")
    h10_val = sl.jcs_encode({"link": {"grant": k_h10_g["xonly"]}})
    ch_h10["names"]["id/h10-restore"] = {
        "registration": reg_h10,
        "updates": [
            {
                "confirmed_height": 749900,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(pol_h10)), name=b"id/h10-restore", rand=b"\x01" * 20, value=b"{}").hex(),
                "owner_policy": pol_h10,
                "txid": reg_h10["txid"],
                "vout": 0,
            },
            _mk_upd(
                "id/h10-restore", pol_h10, h10_val, h10_u1, 749950, reg_h10["txid"], pol_h10,
                sighash_bytes=[0x81],  # Non-SIGHASH_ALL update -> SLNK frame MUST be inert!
                opreturn_hex=_mk_0b_opret("id/h10-restore", reg_h10, "grant", {"m": 1, "pks": [k_h10_g["xonly"]]}, reg_h10["txid"], 749900),
            ),
            _mk_upd("id/h10-restore", pol_h10, h10_val, _h32("d13-h10-u2-clean"), 749960, h10_u1, pol_h10),
        ],
    }
    add(
        "d13-h10-clean-sighash-all-restores-writer-verified-admit",
        ["SL-LDGR-007", "SL-LDGR-010"],
        "name_resolve",
        {"chain": ch_h10, "expected_owner_policy": pol_h10, "name": "id/h10-restore"},
        "ADMIT",
        None,
        "SL-LDGR-007 H-10: Clean SIGHASH_ALL self-update restores writer_verified after an earlier non-SIGHASH_ALL update (whose SLNK frame is inert).",
    )

    ch_h11 = _mk_chain(tip_height=750010)
    ch_h11["names"]["id/h11-selffund"] = sv.make_name_history(
        "id/h11-selffund", {"txid": _h32("d13-h11-reg"), "vout": 0}, pol_h10,
        {"link": {"grant": k_h10_g["xonly"]}},
        first_only=True, firstupdate_self_funded=True,
    )
    add(
        "d13-h11-self-funded-firstupdate-admit",
        ["SL-LDGR-007"],
        "name_resolve",
        {"chain": ch_h11, "expected_owner_policy": pol_h10, "name": "id/h11-selffund"},
        "ADMIT",
        None,
        "SL-LDGR-007 H-11: Self-funded OP_NAME_FIRSTUPDATE (firstupdate_self_funded=True) is writer-verified without requiring an extra OP_NAME_UPDATE.",
    )

    # ========================================================================
    # M-4: Mempool / maturing 0x14 head grace vs matured successor refusal
    # ========================================================================
    ch_m4_mem = copy.deepcopy(eco_b1["chain_at_cp3"])
    # tip_height = 750010; cp2 at 749990 (depth 21 >= 6); cp3 at 750006 (depth 5 < 6 -> maturing 0x14!)
    ch_m4_mem["txs"][eco_b1["cp3_tx"]]["confirmed_height"] = 750006
    add(
        "d13-m4-maturing-0x14-successor-allows-prev-head-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_m4_mem, "checkpoint": eco_b1["cp2_env"], "checkpoint_txid": eco_b1["cp2_tx"], "required_depth": 6},
        "ADMIT",
        None,
        "SL-CONT-012 M-4: When cp2's vout=1 is spent only by a maturing (< required_depth) 0x14 successor, cp2 remains admissible as current head.",
    )
    ch_m4_mat = copy.deepcopy(ch_m4_mem)
    ch_m4_mat["txs"][eco_b1["cp3_tx"]]["confirmed_height"] = 750005  # depth 6 == required_depth -> matured!
    add(
        "d13-m4-matured-0x14-successor-refuses-stale-head",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_m4_mat, "checkpoint": eco_b1["cp2_env"], "checkpoint_txid": eco_b1["cp2_tx"], "required_depth": 6},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 M-4: Once 0x14 successor reaches required_depth (depth == 6), previous head cp2 MUST refuse CHAIN_FRAME_INVALID.",
    )

    # ========================================================================
    # M-5: Gatekeeper global deny-wins, duplicate trusted_notaries, present+absent overlap, role-scoped denial_key
    # ========================================================================
    gk_n1 = bd11._build_log_ecosystem("d13-m5-n1", role="notary")
    gk_n2 = bd11._build_log_ecosystem("d13-m5-n2", role="notary")
    gk_art = {"digest": _h32("d13-m5-art"), "scheme": "sha256"}
    gk_tid = sl.artifact_target_id(gk_art)
    gk_ch = _mk_chain(tip_height=750000)

    def _mint_m5_notary(eco: dict[str, Any], tag: str, status: str) -> tuple[dict[str, Any], dict[str, Any]]:
        ap = {
            "act_kind": "artifact-notarization",
            "attested_at": 1795219000,
            "details": {"artifact_identity": gk_art, "claims": [{"claim_id": "org.seallink.audit/build-reproducible", "verdict": status}], "kind": "artifact-notarization"},
            "genesis": GENESIS_MAIN,
            "lifecycle": "log_tracked",
            "log_id": eco["log_id"],
            "network": "main",
            "notary": eco["iss_role_pin"],
            "target_sha256": gk_tid,
            "tip_hash": gk_ch["tip_hash"],
            "tip_height": gk_ch["tip_height"],
            "type": "seallink-notary/1",
        }
        ae = sl.sign_envelope(ap, [eco["iss_role"]["sk"]])
        aca = sl.content_addr(ae)
        e_a = sl.log_entry_digest(0x01, aca)
        br, bps = sl.build_log_batch_root([e_a])
        cp_p = {
            "batch_count": 1,
            "batch_root": br,
            "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
            "cumulative_entries_count": 1,
            "denials_delta_root": sl.EMPTY_BATCH_ROOT,
            "denials_root": sl.SMT_EMPTY_ROOT,
            "genesis": GENESIS_MAIN,
            "genesis_seal_outpoint": eco["gen_op"],
            "issuer": eco["iss_role_pin"],
            "log_id": eco["log_id"],
            "network": "main",
            "next_log_policy": eco["seal_pol"],
            "next_log_vout": 1,
            "prev_log_outpoint": eco["gen_op"],
            "role": "notary",
            "seq": 1,
            "terminal": False,
            "type": "seallink-log-checkpoint/1",
        }
        cp_e = sl.sign_envelope(cp_p, [eco["iss_role"]["sk"]])
        cp_tx = _h32(f"d13-m5-cp-{tag}")
        gk_ch["names"][eco["iss_name"]] = copy.deepcopy(eco["chain"]["names"][eco["iss_name"]])
        gk_ch["txs"][eco["gen_op"]["txid"]] = {"confirmed_height": 749980, "outputs": {"0": {"script_pubkey_hex": _spk_hex(eco["seal_pol"]), "spent_by_txid": cp_tx}}}
        gk_ch["txs"][cp_tx] = {
            "block_hash": _h32(f"d13-m5-blk-{tag}"),
            "confirmed_height": 749990,
            "inputs": [sv.make_segwit_input(eco["gen_op"]["txid"], 0)],
            "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(cp_e)).hex(),
            "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco["seal_pol"])}},
        }
        entry = {
            "act_smt_proof": sl.smt_prove({}, f"act:{sl.object_id(ap)}|*"),
            "batch_proof": bps[e_a],
            "checkpoint": cp_e,
            "checkpoint_txid": cp_tx,
            "notary_act": ae,
            "target_smt_proof": sl.smt_prove({}, f"target:{gk_tid}|*"),
        }
        return entry, {"log_id": eco["log_id"], "notary_pin": {"name": eco["iss_name"], "owner_policy": eco["iss_pol"], "registration": eco["iss_reg"]}}

    m5_ent1, m5_tn1 = _mint_m5_notary(gk_n1, "n1", "pass")
    m5_ent2, m5_tn2 = _mint_m5_notary(gk_n2, "n2", "fail")
    gk_pol_m5 = {
        "allow_reinstatement": True,
        "mode": "hardened",
        "quorum_m": 1,
        "required_claims": ["org.seallink.audit/build-reproducible"],
        "trusted_notaries": [m5_tn1, m5_tn2],
    }
    gk_tkt_m5 = {
        "artifact_identity": gk_art,
        "genesis": GENESIS_MAIN,
        "network": "main",
        "notarizations": [m5_ent1, m5_ent2],  # pass first (reaches quorum_m=1!), fail second -> MUST deny!
        "target_sha256": gk_tid,
        "type": "seallink-ticket/1",
    }
    add(
        "d13-m5-gatekeeper-fail-deny-wins-after-quorum-refuse",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_ch, "policy": gk_pol_m5, "ticket": gk_tkt_m5},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003 M-5: Global deny-wins for trusted notary status='fail' MUST refuse ARTIFACT_POLICY_DENIED even after earlier entries reach quorum_m.",
        module="artifact-notarization",
    )

    gk_pol_dup = {**gk_pol_m5, "trusted_notaries": [m5_tn1, m5_tn1]}
    add(
        "d13-m5-gatekeeper-duplicate-trusted-notary-refuse",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_ch, "policy": gk_pol_dup, "ticket": {**gk_tkt_m5, "notarizations": [m5_ent1]}},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003 M-5: Duplicate (name, registration) inside GatekeeperPolicy.trusted_notaries MUST refuse ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )

    gk_tkt_overlap = {
        **gk_tkt_m5,
        "absent_notary_proofs": [{
            "head_checkpoint": m5_ent1["checkpoint"],
            "head_checkpoint_txid": m5_ent1["checkpoint_txid"],
            "log_id": gk_n1["log_id"],
            "target_smt_proof": m5_ent1["target_smt_proof"],
        }],
        "notarizations": [m5_ent1],
    }
    add(
        "d13-m5-gatekeeper-notary-present-and-absent-overlap-refuse",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_ch, "policy": {**gk_pol_m5, "trusted_notaries": [m5_tn1]}, "ticket": gk_tkt_overlap},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003 M-5: Same notary appearing in both notarizations[] and absent_notary_proofs[] MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # Role-scoped denial_key: notary revocation with "rel:" prefix and release revocation with "act:" prefix MUST refuse WIRE_MEMBER!
    bad_rel_rev_p = {
        **eco_b1["rev1_env"]["payload"],
        "denial_key": f"rel:{_h32('d13-m5-rel-prefix')}|*",
    }
    bad_rel_rev_env = sl.sign_envelope(bad_rel_rev_p, [eco_b1["iss_role"]["sk"]])
    add(
        "d13-m5-role-scoped-denial-key-notary-rel-prefix-refuse",
        ["SL-CONT-012"],
        "raw_wire",
        {"expected_type": "seallink-log-revocation/1", "object": bad_rel_rev_env},
        "REFUSE",
        "WIRE_MEMBER",
        "SL-CONT-012 M-5: Role-scoped denial_key forbids 'rel:' prefix in a 'notary' role LogRevocation -> WIRE_MEMBER.",
    )
    bad_act_rel_p = {
        **eco_b1["rev1_env"]["payload"],
        "denial_key": f"act:{_h32('d13-m5-act-on-rel')}|*",
        "role": "release",
    }
    bad_act_rel_env = sl.sign_envelope(bad_act_rel_p, [eco_b1["iss_role"]["sk"]])
    add(
        "d13-m5-role-scoped-denial-key-release-act-prefix-refuse",
        ["SL-CONT-012"],
        "raw_wire",
        {"expected_type": "seallink-log-revocation/1", "object": bad_act_rel_env},
        "REFUSE",
        "WIRE_MEMBER",
        "SL-CONT-012 M-5: Role-scoped denial_key forbids 'act:' prefix in a 'release' role LogRevocation -> WIRE_MEMBER.",
    )

    # ========================================================================
    # M-8: A -> B -> A role rotation + 0x0b compromise parity (CRED_ISSUER_CLOSED precedes NAME_ROLE_CHANGED)
    # ========================================================================
    fx_m8 = rm._base_invocation_fixture()
    k_m8_b = _kp("d13-m8-role-b")
    al_o_pol_m8 = {"kind": "key", "pk": fx_m8["_keys"]["alice_own"]["comp"]}
    al_g_m8 = fx_m8["_keys"]["alice_gr"]["xonly"]
    al_reg_m8 = fx_m8["chain"]["names"]["id/alice"]["registration"]
    ch_m8 = copy.deepcopy(fx_m8["chain"])
    m8_u1 = _h32("d13-m8-u1-a")
    m8_u2 = _h32("d13-m8-u2-b")
    m8_va = sl.jcs_encode({"link": {"grant": al_g_m8}})
    m8_vb = sl.jcs_encode({"link": {"grant": k_m8_b["xonly"]}})
    ch_m8["names"]["id/alice"] = {
        "registration": al_reg_m8,
        "updates": [
            {
                "confirmed_height": 749900,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(al_o_pol_m8)), name=b"id/alice", rand=b"\x01" * 20, value=b"{}").hex(),
                "owner_policy": al_o_pol_m8,
                "txid": al_reg_m8["txid"],
                "vout": 0,
            },
            _mk_upd("id/alice", al_o_pol_m8, m8_va, m8_u1, 749910, al_reg_m8["txid"], al_o_pol_m8),
            _mk_upd("id/alice", al_o_pol_m8, m8_vb, m8_u2, 749950, m8_u1, al_o_pol_m8),
            _mk_upd(
                "id/alice", al_o_pol_m8, m8_va, _h32("d13-m8-u3-a-0b"), 749995, m8_u2, al_o_pol_m8,
                opreturn_hex=_mk_0b_opret("id/alice", al_reg_m8, "grant", {"m": 1, "pks": [al_g_m8]}, m8_u2, 749905),
            ),
        ],
    }
    fx_m8["chain"] = ch_m8
    add(
        "d13-m8-role-a-to-b-to-a-plus-0x0b-refuses-cred-issuer-closed",
        ["SL-CONT-009", "SL-GRNT-003"],
        "invocation",
        fx_m8,
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "SL-CONT-009 M-8: When link.grant rotated A->B->A AND A was compromised via 0x0b, CRED_ISSUER_CLOSED takes precedence over NAME_ROLE_CHANGED.",
    )

    # ========================================================================
    # M-10: verify_termination arbiter + ward guardian_approvals[]
    # ========================================================================
    arb_c = _kp("d13-m10-arb-c")
    # Reuse H-2's active Revision 2 ward fixture (where contract_assent quorum has min=1 on active slot 2!)
    fx_m10 = copy.deepcopy(fx_h2)
    ch_m10 = fx_m10["chain"]
    c_m10_obj = copy.deepcopy(fx_m10["contract"])
    p_a_m10 = _kp("d13-m10-pa")
    p_b_m10 = _kp("d13-m10-pb")
    arb_seal_pol = {
        "keys": {
            "a": p_a_m10["comp"],
            "arbiter": arb_c["comp"],
            "b": p_b_m10["comp"],
        },
        "kind": "branch",
        "template": "arbiter_or_both",
    }
    c_m10_obj["seal"]["script_policy"] = arb_seal_pol
    c_m10_id = sl.object_id(c_m10_obj)
    t_arb_p = {
        "contract_id": c_m10_id,
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "network": "main",
        "reason": "Arbiter terminated contract per dispute clause",
        "termination_branch": "arbiter",
        "type": "seallink-termination/1",
    }
    t_arb_env = sl.sign_envelope(t_arb_p, [arb_c["sk"]])
    add(
        "d13-m10-termination-by-contract-arbiter-admit",
        ["SL-CONT-007"],
        "termination",
        {"chain": ch_m10, "contract": c_m10_obj, "termination": t_arb_env},
        "ADMIT",
        None,
        "SL-CONT-007 M-10: seallink-termination/1 signed by the contract's designated arbiter admits.",
    )

    t_ward_base_p = {
        "contract_id": c_m10_id,
        "genesis": GENESIS_MAIN,
        "guardian_context": {"event_class": "contract_assent", "origin_id": fx_m10["_origin_id"], "revision": 2, "ward_name": "id/child-leo"},
        "issued_at": 1795220000,
        "network": "main",
        "reason": "Ward requested termination with guardian quorum",
        "termination_branch": "either_party",
        "type": "seallink-termination/1",
    }
    # Ward attempting termination signed with a stranger key -> REFUSE WIRE_SIGNATURE
    stranger_m10 = _kp("d13-m10-stranger")
    t_ward_bad_g = sl.sign_guardian_envelope(
        t_ward_base_p,
        [{"guardian_name": "id/parent-a", "revision": 2, "signers": [stranger_m10["sk"]], "slot": 2}],
    )
    add(
        "d13-m10-termination-by-ward-stranger-guardian-sig-refuse",
        ["SL-CONT-007", "SL-ORIG-006"],
        "termination",
        {
            "chain": ch_m10,
            "contract": c_m10_obj,
            "origin_bundle": fx_m10["origin_bundle"],
            "termination": t_ward_bad_g,
            "trusted_origin_issuer_pins": fx_m10["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "WIRE_SIGNATURE",
        "SL-CONT-007 M-10: Ward termination with forged guardian_approvals signature MUST refuse WIRE_SIGNATURE.",
    )

    t_ward_ok = sl.sign_guardian_envelope(
        t_ward_base_p,
        [{"guardian_name": "id/parent-a", "revision": 2, "signers": [fx_m10["_keys"]["g1_gr"]["sk"]], "slot": 2}],
    )
    add(
        "d13-m10-termination-by-ward-with-guardian-approvals-admit",
        ["SL-CONT-007", "SL-ORIG-006"],
        "termination",
        {
            "chain": ch_m10,
            "contract": c_m10_obj,
            "origin_bundle": fx_m10["origin_bundle"],
            "termination": t_ward_ok,
            "trusted_origin_issuer_pins": fx_m10["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "SL-CONT-007 M-10: Ward terminating a contract with valid active guardian_approvals[] admits.",
    )

    # ========================================================================
    # M-13 (R12-L6): Default Tier1Verifier() (enabled_modules=None) is fail-closed core-only
    # ========================================================================
    add(
        "d13-m13-default-verifier-core-only-refuses-optional-module",
        ["SL-ARTF-001"],
        "tier2_name_history",
        {"expected_owner_policy": t2_p1, "page": _mk_t2_page("id/t2-p2wsh-rot", [pr_rot1]), "pinned_network": "regtest"},
        "REFUSE",
        "ACTION_UNSUPPORTED",
        "SL-ARTF-001 M-13: Default Tier1Verifier(enabled_modules=None) enables only 'core' and MUST refuse optional-module objects with ACTION_UNSUPPORTED.",
        module="core",
    )

    # ========================================================================
    # Commit 1 Triple-Mutation 100.0% Closure (exact boundaries + live error branches)
    # ========================================================================
    # 1. _verify_rebound_pin exact at_height == h_13 (<= vs <) via eternal subject.mode="name" credential
    cred_iss_mk = _kp("d13-mk-cred-iss")
    cred_iss_o_mk = _kp("d13-mk-cred-iss-o")
    cred_iss_pol_mk = {"kind": "key", "pk": cred_iss_o_mk["comp"]}
    cred_iss_reg_mk = {"txid": _h32("d13-mk-cred-iss-reg"), "vout": 0}
    ch_mk_rb = copy.deepcopy(ch_h1a)
    ch_mk_rb["names"]["id/mk-cred-iss"] = sv.make_name_history(
        "id/mk-cred-iss", cred_iss_reg_mk, cred_iss_pol_mk, {"link": {"cred": cred_iss_mk["xonly"]}}, update_height=749100
    )
    cred_mk_p = {
        "claims": {"ok": True},
        "credential_kind": "org.seallink.test/rebind-boundary",
        "genesis": GENESIS_MAIN,
        "issued_at": 1795210000,
        "issuer": {"name": "id/mk-cred-iss", "owner_policy": cred_iss_pol_mk, "registration": cred_iss_reg_mk, "role_policy": {"m": 1, "pks": [cred_iss_mk["xonly"]]}},
        "lifecycle": "eternal",
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 749000,
        "subject": {"mode": "name", "name_pin": {"name": b1_h1a_name, "owner_policy": b1_h1a_pol, "registration": b1_h1a_reg}},
        "type": "seallink-credential/1",
    }
    cred_mk_env = sl.sign_envelope(cred_mk_p, [cred_iss_mk["sk"]])
    cred_mk_anc = _h32("d13-mk-cred-anc-h13")
    ch_mk_rb["txs"][cred_mk_anc] = {
        "confirmed_height": 749500,  # EXACT h_13!
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cred_mk_env)).hex(),
        "outputs": {},
    }
    ob_bad_mk = copy.deepcopy(fx_h1a["origin_bundle"])
    ob_bad_mk.pop("name_binding", None)
    add(
        "d13-mk-rebound-pin-at-exact-h13-boundary-refuse",
        ["SL-ORIG-017"],
        "credential",
        {
            "anchor_txid": cred_mk_anc,
            "chain": ch_mk_rb,
            "credential": cred_mk_env,
            "origin_bundle": ob_bad_mk,
            "trusted_origin_issuer_pins": fx_h1a["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-017: _verify_rebound_pin MUST evaluate confirmed 0x13 at exact anchor height h_anchor == h_13 (<= boundary).",
    )

    # 2. _verify_rebound_pin ob is None when origin_bundles_by_oid lacks target oid -> ORIGIN_STATUS_INCOMPLETE
    fx_mk_rcpt = rm._base_invocation_fixture()
    rcpt_o_mk = _kp("d13-mk-rcpt-o")
    rcpt_o_pol_mk = {"kind": "key", "pk": rcpt_o_mk["comp"]}
    rcpt_reg_mk = {"txid": _h32("d13-mk-rcpt-reg"), "vout": 0}
    rcpt_u1_mk = _h32("d13-mk-rcpt-u1")
    ch_mk_rcpt = copy.deepcopy(fx_mk_rcpt["chain"])
    ch_mk_rcpt["names"]["id/mk-rcpt"] = {
        "registration": rcpt_reg_mk,
        "updates": [
            {
                "confirmed_height": 749800,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(rcpt_o_pol_mk)), name=b"id/mk-rcpt", rand=b"\x04" * 20, value=b"{}").hex(),
                "owner_policy": rcpt_o_pol_mk,
                "txid": rcpt_reg_mk["txid"],
                "vout": 0,
            },
            _mk_upd("id/mk-rcpt", rcpt_o_pol_mk, sl.jcs_encode({"nostr": fx_mk_rcpt["_keys"]["agent_req"]["xonly"]}), rcpt_u1_mk, 749850, rcpt_reg_mk["txid"], rcpt_o_pol_mk),
            _mk_upd("id/mk-rcpt", rcpt_o_pol_mk, b"{}", _h32("d13-mk-rcpt-0x13"), 749900, rcpt_u1_mk, rcpt_o_pol_mk, opreturn_hex=sl.encode_opreturn(0x13, _h32("d13-mk-rcpt-cand")).hex()),
        ],
    }
    gp_mk_rcpt = copy.deepcopy(fx_mk_rcpt["bundle"]["grants"][0]["payload"])
    gp_mk_rcpt["recipient"] = {"mode": "name", "name": "id/mk-rcpt", "owner_policy": rcpt_o_pol_mk, "registration": rcpt_reg_mk}
    fx_mk_rcpt["chain"] = ch_mk_rcpt
    rm._reanchor_grant(fx_mk_rcpt, gp_mk_rcpt)
    fx_mk_rcpt["bundle"]["origin_bundles_by_oid"] = {_h32("unrelated-oid-mk"): fx_h1a["origin_bundle"]}
    add(
        "d13-mk-rebound-pin-missing-bundle-in-oid-map-incomplete",
        ["SL-ORIG-017"],
        "invocation",
        fx_mk_rcpt,
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: Named recipient with confirmed 0x13 and origin_bundles_by_oid lacking its origin_id MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )

    # 3. Emancipation handover self-renewal at exact block_time == opened_majority (>= vs > on is_post_maj)
    of_maj = rm._base_origin_fixture()
    ch_maj = copy.deepcopy(of_maj["chain"])
    ob_maj = copy.deepcopy(of_maj["origin_bundle"])
    maj_t = ob_maj["opened_majority_unix"]
    ch_maj["now"] = maj_t + 600
    ch_maj["tip_median_time_past"] = maj_t + 600
    ch_maj["credible_utc_interval"] = [maj_t + 600, maj_t + 660]
    ward_new_k = _kp("d13-mk-maj-ward-new")
    ward_new_pol = {"kind": "key", "pk": ward_new_k["comp"]}
    maj_rec_reg = {"txid": _h32("d13-mk-maj-rec-reg"), "vout": 0}
    maj_rec_pol = of_maj["_rec_pol"]
    maj_b2 = {
        "binding_mode": "recovery",
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo-maj-mk",
        "network": "main",
        "next_recovery_policy": maj_rec_pol,
        "next_recovery_vout": 0,
        "origin_id": of_maj["_origin_id"],
        "owner_policy": ward_new_pol,
        "registration": maj_rec_reg,
        "seq": 2,
        "supersedes_binding_id": sl.object_id(ob_maj["name_binding"]),
        "type": "seallink-name-binding/1",
    }
    maj_rtx = _h32("d13-mk-maj-rtx")
    maj_rs_op = ob_maj["origin"]["payload"]["name_recovery"]["recovery_seal"]
    ch_maj["txs"][maj_rs_op["txid"]]["outputs"]["0"]["spent_by_txid"] = maj_rtx
    ch_maj["txs"][maj_rtx] = {
        "confirmed_height": 749600,
        "inputs": [sv.make_segwit_input(maj_rs_op["txid"], maj_rs_op["vout"])],
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(maj_b2)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(maj_rec_pol)}},
    }
    ob_maj["recovery_bindings"] = [maj_b2]
    # Follow with a 0x13 voluntary rebind b2 -> b3 at h=749850 (NO block_time at 749850!) so ONLY emancipation at h=749800 (block_time == maj_t) permits 0x13!
    maj_b3_k = _kp("d13-mk-maj-b3-k")
    maj_b3_pol = {"kind": "key", "pk": maj_b3_k["comp"]}
    maj_b3_reg = {"txid": _h32("d13-mk-maj-b3-reg"), "vout": 0}
    maj_b3_off = _h32("d13-mk-maj-b3-off")
    maj_b3_reb = _h32("d13-mk-maj-b3-reb")
    maj_b3 = {
        "binding_mode": "voluntary",
        "consent_outpoint": {"txid": maj_b3_off, "vout": 1},
        "delay_blocks": 144,
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo-maj-v3",
        "network": "main",
        "origin_id": of_maj["_origin_id"],
        "owner_policy": maj_b3_pol,
        "registration": maj_b3_reg,
        "seq": 3,
        "supersedes_binding_id": sl.object_id(maj_b2),
        "type": "seallink-name-binding/1",
    }
    ob_maj["voluntary_rebind_bindings"] = [maj_b3]
    u_self_maj_tx = _h32("d13-mk-maj-self")
    u_self_maj = _mk_upd("id/child-leo-maj-mk", ward_new_pol, sl.jcs_encode({"link": {"origin": of_maj["_origin_id"]}}), u_self_maj_tx, 749800, maj_rec_reg["txid"], ward_new_pol)
    u_self_maj["block_time"] = maj_t  # EXACT opened_majority!
    u_13_maj = _mk_upd("id/child-leo-maj-mk", ward_new_pol, b"{}", maj_b3_reb, 749850, u_self_maj_tx, ward_new_pol, opreturn_hex=sl.encode_opreturn(0x13, sl.object_id(maj_b3)).hex())
    ch_maj["names"]["id/child-leo-maj-mk"] = {
        "registration": maj_rec_reg,
        "updates": [
            {
                "confirmed_height": 749590,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(ward_new_pol)), name=b"id/child-leo-maj-mk", rand=b"\x05" * 20, value=sl.jcs_encode({"link": {"origin": of_maj["_origin_id"]}})).hex(),
                "owner_policy": ward_new_pol,
                "txid": maj_rec_reg["txid"],
                "vout": 0,
            },
            u_self_maj,
            u_13_maj,
        ],
    }
    ch_maj["names"]["id/child-leo-maj-v3"] = {
        "registration": maj_b3_reg,
        "updates": [
            {
                "confirmed_height": 749810,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(maj_b3_pol)), name=b"id/child-leo-maj-v3", rand=b"\x06" * 20, value=b"{}").hex(),
                "owner_policy": maj_b3_pol,
                "txid": maj_b3_reg["txid"],
                "vout": 0,
            },
            _mk_upd("id/child-leo-maj-v3", maj_b3_pol, b"", maj_b3_off, 749830, maj_b3_reg["txid"], maj_b3_pol),
            _mk_upd("id/child-leo-maj-v3", maj_b3_pol, sl.jcs_encode({"link": {"origin": of_maj["_origin_id"]}}), _h32("d13-mk-maj-b3-act"), 749994, maj_b3_off, maj_b3_pol),
        ],
    }
    ch_maj["txs"][maj_b3_off] = {"confirmed_height": 749830, "outputs": {"1": {"script_pubkey_hex": _spk_hex(maj_b3_pol), "spent_by_txid": maj_b3_reb}}, "version": 0x7100}
    ch_maj["txs"][maj_b3_reb] = {
        "confirmed_height": 749850,
        "inputs": [sv.make_segwit_input(u_self_maj_tx, 0), sv.make_segwit_input(maj_b3_off, 1)],
        "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(maj_b3)).hex(),
        "outputs": {},
        "version": 0x7100,
    }
    ch_maj["block_times"] = {str(749600 + 144): maj_t, "749800": maj_t}
    add(
        "d13-mk-emancipation-self-renewal-at-exact-majority-block-time-admit",
        ["SL-ORIG-010", "SL-ORIG-017"],
        "origin_status",
        {"chain": ch_maj, "expect_active_name": "id/child-leo-maj-v3", "origin_bundle": ob_maj, "trusted_origin_issuer_pins": of_maj["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-010: Post-majority 0x0c recovery self-update at exact block_time == opened_majority schedules emancipation before a subsequent 0x13 rebind to id/child-leo-maj-v3.",
    )

    # 4. Exact automaton step budget state_steps_used == max_automaton_steps (2) -> ADMIT_AUTONOMOUS (> vs >=)
    fx_steps_eq = bd11._build_autonomous_origin_rebind_fixture("d13-mk-steps-eq", h_offer=749450, h_13=749500, h_act=749644, tip_h=749644)
    add(
        "d13-mk-automaton-steps-exact-budget-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": fx_steps_eq["chain"],
            "max_automaton_steps": 2,
            "origin_bundle": fx_steps_eq["origin_bundle"],
            "trusted_origin_issuer_pins": fx_steps_eq["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 M-1: state_steps_used == max_automaton_steps (exact budget boundary) MUST admit.",
    )

    # 5. Unknown-preimage 0x13 pending BEFORE deadline (h_13 < tip < h_13 + min_d) -> ORIGIN_STATUS_INCOMPLETE (kills L4240 wrong-code!)
    fx_unk_pre = bd11._build_autonomous_origin_rebind_fixture("d13-mk-unk-pre", h_offer=749450, h_13=749500, h_act=None, tip_h=749510)
    ob_unk_pre = copy.deepcopy(fx_unk_pre["origin_bundle"])
    ob_unk_pre["voluntary_rebind_bindings"] = []
    add(
        "d13-mk-unknown-preimage-0x13-before-deadline-incomplete",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": fx_unk_pre["chain"],
            "origin_bundle": ob_unk_pre,
            "trusted_origin_issuer_pins": fx_unk_pre["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: Pending unknown-preimage 0x13 inside [h_13, h_13 + min_d) MUST refuse ORIGIN_STATUS_INCOMPLETE (not RECOVERY_FORBIDDEN).",
    )

    # 6. Pre-0x0f trace_slot _walk_exhausted (2-tx vacant<->pending cycle on rev 1 before rev 2 roster_eff_h) -> ORIGIN_STATUS_INCOMPLETE
    fx_pre_cy = copy.deepcopy(fx_h2)
    gp_pcy = fx_pre_cy["origin_bundle"]["origin"]["payload"]["guardian_policy"]
    vac_pcy = gp_pcy["roster_seal"]["script_policy"]
    g_pin_pcy = fx_pre_cy["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]
    g_seal_pcy = _kp("d13-mk-pre-cy-gs")
    pend_pcy_pol = {"delay_blocks": gp_pcy["appointment_delay_blocks"], "keys": {"challenger": gp_pcy["challenger_pk"], "disposer": gp_pcy["disposer_pk"], "guardian": g_seal_pcy["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
    act_pcy_pol = {"keys": sl.canonical_branch_pair(gp_pcy["disposer_pk"], g_seal_pcy["comp"]), "kind": "branch", "template": "either_of_2"}
    halt_pcy_tx = _h32("d13-mk-pre-cy-halt")
    pend_pcy_tx = _h32("d13-mk-pre-cy-pend")
    g_app_pcy_p = {
        "activation_mode": "appointed", "active_policy": act_pcy_pol, "effective_delay_blocks": gp_pcy["appointment_delay_blocks"],
        "genesis": GENESIS_MAIN, "guardian": g_pin_pcy, "issuer": fx_pre_cy["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main", "origin_id": fx_pre_cy["_origin_id"], "pending_policy": pend_pcy_pol, "pending_vout": 0,
        "prev_outpoint": {"txid": halt_pcy_tx, "vout": 0}, "revision": 1, "slot": 1, "term": {"mode": "indefinite"}, "type": "seallink-guardian/1",
    }
    g_app_pcy = sl.sign_envelope(g_app_pcy_p, [fx_pre_cy["_keys"]["reg_cred"]["sk"]])
    g_app_pcy_ass = sl.sign_envelope(
        {"expires_at": fx_pre_cy["chain"]["now"] + 100000, "genesis": GENESIS_MAIN, "issued_at": fx_pre_cy["chain"]["now"] - 100, "network": "main", "nonce": _h32("d13-mk-pre-cy-ga"), "party_id": "g-pcy", "party_name": g_pin_pcy["name"], "party_role": "guardian", "target_id": sl.object_id(g_app_pcy_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1"},
        [fx_pre_cy["_keys"]["g1_gr"]["sk"]],
    )
    fx_pre_cy["origin_bundle"]["guardian_records"].append(g_app_pcy)
    fx_pre_cy["origin_bundle"]["guardian_assents"].append(g_app_pcy_ass)
    fx_pre_cy["chain"]["txs"][rm._h32("og1-init-0x12")]["outputs"]["0"]["spent_by_txid"] = halt_pcy_tx
    fx_pre_cy["chain"]["txs"][halt_pcy_tx] = {"confirmed_height": 749060, "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pcy), "spent_by_txid": pend_pcy_tx}}}
    fx_pre_cy["chain"]["txs"][pend_pcy_tx] = {"confirmed_height": 749061, "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g_app_pcy)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_pcy_pol), "spent_by_txid": halt_pcy_tx}}}
    add(
        "d13-mk-pre-0x0f-slot-walk-exhausted-incomplete",
        ["SL-ORIG-014"],
        "origin_status",
        {"chain": fx_pre_cy["chain"], "origin_bundle": fx_pre_cy["origin_bundle"], "trusted_origin_issuer_pins": fx_pre_cy["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-014 H-2: Exhausted slot walk while snapshotting revision R at roster_eff_h MUST fail closed ORIGIN_STATUS_INCOMPLETE.",
    )

    # 7. verify_ward_approvals approving guardian has unresolved 0x13 while origin_bundles_by_oid is passed -> GUARDIAN_INACTIVE
    ch_g_rb = copy.deepcopy(ch_m10)
    g1_u_rb = ch_g_rb["names"]["id/parent-a"]["updates"]
    g1_prev_rb = g1_u_rb[-1]
    g1_rb_tx = _h32("d13-mk-g1-0x13")
    g1_u_rb.append(
        _mk_upd("id/parent-a", g1_prev_rb["owner_policy"], b"{}", g1_rb_tx, 750050, g1_prev_rb["txid"], g1_prev_rb["owner_policy"], opreturn_hex=sl.encode_opreturn(0x13, _h32("d13-mk-g1-cand")).hex())
    )
    # Restore link.grant in a subsequent update so ONLY _verify_rebound_pin (not resolve_role_policy!) rejects!
    g1_u_rb.append(
        _mk_upd("id/parent-a", g1_prev_rb["owner_policy"], sl.jcs_encode({"link": {"grant": fx_m10["_keys"]["g1_gr"]["xonly"]}}), _h32("d13-mk-g1-restore"), 750060, g1_rb_tx, g1_prev_rb["owner_policy"])
    )
    add(
        "d13-mk-ward-approval-guardian-unresolved-0x13-refuse",
        ["SL-ORIG-006", "SL-ORIG-017"],
        "termination",
        {
            "chain": ch_g_rb,
            "contract": c_m10_obj,
            "origin_bundle": fx_m10["origin_bundle"],
            "origin_bundles_by_oid": {fx_m10["_origin_id"]: fx_m10["origin_bundle"]},
            "termination": t_ward_ok,
            "trusted_origin_issuer_pins": fx_m10["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "GUARDIAN_INACTIVE",
        "SL-ORIG-006: Approving guardian with unresolved 0x13 rebind MUST refuse GUARDIAN_INACTIVE.",
    )

    # 8. _authenticate_predecessor_chain: closed predecessor log, cyclic journal log-head, malformed item, non-terminal predecessor
    j_pred_closed = {
        "journal_id": _h32("d13-mk-j-pred-cl"),
        "initial_entries": [{
            "body": {
                "cause": "NOTARY_LOG_COMPROMISED",
                "observed_at": 1795220000,
                "observed_height": 750000,
                "subject": {"log_id": eco_ho["log_id"], "role": "notary", "subject_kind": "log"},
            },
            "kind": "closure",
        }],
    }
    add(
        "d13-mk-handover-closed-predecessor-log-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_b5, "checkpoint": cp2_1_env, "checkpoint_txid": cp2_1_tx, "journal": j_pred_closed, "predecessor_chain": pred_chain_b5},
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-CONT-012 BLK-5: Handover from a compromised predecessor_log_id closed in journal MUST refuse NOTARY_LOG_COMPROMISED.",
    )

    j_pred_cyc = {
        "journal_id": _h32("d13-mk-j-pred-cyc"),
        "initial_entries": [
            {
                "body": {
                    "block_hash": ch_b5["txs"][eco_ho["cp3_tx"]]["block_hash"],
                    "checkpoint_id": ho_term_ca,
                    "checkpoint_object_id": sl.object_id(ho_term_p),
                    "checkpoint_txid": eco_ho["cp3_tx"],
                    "checkpoints_root": ho_term_p["checkpoints_root"],
                    "confirmed_height": 749994,
                    "denials_root": ho_term_p["denials_root"],
                    "issuer_name": eco_ho["iss_name"],
                    "issuer_registration": eco_ho["iss_reg"],
                    "log_id": eco_ho["log_id"],
                    "max_seq": 3,
                    "predecessor_log_id": eco_ho["log_id"],  # self-cycle!
                    "role": "notary",
                    "terminal": True,
                },
                "kind": "log-head",
            },
        ],
    }
    add(
        "d13-mk-handover-predecessor-cycle-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_b5, "checkpoint": cp2_1_env, "checkpoint_txid": cp2_1_tx, "journal": j_pred_cyc},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 BLK-5: Cyclic predecessor_log_id chain MUST refuse CHAIN_FRAME_INVALID.",
    )
    add(
        "d13-mk-handover-malformed-predecessor-item-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_b5, "checkpoint": cp2_1_env, "checkpoint_txid": cp2_1_tx, "predecessor_chain": [{"checkpoint": "bad"}]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 BLK-5: Malformed predecessor_chain entry MUST refuse CHAIN_FRAME_INVALID.",
    )
    add(
        "d13-mk-handover-non-terminal-predecessor-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_b5,
            "checkpoint": cp2_1_env,
            "checkpoint_txid": cp2_1_tx,
            "predecessor_chain": [{"checkpoint": eco_ho["cp2_env"], "checkpoint_txid": eco_ho["cp2_tx"]}],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 BLK-5: Non-terminal predecessor checkpoint in predecessor_chain MUST refuse CHAIN_FRAME_INVALID.",
    )

    # 9. verify_log_checkpoint head with vout 1 absent_from_utxo -> CHAIN_FRAME_INVALID
    ch_abs_v1 = copy.deepcopy(eco_b1["chain_at_cp2"])
    ch_abs_v1["txs"][eco_b1["cp2_tx"]]["outputs"]["1"]["absent_from_utxo"] = True
    add(
        "d13-mk-checkpoint-head-vout1-absent-from-utxo-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_abs_v1, "checkpoint": eco_b1["cp2_env"], "checkpoint_txid": eco_b1["cp2_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 BLK-2: Non-terminal head checkpoint whose continuation vout 1 is absent_from_utxo MUST refuse CHAIN_FRAME_INVALID.",
    )

    # 10. verify_log_fraud illegal_reversion rec_b_inclusion boundary: seq_ib == seq_a (refuse, kills L6131 < and L6132!) & seq_ib == seq_b (admit, kills L6131 <=!)
    # 10a: seq_ib == seq_b (4) on genuinely forged bad_reinst_env -> ADMIT fraud!
    fp_ib_eq_b = {
        **fp_adj_bad,
        "rec_b_inclusion": {
            "batch_proof": b4_bad_proofs[e_bad_re],
            "checkpoint": cp4_bad_env,
            "checkpoint_txid": eco_b1["cp4_tx"],
        },
    }
    add(
        "d13-mk-fraud-rec-b-inclusion-seq-eq-seq-b-admit",
        ["SL-CONT-013"],
        "log_fraud",
        {"chain": ch_adj_bad, "fraud": fp_ib_eq_b, "journal": {"journal_id": _h32("d13-mk-f-ib-b")}},
        "ADMIT",
        None,
        "SL-CONT-013 BLK-1: rec_b_inclusion at exact seq_ib == seq_b admits illegal_reversion fraud.",
    )
    # 10b: seq_ib == seq_a (3) with valid batch_proof in cp3 AND genuinely forged bad_reinst_env -> REFUSE CHAIN_FRAME_INVALID!
    b3_both_root, b3_both_proofs = sl.build_log_batch_root([sl.log_entry_digest(0x02, sl.content_addr(eco_b1["rev1_env"])), e_bad_re])
    cp3_both_p = {**eco_b1["cp3_env"]["payload"], "batch_count": 2, "batch_root": b3_both_root, "cumulative_entries_count": 3, "denials_delta_root": b3_both_root}
    cp3_both_env = sl.sign_envelope(cp3_both_p, [eco_b1["iss_role"]["sk"]])
    cp3_both_ca = sl.content_addr(cp3_both_env)
    leaves_3_both = eco_b1["leaves_2"] + [sl.ckpt_leaf(3, cp3_both_ca)]
    cp4_ib_a_p = {**cp4_bad_p, "checkpoints_root": sl.rfc9162_mth(leaves_3_both).hex(), "cumulative_entries_count": 4, "prev_checkpoint_id": cp3_both_ca}
    cp4_ib_a_env = sl.sign_envelope(cp4_ib_a_p, [eco_b1["iss_role"]["sk"]])
    ch_ib_a = copy.deepcopy(ch_adj_bad)
    ch_ib_a["txs"][eco_b1["cp3_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, cp3_both_ca).hex()
    ch_ib_a["txs"][eco_b1["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_ib_a_env)).hex()
    fp_ib_eq_a = {
        **fp_adj_bad,
        "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_3_both, 2),
        "cp_a": cp3_both_env,
        "cp_b": cp4_ib_a_env,
        "rec_b_inclusion": {
            "batch_proof": b3_both_proofs[e_bad_re],
            "checkpoint": cp3_both_env,
            "checkpoint_txid": eco_b1["cp3_tx"],
            "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_3_both, 2),
        },
    }
    add(
        "d13-mk-fraud-rec-b-inclusion-seq-eq-seq-a-refuse",
        ["SL-CONT-013"],
        "log_fraud",
        {"chain": ch_ib_a, "expect_zero_closures": True, "fraud": fp_ib_eq_a, "journal": {"journal_id": _h32("d13-mk-f-ib-a")}},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013 BLK-1: rec_b_inclusion at seq_ib == seq_a (not strictly > seq_a) MUST refuse CHAIN_FRAME_INVALID even when rec_b is forged.",
    )

    # 11. verify_tier2_name_history_page remaining branches (trusted_checkpoint schema, cursor_owner_policy mismatch, same-height tx_index, non-JCS value, 1-of-2 P2WSH len(wit)==3, next_cursor.owner_policy mismatch)
    add(
        "d13-mk-tier2-bad-trusted-checkpoint-schema-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": t2_p1, "page": _mk_t2_page("id/t2-p2wsh-rot", [pr_rot1]), "pinned_network": "regtest", "trusted_checkpoint": {"height": 1}},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: Invalid TrustedHeaderCheckpoint schema MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d13-mk-tier2-cursor-owner-policy-mismatch-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page(
                "id/t2-p2wsh-rot", [], cursor_height=750010, cursor_owner_policy=t2_p2, cursor_txid=_h32("mk-cur-tx"), cursor_vout=0,
                headers=[{"header_hex": hdr_rot1.hex(), "height": 750010}],
            ),
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: Mismatched cursor_owner_policy vs expected_owner_policy MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    # Same-height non-increasing tx_index: real chained (NAME_FIRSTUPDATE at tx_index=2, NAME_UPDATE spending it at tx_index=1) in ONE block so ONLY tx_index ordering refuses!
    pair_sh_ok, _, pair_sh_reg = bd11._build_same_block_chained_spv_pair("d13-mk-sh-rev", t2_p1, t2_k1["sk"], "id/t2-same-h", "{}", "{}", block_height=750010, high_s_second=False)
    fu_sh_raw = bytes.fromhex(pair_sh_ok[0]["tx_hex"])
    u1_sh_raw = bytes.fromhex(pair_sh_ok[1]["tx_hex"])
    fu_sh_p = sl.parse_raw_tx(fu_sh_raw)
    u1_sh_p = sl.parse_raw_tx(u1_sh_raw)
    wroot_rev_le, w_rev_br = bd11._btc_merkle_root_and_branches([b"\x00" * 32, u1_sh_p["wtxid_le"], fu_sh_p["wtxid_le"]])
    wit_res_rev = b"\x00" * 32
    cb_rev_raw = bd11._encode_raw_tx(
        2,
        [{"prev_txid": "00" * 32, "prev_vout": 0xFFFFFFFF, "script_sig": b"\x03" + struct.pack("<I", 750010)[:3] + b"slrev"}],
        [(5_000_000_000, b"\x00\x14" + (b"\x55" * 20)), (0, b"\x6a\x24\xaa\x21\xa9\xed" + sl.dsha256(wroot_rev_le + wit_res_rev))],
        witnesses=[[wit_res_rev]],
    )
    cb_rev_p = sl.parse_raw_tx(cb_rev_raw)
    mroot_rev_le, t_rev_br = bd11._btc_merkle_root_and_branches([cb_rev_p["txid_le"], u1_sh_p["txid_le"], fu_sh_p["txid_le"]])
    hdr_rev = _mine_regtest_hdr((0x0001 << 16) | 4, b"\x00" * 32, mroot_rev_le, 1795220000)
    bhash_rev = sl.dsha256(hdr_rev)[::-1].hex()
    pr_sh1 = {
        "block_hash": bhash_rev, "block_header_hex": hdr_rev.hex(), "block_height": 750010,
        "coinbase_merkle_branch": t_rev_br[0], "coinbase_tx_hex": cb_rev_raw.hex(),
        "prevout_tx_hex": pair_sh_ok[0]["prevout_tx_hex"], "tx_hex": fu_sh_raw.hex(), "tx_index": 2,
        "txid_branch": t_rev_br[2], "wtxid_branch": w_rev_br[2], "wtxid_coinbase_branch": w_rev_br[0],
    }
    pr_sh2 = {
        "block_hash": bhash_rev, "block_header_hex": hdr_rev.hex(), "block_height": 750010,
        "coinbase_merkle_branch": t_rev_br[0], "coinbase_tx_hex": cb_rev_raw.hex(),
        "prevout_tx_hex": fu_sh_raw.hex(), "tx_hex": u1_sh_raw.hex(), "tx_index": 1,
        "txid_branch": t_rev_br[1], "wtxid_branch": w_rev_br[1], "wtxid_coinbase_branch": w_rev_br[0],
    }
    add(
        "d13-mk-tier2-same-height-non-increasing-tx-index-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": t2_p1, "page": _mk_t2_page("id/t2-same-h", [pr_sh1, pr_sh2], registration=pair_sh_reg, headers=[{"header_hex": hdr_rev.hex(), "height": 750010}]), "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: Same-height Tier-2 updates with non-increasing tx_index (tx_index=2 followed by tx_index=1) MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    # Non-JCS value "{ }" in Tier-2 update -> TICKET_PROOF_INVALID
    pr_nonjcs, _ = bd11._build_synthetic_spv_proof("d13-mk-nonjcs", t2_p1, [t2_k1["sk"]], "id/t2-nonjcs", "{ }", block_height=750010)
    add(
        "d13-mk-tier2-non-jcs-value-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": t2_p1, "page": _mk_t2_page("id/t2-nonjcs", [pr_nonjcs]), "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: Tier-2 name update carrying non-JCS JSON value MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    # P2WPKH -> 1-of-2 P2WSH (exact len(wit_n) == 3: ["", sig1, witnessScript]) -> ADMIT (kills L6946 >= 3 vs > 3!)
    t2_p_1of2 = {"kind": "multisig", "m": 1, "pks": sorted([t2_k2["comp"], t2_k3["comp"]])}
    pr_1of2_a, hdr_1of2_a = bd11._build_synthetic_spv_proof(
        "d13-mk-1of2-a", t2_p1, [t2_k1["sk"]], "id/t2-1of2", "{}",
        block_height=750010, new_owner_pol=t2_p_1of2, block_time=1795220000,
    )
    pr_1of2_b, hdr_1of2_b = bd11._build_synthetic_spv_proof(
        "d13-mk-1of2-b", t2_p_1of2, [t2_k2["sk"]], "id/t2-1of2", sl.jcs_encode({"link": {"notary": t2_k2["xonly"]}}).decode(),
        block_height=750011, prev_raw_override=bytes.fromhex(pr_1of2_a["tx_hex"]), prev_vout=0,
        prev_block_hash_le=sl.dsha256(hdr_1of2_a), block_time=1795220600,
    )
    add(
        "d13-mk-tier2-p2wsh-1of2-rotation-len-wit-3-admit",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page(
                "id/t2-1of2", [pr_1of2_a, pr_1of2_b],
                headers=[{"header_hex": hdr_1of2_a.hex(), "height": 750010}, {"header_hex": hdr_1of2_b.hex(), "height": 750011}],
            ),
            "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "SL-ARTF-006: P2WPKH -> 1-of-2 P2WSH cold rotation (len(witness) == 3) evolves owner_policy and admits.",
        module="artifact-notarization",
    )
    # next_cursor.owner_policy mismatching verified_updates[-1].new_trailing_script_pubkey -> TICKET_PROOF_INVALID
    add(
        "d13-mk-tier2-next-cursor-owner-policy-mismatch-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_p1,
            "page": _mk_t2_page(
                "id/t2-p2wsh-rot", [pr_rot1],
                registration=pr_rot_reg,
                headers=[{"header_hex": hdr_rot1.hex(), "height": 750010}],
                has_more=True,
                next_cursor={"height": 750010, "owner_policy": t2_p1, "txid": pr_rot1_txid, "vout": 0},
            ),
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: next_cursor.owner_policy mismatching verified_updates[-1].new_trailing_script_pubkey MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # 12. verify_termination ward paths: non-party ward_origin_id, autonomous origin, bad spend_txid 0x08
    t_ward_nonparty = sl.sign_guardian_envelope(
        {**t_ward_base_p, "guardian_context": {**t_ward_base_p["guardian_context"], "origin_id": _h32("d13-mk-nonparty-oid")}},
        [{"guardian_name": "id/parent-a", "revision": 2, "signers": [fx_m10["_keys"]["g1_gr"]["sk"]], "slot": 2}],
    )
    add(
        "d13-mk-termination-ward-nonparty-origin-refuse",
        ["SL-CONT-007"],
        "termination",
        {"chain": ch_m10, "contract": c_m10_obj, "origin_bundle": fx_m10["origin_bundle"], "termination": t_ward_nonparty, "trusted_origin_issuer_pins": fx_m10["trusted_origin_issuer_pins"]},
        "REFUSE",
        "WIRE_SIGNATURE",
        "SL-CONT-007: Ward termination referencing an origin_id absent from contract parties MUST refuse WIRE_SIGNATURE.",
    )
    c_auto_term = copy.deepcopy(c_m10_obj)
    c_auto_term["parties"][0]["ward_origin_id"] = fx_h1a["_oid"]
    c_auto_term_id = sl.object_id(c_auto_term)
    t_auto_ward = sl.sign_guardian_envelope(
        {**t_ward_base_p, "contract_id": c_auto_term_id, "guardian_context": {"event_class": "contract_assent", "origin_id": fx_h1a["_oid"], "revision": 1, "ward_name": b1_h1a_name}},
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [fx_m10["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add(
        "d13-mk-termination-guardian-approvals-for-autonomous-origin-refuse",
        ["SL-CONT-007"],
        "termination",
        {"chain": ch_h1a, "contract": c_auto_term, "origin_bundle": fx_h1a["origin_bundle"], "termination": t_auto_ward, "trusted_origin_issuer_pins": fx_h1a["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_QUORUM_UNMET",
        "SL-CONT-007: guardian_approvals termination for an autonomous (non-ward) origin MUST refuse GUARDIAN_QUORUM_UNMET.",
    )
    add(
        "d13-mk-termination-ward-bad-spend-txid-refuse",
        ["SL-CONT-007"],
        "termination",
        {
            "chain": ch_m10,
            "contract": c_m10_obj,
            "origin_bundle": fx_m10["origin_bundle"],
            "spend_txid": _h32("d13-mk-missing-0x08-spend"),
            "termination": t_ward_ok,
            "trusted_origin_issuer_pins": fx_m10["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-007: Ward termination with missing/mismatched 0x08 spend_txid MUST refuse CHAIN_FRAME_INVALID.",
    )

    # 13. verify_statement device-signed: device_proof head mismatch vs owner_manifest (MANIFEST_MISMATCH) & key absent from entry (DEVICE_UNAUTHORIZED)
    dp_h6_wrong = copy.deepcopy(dp_h6[0])
    dp_h6_wrong["head"]["seq"] = 2
    add(
        "d13-mk-statement-device-list-manifest-mismatch-refuse",
        ["SL-IDEN-008"],
        "statement",
        {"chain": ch_h6_man, "device_proof": dp_h6_wrong, "owner_manifest": man_h6_real, "statement": st_h6},
        "REFUSE",
        "MANIFEST_MISMATCH",
        "SL-IDEN-008: Device-signed statement with device_proof head mismatching owner_manifest.sets.devices MUST refuse MANIFEST_MISMATCH.",
    )
    ed_other_h6 = sl.deterministic_ed25519_seed("d13-mk-unlisted-ed")
    st_h6_unlisted = sl.sign_envelope(st_h6["payload"], [ed_other_h6], alg="ed25519")
    add(
        "d13-mk-statement-device-key-unlisted-refuse",
        ["SL-IDEN-008"],
        "statement",
        {"chain": ch_h6_man, "device_proof": dp_h6[0], "owner_manifest": man_h6_real, "statement": st_h6_unlisted},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "SL-IDEN-008: Device-signed statement signed by a key absent from disclosed DeviceEntry MUST refuse DEVICE_UNAUTHORIZED.",
    )

    # 14. verify_session_open agent/session with contract lacking config_sha256 -> CONTRACT_CONFIG_MISMATCH
    fx_so_nocfg = copy.deepcopy(fx_h3c)
    c_nocfg_obj = copy.deepcopy(c_h3c_obj)
    c_nocfg_obj.pop("config_sha256", None)
    c_nocfg_obj["profile"] = "org.seallink/agent-v1"
    c_nocfg_id = sl.object_id(c_nocfg_obj)
    gp_nocfg = copy.deepcopy(fx_so_nocfg["bundle"]["grants"][0]["payload"])
    gp_nocfg["contract_id"] = c_nocfg_id
    gp_nocfg["capabilities"] = [{"action": "agent/session", "target": "station:id/mail-host-a:slot1"}]
    rm._reanchor_grant(fx_so_nocfg, gp_nocfg)
    fx_so_nocfg["bundle"]["contract"] = c_nocfg_obj
    fx_so_nocfg["bundle"]["contract_assents"] = [
        sl.sign_envelope(
            {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d13-mk-nc-a1"), "party_id": "p-alice", "party_name": "id/alice", "party_role": "principal", "target_id": c_nocfg_id, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
            [fx_so_nocfg["_keys"]["alice_gr"]["sk"]],
        ),
        sl.sign_envelope(
            {"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": _h32("d13-mk-nc-a2"), "party_id": "p-agent", "party_role": "agent", "target_id": c_nocfg_id, "target_type": "seallink-contract/1", "type": "seallink-assent/1"},
            [fx_so_nocfg["_keys"]["agent_req"]["sk"]],
        ),
    ]
    so_nocfg = sl.sign_envelope(
        {**so_h3c_p, "nonce": _h32("d13-mk-nc-so"), "proof_path": fx_so_nocfg["invocation"]["payload"]["proof_path"]},
        [fx_so_nocfg["_keys"]["agent_req"]["sk"]],
    )
    add(
        "d13-mk-session-open-agent-session-missing-config-sha256-refuse",
        ["SL-GRNT-015"],
        "session_lifecycle",
        {
            "executor_cfg": {**fx_so_nocfg["executor_cfg"], "actions": ["agent/session"]},
            "steps": [{
                "bundle": fx_so_nocfg["bundle"],
                "chain": fx_so_nocfg["chain"],
                "kind": "session_open",
                "label": "open-agent-session-no-cfg",
                "session_open": so_nocfg,
                "want_refusal": "CONTRACT_CONFIG_MISMATCH",
                "want_verdict": "REFUSE",
            }],
        },
        "ADMIT",
        None,
        "SL-GRNT-015 H-3: verify_session_open for agent/session backed by a contract without config_sha256 MUST refuse CONTRACT_CONFIG_MISMATCH.",
        module="bearer-sessions",
    )

    # 15. verify_bearer_session: executor_cfg mismatch (GRANT_EXECUTOR_MISMATCH) & missing required_quotas (QUOTA_EXCEEDED)
    tok_mk_bs = _h32("d13-mk-bs-tok")
    tok_mk_bs_h = sl.sha256(tok_mk_bs.encode("utf-8")).hex()
    g_h3_env = fx_h3["bundle"]["grants"][0]
    g_h3_id = sl.object_id(g_h3_env["payload"])
    j_mk_bs = {
        "journal_id": _h32("d13-mk-bs-j"),
        "sessions": {
            tok_mk_bs_h: {
                "closed": False,
                "exp": fx_h3["chain"]["now"] + 600,
                "grant_id": g_h3_id,
                "proof_path": fx_h3["invocation"]["payload"]["proof_path"],
                "quotas": [],
                "root_recent_height": fx_h3["chain"]["blocks"][g_h3_env["payload"]["recent_block"]],
                "session_id": _h32("d13-mk-bs-sid"),
                "slot_binding": "slot-mk-bs",
                "token_sha256": tok_mk_bs_h,
            },
        },
    }
    add(
        "d13-mk-bearer-session-executor-mismatch-refuse",
        ["SL-GRNT-015"],
        "bearer_session",
        {
            "action": "mail/send",
            "arguments": {"body_sha256": _h32("bs-b"), "size_bytes": "100", "subject": "hi", "to": "bob@example.org"},
            "chain": fx_h3["chain"],
            "executor_cfg": {**fx_h3["executor_cfg"], "name": "id/wrong-executor"},
            "grant_env": g_h3_env,
            "journal": j_mk_bs,
            "slot_binding": "slot-mk-bs",
            "target": "mailbox:id/alice:work",
            "token": tok_mk_bs,
        },
        "REFUSE",
        "GRANT_EXECUTOR_MISMATCH",
        "SL-GRNT-015 H-3: verify_bearer_session with executor_cfg mismatching grant.executor MUST refuse GRANT_EXECUTOR_MISMATCH.",
        module="bearer-sessions",
    )
    add(
        "d13-mk-bearer-session-missing-required-quota-refuse",
        ["SL-GRNT-015"],
        "bearer_session",
        {
            "action": "mail/send",
            "arguments": {"body_sha256": _h32("bs-b2"), "size_bytes": "100", "subject": "hi", "to": "bob@example.org"},
            "chain": fx_h3["chain"],
            "executor_cfg": fx_h3["executor_cfg"],
            "grant_env": g_h3_env,
            "journal": j_mk_bs,
            "slot_binding": "slot-mk-bs",
            "target": "mailbox:id/alice:work",
            "token": tok_mk_bs,
        },
        "REFUSE",
        "QUOTA_EXCEEDED",
        "SL-GRNT-015 H-3: verify_bearer_session for mail/send without mandatory messages_per_day quota MUST refuse QUOTA_EXCEEDED.",
        module="bearer-sessions",
    )

    # 16. verify_federation_disclosure with 0x0b compromised grant issuer -> CRED_ISSUER_CLOSED (kills L9896!)
    add(
        "d13-mk-federation-grant-issuer-0x0b-compromised-refuse",
        ["SL-CONT-009", "SL-SERV-004"],
        "federation",
        {
            "chain": fx_m8["chain"],
            "grant": fx_m8["bundle"]["grants"][0],
            "journal": {"journal_id": _h32("d13-mk-fed-j")},
            "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"},
            "policy": {"require_contour_a": False, "trusted_peers": ["id/peer-b"]},
        },
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "SL-CONT-009 M-8: verify_federation_disclosure MUST check on-chain 0x0b compromise on presented role policy before role-rotation check and refuse CRED_ISSUER_CLOSED.",
    )

    _add_draft13_commit2_symmetry_cases(add, fx_h2)


def _add_draft13_commit2_symmetry_cases(add: Callable[..., None], fx_ward_rev2: dict[str, Any]) -> None:
    """Commit 2 pre-rc1 core symmetry & extensibility conformance + mutant-killing cases."""
    # ========================================================================
    # C2-1: Symmetric salted-Merkle sets.auth + sets.devices (selective disclosure,
    #       multi-alg bip340/p256/ed25519, audience binding, cross-set isolation, SL-IDEN-003)
    # ========================================================================
    fx_c2 = rm._base_invocation_fixture()
    now_c2 = fx_c2["chain"]["now"]
    a_bip = _kp("c2-auth-bip340")
    a_p256_sk = sl.deterministic_p256_privkey("c2-auth-p256")
    a_p256_pk = sl.p256_compressed_pubkey(a_p256_sk)
    a_ed_seed = sl.deterministic_ed25519_seed("c2-auth-ed25519")
    a_ed_pk = sl.ed25519_pubkey(a_ed_seed)
    a_decoy = _kp("c2-auth-decoy")

    aseal_pol = {"kind": "key", "pk": _kp("c2-auth-seal")["comp"]}
    aseal_tx = _h32("c2-auth-seal-tx")
    aseal_sp_tx = _h32("c2-auth-seal-spent-tx")
    fx_c2["chain"]["txs"][aseal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(aseal_pol)}}}
    fx_c2["chain"]["txs"][aseal_sp_tx] = {
        "confirmed_height": 749900,
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(aseal_pol), "spent_by_txid": _h32("c2-auth-revoke")}},
    }
    fx_c2["chain"]["txs"][_h32("c2-auth-revoke")] = {"confirmed_height": 750002, "inputs": [sv.make_segwit_input(aseal_sp_tx, 0)], "outputs": {}}

    auth_head_4, auth_proofs_4 = rm.make_salted_auth_set(
        "id/alice",
        [
            {"alg": "bip340", "key": a_bip["xonly"], "label": "workstation-bip340", "seal": {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}},
            {"alg": "p256", "key": a_p256_pk, "label": "phone-enclave-p256", "seal": {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}},
            {"alg": "ed25519", "key": a_ed_pk, "label": "yubikey-ed25519", "seal": {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}},
            {"alg": "bip340", "key": a_decoy["xonly"], "label": "revoked-auth", "seal": {"script_policy": aseal_pol, "txid": aseal_sp_tx, "vout": 0}},
        ],
    )
    d_bip = _kp("c2-dev-bip340")
    d_p256_sk = sl.deterministic_p256_privkey("c2-dev-p256")
    d_p256_pk = sl.p256_compressed_pubkey(d_p256_sk)
    d_ed_seed = sl.deterministic_ed25519_seed("c2-dev-ed25519")
    d_ed_pk = sl.ed25519_pubkey(d_ed_seed)
    dev_head_3, dev_proofs_3 = rm.make_salted_device_set(
        "id/alice",
        [
            {"alg": "bip340", "ceiling": 2, "key": d_bip["xonly"], "label": "dev-bip", "presence": True, "seal": {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}},
            {"alg": "p256", "ceiling": 2, "key": d_p256_pk, "label": "dev-p256", "presence": True, "seal": {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}},
            {"alg": "ed25519", "ceiling": 2, "key": d_ed_pk, "label": "dev-ed", "presence": True, "seal": {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}},
        ],
    )
    man_c2 = rm.bind_sets_manifest(
        fx_c2["chain"],
        "id/alice",
        fx_c2["_alice_owner_pol"],
        fx_c2["_alice_reg"],
        auth_head=auth_head_4,
        device_head=dev_head_3,
        extra_link={"grant": fx_c2["_keys"]["alice_gr"]["xonly"]},
    )
    man_c2_h = sl.content_addr(man_c2)

    def _ac_j(nonce_hex: str, *, aud: str | None = None) -> dict[str, Any]:
        rec: dict[str, Any] = {"expires_at": now_c2 + 60, "issued_at": now_c2, "service_id": "sso.example.org", "used": False}
        if aud is not None:
            rec["audience"] = aud
        return {"auth_nonces": {nonce_hex: rec}, "journal_id": _h32(f"c2-j-{nonce_hex[:12]}")}

    # 1a. Named salted sets.auth ADMIT for bip340 (with audience), p256, and ed25519!
    ac_bip_n = _h32("c2-ac-bip")
    ac_bip_p = {
        "audience": "https://app.example.org/oidc", "auth_alg": "bip340", "auth_pubkey": a_bip["xonly"],
        "expires_at": now_c2 + 60, "genesis": GENESIS_MAIN, "issued_at": now_c2, "name": "id/alice",
        "network": "main", "nonce": ac_bip_n, "service_id": "sso.example.org", "type": "seallink-auth-challenge/1",
    }
    ac_bip_env = sl.sign_envelope(ac_bip_p, [a_bip["sk"]])
    add(
        "d13-c2-auth-salted-bip340-audience-admit",
        ["SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": auth_proofs_4[0], "chain": fx_c2["chain"], "challenge": ac_bip_env, "expected_audience": "https://app.example.org/oidc", "journal": _ac_j(ac_bip_n, aud="https://app.example.org/oidc"), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "ADMIT",
        None,
        "Commit 2: Selective-disclosure 1-of-4 salted sets.auth BIP-340 challenge with matching audience admits.",
    )
    ac_p256_n = _h32("c2-ac-p256")
    ac_p256_env = sl.sign_envelope({**ac_bip_p, "auth_alg": "p256", "auth_pubkey": a_p256_pk, "nonce": ac_p256_n}, [a_p256_sk], alg="p256")
    add(
        "d13-c2-auth-salted-p256-admit",
        ["SL-IDEN-010", "SL-WIRE-013"],
        "auth_challenge",
        {"auth_proof": auth_proofs_4[1], "chain": fx_c2["chain"], "challenge": ac_p256_env, "journal": _ac_j(ac_p256_n, aud="https://app.example.org/oidc"), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "ADMIT",
        None,
        "Commit 2: Selective-disclosure 1-of-4 salted sets.auth P-256 Secure Enclave challenge with journal-recorded audience admits.",
    )
    ac_ed_n = _h32("c2-ac-ed25519")
    ac_ed_env = sl.sign_envelope({**ac_bip_p, "auth_alg": "ed25519", "auth_pubkey": a_ed_pk, "nonce": ac_ed_n}, [a_ed_seed], alg="ed25519")
    add(
        "d13-c2-auth-salted-ed25519-admit",
        ["SL-IDEN-010", "SL-WIRE-013"],
        "auth_challenge",
        {"auth_proof": auth_proofs_4[2], "chain": fx_c2["chain"], "challenge": ac_ed_env, "journal": _ac_j(ac_ed_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "ADMIT",
        None,
        "Commit 2: Selective-disclosure 1-of-4 salted sets.auth Ed25519 challenge admits.",
    )

    # 1b. AuthChallenge & AuthUpgrade negative checks (chain mismatch, audience mismatch, cross-set replay, tampered proof, spent seal, malformed proof container)
    add(
        "d13-c2-auth-challenge-chain-mismatch-refuse",
        ["SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": auth_proofs_4[0], "chain": fx_c2["chain"], "challenge": sl.sign_envelope({**ac_bip_p, "genesis": _h32("bad-ac-g")}, [a_bip["sk"]]), "journal": _ac_j(ac_bip_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "CHAIN_MISMATCH",
        "Commit 2: AuthChallenge with mismatched genesis MUST refuse CHAIN_MISMATCH.",
    )
    add(
        "d13-c2-auth-challenge-audience-mismatch-refuse",
        ["SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": auth_proofs_4[0], "chain": fx_c2["chain"], "challenge": ac_bip_env, "expected_audience": "https://other.example.org/oidc", "journal": _ac_j(ac_bip_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "AUTH_CHALLENGE_INVALID",
        "Commit 2: AuthChallenge with mismatched expected_audience MUST refuse AUTH_CHALLENGE_INVALID.",
    )
    add(
        "d13-c2-auth-challenge-missing-proof-refuse",
        ["SL-IDEN-010"],
        "auth_challenge",
        {"chain": fx_c2["chain"], "challenge": ac_bip_env, "journal": _ac_j(ac_bip_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "AUTH_KEY_UNPINNED",
        "Commit 2: Named AuthChallenge omitting auth_proof MUST refuse AUTH_KEY_UNPINNED.",
    )
    add(
        "d13-c2-auth-proof-extra-key-refuse",
        ["SL-IDEN-010", "SL-WIRE-010"],
        "auth_challenge",
        {"auth_proof": {**auth_proofs_4[0], "extra": 1}, "chain": fx_c2["chain"], "challenge": ac_bip_env, "journal": _ac_j(ac_bip_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "WIRE_MEMBER",
        "Commit 2: AuthEntryProof with unknown top-level member MUST refuse WIRE_MEMBER.",
    )
    add(
        "d13-c2-auth-proof-wrong-head-type-refuse",
        ["SL-IDEN-010", "SL-WIRE-010"],
        "auth_challenge",
        {"auth_proof": {**auth_proofs_4[0], "head": dev_head_3}, "chain": fx_c2["chain"], "challenge": ac_bip_env, "journal": _ac_j(ac_bip_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "WIRE_TYPE",
        "Commit 2: Cross-set replay presenting seallink-device-set-head/1 as auth_proof.head MUST refuse WIRE_TYPE.",
    )
    add(
        "d13-c2-auth-proof-cross-set-device-entry-refuse",
        ["SL-IDEN-010", "SL-WIRE-010"],
        "auth_challenge",
        {"auth_proof": {**auth_proofs_4[0], "entry": dev_proofs_3[0]["entry"]}, "chain": fx_c2["chain"], "challenge": ac_bip_env, "journal": _ac_j(ac_bip_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "WIRE_TYPE",
        "Commit 2: Cross-set replay presenting seallink-device-entry/1 as auth_proof.entry MUST refuse WIRE_TYPE.",
    )
    bad_merkle_schema_pf = {**copy.deepcopy(auth_proofs_4[0]), "proof": {**auth_proofs_4[0]["proof"], "steps": [{"hash": _h32(f"s{i}"), "side": "L"} for i in range(9)]}}
    add(
        "d13-c2-auth-proof-steps-over-8-refuse",
        ["SL-IDEN-010", "SL-WIRE-010"],
        "auth_challenge",
        {"auth_proof": bad_merkle_schema_pf, "chain": fx_c2["chain"], "challenge": ac_bip_env, "journal": _ac_j(ac_bip_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "WIRE_MEMBER",
        "Commit 2: SetEntryMerkleProof exceeding maxItems=8 steps MUST refuse WIRE_MEMBER.",
    )
    tampered_sib_pf = copy.deepcopy(auth_proofs_4[0])
    tampered_sib_pf["proof"]["steps"][0]["hash"] = _h32("tampered-auth-sib")
    add(
        "d13-c2-auth-proof-tampered-sibling-refuse",
        ["SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": tampered_sib_pf, "chain": fx_c2["chain"], "challenge": ac_bip_env, "journal": _ac_j(ac_bip_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "AUTH_KEY_UNPINNED",
        "Commit 2: AuthEntryProof with tampered Merkle sibling hash MUST refuse AUTH_KEY_UNPINNED.",
    )
    ac_rev_n = _h32("c2-ac-rev")
    ac_rev_env = sl.sign_envelope({**ac_bip_p, "auth_pubkey": a_decoy["xonly"], "nonce": ac_rev_n}, [a_decoy["sk"]])
    add(
        "d13-c2-auth-proof-spent-seal-refuse",
        ["SL-IDEN-010", "SL-LDGR-011"],
        "auth_challenge",
        {"auth_proof": auth_proofs_4[3], "chain": fx_c2["chain"], "challenge": ac_rev_env, "journal": _ac_j(ac_rev_n), "manifests": {man_c2_h: man_c2}, "service_id": "sso.example.org"},
        "REFUSE",
        "SEAL_SPENT",
        "Commit 2: AuthEntry whose individual revocation seal is spent on-chain MUST refuse SEAL_SPENT.",
    )
    # Invalid curve point in AuthChallenge (p256) & AuthEntry (ed25519 small-order)
    ac_bad_p256_pk = next(f"02{i:064x}" for i in range(1, 200) if not sl.is_valid_p256_compressed_pubkey(f"02{i:064x}"))
    ac_bad_p256 = {
        "payload": {**ac_bip_p, "auth_alg": "p256", "auth_pubkey": ac_bad_p256_pk},
        "signatures": copy.deepcopy(ac_p256_env["signatures"]),
    }
    add(
        "d13-c2-auth-challenge-invalid-p256-curve-point-refuse",
        ["SL-WIRE-012"],
        "raw_wire",
        {"object": ac_bad_p256},
        "REFUSE",
        "WIRE_KEY",
        "Commit 2: AuthChallenge with off-curve P-256 auth_pubkey MUST refuse WIRE_KEY.",
    )
    add(
        "d13-c2-auth-entry-small-order-ed25519-refuse",
        ["SL-WIRE-012"],
        "raw_wire",
        {"object": {**auth_proofs_4[2]["entry"], "key": "01" + ("00" * 31)}},
        "REFUSE",
        "WIRE_KEY",
        "Commit 2: AuthEntry with small-order Ed25519 pubkey MUST refuse WIRE_KEY.",
    )
    # AuthUpgrade with P-256 + audience ADMIT, wrong genesis -> CHAIN_MISMATCH, wrong audience -> AUTH_CHALLENGE_INVALID, wrong alg -> AUTH_KEY_UNPINNED
    au_p256_p = {
        "account_id": "prov-p256-1", "audience": "https://app.example.org/oidc", "auth_alg": "p256", "auth_pubkey": a_p256_pk,
        "expires_at": now_c2 + 60, "firstupdate_txid": fx_c2["_alice_reg"]["txid"], "genesis": GENESIS_MAIN,
        "issued_at": now_c2, "name": "id/alice", "network": "main", "nonce": _h32("c2-au-p256"),
        "service_id": "sso.example.org", "type": "seallink-auth-upgrade/1",
    }
    au_p256_env = sl.sign_envelope(au_p256_p, [a_p256_sk], alg="p256")
    add(
        "d13-c2-auth-upgrade-p256-audience-admit",
        ["SL-IDEN-010", "SL-WIRE-013"],
        "auth_upgrade",
        {"auth_proof": auth_proofs_4[1], "chain": fx_c2["chain"], "expected_audience": "https://app.example.org/oidc", "expected_provisional_auth_alg": "p256", "expected_provisional_auth_pubkey": a_p256_pk, "expected_service_id": "sso.example.org", "manifests": {man_c2_h: man_c2}, "upgrade": au_p256_env},
        "ADMIT",
        None,
        "Commit 2: seallink-auth-upgrade/1 using P-256 Secure Enclave key + audience + salted sets.auth proof admits.",
    )
    add(
        "d13-c2-auth-upgrade-chain-mismatch-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"auth_proof": auth_proofs_4[1], "chain": fx_c2["chain"], "expected_provisional_auth_alg": "p256", "expected_provisional_auth_pubkey": a_p256_pk, "expected_service_id": "sso.example.org", "manifests": {man_c2_h: man_c2}, "upgrade": sl.sign_envelope({**au_p256_p, "genesis": _h32("bad-aug")}, [a_p256_sk], alg="p256")},
        "REFUSE",
        "CHAIN_MISMATCH",
        "Commit 2: seallink-auth-upgrade/1 with mismatched genesis MUST refuse CHAIN_MISMATCH.",
    )
    add(
        "d13-c2-auth-upgrade-audience-mismatch-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {"auth_proof": auth_proofs_4[1], "chain": fx_c2["chain"], "expected_audience": "https://wrong.example.org", "expected_provisional_auth_alg": "p256", "expected_provisional_auth_pubkey": a_p256_pk, "expected_service_id": "sso.example.org", "manifests": {man_c2_h: man_c2}, "upgrade": au_p256_env},
        "REFUSE",
        "AUTH_CHALLENGE_INVALID",
        "Commit 2: seallink-auth-upgrade/1 with mismatched audience MUST refuse AUTH_CHALLENGE_INVALID.",
    )
    # DeviceEntryProof cross-set replay (auth-entry in device_proof), device BIP-340 key colliding with link.grant, and multisig device statement
    oc_c2_bip = sl.sign_envelope(
        {"arguments": {"scope": "all"}, "command": "keyholder-halt", "exp": now_c2 + 300, "genesis": GENESIS_MAIN, "iat": now_c2, "level": 2, "network": "main", "nonce": _h32("c2-oc-1"), "owner": "id/alice", "target_executor": "id/station-a", "type": "seallink-owner-command/1"},
        [d_bip["sk"]],
    )
    add(
        "d13-c2-device-proof-cross-set-auth-entry-refuse",
        ["SL-IDEN-011", "SL-WIRE-010"],
        "owner_command",
        {"chain": fx_c2["chain"], "command": oc_c2_bip, "device_proof": {**dev_proofs_3[0], "entry": auth_proofs_4[0]["entry"]}, "is_foreign_service": False, "owner_manifest": man_c2},
        "REFUSE",
        "WIRE_TYPE",
        "Commit 2: Cross-set replay presenting seallink-auth-entry/1 as device_proof.entry MUST refuse WIRE_TYPE.",
    )
    st_cfg_c2 = {
        "body_sha256": _h32("c2-cfg"), "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_c2["_alice_owner_pol"], "registration": fx_c2["_alice_reg"]},
        "network": "main", "not_after": now_c2 + 600, "not_before": now_c2, "seq": 1,
        "statement_kind": "config-section", "subject": {"host_id": "id/station-a", "section": "net"},
        "type": "seallink-statement/1",
    }
    add(
        "d13-c2-statement-device-multisig-refuse",
        ["SL-IDEN-011"],
        "statement",
        {"chain": fx_c2["chain"], "device_proof": dev_proofs_3[0], "owner_manifest": man_c2, "statement": sl.sign_envelope(st_cfg_c2, [d_bip["sk"], a_bip["sk"]], m=2)},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "Commit 2: Device-signed config-section statement with 2-of-2 policy MUST refuse DEVICE_UNAUTHORIZED.",
    )
    # Device head with wrong owner/network pinned by manifest (kills head owner/network checks in _verify_salted_set_entry_proof!)
    dh_bad_owner, dp_bad_owner = rm.make_salted_device_set(
        "id/bob",
        [{"alg": "bip340", "ceiling": 2, "key": d_bip["xonly"], "label": "d", "owner": "id/alice", "presence": True, "seal": {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}}],
    )
    ch_bad_dh = copy.deepcopy(fx_c2["chain"])
    man_bad_dh = rm.bind_sets_manifest(ch_bad_dh, "id/alice", fx_c2["_alice_owner_pol"], fx_c2["_alice_reg"], device_head=dh_bad_owner, extra_link={"grant": fx_c2["_keys"]["alice_gr"]["xonly"]})
    add(
        "d13-c2-device-head-owner-mismatch-refuse",
        ["SL-IDEN-011"],
        "owner_command",
        {"chain": ch_bad_dh, "command": oc_c2_bip, "device_proof": dp_bad_owner[0], "is_foreign_service": False, "owner_manifest": man_bad_dh},
        "REFUSE",
        "MANIFEST_MISMATCH",
        "Commit 2: DeviceSetHead whose owner disagrees with command.owner (even if pinned in manifest) MUST refuse MANIFEST_MISMATCH.",
    )

    # ========================================================================
    # C2-2: MembersList roles[], Card avatar/avatars/links[], Manifest service_type='sso' & MirrorEndpoint userinfo ban
    # ========================================================================
    peer_k = _kp("c2-peer-own")
    peer_pol = {"kind": "key", "pk": peer_k["comp"]}
    peer_pin = {"name": "id/org-acme", "owner_policy": peer_pol, "registration": {"txid": _h32("c2-acme-reg"), "vout": 0}}
    ml_ok = {
        "entries": [{
            "name": "id/alice", "owner_policy": fx_c2["_alice_owner_pol"], "registration": fx_c2["_alice_reg"],
            "roles": ["director", "signer.finance"],
            "seal": {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0},
        }],
        "network": "main", "owner": "id/org-acme", "seq": 1, "type": "seallink-members-list/1",
    }
    add("d13-c2-members-list-roles-admit", ["SL-IDEN-006"], "raw_wire", {"object": ml_ok}, "ADMIT", None, "Commit 2: seallink-members-list/1 with valid RoleTag array roles[] admits.")
    ml_bad_role = copy.deepcopy(ml_ok)
    ml_bad_role["entries"][0]["roles"] = ["UPPERCASE"]
    add("d13-c2-members-list-invalid-role-tag-refuse", ["SL-WIRE-010"], "raw_wire", {"object": ml_bad_role}, "REFUSE", "WIRE_MEMBER", "Commit 2: seallink-members-list/1 with uppercase RoleTag MUST refuse WIRE_MEMBER.")

    card_ok = {
        "avatar": {"bytes": 16384, "locators": ["https://cdn.example.org/alice.webp", "blossom://cdn.example.org/" + _h32("av1"), "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"], "mime": "image/webp", "sha256": _h32("av1")},
        "avatars": {"work": {"bytes": 8192, "locators": ["https://cdn.example.org/work.png"], "mime": "image/png", "sha256": _h32("av2")}},
        "contact": "alice@example.org", "display": "Alice Example", "kind": "person",
        "links": [{"label": "Website", "url": "https://alice.example.org"}, {"label": "Nostr", "url": "nostr:npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5z0q4k"}],
        "name": "id/alice", "network": "main", "relays": ["wss://relay.example.org"], "replaces": 0, "role": "engineer", "seq": 1, "transports": [], "type": "seallink-card/1",
    }
    add("d13-c2-card-avatar-and-links-admit", ["SL-IDEN-006"], "raw_wire", {"object": card_ok}, "ADMIT", None, "Commit 2: seallink-card/1 with raster avatar, avatars map, and allowlisted LocatorUri links[] admits.")
    card_svg = copy.deepcopy(card_ok)
    card_svg["avatar"]["mime"] = "image/svg+xml"
    add("d13-c2-card-avatar-svg-forbidden-refuse", ["SL-WIRE-010"], "raw_wire", {"object": card_svg}, "REFUSE", "WIRE_MEMBER", "Commit 2: seallink-card/1 avatar forbidding image/svg+xml MUST refuse WIRE_MEMBER.")
    card_js = copy.deepcopy(card_ok)
    card_js["links"][0]["url"] = "javascript:alert(1)"
    add("d13-c2-card-link-javascript-forbidden-refuse", ["SL-WIRE-010"], "raw_wire", {"object": card_js}, "REFUSE", "WIRE_MEMBER", "Commit 2: seallink-card/1 links[] with forbidden javascript: scheme MUST refuse WIRE_MEMBER.")
    card_uinfo = copy.deepcopy(card_ok)
    card_uinfo["avatar"]["locators"] = ["https://user:pass@evil.example/a.png"]
    add("d13-c2-card-locator-userinfo-forbidden-refuse", ["SL-WIRE-010"], "raw_wire", {"object": card_uinfo}, "REFUSE", "WIRE_MEMBER", "Commit 2: LocatorUri embedding user:pass@ authority credentials MUST refuse WIRE_MEMBER.")

    man_sso = {
        "network": "main", "owner": "id/sso-hub", "seq": 1,
        "service": {"actions": ["mail/read"], "endpoint": "https://sso.example.org/seallink", "receipt_key": _kp("c2-sso-rcpt")["xonly"], "service_type": "sso"},
        "type": "seallink-manifest/1",
    }
    add("d13-c2-manifest-service-type-sso-admit", ["SL-IDEN-006"], "raw_wire", {"object": man_sso}, "ADMIT", None, "Commit 2: seallink-manifest/1 with service.service_type='sso' admits.")

    # SL-IDEN-003 in resolve_manifest: link.grant hash-pin preimage in manifest.role_policies colliding with link.release -> NAME_VALUE_INVALID!
    shared_rpk = _kp("c2-shared-rp")["xonly"]
    pol_gr_coll = {"m": 1, "pks": [shared_rpk]}
    pol_gr_hash = sl.sha256(sl.jcs_encode(pol_gr_coll)).hex()
    man_rp_coll = {
        "network": "main", "owner": "id/alice", "role_policies": {"grant": pol_gr_coll}, "seq": 1, "type": "seallink-manifest/1",
    }
    man_rp_coll_h = sl.content_addr(man_rp_coll)
    ch_rp_coll = copy.deepcopy(fx_c2["chain"])
    ch_rp_coll["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_c2["_alice_reg"], fx_c2["_alice_owner_pol"],
        {"link": {"grant": {"p": pol_gr_hash}, "release": shared_rpk}, "m": {"h": man_rp_coll_h, "s": 1}},
        first_height=748000, update_height=749000,
    )
    add(
        "d13-c2-manifest-role-policy-preimage-collides-with-release-refuse",
        ["SL-IDEN-003", "SL-IDEN-006"],
        "name_resolve",
        {"chain": ch_rp_coll, "check_manifest": True, "manifests": {man_rp_coll_h: man_rp_coll}, "name": "id/alice"},
        "REFUSE",
        "NAME_VALUE_INVALID",
        "Commit 2 / SL-IDEN-003: resolve_manifest MUST detect when a role_policies preimage for link.grant.p shares a key with link.release (NAME_VALUE_INVALID).",
    )

    # ========================================================================
    # C2-3: seallink-statement/1 extensions: transport-binding (signal/x25519/seal),
    #       identity-link (same-controller, member-of+roles, contact, ward guardian_approvals,
    #       ward autonomous ban), profile-section (public + private P2P + seal)
    # ========================================================================
    alice_pin_c2 = {"name": "id/alice", "owner_policy": fx_c2["_alice_owner_pol"], "registration": fx_c2["_alice_reg"]}
    al_gr_sk = fx_c2["_keys"]["alice_gr"]["sk"]
    active_seal = {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}
    spent_seal = {"script_policy": aseal_pol, "txid": aseal_sp_tx, "vout": 0}

    st_tb_sig = sl.sign_envelope(
        {
            "genesis": GENESIS_MAIN, "issuer": alice_pin_c2, "network": "main", "not_after": now_c2 + 600, "not_before": now_c2,
            "seal": active_seal, "seq": 1, "statement_kind": "transport-binding",
            "subject": {"endpoint": "signal:alice.42", "key_alg": "x25519", "key_hex": _h32("c2-x25519-pub"), "transport": "signal"},
            "type": "seallink-statement/1",
        },
        [al_gr_sk],
    )
    add("d13-c2-stmt-transport-binding-signal-x25519-seal-admit", ["SL-IDEN-006"], "statement", {"chain": fx_c2["chain"], "statement": st_tb_sig}, "ADMIT", None, "Commit 2: transport-binding with signal + x25519 + active optional seal admits.")
    st_tb_spent = sl.sign_envelope({**st_tb_sig["payload"], "seal": spent_seal}, [al_gr_sk])
    add("d13-c2-stmt-optional-seal-spent-refuse", ["SL-IDEN-006", "SL-LDGR-011"], "statement", {"chain": fx_c2["chain"], "statement": st_tb_spent}, "REFUSE", "SEAL_SPENT", "Commit 2: seallink-statement/1 whose optional seal is spent on-chain MUST refuse SEAL_SPENT.")

    st_il_mem = sl.sign_envelope(
        {
            "genesis": GENESIS_MAIN, "issuer": alice_pin_c2, "network": "main", "not_after": now_c2 + 600, "not_before": now_c2,
            "seal": active_seal, "seq": 1, "statement_kind": "identity-link",
            "subject": {"peer": peer_pin, "relation": "member-of", "roles": ["core-maintainer", "treasurer"]},
            "type": "seallink-statement/1",
        },
        [al_gr_sk],
    )
    add("d13-c2-stmt-identity-link-member-of-roles-admit", ["SL-IDEN-006"], "statement", {"chain": fx_c2["chain"], "statement": st_il_mem}, "ADMIT", None, "Commit 2: Autonomous identity-link (member-of + roles[] + active seal) admits.")
    st_il_bad_roles = sl.sign_envelope(
        {**st_il_mem["payload"], "subject": {"peer": peer_pin, "relation": "same-controller", "roles": ["invalid-here"]}},
        [al_gr_sk],
    )
    add("d13-c2-stmt-identity-link-roles-on-same-controller-refuse", ["SL-WIRE-010"], "raw_wire", {"object": st_il_bad_roles}, "REFUSE", "WIRE_MEMBER", "Commit 2: identity-link carrying roles[] when relation != 'member-of' MUST refuse WIRE_MEMBER.")

    # profile-section: public (with locators + seal) AND private (no locators, encrypted P2P) + bad locator
    st_ps_pub = sl.sign_envelope(
        {
            "body_sha256": _h32("c2-payments-json"), "genesis": GENESIS_MAIN, "issuer": alice_pin_c2,
            "locators": ["https://alice.example.org/seallink/payments.json", "blossom://relay.example.org/" + _h32("c2-payments-json")],
            "network": "main", "not_after": now_c2 + 600, "not_before": now_c2, "seal": active_seal, "seq": 1,
            "statement_kind": "profile-section", "subject": {"section_kind": "org.seallink/payments-v1", "visibility": "public"},
            "type": "seallink-statement/1",
        },
        [al_gr_sk],
    )
    add("d13-c2-stmt-profile-section-public-admit", ["SL-IDEN-006"], "statement", {"chain": fx_c2["chain"], "statement": st_ps_pub}, "ADMIT", None, "Commit 2: Public profile-section statement with LocatorUri[] and active seal admits.")
    st_ps_priv = sl.sign_envelope(
        {
            "body_sha256": _h32("c2-private-iban"), "genesis": GENESIS_MAIN, "issuer": alice_pin_c2,
            "network": "main", "not_after": now_c2 + 600, "not_before": now_c2, "seq": 1,
            "statement_kind": "profile-section", "subject": {"section_kind": "org.seallink/payments-v1", "visibility": "private"},
            "type": "seallink-statement/1",
        },
        [al_gr_sk],
    )
    add("d13-c2-stmt-profile-section-private-no-locators-admit", ["SL-IDEN-006"], "statement", {"chain": fx_c2["chain"], "statement": st_ps_priv}, "ADMIT", None, "Commit 2: Private profile-section statement omitting locators (for encrypted P2P exchange) admits.")
    st_ps_http = sl.sign_envelope({**st_ps_pub["payload"], "locators": ["http://insecure.example.org/pay.json"]}, [al_gr_sk])
    add("d13-c2-stmt-profile-section-http-locator-refuse", ["SL-WIRE-010"], "raw_wire", {"object": st_ps_http}, "REFUSE", "WIRE_MEMBER", "Commit 2: profile-section with forbidden plaintext http:// locator MUST refuse WIRE_MEMBER.")

    # Ward identity-link with guardian_approvals[] ADMIT, ward autonomous REFUSE WARD_AUTONOMOUS_FORBIDDEN,
    # ward missing origin_bundle REFUSE ORIGIN_UNVERIFIED, wrong ward_name -> GUARDIAN_QUORUM_UNMET,
    # autonomous origin adult -> ADMIT (autonomous) and GUARDIAN_QUORUM_UNMET (if using guardian_approvals)!
    of_w = copy.deepcopy(fx_ward_rev2)
    w_now = of_w["chain"]["now"]
    w_nb = of_w["origin_bundle"]["name_binding"]
    w_pin = {"name": w_nb["name"], "owner_policy": w_nb["owner_policy"], "registration": w_nb["registration"]}
    w_oid = sl.object_id(of_w["origin_bundle"]["origin"]["payload"])
    # Give ward a link.grant key on-chain too so we can test the autonomous ward ban & post-majority autonomy!
    w_gr_k = _kp("c2-ward-grant")
    of_w["chain"]["names"][w_nb["name"]] = sv.make_name_history(
        w_nb["name"], w_nb["registration"], w_nb["owner_policy"],
        {"link": {"grant": w_gr_k["xonly"], "origin": w_oid}},
        first_height=749005, update_height=749015,
    )
    g1_sk = of_w["_keys"]["g1_gr"]["sk"]
    w_il_p = {
        "genesis": GENESIS_MAIN,
        "guardian_context": {"event_class": "contract_assent", "origin_id": w_oid, "revision": 2, "ward_name": w_nb["name"]},
        "issuer": w_pin, "network": "main", "not_after": w_now + 600, "not_before": w_now, "seq": 1,
        "statement_kind": "identity-link",
        "subject": {"peer": peer_pin, "relation": "member-of", "roles": ["student"]},
        "type": "seallink-statement/1",
    }
    w_il_env = sl.sign_guardian_envelope(
        w_il_p,
        [{"guardian_name": "id/parent-a", "revision": 2, "signers": [g1_sk], "slot": 2}],
    )
    add(
        "d13-c2-stmt-ward-identity-link-guardian-quorum-admit",
        ["SL-IDEN-006", "SL-ORIG-008"],
        "statement",
        {"chain": of_w["chain"], "origin_bundle": of_w["origin_bundle"], "statement": w_il_env, "trusted_origin_issuer_pins": of_w["trusted_origin_issuer_pins"]},
        "ADMIT",
        None,
        "Commit 2: Ward identity-link (member-of) authorized by guardian_approvals[] quorum (event_class=contract_assent) admits.",
    )
    # Insufficient guardian quorum (base origin fixture requires min=2 for contract_assent, only slot 1 supplied) -> GUARDIAN_QUORUM_UNMET
    of_w1 = rm._base_origin_fixture()
    w1_nb = of_w1["origin_bundle"]["name_binding"]
    w1_pin = {"name": w1_nb["name"], "owner_policy": w1_nb["owner_policy"], "registration": w1_nb["registration"]}
    w1_oid = sl.object_id(of_w1["origin_bundle"]["origin"]["payload"])
    w1_now = of_w1["chain"]["now"]
    w1_il_p = {
        "genesis": GENESIS_MAIN,
        "guardian_context": {"event_class": "contract_assent", "origin_id": w1_oid, "revision": 1, "ward_name": w1_nb["name"]},
        "issuer": w1_pin, "network": "main", "not_after": w1_now + 600, "not_before": w1_now, "seq": 1,
        "statement_kind": "identity-link",
        "subject": {"peer": peer_pin, "relation": "member-of", "roles": ["student"]},
        "type": "seallink-statement/1",
    }
    w1_il_env = sl.sign_guardian_envelope(
        w1_il_p,
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_w1["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add(
        "d13-c2-stmt-ward-identity-link-quorum-unmet-refuse",
        ["SL-ORIG-008"],
        "statement",
        {"chain": of_w1["chain"], "origin_bundle": of_w1["origin_bundle"], "statement": w1_il_env, "trusted_origin_issuer_pins": of_w1["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_QUORUM_UNMET",
        "Commit 2: Ward identity-link with 1-of-2 guardian approval MUST refuse GUARDIAN_QUORUM_UNMET.",
    )
    # Wrong ward_name in guardian_context -> GUARDIAN_QUORUM_UNMET
    w_il_bad_wn_p = {**w_il_p, "guardian_context": {**w_il_p["guardian_context"], "ward_name": "id/other-ward"}}
    w_il_bad_wn_env = sl.sign_guardian_envelope(
        w_il_bad_wn_p,
        [{"guardian_name": "id/parent-a", "revision": 2, "signers": [g1_sk], "slot": 2}],
    )
    add(
        "d13-c2-stmt-ward-identity-link-wrong-ward-name-refuse",
        ["SL-ORIG-008"],
        "statement",
        {"chain": of_w["chain"], "origin_bundle": of_w["origin_bundle"], "statement": w_il_bad_wn_env, "trusted_origin_issuer_pins": of_w["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_QUORUM_UNMET",
        "Commit 2: Ward identity-link whose guardian_context.ward_name != issuer.name MUST refuse GUARDIAN_QUORUM_UNMET.",
    )
    # Missing origin_bundle on guardian_approvals -> ORIGIN_UNVERIFIED
    add(
        "d13-c2-stmt-ward-identity-link-missing-origin-refuse",
        ["SL-ORIG-002"],
        "statement",
        {"chain": of_w["chain"], "statement": w_il_env, "trusted_origin_issuer_pins": of_w["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "Commit 2: Ward identity-link omitting origin_bundle MUST refuse ORIGIN_UNVERIFIED.",
    )
    # Ward attempting autonomous identity-link (signatures instead of guardian_approvals) -> WARD_AUTONOMOUS_FORBIDDEN!
    w_il_auto = sl.sign_envelope(
        {k: v for k, v in w_il_p.items() if k != "guardian_context"},
        [w_gr_k["sk"]],
    )
    add(
        "d13-c2-stmt-ward-autonomous-identity-link-forbidden",
        ["SL-ORIG-008"],
        "statement",
        {"chain": of_w["chain"], "origin_bundle": of_w["origin_bundle"], "statement": w_il_auto, "trusted_origin_issuer_pins": of_w["trusted_origin_issuer_pins"]},
        "REFUSE",
        "WARD_AUTONOMOUS_FORBIDDEN",
        "Commit 2: Active ward signing identity-link autonomously without guardian_approvals MUST refuse WARD_AUTONOMOUS_FORBIDDEN.",
    )
    # Ward hiding origin_bundle on autonomous identity-link (detected via registered_bindings fallback too!) -> ORIGIN_UNVERIFIED
    ch_w_regb = copy.deepcopy(of_w["chain"])
    ch_w_regb["names"][w_nb["name"]] = sv.make_name_history(
        w_nb["name"], w_nb["registration"], w_nb["owner_policy"],
        {"link": {"grant": w_gr_k["xonly"]}},
        first_height=749005, update_height=749015,
    )
    ch_w_regb.setdefault("registered_bindings", {})[f"{w_nb['registration']['txid']}:{w_nb['registration']['vout']}"] = w_oid
    add(
        "d13-c2-stmt-ward-autonomous-hidden-origin-refuse",
        ["SL-ORIG-002"],
        "statement",
        {"chain": ch_w_regb, "statement": w_il_auto, "trusted_origin_issuer_pins": of_w["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "Commit 2: Origin-bound ward omitting origin_bundle on autonomous identity-link MUST refuse ORIGIN_UNVERIFIED.",
    )
    # Emancipated/autonomous origin adult (after capacity/1 + handover) signing identity-link autonomously -> ADMIT; with guardian_approvals -> GUARDIAN_QUORUM_UNMET!
    of_adult = rm._base_origin_fixture()
    ad_nb = of_adult["origin_bundle"]["name_binding"]
    ad_oid = sl.object_id(of_adult["origin_bundle"]["origin"]["payload"])
    subj_new_pol = {"kind": "key", "pk": _kp("c2-adult-new-own")["comp"]}
    stat_pol_ad = of_adult["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"]
    cap_ad_p = {
        "basis_sha256": _h32("c2-cap-basis"),
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "issuer": of_adult["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "next_status_policy": stat_pol_ad,
        "next_status_vout": 0,
        "origin_id": ad_oid,
        "status_prev_outpoint": {"txid": rm._h32("ostat-tx"), "vout": 0},
        "subject_new_owner_policy": subj_new_pol,
        "type": "seallink-capacity/1",
    }
    cap_ad = sl.sign_envelope(cap_ad_p, [of_adult["_keys"]["reg_cred"]["sk"]])
    cap_ad_tx = _h32("c2-cap-ad-tx")
    of_adult["chain"]["txs"][rm._h32("ostat-tx")]["outputs"]["0"]["spent_by_txid"] = cap_ad_tx
    of_adult["chain"]["txs"][cap_ad_tx] = {
        "confirmed_height": 750050,
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_ad)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_pol_ad)}},
    }
    of_adult["origin_bundle"]["capacity_record"] = cap_ad
    ad_upds = of_adult["chain"]["names"][ad_nb["name"]]["updates"]
    prev_ad = ad_upds[-1]
    ad_spk, _ = sl.compile_script_policy(subj_new_pol)
    ad_val = sl.jcs_encode({"link": {"grant": w_gr_k["xonly"], "origin": ad_oid}})
    ad_xfer_tx = _h32("c2-ad-xfer-tx")
    ad_upds.append({
        "confirmed_height": 750060, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", ad_spk, name=ad_nb["name"].encode("utf-8"), value=ad_val).hex(),
        "owner_policy": subj_new_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": prev_ad["txid"], "vout": prev_ad["vout"], "witness_policy": prev_ad["owner_policy"]},
        "txid": ad_xfer_tx, "vout": 0,
    })
    ad_upds.append({
        "confirmed_height": 750070, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", ad_spk, name=ad_nb["name"].encode("utf-8"), value=ad_val).hex(),
        "owner_policy": subj_new_pol,
        "prev_input": {"sighash_bytes": [0x01], "txid": ad_xfer_tx, "vout": 0, "witness_policy": subj_new_pol},
        "txid": _h32("c2-ad-self-tx"), "vout": 0,
    })
    rm.sync_chain_tip(of_adult["chain"], height=750080, tip_hash=_h32("c2-ad-tip-750080"))
    ad_pin = {"name": ad_nb["name"], "owner_policy": subj_new_pol, "registration": ad_nb["registration"]}
    w_il_adult_auto = sl.sign_envelope(
        {**{k: v for k, v in w_il_p.items() if k != "guardian_context"}, "issuer": ad_pin, "not_after": of_adult["chain"]["now"] + 600, "not_before": of_adult["chain"]["now"]},
        [w_gr_k["sk"]],
    )
    add(
        "d13-c2-stmt-adult-origin-autonomous-identity-link-admit",
        ["SL-IDEN-006", "SL-ORIG-009"],
        "statement",
        {"chain": of_adult["chain"], "origin_bundle": of_adult["origin_bundle"], "statement": w_il_adult_auto, "trusted_origin_issuer_pins": of_adult["trusted_origin_issuer_pins"]},
        "ADMIT",
        None,
        "Commit 2: Emancipated autonomous origin actor signing identity-link autonomously admits.",
    )
    w_il_adult_ga_p = {
        **w_il_p,
        "guardian_context": {"event_class": "contract_assent", "origin_id": ad_oid, "revision": 1, "ward_name": ad_nb["name"]},
        "issuer": ad_pin, "not_after": of_adult["chain"]["now"] + 600, "not_before": of_adult["chain"]["now"],
    }
    w_il_adult_ga_env = sl.sign_guardian_envelope(
        w_il_adult_ga_p,
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_adult["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add(
        "d13-c2-stmt-adult-origin-guardian-approvals-refuse",
        ["SL-ORIG-009"],
        "statement",
        {"chain": of_adult["chain"], "origin_bundle": of_adult["origin_bundle"], "statement": w_il_adult_ga_env, "trusted_origin_issuer_pins": of_adult["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_QUORUM_UNMET",
        "Commit 2: Emancipated autonomous origin actor cannot be bound by guardian_approvals[] on identity-link (GUARDIAN_QUORUM_UNMET).",
    )
