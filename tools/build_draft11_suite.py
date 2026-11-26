#!/usr/bin/env python3
"""
SealLink v1.0.0-draft.11 / v1.0.0-draft.12 Conformance Suite:
  - Section A: 0x13 VOLUNTARY_REBIND (5-subphase 1->2->3->4->4b automaton, T_offer/T_rebind,
               awaiting_activation, first_error_height isolation, verify_assent _name_pin_equal)
  - Section B: 0x14 LOG_CHECKPOINT, acyclic RFC 9162 checkpoints_root, O(1) handover,
               canonical Fixed-Depth-256 SMT (sib != D[h-1]), 4-mode seallink-log-fraud/1 + 100% CLOSE,
               seallink-release/1 & log_tracked seallink-notary/1
  - Section C: PROFILE-artifact-v1 Gatekeeper (seallink-ticket/1, m-of-n, inconclusive, absent-notary veto,
               release_floor, fsverity-sha256, hardened bootstrap ban, provisional gossip deny-wins) &
               Tier-2 consensus-exact SegWitNameUpdateProof (OP_NAME_FIRSTUPDATE + OP_NAME_UPDATE,
               P2WPKH low-S + high-S, P2WSH 2-of-2, 64-byte leaf rejection, Namecoin nc28.0 AuxPoW & retarget).
  - Section D/E: Mutation-closure & exact numeric boundary matrix.
  - Section F: v1.0.0-draft.12 audit closure regressions (B1-B8, H1-H5, M3-M6).
"""

from __future__ import annotations

import copy
import struct
from typing import Any, Callable

import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = rm.GENESIS_MAIN


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-d11-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"d11:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def _ecdsa_sign_bip66(msg32: bytes, privkey: bytes, *, high_s: bool = False, sighash_byte: int = 0x01) -> bytes:
    """Deterministic secp256k1 ECDSA BIP-66 DER signature (optionally negated to consensus-valid high-S)."""
    d = int.from_bytes(privkey, "big")
    z = int.from_bytes(msg32, "big")
    k = int.from_bytes(sl.sha256(b"d11-ecdsa-k:" + privkey + msg32), "big") % (sl._N - 1) + 1
    r_pt = sl._point_mul(sl._G, k)
    assert r_pt is not None
    r = r_pt[0] % sl._N
    s = (pow(k, sl._N - 2, sl._N) * (z + r * d)) % sl._N
    half_n = sl._N // 2
    if high_s:
        if s <= half_n:
            s = sl._N - s
    else:
        if s > half_n:
            s = sl._N - s

    def _der_int(v: int) -> bytes:
        b = v.to_bytes((v.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([sighash_byte])


def _encode_raw_tx(
    version: int,
    vins: list[dict[str, Any]],
    vouts: list[tuple[int, bytes]],
    *,
    witnesses: list[list[bytes]] | None = None,
    locktime: int = 0,
) -> bytes:
    """Encode raw Bitcoin/Namecoin transaction (with BIP-141 witness when witnesses is not None)."""
    out = bytearray(struct.pack("<I", version))
    has_wit = witnesses is not None
    if has_wit:
        out += b"\x00\x01"
    out += sl._encode_varint(len(vins))
    for v in vins:
        out += bytes.fromhex(v["prev_txid"])[::-1]
        out += struct.pack("<I", v["prev_vout"])
        ss = v.get("script_sig", b"")
        out += sl._encode_varint(len(ss)) + ss
        out += struct.pack("<I", v.get("sequence", 0xFFFFFFFF))
    out += sl._encode_varint(len(vouts))
    for val_sat, spk in vouts:
        out += struct.pack("<Q", val_sat) + sl._encode_varint(len(spk)) + spk
    if has_wit:
        assert witnesses is not None
        for stack in witnesses:
            out += sl._encode_varint(len(stack))
            for item in stack:
                out += sl._encode_varint(len(item)) + item
    out += struct.pack("<I", locktime)
    return bytes(out)


def _btc_merkle_root_and_branches(txids_le: list[bytes]) -> tuple[bytes, list[list[str]]]:
    """Compute Bitcoin/Namecoin Merkle root (LE) and per-index BE hex branches."""
    n = len(txids_le)
    branches: list[list[str]] = [[] for _ in range(n)]
    level = list(txids_le)
    idxs = list(range(n))
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        for i in range(n):
            sib_idx = idxs[i] ^ 1
            branches[i].append(level[sib_idx][::-1].hex())
            idxs[i] >>= 1
        level = [sl.dsha256(level[j] + level[j + 1]) for j in range(0, len(level), 2)]
    return level[0], branches


def _build_synthetic_spv_proof(
    label: str,
    owner_pol: dict[str, Any],
    sign_sks: list[bytes],
    name: str,
    value_str: str,
    *,
    block_height: int = 750010,
    high_s: bool = False,
    sighash_byte: int = 0x01,
    tx_version: int = 0x7100,
    extra_dummy_txs: int = 1,
    op_kind: str = "NAME_UPDATE",
    prev_raw_override: bytes | None = None,
    prev_vout: int = 0,
    new_owner_pol: dict[str, Any] | None = None,
    opreturns: list[bytes] | None = None,
    header_version: int = (0x0001 << 16) | 2,
    script_sig_override: bytes = b"",
) -> tuple[dict[str, Any], bytes]:
    """Build a consensus-exact synthetic SegWitNameUpdateProof (OP_NAME_FIRSTUPDATE or OP_NAME_UPDATE) + 80B Namecoin block header."""
    exp_spk, exp_ws = sl.compile_script_policy(owner_pol)
    out_spk, _ = sl.compile_script_policy(new_owner_pol if new_owner_pol is not None else owner_pol)
    rand_b = sl.sha256(f"spv-rand-{label}".encode("utf-8"))[:20]
    if prev_raw_override is not None:
        prev_raw = prev_raw_override
    elif op_kind == "NAME_FIRSTUPDATE":
        h20 = sl.hash160(rand_b + name.encode("utf-8"))
        prev_name_spk = sl.encode_name_output("NAME_NEW", exp_spk, hash20=h20)
        prev_raw = _encode_raw_tx(
            0x7100,
            [{"prev_txid": _h32(f"spv-fund-{label}"), "prev_vout": 0, "script_sig": b"\x01\x01"}],
            [(1_000_000, prev_name_spk), (500_000, b"\x00\x14" + (b"\x22" * 20))],
        )
    else:
        prev_name_spk = sl.encode_name_output("NAME_FIRSTUPDATE", exp_spk, name=name.encode("utf-8"), rand=b"\x11" * 20, value=b"{}")
        prev_raw = _encode_raw_tx(
            0x7100,
            [{"prev_txid": _h32(f"spv-fund-{label}"), "prev_vout": 0, "script_sig": b"\x01\x01"}],
            [(1_000_000, prev_name_spk), (500_000, b"\x00\x14" + (b"\x22" * 20))],
        )
    prev_parsed = sl.parse_raw_tx(prev_raw)
    prev_val_sat = prev_parsed["vout"][prev_vout]["value_sat"]

    if op_kind == "NAME_FIRSTUPDATE":
        new_name_spk = sl.encode_name_output("NAME_FIRSTUPDATE", out_spk, name=name.encode("utf-8"), rand=rand_b, value=value_str.encode("utf-8"))
    else:
        new_name_spk = sl.encode_name_output("NAME_UPDATE", out_spk, name=name.encode("utf-8"), value=value_str.encode("utf-8"))
    tx_vins = [{"prev_txid": prev_parsed["txid"], "prev_vout": prev_vout, "script_sig": script_sig_override, "sequence": 0xFFFFFFFF}]
    tx_vouts: list[tuple[int, bytes]] = [(1_000_000, new_name_spk), (400_000, b"\x00\x14" + (b"\x33" * 20))]
    for opr in (opreturns or []):
        tx_vouts.append((0, opr))
    unsigned_tx = sl.parse_raw_tx(_encode_raw_tx(tx_version, tx_vins, tx_vouts))
    if owner_pol["kind"] == "key":
        pk_b = bytes.fromhex(owner_pol["pk"])
        script_code = b"\x76\xa9\x14" + sl.hash160(pk_b) + b"\x88\xac"
        sighash = sl.compute_bip143_sighash(unsigned_tx, 0, script_code, prev_val_sat, sighash_byte)
        sig_b = _ecdsa_sign_bip66(sighash, sign_sks[0], high_s=high_s, sighash_byte=sighash_byte)
        wit = [[sig_b, pk_b]]
    else:
        assert exp_ws is not None
        sighash = sl.compute_bip143_sighash(unsigned_tx, 0, exp_ws, prev_val_sat, sighash_byte)
        sigs_b = [_ecdsa_sign_bip66(sighash, sk, high_s=high_s, sighash_byte=sighash_byte) for sk in sign_sks]
        wit = [[b""] + sigs_b + [exp_ws]]
    tx_raw = _encode_raw_tx(tx_version, tx_vins, tx_vouts, witnesses=wit)
    tx_parsed = sl.parse_raw_tx(tx_raw)

    dummies: list[dict[str, Any]] = []
    for d_i in range(extra_dummy_txs):
        d_raw = _encode_raw_tx(
            2,
            [{"prev_txid": _h32(f"spv-dum-{label}-{d_i}"), "prev_vout": 0, "script_sig": b"\x02\x03\x04"}],
            [(100_000, b"\x00\x14" + bytes([0x40 + d_i]) * 20)],
        )
        dummies.append(sl.parse_raw_tx(d_raw))

    wtxids_le = [b"\x00" * 32, tx_parsed["wtxid_le"]] + [d["wtxid_le"] for d in dummies]
    wtxid_root_le, w_branches = _btc_merkle_root_and_branches(wtxids_le)
    wit_reserved = b"\x00" * 32
    wit_commit = sl.dsha256(wtxid_root_le + wit_reserved)
    cb_raw = _encode_raw_tx(
        2,
        [{"prev_txid": "00" * 32, "prev_vout": 0xFFFFFFFF, "script_sig": b"\x03" + struct.pack("<I", block_height)[:3] + b"seallink"}],
        [
            (5_000_000_000, b"\x00\x14" + (b"\x55" * 20)),
            (0, b"\x6a\x24\xaa\x21\xa9\xed" + wit_commit),
        ],
        witnesses=[[wit_reserved]],
    )
    cb_parsed = sl.parse_raw_tx(cb_raw)
    txids_le = [cb_parsed["txid_le"], tx_parsed["txid_le"]] + [d["txid_le"] for d in dummies]
    merkle_root_le, t_branches = _btc_merkle_root_and_branches(txids_le)

    # Regtest-style easy nBits (0x207fffff) mined to real valid regtest PoW with Namecoin chain_id=1!
    tgt = sl.bits_to_target(0x207FFFFF)
    hdr = b""
    for nonce in range(100000):
        cand = struct.pack("<I", header_version) + (b"\x00" * 32) + merkle_root_le + struct.pack("<III", 1795220000, 0x207FFFFF, nonce)
        if int.from_bytes(sl.dsha256(cand), "little") <= tgt:
            hdr = cand
            break
    assert hdr
    bhash = sl.dsha256(hdr)[::-1].hex()
    proof = {
        "block_hash": bhash,
        "block_header_hex": hdr.hex(),
        "block_height": block_height,
        "coinbase_merkle_branch": t_branches[0],
        "coinbase_tx_hex": cb_raw.hex(),
        "prevout_tx_hex": prev_raw.hex(),
        "tx_hex": tx_raw.hex(),
        "tx_index": 1,
        "txid_branch": t_branches[1],
        "wtxid_branch": w_branches[1],
        "wtxid_coinbase_branch": w_branches[0],
    }
    return proof, hdr


def _build_same_block_chained_spv_pair(
    label: str,
    owner_pol: dict[str, Any],
    sign_sk: bytes,
    name: str,
    val0: str,
    val1: str,
    *,
    block_height: int = 750010,
    high_s_second: bool = True,
    header_version: int = (0x0001 << 16) | 2,
) -> tuple[list[dict[str, Any]], bytes, dict[str, Any]]:
    """Build two chained SegWitNameUpdateProofs (OP_NAME_FIRSTUPDATE at tx_index=1, OP_NAME_UPDATE at tx_index=2) in ONE block."""
    exp_spk, _ = sl.compile_script_policy(owner_pol)
    pk_b = bytes.fromhex(owner_pol["pk"])
    script_code = b"\x76\xa9\x14" + sl.hash160(pk_b) + b"\x88\xac"
    rand_b = sl.sha256(f"spv-pair-rand-{label}".encode("utf-8"))[:20]
    h20 = sl.hash160(rand_b + name.encode("utf-8"))
    new_raw = _encode_raw_tx(
        0x7100,
        [{"prev_txid": _h32(f"spv-pair-fund-{label}"), "prev_vout": 0, "script_sig": b"\x01\x01"}],
        [(1_000_000, sl.encode_name_output("NAME_NEW", exp_spk, hash20=h20))],
    )
    new_p = sl.parse_raw_tx(new_raw)

    fu_vins = [{"prev_txid": new_p["txid"], "prev_vout": 0, "script_sig": b"", "sequence": 0xFFFFFFFF}]
    fu_vouts = [(1_000_000, sl.encode_name_output("NAME_FIRSTUPDATE", exp_spk, name=name.encode("utf-8"), rand=rand_b, value=val0.encode("utf-8")))]
    fu_u = sl.parse_raw_tx(_encode_raw_tx(0x7100, fu_vins, fu_vouts))
    fu_sig = _ecdsa_sign_bip66(sl.compute_bip143_sighash(fu_u, 0, script_code, 1_000_000, 0x01), sign_sk, high_s=False)
    fu_raw = _encode_raw_tx(0x7100, fu_vins, fu_vouts, witnesses=[[fu_sig, pk_b]])
    fu_p = sl.parse_raw_tx(fu_raw)

    u1_vins = [{"prev_txid": fu_p["txid"], "prev_vout": 0, "script_sig": b"", "sequence": 0xFFFFFFFF}]
    u1_vouts = [(1_000_000, sl.encode_name_output("NAME_UPDATE", exp_spk, name=name.encode("utf-8"), value=val1.encode("utf-8")))]
    u1_u = sl.parse_raw_tx(_encode_raw_tx(0x7100, u1_vins, u1_vouts))
    u1_sig = _ecdsa_sign_bip66(sl.compute_bip143_sighash(u1_u, 0, script_code, 1_000_000, 0x01), sign_sk, high_s=high_s_second)
    u1_raw = _encode_raw_tx(0x7100, u1_vins, u1_vouts, witnesses=[[u1_sig, pk_b]])
    u1_p = sl.parse_raw_tx(u1_raw)

    wtxids_le = [b"\x00" * 32, fu_p["wtxid_le"], u1_p["wtxid_le"]]
    wroot_le, w_branches = _btc_merkle_root_and_branches(wtxids_le)
    wit_res = b"\x00" * 32
    cb_raw = _encode_raw_tx(
        2,
        [{"prev_txid": "00" * 32, "prev_vout": 0xFFFFFFFF, "script_sig": b"\x03" + struct.pack("<I", block_height)[:3] + b"slpair"}],
        [(5_000_000_000, b"\x00\x14" + (b"\x55" * 20)), (0, b"\x6a\x24\xaa\x21\xa9\xed" + sl.dsha256(wroot_le + wit_res))],
        witnesses=[[wit_res]],
    )
    cb_p = sl.parse_raw_tx(cb_raw)
    troot_le, t_branches = _btc_merkle_root_and_branches([cb_p["txid_le"], fu_p["txid_le"], u1_p["txid_le"]])
    tgt = sl.bits_to_target(0x207FFFFF)
    hdr = b""
    for nonce in range(100000):
        cand = struct.pack("<I", header_version) + (b"\x00" * 32) + troot_le + struct.pack("<III", 1795220000, 0x207FFFFF, nonce)
        if int.from_bytes(sl.dsha256(cand), "little") <= tgt:
            hdr = cand
            break
    assert hdr
    bhash = sl.dsha256(hdr)[::-1].hex()
    p0 = {
        "block_hash": bhash, "block_header_hex": hdr.hex(), "block_height": block_height,
        "coinbase_merkle_branch": t_branches[0], "coinbase_tx_hex": cb_raw.hex(),
        "prevout_tx_hex": new_raw.hex(), "tx_hex": fu_raw.hex(), "tx_index": 1,
        "txid_branch": t_branches[1], "wtxid_branch": w_branches[1], "wtxid_coinbase_branch": w_branches[0],
    }
    p1 = {
        "block_hash": bhash, "block_header_hex": hdr.hex(), "block_height": block_height,
        "coinbase_merkle_branch": t_branches[0], "coinbase_tx_hex": cb_raw.hex(),
        "prevout_tx_hex": fu_raw.hex(), "tx_hex": u1_raw.hex(), "tx_index": 2,
        "txid_branch": t_branches[2], "wtxid_branch": w_branches[2], "wtxid_coinbase_branch": w_branches[0],
    }
    return [p0, p1], hdr, {"txid": fu_p["txid"], "vout": 0}


def _build_autonomous_origin_rebind_fixture(
    label: str,
    *,
    recovery_mode: str = "dual_party_delayed",
    delay_blocks: int = 144,
    rec_delay_blocks: int = 144,
    h_offer: int = 749500,
    h_13: int = 749600,
    h_act: int | None = 749744,
    tip_h: int = 749800,
    rotate_b1_before_13: bool = False,
    t_rebind_changes_b1_pol: bool = False,
    t_rebind_value: str = "{}",
    t_rebind_version: int = 0x7100,
    t_offer_version: int = 0x7100,
    b2_corrupt_at: int | None = None,
    b2_corrupt_kind: str = "owner_policy",
    non_default_vin_order: bool = True,
) -> dict[str, Any]:
    """Build a self-contained autonomous origin + 0x13 T_offer -> T_rebind -> Step 3 fixture."""
    reg_own, reg_cred = _kp(f"{label}-reg-own"), _kp(f"{label}-reg-cred")
    b1_own, b1_own2, b1_gr = _kp(f"{label}-b1-own"), _kp(f"{label}-b1-own2"), _kp(f"{label}-b1-gr")
    b2_own, b2_own_bad, b2_gr = _kp(f"{label}-b2-own"), _kp(f"{label}-b2-own-bad"), _kp(f"{label}-b2-gr")
    disp, arb = _kp(f"{label}-disp"), _kp(f"{label}-arb")
    bind_seal_k, stat_k = _kp(f"{label}-bseal"), _kp(f"{label}-stat")

    reg_pol = {"kind": "key", "pk": reg_own["comp"]}
    b1_pol = {"kind": "key", "pk": b1_own["comp"]}
    b1_pol2 = {"kind": "key", "pk": b1_own2["comp"]}
    eff_pol_1 = b1_pol2 if rotate_b1_before_13 else b1_pol
    b2_pol = {"kind": "key", "pk": b2_own["comp"]}
    b2_pol_bad = {"kind": "key", "pk": b2_own_bad["comp"]}
    bind_seal_pol = {"kind": "key", "pk": bind_seal_k["comp"]}
    stat_pol = {"kind": "key", "pk": stat_k["comp"]}
    rec_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["comp"], arb["comp"])}

    reg_op = {"txid": _h32(f"{label}-reg-op"), "vout": 0}
    b1_reg = {"txid": _h32(f"{label}-b1-reg"), "vout": 0}
    b2_reg = {"txid": _h32(f"{label}-b2-reg"), "vout": 0}

    reg_issuer = {"name": "id/reg-d11", "owner_policy": reg_pol, "registration": reg_op, "role_policy": {"m": 1, "pks": [reg_cred["xonly"]]}}
    reg_pin = {"name": "id/reg-d11", "owner_policy": reg_pol, "registration": reg_op}

    nr_obj: dict[str, Any] = {"mode": "none"}
    if recovery_mode == "dual_party_delayed":
        nr_obj = {
            "arbiter_pk": arb["comp"],
            "delay_blocks": rec_delay_blocks,
            "disposer_pk": disp["comp"],
            "mode": "dual_party_delayed",
            "recovery_seal": {"script_policy": rec_pol, "txid": _h32(f"{label}-rec-seal"), "vout": 0},
        }

    orig_p = {
        "binding_seal": {"script_policy": bind_seal_pol, "txid": _h32(f"{label}-bseal-tx"), "vout": 0},
        "claims": {"intended_name": "id/alice-v1", "intended_owner_policy": b1_pol},
        "genesis": GENESIS_MAIN,
        "issuer": reg_issuer,
        "name_recovery": nr_obj,
        "network": "main",
        "origin_class": "person",
        "request_sha256": _h32(f"{label}-orig-req"),
        "status_seal": {"script_policy": stat_pol, "txid": _h32(f"{label}-stat-tx"), "vout": 0},
        "subject_initial_key": b1_gr["xonly"],
        "type": "seallink-origin/1",
    }
    orig_env = sl.sign_envelope(orig_p, [reg_cred["sk"]])
    oid = sl.object_id(orig_p)
    orig_txid = _h32(f"{label}-orig-tx")
    bind_txid = _h32(f"{label}-bind-tx")

    b1 = {
        "binding_mode": "initial",
        "genesis": GENESIS_MAIN,
        "name": "id/alice-v1",
        "network": "main",
        "origin_id": oid,
        "owner_policy": b1_pol,
        "registration": b1_reg,
        "seq": 1,
        "type": "seallink-name-binding/1",
    }
    b1_id = sl.object_id(b1)

    t_offer_txid = _h32(f"{label}-t-offer")
    consent_vout = 2
    b2 = {
        "binding_mode": "voluntary",
        "consent_outpoint": {"txid": t_offer_txid, "vout": consent_vout},
        "delay_blocks": delay_blocks,
        "genesis": GENESIS_MAIN,
        "name": "id/alice-v2",
        "network": "main",
        "origin_id": oid,
        "owner_policy": b2_pol,
        "registration": b2_reg,
        "seq": 2,
        "supersedes_binding_id": b1_id,
        "type": "seallink-name-binding/1",
    }
    b2_id = sl.object_id(b2)
    t_rebind_txid = _h32(f"{label}-t-rebind")

    # B_1 name history: firstupdate (749005) -> update with link.origin (749015) -> optional cold rotation -> T_rebind (h_13)
    b1_hist = sv.make_name_history(
        "id/alice-v1", b1_reg, b1_pol, {"link": {"grant": b1_gr["xonly"], "origin": oid}}, first_height=749005, update_height=749015
    )
    if rotate_b1_before_13:
        prev_u = b1_hist["updates"][-1]
        u_rot1_tx = _h32(f"{label}-b1-rot1")
        b1_hist["updates"].append({
            "block_time": 1795201000,
            "confirmed_height": 749200,
            "op": "NAME_UPDATE",
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b1_pol2)), name=b"id/alice-v1", value=sl.jcs_encode({"link": {"grant": b1_gr["xonly"], "origin": oid}})).hex(),
            "owner_policy": b1_pol2,
            "prev_input": {"sighash_bytes": [1], "txid": prev_u["txid"], "vout": prev_u["vout"], "witness_policy": b1_pol},
            "txid": u_rot1_tx,
            "vout": 0,
        })
        u_rot2_tx = _h32(f"{label}-b1-rot2")
        b1_hist["updates"].append({
            "block_time": 1795201600,
            "confirmed_height": 749210,
            "op": "NAME_UPDATE",
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b1_pol2)), name=b"id/alice-v1", value=sl.jcs_encode({"link": {"grant": b1_gr["xonly"], "origin": oid}})).hex(),
            "owner_policy": b1_pol2,
            "prev_input": {"sighash_bytes": [1], "txid": u_rot1_tx, "vout": 0, "witness_policy": b1_pol2},
            "txid": u_rot2_tx,
            "vout": 0,
        })

    prev_b1 = b1_hist["updates"][-1]
    t_reb_out_pol = b1_pol2 if (t_rebind_changes_b1_pol and not rotate_b1_before_13) else (b1_pol if t_rebind_changes_b1_pol else eff_pol_1)
    b1_hist["updates"].append({
        "block_time": 1795210000,
        "confirmed_height": h_13,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x13, b2_id).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(t_reb_out_pol)), name=b"id/alice-v1", value=t_rebind_value.encode("utf-8")).hex(),
        "owner_policy": t_reb_out_pol,
        "prev_input": {"sighash_bytes": [1], "txid": prev_b1["txid"], "vout": prev_b1["vout"], "witness_policy": eff_pol_1},
        "txid": t_rebind_txid,
        "version": t_rebind_version,
        "vout": 1 if non_default_vin_order else 0,
    })

    # B_2 name history: firstupdate (749400) -> T_offer (h_offer) -> optional corruption -> optional Step 3 activation (h_act)
    b2_hist: dict[str, Any] = {
        "registration": b2_reg,
        "updates": [
            {
                "block_time": 1795205000,
                "confirmed_height": 749400,
                "op": "NAME_FIRSTUPDATE",
                "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(b2_pol)), name=b"id/alice-v2", rand=b"\x07" * 20, value=b"{}").hex(),
                "owner_policy": b2_pol,
                "txid": b2_reg["txid"],
                "vout": 0,
            },
            {
                "block_time": 1795206000,
                "confirmed_height": h_offer,
                "op": "NAME_UPDATE",
                "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b2_pol)), name=b"id/alice-v2", value=b"{}").hex(),
                "owner_policy": b2_pol,
                "prev_input": {"sighash_bytes": [1], "txid": b2_reg["txid"], "vout": 0, "witness_policy": b2_pol},
                "txid": t_offer_txid,
                "version": t_offer_version,
                "vout": 0,
            },
        ],
    }
    if b2_corrupt_at is not None:
        prev_b2 = b2_hist["updates"][-1]
        c_pol = b2_pol_bad if b2_corrupt_kind == "owner_policy" else b2_pol
        c_val = sl.jcs_encode({"link": {"origin": _h32("foreign-oid") if b2_corrupt_kind == "foreign_origin" else oid}}) if "origin" in b2_corrupt_kind else b"{}"
        b2_hist["updates"].append({
            "block_time": 1795208000,
            "confirmed_height": b2_corrupt_at,
            "op": "NAME_UPDATE",
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(c_pol)), name=b"id/alice-v2", value=c_val).hex(),
            "owner_policy": c_pol,
            "prev_input": {"sighash_bytes": [1], "txid": prev_b2["txid"], "vout": prev_b2["vout"], "witness_policy": b2_pol},
            "txid": _h32(f"{label}-b2-corrupt"),
            "vout": 0,
        })
    if h_act is not None:
        prev_b2 = b2_hist["updates"][-1]
        b2_hist["updates"].append({
            "block_time": 1795215000,
            "confirmed_height": h_act,
            "op": "NAME_UPDATE",
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b2_pol)), name=b"id/alice-v2", value=sl.jcs_encode({"link": {"grant": b2_gr["xonly"], "origin": oid}})).hex(),
            "owner_policy": b2_pol,
            "prev_input": {"sighash_bytes": [1], "txid": prev_b2["txid"], "vout": prev_b2["vout"], "witness_policy": prev_b2["owner_policy"]},
            "txid": _h32(f"{label}-b2-step3"),
            "vout": 0,
        })

    fee_in = sv.make_segwit_input(_h32(f"{label}-fee"), 0)
    consent_in = sv.make_segwit_input(t_offer_txid, consent_vout)
    b1_name_in = sv.make_segwit_input(prev_b1["txid"], prev_b1["vout"])
    reb_inputs = [fee_in, consent_in, b1_name_in] if non_default_vin_order else [b1_name_in, consent_in]

    tip_hash = _h32(f"{label}-tip-{tip_h}")
    chain: dict[str, Any] = {
        "best_header_height": tip_h,
        "block_times": {str(h_13 + delay_blocks): 1795214900, str(tip_h): 1795219900},
        "blocks": {tip_hash: tip_h},
        "clock_watermark": 1795219000,
        "comparison_peers": [{"hash_at_tip": tip_hash, "healthy": True, "height": tip_h, "id": "peer-1"}],
        "credible_utc_interval": [1795219950, 1795220050],
        "genesis": GENESIS_MAIN,
        "in_ibd": False,
        "names": {
            "id/reg-d11": sv.make_name_history("id/reg-d11", reg_op, reg_pol, {"link": {"cred": reg_cred["xonly"]}}, first_height=748000, update_height=748500),
            "id/alice-v1": b1_hist,
            "id/alice-v2": b2_hist,
        },
        "network": "main",
        "node_reachable": True,
        "now": 1795220000,
        "observation_bracket": {"consistent": True, "end": {"hash": tip_hash, "height": tip_h}, "start": {"hash": tip_hash, "height": tip_h}},
        "tip_first_sight": 1795219995,
        "tip_hash": tip_hash,
        "tip_header_time": 1795219990,
        "tip_height": tip_h,
        "tip_median_time_past": 1795219900,
        "txindex": True,
        "txs": {
            orig_txid: {"confirmed_height": 749000, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(orig_env)).hex(), "outputs": {}},
            _h32(f"{label}-bseal-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(bind_seal_pol), "spent_by_txid": bind_txid}}},
            bind_txid: {"confirmed_height": 749010, "inputs": [sv.make_segwit_input(_h32(f"{label}-bseal-tx"), 0)], "opreturn_hex": sl.encode_opreturn(0x0C, b1_id).hex(), "outputs": {}},
            _h32(f"{label}-stat-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_pol)}}},
            t_offer_txid: {"confirmed_height": h_offer, "version": t_offer_version, "outputs": {str(consent_vout): {"script_pubkey_hex": _spk_hex(b2_pol), "spent_by_txid": t_rebind_txid}}},
            t_rebind_txid: {
                "confirmed_height": h_13,
                "inputs": reb_inputs,
                "opreturn_hex": sl.encode_opreturn(0x13, b2_id).hex(),
                "outputs": {},
                "version": t_rebind_version,
            },
        },
    }
    if recovery_mode == "dual_party_delayed":
        chain["txs"][_h32(f"{label}-rec-seal")] = {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(rec_pol)}}}

    return {
        "chain": chain,
        "origin_bundle": {
            "name_binding": b1,
            "name_binding_txid": bind_txid,
            "origin": orig_env,
            "origin_anchor_txid": orig_txid,
            "recovery_bindings": [],
            "voluntary_rebind_bindings": [b2],
        },
        "trusted_origin_issuer_pins": [reg_pin],
        "_oid": oid,
        "_b1": b1,
        "_b1_id": b1_id,
        "_b2": b2,
        "_b2_id": b2_id,
        "_b1_pol": b1_pol,
        "_eff_pol_1": eff_pol_1,
        "_b2_pol": b2_pol,
        "_b1_gr": b1_gr,
        "_b2_gr": b2_gr,
        "_rec_pol": rec_pol,
        "_rec_seal_tx": _h32(f"{label}-rec-seal"),
        "_t_rebind_txid": t_rebind_txid,
        "_t_offer_txid": t_offer_txid,
    }


def _build_log_ecosystem(label: str, *, role: str = "notary", with_4_checkpoints: bool = False) -> dict[str, Any]:
    """Build a complete verified 0x14 transparency/denial log fixture (cp1 -> cp2 [-> cp3 -> cp4]) + release/notary items."""
    base_fx = rm._base_invocation_fixture()
    iss_own = _kp(f"{label}-own")
    iss_role = _kp(f"{label}-role")
    seal_k = _kp(f"{label}-seal")
    iss_pol = {"kind": "key", "pk": iss_own["comp"]}
    seal_pol = {"kind": "key", "pk": seal_k["comp"]}
    iss_reg = {"txid": _h32(f"{label}-reg"), "vout": 0}
    iss_name = f"id/{label}-op"
    iss_pin = {"name": iss_name, "owner_policy": iss_pol, "registration": iss_reg}
    iss_role_pin = {**iss_pin, "role_policy": {"m": 1, "pks": [iss_role["xonly"]]}}

    gen_tx = _h32(f"{label}-gen-seal")
    cp1_tx = _h32(f"{label}-cp1-tx")
    cp2_tx = _h32(f"{label}-cp2-tx")
    log_id = sl.compute_log_id("main", GENESIS_MAIN, role, iss_name, iss_reg, {"txid": gen_tx, "vout": 0})

    art = {"digest": _h32(f"{label}-artifact"), "scheme": "sha256"}
    tid = sl.artifact_target_id(art)
    if role == "notary":
        item_p: dict[str, Any] = {
            "act_kind": "artifact-notarization",
            "attested_at": 1795219000,
            "details": {"artifact_identity": art, "claims": [{"claim_id": "seallink.org/build-repro", "verdict": "pass"}], "kind": "artifact-notarization"},
            "genesis": GENESIS_MAIN,
            "lifecycle": "log_tracked",
            "log_id": log_id,
            "network": "main",
            "notary": iss_role_pin,
            "target_sha256": tid,
            "tip_hash": base_fx["chain"]["tip_hash"],
            "tip_height": base_fx["chain"]["tip_height"],
            "type": "seallink-notary/1",
        }
        item_env = sl.sign_envelope(item_p, [iss_role["sk"]])
        item_id = sl.object_id(item_p)
        denial_key = f"act:{item_id}|*"
    else:
        item_p = {
            "artifact_identity": art,
            "genesis": GENESIS_MAIN,
            "issuer": iss_role_pin,
            "lifecycle": "log_tracked",
            "log_id": log_id,
            "network": "main",
            "product_id": "works.relux/curator-cli",
            "release_seq": 5,
            "released_at": 1795219000,
            "target_sha256": tid,
            "type": "seallink-release/1",
            "version_str": "1.2.0",
        }
        item_env = sl.sign_envelope(item_p, [iss_role["sk"]])
        item_id = sl.object_id(item_p)
        denial_key = f"rel:{item_id}|*"

    entry_1 = sl.log_entry_digest(0x01, sl.content_addr(item_env))
    b1_root, b1_proofs = sl.build_log_batch_root([entry_1])
    gen_op = {"txid": gen_tx, "vout": 0}
    cp1_p = {
        "batch_count": 1,
        "batch_root": b1_root,
        "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 1,
        "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": sl.SMT_EMPTY_ROOT,
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": gen_op,
        "issuer": iss_role_pin,
        "log_id": log_id,
        "network": "main",
        "next_log_policy": seal_pol,
        "next_log_vout": 1,
        "prev_log_outpoint": gen_op,
        "role": role,
        "seq": 1,
        "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }
    cp1_env = sl.sign_envelope(cp1_p, [iss_role["sk"]])
    cp1_ca = sl.content_addr(cp1_env)
    cp1_oid = sl.object_id(cp1_p)

    # Revocation record (seq=1) & reinstatement record (seq=2) & second revocation (seq=3)
    rev1_p = {
        "denial_key": denial_key,
        "genesis": GENESIS_MAIN,
        "issued_at": 1795219100,
        "issuer": iss_role_pin,
        "log_id": log_id,
        "network": "main",
        "reason_code": "cve-recalled",
        "role": role,
        "state_seq": 1,
        "type": "seallink-log-revocation/1",
    }
    rev1_env = sl.sign_envelope(rev1_p, [iss_role["sk"]])
    rev1_ca = sl.content_addr(rev1_env)

    reinst2_p = {
        "denial_key": denial_key,
        "genesis": GENESIS_MAIN,
        "issued_at": 1795219200,
        "issuer": iss_role_pin,
        "log_id": log_id,
        "network": "main",
        "prev_record_id": rev1_ca,
        "reason_code": "false-positive-cleared",
        "role": role,
        "state_seq": 2,
        "type": "seallink-log-reinstatement/1",
    }
    reinst2_env = sl.sign_envelope(reinst2_p, [iss_role["sk"]])
    reinst2_ca = sl.content_addr(reinst2_env)

    rev3_p = {
        "denial_key": denial_key,
        "genesis": GENESIS_MAIN,
        "issued_at": 1795219300,
        "issuer": iss_role_pin,
        "log_id": log_id,
        "network": "main",
        "prev_record_id": reinst2_ca,
        "reason_code": "confirmed-issue",
        "role": role,
        "state_seq": 3,
        "type": "seallink-log-revocation/1",
    }
    rev3_env = sl.sign_envelope(rev3_p, [iss_role["sk"]])
    rev3_ca = sl.content_addr(rev3_env)

    # cp2: heartbeat/clean continuation (no revocations yet)
    leaves_1 = [sl.ckpt_leaf(1, cp1_ca)]
    cp2_p = {
        "batch_count": 0,
        "batch_root": sl.EMPTY_BATCH_ROOT,
        "checkpoints_root": sl.rfc9162_mth(leaves_1).hex(),
        "cumulative_entries_count": 1,
        "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": sl.SMT_EMPTY_ROOT,
        "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": gen_op,
        "issuer": iss_role_pin,
        "log_id": log_id,
        "network": "main",
        "next_log_policy": seal_pol,
        "next_log_vout": 1,
        "prev_checkpoint_id": cp1_ca,
        "prev_log_outpoint": {"txid": cp1_tx, "vout": 1},
        "role": role,
        "seq": 2,
        "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }
    cp2_env = sl.sign_envelope(cp2_p, [iss_role["sk"]])
    cp2_ca = sl.content_addr(cp2_env)
    cp2_oid = sl.object_id(cp2_p)

    chain = copy.deepcopy(base_fx["chain"])
    chain["names"][iss_name] = sv.make_name_history(
        iss_name, iss_reg, iss_pol, {"link": {role: iss_role["xonly"]}}, first_height=749000, update_height=749100
    )
    chain["txs"][gen_tx] = {"confirmed_height": 749150, "outputs": {"0": {"script_pubkey_hex": _spk_hex(seal_pol), "spent_by_txid": cp1_tx}}}
    chain["txs"][cp1_tx] = {
        "block_hash": _h32(f"{label}-blk-cp1"),
        "confirmed_height": 749200,
        "inputs": [sv.make_segwit_input(gen_tx, 0)],
        "opreturn_hex": sl.encode_opreturn(0x14, cp1_ca).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(seal_pol), "spent_by_txid": cp2_tx}},
    }
    chain["txs"][cp2_tx] = {
        "block_hash": _h32(f"{label}-blk-cp2"),
        "confirmed_height": 749990,
        "inputs": [sv.make_segwit_input(cp1_tx, 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, cp2_ca).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(seal_pol)}},
    }

    chain_at_cp1 = copy.deepcopy(chain)
    chain_at_cp1["txs"].pop(cp2_tx, None)
    chain_at_cp1["txs"][cp1_tx]["outputs"]["1"].pop("spent_by_txid", None)
    chain_at_cp2 = copy.deepcopy(chain)

    res: dict[str, Any] = {
        "art": art,
        "b1_proof": b1_proofs[entry_1],
        "chain": chain,
        "chain_at_cp1": chain_at_cp1,
        "chain_at_cp2": chain_at_cp2,
        "cp1_ca": cp1_ca,
        "cp1_env": cp1_env,
        "cp1_oid": cp1_oid,
        "cp1_tx": cp1_tx,
        "cp2_ca": cp2_ca,
        "cp2_env": cp2_env,
        "cp2_oid": cp2_oid,
        "cp2_tx": cp2_tx,
        "cp1_in_cp2_proof": sl.rfc9162_inclusion_proof(leaves_1, 0),
        "denial_key": denial_key,
        "gen_op": gen_op,
        "gen_seal": {"script_policy": seal_pol, "txid": gen_tx, "vout": 0},
        "iss_name": iss_name,
        "iss_own": iss_own,
        "iss_pin": iss_pin,
        "iss_pol": iss_pol,
        "iss_reg": iss_reg,
        "iss_role": iss_role,
        "iss_role_pin": iss_role_pin,
        "item_env": item_env,
        "item_id": item_id,
        "log_id": log_id,
        "reinst2_ca": reinst2_ca,
        "reinst2_env": reinst2_env,
        "rev1_ca": rev1_ca,
        "rev1_env": rev1_env,
        "rev3_ca": rev3_ca,
        "rev3_env": rev3_env,
        "seal_pol": seal_pol,
        "tid": tid,
    }
    if with_4_checkpoints:
        cp3_tx = _h32(f"{label}-cp3-tx")
        cp4_tx = _h32(f"{label}-cp4-tx")
        leaves_2 = [sl.ckpt_leaf(1, cp1_ca), sl.ckpt_leaf(2, cp2_ca)]
        e_rev1 = sl.log_entry_digest(0x02, rev1_ca)
        b3_root, b3_proofs = sl.build_log_batch_root([e_rev1])
        kv3 = {denial_key: rev1_ca}
        cp3_p = {
            "batch_count": 1,
            "batch_root": b3_root,
            "checkpoints_root": sl.rfc9162_mth(leaves_2).hex(),
            "cumulative_entries_count": 2,
            "denials_delta_root": b3_root,
            "denials_root": sl.smt_root(kv3),
            "genesis": GENESIS_MAIN,
            "genesis_seal_outpoint": gen_op,
            "issuer": iss_role_pin,
            "log_id": log_id,
            "network": "main",
            "next_log_policy": seal_pol,
            "next_log_vout": 1,
            "prev_checkpoint_id": cp2_ca,
            "prev_log_outpoint": {"txid": cp2_tx, "vout": 1},
            "role": role,
            "seq": 3,
            "terminal": False,
            "type": "seallink-log-checkpoint/1",
        }
        cp3_env = sl.sign_envelope(cp3_p, [iss_role["sk"]])
        cp3_ca = sl.content_addr(cp3_env)
        leaves_3 = leaves_2 + [sl.ckpt_leaf(3, cp3_ca)]
        e_re2 = sl.log_entry_digest(0x03, reinst2_ca)
        b4_root, b4_proofs = sl.build_log_batch_root([e_re2])
        kv4 = {denial_key: reinst2_ca}
        cp4_p = {
            "batch_count": 1,
            "batch_root": b4_root,
            "checkpoints_root": sl.rfc9162_mth(leaves_3).hex(),
            "cumulative_entries_count": 3,
            "denials_delta_root": b4_root,
            "denials_root": sl.smt_root(kv4),
            "genesis": GENESIS_MAIN,
            "genesis_seal_outpoint": gen_op,
            "issuer": iss_role_pin,
            "log_id": log_id,
            "network": "main",
            "prev_checkpoint_id": cp3_ca,
            "prev_log_outpoint": {"txid": cp3_tx, "vout": 1},
            "role": role,
            "seq": 4,
            "terminal": True,
            "type": "seallink-log-checkpoint/1",
        }
        cp4_env = sl.sign_envelope(cp4_p, [iss_role["sk"]])
        cp4_ca = sl.content_addr(cp4_env)
        chain["txs"][cp2_tx]["outputs"]["1"]["spent_by_txid"] = cp3_tx
        chain["txs"][cp3_tx] = {
            "block_hash": _h32(f"{label}-blk-cp3"),
            "confirmed_height": 749994,
            "inputs": [sv.make_segwit_input(cp2_tx, 1)],
            "opreturn_hex": sl.encode_opreturn(0x14, cp3_ca).hex(),
            "outputs": {"1": {"script_pubkey_hex": _spk_hex(seal_pol), "spent_by_txid": cp4_tx}},
        }
        chain_at_cp3 = copy.deepcopy(chain)
        chain_at_cp3["txs"][cp3_tx]["outputs"]["1"].pop("spent_by_txid", None)
        chain["txs"][cp4_tx] = {
            "block_hash": _h32(f"{label}-blk-cp4"),
            "confirmed_height": 749998,
            "inputs": [sv.make_segwit_input(cp3_tx, 1)],
            "opreturn_hex": sl.encode_opreturn(0x14, cp4_ca).hex(),
            "outputs": {},
        }
        res.update({
            "b3_proof": b3_proofs[e_rev1],
            "b4_proof": b4_proofs[e_re2],
            "chain_at_cp3": chain_at_cp3,
            "cp3_ca": cp3_ca,
            "cp3_env": cp3_env,
            "cp3_tx": cp3_tx,
            "cp4_ca": cp4_ca,
            "cp4_env": cp4_env,
            "cp4_tx": cp4_tx,
            "kv3": kv3,
            "kv4": kv4,
            "leaves_2": leaves_2,
            "leaves_3": leaves_3,
        })
    return res


def add_draft11_conformance_cases(add: Callable[..., None]) -> None:
    """Append all v1.0.0-draft.11 conformance, adversarial, and boundary vectors."""

    # =========================================================================
    # SECTION A: 0x13 VOLUNTARY_REBIND (SL-ORIG-017)
    # =========================================================================
    # A1. Happy path: mode="none" + non-default vin order + Step 3 at exact maturity h_13 + D -> ADMIT_AUTONOMOUS
    rb_none = _build_autonomous_origin_rebind_fixture("reb-none", recovery_mode="none", h_act=749744)
    add(
        "d11-0x13-voluntary-rebind-mode-none-exact-maturity-step3-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": rb_none["chain"],
            "expect_active_name": "id/alice-v2",
            "expect_rebind_outcome": "promoted",
            "origin_bundle": rb_none["origin_bundle"],
            "trusted_origin_issuer_pins": rb_none["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: Autonomous mode='none' 0x13 T_offer -> T_rebind (non-default vin/vout) -> Step 3 at exact h_13+D promotes B_2.",
    )

    # A2. Happy path: dual_party_delayed + rotated eff_pol_1 + Step 3 after maturity (h_act > h_13 + D)
    rb_rot = _build_autonomous_origin_rebind_fixture("reb-rot", rotate_b1_before_13=True, h_act=749760)
    add(
        "d11-0x13-voluntary-rebind-rotated-eff-pol-1-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": rb_rot["chain"],
            "expect_active_name": "id/alice-v2",
            "expect_rebind_outcome": "promoted",
            "origin_bundle": rb_rot["origin_bundle"],
            "trusted_origin_issuer_pins": rb_rot["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: T_rebind authenticates against current writer-verified eff_pol_1 after cold owner rotation on B_1.",
    )

    # A3. Delay window exact boundary: eval_h == h_13 + D - 1 refuses RECOVERY_FORBIDDEN
    add(
        "d11-0x13-delay-window-exact-minus1-refuse",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "at_height": 749743,
            "chain": rb_none["chain"],
            "origin_bundle": rb_none["origin_bundle"],
            "trusted_origin_issuer_pins": rb_none["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "RECOVERY_FORBIDDEN",
        "SL-ORIG-017: During [h_13, h_13 + D), eval_h == h_13 + D - 1 MUST refuse RECOVERY_FORBIDDEN.",
    )

    # A4. awaiting_activation gate: matured at h_13 + D without Step 3 link.origin -> ORIGIN_BINDING_INVALID
    rb_await = _build_autonomous_origin_rebind_fixture("reb-await", h_act=None)
    add(
        "d11-0x13-awaiting-activation-refuse-binding-invalid",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": rb_await["chain"],
            "origin_bundle": rb_await["origin_bundle"],
            "trusted_origin_issuer_pins": rb_await["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-017: Matured B_2 without Step 3 link.origin remains in awaiting_activation and refuses ORIGIN_BINDING_INVALID.",
    )

    # A5. Asserting superseded B_1 after B_2 promoted -> ORIGIN_BINDING_INVALID
    add(
        "d11-0x13-assert-superseded-b1-refuse",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "assert_binding_id": rb_none["_b1_id"],
            "chain": rb_none["chain"],
            "origin_bundle": rb_none["origin_bundle"],
            "trusted_origin_issuer_pins": rb_none["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-017: Asserting superseded B_1 after 0x13 promotion MUST refuse ORIGIN_BINDING_INVALID.",
    )

    # A6. Phase 4b same-block 0x10 cancel at exact H == h_13 on B_1 AND on B_2 -> immediately restores B_1
    for side in ("b1", "b2"):
        rb_4b = _build_autonomous_origin_rebind_fixture(f"reb-4b-{side}", h_act=None)
        nm_t = "id/alice-v1" if side == "b1" else "id/alice-v2"
        pol_t = rb_4b["_eff_pol_1"] if side == "b1" else rb_4b["_b2_pol"]
        prev_u = rb_4b["chain"]["names"][nm_t]["updates"][-1]
        rb_4b["chain"]["names"][nm_t]["updates"].append({
            "block_time": 1795210001,
            "confirmed_height": 749600,  # Exact H == h_13 -> Phase 4b!
            "op": "NAME_UPDATE",
            "opreturn_hex": sl.encode_opreturn(0x10, rb_4b["_b2_id"]).hex(),
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(pol_t)), name=nm_t.encode("utf-8"), value=b"{}").hex(),
            "owner_policy": pol_t,
            "prev_input": {"sighash_bytes": [1], "txid": prev_u["txid"], "vout": prev_u["vout"], "witness_policy": pol_t},
            "txid": _h32(f"reb-4b-cancel-{side}"),
            "vout": 0,
        })
        add(
            f"d11-0x13-phase4b-same-block-0x10-cancel-on-{side}-admit",
            ["SL-ORIG-017"],
            "origin_status",
            {
                "chain": rb_4b["chain"],
                "expect_active_name": "id/alice-v1",
                "expect_rebind_outcome": "cancelled_restored",
                "origin_bundle": rb_4b["origin_bundle"],
                "trusted_origin_issuer_pins": rb_4b["trusted_origin_issuer_pins"],
            },
            "ADMIT_AUTONOMOUS",
            None,
            f"SL-ORIG-017 Phase 4b: Same-block 0x10 cancel at H == h_13 on {side.upper()} immediately aborts 0x13 and restores B_1.",
        )

    # A7. Phase 3 0x10 cancel in (h_13, h_13+D) on B_2 (plus assert_binding_id == id(B_2) -> RECOVERY_FORBIDDEN)
    rb_c3 = _build_autonomous_origin_rebind_fixture("reb-p3-cancel", h_act=None)
    prev_b2_c = rb_c3["chain"]["names"]["id/alice-v2"]["updates"][-1]
    rb_c3["chain"]["names"]["id/alice-v2"]["updates"].append({
        "block_time": 1795211000,
        "confirmed_height": 749650,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, rb_c3["_b2_id"]).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_c3["_b2_pol"])), name=b"id/alice-v2", value=b"{}").hex(),
        "owner_policy": rb_c3["_b2_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_b2_c["txid"], "vout": prev_b2_c["vout"], "witness_policy": rb_c3["_b2_pol"]},
        "txid": _h32("reb-p3-cancel-tx"),
        "vout": 0,
    })
    add(
        "d11-0x13-phase3-0x10-cancel-assert-b2-refuse",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "assert_binding_id": rb_c3["_b2_id"],
            "chain": rb_c3["chain"],
            "origin_bundle": rb_c3["origin_bundle"],
            "trusted_origin_issuer_pins": rb_c3["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "RECOVERY_FORBIDDEN",
        "SL-ORIG-017 Phase 3: Asserting cancelled 0x13 candidate B_2 MUST refuse RECOVERY_FORBIDDEN.",
    )

    # A8. Phase 4 same-block 0x0c vs 0x13 AND Phase 3 0x0c intercept during (h_13, h_13+D) — ZERO recovery_burned!
    for label_rc, h_rec_c, want_rb_out in [
        ("same-block-phase4", 749600, "rejected"),
        ("intercept-phase3", 749620, "intercepted_by_0x0c"),
    ]:
        rb_rc = _build_autonomous_origin_rebind_fixture(f"reb-0x0c-{label_rc}", h_act=None, tip_h=749900)
        b_rec_pol = {"kind": "key", "pk": _kp(f"reb-0x0c-new-{label_rc}")["comp"]}
        b_rec = {
            "binding_mode": "recovery",
            "genesis": GENESIS_MAIN,
            "name": "id/alice-rec",
            "network": "main",
            "next_recovery_policy": rb_rc["_rec_pol"],
            "next_recovery_vout": 0,
            "origin_id": rb_rc["_oid"],
            "owner_policy": b_rec_pol,
            "registration": {"txid": _h32(f"reb-0x0c-reg-{label_rc}"), "vout": 0},
            "seq": 2,
            "supersedes_binding_id": rb_rc["_b1_id"],
            "type": "seallink-name-binding/1",
        }
        rtx_id = _h32(f"reb-0x0c-rtx-{label_rc}")
        rb_rc["chain"]["txs"][rb_rc["_rec_seal_tx"]]["outputs"]["0"]["spent_by_txid"] = rtx_id
        rb_rc["chain"]["txs"][rtx_id] = {
            "confirmed_height": h_rec_c,
            "inputs": [sv.make_segwit_input(rb_rc["_rec_seal_tx"], 0)],
            "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(b_rec)).hex(),
            "outputs": {"0": {"script_pubkey_hex": _spk_hex(rb_rc["_rec_pol"])}},
        }
        rb_rc["origin_bundle"]["recovery_bindings"] = [b_rec]
        add(
            f"d11-0x13-0x0c-{label_rc}-wins-no-burn",
            ["SL-ORIG-017"],
            "origin_status",
            {
                "chain": rb_rc["chain"],
                "expect_active_name": "id/alice-rec",
                "expect_rebind_outcome": want_rb_out,
                "expect_recovery_burned": False,
                "origin_bundle": rb_rc["origin_bundle"],
                "trusted_origin_issuer_pins": rb_rc["trusted_origin_issuer_pins"],
            },
            "ADMIT_AUTONOMOUS",
            None,
            f"SL-ORIG-017: 0x0c ({label_rc}) supersedes 0x13 cleanly without recovery_burned and promotes B_rec.",
        )

    # A9. awaiting_activation permits emergency 0x0c recovery while rejecting a second 0x13 (B_2 -> B_3)!
    rb_aw_0c = _build_autonomous_origin_rebind_fixture("reb-aw-0c", h_act=None, tip_h=749950)
    b3_rec_pol = {"kind": "key", "pk": _kp("reb-aw-0c-pol")["comp"]}
    b3_rec = {
        "binding_mode": "recovery",
        "genesis": GENESIS_MAIN,
        "name": "id/alice-aw-rescue",
        "network": "main",
        "next_recovery_policy": rb_aw_0c["_rec_pol"],
        "next_recovery_vout": 0,
        "origin_id": rb_aw_0c["_oid"],
        "owner_policy": b3_rec_pol,
        "registration": {"txid": _h32("reb-aw-0c-reg"), "vout": 0},
        "seq": 3,
        "supersedes_binding_id": rb_aw_0c["_b2_id"],
        "type": "seallink-name-binding/1",
    }
    rtx_aw = _h32("reb-aw-0c-rtx")
    rb_aw_0c["chain"]["txs"][rb_aw_0c["_rec_seal_tx"]]["outputs"]["0"]["spent_by_txid"] = rtx_aw
    rb_aw_0c["chain"]["txs"][rtx_aw] = {
        "confirmed_height": 749760,  # After B_2 matured at 749744, while B_2 is still in awaiting_activation!
        "inputs": [sv.make_segwit_input(rb_aw_0c["_rec_seal_tx"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(b3_rec)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(rb_aw_0c["_rec_pol"])}},
    }
    rb_aw_0c["origin_bundle"]["recovery_bindings"] = [b3_rec]
    add(
        "d11-0x13-awaiting-activation-allows-emergency-0x0c-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": rb_aw_0c["chain"],
            "expect_active_name": "id/alice-aw-rescue",
            "expect_recovery_burned": False,
            "origin_bundle": rb_aw_0c["origin_bundle"],
            "trusted_origin_issuer_pins": rb_aw_0c["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: Emergency 0x0c recovery MUST remain permitted while B_2 is in awaiting_activation.",
    )

    # A10. awaiting_activation forbids second 0x13 (B_2 -> B_3 before Step 3) -> 2nd 0x13 rejected, B_2 activates at Step 3!
    rb_aw_13 = _build_autonomous_origin_rebind_fixture("reb-aw-13", h_act=749780, tip_h=749950)
    b3_reb_pol = {"kind": "key", "pk": _kp("reb-aw-13-b3")["comp"]}
    b3_reg = {"txid": _h32("reb-aw-13-b3-reg"), "vout": 0}
    b3_offer_tx = _h32("reb-aw-13-b3-offer")
    b3_reb = {
        "binding_mode": "voluntary",
        "consent_outpoint": {"txid": b3_offer_tx, "vout": 1},
        "delay_blocks": 144,
        "genesis": GENESIS_MAIN,
        "name": "id/alice-v3",
        "network": "main",
        "origin_id": rb_aw_13["_oid"],
        "owner_policy": b3_reb_pol,
        "registration": b3_reg,
        "seq": 3,
        "supersedes_binding_id": rb_aw_13["_b2_id"],
        "type": "seallink-name-binding/1",
    }
    b3_reb_tx = _h32("reb-aw-13-b3-rebind")
    # Insert 2nd 0x13 on B_2 at height 749750 (BETWEEN maturity 749744 and Step 3 h_act=749780!)
    u_s3 = rb_aw_13["chain"]["names"]["id/alice-v2"]["updates"].pop()
    prev_b2_aw = rb_aw_13["chain"]["names"]["id/alice-v2"]["updates"][-1]
    rb_aw_13["chain"]["names"]["id/alice-v2"]["updates"].append({
        "block_time": 1795214950,
        "confirmed_height": 749750,
        "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_reb)).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_aw_13["_b2_pol"])), name=b"id/alice-v2", value=b"{}").hex(),
        "owner_policy": rb_aw_13["_b2_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_b2_aw["txid"], "vout": prev_b2_aw["vout"], "witness_policy": rb_aw_13["_b2_pol"]},
        "txid": b3_reb_tx,
        "version": 0x7100,
        "vout": 0,
    })
    u_s3["prev_input"] = {"sighash_bytes": [1], "txid": b3_reb_tx, "vout": 0, "witness_policy": rb_aw_13["_b2_pol"]}
    rb_aw_13["chain"]["names"]["id/alice-v2"]["updates"].append(u_s3)
    rb_aw_13["chain"]["txs"][b3_reb_tx] = {"confirmed_height": 749750, "inputs": [sv.make_segwit_input(b3_offer_tx, 1)], "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_reb)).hex(), "outputs": {}, "version": 0x7100}
    rb_aw_13["origin_bundle"]["voluntary_rebind_bindings"].append(b3_reb)
    add(
        "d11-0x13-awaiting-activation-forbids-second-0x13",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": rb_aw_13["chain"],
            "expect_active_name": "id/alice-v2",
            "expect_rebind_outcome": "rejected",
            "origin_bundle": rb_aw_13["origin_bundle"],
            "trusted_origin_issuer_pins": rb_aw_13["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: Second 0x13 (B_2 -> B_3) attempted while B_2 is in awaiting_activation MUST be deterministically rejected.",
    )

    # A11. B_2 corruption in (h_offer, h_13) AND in (h_13, h_13+D), plus T_rebind owner_policy change / non-empty value / wrong nVersion
    for cid_inv, kw_inv, want_out in [
        ("b2-owner-changed-before-h13", {"b2_corrupt_at": 749550, "b2_corrupt_kind": "owner_policy", "h_act": None}, "rejected"),
        ("b2-owner-changed-in-delay", {"b2_corrupt_at": 749650, "b2_corrupt_kind": "owner_policy", "h_act": None}, "aborted_b2_invalid"),
        ("b2-premature-origin-in-delay", {"b2_corrupt_at": 749743, "b2_corrupt_kind": "origin", "h_act": None}, "aborted_b2_invalid"),
        ("t-rebind-changes-b1-owner-policy", {"t_rebind_changes_b1_pol": True, "h_act": None}, "rejected"),
        ("t-rebind-non-empty-value", {"t_rebind_value": '{"link":{}}', "h_act": None}, "rejected"),
        ("t-rebind-bad-nversion", {"t_rebind_version": 2, "h_act": None}, "rejected"),
        ("t-offer-bad-nversion", {"t_offer_version": 2, "h_act": None}, "rejected"),
    ]:
        rb_inv = _build_autonomous_origin_rebind_fixture(f"reb-inv-{cid_inv}", **kw_inv)
        add(
            f"d11-0x13-{cid_inv}-restores-b1",
            ["SL-ORIG-017"],
            "origin_status",
            {
                "chain": rb_inv["chain"],
                "expect_active_name": "id/alice-v1",
                "expect_rebind_outcome": want_out,
                "expect_recovery_burned": False,
                "origin_bundle": rb_inv["origin_bundle"],
                "trusted_origin_issuer_pins": rb_inv["trusted_origin_issuer_pins"],
            },
            "ADMIT_AUTONOMOUS",
            None,
            f"SL-ORIG-017: Invalid 0x13 condition ({cid_inv}) MUST reject/abort ({want_out}) and preserve B_1 without recovery_burned.",
        )

    # A12. Preimage withheld -> ORIGIN_STATUS_INCOMPLETE; invalid preimage -> rejected (B_1 survives)
    rb_wh = _build_autonomous_origin_rebind_fixture("reb-withheld", h_act=None)
    rb_wh["origin_bundle"]["voluntary_rebind_bindings"] = []
    add(
        "d11-0x13-preimage-withheld-incomplete",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": rb_wh["chain"],
            "origin_bundle": rb_wh["origin_bundle"],
            "trusted_origin_issuer_pins": rb_wh["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017 D-1: Confirmed 0x13 with withheld B_2 preimage MUST fail closed ORIGIN_STATUS_INCOMPLETE.",
    )

    rb_badpre = _build_autonomous_origin_rebind_fixture("reb-badpre", h_act=None)
    bad_b2_pre = dict(rb_badpre["_b2"], supersedes_binding_id=_h32("wrong-prev-binding"))
    bad_b2_id = sl.object_id(bad_b2_pre)
    rb_badpre["chain"]["names"]["id/alice-v1"]["updates"][-1]["opreturn_hex"] = sl.encode_opreturn(0x13, bad_b2_id).hex()
    rb_badpre["chain"]["txs"][rb_badpre["_t_rebind_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x13, bad_b2_id).hex()
    rb_badpre["origin_bundle"]["voluntary_rebind_bindings"] = [bad_b2_pre]
    add(
        "d11-0x13-invalid-preimage-rejected-b1-survives",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "chain": rb_badpre["chain"],
            "expect_active_name": "id/alice-v1",
            "expect_rebind_outcome": "rejected",
            "origin_bundle": rb_badpre["origin_bundle"],
            "trusted_origin_issuer_pins": rb_badpre["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 D-1: Confirmed 0x13 whose verified preimage fails supersedes_binding_id is deterministically rejected while B_1 survives.",
    )
    add(
        "d11-0x13-voluntary-delay-below-144-wire-integer",
        ["SL-ORIG-017"],
        "raw_wire",
        {"object": dict(rb_badpre["_b2"], delay_blocks=143)},
        "REFUSE",
        "WIRE_INTEGER",
        "SL-ORIG-017: Voluntary NameBinding with delay_blocks=143 (< 144 schema minimum) MUST refuse WIRE_INTEGER.",
    )

    # A13. Phase 1 H_self > H_promo emancipation for post-trigger B_rec -> enables subsequent 0x13!
    of_hself = rm._base_origin_fixture()
    s_pol_hs = {"kind": "key", "pk": _kp("hs-s-pol")["comp"]}
    cap_hs = sl.sign_envelope({
        "basis_sha256": _h32("hs-basis"), "genesis": GENESIS_MAIN, "issued_at": 1795210000,
        "issuer": of_hself["origin_bundle"]["origin"]["payload"]["issuer"], "network": "main",
        "next_status_policy": of_hself["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"],
        "next_status_vout": 0, "origin_id": of_hself["_origin_id"],
        "status_prev_outpoint": {"txid": of_hself["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"], "vout": 0},
        "subject_new_owner_policy": s_pol_hs, "type": "seallink-capacity/1",
    }, [of_hself["_keys"]["reg_cred"]["sk"]])
    cap_hs_tx = _h32("hs-cap-tx")
    ss_tx = of_hself["origin_bundle"]["origin"]["payload"]["status_seal"]["txid"]
    of_hself["chain"]["txs"][ss_tx]["outputs"]["0"]["spent_by_txid"] = cap_hs_tx
    of_hself["chain"]["txs"][cap_hs_tx] = {"confirmed_height": 749100, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_hs)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(of_hself["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"])}}}
    of_hself["origin_bundle"]["capacity_record"] = cap_hs
    brec_pol = {"kind": "key", "pk": _kp("hs-brec-pol")["comp"]}
    brec_reg = {"txid": _h32("hs-brec-reg"), "vout": 0}
    brec_b2 = {
        "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": "id/leo-brec", "network": "main",
        "next_recovery_policy": of_hself["_rec_pol"], "next_recovery_vout": 0,
        "origin_id": of_hself["_origin_id"], "owner_policy": brec_pol, "registration": brec_reg,
        "seq": 2, "supersedes_binding_id": sl.object_id(of_hself["origin_bundle"]["name_binding"]),
        "type": "seallink-name-binding/1",
    }
    rtx_hs = _h32("hs-0x0c-tx")
    rs_hs = of_hself["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"]
    of_hself["chain"]["txs"][rs_hs]["outputs"]["0"]["spent_by_txid"] = rtx_hs
    of_hself["chain"]["txs"][rtx_hs] = {"confirmed_height": 749200, "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(brec_b2)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(of_hself["_rec_pol"])}}}
    # H_promo = 749200 + 144 = 749344; B_rec self-updates LATER at H_self = 749360 > H_promo!
    brec_hist = sv.make_name_history("id/leo-brec", brec_reg, brec_pol, {"link": {"origin": of_hself["_origin_id"]}}, first_height=749150, update_height=749360)
    b3_hs_pol = {"kind": "key", "pk": _kp("hs-b3-pol")["comp"]}
    b3_hs_reg = {"txid": _h32("hs-b3-reg"), "vout": 0}
    b3_offer = _h32("hs-b3-offer")
    b3_reb = {
        "binding_mode": "voluntary", "consent_outpoint": {"txid": b3_offer, "vout": 1}, "delay_blocks": 144,
        "genesis": GENESIS_MAIN, "name": "id/leo-v3", "network": "main", "origin_id": of_hself["_origin_id"],
        "owner_policy": b3_hs_pol, "registration": b3_hs_reg, "seq": 3, "supersedes_binding_id": sl.object_id(brec_b2),
        "type": "seallink-name-binding/1",
    }
    b3_reb_tx = _h32("hs-b3-rebind")
    prev_br = brec_hist["updates"][-1]
    brec_hist["updates"].append({
        "block_time": 1795212000, "confirmed_height": 749400, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_reb)).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(brec_pol)), name=b"id/leo-brec", value=b"{}").hex(),
        "owner_policy": brec_pol, "prev_input": {"sighash_bytes": [1], "txid": prev_br["txid"], "vout": prev_br["vout"], "witness_policy": brec_pol},
        "txid": b3_reb_tx, "version": 0x7100, "vout": 0,
    })
    b3_hist = {
        "registration": b3_hs_reg,
        "updates": [
            {"block_time": 1795210000, "confirmed_height": 749300, "op": "NAME_FIRSTUPDATE", "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(b3_hs_pol)), name=b"id/leo-v3", rand=b"\x09" * 20, value=b"{}").hex(), "owner_policy": b3_hs_pol, "txid": b3_hs_reg["txid"], "vout": 0},
            {"block_time": 1795211000, "confirmed_height": 749380, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b3_hs_pol)), name=b"id/leo-v3", value=b"{}").hex(), "owner_policy": b3_hs_pol, "prev_input": {"sighash_bytes": [1], "txid": b3_hs_reg["txid"], "vout": 0, "witness_policy": b3_hs_pol}, "txid": b3_offer, "version": 0x7100, "vout": 0},
            {"block_time": 1795216000, "confirmed_height": 749544, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b3_hs_pol)), name=b"id/leo-v3", value=sl.jcs_encode({"link": {"origin": of_hself["_origin_id"]}})).hex(), "owner_policy": b3_hs_pol, "prev_input": {"sighash_bytes": [1], "txid": b3_offer, "vout": 0, "witness_policy": b3_hs_pol}, "txid": _h32("hs-b3-step3"), "vout": 0},
        ],
    }
    of_hself["chain"]["names"]["id/leo-brec"] = brec_hist
    of_hself["chain"]["names"]["id/leo-v3"] = b3_hist
    of_hself["chain"]["txs"][b3_offer] = {"confirmed_height": 749380, "version": 0x7100, "outputs": {"1": {"script_pubkey_hex": _spk_hex(b3_hs_pol), "spent_by_txid": b3_reb_tx}}}
    of_hself["chain"]["txs"][b3_reb_tx] = {"confirmed_height": 749400, "version": 0x7100, "inputs": [sv.make_segwit_input(b3_offer, 1), sv.make_segwit_input(prev_br["txid"], 0)], "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_reb)).hex(), "outputs": {}}
    of_hself["origin_bundle"]["recovery_bindings"] = [brec_b2]
    of_hself["origin_bundle"]["voluntary_rebind_bindings"] = [b3_reb]
    add(
        "d11-0x13-phase1-h-self-gt-h-promo-emancipates-and-rebinds-admit",
        ["SL-ORIG-017", "SL-ORIG-011"],
        "origin_status",
        {
            "chain": of_hself["chain"],
            "expect_active_name": "id/leo-v3",
            "expect_rebind_outcome": "promoted",
            "origin_bundle": of_hself["origin_bundle"],
            "trusted_origin_issuer_pins": of_hself["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 Phase 1: Delayed H_self > H_promo self-update on post-trigger B_rec enters State 4 and permits subsequent 0x13 to B_3.",
    )

    # A14. first_error_height isolation (P0-4): post-maturity corruption of B_1 NEVER taints B_2 or < h_13 lookups,
    # whereas in-window corruption (first_error_height < deadline) fails closed ORIGIN_STATUS_INCOMPLETE!
    rb_feh_ok = copy.deepcopy(rb_none)
    prev_feh_u = rb_feh_ok["chain"]["names"]["id/alice-v1"]["updates"][-1]
    rb_feh_ok["chain"]["names"]["id/alice-v1"]["updates"].append({
        "block_time": 1795215000, "confirmed_height": 749744, "op": "NAME_UPDATE",
        "opreturn_hex": "6a05534c4e4b060100",  # malformed SLNK at exact first_error_height (MUST be excluded by < feh_b!)
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_none["_b1_pol"])), name=b"id/alice-v1", value=b"{}").hex(),
        "owner_policy": rb_none["_b1_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_feh_u["txid"], "vout": prev_feh_u["vout"], "witness_policy": rb_none["_b1_pol"]},
        "txid": _h32("reb-feh-bad-at-deadline"), "vout": 0,
    })
    rb_feh_ok["chain"]["names"]["id/alice-v1"]["history_truncated"] = True
    rb_feh_ok["chain"]["names"]["id/alice-v1"]["first_error_height"] = 749744  # exact deadline -> outside [749600, 749744)!
    add(
        "d11-0x13-first-error-height-at-exact-deadline-isolated-admit",
        ["SL-ORIG-017", "SL-LDGR-015"],
        "origin_status",
        {
            "chain": rb_feh_ok["chain"],
            "expect_active_name": "id/alice-v2",
            "origin_bundle": rb_feh_ok["origin_bundle"],
            "trusted_origin_issuer_pins": rb_feh_ok["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 P0-4: Post-window B_1 first_error_height == h_13 + D does NOT taint matured B_2.",
    )
    rb_feh_bad = copy.deepcopy(rb_none)
    rb_feh_bad["chain"]["names"]["id/alice-v1"]["history_truncated"] = True
    rb_feh_bad["chain"]["names"]["id/alice-v1"]["first_error_height"] = 749743  # inside [749600, 749744)!
    add(
        "d11-0x13-first-error-height-inside-window-incomplete",
        ["SL-ORIG-017", "SL-LDGR-015"],
        "origin_status",
        {
            "chain": rb_feh_bad["chain"],
            "origin_bundle": rb_feh_bad["origin_bundle"],
            "trusted_origin_issuer_pins": rb_feh_bad["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017 P0-4: Truncated B_1 history with first_error_height == h_13 + D - 1 inside cancel window MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )

    # A15. Historical resolve_name at_height < h_13 (untruncated) ADMITS; truncated with later first_error_height refuses NAME_HISTORY_UNAVAILABLE (H2); at_height == h_13 without origin_bundle refuses ORIGIN_STATUS_INCOMPLETE
    add(
        "d11-0x13-resolve-name-before-h13-with-later-feh-admit",
        ["SL-ORIG-017", "SL-LDGR-010"],
        "name_resolve",
        {"at_height": 749599, "chain": rb_none["chain"], "name": "id/alice-v1"},
        "ADMIT",
        None,
        "SL-ORIG-017: Historical resolve_name at at_height == h_13 - 1 succeeds on untruncated lineage despite later confirmed 0x13.",
    )
    add(
        "d11-0x13-resolve-name-at-h13-without-origin-incomplete",
        ["SL-ORIG-017", "SL-LDGR-010"],
        "name_resolve",
        {"at_height": 749600, "chain": rb_none["chain"], "name": "id/alice-v1"},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: resolve_name at at_height == h_13 without origin_bundle MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )

    # A16. verify_assent full NamePin equality (P0-1): superseded B_1 refuses ORIGIN_BINDING_INVALID while active B_2 admits!
    c_p01_seal = {"kind": "key", "pk": _kp("p01-cseal")["comp"]}
    c_p01_b1 = {
        "clause_commitments": [sl.clause_commit(_h32("p01-s"), {"text": "Agree"})],
        "contract_salt": _h32("p01-cs"), "genesis": GENESIS_MAIN, "network": "main",
        "parties": [
            {"name_pin": {"name": "id/alice-v1", "owner_policy": rb_none["_b1_pol"], "registration": rb_none["_b1"]["registration"]}, "party_id": "p1", "role": "client", "signing_policy": {"m": 1, "pks": [rb_none["_b1_gr"]["xonly"]]}},
            {"party_id": "p2", "role": "worker", "signing_policy": {"m": 1, "pks": [rb_none["_b2_gr"]["xonly"]]}},
        ],
        "profile": "org.seallink/generic-v1",
        "seal": {"script_policy": c_p01_seal, "txid": _h32("p01-cseal-tx"), "vout": 0},
        "type": "seallink-contract/1", "window": {"not_after_height": 760000, "not_before_height": 749000},
    }
    # Give B_1 a live link.grant update after T_rebind so resolve_name passes and verify_assent reaches _name_pin_equal!
    rb_ass = copy.deepcopy(rb_none)
    prev_b1_a = rb_ass["chain"]["names"]["id/alice-v1"]["updates"][-1]
    rb_ass["chain"]["names"]["id/alice-v1"]["updates"].append({
        "block_time": 1795218000, "confirmed_height": 749790, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_none["_b1_pol"])), name=b"id/alice-v1", value=sl.jcs_encode({"link": {"grant": rb_none["_b1_gr"]["xonly"]}})).hex(),
        "owner_policy": rb_none["_b1_pol"], "prev_input": {"sighash_bytes": [1], "txid": prev_b1_a["txid"], "vout": prev_b1_a["vout"], "witness_policy": rb_none["_b1_pol"]},
        "txid": _h32("p01-b1-repub"), "vout": 0,
    })
    ass_b1 = sl.sign_envelope({
        "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795219000, "network": "main",
        "nonce": _h32("p01-ass-b1"), "party_id": "p1", "party_name": "id/alice-v1", "party_role": "client",
        "target_id": sl.object_id(c_p01_b1), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
    }, [rb_none["_b1_gr"]["sk"]])
    add(
        "d11-p01-verify-assent-superseded-b1-refuse-binding-invalid",
        ["SL-ORIG-017", "SL-CONT-004"],
        "assent",
        {
            "assent": ass_b1, "chain": rb_ass["chain"], "contract": c_p01_b1,
            "origin_bundle": rb_ass["origin_bundle"], "trusted_origin_issuer_pins": rb_ass["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-017 P0-1: verify_assent MUST reject superseded B_1 binding via _name_pin_equal even if B_1 republishes link.grant.",
    )
    # And active B_2 admits assent!
    c_p01_b2 = copy.deepcopy(c_p01_b1)
    c_p01_b2["parties"][0] = {"name_pin": {"name": "id/alice-v2", "owner_policy": rb_none["_b2_pol"], "registration": rb_none["_b2"]["registration"]}, "party_id": "p1", "role": "client", "signing_policy": {"m": 1, "pks": [rb_none["_b2_gr"]["xonly"]]}}
    ass_b2 = sl.sign_envelope({
        "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795219000, "network": "main",
        "nonce": _h32("p01-ass-b2"), "party_id": "p1", "party_name": "id/alice-v2", "party_role": "client",
        "target_id": sl.object_id(c_p01_b2), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
    }, [rb_none["_b2_gr"]["sk"]])
    add(
        "d11-p01-verify-assent-active-b2-admit",
        ["SL-ORIG-017", "SL-CONT-004"],
        "assent",
        {
            "assent": ass_b2, "chain": rb_ass["chain"], "contract": c_p01_b2,
            "origin_bundle": rb_ass["origin_bundle"], "trusted_origin_issuer_pins": rb_ass["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "SL-ORIG-017 P0-1: verify_assent admits active matured B_2 binding matching _name_pin_equal.",
    )

    # =========================================================================
    # SECTION B: 0x14 LOG_CHECKPOINT, SMT, 4-MODE FRAUD & RELEASES (SL-CONT-012..013)
    # =========================================================================
    nlog = _build_log_ecosystem("nlog1", role="notary", with_4_checkpoints=True)
    rlog = _build_log_ecosystem("rlog1", role="release", with_4_checkpoints=True)

    # B1. Valid seq=1 (with genesis_seal + FencedJournal log-head replay_restart_check!), seq=2 (chaining from seq=1), seq=4 (terminal=True)
    add(
        "d11-0x14-checkpoint-seq1-and-journal-log-head-replay-admit",
        ["SL-CONT-012", "SL-GRNT-014"],
        "log_checkpoint",
        {
            "chain": nlog["chain_at_cp1"],
            "checkpoint": nlog["cp1_env"],
            "checkpoint_txid": nlog["cp1_tx"],
            "genesis_seal": nlog["gen_seal"],
            "journal": {"journal_id": _h32("d11-log-j1")},
            "replay_restart_check": True,
        },
        "ADMIT",
        None,
        "SL-CONT-012: Confirmed 0x14 seq=1 checkpoint verifies log_id, empty checkpoints_root, genesis_seal, and replays FencedJournal log-head.",
    )
    add(
        "d11-0x14-checkpoint-seq2-chained-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": nlog["chain_at_cp2"],
            "checkpoint": nlog["cp2_env"],
            "checkpoint_txid": nlog["cp2_tx"],
            "prev_checkpoint": nlog["cp1_env"],
            "prev_checkpoint_txid": nlog["cp1_tx"],
        },
        "ADMIT",
        None,
        "SL-CONT-012: Confirmed 0x14 seq=2 checkpoint verifies prev_checkpoint_id, next_log_vout, and acyclic checkpoints_root = C_0.",
    )
    add(
        "d11-0x14-checkpoint-seq4-terminal-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": nlog["chain"],
            "checkpoint": nlog["cp4_env"],
            "checkpoint_txid": nlog["cp4_tx"],
            "prev_checkpoint": nlog["cp3_env"],
            "prev_checkpoint_txid": nlog["cp3_tx"],
        },
        "ADMIT",
        None,
        "SL-CONT-012: Terminal 0x14 checkpoint (terminal=True, no next_log_vout) admits cleanly.",
    )

    # B2. O(1) log handover on seq == 1 (authenticated against predecessor_terminal_checkpoint!)
    ho_gen_tx = _h32("d11-ho-gen")
    ho_cp1_tx = _h32("d11-ho-cp1")
    ho_gen_op = {"txid": ho_gen_tx, "vout": 0}
    ho_lid = sl.compute_log_id("main", GENESIS_MAIN, "notary", nlog["iss_name"], nlog["iss_reg"], ho_gen_op)
    ho_cp1_p = {
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 0, "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": nlog["cp4_env"]["payload"]["denials_root"], "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": ho_gen_op,
        "issuer": nlog["iss_role_pin"], "log_id": ho_lid, "network": "main",
        "next_log_policy": nlog["seal_pol"], "next_log_vout": 0,
        "predecessor_log_id": nlog["log_id"], "predecessor_terminal_denials_root": nlog["cp4_env"]["payload"]["denials_root"],
        "prev_log_outpoint": ho_gen_op, "role": "notary", "seq": 1, "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }
    ho_cp1_env = sl.sign_envelope(ho_cp1_p, [nlog["iss_role"]["sk"]])
    ch_ho = copy.deepcopy(nlog["chain"])
    ch_ho["txs"][ho_gen_tx] = {"confirmed_height": 749995, "outputs": {"0": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"]), "spent_by_txid": ho_cp1_tx}}}
    ch_ho["txs"][ho_cp1_tx] = {"block_hash": _h32("d11-ho-blk"), "confirmed_height": 749999, "inputs": [sv.make_segwit_input(ho_gen_tx, 0)], "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(ho_cp1_env)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"])}}}
    ho_pred_term = {"checkpoint": nlog["cp4_env"], "checkpoint_txid": nlog["cp4_tx"]}
    add(
        "d11-0x14-o1-handover-seq1-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_ho, "checkpoint": ho_cp1_env, "checkpoint_txid": ho_cp1_tx, "predecessor_terminal_checkpoint": ho_pred_term},
        "ADMIT",
        None,
        "SL-CONT-012 P1: seq=1 O(1) log handover authenticated against predecessor_terminal_checkpoint with matching denials_root admits.",
    )
    ho_bad_p = dict(ho_cp1_p, denials_root=sl.SMT_EMPTY_ROOT)
    ho_bad_env = sl.sign_envelope(ho_bad_p, [nlog["iss_role"]["sk"]])
    ch_ho_bad = copy.deepcopy(ch_ho)
    ch_ho_bad["txs"][ho_cp1_tx]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(ho_bad_env)).hex()
    add(
        "d11-0x14-o1-handover-seq1-mismatch-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_ho_bad, "checkpoint": ho_bad_env, "checkpoint_txid": ho_cp1_tx, "predecessor_terminal_checkpoint": ho_pred_term},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 P1: seq=1 O(1) log handover dropping predecessor denials_root MUST refuse CHAIN_FRAME_INVALID.",
    )

    # B3. Stale checkpoint rollback against persisted journal log-head -> non-closing CHAIN_FRAME_INVALID (fresh/stateful parity!)
    add(
        "d11-0x14-checkpoint-journal-head-rollback-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": nlog["chain_at_cp2"],
            "checkpoint": nlog["cp1_env"],
            "checkpoint_txid": nlog["cp1_tx"],
            "journal": {
                "journal_id": _h32("d11-log-j-rb"),
                "log_heads": {
                    nlog["log_id"]: {
                        "block_hash": _h32("nlog1-blk-cp2"), "checkpoint_id": nlog["cp2_ca"],
                        "checkpoint_object_id": nlog["cp2_oid"],
                        "checkpoint_txid": nlog["cp2_tx"], "checkpoints_root": nlog["cp2_env"]["payload"]["checkpoints_root"],
                        "confirmed_height": 749990, "denials_root": sl.SMT_EMPTY_ROOT,
                        "log_id": nlog["log_id"], "max_seq": 2,
                        "next_log_outpoint": {"txid": nlog["cp2_tx"], "vout": 1},
                        "next_log_policy": nlog["seal_pol"],
                        "role": "notary", "terminal": False,
                    }
                },
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: Stale checkpoint with seq < persisted journal log_head.max_seq refuses non-closing CHAIN_FRAME_INVALID.",
    )

    # B4. 4-Mode seallink-log-fraud/1 + Unified 100% CLOSE!
    # Mode 1: equivocation (offline cp_b + post-fraud ticket immediately refuses NOTARY_LOG_COMPROMISED!)
    cp1_fork_p = dict(nlog["cp1_env"]["payload"], batch_count=0, batch_root=sl.EMPTY_BATCH_ROOT, cumulative_entries_count=0)
    cp1_fork_env = sl.sign_envelope(cp1_fork_p, [nlog["iss_role"]["sk"]])
    fraud_eq = {
        "cp_a": nlog["cp1_env"], "cp_a_txid": nlog["cp1_tx"], "cp_b": cp1_fork_env,
        "fraud_mode": "equivocation", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
        "log_id": nlog["log_id"], "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
    }
    post_tkt = {
        "artifact_identity": nlog["art"], "genesis": GENESIS_MAIN, "network": "main",
        "notarizations": [{
            "act_smt_proof": sl.smt_prove({}, nlog["denial_key"]),
            "batch_proof": nlog["b1_proof"],
            "checkpoint": nlog["cp1_env"], "checkpoint_txid": nlog["cp1_tx"],
            "notary_act": nlog["item_env"],
            "target_smt_proof": sl.smt_prove({}, f"target:{nlog['tid']}|*"),
        }],
        "target_sha256": nlog["tid"], "type": "seallink-ticket/1",
    }
    post_pol = {"allow_reinstatement": False, "mode": "standard", "quorum_m": 1, "required_claims": ["seallink.org/build-repro"], "trusted_notaries": [{"log_id": nlog["log_id"], "notary_pin": nlog["iss_pin"]}]}
    add(
        "d11-fraud-mode1-equivocation-and-unified-100pct-close",
        ["SL-CONT-012", "SL-ARTF-003"],
        "log_fraud",
        {
            "chain": nlog["chain_at_cp1"], "fraud": fraud_eq, "journal": {"journal_id": _h32("d11-f-eq-j")},
            "post_fraud_policy": post_pol, "post_fraud_ticket": post_tkt,
        },
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-CONT-012 P0-CORE-2: Proven equivocation fraud records log closure blocking 100% of subsequent tickets with NOTARY_LOG_COMPROMISED.",
        module="artifact-notarization",
    )
    # Identical checkpoint is NOT equivocation -> REFUSE CHAIN_FRAME_INVALID
    add(
        "d11-fraud-mode1-identical-cp-not-fraud-refuse",
        ["SL-CONT-012"],
        "log_fraud",
        {"chain": nlog["chain"], "fraud": dict(fraud_eq, cp_b=nlog["cp1_env"])},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: Identical cp_a == cp_b is NOT equivocation and MUST refuse CHAIN_FRAME_INVALID.",
    )

    # Mode 2: revocation_omission (both same-seq without checkpoints_proof AND descendant seq_b > seq_a!)
    ch_om = copy.deepcopy(nlog["chain"])
    cp3_om_p = dict(nlog["cp3_env"]["payload"], denials_root=sl.SMT_EMPTY_ROOT)  # omitted rev1 from denials_root!
    cp3_om_env = sl.sign_envelope(cp3_om_p, [nlog["iss_role"]["sk"]])
    cp3_om_ca = sl.content_addr(cp3_om_env)
    ch_om["txs"][nlog["cp3_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, cp3_om_ca).hex()
    fraud_om_same = {
        "batch_proof": nlog["b3_proof"], "cp_a": cp3_om_env, "cp_a_txid": nlog["cp3_tx"],
        "cp_b": cp3_om_env, "cp_b_txid": nlog["cp3_tx"], "fraud_mode": "revocation_omission",
        "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
        "log_id": nlog["log_id"], "network": "main",
        "revocation": nlog["rev1_env"], "role": "notary",
        "smt_proof": sl.smt_prove({}, nlog["denial_key"]), "type": "seallink-log-fraud/1",
    }
    add(
        "d11-fraud-mode2-revocation-omission-same-seq-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {"chain": ch_om, "fraud": fraud_om_same, "journal": {"journal_id": _h32("d11-f-om1-j")}},
        "ADMIT",
        None,
        "SL-CONT-012 P0-CORE-1: revocation_omission at seq_b == seq_a (no checkpoints_proof) proves fraud.",
    )
    leaves_om = nlog["leaves_2"] + [sl.ckpt_leaf(3, cp3_om_ca)]
    cp4_om_p = dict(nlog["cp4_env"]["payload"], prev_checkpoint_id=cp3_om_ca, checkpoints_root=sl.rfc9162_mth(leaves_om).hex(), denials_root=sl.SMT_EMPTY_ROOT)
    cp4_om_env = sl.sign_envelope(cp4_om_p, [nlog["iss_role"]["sk"]])
    ch_om["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_om_env)).hex()
    fraud_om_desc = {
        "batch_proof": nlog["b3_proof"], "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_om, 2),
        "cp_a": cp3_om_env, "cp_a_txid": nlog["cp3_tx"], "cp_b": cp4_om_env, "cp_b_txid": nlog["cp4_tx"],
        "fraud_mode": "revocation_omission", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
        "log_id": nlog["log_id"], "network": "main", "revocation": nlog["rev1_env"], "role": "notary",
        "smt_proof": sl.smt_prove({}, nlog["denial_key"]), "type": "seallink-log-fraud/1",
    }
    add(
        "d11-fraud-mode2-revocation-omission-descendant-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {"chain": ch_om, "fraud": fraud_om_desc, "journal": {"journal_id": _h32("d11-f-om2-j")}},
        "ADMIT",
        None,
        "SL-CONT-012 P0-CORE-1: revocation_omission across seq_b > seq_a with acyclic RFC 9162 checkpoints_proof proves fraud.",
    )

    # Mode 3: illegal_reversion — (3a) deletion to E, (3b) rollback, (3c) adjacent broken prev_record_id,
    # AND lawful revoke(1) -> reinstate(2) -> revoke(3) MUST NOT be treated as fraud!
    # (3a) deletion to E: cp3 has rev1 included, cp4 deletes back to SMT_EMPTY_ROOT!
    ch_del = copy.deepcopy(nlog["chain"])
    cp4_del_p = dict(nlog["cp4_env"]["payload"], denials_root=sl.SMT_EMPTY_ROOT)
    cp4_del_env = sl.sign_envelope(cp4_del_p, [nlog["iss_role"]["sk"]])
    ch_del["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_del_env)).hex()
    add(
        "d11-fraud-mode3a-illegal-deletion-to-empty-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": ch_del,
            "fraud": {
                "checkpoints_proof": sl.rfc9162_inclusion_proof(nlog["leaves_3"], 2),
                "cp_a": nlog["cp3_env"], "cp_a_txid": nlog["cp3_tx"],
                "cp_b": cp4_del_env, "cp_b_txid": nlog["cp4_tx"],
                "fraud_mode": "illegal_reversion", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "rec_a": nlog["rev1_env"], "role": "notary",
                "smt_proof_a": sl.smt_prove(nlog["kv3"], nlog["denial_key"]),
                "smt_proof_b": sl.smt_prove({}, nlog["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
            "journal": {"journal_id": _h32("d11-f-3a-j")},
        },
        "ADMIT",
        None,
        "SL-CONT-012 P0-CORE-2 (3a): Deleting a recorded SMT denial key back to E proves illegal_reversion fraud.",
    )
    # (3b) rollback: cp4 commits another seq=1 revocation replacing rev1!
    rev1_alt_env = sl.sign_envelope(dict(nlog["rev1_env"]["payload"], reason_code="alt-reason"), [nlog["iss_role"]["sk"]])
    kv4_rb = {nlog["denial_key"]: sl.content_addr(rev1_alt_env)}
    ch_3b = copy.deepcopy(nlog["chain"])
    cp4_3b_env = sl.sign_envelope(dict(nlog["cp4_env"]["payload"], denials_root=sl.smt_root(kv4_rb)), [nlog["iss_role"]["sk"]])
    ch_3b["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_3b_env)).hex()
    add(
        "d11-fraud-mode3b-state-seq-rollback-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": ch_3b,
            "fraud": {
                "checkpoints_proof": sl.rfc9162_inclusion_proof(nlog["leaves_3"], 2),
                "cp_a": nlog["cp3_env"], "cp_a_txid": nlog["cp3_tx"],
                "cp_b": cp4_3b_env, "cp_b_txid": nlog["cp4_tx"],
                "fraud_mode": "illegal_reversion", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "rec_a": nlog["rev1_env"], "rec_b": rev1_alt_env, "role": "notary",
                "smt_proof_a": sl.smt_prove(nlog["kv3"], nlog["denial_key"]),
                "smt_proof_b": sl.smt_prove(kv4_rb, nlog["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
        },
        "ADMIT",
        None,
        "SL-CONT-012 P0-CORE-2 (3b): Same/lower state_seq substitution proves illegal_reversion fraud.",
    )
    # (3c) adjacent broken prev_record_id (state_seq == prev + 1 with wrong prev_record_id)
    reinst2_bad_env = sl.sign_envelope(dict(nlog["reinst2_env"]["payload"], prev_record_id=_h32("wrong-prev")), [nlog["iss_role"]["sk"]])
    kv4_3c = {nlog["denial_key"]: sl.content_addr(reinst2_bad_env)}
    ch_3c = copy.deepcopy(nlog["chain"])
    cp4_3c_env = sl.sign_envelope(dict(nlog["cp4_env"]["payload"], denials_root=sl.smt_root(kv4_3c)), [nlog["iss_role"]["sk"]])
    ch_3c["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_3c_env)).hex()
    add(
        "d11-fraud-mode3c-adjacent-broken-prev-record-id-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": ch_3c,
            "fraud": {
                "checkpoints_proof": sl.rfc9162_inclusion_proof(nlog["leaves_3"], 2),
                "cp_a": nlog["cp3_env"], "cp_a_txid": nlog["cp3_tx"],
                "cp_b": cp4_3c_env, "cp_b_txid": nlog["cp4_tx"],
                "fraud_mode": "illegal_reversion", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "rec_a": nlog["rev1_env"], "rec_b": reinst2_bad_env, "role": "notary",
                "smt_proof_a": sl.smt_prove(nlog["kv3"], nlog["denial_key"]),
                "smt_proof_b": sl.smt_prove(kv4_3c, nlog["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
        },
        "ADMIT",
        None,
        "SL-CONT-012 P0-CORE-2 (3c): Adjacent state_seq == prev + 1 with mismatched prev_record_id proves illegal_reversion fraud.",
    )
    # Lawful multi-step revoke(1) -> reinstate(2) -> revoke(3): cp_a has rev1 (seq 1), cp_b has rev3 (seq 3, prev_record_id = reinst2) -> NOT fraud!
    kv4_ok3 = {nlog["denial_key"]: nlog["rev3_ca"]}
    ch_ok3 = copy.deepcopy(nlog["chain"])
    cp4_ok3_env = sl.sign_envelope(dict(nlog["cp4_env"]["payload"], denials_root=sl.smt_root(kv4_ok3)), [nlog["iss_role"]["sk"]])
    ch_ok3["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_ok3_env)).hex()
    add(
        "d11-fraud-mode3-lawful-revoke1-reinstate2-revoke3-not-fraud-refuse",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": ch_ok3,
            "fraud": {
                "checkpoints_proof": sl.rfc9162_inclusion_proof(nlog["leaves_3"], 2),
                "cp_a": nlog["cp3_env"], "cp_a_txid": nlog["cp3_tx"],
                "cp_b": cp4_ok3_env, "cp_b_txid": nlog["cp4_tx"],
                "fraud_mode": "illegal_reversion", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "rec_a": nlog["rev1_env"], "rec_b": nlog["rev3_env"], "role": "notary",
                "smt_proof_a": sl.smt_prove(nlog["kv3"], nlog["denial_key"]),
                "smt_proof_b": sl.smt_prove(kv4_ok3, nlog["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 P0-CORE-2: Lawful multi-step cycle revoke(1) -> reinstate(2) -> revoke(3) is NOT illegal_reversion fraud.",
    )

    # Mode 4: invalid_checkpoint_chain (seq == 1 bad checkpoints_root AND seq == 4 bad RFC 9162 append + peaks[]!)
    ch_m4_1 = copy.deepcopy(nlog["chain"])
    cp1_bad_cr = sl.sign_envelope(dict(nlog["cp1_env"]["payload"], checkpoints_root=_h32("forged-empty-cr")), [nlog["iss_role"]["sk"]])
    ch_m4_1["txs"][nlog["cp1_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp1_bad_cr)).hex()
    add(
        "d11-fraud-mode4-seq1-bad-checkpoints-root-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": ch_m4_1,
            "fraud": {
                "cp_next": cp1_bad_cr, "cp_next_txid": nlog["cp1_tx"], "fraud_mode": "invalid_checkpoint_chain",
                "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
            },
        },
        "ADMIT",
        None,
        "SL-CONT-012 P0-CORE-2: Mode 4 invalid_checkpoint_chain proves seq=1 non-empty checkpoints_root fraud.",
    )
    add(
        "d11-fraud-mode4-seq1-honest-not-fraud-refuse",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": nlog["chain"],
            "fraud": {
                "cp_next": nlog["cp1_env"], "cp_next_txid": nlog["cp1_tx"], "fraud_mode": "invalid_checkpoint_chain",
                "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 P0-CORE-2: Honest seq=1 checkpoint is NOT invalid_checkpoint_chain fraud.",
    )
    ch_m4_k = copy.deepcopy(nlog["chain"])
    cp4_bad_cr = sl.sign_envelope(dict(nlog["cp4_env"]["payload"], checkpoints_root=_h32("forged-cr-4")), [nlog["iss_role"]["sk"]])
    ch_m4_k["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_bad_cr)).hex()
    peaks_2 = sl.rfc9162_peaks(nlog["leaves_2"])  # k=4 -> k-2=2 -> popcount(2)==1 peak!
    add(
        "d11-fraud-mode4-seq4-peaks-bad-append-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": ch_m4_k,
            "fraud": {
                "cp_next": cp4_bad_cr, "cp_next_txid": nlog["cp4_tx"],
                "cp_prev": nlog["cp3_env"], "cp_prev_txid": nlog["cp3_tx"],
                "fraud_mode": "invalid_checkpoint_chain", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "peaks": peaks_2, "role": "notary", "type": "seallink-log-fraud/1",
            },
            "journal": {"journal_id": _h32("d11-f-m4-j")},
        },
        "ADMIT",
        None,
        "SL-CONT-012 P0-CORE-2: Mode 4 invalid_checkpoint_chain verifies RFC 9162 peaks[] decomposition and proves tampered cp_4.checkpoints_root.",
    )
    add(
        "d11-fraud-mode4-seq4-honest-not-fraud-refuse",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": nlog["chain"],
            "fraud": {
                "cp_next": nlog["cp4_env"], "cp_next_txid": nlog["cp4_tx"],
                "cp_prev": nlog["cp3_env"], "cp_prev_txid": nlog["cp3_tx"],
                "fraud_mode": "invalid_checkpoint_chain", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "peaks": peaks_2, "role": "notary", "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 P0-CORE-2: Honest seq=4 checkpoint matching append_rfc9162_leaf(peaks, 2, C_2) is NOT fraud.",
    )

    # B5. seallink-release/1 (eternal 0x09 + 0x0b release break + log_tracked 0x14 + reinstatement + non-canonical SMT sib == D[h-1]!)
    rel_et_p = {
        "artifact_identity": rlog["art"], "genesis": GENESIS_MAIN, "issuer": rlog["iss_role_pin"],
        "lifecycle": "eternal", "network": "main", "product_id": "works.relux/curator-cli",
        "release_seq": 4, "released_at": 1795218000, "target_sha256": rlog["tid"],
        "type": "seallink-release/1", "version_str": "1.1.0",
    }
    rel_et_env = sl.sign_envelope(rel_et_p, [rlog["iss_role"]["sk"]])
    rel_et_tx = _h32("d11-rel-et-0x09")
    ch_rel = copy.deepcopy(rlog["chain"])
    ch_rel["txs"][rel_et_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(rel_et_env)).hex(), "outputs": {}}
    add(
        "d11-release-eternal-0x09-admit",
        ["SL-CONT-013"],
        "release",
        {"anchor_txid": rel_et_tx, "chain": ch_rel, "release": rel_et_env},
        "ADMIT",
        None,
        "SL-CONT-013: Eternal seallink-release/1 anchored via 0x09 and signed by link.release admits.",
    )
    # 0x0b CredentialBreak(role="release") at h_c = 749500 closes rel_et_env!
    ch_rel_0b = copy.deepcopy(ch_rel)
    prev_ru = ch_rel_0b["names"][rlog["iss_name"]]["updates"][-1]
    brk_rel = {
        "compromised_policy": {"m": 1, "pks": [rlog["iss_role"]["xonly"]]},
        "genesis": GENESIS_MAIN, "h_c": 749500,
        "issuer": rlog["iss_pin"], "name_input": {"txid": prev_ru["txid"], "vout": prev_ru["vout"]},
        "role": "release", "type": "seallink-credential-break/1",
    }
    ch_rel_0b["names"][rlog["iss_name"]]["updates"].append({
        "block_time": 1795219500, "confirmed_height": 749600, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_rel).hex(), h_c=749500).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rlog["iss_pol"])), name=rlog["iss_name"].encode("utf-8"), value=b"{}").hex(),
        "owner_policy": rlog["iss_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_ru["txid"], "vout": prev_ru["vout"], "witness_policy": rlog["iss_pol"]},
        "txid": _h32("d11-rel-0x0b-tx"), "vout": 0,
    })
    add(
        "d11-release-0x0b-break-exact-hc-closed",
        ["SL-CONT-013", "SL-CONT-009"],
        "release",
        {"anchor_txid": rel_et_tx, "chain": ch_rel_0b, "release": rel_et_env},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "SL-CONT-013: 0x0b CredentialBreak(role='release') at exact h_c == h_anchor refuses CRED_ISSUER_CLOSED.",
    )
    # log_tracked release at head cp2 (clean), at head cp3 (revoked), at head cp4 (reinstated: allowed vs disallowed), and non-canonical SMT sib == D[h-1]!
    rel_ctx_ok = {
        "batch_proof": rlog["b1_proof"], "checkpoint": rlog["cp1_env"], "checkpoint_txid": rlog["cp1_tx"],
        "checkpoints_proof": rlog["cp1_in_cp2_proof"], "head_checkpoint": rlog["cp2_env"], "head_checkpoint_txid": rlog["cp2_tx"],
        "smt_proof": sl.smt_prove({}, rlog["denial_key"]),
    }
    add(
        "d11-release-log-tracked-admit",
        ["SL-CONT-013", "SL-CONT-012"],
        "release",
        {"chain": rlog["chain_at_cp2"], "log_ctx": rel_ctx_ok, "release": rlog["item_env"]},
        "ADMIT",
        None,
        "SL-CONT-013: log_tracked seallink-release/1 with 0x14 batch proof, checkpoints_proof, and SMT absence admits.",
    )
    # Non-canonical SMT proof (1-bit in bitmap supplying empty constant D[0]) MUST refuse CHAIN_FRAME_INVALID (P1)!
    bad_smt_canon = copy.deepcopy(rel_ctx_ok["smt_proof"])
    bad_smt_canon["bitmap_hex"] = "00" * 31 + "01"  # d=255 -> h=1 -> D[0]
    bad_smt_canon["siblings"] = [sl.SMT_DEFAULTS[0].hex()]
    add(
        "d11-smt-non-canonical-empty-sibling-refuse",
        ["SL-CONT-012"],
        "release",
        {"chain": rlog["chain_at_cp2"], "log_ctx": dict(rel_ctx_ok, smt_proof=bad_smt_canon), "release": rlog["item_env"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 P1: Non-canonical SmtProof supplying D[h-1] for a 1-bit in bitmap_hex MUST refuse CHAIN_FRAME_INVALID.",
    )
    # Reinstated in cp4: allow_reinstatement=True -> ADMIT, allow_reinstatement=False -> CRED_REVOKED_FOR_CAUSE
    rel_ctx_cp4 = {
        "batch_proof": rlog["b1_proof"], "checkpoint": rlog["cp1_env"], "checkpoint_txid": rlog["cp1_tx"],
        "checkpoints_proof": sl.rfc9162_inclusion_proof(rlog["leaves_3"], 0),
        "head_checkpoint": rlog["cp4_env"], "head_checkpoint_txid": rlog["cp4_tx"],
        "smt_proof": sl.smt_prove(rlog["kv4"], rlog["denial_key"]),
        "state_record": rlog["reinst2_env"],
    }
    add(
        "d11-release-reinstated-allowed-admit",
        ["SL-CONT-012", "SL-CONT-013"],
        "release",
        {"allow_reinstatement": True, "chain": rlog["chain"], "log_ctx": rel_ctx_cp4, "release": rlog["item_env"]},
        "ADMIT",
        None,
        "SL-CONT-012: Reinstated log_tracked release admits when allow_reinstatement=True (terminal checkpoint bypasses heartbeat).",
    )
    add(
        "d11-release-reinstated-disallowed-refuse",
        ["SL-CONT-012", "SL-CONT-013"],
        "release",
        {"allow_reinstatement": False, "chain": rlog["chain"], "log_ctx": rel_ctx_cp4, "release": rlog["item_env"]},
        "REFUSE",
        "CRED_REVOKED_FOR_CAUSE",
        "SL-CONT-012: Reinstated log_tracked release refuses CRED_REVOKED_FOR_CAUSE when allow_reinstatement=False.",
    )
    # Heartbeat stale on non-terminal cp2 (tip 750010 - h_cp2 749990 = 20 > max 19) vs exact boundary (20 == max 20)
    add(
        "d11-release-heartbeat-stale-refuse",
        ["SL-CONT-012"],
        "release",
        {"chain": rlog["chain_at_cp2"], "heartbeat_max_blocks": 19, "log_ctx": rel_ctx_ok, "release": rlog["item_env"]},
        "REFUSE",
        "CRED_WINDOW_CLOSED",
        "SL-CONT-012: Non-terminal log head older than heartbeat_max_blocks refuses CRED_WINDOW_CLOSED.",
    )
    add(
        "d11-release-heartbeat-exact-boundary-admit",
        ["SL-CONT-012"],
        "release",
        {"chain": rlog["chain_at_cp2"], "heartbeat_max_blocks": 20, "log_ctx": rel_ctx_ok, "release": rlog["item_env"]},
        "ADMIT",
        None,
        "SL-CONT-012: Non-terminal log head at exact tip_height - h_head == heartbeat_max_blocks admits.",
    )
    # log_tracked seallink-notary/1 direct test
    add(
        "d11-notary-act-artifact-log-tracked-admit",
        ["SL-CONT-011", "SL-CONT-012"],
        "notary_act",
        {
            "chain": nlog["chain_at_cp2"],
            "log_ctx": {
                "batch_proof": nlog["b1_proof"], "checkpoint": nlog["cp1_env"], "checkpoint_txid": nlog["cp1_tx"],
                "checkpoints_proof": nlog["cp1_in_cp2_proof"], "head_checkpoint": nlog["cp2_env"], "head_checkpoint_txid": nlog["cp2_tx"],
                "smt_proof": sl.smt_prove({}, nlog["denial_key"]),
            },
            "notary": nlog["item_env"],
        },
        "ADMIT",
        None,
        "SL-CONT-011/012: log_tracked artifact-notarization seallink-notary/1 verifies directly via 0x14 log_ctx.",
    )

    # =========================================================================
    # SECTION C: PROFILE-artifact-v1 GATEKEEPER & TIER-2 SPV (SL-ARTF-001..006)
    # =========================================================================
    # Build 3 notaries (n1=pass, n2=pass, n3=absent) + 1 release issuer on ONE shared chain for 2-of-3 Gatekeeper tests!
    n2 = _build_log_ecosystem("nlog2", role="notary")
    n3 = _build_log_ecosystem("nlog3", role="notary")
    # Re-target n1/n2/rlog onto the SAME fsverity-sha256 artifact (salt_hex = "")!
    fsv_art = {"digest": _h32("fsv-app-image"), "params": {"block_size": 4096, "hash_alg": "sha256", "salt_hex": "", "version": 1}, "scheme": "fsverity-sha256"}
    fsv_tid = sl.artifact_target_id(fsv_art)
    gk_chain = copy.deepcopy(nlog["chain"])
    gk_chain["names"].update(n2["chain"]["names"])
    gk_chain["names"].update(n3["chain"]["names"])
    gk_chain["names"].update(rlog["chain"]["names"])
    gk_chain["txs"].update(n2["chain"]["txs"])
    gk_chain["txs"].update(n3["chain"]["txs"])
    gk_chain["txs"].update(rlog["chain"]["txs"])

    def _mint_gk_notary(eco: dict[str, Any], tag: str, claims: list[dict[str, Any]], *, target_revoked: bool = False) -> dict[str, Any]:
        g_tx = _h32(f"gk-gen-{tag}")
        c_tx = _h32(f"gk-cp1-{tag}")
        lid = sl.compute_log_id("main", GENESIS_MAIN, "notary", eco["iss_name"], eco["iss_reg"], {"txid": g_tx, "vout": 0})
        na_p = {
            "act_kind": "artifact-notarization", "attested_at": 1795219500,
            "details": {"artifact_identity": fsv_art, "claims": claims, "kind": "artifact-notarization"},
            "genesis": GENESIS_MAIN, "lifecycle": "log_tracked", "log_id": lid, "network": "main",
            "notary": eco["iss_role_pin"], "target_sha256": fsv_tid,
            "tip_hash": gk_chain["tip_hash"], "tip_height": gk_chain["tip_height"], "type": "seallink-notary/1",
        }
        na_env = sl.sign_envelope(na_p, [eco["iss_role"]["sk"]])
        na_id = sl.object_id(na_p)
        e1 = sl.log_entry_digest(0x01, sl.content_addr(na_env))
        entries = [e1]
        kv: dict[str, str] = {}
        t_rev_env = None
        if target_revoked:
            t_rev_p = {
                "denial_key": f"target:{fsv_tid}|*", "genesis": GENESIS_MAIN, "issued_at": 1795219600,
                "issuer": eco["iss_role_pin"], "log_id": lid, "network": "main",
                "reason_code": "malware-detected", "role": "notary", "state_seq": 1, "type": "seallink-log-revocation/1",
            }
            t_rev_env = sl.sign_envelope(t_rev_p, [eco["iss_role"]["sk"]])
            entries.append(sl.log_entry_digest(0x02, sl.content_addr(t_rev_env)))
            kv[f"target:{fsv_tid}|*"] = sl.content_addr(t_rev_env)
        b_root, b_proofs = sl.build_log_batch_root(entries)
        d_root = sl.build_log_batch_root([entries[1]])[0] if target_revoked else sl.EMPTY_BATCH_ROOT
        cp_p = {
            "batch_count": len(entries), "batch_root": b_root, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
            "cumulative_entries_count": len(entries), "denials_delta_root": d_root,
            "denials_root": sl.smt_root(kv), "genesis": GENESIS_MAIN,
            "genesis_seal_outpoint": {"txid": g_tx, "vout": 0},
            "issuer": eco["iss_role_pin"],
            "log_id": lid, "network": "main", "prev_log_outpoint": {"txid": g_tx, "vout": 0},
            "role": "notary", "seq": 1, "terminal": True, "type": "seallink-log-checkpoint/1",
        }
        cp_env = sl.sign_envelope(cp_p, [eco["iss_role"]["sk"]])
        gk_chain["txs"][g_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(eco["seal_pol"]), "spent_by_txid": c_tx}}}
        gk_chain["txs"][c_tx] = {"block_hash": _h32(f"gk-blk-{tag}"), "confirmed_height": 749995, "inputs": [sv.make_segwit_input(g_tx, 0)], "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(cp_env)).hex(), "outputs": {}}
        entry = {
            "act_smt_proof": sl.smt_prove(kv, f"act:{na_id}|*"),
            "batch_proof": b_proofs[e1],
            "checkpoint": cp_env, "checkpoint_txid": c_tx,
            "notary_act": na_env,
            "target_smt_proof": sl.smt_prove(kv, f"target:{fsv_tid}|*"),
        }
        if t_rev_env is not None:
            entry["target_state_record"] = t_rev_env
        return {"entry": entry, "cp_env": cp_env, "cp_tx": c_tx, "kv": kv, "log_id": lid, "pin": eco["iss_pin"], "t_rev": t_rev_env}

    gn1 = _mint_gk_notary(nlog, "n1", [{"claim_id": "seallink.org/build-repro", "verdict": "pass"}])
    gn2 = _mint_gk_notary(n2, "n2", [{"claim_id": "seallink.org/build-repro", "verdict": "pass"}])
    gn2_inc = _mint_gk_notary(n2, "n2-inc", [{"claim_id": "seallink.org/build-repro", "verdict": "inconclusive"}])
    gn2_fail = _mint_gk_notary(n2, "n2-fail", [{"claim_id": "seallink.org/build-repro", "verdict": "fail"}])
    gn3_clean = _mint_gk_notary(n3, "n3-clean", [{"claim_id": "seallink.org/build-repro", "verdict": "pass"}])
    gn3_veto = _mint_gk_notary(n3, "n3-veto", [{"claim_id": "seallink.org/build-repro", "verdict": "fail"}], target_revoked=True)

    # Mint matching eternal release for fsv_art
    gk_rel_p = {
        "artifact_identity": fsv_art, "genesis": GENESIS_MAIN, "issuer": rlog["iss_role_pin"],
        "lifecycle": "eternal", "network": "main", "product_id": "works.relux/curator-cli",
        "release_seq": 10, "released_at": 1795219000, "target_sha256": fsv_tid,
        "type": "seallink-release/1", "version_str": "2.0.0",
    }
    gk_rel_env = sl.sign_envelope(gk_rel_p, [rlog["iss_role"]["sk"]])
    gk_rel_tx = _h32("gk-rel-0x09")
    gk_chain["txs"][gk_rel_tx] = {"confirmed_height": 749992, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(gk_rel_env)).hex(), "outputs": {}}

    gk_pol_hardened = {
        "allow_reinstatement": False, "mode": "hardened", "quorum_m": 2,
        "release_floor": {"works.relux/curator-cli": 10}, "require_release": True,
        "required_claims": ["seallink.org/build-repro"],
        "trusted_notaries": [
            {"log_id": gn1["log_id"], "notary_pin": gn1["pin"]},
            {"log_id": gn2["log_id"], "notary_pin": gn2["pin"]},
            {"log_id": gn3_clean["log_id"], "notary_pin": gn3_clean["pin"]},
        ],
        "trusted_release_issuers": [{"allowed_product_prefixes": ["works.relux/"], "issuer_pin": rlog["iss_pin"]}],
    }
    gk_ticket_2of3 = {
        "absent_notary_proofs": [{
            "head_checkpoint": gn3_clean["cp_env"], "head_checkpoint_txid": gn3_clean["cp_tx"],
            "log_id": gn3_clean["log_id"], "target_smt_proof": sl.smt_prove({}, f"target:{fsv_tid}|*"),
        }],
        "artifact_identity": fsv_art, "genesis": GENESIS_MAIN, "network": "main",
        "notarizations": [gn1["entry"], gn2["entry"]],
        "release": gk_rel_env, "release_anchor_txid": gk_rel_tx,
        "target_sha256": fsv_tid, "type": "seallink-ticket/1",
    }

    # C1. Core-only module gate (SL-ARTF-001) -> ACTION_UNSUPPORTED on seallink-ticket/1!
    add(
        "d11-artf-core-only-ticket-action-unsupported",
        ["SL-ARTF-001", "SL-WIRE-018"],
        "artifact_ticket",
        {"chain": gk_chain, "enabled_modules": ["core"], "policy": gk_pol_hardened, "ticket": gk_ticket_2of3},
        "REFUSE",
        "ACTION_UNSUPPORTED",
        "SL-ARTF-001: Core-only verifier without 'artifact-notarization' module MUST refuse seallink-ticket/1 with ACTION_UNSUPPORTED.",
        module="core",
    )

    # C2. Hardened 2-of-3 quorum + fsverity-sha256 + release_floor exact equality + absent_notary_proof -> ADMIT!
    add(
        "d11-artf-hardened-2of3-fsverity-and-release-floor-admit",
        ["SL-ARTF-002", "SL-ARTF-003", "SL-ARTF-004"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": gk_ticket_2of3},
        "ADMIT",
        None,
        "SL-ARTF-002..004: Hardened 2-of-3 ticket with fsverity-sha256 (salt_hex=''), exact release_floor=10, and absent_notary_proof admits.",
        module="artifact-notarization",
    )

    # C3. Hardened mode omitting absent_notary_proof -> TICKET_PROOF_INVALID
    tkt_no_abs = copy.deepcopy(gk_ticket_2of3)
    tkt_no_abs.pop("absent_notary_proofs")
    add(
        "d11-artf-hardened-missing-absent-proof-refuse",
        ["SL-ARTF-004"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": tkt_no_abs},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-004: Hardened mode MUST require absent_notary_proof for every absent trusted notary with pinned log_id.",
        module="artifact-notarization",
    )

    # C4. Absent-notary target:<target_id>|* veto -> ARTIFACT_POLICY_DENIED!
    pol_veto = copy.deepcopy(gk_pol_hardened)
    pol_veto["trusted_notaries"][2]["log_id"] = gn3_veto["log_id"]
    tkt_veto = copy.deepcopy(gk_ticket_2of3)
    tkt_veto["absent_notary_proofs"] = [{
        "head_checkpoint": gn3_veto["cp_env"], "head_checkpoint_txid": gn3_veto["cp_tx"],
        "log_id": gn3_veto["log_id"], "target_smt_proof": sl.smt_prove(gn3_veto["kv"], f"target:{fsv_tid}|*"),
        "target_state_record": gn3_veto["t_rev"],
    }]
    add(
        "d11-artf-absent-notary-target-veto-refuse",
        ["SL-ARTF-004"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": pol_veto, "ticket": tkt_veto},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-004: Absent notary's target:<target_id>|* revocation vetoes ticket (deny-wins -> ARTIFACT_POLICY_DENIED).",
        module="artifact-notarization",
    )

    # C5. verdict = "inconclusive" abstains: 1 pass + 1 inconclusive -> ADMIT under quorum_m=1, REFUSE under quorum_m=2!
    pol_inc = copy.deepcopy(gk_pol_hardened)
    pol_inc["mode"] = "standard"
    pol_inc["quorum_m"] = 1
    pol_inc["trusted_notaries"] = [{"log_id": gn1["log_id"], "notary_pin": gn1["pin"]}, {"log_id": gn2_inc["log_id"], "notary_pin": gn2_inc["pin"]}]
    tkt_inc = copy.deepcopy(tkt_no_abs)
    tkt_inc["notarizations"] = [gn1["entry"], gn2_inc["entry"]]
    add(
        "d11-artf-verdict-inconclusive-abstains-quorum1-admit",
        ["SL-ARTF-004"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": pol_inc, "ticket": tkt_inc},
        "ADMIT",
        None,
        "SL-ARTF-004 P1: verdict='inconclusive' abstains (does NOT trigger deny-wins veto); 1 pass satisfies quorum_m=1.",
        module="artifact-notarization",
    )
    add(
        "d11-artf-verdict-inconclusive-not-pass-quorum2-refuse",
        ["SL-ARTF-004"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": dict(pol_inc, quorum_m=2), "ticket": tkt_inc},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-004 P1: verdict='inconclusive' does NOT count as a pass vote; 1 pass + 1 inconclusive fails quorum_m=2.",
        module="artifact-notarization",
    )

    # C6. verdict = "fail" -> immediate ARTIFACT_POLICY_DENIED even under quorum_m=1!
    pol_fail = copy.deepcopy(pol_inc)
    pol_fail["trusted_notaries"][1]["log_id"] = gn2_fail["log_id"]
    tkt_fail = copy.deepcopy(tkt_inc)
    tkt_fail["notarizations"] = [gn1["entry"], gn2_fail["entry"]]
    add(
        "d11-artf-verdict-fail-veto-refuse",
        ["SL-ARTF-004"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": pol_fail, "ticket": tkt_fail},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-004: verdict='fail' from a trusted notary triggers immediate deny-wins ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )

    # C7. release_floor violation, release-only ticket (notarizations=[]), bootstrap_expires_at (expired & hardened ban), provisional gossip deny-wins, fsverity non-empty salt_hex ban
    add(
        "d11-artf-release-floor-below-refuse",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": dict(gk_pol_hardened, release_floor={"works.relux/curator-cli": 11}), "ticket": gk_ticket_2of3},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: release_seq (10) < release_floor (11) MUST refuse ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )
    tkt_rel_only = {
        "artifact_identity": fsv_art, "genesis": GENESIS_MAIN, "network": "main",
        "notarizations": [], "release": gk_rel_env, "release_anchor_txid": gk_rel_tx,
        "target_sha256": fsv_tid, "type": "seallink-ticket/1",
    }
    pol_rel_only = {
        "allow_reinstatement": False, "bootstrap_expires_at": 1795220011, "mode": "standard", "quorum_m": 0,
        "require_release": True, "required_claims": [], "trusted_notaries": [],
        "trusted_release_issuers": [{"allowed_product_prefixes": ["works.relux/"], "issuer_pin": rlog["iss_pin"]}],
    }
    add(
        "d11-artf-release-only-ticket-bootstrap-valid-admit",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": pol_rel_only, "ticket": tkt_rel_only},
        "ADMIT",
        None,
        "SL-ARTF-003: Release-only ticket (notarizations=[]) in standard bootstrap posture before bootstrap_expires_at admits.",
        module="artifact-notarization",
    )
    add(
        "d11-artf-bootstrap-expired-exact-refuse",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": dict(pol_rel_only, bootstrap_expires_at=1795220010), "ticket": tkt_rel_only},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: Exact now == bootstrap_expires_at MUST refuse ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )
    add(
        "d11-artf-hardened-bootstrap-forbidden-wire-member",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": dict(gk_pol_hardened, bootstrap_expires_at=1799999999), "ticket": gk_ticket_2of3},
        "REFUSE",
        "WIRE_MEMBER",
        "SL-ARTF-003: GatekeeperPolicy mode='hardened' forbids bootstrap_expires_at at schema level (WIRE_MEMBER).",
        module="artifact-notarization",
    )
    # Provisional gossip deny-wins (signed by trusted notary live key) -> ARTIFACT_POLICY_DENIED!
    gossip_rev = sl.sign_envelope({
        "denial_key": f"target:{fsv_tid}|*", "genesis": GENESIS_MAIN, "issued_at": 1795219990,
        "issuer": nlog["iss_role_pin"], "log_id": gn1["log_id"], "network": "main",
        "reason_code": "emergency-gossip-halt", "role": "notary", "state_seq": 1, "type": "seallink-log-revocation/1",
    }, [nlog["iss_role"]["sk"]])
    add(
        "d11-artf-provisional-gossip-deny-wins-refuse",
        ["SL-ARTF-003", "SL-CONT-012"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "provisional_revocations": [gossip_rev], "ticket": gk_ticket_2of3},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: Live-signed provisional gossip target: revocation immediately refuses ARTIFACT_POLICY_DENIED (deny-wins).",
        module="artifact-notarization",
    )
    # fsverity-sha256 with non-empty salt_hex MUST refuse WIRE_MEMBER!
    bad_fsv_tkt = copy.deepcopy(tkt_rel_only)
    bad_fsv_tkt["artifact_identity"] = {"digest": fsv_art["digest"], "params": {"block_size": 4096, "hash_alg": "sha256", "salt_hex": "aa", "version": 1}, "scheme": "fsverity-sha256"}
    add(
        "d11-artf-fsverity-non-empty-salt-wire-member",
        ["SL-ARTF-002"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": pol_rel_only, "ticket": bad_fsv_tkt},
        "REFUSE",
        "WIRE_MEMBER",
        "SL-ARTF-002: fsverity-sha256 with non-empty salt_hex MUST refuse WIRE_MEMBER.",
        module="artifact-notarization",
    )

    # C8. Tier-2 Consensus-Exact SegWitNameUpdateProof (P0-CONS-1):
    #     P2WPKH low-S (ADMIT), P2WPKH consensus high-S (ADMIT!), P2WSH 2-of-2 multisig (ADMIT!),
    #     core-only ACTION_UNSUPPORTED, 64B leaf attack, wrong nVersion, non-SIGHASH_ALL, AuxPoW & retarget!
    spv_k1, spv_k2 = _kp("spv-own-1"), _kp("spv-own-2")
    spv_p2wpkh = {"kind": "key", "pk": spv_k1["comp"]}
    spv_p2wsh_pks = sorted([spv_k1["comp"], spv_k2["comp"]])
    spv_p2wsh_sks = [spv_k1["sk"], spv_k2["sk"]] if spv_k1["comp"] < spv_k2["comp"] else [spv_k2["sk"], spv_k1["sk"]]
    spv_p2wsh = {"kind": "multisig", "m": 2, "pks": spv_p2wsh_pks}

    proof_low, hdr_low = _build_synthetic_spv_proof("lows", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', high_s=False)
    proof_high, _ = _build_synthetic_spv_proof("highs", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', high_s=True)
    proof_ms, _ = _build_synthetic_spv_proof("p2wsh", spv_p2wsh, spv_p2wsh_sks, "id/spv-ms", '{"link":{}}', high_s=False)
    proof_bad_ver, _ = _build_synthetic_spv_proof("badver", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', tx_version=2)
    proof_bad_sh, _ = _build_synthetic_spv_proof("badsh", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', sighash_byte=0x81)

    def _mk_page(
        nm: str,
        upds: list[dict[str, Any]],
        *,
        limit: int = 10,
        registration: dict[str, Any] | None = None,
        cursor_height: int | None = None,
        cursor_txid: str | None = None,
        cursor_vout: int | None = None,
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
                reg = {"txid": _h32(f"spv-reg-{nm}"), "vout": 0}
        pg: dict[str, Any] = {
            "genesis": GENESIS_MAIN, "has_more": has_more, "limit": limit, "name": nm,
            "network": "main", "registration": reg,
            "type": "seallink-tier2-name-history/1", "updates": upds,
        }
        if cursor_height is not None:
            pg["cursor_height"] = cursor_height
        if cursor_txid is not None:
            pg["cursor_txid"] = cursor_txid
        if cursor_vout is not None:
            pg["cursor_vout"] = cursor_vout
        if next_cursor is not None:
            pg["next_cursor"] = next_cursor
        return pg

    page_low = _mk_page("id/spv-notary", [proof_low])
    add(
        "d11-tier2-core-only-action-unsupported",
        ["SL-ARTF-001"],
        "tier2_name_history",
        {"enabled_modules": ["core"], "expected_owner_policy": spv_p2wpkh, "page": page_low},
        "REFUSE",
        "ACTION_UNSUPPORTED",
        "SL-ARTF-001: Core-only verifier MUST refuse seallink-tier2-name-history/1 with ACTION_UNSUPPORTED.",
        module="core",
    )
    add(
        "d11-tier2-spv-p2wpkh-low-s-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "headers": [{"header_hex": hdr_low.hex(), "height": 750010}], "page": {**page_low, "network": "regtest"}, "pinned_network": "regtest"},
        "ADMIT",
        None,
        "SL-ARTF-005: Consensus-exact Tier-2 P2WPKH SegWitNameUpdateProof (low-S BIP-66 DER + SIGHASH_ALL + valid header PoW) admits.",
        module="artifact-notarization",
    )
    add(
        "d11-tier2-spv-p2wpkh-consensus-high-s-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_high])},
        "ADMIT",
        None,
        "SL-ARTF-005 P0-CONS-1: Consensus-valid high-S (S > N/2) BIP-66 DER signature mined on chain MUST be accepted by Tier-2 verifier.",
        module="artifact-notarization",
    )
    add(
        "d11-tier2-spv-p2wsh-multisig-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wsh, "page": _mk_page("id/spv-ms", [proof_ms])},
        "ADMIT",
        None,
        "SL-ARTF-005: Consensus-exact Tier-2 P2WSH 2-of-2 multisig SegWitNameUpdateProof admits.",
        module="artifact-notarization",
    )
    add(
        "d11-tier2-spv-bad-nversion-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_bad_ver])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: SegWitNameUpdateProof with nVersion != 0x7100 MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d11-tier2-spv-non-sighash-all-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_bad_sh])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: SegWitNameUpdateProof with non-SIGHASH_ALL (0x81) MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    # Truncated txid_branch (64B / shallow Merkle depth attack!) -> TICKET_PROOF_INVALID
    proof_shallow = copy.deepcopy(proof_low)
    proof_shallow["txid_branch"] = proof_low["txid_branch"][:1]
    proof_shallow["coinbase_merkle_branch"] = proof_low["coinbase_merkle_branch"] + ["00" * 32]
    add(
        "d11-tier2-spv-depth-mismatch-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_shallow])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Mismatched Merkle depth (anti-64B forgery defense) MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # C9. Namecoin AuxPoW (CAuxPow::check) + Epoch Boundary Retarget (H = 2016) positive & negative!
    def _mine_regtest_hdr(ver: int, prev_le: bytes, merkle_le: bytes, ntime: int, nbits: int = 0x207FFFFF) -> bytes:
        tgt = sl.bits_to_target(nbits)
        for nonce in range(100000):
            cand = struct.pack("<I", ver) + prev_le + merkle_le + struct.pack("<III", ntime, nbits, nonce)
            if int.from_bytes(sl.dsha256(cand), "little") <= tgt:
                return cand
        raise AssertionError("regtest header mine failed")

    aux_ver = (0x0001 << 16) | 0x00000100 | 2
    nmc_nonaux_ver = (0x0001 << 16) | 2
    prev_hdr_2015 = _mine_regtest_hdr(nmc_nonaux_ver, b"\x00" * 32, b"\x11" * 32, 1795000000 + 604800, 0x207FFFFF)
    prev_hash_2015_le = sl.dsha256(prev_hdr_2015)
    exp_bits_2016 = sl.compute_namecoin_next_bits(0x207FFFFF, 1795000000, 1795000000 + 604800, network="regtest")
    hdr_2016 = struct.pack("<I", aux_ver) + prev_hash_2015_le + bytes.fromhex(proof_low["block_header_hex"])[36:68] + struct.pack("<III", 1795000000 + 605400, exp_bits_2016, 0)
    bhash_2016_le = sl.dsha256(hdr_2016)
    # Build valid AuxPoW with chain_merkle_size=1, nonce=0 -> aux_root = bhash_2016_le (reversed in scriptSig!)
    parent_cb = _encode_raw_tx(
        2,
        [{"prev_txid": "00" * 32, "prev_vout": 0xFFFFFFFF, "script_sig": b"\x04\x01\x02\x03\x04\xfa\xbe\x6d\x6d" + bhash_2016_le[::-1] + struct.pack("<II", 1, 0)}],
        [(5_000_000_000, b"\x00\x14" + (b"\x77" * 20))],
    )
    parent_cb_txid_le = sl.parse_raw_tx(parent_cb)["txid_le"]
    parent_hdr = _mine_regtest_hdr(2, b"\x00" * 32, parent_cb_txid_le, 1795000000 + 605400, 0x207FFFFF)
    aux_proof_ok = {
        "chain_branch": [], "chain_merkle_nonce": 0, "chain_merkle_size": 1,
        "coinbase_branch": [], "parent_coinbase_hex": parent_cb.hex(), "parent_header_hex": parent_hdr.hex(),
    }
    page_reg_empty = {**_mk_page("id/spv-notary", []), "network": "regtest"}
    add(
        "d11-tier2-auxpow-and-retarget-2016-admit",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [
                {"header_hex": prev_hdr_2015.hex(), "height": 2015},
                {"auxpow": aux_proof_ok, "epoch_start_time": 1795000000, "header_hex": hdr_2016.hex(), "height": 2016},
            ],
            "page": page_reg_empty,
            "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "SL-ARTF-006 P0-CONS-1: Valid Namecoin AuxPoW (chain_id=1, fabe6d6d, GetExpectedIndex) + epoch-2016 retarget admits.",
        module="artifact-notarization",
    )
    # Real retarget failure at H=2016: valid non-AuxPoW regtest PoW with wrong nBits (0x203fffff != exp 0x207fffff)!
    hdr_2016_bad_bits = _mine_regtest_hdr(nmc_nonaux_ver, prev_hash_2015_le, bytes.fromhex(proof_low["block_header_hex"])[36:68], 1795000000 + 605400, 0x203FFFFF)
    add(
        "d11-tier2-retarget-2016-bad-bits-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [
                {"header_hex": prev_hdr_2015.hex(), "height": 2015},
                {"epoch_start_time": 1795000000, "header_hex": hdr_2016_bad_bits.hex(), "height": 2016},
            ],
            "page": page_reg_empty,
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 P0-CONS-1: Valid PoW header with invalid Namecoin retarget nBits at H % 2016 == 0 MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # =========================================================================
    # SECTION D: EXHAUSTIVE MUTATION-CLOSURE & EXACT BOUNDARY MATRIX
    # =========================================================================

    # D1. resolve_name first_error_height empty filtered updates -> NAME_HISTORY_UNAVAILABLE (L1978)
    rn_empty_fx = rm._base_invocation_fixture()
    rn_fu_h = rn_empty_fx["chain"]["names"]["id/alice"]["updates"][0]["confirmed_height"]
    rn_empty_fx["chain"]["names"]["id/alice"]["history_truncated"] = True
    rn_empty_fx["chain"]["names"]["id/alice"]["first_error_height"] = rn_fu_h
    add(
        "d11-mut-resolve-name-feh-empty-updates-unavailable",
        ["SL-LDGR-015"],
        "name_resolve",
        {
            "at_height": rn_fu_h - 1,
            "chain": rn_empty_fx["chain"],
            "name": "id/alice",
        },
        "REFUSE",
        "NAME_HISTORY_UNAVAILABLE",
        "SL-LDGR-015: first_error_height <= firstupdate height leaves zero updates < feh -> NAME_HISTORY_UNAVAILABLE.",
    )

    # D2. pending_rec truncated B_1 history (both mid-window and same-block h_rec == eval_h) -> ORIGIN_STATUS_INCOMPLETE
    of_pr_tr = rm._base_origin_fixture()
    nr_tr = of_pr_tr["origin_bundle"]["origin"]["payload"]["name_recovery"]
    b1_tr = of_pr_tr["origin_bundle"]["name_binding"]
    rec_cand_tr = {
        "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": "id/child-leo-rec-tr", "network": "main",
        "next_recovery_policy": nr_tr["recovery_seal"]["script_policy"], "next_recovery_vout": 0,
        "origin_id": of_pr_tr["_origin_id"], "owner_policy": b1_tr["owner_policy"],
        "registration": {"txid": _h32("pr-tr-reg"), "vout": 0}, "seq": 2,
        "supersedes_binding_id": sl.object_id(b1_tr), "type": "seallink-name-binding/1",
    }
    rec_tr_tx = _h32("pr-tr-0x0c")
    rseal_tr = nr_tr["recovery_seal"]
    of_pr_tr["chain"]["txs"][rseal_tr["txid"]]["outputs"][str(rseal_tr["vout"])]["spent_by_txid"] = rec_tr_tx
    of_pr_tr["chain"]["txs"][rec_tr_tx] = {
        "confirmed_height": 749500,
        "inputs": [sv.make_segwit_input(rseal_tr["txid"], rseal_tr["vout"])],
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(rec_cand_tr)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(rseal_tr["script_policy"])}},
    }
    of_pr_tr["origin_bundle"]["recovery_bindings"] = [rec_cand_tr]
    of_pr_tr["chain"]["names"]["id/child-leo"]["history_truncated"] = True
    of_pr_tr_sb = copy.deepcopy(of_pr_tr)
    of_pr_tr["chain"]["names"]["id/child-leo"]["first_error_height"] = 749505  # > h_rec (749500) so Phase 4b passes and next loop iter hits L3774!
    add(
        "d11-mut-pending-rec-truncated-b1-history-incomplete",
        ["SL-ORIG-015"],
        "origin_status",
        {"chain": of_pr_tr["chain"], "origin_bundle": of_pr_tr["origin_bundle"], "trusted_origin_issuer_pins": of_pr_tr["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-015: Pending 0x0c recovery with mid-window truncated B_1 history (feh=749505) MUST fail closed ORIGIN_STATUS_INCOMPLETE.",
    )
    rm.sync_chain_tip(of_pr_tr_sb["chain"], height=749500, tip_hash=_h32("pr-tr-sb-tip"))
    add(
        "d11-mut-pending-rec-same-block-truncated-b1-incomplete",
        ["SL-ORIG-015"],
        "origin_status",
        {"chain": of_pr_tr_sb["chain"], "origin_bundle": of_pr_tr_sb["origin_bundle"], "trusted_origin_issuer_pins": of_pr_tr_sb["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-015: Same-block 0x0c at tip with truncated B_1 history MUST fail closed ORIGIN_STATUS_INCOMPLETE in Phase 4b.",
    )

    # D3. Unresolved 0x13 without link.origin / origin_bundle in verify_assent AND _verify_backing_grant_chain -> ORIGIN_STATUS_INCOMPLETE
    as_no_oid = rm._base_invocation_fixture()
    al_upds = as_no_oid["chain"]["names"]["id/alice"]["updates"]
    prev_al = al_upds[-1]
    al_13_tx = _h32("al-no-oid-0x13")
    al_upds.append({
        "block_time": 1795219500, "confirmed_height": 749990, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x13, _h32("unseen-b2")).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(as_no_oid["_alice_owner_pol"])), name=b"id/alice", value=b"{}").hex(),
        "owner_policy": as_no_oid["_alice_owner_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_al["txid"], "vout": prev_al["vout"], "witness_policy": as_no_oid["_alice_owner_pol"]},
        "txid": al_13_tx, "version": 0x7100, "vout": 0,
    })
    add(
        "d11-mut-grant-unresolved-0x13-without-origin-incomplete",
        ["SL-ORIG-017"],
        "invocation",
        {
            "bundle": as_no_oid["bundle"], "chain": as_no_oid["chain"],
            "executor_cfg": as_no_oid["executor_cfg"], "invocation": as_no_oid["invocation"],
            "journal": as_no_oid["journal"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: Backing grant issuer with confirmed 0x13 and no origin_bundle MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )
    bob_mut_k = _kp("mut-ass-bob")
    c_no_oid = {
        "clause_commitments": [sl.clause_commit(_h32("cl-no-oid"), {"text": "Agree"})],
        "contract_salt": _h32("cs-no-oid"),
        "genesis": GENESIS_MAIN, "network": "main",
        "parties": [
            {"name_pin": {"name": "id/alice", "owner_policy": as_no_oid["_alice_owner_pol"], "registration": as_no_oid["_alice_reg"]}, "party_id": "p-alice", "role": "buyer", "signing_policy": {"m": 1, "pks": [as_no_oid["_keys"]["alice_gr"]["xonly"]]}},
            {"party_id": "p-bob", "role": "seller", "signing_policy": {"m": 1, "pks": [bob_mut_k["xonly"]]}},
        ],
        "profile": "org.seallink/generic-v1",
        "seal": {"script_policy": {"kind": "key", "pk": bob_mut_k["comp"]}, "txid": _h32("c-no-oid-seal"), "vout": 0},
        "type": "seallink-contract/1",
        "window": {"not_after_height": 760000, "not_before_height": 749000},
    }
    ass_no_oid = sl.sign_envelope({
        "expires_at": 1795229999, "genesis": GENESIS_MAIN, "issued_at": 1795219900, "network": "main",
        "nonce": _h32("ass-no-oid-n"), "party_id": "p-alice", "party_name": "id/alice", "party_role": "buyer",
        "target_id": sl.object_id(c_no_oid), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
    }, [as_no_oid["_keys"]["alice_gr"]["sk"]])
    add(
        "d11-mut-assent-unresolved-0x13-without-origin-incomplete",
        ["SL-ORIG-017"],
        "assent",
        {"assent": ass_no_oid, "chain": as_no_oid["chain"], "contract": c_no_oid},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: Autonomous assent party with confirmed 0x13 and no link.origin MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )

    # D4. verify_notary_act artifact-notarization mismatched target_sha256 -> WIRE_MEMBER (L4999)
    na_bad_tid_p = copy.deepcopy(nlog["item_env"]["payload"])
    na_bad_tid_p["target_sha256"] = _h32("wrong-notary-tid")
    na_bad_tid = sl.sign_envelope(na_bad_tid_p, [nlog["iss_role"]["sk"]])
    add(
        "d11-mut-notary-act-artifact-target-mismatch-wire-member",
        ["SL-CONT-011"],
        "notary_act",
        {"chain": nlog["chain"], "notary": na_bad_tid},
        "REFUSE",
        "WIRE_MEMBER",
        "SL-CONT-011: artifact-notarization seallink-notary/1 with target_sha256 != canonical artifact_target_id refuses WIRE_MEMBER.",
    )

    # D5. Shared rlog RFC 9162 & SMT proofs for D7/D9
    rlog_cp1_in_cp3 = sl.rfc9162_inclusion_proof(rlog["leaves_2"], 0)
    rlog_cp3_in_cp4 = sl.rfc9162_inclusion_proof(rlog["leaves_3"], 2)
    rlog_smt_rev1_cp3 = sl.smt_prove(rlog["kv3"], rlog["denial_key"])
    rlog_smt_reinst2_cp4 = sl.smt_prove(rlog["kv4"], rlog["denial_key"])

    # D6. verify_log_checkpoint exhaustive negative & boundary cases (ALL 9 surviving lines!)
    cp1_wrong_gen = sl.sign_envelope({**nlog["cp1_env"]["payload"], "genesis": _h32("wrong-gen")}, [nlog["iss_role"]["sk"]])
    add(
        "d11-mut-cp-chain-mismatch",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": nlog["chain_at_cp1"], "checkpoint": cp1_wrong_gen, "checkpoint_txid": nlog["cp1_tx"]},
        "REFUSE",
        "CHAIN_MISMATCH",
        "SL-CONT-012: Checkpoint with wrong genesis MUST refuse CHAIN_MISMATCH.",
    )
    add(
        "d11-mut-cp-anchor-missing",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": nlog["chain_at_cp1"], "checkpoint": nlog["cp1_env"], "checkpoint_txid": _h32("missing-cp-tx")},
        "REFUSE",
        "CRED_ANCHOR_MISSING",
        "SL-CONT-012: Unanchored 0x14 checkpoint MUST refuse CRED_ANCHOR_MISSING.",
    )
    # cp2 confirmed at 749990, tip 750010 -> depth = 21! min_depth=22 refuses, min_depth=21 admits!
    add(
        "d11-mut-cp-depth-insufficient",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": nlog["chain_at_cp2"], "checkpoint": nlog["cp2_env"], "checkpoint_txid": nlog["cp2_tx"], "operator_min_depth": 22},
        "REFUSE",
        "CHAIN_DEPTH_INSUFFICIENT",
        "SL-CONT-012: 0x14 checkpoint depth 21 < required_depth 22 MUST refuse CHAIN_DEPTH_INSUFFICIENT.",
    )
    add(
        "d11-mut-cp-depth-exact-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": nlog["chain_at_cp2"], "checkpoint": nlog["cp2_env"], "checkpoint_txid": nlog["cp2_tx"], "operator_min_depth": 21},
        "ADMIT",
        None,
        "SL-CONT-012: 0x14 checkpoint at exact depth == required_depth (21) admits.",
    )
    ch_cp_unspent = copy.deepcopy(nlog["chain_at_cp1"])
    nlog_gen_tx = nlog["cp1_env"]["payload"]["prev_log_outpoint"]["txid"]
    ch_cp_unspent["txs"][nlog_gen_tx]["outputs"]["0"]["spent_by_txid"] = _h32("other-spender")
    add(
        "d11-mut-cp-prev-outpoint-wrong-spender",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_cp_unspent, "checkpoint": nlog["cp1_env"], "checkpoint_txid": nlog["cp1_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: 0x14 checkpoint whose prev_log_outpoint was spent by another tx MUST refuse CHAIN_FRAME_INVALID.",
    )
    cp2_bad_zero = sl.sign_envelope({**nlog["cp2_env"]["payload"], "batch_root": _h32("nonzero-empty-batch")}, [nlog["iss_role"]["sk"]])
    ch_cp_b0 = copy.deepcopy(nlog["chain_at_cp2"])
    ch_cp_b0["txs"][nlog["cp2_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp2_bad_zero)).hex()
    add(
        "d11-mut-cp-batch-count-zero-nonempty-root",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_cp_b0, "checkpoint": cp2_bad_zero, "checkpoint_txid": nlog["cp2_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: batch_count==0 with non-empty batch_root MUST refuse CHAIN_FRAME_INVALID.",
    )
    cp1_bad_lid = sl.sign_envelope({**nlog["cp1_env"]["payload"], "log_id": _h32("fake-log-id")}, [nlog["iss_role"]["sk"]])
    ch_cp_lid = copy.deepcopy(nlog["chain_at_cp1"])
    ch_cp_lid["txs"][nlog["cp1_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp1_bad_lid)).hex()
    add(
        "d11-mut-cp-seq1-wrong-log-id",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_cp_lid, "checkpoint": cp1_bad_lid, "checkpoint_txid": nlog["cp1_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: seq==1 checkpoint with mismatched log_id MUST refuse CHAIN_FRAME_INVALID.",
    )
    add(
        "d11-mut-cp-seq1-wrong-genesis-seal",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": nlog["chain_at_cp1"], "checkpoint": nlog["cp1_env"], "checkpoint_txid": nlog["cp1_tx"],
            "genesis_seal": {"script_policy": nlog["seal_pol"], "txid": _h32("wrong-gen-seal"), "vout": 0},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: seq==1 checkpoint with mismatched genesis_seal MUST refuse CHAIN_FRAME_INVALID.",
    )
    add(
        "d11-mut-cp-prev-cp-mismatch",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": nlog["chain_at_cp2"], "checkpoint": nlog["cp2_env"], "checkpoint_txid": nlog["cp2_tx"],
            "prev_checkpoint": nlog["cp2_env"], "prev_checkpoint_txid": nlog["cp2_tx"],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: Checkpoint with mismatched prev_checkpoint MUST refuse CHAIN_FRAME_INVALID.",
    )
    ch_cp_nonxt = copy.deepcopy(nlog["chain_at_cp2"])
    ch_cp_nonxt["txs"][nlog["cp2_tx"]]["outputs"] = {}
    add(
        "d11-mut-cp-nonterminal-missing-next-out",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_cp_nonxt, "checkpoint": nlog["cp2_env"], "checkpoint_txid": nlog["cp2_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: Non-terminal 0x14 checkpoint missing next_log_vout output MUST refuse CHAIN_FRAME_INVALID.",
    )

    # D7. verify_log_fraud exhaustive negative cases (all 4 modes + CHAIN_MISMATCH + _auth_cp errors)
    fr_eq_base = {
        "cp_a": nlog["cp2_env"], "cp_b": nlog["cp2_env"], "fraud_mode": "equivocation",
        "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
        "log_id": nlog["log_id"], "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
    }
    add(
        "d11-mut-fraud-chain-mismatch",
        ["SL-CONT-013"],
        "log_fraud",
        {"chain": nlog["chain"], "fraud": {**fr_eq_base, "genesis": _h32("wrong-gen")}},
        "REFUSE",
        "CHAIN_MISMATCH",
        "SL-CONT-013: Fraud proof with wrong genesis MUST refuse CHAIN_MISMATCH.",
    )
    cp2_eq_mut = sl.sign_envelope({**nlog["cp2_env"]["payload"], "denials_root": _h32("alt-denials-mut")}, [nlog["iss_role"]["sk"]])
    add(
        "d11-mut-fraud-auth-cp-log-id-mismatch",
        ["SL-CONT-013"],
        "log_fraud",
        {"chain": nlog["chain"], "fraud": {**fr_eq_base, "cp_b": cp2_eq_mut, "log_id": _h32("wrong-lid")}},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013: Fraud proof whose distinct equivocating checkpoints mismatch outer log_id refuses CHAIN_FRAME_INVALID.",
    )
    add(
        "d11-mut-fraud-auth-cp-depth-insufficient",
        ["SL-CONT-013"],
        "log_fraud",
        {"chain": nlog["chain"], "fraud": {**fr_eq_base, "cp_a_txid": nlog["cp2_tx"]}, "operator_min_depth": 22},
        "REFUSE",
        "CHAIN_DEPTH_INSUFFICIENT",
        "SL-CONT-013: Confirmed checkpoint in fraud proof below operator_min_depth refuses CHAIN_DEPTH_INSUFFICIENT.",
    )
    fr_om_base = {
        "batch_proof": rlog["b1_proof"], "cp_a": rlog["cp1_env"], "cp_a_txid": rlog["cp1_tx"],
        "cp_b": rlog["cp2_env"], "cp_b_txid": rlog["cp2_tx"],
        "checkpoints_proof": rlog["cp1_in_cp2_proof"],
        "fraud_mode": "revocation_omission", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": rlog["gen_op"],
        "log_id": rlog["log_id"], "network": "main", "revocation": rlog["rev1_env"], "role": "release",
        "smt_proof": sl.smt_prove({}, rlog["denial_key"]), "type": "seallink-log-fraud/1",
    }
    add(
        "d11-mut-fraud-omission-unanchored-cp-anchor-missing",
        ["SL-CONT-013"],
        "log_fraud",
        {"chain": rlog["chain"], "fraud": {**fr_om_base, "cp_a_txid": _h32("unanchored-cp")}},
        "REFUSE",
        "CRED_ANCHOR_MISSING",
        "SL-CONT-013: revocation_omission with unanchored cp_a_txid refuses CRED_ANCHOR_MISSING.",
    )
    add(
        "d11-mut-fraud-omission-not-proven-frame-invalid",
        ["SL-CONT-013"],
        "log_fraud",
        {"chain": rlog["chain"], "fraud": fr_om_base},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013: revocation_omission where rev1 is NOT in cp1 batch_proof refuses CHAIN_FRAME_INVALID.",
    )
    fr_ir_valid_succ = {
        "checkpoints_proof": rlog_cp3_in_cp4,
        "cp_a": rlog["cp3_env"], "cp_a_txid": rlog["cp3_tx"],
        "cp_b": rlog["cp4_env"], "cp_b_txid": rlog["cp4_tx"],
        "fraud_mode": "illegal_reversion", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": rlog["gen_op"],
        "log_id": rlog["log_id"], "network": "main", "rec_a": rlog["rev1_env"], "rec_b": rlog["reinst2_env"], "role": "release",
        "smt_proof_a": rlog_smt_rev1_cp3, "smt_proof_b": rlog_smt_reinst2_cp4,
        "type": "seallink-log-fraud/1",
    }
    add(
        "d11-mut-fraud-illegal-reversion-valid-transition-frame-invalid",
        ["SL-CONT-013"],
        "log_fraud",
        {"chain": rlog["chain"], "fraud": fr_ir_valid_succ},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013: Honest state_seq 1->2 reinstatement with matching prev_record_id is NOT fraud (CHAIN_FRAME_INVALID).",
    )
    add(
        "d11-mut-fraud-chain-seq1-honest-frame-invalid",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": nlog["chain"],
            "fraud": {
                "cp_next": nlog["cp1_env"], "cp_next_txid": nlog["cp1_tx"], "fraud_mode": "invalid_checkpoint_chain",
                "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013: Honest seq=1 checkpoint is NOT invalid_checkpoint_chain fraud (CHAIN_FRAME_INVALID).",
    )
    add(
        "d11-mut-fraud-chain-seq2-missing-prev-frame-invalid",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": nlog["chain"],
            "fraud": {
                "cp_next": nlog["cp2_env"], "cp_next_txid": nlog["cp2_tx"], "fraud_mode": "invalid_checkpoint_chain",
                "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013: invalid_checkpoint_chain for seq>=2 missing cp_prev refuses CHAIN_FRAME_INVALID.",
    )
    add(
        "d11-mut-fraud-chain-seq2-honest-frame-invalid",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": nlog["chain"],
            "fraud": {
                "cp_next": nlog["cp2_env"], "cp_next_txid": nlog["cp2_tx"],
                "cp_prev": nlog["cp1_env"], "cp_prev_txid": nlog["cp1_tx"],
                "fraud_mode": "invalid_checkpoint_chain", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "peaks": [], "role": "notary", "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-013: Honest seq=2 checkpoint with matching checkpoints_root & cumulative count is NOT fraud (CHAIN_FRAME_INVALID).",
    )

    # D8. verify_release exhaustive negative & boundary cases (ALL 4 surviving lines!)
    rel_wrong_gen = sl.sign_envelope({**gk_rel_env["payload"], "genesis": _h32("wrong-gen")}, [rlog["iss_role"]["sk"]])
    add(
        "d11-mut-release-chain-mismatch",
        ["SL-CONT-012"],
        "release",
        {"anchor_txid": gk_rel_tx, "chain": gk_chain, "release": rel_wrong_gen},
        "REFUSE",
        "CHAIN_MISMATCH",
        "SL-CONT-012: Release with wrong genesis refuses CHAIN_MISMATCH.",
    )
    rel_bad_tid = sl.sign_envelope({**gk_rel_env["payload"], "target_sha256": _h32("wrong-rel-tid")}, [rlog["iss_role"]["sk"]])
    add(
        "d11-mut-release-target-mismatch-wire-member",
        ["SL-CONT-012"],
        "release",
        {"anchor_txid": gk_rel_tx, "chain": gk_chain, "release": rel_bad_tid},
        "REFUSE",
        "WIRE_MEMBER",
        "SL-CONT-012: Release with target_sha256 != canonical artifact_target_id refuses WIRE_MEMBER.",
    )
    add(
        "d11-mut-release-eternal-anchor-missing",
        ["SL-CONT-012"],
        "release",
        {"anchor_txid": _h32("missing-rel-tx"), "chain": gk_chain, "release": gk_rel_env},
        "REFUSE",
        "CRED_ANCHOR_MISSING",
        "SL-CONT-012: Eternal release without confirmed 0x09 anchor refuses CRED_ANCHOR_MISSING.",
    )
    # gk_rel_tx confirmed at 749992, tip 750010 -> depth = 19!
    add(
        "d11-mut-release-eternal-depth-insufficient",
        ["SL-CONT-012"],
        "release",
        {"anchor_txid": gk_rel_tx, "chain": gk_chain, "operator_min_depth": 20, "release": gk_rel_env},
        "REFUSE",
        "CHAIN_DEPTH_INSUFFICIENT",
        "SL-CONT-012: Eternal release depth 19 < operator_min_depth 20 refuses CHAIN_DEPTH_INSUFFICIENT.",
    )
    add(
        "d11-mut-release-eternal-depth-exact-admit",
        ["SL-CONT-012"],
        "release",
        {"anchor_txid": gk_rel_tx, "chain": gk_chain, "operator_min_depth": 19, "release": gk_rel_env},
        "ADMIT",
        None,
        "SL-CONT-012: Eternal release at exact depth == operator_min_depth (19) admits.",
    )

    # D9. verify_artifact_ticket exhaustive negative cases (ALL 17 surviving lines!)
    add(
        "d11-mut-ticket-chain-mismatch",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": {**gk_ticket_2of3, "genesis": _h32("wrong-gen")}},
        "REFUSE",
        "CHAIN_MISMATCH",
        "SL-ARTF-003: Ticket with wrong genesis refuses CHAIN_MISMATCH.",
        module="artifact-notarization",
    )
    add(
        "d11-mut-ticket-release-target-mismatch",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": {**gk_ticket_2of3, "release": rlog["item_env"]}},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003: Ticket release targeting different artifact refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d11-mut-ticket-release-untrusted-prefix",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {
            "chain": gk_chain,
            "policy": {**gk_pol_hardened, "trusted_release_issuers": [{"allowed_product_prefixes": ["org.other/"], "issuer_pin": rlog["iss_pin"]}]},
            "ticket": gk_ticket_2of3,
        },
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: Release product_id outside trusted_release_issuers.allowed_product_prefixes refuses ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )
    # Log-tracked release inside ticket (compromised log -> NOTARY_LOG_COMPROMISED; revoked -> ARTIFACT_POLICY_DENIED)
    tkt_lt_rel_base = {
        "artifact_identity": rlog["item_env"]["payload"]["artifact_identity"],
        "genesis": GENESIS_MAIN, "network": "main", "notarizations": [],
        "release": rlog["item_env"], "release_batch_proof": rlog["b1_proof"],
        "release_checkpoint": rlog["cp1_env"], "release_checkpoint_txid": rlog["cp1_tx"],
        "release_checkpoints_proof": rlog_cp1_in_cp3,
        "release_head_checkpoint": rlog["cp3_env"], "release_head_checkpoint_txid": rlog["cp3_tx"],
        "release_smt_proof": rlog_smt_rev1_cp3, "release_state_record": rlog["rev1_env"],
        "target_sha256": rlog["item_env"]["payload"]["target_sha256"], "type": "seallink-ticket/1",
    }
    pol_lt_rel = {
        "allow_reinstatement": False, "mode": "standard", "quorum_m": 0, "require_release": True,
        "required_claims": [], "trusted_notaries": [],
        "trusted_release_issuers": [{"allowed_product_prefixes": ["works.relux/"], "issuer_pin": rlog["iss_pin"], "log_id": rlog["log_id"]}],
    }
    add(
        "d11-mut-ticket-release-revoked-policy-denied",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": rlog["chain_at_cp3"], "policy": pol_lt_rel, "ticket": tkt_lt_rel_base},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: Revoked log_tracked release in ticket maps CRED_REVOKED_FOR_CAUSE -> ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )
    j_rel_comp_cfg = {
        "initial_entries": [{
            "body": {"cause": "NOTARY_LOG_COMPROMISED", "observed_at": 1795219900, "observed_height": 750000, "subject": {"log_id": rlog["log_id"], "role": "release", "subject_kind": "log"}},
            "kind": "closure",
        }],
        "journal_id": _h32("j-rel-comp"),
    }
    add(
        "d11-mut-ticket-release-log-compromised",
        ["SL-ARTF-003", "SL-CONT-013"],
        "artifact_ticket",
        {"chain": rlog["chain_at_cp3"], "journal": j_rel_comp_cfg, "policy": pol_lt_rel, "ticket": tkt_lt_rel_base},
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-ARTF-003: Ticket release from fraud-closed log refuses NOTARY_LOG_COMPROMISED.",
        module="artifact-notarization",
    )
    add(
        "d11-mut-release-compromised-log-without-log-ctx",
        ["SL-CONT-013"],
        "release",
        {"chain": rlog["chain"], "journal": j_rel_comp_cfg, "release": rlog["item_env"]},
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-CONT-013: log_tracked release from fraud-closed log refuses NOTARY_LOG_COMPROMISED immediately even without log_ctx.",
    )
    add(
        "d11-mut-ticket-release-eternal-unanchored-proof-invalid",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": {**gk_ticket_2of3, "release_anchor_txid": _h32("missing-rel-anc")}},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003: Unanchored eternal release in ticket refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    tkt_no_rel = {k: v for k, v in gk_ticket_2of3.items() if not k.startswith("release")}
    add(
        "d11-mut-ticket-missing-required-release-policy-denied",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": tkt_no_rel},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: Ticket missing release when policy.require_release=True refuses ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )
    nlog_valid_other_entry = {
        "act_smt_proof": sl.smt_prove({}, nlog["denial_key"]),
        "batch_proof": nlog["b1_proof"],
        "checkpoint": nlog["cp1_env"],
        "checkpoint_txid": nlog["cp1_tx"],
        "notary_act": nlog["item_env"],
        "target_smt_proof": sl.smt_prove({}, f"target:{fsv_tid}|*"),
    }
    add(
        "d11-mut-ticket-notary-wrong-target-proof-invalid",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {
            "chain": nlog["chain_at_cp1"],
            "policy": {
                "allow_reinstatement": False, "mode": "standard", "quorum_m": 1, "require_release": False,
                "required_claims": ["seallink.org/build-repro"],
                "trusted_notaries": [{"log_id": nlog["log_id"], "notary_pin": nlog["iss_pin"]}],
            },
            "ticket": {
                "artifact_identity": fsv_art, "genesis": GENESIS_MAIN, "network": "main",
                "notarizations": [nlog_valid_other_entry], "target_sha256": fsv_tid, "type": "seallink-ticket/1",
            },
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003: Validly log-anchored notarization targeting a different artifact MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d11-mut-ticket-duplicate-trusted-notary-proof-invalid",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {
            "chain": gk_chain,
            "policy": {
                "allow_reinstatement": False, "mode": "standard", "quorum_m": 1, "require_release": False,
                "required_claims": ["seallink.org/build-repro"],
                "trusted_notaries": [{"log_id": gn1["log_id"], "notary_pin": gn1["pin"]}],
            },
            "ticket": {
                "artifact_identity": fsv_art, "genesis": GENESIS_MAIN, "network": "main",
                "notarizations": [gn1["entry"], gn1["entry"]], "target_sha256": fsv_tid, "type": "seallink-ticket/1",
            },
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003: Duplicate trusted notary in ticket.notarizations[] MUST refuse TICKET_PROOF_INVALID even under quorum_m=1.",
        module="artifact-notarization",
    )
    pol_wrong_nlid = copy.deepcopy(gk_pol_hardened)
    pol_wrong_nlid["trusted_notaries"][0]["log_id"] = _h32("wrong-notary-lid")
    add(
        "d11-mut-ticket-notary-wrong-log-id-proof-invalid",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": pol_wrong_nlid, "ticket": gk_ticket_2of3},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003: Notarization whose log_id mismatches pinned trusted_notaries[].log_id refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    # Non-log-tracked revocable notary act in ticket (revoked via 0x05 -> ARTIFACT_POLICY_DENIED; unanchored -> TICKET_PROOF_INVALID)
    n1_seal_tx = _h32("gk-rev-na-seal")
    n1_0x05_tx = _h32("gk-rev-na-0x05")
    n1_0x09_tx = _h32("gk-rev-na-0x09")
    na_rev_p = {
        "act_kind": "artifact-notarization", "attested_at": 1795219500,
        "details": {"artifact_identity": fsv_art, "claims": [{"claim_id": "seallink.org/build-repro", "verdict": "pass"}], "kind": "artifact-notarization"},
        "genesis": GENESIS_MAIN, "lifecycle": "revocable", "network": "main",
        "notary": nlog["iss_role_pin"], "notary_seal": {"script_policy": nlog["seal_pol"], "txid": n1_seal_tx, "vout": 0},
        "target_sha256": fsv_tid, "tip_hash": gk_chain["tip_hash"], "tip_height": gk_chain["tip_height"], "type": "seallink-notary/1",
    }
    na_rev_env = sl.sign_envelope(na_rev_p, [nlog["iss_role"]["sk"]])
    gk_ch_revna = copy.deepcopy(gk_chain)
    gk_ch_revna["txs"][n1_0x09_tx] = {"confirmed_height": 749994, "opreturn_hex": sl.encode_opreturn(0x04, sl.content_addr(na_rev_env)).hex(), "outputs": {}}
    gk_ch_revna["txs"][n1_seal_tx] = {"confirmed_height": 749993, "outputs": {"0": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"]), "spent_by_txid": n1_0x05_tx}}}
    gk_ch_revna["txs"][n1_0x05_tx] = {"confirmed_height": 749996, "inputs": [sv.make_segwit_input(n1_seal_tx, 0)], "opreturn_hex": sl.encode_opreturn(0x05, _h32("rev-reason")).hex(), "outputs": {}}
    pol_std_revna = {
        "allow_reinstatement": False, "mode": "standard", "quorum_m": 1, "require_release": False,
        "required_claims": ["seallink.org/build-repro"],
        "trusted_notaries": [{"notary_pin": nlog["iss_pin"]}],
    }
    add(
        "d11-mut-ticket-revocable-notary-0x05-policy-denied",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {
            "chain": gk_ch_revna, "policy": pol_std_revna,
            "ticket": {
                "artifact_identity": fsv_art, "genesis": GENESIS_MAIN, "network": "main",
                "notarizations": [{"anchor_txid": n1_0x09_tx, "notary_act": na_rev_env}],
                "target_sha256": fsv_tid, "type": "seallink-ticket/1",
            },
        },
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: Revocable non-log-tracked notary act revoked by 0x05 maps -> ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )
    add(
        "d11-mut-ticket-revocable-notary-unanchored-proof-invalid",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {
            "chain": gk_ch_revna, "policy": pol_std_revna,
            "ticket": {
                "artifact_identity": fsv_art, "genesis": GENESIS_MAIN, "network": "main",
                "notarizations": [{"anchor_txid": _h32("missing-na-0x09"), "notary_act": na_rev_env}],
                "target_sha256": fsv_tid, "type": "seallink-ticket/1",
            },
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003: Unanchored non-log-tracked notary act in ticket refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    # Absent-notary proof errors (compromised log, unanchored head, wrong issuer, stale heartbeat)
    j_n3_comp_cfg = {
        "initial_entries": [{
            "body": {"cause": "NOTARY_LOG_COMPROMISED", "observed_at": 1795219900, "observed_height": 750000, "subject": {"log_id": gn3_clean["log_id"], "role": "notary", "subject_kind": "log"}},
            "kind": "closure",
        }],
        "journal_id": _h32("j-n3-comp"),
    }
    add(
        "d11-mut-ticket-absent-notary-log-compromised",
        ["SL-ARTF-003", "SL-CONT-013"],
        "artifact_ticket",
        {"chain": gk_chain, "journal": j_n3_comp_cfg, "policy": gk_pol_hardened, "ticket": gk_ticket_2of3},
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-ARTF-003: Absent trusted notary whose log is fraud-closed refuses NOTARY_LOG_COMPROMISED.",
        module="artifact-notarization",
    )
    tkt_abs_unanc = copy.deepcopy(gk_ticket_2of3)
    tkt_abs_unanc["absent_notary_proofs"][0]["head_checkpoint_txid"] = _h32("missing-abs-tx")
    add(
        "d11-mut-ticket-absent-notary-unanchored-proof-invalid",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": tkt_abs_unanc},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003: Absent notary proof with unanchored head_checkpoint_txid refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    tkt_abs_wrong_cp = copy.deepcopy(gk_ticket_2of3)
    tkt_abs_wrong_cp["absent_notary_proofs"][0]["head_checkpoint"] = gn1["cp_env"]
    tkt_abs_wrong_cp["absent_notary_proofs"][0]["head_checkpoint_txid"] = gn1["cp_tx"]
    add(
        "d11-mut-ticket-absent-notary-wrong-issuer-proof-invalid",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": tkt_abs_wrong_cp},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-003: Absent notary proof substituting another notary's checkpoint refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    # Non-terminal absent notary with stale heartbeat (confirmed 749995, tip 750010 -> age 15 > heartbeat 14; exact 15 admits!)
    gk_ch_abs_nt = copy.deepcopy(gk_chain)
    cp_n3_nt_p = {
        **{k: v for k, v in gn3_clean["cp_env"]["payload"].items() if k != "terminal"},
        "next_log_policy": n3["seal_pol"], "next_log_vout": 1, "terminal": False,
    }
    cp_n3_nt = sl.sign_envelope(cp_n3_nt_p, [n3["iss_role"]["sk"]])
    gk_ch_abs_nt["txs"][gn3_clean["cp_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp_n3_nt)).hex()
    gk_ch_abs_nt["txs"][gn3_clean["cp_tx"]]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(n3["seal_pol"])}}
    tkt_abs_nt = copy.deepcopy(gk_ticket_2of3)
    tkt_abs_nt["absent_notary_proofs"][0]["head_checkpoint"] = cp_n3_nt
    pol_abs_hb_stale = copy.deepcopy(gk_pol_hardened)
    pol_abs_hb_stale["trusted_notaries"][2]["heartbeat_max_blocks"] = 14
    add(
        "d11-mut-ticket-absent-notary-stale-heartbeat-denied",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_ch_abs_nt, "policy": pol_abs_hb_stale, "ticket": tkt_abs_nt},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: Non-terminal absent notary checkpoint older than heartbeat_max_blocks (15 > 14) refuses ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )
    pol_abs_hb_ok = copy.deepcopy(gk_pol_hardened)
    pol_abs_hb_ok["trusted_notaries"][2]["heartbeat_max_blocks"] = 15
    add(
        "d11-mut-ticket-absent-notary-exact-heartbeat-admit",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_ch_abs_nt, "policy": pol_abs_hb_ok, "ticket": tkt_abs_nt},
        "ADMIT",
        None,
        "SL-ARTF-003: Non-terminal absent notary checkpoint at exact heartbeat_max_blocks (15 == 15) admits.",
        module="artifact-notarization",
    )
    # required_claims=[] with quorum_m=2 and only 1 notary -> ARTIFACT_POLICY_DENIED (L5861)
    add(
        "d11-mut-ticket-empty-req-claims-quorum-unmet-denied",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {
            "chain": gk_chain,
            "policy": {**gk_pol_hardened, "mode": "standard", "quorum_m": 2, "required_claims": []},
            "ticket": {**gk_ticket_2of3, "notarizations": [gn1["entry"]]},
        },
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: required_claims=[] with 1 valid notary < quorum_m=2 refuses ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )

    # D10. verify_tier2_name_history_page exhaustive negative & boundary cases (ALL 7 surviving lines!)
    add(
        "d11-mut-tier2-chain-mismatch",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": {**page_low, "genesis": _h32("wrong-gen")}},
        "REFUSE",
        "CHAIN_MISMATCH",
        "SL-ARTF-005: Tier-2 page with wrong genesis refuses CHAIN_MISMATCH.",
        module="artifact-notarization",
    )
    spv_pair_upds, spv_pair_hdr, spv_pair_reg = _build_same_block_chained_spv_pair(
        "sameblk", spv_p2wpkh, spv_k1["sk"], "id/spv-chained", "{}", '{"link":{}}', block_height=750010, high_s_second=True
    )
    add(
        "d11-mut-tier2-over-limit-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-chained", spv_pair_upds, limit=1, registration=spv_pair_reg)},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Validly chained len(updates) > limit refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    bad_aux_proof = {**aux_proof_ok, "chain_merkle_nonce": 12345}
    hdr_2016_bad_aux = struct.pack("<I", aux_ver) + prev_hash_2015_le + (b"\x99" * 32) + struct.pack("<III", 1795000000 + 605400, exp_bits_2016, 0)
    add(
        "d11-mut-tier2-auxpow-invalid-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [
                {"header_hex": prev_hdr_2015.hex(), "height": 2015},
                {"auxpow": bad_aux_proof, "epoch_start_time": 1795000000, "header_hex": hdr_2016_bad_aux.hex(), "height": 2016},
            ],
            "page": page_reg_empty,
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: Invalid AuxPoW commitment refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    unmined_hdr = struct.pack("<I", nmc_nonaux_ver) + (b"\x00" * 32) + (b"\x11" * 32) + struct.pack("<III", 1795220000, 0x1D00FFFF, 0)
    add(
        "d11-mut-tier2-non-auxpow-bad-pow-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [{"header_hex": unmined_hdr.hex(), "height": 10}],
            "page": page_reg_empty,
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: Non-AuxPoW header failing PoW target refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    hdr_bad_prev = _mine_regtest_hdr(nmc_nonaux_ver, b"\xff" * 32, b"\x22" * 32, 1795000000 + 605400, 0x207FFFFF)
    add(
        "d11-mut-tier2-header-prevhash-mismatch-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [
                {"header_hex": prev_hdr_2015.hex(), "height": 2015},
                {"header_hex": hdr_bad_prev.hex(), "height": 2016},
            ],
            "page": page_reg_empty,
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: Consecutive headers with broken prev_block_hash link refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    proof_earlier, _ = _build_synthetic_spv_proof(
        "earlier", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}',
        block_height=750009, prev_raw_override=bytes.fromhex(proof_low["tx_hex"]),
    )
    add(
        "d11-mut-tier2-out-of-order-heights-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_low, proof_earlier])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Non-monotonic block_height sequence (750010 -> 750009) refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d11-mut-tier2-header-hash-mismatch-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [{"header_hex": prev_hdr_2015.hex(), "height": 750010}],
            "page": {**page_low, "network": "regtest"},
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Verified header hash mismatching SegWitNameUpdateProof.block_hash refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # =========================================================================
    # SECTION E: EXACT NUMERIC BOUNDARY CLOSURE (100% BOUNDARY MUTATION BAR)
    # =========================================================================

    # E1. resolve_name H2 fail-closed: ANY history_truncated=True MUST refuse NAME_HISTORY_UNAVAILABLE even at at_height < first_error_height!
    rn_feh_bnd = rm._base_invocation_fixture()
    al_hist_b = rn_feh_bnd["chain"]["names"]["id/alice"]
    prev_al_b = al_hist_b["updates"][-1]
    feh_exact = prev_al_b["confirmed_height"] + 20
    al_hist_b["updates"].append({
        "block_time": 1795219000, "confirmed_height": feh_exact, "op": "NAME_UPDATE",
        "output_script_hex": "deadbeef",  # malformed update sitting AT exact feh_exact!
        "owner_policy": rn_feh_bnd["_alice_owner_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_al_b["txid"], "vout": prev_al_b["vout"], "witness_policy": rn_feh_bnd["_alice_owner_pol"]},
        "txid": _h32("al-bad-at-feh"), "vout": 0,
    })
    al_hist_b["history_truncated"] = True
    al_hist_b["first_error_height"] = feh_exact
    add(
        "d11-bnd-resolve-name-at-height-eq-feh-unavailable",
        ["SL-LDGR-015"],
        "name_resolve",
        {"at_height": feh_exact, "chain": rn_feh_bnd["chain"], "name": "id/alice"},
        "REFUSE",
        "NAME_HISTORY_UNAVAILABLE",
        "SL-LDGR-015: Exact at_height == first_error_height MUST refuse NAME_HISTORY_UNAVAILABLE.",
    )
    add(
        "d11-bnd-resolve-name-truncated-at-height-lt-feh-unavailable",
        ["SL-LDGR-015"],
        "name_resolve",
        {"at_height": feh_exact - 1, "chain": rn_feh_bnd["chain"], "name": "id/alice"},
        "REFUSE",
        "NAME_HISTORY_UNAVAILABLE",
        "SL-LDGR-015 H2: Truncated history MUST ALWAYS refuse NAME_HISTORY_UNAVAILABLE even at at_height < first_error_height (prevents masking retroactive 0x0b / 0x1b..0x1f).",
    )

    # E2. _validate_b2_invariant exact boundaries (L2935, L2936, L2949, L2969, L2973, L2990)
    rb_b2_at_h13 = _build_autonomous_origin_rebind_fixture("bnd-b2-h13", b2_corrupt_at=749600, b2_corrupt_kind="owner_policy", h_act=None)
    add(
        "d11-bnd-b2-corrupt-at-exact-h13-rejected",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_b2_at_h13["chain"], "expect_active_name": "id/alice-v1", "expect_rebind_outcome": "rejected", "origin_bundle": rb_b2_at_h13["origin_bundle"], "trusted_origin_issuer_pins": rb_b2_at_h13["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: B_2 policy mutation at exact confirmed_height == h_13 MUST reject 0x13 (boundary <= check_until_h).",
    )
    rb_b2_fu_eq = _build_autonomous_origin_rebind_fixture("bnd-b2-fu-eq", h_offer=749600, h_13=749600, h_act=None)
    rb_b2_fu_eq["chain"]["names"]["id/alice-v2"]["updates"][0]["confirmed_height"] = 749600
    add(
        "d11-bnd-b2-firstupdate-at-exact-h13-rejected",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_b2_fu_eq["chain"], "expect_active_name": "id/alice-v1", "expect_rebind_outcome": "rejected", "origin_bundle": rb_b2_fu_eq["origin_bundle"], "trusted_origin_issuer_pins": rb_b2_fu_eq["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: B_2 NAME_FIRSTUPDATE at exact h_13 MUST reject 0x13 (boundary >= h_13).",
    )
    rb_b2_off_eq = _build_autonomous_origin_rebind_fixture("bnd-b2-off-eq", h_offer=749600, h_13=749600, h_act=None)
    add(
        "d11-bnd-b2-t-offer-at-exact-h13-rejected",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_b2_off_eq["chain"], "expect_active_name": "id/alice-v1", "expect_rebind_outcome": "rejected", "origin_bundle": rb_b2_off_eq["origin_bundle"], "trusted_origin_issuer_pins": rb_b2_off_eq["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: T_offer at exact h_offer == h_13 MUST reject 0x13 (boundary >= h_13).",
    )
    rb_b2_gap_exp = _build_autonomous_origin_rebind_fixture("bnd-b2-gap-exp", h_offer=785400, h_13=785500, h_act=None, tip_h=785700)
    # firstupdate is at 749400 -> 749400 + 36000 == 785400 (exact expiry gap between firstupdate and T_offer!)
    add(
        "d11-bnd-b2-update-exact-expiry-gap-rejected",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_b2_gap_exp["chain"], "expect_active_name": "id/alice-v1", "expect_rebind_outcome": "rejected", "origin_bundle": rb_b2_gap_exp["origin_bundle"], "trusted_origin_issuer_pins": rb_b2_gap_exp["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: B_2 update at exact prev_h + name_expiry_blocks MUST reject 0x13 (boundary >=).",
    )
    rb_b2_off_pol = _build_autonomous_origin_rebind_fixture("bnd-b2-off-pol", h_act=None)
    b2_alt_pol = {"kind": "key", "pk": _kp("bnd-b2-alt")["comp"]}
    rb_b2_off_pol["chain"]["names"]["id/alice-v2"]["updates"][1]["owner_policy"] = b2_alt_pol
    add(
        "d11-bnd-b2-t-offer-changes-policy-rejected",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_b2_off_pol["chain"], "expect_active_name": "id/alice-v1", "expect_rebind_outcome": "rejected", "origin_bundle": rb_b2_off_pol["origin_bundle"], "trusted_origin_issuer_pins": rb_b2_off_pol["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: T_offer itself altering B_2 owner_policy MUST reject 0x13 (boundary idx >= offer_idx).",
    )
    rb_b2_end_exp = _build_autonomous_origin_rebind_fixture("bnd-b2-end-exp", h_offer=749500, h_13=785500, h_act=None, tip_h=785700)
    # T_offer at 749500 -> h_13 = 749500 + 36000 == 785500 (exact check_until_h == last_update + 36000!)
    add(
        "d11-bnd-b2-expired-at-exact-h13-rejected",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_b2_end_exp["chain"], "expect_active_name": "id/alice-v1", "expect_rebind_outcome": "rejected", "origin_bundle": rb_b2_end_exp["origin_bundle"], "trusted_origin_issuer_pins": rb_b2_end_exp["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: B_2 expired at exact check_until_h == updates[-1] + 36000 MUST reject 0x13 (boundary >=).",
    )

    # E3. delay_blocks == 35000 exact maximum boundary (M6: strictly < 36000 mainnet expiry!) -> ADMIT_AUTONOMOUS!
    rb_max_d = _build_autonomous_origin_rebind_fixture("bnd-max-35000", recovery_mode="none", delay_blocks=35000, h_offer=749500, h_13=749600, h_act=784600, tip_h=784610)
    # Insert benign renewal of B_2 inside the 35000-block delay (at 770000) before Step 3 at 784600 so B_2 stays live!
    b2_u_max = rb_max_d["chain"]["names"]["id/alice-v2"]["updates"]
    s3_u = b2_u_max.pop()
    ren1_tx = _h32("maxd-ren1")
    b2_u_max.append({
        "block_time": 1795212000, "confirmed_height": 770000, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_max_d["_b2_pol"])), name=b"id/alice-v2", value=b"{}").hex(),
        "owner_policy": rb_max_d["_b2_pol"], "prev_input": {"sighash_bytes": [1], "txid": b2_u_max[-1]["txid"], "vout": 0, "witness_policy": rb_max_d["_b2_pol"]},
        "txid": ren1_tx, "vout": 0,
    })
    s3_u["prev_input"]["txid"] = ren1_tx
    b2_u_max.append(s3_u)
    add(
        "d11-bnd-0x13-delay-exact-max-35000-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_max_d["chain"], "expect_active_name": "id/alice-v2", "origin_bundle": rb_max_d["origin_bundle"], "trusted_origin_issuer_pins": rb_max_d["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 M6: Voluntary rebind at exact maximum delay_blocks == 35000 (< 36000 mainnet expiry) admits (boundary <= 35000).",
    )
    add(
        "d12-m6-0x13-delay-above-35000-wire-integer",
        ["SL-ORIG-017"],
        "raw_wire",
        {"object": dict(rb_max_d["_b2"], delay_blocks=35001)},
        "REFUSE",
        "WIRE_INTEGER",
        "SL-ORIG-017 M6: Voluntary NameBinding with delay_blocks=35001 (> 35000 schema maximum) MUST refuse WIRE_INTEGER.",
    )

    # E4. _check_b2_step3_activated exact expiry boundary (L3080)
    rb_s3_gap = _build_autonomous_origin_rebind_fixture("bnd-s3-gap", recovery_mode="none", delay_blocks=144, h_offer=749500, h_13=749600, h_act=785500, tip_h=785510)
    # Step 3 update at exact h_offer (749500) + 36000 == 785500 -> B_2 expired before Step 3!
    add(
        "d11-bnd-b2-step3-exact-expiry-gap-refuse",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_s3_gap["chain"], "origin_bundle": rb_s3_gap["origin_bundle"], "trusted_origin_issuer_pins": rb_s3_gap["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-017: Step 3 activation on B_2 at exact prev_h + 36000 fails expiry check -> ORIGIN_BINDING_INVALID.",
    )

    # E5. _collect_0x13_events exact eval_h boundary (L3686) & verify_assent exact anchor_height == h_13 (L4779)
    add(
        "d11-bnd-0x13-at-exact-eval-h-pending-recovery-forbidden",
        ["SL-ORIG-017"],
        "origin_status",
        {
            "at_height": 749600,
            "chain": rb_none["chain"],
            "origin_bundle": rb_none["origin_bundle"],
            "trusted_origin_issuer_pins": rb_none["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "RECOVERY_FORBIDDEN",
        "SL-ORIG-017: Querying origin_status at exact at_height == h_13 collects 0x13 and refuses RECOVERY_FORBIDDEN (boundary <= eval_h).",
    )
    add(
        "d11-bnd-assent-unresolved-0x13-at-exact-anchor-height-incomplete",
        ["SL-ORIG-017"],
        "assent",
        {"anchor_height": 749990, "anchor_time": 1795219950, "assent": ass_no_oid, "chain": as_no_oid["chain"], "contract": c_no_oid},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: Autonomous assent at exact anchor_height == h_13 without origin_bundle refuses ORIGIN_STATUS_INCOMPLETE (boundary <=).",
    )

    # E6. Exact emancipation boundaries in Phase 1 (L3808 cap_at_h, L3809 maj_at_h) & Phase 2 _promote_pending_rec (L3650, L3653)
    def _build_exact_emancipate_then_rebind(tag: str, *, mode: str) -> dict[str, Any]:
        """mode in ('p2_cap', 'p2_maj', 'p1_cap', 'p1_maj')."""
        fx_e = rm._base_origin_fixture()
        oid_e = fx_e["_origin_id"]
        b1_e = fx_e["origin_bundle"]["name_binding"]
        orig_p_e = fx_e["origin_bundle"]["origin"]["payload"]
        reg_sk_e = fx_e["_keys"]["reg_cred"]["sk"]
        stat_s = orig_p_e["status_seal"]
        b2_pol_e = {"kind": "key", "pk": _kp(f"{tag}-b2")["comp"]}
        b2_reg_e = {"txid": _h32(f"{tag}-b2-reg"), "vout": 0}
        b3_pol_e = {"kind": "key", "pk": _kp(f"{tag}-b3")["comp"]}
        b3_reg_e = {"txid": _h32(f"{tag}-b3-reg"), "vout": 0}
        b3_off_tx = _h32(f"{tag}-b3-off")
        b3_reb_tx = _h32(f"{tag}-b3-reb")

        if mode in ("p2_cap", "p2_maj"):
            # 0x0c at 749200, delay=144 -> h_promo = 749344; self-update on B_rec at 749344; T_rebind at 749344 (same block as promo!)
            # If Phase 2 _promote_pending_rec fails to set is_autonomous=True at H=749344, Phase 4 at H=749344 REJECTS 0x13!
            h_promo = 749344
            if mode == "p2_cap":
                cap_p_e = {
                    "basis_sha256": _h32(f"{tag}-cap-b"), "genesis": GENESIS_MAIN, "issued_at": 1795205000,
                    "issuer": orig_p_e["issuer"], "network": "main",
                    "next_status_policy": stat_s["script_policy"], "next_status_vout": 0, "origin_id": oid_e,
                    "status_prev_outpoint": {"txid": stat_s["txid"], "vout": stat_s["vout"]},
                    "subject_new_owner_policy": b2_pol_e, "type": "seallink-capacity/1",
                }
                cap_e = sl.sign_envelope(cap_p_e, [reg_sk_e])
                cap_tx_e = _h32(f"{tag}-cap-tx")
                fx_e["chain"]["txs"][stat_s["txid"]]["outputs"][str(stat_s["vout"])]["spent_by_txid"] = cap_tx_e
                fx_e["chain"]["txs"][cap_tx_e] = {
                    "confirmed_height": h_promo,  # EXACT h_promo == cap_confirmed_height!
                    "inputs": [sv.make_segwit_input(stat_s["txid"], stat_s["vout"])],
                    "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_e)).hex(),
                    "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_s["script_policy"])}},
                }
                fx_e["origin_bundle"]["capacity_record"] = cap_e
            else:
                maj_t = fx_e["origin_bundle"]["opened_majority_unix"]
                fx_e["chain"]["now"] = maj_t + 5000
                fx_e["chain"]["tip_median_time_past"] = maj_t + 5000
                fx_e["chain"]["clock_watermark"] = maj_t + 4000
                fx_e["chain"]["tip_header_time"] = maj_t + 4990
                fx_e["chain"]["tip_first_sight"] = maj_t + 4995
                fx_e["chain"]["credible_utc_interval"] = [maj_t + 4950, maj_t + 5050]
                fx_e["chain"]["block_times"] = {str(h_promo): maj_t, str(fx_e["chain"]["tip_height"]): maj_t + 5000}  # EXACT promo_bt == opened_majority!

            rec_b2_e = {
                "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": f"id/{tag}-brec", "network": "main",
                "next_recovery_policy": orig_p_e["name_recovery"]["recovery_seal"]["script_policy"], "next_recovery_vout": 0,
                "origin_id": oid_e, "owner_policy": b2_pol_e, "registration": b2_reg_e, "seq": 2,
                "supersedes_binding_id": sl.object_id(b1_e), "type": "seallink-name-binding/1",
            }
            rs_e = orig_p_e["name_recovery"]["recovery_seal"]
            rtx_e = _h32(f"{tag}-0x0c")
            fx_e["chain"]["txs"][rs_e["txid"]]["outputs"][str(rs_e["vout"])]["spent_by_txid"] = rtx_e
            fx_e["chain"]["txs"][rtx_e] = {
                "confirmed_height": 749200, "inputs": [sv.make_segwit_input(rs_e["txid"], rs_e["vout"])],
                "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(rec_b2_e)).hex(),
                "outputs": {"0": {"script_pubkey_hex": _spk_hex(rs_e["script_policy"])}},
            }
            brec_h = sv.make_name_history(f"id/{tag}-brec", b2_reg_e, b2_pol_e, {"link": {"origin": oid_e}}, first_height=749150, update_height=h_promo)
            b3_reb_e = {
                "binding_mode": "voluntary", "consent_outpoint": {"txid": b3_off_tx, "vout": 1}, "delay_blocks": 144,
                "genesis": GENESIS_MAIN, "name": f"id/{tag}-v3", "network": "main", "origin_id": oid_e,
                "owner_policy": b3_pol_e, "registration": b3_reg_e, "seq": 3, "supersedes_binding_id": sl.object_id(rec_b2_e),
                "type": "seallink-name-binding/1",
            }
            prev_u_e = brec_h["updates"][-1]
            brec_h["updates"].append({
                "block_time": 1795212000, "confirmed_height": h_promo, "op": "NAME_UPDATE",
                "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_reb_e)).hex(),
                "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b2_pol_e)), name=f"id/{tag}-brec".encode("utf-8"), value=b"{}").hex(),
                "owner_policy": b2_pol_e, "prev_input": {"sighash_bytes": [1], "txid": prev_u_e["txid"], "vout": prev_u_e["vout"], "witness_policy": b2_pol_e},
                "txid": b3_reb_tx, "version": 0x7100, "vout": 0,
            })
            b3_h = {
                "registration": b3_reg_e,
                "updates": [
                    {"block_time": 1795210000, "confirmed_height": 749250, "op": "NAME_FIRSTUPDATE", "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v3".encode("utf-8"), rand=b"\x0a" * 20, value=b"{}").hex(), "owner_policy": b3_pol_e, "txid": b3_reg_e["txid"], "vout": 0},
                    {"block_time": 1795211000, "confirmed_height": 749300, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v3".encode("utf-8"), value=b"{}").hex(), "owner_policy": b3_pol_e, "prev_input": {"sighash_bytes": [1], "txid": b3_reg_e["txid"], "vout": 0, "witness_policy": b3_pol_e}, "txid": b3_off_tx, "version": 0x7100, "vout": 0},
                    {"block_time": 1795216000, "confirmed_height": h_promo + 144, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v3".encode("utf-8"), value=sl.jcs_encode({"link": {"origin": oid_e}})).hex(), "owner_policy": b3_pol_e, "prev_input": {"sighash_bytes": [1], "txid": b3_off_tx, "vout": 0, "witness_policy": b3_pol_e}, "txid": _h32(f"{tag}-s3"), "vout": 0},
                ],
            }
            fx_e["chain"]["names"][f"id/{tag}-brec"] = brec_h
            fx_e["chain"]["names"][f"id/{tag}-v3"] = b3_h
            fx_e["chain"]["txs"][b3_off_tx] = {"confirmed_height": 749300, "version": 0x7100, "outputs": {"1": {"script_pubkey_hex": _spk_hex(b3_pol_e), "spent_by_txid": b3_reb_tx}}}
            fx_e["chain"]["txs"][b3_reb_tx] = {"confirmed_height": h_promo, "version": 0x7100, "inputs": [sv.make_segwit_input(b3_off_tx, 1), sv.make_segwit_input(prev_u_e["txid"], 0)], "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_reb_e)).hex(), "outputs": {}}
            fx_e["origin_bundle"]["recovery_bindings"] = [rec_b2_e]
            fx_e["origin_bundle"]["voluntary_rebind_bindings"] = [b3_reb_e]
            return {"chain": fx_e["chain"], "expect_active_name": f"id/{tag}-v3", "origin_bundle": fx_e["origin_bundle"], "trusted_origin_issuer_pins": fx_e["trusted_origin_issuer_pins"]}

        if mode == "p1_maj":
            # Post-trigger 0x0c promotes at h_promo=749250 (no self-update yet); B_rec self-updates at H=749300 with block_times[749300]==maj_t AND T_rebind at H=749300!
            # Kills L3809 (Phase 1 bt_h >= opened_majority): if >= -> >, Phase 1 at H=749300 skips emancipation and Phase 4 rejects 0x13!
            h_promo = 749250
            h_em = 749300
            maj_t = fx_e["origin_bundle"]["opened_majority_unix"]
            fx_e["chain"]["now"] = maj_t + 5000
            fx_e["chain"]["tip_median_time_past"] = maj_t + 5000
            fx_e["chain"]["clock_watermark"] = maj_t + 4000
            fx_e["chain"]["tip_header_time"] = maj_t + 4990
            fx_e["chain"]["tip_first_sight"] = maj_t + 4995
            fx_e["chain"]["credible_utc_interval"] = [maj_t + 4950, maj_t + 5050]
            fx_e["chain"]["block_times"] = {str(h_promo): maj_t, str(h_em): maj_t, str(fx_e["chain"]["tip_height"]): maj_t + 5000}
            rec_b2_e = {
                "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": f"id/{tag}-brec", "network": "main",
                "next_recovery_policy": orig_p_e["name_recovery"]["recovery_seal"]["script_policy"], "next_recovery_vout": 0,
                "origin_id": oid_e, "owner_policy": b2_pol_e, "registration": b2_reg_e, "seq": 2,
                "supersedes_binding_id": sl.object_id(b1_e), "type": "seallink-name-binding/1",
            }
            rs_e = orig_p_e["name_recovery"]["recovery_seal"]
            rtx_e = _h32(f"{tag}-0x0c")
            fx_e["chain"]["txs"][rs_e["txid"]]["outputs"][str(rs_e["vout"])]["spent_by_txid"] = rtx_e
            fx_e["chain"]["txs"][rtx_e] = {
                "confirmed_height": h_promo - 144, "inputs": [sv.make_segwit_input(rs_e["txid"], rs_e["vout"])],
                "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(rec_b2_e)).hex(),
                "outputs": {"0": {"script_pubkey_hex": _spk_hex(rs_e["script_policy"])}},
            }
            brec_h = sv.make_name_history(f"id/{tag}-brec", b2_reg_e, b2_pol_e, {"link": {"origin": oid_e}}, first_height=749050, update_height=h_em)
            b3_reb_e = {
                "binding_mode": "voluntary", "consent_outpoint": {"txid": b3_off_tx, "vout": 1}, "delay_blocks": 144,
                "genesis": GENESIS_MAIN, "name": f"id/{tag}-v3", "network": "main", "origin_id": oid_e,
                "owner_policy": b3_pol_e, "registration": b3_reg_e, "seq": 3, "supersedes_binding_id": sl.object_id(rec_b2_e),
                "type": "seallink-name-binding/1",
            }
            prev_u_e = brec_h["updates"][-1]
            brec_h["updates"].append({
                "block_time": maj_t, "confirmed_height": h_em, "op": "NAME_UPDATE",
                "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_reb_e)).hex(),
                "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b2_pol_e)), name=f"id/{tag}-brec".encode("utf-8"), value=b"{}").hex(),
                "owner_policy": b2_pol_e, "prev_input": {"sighash_bytes": [1], "txid": prev_u_e["txid"], "vout": prev_u_e["vout"], "witness_policy": b2_pol_e},
                "txid": b3_reb_tx, "version": 0x7100, "vout": 0,
            })
            b3_h = {
                "registration": b3_reg_e,
                "updates": [
                    {"block_time": maj_t - 100, "confirmed_height": 749200, "op": "NAME_FIRSTUPDATE", "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v3".encode("utf-8"), rand=b"\x0c" * 20, value=b"{}").hex(), "owner_policy": b3_pol_e, "txid": b3_reg_e["txid"], "vout": 0},
                    {"block_time": maj_t - 50, "confirmed_height": 749260, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v3".encode("utf-8"), value=b"{}").hex(), "owner_policy": b3_pol_e, "prev_input": {"sighash_bytes": [1], "txid": b3_reg_e["txid"], "vout": 0, "witness_policy": b3_pol_e}, "txid": b3_off_tx, "version": 0x7100, "vout": 0},
                    {"block_time": maj_t + 1000, "confirmed_height": h_em + 144, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v3".encode("utf-8"), value=sl.jcs_encode({"link": {"origin": oid_e}})).hex(), "owner_policy": b3_pol_e, "prev_input": {"sighash_bytes": [1], "txid": b3_off_tx, "vout": 0, "witness_policy": b3_pol_e}, "txid": _h32(f"{tag}-s3"), "vout": 0},
                ],
            }
            fx_e["chain"]["names"][f"id/{tag}-brec"] = brec_h
            fx_e["chain"]["names"][f"id/{tag}-v3"] = b3_h
            fx_e["chain"]["txs"][b3_off_tx] = {"confirmed_height": 749260, "version": 0x7100, "outputs": {"1": {"script_pubkey_hex": _spk_hex(b3_pol_e), "spent_by_txid": b3_reb_tx}}}
            fx_e["chain"]["txs"][b3_reb_tx] = {"confirmed_height": h_em, "version": 0x7100, "inputs": [sv.make_segwit_input(b3_off_tx, 1), sv.make_segwit_input(prev_u_e["txid"], 0)], "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b3_reb_e)).hex(), "outputs": {}}
            fx_e["origin_bundle"]["recovery_bindings"] = [rec_b2_e]
            fx_e["origin_bundle"]["voluntary_rebind_bindings"] = [b3_reb_e]
            return {"chain": fx_e["chain"], "expect_active_name": f"id/{tag}-v3", "origin_bundle": fx_e["origin_bundle"], "trusted_origin_issuer_pins": fx_e["trusted_origin_issuer_pins"]}

        # p1_cap: Cooperative handover on B_1 completes at H_em = 749300 AND T_rebind is AT H_em = 749300!
        h_em = 749300
        cap_p_e = {
            "basis_sha256": _h32(f"{tag}-cap-b"), "genesis": GENESIS_MAIN, "issued_at": 1795205000,
            "issuer": orig_p_e["issuer"], "network": "main",
            "next_status_policy": stat_s["script_policy"], "next_status_vout": 0, "origin_id": oid_e,
            "status_prev_outpoint": {"txid": stat_s["txid"], "vout": stat_s["vout"]},
            "subject_new_owner_policy": b2_pol_e, "type": "seallink-capacity/1",
        }
        cap_e = sl.sign_envelope(cap_p_e, [reg_sk_e])
        cap_tx_e = _h32(f"{tag}-cap-tx")
        fx_e["chain"]["txs"][stat_s["txid"]]["outputs"][str(stat_s["vout"])]["spent_by_txid"] = cap_tx_e
        fx_e["chain"]["txs"][cap_tx_e] = {
            "confirmed_height": h_em,  # EXACT H == cap_confirmed_height!
            "inputs": [sv.make_segwit_input(stat_s["txid"], stat_s["vout"])],
            "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_e)).hex(),
            "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_s["script_policy"])}},
        }
        fx_e["origin_bundle"]["capacity_record"] = cap_e

        # Cooperative handover on B_1 (id/child-leo): transfer to b2_pol_e + adult self-update + T_rebind ALL on block h_em = 749300!
        b1_u = fx_e["chain"]["names"]["id/child-leo"]["updates"]
        p_b1 = b1_u[-1]
        xfer_tx = _h32(f"{tag}-xfer")
        self_tx = _h32(f"{tag}-self")
        em_bt = fx_e["origin_bundle"]["opened_majority_unix"] if mode == "p1_maj" else 1795210000
        b1_u.append({
            "block_time": em_bt, "confirmed_height": h_em, "op": "NAME_UPDATE",
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b2_pol_e)), name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": oid_e}})).hex(),
            "owner_policy": b2_pol_e, "prev_input": {"sighash_bytes": [1], "txid": p_b1["txid"], "vout": p_b1["vout"], "witness_policy": b1_e["owner_policy"]},
            "txid": xfer_tx, "vout": 0,
        })
        b1_u.append({
            "block_time": em_bt, "confirmed_height": h_em, "op": "NAME_UPDATE",
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b2_pol_e)), name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": oid_e}})).hex(),
            "owner_policy": b2_pol_e, "prev_input": {"sighash_bytes": [1], "txid": xfer_tx, "vout": 0, "witness_policy": b2_pol_e},
            "txid": self_tx, "vout": 0,
        })
        b2_reb_e = {
            "binding_mode": "voluntary", "consent_outpoint": {"txid": b3_off_tx, "vout": 1}, "delay_blocks": 144,
            "genesis": GENESIS_MAIN, "name": f"id/{tag}-v2", "network": "main", "origin_id": oid_e,
            "owner_policy": b3_pol_e, "registration": b3_reg_e, "seq": 2, "supersedes_binding_id": sl.object_id(b1_e),
            "type": "seallink-name-binding/1",
        }
        b1_u.append({
            "block_time": em_bt, "confirmed_height": h_em, "op": "NAME_UPDATE",
            "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b2_reb_e)).hex(),
            "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b2_pol_e)), name=b"id/child-leo", value=b"{}").hex(),
            "owner_policy": b2_pol_e, "prev_input": {"sighash_bytes": [1], "txid": self_tx, "vout": 0, "witness_policy": b2_pol_e},
            "txid": b3_reb_tx, "version": 0x7100, "vout": 0,
        })
        b2_h_e = {
            "registration": b3_reg_e,
            "updates": [
                {"block_time": 1795208000, "confirmed_height": 749250, "op": "NAME_FIRSTUPDATE", "output_script_hex": sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v2".encode("utf-8"), rand=b"\x0b" * 20, value=b"{}").hex(), "owner_policy": b3_pol_e, "txid": b3_reg_e["txid"], "vout": 0},
                {"block_time": 1795209000, "confirmed_height": 749280, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v2".encode("utf-8"), value=b"{}").hex(), "owner_policy": b3_pol_e, "prev_input": {"sighash_bytes": [1], "txid": b3_reg_e["txid"], "vout": 0, "witness_policy": b3_pol_e}, "txid": b3_off_tx, "version": 0x7100, "vout": 0},
                {"block_time": 1795215000, "confirmed_height": h_em + 144, "op": "NAME_UPDATE", "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(b3_pol_e)), name=f"id/{tag}-v2".encode("utf-8"), value=sl.jcs_encode({"link": {"origin": oid_e}})).hex(), "owner_policy": b3_pol_e, "prev_input": {"sighash_bytes": [1], "txid": b3_off_tx, "vout": 0, "witness_policy": b3_pol_e}, "txid": _h32(f"{tag}-s3"), "vout": 0},
            ],
        }
        fx_e["chain"]["names"][f"id/{tag}-v2"] = b2_h_e
        fx_e["chain"]["txs"][b3_off_tx] = {"confirmed_height": 749280, "version": 0x7100, "outputs": {"1": {"script_pubkey_hex": _spk_hex(b3_pol_e), "spent_by_txid": b3_reb_tx}}}
        fx_e["chain"]["txs"][b3_reb_tx] = {"confirmed_height": h_em, "version": 0x7100, "inputs": [sv.make_segwit_input(b3_off_tx, 1), sv.make_segwit_input(self_tx, 0)], "opreturn_hex": sl.encode_opreturn(0x13, sl.object_id(b2_reb_e)).hex(), "outputs": {}}
        fx_e["origin_bundle"]["voluntary_rebind_bindings"] = [b2_reb_e]
        return {"chain": fx_e["chain"], "expect_active_name": f"id/{tag}-v2", "origin_bundle": fx_e["origin_bundle"], "trusted_origin_issuer_pins": fx_e["trusted_origin_issuer_pins"]}

    for m_tag, m_mode, m_desc in [
        ("bnd-p2cap", "p2_cap", "Phase 2 _promote_pending_rec at exact h_promo == cap_confirmed_height emancipates & permits same-block 0x13."),
        ("bnd-p2maj", "p2_maj", "Phase 2 _promote_pending_rec at exact promo_bt == opened_majority emancipates & permits same-block 0x13."),
        ("bnd-p1cap", "p1_cap", "Phase 1 cooperative handover at exact H == cap_confirmed_height emancipates & permits same-block 0x13."),
        ("bnd-p1maj", "p1_maj", "Phase 1 cooperative handover at exact block_times[H] == opened_majority emancipates & permits same-block 0x13."),
    ]:
        add(f"d11-{m_tag}-exact-boundary-admit", ["SL-ORIG-017", "SL-ORIG-011"], "origin_status", _build_exact_emancipate_then_rebind(m_tag, mode=m_mode), "ADMIT_AUTONOMOUS", None, f"SL-ORIG-017: {m_desc}")

    # E7. verify_log_checkpoint idempotent re-verification of exact same seq == max_seq (0 journal writes!)
    j_idem_cp2 = {
        "initial_entries": [{
            "body": {
                "block_hash": nlog["chain"]["txs"][nlog["cp2_tx"]]["block_hash"],
                "checkpoint_id": nlog["cp2_ca"],
                "checkpoint_object_id": nlog["cp2_oid"],
                "checkpoint_txid": nlog["cp2_tx"],
                "checkpoints_root": nlog["cp2_env"]["payload"]["checkpoints_root"],
                "confirmed_height": 749990, "denials_root": nlog["cp2_env"]["payload"]["denials_root"],
                "log_id": nlog["log_id"], "max_seq": 2,
                "next_log_outpoint": {"txid": nlog["cp2_tx"], "vout": 1},
                "next_log_policy": nlog["seal_pol"],
                "role": "notary", "terminal": False,
            },
            "kind": "log-head",
        }],
        "journal_id": _h32("j-idem-cp2"),
    }
    add(
        "d11-bnd-cp-idempotent-same-seq-log-head-zero-writes",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": nlog["chain_at_cp2"], "checkpoint": nlog["cp2_env"], "checkpoint_txid": nlog["cp2_tx"], "expect_journal_writes": 0, "journal": j_idem_cp2},
        "ADMIT",
        None,
        "SL-CONT-012: Re-verifying identical checkpoint at exact seq == max_seq admits with 0 duplicate log-head writes.",
    )

    # E8. verify_log_fraud _auth_cp exact depth boundary (tip 750010 - h_cp2 749990 + 1 == 21!)
    cp2_eq_alt = sl.sign_envelope({**nlog["cp2_env"]["payload"], "denials_root": _h32("alt-denials-eq")}, [nlog["iss_role"]["sk"]])
    add(
        "d11-bnd-fraud-auth-cp-exact-depth-admit",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": nlog["chain"],
            "fraud": {
                "cp_a": nlog["cp2_env"], "cp_a_txid": nlog["cp2_tx"], "cp_b": cp2_eq_alt,
                "fraud_mode": "equivocation", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
            },
            "operator_min_depth": 21,
        },
        "ADMIT",
        None,
        "SL-CONT-013: Fraud proof confirmed checkpoint at exact depth == operator_min_depth (21) admits.",
    )

    # E9. verify_tier2_name_history_page exact len(updates)==limit AND chained same-block updates (OP_NAME_FIRSTUPDATE -> OP_NAME_UPDATE)!
    add(
        "d11-bnd-tier2-exact-limit-and-same-height-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [{"header_hex": spv_pair_hdr.hex(), "height": 750010}],
            "page": {
                **_mk_page("id/spv-chained", spv_pair_upds, limit=2, registration=spv_pair_reg),
                "network": "regtest",
            },
            "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "SL-ARTF-005 B4: Tier-2 page with len(updates) == limit (2), OP_NAME_FIRSTUPDATE -> OP_NAME_UPDATE chained in the same block (tx_index 1 < 2), admits.",
        module="artifact-notarization",
    )

    # E10. Journal log-head already at cp2 (seq=2): ancestor inclusion cp1 with fresh head cp2 ADMITS,
    #      whereas presenting stale head cp1 (seq=1 < max_seq=2) REFUSES non-closing CHAIN_FRAME_INVALID!
    add(
        "d11-bnd-log-ancestor-cp1-admits-when-journal-at-cp2",
        ["SL-CONT-012", "SL-CONT-010"],
        "notary_act",
        {
            "chain": nlog["chain_at_cp2"],
            "journal": j_idem_cp2,
            "log_ctx": {
                "batch_proof": nlog["b1_proof"],
                "checkpoint": nlog["cp1_env"],
                "checkpoint_txid": nlog["cp1_tx"],
                "checkpoints_proof": sl.rfc9162_inclusion_proof([sl.ckpt_leaf(1, nlog["cp1_ca"])], 0),
                "head_checkpoint": nlog["cp2_env"],
                "head_checkpoint_txid": nlog["cp2_tx"],
                "smt_proof": sl.smt_prove({}, nlog["denial_key"]),
            },
            "notary": nlog["item_env"],
        },
        "ADMIT",
        None,
        "SL-CONT-012: Historical inclusion checkpoint cp1 (seq=1) proven under fresh head cp2 (seq=2) MUST admit when journal log-head is already at max_seq=2.",
    )
    add(
        "d11-bnd-log-stale-head-cp1-refused-when-journal-at-cp2",
        ["SL-CONT-012", "SL-CONT-010"],
        "notary_act",
        {
            "chain": nlog["chain_at_cp2"],
            "journal": j_idem_cp2,
            "log_ctx": {
                "batch_proof": nlog["b1_proof"],
                "checkpoint": nlog["cp1_env"],
                "checkpoint_txid": nlog["cp1_tx"],
                "smt_proof": sl.smt_prove({}, nlog["denial_key"]),
            },
            "notary": nlog["item_env"],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B2: Presenting stale head checkpoint cp1 (seq=1 < journal max_seq=2) refuses non-closing CHAIN_FRAME_INVALID (matching fresh verifier).",
    )

    # =========================================================================
    # SECTION F: v1.0.0-draft.12 AUDIT CLOSURE REGRESSIONS (B1-B8, H1-H5, M3-M4)
    # =========================================================================

    # F1 (B1): Cross-issuer log_id forgery on seq>=2 checkpoint & equivocation fraud, plus journal same-seq equivocation vs multisig subset invariance
    n2_forg_cp2_p = {
        **nlog["cp2_env"]["payload"],
        "issuer": n2["iss_role_pin"],  # Attacker n2 claims victim nlog's log_id & genesis_seal_outpoint!
    }
    n2_forg_cp2 = sl.sign_envelope(n2_forg_cp2_p, [n2["iss_role"]["sk"]])
    ch_b1_forg = copy.deepcopy(gk_chain)
    b1_forg_tx = _h32("d12-b1-forg-cp2-tx")
    ch_b1_forg["txs"][nlog["cp1_tx"]]["outputs"]["1"]["spent_by_txid"] = b1_forg_tx
    ch_b1_forg["txs"][b1_forg_tx] = {
        "block_hash": _h32("d12-b1-forg-blk"),
        "confirmed_height": 749991,
        "inputs": [sv.make_segwit_input(nlog["cp1_tx"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(n2_forg_cp2)).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"])}},
    }
    add(
        "d12-b1-cross-issuer-log-id-forgery-cp-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_b1_forg, "checkpoint": n2_forg_cp2, "checkpoint_txid": b1_forg_tx},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B1: Attacker signing seq>=2 checkpoint claiming victim log_id MUST fail unconditional compute_log_id binding.",
    )
    add(
        "d12-b1-cross-issuer-equivocation-fraud-refuse",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": gk_chain,
            "fraud": {
                "cp_a": nlog["cp2_env"], "cp_a_txid": nlog["cp2_tx"], "cp_b": n2_forg_cp2,
                "fraud_mode": "equivocation", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B1: Cross-issuer equivocation fraud proof forging victim log_id MUST refuse CHAIN_FRAME_INVALID.",
    )
    cp2_diff_oid = sl.sign_envelope({**nlog["cp2_env"]["payload"], "denials_root": _h32("d12-b1-equiv-root")}, [nlog["iss_role"]["sk"]])
    ch_b1_eq = copy.deepcopy(nlog["chain_at_cp2"])
    ch_b1_eq["txs"][nlog["cp2_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp2_diff_oid)).hex()
    add(
        "d12-b1-same-seq-equivocation-journal-compromised",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_b1_eq, "checkpoint": cp2_diff_oid, "checkpoint_txid": nlog["cp2_tx"], "journal": j_idem_cp2},
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-CONT-012 B1: Same-seq checkpoint with different object_id(payload) against persisted log-head MUST refuse NOTARY_LOG_COMPROMISED.",
    )
    # 2-of-3 multisig notary signing SAME cp1 payload with subset {k1,k2} vs {k1,k3}: identical object_id(payload) -> NOT equivocation!
    ms_own = _kp("d12-ms-own")
    ms_r1, ms_r2, ms_r3 = _kp("d12-ms-r1"), _kp("d12-ms-r2"), _kp("d12-ms-r3")
    ms_pks = sorted([ms_r1["xonly"], ms_r2["xonly"], ms_r3["xonly"]])
    ms_pol = {"kind": "key", "pk": ms_own["comp"]}
    ms_reg = {"txid": _h32("d12-ms-reg"), "vout": 0}
    ms_gen = _h32("d12-ms-gen")
    ms_cp1_tx = _h32("d12-ms-cp1-tx")
    ms_lid = sl.compute_log_id("main", GENESIS_MAIN, "notary", "id/d12-ms-notary", ms_reg, {"txid": ms_gen, "vout": 0})
    ms_role_pol = {"m": 2, "pks": ms_pks}
    ms_iss_pin = {"name": "id/d12-ms-notary", "owner_policy": ms_pol, "registration": ms_reg, "role_policy": ms_role_pol}
    ms_cp1_p = {
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 0, "denials_delta_root": sl.EMPTY_BATCH_ROOT, "denials_root": sl.SMT_EMPTY_ROOT,
        "genesis": GENESIS_MAIN, "genesis_seal_outpoint": {"txid": ms_gen, "vout": 0},
        "issuer": ms_iss_pin, "log_id": ms_lid, "network": "main",
        "next_log_policy": nlog["seal_pol"], "next_log_vout": 1,
        "prev_log_outpoint": {"txid": ms_gen, "vout": 0}, "role": "notary", "seq": 1, "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }
    ms_sk_map = {ms_r1["xonly"]: ms_r1["sk"], ms_r2["xonly"]: ms_r2["sk"], ms_r3["xonly"]: ms_r3["sk"]}
    ms_cp1_ab = sl.sign_envelope(ms_cp1_p, [ms_sk_map[ms_pks[0]], ms_sk_map[ms_pks[1]]], policy_pks=ms_pks, m=2)
    ms_cp1_ac = sl.sign_envelope(ms_cp1_p, [ms_sk_map[ms_pks[0]], ms_sk_map[ms_pks[2]]], policy_pks=ms_pks, m=2)
    assert sl.content_addr(ms_cp1_ab) != sl.content_addr(ms_cp1_ac) and sl.object_id(ms_cp1_ab["payload"]) == sl.object_id(ms_cp1_ac["payload"])
    ch_ms = copy.deepcopy(nlog["chain_at_cp1"])
    ch_ms["names"]["id/d12-ms-notary"] = sv.make_name_history("id/d12-ms-notary", ms_reg, ms_pol, {"link": {"notary": {"p": sv._policy_sha256(ms_role_pol)}}}, first_height=749000, update_height=749100)
    ch_ms["txs"][ms_gen] = {"confirmed_height": 749150, "outputs": {"0": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"]), "spent_by_txid": ms_cp1_tx}}}
    ch_ms["txs"][ms_cp1_tx] = {"block_hash": _h32("d12-ms-blk"), "confirmed_height": 749990, "inputs": [sv.make_segwit_input(ms_gen, 0)], "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(ms_cp1_ac)).hex(), "outputs": {"1": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"])}}}
    add(
        "d12-b1-multisig-different-subset-same-payload-not-equivocation-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_ms, "checkpoint": ms_cp1_ac, "checkpoint_txid": ms_cp1_tx,
            "journal": {
                "journal_id": _h32("d12-ms-j"),
                "initial_entries": [{
                    "body": {
                        "block_hash": _h32("d12-ms-blk"), "checkpoint_id": sl.content_addr(ms_cp1_ab),
                        "checkpoint_object_id": sl.object_id(ms_cp1_p), "checkpoint_txid": ms_cp1_tx,
                        "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT, "confirmed_height": 749990,
                        "denials_root": sl.SMT_EMPTY_ROOT, "log_id": ms_lid, "max_seq": 1,
                        "next_log_outpoint": {"txid": ms_cp1_tx, "vout": 1}, "next_log_policy": nlog["seal_pol"],
                        "role": "notary", "terminal": False,
                    },
                    "kind": "log-head",
                }],
            },
        },
        "ADMIT",
        None,
        "SL-CONT-012 B1: Re-signing identical checkpoint payload with different m-of-n threshold subset has identical object_id(payload) and is NOT equivocation.",
    )

    # F2 (B2): Fresh verifier stale head suppression, log_seal UTXO chain auth, & authenticated O(1) handover!
    add(
        "d12-b2-fresh-verifier-stale-cp2-head-rejected",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": nlog["chain"], "checkpoint": nlog["cp2_env"], "checkpoint_txid": nlog["cp2_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B2: Fresh verifier (no journal) MUST reject stale non-terminal cp2 whose next_log_vout is already spent by cp3.",
    )
    tkt_stale_fresh = {
        "artifact_identity": nlog["art"], "genesis": GENESIS_MAIN, "network": "main",
        "notarizations": [{
            "act_smt_proof": sl.smt_prove({}, nlog["denial_key"]),
            "batch_proof": nlog["b1_proof"],
            "checkpoint": nlog["cp1_env"], "checkpoint_txid": nlog["cp1_tx"],
            "checkpoints_proof": nlog["cp1_in_cp2_proof"],
            "head_checkpoint": nlog["cp2_env"], "head_checkpoint_txid": nlog["cp2_tx"],
            "notary_act": nlog["item_env"],
            "target_smt_proof": sl.smt_prove({}, f"target:{nlog['tid']}|*"),
        }],
        "target_sha256": nlog["tid"], "type": "seallink-ticket/1",
    }
    add(
        "d12-b2-fresh-verifier-stale-ticket-head-rejected",
        ["SL-CONT-012", "SL-ARTF-003"],
        "artifact_ticket",
        {"chain": nlog["chain"], "policy": post_pol, "ticket": tkt_stale_fresh},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-CONT-012 B2: Fresh Gatekeeper verifier MUST reject ticket presenting superseded head cp2 when cp3 spent cp2:next_log_vout.",
        module="artifact-notarization",
    )
    # Forged cp2 spending an arbitrary non-log UTXO (not cp1:1) -> CHAIN_FRAME_INVALID!
    rand_utxo_tx = _h32("d12-b2-rand-utxo")
    forg_cp2_tx = _h32("d12-b2-forg-cp2")
    forg_cp2_p = {**nlog["cp2_env"]["payload"], "prev_log_outpoint": {"txid": rand_utxo_tx, "vout": 0}}
    forg_cp2_env = sl.sign_envelope(forg_cp2_p, [nlog["iss_role"]["sk"]])
    ch_b2_utxo = copy.deepcopy(nlog["chain_at_cp1"])
    ch_b2_utxo["txs"][rand_utxo_tx] = {"confirmed_height": 749500, "outputs": {"0": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"]), "spent_by_txid": forg_cp2_tx}}}
    ch_b2_utxo["txs"][forg_cp2_tx] = {"block_hash": _h32("d12-b2-blk"), "confirmed_height": 749991, "inputs": [sv.make_segwit_input(rand_utxo_tx, 0)], "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(forg_cp2_env)).hex(), "outputs": {"1": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"])}}}
    add(
        "d12-b2-forged-cp2-spending-random-utxo-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_b2_utxo, "checkpoint": forg_cp2_env, "checkpoint_txid": forg_cp2_tx},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B2: seq>=2 checkpoint spending an arbitrary non-log UTXO (not chained back to genesis_seal_outpoint) refuses CHAIN_FRAME_INVALID.",
    )
    add(
        "d12-b2-unauthenticated-o1-handover-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_ho, "checkpoint": ho_cp1_env, "checkpoint_txid": ho_cp1_tx},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B2: seq=1 O(1) log handover WITHOUT predecessor_terminal_checkpoint or persisted terminal log-head refuses CHAIN_FRAME_INVALID.",
    )
    add(
        "d12-b2-compromised-predecessor-o1-handover-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_ho, "checkpoint": ho_cp1_env, "checkpoint_txid": ho_cp1_tx,
            "predecessor_terminal_checkpoint": ho_pred_term,
            "journal": {
                "journal_id": _h32("d12-b2-ho-comp"),
                "initial_entries": [{
                    "body": {"cause": "NOTARY_LOG_COMPROMISED", "observed_at": 1795219900, "observed_height": 750000, "subject": {"log_id": nlog["log_id"], "role": "notary", "subject_kind": "log"}},
                    "kind": "closure",
                }],
            },
        },
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-CONT-012 B2: O(1) handover from a fraud-closed predecessor log MUST refuse NOTARY_LOG_COMPROMISED.",
    )

    # F3 (B3): Namecoin Core nc28.0 consensus header checks (non-contiguous, non-retarget nBits drift, parent.IsAuxpow, parent_chain_id==1, missing chain_id)
    hdr_2017_gap = _mine_regtest_hdr(nmc_nonaux_ver, prev_hash_2015_le, b"\x33" * 32, 1795000000 + 605400, 0x207FFFFF)
    add(
        "d12-b3-non-contiguous-headers-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "headers": [{"header_hex": prev_hdr_2015.hex(), "height": 2015}, {"header_hex": hdr_2017_gap.hex(), "height": 2017}], "page": page_reg_empty, "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 B3: Non-contiguous header heights (2015 -> 2017) MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    hdr_2017_drift = _mine_regtest_hdr(nmc_nonaux_ver, bhash_2016_le, b"\x44" * 32, 1795000000 + 606000, 0x203FFFFF)
    add(
        "d12-b3-non-retarget-nbits-drift-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [
                {"header_hex": prev_hdr_2015.hex(), "height": 2015},
                {"auxpow": aux_proof_ok, "epoch_start_time": 1795000000, "header_hex": hdr_2016.hex(), "height": 2016},
                {"header_hex": hdr_2017_drift.hex(), "height": 2017},
            ],
            "page": page_reg_empty, "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 B3: Non-retarget height 2017 changing nBits (0x203fffff != prev 0x207fffff) refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    parent_hdr_is_aux = _mine_regtest_hdr(0x00000102, b"\x00" * 32, parent_cb_txid_le, 1795000000 + 605400, 0x207FFFFF)
    add(
        "d12-b3-auxpow-parent-is-auxpow-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "headers": [{"auxpow": {**aux_proof_ok, "parent_header_hex": parent_hdr_is_aux.hex()}, "header_hex": hdr_2016.hex(), "height": 2016}], "page": page_reg_empty, "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 B3: AuxPoW parent header with AuxPoW flag 0x100 set MUST refuse TICKET_PROOF_INVALID (!parentBlock.IsAuxpow()).",
        module="artifact-notarization",
    )
    parent_hdr_cid1 = _mine_regtest_hdr((0x0001 << 16) | 2, b"\x00" * 32, parent_cb_txid_le, 1795000000 + 605400, 0x207FFFFF)
    add(
        "d12-b3-auxpow-parent-chain-id-1-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "headers": [{"auxpow": {**aux_proof_ok, "parent_header_hex": parent_hdr_cid1.hex()}, "header_hex": hdr_2016.hex(), "height": 2016}], "page": page_reg_empty, "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 B3: AuxPoW parent header with chain_id==1 (fStrictChainId) MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    hdr_no_cid = _mine_regtest_hdr(2, b"\x00" * 32, b"\x11" * 32, 1795000000, 0x207FFFFF)
    add(
        "d12-b3-non-auxpow-missing-chain-id-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "headers": [{"header_hex": hdr_no_cid.hex(), "height": 2015}], "page": page_reg_empty, "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006 B3: Non-AuxPoW header with chain_id==0 (!= 1) MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # F4 (B4): Tier-2 OP_NAME_FIRSTUPDATE, unlinked update, cursor pagination, branch unsupported, non-empty scriptSig, same-block tx_index tie, bad SLNK
    proof_fu, hdr_fu = _build_synthetic_spv_proof("fu-only", spv_p2wpkh, [spv_k1["sk"]], "id/spv-fu", '{"link":{}}', op_kind="NAME_FIRSTUPDATE", block_height=750010)
    add(
        "d12-b4-tier2-firstupdate-only-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "headers": [{"header_hex": hdr_fu.hex(), "height": 750010}], "page": {**_mk_page("id/spv-fu", [proof_fu]), "network": "regtest"}, "pinned_network": "regtest"},
        "ADMIT",
        None,
        "SL-ARTF-005 B4: Standalone OP_NAME_FIRSTUPDATE spending OP_NAME_NEW (HASH160(rand||name)==hash20) admits in Tier-2.",
        module="artifact-notarization",
    )
    spv_reg_pol = {"kind": "key", "pk": spv_k2["comp"]}
    proof_fu_reg, hdr_fu_reg = _build_synthetic_spv_proof("fu-reg-fund", spv_reg_pol, [spv_k2["sk"]], "id/spv-fu-reg", '{"link":{}}', op_kind="NAME_FIRSTUPDATE", new_owner_pol=spv_p2wpkh, block_height=750010)
    add(
        "d12-b4-tier2-firstupdate-registrar-funded-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "headers": [{"header_hex": hdr_fu_reg.hex(), "height": 750010}], "page": {**_mk_page("id/spv-fu-reg", [proof_fu_reg]), "network": "regtest"}, "pinned_network": "regtest"},
        "ADMIT",
        None,
        "SL-ARTF-005 B4: Registrar-funded OP_NAME_FIRSTUPDATE (funding P2WPKH NAME_NEW -> owner_policy output, matching real nc28.0 & SL-LDGR-007) admits with owner_authored=false.",
        module="artifact-notarization",
    )
    proof_fu_wrong_out, _ = _build_synthetic_spv_proof("fu-wrong-out", spv_reg_pol, [spv_k2["sk"]], "id/spv-fu-bad", '{"link":{}}', op_kind="NAME_FIRSTUPDATE", new_owner_pol=spv_reg_pol, block_height=750010)
    add(
        "d12-b4-tier2-firstupdate-wrong-output-owner-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-fu-bad", [proof_fu_wrong_out])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005 B4: OP_NAME_FIRSTUPDATE whose output trailing script mismatches expected_owner_policy MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    proof_unlinked_next, _ = _build_synthetic_spv_proof("unlinked-next", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', block_height=750011)
    add(
        "d12-b4-tier2-unlinked-second-update-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_low, proof_unlinked_next])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005 B4: Unchained updates[1] (at later height 750011) not spending updates[0]'s name output MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    p0_txid = sl.parse_raw_tx(bytes.fromhex(spv_pair_upds[0]["tx_hex"]))["txid"]
    p1_txid = sl.parse_raw_tx(bytes.fromhex(spv_pair_upds[1]["tx_hex"]))["txid"]
    add(
        "d12-b4-tier2-cursor-pagination-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "page": _mk_page(
                "id/spv-chained", [spv_pair_upds[1]], limit=1, registration=spv_pair_reg,
                cursor_height=750010, cursor_txid=p0_txid, cursor_vout=0,
                next_cursor={"height": 750010, "txid": p1_txid, "vout": 0}, has_more=True,
            ),
        },
        "ADMIT",
        None,
        "SL-ARTF-005 B4: Paginated Tier-2 page with cursor_txid/cursor_vout/cursor_height and matching next_cursor admits.",
        module="artifact-notarization",
    )
    spv_branch_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(spv_k1["comp"], spv_k2["comp"])}
    add(
        "d12-b4-tier2-branch-policy-unsupported",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_branch_pol, "page": _mk_page("id/spv-notary", [proof_low])},
        "REFUSE",
        "CHAIN_SCRIPT_UNSUPPORTED",
        "SL-ARTF-005 B4: Tier-2 SPV is scoped to key/multisig; branch ScriptPolicy refuses CHAIN_SCRIPT_UNSUPPORTED.",
        module="artifact-notarization",
    )
    proof_nonempty_ss, _ = _build_synthetic_spv_proof("nonempty-ss", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', script_sig_override=b"\x01\x01")
    add(
        "d12-b4-tier2-non-empty-script-sig-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_nonempty_ss])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005 B4: Native SegWit name spend with non-empty scriptSig MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    proof_bad_slnk, _ = _build_synthetic_spv_proof("bad-slnk", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', opreturns=[b"\x6a\x05SLNK\x06\x01\x00"])
    add(
        "d12-b4-tier2-bad-slnk-frame-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_bad_slnk])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005 B4: Tier-2 name update carrying malformed SLNK OP_RETURN MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # F5 (B6): Closed 3-key DenialKeyStr (forbid |cap:) + provisional gossip act: veto
    bad_cap_rev = sl.sign_envelope({
        **nlog["rev1_env"]["payload"],
        "denial_key": f"act:{nlog['item_id']}|cap:seallink.org/build-repro",
    }, [nlog["iss_role"]["sk"]])
    add(
        "d12-b6-denial-key-cap-suffix-wire-member",
        ["SL-CONT-012", "SL-ARTF-003"],
        "raw_wire",
        {"object": bad_cap_rev},
        "REFUSE",
        "WIRE_MEMBER",
        "SL-CONT-012 B6: DenialKeyStr |cap:<claim_id> suffix is removed in v1.0 closed 3-key universe and MUST refuse WIRE_MEMBER.",
    )
    gn1_act_id = sl.object_id(gn1["entry"]["notary_act"]["payload"])
    gossip_act_rev = sl.sign_envelope({
        "denial_key": f"act:{gn1_act_id}|*", "genesis": GENESIS_MAIN, "issued_at": 1795219991,
        "issuer": nlog["iss_role_pin"], "log_id": gn1["log_id"], "network": "main",
        "reason_code": "act-recalled-gossip", "role": "notary", "state_seq": 1, "type": "seallink-log-revocation/1",
    }, [nlog["iss_role"]["sk"]])
    add(
        "d12-b6-provisional-gossip-act-veto-refuse",
        ["SL-ARTF-003", "SL-CONT-012"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "provisional_revocations": [gossip_act_rev], "ticket": gk_ticket_2of3},
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003 B6: Live-signed provisional gossip act:<act_id>|* revocation triggers deny-wins ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )

    # F6 (B8): Routine link.notary K1->K2 + cold owner_policy P1->P2 rotation + StateRecordInclusion + unchanged rec_b==rec_a NOT fraud!
    rot_eco = _build_log_ecosystem("d12rot", role="notary", with_4_checkpoints=True)
    rot_k2 = _kp("d12rot-role-k2")
    rot_p2 = {"kind": "key", "pk": _kp("d12rot-own-p2")["comp"]}
    rot_ch = copy.deepcopy(rot_eco["chain"])
    # Make cp4 non-terminal so we can rotate K1->K2 & P1->P2 at height 750000 and emit cp5 (terminal) signed by K2 at height 750005!
    cp4_nt_p = {**rot_eco["cp4_env"]["payload"], "next_log_policy": rot_eco["seal_pol"], "next_log_vout": 1, "terminal": False}
    cp4_nt_env = sl.sign_envelope(cp4_nt_p, [rot_eco["iss_role"]["sk"]])
    cp4_nt_ca = sl.content_addr(cp4_nt_env)
    cp5_tx = _h32("d12rot-cp5-tx")
    rot_ch["txs"][rot_eco["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, cp4_nt_ca).hex()
    rot_ch["txs"][rot_eco["cp4_tx"]]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(rot_eco["seal_pol"]), "spent_by_txid": cp5_tx}}
    # Rotate both owner_policy P1->P2 and link.notary K1->K2 on id/d12rot-op at height 750000!
    rot_nu = rot_ch["names"][rot_eco["iss_name"]]["updates"]
    prev_rn = rot_nu[-1]
    u_rot1 = _h32("d12rot-u-rot1")
    u_rot2 = _h32("d12rot-u-rot2")
    rot_nu.append({
        "block_time": 1795219800, "confirmed_height": 750000, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rot_p2)), name=rot_eco["iss_name"].encode("utf-8"), value=sl.jcs_encode({"link": {"notary": rot_k2["xonly"]}})).hex(),
        "owner_policy": rot_p2, "prev_input": {"sighash_bytes": [1], "txid": prev_rn["txid"], "vout": prev_rn["vout"], "witness_policy": rot_eco["iss_pol"]},
        "txid": u_rot1, "vout": 0,
    })
    rot_nu.append({
        "block_time": 1795219850, "confirmed_height": 750002, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rot_p2)), name=rot_eco["iss_name"].encode("utf-8"), value=sl.jcs_encode({"link": {"notary": rot_k2["xonly"]}})).hex(),
        "owner_policy": rot_p2, "prev_input": {"sighash_bytes": [1], "txid": u_rot1, "vout": 0, "witness_policy": rot_p2},
        "txid": u_rot2, "vout": 0,
    })
    rot_iss_pin_v2 = {"name": rot_eco["iss_name"], "owner_policy": rot_p2, "registration": rot_eco["iss_reg"], "role_policy": {"m": 1, "pks": [rot_k2["xonly"]]}}
    leaves_4_rot = rot_eco["leaves_3"] + [sl.ckpt_leaf(4, cp4_nt_ca)]
    cp5_p = {
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.rfc9162_mth(leaves_4_rot).hex(),
        "cumulative_entries_count": 3, "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": rot_eco["cp4_env"]["payload"]["denials_root"], "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": rot_eco["gen_op"], "issuer": rot_iss_pin_v2, "log_id": rot_eco["log_id"],
        "network": "main", "prev_checkpoint_id": cp4_nt_ca, "prev_log_outpoint": {"txid": rot_eco["cp4_tx"], "vout": 1},
        "role": "notary", "seq": 5, "terminal": True, "type": "seallink-log-checkpoint/1",
    }
    cp5_env = sl.sign_envelope(cp5_p, [rot_k2["sk"]])
    rot_ch["txs"][cp5_tx] = {"block_hash": _h32("d12rot-blk-cp5"), "confirmed_height": 750005, "inputs": [sv.make_segwit_input(rot_eco["cp4_tx"], 1)], "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(cp5_env)).hex(), "outputs": {}}
    reinst2_inc = {
        "batch_proof": rot_eco["b4_proof"], "checkpoint": cp4_nt_env, "checkpoint_txid": rot_eco["cp4_tx"],
        "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_4_rot, 3),
    }
    add(
        "d12-b8-routine-role-and-owner-rotation-state-inclusion-admit",
        ["SL-CONT-012"],
        "notary_act",
        {
            "allow_reinstatement": True, "chain": rot_ch,
            "log_ctx": {
                "batch_proof": rot_eco["b1_proof"], "checkpoint": rot_eco["cp1_env"], "checkpoint_txid": rot_eco["cp1_tx"],
                "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_4_rot, 0),
                "head_checkpoint": cp5_env, "head_checkpoint_txid": cp5_tx,
                "smt_proof": sl.smt_prove(rot_eco["kv4"], rot_eco["denial_key"]),
                "state_record": rot_eco["reinst2_env"],
                "state_record_inclusion": reinst2_inc,
            },
            "notary": rot_eco["item_env"],
        },
        "ADMIT",
        None,
        "SL-CONT-012 B8: Routine link.notary K1->K2 + cold owner_policy P1->P2 rotation preserves historical K1-signed state_record verification via state_record_inclusion.",
    )
    add(
        "d12-b8-unchanged-rec-after-rotation-not-fraud-refuse",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": rot_ch,
            "fraud": {
                "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_4_rot, 3),
                "cp_a": cp4_nt_env, "cp_a_txid": rot_eco["cp4_tx"],
                "cp_b": cp5_env, "cp_b_txid": cp5_tx,
                "fraud_mode": "illegal_reversion", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": rot_eco["gen_op"],
                "log_id": rot_eco["log_id"], "network": "main",
                "rec_a": rot_eco["reinst2_env"], "rec_b": rot_eco["reinst2_env"], "role": "notary",
                "smt_proof_a": sl.smt_prove(rot_eco["kv4"], rot_eco["denial_key"]),
                "smt_proof_b": sl.smt_prove(rot_eco["kv4"], rot_eco["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B8: Unchanged SMT leaf rec_b == rec_a (signed by K1 before K1->K2 rotation) MUST NOT trigger false illegal_reversion fraud.",
    )

    # F7 (H1): 0x13 automaton hardening (pre-offer B_2 rotation, non-SIGHASH_ALL inert, unknown-preimage rescue & ward ignore, post-emancipation 0x10 cancel, post-step3 corruption, origin_bundle invocation)
    rb_pre_rot = _build_autonomous_origin_rebind_fixture("d12-b2-prerot", recovery_mode="none", h_act=749744)
    b2_old_pol = {"kind": "key", "pk": _kp("d12-b2-old-pol")["comp"]}
    b2_u_pr = rb_pre_rot["chain"]["names"]["id/alice-v2"]["updates"]
    # Insert pre-offer cold rotation from b2_old_pol -> b2_pol BEFORE T_offer!
    b2_u_pr[0]["owner_policy"] = b2_old_pol
    b2_u_pr[0]["output_script_hex"] = sl.encode_name_output("NAME_FIRSTUPDATE", bytes.fromhex(_spk_hex(b2_old_pol)), name=b"id/alice-v2", rand=b"\x07" * 20, value=b"{}").hex()
    rot_b2_tx = _h32("d12-b2-preoffer-rot")
    b2_u_pr.insert(1, {
        "block_time": 1795205500, "confirmed_height": 749450, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_pre_rot["_b2_pol"])), name=b"id/alice-v2", value=b"{}").hex(),
        "owner_policy": rb_pre_rot["_b2_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": b2_u_pr[0]["txid"], "vout": 0, "witness_policy": b2_old_pol},
        "txid": rot_b2_tx, "vout": 0,
    })
    b2_u_pr[2]["prev_input"] = {"sighash_bytes": [1], "txid": rot_b2_tx, "vout": 0, "witness_policy": rb_pre_rot["_b2_pol"]}
    add(
        "d12-h1-pre-offer-b2-owner-rotation-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_pre_rot["chain"], "expect_active_name": "id/alice-v2", "origin_bundle": rb_pre_rot["origin_bundle"], "trusted_origin_issuer_pins": rb_pre_rot["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 H1: Cold owner rotation on B_2 BEFORE T_offer (while keeping b2_pol invariant on [h_offer, h_act]) admits cleanly.",
    )
    rb_nonsha = _build_autonomous_origin_rebind_fixture("d12-nonsha", recovery_mode="none", h_act=None)
    rb_nonsha["chain"]["names"]["id/alice-v1"]["updates"][-1]["prev_input"]["sighash_bytes"] = [0x81]  # SIGHASH_ANYONECANPAY -> inert!
    add(
        "d12-h1-non-sighash-all-0x13-inert-admit",
        ["SL-ORIG-017", "SL-LDGR-010"],
        "origin_status",
        {"chain": rb_nonsha["chain"], "expect_active_name": "id/alice-v1", "origin_bundle": rb_nonsha["origin_bundle"], "trusted_origin_issuer_pins": rb_nonsha["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 H1: Non-SIGHASH_ALL (0x81) 0x13 frame is inert and MUST NOT stall B_1.",
    )
    rb_resc = _build_autonomous_origin_rebind_fixture("d12-resc", recovery_mode="none", h_act=None)
    rb_resc["origin_bundle"]["voluntary_rebind_bindings"] = []  # withheld preimage!
    prev_r1 = rb_resc["chain"]["names"]["id/alice-v1"]["updates"][-1]
    rb_resc["chain"]["names"]["id/alice-v1"]["updates"].append({
        "block_time": 1795211000, "confirmed_height": 749650, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, rb_resc["_b2_id"]).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_resc["_b1_pol"])), name=b"id/alice-v1", value=sl.jcs_encode({"link": {"grant": rb_resc["_b1_gr"]["xonly"], "origin": rb_resc["_oid"]}})).hex(),
        "owner_policy": rb_resc["_b1_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_r1["txid"], "vout": prev_r1["vout"], "witness_policy": rb_resc["_b1_pol"]},
        "txid": _h32("d12-resc-0x10"), "vout": 0,
    })
    add(
        "d12-h1-unknown-preimage-0x13-rescued-by-0x10-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_resc["chain"], "expect_active_name": "id/alice-v1", "origin_bundle": rb_resc["origin_bundle"], "trusted_origin_issuer_pins": rb_resc["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 H1: Confirmed 0x13 with withheld preimage is rescued by owner-signed 0x10 cancel within 35000 blocks -> ADMIT_AUTONOMOUS.",
    )
    of_ward_13 = rm._base_origin_fixture()
    wu = of_ward_13["chain"]["names"]["id/child-leo"]["updates"]
    prev_wu = wu[-1]
    wu.append({
        "block_time": 1795211000, "confirmed_height": 749500, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x13, _h32("ward-unknown-b2")).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(prev_wu["owner_policy"])), name=b"id/child-leo", value=b"{}").hex(),
        "owner_policy": prev_wu["owner_policy"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_wu["txid"], "vout": prev_wu["vout"], "witness_policy": prev_wu["owner_policy"]},
        "txid": _h32("d12-ward-0x13"), "version": 0x7100, "vout": 0,
    })
    add(
        "d12-h1-unknown-preimage-0x13-ignored-on-ward-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": of_ward_13["chain"], "origin_bundle": of_ward_13["origin_bundle"], "trusted_origin_issuer_pins": of_ward_13["trusted_origin_issuer_pins"]},
        "ADMIT_WARD",
        None,
        "SL-ORIG-017 H1: Precondition check runs before preimage lookup so unknown-preimage 0x13 on a ward origin is ignored (ADMIT_WARD).",
    )
    # Post-emancipation 0x13 cancelled by 0x10 (must bypass State-3 lockout since is_autonomous=True and h_emancipated < h_10!)
    em_c = _build_exact_emancipate_then_rebind("d12-em10", mode="p1_cap")
    em_b1_u = em_c["chain"]["names"]["id/child-leo"]["updates"]
    prev_em_b1 = em_b1_u[-1]
    em_b2_id = sl.object_id(em_c["origin_bundle"]["voluntary_rebind_bindings"][0])
    em_b1_u.append({
        "block_time": 1795213000, "confirmed_height": 749350, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, em_b2_id).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(prev_em_b1["owner_policy"])), name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": sl.object_id(em_c["origin_bundle"]["origin"]["payload"])}})).hex(),
        "owner_policy": prev_em_b1["owner_policy"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_em_b1["txid"], "vout": prev_em_b1["vout"], "witness_policy": prev_em_b1["owner_policy"]},
        "txid": _h32("d12-em10-cancel"), "vout": 0,
    })
    add(
        "d12-h1-post-emancipation-0x13-0x10-cancel-admit",
        ["SL-ORIG-017", "SL-ORIG-011"],
        "origin_status",
        {"chain": em_c["chain"], "expect_active_name": "id/child-leo", "origin_bundle": em_c["origin_bundle"], "trusted_origin_issuer_pins": em_c["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017 H1: Emancipated adult (State 4) cancelling a post-emancipation 0x13 via 0x10 bypasses State-3 lockout and restores active binding.",
    )
    # Post-Step-3 B_2 later corrupted (non-SIGHASH_ALL update breaking writer authorship after Step 3) -> ORIGIN_BINDING_INVALID!
    rb_post_corrupt = _build_autonomous_origin_rebind_fixture("d12-post-cor", recovery_mode="none", h_act=749744, tip_h=749800)
    b2_u_pc = rb_post_corrupt["chain"]["names"]["id/alice-v2"]["updates"]
    prev_pc = b2_u_pc[-1]
    b2_u_pc.append({
        "block_time": 1795218000, "confirmed_height": 749780, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_post_corrupt["_b2_pol"])), name=b"id/alice-v2", value=b"{}").hex(),
        "owner_policy": rb_post_corrupt["_b2_pol"],
        "prev_input": {"sighash_bytes": [0x81], "txid": prev_pc["txid"], "vout": prev_pc["vout"], "witness_policy": rb_post_corrupt["_b2_pol"]},
        "txid": _h32("d12-post-cor-tx"), "vout": 0,
    })
    add(
        "d12-h1-post-step3-b2-corrupted-refuse",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_post_corrupt["chain"], "origin_bundle": rb_post_corrupt["origin_bundle"], "trusted_origin_issuer_pins": rb_post_corrupt["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-017 H1: Post-Step-3 non-SIGHASH_ALL update corrupting B_2 authorship MUST fail final _check_b2_step3_activated -> ORIGIN_BINDING_INVALID.",
    )
    # Issuer invocation on B_1 after a cancelled 0x13 ADMITS when issuer_origin_bundle is wired into verify_invocation!
    fx_inv_13 = rm._base_invocation_fixture()
    rb_inv13 = _build_autonomous_origin_rebind_fixture("d12-inv13", recovery_mode="none", h_act=None)
    # Cancel the 0x13 at 749600 via same-block 0x10 and republish link.grant + link.origin + manifest on id/alice-v1!
    inv13_mans = copy.deepcopy(fx_inv_13["bundle"]["manifests"])
    al_man_old = next(m for m in inv13_mans.values() if m.get("owner") == "id/alice")
    al_man_v1 = copy.deepcopy(al_man_old)
    al_man_v1["owner"] = "id/alice-v1"
    al_man_v1_ca = sl.content_addr(al_man_v1)
    inv13_mans[al_man_v1_ca] = al_man_v1
    p_inv13 = rb_inv13["chain"]["names"]["id/alice-v1"]["updates"][-1]
    rb_inv13["chain"]["names"]["id/alice-v1"]["updates"].append({
        "block_time": 1795210005, "confirmed_height": 749600, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x10, rb_inv13["_b2_id"]).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_inv13["_b1_pol"])), name=b"id/alice-v1", value=sl.jcs_encode({"link": {"grant": rb_inv13["_b1_gr"]["xonly"], "origin": rb_inv13["_oid"]}, "m": {"h": al_man_v1_ca, "s": 1}})).hex(),
        "owner_policy": rb_inv13["_b1_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": p_inv13["txid"], "vout": p_inv13["vout"], "witness_policy": rb_inv13["_b1_pol"]},
        "txid": _h32("d12-inv13-0x10"), "vout": 0,
    })
    ch_inv13 = copy.deepcopy(fx_inv_13["chain"])
    ch_inv13["names"].update(rb_inv13["chain"]["names"])
    ch_inv13["txs"].update(rb_inv13["chain"]["txs"])
    g_inv13_p = copy.deepcopy(fx_inv_13["bundle"]["grants"][0]["payload"])
    g_inv13_p["issuer"] = {"name": "id/alice-v1", "owner_policy": rb_inv13["_b1_pol"], "registration": rb_inv13["_b1"]["registration"], "role_policy": {"m": 1, "pks": [rb_inv13["_b1_gr"]["xonly"]]}}
    if "executor_ref" in g_inv13_p:
        g_inv13_p["executor_ref"] = {**g_inv13_p["executor_ref"], "provider_of": "id/alice-v1"}
    g_inv13_p["capabilities"] = [{"action": "mail/read", "target": "mailbox:id/alice-v1:work", "where": {"folder": {"in": ["Invoices"]}}}]
    g_inv13_env = sl.sign_envelope(g_inv13_p, [rb_inv13["_b1_gr"]["sk"]])
    g_inv13_id = sl.object_id(g_inv13_p)
    iss_tx_13 = fx_inv_13["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    ch_inv13["txs"][iss_tx_13]["opreturn_hex"] = sl.encode_opreturn(0x01, sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_inv13_env), "grant_id": g_inv13_id, "type": "seallink-issuance/1"}).hex()).hex()
    inv_13_p = copy.deepcopy(fx_inv_13["invocation"]["payload"])
    inv_13_p["target"] = "mailbox:id/alice-v1:work"
    inv_13_p["proof_path"] = [{"grant_id": g_inv13_id, "issuance_txid": iss_tx_13}]
    inv_13_env = sl.sign_envelope(inv_13_p, [fx_inv_13["_keys"]["agent_req"]["sk"]])
    add(
        "d12-h1-invocation-after-cancelled-0x13-with-origin-bundle-admit",
        ["SL-ORIG-017", "SL-GRNT-010"],
        "invocation",
        {
            "actual_message_meta": {"folder": "Invoices"},
            "bundle": {**fx_inv_13["bundle"], "grants": [g_inv13_env], "manifests": inv13_mans, "origin_bundle": rb_inv13["origin_bundle"]},
            "chain": ch_inv13, "executor_cfg": fx_inv_13["executor_cfg"],
            "invocation": inv_13_env, "journal": fx_inv_13["journal"],
            "trusted_origin_issuer_pins": rb_inv13["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "SL-ORIG-017 H1: Backing grant on B_1 after cancelled 0x13 admits when origin_bundle resolves active binding.",
    )

    # F8 (H3): Untrusted notary skipped first, required_claims=[] all-inconclusive denied, dup absent_notary_proofs refused, 0x0b CRED_ISSUER_CLOSED propagated
    untrusted_entry = copy.deepcopy(nlog_valid_other_entry)
    pol_h3_untr = copy.deepcopy(gk_pol_hardened)
    pol_h3_untr["mode"] = "standard"
    pol_h3_untr["quorum_m"] = 1
    pol_h3_untr["trusted_notaries"] = [{"log_id": gn2["log_id"], "notary_pin": gn2["pin"]}]
    add(
        "d12-h3-untrusted-notary-wrong-target-ignored-admit",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {
            "chain": gk_chain, "policy": pol_h3_untr,
            "ticket": {**tkt_no_abs, "notarizations": [untrusted_entry, gn2["entry"]]},
        },
        "ADMIT",
        None,
        "SL-ARTF-003 H3: Untrusted third-party notarization (even targeting a different artifact) is skipped before proof/target checks.",
        module="artifact-notarization",
    )
    add(
        "d12-h3-empty-required-claims-inconclusive-denied",
        ["SL-ARTF-004"],
        "artifact_ticket",
        {
            "chain": gk_chain,
            "policy": {"allow_reinstatement": False, "mode": "standard", "quorum_m": 1, "require_release": False, "required_claims": [], "trusted_notaries": [{"log_id": gn2_inc["log_id"], "notary_pin": gn2_inc["pin"]}]},
            "ticket": {"artifact_identity": fsv_art, "genesis": GENESIS_MAIN, "network": "main", "notarizations": [gn2_inc["entry"]], "target_sha256": fsv_tid, "type": "seallink-ticket/1"},
        },
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-004 H3: required_claims=[] MUST require at least one passed claim per quorum vote (inconclusive-only abstains -> ARTIFACT_POLICY_DENIED).",
        module="artifact-notarization",
    )
    tkt_dup_abs = copy.deepcopy(gk_ticket_2of3)
    tkt_dup_abs["absent_notary_proofs"] = [tkt_dup_abs["absent_notary_proofs"][0], tkt_dup_abs["absent_notary_proofs"][0]]
    add(
        "d12-h3-duplicate-absent-notary-log-id-refuse",
        ["SL-ARTF-004"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": tkt_dup_abs},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-004 H3: Duplicate log_id in absent_notary_proofs[] MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    gk_ch_0b_rel = copy.deepcopy(gk_chain)
    prev_ru_gk = gk_ch_0b_rel["names"][rlog["iss_name"]]["updates"][-1]
    brk_gk_rel = {
        "compromised_policy": {"m": 1, "pks": [rlog["iss_role"]["xonly"]]},
        "genesis": GENESIS_MAIN, "h_c": 749990,
        "issuer": rlog["iss_pin"], "name_input": {"txid": prev_ru_gk["txid"], "vout": prev_ru_gk["vout"]},
        "role": "release", "type": "seallink-credential-break/1",
    }
    gk_ch_0b_rel["names"][rlog["iss_name"]]["updates"].append({
        "block_time": 1795219950, "confirmed_height": 750000, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_gk_rel).hex(), h_c=749990).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rlog["iss_pol"])), name=rlog["iss_name"].encode("utf-8"), value=b"{}").hex(),
        "owner_policy": rlog["iss_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_ru_gk["txid"], "vout": prev_ru_gk["vout"], "witness_policy": rlog["iss_pol"]},
        "txid": _h32("d12-gk-rel-0x0b-tx"), "vout": 0,
    })
    add(
        "d12-h3-0x0b-cred-issuer-closed-propagated",
        ["SL-ARTF-003", "SL-CONT-009"],
        "artifact_ticket",
        {"chain": gk_ch_0b_rel, "policy": gk_pol_hardened, "ticket": gk_ticket_2of3},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "SL-ARTF-003 H3: Release issuer 0x0b compromise MUST propagate CRED_ISSUER_CLOSED instead of downgrading to TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # F9 (H4): revocation_omission proving stale rec_b (state_seq 1 < rev3.state_seq 3) in denials_root!
    ch_h4 = copy.deepcopy(nlog["chain"])
    e_rev3 = sl.log_entry_digest(0x02, nlog["rev3_ca"])
    b4_rev3_root, b4_rev3_pfs = sl.build_log_batch_root([e_rev3])
    # cp4 batches rev3 (state_seq=3) in batch_root, but keeps STALE rev1 (state_seq=1) in denials_root!
    cp4_h4_p = {**nlog["cp4_env"]["payload"], "batch_root": b4_rev3_root, "denials_delta_root": b4_rev3_root, "denials_root": sl.smt_root(nlog["kv3"])}
    cp4_h4_env = sl.sign_envelope(cp4_h4_p, [nlog["iss_role"]["sk"]])
    ch_h4["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_h4_env)).hex()
    add(
        "d12-h4-revocation-omission-stale-rec-b-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": ch_h4,
            "fraud": {
                "batch_proof": b4_rev3_pfs[e_rev3], "cp_a": cp4_h4_env, "cp_a_txid": nlog["cp4_tx"],
                "cp_b": cp4_h4_env, "cp_b_txid": nlog["cp4_tx"],
                "fraud_mode": "revocation_omission", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main",
                "rec_b": nlog["rev1_env"], "revocation": nlog["rev3_env"], "role": "notary",
                "smt_proof": sl.smt_prove(nlog["kv3"], nlog["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
        },
        "ADMIT",
        None,
        "SL-CONT-012 H4: revocation_omission with stale rec_b (state_seq 1 < rev3.state_seq 3) in denials_root proves fraud.",
    )

    # F10 (H5): Bearer session root_recent_height reorg check, federation single_use ban, resolve_role_policy mempool rotation without rbh
    fx_h5_bs = rm._base_invocation_fixture()
    g_h5_bs = fx_h5_bs["bundle"]["grants"][0]
    gid_h5_bs = sl.object_id(g_h5_bs["payload"])
    itx_h5_bs = fx_h5_bs["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    so_h5_bs = sl.sign_envelope(
        {"executor": fx_h5_bs["invocation"]["payload"]["executor"], "exp": fx_h5_bs["chain"]["now"] + 600, "genesis": GENESIS_MAIN, "iat": fx_h5_bs["chain"]["now"], "network": "main", "nonce": _h32("d12-h5-so"), "op": "open", "proof_path": [{"grant_id": gid_h5_bs, "issuance_txid": itx_h5_bs}], "quotas": [], "slot_binding": "slot-h5", "type": "seallink-session-open/1"},
        [fx_h5_bs["_keys"]["agent_req"]["sk"]],
    )
    ch_h5_reorg = copy.deepcopy(fx_h5_bs["chain"])
    ch_h5_reorg["blocks"][g_h5_bs["payload"]["recent_block"]] = 749989  # Shifted from persisted root_recent_height=749990!
    add(
        "d12-h5-bearer-session-recent-block-reorg-refuse",
        ["SL-GRNT-013"],
        "session_lifecycle",
        {
            "executor_cfg": fx_h5_bs["executor_cfg"],
            "journal": {"journal_id": _h32("d12-h5-bs-j")},
            "steps": [
                {"bundle": fx_h5_bs["bundle"], "chain": fx_h5_bs["chain"], "kind": "session_open", "label": "open-h5", "session_open": so_h5_bs, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "actual_message_meta": {"folder": "Invoices"}, "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": ch_h5_reorg, "expect_zero_writes": True, "grant_env": g_h5_bs, "kind": "bearer_session", "label": "reorged-recent-block-refuse", "slot_binding": "slot-h5", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "SL-GRNT-013 H5: Bearer session live recheck MUST refuse SESSION_INVALID when recent_block height shifts from persisted root_recent_height.",
        module="bearer-sessions",
    )
    fx_h5_fed = rm._base_invocation_fixture()
    g_fed_su_p = copy.deepcopy(fx_h5_fed["bundle"]["grants"][0]["payload"])
    g_fed_su_p["revocation"] = {"construction": "W", "kind": "single_use", "mode": "seal", "seal": {"script_policy": {"kind": "branch", "template": "single_use_1_of_2", "keys": {"grantee": _kp("d12-fsu-g")["comp"], "issuer": _kp("d12-fsu-i")["comp"]}}, "txid": _h32("d12-fsu-tx"), "vout": 0}}
    g_fed_su = sl.sign_envelope(g_fed_su_p, [fx_h5_fed["_keys"]["alice_gr"]["sk"]])
    add(
        "d12-h5-federation-single-use-grant-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_h5_fed["chain"],
            "grant": g_fed_su,
            "journal": {"journal_id": _h32("d12-h5-fed-j")},
            "peer_ctx": {"phase": "screening"},
            "policy": {"federation_id": "fed.example/a", "peer_min_tier": 1, "pii_contour": "A"},
        },
        "REFUSE",
        "FEDERATION_POLICY_DENIED",
        "SL-SERV-004 H5: verify_federation_disclosure MUST forbid single_use grants (revocable UTXO seal only).",
        module="federated-screening",
    )
    # resolve_role_policy mempool rotation without recent_block_height (live verify_assent) -> NAME_ROLE_CHANGED!
    ch_h5_mp = copy.deepcopy(rb_ass["chain"])
    mp_new_gr = _kp("d12-h5-mp-new-gr")
    last_v2_u = ch_h5_mp["names"]["id/alice-v2"]["updates"][-1]
    ch_h5_mp["names"]["id/alice-v2"]["mempool_updates"] = [{
        "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rb_none["_b2_pol"])), name=b"id/alice-v2", value=sl.jcs_encode({"link": {"grant": mp_new_gr["xonly"], "origin": rb_none["_oid"]}})).hex(),
        "owner_policy": rb_none["_b2_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": last_v2_u["txid"], "vout": last_v2_u["vout"], "witness_policy": rb_none["_b2_pol"]},
        "txid": _h32("d12-h5-mp-rot"),
    }]
    add(
        "d12-h5-assent-mempool-role-rotation-without-rbh-refuse",
        ["SL-IDEN-004"],
        "assent",
        {
            "assent": ass_b2, "chain": ch_h5_mp, "contract": c_p01_b2,
            "origin_bundle": rb_ass["origin_bundle"], "trusted_origin_issuer_pins": rb_ass["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "CONTRACT_ASSENT_INVALID",
        "SL-IDEN-004 H5: Live resolve_role_policy without recent_block_height MUST honor mempool role rotation (mapped by verify_assent to CONTRACT_ASSENT_INVALID).",
    )

    # F11 (M3 & M4): updates[0] malformed SLNK frame caught (CHAIN_FRAME_INVALID) + verify_notary_act log_tracked expected_child_binding!
    fx_m3 = rm._base_invocation_fixture()
    fx_m3["chain"]["names"]["id/alice"]["updates"][0]["opreturn_hex"] = "6a05534c4e4b060100"  # malformed SLNK on updates[0]!
    add(
        "d12-m3-updates0-bad-slnk-frame-invalid",
        ["SL-LDGR-010"],
        "name_resolve",
        {"chain": fx_m3["chain"], "name": "id/alice"},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-LDGR-010 M3: Outer SLNK framing MUST scan updates[0] (NAME_FIRSTUPDATE) and refuse CHAIN_FRAME_INVALID on malformed frame.",
    )
    add(
        "d12-m4-notary-act-log-tracked-expected-child-binding-refuse",
        ["SL-CONT-011", "SL-CONT-012"],
        "notary_act",
        {
            "chain": nlog["chain_at_cp2"],
            "expected_child_binding": {"child_grant_id": _h32("child-g"), "ordinal": 1, "parent_grant_id": _h32("parent-g")},
            "log_ctx": {
                "batch_proof": nlog["b1_proof"], "checkpoint": nlog["cp1_env"], "checkpoint_txid": nlog["cp1_tx"],
                "checkpoints_proof": nlog["cp1_in_cp2_proof"], "head_checkpoint": nlog["cp2_env"], "head_checkpoint_txid": nlog["cp2_tx"],
                "smt_proof": sl.smt_prove({}, nlog["denial_key"]),
            },
            "notary": nlog["item_env"],
        },
        "REFUSE",
        "NOTARY_REQUIRED",
        "SL-CONT-011 M4: verify_notary_act MUST enforce expected_child_binding uniformly on log_tracked acts as well as eternal/revocable acts.",
    )

    # =========================================================================
    # SECTION G: 100% 3-OPERATOR MUTATION CLOSURE FOR v1.0.0-draft.12 HARDENING
    # =========================================================================

    # G1. _verify_rebound_pin: revocable credential targeting superseded B_1 with origin_bundle -> ORIGIN_BINDING_INVALID
    cred_iss_k = _kp("d12-g1-cred-iss")
    cred_iss_own = _kp("d12-g1-cred-own")
    cred_iss_pol = {"kind": "key", "pk": cred_iss_own["comp"]}
    cred_iss_reg = {"txid": _h32("d12-g1-cred-reg"), "vout": 0}
    cred_seal_pol = {"kind": "key", "pk": _kp("d12-g1-cseal")["comp"]}
    cred_seal_tx = _h32("d12-g1-cseal-tx")
    cred_anc_tx = _h32("d12-g1-canc-tx")
    cred_b1_p = {
        "claims": {"degree": "MSc"}, "credential_kind": "org.seallink/degree-v1",
        "genesis": GENESIS_MAIN, "issued_at": 1795218000,
        "issuer": {"name": "id/univ-g1", "owner_policy": cred_iss_pol, "registration": cred_iss_reg, "role_policy": {"m": 1, "pks": [cred_iss_k["xonly"]]}},
        "lifecycle": "revocable", "network": "main", "not_before_height": 749000,
        "revocation_seal": {"script_policy": cred_seal_pol, "txid": cred_seal_tx, "vout": 0},
        "subject": {"mode": "name", "name_pin": {"name": "id/alice-v1", "owner_policy": rb_none["_b1_pol"], "registration": rb_none["_b1"]["registration"]}},
        "type": "seallink-credential/1",
    }
    cred_b1_env = sl.sign_envelope(cred_b1_p, [cred_iss_k["sk"]])
    ch_g1 = copy.deepcopy(rb_ass["chain"])
    ch_g1["names"]["id/univ-g1"] = sv.make_name_history("id/univ-g1", cred_iss_reg, cred_iss_pol, {"link": {"cred": cred_iss_k["xonly"]}}, first_height=748000, update_height=748500)
    ch_g1["txs"][cred_seal_tx] = {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": _spk_hex(cred_seal_pol)}}}
    ch_g1["txs"][cred_anc_tx] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cred_b1_env)).hex(), "outputs": {}}
    add(
        "d12-mut-rebound-pin-superseded-b1-cred-refuse",
        ["SL-ORIG-017", "SL-CONT-008"],
        "credential",
        {
            "anchor_txid": cred_anc_tx, "chain": ch_g1, "credential": cred_b1_env,
            "origin_bundle": rb_ass["origin_bundle"], "supported_kinds": ["org.seallink/degree-v1"],
            "trusted_origin_issuer_pins": rb_ass["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-017: Revocable credential targeting superseded B_1 with origin_bundle MUST refuse ORIGIN_BINDING_INVALID.",
    )

    # G2. _collect_0x13_events malformed SLNK, automaton step cap, unknown-preimage stalled > 35000, final active truncated, post-Step-3 exact expiry
    rb_bad_slnk_13 = _build_autonomous_origin_rebind_fixture("d12-g2-badslnk", recovery_mode="none", h_act=None)
    rb_bad_slnk_13["chain"]["names"]["id/alice-v1"]["updates"][-1]["opreturn_hex"] = "6a05534c4e4b060100"
    add(
        "d12-mut-0x13-collect-malformed-slnk-frame-invalid",
        ["SL-ORIG-017", "SL-LDGR-010"],
        "origin_status",
        {"chain": rb_bad_slnk_13["chain"], "origin_bundle": rb_bad_slnk_13["origin_bundle"], "trusted_origin_issuer_pins": rb_bad_slnk_13["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-ORIG-017: Malformed SLNK frame on active binding during 0x13 scan MUST refuse CHAIN_FRAME_INVALID.",
    )
    add(
        "d12-mut-0x13-automaton-step-cap-incomplete",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_none["chain"], "max_automaton_steps": 1, "origin_bundle": rb_none["origin_bundle"], "trusted_origin_issuer_pins": rb_none["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: Exceeding max_automaton_steps MUST fail closed ORIGIN_STATUS_INCOMPLETE.",
    )
    rb_stall = _build_autonomous_origin_rebind_fixture("d12-g2-stall", recovery_mode="none", h_act=None, tip_h=749600 + 35000 + 10)
    rb_stall["origin_bundle"]["voluntary_rebind_bindings"] = []
    add(
        "d12-mut-0x13-unknown-preimage-past-35000-stalled-incomplete",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_stall["chain"], "origin_bundle": rb_stall["origin_bundle"], "trusted_origin_issuer_pins": rb_stall["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: Unrescued unknown-preimage 0x13 past 35000-block rescue window stalls fail-closed ORIGIN_STATUS_INCOMPLETE.",
    )
    rb_act_trunc = copy.deepcopy(rb_none)
    rb_act_trunc["chain"]["names"]["id/alice-v2"]["history_truncated"] = True
    rb_act_trunc["chain"]["names"]["id/alice-v2"]["first_error_height"] = 749800  # exact eval_h
    add(
        "d12-mut-active-binding-truncated-history-incomplete",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_act_trunc["chain"], "origin_bundle": rb_act_trunc["origin_bundle"], "trusted_origin_issuer_pins": rb_act_trunc["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ORIG-017: Final active binding with truncated history at eval_h MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )
    rb_exp_s3 = _build_autonomous_origin_rebind_fixture("d12-g2-exps3", recovery_mode="none", h_act=749744, tip_h=749744 + 36000)
    add(
        "d12-mut-b2-step3-post-activation-exact-expiry-refuse",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_exp_s3["chain"], "origin_bundle": rb_exp_s3["origin_bundle"], "trusted_origin_issuer_pins": rb_exp_s3["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_BINDING_INVALID",
        "SL-ORIG-017: Post-Step-3 B_2 at exact eval_h == h_act + 36000 expires -> ORIGIN_BINDING_INVALID.",
    )
    rb_exp_s3_ok = _build_autonomous_origin_rebind_fixture("d12-g2-exps3-ok", recovery_mode="none", h_act=749744, tip_h=749744 + 35999)
    add(
        "d12-mut-b2-step3-post-activation-exact-expiry-minus1-admit",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_exp_s3_ok["chain"], "expect_active_name": "id/alice-v2", "origin_bundle": rb_exp_s3_ok["origin_bundle"], "trusted_origin_issuer_pins": rb_exp_s3_ok["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "SL-ORIG-017: Post-Step-3 B_2 at exact eval_h == h_act + 35999 remains live -> ADMIT_AUTONOMOUS.",
    )

    # G3. StateRecordInclusion negative tests & state_record 0x0b CRED_ISSUER_CLOSED propagation
    rot_lctx_base = {
        "batch_proof": rot_eco["b1_proof"], "checkpoint": rot_eco["cp1_env"], "checkpoint_txid": rot_eco["cp1_tx"],
        "checkpoints_proof": sl.rfc9162_inclusion_proof(leaves_4_rot, 0),
        "head_checkpoint": cp5_env, "head_checkpoint_txid": cp5_tx,
        "smt_proof": sl.smt_prove(rot_eco["kv4"], rot_eco["denial_key"]),
        "state_record": rot_eco["reinst2_env"],
    }
    bad_inc_bp = copy.deepcopy(reinst2_inc)
    bad_inc_bp["batch_proof"]["root"] = _h32("bad-inc-root")
    add(
        "d12-mut-state-rec-inc-bad-batch-proof-refuse",
        ["SL-CONT-012"],
        "notary_act",
        {"allow_reinstatement": True, "chain": rot_ch, "log_ctx": {**rot_lctx_base, "state_record_inclusion": bad_inc_bp}, "notary": rot_eco["item_env"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B8: Tampered state_record_inclusion batch_proof MUST refuse CHAIN_FRAME_INVALID.",
    )
    add(
        "d12-mut-state-rec-inc-malformed-dict-refuse",
        ["SL-CONT-012"],
        "notary_act",
        {"allow_reinstatement": True, "chain": rot_ch, "log_ctx": {**rot_lctx_base, "state_record_inclusion": {}}, "notary": rot_eco["item_env"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B8: Missing fields in state_record_inclusion dict MUST refuse CHAIN_FRAME_INVALID.",
    )
    # 0x0b break by same cold owner P1 after routine hot-key rotation K1->K2 compromises historical K1-signed state_record!
    rot_ch_0b_k1 = copy.deepcopy(rot_eco["chain"])
    rot_ch_0b_k1["txs"][rot_eco["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, cp4_nt_ca).hex()
    rot_ch_0b_k1["txs"][rot_eco["cp4_tx"]]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(rot_eco["seal_pol"]), "spent_by_txid": cp5_tx}}
    nu_0b = rot_ch_0b_k1["names"][rot_eco["iss_name"]]["updates"]
    prev_0b0 = nu_0b[-1]
    u_rk2 = _h32("d12-rot-k2-only")
    nu_0b.append({
        "block_time": 1795219800, "confirmed_height": 750000, "op": "NAME_UPDATE",
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rot_eco["iss_pol"])), name=rot_eco["iss_name"].encode("utf-8"), value=sl.jcs_encode({"link": {"notary": rot_k2["xonly"]}})).hex(),
        "owner_policy": rot_eco["iss_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": prev_0b0["txid"], "vout": prev_0b0["vout"], "witness_policy": rot_eco["iss_pol"]},
        "txid": u_rk2, "vout": 0,
    })
    brk_rot_k1 = {
        "compromised_policy": {"m": 1, "pks": [rot_eco["iss_role"]["xonly"]]},
        "genesis": GENESIS_MAIN, "h_c": 749995,  # > h_cp1 (749200) so cp1 admits, <= h_cp4 (749998) so reinst2 inc_cp compromises!
        "issuer": rot_eco["iss_pin"],
        "name_input": {"txid": u_rk2, "vout": 0},
        "role": "notary", "type": "seallink-credential-break/1",
    }
    nu_0b.append({
        "block_time": 1795219960, "confirmed_height": 750006, "op": "NAME_UPDATE",
        "opreturn_hex": sl.encode_opreturn(0x0B, sl.signing_digest(brk_rot_k1).hex(), h_c=749995).hex(),
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", bytes.fromhex(_spk_hex(rot_eco["iss_pol"])), name=rot_eco["iss_name"].encode("utf-8"), value=sl.jcs_encode({"link": {"notary": rot_k2["xonly"]}})).hex(),
        "owner_policy": rot_eco["iss_pol"],
        "prev_input": {"sighash_bytes": [1], "txid": u_rk2, "vout": 0, "witness_policy": rot_eco["iss_pol"]},
        "txid": _h32("d12-rot-k1-0x0b"), "vout": 0,
    })
    cp5_p1_env = sl.sign_envelope({**cp5_p, "issuer": {**rot_eco["iss_pin"], "role_policy": {"m": 1, "pks": [rot_k2["xonly"]]}}}, [rot_k2["sk"]])
    rot_ch_0b_k1["txs"][cp5_tx] = {"block_hash": _h32("d12rot-blk-cp5-p1"), "confirmed_height": 750005, "inputs": [sv.make_segwit_input(rot_eco["cp4_tx"], 1)], "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(cp5_p1_env)).hex(), "outputs": {}}
    add(
        "d12-mut-state-rec-0x0b-issuer-closed-propagated",
        ["SL-CONT-012", "SL-CONT-009"],
        "notary_act",
        {"allow_reinstatement": True, "chain": rot_ch_0b_k1, "log_ctx": {**rot_lctx_base, "head_checkpoint": cp5_p1_env, "state_record_inclusion": reinst2_inc}, "notary": rot_eco["item_env"]},
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "SL-CONT-012 B8: 0x0b break by cold owner P1 compromising historical K1-signed state_record MUST propagate CRED_ISSUER_CLOSED.",
    )

    # G4. verify_log_checkpoint exhaustive closure (seq==1 bad cr, unanchored handover pred, persisted closed pred, terminal advance/equivocation, seq==max_seq+1 mismatch, eclipsed rollback, missing block_hash)
    cp1_bad_cr_g4 = sl.sign_envelope({**nlog["cp1_env"]["payload"], "checkpoints_root": _h32("g4-bad-cr")}, [nlog["iss_role"]["sk"]])
    ch_g4_cr = copy.deepcopy(nlog["chain_at_cp1"])
    ch_g4_cr["txs"][nlog["cp1_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp1_bad_cr_g4)).hex()
    add(
        "d12-mut-cp-seq1-bad-checkpoints-root-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_g4_cr, "checkpoint": cp1_bad_cr_g4, "checkpoint_txid": nlog["cp1_tx"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: seq==1 checkpoint with non-empty checkpoints_root MUST refuse CHAIN_FRAME_INVALID.",
    )
    add(
        "d12-mut-cp-handover-unanchored-pred-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_ho, "checkpoint": ho_cp1_env, "checkpoint_txid": ho_cp1_tx, "predecessor_terminal_checkpoint": {"checkpoint": nlog["cp4_env"], "checkpoint_txid": _h32("g4-missing-pred")}},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B2: O(1) handover with unanchored predecessor_terminal_checkpoint MUST refuse CHAIN_FRAME_INVALID.",
    )
    j_term_cp4 = {
        "journal_id": _h32("d12-j-term-cp4"),
        "initial_entries": [{
            "body": {
                "block_hash": nlog["chain"]["txs"][nlog["cp4_tx"]]["block_hash"],
                "checkpoint_id": nlog["cp4_ca"],
                "checkpoint_object_id": sl.object_id(nlog["cp4_env"]["payload"]),
                "checkpoint_txid": nlog["cp4_tx"],
                "checkpoints_root": nlog["cp4_env"]["payload"]["checkpoints_root"],
                "confirmed_height": 749998, "denials_root": nlog["cp4_env"]["payload"]["denials_root"],
                "log_id": nlog["log_id"], "max_seq": 4, "role": "notary", "terminal": True,
            },
            "kind": "log-head",
        }],
    }
    j_term_cp4_closed = copy.deepcopy(j_term_cp4)
    j_term_cp4_closed["initial_entries"].append({
        "body": {"cause": "NOTARY_LOG_COMPROMISED", "observed_at": 1795219999, "observed_height": 750000, "subject": {"log_id": nlog["log_id"], "role": "notary", "subject_kind": "log"}},
        "kind": "closure",
    })
    add(
        "d12-mut-cp-handover-persisted-pred-compromised",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_ho, "checkpoint": ho_cp1_env, "checkpoint_txid": ho_cp1_tx, "journal": j_term_cp4_closed},
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-CONT-012 B2: O(1) handover relying on journal predecessor log_head that is fraud-closed refuses NOTARY_LOG_COMPROMISED.",
    )
    # Journal at terminal cp4 (seq=4, terminal=True): trying to advance to seq=5 refuses CHAIN_FRAME_INVALID!
    cp5_after_term_tx = _h32("d12-cp5-after-term")
    cp5_after_term_p = {
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT,
        "checkpoints_root": sl.rfc9162_mth(nlog["leaves_3"] + [sl.ckpt_leaf(4, nlog["cp4_ca"])]).hex(),
        "cumulative_entries_count": 3, "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": nlog["cp4_env"]["payload"]["denials_root"], "genesis": GENESIS_MAIN,
        "genesis_seal_outpoint": nlog["gen_op"], "issuer": nlog["iss_role_pin"], "log_id": nlog["log_id"],
        "network": "main", "prev_checkpoint_id": nlog["cp4_ca"],
        "prev_log_outpoint": {"txid": nlog["cp4_tx"], "vout": 0}, "role": "notary", "seq": 5, "terminal": True,
        "type": "seallink-log-checkpoint/1",
    }
    cp5_after_term = sl.sign_envelope(cp5_after_term_p, [nlog["iss_role"]["sk"]])
    ch_g4_t5 = copy.deepcopy(nlog["chain"])
    ch_g4_t5["txs"][nlog["cp4_tx"]]["outputs"] = {"0": {"script_pubkey_hex": _spk_hex(nlog["seal_pol"]), "spent_by_txid": cp5_after_term_tx}}
    ch_g4_t5["txs"][cp5_after_term_tx] = {"block_hash": _h32("d12-g4-t5-blk"), "confirmed_height": 749999, "inputs": [sv.make_segwit_input(nlog["cp4_tx"], 0)], "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(cp5_after_term)).hex(), "outputs": {}}
    add(
        "d12-mut-cp-terminal-journal-advance-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_g4_t5, "checkpoint": cp5_after_term, "checkpoint_txid": cp5_after_term_tx, "journal": j_term_cp4},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: Advancing seq=5 past persisted terminal log-head (max_seq=4, terminal=True) MUST refuse CHAIN_FRAME_INVALID.",
    )
    cp4_equiv = sl.sign_envelope({**nlog["cp4_env"]["payload"], "denials_root": _h32("d12-cp4-equiv")}, [nlog["iss_role"]["sk"]])
    ch_g4_eq4 = copy.deepcopy(nlog["chain"])
    ch_g4_eq4["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_equiv)).hex()
    add(
        "d12-mut-cp-terminal-journal-same-seq-equivocation",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_g4_eq4, "checkpoint": cp4_equiv, "checkpoint_txid": nlog["cp4_tx"], "journal": j_term_cp4},
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "SL-CONT-012 B1: Same-seq equivocation at terminal max_seq=4 MUST refuse NOTARY_LOG_COMPROMISED (not CHAIN_FRAME_INVALID).",
    )
    j_bad_next_cp2 = copy.deepcopy(j_idem_cp2)
    j_bad_next_cp2["initial_entries"][0]["body"]["checkpoint_id"] = _h32("d12-wrong-prev-cid")
    add(
        "d12-mut-cp-seq-plus1-mismatched-ex-head-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": nlog["chain_at_cp3"], "checkpoint": nlog["cp3_env"], "checkpoint_txid": nlog["cp3_tx"], "journal": j_bad_next_cp2},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012: Advancing seq == max_seq + 1 with mismatched persisted ex_head.checkpoint_id MUST refuse CHAIN_FRAME_INVALID.",
    )
    add(
        "d12-mut-cp-eclipsed-rollback-seq-lt-max-seq",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": nlog["chain_at_cp1"], "checkpoint": nlog["cp1_env"], "checkpoint_txid": nlog["cp1_tx"], "journal": j_idem_cp2},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 B2: Eclipsed chain presenting unspent cp1 (seq=1) when local journal is already at max_seq=2 refuses CHAIN_FRAME_INVALID.",
    )
    ch_no_bh = copy.deepcopy(nlog["chain_at_cp1"])
    ch_no_bh["txs"][nlog["cp1_tx"]].pop("block_hash", None)
    add(
        "d12-mut-cp-missing-block-hash-chain-unhealthy",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_no_bh, "checkpoint": nlog["cp1_env"], "checkpoint_txid": nlog["cp1_tx"], "journal": {"journal_id": _h32("d12-no-bh-j")}},
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "SL-CONT-012: Persisting log-head without verified 64-hex block_hash MUST refuse CHAIN_UNHEALTHY.",
    )

    # G5. verify_log_fraud revocation_omission rec_b.state_seq == rev.state_seq NOT fraud (kills < -> <= boundary!)
    ch_g5_eq = copy.deepcopy(nlog["chain"])
    kv4_eq3 = {nlog["denial_key"]: nlog["rev3_ca"]}
    cp4_eq3_env = sl.sign_envelope({**nlog["cp4_env"]["payload"], "batch_root": b4_rev3_root, "denials_delta_root": b4_rev3_root, "denials_root": sl.smt_root(kv4_eq3)}, [nlog["iss_role"]["sk"]])
    ch_g5_eq["txs"][nlog["cp4_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(cp4_eq3_env)).hex()
    add(
        "d12-mut-fraud-omission-rec-b-eq-seq-not-fraud",
        ["SL-CONT-012"],
        "log_fraud",
        {
            "chain": ch_g5_eq,
            "fraud": {
                "batch_proof": b4_rev3_pfs[e_rev3], "cp_a": cp4_eq3_env, "cp_a_txid": nlog["cp4_tx"],
                "cp_b": cp4_eq3_env, "cp_b_txid": nlog["cp4_tx"],
                "fraud_mode": "revocation_omission", "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nlog["gen_op"],
                "log_id": nlog["log_id"], "network": "main",
                "rec_b": nlog["rev3_env"], "revocation": nlog["rev3_env"], "role": "notary",
                "smt_proof": sl.smt_prove(kv4_eq3, nlog["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "SL-CONT-012 H4: revocation_omission where cp_b holds rec_b with state_seq == rev.state_seq is NOT fraud (boundary <).",
    )

    # G6. verify_artifact_ticket: notary wrong genesis -> CHAIN_MISMATCH, notary act credential closure -> ARTIFACT_POLICY_DENIED
    tkt_na_badgen = copy.deepcopy(gk_ticket_2of3)
    tkt_na_badgen["notarizations"][0]["notary_act"] = sl.sign_envelope({**gn1["entry"]["notary_act"]["payload"], "genesis": _h32("wrong-na-gen")}, [nlog["iss_role"]["sk"]])
    add(
        "d12-mut-ticket-notary-wrong-genesis-chain-mismatch",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {"chain": gk_chain, "policy": gk_pol_hardened, "ticket": tkt_na_badgen},
        "REFUSE",
        "CHAIN_MISMATCH",
        "SL-ARTF-003: Trusted notarization with wrong genesis MUST refuse CHAIN_MISMATCH.",
        module="artifact-notarization",
    )
    add(
        "d12-mut-ticket-notary-act-journal-closed-denied",
        ["SL-ARTF-003"],
        "artifact_ticket",
        {
            "chain": gk_chain,
            "journal": {
                "journal_id": _h32("d12-j-act-cl"),
                "initial_entries": [{
                    "body": {"cause": "CRED_REVOKED_FOR_CAUSE", "observed_at": 1795219990, "observed_height": 750000, "subject": {"subject_id": gn1_act_id, "subject_kind": "credential"}},
                    "kind": "closure",
                }],
            },
            "policy": gk_pol_hardened,
            "ticket": gk_ticket_2of3,
        },
        "REFUSE",
        "ARTIFACT_POLICY_DENIED",
        "SL-ARTF-003: Trusted notarization whose act_id has a durable credential closure in journal MUST refuse ARTIFACT_POLICY_DENIED.",
        module="artifact-notarization",
    )

    # G7. verify_tier2_name_history_page exhaustive mutation & boundary closure
    add(
        "d12-mut-tier2-bad-header-schema-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "headers": [{"header_hex": "abcd", "height": 1}], "page": page_reg_empty, "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: BlockHeaderProof failing schema validation refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d12-mut-tier2-missing-epoch-start-time-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "headers": [
                {"header_hex": prev_hdr_2015.hex(), "height": 2015},
                {"auxpow": aux_proof_ok, "header_hex": hdr_2016.hex(), "height": 2016},
            ],
            "page": page_reg_empty, "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-006: Retarget height H % 2016 == 0 missing epoch_start_time (and ancestor header) refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    proof_exp_eq, _ = _build_synthetic_spv_proof("exp-eq", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', block_height=750010 + 36000, prev_raw_override=bytes.fromhex(proof_low["tx_hex"]))
    proof_exp_m1, _ = _build_synthetic_spv_proof("exp-m1", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', block_height=750010 + 35999, prev_raw_override=bytes.fromhex(proof_low["tx_hex"]))
    add(
        "d12-mut-tier2-exact-expiry-gap-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_low, proof_exp_eq])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Chained Tier-2 update at exact prev_h + 36000 expires -> TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d12-mut-tier2-exact-expiry-minus1-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_low, proof_exp_m1])},
        "ADMIT",
        None,
        "SL-ARTF-005: Chained Tier-2 update at exact prev_h + 35999 remains live -> ADMIT.",
        module="artifact-notarization",
    )
    proof_sameh_diffblk, _ = _build_synthetic_spv_proof("sameh-diffblk", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', block_height=750010, prev_raw_override=bytes.fromhex(proof_low["tx_hex"]))
    add(
        "d12-mut-tier2-same-height-diff-block-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_low, proof_sameh_diffblk])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Chained Tier-2 updates at equal block_height with different block_hash refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    proof_bad_jcs, _ = _build_synthetic_spv_proof("bad-jcs", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", "not-valid-json")
    add(
        "d12-mut-tier2-bad-jcs-value-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_bad_jcs])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Tier-2 update with non-JCS name value refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    pl_0x15 = bytes([0x01]) + bytes.fromhex(_h32("d12-t2-0x15")) + bytes([0x00])
    scr_0x15 = bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x15, len(pl_0x15)]) + pl_0x15
    proof_0x15, _ = _build_synthetic_spv_proof("crit-0x15", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', opreturns=[scr_0x15])
    add(
        "d12-mut-tier2-future-critical-0x15-incomplete",
        ["SL-ARTF-005", "SL-LDGR-010"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_0x15])},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "SL-ARTF-005: Tier-2 update carrying unknown future critical 0x15 SLNK frame fails closed ORIGIN_STATUS_INCOMPLETE.",
        module="artifact-notarization",
    )
    proof_0b_gt, _ = _build_synthetic_spv_proof("0b-gt", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', block_height=750010, opreturns=[sl.encode_opreturn(0x0B, _h32("d12-t2-0b-gt"), h_c=750011)])
    proof_0b_eq, _ = _build_synthetic_spv_proof("0b-eq", spv_p2wpkh, [spv_k1["sk"]], "id/spv-notary", '{"link":{}}', block_height=750010, opreturns=[sl.encode_opreturn(0x0B, _h32("d12-t2-0b-eq"), h_c=750010)])
    add(
        "d12-mut-tier2-0x0b-hc-gt-uh-refuse",
        ["SL-ARTF-005", "SL-LDGR-010"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_0b_gt])},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Tier-2 update with 0x0b h_c == uh + 1 (> block_height) refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d12-mut-tier2-0x0b-hc-eq-uh-admit",
        ["SL-ARTF-005", "SL-LDGR-010"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-notary", [proof_0b_eq])},
        "ADMIT",
        None,
        "SL-ARTF-005: Tier-2 update with 0x0b at exact h_c == block_height admits (boundary >).",
        module="artifact-notarization",
    )
    spv_p2wpkh_2 = {"kind": "key", "pk": spv_k2["comp"]}
    proof_rot_1, _ = _build_synthetic_spv_proof("t2-rot1", spv_p2wpkh, [spv_k1["sk"]], "id/spv-rot", '{"link":{}}', block_height=750010, new_owner_pol=spv_p2wpkh_2)
    proof_rot_2, _ = _build_synthetic_spv_proof("t2-rot2", spv_p2wpkh_2, [spv_k2["sk"]], "id/spv-rot", '{"link":{}}', block_height=750011, prev_raw_override=bytes.fromhex(proof_rot_1["tx_hex"]))
    add(
        "d12-mut-tier2-cold-p2wpkh-rotation-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {"expected_owner_policy": spv_p2wpkh, "page": _mk_page("id/spv-rot", [proof_rot_1, proof_rot_2])},
        "ADMIT",
        None,
        "SL-ARTF-005: Tier-2 page evolves expected P2WPKH owner_policy across authorized cold owner rotation.",
        module="artifact-notarization",
    )
    add(
        "d12-mut-tier2-bad-next-cursor-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expected_owner_policy": spv_p2wpkh,
            "page": _mk_page("id/spv-notary", [proof_low], next_cursor={"height": 750010, "txid": _h32("wrong-nc-tx"), "vout": 0}, has_more=True),
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "SL-ARTF-005: Tier-2 page with mismatched next_cursor refuses TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # G8. verify_federation_disclosure exhaustive closure (journal seal closure, missing recent_block, role CRED_ISSUER_CLOSED & NAME_ROLE_CHANGED exact boundaries)
    fx_g8 = rm._base_invocation_fixture()
    g8_p = copy.deepcopy(fx_g8["bundle"]["grants"][0]["payload"])
    g8_p.pop("executor_ref", None)
    g8_p["executor"] = fx_g8["invocation"]["payload"]["executor"]
    g8_p["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "10", "resource": "requests", "unit": "calls", "window": "term"}]
    g_g8 = sl.sign_envelope(g8_p, [fx_g8["_keys"]["alice_gr"]["sk"]])
    g8_itx = fx_g8["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    fx_g8["chain"]["txs"][g8_itx]["opreturn_hex"] = sl.encode_opreturn(
        0x01,
        sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(g_g8), "grant_id": sl.object_id(g8_p), "type": "seallink-issuance/1"}).hex(),
    ).hex()
    g8_seal = g8_p["revocation"]["seal"]
    g8_iss = g8_p["issuer"]
    g8_pol_fed = {"federation_id": "fed.example/a", "peer_min_tier": 1, "pii_contour": "A", "trusted_peers": ["id/peer-a"]}
    g8_ctx = {"phase": "screening", "peer_id": "id/peer-a", "peer_tier": 1, "issuance_txid": g8_itx}
    add(
        "d12-mut-fed-journal-seal-closure-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_g8["chain"], "grant": g_g8,
            "journal": {
                "journal_id": _h32("d12-g8-j-seal"),
                "initial_entries": [{
                    "body": {"cause": "SEAL_SPENT", "observed_at": 1795219900, "observed_height": 750000, "subject": {"outpoint": {"txid": g8_seal["txid"], "vout": g8_seal["vout"]}, "subject_kind": "seal"}},
                    "kind": "closure",
                }],
            },
            "peer_ctx": g8_ctx, "policy": g8_pol_fed,
        },
        "REFUSE",
        "SEAL_SPENT",
        "SL-SERV-004 H5: Federation screening MUST enforce durable journal seal closure -> SEAL_SPENT.",
        module="federated-screening",
    )
    ch_g8_norb = copy.deepcopy(fx_g8["chain"])
    ch_g8_norb["blocks"].pop(g_g8["payload"]["recent_block"], None)
    add(
        "d12-mut-fed-missing-recent-block-recency-invalid",
        ["SL-SERV-004"],
        "federation",
        {"chain": ch_g8_norb, "grant": g_g8, "journal": {"journal_id": _h32("d12-g8-j-rb")}, "peer_ctx": g8_ctx, "policy": g8_pol_fed},
        "REFUSE",
        "CHAIN_RECENCY_INVALID",
        "SL-SERV-004 H5: Federation screening with unknown recent_block refuses CHAIN_RECENCY_INVALID.",
        module="federated-screening",
    )
    g8_rsubj_base = {"name": g8_iss["name"], "policy_sha256": sv._policy_sha256(g8_iss["role_policy"]), "registration": g8_iss["registration"], "role": "grant", "subject_kind": "role"}
    # Exact tip_height (750010) == cutoff_height -> CRED_ISSUER_CLOSED; tip_height == cutoff_height - 1 (750011) -> ADMIT!
    add(
        "d12-mut-fed-role-cred-issuer-closed-exact-cutoff-refuse",
        ["SL-SERV-004", "SL-CONT-009"],
        "federation",
        {
            "chain": fx_g8["chain"], "grant": g_g8,
            "journal": {
                "journal_id": _h32("d12-g8-j-rc1"),
                "initial_entries": [{
                    "body": {"cause": "CRED_ISSUER_CLOSED", "observed_at": 1795219900, "observed_height": 750010, "subject": {**g8_rsubj_base, "cutoff_height": 750010}},
                    "kind": "closure",
                }],
            },
            "peer_ctx": g8_ctx, "policy": g8_pol_fed,
        },
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "SL-SERV-004 H5: Federation screening enforces durable journal CRED_ISSUER_CLOSED at exact tip_height == cutoff_height.",
        module="federated-screening",
    )
    add(
        "d12-mut-fed-role-cred-issuer-closed-above-tip-admit",
        ["SL-SERV-004", "SL-CONT-009"],
        "federation",
        {
            "chain": fx_g8["chain"], "grant": g_g8,
            "journal": {
                "journal_id": _h32("d12-g8-j-rc2"),
                "initial_entries": [{
                    "body": {"cause": "CRED_ISSUER_CLOSED", "observed_at": 1795219900, "observed_height": 750010, "subject": {**g8_rsubj_base, "cutoff_height": 750011}},
                    "kind": "closure",
                }],
            },
            "peer_ctx": g8_ctx, "policy": g8_pol_fed,
        },
        "ADMIT",
        None,
        "SL-SERV-004 H5: Federation screening admits when journal CRED_ISSUER_CLOSED cutoff_height == tip_height + 1 (boundary >=).",
        module="federated-screening",
    )
    # Exact f_recent_h (749990) < retired_before_height (749991) -> NAME_ROLE_CHANGED; f_recent_h == retired_before_height (749990) -> ADMIT!
    add(
        "d12-mut-fed-role-changed-below-rbh-refuse",
        ["SL-SERV-004", "SL-IDEN-004"],
        "federation",
        {
            "chain": fx_g8["chain"], "grant": g_g8,
            "journal": {
                "journal_id": _h32("d12-g8-j-rr1"),
                "initial_entries": [{
                    "body": {"cause": "NAME_ROLE_CHANGED", "observed_at": 1795219900, "observed_height": 750000, "subject": {**g8_rsubj_base, "retired_before_height": 749991}},
                    "kind": "closure",
                }],
            },
            "peer_ctx": g8_ctx, "policy": g8_pol_fed,
        },
        "REFUSE",
        "NAME_ROLE_CHANGED",
        "SL-SERV-004 H5: Federation screening refuses NAME_ROLE_CHANGED when recent_block height (749990) < retired_before_height (749991).",
        module="federated-screening",
    )
    add(
        "d12-mut-fed-role-changed-exact-rbh-admit",
        ["SL-SERV-004", "SL-IDEN-004"],
        "federation",
        {
            "chain": fx_g8["chain"], "grant": g_g8,
            "journal": {
                "journal_id": _h32("d12-g8-j-rr2"),
                "initial_entries": [{
                    "body": {"cause": "NAME_ROLE_CHANGED", "observed_at": 1795219900, "observed_height": 750000, "subject": {**g8_rsubj_base, "retired_before_height": 749990}},
                    "kind": "closure",
                }],
            },
            "peer_ctx": g8_ctx, "policy": g8_pol_fed,
        },
        "ADMIT",
        None,
        "SL-SERV-004 H5: Federation screening admits new-epoch grant at exact recent_block height == retired_before_height (749990, boundary <).",
        module="federated-screening",
    )
