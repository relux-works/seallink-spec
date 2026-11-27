#!/usr/bin/env python3
"""
Deterministic Conformance Vector Generator for SealLink v1.0.0-draft.12.

Produces nine executable JSON vector suites under vectors/:
  1. wire-jcs-and-hashes.json
  2. ledger-scripts-and-opreturn.json
  3. constraints-and-schemas.json
  4. trace-01-mail-offline-revoke.json
  5. trace-02-guardian-succession-assent.json
  6. trace-03-delegation-pool-single-use.json
  7. trace-04-agent-guardian-intake.json
  8. refusal-coverage-matrix.json
  9. security-conformance.json
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_refusal_matrix as rm
import build_security_suite as sec
import seallink_ref as sl
import seallink_verifier as sv

VERSION = "1.0.0-draft.12"
GENESIS_MAIN = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
VECTORS_DIR = ROOT / "vectors"


def h32(label: str) -> str:
    """Deterministic synthetic 32-byte lowercase hex (txid / salt / nonce / hash for vectors)."""
    return sl.sha256(f"seallink-vector-hex:{label}".encode("utf-8")).hex()


def make_keypair(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(label)
    return {
        "label": label,
        "priv_hex": sk.hex(),
        "xonly_pk": sl.xonly_pubkey(sk),
        "compressed_pk": sl.compressed_pubkey(sk),
        "_sk": sk,
    }


def spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def make_role_pin(name: str, reg_label: str, owner_kp: dict[str, Any], role_pks: list[str], m: int = 1) -> dict[str, Any]:
    return {
        "name": name,
        "owner_policy": {"kind": "key", "pk": owner_kp["compressed_pk"]},
        "registration": {"txid": h32(reg_label), "vout": 0},
        "role_policy": {"m": m, "pks": sorted(role_pks)},
    }


def make_name_pin(name: str, reg_label: str, owner_policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "owner_policy": owner_policy,
        "registration": {"txid": h32(reg_label), "vout": 0},
    }


def envelope_record(env: dict[str, Any], schema_ref: str) -> dict[str, Any]:
    canonical = sl.jcs_encode(env).decode("utf-8")
    return {
        "schema": schema_ref,
        "object": env,
        "canonical_jcs": canonical,
        "object_id": sl.object_id(env["payload"]),
        "signing_digest": sl.signing_digest(env["payload"]).hex(),
        "content_addr": sl.content_addr(env),
    }


def unsigned_record(obj: dict[str, Any], schema_ref: str) -> dict[str, Any]:
    canonical = sl.jcs_encode(obj).decode("utf-8")
    return {
        "schema": schema_ref,
        "object": obj,
        "canonical_jcs": canonical,
        "object_id": sl.object_id(obj),
        "content_addr": sl.content_addr(obj),
    }


def build_wire_vectors() -> dict[str, Any]:
    k1 = make_keypair("wire-signer-1")
    k2 = make_keypair("wire-signer-2")
    k3 = make_keypair("wire-signer-3")
    owner = make_keypair("wire-owner")
    rcpt = make_keypair("wire-recipient")
    exec_k = make_keypair("wire-executor")
    seal_k = make_keypair("wire-seal")

    utf16_obj = {"\ue000": "private", "\U0001f512": "surrogate-pair", "a": 1, "b": "line1"}
    multiline_obj = {"terms_text": "Line 1\nLine 2", "type": "seallink-grant/1"}
    max_int_obj = {"amount": "18446744073709551615", "height": 9007199254740991}

    positive_jcs = [
        {
            "id": "jcs-utf16-key-order",
            "rule": "SL-WIRE-006",
            "input_utf8": sl.jcs_encode(utf16_obj).decode("utf-8"),
            "expected": "VALID",
            "notes": "UTF-16 code-unit key order places U+1F512 (D83D DD12) before U+E000 (E000).",
        },
        {
            "id": "jcs-multiline-lf-allowed",
            "rule": "SL-WIRE-005",
            "input_utf8": sl.jcs_encode(multiline_obj).decode("utf-8"),
            "expected": "VALID",
        },
        {
            "id": "jcs-typed-card-role-lf-allowed",
            "rule": "SL-WIRE-005",
            "input_utf8": sl.jcs_encode({"display": "Alice", "kind": "person", "name": "id/alice", "role": "Engineer\nFounder", "type": "seallink-card/1"}).decode("utf-8"),
            "expected": "VALID",
            "notes": "LF is permitted on the exact typed path seallink-card/1 role (x-seallink-allow-lf).",
        },
        {
            "id": "jcs-max-integers",
            "rule": "SL-WIRE-007",
            "input_utf8": sl.jcs_encode(max_int_obj).decode("utf-8"),
            "expected": "VALID",
        },
    ]

    deep16: Any = {"v": 1}
    for _ in range(15):
        deep16 = {"a": deep16}
    deep17: Any = {"a": deep16}
    # Build depth-1000 raw bytes directly so Python 3.11+ never hits RecursionError in json.dumps
    deep1000_raw = (b'{"a":' * 999) + b'{"v":1}' + (b'}' * 999)

    positive_jcs.append({
        "id": "jcs-depth-16-allowed",
        "rule": "SL-WIRE-001",
        "input_utf8": json.dumps(deep16, separators=(",", ":")),
        "expected": "VALID",
        "notes": "Exact container nesting depth 16 MUST be accepted (only container depth > 16 refuses WIRE_SIZE).",
    })

    negative_jcs = [
        {"id": "neg-depth-17", "rule": "SL-WIRE-001", "input_hex": json.dumps(deep17, separators=(",", ":")).encode("utf-8").hex(), "expected_refusal": "WIRE_SIZE"},
        {"id": "neg-depth-1000-iterative", "rule": "SL-WIRE-001", "input_hex": deep1000_raw.hex(), "expected_refusal": "WIRE_SIZE"},
        {"id": "neg-utf8-bom", "rule": "SL-WIRE-002", "input_hex": (b"\xef\xbb\xbf" + b'{"a":1}').hex(), "expected_refusal": "WIRE_JSON"},
        {"id": "neg-trailing-space", "rule": "SL-WIRE-002", "input_hex": b'{"a":1}\n'.hex(), "expected_refusal": "WIRE_JSON"},
        {"id": "neg-array-root", "rule": "SL-WIRE-002", "input_hex": b"[1,2]".hex(), "expected_refusal": "WIRE_JSON"},
        {"id": "neg-duplicate-key", "rule": "SL-WIRE-003", "input_hex": b'{"a":1,"a":2}'.hex(), "expected_refusal": "WIRE_DUPLICATE"},
        {"id": "neg-null-value", "rule": "SL-WIRE-004", "input_hex": b'{"a":null}'.hex(), "expected_refusal": "WIRE_VALUE"},
        {"id": "neg-null-precedes-control-string", "rule": "SL-WIRE-018", "input_hex": b'{"a":"\\t","b":null}'.hex(), "expected_refusal": "WIRE_VALUE"},
        {"id": "neg-float-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":1.5}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-trailing-dot-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":1.}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-leading-dot-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":.5}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-neg-leading-dot-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":-.5}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-plus-prefix-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":+1}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-incomplete-exp-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":1e}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-leading-zero-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":01}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-negative-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":-1}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-uint53-overflow", "rule": "SL-WIRE-007", "input_hex": b'{"a":9007199254740992}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-huge-5000-digit-int", "rule": "SL-WIRE-007", "input_hex": (b'{"a":' + (b"9" * 5000) + b"}").hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-nan-constant", "rule": "SL-WIRE-002", "input_hex": b'{"a":NaN}'.hex(), "expected_refusal": "WIRE_JSON"},
        {"id": "neg-infinity-constant", "rule": "SL-WIRE-002", "input_hex": b'{"a":Infinity}'.hex(), "expected_refusal": "WIRE_JSON"},
        {"id": "neg-arabic-digit-number", "rule": "SL-WIRE-002", "input_hex": '{"a":0\u0661}'.encode("utf-8").hex(), "expected_refusal": "WIRE_JSON"},
        {"id": "neg-del-char", "rule": "SL-WIRE-005", "input_hex": b'{"a":"x\x7fy"}'.hex(), "expected_refusal": "WIRE_STRING"},
        {"id": "neg-c1-control", "rule": "SL-WIRE-005", "input_hex": '{"a":"x\u0085y"}'.encode("utf-8").hex(), "expected_refusal": "WIRE_STRING"},
        {"id": "neg-lf-in-non-multiline", "rule": "SL-WIRE-005", "input_hex": b'{"name":"id/a\\nb"}'.hex(), "expected_refusal": "WIRE_STRING"},
        {"id": "neg-lf-in-untyped-terms-text", "rule": "SL-WIRE-005", "input_hex": b'{"terms_text":"Line 1\\nLine 2"}'.hex(), "expected_refusal": "WIRE_STRING"},
        {"id": "neg-unsorted-keys", "rule": "SL-WIRE-006", "input_hex": b'{"b":1,"a":2}'.hex(), "expected_refusal": "WIRE_NOT_CANONICAL"},
        {"id": "neg-pretty-whitespace", "rule": "SL-WIRE-006", "input_hex": b'{"a": 1}'.hex(), "expected_refusal": "WIRE_NOT_CANONICAL"},
    ]

    for c in positive_jcs:
        ok, res = sl.jcs_validate(c["input_utf8"].encode("utf-8"))
        assert ok, f"positive JCS failed: {c['id']} -> {res}"
    for c in negative_jcs:
        ok, code = sl.jcs_validate(bytes.fromhex(c["input_hex"]))
        assert (not ok) and code == c["expected_refusal"], f"negative JCS mismatch {c['id']}: got {(ok, code)}"

    salt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    clause_obj = {"text": "Room inspection"}
    clause_digest = sl.clause_commit(salt, clause_obj)

    grant_payload = {
        "capabilities": [{"action": "mail/read", "target": "mailbox:id/alice:work", "where": {"folder": {"eq": "Invoices"}}}],
        "executor": {"key": exec_k["xonly_pk"], "name": "id/mail-host-a"},
        "genesis": GENESIS_MAIN,
        "issuer": make_role_pin("id/alice", "wire-alice-reg", owner, [k1["xonly_pk"], k2["xonly_pk"], k3["xonly_pk"]], m=2),
        "network": "main",
        "not_after_height": 750100,
        "not_before_height": 750000,
        "recent_block": h32("wire-recent-block"),
        "recipient": {"key": rcpt["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "revocable",
            "mode": "seal",
            "seal": {"script_policy": {"kind": "key", "pk": seal_k["compressed_pk"]}, "txid": h32("wire-seal-tx"), "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    env_2of3_a = sl.sign_envelope(
        grant_payload,
        [k1["_sk"], k2["_sk"]],
        policy_pks=[k1["xonly_pk"], k2["xonly_pk"], k3["xonly_pk"]],
        m=2,
    )
    env_2of3_b = sl.sign_envelope(
        grant_payload,
        [k1["_sk"], k3["_sk"]],
        policy_pks=[k1["xonly_pk"], k2["xonly_pk"], k3["xonly_pk"]],
        m=2,
    )
    assert sl.object_id(env_2of3_a["payload"]) == sl.object_id(env_2of3_b["payload"])
    assert sl.content_addr(env_2of3_a) != sl.content_addr(env_2of3_b)
    assert sl.verify_envelope_signatures(env_2of3_a)[0]
    assert sl.verify_envelope_signatures(env_2of3_b)[0]

    bad_5of2 = copy.deepcopy(env_2of3_a)
    bad_5of2["signatures"]["policy"] = {"m": 5, "pks": sorted([k1["xonly_pk"], k2["xonly_pk"]])}
    bad_dup_sig = copy.deepcopy(env_2of3_a)
    bad_dup_sig["signatures"]["sigs"] = [bad_dup_sig["signatures"]["sigs"][0], bad_dup_sig["signatures"]["sigs"][0]]
    bad_flipped = copy.deepcopy(env_2of3_a)
    s0 = bad_flipped["signatures"]["sigs"][0]["sig"]
    bad_flipped["signatures"]["sigs"][0]["sig"] = ("0" if s0[0] != "0" else "1") + s0[1:]

    # Device signature algorithm vectors (RFC 8032 Ed25519 & SEC 1 NIST P-256 low-S + high-S negative + wrong-type negative)
    ed_seed = sl.deterministic_ed25519_seed("wire-device-ed25519")
    p256_sk = sl.deterministic_p256_privkey("wire-device-p256")
    dev_cmd_payload = {
        "arguments": {"scope": "all"},
        "command": "keyholder-halt",
        "exp": 1795220300,
        "genesis": GENESIS_MAIN,
        "iat": 1795220000,
        "level": 2,
        "network": "main",
        "nonce": h32("wire-dev-cmd-nonce"),
        "owner": "id/alice",
        "target_executor": "id/station-a",
        "type": "seallink-owner-command/1",
    }
    env_cmd_ed25519 = sl.sign_envelope(dev_cmd_payload, [ed_seed], alg="ed25519")
    env_cmd_p256 = sl.sign_envelope({**dev_cmd_payload, "nonce": h32("wire-dev-cmd-nonce-2")}, [p256_sk], alg="p256")
    assert sl.verify_envelope_signatures(env_cmd_ed25519)[0]
    assert sl.verify_envelope_signatures(env_cmd_p256)[0]

    env_cmd_p256_high_s = copy.deepcopy(env_cmd_p256)
    low_sig = env_cmd_p256_high_s["signatures"]["sigs"][0]["sig"]
    env_cmd_p256_high_s["signatures"]["sigs"][0]["sig"] = low_sig[:64] + f"{(sl._P256_N - int(low_sig[64:], 16)):064x}"
    assert sl.verify_envelope_signatures(env_cmd_p256_high_s) == (False, "WIRE_SIGNATURE")

    # Non-bip340 alg on non-device object type (seallink-grant/1) MUST refuse WIRE_MEMBER (SPEC-01 §7 Step 8 + SL-WIRE-013)
    bad_ed_on_grant = sl.sign_envelope(grant_payload, [ed_seed], alg="ed25519")
    bad_p256_on_grant = sl.sign_envelope(grant_payload, [p256_sk], alg="p256")
    assert sl.verify_envelope_signatures(bad_ed_on_grant) == (False, "WIRE_MEMBER")
    assert sl.verify_envelope_signatures(bad_p256_on_grant) == (False, "WIRE_MEMBER")

    # Cofactorless Ed25519: small-order pubkey (identity 0x01 || 00*31) MUST refuse WIRE_KEY (R3 B6, W-11)
    bad_ed_small_order = copy.deepcopy(env_cmd_ed25519)
    small_order_pk = "01" + ("00" * 31)
    bad_ed_small_order["signatures"]["policy"]["pks"] = [small_order_pk]
    bad_ed_small_order["signatures"]["sigs"][0]["pk"] = small_order_pk
    assert sl.verify_envelope_signatures(bad_ed_small_order) == (False, "WIRE_KEY")

    # Unsorted sigs[].pk MUST refuse WIRE_SIGNATURE (S-1)
    bad_unsorted_sigs = copy.deepcopy(env_2of3_a)
    bad_unsorted_sigs["signatures"]["sigs"] = list(reversed(bad_unsorted_sigs["signatures"]["sigs"]))
    assert sl.verify_envelope_signatures(bad_unsorted_sigs) == (False, "WIRE_SIGNATURE")

    # Explicit "alg": "bip340" on ThresholdPolicy MUST refuse WIRE_MEMBER (canonical single encoding)
    bad_explicit_bip340 = copy.deepcopy(env_2of3_a)
    bad_explicit_bip340["signatures"]["policy"]["alg"] = "bip340"
    assert sl.verify_envelope_signatures(bad_explicit_bip340) == (False, "WIRE_MEMBER")

    # Standalone atomic golden vectors for draft.11/draft.12 primitives (fsverity, target_id, log_id, RFC 9162, SMT256)
    fsv_empty = sl.fsverity_sha256_digest(b"")
    assert fsv_empty == "3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95"
    fsv_small_data = b"SealLink v1.0"
    fsv_small = sl.fsverity_sha256_digest(fsv_small_data)
    fsv_multi_data = (b"A" * 4096) + (b"B" * 100)
    fsv_multi = sl.fsverity_sha256_digest(fsv_multi_data)
    fsv_3level_digest = sl.fsverity_sha256_digest(b"\x5a" * 524289)
    art_sha = {"digest": sl.sha256(fsv_small_data).hex(), "scheme": "sha256"}
    art_fsv = {"digest": fsv_empty, "params": {"block_size": 4096, "hash_alg": "sha256", "salt_hex": "", "version": 1}, "scheme": "fsverity-sha256"}
    g_log_reg = {"txid": h32("golden-log-reg"), "vout": 0}
    g_log_gen = {"txid": h32("golden-log-gen"), "vout": 2}
    g_log_id = sl.compute_log_id("main", GENESIS_MAIN, "notary", "id/notary-golden", g_log_reg, g_log_gen)
    g_log_gen_next = {"txid": h32("golden-log-gen-2"), "vout": 0}
    g_log_id_ho = sl.compute_log_id("main", GENESIS_MAIN, "notary", "id/notary-golden", g_log_reg, g_log_gen_next, predecessor_log_id=g_log_id)
    g_ckpts = [sl.ckpt_leaf(i + 1, h32(f"golden-cp-{i + 1}")) for i in range(5)]
    g_mth_3 = sl.rfc9162_mth(g_ckpts[:3]).hex()
    g_peaks_3 = sl.rfc9162_peaks(g_ckpts[:3])
    g_mth_4 = sl.rfc9162_mth(g_ckpts[:4]).hex()
    assert sl.rfc9162_append_leaf_to_peaks(g_peaks_3, 3, g_ckpts[3]) == g_mth_4
    g_mth_5 = sl.rfc9162_mth(g_ckpts).hex()
    g_inc_2_in_5 = sl.rfc9162_inclusion_proof(g_ckpts, 2)
    assert sl.rfc9162_verify_inclusion(g_ckpts[2], 2, 5, g_inc_2_in_5["hashes"], g_mth_5)
    g_smt_kv = {
        f"act:{h32('golden-act')}|*": h32("golden-rev-1"),
        f"target:{sl.artifact_target_id(art_fsv)}|*": h32("golden-rev-2"),
    }
    g_smt_root = sl.smt_root(g_smt_kv)
    g_smt_inc = sl.smt_prove(g_smt_kv, f"act:{h32('golden-act')}|*")
    g_smt_abs = sl.smt_prove(g_smt_kv, f"rel:{h32('golden-absent')}|*")
    assert (
        sl.smt_verify_proof(g_smt_inc)
        and g_smt_inc["root"] == g_smt_root
        and sl.smt_verify_proof(g_smt_abs)
        and g_smt_abs["root"] == g_smt_root
    )
    g_smt4_kv = {
        f"act:{h32('smt4-k1')}|*": h32("smt4-v1"),
        f"act:{h32('smt4-k2')}|*": h32("smt4-v2"),
        f"target:{h32('smt4-k3')}|*": h32("smt4-v3"),
        f"rel:{h32('smt4-k4')}|*": h32("smt4-v4"),
    }
    g_smt4_root = sl.smt_root(g_smt4_kv)
    g_smt4_proofs = [
        sl.smt_prove(g_smt4_kv, f"act:{h32('smt4-k1')}|*"),
        sl.smt_prove(g_smt4_kv, f"rel:{h32('smt4-k4')}|*"),
        sl.smt_prove(g_smt4_kv, f"act:{h32('smt4-absent')}|*"),
    ]
    assert all(sl.smt_verify_proof(p) and p["root"] == g_smt4_root for p in g_smt4_proofs)

    # Atomic journal_commit_init / journal_commit_step & strict cofactorless Ed25519 vectors (L-2)
    g_jid = h32("golden-journal-id")
    g_c0 = sl.journal_commit_init(g_jid)
    g_je1 = {"body": {"cause": "SEAL_SPENT", "observed_at": 1795220000, "subject": {"subject_id": h32("g-sub"), "subject_kind": "grant"}}, "kind": "closure", "pos": 1}
    g_c1 = sl.journal_commit_step(g_c0, g_je1)
    g_je2 = {"body": {"expires_at": 1795220300, "invocation_id": h32("g-inv"), "nonce": h32("g-nonce"), "scope": "invocation"}, "kind": "nonce", "pos": 2}
    g_c2 = sl.journal_commit_step(g_c1, g_je2)

    ed_msg = b"SealLink-Ed25519-SpecCheck-v1"
    ed_pk_ok = sl.ed25519_pubkey(ed_seed)
    ed_sig_ok = sl.ed25519_sign(ed_msg, ed_seed)
    # Non-canonical S == L (ed25519 group order) MUST be rejected!
    ed_sig_noncanon_s = ed_sig_ok[:64] + sl._ED_L.to_bytes(32, "little").hex()
    ed_speccheck = [
        {"id": "ed25519-valid", "msg_hex": ed_msg.hex(), "pubkey_hex": ed_pk_ok, "sig_hex": ed_sig_ok, "expected_valid": True},
        {"id": "ed25519-small-order-identity-pk", "msg_hex": ed_msg.hex(), "pubkey_hex": "01" + ("00" * 31), "sig_hex": ed_sig_ok, "expected_valid": False},
        {"id": "ed25519-noncanonical-s-eq-L", "msg_hex": ed_msg.hex(), "pubkey_hex": ed_pk_ok, "sig_hex": ed_sig_noncanon_s, "expected_valid": False},
        {"id": "ed25519-wrong-msg", "msg_hex": b"wrong-msg".hex(), "pubkey_hex": ed_pk_ok, "sig_hex": ed_sig_ok, "expected_valid": False},
    ]
    for ec in ed_speccheck:
        assert sl.ed25519_verify(bytes.fromhex(ec["msg_hex"]), ec["pubkey_hex"], ec["sig_hex"]) is ec["expected_valid"]

    return {
        "suite": "wire-jcs-and-hashes",
        "version": VERSION,
        "description": "Restricted RFC 8785 JCS positive/negative vectors (incl. depth 16/17/1000 & leading-zero), 3 hashes, clause_commit, BIP-340 SignatureSet, strict cofactorless Ed25519 + low-S NIST P-256 device-key signature checks, and atomic Linux fsverity-sha256 / RFC 9162 / SMT256 golden vectors.",
        "jcs_positive": positive_jcs,
        "jcs_negative": negative_jcs,
        "clause_commitment": {
            "rule": "SL-WIRE-014",
            "salt_hex": salt,
            "clause_obj": clause_obj,
            "clause_jcs_hex": sl.jcs_encode(clause_obj).hex(),
            "commitment_hex": clause_digest,
        },
        "three_hashes_and_signatureset": {
            "rule": "SL-WIRE-011",
            "envelope_2of3_subset_ab": envelope_record(env_2of3_a, "schemas/grant.schema.json"),
            "envelope_2of3_subset_ac": envelope_record(env_2of3_b, "schemas/grant.schema.json"),
            "invariance_note": "Both 2-of-3 subsets share identical object_id and signing_digest, while content_addr differs.",
            "negative_signaturesets": [
                {"id": "sigset-5-of-2", "object": bad_5of2, "expected_refusal": "WIRE_SIGNATURE"},
                {"id": "sigset-duplicate-pk", "object": bad_dup_sig, "expected_refusal": "WIRE_SIGNATURE"},
                {"id": "sigset-unsorted-sigs", "object": bad_unsorted_sigs, "expected_refusal": "WIRE_SIGNATURE"},
                {"id": "sigset-explicit-bip340-alg", "object": bad_explicit_bip340, "expected_refusal": "WIRE_MEMBER"},
                {"id": "sigset-tampered-sig", "object": bad_flipped, "expected_refusal": "WIRE_SIGNATURE"},
                {"id": "sigset-p256-high-s", "object": env_cmd_p256_high_s, "expected_refusal": "WIRE_SIGNATURE"},
                {"id": "sigset-ed25519-small-order-pk", "object": bad_ed_small_order, "expected_refusal": "WIRE_KEY"},
                {"id": "sigset-ed25519-forbidden-on-grant", "object": bad_ed_on_grant, "expected_refusal": "WIRE_MEMBER"},
                {"id": "sigset-p256-forbidden-on-grant", "object": bad_p256_on_grant, "expected_refusal": "WIRE_MEMBER"},
            ],
        },
        "device_signature_algorithms": {
            "rule": "SL-WIRE-012",
            "owner_command_ed25519": envelope_record(env_cmd_ed25519, "schemas/invocation.schema.json#/$defs/OwnerCommand"),
            "owner_command_p256_low_s": envelope_record(env_cmd_p256, "schemas/invocation.schema.json#/$defs/OwnerCommand"),
        },
        "ed25519_speccheck": ed_speccheck,
        "journal_commit_vectors": {
            "journal_id": g_jid,
            "c0": g_c0,
            "steps": [
                {"id": "step-1-closure", "entry": g_je1, "c_after": g_c1},
                {"id": "step-2-nonce", "entry": g_je2, "c_after": g_c2},
            ],
        },
        "artifact_and_log_primitives": {
            "rules": ["SL-ARTF-002", "SL-CONT-012"],
            "fsverity_sha256_linux": [
                {"id": "fsverity-empty", "data_hex": "", "data_len": 0, "digest": fsv_empty},
                {"id": "fsverity-13b", "data_hex": fsv_small_data.hex(), "data_len": len(fsv_small_data), "digest": fsv_small},
                {"id": "fsverity-4196b-2blocks", "pattern": "4096*0x41 || 100*0x42", "data_len": len(fsv_multi_data), "digest": fsv_multi},
                {"id": "fsverity-524289b-3levels", "data_pattern": {"byte": 0x5A, "length": 524289}, "data_len": 524289, "digest": fsv_3level_digest},
            ],
            "artifact_target_ids": [
                {"id": "target-id-sha256", "artifact_identity": art_sha, "target_id": sl.artifact_target_id(art_sha)},
                {"id": "target-id-fsverity-empty", "artifact_identity": art_fsv, "target_id": sl.artifact_target_id(art_fsv)},
            ],
            "log_id_golden": {
                "network": "main",
                "genesis": GENESIS_MAIN,
                "role": "notary",
                "name": "id/notary-golden",
                "registration": g_log_reg,
                "genesis_seal_outpoint": g_log_gen,
                "log_id": g_log_id,
            },
            "log_id_with_predecessor": {
                "network": "main",
                "genesis": GENESIS_MAIN,
                "role": "notary",
                "name": "id/notary-golden",
                "registration": g_log_reg,
                "genesis_seal_outpoint": g_log_gen_next,
                "predecessor_log_id": g_log_id,
                "log_id": g_log_id_ho,
            },
            "log_entry_digests": {
                "input_content_addr": h32("golden-entry"),
                "entry_0x01": sl.log_entry_digest(0x01, h32("golden-entry")),
                "entry_0x02": sl.log_entry_digest(0x02, h32("golden-entry")),
                "entry_0x03": sl.log_entry_digest(0x03, h32("golden-entry")),
            },
            "rfc9162_checkpoints_tree": {
                "empty_root": sl.EMPTY_CHECKPOINTS_ROOT,
                "checkpoint_content_addrs": [h32(f"golden-cp-{i + 1}") for i in range(5)],
                "mth_3": g_mth_3,
                "peaks_3": g_peaks_3,
                "mth_4": g_mth_4,
                "mth_5": g_mth_5,
                "inclusion_idx2_in_5": g_inc_2_in_5,
            },
            "smt256_fixed_depth": {
                "D0": sl.SMT_DEFAULTS[0].hex(),
                "D1": sl.SMT_DEFAULTS[1].hex(),
                "D256_empty_root": sl.SMT_EMPTY_ROOT,
                "kv": g_smt_kv,
                "root": g_smt_root,
                "inclusion_proof": g_smt_inc,
                "absence_proof": g_smt_abs,
            },
            "smt256_multi_leaf": {
                "kv": g_smt4_kv,
                "root": g_smt4_root,
                "proofs": g_smt4_proofs,
            },
        },
    }


def build_ledger_vectors() -> dict[str, Any]:
    ka = make_keypair("ledger-a")
    kb = make_keypair("ledger-b")
    kc = make_keypair("ledger-c")
    kd = make_keypair("ledger-d")
    ke = make_keypair("ledger-e")
    arb = make_keypair("ledger-arbiter")
    arb2 = make_keypair("ledger-arbiter-2")
    arb3 = make_keypair("ledger-arbiter-3")
    chal = make_keypair("ledger-challenger")
    chal2 = make_keypair("ledger-challenger-2")

    disp_2of3 = {"m": 2, "pks": sorted([ka["compressed_pk"], kc["compressed_pk"], kd["compressed_pk"]])}
    arb_2of3 = {"m": 2, "pks": sorted([arb["compressed_pk"], arb2["compressed_pk"], arb3["compressed_pk"]])}
    chal_1of2 = {"m": 1, "pks": sorted([chal["compressed_pk"], chal2["compressed_pk"]])}

    policies = [
        {"id": "p2wpkh-key", "policy": {"kind": "key", "pk": ka["compressed_pk"]}},
        {"id": "p2wsh-multisig-2of3", "policy": {"kind": "multisig", "m": 2, "pks": sorted([ka["compressed_pk"], kb["compressed_pk"], kc["compressed_pk"]])}},
        {"id": "p2wsh-either-of-2", "policy": {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(ka["compressed_pk"], kb["compressed_pk"])}},
        {"id": "p2wsh-both-of-2", "policy": {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(ka["compressed_pk"], kb["compressed_pk"])}},
        {"id": "p2wsh-arbiter-or-both", "policy": {"kind": "branch", "template": "arbiter_or_both", "keys": {**sl.canonical_branch_pair(ka["compressed_pk"], kb["compressed_pk"]), "arbiter": arb["compressed_pk"]}}},
        {"id": "p2wsh-single-use", "policy": {"kind": "branch", "template": "single_use_1_of_2", "keys": {"issuer": ka["compressed_pk"], "grantee": kb["compressed_pk"]}}},
        {"id": "p2wsh-guardian-pending", "policy": {"kind": "branch", "template": "guardian_slot_pending", "keys": {"disposer": ka["compressed_pk"], "challenger": chal["compressed_pk"], "guardian": kb["compressed_pk"]}, "delay_blocks": 144}},
        {"id": "p2wsh-either-of-2-branch-mofn", "policy": {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(kb["compressed_pk"], disp_2of3)}},
        {"id": "p2wsh-both-of-2-branch-mofn", "policy": {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp_2of3, arb_2of3)}},
        {"id": "p2wsh-arbiter-or-both-branch-mofn", "policy": {"kind": "branch", "template": "arbiter_or_both", "keys": {**sl.canonical_branch_pair(kb["compressed_pk"], ke["compressed_pk"]), "arbiter": arb_2of3}}},
        {"id": "p2wsh-guardian-pending-branch-mofn", "policy": {"kind": "branch", "template": "guardian_slot_pending", "keys": {"disposer": disp_2of3, "challenger": chal_1of2, "guardian": kb["compressed_pk"]}, "delay_blocks": 144}},
    ]
    compiled_policies = []
    for item in policies:
        spk, ws = sl.compile_script_policy(item["policy"])
        compiled_policies.append({
            "id": item["id"],
            "policy": item["policy"],
            "script_pubkey_hex": spk.hex(),
            "script_pubkey_bytes": len(spk),
            "witness_script_hex": ws.hex() if ws else "",
        })

    spk_p2wpkh, _ = sl.compile_script_policy(policies[0]["policy"])
    spk_2of2, _ = sl.compile_script_policy(policies[3]["policy"])
    name_bytes = b"id/alice"
    rand_bytes = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")
    val_bytes = sl.jcs_encode({"link": {"grant": ka["xonly_pk"]}, "m": {"h": h32("alice-manifest"), "s": 1}})
    new_hash20 = sl.hash160(rand_bytes + name_bytes)

    s_new = sl.encode_name_output("NAME_NEW", spk_p2wpkh, hash20=new_hash20)
    s_first = sl.encode_name_output("NAME_FIRSTUPDATE", spk_2of2, name=name_bytes, rand=rand_bytes, value=val_bytes)
    s_upd = sl.encode_name_output("NAME_UPDATE", spk_2of2, name=name_bytes, value=val_bytes)
    s_upd_empty = sl.encode_name_output("NAME_UPDATE", spk_p2wpkh, name=name_bytes, value=b"")

    bad_first = bytes([sl.OP_NAME_FIRSTUPDATE]) + sl._push_data(name_bytes) + sl._push_data(rand_bytes) + sl._push_data(val_bytes) + bytes([sl.OP_2DROP, sl.OP_DROP]) + spk_2of2
    legacy_p2pkh = bytes.fromhex("76a914" + "11" * 20 + "88ac")
    bad_legacy = sl.encode_name_output("NAME_UPDATE", legacy_p2pkh, name=name_bytes, value=val_bytes)

    batch_items = [h32(f"batch-item-{i}") for i in range(5)]
    root_hex, proofs = sl.build_merkle_tree(batch_items)
    for pf in proofs.values():
        assert sl.verify_merkle_proof(pf)

    first_leaf = sorted(batch_items, key=bytes.fromhex)[0]
    tampered_pf = copy.deepcopy(proofs[first_leaf])
    tampered_pf["steps"][0]["hash"] = h32("tampered-sibling")
    assert not sl.verify_merkle_proof(tampered_pf)

    opreturn_frames = []
    for act, label, loc, ptr, hc in [
        (0x01, "GRANT_ISSUANCE_private", 0x00, None, None),
        (0x01, "GRANT_ISSUANCE_blossom", 0x01, h32("blossom-ptr"), None),
        (0x02, "BATCH_ANCHOR_merkle5", 0x00, None, None),
        (0x04, "NOTARY_ACT", 0x00, None, None),
        (0x04, "NOTARY_ACT_blossom", 0x01, h32("blossom-notary-ptr"), None),
        (0x07, "CONTRACT_ANCHOR", 0x00, None, None),
        (0x09, "ORIGIN_OR_CRED_ANCHOR", 0x00, None, None),
        (0x0B, "KEY_COMPROMISE_BREAK", 0x00, None, 750050),
        (0x0C, "NAME_BINDING", 0x00, None, None),
        (0x0D, "GUARDIAN_APPOINTMENT", 0x00, None, None),
        (0x0E, "GUARDIAN_ACTIVATION", 0x00, None, None),
        (0x0F, "GUARDIAN_ROSTER_TRANSITION", 0x00, None, None),
        (0x10, "RECOVERY_CANCEL", 0x00, None, None),
        (0x11, "SINGLE_USE_CONSUMPTION", 0x00, None, None),
        (0x12, "GUARDIAN_INITIAL_ACTIVATION", 0x00, None, None),
        (0x13, "VOLUNTARY_REBIND", 0x00, None, None),
        (0x14, "LOG_CHECKPOINT", 0x00, None, None),
    ]:
        comm = root_hex if act == 0x02 else h32(f"comm-{label}")
        scr = sl.encode_opreturn(act, comm, loc_type=loc, pointer_hex=ptr, h_c=hc)
        dec = sl.decode_opreturn(scr)
        opreturn_frames.append({
            "id": label,
            "action": f"0x{act:02x}",
            "script_hex": scr.hex(),
            "script_bytes": len(scr),
            "decoded": dec,
        })

    reserved_06_hex = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x06, 0x22, 0x01]) + bytes.fromhex(h32("bad06")) + bytes([0x00])).hex()
    # R12-L2: Real properly-framed forbidden locator 0x01 on 0x10 (RECOVERY_CANCEL allows only loc_type 0x00!)
    bad_loc_10_hex = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x10, 0x42, 0x01]) + bytes.fromhex(h32("bad10c")) + bytes([0x01]) + bytes.fromhex(h32("bad10p"))).hex()
    valid_14_raw = sl.encode_opreturn(0x14, h32("nonmin-14"))
    nonminimal_pushdata1_hex = (valid_14_raw[:7] + bytes([0x4C, len(valid_14_raw) - 8]) + valid_14_raw[8:]).hex()
    bad_op5_push_hex = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x15, 0x55])).hex()  # OP_5 instead of direct length prefix 0x01 0x05
    bad_84b_overlimit_hex = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x20, 0x4C, 75]) + (b"\xaa" * 75)).hex()  # 84 bytes > 83B max
    bad_0x30_unallocated_hex = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x30, 0x01, 0x01])).hex()

    opreturn_criticality = []
    for act_c, scope_lbl, payload_c in [
        (0x15, "forward_only", bytes([0x01]) + bytes.fromhex(h32("crit-15")) + bytes([0x00])),
        (0x1A, "forward_only", bytes([0x05])),  # 1-byte payload (8-byte total script, direct length prefix 0x01 0x05!)
        (0x1B, "retroactive", bytes([0x01]) + bytes.fromhex(h32("crit-1b")) + bytes([0x00])),
        (0x1C, "retroactive", b"\xaa" * 74),  # exact 83-byte max OP_RETURN script (6a 05 SLNK 1c 4a <74B>)!
        (0x1F, "retroactive", bytes([0x01]) + bytes.fromhex(h32("crit-1f")) + bytes([0x00])),
        (0x20, "advisory", bytes([0x01]) + bytes.fromhex(h32("crit-20")) + bytes([0x00])),
        (0x2F, "advisory", bytes([0x01]) + bytes.fromhex(h32("crit-2f")) + bytes([0x00])),
    ]:
        scr_c = bytes([0x6A, 0x05]) + b"SLNK" + bytes([act_c, len(payload_c)]) + payload_c
        dec_c = sl.decode_opreturn_with_criticality(scr_c)
        if scope_lbl == "advisory":
            assert dec_c.get("advisory") is True
        else:
            assert dec_c.get("critical_scope") == scope_lbl
        opreturn_criticality.append({"id": f"future-0x{act_c:02x}-{scope_lbl}", "script_hex": scr_c.hex(), "decoded": dec_c})

    # Real Namecoin Core nc28.0 mainnet archival retarget tuples (verifying post-AuxPoW H - 2017 ancestor!)
    retarget_vectors = []
    for h_rt, prev_b, anc_h, anc_t, prev_t, exp_b in [
        (24192, 0x1B00B269, 22175, 1318761208, 1319487998, 0x1A6B32B1),
        (30240, 0x1A385BFC, 28223, 1321247518, 1322148153, 0x1A29F6AE),
        (733824, 0x1705D999, 731807, 1723460218, 1724608760, 0x17058E00),
    ]:
        assert sl.namecoin_retarget_ancestor_height(h_rt, network="main") == anc_h
        got_b = sl.compute_namecoin_next_bits(prev_b, anc_t, prev_t, network="main")
        assert got_b == exp_b, f"retarget {h_rt}: {got_b:#x} != {exp_b:#x}"
        retarget_vectors.append({
            "height": h_rt,
            "ancestor_height": anc_h,
            "prev_bits_hex": f"{prev_b:08x}",
            "epoch_start_time": anc_t,
            "prev_block_time": prev_t,
            "expected_next_bits_hex": f"{exp_b:08x}",
        })

    return {
        "suite": "ledger-scripts-and-opreturn",
        "version": VERSION,
        "description": "Namecoin prefix scripts (NAME_NEW/NAME_FIRSTUPDATE/NAME_UPDATE incl. OP_0 empty value), ScriptPolicy compilations (incl. BranchKeySpec native P2WSH m-of-n), TRUC/P2A CPFP, SLNK OP_RETURN frames (0x01-0x14 + 0x15..0x2f criticality + minimal push), 5-leaf Merkle batch 0x02 proofs, and real Namecoin mainnet archival retarget tuples (H - 2017).",
        "script_policies": compiled_policies,
        "namecoin_prefix_scripts": {
            "positive": [
                {"id": "nc-name-new-p2wpkh", "script_hex": s_new.hex(), "parsed": sl.parse_name_output(s_new)},
                {"id": "nc-name-firstupdate-p2wsh", "script_hex": s_first.hex(), "parsed": sl.parse_name_output(s_first)},
                {"id": "nc-name-update-p2wsh", "script_hex": s_upd.hex(), "parsed": sl.parse_name_output(s_upd)},
                {"id": "nc-name-update-op0-empty-value", "script_hex": s_upd_empty.hex(), "parsed": sl.parse_name_output(s_upd_empty)},
            ],
            "negative": [
                {"id": "nc-bad-firstupdate-cleanup", "script_hex": bad_first.hex(), "expected_refusal": "CHAIN_SCRIPT_UNSUPPORTED"},
                {"id": "nc-legacy-p2pkh-tail", "script_hex": bad_legacy.hex(), "expected_refusal": "CHAIN_SCRIPT_UNSUPPORTED"},
            ],
        },
        "cpfp_anchor": {
            "rule": "SL-LDGR-013",
            "truc_version": 3,
            "p2a_script_pubkey_hex": sl.P2A_SCRIPTPUBKEY.hex(),
            "p2a_bytes": len(sl.P2A_SCRIPTPUBKEY),
            "p2a_dust_floor_base_units": 240,
            "nc28_minrelaytxfee_base_units_per_kvb": 100000,
            "forbidden_bare_op_true_hex": "51",
            "regtest_evidence_dir": "conformance/p2a-regtest",
        },
        "opreturn_frames": opreturn_frames,
        "opreturn_criticality": opreturn_criticality,
        "opreturn_negative": [
            {"id": "reserved-action-0x06", "script_hex": reserved_06_hex, "expected_refusal": "CHAIN_FRAME_INVALID"},
            {"id": "forbidden-locator-0x01-on-0x10", "script_hex": bad_loc_10_hex, "expected_refusal": "CHAIN_FRAME_INVALID"},
            {"id": "non-minimal-op-pushdata1", "script_hex": nonminimal_pushdata1_hex, "expected_refusal": "CHAIN_FRAME_INVALID"},
            {"id": "op5-instead-of-direct-len-prefix", "script_hex": bad_op5_push_hex, "expected_refusal": "CHAIN_FRAME_INVALID"},
            {"id": "over-83-bytes-opreturn", "script_hex": bad_84b_overlimit_hex, "expected_refusal": "CHAIN_FRAME_INVALID"},
            {"id": "unallocated-action-0x30", "script_hex": bad_0x30_unallocated_hex, "expected_refusal": "CHAIN_FRAME_INVALID"},
        ],
        "merkle_batch_0x02": {
            "rule": "SL-LDGR-014",
            "unsorted_input_digests": batch_items,
            "sorted_digests": sorted(batch_items, key=bytes.fromhex),
            "merkle_root": root_hex,
            "opreturn_hex": sl.encode_opreturn(0x02, root_hex, 0x00).hex(),
            "proofs": [proofs[d] for d in sorted(batch_items, key=bytes.fromhex)],
            "negative_tampered_proof": tampered_pf,
        },
        "namecoin_consensus_retargets": {
            "rule": "SL-ARTF-006",
            "mainnet_archival": retarget_vectors,
        },
    }


def build_constraints_vectors() -> dict[str, Any]:
    pred_match_cases = [
        {"id": "eq-str-ok", "pred": {"eq": "Invoices"}, "arg": "Invoices", "expected": True},
        {"id": "eq-str-fail", "pred": {"eq": "Invoices"}, "arg": "Personal", "expected": False},
        {"id": "in-ok", "pred": {"in": ["Archive", "Invoices"]}, "arg": "Invoices", "expected": True},
        {"id": "in-fail", "pred": {"in": ["Archive", "Invoices"]}, "arg": "Inbox", "expected": False},
        {"id": "not-in-ok", "pred": {"not_in": ["Private", "Trash"]}, "arg": "Invoices", "expected": True},
        {"id": "not-in-fail", "pred": {"not_in": ["Private", "Trash"]}, "arg": "Private", "expected": False},
        {"id": "prefix-ok", "pred": {"prefix": "Work/"}, "arg": "Work/2026", "expected": True},
        {"id": "prefix-fail", "pred": {"prefix": "Work/"}, "arg": "Home/2026", "expected": False},
        {"id": "suffix-ok", "pred": {"suffix": "@relux.works"}, "arg": "ivan@relux.works", "expected": True},
        {"id": "suffix-fail", "pred": {"suffix": "@relux.works"}, "arg": "ivan@evil.example", "expected": False},
        {"id": "range-ok", "pred": {"range": ["100", "5000"]}, "arg": "5000", "expected": True},
        {"id": "range-fail", "pred": {"range": ["100", "5000"]}, "arg": "5001", "expected": False},
        {"id": "hash-eq-ok", "pred": {"hash_eq": h32("doc1")}, "arg": h32("doc1"), "expected": True},
        {"id": "hash-eq-fail", "pred": {"hash_eq": h32("doc1")}, "arg": h32("doc2"), "expected": False},
    ]
    for c in pred_match_cases:
        assert sl.match_predicate(c["pred"], c["arg"]) is c["expected"], c["id"]

    narrowing_cases = [
        {"id": "in-to-eq-ok", "parent": {"in": ["Archive", "Invoices"]}, "child": {"eq": "Invoices"}, "expected": True},
        {"id": "eq-to-singleton-in-conservative-fail", "parent": {"eq": "Invoices"}, "child": {"in": ["Invoices"]}, "expected": False, "note": "Conservative pairwise rule (SPEC-01 §6.2)."},
        {"id": "not-in-to-superset-ok", "parent": {"not_in": ["Private"]}, "child": {"not_in": ["Private", "Trash"]}, "expected": True},
        {"id": "not-in-to-disjoint-in-ok", "parent": {"not_in": ["Private"]}, "child": {"in": ["Archive", "Invoices"]}, "expected": True},
        {"id": "not-in-to-overlapping-in-fail", "parent": {"not_in": ["Private"]}, "child": {"in": ["Invoices", "Private"]}, "expected": False},
        {"id": "prefix-narrow-ok", "parent": {"prefix": "Work/"}, "child": {"prefix": "Work/2026/"}, "expected": True},
        {"id": "prefix-widen-fail", "parent": {"prefix": "Work/2026/"}, "child": {"prefix": "Work/"}, "expected": False},
        {"id": "suffix-narrow-ok", "parent": {"suffix": ".relux.works"}, "child": {"eq": "mail.relux.works"}, "expected": True},
        {"id": "range-narrow-ok", "parent": {"range": ["0", "10000"]}, "child": {"range": ["100", "5000"]}, "expected": True},
        {"id": "range-widen-fail", "parent": {"range": ["100", "5000"]}, "child": {"range": ["50", "5000"]}, "expected": False},
        {"id": "hash-eq-same-ok", "parent": {"hash_eq": h32("cfg")}, "child": {"hash_eq": h32("cfg")}, "expected": True},
        {"id": "hash-eq-diff-fail", "parent": {"hash_eq": h32("cfg")}, "child": {"hash_eq": h32("cfg2")}, "expected": False},
    ]
    for c in narrowing_cases:
        assert sl.narrows_predicate(c["child"], c["parent"]) is c["expected"], c["id"]

    k_owner = make_keypair("neg-owner")
    k_grant = make_keypair("neg-grant")
    k_rcpt = make_keypair("neg-rcpt")
    k_exec = make_keypair("neg-exec")
    k_seal = make_keypair("neg-seal")

    base_grant_payload = {
        "capabilities": [{"action": "mail/read", "target": "mailbox:id/alice:work"}],
        "executor": {"key": k_exec["xonly_pk"], "name": "id/mail-host-a"},
        "genesis": GENESIS_MAIN,
        "issuer": make_role_pin("id/alice", "neg-reg", k_owner, [k_grant["xonly_pk"]]),
        "network": "main",
        "not_after_height": 750010,
        "not_before_height": 750000,
        "recent_block": h32("neg-rb"),
        "recipient": {"key": k_rcpt["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "revocable",
            "mode": "seal",
            "seal": {"script_policy": {"kind": "key", "pk": k_seal["compressed_pk"]}, "txid": h32("neg-seal-tx"), "vout": 0},
        },
        "type": "seallink-grant/1",
    }

    g_no_issuer = copy.deepcopy(base_grant_payload)
    del g_no_issuer["issuer"]
    g_both_issuer_parent = copy.deepcopy(base_grant_payload)
    g_both_issuer_parent["parent"] = {"grant_id": h32("p1"), "ordinal": 1}
    g_ref_with_quota = copy.deepcopy(base_grant_payload)
    del g_ref_with_quota["executor"]
    g_ref_with_quota["executor_ref"] = {"label": "work", "provider_of": "id/alice", "service_type": "mail"}
    g_ref_with_quota["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "requests", "window": "term"}]
    g_with_ext = copy.deepcopy(base_grant_payload)
    g_with_ext["capabilities"][0]["extensions"] = {"future": True}
    g_window_too_long = copy.deepcopy(base_grant_payload)
    g_window_too_long["revocation"] = {"mode": "window_only"}
    g_window_too_long["not_after_height"] = 1750000
    g_unsorted_in = copy.deepcopy(base_grant_payload)
    g_unsorted_in["capabilities"][0]["where"] = {"folder": {"in": ["Zeta", "Alpha"]}}
    g_mech_text = copy.deepcopy(base_grant_payload)
    g_mech_text["terms_text"] = "Only read polite invoices."

    def wrap(p: dict[str, Any]) -> dict[str, Any]:
        return sl.sign_envelope(p, [k_grant["_sk"]])

    # SL-ORIG-016 negative guardianship consistency fixtures (executed via seallink_verifier!)
    disp = make_keypair("neg-g-disp")
    arb = make_keypair("neg-g-arb")
    chal = make_keypair("neg-g-chal")
    base_gp = {
        "appointment_delay_blocks": 144,
        "arbiter_pk": arb["compressed_pk"],
        "challenger_pk": chal["compressed_pk"],
        "disposer_pk": disp["compressed_pk"],
        "quorums": {
            "contract_assent": {"den": 2, "min": 2, "num": 2},
            "custody_change": {"den": 2, "min": 2, "num": 2},
            "effect_grant": {"den": 2, "min": 1, "num": 1},
            "routine_read": {"den": 2, "min": 1, "num": 1},
        },
        "revision": 1,
        "revision_size": 2,
        "roster_seal": {
            "script_policy": {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["compressed_pk"], arb["compressed_pk"])},
            "txid": h32("neg-roster-seal"),
            "vout": 0,
        },
        "slots": [
            {"initial_guardian_commitment": h32("ig1"), "slot": 1, "vacant_utxo": {"txid": h32("nv1"), "vout": 0}},
            {"initial_guardian_commitment": h32("ig2"), "slot": 2, "vacant_utxo": {"txid": h32("nv2"), "vout": 0}},
        ],
    }
    assert sl.check_guardian_policy_consistency(base_gp) == (True, "OK")

    gp_num_gt_den = copy.deepcopy(base_gp)
    gp_num_gt_den["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 3}
    gp_min_gt_size = copy.deepcopy(base_gp)
    gp_min_gt_size["quorums"]["contract_assent"] = {"den": 2, "min": 3, "num": 2}
    gp_dup_slot = copy.deepcopy(base_gp)
    gp_dup_slot["slots"][1]["slot"] = 1
    gp_missing_slot = copy.deepcopy(base_gp)
    gp_missing_slot["slots"] = gp_missing_slot["slots"][:1]
    gp_same_disp_arb = copy.deepcopy(base_gp)
    gp_same_disp_arb["arbiter_pk"] = disp["compressed_pk"]
    gp_non_monotonic_q = copy.deepcopy(base_gp)
    gp_non_monotonic_q["quorums"]["routine_read"] = {"den": 1, "min": 2, "num": 1}
    gp_non_monotonic_q["quorums"]["effect_grant"] = {"den": 2, "min": 1, "num": 1}
    gp_dup_vacant = copy.deepcopy(base_gp)
    gp_dup_vacant["slots"][1]["vacant_utxo"] = copy.deepcopy(gp_dup_vacant["slots"][0]["vacant_utxo"])

    new_disp = make_keypair("neg-g-disp-rotated")
    new_both_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(new_disp["compressed_pk"], arb["compressed_pk"])}
    roster_rot_bad = {
        "arbiter_pk": arb["compressed_pk"],
        "challenger_pk": chal["compressed_pk"],
        "disposer_pk": new_disp["compressed_pk"],
        "next_roster_policy": new_both_pol,
        "quorums": base_gp["quorums"],
        "revision": 2,
        "revision_size": 2,
        "slots": [
            {"action": "retain_active", "active_outpoint": {"txid": h32("act1"), "vout": 0}, "guardian_id": h32("gid1"), "slot": 1},
            {"action": "new_vacant", "new_vacant_policy": new_both_pol, "new_vacant_vout": 1, "slot": 2},
        ],
    }
    assert sl.check_guardian_policy_consistency(roster_rot_bad, prev_roster=base_gp) == (False, "CHAIN_SCRIPT_UNSUPPORTED")

    guardian_consistency_negative = [
        {"id": "orig-quorum-num-gt-den", "rule": "SL-ORIG-016", "guardian_policy": gp_num_gt_den, "expected_refusal": "WIRE_INTEGER"},
        {"id": "orig-quorum-min-gt-revision-size", "rule": "SL-ORIG-016", "guardian_policy": gp_min_gt_size, "expected_refusal": "WIRE_INTEGER"},
        {"id": "orig-quorum-non-monotonic", "rule": "SL-ORIG-016", "guardian_policy": gp_non_monotonic_q, "expected_refusal": "WIRE_INTEGER"},
        {"id": "orig-duplicate-slot-number", "rule": "SL-ORIG-016", "guardian_policy": gp_dup_slot, "expected_refusal": "WIRE_INTEGER"},
        {"id": "orig-slots-length-mismatch", "rule": "SL-ORIG-016", "guardian_policy": gp_missing_slot, "expected_refusal": "WIRE_INTEGER"},
        {"id": "orig-disposer-equals-arbiter", "rule": "SL-ORIG-016", "guardian_policy": gp_same_disp_arb, "expected_refusal": "ORIGIN_UNVERIFIED"},
        {"id": "orig-duplicate-vacant-utxo", "rule": "SL-ORIG-016", "guardian_policy": gp_dup_vacant, "expected_refusal": "ORIGIN_UNVERIFIED"},
        {"id": "orig-disposer-rotation-forbids-retain-active", "rule": "SL-ORIG-015", "guardian_policy": roster_rot_bad, "prev_roster": base_gp, "expected_refusal": "CHAIN_SCRIPT_UNSUPPORTED"},
    ]
    for gc_case in guardian_consistency_negative:
        ok_gc, code_gc = sl.check_guardian_policy_consistency(gc_case["guardian_policy"], prev_roster=gc_case.get("prev_roster"))
        assert (not ok_gc) and code_gc == gc_case["expected_refusal"], f"{gc_case['id']}: got {(ok_gc, code_gc)}"

    return {
        "suite": "constraints-and-schemas",
        "version": VERSION,
        "description": "All 7 Constraint Algebra predicates (match + conservative narrowing), negative schema/semantic fixtures with deterministic x-seallink-refusal codes, and SL-ORIG-016 guardianship consistency fixtures.",
        "predicate_matches": pred_match_cases,
        "predicate_narrowing": narrowing_cases,
        "negative_schema_fixtures": [
            {"id": "grant-neither-issuer-nor-parent", "schema": "schemas/grant.schema.json", "object": wrap(g_no_issuer), "expected_refusal": "WIRE_MEMBER"},
            {"id": "grant-both-issuer-and-parent", "schema": "schemas/grant.schema.json", "object": wrap(g_both_issuer_parent), "expected_refusal": "WIRE_MEMBER"},
            {"id": "grant-executor-ref-with-quota", "schema": "schemas/grant.schema.json", "object": wrap(g_ref_with_quota), "expected_refusal": "WIRE_MEMBER"},
            {"id": "grant-populated-extensions", "schema": "schemas/grant.schema.json", "object": wrap(g_with_ext), "expected_refusal": "WIRE_CONSTRAINT"},
        ],
        "negative_semantic_fixtures": [
            {"id": "grant-window-only-exceeds-12-blocks", "schema": "schemas/grant.schema.json", "object": wrap(g_window_too_long), "expected_refusal": "WIRE_INTEGER"},
            {"id": "grant-unsorted-in-predicate", "schema": "schemas/grant.schema.json", "object": wrap(g_unsorted_in), "expected_refusal": "WIRE_CONSTRAINT"},
            {"id": "grant-terms-text-on-mechanical-mail", "schema": "schemas/grant.schema.json", "object": wrap(g_mech_text), "expected_refusal": "GRANT_TEXT_FORBIDDEN"},
        ],
        "negative_guardian_consistency_fixtures": guardian_consistency_negative,
    }


def build_trace_01_mail() -> dict[str, Any]:
    alice_owner = make_keypair("t1-alice-owner")
    alice_grant = make_keypair("t1-alice-grant")
    alice_seal = make_keypair("t1-alice-seal")
    host_owner = make_keypair("t1-host-owner")
    host_receipt = make_keypair("t1-host-receipt")
    agent_owner = make_keypair("t1-agent-owner")
    agent_req = make_keypair("t1-agent-req")

    alice_owner_pol = {"kind": "key", "pk": alice_owner["compressed_pk"]}
    host_owner_pol = {"kind": "key", "pk": host_owner["compressed_pk"]}
    agent_owner_pol = {"kind": "key", "pk": agent_owner["compressed_pk"]}
    seal_pol = {"kind": "key", "pk": alice_seal["compressed_pk"]}
    host_pin = make_name_pin("id/mail-host-a", "t1-host-reg", host_owner_pol)

    host_manifest = {
        "network": "main",
        "owner": "id/mail-host-a",
        "seq": 1,
        "service": {
            "actions": ["mail/list", "mail/read", "mail/send"],
            "endpoint": "https://mail-a.example/seallink/v1",
            "receipt_key": host_receipt["xonly_pk"],
            "service_type": "mail",
            "tls_spki_sha256": h32("t1-host-spki"),
        },
        "type": "seallink-manifest/1",
    }
    host_name_val = {"m": {"h": sl.content_addr(host_manifest), "s": 1}}

    alice_manifest = {
        "network": "main",
        "owner": "id/alice",
        "providers": [{"label": "work", "provider": host_pin, "service_type": "mail"}],
        "seq": 1,
        "type": "seallink-manifest/1",
    }
    alice_name_val = {
        "link": {"grant": alice_grant["xonly_pk"]},
        "m": {"h": sl.content_addr(alice_manifest), "s": 1},
    }
    agent_name_val = {"nostr": agent_req["xonly_pk"]}

    seal_txid = h32("t1-seal-tx")
    recent_blk = h32("t1-recent-block-749990")
    grant_payload = {
        "capabilities": [
            {
                "action": "mail/read",
                "target": "mailbox:id/alice:work",
                "where": {"folder": {"in": ["Invoices"]}},
            }
        ],
        "executor_ref": {"label": "work", "provider_of": "id/alice", "service_type": "mail"},
        "genesis": GENESIS_MAIN,
        "issuer": make_role_pin("id/alice", "t1-alice-reg", alice_owner, [alice_grant["xonly_pk"]]),
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 750000,
        "recent_block": recent_blk,
        "recipient": {
            "mode": "name",
            "name": "id/alice-acct-agent",
            "owner_policy": agent_owner_pol,
            "registration": {"txid": h32("t1-agent-reg"), "vout": 0},
        },
        "revocation": {
            "construction": "W",
            "kind": "revocable",
            "mode": "seal",
            "seal": {"script_policy": seal_pol, "txid": seal_txid, "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    grant_env = sl.sign_envelope(grant_payload, [alice_grant["_sk"]])
    grant_id = sl.object_id(grant_payload)
    issuance = {
        "genesis": GENESIS_MAIN,
        "grant_content_addr": sl.content_addr(grant_env),
        "grant_id": grant_id,
        "type": "seallink-issuance/1",
    }
    issuance_txid = h32("t1-issuance-tx")
    issuance_opreturn_hex = sl.encode_opreturn(0x01, sl.signing_digest(issuance).hex(), 0x00).hex()

    # Raw RFC 5322 bytes -> exact derived length (69 bytes!)
    mime_bytes = b"From: billing@vendor.example\r\nSubject: Invoice #1\r\n\r\nTotal: 100 EUR\r\n"
    assert len(mime_bytes) == 69

    inv_ok_payload = {
        "action": "mail/read",
        "arguments": {"folder": "Invoices", "message_id": "msg-2026-001"},
        "executor": {"key": host_receipt["xonly_pk"], "name": "id/mail-host-a"},
        "exp": 1795220300,
        "genesis": GENESIS_MAIN,
        "iat": 1795220000,
        "network": "main",
        "nonce": h32("t1-nonce-1"),
        "proof_path": [{"grant_id": grant_id, "issuance_txid": issuance_txid}],
        "target": "mailbox:id/alice:work",
        "type": "seallink-invocation/1",
    }
    inv_ok = sl.sign_envelope(inv_ok_payload, [agent_req["_sk"]])
    inv_ok_id = sl.object_id(inv_ok_payload)
    mail_result = {
        "folder": "Invoices",
        "message_id": "msg-2026-001",
        "mime_sha256": sl.sha256(mime_bytes).hex(),
        "received_at": 1795219000,
        "sender_domain": "vendor.example",
        "size_bytes": str(len(mime_bytes)),
    }
    rcpt_ok = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": "id/mail-host-a",
            "genesis": GENESIS_MAIN,
            "grant_id": grant_id,
            "invocation_id": inv_ok_id,
            "network": "main",
            "outcome": "executed",
            "recorded_at": 1795220010,
            "result_sha256": sl.content_addr(mail_result),
            "tip_hash": h32("t1-tip-750010"),
            "tip_height": 750010,
            "type": "seallink-receipt/1",
        },
        [host_receipt["_sk"]],
    )

    inv_bad_payload = {
        "action": "mail/read",
        "arguments": {"folder": "Personal", "message_id": "msg-2026-999"},
        "executor": {"key": host_receipt["xonly_pk"], "name": "id/mail-host-a"},
        "exp": 1795220400,
        "genesis": GENESIS_MAIN,
        "iat": 1795220100,
        "network": "main",
        "nonce": h32("t1-nonce-2"),
        "proof_path": [{"grant_id": grant_id, "issuance_txid": issuance_txid}],
        "target": "mailbox:id/alice:work",
        "type": "seallink-invocation/1",
    }
    inv_bad = sl.sign_envelope(inv_bad_payload, [agent_req["_sk"]])
    rcpt_bad = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": "id/mail-host-a",
            "genesis": GENESIS_MAIN,
            "grant_id": grant_id,
            "invocation_id": sl.object_id(inv_bad_payload),
            "network": "main",
            "outcome": "refused",
            "recorded_at": 1795220105,
            "refusal_code": "INVOKE_CONSTRAINT_FAILED",
            "tip_hash": h32("t1-tip-750010"),
            "tip_height": 750010,
            "type": "seallink-receipt/1",
        },
        [host_receipt["_sk"]],
    )

    revoke_txid = h32("t1-revoke-spend-tx")

    inv_after_payload = {
        "action": "mail/read",
        "arguments": {"folder": "Invoices", "message_id": "msg-2026-001"},
        "executor": {"key": host_receipt["xonly_pk"], "name": "id/mail-host-a"},
        "exp": 1795220900,
        "genesis": GENESIS_MAIN,
        "iat": 1795220600,
        "network": "main",
        "nonce": h32("t1-nonce-3"),
        "proof_path": [{"grant_id": grant_id, "issuance_txid": issuance_txid}],
        "target": "mailbox:id/alice:work",
        "type": "seallink-invocation/1",
    }
    inv_after = sl.sign_envelope(inv_after_payload, [agent_req["_sk"]])
    rcpt_after = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": "id/mail-host-a",
            "genesis": GENESIS_MAIN,
            "grant_id": grant_id,
            "invocation_id": sl.object_id(inv_after_payload),
            "network": "main",
            "outcome": "refused",
            "recorded_at": 1795220605,
            "refusal_code": "GRANT_CLOSED",
            "tip_hash": h32("t1-tip-750011"),
            "tip_height": 750011,
            "type": "seallink-receipt/1",
        },
        [host_receipt["_sk"]],
    )

    # Full declarative initial chain & journal state for live Tier1Verifier replay!
    jid = h32("t1-host-journal")
    initial_chain_state = {
        "network": "main",
        "genesis": GENESIS_MAIN,
        "tip_height": 750010,
        "tip_hash": h32("t1-tip-750010"),
        "tip_header_time": 1795220000,
        "tip_median_time_past": 1795219900,
        "tip_first_sight": 1795220005,
        "now": 1795220010,
        "clock_watermark": 1795219000,
        "best_header_height": 750010,
        "in_ibd": False,
        "txindex": True,
        "node_reachable": True,
        "observation_bracket": {
            "consistent": True,
            "start": {"height": 750010, "hash": h32("t1-tip-750010")},
            "end": {"height": 750010, "hash": h32("t1-tip-750010")},
        },
        "comparison_peers": [{"id": "observer-1", "healthy": True, "height": 750010, "hash_at_tip": h32("t1-tip-750010")}],
        "blocks": {recent_blk: 749990},
        "names": {
            "id/alice": sv.make_name_history(
                "id/alice", {"txid": h32("t1-alice-reg"), "vout": 0}, alice_owner_pol, alice_name_val, first_height=748000, update_height=749000
            ),
            "id/mail-host-a": sv.make_name_history(
                "id/mail-host-a", {"txid": h32("t1-host-reg"), "vout": 0}, host_owner_pol, host_name_val, first_height=748000, update_height=749000
            ),
            "id/alice-acct-agent": sv.make_name_history(
                "id/alice-acct-agent", {"txid": h32("t1-agent-reg"), "vout": 0}, agent_owner_pol, agent_name_val, first_height=748000, update_height=749000
            ),
        },
        "txs": {
            seal_txid: {
                "confirmed_height": 749995,
                "inputs": [sv.make_segwit_input(h32("t1-alice-fund"), 0)],
                "outputs": {"0": {"script_pubkey_hex": spk_hex(seal_pol)}, "1": {"script_pubkey_hex": spk_hex(alice_owner_pol)}},
            },
            issuance_txid: {
                "confirmed_height": 749998,
                "inputs": [sv.make_segwit_input(seal_txid, 1)],
                "opreturn_hex": issuance_opreturn_hex,
                "outputs": {},
            },
        },
        "manifests": {
            sl.content_addr(alice_manifest): alice_manifest,
            sl.content_addr(host_manifest): host_manifest,
        },
    }
    executor_config = {
        "name": "id/mail-host-a",
        "key": host_receipt["xonly_pk"],
        "pin": make_name_pin("id/mail-host-a", "t1-host-reg", host_owner_pol),
        "actions": ["mail/list", "mail/read", "mail/send"],
    }
    initial_journal_state = {"journal_id": jid}

    # Execute through Tier1Verifier to derive exact journal writes and assert every step!
    v = sv.Tier1Verifier()
    ch = sv.ChainView(initial_chain_state)
    jr = sv.FencedJournal.from_dict(initial_journal_state)
    bundle = {
        "grants": [grant_env],
        "manifests": {sl.content_addr(alice_manifest): alice_manifest, sl.content_addr(host_manifest): host_manifest},
    }

    r1 = v.verify_invocation(
        inv_ok,
        bundle,
        ch,
        jr,
        executor_config,
        receipt_env_for_cache=rcpt_ok,
        actual_message_meta={"folder": "Invoices", "sender_domain": "vendor.example", "size_bytes": str(len(mime_bytes))},
    )
    assert r1.verdict == "ADMIT" and len(r1.journal_writes) == 2, r1
    jw1 = r1.journal_writes[0]
    jw1_set = r1.journal_writes[1]

    step2_patch = {"now": 1795220105}
    ch.apply_patch(step2_patch)
    r2 = v.verify_invocation(inv_bad, bundle, ch, jr, executor_config)
    assert r2.verdict == "REFUSE" and r2.refusal_code == "INVOKE_CONSTRAINT_FAILED"

    step3_patch = {
        "tip_height": 750011,
        "tip_hash": h32("t1-tip-750011"),
        "best_header_height": 750011,
        "observation_bracket": {
            "consistent": True,
            "start": {"height": 750011, "hash": h32("t1-tip-750011")},
            "end": {"height": 750011, "hash": h32("t1-tip-750011")},
        },
        "tip_header_time": 1795220480,
        "tip_first_sight": 1795220490,
        "now": 1795220500,
        "comparison_peers": [{"id": "observer-1", "healthy": True, "height": 750011, "hash_at_tip": h32("t1-tip-750011")}],
        "txs": {seal_txid: {"outputs": {"0": {"script_pubkey_hex": spk_hex(seal_pol), "spent_by_txid": revoke_txid, "spend_in_mempool": True}}}},
    }
    ch.apply_patch(step3_patch)
    _, serr3, jw2 = v.evaluate_seal(grant_payload["revocation"]["seal"], ch, required_depth=1, journal=jr, subject_id=grant_id, subject_kind="grant")
    assert serr3 == "SEAL_SPENT" and jw2 is not None

    step4_patch = {"now": 1795220605}
    ch.apply_patch(step4_patch)
    r4 = v.verify_invocation(inv_after, bundle, ch, jr, executor_config)
    assert r4.verdict == "REFUSE" and r4.refusal_code == "GRANT_CLOSED"

    return {
        "suite": "trace-01-mail-offline-revoke",
        "version": VERSION,
        "description": "Executable RFC 8448-style trace: mail/read via executor_ref and named recipient while issuer offline, 69B MIME result, constraint refusal, mempool seal spend closure, and exact GRANT_CLOSED refusal.",
        "executor_config": executor_config,
        "initial_chain_state": initial_chain_state,
        "initial_journal_state": initial_journal_state,
        "ledger_state": {
            "network": "main",
            "genesis": GENESIS_MAIN,
            "alice_name_value": unsigned_record(alice_name_val, "schemas/name-value.schema.json"),
            "host_name_value": unsigned_record(host_name_val, "schemas/name-value.schema.json"),
            "agent_name_value": unsigned_record(agent_name_val, "schemas/name-value.schema.json"),
            "alice_manifest": unsigned_record(alice_manifest, "schemas/manifest.schema.json"),
            "host_manifest": unsigned_record(host_manifest, "schemas/manifest.schema.json"),
            "issuance_txid": issuance_txid,
            "issuance_opreturn_hex": issuance_opreturn_hex,
            "revoke_spend_txid": revoke_txid,
            "mime_bytes_hex": mime_bytes.hex(),
        },
        "grant": envelope_record(grant_env, "schemas/grant.schema.json"),
        "issuance": unsigned_record(issuance, "schemas/grant.schema.json#/$defs/IssuancePrep"),
        "steps": [
            {
                "step": 1,
                "name": "offline_issuer_admit_mail_read",
                "invocation": envelope_record(inv_ok, "schemas/invocation.schema.json#/$defs/Invocation"),
                "actual_message_meta": {"folder": "Invoices", "sender_domain": "vendor.example", "size_bytes": str(len(mime_bytes))},
                "profile_args_schema": "schemas/profile-mail.schema.json#/$defs/MailReadArgs",
                "result_object": unsigned_record(mail_result, "schemas/profile-mail.schema.json#/$defs/MailReadResult"),
                "expected_verdict": "ADMIT",
                "receipt": envelope_record(rcpt_ok, "schemas/invocation.schema.json#/$defs/Receipt"),
                "journal_write": {
                    "entry": unsigned_record(jw1["entry"], "schemas/invocation.schema.json#/$defs/JournalEntry"),
                    "c_before": jw1["c_before"],
                    "c_after": jw1["c_after"],
                },
                "settlement_journal_write": {
                    "entry": unsigned_record(jw1_set["entry"], "schemas/invocation.schema.json#/$defs/JournalEntry"),
                    "c_before": jw1_set["c_before"],
                    "c_after": jw1_set["c_after"],
                },
            },
            {
                "step": 2,
                "name": "forbidden_folder_refused_non_closing",
                "chain_patch": step2_patch,
                "invocation": envelope_record(inv_bad, "schemas/invocation.schema.json#/$defs/Invocation"),
                "profile_args_schema": "schemas/profile-mail.schema.json#/$defs/MailReadArgs",
                "expected_verdict": "REFUSE",
                "expected_refusal": "INVOKE_CONSTRAINT_FAILED",
                "receipt": envelope_record(rcpt_bad, "schemas/invocation.schema.json#/$defs/Receipt"),
            },
            {
                "step": 3,
                "name": "witnessed_mempool_seal_spend_closure",
                "chain_patch": step3_patch,
                "spend_txid": revoke_txid,
                "expected_seal_refusal": "SEAL_SPENT",
                "journal_write": {
                    "entry": unsigned_record(jw2["entry"], "schemas/invocation.schema.json#/$defs/JournalEntry"),
                    "c_before": jw2["c_before"],
                    "c_after": jw2["c_after"],
                },
            },
            {
                "step": 4,
                "name": "post_revocation_request_returns_exact_grant_closed",
                "chain_patch": step4_patch,
                "invocation": envelope_record(inv_after, "schemas/invocation.schema.json#/$defs/Invocation"),
                "profile_args_schema": "schemas/profile-mail.schema.json#/$defs/MailReadArgs",
                "expected_verdict": "REFUSE",
                "expected_refusal": "GRANT_CLOSED",
                "receipt": envelope_record(rcpt_after, "schemas/invocation.schema.json#/$defs/Receipt"),
            },
        ],
    }


def build_trace_02_guardian() -> dict[str, Any]:
    reg_owner = make_keypair("t2-registrar-owner")
    reg_cred = make_keypair("t2-registrar-cred")
    disposer = make_keypair("t2-disposer")
    arbiter = make_keypair("t2-arbiter")
    challenger = make_keypair("t2-challenger")
    ward_init = make_keypair("t2-ward-init")
    ward_grant = make_keypair("t2-ward-grant")
    bind_seal = make_keypair("t2-bind-seal")
    status_cap = make_keypair("t2-status-cap")
    status_end = make_keypair("t2-status-end")
    recov_disp = make_keypair("t2-recov-disp")
    recov_arb = make_keypair("t2-recov-arb")

    p_old_owner = make_keypair("t2-parent-old-owner")
    p_old_grant = make_keypair("t2-parent-old-grant")
    p_old_seal = make_keypair("t2-parent-old-seal")
    p2_owner = make_keypair("t2-parent2-owner")
    g_new_owner = make_keypair("t2-guardian-new-owner")
    g_new_grant = make_keypair("t2-guardian-new-grant")
    g_new_seal = make_keypair("t2-guardian-new-seal")
    counterparty_owner = make_keypair("t2-school-owner")
    counterparty_grant = make_keypair("t2-school-grant")
    contract_seal_a = make_keypair("t2-cseal-a")
    contract_seal_b = make_keypair("t2-cseal-b")

    ward_owner_policy = {
        "kind": "multisig",
        "m": 2,
        "pks": sorted([p_old_owner["compressed_pk"], p2_owner["compressed_pk"], reg_owner["compressed_pk"]]),
    }
    vacant_policy = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disposer["compressed_pk"], arbiter["compressed_pk"])}
    status_policy = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(status_cap["compressed_pk"], status_end["compressed_pk"])}
    recovery_policy = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(recov_disp["compressed_pk"], recov_arb["compressed_pk"])}

    p_old_pin = make_name_pin("id/parent-a", "t2-parent-a-reg", {"kind": "key", "pk": p_old_owner["compressed_pk"]})
    p2_pin = make_name_pin("id/parent-b", "t2-parent-b-reg", {"kind": "key", "pk": p2_owner["compressed_pk"]})
    g_new_pin = make_name_pin("id/guardian-carol", "t2-carol-reg", {"kind": "key", "pk": g_new_owner["compressed_pk"]})

    salt_maj = h32("t2-salt-majority")
    salt_g1 = h32("t2-salt-g1")
    salt_g2 = h32("t2-salt-g2")
    maj_unix = 2363241600  # 2044-11-22
    maj_obj = {"majority_unix": maj_unix}

    # Closed 4-class linear QuorumMap (SPEC-04 §3.1)
    quorums_v1 = {
        "contract_assent": {"den": 1, "min": 2, "num": 1},
        "custody_change": {"den": 1, "min": 2, "num": 1},
        "effect_grant": {"den": 2, "min": 1, "num": 1},
        "routine_read": {"den": 2, "min": 1, "num": 1},
    }

    origin_payload = {
        "binding_seal": {"script_policy": {"kind": "key", "pk": bind_seal["compressed_pk"]}, "txid": h32("t2-bind-seal-tx"), "vout": 0},
        "capacity_authority": make_name_pin("id/civil-registry", "t2-reg-outpoint", {"kind": "key", "pk": reg_owner["compressed_pk"]}),
        "claims": {
            "intended_name": "id/child-leo",
            "intended_owner_policy": ward_owner_policy,
            "majority_commitment": sl.clause_commit(salt_maj, maj_obj),
        },
        "genesis": GENESIS_MAIN,
        "guardian_policy": {
            "appointment_delay_blocks": 144,
            "arbiter_pk": arbiter["compressed_pk"],
            "challenger_pk": challenger["compressed_pk"],
            "disposer_pk": disposer["compressed_pk"],
            "quorums": quorums_v1,
            "revision": 1,
            "revision_size": 2,
            "roster_seal": {"script_policy": vacant_policy, "txid": h32("t2-roster-seal-tx"), "vout": 0},
            "slots": [
                {"initial_guardian_commitment": sl.clause_commit(salt_g1, p_old_pin), "slot": 1, "vacant_utxo": {"txid": h32("t2-slot1-vac0"), "vout": 0}},
                {"initial_guardian_commitment": sl.clause_commit(salt_g2, p2_pin), "slot": 2, "vacant_utxo": {"txid": h32("t2-slot2-vac0"), "vout": 0}},
            ],
        },
        "issuer": make_role_pin("id/civil-registry", "t2-reg-outpoint", reg_owner, [reg_cred["xonly_pk"]]),
        "name_recovery": {
            "arbiter_pk": recov_arb["compressed_pk"],
            "delay_blocks": 1008,
            "disposer_pk": recov_disp["compressed_pk"],
            "mode": "dual_party_delayed",
            "recovery_seal": {"script_policy": recovery_policy, "txid": h32("t2-recov-seal-tx"), "vout": 0},
        },
        "network": "main",
        "origin_class": "person",
        "request_sha256": h32("t2-birth-req"),
        "status_seal": {"script_policy": status_policy, "txid": h32("t2-status-seal-tx"), "vout": 0},
        "subject_initial_key": ward_init["xonly_pk"],
        "type": "seallink-origin/1",
    }
    origin_env = sl.sign_envelope(origin_payload, [reg_cred["_sk"]])
    origin_id = sl.object_id(origin_payload)
    origin_txid = h32("t2-origin-anchor-tx")
    origin_opreturn_hex = sl.encode_opreturn(0x09, sl.content_addr(origin_env), 0x00).hex()

    # NameBinding (0x0c)
    binding = {
        "binding_mode": "initial",
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo",
        "network": "main",
        "origin_id": origin_id,
        "owner_policy": ward_owner_policy,
        "registration": {"txid": h32("t2-leo-reg-tx"), "vout": 0},
        "seq": 1,
        "type": "seallink-name-binding/1",
    }
    binding_txid = h32("t2-binding-tx-0x0c")
    binding_opreturn_hex = sl.encode_opreturn(0x0C, sl.object_id(binding), 0x00).hex()

    # Stage 0: Initial slot activation (0x12, activation_mode = "initial") for parent-a in slot 1
    init_active_policy = {"keys": sl.canonical_branch_pair(disposer["compressed_pk"], p_old_seal["compressed_pk"]), "kind": "branch", "template": "either_of_2"}
    init_guardian_payload = {
        "active_policy": init_active_policy,
        "active_vout": 0,
        "activation_mode": "initial",
        "genesis": GENESIS_MAIN,
        "guardian": p_old_pin,
        "issuer": make_role_pin("id/civil-registry", "t2-reg-outpoint", reg_owner, [reg_cred["xonly_pk"]]),
        "network": "main",
        "origin_id": origin_id,
        "prev_outpoint": {"txid": h32("t2-slot1-vac0"), "vout": 0},
        "revision": 1,
        "slot": 1,
        "term": {"ceiling_height": 1750000, "mode": "calendar", "not_after_unix": maj_unix},
        "type": "seallink-guardian/1",
    }
    init_guardian_env = sl.sign_envelope(init_guardian_payload, [reg_cred["_sk"]])
    init_guardian_id = sl.object_id(init_guardian_payload)
    init_guardian_assent = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "network": "main",
            "nonce": h32("t2-parent-a-init-assent"),
            "party_id": "slot-1",
            "party_name": "id/parent-a",
            "party_role": "guardian",
            "target_id": init_guardian_id,
            "target_type": "seallink-guardian/1",
            "type": "seallink-assent/1",
        },
        [p_old_grant["_sk"]],
    )
    init_txid = h32("t2-init-activation-tx-0x12")
    init_opreturn_hex = sl.encode_opreturn(0x12, sl.content_addr(init_guardian_env), 0x00).hex()

    # Fast halt of parent-a -> vacant_after_halt
    halt_txid = h32("t2-slot1-vac-after-halt")
    vacant_after_halt = {"txid": halt_txid, "vout": 0}

    # Stage 1: Acyclic successor appointment (0x0d, activation_mode = "appointed") for Carol in slot 1
    pending_policy = {
        "delay_blocks": 144,
        "keys": {"challenger": challenger["compressed_pk"], "disposer": disposer["compressed_pk"], "guardian": g_new_seal["compressed_pk"]},
        "kind": "branch",
        "template": "guardian_slot_pending",
    }
    active_policy = {"keys": sl.canonical_branch_pair(disposer["compressed_pk"], g_new_seal["compressed_pk"]), "kind": "branch", "template": "either_of_2"}
    guardian_payload = {
        "active_policy": active_policy,
        "activation_mode": "appointed",
        "effective_delay_blocks": 144,
        "genesis": GENESIS_MAIN,
        "guardian": g_new_pin,
        "issuer": make_role_pin("id/civil-registry", "t2-reg-outpoint", reg_owner, [reg_cred["xonly_pk"]]),
        "network": "main",
        "origin_id": origin_id,
        "pending_policy": pending_policy,
        "pending_vout": 0,
        "prev_outpoint": vacant_after_halt,
        "revision": 1,
        "slot": 1,
        "term": {"ceiling_height": 1750000, "mode": "calendar", "not_after_unix": maj_unix},
        "type": "seallink-guardian/1",
    }
    guardian_env = sl.sign_envelope(guardian_payload, [reg_cred["_sk"]])
    guardian_id = sl.object_id(guardian_payload)
    guardian_assent = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "network": "main",
            "nonce": h32("t2-carol-assent-nonce"),
            "party_id": "slot-1",
            "party_name": "id/guardian-carol",
            "party_role": "guardian",
            "target_id": guardian_id,
            "target_type": "seallink-guardian/1",
            "type": "seallink-assent/1",
        },
        [g_new_grant["_sk"]],
    )
    app_txid = h32("t2-appointment-tx-0x0d")
    app_opreturn_hex = sl.encode_opreturn(0x0D, sl.content_addr(guardian_env), 0x00).hex()
    derived_pending_outpoint = {"txid": app_txid, "vout": 0}

    # Stage 2: Activation (0x0e) after 144 blocks -> active outpoint (T_act, 0)
    act_txid = h32("t2-activation-tx-0x0e")
    act_opreturn_hex = sl.encode_opreturn(0x0E, guardian_id, 0x00).hex()
    derived_active_outpoint = {"txid": act_txid, "vout": 0}

    # Roster revision 1 -> 2 (revision_size = 1, retaining slot 1 active Carol, authorized by disposer_pk + arbiter_pk)
    quorums_v2 = {
        "contract_assent": {"den": 1, "min": 1, "num": 1},
        "custody_change": {"den": 1, "min": 1, "num": 1},
        "effect_grant": {"den": 1, "min": 1, "num": 1},
        "routine_read": {"den": 1, "min": 1, "num": 1},
    }
    roster_payload = {
        "arbiter_pk": arbiter["compressed_pk"],
        "challenger_pk": challenger["compressed_pk"],
        "disposer_pk": disposer["compressed_pk"],
        "effective_delay_blocks": 144,
        "genesis": GENESIS_MAIN,
        "issuer": make_role_pin("id/civil-registry", "t2-reg-outpoint", reg_owner, [reg_cred["xonly_pk"]]),
        "network": "main",
        "next_roster_policy": vacant_policy,
        "next_roster_vout": 0,
        "origin_id": origin_id,
        "prev_revision": 1,
        "prev_roster_outpoint": {"txid": h32("t2-roster-seal-tx"), "vout": 0},
        "quorums": quorums_v2,
        "revision": 2,
        "revision_size": 1,
        "slots": [{"action": "retain_active", "active_outpoint": derived_active_outpoint, "guardian_id": guardian_id, "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    roster_env = sl.sign_envelope(roster_payload, [reg_cred["_sk"]])
    roster_txid = h32("t2-roster-tx-0x0f")
    roster_opreturn_hex = sl.encode_opreturn(0x0F, sl.content_addr(roster_env), 0x00).hex()

    # Contract with ward party bound by `ward_origin_id` (NOT static signing_policy!)
    clause0_salt = h32("t2-clause0-salt")
    clause0_obj = {
        "machine_terms": {
            "capabilities": [
                {"action": "mail/read", "target": "mailbox:id/child-leo:school", "where": {"folder": {"eq": "Enrollment"}}}
            ],
            "not_after_height": 790000,
            "not_before_height": 750500,
        },
        "text": "Music school enrollment\nTerm 2026-2027",
        "title": "Enrollment Terms",
    }
    clause1_salt = h32("t2-clause1-salt")
    clause1_obj = {"text": "Confidential allergy note (undisclosed to third parties)"}
    contract_obj = {
        "clause_commitments": [sl.clause_commit(clause0_salt, clause0_obj), sl.clause_commit(clause1_salt, clause1_obj)],
        "contract_salt": h32("t2-contract-salt"),
        "genesis": GENESIS_MAIN,
        "machine_clause_indices": [0],
        "network": "main",
        "parties": [
            {
                "name_pin": make_name_pin("id/child-leo", "t2-leo-reg-tx", ward_owner_policy),
                "party_id": "student-1",
                "role": "student_ward",
                "ward_origin_id": origin_id,
            },
            {
                "name_pin": make_name_pin("id/music-school", "t2-school-reg", {"kind": "key", "pk": counterparty_owner["compressed_pk"]}),
                "party_id": "school-1",
                "role": "school",
                "signing_policy": {"m": 1, "pks": [counterparty_grant["xonly_pk"]]},
            },
        ],
        "profile": "org.seallink/enrollment-v1",
        "seal": {
            "script_policy": {"keys": sl.canonical_branch_pair(contract_seal_a["compressed_pk"], contract_seal_b["compressed_pk"]), "kind": "branch", "template": "either_of_2"},
            "txid": h32("t2-contract-seal-tx"),
            "vout": 0,
        },
        "type": "seallink-contract/1",
        "window": {"not_after_height": 790000, "not_before_height": 750500},
    }
    contract_id = sl.object_id(contract_obj)

    # Verdict 1: Unrepresented ward signs assent alone -> WARD_AUTONOMOUS_FORBIDDEN
    assent_ward_alone = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "network": "main",
            "nonce": h32("t2-assent-ward-alone"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": contract_id,
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [ward_grant["_sk"]],
    )

    # Verdict 2: Former halted guardian parent-a signs via guardian_approvals[] -> GUARDIAN_INACTIVE
    assent_old_guardian = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": origin_id, "revision": 2, "ward_name": "id/child-leo"},
            "issued_at": 1795220000,
            "network": "main",
            "nonce": h32("t2-assent-old-g"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": contract_id,
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [{"slot": 1, "revision": 2, "guardian_name": "id/parent-a", "signers": [p_old_grant["_sk"]]}],
    )

    # Verdict 3: Active successor guardian Carol signs via guardian_approvals[] -> ADMIT
    assent_new_guardian = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": origin_id, "revision": 2, "ward_name": "id/child-leo"},
            "issued_at": 1795220000,
            "network": "main",
            "nonce": h32("t2-assent-new-g"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": contract_id,
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [{"slot": 1, "revision": 2, "guardian_name": "id/guardian-carol", "signers": [g_new_grant["_sk"]]}],
    )

    # Declarative chain state capturing the FULL derived UTXO & name update history (0x09 -> 0x0c -> 0x12 -> halt -> 0x0d -> 0x0e -> 0x0f)!
    chain_state = {
        "network": "main",
        "genesis": GENESIS_MAIN,
        "tip_height": 750600,
        "tip_hash": h32("t2-tip-750600"),
        "tip_header_time": 1795220000,
        "tip_median_time_past": 1795219900,
        "tip_first_sight": 1795220005,
        "now": 1795220010,
        "clock_watermark": 1795219000,
        "best_header_height": 750600,
        "in_ibd": False,
        "txindex": True,
        "node_reachable": True,
        "observation_bracket": {
            "consistent": True,
            "start": {"height": 750600, "hash": h32("t2-tip-750600")},
            "end": {"height": 750600, "hash": h32("t2-tip-750600")},
        },
        "credible_utc_interval": [1795220000, 1795220020],
        "comparison_peers": [{"id": "observer-1", "healthy": True, "height": 750600, "hash_at_tip": h32("t2-tip-750600")}],
        "blocks": {},
        "names": {
            "id/civil-registry": sv.make_name_history(
                "id/civil-registry", {"txid": h32("t2-reg-outpoint"), "vout": 0}, {"kind": "key", "pk": reg_owner["compressed_pk"]},
                {"link": {"cred": reg_cred["xonly_pk"]}}, first_height=748000, update_height=748500,
            ),
            "id/parent-a": sv.make_name_history(
                "id/parent-a", p_old_pin["registration"], p_old_pin["owner_policy"],
                {"link": {"grant": p_old_grant["xonly_pk"]}}, first_height=748000, update_height=748600,
            ),
            "id/guardian-carol": sv.make_name_history(
                "id/guardian-carol", g_new_pin["registration"], g_new_pin["owner_policy"],
                {"link": {"grant": g_new_grant["xonly_pk"]}}, first_height=748000, update_height=748600,
            ),
            "id/child-leo": sv.make_name_history(
                "id/child-leo", binding["registration"], ward_owner_policy,
                {"link": {"origin": origin_id}}, first_height=749005, update_height=749015,
            ),
        },
        "txs": {
            origin_txid: {"confirmed_height": 749000, "opreturn_hex": origin_opreturn_hex, "outputs": {}},
            h32("t2-bind-seal-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex({"kind": "key", "pk": bind_seal["compressed_pk"]}), "spent_by_txid": binding_txid}}},
            binding_txid: {"confirmed_height": 749010, "inputs": [sv.make_segwit_input(h32("t2-bind-seal-tx"), 0)], "opreturn_hex": binding_opreturn_hex, "outputs": {}},
            h32("t2-status-seal-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(status_policy)}}},
            h32("t2-recov-seal-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(recovery_policy)}}},
            h32("t2-roster-seal-tx"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(vacant_policy), "spent_by_txid": roster_txid}}},
            h32("t2-slot1-vac0"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(vacant_policy), "spent_by_txid": init_txid}}},
            h32("t2-slot2-vac0"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(vacant_policy)}}},
            init_txid: {"confirmed_height": 749020, "opreturn_hex": init_opreturn_hex, "outputs": {"0": {"script_pubkey_hex": spk_hex(init_active_policy), "spent_by_txid": halt_txid}}},
            halt_txid: {"confirmed_height": 749100, "outputs": {"0": {"script_pubkey_hex": spk_hex(vacant_policy), "spent_by_txid": app_txid}}},
            app_txid: {"confirmed_height": 749110, "opreturn_hex": app_opreturn_hex, "outputs": {"0": {"script_pubkey_hex": spk_hex(pending_policy), "spent_by_txid": act_txid}}},
            act_txid: {"confirmed_height": 749260, "inputs": [sv.make_guardian_csv_input(app_txid, 0, pending_policy, sequence=144)], "opreturn_hex": act_opreturn_hex, "outputs": {"0": {"script_pubkey_hex": spk_hex(active_policy)}}},
            roster_txid: {"confirmed_height": 749300, "opreturn_hex": roster_opreturn_hex, "outputs": {"0": {"script_pubkey_hex": spk_hex(vacant_policy)}}},
        },
    }

    origin_bundle = {
        "origin": origin_env,
        "origin_anchor_txid": origin_txid,
        "name_binding": binding,
        "name_binding_txid": binding_txid,
        "guardian_records": [init_guardian_env, guardian_env],
        "guardian_assents": [init_guardian_assent, guardian_assent],
        "roster_records": [roster_env],
        "initial_guardian_disclosures": {"1": {"salt_hex": salt_g1, "name_pin": p_old_pin}},
        "opened_majority_unix": maj_unix,
        "majority_salt_hex": salt_maj,
    }

    reg_issuer_pin = {k: origin_payload["issuer"][k] for k in ("name", "owner_policy", "registration")}
    # Live-execute all 3 ward assent verdicts through Tier1Verifier!
    v = sv.Tier1Verifier(trusted_origin_issuer_pins=[reg_issuer_pin])
    ch = sv.ChainView(chain_state)
    res1 = v.verify_assent(assent_ward_alone, contract_obj, origin_bundle, ch)
    assert res1.verdict == "REFUSE" and res1.refusal_code == "WARD_AUTONOMOUS_FORBIDDEN", res1
    res2 = v.verify_assent(assent_old_guardian, contract_obj, origin_bundle, ch)
    assert res2.verdict == "REFUSE" and res2.refusal_code == "GUARDIAN_INACTIVE", res2
    res3 = v.verify_assent(assent_new_guardian, contract_obj, origin_bundle, ch)
    assert res3.verdict == "ADMIT" and res3.details["verified_slots"] == [1] and res3.details["verified_revision"] == 2, res3

    # Co-tenant same-role contract positive control (two autonomous parties both with role="tenant", distinct party_id!)
    ll_k = make_keypair("t2-landlord-gr")
    t1_k = make_keypair("t2-cotenant1-gr")
    t2_k = make_keypair("t2-cotenant2-gr")
    lease_contract = {
        "clause_commitments": [sl.clause_commit(h32("t2-lease-c0"), {"text": "Joint residential lease"})],
        "contract_salt": h32("t2-lease-salt"),
        "genesis": GENESIS_MAIN,
        "machine_clause_indices": [0],
        "network": "main",
        "parties": [
            {"party_id": "landlord-1", "role": "landlord", "signing_policy": {"m": 1, "pks": [ll_k["xonly_pk"]]}},
            {"party_id": "tenant-1", "role": "tenant", "signing_policy": {"m": 1, "pks": [t1_k["xonly_pk"]]}},
            {"party_id": "tenant-2", "role": "tenant", "signing_policy": {"m": 1, "pks": [t2_k["xonly_pk"]]}},
        ],
        "profile": "org.seallink/co-tenant-lease-v1",
        "seal": contract_obj["seal"],
        "type": "seallink-contract/1",
        "window": {"not_after_height": 790000, "not_before_height": 750500},
    }
    lease_cid = sl.object_id(lease_contract)
    lease_assents = [
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": h32("t2-la-ll"), "party_id": "landlord-1", "party_role": "landlord", "target_id": lease_cid, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [ll_k["_sk"]]),
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": h32("t2-la-t1"), "party_id": "tenant-1", "party_role": "tenant", "target_id": lease_cid, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [t1_k["_sk"]]),
        sl.sign_envelope({"expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main", "nonce": h32("t2-la-t2"), "party_id": "tenant-2", "party_role": "tenant", "target_id": lease_cid, "target_type": "seallink-contract/1", "type": "seallink-assent/1"}, [t2_k["_sk"]]),
    ]
    res_lease = v.verify_contract_assents(lease_contract, lease_assents, None, ch)
    assert res_lease.verdict == "ADMIT" and res_lease.details["covered_party_ids"] == ["landlord-1", "tenant-1", "tenant-2"], res_lease

    # Positive name_recovery traces (SPEC-04 §6):
    # Branch A: recovery_seal spent with 0x0c proposing B2 -> owner broadcasts 0x10 cancel -> B1 restored & recovery_seal advances to (T_rec1, 0)!
    # Branch B: subsequent 0x0c spends (T_rec1, 0) proposing B3 -> after 1008 blocks without 0x10 -> B3 promoted & recovery_seal advances to (T_rec2, 0)!
    b2 = {
        "binding_mode": "recovery",
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo-attempted-rec",
        "network": "main",
        "next_recovery_policy": recovery_policy,
        "next_recovery_vout": 0,
        "origin_id": origin_id,
        "owner_policy": ward_owner_policy,
        "registration": {"txid": h32("t2-leo-b2-reg"), "vout": 0},
        "seq": 2,
        "supersedes_binding_id": sl.object_id(binding),
        "type": "seallink-name-binding/1",
    }
    b2_id = sl.object_id(b2)
    t_rec1 = h32("t2-rec1-0x0c-tx")
    b3_owner = make_keypair("t2-leo-b3-new-owner")
    b3_owner_pol = {"kind": "key", "pk": b3_owner["compressed_pk"]}
    b3 = {
        "binding_mode": "recovery",
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo-recovered-final",
        "network": "main",
        "next_recovery_policy": recovery_policy,
        "next_recovery_vout": 0,
        "origin_id": origin_id,
        "owner_policy": b3_owner_pol,
        "registration": {"txid": h32("t2-leo-b3-reg"), "vout": 0},
        "seq": 2,
        "supersedes_binding_id": sl.object_id(binding),
        "type": "seallink-name-binding/1",
    }
    b3_id = sl.object_id(b3)
    t_rec2 = h32("t2-rec2-0x0c-tx")

    # Build Branch A chain (cancel B2 via owner-authored 0x10 at height 750500 < 750400 + 1008)
    ch_rec_a_raw = copy.deepcopy(chain_state)
    ch_rec_a_raw["txs"][h32("t2-recov-seal-tx")]["outputs"]["0"]["spent_by_txid"] = t_rec1
    ch_rec_a_raw["txs"][t_rec1] = {
        "confirmed_height": 750400,
        "opreturn_hex": sl.encode_opreturn(0x0C, b2_id).hex(),
        "outputs": {"0": {"script_pubkey_hex": spk_hex(recovery_policy)}},
    }
    leo_u = ch_rec_a_raw["names"]["id/child-leo"]["updates"]
    prev_lu = leo_u[-1]
    leo_spk, _ = sl.compile_script_policy(ward_owner_policy)
    leo_u.append({
        "op": "NAME_UPDATE",
        "txid": h32("t2-leo-0x10-cancel-tx"),
        "vout": 0,
        "confirmed_height": 750500,
        "block_time": 1795219000,
        "owner_policy": ward_owner_policy,
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", leo_spk, name=b"id/child-leo", value=sl.jcs_encode({"link": {"origin": origin_id}})).hex(),
        "prev_input": {"txid": prev_lu["txid"], "vout": prev_lu["vout"], "witness_policy": ward_owner_policy, "sighash_bytes": [0x01]},
        "opreturn_hex": sl.encode_opreturn(0x10, b2_id).hex(),
    })
    ob_rec_a = {**origin_bundle, "recovery_bindings": [b2]}
    st_a, err_a = v.verify_origin_and_status(ob_rec_a, sv.ChainView(ch_rec_a_raw))
    assert err_a is None and st_a is not None and sl.object_id(st_a["binding"]) == sl.object_id(binding), (st_a, err_a)
    assert st_a["active_recovery_seal"]["txid"] == t_rec1 and st_a["active_recovery_seal"]["vout"] == 0
    _, err_a_b2 = v.verify_origin_and_status(ob_rec_a, sv.ChainView(ch_rec_a_raw), assert_binding_id=b2_id)
    assert err_a_b2 == "RECOVERY_FORBIDDEN"

    # Build Branch B chain (subsequent 0x0c spends continued (t_rec1, 0) at 751000, tip advances to 752100 >= 751000+1008 -> B3 promoted!)
    ch_rec_b_raw = copy.deepcopy(ch_rec_a_raw)
    ch_rec_b_raw["tip_height"] = 752100
    ch_rec_b_raw["tip_hash"] = h32("t2-tip-752100")
    ch_rec_b_raw["best_header_height"] = 752100
    ch_rec_b_raw["observation_bracket"] = {
        "consistent": True,
        "start": {"height": 752100, "hash": h32("t2-tip-752100")},
        "end": {"height": 752100, "hash": h32("t2-tip-752100")},
    }
    ch_rec_b_raw["comparison_peers"] = [{"id": "observer-1", "healthy": True, "height": 752100, "hash_at_tip": h32("t2-tip-752100")}]
    ch_rec_b_raw["names"]["id/child-leo-recovered-final"] = sv.make_name_history(
        "id/child-leo-recovered-final", b3["registration"], b3_owner_pol,
        {"link": {"origin": origin_id}}, first_height=750900, update_height=750950,
    )
    ch_rec_b_raw["txs"][t_rec1]["outputs"]["0"]["spent_by_txid"] = t_rec2
    ch_rec_b_raw["txs"][t_rec2] = {
        "confirmed_height": 751000,
        "opreturn_hex": sl.encode_opreturn(0x0C, b3_id).hex(),
        "outputs": {"0": {"script_pubkey_hex": spk_hex(recovery_policy)}},
    }
    ob_rec_b = {**origin_bundle, "recovery_bindings": [b2, b3]}
    st_b, err_b = v.verify_origin_and_status(ob_rec_b, sv.ChainView(ch_rec_b_raw))
    assert err_b is None and st_b is not None and sl.object_id(st_b["binding"]) == b3_id, (st_b, err_b)
    assert st_b["active_recovery_seal"]["txid"] == t_rec2 and st_b["active_recovery_seal"]["vout"] == 0
    _, err_b_old = v.verify_origin_and_status(ob_rec_b, sv.ChainView(ch_rec_b_raw), assert_binding_id=sl.object_id(binding))
    assert err_b_old == "ORIGIN_BINDING_INVALID"

    return {
        "suite": "trace-02-guardian-succession-assent",
        "version": VERSION,
        "description": "Executable RFC 8448-style trace: private origin/1 + status_seal, initial slot activation (0x12) + incoming guardian assent -> fast halt -> acyclic Stage 1 (0x0d) -> Stage 2 (0x0e) -> roster transition (0x0f), ward contract assent via guardian_approvals[] + party_id, co-tenant same-role party_id contract coverage, and both positive name_recovery continuation branches (0x10 cancel restores B1; post-delay promotes B3).",
        "chain_state": chain_state,
        "trusted_origin_issuer_pins": [reg_issuer_pin],
        "origin": envelope_record(origin_env, "schemas/origin.schema.json"),
        "origin_anchor_txid": origin_txid,
        "origin_opreturn_hex": origin_opreturn_hex,
        "majority_disclosure": {"salt_hex": salt_maj, "majority_obj": maj_obj, "commitment_hex": sl.clause_commit(salt_maj, maj_obj)},
        "initial_guardian_1_disclosure": {"salt_hex": salt_g1, "name_pin": p_old_pin, "commitment_hex": sl.clause_commit(salt_g1, p_old_pin)},
        "name_binding": unsigned_record(binding, "schemas/guardian.schema.json#/$defs/NameBinding"),
        "name_binding_txid": binding_txid,
        "name_binding_opreturn_hex": binding_opreturn_hex,
        "stage_0_initial_activation": {
            "guardian_record": envelope_record(init_guardian_env, "schemas/guardian.schema.json#/$defs/GuardianRecord"),
            "guardian_assent": envelope_record(init_guardian_assent, "schemas/contract.schema.json#/$defs/Assent"),
            "activation_txid": init_txid,
            "opreturn_hex": init_opreturn_hex,
            "derived_active_outpoint": {"txid": init_txid, "vout": 0},
            "halt_txid": halt_txid,
            "vacant_after_halt": vacant_after_halt,
        },
        "stage_1_appointment": {
            "guardian_record": envelope_record(guardian_env, "schemas/guardian.schema.json#/$defs/GuardianRecord"),
            "guardian_assent": envelope_record(guardian_assent, "schemas/contract.schema.json#/$defs/Assent"),
            "anchor_txid": app_txid,
            "opreturn_hex": app_opreturn_hex,
            "derived_pending_outpoint": derived_pending_outpoint,
        },
        "stage_2_activation": {
            "activation_txid": act_txid,
            "opreturn_hex": act_opreturn_hex,
            "derived_active_outpoint": derived_active_outpoint,
            "active_script_pubkey_hex": spk_hex(active_policy),
        },
        "roster_transition": {
            "roster_record": envelope_record(roster_env, "schemas/guardian.schema.json#/$defs/GuardianRoster"),
            "anchor_txid": roster_txid,
            "opreturn_hex": roster_opreturn_hex,
        },
        "contract": unsigned_record(contract_obj, "schemas/contract.schema.json#/$defs/Contract"),
        "machine_clause_0_disclosure": {"index": 0, "salt_hex": clause0_salt, "clause": clause0_obj, "commitment_hex": sl.clause_commit(clause0_salt, clause0_obj)},
        "assent_verdicts": [
            {
                "id": "ward-autonomous-assent-forbidden",
                "assent": envelope_record(assent_ward_alone, "schemas/contract.schema.json#/$defs/Assent"),
                "expected_verdict": "REFUSE",
                "expected_refusal": "WARD_AUTONOMOUS_FORBIDDEN",
            },
            {
                "id": "former-halted-guardian-refused",
                "assent": envelope_record(assent_old_guardian, "schemas/contract.schema.json#/$defs/Assent"),
                "expected_verdict": "REFUSE",
                "expected_refusal": "GUARDIAN_INACTIVE",
            },
            {
                "id": "active-successor-guardian-admitted",
                "assent": envelope_record(assent_new_guardian, "schemas/contract.schema.json#/$defs/Assent"),
                "expected_verdict": "ADMIT",
                "verified_slots": [1],
                "verified_guardians": ["id/guardian-carol"],
                "verified_revision": 2,
                "derived_event_class": "contract_assent",
            },
        ],
        "co_tenant_same_role_contract": {
            "contract": unsigned_record(lease_contract, "schemas/contract.schema.json#/$defs/Contract"),
            "assents": [envelope_record(a, "schemas/contract.schema.json#/$defs/Assent") for a in lease_assents],
            "expected_verdict": "ADMIT",
            "expected_covered_party_ids": ["landlord-1", "tenant-1", "tenant-2"],
        },
        "name_recovery_positive_traces": {
            "candidate_b2": unsigned_record(b2, "schemas/guardian.schema.json#/$defs/NameBinding"),
            "candidate_b3": unsigned_record(b3, "schemas/guardian.schema.json#/$defs/NameBinding"),
            "branch_a_timely_0x10_cancel_restores_b1": {
                "chain_state": ch_rec_a_raw,
                "expected_active_binding_id": sl.object_id(binding),
                "expected_active_recovery_seal": {"txid": t_rec1, "vout": 0},
                "expected_cancelled_b2_refusal": "RECOVERY_FORBIDDEN",
            },
            "branch_b_post_delay_recovery_promotes_b3": {
                "chain_state": ch_rec_b_raw,
                "expected_active_binding_id": b3_id,
                "expected_active_recovery_seal": {"txid": t_rec2, "vout": 0},
                "expected_superseded_b1_refusal": "ORIGIN_BINDING_INVALID",
            },
        },
    }


def build_trace_03_delegation() -> dict[str, Any]:
    org_owner = make_keypair("t3-org-owner")
    org_grant = make_keypair("t3-org-grant")
    parent_seal = make_keypair("t3-parent-seal")
    del_key = make_keypair("t3-delegate-key")
    child_seal_key = make_keypair("t3-child-seal-key")
    row_coin_k = make_keypair("t3-row-coin")
    st_a_rcpt = make_keypair("t3-station-a-rcpt")
    st_b_rcpt = make_keypair("t3-station-b-rcpt")
    w1_req = make_keypair("t3-worker1-req")
    w1_seal = make_keypair("t3-worker1-seal")
    w2_req = make_keypair("t3-worker2-req")
    w2_seal = make_keypair("t3-worker2-seal")
    attacker = make_keypair("t3-attacker-forger")

    org_owner_pol = {"kind": "key", "pk": org_owner["compressed_pk"]}
    parent_seal_pol = {"kind": "key", "pk": parent_seal["compressed_pk"]}
    pool_q_a = {"kind": "seallink/count", "max": "6", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}
    pool_q_b = {"kind": "seallink/count", "max": "4", "resource": "station:id/station-b:tools", "unit": "calls", "window": "term"}
    pool_q_bytes = {"kind": "seallink/bytes", "max": "500000", "resource": "station:fleet:tools", "unit": "bytes", "window": "term"}
    row_q_a = {"kind": "seallink/count", "max": "2", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}
    row_q_a_bytes = {"kind": "seallink/bytes", "max": "100000", "resource": "station:fleet:tools", "unit": "bytes", "window": "term"}
    row_q_b = {"kind": "seallink/count", "max": "2", "resource": "station:id/station-b:tools", "unit": "calls", "window": "term"}
    row_q_b_bytes = {"kind": "seallink/bytes", "max": "100000", "resource": "station:fleet:tools", "unit": "bytes", "window": "term"}

    recent_blk = h32("t3-recent-block")
    parent_seal_tx = h32("t3-parent-seal-tx")
    rows_a_tx = h32("t3-rows-a-tx")
    rows_b_tx = h32("t3-rows-b-tx")

    parent_payload = {
        "capabilities": [
            {"action": "agent/tool", "quotas": [pool_q_a, pool_q_bytes], "target": "station:id/station-a:tools"},
            {"action": "agent/tool", "quotas": [pool_q_b, pool_q_bytes], "target": "station:id/station-b:tools"},
        ],
        "delegate": {
            "child_seal_key": child_seal_key["compressed_pk"],
            "groups": [
                {
                    "ranges": [{"count": 3, "first": 0, "script_policy": {"kind": "key", "pk": row_coin_k["compressed_pk"]}, "txid": rows_a_tx}],
                    "template": {
                        "capabilities": [
                            {
                                "action": "agent/tool",
                                "quotas": [row_q_a, row_q_a_bytes],
                                "target": "station:id/station-a:tools",
                                "where": {"tool_name": {"in": ["git-diff", "pytest"]}},
                            }
                        ],
                        "executor": {"key": st_a_rcpt["xonly_pk"], "name": "id/station-a"},
                        "notary_mode": "none",
                        "recipient_rule": {"key": w1_req["xonly_pk"], "mode": "exact_key"},
                    },
                },
                {
                    "ranges": [{"count": 2, "first": 0, "script_policy": {"kind": "key", "pk": row_coin_k["compressed_pk"]}, "txid": rows_b_tx}],
                    "template": {
                        "capabilities": [
                            {
                                "action": "agent/tool",
                                "quotas": [row_q_b, row_q_b_bytes],
                                "target": "station:id/station-b:tools",
                                "where": {"tool_name": {"in": ["lint", "pytest"]}},
                            }
                        ],
                        "executor": {"key": st_b_rcpt["xonly_pk"], "name": "id/station-b"},
                        "notary_mode": "none",
                        "recipient_rule": {"key": w2_req["xonly_pk"], "mode": "exact_key"},
                    },
                },
            ],
            "key": del_key["xonly_pk"],
            "pools": [pool_q_a, pool_q_b, pool_q_bytes],
        },
        "executor": {"key": st_a_rcpt["xonly_pk"], "name": "id/station-a"},
        "genesis": GENESIS_MAIN,
        "issuer": make_role_pin("id/org-treasury", "t3-org-reg", org_owner, [org_grant["xonly_pk"]]),
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 750000,
        "recent_block": recent_blk,
        "recipient": {"key": w1_req["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "revocable",
            "mode": "seal",
            "seal": {"script_policy": parent_seal_pol, "txid": parent_seal_tx, "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    ok_r85, totals_r85 = sl.check_whole_parent_budget_r85(parent_payload["delegate"])
    assert ok_r85 and sl.check_disjoint_ranges_r86(parent_payload)

    bad_r85 = copy.deepcopy(parent_payload)
    bad_r85["delegate"]["groups"][0]["template"]["capabilities"][0]["quotas"][0]["max"] = "3"
    assert not sl.check_whole_parent_budget_r85(bad_r85["delegate"])[0]

    bad_r86 = copy.deepcopy(parent_payload)
    bad_r86["delegate"]["groups"][1]["ranges"][0]["txid"] = rows_a_tx
    bad_r86["delegate"]["groups"][1]["ranges"][0]["first"] = 2
    assert not sl.check_disjoint_ranges_r86(bad_r86)

    parent_env = sl.sign_envelope(parent_payload, [org_grant["_sk"]])
    parent_id = sl.object_id(parent_payload)
    parent_issuance_txid = h32("t3-parent-issuance-tx")
    parent_iss_opret = sl.encode_opreturn(
        0x01,
        sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(parent_env), "grant_id": parent_id, "type": "seallink-issuance/1"}).hex(),
    ).hex()

    c1_seal_policy = {"keys": {"grantee": w1_seal["compressed_pk"], "issuer": child_seal_key["compressed_pk"]}, "kind": "branch", "template": "single_use_1_of_2"}
    c1_seal_tx = h32("t3-c1-seal-tx")
    c1_payload = {
        "capabilities": [
            {
                "action": "agent/tool",
                "quotas": [
                    {"kind": "seallink/count", "max": "1", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"},
                    {"kind": "seallink/bytes", "max": "100000", "resource": "station:fleet:tools", "unit": "bytes", "window": "term"},
                ],
                "target": "station:id/station-a:tools",
                "where": {"tool_name": {"eq": "pytest"}},
            }
        ],
        "executor": {"key": st_a_rcpt["xonly_pk"], "name": "id/station-a"},
        "genesis": GENESIS_MAIN,
        "min_depth": 1,
        "network": "main",
        "not_after_height": 755000,
        "not_before_height": 750100,
        "parent": {"grant_id": parent_id, "ordinal": 1},
        "recent_block": recent_blk,
        "recipient": {"key": w1_req["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "single_use",
            "mode": "seal",
            "seal": {"script_policy": c1_seal_policy, "txid": c1_seal_tx, "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    c1_env = sl.sign_envelope(c1_payload, [del_key["_sk"]])
    c1_id = sl.object_id(c1_payload)
    c1_issuance_txid = h32("t3-c1-issuance-tx")
    c1_iss_opret = sl.encode_opreturn(
        0x01,
        sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c1_env), "grant_id": c1_id, "type": "seallink-issuance/1"}).hex(),
    ).hex()

    inv1_payload = {
        "action": "agent/tool",
        "arguments": {"input_sha256": h32("t3-pytest-args"), "max_output_bytes": "65536", "tool_name": "pytest"},
        "executor": {"key": st_a_rcpt["xonly_pk"], "name": "id/station-a"},
        "exp": 1795221000,
        "genesis": GENESIS_MAIN,
        "iat": 1795220000,
        "network": "main",
        "nonce": h32("t3-inv1-nonce"),
        "proof_path": [
            {"grant_id": parent_id, "issuance_txid": parent_issuance_txid},
            {"grant_id": c1_id, "issuance_txid": c1_issuance_txid},
        ],
        "target": "station:id/station-a:tools",
        "type": "seallink-invocation/1",
    }
    inv1_env = sl.sign_envelope(inv1_payload, [w1_req["_sk"]])
    inv1_id = sl.object_id(inv1_payload)
    inv1_caddr = sl.content_addr(inv1_env)
    use_txid = h32("t3-use-tx-branch0")
    use_opreturn_hex = sl.encode_opreturn(0x11, inv1_caddr, 0x00).hex()

    # Forged replay with IDENTICAL payload/invocation_id signed by attacker -> MUST fail Step 3b WIRE_SIGNATURE before Step 3c cached receipt!
    inv1_forged = sl.sign_envelope(inv1_payload, [attacker["_sk"]])
    assert sl.object_id(inv1_forged["payload"]) == inv1_id

    tool_result = {"exit_code": 0, "output_bytes": "1240", "output_sha256": h32("t3-pytest-out"), "tool_name": "pytest"}
    rcpt1 = sl.sign_envelope(
        {
            "action": "agent/tool",
            "executor_name": "id/station-a",
            "genesis": GENESIS_MAIN,
            "grant_id": c1_id,
            "invocation_id": inv1_id,
            "network": "main",
            "outcome": "executed",
            "recorded_at": 1795220050,
            "result_sha256": sl.content_addr(tool_result),
            "settlements": [
                {"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "settled": "1", "unit": "calls", "window": "term"},
                {"account": "row", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:id/station-a:tools", "row_ordinal": 1, "settled": "1", "unit": "calls", "window": "term"},
                {"account": "own", "kind": "seallink/bytes", "released": "64296", "reserved": "65536", "resource": "station:fleet:tools", "settled": "1240", "unit": "bytes", "window": "term"},
                {"account": "row", "kind": "seallink/bytes", "released": "64296", "reserved": "65536", "resource": "station:fleet:tools", "row_ordinal": 1, "settled": "1240", "unit": "bytes", "window": "term"},
            ],
            "tip_hash": h32("t3-tip-750110"),
            "tip_height": 750110,
            "type": "seallink-receipt/1",
        },
        [st_a_rcpt["_sk"]],
    )

    inv1_replay_new = sl.sign_envelope(
        {**inv1_payload, "iat": 1795220100, "nonce": h32("t3-inv1-second-nonce")},
        [w1_req["_sk"]],
    )

    # Child 2 (ordinal 4, station-b) revoked via issuer branch 1 spend
    c2_seal_policy = {"keys": {"grantee": w2_seal["compressed_pk"], "issuer": child_seal_key["compressed_pk"]}, "kind": "branch", "template": "single_use_1_of_2"}
    c2_seal_tx = h32("t3-c2-seal-tx")
    c2_payload = {
        "capabilities": [
            {
                "action": "agent/tool",
                "quotas": [
                    {"kind": "seallink/count", "max": "1", "resource": "station:id/station-b:tools", "unit": "calls", "window": "term"},
                    {"kind": "seallink/bytes", "max": "100000", "resource": "station:fleet:tools", "unit": "bytes", "window": "term"},
                ],
                "target": "station:id/station-b:tools",
                "where": {"tool_name": {"eq": "lint"}},
            }
        ],
        "executor": {"key": st_b_rcpt["xonly_pk"], "name": "id/station-b"},
        "genesis": GENESIS_MAIN,
        "network": "main",
        "not_after_height": 755000,
        "not_before_height": 750100,
        "parent": {"grant_id": parent_id, "ordinal": 4},
        "recent_block": recent_blk,
        "recipient": {"key": w2_req["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "single_use",
            "mode": "seal",
            "seal": {"script_policy": c2_seal_policy, "txid": c2_seal_tx, "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    c2_env = sl.sign_envelope(c2_payload, [del_key["_sk"]])
    c2_id = sl.object_id(c2_payload)
    c2_issuance_txid = h32("t3-c2-issuance-tx")
    c2_iss_opret = sl.encode_opreturn(
        0x01,
        sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c2_env), "grant_id": c2_id, "type": "seallink-issuance/1"}).hex(),
    ).hex()
    c2_revoke_tx = h32("t3-c2-issuer-revoke-tx")
    inv2_env = sl.sign_envelope(
        {
            "action": "agent/tool",
            "arguments": {"input_sha256": h32("t3-lint-args"), "max_output_bytes": "4096", "tool_name": "lint"},
            "executor": {"key": st_b_rcpt["xonly_pk"], "name": "id/station-b"},
            "exp": 1795221000,
            "genesis": GENESIS_MAIN,
            "iat": 1795220000,
            "network": "main",
            "nonce": h32("t3-inv2-nonce-1"),
            "proof_path": [{"grant_id": parent_id, "issuance_txid": parent_issuance_txid}, {"grant_id": c2_id, "issuance_txid": c2_issuance_txid}],
            "target": "station:id/station-b:tools",
            "type": "seallink-invocation/1",
        },
        [w2_req["_sk"]],
    )
    inv2_env_subseq = sl.sign_envelope(
        {**inv2_env["payload"], "nonce": h32("t3-inv2-nonce-2")},
        [w2_req["_sk"]],
    )

    # Child 3 (ordinal 2, station-a, revocable) for atomic multi-quota rollback test: calls fits, bytes exceeds 50000!
    c3_seal_pol = {"kind": "key", "pk": child_seal_key["compressed_pk"]}
    c3_seal_tx = h32("t3-c3-seal-tx")
    c3_payload = {
        "capabilities": [
            {
                "action": "agent/tool",
                "quotas": [
                    {"kind": "seallink/count", "max": "2", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"},
                    {"kind": "seallink/bytes", "max": "50000", "resource": "station:fleet:tools", "unit": "bytes", "window": "term"},
                ],
                "target": "station:id/station-a:tools",
                "where": {"tool_name": {"eq": "pytest"}},
            }
        ],
        "executor": {"key": st_a_rcpt["xonly_pk"], "name": "id/station-a"},
        "genesis": GENESIS_MAIN,
        "network": "main",
        "not_after_height": 755000,
        "not_before_height": 750100,
        "parent": {"grant_id": parent_id, "ordinal": 2},
        "recent_block": recent_blk,
        "recipient": {"key": w1_req["xonly_pk"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": c3_seal_pol, "txid": c3_seal_tx, "vout": 0}},
        "type": "seallink-grant/1",
    }
    c3_env = sl.sign_envelope(c3_payload, [del_key["_sk"]])
    c3_id = sl.object_id(c3_payload)
    c3_issuance_txid = h32("t3-c3-issuance-tx")
    c3_iss_opret = sl.encode_opreturn(
        0x01,
        sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(c3_env), "grant_id": c3_id, "type": "seallink-issuance/1"}).hex(),
    ).hex()
    inv3_exceed_bytes = sl.sign_envelope(
        {
            "action": "agent/tool",
            "arguments": {"input_sha256": h32("t3-rb-args"), "max_output_bytes": "65536", "tool_name": "pytest"},
            "executor": {"key": st_a_rcpt["xonly_pk"], "name": "id/station-a"},
            "exp": 1795221000,
            "genesis": GENESIS_MAIN,
            "iat": 1795220000,
            "network": "main",
            "nonce": h32("t3-inv3-nonce-rb"),
            "proof_path": [{"grant_id": parent_id, "issuance_txid": parent_issuance_txid}, {"grant_id": c3_id, "issuance_txid": c3_issuance_txid}],
            "target": "station:id/station-a:tools",
            "type": "seallink-invocation/1",
        },
        [w1_req["_sk"]],
    )

    # Full declarative derived chain state for station-a (Child 1, Child 3) & station-b (Child 2)
    base_chain = {
        "network": "main",
        "genesis": GENESIS_MAIN,
        "tip_height": 750110,
        "tip_hash": h32("t3-tip-750110"),
        "tip_header_time": 1795220040,
        "tip_first_sight": 1795220045,
        "now": 1795220050,
        "clock_watermark": 1795219000,
        "best_header_height": 750110,
        "in_ibd": False,
        "txindex": True,
        "node_reachable": True,
        "observation_bracket": {
            "consistent": True,
            "start": {"height": 750110, "hash": h32("t3-tip-750110")},
            "end": {"height": 750110, "hash": h32("t3-tip-750110")},
        },
        "comparison_peers": [{"id": "observer-1", "healthy": True, "height": 750110, "hash_at_tip": h32("t3-tip-750110")}],
        "blocks": {recent_blk: 750000},
        "names": {
            "id/org-treasury": sv.make_name_history(
                "id/org-treasury", {"txid": h32("t3-org-reg"), "vout": 0}, org_owner_pol,
                {"link": {"grant": org_grant["xonly_pk"]}}, first_height=748000, update_height=749000,
            )
        },
        "txs": {
            rows_a_tx: {
                "confirmed_height": 749990,
                "outputs": {
                    "0": {"script_pubkey_hex": spk_hex({"kind": "key", "pk": row_coin_k["compressed_pk"]}), "spent_by_txid": c1_issuance_txid},
                    "1": {"script_pubkey_hex": spk_hex({"kind": "key", "pk": row_coin_k["compressed_pk"]}), "spent_by_txid": c3_issuance_txid},
                    "2": {"script_pubkey_hex": spk_hex({"kind": "key", "pk": row_coin_k["compressed_pk"]})},
                },
            },
            rows_b_tx: {
                "confirmed_height": 749990,
                "outputs": {
                    "0": {"script_pubkey_hex": spk_hex({"kind": "key", "pk": row_coin_k["compressed_pk"]}), "spent_by_txid": c2_issuance_txid},
                    "1": {"script_pubkey_hex": spk_hex({"kind": "key", "pk": row_coin_k["compressed_pk"]})},
                },
            },
            parent_seal_tx: {
                "confirmed_height": 750002,
                "inputs": [sv.make_segwit_input(h32("t3-org-fund"), 0)],
                "outputs": {"0": {"script_pubkey_hex": spk_hex(parent_seal_pol)}, "1": {"script_pubkey_hex": spk_hex(org_owner_pol)}},
            },
            parent_issuance_txid: {
                "confirmed_height": 750005,
                "inputs": [sv.make_segwit_input(parent_seal_tx, 1)],
                "opreturn_hex": parent_iss_opret,
                "outputs": {},
            },
            c1_seal_tx: {
                "confirmed_height": 750101,
                "inputs": [sv.make_segwit_input(h32("t3-c1-fund"), 0)],
                "outputs": {
                    "0": {"script_pubkey_hex": spk_hex(c1_seal_policy), "spent_by_txid": use_txid},
                    "1": {"script_pubkey_hex": spk_hex(org_owner_pol)},
                },
            },
            c1_issuance_txid: {
                "confirmed_height": 750102,
                "inputs": [sv.make_segwit_input(rows_a_tx, 0), sv.make_segwit_input(c1_seal_tx, 1)],
                "opreturn_hex": c1_iss_opret,
                "outputs": {},
            },
            use_txid: {
                "mempool": True,
                "inputs": [sv.make_single_use_spend_input(c1_payload["revocation"]["seal"], branch=0)],
                "opreturn_hex": use_opreturn_hex,
                "outputs": {},
            },
            c2_seal_tx: {
                "confirmed_height": 750101,
                "inputs": [sv.make_segwit_input(h32("t3-c2-fund"), 0)],
                "outputs": {
                    "0": {"script_pubkey_hex": spk_hex(c2_seal_policy), "spent_by_txid": c2_revoke_tx},
                    "1": {"script_pubkey_hex": spk_hex(org_owner_pol)},
                },
            },
            c2_revoke_tx: {
                "mempool": True,
                "inputs": [sv.make_single_use_spend_input(c2_payload["revocation"]["seal"], branch=1)],
                "outputs": {},
            },
            c2_issuance_txid: {
                "confirmed_height": 750102,
                "inputs": [sv.make_segwit_input(rows_b_tx, 0), sv.make_segwit_input(c2_seal_tx, 1)],
                "opreturn_hex": c2_iss_opret,
                "outputs": {},
            },
            c3_seal_tx: {
                "confirmed_height": 750101,
                "inputs": [sv.make_segwit_input(h32("t3-c3-fund"), 0)],
                "outputs": {"0": {"script_pubkey_hex": spk_hex(c3_seal_pol)}, "1": {"script_pubkey_hex": spk_hex(org_owner_pol)}},
            },
            c3_issuance_txid: {
                "confirmed_height": 750102,
                "inputs": [sv.make_segwit_input(rows_a_tx, 1), sv.make_segwit_input(c3_seal_tx, 1)],
                "opreturn_hex": c3_iss_opret,
                "outputs": {},
            },
        },
    }
    org_pin = make_name_pin("id/org-treasury", "t3-org-reg", org_owner_pol)
    exec_a = {
        "name": "id/station-a",
        "key": st_a_rcpt["xonly_pk"],
        "actions": ["agent/tool"],
        "station_slot_bindings": {"station:id/station-a:tools": [org_pin]},
    }
    exec_b = {
        "name": "id/station-b",
        "key": st_b_rcpt["xonly_pk"],
        "actions": ["agent/tool"],
        "station_slot_bindings": {"station:id/station-b:tools": [org_pin]},
    }
    jid_a = h32("t3-station-a-journal")
    jid_crash = h32("t3-station-a-crash-journal")
    jid_b = h32("t3-station-b-journal")
    jid_rb = h32("t3-station-a-rollback-journal")

    # Live-execute ALL steps through Tier1Verifier!
    v = sv.Tier1Verifier()
    bundle_c1 = {"grants": [parent_env, c1_env]}
    ch_a = sv.ChainView(base_chain)
    jr_a = sv.FencedJournal.from_dict({"journal_id": jid_a})
    actual_usage_c1 = {"seallink/bytes|station:fleet:tools|bytes|term": 1240}

    # Step A: mempool unconfirmed -> CHAIN_DEPTH_INSUFFICIENT
    ra = v.verify_invocation(inv1_env, bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid, actual_quota_usage=actual_usage_c1)
    assert ra.verdict == "REFUSE" and ra.refusal_code == "CHAIN_DEPTH_INSUFFICIENT", ra

    # Confirm use_txid at height 750110
    confirm_patch = {"txs": {use_txid: {"confirmed_height": 750110, "mempool": False}}}
    ch_a.apply_patch(confirm_patch)

    # Step B (crash-in-effect-window with FULL atomic dual-account multi-quota replay from persisted entries!):
    # 1. Reserves own+row for calls+bytes in ONE atomic reservation entry (4 lines) and crashes before settlement -> UNCERTAIN
    # 2. Reconstruct a brand-new FencedJournal strictly from persisted entries + witness head and retry -> UNCERTAIN, all 4 reservations retained!
    jr_crash = sv.FencedJournal.from_dict({"journal_id": jid_crash})
    rb1 = v.verify_invocation(inv1_env, bundle_c1, ch_a, jr_crash, exec_a, use_txid=use_txid, simulate_crash_before_settlement=True, actual_quota_usage=actual_usage_c1)
    assert rb1.verdict == "UNCERTAIN" and rb1.outcome == "uncertain" and len(rb1.journal_writes) == 1, rb1
    assert len(rb1.journal_writes[0]["entry"]["body"]["reservations"]) == 4
    jr_restarted = sv.FencedJournal.replay_persisted_entries(
        jid_crash,
        [w["entry"] for w in rb1.journal_writes],
        witness_pos=jr_crash.pos,
        witness_commitment=jr_crash.commitment,
    )
    rb2 = v.verify_invocation(inv1_env, bundle_c1, ch_a, jr_restarted, exec_a, use_txid=use_txid, actual_quota_usage=actual_usage_c1)
    assert rb2.verdict == "UNCERTAIN" and rb2.outcome == "uncertain" and rb2.details.get("unsettled_count") == 4 and len(rb2.journal_writes) == 0, rb2

    # Step C: normal confirmed execute on jr_a -> ADMIT + unified 2-entry dual-account multi-quota + single_use atomic terminal journal chain!
    rc = v.verify_invocation(inv1_env, bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid, receipt_env_for_cache=rcpt1, actual_quota_usage=actual_usage_c1)
    assert rc.verdict == "ADMIT" and len(rc.journal_writes) == 2 and not jr_a.unsettled_reservations, rc
    # Verify BOTH own(c1_id) and row(parent_id, row_ordinal=1) settled to exact (1 call, 1240 bytes)!
    q_calls_k = "seallink/count|station:id/station-a:tools|calls|term"
    q_bytes_k = "seallink/bytes|station:fleet:tools|bytes|term"
    assert jr_a.quotas_used[(f"own:{c1_id}", q_calls_k, "term")] == 1
    assert jr_a.quotas_used[(f"row:{parent_id}:1", q_calls_k, "term")] == 1
    assert jr_a.quotas_used[(f"own:{c1_id}", q_bytes_k, "term")] == 1240
    assert jr_a.quotas_used[(f"row:{parent_id}:1", q_bytes_k, "term")] == 1240

    # Step D: unauthenticated forged replay of same invocation_id -> WIRE_SIGNATURE (Step 3b BEFORE Step 3c!)
    rd = v.verify_invocation(inv1_forged, bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid)
    assert rd.verdict == "REFUSE" and rd.refusal_code == "WIRE_SIGNATURE", rd

    # Step E: authenticated replay of same invocation_id -> cached receipt, zero second effect
    re_res = v.verify_invocation(inv1_env, bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid)
    assert re_res.verdict == "ADMIT" and re_res.cached_receipt_content_addr == sl.content_addr(rcpt1) and len(re_res.journal_writes) == 0, re_res

    # Step F: new nonce against already-consumed single-use child -> INVOKE_REPLAY
    step_f_patch = {"now": 1795220120}
    ch_a.apply_patch(step_f_patch)
    rf = v.verify_invocation(inv1_replay_new, bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid)
    assert rf.verdict == "REFUSE" and rf.refusal_code == "INVOKE_REPLAY", rf

    # Atomic multi-quota rollback check on Child 3: 1st quota (calls) fits, 2nd quota (bytes) exceeds 50000 -> QUOTA_EXCEEDED + ZERO writes + ZERO balance change!
    jr_rb = sv.FencedJournal.from_dict({"journal_id": jid_rb})
    bundle_c3 = {"grants": [parent_env, c3_env]}
    r_rb = v.verify_invocation(inv3_exceed_bytes, bundle_c3, sv.ChainView(base_chain), jr_rb, exec_a)
    assert r_rb.verdict == "REFUSE" and r_rb.refusal_code == "QUOTA_EXCEEDED" and not r_rb.journal_writes and not jr_rb.quotas_used, r_rb

    # Child 2 issuer branch 1 revocation on station-b
    bundle_c2 = {"grants": [parent_env, c2_env]}
    ch_b = sv.ChainView(base_chain)
    jr_b = sv.FencedJournal.from_dict({"journal_id": jid_b})
    rc2_first = v.verify_invocation(inv2_env, bundle_c2, ch_b, jr_b, exec_b)
    assert rc2_first.verdict == "REFUSE" and rc2_first.refusal_code == "SEAL_SPENT" and len(rc2_first.journal_writes) == 1, rc2_first
    rc2_next = v.verify_invocation(inv2_env_subseq, bundle_c2, ch_b, jr_b, exec_b)
    assert rc2_next.verdict == "REFUSE" and rc2_next.refusal_code == "GRANT_CLOSED", rc2_next

    return {
        "suite": "trace-03-delegation-pool-single-use",
        "version": VERSION,
        "description": "Executable RFC 8448-style trace: parent delegation with 2 groups sharing 2-unit pools (R8.5 & R8.6 positive/negative), atomic dual-account (own + row) multi-quota reservation/settlement & rollback, acyclic single-use branch-0 execution (0x11), crash-in-effect-window uncertain recovery across journal reconstruction, Step 3b auth-before-cache check, authenticated replay idempotency, new-nonce replay refusal, and issuer branch-1 revocation.",
        "initial_chain_state": base_chain,
        "confirm_use_tx_patch": confirm_patch,
        "station_a_config": exec_a,
        "station_b_config": exec_b,
        "station_a_journal_id": jid_a,
        "station_a_crash_journal_id": jid_crash,
        "station_a_rollback_journal_id": jid_rb,
        "station_b_journal_id": jid_b,
        "parent_grant": envelope_record(parent_env, "schemas/grant.schema.json"),
        "r85_aggregate_budget": {"passed": True, "pool_max_calls": 10, "pool_max_bytes": 500000, "computed_totals": totals_r85},
        "r85_negative_parent": {"object": sl.sign_envelope(bad_r85, [org_grant["_sk"]]), "expected_refusal": "GRANT_CHILD_WIDER"},
        "r86_negative_parent": {"object": sl.sign_envelope(bad_r86, [org_grant["_sk"]]), "expected_refusal": "GRANT_ROW_INVALID"},
        "child_1_single_use": envelope_record(c1_env, "schemas/grant.schema.json"),
        "child_1_trace": {
            "invocation": envelope_record(inv1_env, "schemas/invocation.schema.json#/$defs/Invocation"),
            "profile_args_schema": "schemas/profile-agent.schema.json#/$defs/AgentToolArgs",
            "use_txid_wrapper": use_txid,
            "use_opreturn_0x11_hex": use_opreturn_hex,
            "actual_quota_usage": actual_usage_c1,
            "step_a_mempool_unconfirmed": {"expected_verdict": "REFUSE", "expected_refusal": "CHAIN_DEPTH_INSUFFICIENT"},
            "step_b_crash_in_effect_window": {
                "expected_verdict_after_restart": "UNCERTAIN",
                "expected_outcome": "uncertain",
                "expected_unsettled_count": 4,
                "reservation_retained": True,
                "zero_second_effect": True,
                "crash_journal_writes": [
                    {"entry": unsigned_record(jw["entry"], "schemas/invocation.schema.json#/$defs/JournalEntry"), "c_before": jw["c_before"], "c_after": jw["c_after"]}
                    for jw in rb1.journal_writes
                ],
            },
            "step_c_confirmed_execute": {
                "expected_verdict": "ADMIT",
                "result_object": unsigned_record(tool_result, "schemas/profile-agent.schema.json#/$defs/AgentToolResult"),
                "receipt": envelope_record(rcpt1, "schemas/invocation.schema.json#/$defs/Receipt"),
                "expected_settled_balances": {
                    f"own:{c1_id}|{q_calls_k}": 1,
                    f"row:{parent_id}:1|{q_calls_k}": 1,
                    f"own:{c1_id}|{q_bytes_k}": 1240,
                    f"row:{parent_id}:1|{q_bytes_k}": 1240,
                },
                "journal_chain": [
                    {"entry": unsigned_record(jw["entry"], "schemas/invocation.schema.json#/$defs/JournalEntry"), "c_before": jw["c_before"], "c_after": jw["c_after"]}
                    for jw in rc.journal_writes
                ],
            },
            "step_d_unauthenticated_replay_rejected": {
                "invocation": envelope_record(inv1_forged, "schemas/invocation.schema.json#/$defs/Invocation"),
                "expected_verdict": "REFUSE",
                "expected_refusal": "WIRE_SIGNATURE",
                "note": "Proves SPEC-06 §4 Step 3b recipient authentication executes BEFORE Step 3c cached-receipt lookup.",
            },
            "step_e_authenticated_replay_same_invocation_id": {
                "expected_verdict": "ADMIT",
                "expected_behavior": "RETURN_CACHED_RECEIPT_ZERO_SECOND_EFFECT",
                "cached_receipt_content_addr": sl.content_addr(rcpt1),
            },
            "step_f_new_nonce_replay": {
                "chain_patch": step_f_patch,
                "invocation": envelope_record(inv1_replay_new, "schemas/invocation.schema.json#/$defs/Invocation"),
                "expected_verdict": "REFUSE",
                "expected_refusal": "INVOKE_REPLAY",
            },
        },
        "atomic_quota_rollback": {
            "grant": envelope_record(c3_env, "schemas/grant.schema.json"),
            "invocation": envelope_record(inv3_exceed_bytes, "schemas/invocation.schema.json#/$defs/Invocation"),
            "profile_args_schema": "schemas/profile-agent.schema.json#/$defs/AgentToolArgs",
            "expected_verdict": "REFUSE",
            "expected_refusal": "QUOTA_EXCEEDED",
            "expected_journal_writes": 0,
            "expected_balances_unchanged": True,
        },
        "child_2_issuer_revocation": {
            "grant": envelope_record(c2_env, "schemas/grant.schema.json"),
            "first_invocation": envelope_record(inv2_env, "schemas/invocation.schema.json#/$defs/Invocation"),
            "subsequent_invocation": envelope_record(inv2_env_subseq, "schemas/invocation.schema.json#/$defs/Invocation"),
            "issuer_branch_1_spend_txid": c2_revoke_tx,
            "first_observation_refusal": "SEAL_SPENT",
            "subsequent_request_refusal": "GRANT_CLOSED",
            "closure_journal_write": {
                "entry": unsigned_record(rc2_first.journal_writes[0]["entry"], "schemas/invocation.schema.json#/$defs/JournalEntry"),
                "c_before": rc2_first.journal_writes[0]["c_before"],
                "c_after": rc2_first.journal_writes[0]["c_after"],
            },
        },
    }


def build_trace_04_agent_guardian_intake() -> dict[str, Any]:
    """Build executable PROFILE-agent-v1 trace for agent/guardian-message (strict_drop, effect_grant)."""
    reg_own = make_keypair("t4-reg-own")
    reg_cred = make_keypair("t4-reg-cred")
    disp = make_keypair("t4-disp")
    arb = make_keypair("t4-arb")
    chal = make_keypair("t4-chal")
    ward_init = make_keypair("t4-ward-init")
    bind_seal = make_keypair("t4-bind-seal")
    stat_cap = make_keypair("t4-stat-cap")
    stat_end = make_keypair("t4-stat-end")
    rec_disp = make_keypair("t4-recov-disp")
    rec_arb = make_keypair("t4-recov-arb")
    ga_own = make_keypair("t4-ga-own")
    ga_gr = make_keypair("t4-ga-gr")
    ga_seal = make_keypair("t4-ga-seal")
    gb_own = make_keypair("t4-gb-own")
    gb_gr = make_keypair("t4-gb-gr")
    gb_seal = make_keypair("t4-gb-seal")
    bridge_req = make_keypair("t4-bridge-req")
    station_rcpt = make_keypair("t4-station-rcpt")
    grant_seal = make_keypair("t4-grant-seal")
    stranger = make_keypair("t4-stranger")

    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["compressed_pk"], arb["compressed_pk"])}
    stat_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(stat_cap["compressed_pk"], stat_end["compressed_pk"])}
    rec_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(rec_disp["compressed_pk"], rec_arb["compressed_pk"])}
    ward_owner_pol = {"kind": "multisig", "m": 2, "pks": sorted([ga_own["compressed_pk"], gb_own["compressed_pk"]])}
    ga_pin = make_name_pin("id/guardian-a", "t4-ga-reg", {"kind": "key", "pk": ga_own["compressed_pk"]})
    gb_pin = make_name_pin("id/guardian-b", "t4-gb-reg", {"kind": "key", "pk": gb_own["compressed_pk"]})
    salt_ga = h32("t4-salt-ga")
    salt_gb = h32("t4-salt-gb")

    # Note: routine_read requires 1-of-2, while effect_grant requires 2-of-2!
    # So downgrading agent/guardian-message to routine_read with 1 guardian MUST refuse GUARDIAN_QUORUM_UNMET!
    quorums = {
        "contract_assent": {"den": 1, "min": 2, "num": 1},
        "custody_change": {"den": 1, "min": 2, "num": 1},
        "effect_grant": {"den": 1, "min": 2, "num": 1},
        "routine_read": {"den": 2, "min": 1, "num": 1},
    }
    origin_payload = {
        "binding_seal": {"script_policy": {"kind": "key", "pk": bind_seal["compressed_pk"]}, "txid": h32("t4-bind-seal"), "vout": 0},
        "claims": {
            "config_sha256": h32("t4-nova-config"),
            "intended_name": "id/agent-nova",
            "intended_owner_policy": ward_owner_pol,
        },
        "genesis": GENESIS_MAIN,
        "guardian_policy": {
            "appointment_delay_blocks": 144,
            "arbiter_pk": arb["compressed_pk"],
            "challenger_pk": chal["compressed_pk"],
            "disposer_pk": disp["compressed_pk"],
            "quorums": quorums,
            "revision": 1,
            "revision_size": 2,
            "roster_seal": {"script_policy": vac_pol, "txid": h32("t4-roster-seal"), "vout": 0},
            "slots": [
                {"initial_guardian_commitment": sl.clause_commit(salt_ga, ga_pin), "slot": 1, "vacant_utxo": {"txid": h32("t4-s1-vac"), "vout": 0}},
                {"initial_guardian_commitment": sl.clause_commit(salt_gb, gb_pin), "slot": 2, "vacant_utxo": {"txid": h32("t4-s2-vac"), "vout": 0}},
            ],
        },
        "issuer": make_role_pin("id/agent-registry", "t4-reg-op", reg_own, [reg_cred["xonly_pk"]]),
        "name_recovery": {
            "arbiter_pk": rec_arb["compressed_pk"],
            "delay_blocks": 1008,
            "disposer_pk": rec_disp["compressed_pk"],
            "mode": "dual_party_delayed",
            "recovery_seal": {"script_policy": rec_pol, "txid": h32("t4-recov-seal"), "vout": 0},
        },
        "network": "main",
        "origin_class": "agent",
        "request_sha256": h32("t4-mat-req"),
        "status_seal": {"script_policy": stat_pol, "txid": h32("t4-stat-seal"), "vout": 0},
        "subject_initial_key": ward_init["xonly_pk"],
        "type": "seallink-origin/1",
    }
    origin_env = sl.sign_envelope(origin_payload, [reg_cred["_sk"]])
    origin_id = sl.object_id(origin_payload)
    origin_txid = h32("t4-origin-tx")

    binding = {
        "binding_mode": "initial",
        "genesis": GENESIS_MAIN,
        "name": "id/agent-nova",
        "network": "main",
        "origin_id": origin_id,
        "owner_policy": ward_owner_pol,
        "registration": {"txid": h32("t4-nova-reg"), "vout": 0},
        "seq": 1,
        "type": "seallink-name-binding/1",
    }
    binding_txid = h32("t4-bind-tx")

    # Initial activation 0x12 for Slot 1 (guardian-a) and Slot 2 (guardian-b)
    act_pol_a = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp["compressed_pk"], ga_seal["compressed_pk"])}
    act_pol_b = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp["compressed_pk"], gb_seal["compressed_pk"])}
    ga_rec = sl.sign_envelope(
        {
            "active_policy": act_pol_a, "active_vout": 0, "activation_mode": "initial",
            "genesis": GENESIS_MAIN, "guardian": ga_pin, "issuer": origin_payload["issuer"],
            "network": "main", "origin_id": origin_id, "prev_outpoint": {"txid": h32("t4-s1-vac"), "vout": 0},
            "revision": 1, "slot": 1, "term": {"mode": "indefinite"}, "type": "seallink-guardian/1",
        },
        [reg_cred["_sk"]],
    )
    gb_rec = sl.sign_envelope(
        {
            "active_policy": act_pol_b, "active_vout": 0, "activation_mode": "initial",
            "genesis": GENESIS_MAIN, "guardian": gb_pin, "issuer": origin_payload["issuer"],
            "network": "main", "origin_id": origin_id, "prev_outpoint": {"txid": h32("t4-s2-vac"), "vout": 0},
            "revision": 1, "slot": 2, "term": {"mode": "indefinite"}, "type": "seallink-guardian/1",
        },
        [reg_cred["_sk"]],
    )
    ga_assent = sl.sign_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
            "nonce": h32("t4-ga-assent-nonce"), "party_id": "slot-1", "party_name": "id/guardian-a", "party_role": "guardian",
            "target_id": sl.object_id(ga_rec["payload"]), "target_type": "seallink-guardian/1", "type": "seallink-assent/1",
        },
        [ga_gr["_sk"]],
    )
    gb_assent = sl.sign_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
            "nonce": h32("t4-gb-assent-nonce"), "party_id": "slot-2", "party_name": "id/guardian-b", "party_role": "guardian",
            "target_id": sl.object_id(gb_rec["payload"]), "target_type": "seallink-guardian/1", "type": "seallink-assent/1",
        },
        [gb_gr["_sk"]],
    )
    ga_init_tx = h32("t4-ga-init-0x12")
    gb_init_tx = h32("t4-gb-init-0x12")

    raw_msg = b"Rotate workspace target branch to release/v2 and pause external pushes."
    msg_sha = sl.sha256(raw_msg).hex()
    recent_blk = h32("t4-recent-blk")
    grant_seal_pol = {"kind": "key", "pk": grant_seal["compressed_pk"]}
    grant_seal_tx = h32("t4-grant-seal-tx")

    # Ward grant (valid effect_grant, signed by both active slots via guardian_approvals[])
    ward_grant_payload = {
        "capabilities": [
            {
                "action": "agent/guardian-message",
                "target": f"ward:{origin_id}",
                "where": {
                    "channel": {"eq": "nostr-dm"},
                    "delivery_mode": {"eq": "strict_drop"},
                    "message_sha256": {"hash_eq": msg_sha},
                    "origin_id": {"eq": origin_id},
                    "subject_ward_name": {"eq": "id/agent-nova"},
                },
            }
        ],
        "executor": {"key": station_rcpt["xonly_pk"], "name": "id/station-nova"},
        "genesis": GENESIS_MAIN,
        "guardian_context": {"event_class": "effect_grant", "origin_id": origin_id, "revision": 1, "ward_name": "id/agent-nova"},
        "issuer": {"name": "id/agent-nova", "owner_policy": ward_owner_pol, "registration": binding["registration"]},
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 750000,
        "recent_block": recent_blk,
        "recipient": {"key": bridge_req["xonly_pk"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": grant_seal_pol, "txid": grant_seal_tx, "vout": 0}},
        "type": "seallink-grant/1",
    }
    ward_grant_ok = sl.sign_guardian_envelope(
        ward_grant_payload,
        [
            {"slot": 1, "revision": 1, "guardian_name": "id/guardian-a", "signers": [ga_gr["_sk"]]},
            {"slot": 2, "revision": 1, "guardian_name": "id/guardian-b", "signers": [gb_gr["_sk"]]},
        ],
    )
    ward_grant_ok_id = sl.object_id(ward_grant_payload)
    iss_ok_tx = h32("t4-iss-ok-tx")
    iss_ok_opret = sl.encode_opreturn(
        0x01,
        sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(ward_grant_ok), "grant_id": ward_grant_ok_id, "type": "seallink-issuance/1"}).hex(),
    ).hex()

    # Downgraded ward grant claiming event_class = "routine_read" with only 1 slot -> MUST refuse GUARDIAN_QUORUM_UNMET!
    ward_grant_down_p = copy.deepcopy(ward_grant_payload)
    ward_grant_down_p["guardian_context"]["event_class"] = "routine_read"
    ward_grant_down = sl.sign_guardian_envelope(
        ward_grant_down_p,
        [{"slot": 1, "revision": 1, "guardian_name": "id/guardian-a", "signers": [ga_gr["_sk"]]}],
    )
    ward_grant_down_id = sl.object_id(ward_grant_down_p)
    iss_down_tx = h32("t4-iss-down-tx")
    iss_down_opret = sl.encode_opreturn(
        0x01,
        sl.signing_digest({"genesis": GENESIS_MAIN, "grant_content_addr": sl.content_addr(ward_grant_down), "grant_id": ward_grant_down_id, "type": "seallink-issuance/1"}).hex(),
    ).hex()

    base_args = {
        "channel": "nostr-dm",
        "delivery_mode": "strict_drop",
        "message_sha256": msg_sha,
        "origin_id": origin_id,
        "revision": 1,
        "subject_ward_name": "id/agent-nova",
    }
    inv_unauth = sl.sign_envelope(
        {
            "action": "agent/guardian-message", "arguments": base_args,
            "executor": {"key": station_rcpt["xonly_pk"], "name": "id/station-nova"},
            "exp": 1795220500, "genesis": GENESIS_MAIN, "iat": 1795220000, "network": "main",
            "nonce": h32("t4-inv-n1"), "proof_path": [{"grant_id": ward_grant_ok_id, "issuance_txid": iss_ok_tx}],
            "target": f"ward:{origin_id}", "type": "seallink-invocation/1",
        },
        [stranger["_sk"]],
    )
    inv_inactive = sl.sign_envelope(
        {
            "action": "agent/guardian-message", "arguments": base_args,
            "executor": {"key": station_rcpt["xonly_pk"], "name": "id/station-nova"},
            "exp": 1795220500, "genesis": GENESIS_MAIN, "iat": 1795220000, "network": "main",
            "nonce": h32("t4-inv-n2"), "proof_path": [{"grant_id": ward_grant_ok_id, "issuance_txid": iss_ok_tx}],
            "target": f"ward:{origin_id}", "type": "seallink-invocation/1",
        },
        [bridge_req["_sk"]],
    )
    inv_downgraded = sl.sign_envelope(
        {
            "action": "agent/guardian-message", "arguments": base_args,
            "executor": {"key": station_rcpt["xonly_pk"], "name": "id/station-nova"},
            "exp": 1795220500, "genesis": GENESIS_MAIN, "iat": 1795220000, "network": "main",
            "nonce": h32("t4-inv-n3"), "proof_path": [{"grant_id": ward_grant_down_id, "issuance_txid": iss_down_tx}],
            "target": f"ward:{origin_id}", "type": "seallink-invocation/1",
        },
        [bridge_req["_sk"]],
    )
    inv_valid = sl.sign_envelope(
        {
            "action": "agent/guardian-message", "arguments": base_args,
            "executor": {"key": station_rcpt["xonly_pk"], "name": "id/station-nova"},
            "exp": 1795220500, "genesis": GENESIS_MAIN, "iat": 1795220000, "network": "main",
            "nonce": h32("t4-inv-n4"), "proof_path": [{"grant_id": ward_grant_ok_id, "issuance_txid": iss_ok_tx}],
            "target": f"ward:{origin_id}", "type": "seallink-invocation/1",
        },
        [bridge_req["_sk"]],
    )

    frame_obj = {
        "channel": "nostr-dm",
        "grant_id": ward_grant_ok_id,
        "invocation_id": sl.object_id(inv_valid["payload"]),
        "message_sha256": msg_sha,
        "origin_id": origin_id,
        "recorded_at": 1795220020,
        "revision": 1,
        "subject_ward_name": "id/agent-nova",
        "verified_guardians": ["id/guardian-a", "id/guardian-b"],
        "verified_slots": [1, 2],
    }
    gm_result = {
        "delivered": True,
        "frame_sha256": sl.content_addr(frame_obj),
        "message_sha256": msg_sha,
        "recorded_at": 1795220020,
        "verified_guardians": ["id/guardian-a", "id/guardian-b"],
        "verified_slots": [1, 2],
    }
    rcpt_ok = sl.sign_envelope(
        {
            "action": "agent/guardian-message",
            "executor_name": "id/station-nova",
            "genesis": GENESIS_MAIN,
            "grant_id": ward_grant_ok_id,
            "invocation_id": sl.object_id(inv_valid["payload"]),
            "network": "main",
            "outcome": "executed",
            "recorded_at": 1795220020,
            "result_sha256": sl.content_addr(gm_result),
            "tip_hash": h32("t4-tip-750010"),
            "tip_height": 750010,
            "type": "seallink-receipt/1",
        },
        [station_rcpt["_sk"]],
    )

    # Initial chain: Slot 1 active, Slot 2 NOT yet activated (for step 2 GUARDIAN_INACTIVE) -> then patch activates Slot 2!
    initial_chain = {
        "network": "main",
        "genesis": GENESIS_MAIN,
        "tip_height": 750010,
        "tip_hash": h32("t4-tip-750010"),
        "tip_header_time": 1795220000,
        "tip_median_time_past": 1795219900,
        "tip_first_sight": 1795220005,
        "now": 1795220020,
        "clock_watermark": 1795219000,
        "best_header_height": 750010,
        "in_ibd": False,
        "txindex": True,
        "node_reachable": True,
        "observation_bracket": {
            "consistent": True,
            "start": {"height": 750010, "hash": h32("t4-tip-750010")},
            "end": {"height": 750010, "hash": h32("t4-tip-750010")},
        },
        "comparison_peers": [{"id": "observer-1", "healthy": True, "height": 750010, "hash_at_tip": h32("t4-tip-750010")}],
        "blocks": {recent_blk: 749990},
        "names": {
            "id/agent-registry": sv.make_name_history(
                "id/agent-registry", {"txid": h32("t4-reg-op"), "vout": 0}, {"kind": "key", "pk": reg_own["compressed_pk"]},
                {"link": {"cred": reg_cred["xonly_pk"]}}, first_height=748000, update_height=748500,
            ),
            "id/agent-nova": sv.make_name_history(
                "id/agent-nova", binding["registration"], ward_owner_pol,
                {"link": {"origin": origin_id}}, first_height=749005, update_height=749015,
            ),
            "id/guardian-a": sv.make_name_history(
                "id/guardian-a", ga_pin["registration"], ga_pin["owner_policy"],
                {"link": {"grant": ga_gr["xonly_pk"]}}, first_height=748000, update_height=748600,
            ),
            "id/guardian-b": sv.make_name_history(
                "id/guardian-b", gb_pin["registration"], gb_pin["owner_policy"],
                {"link": {"grant": gb_gr["xonly_pk"]}}, first_height=748000, update_height=748600,
            ),
        },
        "txs": {
            origin_txid: {"confirmed_height": 749000, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(origin_env)).hex(), "outputs": {}},
            h32("t4-bind-seal"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex({"kind": "key", "pk": bind_seal["compressed_pk"]}), "spent_by_txid": binding_txid}}},
            binding_txid: {"confirmed_height": 749010, "inputs": [sv.make_segwit_input(h32("t4-bind-seal"), 0)], "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(binding)).hex(), "outputs": {}},
            h32("t4-stat-seal"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(stat_pol)}}},
            h32("t4-recov-seal"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(rec_pol)}}},
            h32("t4-roster-seal"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(vac_pol)}}},
            h32("t4-s1-vac"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(vac_pol), "spent_by_txid": ga_init_tx}}},
            h32("t4-s2-vac"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(vac_pol)}}},
            ga_init_tx: {"confirmed_height": 749020, "opreturn_hex": sl.encode_opreturn(0x12, sl.content_addr(ga_rec)).hex(), "outputs": {"0": {"script_pubkey_hex": spk_hex(act_pol_a)}}},
            grant_seal_tx: {
                "confirmed_height": 749995,
                "inputs": [sv.make_segwit_input(h32("t4-gseal-fund"), 0)],
                "outputs": {"0": {"script_pubkey_hex": spk_hex(grant_seal_pol)}, "1": {"script_pubkey_hex": spk_hex(grant_seal_pol)}},
            },
            iss_ok_tx: {"confirmed_height": 749998, "inputs": [sv.make_segwit_input(grant_seal_tx, 1)], "opreturn_hex": iss_ok_opret, "outputs": {}},
            iss_down_tx: {"confirmed_height": 749998, "inputs": [sv.make_segwit_input(grant_seal_tx, 1)], "opreturn_hex": iss_down_opret, "outputs": {}},
        },
    }
    activate_s2_patch = {
        "txs": {
            h32("t4-s2-vac"): {"confirmed_height": 749000, "outputs": {"0": {"script_pubkey_hex": spk_hex(vac_pol), "spent_by_txid": gb_init_tx}}},
            gb_init_tx: {"confirmed_height": 749025, "opreturn_hex": sl.encode_opreturn(0x12, sl.content_addr(gb_rec)).hex(), "outputs": {"0": {"script_pubkey_hex": spk_hex(act_pol_b)}}},
        }
    }
    exec_cfg = {
        "name": "id/station-nova",
        "key": station_rcpt["xonly_pk"],
        "actions": ["agent/guardian-message"],
        "pinned_ward_origin_id": origin_id,
    }
    origin_bundle = {
        "origin": origin_env,
        "origin_anchor_txid": origin_txid,
        "name_binding": binding,
        "name_binding_txid": binding_txid,
        "guardian_records": [ga_rec, gb_rec],
        "guardian_assents": [ga_assent, gb_assent],
        "roster_records": [],
        "initial_guardian_disclosures": {
            "1": {"salt_hex": salt_ga, "name_pin": ga_pin},
            "2": {"salt_hex": salt_gb, "name_pin": gb_pin},
        },
    }
    jid = h32("t4-station-nova-journal")

    ag_reg_issuer_pin = {k: origin_env["payload"]["issuer"][k] for k in ("name", "owner_policy", "registration")}
    # Live-execute all 4 steps through Tier1Verifier!
    v = sv.Tier1Verifier(trusted_origin_issuer_pins=[ag_reg_issuer_pin])
    ch = sv.ChainView(initial_chain)
    jr = sv.FencedJournal.from_dict({"journal_id": jid})
    bundle_ok = {"grants": [ward_grant_ok], "origin_bundle": origin_bundle}
    bundle_down = {"grants": [ward_grant_down], "origin_bundle": origin_bundle}

    s1 = v.verify_invocation(inv_unauth, bundle_ok, ch, jr, exec_cfg, raw_message_bytes=raw_msg)
    assert s1.verdict == "REFUSE" and s1.refusal_code == "WIRE_SIGNATURE", s1

    s2 = v.verify_invocation(inv_inactive, bundle_ok, ch, jr, exec_cfg, raw_message_bytes=raw_msg)
    assert s2.verdict == "REFUSE" and s2.refusal_code == "GUARDIAN_INACTIVE", s2

    ch.apply_patch(activate_s2_patch)
    s3 = v.verify_invocation(inv_downgraded, bundle_down, ch, jr, exec_cfg, raw_message_bytes=raw_msg)
    assert s3.verdict == "REFUSE" and s3.refusal_code == "GUARDIAN_QUORUM_UNMET", s3

    s4 = v.verify_invocation(inv_valid, bundle_ok, ch, jr, exec_cfg, receipt_env_for_cache=rcpt_ok, raw_message_bytes=raw_msg)
    assert s4.verdict == "ADMIT" and s4.details["derived_event_class"] == "effect_grant" and s4.details["verified_slots"] == [1, 2], s4
    assert s4.details["frame_sha256"] == gm_result["frame_sha256"], (s4.details["frame_sha256"], gm_result["frame_sha256"])

    return {
        "suite": "trace-04-agent-guardian-intake",
        "version": VERSION,
        "description": "Executable PROFILE-agent-v1 trace for agent/guardian-message: strict_drop rejects unauthenticated caller (WIRE_SIGNATURE), inactive guardian slot (GUARDIAN_INACTIVE), downgraded routine_read event_class (GUARDIAN_QUORUM_UNMET), and admits 2-of-2 effect_grant guardian_approvals[] into an Authority Frame.",
        "executor_config": exec_cfg,
        "trusted_origin_issuer_pins": [ag_reg_issuer_pin],
        "initial_chain_state": initial_chain,
        "initial_journal_state": {"journal_id": jid},
        "raw_message_utf8": raw_msg.decode("utf-8"),
        "origin": envelope_record(origin_env, "schemas/origin.schema.json"),
        "origin_anchor_txid": origin_txid,
        "name_binding": unsigned_record(binding, "schemas/guardian.schema.json#/$defs/NameBinding"),
        "name_binding_txid": binding_txid,
        "initial_guardian_disclosures": {
            "1": {"salt_hex": salt_ga, "name_pin": ga_pin, "commitment_hex": sl.clause_commit(salt_ga, ga_pin)},
            "2": {"salt_hex": salt_gb, "name_pin": gb_pin, "commitment_hex": sl.clause_commit(salt_gb, gb_pin)},
        },
        "guardian_records": [
            envelope_record(ga_rec, "schemas/guardian.schema.json#/$defs/GuardianRecord"),
            envelope_record(gb_rec, "schemas/guardian.schema.json#/$defs/GuardianRecord"),
        ],
        "guardian_assents": [
            envelope_record(ga_assent, "schemas/contract.schema.json#/$defs/Assent"),
            envelope_record(gb_assent, "schemas/contract.schema.json#/$defs/Assent"),
        ],
        "ward_grant_valid": envelope_record(ward_grant_ok, "schemas/grant.schema.json"),
        "ward_grant_downgraded": envelope_record(ward_grant_down, "schemas/grant.schema.json"),
        "steps": [
            {
                "step": 1,
                "name": "strict_drop_unauthenticated_sender",
                "grant_ref": "ward_grant_valid",
                "invocation": envelope_record(inv_unauth, "schemas/invocation.schema.json#/$defs/Invocation"),
                "profile_args_schema": "schemas/profile-agent.schema.json#/$defs/AgentGuardianMessageArgs",
                "expected_verdict": "REFUSE",
                "expected_refusal": "WIRE_SIGNATURE",
                "dropped_before_model_context": True,
            },
            {
                "step": 2,
                "name": "inactive_slot_2_refused",
                "grant_ref": "ward_grant_valid",
                "invocation": envelope_record(inv_inactive, "schemas/invocation.schema.json#/$defs/Invocation"),
                "profile_args_schema": "schemas/profile-agent.schema.json#/$defs/AgentGuardianMessageArgs",
                "expected_verdict": "REFUSE",
                "expected_refusal": "GUARDIAN_INACTIVE",
            },
            {
                "step": 3,
                "name": "downgraded_routine_read_event_class_refused",
                "chain_patch": activate_s2_patch,
                "grant_ref": "ward_grant_downgraded",
                "invocation": envelope_record(inv_downgraded, "schemas/invocation.schema.json#/$defs/Invocation"),
                "profile_args_schema": "schemas/profile-agent.schema.json#/$defs/AgentGuardianMessageArgs",
                "expected_verdict": "REFUSE",
                "expected_refusal": "GUARDIAN_QUORUM_UNMET",
            },
            {
                "step": 4,
                "name": "valid_effect_grant_2of2_admitted_to_authority_frame",
                "grant_ref": "ward_grant_valid",
                "invocation": envelope_record(inv_valid, "schemas/invocation.schema.json#/$defs/Invocation"),
                "profile_args_schema": "schemas/profile-agent.schema.json#/$defs/AgentGuardianMessageArgs",
                "result_object": unsigned_record(gm_result, "schemas/profile-agent.schema.json#/$defs/AgentGuardianMessageResult"),
                "expected_verdict": "ADMIT",
                "derived_event_class": "effect_grant",
                "verified_slots": [1, 2],
                "verified_guardians": ["id/guardian-a", "id/guardian-b"],
                "receipt": envelope_record(rcpt_ok, "schemas/invocation.schema.json#/$defs/Receipt"),
                "journal_write": {
                    "entry": unsigned_record(s4.journal_writes[0]["entry"], "schemas/invocation.schema.json#/$defs/JournalEntry"),
                    "c_before": s4.journal_writes[0]["c_before"],
                    "c_after": s4.journal_writes[0]["c_after"],
                },
                "settlement_journal_write": {
                    "entry": unsigned_record(s4.journal_writes[1]["entry"], "schemas/invocation.schema.json#/$defs/JournalEntry"),
                    "c_before": s4.journal_writes[1]["c_before"],
                    "c_after": s4.journal_writes[1]["c_after"],
                },
            },
        ],
    }


def main() -> int:
    sl.self_test()
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    suites = [
        ("wire-jcs-and-hashes.json", build_wire_vectors()),
        ("ledger-scripts-and-opreturn.json", build_ledger_vectors()),
        ("constraints-and-schemas.json", build_constraints_vectors()),
        ("trace-01-mail-offline-revoke.json", build_trace_01_mail()),
        ("trace-02-guardian-succession-assent.json", build_trace_02_guardian()),
        ("trace-03-delegation-pool-single-use.json", build_trace_03_delegation()),
        ("trace-04-agent-guardian-intake.json", build_trace_04_agent_guardian_intake()),
        ("refusal-coverage-matrix.json", rm.build_refusal_coverage_matrix()),
        ("security-conformance.json", sec.build_security_conformance_suite()),
    ]
    for fname, data in suites:
        out = VECTORS_DIR / fname
        text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        out.write_text(text, encoding="utf-8")
        print(f"Wrote vectors/{fname} ({len(text.encode('utf-8'))} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
