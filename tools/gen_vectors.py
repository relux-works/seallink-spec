#!/usr/bin/env python3
"""
Deterministic Conformance Vector Generator for SealLink v1.0.0-draft.1.

Produces six JSON vector files under vectors/:
  1. wire-jcs-and-hashes.json
  2. ledger-scripts-and-opreturn.json
  3. constraints-and-schemas.json
  4. trace-01-mail-offline-revoke.json
  5. trace-02-guardian-succession-assent.json
  6. trace-03-delegation-pool-single-use.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import seallink_ref as sl

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

    # JCS positive cases
    utf16_obj = {"\ue000": "private", "\U0001f512": "surrogate-pair", "a": 1, "b": "line1"}
    multiline_obj = {"terms_text": "Line 1\nLine 2"}
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
            "id": "jcs-max-integers",
            "rule": "SL-WIRE-007",
            "input_utf8": sl.jcs_encode(max_int_obj).decode("utf-8"),
            "expected": "VALID",
        },
    ]

    # Depth-17 nested object
    deep: Any = {"v": 1}
    for _ in range(16):
        deep = {"a": deep}

    negative_jcs = [
        {"id": "neg-depth-17", "rule": "SL-WIRE-001", "input_hex": json.dumps(deep, separators=(",", ":")).encode("utf-8").hex(), "expected_refusal": "WIRE_SIZE"},
        {"id": "neg-utf8-bom", "rule": "SL-WIRE-002", "input_hex": (b"\xef\xbb\xbf" + b'{"a":1}').hex(), "expected_refusal": "WIRE_JSON"},
        {"id": "neg-trailing-space", "rule": "SL-WIRE-002", "input_hex": b'{"a":1}\n'.hex(), "expected_refusal": "WIRE_NOT_CANONICAL"},
        {"id": "neg-array-root", "rule": "SL-WIRE-002", "input_hex": b'[1,2]'.hex(), "expected_refusal": "WIRE_JSON"},
        {"id": "neg-duplicate-key", "rule": "SL-WIRE-003", "input_hex": b'{"a":1,"a":2}'.hex(), "expected_refusal": "WIRE_DUPLICATE"},
        {"id": "neg-null-value", "rule": "SL-WIRE-004", "input_hex": b'{"a":null}'.hex(), "expected_refusal": "WIRE_VALUE"},
        {"id": "neg-float-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":1.5}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-negative-number", "rule": "SL-WIRE-007", "input_hex": b'{"a":-1}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-uint53-overflow", "rule": "SL-WIRE-007", "input_hex": b'{"a":9007199254740992}'.hex(), "expected_refusal": "WIRE_NUMBER"},
        {"id": "neg-del-char", "rule": "SL-WIRE-005", "input_hex": b'{"a":"x\x7fy"}'.hex(), "expected_refusal": "WIRE_STRING"},
        {"id": "neg-c1-control", "rule": "SL-WIRE-005", "input_hex": '{"a":"x\u0085y"}'.encode("utf-8").hex(), "expected_refusal": "WIRE_STRING"},
        {"id": "neg-lf-in-non-multiline", "rule": "SL-WIRE-005", "input_hex": b'{"name":"id/a\\nb"}'.hex(), "expected_refusal": "WIRE_STRING"},
        {"id": "neg-unsorted-keys", "rule": "SL-WIRE-006", "input_hex": b'{"b":1,"a":2}'.hex(), "expected_refusal": "WIRE_NOT_CANONICAL"},
        {"id": "neg-pretty-whitespace", "rule": "SL-WIRE-006", "input_hex": b'{"a": 1}'.hex(), "expected_refusal": "WIRE_NOT_CANONICAL"},
    ]

    # Verify every JCS vector live
    for c in positive_jcs:
        ok, res = sl.jcs_validate(c["input_utf8"].encode("utf-8"))
        assert ok, f"positive JCS failed: {c['id']} -> {res}"
    for c in negative_jcs:
        ok, code = sl.jcs_validate(bytes.fromhex(c["input_hex"]))
        assert (not ok) and code == c["expected_refusal"], f"negative JCS mismatch {c['id']}: got {(ok, code)}"

    # Clause commitment vector (SPEC-01 §5)
    salt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    clause_obj = {"text": "Room inspection"}
    clause_digest = sl.clause_commit(salt, clause_obj)

    # Three hashes + SignatureSet (1-of-1 and 2-of-3) + re-signing invariance
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
        [(k1["_sk"], None, None), (k2["_sk"], None, None)],
        policy_pks=[k1["xonly_pk"], k2["xonly_pk"], k3["xonly_pk"]],
        m=2,
    )
    env_2of3_b = sl.sign_envelope(
        grant_payload,
        [(k1["_sk"], None, None), (k3["_sk"], None, None)],
        policy_pks=[k1["xonly_pk"], k2["xonly_pk"], k3["xonly_pk"]],
        m=2,
    )
    assert sl.object_id(env_2of3_a["payload"]) == sl.object_id(env_2of3_b["payload"])
    assert sl.content_addr(env_2of3_a) != sl.content_addr(env_2of3_b)
    assert sl.verify_envelope_signatures(env_2of3_a)[0]
    assert sl.verify_envelope_signatures(env_2of3_b)[0]

    # Negative SignatureSets
    bad_5of2 = json.loads(json.dumps(env_2of3_a))
    bad_5of2["signatures"]["policy"] = {"m": 5, "pks": sorted([k1["xonly_pk"], k2["xonly_pk"]])}
    bad_dup_sig = json.loads(json.dumps(env_2of3_a))
    bad_dup_sig["signatures"]["sigs"] = [bad_dup_sig["signatures"]["sigs"][0], bad_dup_sig["signatures"]["sigs"][0]]
    bad_flipped = json.loads(json.dumps(env_2of3_a))
    s0 = bad_flipped["signatures"]["sigs"][0]["sig"]
    bad_flipped["signatures"]["sigs"][0]["sig"] = ("0" if s0[0] != "0" else "1") + s0[1:]

    return {
        "suite": "wire-jcs-and-hashes",
        "version": "1.0.0-draft.1",
        "description": "Restricted RFC 8785 JCS positive/negative vectors, 3 hashes, clause_commit, and BIP-340 SignatureSet checks.",
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
                {"id": "sigset-tampered-sig", "object": bad_flipped, "expected_refusal": "WIRE_SIGNATURE"},
            ],
        },
    }


def build_ledger_vectors() -> dict[str, Any]:
    ka = make_keypair("ledger-a")
    kb = make_keypair("ledger-b")
    kc = make_keypair("ledger-c")
    arb = make_keypair("ledger-arbiter")
    chal = make_keypair("ledger-challenger")

    policies = [
        {"id": "p2wpkh-key", "policy": {"kind": "key", "pk": ka["compressed_pk"]}},
        {"id": "p2wsh-multisig-2of3", "policy": {"kind": "multisig", "m": 2, "pks": sorted([ka["compressed_pk"], kb["compressed_pk"], kc["compressed_pk"]])}},
        {"id": "p2wsh-either-of-2", "policy": {"kind": "branch", "template": "either_of_2", "keys": {"a": ka["compressed_pk"], "b": kb["compressed_pk"]}}},
        {"id": "p2wsh-both-of-2", "policy": {"kind": "branch", "template": "both_of_2", "keys": {"a": ka["compressed_pk"], "b": kb["compressed_pk"]}}},
        {"id": "p2wsh-arbiter-or-both", "policy": {"kind": "branch", "template": "arbiter_or_both", "keys": {"a": ka["compressed_pk"], "b": kb["compressed_pk"], "arbiter": arb["compressed_pk"]}}},
        {"id": "p2wsh-single-use", "policy": {"kind": "branch", "template": "single_use_1_of_2", "keys": {"issuer": ka["compressed_pk"], "grantee": kb["compressed_pk"]}}},
        {"id": "p2wsh-guardian-pending", "policy": {"kind": "branch", "template": "guardian_slot_pending", "keys": {"disposer": ka["compressed_pk"], "challenger": chal["compressed_pk"], "guardian": kb["compressed_pk"]}, "delay_blocks": 144}},
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

    # Three Namecoin prefix operations (NAME_NEW, NAME_FIRSTUPDATE, NAME_UPDATE)
    spk_p2wpkh, _ = sl.compile_script_policy(policies[0]["policy"])
    spk_2of2, _ = sl.compile_script_policy(policies[3]["policy"])
    name_bytes = b"id/alice"
    rand_bytes = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")
    val_bytes = sl.jcs_encode({"link": {"grant": ka["xonly_pk"]}, "m": {"h": h32("alice-manifest"), "s": 1}})
    new_hash20 = sl.hash160(rand_bytes + name_bytes)

    s_new = sl.encode_name_output("NAME_NEW", spk_p2wpkh, hash20=new_hash20)
    s_first = sl.encode_name_output("NAME_FIRSTUPDATE", spk_2of2, name=name_bytes, rand=rand_bytes, value=val_bytes)
    s_upd = sl.encode_name_output("NAME_UPDATE", spk_2of2, name=name_bytes, value=val_bytes)

    assert sl.parse_name_output(s_new)["op"] == "NAME_NEW"
    assert sl.parse_name_output(s_first)["op"] == "NAME_FIRSTUPDATE"
    assert sl.parse_name_output(s_upd)["op"] == "NAME_UPDATE"

    # Negative Namecoin script: NAME_FIRSTUPDATE with wrong cleanup OP_2DROP OP_DROP
    bad_first = bytes([sl.OP_NAME_FIRSTUPDATE]) + sl._push_data(name_bytes) + sl._push_data(rand_bytes) + sl._push_data(val_bytes) + bytes([sl.OP_2DROP, sl.OP_DROP]) + spk_2of2
    # Negative Namecoin script: legacy P2PKH tail
    legacy_p2pkh = bytes.fromhex("76a914" + "11" * 20 + "88ac")
    bad_legacy = sl.encode_name_output("NAME_UPDATE", legacy_p2pkh, name=name_bytes, value=val_bytes)

    # Merkle batch 0x02 (5 leaves -> exercises odd-node promotion at level 0 and level 1!)
    batch_items = [h32(f"batch-item-{i}") for i in range(5)]
    root_hex, proofs = sl.build_merkle_tree(batch_items)
    for d, pf in proofs.items():
        assert sl.verify_merkle_proof(pf)

    # Tampered proof
    first_leaf = sorted(batch_items, key=bytes.fromhex)[0]
    tampered_pf = json.loads(json.dumps(proofs[first_leaf]))
    tampered_pf["steps"][0]["hash"] = h32("tampered-sibling")
    assert not sl.verify_merkle_proof(tampered_pf)

    # SLNK OP_RETURN frames
    opreturn_frames = []
    for act, label, loc, ptr, hc in [
        (0x01, "GRANT_ISSUANCE_private", 0x00, None, None),
        (0x01, "GRANT_ISSUANCE_blossom", 0x01, h32("blossom-ptr"), None),
        (0x02, "BATCH_ANCHOR_merkle5", 0x00, None, None),
        (0x04, "NOTARY_ACT", 0x00, None, None),
        (0x07, "CONTRACT_ANCHOR", 0x00, None, None),
        (0x09, "ORIGIN_OR_CRED_ANCHOR", 0x00, None, None),
        (0x0B, "KEY_COMPROMISE_BREAK", 0x00, None, 750050),
        (0x0C, "NAME_BINDING", 0x00, None, None),
        (0x0D, "GUARDIAN_APPOINTMENT", 0x00, None, None),
        (0x0E, "GUARDIAN_ACTIVATION", 0x00, None, None),
        (0x0F, "GUARDIAN_ROSTER_TRANSITION", 0x00, None, None),
        (0x10, "RECOVERY_CANCEL", 0x00, None, None),
        (0x11, "SINGLE_USE_CONSUMPTION", 0x00, None, None),
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

    # Reserved action 0x06 raw script (must refuse CHAIN_FRAME_INVALID)
    reserved_06_hex = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x06, 0x22, 0x01]) + bytes.fromhex(h32("bad06")) + bytes([0x00])).hex()

    return {
        "suite": "ledger-scripts-and-opreturn",
        "version": "1.0.0-draft.1",
        "description": "Namecoin prefix scripts (NAME_NEW/NAME_FIRSTUPDATE/NAME_UPDATE), ScriptPolicy compilations, P2A CPFP, SLNK OP_RETURN frames, and 5-leaf Merkle batch 0x02 proofs.",
        "script_policies": compiled_policies,
        "namecoin_prefix_scripts": {
            "positive": [
                {"id": "nc-name-new-p2wpkh", "script_hex": s_new.hex(), "parsed": sl.parse_name_output(s_new)},
                {"id": "nc-name-firstupdate-p2wsh", "script_hex": s_first.hex(), "parsed": sl.parse_name_output(s_first)},
                {"id": "nc-name-update-p2wsh", "script_hex": s_upd.hex(), "parsed": sl.parse_name_output(s_upd)},
            ],
            "negative": [
                {"id": "nc-bad-firstupdate-cleanup", "script_hex": bad_first.hex(), "expected_refusal": "CHAIN_SCRIPT_UNSUPPORTED"},
                {"id": "nc-legacy-p2pkh-tail", "script_hex": bad_legacy.hex(), "expected_refusal": "CHAIN_SCRIPT_UNSUPPORTED"},
            ],
        },
        "cpfp_anchor": {
            "rule": "SL-LDGR-013",
            "p2a_script_pubkey_hex": sl.P2A_SCRIPTPUBKEY.hex(),
            "p2a_bytes": len(sl.P2A_SCRIPTPUBKEY),
            "forbidden_bare_op_true_hex": "51",
        },
        "opreturn_frames": opreturn_frames,
        "opreturn_negative": [
            {"id": "reserved-action-0x06", "script_hex": reserved_06_hex, "expected_refusal": "CHAIN_FRAME_INVALID"}
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

    # Negative schema & semantic fixtures
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

    # 1. Neither issuer nor parent (schema reject)
    g_no_issuer = json.loads(json.dumps(base_grant_payload))
    del g_no_issuer["issuer"]
    # 2. Both issuer and parent (schema reject)
    g_both_issuer_parent = json.loads(json.dumps(base_grant_payload))
    g_both_issuer_parent["parent"] = {"grant_id": h32("p1"), "ordinal": 1}
    # 3. executor_ref + quotas (schema reject)
    g_ref_with_quota = json.loads(json.dumps(base_grant_payload))
    del g_ref_with_quota["executor"]
    g_ref_with_quota["executor_ref"] = {"label": "work", "provider_of": "id/alice", "service_type": "mail"}
    g_ref_with_quota["capabilities"][0]["quotas"] = [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/alice:work", "unit": "requests", "window": "term"}]
    # 4. Populated extensions (schema reject + WIRE_CONSTRAINT)
    g_with_ext = json.loads(json.dumps(base_grant_payload))
    g_with_ext["capabilities"][0]["extensions"] = {"future": True}
    # 5. window_only with 1000000-block window (semantic reject WIRE_INTEGER)
    g_window_too_long = json.loads(json.dumps(base_grant_payload))
    g_window_too_long["revocation"] = {"mode": "window_only"}
    g_window_too_long["not_after_height"] = 1750000
    # 6. Unsorted `in` array (semantic reject WIRE_CONSTRAINT)
    g_unsorted_in = json.loads(json.dumps(base_grant_payload))
    g_unsorted_in["capabilities"][0]["where"] = {"folder": {"in": ["Zeta", "Alpha"]}}
    # 7. terms_text on mechanical mail/read grant (semantic reject GRANT_TEXT_FORBIDDEN)
    g_mech_text = json.loads(json.dumps(base_grant_payload))
    g_mech_text["terms_text"] = "Only read polite invoices."

    def wrap(p: dict[str, Any]) -> dict[str, Any]:
        return sl.sign_envelope(p, [(k_grant["_sk"], None, None)])

    return {
        "suite": "constraints-and-schemas",
        "version": "1.0.0-draft.1",
        "description": "All 7 Constraint Algebra predicates (match + conservative narrowing) and negative schema/semantic fixtures.",
        "predicate_matches": pred_match_cases,
        "predicate_narrowing": narrowing_cases,
        "negative_schema_fixtures": [
            {"id": "grant-neither-issuer-nor-parent", "schema": "schemas/grant.schema.json", "object": wrap(g_no_issuer), "expected_refusal": "WIRE_MEMBER"},
            {"id": "grant-both-issuer-and-parent", "schema": "schemas/grant.schema.json", "object": wrap(g_both_issuer_parent), "expected_refusal": "WIRE_MEMBER"},
            {"id": "grant-executor-ref-with-quota", "schema": "schemas/grant.schema.json", "object": wrap(g_ref_with_quota), "expected_refusal": "GRANT_EXECUTOR_REF_FORBIDDEN"},
            {"id": "grant-populated-extensions", "schema": "schemas/grant.schema.json", "object": wrap(g_with_ext), "expected_refusal": "WIRE_CONSTRAINT"},
        ],
        "negative_semantic_fixtures": [
            {"id": "grant-window-only-exceeds-12-blocks", "schema": "schemas/grant.schema.json", "object": wrap(g_window_too_long), "expected_refusal": "WIRE_INTEGER"},
            {"id": "grant-unsorted-in-predicate", "schema": "schemas/grant.schema.json", "object": wrap(g_unsorted_in), "expected_refusal": "WIRE_CONSTRAINT"},
            {"id": "grant-terms-text-on-mechanical-mail", "schema": "schemas/grant.schema.json", "object": wrap(g_mech_text), "expected_refusal": "GRANT_TEXT_FORBIDDEN"},
        ],
    }


def build_trace_01_mail() -> dict[str, Any]:
    alice_owner = make_keypair("t1-alice-owner")
    alice_grant = make_keypair("t1-alice-grant")
    alice_seal = make_keypair("t1-alice-seal")
    host_owner = make_keypair("t1-host-owner")
    host_receipt = make_keypair("t1-host-receipt")
    agent_req = make_keypair("t1-agent-req")

    host_pin = make_name_pin("id/mail-host-a", "t1-host-reg", {"kind": "key", "pk": host_owner["compressed_pk"]})

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
        "recent_block": h32("t1-recent-block-749990"),
        "recipient": {"key": agent_req["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "revocable",
            "mode": "seal",
            "seal": {"script_policy": {"kind": "key", "pk": alice_seal["compressed_pk"]}, "txid": h32("t1-seal-tx"), "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    grant_env = sl.sign_envelope(grant_payload, [(alice_grant["_sk"], None, None)])
    grant_id = sl.object_id(grant_payload)
    issuance = {
        "genesis": GENESIS_MAIN,
        "grant_content_addr": sl.content_addr(grant_env),
        "grant_id": grant_id,
        "type": "seallink-issuance/1",
    }
    issuance_txid = h32("t1-issuance-tx")
    issuance_opreturn_hex = sl.encode_opreturn(0x01, sl.signing_digest(issuance).hex(), 0x00).hex()

    # Step 1: Admitted mail/read on folder "Invoices" (Alice offline)
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
    inv_ok = sl.sign_envelope(inv_ok_payload, [(agent_req["_sk"], None, None)])
    inv_ok_id = sl.object_id(inv_ok_payload)
    mail_result = {
        "folder": "Invoices",
        "message_id": "msg-2026-001",
        "mime_sha256": sl.sha256(b"From: billing@vendor.example\r\nSubject: Invoice #1\r\n\r\nTotal: 100 EUR\r\n").hex(),
        "received_at": 1795219000,
        "sender_domain": "vendor.example",
        "size_bytes": "72",
    }
    result_sha = sl.content_addr(mail_result)
    rcpt_ok_payload = {
        "action": "mail/read",
        "executor_name": "id/mail-host-a",
        "genesis": GENESIS_MAIN,
        "grant_id": grant_id,
        "invocation_id": inv_ok_id,
        "network": "main",
        "outcome": "executed",
        "recorded_at": 1795220010,
        "result_sha256": result_sha,
        "tip_hash": h32("t1-tip-750010"),
        "tip_height": 750010,
        "type": "seallink-receipt/1",
    }
    rcpt_ok = sl.sign_envelope(rcpt_ok_payload, [(host_receipt["_sk"], None, None)])

    # Journal c(0) -> c(1) nonce
    jid = h32("t1-host-journal")
    c0 = sl.journal_commit_init(jid)
    je1 = {
        "body": {"expires_at": 1795220300, "invocation_id": inv_ok_id, "nonce": h32("t1-nonce-1"), "scope": "invocation"},
        "journal_id": jid,
        "kind": "nonce",
        "pos": 1,
        "prev_commitment": c0,
        "type": "seallink-journal-entry/1",
    }
    c1 = sl.journal_commit_step(c0, je1)

    # Step 2: Refused mail/read on folder "Personal" -> INVOKE_CONSTRAINT_FAILED (non-closing)
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
    inv_bad = sl.sign_envelope(inv_bad_payload, [(agent_req["_sk"], None, None)])
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
        [(host_receipt["_sk"], None, None)],
    )

    # Step 3: Alice spends seal -> host observes mempool spend -> writes closure c(1) -> c(2)
    revoke_txid = h32("t1-revoke-spend-tx")
    je2 = {
        "body": {
            "cause": "SEAL_SPENT",
            "observed_at": 1795220500,
            "observed_height": 750011,
            "spend_txid": revoke_txid,
            "subject_id": grant_id,
            "subject_kind": "grant",
        },
        "journal_id": jid,
        "kind": "closure",
        "pos": 2,
        "prev_commitment": c1,
        "type": "seallink-journal-entry/1",
    }
    c2 = sl.journal_commit_step(c1, je2)

    # Step 4: Subsequent request on "Invoices" -> exact single refusal code GRANT_CLOSED
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
    inv_after = sl.sign_envelope(inv_after_payload, [(agent_req["_sk"], None, None)])
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
        [(host_receipt["_sk"], None, None)],
    )

    return {
        "suite": "trace-01-mail-offline-revoke",
        "version": "1.0.0-draft.1",
        "description": "RFC 8448-style trace: mail/read via executor_ref while issuer offline, constraint refusal, mempool seal spend closure, and exact GRANT_CLOSED refusal.",
        "ledger_state": {
            "network": "main",
            "genesis": GENESIS_MAIN,
            "alice_name_value": unsigned_record(alice_name_val, "schemas/name-value.schema.json"),
            "host_name_value": unsigned_record(host_name_val, "schemas/name-value.schema.json"),
            "alice_manifest": unsigned_record(alice_manifest, "schemas/manifest.schema.json"),
            "host_manifest": unsigned_record(host_manifest, "schemas/manifest.schema.json"),
            "issuance_txid": issuance_txid,
            "issuance_opreturn_hex": issuance_opreturn_hex,
            "revoke_spend_txid": revoke_txid,
        },
        "grant": envelope_record(grant_env, "schemas/grant.schema.json"),
        "issuance": unsigned_record(issuance, "schemas/grant.schema.json#/$defs/IssuancePrep"),
        "steps": [
            {
                "step": 1,
                "name": "offline_issuer_admit_mail_read",
                "invocation": envelope_record(inv_ok, "schemas/invocation.schema.json#/$defs/Invocation"),
                "profile_args_schema": "schemas/profile-mail.schema.json#/$defs/MailReadArgs",
                "result_object": unsigned_record(mail_result, "schemas/profile-mail.schema.json#/$defs/MailReadResult"),
                "expected_verdict": "ADMIT",
                "receipt": envelope_record(rcpt_ok, "schemas/invocation.schema.json#/$defs/Receipt"),
                "journal_write": {
                    "entry": unsigned_record(je1, "schemas/invocation.schema.json#/$defs/JournalEntry"),
                    "c_before": c0,
                    "c_after": c1,
                },
            },
            {
                "step": 2,
                "name": "forbidden_folder_refused_non_closing",
                "invocation": envelope_record(inv_bad, "schemas/invocation.schema.json#/$defs/Invocation"),
                "profile_args_schema": "schemas/profile-mail.schema.json#/$defs/MailReadArgs",
                "expected_verdict": "REFUSE",
                "expected_refusal": "INVOKE_CONSTRAINT_FAILED",
                "receipt": envelope_record(rcpt_bad, "schemas/invocation.schema.json#/$defs/Receipt"),
            },
            {
                "step": 3,
                "name": "witnessed_mempool_seal_spend_closure",
                "spend_txid": revoke_txid,
                "journal_write": {
                    "entry": unsigned_record(je2, "schemas/invocation.schema.json#/$defs/JournalEntry"),
                    "c_before": c1,
                    "c_after": c2,
                },
            },
            {
                "step": 4,
                "name": "post_revocation_request_returns_exact_grant_closed",
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
    vacant_policy = {"kind": "branch", "template": "both_of_2", "keys": {"a": disposer["compressed_pk"], "b": arbiter["compressed_pk"]}}
    status_policy = {"kind": "branch", "template": "either_of_2", "keys": {"a": status_cap["compressed_pk"], "b": status_end["compressed_pk"]}}
    recovery_policy = {"kind": "branch", "template": "both_of_2", "keys": {"a": recov_disp["compressed_pk"], "b": recov_arb["compressed_pk"]}}

    p_old_pin = make_name_pin("id/parent-a", "t2-parent-a-reg", {"kind": "key", "pk": p_old_owner["compressed_pk"]})
    p2_pin = make_name_pin("id/parent-b", "t2-parent-b-reg", {"kind": "key", "pk": p2_owner["compressed_pk"]})
    g_new_pin = make_name_pin("id/guardian-carol", "t2-carol-reg", {"kind": "key", "pk": g_new_owner["compressed_pk"]})

    salt_maj = h32("t2-salt-majority")
    salt_g1 = h32("t2-salt-g1")
    salt_g2 = h32("t2-salt-g2")
    maj_obj = {"majority_unix": 2363241600}  # 2044-11-22

    quorums_v1 = {
        "contract_assent": {"den": 1, "min": 2, "num": 1},
        "custody_change": {"den": 1, "min": 2, "num": 1},
        "effect_grant": {"den": 2, "min": 1, "num": 1},
        "governance_change": {"den": 1, "min": 2, "num": 1},
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
        "claims_salt": h32("t2-claims-salt"),
        "genesis": GENESIS_MAIN,
        "guardian_policy": {
            "appointment_delay_blocks": 144,
            "arbiter": {"kind": "key", "pk": arbiter["compressed_pk"]},
            "disposer": {"kind": "key", "pk": disposer["compressed_pk"]},
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
            "arbiter": {"kind": "key", "pk": recov_arb["compressed_pk"]},
            "delay_blocks": 1008,
            "disposer": {"kind": "key", "pk": recov_disp["compressed_pk"]},
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
    origin_env = sl.sign_envelope(origin_payload, [(reg_cred["_sk"], None, None)])
    origin_id = sl.object_id(origin_payload)
    origin_opreturn_hex = sl.encode_opreturn(0x09, sl.content_addr(origin_env), 0x00).hex()

    # NameBinding (0x0c)
    binding = {
        "genesis": GENESIS_MAIN,
        "name": "id/child-leo",
        "network": "main",
        "origin_id": origin_id,
        "owner_policy": ward_owner_policy,
        "registration": {"txid": h32("t2-leo-reg-tx"), "vout": 0},
        "seq": 1,
        "type": "seallink-name-binding/1",
    }
    binding_opreturn_hex = sl.encode_opreturn(0x0C, sl.object_id(binding), 0x00).hex()

    # Stage 1: Acyclic successor appointment for slot 1 (after parent-a halted slot 1 -> vacant_after_halt)
    vacant_after_halt = {"txid": h32("t2-slot1-vac-after-halt"), "vout": 0}
    pending_policy = {
        "delay_blocks": 144,
        "keys": {"challenger": challenger["compressed_pk"], "disposer": disposer["compressed_pk"], "guardian": g_new_seal["compressed_pk"]},
        "kind": "branch",
        "template": "guardian_slot_pending",
    }
    active_policy = {"keys": {"a": disposer["compressed_pk"], "b": g_new_seal["compressed_pk"]}, "kind": "branch", "template": "either_of_2"}
    guardian_payload = {
        "active_policy": active_policy,
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
        "term": {"ceiling_height": 1750000, "mode": "calendar", "not_after_unix": 2363241600},
        "type": "seallink-guardian/1",
    }
    guardian_env = sl.sign_envelope(guardian_payload, [(reg_cred["_sk"], None, None)])
    guardian_id = sl.object_id(guardian_payload)
    guardian_assent = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "network": "main",
            "nonce": h32("t2-carol-assent-nonce"),
            "party_name": "id/guardian-carol",
            "party_role": "guardian",
            "target_id": guardian_id,
            "target_type": "seallink-guardian/1",
            "type": "seallink-assent/1",
        },
        [(g_new_grant["_sk"], None, None)],
    )
    app_txid = h32("t2-appointment-tx-0x0d")
    app_opreturn_hex = sl.encode_opreturn(0x0D, sl.content_addr(guardian_env), 0x00).hex()
    derived_pending_outpoint = {"txid": app_txid, "vout": 0}

    # Stage 2: Activation (0x0e) after 144 blocks -> deterministic active outpoint (T_act, 0)
    act_txid = h32("t2-activation-tx-0x0e")
    act_opreturn_hex = sl.encode_opreturn(0x0E, guardian_id, 0x00).hex()
    derived_active_outpoint = {"txid": act_txid, "vout": 0}

    # Roster revision 1 -> 2 (revision_size = 1, retaining slot 1 active Carol after slot 2 closed)
    quorums_v2 = {
        "contract_assent": {"den": 1, "min": 1, "num": 1},
        "custody_change": {"den": 1, "min": 1, "num": 1},
        "effect_grant": {"den": 1, "min": 1, "num": 1},
        "governance_change": {"den": 1, "min": 1, "num": 1},
        "routine_read": {"den": 1, "min": 1, "num": 1},
    }
    roster_payload = {
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
    roster_env = sl.sign_envelope(roster_payload, [(reg_cred["_sk"], None, None)])
    roster_opreturn_hex = sl.encode_opreturn(0x0F, sl.content_addr(roster_env), 0x00).hex()

    # Contract requiring ward assent
    clause0_salt = h32("t2-clause0-salt")
    clause0_obj = {"max_tuition_eur": "1200", "text": "Music school enrollment\nTerm 2026-2027"}
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
                "role": "student_ward",
                "signing_policy": {"m": 1, "pks": [g_new_grant["xonly_pk"]]},
            },
            {
                "name_pin": make_name_pin("id/music-school", "t2-school-reg", {"kind": "key", "pk": counterparty_owner["compressed_pk"]}),
                "role": "school",
                "signing_policy": {"m": 1, "pks": [counterparty_grant["xonly_pk"]]},
            },
        ],
        "profile": "org.seallink/enrollment-v1",
        "seal": {
            "script_policy": {"keys": {"a": contract_seal_a["compressed_pk"], "b": contract_seal_b["compressed_pk"]}, "kind": "branch", "template": "either_of_2"},
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
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": contract_id,
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [(ward_grant["_sk"], None, None)],
    )

    # Verdict 2: Former halted guardian parent-a signs assent -> GUARDIAN_INACTIVE
    assent_old_guardian = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": origin_id, "revision": 2, "ward_name": "id/child-leo"},
            "issued_at": 1795220000,
            "network": "main",
            "nonce": h32("t2-assent-old-g"),
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": contract_id,
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [(p_old_grant["_sk"], 1, 2)],
    )

    # Verdict 3: Active new guardian Carol signs assent with guardian_context -> ADMIT
    assent_new_guardian = sl.sign_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": origin_id, "revision": 2, "ward_name": "id/child-leo"},
            "issued_at": 1795220000,
            "network": "main",
            "nonce": h32("t2-assent-new-g"),
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": contract_id,
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [(g_new_grant["_sk"], 1, 2)],
    )

    return {
        "suite": "trace-02-guardian-succession-assent",
        "version": "1.0.0-draft.1",
        "description": "RFC 8448-style trace: private origin/1 + status_seal, acyclic Stage 1 (0x0d) -> Stage 2 (0x0e) guardian activation, roster transition (0x0f), and ward contract assent (ward alone refused, old guardian refused, new guardian admitted).",
        "origin": envelope_record(origin_env, "schemas/origin.schema.json"),
        "origin_opreturn_hex": origin_opreturn_hex,
        "initial_guardian_1_disclosure": {"salt_hex": salt_g1, "name_pin": p_old_pin, "commitment_hex": sl.clause_commit(salt_g1, p_old_pin)},
        "name_binding": unsigned_record(binding, "schemas/guardian.schema.json#/$defs/NameBinding"),
        "name_binding_opreturn_hex": binding_opreturn_hex,
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
            "active_script_pubkey_hex": sl.compile_script_policy(active_policy)[0].hex(),
        },
        "roster_transition": {
            "roster_record": envelope_record(roster_env, "schemas/guardian.schema.json#/$defs/GuardianRoster"),
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
                "verified_slot": 1,
                "verified_revision": 2,
                "derived_event_class": "contract_assent",
            },
        ],
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

    pool_q = {"kind": "seallink/count", "max": "10", "resource": "station:fleet:tools", "unit": "calls", "window": "term"}
    row_q_a = {"kind": "seallink/count", "max": "2", "resource": "station:fleet:tools", "unit": "calls", "window": "term"}
    row_q_b = {"kind": "seallink/count", "max": "2", "resource": "station:fleet:tools", "unit": "calls", "window": "term"}

    parent_payload = {
        "capabilities": [{"action": "agent/tool", "quotas": [pool_q], "target": "station:fleet:tools"}],
        "delegate": {
            "child_seal_key": child_seal_key["compressed_pk"],
            "groups": [
                {
                    "ranges": [{"count": 3, "first": 0, "script_policy": {"kind": "key", "pk": row_coin_k["compressed_pk"]}, "txid": h32("t3-rows-a-tx")}],
                    "template": {
                        "capabilities": [
                            {
                                "action": "agent/tool",
                                "quotas": [row_q_a],
                                "target": "station:fleet:tools",
                                "where": {"tool_name": {"in": ["git-diff", "pytest"]}},
                            }
                        ],
                        "executor": {"key": st_a_rcpt["xonly_pk"], "name": "id/station-a"},
                        "notary_mode": "none",
                        "recipient_rule": {"key": w1_req["xonly_pk"], "mode": "exact_key"},
                    },
                },
                {
                    "ranges": [{"count": 2, "first": 0, "script_policy": {"kind": "key", "pk": row_coin_k["compressed_pk"]}, "txid": h32("t3-rows-b-tx")}],
                    "template": {
                        "capabilities": [
                            {
                                "action": "agent/tool",
                                "quotas": [row_q_b],
                                "target": "station:fleet:tools",
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
            "pools": [pool_q],
        },
        "executor": {"key": st_a_rcpt["xonly_pk"], "name": "id/station-a"},
        "genesis": GENESIS_MAIN,
        "issuer": make_role_pin("id/org-treasury", "t3-org-reg", org_owner, [org_grant["xonly_pk"]]),
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 750000,
        "recent_block": h32("t3-recent-block"),
        "recipient": {"key": w1_req["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "revocable",
            "mode": "seal",
            "seal": {"script_policy": {"kind": "key", "pk": parent_seal["compressed_pk"]}, "txid": h32("t3-parent-seal-tx"), "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    ok_r85, totals_r85 = sl.check_whole_parent_budget_r85(parent_payload["delegate"])
    assert ok_r85 and sl.check_disjoint_ranges_r86(parent_payload)

    # Negative R8.5 counterexample (3*3 + 2*2 = 13 > 10)
    bad_r85 = json.loads(json.dumps(parent_payload))
    bad_r85["delegate"]["groups"][0]["template"]["capabilities"][0]["quotas"][0]["max"] = "3"
    assert not sl.check_whole_parent_budget_r85(bad_r85["delegate"])[0]

    # Negative R8.6 counterexample (overlapping row range)
    bad_r86 = json.loads(json.dumps(parent_payload))
    bad_r86["delegate"]["groups"][1]["ranges"][0]["txid"] = h32("t3-rows-a-tx")
    bad_r86["delegate"]["groups"][1]["ranges"][0]["first"] = 2
    assert not sl.check_disjoint_ranges_r86(bad_r86)

    parent_env = sl.sign_envelope(parent_payload, [(org_grant["_sk"], None, None)])
    parent_id = sl.object_id(parent_payload)
    parent_issuance_txid = h32("t3-parent-issuance-tx")

    # Child 1 (ordinal 1, single_use_1_of_2 on station-a)
    c1_seal_policy = {"keys": {"grantee": w1_seal["compressed_pk"], "issuer": child_seal_key["compressed_pk"]}, "kind": "branch", "template": "single_use_1_of_2"}
    c1_payload = {
        "capabilities": [
            {
                "action": "agent/tool",
                "quotas": [{"kind": "seallink/count", "max": "1", "resource": "station:fleet:tools", "unit": "calls", "window": "term"}],
                "target": "station:fleet:tools",
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
        "recent_block": h32("t3-recent-block"),
        "recipient": {"key": w1_req["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "single_use",
            "mode": "seal",
            "seal": {"script_policy": c1_seal_policy, "txid": h32("t3-c1-seal-tx"), "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    c1_env = sl.sign_envelope(c1_payload, [(del_key["_sk"], None, None)])
    c1_id = sl.object_id(c1_payload)
    c1_issuance_txid = h32("t3-c1-issuance-tx")

    # Acyclic single-use invocation (NO use_txid inside signed payload!)
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
        "target": "station:fleet:tools",
        "type": "seallink-invocation/1",
    }
    inv1_env = sl.sign_envelope(inv1_payload, [(w1_req["_sk"], None, None)])
    inv1_id = sl.object_id(inv1_payload)
    inv1_caddr = sl.content_addr(inv1_env)
    use_txid = h32("t3-use-tx-branch0")
    use_opreturn_hex = sl.encode_opreturn(0x11, inv1_caddr, 0x00).hex()

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
            "settlements": [{"kind": "seallink/count", "released": "0", "reserved": "1", "resource": "station:fleet:tools", "settled": "1", "unit": "calls"}],
            "tip_hash": h32("t3-tip-750110"),
            "tip_height": 750110,
            "type": "seallink-receipt/1",
        },
        [(st_a_rcpt["_sk"], None, None)],
    )

    # Journal entries for Child 1 single-use execution
    jid = h32("t3-station-a-journal")
    c0 = sl.journal_commit_init(jid)
    je1 = {
        "body": {
            "account": "row",
            "amount": "1",
            "bucket_id": "term",
            "grant_id": c1_id,
            "invocation_id": inv1_id,
            "quota_kind": "seallink/count",
            "recorded_at": 1795220045,
            "resource": "station:fleet:tools",
            "unit": "calls",
            "window": "term",
        },
        "journal_id": jid,
        "kind": "reservation",
        "pos": 1,
        "prev_commitment": c0,
        "type": "seallink-journal-entry/1",
    }
    c1_j = sl.journal_commit_step(c0, je1)
    je2 = {
        "body": {"grant_id": c1_id, "invocation_id": inv1_id, "outcome": "executed", "receipt_sha256": sl.content_addr(rcpt1), "recorded_at": 1795220050, "released": "0", "settled": "1"},
        "journal_id": jid,
        "kind": "settlement",
        "pos": 2,
        "prev_commitment": c1_j,
        "type": "seallink-journal-entry/1",
    }
    c2_j = sl.journal_commit_step(c1_j, je2)
    je3 = {
        "body": {"grant_id": c1_id, "invocation_id": inv1_id, "receipt_sha256": sl.content_addr(rcpt1), "recorded_at": 1795220050, "use_txid": use_txid},
        "journal_id": jid,
        "kind": "single-use-consumed",
        "pos": 3,
        "prev_commitment": c2_j,
        "type": "seallink-journal-entry/1",
    }
    c3_j = sl.journal_commit_step(c2_j, je3)
    je4 = {
        "body": {"cause": "SINGLE_USE_CONSUMED", "observed_at": 1795220050, "observed_height": 750110, "spend_txid": use_txid, "subject_id": c1_id, "subject_kind": "grant"},
        "journal_id": jid,
        "kind": "closure",
        "pos": 4,
        "prev_commitment": c3_j,
        "type": "seallink-journal-entry/1",
    }
    c4_j = sl.journal_commit_step(c3_j, je4)

    # New invocation with fresh nonce against already-consumed Child 1 -> INVOKE_REPLAY
    inv1_replay_new = sl.sign_envelope(
        {
            **inv1_payload,
            "iat": 1795220100,
            "nonce": h32("t3-inv1-second-nonce"),
        },
        [(w1_req["_sk"], None, None)],
    )

    # Child 2 (ordinal 4, station-b) revoked via issuer branch 1 spend -> SEAL_SPENT then GRANT_CLOSED
    c2_seal_policy = {"keys": {"grantee": w2_seal["compressed_pk"], "issuer": child_seal_key["compressed_pk"]}, "kind": "branch", "template": "single_use_1_of_2"}
    c2_payload = {
        "capabilities": [
            {
                "action": "agent/tool",
                "quotas": [{"kind": "seallink/count", "max": "1", "resource": "station:fleet:tools", "unit": "calls", "window": "term"}],
                "target": "station:fleet:tools",
                "where": {"tool_name": {"eq": "lint"}},
            }
        ],
        "executor": {"key": st_b_rcpt["xonly_pk"], "name": "id/station-b"},
        "genesis": GENESIS_MAIN,
        "network": "main",
        "not_after_height": 755000,
        "not_before_height": 750100,
        "parent": {"grant_id": parent_id, "ordinal": 4},
        "recent_block": h32("t3-recent-block"),
        "recipient": {"key": w2_req["xonly_pk"], "mode": "key"},
        "revocation": {
            "construction": "W",
            "kind": "single_use",
            "mode": "seal",
            "seal": {"script_policy": c2_seal_policy, "txid": h32("t3-c2-seal-tx"), "vout": 0},
        },
        "type": "seallink-grant/1",
    }
    c2_env = sl.sign_envelope(c2_payload, [(del_key["_sk"], None, None)])

    return {
        "suite": "trace-03-delegation-pool-single-use",
        "version": "1.0.0-draft.1",
        "description": "RFC 8448-style trace: parent delegation with 2 groups sharing 1 pool (R8.5 & R8.6 positive/negative), acyclic single-use branch-0 execution (0x11), crash replay idempotency, new-nonce replay refusal, and issuer branch-1 revocation.",
        "parent_grant": envelope_record(parent_env, "schemas/grant.schema.json"),
        "r85_aggregate_budget": {"passed": True, "pool_max": 10, "computed_totals": totals_r85},
        "r85_negative_parent": {"object": sl.sign_envelope(bad_r85, [(org_grant["_sk"], None, None)]), "expected_refusal": "GRANT_CHILD_WIDER"},
        "r86_negative_parent": {"object": sl.sign_envelope(bad_r86, [(org_grant["_sk"], None, None)]), "expected_refusal": "GRANT_ROW_INVALID"},
        "child_1_single_use": envelope_record(c1_env, "schemas/grant.schema.json"),
        "child_1_trace": {
            "invocation": envelope_record(inv1_env, "schemas/invocation.schema.json#/$defs/Invocation"),
            "profile_args_schema": "schemas/profile-agent.schema.json#/$defs/AgentToolArgs",
            "use_txid_wrapper": use_txid,
            "use_opreturn_0x11_hex": use_opreturn_hex,
            "step_a_mempool_unconfirmed": {"expected_verdict": "REFUSE", "expected_refusal": "CHAIN_DEPTH_INSUFFICIENT"},
            "step_b_confirmed_execute": {
                "expected_verdict": "ADMIT",
                "result_object": unsigned_record(tool_result, "schemas/profile-agent.schema.json#/$defs/AgentToolResult"),
                "receipt": envelope_record(rcpt1, "schemas/invocation.schema.json#/$defs/Receipt"),
                "remaining_row_1_calls": 1,
                "remaining_pool_calls": 9,
                "journal_chain": [
                    {"entry": unsigned_record(je1, "schemas/invocation.schema.json#/$defs/JournalEntry"), "c_before": c0, "c_after": c1_j},
                    {"entry": unsigned_record(je2, "schemas/invocation.schema.json#/$defs/JournalEntry"), "c_before": c1_j, "c_after": c2_j},
                    {"entry": unsigned_record(je3, "schemas/invocation.schema.json#/$defs/JournalEntry"), "c_before": c2_j, "c_after": c3_j},
                    {"entry": unsigned_record(je4, "schemas/invocation.schema.json#/$defs/JournalEntry"), "c_before": c3_j, "c_after": c4_j},
                ],
            },
            "step_c_crash_replay_same_invocation_id": {
                "expected_behavior": "RETURN_CACHED_RECEIPT_ZERO_SECOND_EFFECT",
                "cached_receipt_content_addr": sl.content_addr(rcpt1),
            },
            "step_d_new_nonce_replay": {
                "invocation": envelope_record(inv1_replay_new, "schemas/invocation.schema.json#/$defs/Invocation"),
                "expected_verdict": "REFUSE",
                "expected_refusal": "INVOKE_REPLAY",
            },
        },
        "child_2_issuer_revocation": {
            "grant": envelope_record(c2_env, "schemas/grant.schema.json"),
            "issuer_branch_1_spend_txid": h32("t3-c2-issuer-revoke-tx"),
            "first_observation_refusal": "SEAL_SPENT",
            "subsequent_request_refusal": "GRANT_CLOSED",
        },
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
    ]
    for fname, data in suites:
        out = VECTORS_DIR / fname
        text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        out.write_text(text, encoding="utf-8")
        print(f"Wrote vectors/{fname} ({len(text.encode('utf-8'))} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
