#!/usr/bin/env python3
"""
SealLink v1.0 Executable Pure-Python Reference Verifier Core.

Implements the normative verification state machines of SPEC-01 through SPEC-07
and PROFILE-mail-v1 / PROFILE-agent-v1 over a declarative in-memory ChainView
(deriving history, authorship, expiry, witness profile W, single-use branch,
0x0a/0x0b/0x10 frames, and handover transfers directly from structured records)
and a stateful hash-chained FencedJournal.

CRITICAL DESIGN PROPERTIES:
  1. Computes every verdict, refusal code, receipt outcome, and journal
     hash-chain delta strictly from protocol inputs and chain/journal state.
     NEVER reads any `expected_*` field from test vectors.
  2. Enforces Draft 2020-12 closed schemas (including profile action argument
     schemas) inside the wire ingress pipeline.
  3. Binds every signed protocol object (including origin/1, guardian/1,
     guardian-roster/1, capacity/1, end/1, and migration/1) to its
     authoritative on-chain role policy or manifest key (SL-WIRE-013 item 4).
"""

from __future__ import annotations

import copy
import hmac
import json
import re
import secrets
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import seallink_ref as sl

ROOT = Path(__file__).resolve().parent.parent

# Deterministic fixed precedence order for schema refusal codes (SPEC-01 §7, B-11)
SCHEMA_REFUSAL_PRECEDENCE: dict[str, int] = {
    "WIRE_DUPLICATE": 0,
    "WIRE_STRING": 1,
    "WIRE_TYPE": 2,
    "WIRE_MEMBER": 3,
    "WIRE_INTEGER": 4,
    "WIRE_KEY": 5,
    "WIRE_SIGNATURE": 6,
    "WIRE_CONSTRAINT": 7,
    "CHAIN_SCRIPT_UNSUPPORTED": 8,
}

# Load standard action profiles authoritatively from registry/actions.json (B-8, R3 M6)
def _load_action_profiles() -> dict[str, dict[str, Any]]:
    raw = json.loads((ROOT / "registry" / "actions.json").read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for entry in raw.get("actions", []):
        out[entry["action"]] = copy.deepcopy(entry)
    return out


def _load_refusal_codes() -> frozenset[str]:
    raw = json.loads((ROOT / "registry" / "refusal-codes.json").read_text(encoding="utf-8"))
    return frozenset(entry["code"] for entry in raw.get("codes", []))


ACTION_PROFILES: dict[str, dict[str, Any]] = _load_action_profiles()
REGISTERED_REFUSAL_CODES: frozenset[str] = _load_refusal_codes()

_FORBIDDEN_EXPORT_MEDIA_TYPES = frozenset({
    "application/x-pem-file",
    "application/pkcs8",
    "application/pkcs12",
    "application/x-pkcs12",
    "application/x-x509-key",
    "application/vnd.seallink.secret",
    "application/vnd.seallink.private-key",
    "application/vnd.seallink.execution-credential",
    "application/vnd.seallink.bearer-token",
    "application/vnd.seallink.active-grant",
    "application/x-seallink-secret",
    "private_key",
    "execution_credential",
    "bearer_token",
    "dkim_key",
    "tls_private_key",
    "active_grant",
})
_FORBIDDEN_EXPORT_DIR_PREFIXES = (".seallink/", "seallink-secrets/", "secrets/", "keys/")
_FORBIDDEN_EXPORT_EXTENSIONS = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".seed", ".mnemonic", ".env")
_FORBIDDEN_EXPORT_BASENAMES = frozenset({
    ".env",
    "private_key",
    "private-key",
    "execution_credential",
    "bearer_token",
    "dkim_key",
    "tls_private_key",
    "active_grant",
})


def _is_forbidden_export_item(item: dict[str, Any]) -> bool:
    """Structured execution-credential export blocklist (SPEC-07 §2.1); permits benign prose like notes/history-of-private-keys.md."""
    mt = str(item.get("media_type", "")).split(";", 1)[0].strip().lower()
    if mt in _FORBIDDEN_EXPORT_MEDIA_TYPES:
        return True
    p = str(item.get("path", "")).strip().lstrip("/").lower()
    if p.startswith(_FORBIDDEN_EXPORT_DIR_PREFIXES) or p.endswith(_FORBIDDEN_EXPORT_EXTENSIONS):
        return True
    base = p.rsplit("/", 1)[-1]
    stem = base.split(".", 1)[0] if "." in base and not base.startswith(".") else base
    return base in _FORBIDDEN_EXPORT_BASENAMES or stem in _FORBIDDEN_EXPORT_BASENAMES

_REGISTERED_TYPES_CACHE: dict[str, dict[str, Any]] | None = None
_SCHEMA_REGISTRY_STATE: dict[str, Any] | None = None


def registered_types() -> dict[str, dict[str, Any]]:
    global _REGISTERED_TYPES_CACHE
    if _REGISTERED_TYPES_CACHE is None:
        reg = json.loads((ROOT / "registry" / "object-types.json").read_text(encoding="utf-8"))
        _REGISTERED_TYPES_CACHE = {e["type"]: e for e in reg["types"]}
    return _REGISTERED_TYPES_CACHE


def _init_schema_store() -> dict[str, Any]:
    global _SCHEMA_REGISTRY_STATE
    if _SCHEMA_REGISTRY_STATE is not None:
        return _SCHEMA_REGISTRY_STATE
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError:
        _SCHEMA_REGISTRY_STATE = {"available": False, "validators": {}}
        return _SCHEMA_REGISTRY_STATE

    resources = []
    id_by_name: dict[str, str] = {}
    docs_by_uri: dict[str, dict[str, Any]] = {}
    for sp in sorted((ROOT / "schemas").glob("*.schema.json")):
        sdoc = json.loads(sp.read_text(encoding="utf-8"))
        uri = sdoc.get("$id", f"https://seallink.org/schemas/{sp.name}")
        id_by_name[sp.name] = uri
        docs_by_uri[uri] = sdoc
        resources.append((uri, Resource.from_contents(sdoc, default_specification=DRAFT202012)))
    registry = Registry().with_resources(resources)
    _SCHEMA_REGISTRY_STATE = {
        "available": True,
        "registry": registry,
        "id_by_name": id_by_name,
        "docs_by_uri": docs_by_uri,
        "validator_cls": Draft202012Validator,
        "validators": {},
    }
    return _SCHEMA_REGISTRY_STATE


def jsonschema_available() -> bool:
    return bool(_init_schema_store()["available"])


_SCALAR_ONEOF_DISCRIMINATORS: tuple[str, ...] = (
    "type",
    "kind",
    "template",
    "mode",
    "op",
    "command",
    "subject_kind",
    "activation_mode",
    "action",
    "lifecycle",
    "statement_kind",
    "binding_mode",
    "fraud_mode",
    "scheme",
    "key_alg",
    "healthy",
    "unparseable",
)


def _resolve_schema_node(node: Any, store: dict[str, Any] | None, *, depth: int = 0) -> dict[str, Any]:
    """Follow local or cross-schema $ref chains to inspect branch discriminator schemas."""
    if not isinstance(node, dict) or depth == 9 or not store or not store.get("available"):
        return node if isinstance(node, dict) else {}
    ref = node.get("$ref")
    if not isinstance(ref, str):
        return node
    docs_by_uri: dict[str, dict[str, Any]] = store.get("docs_by_uri", {})
    id_by_name: dict[str, str] = store.get("id_by_name", {})
    file_part, ptr = ref.split("#", 1) if "#" in ref else (ref, "")
    target_doc: dict[str, Any] | None = None
    if not file_part:
        # Local fragment ref: search across schema docs for exact $defs key
        parts = [p for p in ptr.split("/") if p]
        for sdoc in docs_by_uri.values():
            cur: Any = sdoc
            for seg in parts:
                cur = cur.get(seg) if isinstance(cur, dict) else None
            if isinstance(cur, dict):
                return _resolve_schema_node(cur, store, depth=depth + 1)
        return node
    base_uri = id_by_name.get(Path(file_part).name, file_part)
    target_doc = docs_by_uri.get(base_uri)
    if target_doc is None:
        return node
    cur = target_doc
    for seg in [p for p in ptr.split("/") if p]:
        cur = cur.get(seg) if isinstance(cur, dict) else None
    return _resolve_schema_node(cur, store, depth=depth + 1) if isinstance(cur, dict) else node


def _select_discriminated_branches(
    inst: Any,
    branches: list[Any],
    store: dict[str, Any] | None,
) -> list[int]:
    """Library-independent protocol-level discriminator selection for SealLink oneOf/anyOf (SPEC-01 §7, B-11)."""
    resolved = [_resolve_schema_node(b, store) for b in branches]
    # 1. JSON value type discrimination (str vs dict, e.g., BranchKeySpec, RoleKeyOrPolicyPin, nostr)
    if isinstance(inst, str):
        str_hits = [i for i, b in enumerate(resolved) if b.get("type") == "string"]
        if str_hits:
            return str_hits
        return []
    if not isinstance(inst, dict):
        return []

    obj_idxs = [i for i, b in enumerate(resolved) if b.get("type") == "object" or "properties" in b or "required" in b or "oneOf" in b]
    if not obj_idxs:
        return []

    # 2. Scalar const/enum discriminators (kind, template, mode, op, command, subject_kind, activation_mode, action, lifecycle, statement_kind)
    cands = list(obj_idxs)
    for dk in _SCALAR_ONEOF_DISCRIMINATORS:
        if dk not in inst:
            continue
        iv = inst[dk]
        matched: list[int] = []
        any_constrained = False
        for i in cands:
            props = resolved[i].get("properties", {})
            dprop = props.get(dk)
            if isinstance(dprop, dict) and ("const" in dprop or "enum" in dprop):
                any_constrained = True
                if ("const" in dprop and iv == dprop["const"]) or ("enum" in dprop and iv in dprop["enum"]):
                    matched.append(i)
        if any_constrained:
            cands = matched
            if not cands:
                return []

    # 3. DeviceThresholdPolicy `alg` discriminator (omitted vs p256/ed25519)
    has_alg_branches = any(
        isinstance(resolved[i].get("properties", {}).get("alg"), dict) for i in cands
    )
    if has_alg_branches:
        if "alg" in inst:
            cands = [
                i for i in cands
                if isinstance(resolved[i].get("properties", {}).get("alg"), dict)
                and (
                    resolved[i]["properties"]["alg"].get("const") == inst["alg"]
                    or inst["alg"] in resolved[i]["properties"]["alg"].get("enum", [])
                )
            ]
        else:
            cands = [i for i in cands if "alg" not in resolved[i].get("required", [])]
        if not cands:
            return []

    # 4. Structural presence discriminators (Grant/Assent envelope, RootGrant vs ChildGrant, Executor vs ExecutorRef, ContractParty, ConstraintPredicate)
    for key_present, key_alt in (
        ("guardian_approvals", "signatures"),
        ("guardian_context", "signatures"),
        ("parent", "issuer"),
        ("executor_ref", "executor"),
        ("ward_origin_id", "signing_policy"),
    ):
        req_present = [i for i in cands if key_present in resolved[i].get("required", [])]
        req_alt = [i for i in cands if key_alt in resolved[i].get("required", [])]
        if req_present and req_alt:
            if key_present in inst:
                cands = req_present
            elif key_alt in inst:
                cands = req_alt

    # 5. ConstraintPredicate single-operator-key discriminator
    if len(inst) == 1:
        sole_k = next(iter(inst.keys()))
        op_hits = [i for i in cands if resolved[i].get("required") == [sole_k]]
        if op_hits:
            return op_hits

    return cands


def _map_schema_error_to_refusal(
    err: Any,
    store: dict[str, Any] | None = None,
    parent_fallback: str | None = None,
) -> str:
    """Deterministically map a Draft 2020-12 ValidationError using library-independent discriminator selection & leaf-wins precedence (SPEC-01 §7, B-11)."""
    schema = getattr(err, "schema", None)
    validator = getattr(err, "validator", "")
    own_ann = schema.get("x-seallink-refusal") if isinstance(schema, dict) else None
    if not (isinstance(own_ann, str) and own_ann in SCHEMA_REFUSAL_PRECEDENCE):
        own_ann = None

    ctx = getattr(err, "context", None)
    if validator in ("oneOf", "anyOf") and ctx:
        branches = schema.get(validator, []) if isinstance(schema, dict) else []
        inst = getattr(err, "instance", None)
        by_branch: dict[Any, list[Any]] = {}
        for sub in ctx:
            sp = list(getattr(sub, "schema_path", []))
            br = sp[0] if sp else 0
            by_branch.setdefault(br, []).append(sub)

        disc_idxs = _select_discriminated_branches(inst, branches, store)
        disc_subs = [s for idx in disc_idxs for s in by_branch.get(idx, [])]
        if disc_subs:
            sub_codes = [_map_schema_error_to_refusal(s, store, own_ann or parent_fallback) for s in disc_subs]
            sub_codes.sort(key=lambda c: SCHEMA_REFUSAL_PRECEDENCE.get(c, 99))
            return sub_codes[0]

        # No branch matched discriminator (e.g., unknown ScriptPolicy kind/template, unknown ConstraintPredicate operator, or type mismatch)
        if own_ann is not None:
            return own_ann
        base_len = len(list(getattr(err, "path", [])))
        disc_ann_codes: list[str] = []
        for sub in ctx:
            spath = list(getattr(sub, "path", []))
            if len(spath) == base_len + 1 and spath[-1] in _SCALAR_ONEOF_DISCRIMINATORS:
                s_sch = getattr(sub, "schema", None)
                s_ann = s_sch.get("x-seallink-refusal") if isinstance(s_sch, dict) else None
                if isinstance(s_ann, str) and s_ann in SCHEMA_REFUSAL_PRECEDENCE:
                    disc_ann_codes.append(s_ann)
        if disc_ann_codes:
            disc_ann_codes.sort(key=lambda c: SCHEMA_REFUSAL_PRECEDENCE.get(c, 99))
            return disc_ann_codes[0]

    # Leaf error: JSON type/form mismatch on a member -> WIRE_MEMBER (unless enclosed by WIRE_CONSTRAINT)
    if validator == "type":
        return "WIRE_CONSTRAINT" if (own_ann == "WIRE_CONSTRAINT" or parent_fallback == "WIRE_CONSTRAINT") else "WIRE_MEMBER"
    if own_ann is not None:
        return own_ann
    return parent_fallback or "WIRE_MEMBER"


def validate_against_schema(schema_ref: str, obj: Any, *, require_jsonschema: bool = True) -> str | None:
    """Validate `obj` against a Draft 2020-12 schema ref using fixed x-seallink-refusal precedence (SPEC-01 §7)."""
    store = _init_schema_store()
    if not store["available"]:
        if require_jsonschema:
            raise RuntimeError("jsonschema package is required for Draft 2020-12 schema enforcement")
        return None
    val = store["validators"].get(schema_ref)
    if val is None:
        if "#" in schema_ref:
            spath, ptr = schema_ref.split("#", 1)
            base_uri = store["id_by_name"][Path(spath).name]
            sub = {"$ref": f"{base_uri}#{ptr}"}
        else:
            base_uri = store["id_by_name"][Path(schema_ref).name]
            sub = {"$ref": base_uri}
        val = store["validator_cls"](sub, registry=store["registry"])
        store["validators"][schema_ref] = val
    codes: list[str] = []
    for err in val.iter_errors(obj):
        codes.append(_map_schema_error_to_refusal(err, store))
    if not codes:
        return None
    codes.sort(key=lambda c: SCHEMA_REFUSAL_PRECEDENCE.get(c, 99))
    return codes[0]


def _outpoint_key(op: dict[str, Any]) -> str:
    return f"{op['txid']}:{op['vout']}"


def _name_pin_equal(a: dict[str, Any] | None, b: dict[str, Any] | None) -> bool:
    """Exact off-chain NamePin equality (name, registration, canonical JCS owner_policy) (Decision 4, L-4, B-14)."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    if a.get("name") != b.get("name") or a.get("registration") != b.get("registration"):
        return False
    try:
        sl.compile_script_policy(a["owner_policy"])
        sl.compile_script_policy(b["owner_policy"])
        return sl.jcs_encode(a["owner_policy"]) == sl.jcs_encode(b["owner_policy"])
    except (ValueError, KeyError, TypeError):
        return False


def _same_actor_reg(a: dict[str, Any] | None, b: dict[str, Any] | None) -> bool:
    """Cross-height actor identity equality on (name, registration) surviving routine cold owner_policy rotation (SL-CONT-012)."""
    return isinstance(a, dict) and isinstance(b, dict) and a.get("name") == b.get("name") and a.get("registration") == b.get("registration")


def _normalize_policy(p: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"m": p["m"], "pks": list(p["pks"])}
    if "alg" in p and p["alg"] != "bip340":
        out["alg"] = p["alg"]
    return out


def _policy_sha256(p: dict[str, Any]) -> str:
    return sl.sha256(sl.jcs_encode(_normalize_policy(p))).hex()


def _closure_subject_key(subject: dict[str, Any], cause: str | None = None) -> str:
    sk = subject.get("subject_kind")
    if sk in ("grant", "contract", "credential", "origin"):
        return f"{sk}:{subject['subject_id']}"
    if sk == "seal":
        return f"seal:{_outpoint_key(subject['outpoint'])}"
    if sk == "row":
        return f"row:{subject['grant_id']}:{subject['ordinal']}"
    if sk == "role":
        c_part = f"{cause}:" if cause else ""
        return f"role:{c_part}{subject['name']}:{_outpoint_key(subject['registration'])}:{subject['role']}:{subject['policy_sha256']}"
    if sk == "guardian_slot":
        return f"guardian_slot:{subject['origin_id']}:{subject['slot']}:{_outpoint_key(subject['outpoint'])}"
    if sk == "log":
        return f"log:{subject['log_id']}"
    return str(subject)


_CURVE_VALIDATORS: dict[str, Any] = {
    "bip340": sl.is_valid_xonly_pubkey,
    "p256": sl.is_valid_p256_compressed_pubkey,
    "ed25519": sl.is_valid_ed25519_pubkey,
    "secp256k1_comp": sl.is_valid_compressed_pubkey,
}
_XONLY_KEY_FIELDS = frozenset({"auth_key", "auth_pubkey", "receipt_key", "transport_key", "moderator_key", "subject_initial_key"})
_COMP_KEY_FIELDS = frozenset({"child_seal_key", "guardian_seal_pk"})
_BRANCH_KEY_FIELDS = frozenset({"disposer_pk", "arbiter_pk", "challenger_pk"})
_BRANCH_POLICY_KEYS = frozenset({"a", "b", "arbiter", "disposer", "challenger"})


def _collect_curve_key_errors(
    obj: Any,
    parent_key: str | None = None,
    root_type: str | None = None,
) -> tuple[bool, bool, bool]:
    """Return `(bad_wire_key, bad_wire_sig, bad_script_policy)` across every key, ThresholdPolicy, ScriptPolicy, & BranchKeySpec in `obj` (SPEC-01 §7, H-21, S-7, R2-10)."""
    if isinstance(obj, list):
        for item in obj:
            bk, bsig, bs = _collect_curve_key_errors(item, parent_key, root_type)
            if bk or bsig or bs:
                return bk, bsig, bs
        return False, False, False
    if not isinstance(obj, dict):
        return False, False, False

    bad_key = False
    bad_sig = False
    bad_script = False
    # 1. ScriptPolicy object
    if obj.get("kind") in ("key", "multisig", "branch"):
        kind = obj["kind"]
        if kind == "key":
            pk = obj.get("pk")
            bad_key = not isinstance(pk, str) or not sl.is_valid_compressed_pubkey(pk)
        elif kind == "multisig":
            bad_key = any(not isinstance(pk, str) or not sl.is_valid_compressed_pubkey(pk) for pk in obj.get("pks", []))
        elif kind == "branch":
            keys = obj.get("keys", {})
            if isinstance(keys, dict):
                for bk_name, bv in keys.items():
                    if bk_name in _BRANCH_POLICY_KEYS:
                        if any(not sl.is_valid_compressed_pubkey(pk) for pk in sl.branch_key_spec_pks(bv)):
                            bad_key = True
                        elif not sl.is_valid_branch_key_spec(bv):
                            if isinstance(bv, str):
                                bad_key = True
                            else:
                                bad_script = True
                    elif not isinstance(bv, str) or not sl.is_valid_compressed_pubkey(bv):
                        bad_key = True
        if not bad_key and not bad_script:
            try:
                sl.compile_script_policy(obj)
            except ValueError:
                bad_script = True
        return bad_key, False, bad_script

    # 2. ThresholdPolicy / DeviceThresholdPolicy / BranchKeySpec multisig (S-7, W-8)
    if "m" in obj and "pks" in obj and "kind" not in obj:
        if parent_key in _BRANCH_KEY_FIELDS:
            bad_key = any(not isinstance(pk, str) or not sl.is_valid_compressed_pubkey(pk) for pk in obj.get("pks", []))
            bad_script = (not bad_key) and (not sl.is_valid_branch_key_spec(obj))
            return bad_key, False, bad_script
        fn = _CURVE_VALIDATORS.get(obj.get("alg", "bip340"))
        pks = obj.get("pks", [])
        m_val = obj.get("m")
        bad_key = fn is None or not isinstance(pks, list) or any(not isinstance(pk, str) or not fn(pk) for pk in pks)
        if not bad_key:
            if not isinstance(m_val, int) or isinstance(m_val, bool) or m_val < 1 or m_val > len(pks) or pks != sorted(set(pks)):
                bad_sig = True
        return bad_key, bad_sig, False

    # 3. DeviceList entry & transport-binding statement subject
    if "alg" in obj and "key" in obj and "ceiling" in obj:
        fn = _CURVE_VALIDATORS.get(obj["alg"])
        if fn is not None and not fn(obj["key"]):
            return True, False, False
    if "key_alg" in obj and "key_hex" in obj:
        fn = _CURVE_VALIDATORS.get(obj["key_alg"])
        if fn is not None and not fn(obj["key_hex"]):
            return True, False, False

    # 4. Single named key fields & BranchKeySpec fields (skip open user maps: credential.claims, invocation.arguments; R2-10)
    for k, v in obj.items():
        if (k == "claims" and root_type == "seallink-credential/1") or (k == "arguments" and root_type == "seallink-invocation/1"):
            continue
        if k in _XONLY_KEY_FIELDS or (k == "key" and isinstance(v, str) and "alg" not in obj):
            if isinstance(v, str) and not sl.is_valid_xonly_pubkey(v):
                return True, False, False
        elif k in _COMP_KEY_FIELDS:
            if isinstance(v, str) and not sl.is_valid_compressed_pubkey(v):
                return True, False, False
        elif k in _BRANCH_KEY_FIELDS:
            if isinstance(v, str):
                if not sl.is_valid_compressed_pubkey(v):
                    return True, False, False
                continue
        bk, bsig, bs = _collect_curve_key_errors(v, k, root_type)
        if bk or bsig or bs:
            return bk, bsig, bs
    return False, False, False


def _validate_all_curve_keys(obj: Any, parent_key: str | None = None) -> str | None:
    """Step 9 wire check: validate curve points, embedded ThresholdPolicies, and ScriptPolicies (SPEC-01 §7, H-21, S-7)."""
    root_type = sl._extract_root_type(obj)
    bad_key, bad_sig, bad_script = _collect_curve_key_errors(obj, parent_key, root_type)
    if bad_key:
        return "WIRE_KEY"
    if bad_sig:
        return "WIRE_SIGNATURE"
    if bad_script:
        return "CHAIN_SCRIPT_UNSUPPORTED"
    return None


# ============================================================================
# Declarative ChainView Construction Helpers (Derived Evidence, Zero Booleans)
# ============================================================================


def make_segwit_input(
    prev_txid: str,
    prev_vout: int,
    *,
    sighash: int = 0x01,
    witness_extra: list[str] | None = None,
    script_sig_hex: str = "",
) -> dict[str, Any]:
    """Construct a structured native SegWit v0 transaction input for ChainView."""
    sig_hex = "3044" + ("aa" * 68) + f"{sighash:02x}"
    wit = [sig_hex] + (list(witness_extra) if witness_extra is not None else ["02" + ("bb" * 32)])
    return {
        "prev_txid": prev_txid,
        "prev_vout": prev_vout,
        "script_sig_hex": script_sig_hex,
        "witness": wit,
    }


def make_single_use_spend_input(
    seal: dict[str, Any],
    branch: int,
    *,
    sighash: int = 0x01,
    script_sig_hex: str = "",
) -> dict[str, Any]:
    """Construct the exact P2WSH witness input spending a single_use_1_of_2 seal."""
    _, ws = sl.compile_script_policy(seal["script_policy"])
    assert ws is not None
    selector = "01" if branch == 1 else ""
    sig_hex = "3044" + ("11" * 68 if branch == 1 else "22" * 68) + f"{sighash:02x}"
    return {
        "prev_txid": seal["txid"],
        "prev_vout": seal["vout"],
        "script_sig_hex": script_sig_hex,
        "witness": [sig_hex, selector, ws.hex()],
    }


def make_guardian_csv_input(
    prev_txid: str,
    prev_vout: int,
    pending_policy: dict[str, Any],
    *,
    sequence: int | None = None,
    sighash: int = 0x01,
    script_sig_hex: str = "",
) -> dict[str, Any]:
    """Construct the exact 4-item P2WSH CSV witness input spending a guardian_slot_pending seal via <guardian>."""
    _, ws = sl.compile_script_policy(pending_policy)
    assert ws is not None
    seq = pending_policy["delay_blocks"] if sequence is None else sequence
    sig_hex = "30440220" + ("33" * 32) + "0220" + ("44" * 32) + f"{sighash:02x}"
    return {
        "prev_txid": prev_txid,
        "prev_vout": prev_vout,
        "script_sig_hex": script_sig_hex,
        "sequence": seq,
        "witness": [sig_hex, "", "", ws.hex()],
    }


def make_name_history(
    name: str,
    registration: dict[str, Any],
    owner_policy: dict[str, Any],
    value_obj: dict[str, Any] | str,
    *,
    first_height: int = 748000,
    update_height: int = 749000,
    update_txid: str | None = None,
    first_only: bool = False,
    firstupdate_self_funded: bool | None = None,
    bad_sighash: bool = False,
    extra_updates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a structured Namecoin name update history with exact encoded prefix scripts."""
    val_bytes = value_obj.encode("utf-8") if isinstance(value_obj, str) else sl.jcs_encode(value_obj)
    spk, _ = sl.compile_script_policy(owner_policy)
    rand_b = sl.sha256(f"seallink-rand:{name}:{registration['txid']}".encode("utf-8"))[:20]
    s_first = sl.encode_name_output("NAME_FIRSTUPDATE", spk, name=name.encode("utf-8"), rand=rand_b, value=val_bytes)
    first_u: dict[str, Any] = {
        "op": "NAME_FIRSTUPDATE",
        "txid": registration["txid"],
        "vout": registration["vout"],
        "confirmed_height": first_height,
        "owner_policy": copy.deepcopy(owner_policy),
        "output_script_hex": s_first.hex(),
    }
    if firstupdate_self_funded is not None:
        first_u["firstupdate_self_funded"] = bool(firstupdate_self_funded)
    updates: list[dict[str, Any]] = [first_u]
    if not first_only:
        upd_txid = update_txid or sl.sha256(f"seallink-upd1:{name}:{registration['txid']}".encode("utf-8")).hex()
        s_upd = sl.encode_name_output("NAME_UPDATE", spk, name=name.encode("utf-8"), value=val_bytes)
        updates.append({
            "op": "NAME_UPDATE",
            "txid": upd_txid,
            "vout": 0,
            "confirmed_height": update_height,
            "owner_policy": copy.deepcopy(owner_policy),
            "output_script_hex": s_upd.hex(),
            "prev_input": {
                "txid": registration["txid"],
                "vout": registration["vout"],
                "witness_policy": copy.deepcopy(owner_policy),
                "sighash_bytes": [0x81 if bad_sighash else 0x01],
            },
        })
    if extra_updates:
        for eu in extra_updates:
            prev = updates[-1]
            eu_owner = eu.get("owner_policy", prev["owner_policy"])
            eu_spk, _ = sl.compile_script_policy(eu_owner)
            eu_val = eu["value"]
            eu_val_b = eu_val.encode("utf-8") if isinstance(eu_val, str) else sl.jcs_encode(eu_val)
            s_eu = sl.encode_name_output("NAME_UPDATE", eu_spk, name=name.encode("utf-8"), value=eu_val_b)
            entry: dict[str, Any] = {
                "op": "NAME_UPDATE",
                "txid": eu["txid"],
                "vout": eu.get("vout", 0),
                "confirmed_height": eu["confirmed_height"],
                "owner_policy": copy.deepcopy(eu_owner),
                "output_script_hex": s_eu.hex(),
                "prev_input": {
                    "txid": prev["txid"],
                    "vout": prev["vout"],
                    "witness_policy": copy.deepcopy(eu.get("witness_policy", prev["owner_policy"])),
                    "sighash_bytes": list(eu.get("sighash_bytes", [0x01])),
                },
            }
            if "opreturn_hex" in eu:
                entry["opreturn_hex"] = eu["opreturn_hex"]
            updates.append(entry)
    return {"registration": copy.deepcopy(registration), "updates": updates}


def compute_quota_debit(
    action: str,
    arguments: dict[str, Any],
    quota: dict[str, Any],
) -> tuple[int, int]:
    """Compute profile-driven (reserve_amount, reserve_amount) using exact integer arithmetic (registry/constraints.json)."""
    kind = quota["kind"]
    if kind == "seallink/count":
        # agent/session checkpoint and halt consume 0 starts (B-8 / registry/constraints.json)
        reserve = 0 if (action == "agent/session" and arguments.get("op") in ("checkpoint", "halt")) else 1
    elif kind == "seallink/bytes":
        raw = arguments.get("max_output_bytes") or arguments.get("size_bytes") or arguments.get("max_bytes") or "1"
        reserve = int(raw)
    elif kind == "seallink/duration":
        raw = arguments.get("max_duration_sec") or arguments.get("max_wall_sec") or "1"
        reserve = int(raw)
    elif kind in ("seallink/tokens", "seallink/cost", "seallink/coins"):
        raw = arguments.get("max_tokens") or arguments.get("max_cost") or arguments.get("amount") or "1"
        reserve = int(raw)
    else:
        reserve = 1
    return reserve, reserve


@dataclass
class VerifierResult:
    verdict: str  # "ADMIT", "REFUSE", "UNCERTAIN"
    refusal_code: str | None = None
    outcome: str = "refused"  # "executed", "reserved", "refused", "uncertain"
    cached_receipt_content_addr: str | None = None
    journal_writes: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


class FencedJournal:
    """Stateful anti-rollback hash-chained journal + external CAS witness (SPEC-06 §6)."""

    def __init__(
        self,
        journal_id: str,
        *,
        external_witness: dict[str, Any] | None = None,
        write_token: int = 1,
    ) -> None:
        self.journal_id = journal_id
        self.pos = 0
        self.commitment = sl.journal_commit_init(journal_id)
        self.entries: list[dict[str, Any]] = []
        # External witness state (and optional shared CAS witness dict for multi-writer fencing, G7-11)
        self.witness_readable = True
        self.store_readable = True
        self.witness_journal_id = journal_id
        self.witness_pos = 0
        self.witness_commitment = self.commitment
        self.write_token = int(write_token)
        self.write_token_active = True
        self.external_witness: dict[str, Any] | None = external_witness
        if external_witness is not None:
            external_witness.setdefault("journal_id", journal_id)
            external_witness.setdefault("pos", 0)
            external_witness.setdefault("commitment", self.commitment)
            external_witness.setdefault("active_write_token", self.write_token)
        # Materialized indices derived from journal entries
        self.closures: dict[str, dict[str, Any]] = {}
        self.nonces: dict[str, str] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self.receipt_store: dict[str, dict[str, Any]] = {}
        self.terminal_invocations: dict[str, dict[str, Any]] = {}
        self.unsettled_reservations: dict[str, dict[str, Any]] = {}
        self.quotas_used: dict[tuple[str, str, str], int] = {}
        self.quota_watermarks: dict[str, int] = {}
        self.manifest_heads: dict[tuple[str, str], dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.sessions_by_id: dict[str, dict[str, Any]] = {}
        self.auth_nonces: dict[str, dict[str, Any]] = {}
        self.migrations_applied: set[str] = set()
        self.log_heads: dict[str, dict[str, Any]] = {}

    @classmethod
    def from_dict(cls, cfg: dict[str, Any]) -> "FencedJournal":
        j = cls(
            cfg["journal_id"],
            external_witness=cfg.get("external_witness"),
            write_token=int(cfg.get("write_token", 1)),
        )
        j.witness_readable = cfg.get("witness_readable", True)
        j.store_readable = cfg.get("store_readable", True)
        j.witness_journal_id = cfg.get("witness_journal_id", j.journal_id)
        j.write_token_active = cfg.get("write_token_active", True)
        for k, v in cfg.get("receipt_store", {}).items():
            j.receipt_store[k] = copy.deepcopy(v)
        for item in cfg.get("initial_entries", []):
            j.append(item["kind"], item["body"], check_external_witness=False)
        if "witness_pos" in cfg:
            j.witness_pos = cfg["witness_pos"]
        if "witness_commitment" in cfg:
            j.witness_commitment = cfg["witness_commitment"]
        for k, v in cfg.get("closures", {}).items():
            cv = copy.deepcopy(v)
            if isinstance(cv, dict) and "cause" not in cv:
                cv["cause"] = cv.get("reason", "SEAL_SPENT")
            j.closures[k] = cv
            if isinstance(cv, dict) and isinstance(cv.get("subject"), dict):
                ck = _closure_subject_key(cv["subject"], cv.get("cause"))
                j.closures[ck] = cv
        for k, v in cfg.get("nonces", {}).items():
            j.nonces[k] = v
        for k, v in cfg.get("receipts", {}).items():
            j.receipts[k] = copy.deepcopy(v)
            try:
                rsha = sl.content_addr(v)
                j.receipt_store[rsha] = copy.deepcopy(v)
                j.terminal_invocations[k] = {"outcome": v.get("payload", {}).get("outcome", "executed"), "receipt_sha256": rsha}
            except Exception:
                pass
        for k, v in cfg.get("terminal_invocations", {}).items():
            j.terminal_invocations[k] = copy.deepcopy(v)
        for k, v in cfg.get("unsettled_reservations", {}).items():
            if isinstance(v, dict) and "reservations" in v:
                j.unsettled_reservations[k] = copy.deepcopy(v)
            else:
                lines = copy.deepcopy(v) if isinstance(v, list) else [copy.deepcopy(v)]
                j.unsettled_reservations[k] = {"invocation_id": k, "reservations": lines}
        for item in cfg.get("quotas_used", []):
            j.quotas_used[(item["scope"], item["quota_key"], item["bucket_id"])] = int(item["used"])
        for k, v in cfg.get("quota_watermarks", {}).items():
            j.quota_watermarks[k] = int(v)
        for item in cfg.get("manifest_heads", []):
            j.manifest_heads[(item["name"], item["reg_key"])] = copy.deepcopy(item)
        for k, v in cfg.get("sessions", {}).items():
            j.sessions[k] = copy.deepcopy(v)
            if isinstance(v, dict) and "session_id" in v:
                j.sessions_by_id[v["session_id"]] = j.sessions[k]
        for k, v in cfg.get("auth_nonces", {}).items():
            j.auth_nonces[k] = copy.deepcopy(v)
        for mid in cfg.get("migrations_applied", []):
            j.migrations_applied.add(mid)
        for lid, lhead in cfg.get("log_heads", {}).items():
            j.log_heads[lid] = copy.deepcopy(lhead)
        return j

    @classmethod
    def replay_persisted_entries(
        cls,
        journal_id: str,
        persisted_entries: list[dict[str, Any]],
        *,
        receipt_store: dict[str, dict[str, Any]] | None = None,
        witness_pos: int | None = None,
        witness_commitment: str | None = None,
        witness_journal_id: str | None = None,
        write_token_active: bool = True,
        witness_readable: bool = True,
        store_readable: bool = True,
        require_witness: bool = True,
        external_witness: dict[str, Any] | None = None,
        write_token: int = 1,
        session_token_map: dict[str, str] | None = None,
    ) -> "FencedJournal":
        """Reconstruct a fresh FencedJournal strictly by replaying persisted wire-valid entries (ZERO asserts; H-8, G7-11, R1 #3).

        Requires a verified external CAS witness head by default (`require_witness=True`); omitting
        `witness_pos` or `witness_commitment` (when `external_witness` is also absent) marks the
        witness unreadable so `check_continuity()` fails closed with `JOURNAL_LOST`. Validates every
        replayed entry against `seallink-journal-entry/1` wire bytes and Draft 2020-12 closed schema
        before applying state transitions.
        """
        j = cls(journal_id, write_token=write_token)
        j.witness_readable = witness_readable
        j.store_readable = store_readable
        j.witness_journal_id = witness_journal_id if witness_journal_id is not None else journal_id
        j.write_token_active = write_token_active
        if receipt_store is not None:
            j.receipt_store = {k: copy.deepcopy(v) for k, v in receipt_store.items()}
        if not isinstance(persisted_entries, list):
            j.store_readable = False
            return j
        for e in persisted_entries:
            if (
                not isinstance(e, dict)
                or e.get("type") != "seallink-journal-entry/1"
                or e.get("journal_id") != journal_id
                or e.get("pos") != j.pos + 1
                or e.get("prev_commitment") != j.commitment
                or not isinstance(e.get("kind"), str)
                or not isinstance(e.get("body"), dict)
            ):
                j.store_readable = False
                break
            try:
                # Re-validate exact wire encoding & closed Draft 2020-12 schema of persisted entry (R1 #3, G7-11)
                j.append(e["kind"], e["body"], validate_entry=True, check_external_witness=False)
                if j.entries[-1] != e:
                    j.store_readable = False
                    break
            except Exception:
                j.store_readable = False
                break
        # Bind external CAS witness snapshot AFTER replay so check_continuity() verifies it!
        if external_witness is not None:
            j.external_witness = external_witness
            j.witness_journal_id = str(external_witness.get("journal_id", ""))
            j.witness_pos = int(external_witness.get("pos", -1))
            j.witness_commitment = str(external_witness.get("commitment", ""))
            j.write_token_active = (external_witness.get("active_write_token") == j.write_token) and write_token_active
        elif witness_pos is not None and witness_commitment is not None:
            j.witness_pos = int(witness_pos)
            j.witness_commitment = str(witness_commitment)
        elif require_witness:
            # G7-11: Missing external witness on restart MUST fail closed with JOURNAL_LOST!
            j.witness_readable = False
        if session_token_map:
            for sid, thash in session_token_map.items():
                if sid in j.sessions_by_id:
                    j.sessions_by_id[sid]["token_sha256"] = thash
                    j.sessions[thash] = j.sessions_by_id[sid]
        return j

    def check_continuity(self) -> str | None:
        """Check SPEC-06 §6 continuity precedence (with live external CAS witness sync when attached, G7-11)."""
        if self.external_witness is not None:
            ew = self.external_witness
            self.witness_journal_id = str(ew.get("journal_id", ""))
            self.witness_pos = int(ew.get("pos", -1))
            self.witness_commitment = str(ew.get("commitment", ""))
            self.write_token_active = (ew.get("active_write_token") == self.write_token) and self.write_token_active
        if not self.witness_readable or not self.store_readable:
            return "JOURNAL_LOST"
        if self.witness_journal_id != self.journal_id:
            return "JOURNAL_LOST"
        if not self.write_token_active:
            return "JOURNAL_FENCED"
        if self.pos == self.witness_pos and self.commitment == self.witness_commitment:
            return None
        if self.pos == self.witness_pos + 1 and self.entries and self.entries[-1]["prev_commitment"] == self.witness_commitment:
            self.witness_pos = self.pos
            self.witness_commitment = self.commitment
            if self.external_witness is not None:
                self.external_witness["pos"] = self.pos
                self.external_witness["commitment"] = self.commitment
            return None
        return "JOURNAL_LOST"

    def record_closure(
        self,
        subject: dict[str, Any],
        cause: str,
        *,
        observed_at: int,
        observed_height: int | None = None,
        spend_txid: str | None = None,
    ) -> dict[str, Any] | None:
        """Idempotently append a cause-keyed schema-valid ClosureSubject closure entry (SPEC-05 §4.1, SPEC-06 §6, H-4, M-1)."""
        ckey = _closure_subject_key(subject, cause)
        existing = self.closures.get(ckey)
        if existing is not None and existing.get("cause") == cause:
            ex_subj = existing.get("subject", {}) if isinstance(existing.get("subject"), dict) else {}
            if cause == "CRED_ISSUER_CLOSED":
                new_hc = subject.get("cutoff_height")
                old_hc = ex_subj.get("cutoff_height")
                if new_hc is None or (old_hc is not None and int(old_hc) <= int(new_hc)):
                    return None
            elif cause == "NAME_ROLE_CHANGED":
                new_rbh = subject.get("retired_before_height")
                old_rbh = ex_subj.get("retired_before_height")
                if old_rbh is None or (new_rbh is not None and int(new_rbh) <= int(old_rbh)):
                    return None
            else:
                return None
        body: dict[str, Any] = {
            "cause": cause,
            "observed_at": int(observed_at),
            "subject": copy.deepcopy(subject),
        }
        if observed_height is not None:
            body["observed_height"] = int(observed_height)
        if spend_txid is not None:
            body["spend_txid"] = spend_txid
        return self.append("closure", body)

    def lookup_closure(
        self,
        subject: dict[str, Any],
        legacy_key: str | None = None,
        *,
        cause: str | None = None,
    ) -> dict[str, Any] | None:
        ckey = _closure_subject_key(subject, cause)
        if ckey in self.closures:
            return self.closures[ckey]
        if cause is not None:
            uncaused = _closure_subject_key(subject, None)
            hit = self.closures.get(uncaused)
            if isinstance(hit, dict) and hit.get("cause") == cause:
                return hit
        if legacy_key is not None and legacy_key in self.closures:
            return self.closures[legacy_key]
        return None

    def append(
        self,
        kind: str,
        body: dict[str, Any],
        *,
        validate_entry: bool = True,
        check_external_witness: bool = True,
    ) -> dict[str, Any]:
        c_before = self.commitment
        entry = {
            "body": copy.deepcopy(body),
            "journal_id": self.journal_id,
            "kind": kind,
            "pos": self.pos + 1,
            "prev_commitment": c_before,
            "type": "seallink-journal-entry/1",
        }
        # R1 #3 / G7-11: Validate wire bytes, max_bytes (65536 B), and closed Draft 2020-12 schema BEFORE mutating state!
        max_b = registered_types()["seallink-journal-entry/1"]["max_bytes"]
        raw_entry = sl.jcs_encode(entry)
        if len(raw_entry) > max_b:
            raise ValueError("WIRE_SIZE")
        if validate_entry:
            ok_w, res_w = sl.jcs_validate(raw_entry, max_bytes=max_b)
            if not ok_w:
                raise ValueError(str(res_w))
            if jsonschema_available():
                sch_err = validate_against_schema(
                    "schemas/invocation.schema.json#/$defs/JournalEntry", entry, require_jsonschema=False
                )
                if sch_err is not None:
                    raise ValueError(sch_err)
            if kind == "settlement" and body.get("outcome") == "uncertain":
                for ln_u in body.get("settlements", []):
                    if isinstance(ln_u, dict) and int(ln_u.get("released", "0")) != 0:
                        raise ValueError("WIRE_MEMBER")

        c_after = sl.journal_commit_step(c_before, entry)
        # External CAS witness check (atomic write-token fencing + head-pos CAS, G7-11)
        if check_external_witness and self.external_witness is not None:
            ew = self.external_witness
            if ew.get("journal_id") != self.journal_id:
                raise RuntimeError("JOURNAL_LOST")
            if ew.get("active_write_token") != self.write_token or not self.write_token_active:
                self.write_token_active = False
                raise PermissionError("JOURNAL_FENCED")
            if int(ew.get("pos", -1)) != self.pos or ew.get("commitment") != c_before:
                raise RuntimeError("JOURNAL_LOST")
            ew["pos"] = self.pos + 1
            ew["commitment"] = c_after

        self.pos += 1
        self.commitment = c_after
        self.witness_pos = self.pos
        self.witness_commitment = c_after
        self.entries.append(entry)
        # Update materialized indices
        if kind == "closure":
            if "subject" in body and isinstance(body["subject"], dict):
                ckey = _closure_subject_key(body["subject"], body.get("cause"))
                self.closures[ckey] = copy.deepcopy(body)
            elif "subject_id" in body:
                self.closures[body["subject_id"]] = copy.deepcopy(body)
        elif kind == "nonce":
            self.nonces[body["nonce"]] = body["invocation_id"]
        elif kind == "reservation":
            inv_id = body["invocation_id"]
            if "nonce" in body:
                self.nonces[body["nonce"]] = inv_id
            lines = body["reservations"] if "reservations" in body else [body]
            res_rec: dict[str, Any] = {
                "grant_id": body["grant_id"],
                "invocation_id": inv_id,
                "recorded_at": body.get("recorded_at", 0),
                "reservations": copy.deepcopy(lines),
            }
            if "action" in body:
                res_rec["action"] = body["action"]
            if body.get("single_use") is True:
                res_rec["single_use"] = True
                res_rec["use_txid"] = body["use_txid"]
            self.unsettled_reservations[inv_id] = res_rec
            rec_at = body.get("recorded_at")
            for ln in lines:
                scope = (
                    f"row:{ln['grant_id']}:{ln['row_ordinal']}"
                    if ln["account"] == "row"
                    else f"{ln['account']}:{ln['grant_id']}"
                )
                qkey = f"{ln['quota_kind']}|{ln['resource']}|{ln['unit']}|{ln['window']}"
                bkey = (scope, qkey, ln["bucket_id"])
                self.quotas_used[bkey] = self.quotas_used.get(bkey, 0) + int(ln["amount"])
                if ln["window"].startswith("seconds:") and rec_at is not None:
                    self.quota_watermarks[qkey] = max(self.quota_watermarks.get(qkey, 0), int(rec_at))
        elif kind == "settlement":
            inv_id = body["invocation_id"]
            rec_at = body.get("recorded_at")
            outcome = body.get("outcome", "executed")
            rsha = body.get("receipt_sha256")
            slines = body["settlements"] if "settlements" in body else ([body] if "quota_kind" in body else [])
            for ln in slines:
                if ln.get("window", "").startswith("seconds:") and rec_at is not None and "quota_kind" in ln:
                    sqkey = f"{ln['quota_kind']}|{ln['resource']}|{ln['unit']}|{ln['window']}"
                    self.quota_watermarks[sqkey] = max(self.quota_watermarks.get(sqkey, 0), int(rec_at))
                released = int(ln.get("released", "0"))
                if released:
                    scope = (
                        f"row:{ln['grant_id']}:{ln['row_ordinal']}"
                        if ln["account"] == "row"
                        else f"{ln['account']}:{ln['grant_id']}"
                    )
                    qkey = f"{ln['quota_kind']}|{ln['resource']}|{ln['unit']}|{ln['window']}"
                    bkey = (scope, qkey, ln["bucket_id"])
                    self.quotas_used[bkey] = max(0, self.quotas_used.get(bkey, 0) - released)
            if outcome != "uncertain":
                self.unsettled_reservations.pop(inv_id, None)
                self.terminal_invocations[inv_id] = {"outcome": outcome, "receipt_sha256": rsha}
            elif inv_id in self.unsettled_reservations and rsha:
                self.unsettled_reservations[inv_id]["uncertain_receipt_sha256"] = rsha
            # R3 Blocker #2 / L-11: Unified atomic single-use terminal closure inside settlement entry (+1 witness advance!)
            if body.get("single_use_consumed") is True and "closes_grant_id" in body:
                cgid = body["closes_grant_id"]
                self.closures[f"grant:{cgid}"] = {
                    "cause": "SINGLE_USE_CONSUMED",
                    "observed_at": int(rec_at or 0),
                    "spend_txid": body.get("use_txid", "0" * 64),
                    "subject": {"subject_id": cgid, "subject_kind": "grant"},
                }
                if inv_id in self.unsettled_reservations:
                    self.unsettled_reservations[inv_id]["single_use_consumed_recorded"] = True
            if outcome != "uncertain" and rsha and rsha in self.receipt_store:
                try:
                    if sl.content_addr(self.receipt_store[rsha]) == rsha:
                        self.receipts[inv_id] = copy.deepcopy(self.receipt_store[rsha])
                except Exception:
                    pass
        elif kind == "single-use-consumed":
            inv_id = body["invocation_id"]
            cgid = body["grant_id"]
            rsha = body.get("receipt_sha256")
            self.unsettled_reservations.pop(inv_id, None)
            self.terminal_invocations[inv_id] = {"outcome": "executed", "receipt_sha256": rsha}
            self.closures[f"grant:{cgid}"] = {
                "cause": "SINGLE_USE_CONSUMED",
                "observed_at": int(body.get("recorded_at", 0)),
                "spend_txid": body.get("use_txid", "0" * 64),
                "subject": {"subject_id": cgid, "subject_kind": "grant"},
            }
            if rsha and rsha in self.receipt_store:
                try:
                    if sl.content_addr(self.receipt_store[rsha]) == rsha:
                        self.receipts[inv_id] = copy.deepcopy(self.receipt_store[rsha])
                except Exception:
                    pass
        elif kind == "manifest-head":
            self.manifest_heads[(body["name"], _outpoint_key(body["registration"]))] = {
                "anchoring_txid": body.get("anchoring_txid"),
                "anchoring_txid_active": True,
                "seq": int(body["seq"]),
                "sha256": body["manifest_sha256"],
            }
        elif kind == "session-state":
            sid = body["session_id"]
            op_s = body["op"]
            if "nonce" in body:
                self.nonces[body["nonce"]] = sid
            prev = self.sessions_by_id.get(sid, {})
            updated = {
                **prev,
                "closed": (op_s == "close"),
                "exp": int(body["expires_at"]),
                "grant_id": body["grant_id"],
                "quotas": copy.deepcopy(body.get("quotas", prev.get("quotas", []))),
                "recorded_at": int(body["recorded_at"]),
                "session_id": sid,
                "slot_binding": body["slot_binding"],
            }
            if "token_sha256" in body:
                updated["token_sha256"] = body["token_sha256"]
            if "proof_path" in body:
                updated["proof_path"] = copy.deepcopy(body["proof_path"])
            if "root_recent_height" in body:
                updated["root_recent_height"] = int(body["root_recent_height"])
            self.sessions_by_id[sid] = updated
            if "token_sha256" in updated:
                self.sessions[updated["token_sha256"]] = updated
        elif kind == "session-use":
            sid = body["session_id"]
            rec_at = body.get("recorded_at")
            for ln in body.get("debits", []):
                scope = (
                    f"row:{ln['grant_id']}:{ln['row_ordinal']}"
                    if ln["account"] == "row"
                    else (f"session:{sid}" if ln["account"] == "session" else f"{ln['account']}:{ln['grant_id']}")
                )
                qkey = f"{ln['quota_kind']}|{ln['resource']}|{ln['unit']}|{ln['window']}"
                bkey = (scope, qkey, ln["bucket_id"])
                self.quotas_used[bkey] = self.quotas_used.get(bkey, 0) + int(ln["amount"])
                if ln["window"].startswith("seconds:") and rec_at is not None:
                    self.quota_watermarks[qkey] = max(self.quota_watermarks.get(qkey, 0), int(rec_at))
        elif kind == "migration-applied":
            self.migrations_applied.add(body["migration_id"])
        elif kind == "log-head":
            self.log_heads[body["log_id"]] = copy.deepcopy(body)
        return {"entry": entry, "c_before": c_before, "c_after": c_after}


def _append_journal_checked(
    journal: FencedJournal, kind: str, body: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """Append a validated JournalEntry to a CAS-fenced FencedJournal, mapping fencing/loss/wire errors cleanly."""
    try:
        return journal.append(kind, body), None
    except PermissionError:
        return None, "JOURNAL_FENCED"
    except RuntimeError:
        return None, "JOURNAL_LOST"
    except ValueError as exc:
        code_v = str(exc)
        return None, code_v if code_v in REGISTERED_REFUSAL_CODES else "WIRE_SIZE"


class ChainView:
    """Declarative in-memory Namecoin/UTXO ledger view satisfying SPEC-02 §1."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.raw = copy.deepcopy(data)

    @property
    def network(self) -> str:
        return self.raw["network"]

    @property
    def genesis(self) -> str:
        return self.raw["genesis"]

    @property
    def tip_height(self) -> int:
        return int(self.raw["tip_height"])

    @property
    def tip_hash(self) -> str:
        return self.raw["tip_hash"]

    @property
    def now(self) -> int:
        return int(self.raw["now"])

    @property
    def name_expiry_blocks(self) -> int:
        return 30 if self.network == "regtest" else 36000

    def apply_patch(self, patch: dict[str, Any]) -> None:
        """Apply a declarative chain state transition (e.g., new block, mempool seal spend)."""
        for k, v in patch.items():
            if k in ("names", "name_registrations", "txs", "blocks", "manifests", "registered_bindings") and isinstance(v, dict):
                self.raw.setdefault(k, {})
                for subk, subv in v.items():
                    if isinstance(subv, dict) and isinstance(self.raw[k].get(subk), dict):
                        self.raw[k][subk].update(copy.deepcopy(subv))
                    else:
                        self.raw[k][subk] = copy.deepcopy(subv)
            else:
                self.raw[k] = copy.deepcopy(v)

    def get_name(self, name: str) -> dict[str, Any] | None:
        return self.raw.get("names", {}).get(name)

    def get_name_for_registration(
        self,
        name: str,
        expected_registration: dict[str, Any] | None,
        *,
        historical: bool = False,
    ) -> dict[str, Any] | None:
        """Select current active name record, or a pinned historical registration lineage for at_height lookups (B-5)."""
        cur = self.get_name(name)
        if not historical or expected_registration is None:
            return cur
        if cur is not None and cur.get("registration") == expected_registration:
            return cur
        for cand in self.raw.get("name_registrations", {}).get(name, []):
            if isinstance(cand, dict) and cand.get("registration") == expected_registration:
                return cand
        return None

    def get_tx(self, txid: str) -> dict[str, Any] | None:
        return self.raw.get("txs", {}).get(txid)

    def get_output(self, txid: str, vout: int) -> dict[str, Any] | None:
        tx = self.get_tx(txid)
        if not tx:
            return None
        return tx.get("outputs", {}).get(str(vout)) or tx.get("outputs", {}).get(vout)


ALL_OPTIONAL_MODULES: frozenset[str] = frozenset({
    "core",
    "bearer-sessions",
    "service-migration",
    "federated-screening",
    "artifact-notarization",
})


class Tier1Verifier:
    """Reference Verifier Core implementing SPEC-01 through SPEC-07."""

    _VALID_MODULES = ALL_OPTIONAL_MODULES
    _TYPE_REQUIRED_MODULE: dict[str, str] = {
        "seallink-session-open/1": "bearer-sessions",
        "seallink-migration/1": "service-migration",
        "seallink-ticket/1": "artifact-notarization",
        "seallink-tier2-name-history/1": "artifact-notarization",
    }

    def __init__(
        self,
        pinned_network: str = "main",
        pinned_genesis: str = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
        operator_min_depth: int = 1,
        allow_window_only: bool = False,
        trusted_origin_issuer_pins: list[dict[str, Any]] | None = None,
        enforce_schemas: bool = True,
        require_jsonschema: bool = True,
        max_history_steps: int = 4096,
        require_observation_bracket: bool = True,
        enabled_modules: set[str] | frozenset[str] | list[str] | tuple[str, ...] | None = None,
        lag_limit: int = 1,
        future_bound_s: int = 600,
        recency_k: int = 432,
        max_automaton_steps: int = 1024,
    ) -> None:
        self.pinned_network = pinned_network
        self.pinned_genesis = pinned_genesis
        self.operator_min_depth = operator_min_depth
        self.allow_window_only = allow_window_only
        self.enforce_schemas = enforce_schemas
        self.require_jsonschema = require_jsonschema
        # B-1 (SL-ORIG-002): Trust origin issuers strictly by complete schema-valid NamePin — NEVER bare strings or typos!
        self.trusted_origin_issuer_pins: list[dict[str, Any]] = []
        if trusted_origin_issuer_pins is not None:
            if not isinstance(trusted_origin_issuer_pins, (list, tuple)):
                raise ValueError("trusted_origin_issuer_pins must be a list of NamePin dicts")
            for p in trusted_origin_issuer_pins:
                if not isinstance(p, dict) or not all(k in p for k in ("name", "registration", "owner_policy")):
                    raise ValueError("trusted_origin_issuer_pins entries MUST be full NamePin dicts (bare strings forbidden)")
                if self.enforce_schemas:
                    pin_err = validate_against_schema(
                        "schemas/common.schema.json#/$defs/NamePin",
                        p,
                        require_jsonschema=self.require_jsonschema,
                    )
                    if pin_err is not None:
                        raise ValueError(f"invalid NamePin in trusted_origin_issuer_pins: {pin_err}")
                sl.compile_script_policy(p["owner_policy"])
                self.trusted_origin_issuer_pins.append(copy.deepcopy(p))
        self.max_history_steps = max_history_steps
        self.max_automaton_steps = int(max_automaton_steps)
        self.require_observation_bracket = require_observation_bracket
        self.lag_limit = int(lag_limit)
        self.future_bound_s = int(future_bound_s)
        self.recency_k = int(recency_k)
        # M-12 / R12-L6: Fail-closed default (core-only when enabled_modules is omitted); strictly validate explicit collections
        if enabled_modules is None:
            self.enabled_modules: frozenset[str] = frozenset({"core"})
        else:
            if isinstance(enabled_modules, (str, bytes)) or not isinstance(enabled_modules, (set, frozenset, list, tuple)):
                raise ValueError("enabled_modules must be a collection of registered module names")
            mods = frozenset(enabled_modules)
            unknown = mods - self._VALID_MODULES
            if unknown or "core" not in mods:
                raise ValueError(f"invalid enabled_modules: {sorted(mods)}")
            self.enabled_modules = mods

    # ------------------------------------------------------------------
    # SPEC-01 §7 Wire Pipeline (steps 1..10, closed Draft 2020-12 schemas)
    # ------------------------------------------------------------------

    def verify_wire_bytes(
        self,
        raw: bytes,
        schema_validator_fn: Any = None,
        max_bytes_override: int | None = None,
        allow_untyped: bool = False,
    ) -> tuple[bool, Any]:
        """Execute SPEC-01 §7 steps 1..10 on raw bytes. Returns (True, obj) or (False, refusal_code)."""
        max_b = max_bytes_override if max_bytes_override is not None else 1048576
        ok, res = sl.jcs_validate(raw, max_bytes=max_b)
        if not ok:
            return False, res
        obj = res
        reg = registered_types()
        # Step 7: Extract & validate registered type (W-9: missing type refuses WIRE_TYPE unless allow_untyped)
        if "payload" in obj:
            if not isinstance(obj["payload"], dict):
                return False, "WIRE_MEMBER"
            obj_type = obj["payload"].get("type")
        else:
            obj_type = obj.get("type")
        if obj_type is None:
            if not allow_untyped:
                return False, "WIRE_TYPE"
        else:
            if not isinstance(obj_type, str) or obj_type not in reg:
                return False, "WIRE_TYPE"
            # Step 7 per-type max_bytes runs BEFORE optional-module gate (SPEC-01 §7)
            type_max = reg[obj_type]["max_bytes"]
            if len(raw) > type_max:
                return False, "WIRE_SIZE"
            # Step 7b (H-13 / M-11): Uniform disabled optional module rejection across ALL wire & domain entrypoints!
            req_mod = self._TYPE_REQUIRED_MODULE.get(obj_type)
            if req_mod is None and "payload" in obj and isinstance(obj["payload"], dict):
                p_mod = obj["payload"]
                if obj_type == "seallink-owner-command/1" and p_mod.get("command") == "approve-pii-disclosure":
                    req_mod = "federated-screening"
                elif obj_type == "seallink-statement/1" and p_mod.get("statement_kind") in ("migration-accept", "migration-fence"):
                    req_mod = "service-migration"
                elif obj_type == "seallink-assent/1" and p_mod.get("target_type") == "seallink-migration/1":
                    req_mod = "service-migration"
            if req_mod is not None and req_mod not in self.enabled_modules:
                return False, "ACTION_UNSUPPORTED"
        # Step 8: Closed Draft 2020-12 JSON Schema validation with fixed x-seallink-refusal precedence (B-11)
        if obj_type in reg:
            if schema_validator_fn is not None:
                err = schema_validator_fn(reg[obj_type]["schema"], obj)
                if err is not None:
                    return False, err
            elif self.enforce_schemas:
                err = validate_against_schema(reg[obj_type]["schema"], obj, require_jsonschema=self.require_jsonschema)
                if err is not None:
                    return False, err
                if obj_type == "seallink-invocation/1":
                    act = obj["payload"].get("action")
                    act_prof = ACTION_PROFILES.get(act)
                    if act_prof is not None and "args_schema" in act_prof:
                        aerr = validate_against_schema(
                            act_prof["args_schema"], obj["payload"].get("arguments"), require_jsonschema=self.require_jsonschema
                        )
                        if aerr is not None:
                            return False, aerr
        # Domain-specific wire semantics (Constraint Algebra sorting, integer ordering, guardian consistency)
        code = self._check_wire_semantics(obj)
        if code:
            return False, code
        # Step 9: Curve-point validation across ALL key fields in the object (H-21)
        key_err = _validate_all_curve_keys(obj)
        if key_err:
            return False, key_err
        # Step 10: Cryptographic signature verification & SL-WIRE-013 ordering/threshold checks
        if "signatures" in obj or "guardian_approvals" in obj:
            ok_sig, sig_code = sl.verify_envelope_signatures(obj)
            if not ok_sig:
                return False, sig_code
        return True, obj

    def _verify_object_wire(self, obj: Any, expected_type: str | None = None) -> tuple[bool, Any]:
        """Validate raw wire bytes directly, or encode a Python dict to canonical JCS, via verify_wire_bytes."""
        if isinstance(obj, (bytes, bytearray)):
            raw = bytes(obj)
        elif isinstance(obj, dict):
            try:
                raw = sl.jcs_encode(obj)
            except ValueError as exc:
                return False, str(exc)
        else:
            return False, "WIRE_JSON"
        ok, res = self.verify_wire_bytes(raw)
        if not ok:
            return False, res
        if expected_type is not None:
            got_type = res["payload"].get("type") if "payload" in res else res.get("type")
            if got_type != expected_type:
                return False, "WIRE_TYPE"
        return True, res

    def _check_wire_semantics(self, obj: dict[str, Any]) -> str | None:
        payload = obj["payload"] if ("payload" in obj and isinstance(obj["payload"], dict)) else obj
        t = payload.get("type")
        if t == "seallink-grant/1":
            nb = payload.get("not_before_height")
            na = payload.get("not_after_height")
            rev = payload.get("revocation", {})
            if isinstance(nb, int) and isinstance(na, int):
                if nb >= na or (isinstance(rev, dict) and rev.get("mode") == "window_only" and (na - nb) > 12):
                    return "WIRE_INTEGER"
            all_caps: list[dict[str, Any]] = [c for c in payload.get("capabilities", []) if isinstance(c, dict)]
            if "delegate" in payload and isinstance(payload["delegate"], dict):
                for g in payload["delegate"].get("groups", []):
                    if isinstance(g, dict):
                        all_caps.extend(c for c in g.get("template", {}).get("capabilities", []) if isinstance(c, dict))
            for cap in all_caps:
                where = cap.get("where", {})
                act_prof = ACTION_PROFILES.get(cap.get("action", ""))
                allowed_where = act_prof.get("allowed_where_predicates") if act_prof else None
                if isinstance(where, dict):
                    for arg_k, pred in where.items():
                        if not isinstance(pred, dict) or not sl.validate_predicate(pred):
                            return "WIRE_CONSTRAINT"
                        if allowed_where is not None:
                            op_k = next(iter(pred.keys()))
                            if arg_k not in allowed_where or op_k not in allowed_where[arg_k]:
                                return "WIRE_CONSTRAINT"
                # W-13: Forbid duplicate (kind, resource, unit, window) entries within Capability.quotas[]
                quotas = cap.get("quotas", [])
                if isinstance(quotas, list):
                    q_keys = [(q["kind"], q["resource"], q["unit"], q["window"]) for q in quotas if isinstance(q, dict) and all(f in q for f in ("kind", "resource", "unit", "window"))]
                    if len(q_keys) != len(set(q_keys)):
                        return "WIRE_CONSTRAINT"
        elif t == "seallink-session-open/1":
            quotas = payload.get("quotas", [])
            if isinstance(quotas, list):
                q_keys = [(q["kind"], q["resource"], q["unit"], q["window"]) for q in quotas if isinstance(q, dict) and all(f in q for f in ("kind", "resource", "unit", "window"))]
                if len(q_keys) != len(set(q_keys)):
                    return "WIRE_CONSTRAINT"
        elif t == "seallink-receipt/1":
            # S-13: Validate registered refusal_code and reserved == settled + released arithmetic
            rc = payload.get("refusal_code")
            if rc is not None and rc not in REGISTERED_REFUSAL_CODES:
                return "WIRE_MEMBER"
            for sln in payload.get("settlements", []):
                if isinstance(sln, dict) and all(k in sln for k in ("reserved", "settled", "released")):
                    if int(sln["reserved"]) != int(sln["settled"]) + int(sln["released"]):
                        return "WIRE_INTEGER"
        elif t == "seallink-origin/1":
            # Check all origin seals are pairwise distinct & name_recovery disposer != arbiter (G-9, D-2)
            nr = payload.get("name_recovery")
            gp_o = payload.get("guardian_policy")
            seal_list: list[Any] = [payload.get("binding_seal"), payload.get("status_seal")]
            if isinstance(nr, dict) and nr.get("mode") == "dual_party_delayed":
                seal_list.append(nr.get("recovery_seal"))
            if isinstance(gp_o, dict):
                seal_list.append(gp_o.get("roster_seal"))
                seal_list.extend(s.get("vacant_utxo") for s in gp_o.get("slots", []) if isinstance(s, dict))
            op_keys = [(s["txid"], s["vout"]) for s in seal_list if isinstance(s, dict) and "txid" in s and "vout" in s]
            dup_seals = len(op_keys) != len(set(op_keys))
            bad_rec_keys = (
                isinstance(nr, dict)
                and nr.get("mode") == "dual_party_delayed"
                and (
                    nr.get("disposer_pk") == nr.get("arbiter_pk")
                    or not sl.branch_key_spec_xcoords(nr.get("disposer_pk")).isdisjoint(sl.branch_key_spec_xcoords(nr.get("arbiter_pk")))
                )
            )
            if dup_seals or bad_rec_keys:
                return "ORIGIN_UNVERIFIED"
            if isinstance(nr, dict) and nr.get("mode") == "dual_party_delayed" and isinstance(nr.get("recovery_seal"), dict):
                try:
                    exp_rec_spk, _ = sl.compile_script_policy({"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(nr["disposer_pk"], nr["arbiter_pk"])})
                    got_rec_spk, _ = sl.compile_script_policy(nr["recovery_seal"]["script_policy"])
                    rec_ok = (got_rec_spk == exp_rec_spk)
                except (ValueError, KeyError, TypeError):
                    rec_ok = False
                if not rec_ok:
                    return "CHAIN_SCRIPT_UNSUPPORTED"
            if isinstance(gp_o, dict):
                ok_g, code_g = sl.check_guardian_policy_consistency(gp_o)
                if not ok_g:
                    return code_g
        elif t == "seallink-guardian-roster/1":
            ok_g, code_g = sl.check_guardian_policy_consistency(payload)
            if not ok_g:
                return code_g
        elif t == "seallink-contract/1":
            parties = payload.get("parties")
            if isinstance(parties, list):
                pids = [pt.get("party_id") for pt in parties if isinstance(pt, dict) and "party_id" in pt]
                if len(pids) != len(set(pids)):
                    return "WIRE_MEMBER"
            mci = payload.get("machine_clause_indices", [])
            cc = payload.get("clause_commitments", [])
            if isinstance(mci, list) and isinstance(cc, list):
                if mci != sorted(set(mci)) or any(not isinstance(i, int) or i < 0 or i >= len(cc) for i in mci):
                    return "WIRE_INTEGER"
        return None

    @staticmethod
    def _extract_slnk_bytes_strict(rec: dict[str, Any]) -> tuple[bytes | None, bool]:
        """Return `(slnk_bytes_or_None, frame_invalid)` enforcing <= 1 zero-value SLNK output across opreturns[] or opreturn_hex (SPEC-02 §5.2)."""
        if "opreturns" in rec and isinstance(rec["opreturns"], list):
            raw_oprets = [it for it in rec["opreturns"] if isinstance(it, dict)]
        elif rec.get("opreturn_hex"):
            raw_oprets = [{"script_pubkey_hex": rec["opreturn_hex"], "value_sat": rec.get("opreturn_value_sat", 0)}]
        else:
            return None, False
        slnk_items: list[tuple[dict[str, Any], bytes]] = []
        for it in raw_oprets:
            try:
                sb = bytes.fromhex(it.get("script_pubkey_hex", ""))
            except ValueError:
                return None, True
            if sl.is_slnk_opreturn(sb):
                slnk_items.append((it, sb))
        if len(slnk_items) > 1 or (len(slnk_items) == 1 and slnk_items[0][0].get("value_sat", 0) != 0):
            return None, True
        return (slnk_items[0][1], False) if slnk_items else (None, False)

    @staticmethod
    def _decode_opreturn_tx(
        tx: dict[str, Any] | None,
        *,
        require_confirmed: bool = True,
        expected_action: str | None = None,
        expected_commitment: str | None = None,
    ) -> dict[str, Any] | None:
        """Decode and validate a single zero-value SLNK OP_RETURN frame on `tx` (SPEC-02 §5.2, H-23)."""
        if not tx:
            return None
        if require_confirmed and tx.get("confirmed_height") is None:
            return None
        slnk_b, bad = Tier1Verifier._extract_slnk_bytes_strict(tx)
        if bad or slnk_b is None:
            return None
        try:
            dec = sl.decode_opreturn(slnk_b)
        except ValueError:
            return None
        if expected_action is not None and dec["action"] != expected_action:
            return None
        if expected_commitment is not None and dec["commitment"] != expected_commitment:
            return None
        return dec

    # ------------------------------------------------------------------
    # SPEC-02 §4 Chain Observation & Freshness
    # ------------------------------------------------------------------

    def _is_bracket_consistent(self, chain: ChainView) -> bool:
        c = chain.raw
        ob = c.get("observation_bracket")
        ob_complete = False
        if isinstance(ob, dict):
            if ob.get("consistent") is not True:
                return False
            st = ob.get("start")
            en = ob.get("end")
            if (
                not isinstance(st, dict)
                or not isinstance(en, dict)
                or st.get("height") != en.get("height")
                or st.get("hash") != en.get("hash")
                or st.get("height") != chain.tip_height
                or st.get("hash") != chain.tip_hash
            ):
                return False
            ob_complete = True
        elif ob is not None:
            return False
        rb = c.get("rebracket_tip")
        if rb and (rb.get("height") != chain.tip_height or rb.get("hash") != chain.tip_hash):
            return False
        return ob_complete or not self.require_observation_bracket

    def check_chain_observation(self, chain: ChainView, risk_class: int = 1) -> str | None:
        c = chain.raw
        # Step 4a: Snapshot bracket consistency FIRST (before peer comparison! SPEC-02 §4, H-1 / SL-LDGR-015)
        if (self.require_observation_bracket or c.get("observation_bracket") is not None) and not self._is_bracket_consistent(chain):
            return "CHAIN_OBSERVATION_VOID"
        # Step 4b: Chain/genesis pin
        if chain.network != self.pinned_network or chain.genesis != self.pinned_genesis:
            return "CHAIN_MISMATCH"
        # Step 4c: Reading node health (!IBD, txindex=true, node_reachable=true, header lag <= self.lag_limit; omitted -> fail closed!)
        in_ibd = c.get("in_ibd")
        txindex = c.get("txindex")
        node_reachable = c.get("node_reachable")
        best_hdr = c.get("best_header_height")
        if (
            not isinstance(in_ibd, bool)
            or not isinstance(txindex, bool)
            or not isinstance(node_reachable, bool)
            or not isinstance(best_hdr, int)
            or isinstance(best_hdr, bool)
            or in_ibd
            or not txindex
            or not node_reachable
        ):
            return "CHAIN_UNHEALTHY"
        if best_hdr - chain.tip_height > self.lag_limit:
            return "CHAIN_UNHEALTHY"
        # Step 4d: Require >= 1 healthy independent comparison peer with mandatory (height, hash_at_tip); single disagreeing peer vetoes (H-1)
        peers_raw = c.get("comparison_peers")
        healthy_peers = (
            [p for p in peers_raw if isinstance(p, dict) and p.get("healthy") is True]
            if isinstance(peers_raw, list)
            else []
        )
        if not healthy_peers:
            return "CHAIN_UNHEALTHY"
        for peer in healthy_peers:
            p_h = peer.get("height")
            p_hash = peer.get("hash_at_tip")
            if not isinstance(p_h, int) or isinstance(p_h, bool) or not isinstance(p_hash, str) or len(p_hash) != 64:
                return "CHAIN_UNHEALTHY"
            if p_h > chain.tip_height or p_hash != chain.tip_hash:
                return "CHAIN_NODE_DISAGREEMENT"
        # Step 4e: Monotonic UTC clock watermark & future header bound S (verifier config, never snapshot override!)
        now = c.get("now")
        watermark = c.get("clock_watermark")
        hdr_time = c.get("tip_header_time")
        first_sight = c.get("tip_first_sight")
        if (
            not isinstance(now, int)
            or isinstance(now, bool)
            or not isinstance(watermark, int)
            or isinstance(watermark, bool)
            or not isinstance(hdr_time, int)
            or isinstance(hdr_time, bool)
            or not isinstance(first_sight, int)
            or isinstance(first_sight, bool)
        ):
            return "CHAIN_CLOCK_ERROR"
        if now < watermark or (chain.network == "main" and c.get("clock_source") == "regtest_deterministic"):
            return "CHAIN_CLOCK_ERROR"
        if hdr_time - now > self.future_bound_s:
            return "CHAIN_CLOCK_ERROR"
        # Step 4f: Dual tip-age freshness (evaluated at unified decision clock & closing bracket)
        tip_age = max(now - hdr_time, now - first_sight)
        cutoff = 3600 if risk_class == 1 else 5400
        if tip_age > cutoff:
            return "CHAIN_TIP_STALE"
        if self.require_observation_bracket or c.get("observation_bracket") is not None:
            rb_err = self.check_rebracket(chain, risk_class=risk_class)
            if rb_err:
                return rb_err
        return None

    def check_rebracket(self, chain: ChainView, risk_class: int = 1) -> str | None:
        if not self._is_bracket_consistent(chain):
            return "CHAIN_OBSERVATION_VOID"
        rb = chain.raw.get("rebracket_tip")
        if not rb:
            return None
        now = rb.get("now", chain.now)
        hdr_time = rb.get("header_time", chain.raw.get("tip_header_time", now - 60))
        first_sight = rb.get("first_sight", chain.raw.get("tip_first_sight", hdr_time))
        tip_age = max(now - hdr_time, now - first_sight)
        cutoff = 3600 if risk_class == 1 else 5400
        if tip_age > cutoff:
            return "CHAIN_TIP_STALE"
        return None

    # ------------------------------------------------------------------
    # SPEC-02 §5 & §6 Derived Witness W, Seals & Single-Use Attribution
    # ------------------------------------------------------------------

    @staticmethod
    def _is_der_sighash_all(item: Any) -> bool:
        return isinstance(item, str) and item.startswith("30") and item.endswith("01") and len(item) in range(16, 200)

    def _tx_satisfies_witness_w(self, tx: dict[str, Any]) -> bool:
        """Derive Witness Profile W strictly from tx.inputs[] (SL-LDGR-009)."""
        inputs = tx.get("inputs")
        if not isinstance(inputs, list) or not inputs:
            return False
        for inp in inputs:
            if not isinstance(inp, dict):
                return False
            if inp.get("script_sig_hex", "") != "":
                return False
            wit = inp.get("witness")
            if not isinstance(wit, list) or not wit:
                return False
            # Verify signature witness items (DER signatures starting with 0x30) end with strict 0x01 SIGHASH_ALL
            saw_sig = False
            for item in wit:
                if not isinstance(item, str):
                    return False
                if item.startswith("30") and len(item) in range(16, 200):
                    saw_sig = True
                    if not item.endswith("01"):
                        return False
            if not saw_sig:
                return False
        return True

    def _extract_single_use_branch(self, seal: dict[str, Any], spend_tx: dict[str, Any]) -> int | None:
        """Derive single_use_1_of_2 spend branch (0=grantee, 1=issuer) via Bitcoin Script CastToBool (L-12)."""
        try:
            _, exp_ws = sl.compile_script_policy(seal["script_policy"])
        except ValueError:
            return None
        if exp_ws is None:
            return None
        exp_ws_hex = exp_ws.hex()
        inputs = spend_tx.get("inputs")
        if not isinstance(inputs, list):
            return None
        for inp in inputs:
            if inp.get("prev_txid") == seal["txid"] and inp.get("prev_vout") == seal["vout"]:
                if inp.get("script_sig_hex", "") != "":
                    return None
                wit = inp.get("witness", [])
                if not isinstance(wit, list) or len(wit) != 3:
                    return None
                sig_hex, selector, ws_hex = wit[0], wit[1], wit[2]
                if ws_hex != exp_ws_hex or not self._is_der_sighash_all(sig_hex) or not isinstance(selector, str):
                    return None
                try:
                    sel_b = bytes.fromhex(selector)
                except ValueError:
                    return None
                return 1 if sl.cast_to_bool(sel_b) else 0
        return None

    def evaluate_seal(
        self,
        seal: dict[str, Any],
        chain: ChainView,
        required_depth: int = 1,
        journal: FencedJournal | None = None,
        subject_id: str | None = None,
        subject_kind: str = "grant",
        closure_subject: dict[str, Any] | None = None,
    ) -> tuple[str, str | None, dict[str, Any] | None]:
        """Evaluate standard revocable seal (SPEC-02 §6.1, H-2 fail-closed on node_reachable=False)."""
        if chain.raw.get("node_reachable") is False:
            return "unavailable", "CHAIN_UNHEALTHY", None
        try:
            exp_spk, _ = sl.compile_script_policy(seal["script_policy"])
        except ValueError:
            return "unavailable", "CHAIN_SCRIPT_UNSUPPORTED", None
        tx = chain.get_tx(seal["txid"])
        conf_h = tx.get("confirmed_height") if tx else None
        out = chain.get_output(seal["txid"], seal["vout"]) if tx else None
        if not tx or conf_h is None or not out or out.get("script_pubkey_hex") != exp_spk.hex():
            return "unavailable", "SEAL_UNAVAILABLE", None
        if out.get("spent_by_txid") or out.get("absent_from_utxo"):
            jw = None
            if journal is not None and (closure_subject is not None or subject_id is not None):
                subj = closure_subject or {"subject_id": subject_id, "subject_kind": subject_kind}
                jw = journal.record_closure(
                    subj,
                    "SEAL_SPENT",
                    observed_at=chain.now,
                    observed_height=chain.tip_height,
                    spend_txid=out.get("spent_by_txid", "0" * 64),
                )
            return "revoked", "SEAL_SPENT", jw
        depth = chain.tip_height - conf_h + 1
        if depth < required_depth:
            return "unavailable", "SEAL_UNAVAILABLE", None
        return "unspent", None, None

    def evaluate_single_use_seal(
        self,
        seal: dict[str, Any],
        use_txid: str | None,
        invocation_content_addr: str,
        required_depth: int,
        chain: ChainView,
        journal: FencedJournal | None = None,
        grant_id: str | None = None,
    ) -> tuple[str, str | None, dict[str, Any] | None]:
        """Evaluate single_use_1_of_2 seal deriving spend branch strictly from witness (SPEC-02 §6.2, H-2)."""
        if chain.raw.get("node_reachable") is False:
            return "unavailable", "CHAIN_UNHEALTHY", None
        try:
            if seal["script_policy"].get("template") != "single_use_1_of_2":
                raise ValueError("not single_use_1_of_2")
            exp_spk, _ = sl.compile_script_policy(seal["script_policy"])
        except ValueError:
            return "unavailable", "CHAIN_SCRIPT_UNSUPPORTED", None
        tx = chain.get_tx(seal["txid"])
        out = chain.get_output(seal["txid"], seal["vout"]) if tx else None
        if not tx or tx.get("confirmed_height") is None or not out or out.get("script_pubkey_hex") != exp_spk.hex():
            return "unavailable", "SEAL_UNAVAILABLE", None

        spent_by = out.get("spent_by_txid")
        if not spent_by and not out.get("absent_from_utxo"):
            return "awaiting_spend", "SEAL_UNAVAILABLE", None

        spend_tx = chain.get_tx(spent_by) if spent_by else None
        branch = self._extract_single_use_branch(seal, spend_tx) if spend_tx else None
        dec_11 = (
            self._decode_opreturn_tx(spend_tx, require_confirmed=False, expected_action="0x11")
            if (branch == 0 and not out.get("absent_from_utxo") and spend_tx is not None)
            else None
        )
        if branch != 0 or out.get("absent_from_utxo") or dec_11 is None:
            jw = None
            if journal is not None and grant_id is not None:
                jw = journal.record_closure(
                    {"subject_id": grant_id, "subject_kind": "grant"},
                    "SEAL_SPENT",
                    observed_at=chain.now,
                    observed_height=chain.tip_height,
                    spend_txid=spent_by or ("0" * 64),
                )
            return "revoked", "SEAL_SPENT", jw

        # Branch 0 (grantee): do NOT permanently close grant_id if grantee legitimately committed a DIFFERENT invocation (G7-05 anti-DoS)!
        assert spend_tx is not None
        if (use_txid is not None and spent_by != use_txid) or dec_11["commitment"] != invocation_content_addr:
            return "revoked", "SEAL_SPENT", None

        spend_h = spend_tx.get("confirmed_height")
        if spend_h is None or (chain.tip_height - spend_h + 1) < required_depth:
            return "pending_confirm", "CHAIN_DEPTH_INSUFFICIENT", None
        return "ready_once", None, None

    # ------------------------------------------------------------------
    # SPEC-03 Name History Walk, Author Verification, Roles, Manifests, Auth, Devices
    # ------------------------------------------------------------------

    def _is_owner_authored_update(self, upd: dict[str, Any], prev_upd: dict[str, Any]) -> bool:
        """Derive SL-LDGR-007 SIGHASH_ALL owner authorship from update's prev_input witness."""
        if upd.get("op") != "NAME_UPDATE":
            return False
        pinp = upd.get("prev_input")
        if not isinstance(pinp, dict):
            return False
        if pinp.get("txid") != prev_upd.get("txid") or pinp.get("vout") != prev_upd.get("vout"):
            return False
        try:
            wit_spk, _ = sl.compile_script_policy(pinp["witness_policy"])
            prev_spk, _ = sl.compile_script_policy(prev_upd["owner_policy"])
        except (ValueError, KeyError, TypeError):
            return False
        if wit_spk != prev_spk:
            return False
        sh_bytes = pinp.get("sighash_bytes")
        if not isinstance(sh_bytes, list) or not sh_bytes:
            return False
        return all(b == 0x01 for b in sh_bytes)

    def _parse_update_value(self, upd: dict[str, Any], expected_name: str) -> tuple[dict[str, Any] | None, str | None]:
        """Parse exact Namecoin output script and validate 520B JCS name value, 71 case-fold aliases, & role disjointness (H-19)."""
        try:
            parsed = sl.parse_name_output(bytes.fromhex(upd["output_script_hex"]))
            exp_spk, _ = sl.compile_script_policy(upd["owner_policy"])
        except (ValueError, KeyError, TypeError):
            return None, "CHAIN_SCRIPT_UNSUPPORTED"
        if parsed.get("name") != expected_name or parsed["trailing_script_pubkey"] != exp_spk.hex():
            return None, "CHAIN_SCRIPT_UNSUPPORTED"
        raw_b = parsed["value"].encode("utf-8")
        ok_j, val_obj = sl.jcs_validate(raw_b, max_bytes=520)
        if not ok_j:
            return None, "WIRE_DUPLICATE" if val_obj == "WIRE_DUPLICATE" else "NAME_VALUE_INVALID"
        if self.enforce_schemas:
            sch_err = validate_against_schema("schemas/name-value.schema.json", val_obj, require_jsonschema=self.require_jsonschema)
            if sch_err is not None:
                return None, "WIRE_DUPLICATE" if sch_err == "WIRE_DUPLICATE" else "NAME_VALUE_INVALID"
        valid_val = True
        used_keys: set[str] = set()
        used_policy_hashes: set[str] = set()
        link = val_obj.get("link", {})
        if isinstance(link, dict):
            for r in ("grant", "cred", "notary", "release"):
                rk = link.get(r)
                if isinstance(rk, str):
                    if not sl.is_valid_xonly_pubkey(rk) or rk in used_keys:
                        valid_val = False
                        break
                    used_keys.add(rk)
                elif isinstance(rk, dict) and isinstance(rk.get("p"), str):
                    # H-19: Cross-role policy-hash disjointness in name value
                    if rk["p"] in used_policy_hashes:
                        valid_val = False
                        break
                    used_policy_hashes.add(rk["p"])
        nostr = val_obj.get("nostr")
        nostr_pk: str | None = (
            nostr
            if isinstance(nostr, str)
            else (nostr["names"]["_"] if isinstance(nostr, dict) and isinstance(nostr.get("names"), dict) and isinstance(nostr["names"].get("_"), str) else None)
        )
        if valid_val and nostr_pk is not None and (not sl.is_valid_xonly_pubkey(nostr_pk) or nostr_pk in used_keys):
            valid_val = False
        if not valid_val:
            return None, "NAME_VALUE_INVALID"
        return val_obj, None

    def resolve_name(
        self,
        name: str,
        chain: ChainView,
        expected_owner_policy: dict[str, Any] | None = None,
        expected_registration: dict[str, Any] | None = None,
        require_writer: bool = True,
        require_history: bool = True,
        at_height: int | None = None,
        historical: bool = False,
        allow_unresolved_voluntary_rebind: bool = False,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Resolve a Namecoin name strictly by walking its structured updates[] history (B-9, B-12, A-5, A-7, R2-L-01, P0-4)."""
        is_hist = at_height is not None or historical
        raw_cur = chain.get_name(name)
        rec = chain.get_name_for_registration(name, expected_registration, historical=is_hist)
        if not rec or (expected_registration is not None and rec.get("registration") != expected_registration):
            cands = (
                ([raw_cur] if isinstance(raw_cur, dict) else [])
                + ([rec] if isinstance(rec, dict) else [])
                + list(chain.raw.get("name_registrations", {}).get(name, []))
            )
            if any(isinstance(r, dict) and r.get("history_truncated") is True and not r.get("updates") for r in cands):
                return None, "NAME_HISTORY_UNAVAILABLE"
            return None, "NAME_NOT_FOUND" if not rec else "NAME_OWNER_MISMATCH"
        updates = rec.get("updates")
        if not isinstance(updates, list) or not updates:
            return None, "NAME_HISTORY_UNAVAILABLE"
        if require_history:
            if rec.get("history_truncated", False) or len(updates) > self.max_history_steps:
                return None, "NAME_HISTORY_UNAVAILABLE"
            reg = rec.get("registration")
            if not reg or updates[0].get("txid") != reg.get("txid") or updates[0].get("vout") != reg.get("vout"):
                return None, "NAME_HISTORY_UNAVAILABLE"
            # Verify unbroken update chain
            for idx in range(1, len(updates)):
                pinp = updates[idx].get("prev_input")
                if not isinstance(pinp, dict) or pinp.get("txid") != updates[idx - 1].get("txid") or pinp.get("vout") != updates[idx - 1].get("vout"):
                    return None, "NAME_HISTORY_UNAVAILABLE"

        # Select target update (tip or historical at_height)
        target_idx: int | None = None
        if at_height is None:
            target_idx = len(updates) - 1
        else:
            for idx, u in enumerate(updates):
                uh = u.get("confirmed_height")
                if uh is not None and uh <= at_height:
                    target_idx = idx
            if target_idx is None:
                return None, "NAME_HISTORY_UNAVAILABLE"

        target_upd = updates[target_idx]

        # Derive name expiry at evaluation height (tip or historical at_height) (SL-LDGR-003)
        eval_h = chain.tip_height if at_height is None else at_height
        target_h = target_upd.get("confirmed_height")
        if target_h is None or eval_h >= target_h + chain.name_expiry_blocks:
            return None, "NAME_EXPIRED"

        try:
            target_owner_spk, _ = sl.compile_script_policy(target_upd["owner_policy"])
        except (ValueError, KeyError, TypeError):
            return None, "CHAIN_SCRIPT_UNSUPPORTED"

        # Derive SIGHASH_ALL owner authorship on target_upd (SL-LDGR-007, H-10 / H-11):
        # - On OP_NAME_FIRSTUPDATE (target_idx == 0), requires verified firstupdate_self_funded == True (unifying Tier-1 & Tier-2).
        # - On OP_NAME_UPDATE (target_idx > 0), requires target_upd itself to be a SIGHASH_ALL self-update by the current owner
        #   (prev_owner == target_owner); a subsequent clean SIGHASH_ALL self-update restores writer_verified after an earlier non-ALL tx.
        if require_writer:
            if target_idx == 0:
                writer_ok = bool(target_upd.get("firstupdate_self_funded", False))
            else:
                writer_ok = (
                    self._is_owner_authored_update(updates[target_idx], updates[target_idx - 1])
                    and target_owner_spk == sl.compile_script_policy(updates[target_idx - 1]["owner_policy"])[0]
                )
            if not writer_ok:
                return None, "NAME_WRITER_UNVERIFIED"

        # Check expected owner_policy byte-for-byte via ScriptPolicy compilation
        if expected_owner_policy is not None:
            try:
                exp_spk, _ = sl.compile_script_policy(expected_owner_policy)
            except (ValueError, KeyError, TypeError):
                return None, "CHAIN_SCRIPT_UNSUPPORTED"
            if exp_spk != target_owner_spk:
                return None, "NAME_OWNER_MISMATCH"

        val_obj, val_err = self._parse_update_value(target_upd, name)
        if val_err:
            return None, val_err

        # Fail-closed history-based permanent origin detection across ALL confirmed updates (B-12, R2-L-01)
        hist_origins: set[str] = set()
        for u in updates:
            try:
                parsed_u = sl.parse_name_output(bytes.fromhex(u["output_script_hex"]))
            except (ValueError, KeyError, TypeError):
                parsed_u = None
            if not parsed_u or parsed_u.get("name") != name:
                if require_history:
                    return None, "NAME_HISTORY_UNAVAILABLE"
                continue
            raw_val_s = parsed_u.get("value", "")
            if raw_val_s == "":
                continue
            ok_uj, u_vobj = sl.jcs_validate(raw_val_s.encode("utf-8"), max_bytes=520)
            if not ok_uj:
                if require_history:
                    return None, "NAME_VALUE_INVALID"
                continue
            if isinstance(u_vobj.get("link"), dict):
                oid_u = u_vobj["link"].get("origin")
                if isinstance(oid_u, str):
                    hist_origins.add(oid_u)
        if len(hist_origins) > 1:
            return None, "ORIGIN_UNVERIFIED"
        historical_origin_id = next(iter(hist_origins)) if hist_origins else None

        # Derive 0x0b compromise breaks, 0x10 recovery cancels, & 0x13 voluntary rebinds from confirmed owner-authored
        # (SIGHASH_ALL) updates in history (SPEC-02 §5.2, H-10 / R12-M3): SLNK frames (including criticality ranges) in
        # non-owner-authored or non-SIGHASH_ALL transactions (e.g. third-party SINGLE|ACP) are completely inert so they
        # can NEVER retroactively break history or poison eternal artifacts!
        compromised_breaks: list[dict[str, Any]] = []
        recovery_cancels: list[dict[str, Any]] = []
        voluntary_rebinds: list[dict[str, Any]] = []
        for idx, u in enumerate(updates):
            uh_conf = u.get("confirmed_height")
            if uh_conf is None:
                continue
            if idx == 0:
                if not u.get("firstupdate_self_funded", False):
                    continue
            elif not self._is_owner_authored_update(u, updates[idx - 1]):
                continue
            slnk_b, frame_bad = self._extract_slnk_bytes_strict(u)
            if frame_bad:
                return None, "CHAIN_FRAME_INVALID"
            if slnk_b is None:
                continue
            try:
                dec = sl.decode_opreturn_with_criticality(slnk_b)
            except ValueError:
                return None, "CHAIN_FRAME_INVALID"
            cscope = dec.get("critical_scope")
            if cscope == "retroactive":
                return None, "ORIGIN_STATUS_INCOMPLETE"
            if cscope == "forward_only":
                if at_height is None or int(uh_conf) <= at_height:
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                continue
            if dec.get("advisory"):
                continue
            if dec["action"] == "0x0b" and dec["h_c"] > int(uh_conf):
                return None, "CHAIN_FRAME_INVALID"
            if idx == 0:
                continue
            if dec["action"] == "0x13":
                voluntary_rebinds.append({
                    "binding_id": dec["commitment"],
                    "confirmed_height": int(uh_conf),
                    "txid": u.get("txid"),
                    "update_idx": idx,
                })
                if not allow_unresolved_voluntary_rebind and (at_height is None or int(uh_conf) <= at_height):
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                continue
            prev_owner_spk = None
            try:
                prev_owner_spk = sl.compile_script_policy(updates[idx - 1]["owner_policy"])[0].hex()
            except (ValueError, KeyError, TypeError):
                pass
            if dec["action"] == "0x0b":
                pinp = u["prev_input"]
                compromised_breaks.append({
                    "h_c": dec["h_c"],
                    "commitment": dec["commitment"],
                    "inclusion_height": int(uh_conf),
                    "name_input": {"txid": pinp["txid"], "vout": pinp["vout"]},
                    "prev_owner_spk_hex": prev_owner_spk,
                })
            elif dec["action"] == "0x10":
                c_rec: dict[str, Any] = {
                    "binding_id": dec["commitment"],
                    "confirmed_height": int(uh_conf),
                    "prev_owner_spk_hex": prev_owner_spk,
                }
                if "block_time" in u and u["block_time"] is not None:
                    c_rec["block_time"] = int(u["block_time"])
                recovery_cancels.append(c_rec)

        return {
            **rec,
            "owner_policy": target_upd["owner_policy"],
            "_value_obj": val_obj,
            "_target_update_idx": target_idx,
            "_target_confirmed_height": target_h,
            "_is_historical": (at_height is not None),
            "_name": name,
            "_historical_origin_id": historical_origin_id,
            "_compromised_breaks": compromised_breaks,
            "_recovery_cancels": recovery_cancels,
            "_voluntary_rebinds": voluntary_rebinds,
            "_mempool_updates": list(rec.get("mempool_updates", [])),
        }, None

    def resolve_role_policy(
        self,
        name_rec: dict[str, Any],
        role: str,
        presented_role_policy: dict[str, Any] | None = None,
        recent_block_height: int | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Resolve link.<role> and derive owner_policy + role continuity across updates[] & live mempool (B-9, A-5, H-25, H5)."""
        updates = name_rec.get("updates", [])
        target_name = name_rec.get("_name", "")
        baseline_entry = None
        baseline_owner_spk: bytes | None = None
        has_baseline = False
        owner_changed = False
        role_changed = False
        if recent_block_height is not None and updates:
            for u in updates:
                uh = u.get("confirmed_height")
                if uh is None:
                    continue
                vobj, verr = self._parse_update_value(u, target_name)
                if verr:
                    return None, verr
                assert vobj is not None
                cur_entry = vobj.get("link", {}).get(role)
                cur_ospk, _ = sl.compile_script_policy(u["owner_policy"])
                if uh <= recent_block_height or not has_baseline:
                    baseline_entry = cur_entry
                    baseline_owner_spk = cur_ospk
                    has_baseline = True
                else:
                    if cur_ospk != baseline_owner_spk:
                        owner_changed = True
                    elif cur_entry != baseline_entry:
                        role_changed = True
        elif updates and not name_rec.get("_is_historical", False) and name_rec.get("_mempool_updates"):
            baseline_entry = name_rec.get("_value_obj", {}).get("link", {}).get(role)
            baseline_owner_spk, _ = sl.compile_script_policy(updates[-1]["owner_policy"])
            has_baseline = True
        if updates and not name_rec.get("_is_historical", False):
            # Check locally observed mempool OP_NAME_UPDATE accelerator for role/owner change (A-5, R2-A-03, H5)
            last_confirmed = updates[-1]
            for mu in name_rec.get("_mempool_updates", []):
                if isinstance(mu, dict) and mu.get("unparseable"):
                    return None, "NAME_HISTORY_UNAVAILABLE"
                if isinstance(mu, dict) and self._is_owner_authored_update(mu, last_confirmed):
                    try:
                        parsed_m = sl.parse_name_output(bytes.fromhex(mu["output_script_hex"]))
                    except (ValueError, KeyError, TypeError):
                        return None, "CHAIN_SCRIPT_UNSUPPORTED"
                    if parsed_m.get("name") != target_name:
                        return None, "CHAIN_SCRIPT_UNSUPPORTED"
                    if baseline_owner_spk is not None and parsed_m["trailing_script_pubkey"] != baseline_owner_spk.hex():
                        owner_changed = True
                    else:
                        ok_mj, mvobj = sl.jcs_validate(parsed_m["value"].encode("utf-8"), max_bytes=520)
                        if not ok_mj:
                            return None, "NAME_VALUE_INVALID"
                        m_entry = mvobj.get("link", {}).get(role) if isinstance(mvobj.get("link"), dict) else None
                        if has_baseline and m_entry != baseline_entry:
                            role_changed = True
        if owner_changed:
            return None, "NAME_OWNER_MISMATCH"
        if role_changed:
            return None, "NAME_ROLE_CHANGED"

        link = name_rec.get("_value_obj", {}).get("link", {})
        entry = link.get(role)
        if entry is None:
            return None, "NAME_ROLE_CHANGED"
        if isinstance(entry, str):
            resolved = {"m": 1, "pks": [entry]}
        else:
            if not isinstance(entry, dict) or "p" not in entry or presented_role_policy is None or sl.sha256(sl.jcs_encode(presented_role_policy)).hex() != entry["p"]:
                return None, "WIRE_SIGNATURE"
            resolved = _normalize_policy(presented_role_policy)
        if presented_role_policy is not None and _normalize_policy(presented_role_policy) != resolved:
            return None, "WIRE_SIGNATURE"
        return resolved, None

    def _first_role_change_height(
        self,
        name_rec: dict[str, Any],
        role: str,
        recent_block_height: int | None,
        chain: ChainView,
    ) -> int | None:
        """Return confirmed height of the first link.<role> change after `recent_block_height` (or tip+1 on mempool rotation) for A->B->A epoch scoping."""
        if recent_block_height is None:
            return None
        updates = name_rec.get("updates", [])
        target_name = name_rec.get("_name", "")
        baseline_entry = None
        has_baseline = False
        for u in updates:
            uh = u.get("confirmed_height")
            if uh is None:
                continue
            vobj, verr = self._parse_update_value(u, target_name)
            if verr or vobj is None:
                return None
            cur_entry = vobj.get("link", {}).get(role)
            if int(uh) <= recent_block_height or not has_baseline:
                baseline_entry = cur_entry
                has_baseline = True
            elif cur_entry != baseline_entry:
                return int(uh)
        return chain.tip_height + 1

    def _resolve_historical_role_policy(
        self,
        name_rec: dict[str, Any],
        role: str,
        presented_role_policy: dict[str, Any] | None,
        at_height: int | None,
    ) -> dict[str, Any] | None:
        """Resolve link.<role> active at historical block height `at_height` (without recency diff) for H-4 authentication."""
        if at_height is None:
            return None
        updates = name_rec.get("updates", [])
        target_name = name_rec.get("_name", "")
        target_u = None
        for u in updates:
            uh = u.get("confirmed_height")
            if uh is not None and uh <= at_height:
                target_u = u
        if target_u is None:
            return None
        vobj, verr = self._parse_update_value(target_u, target_name)
        if verr or vobj is None:
            return None
        entry = vobj.get("link", {}).get(role)
        if entry is None:
            return None
        if isinstance(entry, str):
            resolved = {"m": 1, "pks": [entry]}
        else:
            if not isinstance(entry, dict) or "p" not in entry or presented_role_policy is None:
                return None
            if sl.sha256(sl.jcs_encode(presented_role_policy)).hex() != entry["p"]:
                return None
            resolved = _normalize_policy(presented_role_policy)
        if presented_role_policy is not None and _normalize_policy(presented_role_policy) != resolved:
            return None
        return resolved

    def _policy_compromised_cutoff(
        self,
        nrec: dict[str, Any],
        issuer_pin: dict[str, Any],
        role: str,
        resolved_policy: dict[str, Any],
        chain: ChainView,
    ) -> int | None:
        """Reconstruct seallink-credential-break/1 from on-chain 0x0b frames and return min(h_c) or None (BLK-6: registration-bound, survives cold owner_policy rotation)."""
        if role not in ("cred", "notary", "grant", "release"):
            return None
        issuer_reg_pin = {
            "name": issuer_pin["name"],
            "registration": issuer_pin["registration"],
        }
        norm_pol = _normalize_policy(resolved_policy)
        min_hc: int | None = None
        for brk in nrec.get("_compromised_breaks", []):
            if brk["h_c"] > brk["inclusion_height"]:
                continue
            cand_break = {
                "compromised_policy": norm_pol,
                "genesis": chain.genesis,
                "h_c": brk["h_c"],
                "issuer": issuer_reg_pin,
                "name_input": brk["name_input"],
                "role": role,
                "type": "seallink-credential-break/1",
            }
            if sl.signing_digest(cand_break).hex() == brk["commitment"]:
                min_hc = brk["h_c"] if min_hc is None else min(min_hc, brk["h_c"])
        return min_hc

    def _is_policy_compromised_at(
        self,
        nrec: dict[str, Any],
        issuer_pin: dict[str, Any],
        role: str,
        resolved_policy: dict[str, Any],
        anchor_height: int,
        chain: ChainView,
    ) -> bool:
        min_hc = self._policy_compromised_cutoff(nrec, issuer_pin, role, resolved_policy, chain)
        return min_hc is not None and anchor_height >= min_hc

    def _verify_rebound_pin(
        self,
        nrec: dict[str, Any],
        expected_pin: dict[str, Any],
        origin_bundle: dict[str, Any] | None,
        chain: ChainView,
        journal: FencedJournal | None = None,
        *,
        name_and_reg_only: bool = False,
        at_height: int | None = None,
        origin_bundles_by_oid: dict[str, dict[str, Any]] | None = None,
    ) -> str | None:
        """Verify active origin binding when a resolved name has confirmed 0x13 events (H1, H-1a)."""
        rebs = nrec.get("_voluntary_rebinds", [])
        if at_height is not None:
            rebs = [ev for ev in rebs if ev["confirmed_height"] <= at_height]
        if not rebs:
            return None
        ob = origin_bundle
        hist_oid = nrec.get("_historical_origin_id") or chain.raw.get("registered_bindings", {}).get(_outpoint_key(expected_pin["registration"]))
        if isinstance(hist_oid, str) and isinstance(origin_bundles_by_oid, dict) and hist_oid in origin_bundles_by_oid:
            ob = origin_bundles_by_oid[hist_oid]
        if ob is None:
            return "ORIGIN_STATUS_INCOMPLETE"
        wst, oerr = self.verify_origin_and_status(ob, chain, journal=journal, at_height=at_height)
        if oerr:
            return oerr
        assert wst is not None
        eb = wst.get("effective_binding", wst["binding"])
        matched = (eb["name"] == expected_pin["name"] and eb["registration"] == expected_pin["registration"]) if name_and_reg_only else _name_pin_equal(eb, expected_pin)
        if not matched:
            return "ORIGIN_BINDING_INVALID"
        return None

    def verify_issuer_role_at_height(
        self,
        issuer_pin: dict[str, Any],
        env: dict[str, Any],
        role: str,
        anchor_height: int,
        chain: ChainView,
        *,
        resolve_at_tip: bool = False,
        journal: FencedJournal | None = None,
        origin_bundle: dict[str, Any] | None = None,
    ) -> str | None:
        """Authoritatively verify an object's signatures against issuer's link.<role> + policy-scoped 0x0b h_c cutoff (M-1, H-1a)."""
        eval_h_opt = None if resolve_at_tip else anchor_height
        nrec, nerr = self.resolve_name(
            issuer_pin["name"],
            chain,
            expected_owner_policy=issuer_pin["owner_policy"],
            expected_registration=issuer_pin["registration"],
            require_writer=True,
            require_history=True,
            at_height=eval_h_opt,
            allow_unresolved_voluntary_rebind=(origin_bundle is not None),
        )
        if nerr:
            return nerr
        assert nrec is not None
        rb_err = self._verify_rebound_pin(nrec, issuer_pin, origin_bundle, chain, journal, at_height=eval_h_opt)
        if rb_err:
            return rb_err
        rpol, rerr = self.resolve_role_policy(nrec, role, issuer_pin.get("role_policy"))
        if rerr:
            return rerr
        assert rpol is not None
        pol_sha = _policy_sha256(rpol)
        role_subj: dict[str, Any] = {
            "name": issuer_pin["name"],
            "policy_sha256": pol_sha,
            "registration": issuer_pin["registration"],
            "role": role,
            "subject_kind": "role",
        }
        # M-1: Check policy- & cutoff-scoped durable role closure BEFORE signature checks (never blocks < h_c or successor policy B!)
        if journal is not None:
            ex_cl = journal.lookup_closure(role_subj, cause="CRED_ISSUER_CLOSED")
            if ex_cl is not None:
                ex_hc = ex_cl.get("subject", {}).get("cutoff_height")
                if ex_hc is None or anchor_height >= int(ex_hc):
                    return "CRED_ISSUER_CLOSED"
        min_hc = self._policy_compromised_cutoff(nrec, issuer_pin, role, rpol, chain)
        if min_hc is not None and anchor_height >= min_hc:
            if journal is not None:
                journal.record_closure(
                    {**role_subj, "cutoff_height": min_hc},
                    "CRED_ISSUER_CLOSED",
                    observed_at=chain.now,
                    observed_height=chain.tip_height,
                )
            return "CRED_ISSUER_CLOSED"
        ok_sig, scode = sl.verify_signature_set(
            sl.signing_digest(env["payload"]),
            env.get("signatures", {}),
            expected_policy=rpol,
            obj_type=env["payload"]["type"],
        )
        if not ok_sig:
            return scode
        return None

    def resolve_manifest(
        self,
        name: str,
        name_rec: dict[str, Any],
        presented_manifests: dict[str, dict[str, Any]],
        chain: ChainView,
        journal: FencedJournal | None = None,
        *,
        record_head: bool = False,
    ) -> tuple[dict[str, Any] | None, str | None]:
        m_pin = name_rec.get("_value_obj", {}).get("m")
        if not isinstance(m_pin, dict) or "h" not in m_pin or "s" not in m_pin:
            return None, "MANIFEST_UNAVAILABLE"
        target_h = m_pin["h"]
        target_s = m_pin["s"]
        man = presented_manifests.get(target_h) or presented_manifests.get(name) or chain.raw.get("manifests", {}).get(target_h)
        if man is None:
            return None, "MANIFEST_UNAVAILABLE"
        ok_m, m_res = self._verify_object_wire(man, expected_type="seallink-manifest/1")
        if not ok_m:
            return None, m_res
        if sl.content_addr(man) != target_h:
            return None, "MANIFEST_MISMATCH"
        if man.get("owner") != name or man.get("network") != chain.network or man.get("seq") != target_s:
            return None, "MANIFEST_MISMATCH"
        # Full role-key disjointness across link.*, manifest.role_policies, nostr, and manifest.auth_key (H-19)
        vobj = name_rec.get("_value_obj", {})
        role_sets: list[set[str]] = []
        link = vobj.get("link", {})
        rp_map = man.get("role_policies", {})
        for rname in ("grant", "cred", "notary", "release"):
            rk = link.get(rname)
            if isinstance(rk, str):
                role_sets.append({rk})
            elif isinstance(rk, dict) and "p" in rk and isinstance(rp_map, dict) and rname in rp_map:
                if sl.sha256(sl.jcs_encode(rp_map[rname])).hex() == rk["p"]:
                    role_sets.append(set(rp_map[rname].get("pks", [])))
        nostr = vobj.get("nostr")
        if isinstance(nostr, str):
            role_sets.append({nostr})
        elif isinstance(nostr, dict) and isinstance(nostr.get("names"), dict) and isinstance(nostr["names"].get("_"), str):
            role_sets.append({nostr["names"]["_"]})
        if isinstance(man.get("auth_key"), str):
            role_sets.append({man["auth_key"]})
        seen_all: set[str] = set()
        for rset in role_sets:
            if not seen_all.isdisjoint(rset):
                return None, "NAME_VALUE_INVALID"
            seen_all |= rset

        reg_key = _outpoint_key(name_rec["registration"])
        if journal is not None and (name, reg_key) in journal.manifest_heads:
            prev = journal.manifest_heads[(name, reg_key)]
            if prev.get("anchoring_txid_active", True):
                if target_s < prev["seq"] or (target_s == prev["seq"] and target_h != prev["sha256"]):
                    return None, "MANIFEST_ROLLBACK"
        if record_head and journal is not None:
            prev_h = journal.manifest_heads.get((name, reg_key))
            if prev_h is None or prev_h["seq"] != target_s:
                t_idx = name_rec.get("_target_update_idx", len(name_rec.get("updates", [])) - 1)
                anch_txid = name_rec["updates"][t_idx]["txid"] if name_rec.get("updates") else ("0" * 64)
                journal.append(
                    "manifest-head",
                    {
                        "anchoring_txid": anch_txid,
                        "manifest_sha256": target_h,
                        "name": name,
                        "registration": copy.deepcopy(name_rec["registration"]),
                        "seq": target_s,
                    },
                )
        return man, None

    def verify_auth_challenge(
        self,
        challenge_env: dict[str, Any],
        chain: ChainView,
        journal: FencedJournal,
        service_id: str,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
        *,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        ok, res = self._verify_object_wire(challenge_env, expected_type="seallink-auth-challenge/1")
        if not ok:
            return VerifierResult("REFUSE", res)
        p = res["payload"]
        nonce = p["nonce"]
        rec = journal.auth_nonces.get(nonce)
        # Service-recorded service_id, issued_at, expires_at exact equality check (mandatory per H-26)
        if (
            p["service_id"] != service_id
            or rec is None
            or rec.get("used", False)
            or nonce in journal.nonces
            or rec.get("service_id") != service_id
            or "issued_at" not in rec
            or "expires_at" not in rec
            or p["issued_at"] != int(rec["issued_at"])
            or p["expires_at"] != int(rec["expires_at"])
        ):
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_INVALID")
        if (
            (p["expires_at"] - p["issued_at"]) > 120
            or chain.now < p["issued_at"]
            or chain.now >= p["expires_at"]
        ):
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_EXPIRED")
        ok_sig, code_sig = sl.verify_signature_set(
            sl.signing_digest(p),
            challenge_env["signatures"],
            expected_policy={"m": 1, "pks": [p["auth_pubkey"]]},
            obj_type="seallink-auth-challenge/1",
        )
        if not ok_sig:
            return VerifierResult("REFUSE", code_sig)
        if "name" in p:
            obs_err = self.check_chain_observation(chain, risk_class=2)
            if obs_err:
                return VerifierResult("REFUSE", obs_err)
            nrec, nerr = self.resolve_name(
                p["name"], chain, allow_unresolved_voluntary_rebind=(origin_bundle is not None)
            )
            if nerr:
                return VerifierResult("REFUSE", nerr)
            assert nrec is not None
            rb_err_a = self._verify_rebound_pin(
                nrec, {"name": p["name"], "registration": nrec["registration"]}, origin_bundle, chain, journal, name_and_reg_only=True
            )
            if rb_err_a:
                return VerifierResult("REFUSE", rb_err_a)
            man, merr = self.resolve_manifest(p["name"], nrec, presented_manifests or {}, chain, journal)
            if merr:
                return VerifierResult("REFUSE", merr)
            assert man is not None
            if man.get("auth_key") != p["auth_pubkey"] or "auth_seal" not in man:
                return VerifierResult("REFUSE", "AUTH_KEY_UNPINNED")
            _, serr, _ = self.evaluate_seal(man["auth_seal"], chain, required_depth=1)
            if serr:
                return VerifierResult("REFUSE", serr)
        rec["used"] = True
        journal.nonces[nonce] = sl.object_id(p)
        return VerifierResult("ADMIT", None, outcome="executed")

    def verify_auth_upgrade(
        self,
        upgrade_env: dict[str, Any],
        expected_service_id: str,
        expected_provisional_auth_pubkey: str,
        chain: ChainView,
        journal: FencedJournal,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
        *,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Verify atomic seallink-auth-upgrade/1 binding a confirmed registration to a provisional cell (SPEC-03 §5, H-24)."""
        ok, res = self._verify_object_wire(upgrade_env, expected_type="seallink-auth-upgrade/1")
        if not ok:
            return VerifierResult("REFUSE", res)
        p = res["payload"]
        if (
            p["service_id"] != expected_service_id
            or p["expires_at"] <= p["issued_at"]
            or p["expires_at"] - p["issued_at"] > 120
            or p["nonce"] in journal.nonces
        ):
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_INVALID")
        if p["auth_pubkey"] != expected_provisional_auth_pubkey:
            return VerifierResult("REFUSE", "AUTH_KEY_UNPINNED")
        if chain.now < p["issued_at"] or chain.now >= p["expires_at"]:
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_EXPIRED")
        ok_sig, code_sig = sl.verify_signature_set(
            sl.signing_digest(p),
            upgrade_env["signatures"],
            expected_policy={"m": 1, "pks": [expected_provisional_auth_pubkey]},
            obj_type="seallink-auth-upgrade/1",
        )
        if not ok_sig:
            return VerifierResult("REFUSE", code_sig)
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)
        nrec, nerr = self.resolve_name(
            p["name"],
            chain,
            allow_unresolved_voluntary_rebind=(origin_bundle is not None),
        )
        if nerr:
            return VerifierResult("REFUSE", nerr)
        assert nrec is not None
        if nrec.get("registration", {}).get("txid") != p["firstupdate_txid"]:
            return VerifierResult("REFUSE", "NAME_OWNER_MISMATCH")
        if nrec.get("_voluntary_rebinds"):
            rb_err = self._verify_rebound_pin(
                nrec,
                {"name": p["name"], "registration": nrec["registration"], "owner_policy": nrec["owner_policy"]},
                origin_bundle,
                chain,
                journal,
            )
            if rb_err:
                return VerifierResult("REFUSE", rb_err)
        man, merr = self.resolve_manifest(p["name"], nrec, presented_manifests or {}, chain, journal)
        if merr:
            return VerifierResult("REFUSE", merr)
        assert man is not None
        if man.get("auth_key") != expected_provisional_auth_pubkey or "auth_seal" not in man:
            return VerifierResult("REFUSE", "AUTH_KEY_UNPINNED")
        _, serr, _ = self.evaluate_seal(man["auth_seal"], chain, required_depth=self.operator_min_depth)
        if serr:
            return VerifierResult("REFUSE", serr)
        jw = journal.append(
            "nonce",
            {
                "expires_at": p["expires_at"],
                "invocation_id": sl.object_id(p),
                "nonce": p["nonce"],
                "scope": "auth",
            },
        )
        return VerifierResult(
            "ADMIT", None, outcome="executed", journal_writes=[jw], details={"upgraded_name": p["name"], "account_id": p["account_id"]}
        )

    def verify_owner_command(
        self,
        cmd_env: dict[str, Any],
        device_list: dict[str, Any],
        is_foreign_service: bool,
        chain: ChainView,
        *,
        owner_manifest: dict[str, Any] | None = None,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
        journal: FencedJournal | None = None,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        ok, res = self._verify_object_wire(cmd_env, expected_type="seallink-owner-command/1")
        if not ok:
            return VerifierResult("REFUSE", res)
        ok_dl, dl_res = self._verify_object_wire(device_list, expected_type="seallink-device-list/1")
        if not ok_dl:
            return VerifierResult("REFUSE", dl_res)
        if is_foreign_service:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        p = res["payload"]
        if p["network"] != self.pinned_network or p["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        if not (p["iat"] <= chain.now < p["exp"]):
            return VerifierResult("REFUSE", "INVOKE_TIME_INVALID")
        if dl_res.get("owner") != p["owner"]:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        # H01 / H-6 / SL-ORIG-017: Resolve p["owner"] on-chain (including 0x13 origin_bundle check) and bind
        # owner_manifest -> confirmed name value m.h -> sets.devices pin!
        nrec, nerr = self.resolve_name(
            p["owner"],
            chain,
            require_writer=True,
            require_history=True,
            allow_unresolved_voluntary_rebind=(origin_bundle is not None),
        )
        if nerr:
            return VerifierResult("REFUSE", nerr)
        assert nrec is not None
        if nrec.get("_voluntary_rebinds"):
            rb_err = self._verify_rebound_pin(
                nrec,
                {"name": p["owner"], "registration": nrec["registration"], "owner_policy": nrec["owner_policy"]},
                origin_bundle,
                chain,
                journal,
            )
            if rb_err:
                return VerifierResult("REFUSE", rb_err)
        pres_m: dict[str, dict[str, Any]] = (
            {p["owner"]: owner_manifest} if owner_manifest is not None else dict(presented_manifests or {})
        )
        man, merr = self.resolve_manifest(p["owner"], nrec, pres_m, chain, journal)
        if merr:
            return VerifierResult("REFUSE", merr)
        assert man is not None
        dev_set_pin = man.get("sets", {}).get("devices")
        if not dev_set_pin or sl.content_addr(dl_res) != dev_set_pin.get("sha256") or dl_res.get("seq") != dev_set_pin.get("seq"):
            return VerifierResult("REFUSE", "MANIFEST_MISMATCH")
        sig_pol = cmd_env["signatures"]["policy"]
        sig_pks = sig_pol["pks"]
        sig_alg = sig_pol.get("alg", "bip340")
        if len(sig_pks) != 1 or sig_pol["m"] != 1:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        dev_pk = sig_pks[0]
        matched = None
        for d in device_list.get("devices", []):
            if d["key"] == dev_pk and d["alg"] == sig_alg:
                matched = d
                break
        if matched is None:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        if p["level"] > matched["ceiling"]:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        if p["command"] in ("policy-apply", "keyholder-halt", "approve-pii-disclosure") and (
            matched["ceiling"] < 2 or not matched.get("presence", False)
        ):
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        _, serr, _ = self.evaluate_seal(matched["seal"], chain, required_depth=1)
        if serr:
            return VerifierResult("REFUSE", serr)
        return VerifierResult("ADMIT", None, outcome="executed", details={"device_alg": sig_alg, "device_label": matched["label"]})

    # ------------------------------------------------------------------
    # SPEC-04 Origin, Status Spine, Guardianship, and Full Name Recovery
    # ------------------------------------------------------------------

    def _verify_guardian_incoming_assent(
        self,
        grec: dict[str, Any],
        assents_by_target: dict[str, dict[str, Any]],
        chain: ChainView,
        at_height: int | None = None,
    ) -> bool:
        """Verify incoming guardian's seallink-assent/1 against its resolved link.grant policy (SL-ORIG-007)."""
        gp_rec = grec["payload"]
        gid = sl.object_id(gp_rec)
        g_assent = assents_by_target.get(gid)
        if g_assent is None:
            return False
        ok_w, _ = self._verify_object_wire(g_assent, expected_type="seallink-assent/1")
        if not ok_w or "signatures" not in g_assent:
            return False
        ap = g_assent["payload"]
        gpin = gp_rec["guardian"]
        if (
            ap.get("target_type") != "seallink-guardian/1"
            or ap.get("target_id") != gid
            or ap.get("party_name") != gpin["name"]
            or ap.get("network") != gp_rec["network"]
            or ap.get("genesis") != gp_rec["genesis"]
            or ap["expires_at"] <= ap["issued_at"]
        ):
            return False
        gnrec, gerr = self.resolve_name(
            gpin["name"],
            chain,
            expected_owner_policy=gpin["owner_policy"],
            expected_registration=gpin["registration"],
            at_height=at_height,
        )
        if gerr or gnrec is None:
            return False
        gpol, rerr = self.resolve_role_policy(gnrec, "grant", g_assent["signatures"]["policy"])
        if rerr or gpol is None:
            return False
        ok_s, _ = sl.verify_signature_set(
            sl.signing_digest(ap),
            g_assent["signatures"],
            expected_policy=gpol,
            obj_type="seallink-assent/1",
        )
        return ok_s

    @staticmethod
    def _extract_policy_pubkeys(pol: Any) -> set[str]:
        """Extract normalized 32-byte x-coordinate public key hex strings referenced anywhere in a ScriptPolicy / BranchKeySpec (M-9, SL-LDGR-004)."""
        out: set[str] = set()
        if not isinstance(pol, dict):
            return out

        def _norm_pk(k: str) -> str:
            return k[2:] if (len(k) == 66 and k[:2] in ("02", "03")) else k

        pk = pol.get("pk")
        if isinstance(pk, str):
            out.add(_norm_pk(pk))
        pks = pol.get("pks")
        if isinstance(pks, list):
            for k in pks:
                if isinstance(k, str):
                    out.add(_norm_pk(k))
        keys = pol.get("keys")
        if isinstance(keys, dict):
            for v in keys.values():
                if isinstance(v, str):
                    out.add(_norm_pk(v))
                elif isinstance(v, dict):
                    out.update(Tier1Verifier._extract_policy_pubkeys(v))
        return out

    def _check_emancipation_handover(
        self,
        ward_name: str,
        registration: dict[str, Any],
        initial_owner_policy: dict[str, Any],
        subject_new_owner_policy: dict[str, Any] | None,
        chain: ChainView,
        *,
        active_binding: dict[str, Any] | None = None,
        at_height: int | None = None,
        cap_confirmed_height: int | None = None,
        last_recovery_promo_height: int | None = None,
        last_recovery_promo_time: int | None = None,
        majority_cutoff_reached: bool = False,
        opened_majority: int | None = None,
        pre_trigger_pks: set[str] | None = None,
    ) -> tuple[bool, dict[str, Any] | None]:
        """Derive unified Decision 1B emancipation handover strictly from ward name.updates[] (R2G-02, R2G-04, B-13, H-5, M-9).

        Transition to State 4 (autonomous) ALWAYS requires cryptographically authenticated
        subject_new_owner_policy disjoint from ALL pre-emancipation guardian pubkeys via either:
          - Confirmed seallink-capacity/1 (subject_new_owner_policy != None) + handover transfer (>= cap_confirmed_height) + SIGHASH_ALL self-update, OR
          - Confirmed dual_party_delayed 0x0c recovery (active_binding.seq >= 2, fresh disjoint owner_policy, taking effect AT/AFTER
            the emancipation trigger: h_promo >= cap_confirmed_height OR t_promo >= opened_majority) + SIGHASH_ALL self-update.
        Calendar majority T alone NEVER transitions to State 4 without capacity/1 or post-trigger 0x0c recovery.
        Returns `(True, current_subject_owner_policy)` on verified State 4 transition, else `(False, None)`.
        """
        init_spk, _ = sl.compile_script_policy(initial_owner_policy)
        target_spk = sl.compile_script_policy(subject_new_owner_policy)[0] if subject_new_owner_policy else None
        forbidden_pks = self._extract_policy_pubkeys(initial_owner_policy) | (pre_trigger_pks or set())
        eval_h = chain.tip_height if at_height is None else at_height
        rec = chain.get_name_for_registration(ward_name, registration, historical=(at_height is not None))
        if not rec or rec.get("registration") != registration or not isinstance(rec.get("updates"), list):
            return False, None
        updates = [u for u in rec["updates"] if u.get("confirmed_height") is not None and u["confirmed_height"] <= eval_h]
        if len(updates) < 2:
            return False, None
        latest_owner = updates[-1].get("owner_policy")
        try:
            latest_spk, _ = sl.compile_script_policy(latest_owner)
        except (ValueError, KeyError, TypeError):
            return False, None
        latest_pks = self._extract_policy_pubkeys(latest_owner)
        if latest_spk == init_spk or not latest_pks or not latest_pks.isdisjoint(forbidden_pks):
            return False, None

        # Case 1 (Decision 1B / H-5 / M-9): Confirmed post-trigger dual_party_delayed 0x0c recovery (seq >= 2) with fresh disjoint owner_policy + self-update
        cap_ok = (
            cap_confirmed_height is not None
            and last_recovery_promo_height is not None
            and last_recovery_promo_height >= cap_confirmed_height
        )
        maj_ok = (
            majority_cutoff_reached
            and opened_majority is not None
            and last_recovery_promo_time is not None
            and last_recovery_promo_time >= opened_majority
        )
        rec_order_ok = cap_ok or maj_ok
        if active_binding is not None and active_binding.get("seq", 1) >= 2 and rec_order_ok:
            try:
                b_spk, _ = sl.compile_script_policy(active_binding["owner_policy"])
            except (ValueError, KeyError, TypeError):
                b_spk = b""
            b_pks = self._extract_policy_pubkeys(active_binding["owner_policy"])
            if b_spk and b_spk != init_spk and b_pks and b_pks.isdisjoint(forbidden_pks):
                for j in range(1, len(updates)):
                    if self._is_owner_authored_update(updates[j], updates[j - 1]):
                        try:
                            s_spk, _ = sl.compile_script_policy(updates[j]["owner_policy"])
                        except (ValueError, KeyError, TypeError):
                            continue
                        if s_spk == b_spk and all(
                            self._is_owner_authored_update(updates[k], updates[k - 1]) for k in range(j, len(updates))
                        ):
                            return True, copy.deepcopy(latest_owner)

        # Case 2 (Decision 1B / H-5 / M-9): Confirmed seallink-capacity/1 committing fresh disjoint subject_new_owner_policy + handover transfer (>= h_cap) + self-update
        target_pks = self._extract_policy_pubkeys(subject_new_owner_policy) if subject_new_owner_policy else set()
        if target_spk is not None and target_spk != init_spk and target_pks and target_pks.isdisjoint(forbidden_pks) and len(updates) >= 3:
            for idx in range(1, len(updates)):
                u_xfer = updates[idx]
                if cap_confirmed_height is not None and u_xfer["confirmed_height"] < cap_confirmed_height:
                    continue
                try:
                    u_spk, _ = sl.compile_script_policy(u_xfer["owner_policy"])
                except (ValueError, KeyError, TypeError):
                    continue
                if u_spk != target_spk:
                    continue
                if not self._is_owner_authored_update(u_xfer, updates[idx - 1]):
                    continue
                if not target_pks.isdisjoint(self._extract_policy_pubkeys(updates[idx - 1].get("owner_policy"))):
                    continue
                for j in range(idx + 1, len(updates)):
                    u_subj = updates[j]
                    if self._is_owner_authored_update(u_subj, updates[j - 1]):
                        try:
                            s_spk, _ = sl.compile_script_policy(u_subj["owner_policy"])
                        except (ValueError, KeyError, TypeError):
                            continue
                        if s_spk == target_spk and all(
                            self._is_owner_authored_update(updates[k], updates[k - 1]) for k in range(j, len(updates))
                        ):
                            return True, copy.deepcopy(latest_owner)
        return False, None

    @staticmethod
    def _tx_spends_outpoint(tx: dict[str, Any] | None, outpoint: dict[str, Any]) -> bool:
        if not tx or not isinstance(tx.get("inputs"), list):
            return False
        txid, vout = outpoint.get("txid"), outpoint.get("vout")
        return any(
            isinstance(i, dict) and i.get("prev_txid") == txid and i.get("prev_vout") == vout
            for i in tx["inputs"]
        )

    @staticmethod
    def _is_0x0e_guardian_csv_branch(
        spend_tx: dict[str, Any],
        pending_outpoint: dict[str, Any],
        pending_policy: dict[str, Any],
        delay_blocks: int,
    ) -> bool:
        """Verify 0x0e spends pending_outpoint via real P2WSH CSV <guardian> witness + BIP-68 sequence (R3 H4, R2-L-02)."""
        inputs = spend_tx.get("inputs")
        if not isinstance(inputs, list):
            return False
        try:
            _, exp_ws = sl.compile_script_policy(pending_policy)
        except ValueError:
            return False
        if exp_ws is None:
            return False
        exp_ws_hex = exp_ws.hex()
        for inp in inputs:
            if not isinstance(inp, dict):
                continue
            if inp.get("prev_txid") != pending_outpoint["txid"] or inp.get("prev_vout") != pending_outpoint["vout"]:
                continue
            if inp.get("script_sig_hex", "") != "":
                return False
            # Mandatory BIP-68 block-based relative locktime >= delay_blocks (R2-L-02)
            if "sequence" not in inp or isinstance(inp["sequence"], bool):
                return False
            try:
                seq = int(inp["sequence"])
            except (ValueError, TypeError):
                return False
            if (seq & (1 << 31)) != 0 or (seq & (1 << 22)) != 0 or (seq & 0xFFFF) < delay_blocks:
                return False
            wit = inp.get("witness")
            # Strict 4-item P2WSH CSV branch witness: [sig, inner_sel=FALSE, outer_sel=FALSE, witnessScript]
            if not isinstance(wit, list) or len(wit) != 4 or wit[-1] != exp_ws_hex:
                return False
            if not Tier1Verifier._is_der_sighash_all(wit[0]):
                return False
            try:
                return not (sl.cast_to_bool(bytes.fromhex(wit[-2])) or sl.cast_to_bool(bytes.fromhex(wit[-3])))
            except ValueError:
                return False
        return False

    def _is_trusted_origin_issuer(self, issuer_pin: dict[str, Any]) -> bool:
        return any(_name_pin_equal(issuer_pin, pin) for pin in self.trusted_origin_issuer_pins)

    @staticmethod
    def _binding_history_ok_until(nrec: dict[str, Any] | None, cutoff_h: int) -> bool:
        """Return True iff name registration history is untruncated through `cutoff_h` (P0-4 `first_error_height`)."""
        if not isinstance(nrec, dict):
            return False
        if not nrec.get("history_truncated", False):
            return True
        feh = nrec.get("first_error_height")
        return isinstance(feh, int) and not isinstance(feh, bool) and feh > cutoff_h

    def _validate_b2_invariant(
        self,
        cand: dict[str, Any],
        chain: ChainView,
        h_13: int,
        check_until_h: int,
        origin_id: str,
        *,
        allow_origin_at_exact: str | None = None,
    ) -> tuple[str, int | None]:
        """Verify B_2 registration, T_offer consent_utxo, no expiry, writer authorship, owner_policy invariance on [h_offer, check_until_h], and no link.origin before maturity.
        Returns tri-state ('valid' | 'invalid' | 'incomplete', h_offer) so boundary history gaps fail closed ORIGIN_STATUS_INCOMPLETE (H02 / H-1c).
        """
        reg_key = _outpoint_key(cand["registration"])
        existing_oid = chain.raw.get("registered_bindings", {}).get(reg_key)
        if existing_oid is not None and existing_oid != origin_id:
            return "invalid", None
        b2_nrec = chain.get_name_for_registration(cand["name"], cand["registration"], historical=True)
        if b2_nrec is None:
            return "invalid", None
        if not self._binding_history_ok_until(b2_nrec, check_until_h):
            return "incomplete", None
        raw_updates = b2_nrec.get("updates", [])
        updates = [u for u in raw_updates if u.get("confirmed_height") is not None and u["confirmed_height"] <= check_until_h]
        if len(updates) < 2:
            return "invalid", None
        b2_spk = sl.compile_script_policy(cand["owner_policy"])[0]
        consent_op = cand["consent_outpoint"]
        offer_idx: int | None = None
        for idx, u in enumerate(updates):
            if u.get("txid") == consent_op["txid"]:
                offer_idx = idx
                break
        if offer_idx is None or offer_idx < 1:
            return "invalid", None
        u_offer = updates[offer_idx]
        h_offer = int(u_offer["confirmed_height"])
        if u_offer.get("op") != "NAME_UPDATE" or h_offer >= h_13:
            return "invalid", None
        offer_tx = chain.get_tx(consent_op["txid"])
        if offer_tx is not None and "version" in offer_tx and offer_tx["version"] != 0x7100:
            return "invalid", None
        if "version" in u_offer and u_offer["version"] != 0x7100:
            return "invalid", None
        consent_out = chain.get_output(consent_op["txid"], consent_op["vout"])
        if not consent_out or consent_out.get("script_pubkey_hex") != b2_spk.hex():
            return "invalid", None
        if sl.compile_script_policy(updates[offer_idx - 1]["owner_policy"])[0] != b2_spk:
            return "invalid", None
        for idx, u in enumerate(updates):
            uh = int(u["confirmed_height"])
            if idx > 0:
                prev_h = int(updates[idx - 1]["confirmed_height"])
                if uh >= prev_h + chain.name_expiry_blocks:
                    return "invalid", None
                if not self._is_owner_authored_update(u, updates[idx - 1]):
                    return "invalid", None
            if idx >= offer_idx:
                if sl.compile_script_policy(u["owner_policy"])[0] != b2_spk:
                    return "invalid", None
            try:
                parsed_u = sl.parse_name_output(bytes.fromhex(u["output_script_hex"]))
            except (ValueError, KeyError, TypeError):
                return "invalid", None
            if parsed_u.get("name") != cand["name"]:
                return "invalid", None
            raw_v = parsed_u.get("value", "")
            if raw_v != "":
                ok_v, vobj = sl.jcs_validate(raw_v.encode("utf-8"), max_bytes=520)
                if not ok_v:
                    return "invalid", None
                if isinstance(vobj.get("link"), dict) and "origin" in vobj["link"]:
                    if allow_origin_at_exact is None or uh < check_until_h or vobj["link"]["origin"] != allow_origin_at_exact:
                        return "invalid", None
        if check_until_h >= int(updates[-1]["confirmed_height"]) + chain.name_expiry_blocks:
            return "invalid", None
        return "valid", h_offer

    def _validate_voluntary_rebind_tx(
        self,
        cand: dict[str, Any],
        u13: dict[str, Any],
        u13_idx: int,
        b1_updates: list[dict[str, Any]],
        active_binding: dict[str, Any],
        origin_id: str,
        nr: dict[str, Any],
        seen_binding_regs: set[tuple[str, str]],
        chain: ChainView,
        h_13: int,
    ) -> tuple[bool, int | None, str | None]:
        """Validate all §6.1 rules for T_rebind (0x13) and T_offer against current writer-verified eff_pol_1."""
        min_d = max(144, int(nr["delay_blocks"])) if nr["mode"] == "dual_party_delayed" else 144
        if (
            cand.get("binding_mode") != "voluntary"
            or cand["origin_id"] != origin_id
            or cand["network"] != self.pinned_network
            or cand["genesis"] != self.pinned_genesis
            or cand.get("supersedes_binding_id") != sl.object_id(active_binding)
            or cand["seq"] != active_binding["seq"] + 1
            or (cand["name"], _outpoint_key(cand["registration"])) in seen_binding_regs
            or len(seen_binding_regs) == 257
            or not (min_d <= cand["delay_blocks"] <= 35000)
        ):
            return False, None, None
        if u13.get("op") != "NAME_UPDATE":
            return False, None, None
        if "version" in u13 and u13["version"] != 0x7100:
            return False, None, None
        try:
            parsed_13 = sl.parse_name_output(bytes.fromhex(u13["output_script_hex"]))
        except (ValueError, KeyError, TypeError):
            return False, None, None
        if parsed_13.get("name") != active_binding["name"] or parsed_13.get("value") != "{}":
            return False, None, None
        # Verify active_binding owner_policy at its binding anchor (T_offer for voluntary rebinds, supporting permitted
        # pre-offer cold rotation on B_2 before B_2 -> B_3! H-1b / H-3 / D12-H3), owner authorship from anchor..u13_idx,
        # and preservation of current writer-verified eff_pol_1 across T_rebind.
        anchor_idx = 0
        if active_binding.get("binding_mode") == "voluntary":
            offer_txid_b1 = active_binding.get("consent_outpoint", {}).get("txid")
            found_a: int | None = None
            for idx_a, u_a in enumerate(b1_updates[1:u13_idx], start=1):
                if u_a.get("txid") == offer_txid_b1:
                    found_a = idx_a
                    break
            if found_a is None:
                return False, None, None
            anchor_idx = found_a
        if sl.compile_script_policy(b1_updates[anchor_idx]["owner_policy"])[0] != sl.compile_script_policy(active_binding["owner_policy"])[0]:
            return False, None, None
        for i in range(anchor_idx + 1, u13_idx + 1):
            if not self._is_owner_authored_update(b1_updates[i], b1_updates[i - 1]):
                return False, None, None
        eff_pol_1 = b1_updates[u13_idx - 1]["owner_policy"]
        eff_spk_1 = sl.compile_script_policy(eff_pol_1)[0]
        if sl.compile_script_policy(u13["owner_policy"])[0] != eff_spk_1:
            return False, None, None
        tx13 = chain.get_tx(u13["txid"])
        if (
            not tx13
            or tx13.get("confirmed_height") != h_13
            or ("version" in tx13 and tx13["version"] != 0x7100)
            or not self._tx_spends_outpoint(tx13, cand["consent_outpoint"])
            or not self._tx_satisfies_witness_w(tx13)
        ):
            return False, None, None
        b2_st, h_offer = self._validate_b2_invariant(cand, chain, h_13, h_13, origin_id)
        if b2_st == "incomplete":
            return False, -1, None
        if b2_st != "valid" or h_offer is None:
            return False, None, None
        return True, h_offer, eff_spk_1.hex()

    def _check_b2_step3_activated(
        self,
        binding: dict[str, Any],
        origin_id: str,
        since_h: int,
        until_h: int,
        chain: ChainView,
    ) -> tuple[bool, dict[str, Any] | None]:
        """Verify Step 3 activation on matured voluntary-rebind B_2 (confirmed SIGHASH_ALL OP_NAME_UPDATE at h_act >= since_h writing link.origin == origin_id; invariant from offer_idx onward)."""
        b2_nrec = chain.get_name_for_registration(binding["name"], binding["registration"], historical=True)
        if not self._binding_history_ok_until(b2_nrec, until_h):
            return False, None
        assert b2_nrec is not None
        updates = [u for u in b2_nrec.get("updates", []) if u.get("confirmed_height") is not None and u["confirmed_height"] <= until_h]
        offer_txid = binding.get("consent_outpoint", {}).get("txid")
        offer_idx: int | None = None
        for idx, u in enumerate(updates):
            if u.get("txid") == offer_txid:
                offer_idx = idx
                break
        if offer_idx is None or offer_idx < 1:
            return False, None
        b2_spk = sl.compile_script_policy(binding["owner_policy"])[0]
        if sl.compile_script_policy(updates[offer_idx]["owner_policy"])[0] != b2_spk:
            return False, None
        activated = False
        for idx in range(1, len(updates)):
            u = updates[idx]
            uh = int(u["confirmed_height"])
            if uh >= int(updates[idx - 1]["confirmed_height"]) + chain.name_expiry_blocks:
                return False, None
            if not self._is_owner_authored_update(u, updates[idx - 1]):
                return False, None
            if not activated and idx in range(offer_idx + 1, len(updates)):
                if sl.compile_script_policy(u["owner_policy"])[0] != b2_spk:
                    return False, None
                if uh >= since_h:
                    vobj, verr = self._parse_update_value(u, binding["name"])
                    if verr is None and vobj is not None and vobj.get("link", {}).get("origin") == origin_id:
                        activated = True
        if not activated or until_h >= int(updates[-1]["confirmed_height"]) + chain.name_expiry_blocks:
            return False, None
        return True, copy.deepcopy(updates[-1]["owner_policy"])

    def verify_origin_and_status(
        self,
        origin_bundle: dict[str, Any] | None,
        chain: ChainView,
        *,
        assert_binding_id: str | None = None,
        journal: FencedJournal | None = None,
        at_height: int | None = None,
        at_time: int | None = None,
        historical_existence_only: bool = False,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Walk origin/1, name-binding/1, status_seal, majority, name_recovery spine, roster_seal, and per-slot states.

        Supports historical evaluation at `(at_height, at_time)` for anchored ward contracts (R1 #1, R2-04)
        and `historical_existence_only=True` for eternal `subject.mode="origin"` credentials (R2-03, D-6).
        """
        if not isinstance(origin_bundle, dict):
            return None, "ORIGIN_UNVERIFIED"
        origin_env = origin_bundle.get("origin")
        if not isinstance(origin_env, dict):
            return None, "ORIGIN_UNVERIFIED"
        ok_o, o_res = self._verify_object_wire(origin_env, expected_type="seallink-origin/1")
        if not ok_o:
            return None, o_res
        op = o_res["payload"]
        if op["network"] != self.pinned_network or op["genesis"] != self.pinned_genesis:
            return None, "CHAIN_MISMATCH"
        # Fail-closed trusted_origin_issuers / trusted_origin_issuer_pins (SL-ORIG-002 item 1, R2-05)
        if not self._is_trusted_origin_issuer(op["issuer"]):
            return None, "ORIGIN_UNVERIFIED"
        card_obj = origin_bundle.get("card")
        if "card" in origin_bundle:
            if (
                not isinstance(card_obj, dict)
                or not self._verify_object_wire(card_obj, expected_type="seallink-card/1")[0]
                or card_obj.get("kind") != op["origin_class"]
                or card_obj.get("network") != op["network"]
            ):
                return None, "ORIGIN_UNVERIFIED"
        if "guardian_policy" in op:
            ok_c, code_c = sl.check_guardian_policy_consistency(op["guardian_policy"])
            if not ok_c:
                return None, code_c

        eval_h = chain.tip_height if at_height is None else at_height
        eval_t = chain.now if at_time is None else at_time

        # Verify origin 0x09 anchor & confirmation depth
        origin_txid = origin_bundle.get("origin_anchor_txid")
        origin_tx = chain.get_tx(origin_txid) if isinstance(origin_txid, str) else None
        dec_o = self._decode_opreturn_tx(origin_tx, expected_action="0x09", expected_commitment=sl.content_addr(origin_env))
        if dec_o is None:
            return None, "ORIGIN_UNVERIFIED"
        assert origin_tx is not None
        h_origin = origin_tx["confirmed_height"]
        if h_origin > eval_h:
            return None, "ORIGIN_UNVERIFIED"
        if chain.tip_height - h_origin + 1 < self.operator_min_depth:
            return None, "CHAIN_DEPTH_INSUFFICIENT"
        origin_id = sl.object_id(op)

        # Check durable origin closure at tip (H-4, G7-06)
        if at_height is None and not historical_existence_only and journal is not None:
            ocl = journal.lookup_closure({"subject_id": origin_id, "subject_kind": "origin"}, legacy_key=origin_id)
            if ocl is not None:
                return None, ocl["cause"]

        # Authoritatively bind origin/1 signature to issuer's link.cred at h_origin + policy-scoped 0x0b h_c cutoff!
        iss_err = self.verify_issuer_role_at_height(op["issuer"], origin_env, "cred", h_origin, chain, journal=journal)
        if iss_err:
            if iss_err in ("CRED_ISSUER_CLOSED", "WIRE_SIGNATURE"):
                return None, iss_err
            return None, "ORIGIN_UNVERIFIED"

        # D-6 / R2-03 / M-8: Eternal credential with subject.mode="origin" verifies historical origin existence,
        # trusted issuance (h_origin <= eval_h, valid issuer link.cred, h_origin < h_c), confirmed binding_seal &
        # status_seal UTXOs at <= eval_h, and (if supplied) valid binding identity — WITHOUT requiring initial 0x0c NameBinding!
        if historical_existence_only:
            bs_chk = op["binding_seal"]
            bs_chk_spk, _ = sl.compile_script_policy(bs_chk["script_policy"])
            bs_chk_tx = chain.get_tx(bs_chk["txid"])
            bs_chk_out = chain.get_output(bs_chk["txid"], bs_chk["vout"])
            if (
                not bs_chk_tx
                or bs_chk_tx.get("confirmed_height") is None
                or bs_chk_tx["confirmed_height"] > eval_h
                or not bs_chk_out
                or bs_chk_out.get("script_pubkey_hex") != bs_chk_spk.hex()
            ):
                return None, "ORIGIN_BINDING_INVALID"
            ss_chk = op["status_seal"]
            ss_chk_spk, _ = sl.compile_script_policy(ss_chk["script_policy"])
            ss_chk_tx = chain.get_tx(ss_chk["txid"])
            ss_chk_out = chain.get_output(ss_chk["txid"], ss_chk["vout"])
            if (
                not ss_chk_tx
                or ss_chk_tx.get("confirmed_height") is None
                or ss_chk_tx["confirmed_height"] > eval_h
                or not ss_chk_out
                or ss_chk_out.get("script_pubkey_hex") != ss_chk_spk.hex()
            ):
                return None, "ORIGIN_STATUS_INCOMPLETE"
            if "name_binding" in origin_bundle and origin_bundle["name_binding"] is not None:
                hb = origin_bundle["name_binding"]
                if (
                    not isinstance(hb, dict)
                    or not self._verify_object_wire(hb, expected_type="seallink-name-binding/1")[0]
                    or hb.get("origin_id") != origin_id
                    or hb.get("seq") != 1
                    or hb.get("name") != op["claims"]["intended_name"]
                    or sl.compile_script_policy(hb["owner_policy"])[0] != sl.compile_script_policy(op["claims"]["intended_owner_policy"])[0]
                ):
                    return None, "ORIGIN_BINDING_INVALID"
            return {
                "origin_id": origin_id,
                "capacity": "historical",
            }, None

        # Verify initial NameBinding (0x0c) + binding_seal spend + intended_* + h_origin < h_firstupdate (B-5, R3 B3)
        binding = origin_bundle.get("name_binding")
        bind_txid = origin_bundle.get("name_binding_txid")
        if (
            not isinstance(binding, dict)
            or not isinstance(bind_txid, str)
            or not bind_txid
            or not self._verify_object_wire(binding, expected_type="seallink-name-binding/1")[0]
            or binding.get("origin_id") != origin_id
            or binding.get("seq") != 1
        ):
            return None, "ORIGIN_BINDING_INVALID"
        if binding["network"] != self.pinned_network or binding["genesis"] != self.pinned_genesis:
            return None, "CHAIN_MISMATCH"
        int_spk, _ = sl.compile_script_policy(op["claims"]["intended_owner_policy"])
        bnd_spk, _ = sl.compile_script_policy(binding["owner_policy"])
        bs_spk, _ = sl.compile_script_policy(op["binding_seal"]["script_policy"])
        bind_tx = chain.get_tx(bind_txid)
        dec_b = self._decode_opreturn_tx(bind_tx, expected_action="0x0c", expected_commitment=sl.object_id(binding))
        if (
            binding["name"] != op["claims"]["intended_name"]
            or bnd_spk != int_spk
            or dec_b is None
            or bind_tx["confirmed_height"] > eval_h
        ):
            return None, "ORIGIN_BINDING_INVALID"
        if chain.tip_height - bind_tx["confirmed_height"] + 1 < self.operator_min_depth:
            return None, "CHAIN_DEPTH_INSUFFICIENT"
        bseal = op["binding_seal"]
        bseal_tx = chain.get_tx(bseal["txid"])
        bseal_out = chain.get_output(bseal["txid"], bseal["vout"])
        spent_match = (
            bool(bseal_out)
            and ((bseal_out.get("spent_by_txid") == bind_txid) or self._tx_spends_outpoint(bind_tx, bseal))
            and not (bseal_out.get("spent_by_txid") and bseal_out["spent_by_txid"] != bind_txid)
            and not (bind_tx.get("inputs") and not self._tx_spends_outpoint(bind_tx, bseal))
        )
        if not bseal_tx or bseal_tx.get("confirmed_height") is None or not bseal_out or bseal_out.get("script_pubkey_hex") != bs_spk.hex() or not spent_match:
            return None, "ORIGIN_BINDING_INVALID"
        # B-5 / BLK-7 (B01): Binding registration MUST exist on-chain with h_origin < h_firstupdate <= h_bind,
        # AND updates[0] (OP_NAME_FIRSTUPDATE) MUST publicly commit link.origin == origin_id so cold observers
        # discover guardianship status from block 0 of the registration without any side-channel index!
        b_nrec = chain.get_name_for_registration(binding["name"], binding["registration"], historical=True)
        if b_nrec is None or not isinstance(b_nrec.get("updates"), list) or not b_nrec["updates"]:
            return None, "ORIGIN_BINDING_INVALID"
        h_fu = b_nrec["updates"][0].get("confirmed_height")
        if h_fu is None or h_fu <= h_origin or bind_tx["confirmed_height"] < h_fu:
            return None, "ORIGIN_BINDING_INVALID"
        fu_val, fu_err = self._parse_update_value(b_nrec["updates"][0], binding["name"])
        if fu_err is not None or not isinstance(fu_val, dict) or fu_val.get("link", {}).get("origin") != origin_id:
            return None, "ORIGIN_BINDING_INVALID"
        reg_key = _outpoint_key(binding["registration"])
        existing_oid = chain.raw.get("registered_bindings", {}).get(reg_key)
        if existing_oid is not None and existing_oid != origin_id:
            return None, "ORIGIN_BINDING_INVALID"

        # Expected exact NamePins for institutional authorities (B-14)
        exp_cap_auth = op.get("capacity_authority", op["issuer"])
        exp_end_auth = op.get("end_authority", exp_cap_auth)
        allowed_guard_issuers = [op["issuer"]] + ([op["capacity_authority"]] if "capacity_authority" in op else [])

        # Walk status_seal spine FIRST so emancipation trigger & height are known for D-2 non-retroactive 0x10 lockout!
        cur_status_seal = op["status_seal"]
        capacity_confirmed = False
        cap_confirmed_height: int | None = None
        majority_cutoff_reached = False
        emancipated_by_majority = False
        subject_new_owner_policy: dict[str, Any] | None = None
        cap_rec = origin_bundle.get("capacity_record")
        end_rec = origin_bundle.get("end_record")
        cap_caddr = sl.content_addr(cap_rec) if isinstance(cap_rec, dict) and self._verify_object_wire(cap_rec, expected_type="seallink-capacity/1")[0] else None
        end_caddr = sl.content_addr(end_rec) if isinstance(end_rec, dict) and self._verify_object_wire(end_rec, expected_type="seallink-end/1")[0] else None
        seen_status_ops: set[str] = set()
        status_terminal_ok = False
        while True:
            cur_s_key = _outpoint_key(cur_status_seal)
            cur_s_spk, _ = sl.compile_script_policy(cur_status_seal["script_policy"])
            st_tx = chain.get_tx(cur_status_seal["txid"])
            sout = chain.get_output(cur_status_seal["txid"], cur_status_seal["vout"])
            if (
                cur_s_key in seen_status_ops
                or len(seen_status_ops) == 257
                or not st_tx
                or st_tx.get("confirmed_height") is None
                or st_tx["confirmed_height"] > eval_h
                or not sout
                or sout.get("script_pubkey_hex") != cur_s_spk.hex()
            ):
                return None, "ORIGIN_STATUS_INCOMPLETE"
            seen_status_ops.add(cur_s_key)
            spend_txid = sout.get("spent_by_txid")
            if not spend_txid:
                if not sout.get("absent_from_utxo"):
                    status_terminal_ok = True
                break
            stx = chain.get_tx(spend_txid)
            if stx is not None and stx.get("confirmed_height") is None:
                if at_height is not None:
                    status_terminal_ok = True
                break
            if at_height is not None and stx is not None and stx["confirmed_height"] > eval_h:
                status_terminal_ok = True
                break
            dec_s = self._decode_opreturn_tx(stx, expected_action="0x09")
            if dec_s is None or (stx.get("inputs") and not self._tx_spends_outpoint(stx, cur_status_seal)):
                break
            assert stx is not None
            h_spend = stx["confirmed_height"]
            if chain.tip_height - h_spend + 1 < self.operator_min_depth:
                return None, "CHAIN_DEPTH_INSUFFICIENT"
            cur_s_op = {"txid": cur_status_seal["txid"], "vout": cur_status_seal["vout"]}
            if end_caddr is not None and end_caddr == dec_s["commitment"]:
                assert isinstance(end_rec, dict)
                ep = end_rec["payload"]
                if (
                    ep["origin_id"] != origin_id
                    or ep["status_prev_outpoint"] != cur_s_op
                    or not _name_pin_equal(ep["issuer"], exp_end_auth)
                ):
                    break
                if ep["network"] != self.pinned_network or ep["genesis"] != self.pinned_genesis:
                    return None, "CHAIN_MISMATCH"
                e_iss_err = self.verify_issuer_role_at_height(ep["issuer"], end_rec, "cred", h_spend, chain, journal=journal)
                if e_iss_err:
                    return None, "CRED_ISSUER_CLOSED" if e_iss_err == "CRED_ISSUER_CLOSED" else "ORIGIN_STATUS_INCOMPLETE"
                if at_height is None and journal is not None:
                    journal.record_closure(
                        {"subject_id": origin_id, "subject_kind": "origin"},
                        "SUBJECT_ENDED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                        spend_txid=spend_txid,
                    )
                return None, "SUBJECT_ENDED"
            if cap_caddr is not None and cap_caddr == dec_s["commitment"]:
                assert isinstance(cap_rec, dict)
                cp = cap_rec["payload"]
                if (
                    cp["origin_id"] != origin_id
                    or cp["status_prev_outpoint"] != cur_s_op
                    or not _name_pin_equal(cp["issuer"], exp_cap_auth)
                ):
                    break
                if cp["network"] != self.pinned_network or cp["genesis"] != self.pinned_genesis:
                    return None, "CHAIN_MISMATCH"
                c_iss_err = self.verify_issuer_role_at_height(cp["issuer"], cap_rec, "cred", h_spend, chain, journal=journal)
                if c_iss_err:
                    return None, "CRED_ISSUER_CLOSED" if c_iss_err == "CRED_ISSUER_CLOSED" else "ORIGIN_STATUS_INCOMPLETE"
                nxt_out = chain.get_output(spend_txid, cp["next_status_vout"])
                nxt_spk, _ = sl.compile_script_policy(cp["next_status_policy"])
                if nxt_out and nxt_out.get("script_pubkey_hex") == nxt_spk.hex():
                    capacity_confirmed = True
                    if cap_confirmed_height is None:
                        cap_confirmed_height = h_spend
                    subject_new_owner_policy = cp["subject_new_owner_policy"]
                    cur_status_seal = {"txid": spend_txid, "vout": cp["next_status_vout"], "script_policy": cp["next_status_policy"]}
                    continue
            break
        if not status_terminal_ok:
            return None, "ORIGIN_STATUS_INCOMPLETE"

        # Check majority_commitment (MANDATORY on minor person origins; R2G-03 ORIGIN_UNVERIFIED; R2G-06 mandatory MTP!)
        opened_majority = origin_bundle.get("opened_majority_unix")
        salt_m = origin_bundle.get("majority_salt_hex")
        if "majority_commitment" in op["claims"]:
            if opened_majority is None or isinstance(opened_majority, bool) or not isinstance(opened_majority, int) or not isinstance(salt_m, str):
                return None, "ORIGIN_STATUS_INCOMPLETE"
            try:
                got_mc = sl.clause_commit(salt_m, {"majority_unix": opened_majority})
            except ValueError:
                got_mc = None
            if got_mc != op["claims"]["majority_commitment"]:
                return None, "ORIGIN_UNVERIFIED"
            if at_time is not None:
                if eval_t >= opened_majority:
                    majority_cutoff_reached = True
                    emancipated_by_majority = True
            else:
                interval = chain.raw.get("credible_utc_interval")
                mtp = chain.raw.get("tip_median_time_past")
                if (
                    interval is None
                    or not isinstance(interval, list)
                    or len(interval) != 2
                    or isinstance(interval[0], bool)
                    or isinstance(interval[1], bool)
                    or not isinstance(interval[0], int)
                    or not isinstance(interval[1], int)
                    or interval[0] > interval[1]
                    or mtp is None
                    or isinstance(mtp, bool)
                    or not isinstance(mtp, int)
                    or mtp < 0
                ):
                    return None, "GUARDIAN_TIME_BOUNDARY"
                t_low, t_high = interval[0], interval[1]
                if (t_low < opened_majority <= t_high) or (t_low < opened_majority and mtp >= opened_majority):
                    return None, "GUARDIAN_TIME_BOUNDARY"
                if t_low >= opened_majority:
                    majority_cutoff_reached = True
                    emancipated_by_majority = True

        # Unified 5-subphase (1 -> 2 -> 3 -> 4 -> 4b) height-ordered binding state machine
        # (SPEC-04 §6, voluntary-rebind-design-v2.2, 3-way D-1, non-retroactive D-2, H-5, H-6, M-9, P0-4)
        active_binding = binding
        seen_binding_regs: set[tuple[str, str]] = {(binding["name"], _outpoint_key(binding["registration"]))}
        active_recovery_seal: dict[str, Any] | None = None
        last_recovery_promo_height: int | None = None
        last_recovery_promo_time: int | None = None
        pre_trigger_pks: set[str] = set(self._extract_policy_pubkeys(op["claims"]["intended_owner_policy"]))
        for bu in b_nrec.get("updates", []):
            bh_u = bu.get("confirmed_height")
            if bh_u is None:
                continue
            before_cap = cap_confirmed_height is None or bh_u < cap_confirmed_height
            bu_bt = bu.get("block_time")
            before_maj = opened_majority is None or bu_bt is None or int(bu_bt) < opened_majority
            if before_cap and before_maj:
                pre_trigger_pks.update(self._extract_policy_pubkeys(bu.get("owner_policy")))
        recovery_events: list[dict[str, Any]] = []
        voluntary_rebind_events: list[dict[str, Any]] = []
        recovery_burned = False
        nr = op["name_recovery"]
        raw_rec_cands = origin_bundle.get("recovery_bindings", [])
        raw_reb_cands = origin_bundle.get("voluntary_rebind_bindings", [])
        if not isinstance(raw_rec_cands, list) or not isinstance(raw_reb_cands, list):
            return None, "ORIGIN_STATUS_INCOMPLETE"
        rec_candidates_list: list[Any] = list(raw_rec_cands) + list(raw_reb_cands)
        if origin_bundle.get("pending_recovery_binding") is not None:
            rec_candidates_list.append(origin_bundle["pending_recovery_binding"])
        rec_by_id: dict[str, dict[str, Any]] = {}
        invalid_rec_preimages: set[str] = set()
        for rb in rec_candidates_list:
            if not isinstance(rb, dict):
                continue
            ok_rb, _ = self._verify_object_wire(rb, expected_type="seallink-name-binding/1")
            if ok_rb:
                rec_by_id[sl.object_id(rb)] = rb
            else:
                try:
                    invalid_rec_preimages.add(sl.object_id(rb))
                except Exception:
                    pass

        if nr["mode"] == "none":
            if any(isinstance(rb, dict) and rb.get("binding_mode") != "voluntary" for rb in rec_candidates_list):
                return None, "RECOVERY_FORBIDDEN"
            exp_rec_spk: bytes | None = None
        else:
            active_recovery_seal = nr["recovery_seal"]
            exp_rec_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(nr["disposer_pk"], nr["arbiter_pk"])}
            exp_rec_spk = sl.compile_script_policy(exp_rec_pol)[0]

        seen_rec_ops: set[str] = set()
        is_autonomous: bool = "guardian_policy" not in op
        h_emancipated: int | None = h_origin if is_autonomous else None
        emancipated_owner_policy: dict[str, Any] | None = None
        awaiting_activation = False
        awaiting_activation_since: int | None = None
        pending_rec: dict[str, Any] | None = None
        pending_reb: dict[str, Any] | None = None
        unknown_rebind_stalled = False
        processed_13_txids: set[str] = set()

        def _block_time_at(h_q: int, fallback_tx: dict[str, Any] | None = None, zero_delay: bool = False) -> int | None:
            blk_times = chain.raw.get("block_times", {})
            bt = blk_times.get(str(h_q))
            if bt is None:
                bt = blk_times.get(h_q)
            if bt is None and fallback_tx is not None and fallback_tx.get("deadline_block_time") is not None:
                bt = fallback_tx["deadline_block_time"]
            if bt is None and fallback_tx is not None and fallback_tx.get("block_time") is not None and zero_delay:
                bt = fallback_tx["block_time"]
            return int(bt) if (bt is not None and not isinstance(bt, bool)) else None

        def _inspect_active_rec_seal() -> tuple[int | None, str | None, dict[str, Any] | None, str | None]:
            if active_recovery_seal is None or recovery_burned or exp_rec_spk is None:
                return None, None, None, None
            cur_r_key = _outpoint_key(active_recovery_seal)
            r_tx_cre = chain.get_tx(active_recovery_seal["txid"])
            rout = chain.get_output(active_recovery_seal["txid"], active_recovery_seal["vout"])
            if (
                cur_r_key in seen_rec_ops
                or len(seen_rec_ops) == 257
                or not r_tx_cre
                or r_tx_cre.get("confirmed_height") is None
                or r_tx_cre["confirmed_height"] > eval_h
                or not rout
                or rout.get("script_pubkey_hex") != exp_rec_spk.hex()
            ):
                return None, None, None, "ORIGIN_STATUS_INCOMPLETE"
            rspend = rout.get("spent_by_txid")
            if not rspend:
                if rout.get("absent_from_utxo"):
                    return None, None, None, "ORIGIN_STATUS_INCOMPLETE"
                return None, None, None, None
            rtx = chain.get_tx(rspend)
            if rtx is None or rtx.get("confirmed_height") is None:
                if at_height is not None:
                    return None, None, None, None
                return None, None, None, "ORIGIN_STATUS_INCOMPLETE"
            if at_height is not None and rtx["confirmed_height"] > eval_h:
                return None, None, None, None
            return int(rtx["confirmed_height"]), rspend, rtx, None

        def _try_open_0x0c(rspend: str, rtx: dict[str, Any], h_r: int) -> tuple[dict[str, Any] | None, str | None]:
            nonlocal active_recovery_seal, recovery_burned
            assert active_recovery_seal is not None and exp_rec_spk is not None
            seen_rec_ops.add(_outpoint_key(active_recovery_seal))
            dec_r = self._decode_opreturn_tx(rtx, expected_action="0x0c")
            has_cont_out = any(
                isinstance(ov, dict) and ov.get("script_pubkey_hex") == exp_rec_spk.hex()
                for ov in (rtx.get("outputs") or {}).values()
            )
            if dec_r is None or (rtx.get("inputs") and not self._tx_spends_outpoint(rtx, active_recovery_seal)) or not has_cont_out:
                recovery_burned = True
                recovery_events.append({"outcome": "recovery_burned", "spend_txid": rspend})
                return None, None
            cand_id = dec_r["commitment"]
            cand = rec_by_id.get(cand_id)
            if cand is None:
                if cand_id in invalid_rec_preimages:
                    recovery_burned = True
                    recovery_events.append({"outcome": "recovery_burned", "spend_txid": rspend})
                    return None, None
                return None, "ORIGIN_STATUS_INCOMPLETE"
            bad_cand = (
                cand.get("binding_mode") != "recovery"
                or cand["origin_id"] != origin_id
                or cand["network"] != self.pinned_network
                or cand["genesis"] != self.pinned_genesis
                or cand.get("supersedes_binding_id") != sl.object_id(active_binding)
                or cand["seq"] != active_binding["seq"] + 1
                or sl.compile_script_policy(cand["next_recovery_policy"])[0] != exp_rec_spk
            )
            if bad_cand:
                recovery_burned = True
                recovery_events.append({"outcome": "recovery_burned", "spend_txid": rspend})
                return None, None
            # BLK-7 (B01): When recovery registration is present on-chain, its OP_NAME_FIRSTUPDATE MUST commit link.origin == origin_id!
            cand_nrec_0c = chain.get_name_for_registration(cand["name"], cand["registration"], historical=True)
            if isinstance(cand_nrec_0c, dict) and isinstance(cand_nrec_0c.get("updates"), list) and cand_nrec_0c["updates"]:
                cfu_val, cfu_err = self._parse_update_value(cand_nrec_0c["updates"][0], cand["name"])
                if cfu_err is not None or not isinstance(cfu_val, dict) or cfu_val.get("link", {}).get("origin") != origin_id:
                    recovery_burned = True
                    recovery_events.append({"outcome": "recovery_burned", "spend_txid": rspend})
                    return None, None
            next_seal_out = chain.get_output(rspend, cand["next_recovery_vout"])
            if not next_seal_out or next_seal_out.get("script_pubkey_hex") != exp_rec_spk.hex():
                recovery_burned = True
                recovery_events.append({"outcome": "recovery_burned", "spend_txid": rspend})
                return None, None
            next_rec_seal = {
                "txid": rspend,
                "vout": cand["next_recovery_vout"],
                "script_policy": cand["next_recovery_policy"],
            }
            active_recovery_seal = next_rec_seal
            return {
                "cand": cand,
                "cand_id": cand_id,
                "deadline": h_r + nr["delay_blocks"],
                "h_start": h_r,
                "next_rec_seal": next_rec_seal,
                "rtx": rtx,
            }, None

        def _check_0x10_at_h(
            bnd: dict[str, Any],
            cand_id: str,
            h_q: int,
            *,
            check_state3_lockout: bool,
            exp_prev_spk_hex: str | None = None,
        ) -> str:
            nrec_c = chain.get_name_for_registration(bnd["name"], bnd["registration"], historical=True)
            if not self._binding_history_ok_until(nrec_c, h_q):
                return "NONE"
            assert nrec_c is not None
            upds_c = nrec_c.get("updates", [])
            for u_idx in range(1, len(upds_c)):
                u_c = upds_c[u_idx]
                if u_c.get("confirmed_height") != h_q:
                    continue
                if not self._is_owner_authored_update(u_c, upds_c[u_idx - 1]):
                    continue
                if exp_prev_spk_hex is not None:
                    if sl.compile_script_policy(upds_c[u_idx - 1]["owner_policy"])[0].hex() != exp_prev_spk_hex:
                        continue
                slnk_c, bad_c = self._extract_slnk_bytes_strict(u_c)
                if bad_c or slnk_c is None:
                    continue
                try:
                    dec_c = sl.decode_opreturn_with_criticality(slnk_c)
                except ValueError:
                    continue
                if dec_c.get("advisory") or dec_c.get("critical_scope") or dec_c["action"] != "0x10" or dec_c["commitment"] != cand_id:
                    continue
                if check_state3_lockout and "guardian_policy" in op and not is_autonomous:
                    locked_by_cap = cap_confirmed_height is not None and h_q >= cap_confirmed_height
                    cancel_bt = u_c.get("block_time")
                    locked_by_maj = (opened_majority is not None) and (cancel_bt is None or int(cancel_bt) >= opened_majority)
                    if locked_by_cap or locked_by_maj:
                        already_s4, _ = self._check_emancipation_handover(
                            bnd["name"],
                            bnd["registration"],
                            op["claims"]["intended_owner_policy"],
                            subject_new_owner_policy,
                            chain,
                            active_binding=bnd,
                            at_height=h_q - 1,
                            cap_confirmed_height=cap_confirmed_height,
                            last_recovery_promo_height=last_recovery_promo_height,
                            last_recovery_promo_time=last_recovery_promo_time,
                            majority_cutoff_reached=locked_by_maj,
                            opened_majority=opened_majority,
                            pre_trigger_pks=pre_trigger_pks,
                        )
                        if not already_s4:
                            continue
                return "CANCEL"
            return "NONE"

        def _promote_pending_rec(prec: dict[str, Any], h_promo: int) -> str | None:
            nonlocal active_binding, last_recovery_promo_height, last_recovery_promo_time
            nonlocal awaiting_activation, awaiting_activation_since, is_autonomous, h_emancipated, emancipated_owner_policy, unknown_rebind_stalled
            cand = prec["cand"]
            cand_id = prec["cand_id"]
            prev_id = sl.object_id(active_binding)
            promo_bt_int = _block_time_at(h_promo, prec["rtx"], zero_delay=(nr["delay_blocks"] == 0))
            promoted_before_cap = cap_confirmed_height is None or h_promo < cap_confirmed_height
            promoted_before_maj = opened_majority is None or promo_bt_int is None or promo_bt_int < opened_majority
            if promoted_before_cap and promoted_before_maj:
                pre_trigger_pks.update(self._extract_policy_pubkeys(cand.get("owner_policy")))
            last_recovery_promo_height = h_promo
            last_recovery_promo_time = promo_bt_int
            recovery_events.append({
                "candidate_id": cand_id,
                "next_recovery_seal": prec["next_rec_seal"],
                "outcome": "promoted",
                "superseded_id": prev_id,
            })
            if assert_binding_id is not None and assert_binding_id == prev_id:
                return "ORIGIN_BINDING_INVALID"
            active_binding = cand
            seen_binding_regs.add((cand["name"], _outpoint_key(cand["registration"])))
            awaiting_activation = False
            awaiting_activation_since = None
            unknown_rebind_stalled = False
            emancipated_owner_policy = None
            if not is_autonomous and "guardian_policy" in op:
                maj_reached_here = (opened_majority is not None and promo_bt_int is not None and promo_bt_int >= opened_majority) or (
                    majority_cutoff_reached and h_promo == eval_h
                )
                cap_reached_here = cap_confirmed_height is not None and h_promo >= cap_confirmed_height
                if cap_reached_here or maj_reached_here:
                    hok, hpol = self._check_emancipation_handover(
                        active_binding["name"],
                        active_binding["registration"],
                        op["claims"]["intended_owner_policy"],
                        subject_new_owner_policy,
                        chain,
                        active_binding=active_binding,
                        at_height=h_promo,
                        cap_confirmed_height=cap_confirmed_height,
                        last_recovery_promo_height=last_recovery_promo_height,
                        last_recovery_promo_time=last_recovery_promo_time,
                        majority_cutoff_reached=maj_reached_here,
                        opened_majority=opened_majority,
                        pre_trigger_pks=pre_trigger_pks,
                    )
                    if hok and hpol is not None:
                        is_autonomous = True
                        h_emancipated = h_promo
                        emancipated_owner_policy = hpol
            return None

        # Pre-index owner-authored 0x13 and 0x10 events per registration once (O(n) instead of O(n^2), M-1 / R12-M1)
        events_13_cache: dict[tuple[str, str], tuple[list[tuple[int, int, str, dict[str, Any], list[dict[str, Any]]]], str | None]] = {}
        events_10_cache: dict[tuple[str, str], dict[str, list[int]]] = {}

        def _get_indexed_events(bnd: dict[str, Any]) -> tuple[list[tuple[int, int, str, dict[str, Any], list[dict[str, Any]]]], dict[str, list[int]], str | None]:
            ckey = (bnd["name"], _outpoint_key(bnd["registration"]))
            if ckey in events_13_cache:
                evs, err_c = events_13_cache[ckey]
                return evs, events_10_cache.get(ckey, {}), err_c
            nrec_b = chain.get_name_for_registration(bnd["name"], bnd["registration"], historical=True)
            if not isinstance(nrec_b, dict):
                events_13_cache[ckey] = ([], None)
                events_10_cache[ckey] = {}
                return [], {}, None
            raw_u = nrec_b.get("updates", [])
            feh_b = nrec_b.get("first_error_height") if nrec_b.get("history_truncated", False) else None
            upds_b = [
                u for u in raw_u
                if u.get("confirmed_height") is not None
                and int(u["confirmed_height"]) <= eval_h
                and (feh_b is None or int(u["confirmed_height"]) < int(feh_b))
            ]
            out_13: list[tuple[int, int, str, dict[str, Any], list[dict[str, Any]]]] = []
            out_10: dict[str, list[int]] = {}
            for idx in range(1, len(upds_b)):
                u = upds_b[idx]
                uh = int(u["confirmed_height"])
                if not self._is_owner_authored_update(u, upds_b[idx - 1]):
                    continue
                slnk_b, bad_b = self._extract_slnk_bytes_strict(u)
                if not bad_b and slnk_b is None:
                    continue
                try:
                    if bad_b or slnk_b is None:
                        raise ValueError("CHAIN_FRAME_INVALID")
                    dec_b = sl.decode_opreturn_with_criticality(slnk_b)
                except ValueError:
                    events_13_cache[ckey] = ([], "CHAIN_FRAME_INVALID")
                    events_10_cache[ckey] = {}
                    return [], {}, "CHAIN_FRAME_INVALID"
                act_b = dec_b.get("action")
                if act_b == "0x13":
                    out_13.append((uh, idx, dec_b["commitment"], u, upds_b))
                elif act_b == "0x10":
                    out_10.setdefault(dec_b["commitment"], []).append(uh)
            events_13_cache[ckey] = (out_13, None)
            events_10_cache[ckey] = out_10
            return out_13, out_10, None

        def _collect_0x13_events(bnd: dict[str, Any], min_h: int) -> tuple[list[tuple[int, int, str, dict[str, Any], list[dict[str, Any]]]], str | None]:
            evs_all, _, err_c = _get_indexed_events(bnd)
            if err_c is not None:
                return [], err_c
            return [e for e in evs_all if e[0] >= min_h and e[3].get("txid") not in processed_13_txids], None

        def _apply_0x10_cancel_rec(h_q: int) -> tuple[bool, str | None]:
            nonlocal pending_rec
            assert pending_rec is not None
            c_res = _check_0x10_at_h(active_binding, pending_rec["cand_id"], h_q, check_state3_lockout=True)
            if c_res == "CANCEL":
                recovery_events.append({
                    "candidate_id": pending_rec["cand_id"],
                    "next_recovery_seal": pending_rec["next_rec_seal"],
                    "outcome": "cancelled_restored",
                })
                if assert_binding_id is not None and assert_binding_id == pending_rec["cand_id"]:
                    return False, "RECOVERY_FORBIDDEN"
                pending_rec = None
                return True, None
            return False, None

        def _apply_0x10_cancel_reb(h_q: int) -> tuple[bool, str | None]:
            nonlocal pending_reb
            assert pending_reb is not None
            c_b1 = _check_0x10_at_h(
                active_binding, pending_reb["cand_id"], h_q, check_state3_lockout=False, exp_prev_spk_hex=pending_reb["eff_spk_1_hex"]
            )
            c_b2 = (
                _check_0x10_at_h(
                    pending_reb["cand"], pending_reb["cand_id"], h_q, check_state3_lockout=False, exp_prev_spk_hex=pending_reb["b2_spk_hex"]
                )
                if pending_reb.get("cand") is not None
                else "NONE"
            )
            if c_b1 == "CANCEL" or c_b2 == "CANCEL":
                voluntary_rebind_events.append({
                    "candidate_id": pending_reb["cand_id"],
                    "outcome": "cancelled_restored",
                })
                if assert_binding_id is not None and assert_binding_id == pending_reb["cand_id"]:
                    return False, "RECOVERY_FORBIDDEN"
                pending_reb = None
                return True, None
            return False, None

        cur_h = int(bind_tx["confirmed_height"])
        automaton_completed = False
        state_steps_used = 0
        max_total_iters = max(self.max_automaton_steps * 8, 65536)
        for _iter in range(max_total_iters):
            rec_spend_h: int | None = None
            rec_spend_txid: str | None = None
            rec_spend_tx: dict[str, Any] | None = None
            if pending_rec is None:
                rec_spend_h, rec_spend_txid, rec_spend_tx, r_err = _inspect_active_rec_seal()
                if r_err is not None:
                    return None, r_err

            h_cands: set[int] = set()

            def _add_cand(h_val: int | None, *, lo: int = cur_h, hi: int = eval_h) -> None:
                if h_val is not None and int(h_val) in range(lo, hi + 1):
                    h_cands.add(int(h_val))

            # M-1 / F-09: NEVER schedule routine ward renewals — only cap_confirmed_height, policy-change heights, or post-trigger heights!
            if not is_autonomous and "guardian_policy" in op:
                _add_cand(cap_confirmed_height)
                act_nrec_em = chain.get_name_for_registration(active_binding["name"], active_binding["registration"], historical=True)
                if isinstance(act_nrec_em, dict):
                    u_list_em = act_nrec_em.get("updates", [])
                    prev_em_spk: bytes | None = None
                    for u_em in u_list_em:
                        try:
                            cur_em_spk = sl.compile_script_policy(u_em.get("owner_policy"))[0]
                        except (ValueError, KeyError, TypeError):
                            cur_em_spk = None
                        uh_em = u_em.get("confirmed_height")
                        bt_em = u_em.get("block_time")
                        is_policy_chg = prev_em_spk is not None and cur_em_spk != prev_em_spk
                        is_post_cap = cap_confirmed_height is not None and uh_em is not None and int(uh_em) in range(cap_confirmed_height + 1, eval_h + 1)
                        is_post_maj = opened_majority is not None and bt_em is not None and int(bt_em) >= opened_majority
                        if is_policy_chg or is_post_cap or is_post_maj:
                            _add_cand(uh_em)
                        prev_em_spk = cur_em_spk
            if awaiting_activation and awaiting_activation_since is not None:
                act_nrec_s3 = chain.get_name_for_registration(active_binding["name"], active_binding["registration"], historical=True)
                if isinstance(act_nrec_s3, dict):
                    lo_s3 = max(cur_h, awaiting_activation_since)
                    for u_s3 in act_nrec_s3.get("updates", []):
                        uh_s3 = u_s3.get("confirmed_height")
                        if uh_s3 is not None and int(uh_s3) in range(lo_s3, eval_h + 1):
                            v_s3, e_s3 = self._parse_update_value(u_s3, active_binding["name"])
                            if e_s3 is None and v_s3 is not None and v_s3.get("link", {}).get("origin") == origin_id:
                                _add_cand(uh_s3, lo=lo_s3)
                                break
            if pending_rec is not None:
                win_end = min(pending_rec["deadline"] - 1, eval_h)
                nrec_pr = chain.get_name_for_registration(active_binding["name"], active_binding["registration"], historical=True)
                if not self._binding_history_ok_until(nrec_pr, win_end):
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                _, evs10_pr, err10_pr = _get_indexed_events(active_binding)
                if err10_pr is not None:
                    return None, err10_pr
                for uh_10 in evs10_pr.get(pending_rec["cand_id"], ()):
                    _add_cand(uh_10, hi=win_end)
                _add_cand(pending_rec["deadline"])
            if pending_reb is not None:
                win_end_r = min(pending_reb["deadline"] - 1, eval_h)
                b_chk_list = (active_binding, pending_reb["cand"]) if pending_reb.get("cand") is not None else (active_binding,)
                for b_chk in b_chk_list:
                    nrec_rb = chain.get_name_for_registration(b_chk["name"], b_chk["registration"], historical=True)
                    if not self._binding_history_ok_until(nrec_rb, win_end_r):
                        return None, "ORIGIN_STATUS_INCOMPLETE"
                    _, evs10_rb, err10_rb = _get_indexed_events(b_chk)
                    if err10_rb is not None:
                        return None, err10_rb
                    for uh_10 in evs10_rb.get(pending_reb["cand_id"], ()):
                        _add_cand(uh_10, hi=win_end_r)
                _add_cand(pending_reb["deadline"])
            _add_cand(rec_spend_h)
            evs_13, ev13_err = _collect_0x13_events(active_binding, cur_h)
            if ev13_err is not None:
                return None, ev13_err
            for uh_13, _idx13, _cid13, _u13, _upds13 in evs_13:
                h_cands.add(uh_13)

            # Decouple termination from step budget: empty h_cands completes without consuming a step (M01)
            if not h_cands:
                automaton_completed = True
                break
            H = min(h_cands)
            step_changed_state = False

            # ---- Phase 1: Status, Emancipation (incl. H_self > H_promo for B_rec), & Step 3 activation ----
            if not is_autonomous and "guardian_policy" in op:
                bt_h = _block_time_at(H)
                cap_at_h = cap_confirmed_height is not None and H >= cap_confirmed_height
                maj_at_h = (opened_majority is not None and bt_h is not None and bt_h >= opened_majority) or (
                    majority_cutoff_reached and H == eval_h
                )
                if cap_at_h or maj_at_h:
                    hok, hpol = self._check_emancipation_handover(
                        active_binding["name"],
                        active_binding["registration"],
                        op["claims"]["intended_owner_policy"],
                        subject_new_owner_policy,
                        chain,
                        active_binding=active_binding,
                        at_height=H,
                        cap_confirmed_height=cap_confirmed_height,
                        last_recovery_promo_height=last_recovery_promo_height,
                        last_recovery_promo_time=last_recovery_promo_time,
                        majority_cutoff_reached=maj_at_h,
                        opened_majority=opened_majority,
                        pre_trigger_pks=pre_trigger_pks,
                    )
                    if hok and hpol is not None:
                        is_autonomous = True
                        h_emancipated = H
                        emancipated_owner_policy = hpol
                        step_changed_state = True
            if awaiting_activation and awaiting_activation_since is not None:
                s3_ok, s3_pol = self._check_b2_step3_activated(active_binding, origin_id, awaiting_activation_since, H, chain)
                if s3_ok and s3_pol is not None:
                    awaiting_activation = False
                    awaiting_activation_since = None
                    emancipated_owner_policy = s3_pol
                    step_changed_state = True

            # ---- Phase 2: Maturity of pending transitions (deadline == H) ----
            if pending_rec is not None and pending_rec["deadline"] == H:
                perr = _promote_pending_rec(pending_rec, H)
                if perr is not None:
                    return None, perr
                pending_rec = None
                step_changed_state = True
                # Re-inspect newly active recovery seal if it also has a spend on or after H
                rec_spend_h, rec_spend_txid, rec_spend_tx, r_err2 = _inspect_active_rec_seal()
                if r_err2 is not None:
                    return None, r_err2
            if pending_reb is not None and pending_reb["deadline"] == H:
                step_changed_state = True
                if pending_reb.get("unknown_preimage"):
                    unknown_rebind_stalled = True
                    pending_reb = None
                else:
                    b2_mat_st, _ = self._validate_b2_invariant(
                        pending_reb["cand"], chain, pending_reb["h_start"], H, origin_id, allow_origin_at_exact=origin_id
                    )
                    if b2_mat_st == "incomplete":
                        return None, "ORIGIN_STATUS_INCOMPLETE"
                    if b2_mat_st == "valid":
                        prev_id_rb = sl.object_id(active_binding)
                        voluntary_rebind_events.append({
                            "candidate_id": pending_reb["cand_id"],
                            "outcome": "promoted",
                            "superseded_id": prev_id_rb,
                        })
                        if assert_binding_id is not None and assert_binding_id == prev_id_rb:
                            return None, "ORIGIN_BINDING_INVALID"
                        active_binding = pending_reb["cand"]
                        seen_binding_regs.add((active_binding["name"], _outpoint_key(active_binding["registration"])))
                        awaiting_activation = True
                        awaiting_activation_since = H
                        s3_now, s3_now_pol = self._check_b2_step3_activated(active_binding, origin_id, H, H, chain)
                        if s3_now and s3_now_pol is not None:
                            awaiting_activation = False
                            awaiting_activation_since = None
                            emancipated_owner_policy = s3_now_pol
                    else:
                        voluntary_rebind_events.append({
                            "candidate_id": pending_reb["cand_id"],
                            "outcome": "aborted_b2_invalid",
                        })
                    pending_reb = None

            # ---- Phase 3: Cancellations (0x10) & 0x0c intercepts of previously opened transitions (H < deadline) ----
            opened_rec_at_h = False
            opened_reb_at_h = False
            if pending_rec is not None:
                cancelled_r, cerr_r = _apply_0x10_cancel_rec(H)
                if cerr_r is not None:
                    return None, cerr_r
                if cancelled_r:
                    step_changed_state = True
                    rec_spend_h, rec_spend_txid, rec_spend_tx, r_err3 = _inspect_active_rec_seal()
                    if r_err3 is not None:
                        return None, r_err3
            if pending_reb is not None:
                if rec_spend_h == H and rec_spend_txid is not None and rec_spend_tx is not None and not recovery_burned:
                    new_prec, o_err = _try_open_0x0c(rec_spend_txid, rec_spend_tx, H)
                    if o_err is not None:
                        return None, o_err
                    rec_spend_h = None
                    step_changed_state = True
                    if new_prec is not None:
                        voluntary_rebind_events.append({
                            "candidate_id": pending_reb["cand_id"],
                            "outcome": "intercepted_by_0x0c",
                        })
                        pending_reb = None
                        pending_rec = new_prec
                        opened_rec_at_h = True
                if pending_reb is not None:
                    cancelled_rb, cerr_rb = _apply_0x10_cancel_reb(H)
                    if cerr_rb is not None:
                        return None, cerr_rb
                    if cancelled_rb:
                        step_changed_state = True

            # ---- Phase 4: New proposals (0x0c STRICTLY BEFORE 0x13) ----
            started_0x0c_at_h = opened_rec_at_h
            # BLK-3: Once unknown_rebind_stalled is True (H >= h_13 + min_d without B_2 preimage), forbid 0x0c superseding B_1!
            if (
                pending_rec is None
                and pending_reb is None
                and not unknown_rebind_stalled
                and rec_spend_h == H
                and rec_spend_txid is not None
                and rec_spend_tx is not None
                and not recovery_burned
            ):
                new_prec4, o_err4 = _try_open_0x0c(rec_spend_txid, rec_spend_tx, H)
                if o_err4 is not None:
                    return None, o_err4
                rec_spend_h = None
                step_changed_state = True
                if new_prec4 is not None:
                    pending_rec = new_prec4
                    opened_rec_at_h = True
                    started_0x0c_at_h = True

            evs_13_h, ev13_h_err = _collect_0x13_events(active_binding, H)
            if ev13_h_err is not None:
                return None, ev13_h_err
            for uh_13, idx13, cid13, u13, upds13 in evs_13_h:
                if uh_13 != H:
                    continue
                processed_13_txids.add(u13["txid"])
                precond_ok = (
                    not started_0x0c_at_h
                    and pending_rec is None
                    and pending_reb is None
                    and not unknown_rebind_stalled
                    and is_autonomous
                    and not awaiting_activation
                )
                if not precond_ok:
                    voluntary_rebind_events.append({"candidate_id": cid13, "outcome": "rejected", "txid": u13["txid"]})
                    continue
                cand_13 = rec_by_id.get(cid13)
                if cand_13 is None:
                    if cid13 in invalid_rec_preimages:
                        voluntary_rebind_events.append({"candidate_id": cid13, "outcome": "rejected", "txid": u13["txid"]})
                        continue
                    # BLK-3: Cap unknown_preimage rescue window strictly to H + min_d (NEVER H + 35000!),
                    # preventing split-brain resurrection of superseded B_1 after B_2 could already have matured!
                    min_d_u = max(144, int(nr["delay_blocks"])) if nr["mode"] == "dual_party_delayed" else 144
                    pending_reb = {
                        "cand": None,
                        "cand_id": cid13,
                        "deadline": H + min_d_u,
                        "eff_spk_1_hex": sl.compile_script_policy(upds13[idx13 - 1]["owner_policy"])[0].hex(),
                        "h_start": H,
                        "txid": u13["txid"],
                        "unknown_preimage": True,
                    }
                    opened_reb_at_h = True
                    step_changed_state = True
                    continue
                ok_13, h_offer_13, eff_spk_1_hex = self._validate_voluntary_rebind_tx(
                    cand_13, u13, idx13, upds13, active_binding, origin_id, nr, seen_binding_regs, chain, H
                )
                if not ok_13 and h_offer_13 == -1:
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                if not ok_13 or h_offer_13 is None or eff_spk_1_hex is None:
                    voluntary_rebind_events.append({"candidate_id": cid13, "outcome": "rejected", "txid": u13["txid"]})
                    continue
                pending_reb = {
                    "b2_spk_hex": sl.compile_script_policy(cand_13["owner_policy"])[0].hex(),
                    "cand": cand_13,
                    "cand_id": cid13,
                    "deadline": H + cand_13["delay_blocks"],
                    "eff_spk_1_hex": eff_spk_1_hex,
                    "h_offer": h_offer_13,
                    "h_start": H,
                    "txid": u13["txid"],
                }
                opened_reb_at_h = True
                step_changed_state = True

            # ---- Phase 4b: Same-block 0x10 on newly opened transitions at H (inclusive [h_start, deadline)) ----
            if opened_rec_at_h and pending_rec is not None:
                if pending_rec["deadline"] == H:
                    perr_0 = _promote_pending_rec(pending_rec, H)
                    if perr_0 is not None:
                        return None, perr_0
                    pending_rec = None
                else:
                    _, cerr_4b_r = _apply_0x10_cancel_rec(H)
                    if cerr_4b_r is not None:
                        return None, cerr_4b_r
            if opened_reb_at_h and pending_reb is not None:
                _, cerr_4b_rb = _apply_0x10_cancel_reb(H)
                if cerr_4b_rb is not None:
                    return None, cerr_4b_rb

            # M-1: Budget applies strictly to state-changing transitions (rejected/junk frames never brick recovery!)
            if step_changed_state:
                state_steps_used += 1
                if state_steps_used > self.max_automaton_steps:
                    return None, "ORIGIN_STATUS_INCOMPLETE"

            # Re-check if active_recovery_seal advanced to a new seal also spent at H; otherwise strictly advance H + 1
            if pending_rec is None and pending_reb is None and active_recovery_seal is not None and not recovery_burned and not unknown_rebind_stalled:
                next_rh, _, _, next_rerr = _inspect_active_rec_seal()
                if next_rerr is not None:
                    return None, next_rerr
                if next_rh == H:
                    cur_h = H
                    continue
            cur_h = H + 1

        if not automaton_completed or unknown_rebind_stalled:
            return None, "ORIGIN_STATUS_INCOMPLETE"
        if pending_rec is not None:
            return None, "RECOVERY_FORBIDDEN"
        if pending_reb is not None:
            return None, "ORIGIN_STATUS_INCOMPLETE" if pending_reb.get("unknown_preimage") else "RECOVERY_FORBIDDEN"
        final_active_nrec = chain.get_name_for_registration(active_binding["name"], active_binding["registration"], historical=True)
        if final_active_nrec is not None and not self._binding_history_ok_until(final_active_nrec, eval_h):
            return None, "ORIGIN_STATUS_INCOMPLETE"
        voluntary_latest_pol: dict[str, Any] | None = None
        if awaiting_activation or active_binding.get("binding_mode") == "voluntary":
            s3_fin_ok, voluntary_latest_pol = self._check_b2_step3_activated(active_binding, origin_id, 0, eval_h, chain)
            if awaiting_activation or not s3_fin_ok or voluntary_latest_pol is None:
                return None, "ORIGIN_BINDING_INVALID"
        if recovery_burned and assert_binding_id is not None and assert_binding_id != sl.object_id(active_binding):
            return None, "RECOVERY_FORBIDDEN"

        # G-9: Verify presented card matches active_binding name
        if card_obj is not None and card_obj.get("name") != active_binding["name"]:
            return None, "ORIGIN_UNVERIFIED"

        # Decision 1B / H-5 / M-9: Unified emancipation state machine for BOTH person & agent (R2G-02, R2G-04)
        emancipation_triggered = capacity_confirmed or majority_cutoff_reached
        if emancipation_triggered:
            if active_binding.get("binding_mode") == "voluntary":
                emancipated_owner_policy = voluntary_latest_pol
            else:
                handover_ok, latest_em_pol = self._check_emancipation_handover(
                    active_binding["name"],
                    active_binding["registration"],
                    op["claims"]["intended_owner_policy"],
                    subject_new_owner_policy,
                    chain,
                    active_binding=active_binding,
                    at_height=at_height,
                    cap_confirmed_height=cap_confirmed_height,
                    last_recovery_promo_height=last_recovery_promo_height,
                    last_recovery_promo_time=last_recovery_promo_time,
                    majority_cutoff_reached=majority_cutoff_reached,
                    opened_majority=opened_majority,
                    pre_trigger_pks=pre_trigger_pks,
                )
                if not handover_ok or latest_em_pol is None:
                    return None, "GUARDIAN_TRANSFER_PENDING"
                emancipated_owner_policy = latest_em_pol
            eff_binding = copy.deepcopy(active_binding)
            if emancipated_owner_policy is not None:
                eff_binding["owner_policy"] = copy.deepcopy(emancipated_owner_policy)
            return {
                "origin_id": origin_id,
                "capacity": "autonomous",
                "binding": active_binding,
                "effective_binding": eff_binding,
                "active_recovery_seal": active_recovery_seal,
                "recovery_burned": recovery_burned,
                "recovery_events": recovery_events,
                "voluntary_rebind_events": voluntary_rebind_events,
                "emancipated_by_majority": emancipated_by_majority,
            }, None

        if "guardian_policy" not in op:
            if active_binding.get("binding_mode") == "voluntary":
                emancipated_owner_policy = voluntary_latest_pol
            elif isinstance(final_active_nrec, dict):
                nrec_eff, nerr_eff = self.resolve_name(
                    active_binding["name"],
                    chain,
                    expected_registration=active_binding["registration"],
                    require_writer=True,
                    require_history=True,
                    at_height=at_height,
                    historical=(at_height is not None),
                    allow_unresolved_voluntary_rebind=True,
                )
                if nerr_eff is None and nrec_eff is not None:
                    emancipated_owner_policy = copy.deepcopy(nrec_eff["owner_policy"])
            eff_b = copy.deepcopy(active_binding)
            if emancipated_owner_policy is not None:
                eff_b["owner_policy"] = copy.deepcopy(emancipated_owner_policy)
            return {
                "origin_id": origin_id,
                "capacity": "autonomous",
                "binding": active_binding,
                "effective_binding": eff_b,
                "active_recovery_seal": active_recovery_seal,
                "recovery_burned": recovery_burned,
                "recovery_events": recovery_events,
                "voluntary_rebind_events": voluntary_rebind_events,
            }, None

        # Walk roster_seal chain & per-slot UTXO chains at eval_h (R1 #1, G-5, R2G-08, H-4, Decision 4)
        gp = op["guardian_policy"]
        active_roster: dict[str, Any] = {
            "revision": gp["revision"],
            "revision_size": gp["revision_size"],
            "disposer_pk": gp["disposer_pk"],
            "arbiter_pk": gp["arbiter_pk"],
            "challenger_pk": gp["challenger_pk"],
            "quorums": gp["quorums"],
            "appointment_delay_blocks": gp["appointment_delay_blocks"],
        }
        cur_roster_seal = gp["roster_seal"]
        raw_roster_recs = origin_bundle.get("roster_records", [])
        raw_guard_recs = origin_bundle.get("guardian_records", [])
        raw_init_disc = origin_bundle.get("initial_guardian_disclosures", {})
        raw_guard_assents = origin_bundle.get("guardian_assents", [])
        if (
            not isinstance(raw_roster_recs, list)
            or not isinstance(raw_guard_recs, list)
            or not isinstance(raw_init_disc, dict)
            or not isinstance(raw_guard_assents, list)
        ):
            return None, "ORIGIN_STATUS_INCOMPLETE"
        roster_records_by_caddr: dict[str, dict[str, Any]] = {}
        for r in raw_roster_recs:
            if isinstance(r, dict):
                try:
                    roster_records_by_caddr[sl.content_addr(r)] = r
                except Exception:
                    pass
        slot_states: dict[int, dict[str, Any]] = {}
        init_vac_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(gp["disposer_pk"], gp["arbiter_pk"])}
        for s in gp["slots"]:
            slot_states[s["slot"]] = {
                "state": "initial_vacant",
                "vacant_outpoint": {"txid": s["vacant_utxo"]["txid"], "vout": s["vacant_utxo"]["vout"]},
                "vacant_policy": s["vacant_utxo"].get("script_policy", init_vac_pol),
                "initial_guardian_commitment": s["initial_guardian_commitment"],
            }

        g_by_caddr: dict[str, dict[str, Any]] = {}
        g_by_id: dict[str, dict[str, Any]] = {}
        for g in raw_guard_recs:
            if isinstance(g, dict) and isinstance(g.get("payload"), dict):
                try:
                    g_by_caddr[sl.content_addr(g)] = g
                    g_by_id[sl.object_id(g["payload"])] = g
                except Exception:
                    pass
        init_disclosures = raw_init_disc
        g_assents_by_target: dict[str, dict[str, Any]] = {}
        for ga in raw_guard_assents:
            if isinstance(ga, dict) and isinstance(ga.get("payload"), dict) and isinstance(ga["payload"].get("target_id"), str):
                g_assents_by_target[ga["payload"]["target_id"]] = ga

        def _is_allowed_guard_issuer(iss_pin: dict[str, Any]) -> bool:
            return any(_name_pin_equal(iss_pin, allow) for allow in allowed_guard_issuers)

        def trace_slot(
            slot_num: int,
            st: dict[str, Any],
            roster_ctx: dict[str, Any],
            *,
            max_h: int | None = None,
        ) -> dict[str, Any]:
            limit_h = eval_h if max_h is None else max_h
            is_hist_cutoff = (at_height is not None) or (max_h is not None)
            cur = copy.deepcopy(st)
            exp_vac_spk, _ = sl.compile_script_policy(
                {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(roster_ctx["disposer_pk"], roster_ctx["arbiter_pk"])}
            )
            for _ in range(257):
                if cur["state"] in ("initial_vacant", "vacant"):
                    op_u = cur["vacant_outpoint"]
                    u_tx = chain.get_tx(op_u["txid"])
                    uout = chain.get_output(op_u["txid"], op_u["vout"])
                    if (
                        not u_tx
                        or u_tx.get("confirmed_height") is None
                        or u_tx["confirmed_height"] > limit_h
                        or not uout
                        or uout.get("script_pubkey_hex") != exp_vac_spk.hex()
                    ):
                        cur["state"] = "contested_burned"
                        return cur
                    if not uout.get("spent_by_txid"):
                        if uout.get("absent_from_utxo"):
                            cur["state"] = "contested_burned"
                        return cur
                    stxid = uout["spent_by_txid"]
                    stx = chain.get_tx(stxid)
                    if not stx:
                        cur["state"] = "contested_burned"
                        return cur
                    # G-5: Unconfirmed 0x12/0x0d spend MUST NOT burn slot; R1 #1 & H-2: spend after limit_h ignored!
                    h_stx = stx.get("confirmed_height")
                    if h_stx is None or h_stx > limit_h:
                        return cur
                    dec = self._decode_opreturn_tx(stx, require_confirmed=True)
                    if dec is None:
                        cur["state"] = "contested_burned"
                        return cur
                    if stx.get("inputs") and not self._tx_spends_outpoint(stx, op_u):
                        cur["state"] = "contested_burned"
                        return cur
                    if chain.tip_height - h_stx + 1 < self.operator_min_depth:
                        return cur

                    # Direct initial activation (0x12) ONLY from initial_vacant at revision 1
                    if dec["action"] == "0x12":
                        if cur["state"] != "initial_vacant" or roster_ctx["revision"] != 1:
                            cur["state"] = "contested_burned"
                            return cur
                        grec = g_by_caddr.get(dec["commitment"])
                        if not grec:
                            cur["state"] = "contested_burned"
                            return cur
                        ok_gw, _ = self._verify_object_wire(grec, expected_type="seallink-guardian/1")
                        if not ok_gw or grec["payload"].get("activation_mode") != "initial":
                            cur["state"] = "contested_burned"
                            return cur
                        gp_rec = grec["payload"]
                        if (
                            gp_rec["origin_id"] != origin_id
                            or gp_rec["slot"] != slot_num
                            or gp_rec["revision"] != 1
                            or gp_rec["network"] != self.pinned_network
                            or gp_rec["genesis"] != self.pinned_genesis
                            or gp_rec["prev_outpoint"] != {"txid": op_u["txid"], "vout": op_u["vout"]}
                            or not _is_allowed_guard_issuer(gp_rec["issuer"])
                        ):
                            cur["state"] = "contested_burned"
                            return cur
                        if self.verify_issuer_role_at_height(gp_rec["issuer"], grec, "cred", h_stx, chain, journal=journal) is not None:
                            cur["state"] = "contested_burned"
                            return cur
                        if not self._verify_guardian_incoming_assent(grec, g_assents_by_target, chain, at_height=h_stx):
                            cur["state"] = "contested_burned"
                            return cur
                        disc = init_disclosures.get(str(slot_num)) or init_disclosures.get(slot_num)
                        try:
                            disc_ok = (
                                isinstance(disc, dict)
                                and isinstance(disc.get("salt_hex"), str)
                                and sl.clause_commit(disc["salt_hex"], gp_rec["guardian"]) == cur["initial_guardian_commitment"]
                            )
                        except ValueError:
                            disc_ok = False
                        if not disc_ok:
                            cur["state"] = "contested_burned"
                            return cur
                        ap_pol = gp_rec["active_policy"]
                        if ap_pol.get("template") != "either_of_2" or (
                            ap_pol["keys"]["a"] != roster_ctx["disposer_pk"] and ap_pol["keys"]["b"] != roster_ctx["disposer_pk"]
                        ):
                            cur["state"] = "contested_burned"
                            return cur
                        act_op = {"txid": stxid, "vout": gp_rec["active_vout"]}
                        aout = chain.get_output(act_op["txid"], act_op["vout"])
                        exp_act_spk, _ = sl.compile_script_policy(ap_pol)
                        if not aout or aout.get("script_pubkey_hex") != exp_act_spk.hex():
                            cur["state"] = "contested_burned"
                            return cur
                        cur = {
                            "state": "active",
                            "active_outpoint": act_op,
                            "active_policy": ap_pol,
                            "guardian_name": gp_rec["guardian"]["name"],
                            "guardian_pin": gp_rec["guardian"],
                            "guardian_id": sl.object_id(gp_rec),
                            "term": gp_rec["term"],
                        }
                        continue

                    # Stage 1 appointment (0x0d)
                    if dec["action"] == "0x0d":
                        # B-15: forbid 0x0d on new_vacant before roster revision effective_delay_blocks elapsed!
                        if cur.get("min_appoint_height") is not None and h_stx < cur["min_appoint_height"]:
                            cur["state"] = "contested_burned"
                            return cur
                        grec = g_by_caddr.get(dec["commitment"])
                        if not grec:
                            cur["state"] = "contested_burned"
                            return cur
                        ok_gw, _ = self._verify_object_wire(grec, expected_type="seallink-guardian/1")
                        if not ok_gw or grec["payload"].get("activation_mode") != "appointed":
                            cur["state"] = "contested_burned"
                            return cur
                        gp_rec = grec["payload"]
                        if (
                            gp_rec["origin_id"] != origin_id
                            or gp_rec["slot"] != slot_num
                            or gp_rec["revision"] != roster_ctx["revision"]
                            or gp_rec["network"] != self.pinned_network
                            or gp_rec["genesis"] != self.pinned_genesis
                            or gp_rec["prev_outpoint"] != {"txid": op_u["txid"], "vout": op_u["vout"]}
                            or not _is_allowed_guard_issuer(gp_rec["issuer"])
                        ):
                            cur["state"] = "contested_burned"
                            return cur
                        if self.verify_issuer_role_at_height(gp_rec["issuer"], grec, "cred", h_stx, chain, journal=journal) is not None:
                            cur["state"] = "contested_burned"
                            return cur
                        if not self._verify_guardian_incoming_assent(grec, g_assents_by_target, chain, at_height=h_stx):
                            cur["state"] = "contested_burned"
                            return cur
                        pp = gp_rec["pending_policy"]
                        ap_pol = gp_rec["active_policy"]
                        try:
                            exp_act_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(pp["keys"]["guardian"], roster_ctx["disposer_pk"])}
                            exp_act_spk_chk, _ = sl.compile_script_policy(exp_act_pol)
                            got_act_spk_chk, _ = sl.compile_script_policy(ap_pol)
                        except (ValueError, KeyError, TypeError):
                            exp_act_spk_chk, got_act_spk_chk = b"", b"x"
                        if (
                            pp.get("template") != "guardian_slot_pending"
                            or pp["keys"]["disposer"] != roster_ctx["disposer_pk"]
                            or pp["keys"]["challenger"] != roster_ctx["challenger_pk"]
                            or pp["delay_blocks"] != gp_rec["effective_delay_blocks"]
                            or gp_rec["effective_delay_blocks"] < roster_ctx["appointment_delay_blocks"]
                            or ap_pol.get("template") != "either_of_2"
                            or got_act_spk_chk != exp_act_spk_chk
                        ):
                            cur["state"] = "contested_burned"
                            return cur
                        pend_op = {"txid": stxid, "vout": gp_rec["pending_vout"]}
                        pout = chain.get_output(pend_op["txid"], pend_op["vout"])
                        exp_pend_spk, _ = sl.compile_script_policy(pp)
                        if not pout or pout.get("script_pubkey_hex") != exp_pend_spk.hex():
                            cur["state"] = "contested_burned"
                            return cur
                        cur = {
                            "state": "pending_delay",
                            "pending_outpoint": pend_op,
                            "pending_policy": pp,
                            "pending_height": h_stx,
                            "delay_blocks": gp_rec["effective_delay_blocks"],
                            "guardian_record": grec,
                        }
                        continue
                    cur["state"] = "contested_burned"
                    return cur
                elif cur["state"] == "pending_delay":
                    pop = cur["pending_outpoint"]
                    pout = chain.get_output(pop["txid"], pop["vout"])
                    if not pout:
                        cur["state"] = "contested_burned"
                        return cur
                    if not pout.get("spent_by_txid"):
                        if pout.get("absent_from_utxo"):
                            cur["state"] = "contested_burned"
                        return cur
                    stxid = pout["spent_by_txid"]
                    stx = chain.get_tx(stxid)
                    if not stx or stx.get("confirmed_height") is None or stx["confirmed_height"] > limit_h:
                        return cur
                    dec = self._decode_opreturn_tx(stx, require_confirmed=True)
                    grec = cur["guardian_record"]
                    gp_rec = grec["payload"]
                    gid = sl.object_id(gp_rec)
                    if dec is not None and dec.get("action") == "0x0e" and dec.get("commitment") == gid:
                        # R3 H4 + R2-L-02: verify height delay, depth, AND strict 4-item CSV witness + BIP-68 sequence!
                        if stx["confirmed_height"] < cur["pending_height"] + cur["delay_blocks"]:
                            cur["state"] = "contested_burned"
                            return cur
                        if chain.tip_height - stx["confirmed_height"] + 1 < self.operator_min_depth:
                            return cur
                        if not self._is_0x0e_guardian_csv_branch(
                            stx, pop, cur["pending_policy"], cur["delay_blocks"]
                        ):
                            cur["state"] = "contested_burned"
                            return cur
                        act_op = {"txid": stxid, "vout": 0}
                        aout = chain.get_output(stxid, 0)
                        exp_act_spk, _ = sl.compile_script_policy(gp_rec["active_policy"])
                        if not aout or aout.get("script_pubkey_hex") != exp_act_spk.hex():
                            cur["state"] = "contested_burned"
                            return cur
                        cur = {
                            "state": "active",
                            "active_outpoint": act_op,
                            "active_policy": gp_rec["active_policy"],
                            "guardian_name": gp_rec["guardian"]["name"],
                            "guardian_pin": gp_rec["guardian"],
                            "guardian_id": gid,
                            "term": gp_rec["term"],
                        }
                        continue
                    vout0 = chain.get_output(stxid, 0)
                    if vout0 and vout0.get("script_pubkey_hex") == exp_vac_spk.hex():
                        cur = {"state": "vacant", "vacant_outpoint": {"txid": stxid, "vout": 0}}
                        continue
                    cur["state"] = "contested_burned"
                    return cur
                elif cur["state"] == "active":
                    aop = cur["active_outpoint"]
                    # H-4: Check persisted guardian_slot closure at tip (only on final tip pass, not intermediate 0x0f snapshot!)
                    if not is_hist_cutoff and journal is not None:
                        scl = journal.lookup_closure(
                            {"origin_id": origin_id, "outpoint": aop, "slot": slot_num, "subject_kind": "guardian_slot"}
                        )
                        if scl is not None:
                            cur["state"] = "contested_burned"
                            return cur
                    aout = chain.get_output(aop["txid"], aop["vout"])
                    if not aout:
                        cur["state"] = "contested_burned"
                        return cur
                    if not aout.get("spent_by_txid"):
                        if aout.get("absent_from_utxo"):
                            cur["state"] = "contested_burned"
                        return cur
                    stxid = aout["spent_by_txid"]
                    stx = chain.get_tx(stxid)
                    # R1 #1 / H-2: At historical eval_h or intermediate 0x0f transition height limit_h, spends > limit_h (or unconfirmed) had not occurred yet!
                    if is_hist_cutoff and stx is not None and (stx.get("confirmed_height") is None or stx["confirmed_height"] > limit_h):
                        return cur
                    vout0 = chain.get_output(stxid, 0)
                    # Mempool halt at tip acts immediately -> record closure & slot is no longer active!
                    if not is_hist_cutoff and journal is not None:
                        journal.record_closure(
                            {"origin_id": origin_id, "outpoint": aop, "slot": slot_num, "subject_kind": "guardian_slot"},
                            "SEAL_SPENT",
                            observed_at=chain.now,
                            observed_height=chain.tip_height,
                            spend_txid=stxid,
                        )
                    if stx and stx.get("confirmed_height") is not None and vout0 and vout0.get("script_pubkey_hex") == exp_vac_spk.hex():
                        cur = {"state": "vacant", "vacant_outpoint": {"txid": stxid, "vout": 0}}
                        continue
                    cur["state"] = "contested_burned"
                    return cur
                else:
                    return cur
            # R2G-08 / H-28: Walk depth exhausted (> 256 transitions) -> ORIGIN_STATUS_INCOMPLETE!
            return {"state": "_walk_exhausted"}

        # Walk roster_seal transitions (0x0f) up to eval_h (R1 #1, B-14, B-15, G-5, H-27, H-28, H-31, H-33, H-2/F-05)
        # H-2 (F-05): Trace revision R's slots strictly up to roster_eff_h BEFORE handing off carried-over outpoints to R+1!
        seen_roster_ops: set[str] = set()
        while True:
            cur_rk = _outpoint_key(cur_roster_seal)
            exp_r_spk, _ = sl.compile_script_policy(
                {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(active_roster["disposer_pk"], active_roster["arbiter_pk"])}
            )
            r_cre_tx = chain.get_tx(cur_roster_seal["txid"])
            rout = chain.get_output(cur_roster_seal["txid"], cur_roster_seal["vout"])
            if (
                cur_rk in seen_roster_ops
                or len(seen_roster_ops) == 257
                or not r_cre_tx
                or r_cre_tx.get("confirmed_height") is None
                or r_cre_tx["confirmed_height"] > eval_h
                or not rout
                or rout.get("script_pubkey_hex") != exp_r_spk.hex()
            ):
                return None, "ORIGIN_STATUS_INCOMPLETE"
            seen_roster_ops.add(cur_rk)
            rspend = rout.get("spent_by_txid")
            if not rspend:
                if rout.get("absent_from_utxo"):
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                break
            rtx = chain.get_tx(rspend)
            # G-5: Unconfirmed 0x0f does not invalidate active roster; R1 #1: 0x0f after eval_h not yet active!
            if rtx is not None and (rtx.get("confirmed_height") is None or rtx["confirmed_height"] > eval_h):
                break
            dec_r = self._decode_opreturn_tx(rtx, expected_action="0x0f")
            if dec_r is None or (rtx.get("inputs") and not self._tx_spends_outpoint(rtx, cur_roster_seal)):
                return None, "ORIGIN_STATUS_INCOMPLETE"
            assert rtx is not None
            if chain.tip_height - rtx["confirmed_height"] + 1 < self.operator_min_depth:
                return None, "CHAIN_DEPTH_INSUFFICIENT"
            rrec = roster_records_by_caddr.get(dec_r["commitment"])
            ok_rw = self._verify_object_wire(rrec, expected_type="seallink-guardian-roster/1")[0] if rrec else False
            if not rrec or not ok_rw:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            rp = rrec["payload"]
            if (
                rp["origin_id"] != origin_id
                or rp["network"] != self.pinned_network
                or rp["genesis"] != self.pinned_genesis
                or rp["prev_revision"] != active_roster["revision"]
                or rp["revision"] != active_roster["revision"] + 1
                or rp["prev_roster_outpoint"] != {"txid": cur_roster_seal["txid"], "vout": cur_roster_seal["vout"]}
                or not _is_allowed_guard_issuer(rp["issuer"])
                or rp["effective_delay_blocks"] < active_roster["appointment_delay_blocks"]
            ):
                return None, "ORIGIN_STATUS_INCOMPLETE"
            r_iss_err = self.verify_issuer_role_at_height(rp["issuer"], rrec, "cred", rtx["confirmed_height"], chain, journal=journal)
            if r_iss_err:
                return None, r_iss_err if r_iss_err in ("CRED_ISSUER_CLOSED", "WIRE_SIGNATURE") else "ORIGIN_STATUS_INCOMPLETE"
            ok_rc, code_rc = sl.check_guardian_policy_consistency(rp, prev_roster=active_roster)
            if not ok_rc:
                return None, code_rc
            nxt_rout = chain.get_output(rspend, rp["next_roster_vout"])
            exp_nr_spk, _ = sl.compile_script_policy(rp["next_roster_policy"])
            if not nxt_rout or nxt_rout.get("script_pubkey_hex") != exp_nr_spk.hex():
                return None, "ORIGIN_STATUS_INCOMPLETE"
            roster_eff_h = rtx["confirmed_height"] + rp["effective_delay_blocks"]
            if eval_h < roster_eff_h:
                break
            # Snapshot revision R's slots at exact transition height roster_eff_h (NEVER past roster_eff_h!)
            prev_slot_states: dict[int, dict[str, Any]] = {}
            for snum in list(slot_states.keys()):
                prev_slot_states[snum] = trace_slot(snum, slot_states[snum], active_roster, max_h=roster_eff_h)
                if prev_slot_states[snum].get("state") == "_walk_exhausted":
                    return None, "ORIGIN_STATUS_INCOMPLETE"
            # Build provenance maps of active & vacant outpoints from immediately preceding revision (H-33: supports renumbering!)
            prev_active_by_op: dict[str, dict[str, Any]] = {}
            prev_vacant_by_op: dict[str, dict[str, Any]] = {}
            for ps in prev_slot_states.values():
                if ps.get("state") == "active" and "active_outpoint" in ps:
                    prev_active_by_op[_outpoint_key(ps["active_outpoint"])] = ps
                elif ps.get("state") in ("vacant", "initial_vacant") and "vacant_outpoint" in ps:
                    prev_vacant_by_op[_outpoint_key(ps["vacant_outpoint"])] = ps
            used_carried_ops: set[str] = set()

            active_roster = {
                "revision": rp["revision"],
                "revision_size": rp["revision_size"],
                "disposer_pk": rp["disposer_pk"],
                "arbiter_pk": rp["arbiter_pk"],
                "challenger_pk": rp["challenger_pk"],
                "quorums": rp["quorums"],
                "appointment_delay_blocks": active_roster["appointment_delay_blocks"],
            }
            cur_roster_seal = {
                "txid": rspend,
                "vout": rp["next_roster_vout"],
                "script_policy": rp["next_roster_policy"],
            }
            new_slot_states: dict[int, dict[str, Any]] = {}
            for sspec in rp["slots"]:
                sn = sspec["slot"]
                act = sspec["action"]
                if act == "retain_active":
                    opk = _outpoint_key(sspec["active_outpoint"])
                    prev_s = prev_active_by_op.get(opk)
                    grec = g_by_id.get(sspec["guardian_id"])
                    if (
                        opk in used_carried_ops
                        or not prev_s
                        or prev_s.get("guardian_id") != sspec["guardian_id"]
                        or not grec
                    ):
                        new_slot_states[sn] = {"state": "contested_burned"}
                    else:
                        used_carried_ops.add(opk)
                        new_slot_states[sn] = copy.deepcopy(prev_s)
                elif act == "retain_vacant":
                    opk = _outpoint_key(sspec["vacant_outpoint"])
                    prev_v = prev_vacant_by_op.get(opk)
                    if opk in used_carried_ops or not prev_v:
                        new_slot_states[sn] = {"state": "contested_burned"}
                    else:
                        used_carried_ops.add(opk)
                        new_slot_states[sn] = {"state": "vacant", "vacant_outpoint": sspec["vacant_outpoint"]}
                elif act == "new_vacant":
                    nv_out = chain.get_output(rspend, sspec["new_vacant_vout"])
                    nv_spk, _ = sl.compile_script_policy(sspec["new_vacant_policy"])
                    if not nv_out or nv_out.get("script_pubkey_hex") != nv_spk.hex():
                        new_slot_states[sn] = {"state": "contested_burned"}
                    else:
                        new_slot_states[sn] = {
                            "state": "vacant",
                            "vacant_outpoint": {"txid": rspend, "vout": sspec["new_vacant_vout"]},
                            "min_appoint_height": roster_eff_h,
                        }
            slot_states = new_slot_states

        # Trace final active revision's slots up to eval_h
        for snum in list(slot_states.keys()):
            if slot_states[snum].get("state") != "contested_burned":
                slot_states[snum] = trace_slot(snum, slot_states[snum], active_roster)
                if slot_states[snum].get("state") == "_walk_exhausted":
                    return None, "ORIGIN_STATUS_INCOMPLETE"

        return {
            "origin_id": origin_id,
            "capacity": "ward",
            "binding": active_binding,
            "effective_binding": active_binding,
            "active_recovery_seal": active_recovery_seal,
            "recovery_burned": recovery_burned,
            "recovery_events": recovery_events,
            "roster": active_roster,
            "slots": slot_states,
            "opened_majority_unix": opened_majority,
        }, None

    def verify_ward_approvals(
        self,
        env: dict[str, Any],
        ward_state: dict[str, Any],
        chain: ChainView,
        *,
        at_height: int | None = None,
        at_time: int | None = None,
        journal: FencedJournal | None = None,
        origin_bundles_by_oid: dict[str, dict[str, Any]] | None = None,
    ) -> tuple[bool, str | None, dict[str, Any]]:
        """Enforce SL-ORIG-006 + SL-WIRE-013 guardian_approvals[] verification in canonical precedence (R1 #1, R2-04, H-34, H-35, H-4)."""
        payload = env["payload"]
        if "guardian_context" not in payload or "guardian_approvals" not in env or "signatures" in env:
            return False, "WARD_AUTONOMOUS_FORBIDDEN", {}
        gc = payload["guardian_context"]
        if gc["origin_id"] != ward_state["origin_id"] or gc["ward_name"] != ward_state["binding"]["name"]:
            return False, "ORIGIN_UNVERIFIED", {}
        roster = ward_state["roster"]
        if gc["revision"] != roster["revision"]:
            return False, "GUARDIAN_QUORUM_UNMET", {}

        approvals = env["guardian_approvals"]
        for item in approvals:
            if item["revision"] != gc["revision"]:
                return False, "GUARDIAN_QUORUM_UNMET", {}

        eval_h = chain.tip_height if at_height is None else at_height
        eval_t = chain.now if at_time is None else at_time
        recent_blk_h = (
            chain.raw.get("blocks", {}).get(payload["recent_block"])
            if (at_height is None and isinstance(payload.get("recent_block"), str))
            else None
        )
        digest = sl.signing_digest(payload)
        verified_slots: list[int] = []
        verified_guardians: list[str] = []
        seen_guardian_regs: set[str] = set()
        opened_maj = ward_state.get("opened_majority_unix")

        # Pass 1 (H-34 / M-6): Validate ALL slot states, terms, distinct registrations, & guardian identities BEFORE 0x0b & sig checks!
        resolved_entries: list[tuple[dict[str, Any], dict[str, Any] | None, str | None, int, dict[str, Any], dict[str, Any]]] = []
        for item in approvals:
            sn = item["slot"]
            st = ward_state["slots"].get(sn)
            if not st or st.get("state") != "active":
                return False, "GUARDIAN_INACTIVE", {}
            if st["guardian_name"] != item["guardian_name"]:
                return False, "GUARDIAN_INACTIVE", {}
            term = st.get("term", {"mode": "indefinite"})
            if term.get("mode") == "calendar":
                if opened_maj is not None and term["not_after_unix"] > opened_maj:
                    return False, "GUARDIAN_INACTIVE", {}
                if eval_h >= term["ceiling_height"] or eval_t >= term["not_after_unix"]:
                    return False, "GUARDIAN_INACTIVE", {}
            gpin = st["guardian_pin"]
            greg = _outpoint_key(gpin["registration"])
            if greg in seen_guardian_regs:
                return False, "GUARDIAN_INACTIVE", {}
            seen_guardian_regs.add(greg)
            # R1 #1 / R2-04 / F-12b: Resolve guardian's link.grant at eval_h (historical anchor or live tip) + 0x13 origin_bundles_by_oid!
            gnrec, gerr = self.resolve_name(
                gpin["name"],
                chain,
                expected_owner_policy=gpin["owner_policy"],
                expected_registration=gpin["registration"],
                at_height=at_height,
                allow_unresolved_voluntary_rebind=bool(origin_bundles_by_oid),
            )
            if gerr or gnrec is None:
                return False, "GUARDIAN_INACTIVE", {}
            if gnrec.get("_voluntary_rebinds"):
                rb_err_g = self._verify_rebound_pin(
                    gnrec, gpin, None, chain, journal, origin_bundles_by_oid=origin_bundles_by_oid, at_height=at_height
                )
                if rb_err_g:
                    return False, "GUARDIAN_INACTIVE", {}
            gpol, rerr = self.resolve_role_policy(
                gnrec, "grant", item["signatures"]["policy"], recent_block_height=recent_blk_h
            )
            if rerr and rerr != "WIRE_SIGNATURE":
                return False, "GUARDIAN_INACTIVE", {}
            resolved_entries.append((item, gpol, rerr, sn, gpin, gnrec))

        # Pass 2 (M-6 / A-17): Check policy-scoped 0x0b compromise (BOTH historical & live tip!) & cryptographic SignatureSet
        for item, gpol, rerr, sn, gpin, gnrec in resolved_entries:
            if rerr is not None or gpol is None:
                return False, "WIRE_SIGNATURE", {}
            min_hc = self._policy_compromised_cutoff(gnrec, gpin, "grant", gpol, chain)
            if min_hc is not None and eval_h >= min_hc:
                if journal is not None and at_height is None:
                    journal.record_closure(
                        {
                            "cutoff_height": min_hc,
                            "name": gpin["name"],
                            "policy_sha256": _policy_sha256(gpol),
                            "registration": gpin["registration"],
                            "role": "grant",
                            "subject_kind": "role",
                        },
                        "CRED_ISSUER_CLOSED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                    )
                return False, "CRED_ISSUER_CLOSED", {}
            ok_s, code_s = sl.verify_signature_set(
                digest, item["signatures"], expected_policy=gpol, obj_type="__guardian_approval__"
            )
            if not ok_s:
                return False, code_s, {}
            verified_slots.append(sn)
            verified_guardians.append(gpin["name"])

        derived_class = sl.derive_guardian_event_class(payload)
        if gc["event_class"] != derived_class:
            return False, "GUARDIAN_QUORUM_UNMET", {}
        req = sl.required_guardian_slots(roster["quorums"][derived_class], roster["revision_size"])
        if len(verified_slots) < req:
            return False, "GUARDIAN_QUORUM_UNMET", {}

        return True, None, {
            "derived_event_class": derived_class,
            "verified_slots": verified_slots,
            "verified_guardians": verified_guardians,
            "verified_revision": roster["revision"],
        }

    # ------------------------------------------------------------------
    # SPEC-05 Assent (multi-ward & anchor-time freshness), Contract, Credential, Notary, Verdict, Termination, Statements
    # ------------------------------------------------------------------

    @staticmethod
    def _pick_origin_bundle_for_oid(
        oid: str,
        origin_bundle: dict[str, Any] | None,
        origin_bundles_by_oid: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        cand = None
        if origin_bundles_by_oid and oid in origin_bundles_by_oid:
            cand = origin_bundles_by_oid[oid]
        elif origin_bundle is not None:
            if oid in origin_bundle and isinstance(origin_bundle[oid], dict) and "origin" in origin_bundle[oid]:
                cand = origin_bundle[oid]
            elif "origin" in origin_bundle and isinstance(origin_bundle["origin"], dict):
                cand = origin_bundle
        if isinstance(cand, dict) and isinstance(cand.get("origin"), dict) and isinstance(cand["origin"].get("payload"), dict):
            try:
                if sl.object_id(cand["origin"]["payload"]) == oid:
                    return cand
            except Exception:
                return None
        return None

    def verify_assent(
        self,
        assent_env: dict[str, Any],
        contract_obj: dict[str, Any],
        origin_bundle: dict[str, Any] | None,
        chain: ChainView,
        *,
        origin_bundles_by_oid: dict[str, dict[str, Any]] | None = None,
        anchor_time: int | None = None,
        anchor_height: int | None = None,
        journal: FencedJournal | None = None,
    ) -> VerifierResult:
        ok_a, a_res = self._verify_object_wire(assent_env, expected_type="seallink-assent/1")
        if not ok_a:
            return VerifierResult("REFUSE", a_res)
        ok_c, c_res = self._verify_object_wire(contract_obj, expected_type="seallink-contract/1")
        if not ok_c:
            return VerifierResult("REFUSE", c_res)
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        ap = a_res["payload"]
        if ap["network"] != self.pinned_network or ap["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        if ap["target_type"] != "seallink-contract/1" or ap["target_id"] != sl.object_id(contract_obj):
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        # R2-02 / H-5: Check exact 72h freshness at anchor_time when anchored, else chain.now (issued_at <= ref_t < expires_at, expires_at - issued_at <= 259200)
        ref_t = anchor_time if anchor_time is not None else chain.now
        if (
            (ap["expires_at"] - ap["issued_at"]) > 259200
            or ref_t < ap["issued_at"]
            or ref_t >= ap["expires_at"]
        ):
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        # Locate party strictly by unique party_id AND verify legal role matches (SL-CONT-002 / SL-CONT-004)
        party = None
        for pt in contract_obj.get("parties", []):
            if pt["party_id"] == ap["party_id"]:
                party = pt
                break
        if party is None or party["role"] != ap["party_role"]:
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        if "ward_origin_id" in party:
            ob = self._pick_origin_bundle_for_oid(party["ward_origin_id"], origin_bundle, origin_bundles_by_oid)
            # R1 #1 / R2-04: Reconstruct ward roster, slots, and guardian keys at verified contract (anchor_height, anchor_time)!
            wstate, oerr = self.verify_origin_and_status(
                ob, chain, journal=journal, at_height=anchor_height, at_time=anchor_time
            )
            if oerr:
                return VerifierResult("REFUSE", oerr)
            assert wstate is not None
            wb = wstate.get("effective_binding", wstate["binding"])
            if "name_pin" in party and not _name_pin_equal(wb, party["name_pin"]):
                return VerifierResult("REFUSE", "ORIGIN_BINDING_INVALID")
            if "party_name" in ap and ap["party_name"] != wb["name"]:
                return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
            # H-32: Verify ward's own name existed and matched binding at anchor_height (or tip)
            _, wnerr = self.resolve_name(
                wb["name"],
                chain,
                expected_owner_policy=wb["owner_policy"],
                expected_registration=wb["registration"],
                at_height=anchor_height,
                require_writer=False,
                allow_unresolved_voluntary_rebind=True,
            )
            if wnerr:
                return VerifierResult("REFUSE", wnerr)
            if wstate["capacity"] == "ward":
                ok_g, gerr, details = self.verify_ward_approvals(
                    assent_env,
                    wstate,
                    chain,
                    at_height=anchor_height,
                    at_time=anchor_time,
                    journal=journal,
                    origin_bundles_by_oid=origin_bundles_by_oid,
                )
                if not ok_g:
                    return VerifierResult("REFUSE", gerr)
                return VerifierResult("ADMIT", None, outcome="executed", details={**details, "party_id": party["party_id"]})
        if "signing_policy" not in party:
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        # H-32 / D-5 / P0-1: If autonomous party declares name_pin, verify party_name, name_pin, link.grant, 0x0b break, & history-based origin/rebind check!
        if "name_pin" in party:
            npin = party["name_pin"]
            if "party_name" in ap and ap["party_name"] != npin["name"]:
                return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
            pnrec, pnerr = self.resolve_name(
                npin["name"],
                chain,
                expected_owner_policy=npin["owner_policy"],
                expected_registration=npin["registration"],
                at_height=anchor_height,
                allow_unresolved_voluntary_rebind=True,
            )
            if pnerr:
                return VerifierResult("REFUSE", pnerr)
            assert pnrec is not None
            eval_h_a = chain.tip_height if anchor_height is None else anchor_height
            has_rebind_by_eval = any(
                ev["confirmed_height"] <= eval_h_a for ev in pnrec.get("_voluntary_rebinds", [])
            )
            # Reject ward masquerading as an autonomous party OR superseded voluntary-rebind binding (B-12 / H-32 / P0-1 / H1)
            hist_oid = pnrec.get("_historical_origin_id")
            if not hist_oid:
                reg_b_a = chain.raw.get("registered_bindings", {}).get(_outpoint_key(npin["registration"]))
                if isinstance(reg_b_a, str):
                    hist_oid = reg_b_a
            if hist_oid:
                ob_p = self._pick_origin_bundle_for_oid(hist_oid, origin_bundle, origin_bundles_by_oid)
                pwstate, pwoerr = self.verify_origin_and_status(
                    ob_p, chain, journal=journal, at_height=anchor_height, at_time=anchor_time
                )
                if pwoerr:
                    return VerifierResult("REFUSE", pwoerr)
                assert pwstate is not None
                if pwstate["capacity"] == "ward":
                    return VerifierResult("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN")
                if not _name_pin_equal(pwstate.get("effective_binding", pwstate["binding"]), npin):
                    return VerifierResult("REFUSE", "ORIGIN_BINDING_INVALID")
            elif has_rebind_by_eval:
                return VerifierResult("REFUSE", "ORIGIN_STATUS_INCOMPLETE")
            rpol_p, rerr_p = self.resolve_role_policy(pnrec, "grant", party["signing_policy"])
            if rerr_p or rpol_p != _normalize_policy(party["signing_policy"]):
                return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
            # H-5 (F-07 / H-4): Check 0x0b compromise break unconditionally at eval_h_a (tip when live, anchor_height when anchored)!
            if self._is_policy_compromised_at(pnrec, npin, "grant", rpol_p, eval_h_a, chain):
                return VerifierResult("REFUSE", "CRED_ISSUER_CLOSED")
        ok_s, scode = sl.verify_signature_set(
            sl.signing_digest(ap),
            assent_env.get("signatures", {}),
            expected_policy=party["signing_policy"],
            obj_type="seallink-assent/1",
        )
        if not ok_s:
            return VerifierResult("REFUSE", scode)
        return VerifierResult("ADMIT", None, outcome="executed", details={"party_id": party["party_id"], "party_role": party["role"]})

    def verify_contract_assents(
        self,
        contract_obj: dict[str, Any],
        assents: list[dict[str, Any]],
        origin_bundle: dict[str, Any] | None,
        chain: ChainView,
        *,
        origin_bundles_by_oid: dict[str, dict[str, Any]] | None = None,
        anchor_time: int | None = None,
        anchor_height: int | None = None,
        journal: FencedJournal | None = None,
    ) -> VerifierResult:
        """Verify strict 1-to-1 signatory coverage across every distinct party_id (supports multi-ward contracts, R1-C, R1 #1)."""
        ok_c, c_res = self._verify_object_wire(contract_obj, expected_type="seallink-contract/1")
        if not ok_c:
            return VerifierResult("REFUSE", c_res)
        expected_ids = {pt["party_id"] for pt in contract_obj["parties"]}
        covered: set[str] = set()
        for a in assents:
            ares = self.verify_assent(
                a,
                contract_obj,
                origin_bundle,
                chain,
                origin_bundles_by_oid=origin_bundles_by_oid,
                anchor_time=anchor_time,
                anchor_height=anchor_height,
                journal=journal,
            )
            if ares.verdict != "ADMIT":
                if ares.refusal_code in (
                    "WARD_AUTONOMOUS_FORBIDDEN",
                    "ORIGIN_UNVERIFIED",
                    "GUARDIAN_INACTIVE",
                    "GUARDIAN_QUORUM_UNMET",
                    "CRED_ISSUER_CLOSED",
                ):
                    return VerifierResult("REFUSE", ares.refusal_code)
                return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
            pid = a["payload"]["party_id"]
            if pid in covered:
                return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
            covered.add(pid)
        if covered != expected_ids:
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        return VerifierResult("ADMIT", None, outcome="executed", details={"covered_party_ids": sorted(covered)})

    def verify_credential(
        self,
        cred_env: dict[str, Any],
        anchor_txid: str | None,
        chain: ChainView,
        supported_kinds: set[str] | None = None,
        *,
        journal: FencedJournal | None = None,
        withdrawal_doc: dict[str, Any] | None = None,
        origin_bundle: dict[str, Any] | None = None,
        issuer_origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Execute SPEC-05 §4.2 deterministic 8-step credential verification order (D-6, R2-03, H-4, R3 H8)."""
        # 1. Wire & closed Draft 2020-12 schema check
        ok_w, w_res = self._verify_object_wire(cred_env, expected_type="seallink-credential/1")
        if not ok_w:
            return VerifierResult("REFUSE", w_res)
        cp = w_res["payload"]
        cred_id = sl.object_id(cp)
        # 2. Supported kind
        if supported_kinds is not None and cp["credential_kind"] not in supported_kinds:
            return VerifierResult("REFUSE", "WIRE_TYPE")
        # 3. Chain match
        if cp["network"] != self.pinned_network or cp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=2)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        # 4. Signed-form 0x09 anchor (resolved BEFORE subject lookup so eternal subject uses h_anchor! D-6)
        atx = chain.get_tx(anchor_txid) if anchor_txid else None
        if self._decode_opreturn_tx(atx, expected_action="0x09", expected_commitment=sl.content_addr(cred_env)) is None:
            return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
        assert atx is not None
        h_anchor = atx["confirmed_height"]
        if chain.tip_height - h_anchor + 1 < self.operator_min_depth:
            return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
        # 5. Subject verification: eternal name_pin checked at h_anchor (D-6); mode='origin' MANDATORY origin_bundle (R2-03)!
        subj = cp["subject"]
        if subj.get("mode") == "name":
            is_rev_s = cp["lifecycle"] != "eternal"
            eval_s_h = None if is_rev_s else h_anchor
            snrec, serr = self.resolve_name(
                subj["name_pin"]["name"],
                chain,
                expected_owner_policy=subj["name_pin"]["owner_policy"],
                expected_registration=subj["name_pin"]["registration"],
                at_height=eval_s_h,
                allow_unresolved_voluntary_rebind=(origin_bundle is not None),
            )
            if serr:
                return VerifierResult("REFUSE", serr)
            if snrec is not None:
                rb_err_s = self._verify_rebound_pin(snrec, subj["name_pin"], origin_bundle, chain, journal, at_height=eval_s_h)
                if rb_err_s:
                    return VerifierResult("REFUSE", rb_err_s)
        elif subj.get("mode") == "origin":
            wstate, oerr = self.verify_origin_and_status(
                origin_bundle,
                chain,
                journal=journal,
                at_height=h_anchor if cp["lifecycle"] == "eternal" else None,
                historical_existence_only=(cp["lifecycle"] == "eternal"),
            )
            if oerr:
                return VerifierResult("REFUSE", oerr)
            assert wstate is not None
            if wstate["origin_id"] != subj["origin_id"]:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
        # 6. Issuer history, owner_policy, link.cred policy (at tip for revocable, at h_anchor for eternal), policy-scoped 0x0b h_c break
        iss = cp["issuer"]
        i_err = self.verify_issuer_role_at_height(
            iss,
            cred_env,
            "cred",
            h_anchor,
            chain,
            resolve_at_tip=(cp["lifecycle"] != "eternal"),
            journal=journal,
            origin_bundle=issuer_origin_bundle,
        )
        if i_err:
            return VerifierResult("REFUSE", i_err)
        # 7. Height window AND calendar not_after_unix check (R3 H8)
        if chain.tip_height < cp["not_before_height"]:
            return VerifierResult("REFUSE", "CRED_WINDOW_CLOSED")
        if "not_after_height" in cp and chain.tip_height >= cp["not_after_height"]:
            return VerifierResult("REFUSE", "CRED_WINDOW_CLOSED")
        if "not_after_unix" in cp and chain.now >= cp["not_after_unix"]:
            return VerifierResult("REFUSE", "CRED_WINDOW_CLOSED")
        # 8. Persisted durable credential closure check AND revocable seal state (SPEC-05 §4.2, H-4 / G7-06)
        if journal is not None:
            ccl = journal.lookup_closure({"subject_id": cred_id, "subject_kind": "credential"}, legacy_key=cred_id)
            if ccl is not None:
                return VerifierResult("REFUSE", ccl["cause"])
        if cp["lifecycle"] == "revocable":
            seal = cp["revocation_seal"]
            out = chain.get_output(seal["txid"], seal["vout"])
            if out and out.get("spent_by_txid"):
                stxid = out["spent_by_txid"]
                stx = chain.get_tx(stxid)
                dec_w = self._decode_opreturn_tx(stx, require_confirmed=False, expected_action="0x0a")
                if dec_w is not None:
                    # If withdrawal_doc supplied, verify its schema, credential_id, genesis, and 0x0a commitment (R3 H8)
                    if withdrawal_doc is not None:
                        ok_wd, wd_res = self._verify_object_wire(withdrawal_doc, expected_type="seallink-credential-withdrawal/1")
                        if not ok_wd or wd_res.get("credential_id") != cred_id or wd_res.get("genesis") != self.pinned_genesis or sl.signing_digest(wd_res).hex() != dec_w["commitment"]:
                            return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                    if journal is not None:
                        journal.record_closure(
                            {"subject_id": cred_id, "subject_kind": "credential"},
                            "CRED_REVOKED_FOR_CAUSE",
                            observed_at=chain.now,
                            observed_height=chain.tip_height,
                            spend_txid=stxid,
                        )
                    return VerifierResult("REFUSE", "CRED_REVOKED_FOR_CAUSE")
            _, serr, _ = self.evaluate_seal(
                seal, chain, required_depth=1, journal=journal, subject_id=cred_id, subject_kind="credential"
            )
            if serr:
                return VerifierResult("REFUSE", serr)
        return VerifierResult("ADMIT", None, outcome="executed")

    def verify_notary_act(
        self,
        notary_env: dict[str, Any],
        anchor_txid: str | None,
        chain: ChainView,
        *,
        journal: FencedJournal | None = None,
        allowed_notaries: list[dict[str, Any]] | None = None,
        expected_notary_name: str | None = None,
        expected_child_binding: dict[str, Any] | None = None,
        log_ctx: dict[str, Any] | None = None,
        allow_reinstatement: bool = True,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Execute SPEC-05 §5 deterministic seallink-notary/1 verification (0x04/0x05/0x0b/0x14, B-4, H-24)."""
        ok_w, w_res = self._verify_object_wire(notary_env, expected_type="seallink-notary/1")
        if not ok_w:
            return VerifierResult("REFUSE", w_res)
        np = w_res["payload"]
        act_id = sl.object_id(np)
        if np["network"] != self.pinned_network or np["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        if np.get("act_kind") == "artifact-notarization":
            if np["target_sha256"] != sl.artifact_target_id(np["details"]["artifact_identity"]):
                return VerifierResult("REFUSE", "WIRE_MEMBER")
        notary_pin = np["notary"]
        if expected_notary_name is not None and notary_pin["name"] != expected_notary_name:
            return VerifierResult("REFUSE", "NOTARY_REQUIRED")
        if allowed_notaries is not None and not any(_name_pin_equal(notary_pin, an) for an in allowed_notaries):
            return VerifierResult("REFUSE", "NOTARY_REQUIRED")
        if expected_child_binding is not None:
            det = np.get("details", {})
            if (
                np.get("act_kind") != "child-within-parent"
                or det.get("parent_grant_id") != expected_child_binding["parent_grant_id"]
                or det.get("child_grant_id") != expected_child_binding["child_grant_id"]
                or det.get("ordinal") != expected_child_binding["ordinal"]
            ):
                return VerifierResult("REFUSE", "NOTARY_REQUIRED")
        if journal is not None:
            ncl = journal.lookup_closure({"subject_id": act_id, "subject_kind": "credential"}, legacy_key=act_id)
            if ncl is not None:
                return VerifierResult("REFUSE", ncl["cause"])
        if np["lifecycle"] == "log_tracked":
            ok_lt, lt_err, lt_det = self._verify_log_tracked_item(
                notary_env,
                np["log_id"],
                "notary",
                notary_pin,
                f"act:{act_id}|*",
                log_ctx,
                chain,
                journal=journal,
                allow_reinstatement=allow_reinstatement,
                origin_bundle=origin_bundle,
            )
            if not ok_lt:
                return VerifierResult("REFUSE", lt_err)
            return VerifierResult("ADMIT", None, outcome="executed", details={"notary_act_id": act_id, "act_kind": np["act_kind"], **lt_det})
        atx = chain.get_tx(anchor_txid) if anchor_txid else None
        if self._decode_opreturn_tx(atx, expected_action="0x04", expected_commitment=sl.content_addr(notary_env)) is None:
            return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
        assert atx is not None
        h_anchor = atx["confirmed_height"]
        if chain.tip_height - h_anchor + 1 < self.operator_min_depth:
            return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
        n_err = self.verify_issuer_role_at_height(
            notary_pin, notary_env, "notary", h_anchor, chain, resolve_at_tip=(np["lifecycle"] != "eternal"), journal=journal, origin_bundle=origin_bundle
        )
        if n_err:
            return VerifierResult("REFUSE", n_err)
        if np["lifecycle"] == "revocable":
            seal = np["notary_seal"]
            out = chain.get_output(seal["txid"], seal["vout"])
            if out and out.get("spent_by_txid"):
                stxid = out["spent_by_txid"]
                stx = chain.get_tx(stxid)
                dec_w = self._decode_opreturn_tx(stx, require_confirmed=False, expected_action="0x05")
                if dec_w is not None:
                    if journal is not None:
                        journal.record_closure(
                            {"subject_id": act_id, "subject_kind": "credential"},
                            "CRED_REVOKED_FOR_CAUSE",
                            observed_at=chain.now,
                            observed_height=chain.tip_height,
                            spend_txid=stxid,
                        )
                    return VerifierResult("REFUSE", "CRED_REVOKED_FOR_CAUSE")
            _, serr, _ = self.evaluate_seal(
                seal, chain, required_depth=1, journal=journal, subject_id=act_id, subject_kind="credential"
            )
            if serr:
                return VerifierResult("REFUSE", serr)
        return VerifierResult("ADMIT", None, outcome="executed", details={"notary_act_id": act_id, "act_kind": np["act_kind"]})

    # ------------------------------------------------------------------
    # SPEC-05 §6..§8 Transparency/Denial Logs (0x14), Fraud Proofs & Releases
    # ------------------------------------------------------------------

    def _authenticate_predecessor_chain(
        self,
        start_pred_lid: str | None,
        role: str,
        issuer_pin: dict[str, Any],
        chain: ChainView,
        *,
        predecessor_chain: list[dict[str, Any]] | None = None,
        predecessor_terminal_checkpoint: dict[str, Any] | None = None,
        journal: FencedJournal | None = None,
        origin_bundle: dict[str, Any] | None = None,
        expected_first_denials_root: str | None = None,
    ) -> tuple[set[str], str | None]:
        """Authenticate an O(1) log handover predecessor chain (<= 16 hops) via presented checkpoints or journal log-heads (BLK-5)."""
        if start_pred_lid is None:
            return set(), None
        pred_items: list[dict[str, Any]] = []
        if isinstance(predecessor_chain, list):
            pred_items = list(predecessor_chain)
        elif isinstance(predecessor_terminal_checkpoint, dict):
            pred_items = [predecessor_terminal_checkpoint]

        valid_preds: set[str] = set()
        cur_pred_lid: str | None = start_pred_lid
        idx = 0
        while cur_pred_lid is not None:
            if cur_pred_lid in valid_preds or len(valid_preds) == 16:
                return set(), "CHAIN_FRAME_INVALID"
            if journal is not None and journal.lookup_closure({"log_id": cur_pred_lid, "role": role, "subject_kind": "log"}) is not None:
                return set(), "NOTARY_LOG_COMPROMISED"
            if idx < len(pred_items):
                pt_ent = pred_items[idx]
                pt_cp = pt_ent.get("checkpoint") if isinstance(pt_ent, dict) else None
                pt_txid = pt_ent.get("checkpoint_txid") if isinstance(pt_ent, dict) else None
                pt_res = self.verify_log_checkpoint(
                    pt_cp, pt_txid, chain, journal=journal, is_head=False, origin_bundle=origin_bundle,
                    predecessor_chain=pred_items[idx + 1 :] or None,
                )
                if pt_res.verdict != "ADMIT":
                    if pt_res.refusal_code in ("NOTARY_LOG_COMPROMISED", "CRED_ISSUER_CLOSED", "JOURNAL_LOST", "JOURNAL_FENCED"):
                        return set(), pt_res.refusal_code
                    return set(), "CHAIN_FRAME_INVALID"
                pt_p = pt_cp["payload"]
                if (
                    pt_p["log_id"] != cur_pred_lid
                    or pt_p["role"] != role
                    or pt_p["terminal"] is not True
                    or not _same_actor_reg(pt_p["issuer"], issuer_pin)
                    or (idx == 0 and expected_first_denials_root is not None and pt_p["denials_root"] != expected_first_denials_root)
                ):
                    return set(), "CHAIN_FRAME_INVALID"
                valid_preds.add(cur_pred_lid)
                cur_pred_lid = pt_p.get("predecessor_log_id")
                idx += 1
            elif journal is not None:
                ex_pred = journal.log_heads.get(cur_pred_lid)
                if (
                    ex_pred is None
                    or ex_pred["role"] != role
                    or ex_pred["terminal"] is not True
                    or ex_pred.get("issuer_name") != issuer_pin["name"]
                    or ex_pred.get("issuer_registration") != issuer_pin["registration"]
                    or (idx == 0 and expected_first_denials_root is not None and ex_pred["denials_root"] != expected_first_denials_root)
                ):
                    return set(), "CHAIN_FRAME_INVALID"
                valid_preds.add(cur_pred_lid)
                cur_pred_lid = ex_pred.get("predecessor_log_id")
                idx += 1
            else:
                return set(), "CHAIN_FRAME_INVALID"
        return valid_preds, None

    def _verify_state_record_inclusion_height(
        self,
        state_record: dict[str, Any],
        stype: str,
        inclusion: dict[str, Any],
        log_id: str,
        role: str,
        issuer_pin: dict[str, Any],
        target_cp: dict[str, Any],
        chain: ChainView,
        *,
        journal: FencedJournal | None = None,
        valid_log_ids: set[str] | None = None,
        origin_bundle: dict[str, Any] | None = None,
    ) -> tuple[int | None, str | None, int | None]:
        """Verify StateRecordInclusion proving state_record entered batch_root at ancestor cp_intro <= target_cp (B8, BLK-1/BLK-5).
        Returns (confirmed_height, err_code, intro_seq).
        """
        inc_cp = inclusion.get("checkpoint")
        inc_txid = inclusion.get("checkpoint_txid")
        inc_bp = inclusion.get("batch_proof")
        inc_res = (
            self.verify_log_checkpoint(inc_cp, inc_txid, chain, journal=journal, is_head=False, origin_bundle=origin_bundle)
            if isinstance(inc_cp, dict) and isinstance(inc_txid, str) and isinstance(inc_bp, dict)
            else None
        )
        if inc_res is None:
            return None, None, None
        if inc_res.verdict != "ADMIT":
            return None, inc_res.refusal_code, None
        icp = inc_cp["payload"]
        tcp = target_cp["payload"]
        k_byte = 0x02 if stype == "seallink-log-revocation/1" else 0x03
        exp_leaf = sl.log_entry_digest(k_byte, sl.content_addr(state_record))
        cpr = inclusion.get("checkpoints_proof")
        valid_lids = valid_log_ids if valid_log_ids is not None else {log_id}
        same_log = icp["log_id"] == tcp["log_id"]
        if same_log:
            anc_ok = (
                sl.content_addr(inc_cp) == sl.content_addr(target_cp)
                if icp["seq"] == tcp["seq"]
                else (
                    isinstance(cpr, dict)
                    and cpr.get("leaf_index") == icp["seq"] - 1
                    and cpr.get("tree_size") == tcp["seq"] - 1
                    and sl.rfc9162_verify_inclusion(sl.ckpt_leaf(icp["seq"], sl.content_addr(inc_cp)), cpr["leaf_index"], cpr["tree_size"], cpr.get("hashes", []), tcp["checkpoints_root"])
                )
            )
        else:
            # Inherited state_record from authenticated predecessor log (BLK-5): verified against predecessor checkpoint
            anc_ok = icp["log_id"] in valid_lids
        if (
            icp["log_id"] not in valid_lids
            or icp["role"] != role
            or not _same_actor_reg(icp["issuer"], issuer_pin)
            or inc_bp.get("root") != icp["batch_root"]
            or inc_bp.get("leaf_digest") != exp_leaf
            or not sl.verify_merkle_proof(inc_bp)
            or not anc_ok
        ):
            return None, None, None
        return int(inc_res.details["confirmed_height"]), None, int(icp["seq"])

    def _check_smt_denial(
        self,
        smt_proof: Any,
        denials_root: str,
        denial_key: str,
        state_record: Any,
        log_id: str,
        role: str,
        issuer_pin: dict[str, Any],
        h_head: int,
        chain: ChainView,
        *,
        journal: FencedJournal | None = None,
        allow_reinstatement: bool = True,
        proof_err: str = "CHAIN_FRAME_INVALID",
        revoked_err: str = "CRED_REVOKED_FOR_CAUSE",
        state_record_inclusion: dict[str, Any] | None = None,
        head_cp: dict[str, Any] | None = None,
        valid_log_ids: set[str] | None = None,
        origin_bundle: dict[str, Any] | None = None,
    ) -> str | None:
        """Verify canonical Fixed-Depth-256 SMT proof & optional LogStateRecord (at h_intro via StateRecordInclusion or h_head; BLK-5 / M-5)."""
        if (
            not isinstance(smt_proof, dict)
            or smt_proof.get("root") != denials_root
            or smt_proof.get("key_str") != denial_key
            or not sl.smt_verify_proof(smt_proof)
        ):
            return proof_err
        if smt_proof["state"] == "absent":
            return None
        if not isinstance(state_record, dict):
            return proof_err
        ok_sr, sr_res = self._verify_object_wire(state_record)
        if not ok_sr:
            return proof_err
        sp = sr_res.get("payload", {})
        stype = sp.get("type")
        valid_lids = valid_log_ids if valid_log_ids is not None else {log_id}
        if (
            stype not in ("seallink-log-revocation/1", "seallink-log-reinstatement/1")
            or sl.content_addr(state_record) != smt_proof["value"]
            or sp["network"] != self.pinned_network
            or sp["genesis"] != self.pinned_genesis
            or sp["role"] != role
            or sp["log_id"] not in valid_lids
            or sp["denial_key"] != denial_key
            or not _same_actor_reg(sp["issuer"], issuer_pin)
        ):
            return proof_err
        h_verify = h_head
        _PROPAGATE_ERRS = ("CRED_ISSUER_CLOSED", "NOTARY_LOG_COMPROMISED", "JOURNAL_LOST", "JOURNAL_FENCED")
        if state_record_inclusion is not None:
            if not isinstance(head_cp, dict):
                return proof_err
            h_inc, inc_err, _ = self._verify_state_record_inclusion_height(
                state_record, stype, state_record_inclusion, log_id, role, issuer_pin, head_cp, chain,
                journal=journal, valid_log_ids=valid_lids, origin_bundle=origin_bundle,
            )
            if inc_err or h_inc is None:
                return inc_err if inc_err in _PROPAGATE_ERRS else proof_err
            h_verify = h_inc
        s_err = self.verify_issuer_role_at_height(sp["issuer"], state_record, role, h_verify, chain, journal=journal, origin_bundle=origin_bundle)
        if s_err:
            return s_err if s_err in _PROPAGATE_ERRS else proof_err
        if stype == "seallink-log-revocation/1" or not allow_reinstatement:
            return revoked_err
        return None

    def _verify_0x14_utxo_chain(
        self,
        seq: int,
        prev_op: dict[str, Any],
        prev_cp_id: str,
        gen_op: dict[str, Any],
        chain: ChainView,
        ex_head: dict[str, Any] | None = None,
    ) -> bool:
        """Walk confirmed 0x14 single-use-seal UTXO chain backwards strictly along canonical vout=1 to ex_head or genesis_seal_outpoint (BLK-2)."""
        cur_op = prev_op
        cur_exp_caddr: str | None = prev_cp_id
        rem = seq - 1
        visited_txids: set[str] = set()
        while rem >= 1:
            # BLK-2: Every intermediate continuation output MUST be canonical vout == 1 (never fee-change or P2A at vout >= 2, never terminal len(vout)==1)!
            if cur_op.get("vout") != 1:
                return False
            # BLK-2: Forbid bypassing ex_head via a different vout or resurrecting a terminal ex_head!
            if ex_head is not None and (rem == ex_head["max_seq"] or cur_op["txid"] == ex_head["checkpoint_txid"]):
                if (
                    ex_head["terminal"]
                    or rem != ex_head["max_seq"]
                    or cur_op != ex_head.get("next_log_outpoint")
                    or (cur_exp_caddr is not None and cur_exp_caddr != ex_head["checkpoint_id"])
                ):
                    return False
                p_out = chain.get_output(cur_op["txid"], cur_op["vout"])
                exp_p_spk = sl.compile_script_policy(ex_head["next_log_policy"])[0].hex()
                return bool(p_out and p_out.get("script_pubkey_hex") == exp_p_spk)
            if cur_op["txid"] in visited_txids:
                return False
            visited_txids.add(cur_op["txid"])
            ptx = chain.get_tx(cur_op["txid"])
            if self._decode_opreturn_tx(ptx, expected_action="0x14", expected_commitment=cur_exp_caddr) is None:
                return False
            assert ptx is not None
            # Verify predecessor tx actually created canonical continuation output vout == 1 (terminal txs have len(outputs) == 1!)
            if chain.get_output(cur_op["txid"], 1) is None:
                return False
            cur_exp_caddr = None
            if rem == 1:
                gen_out = chain.get_output(gen_op["txid"], gen_op["vout"])
                return bool(
                    self._tx_spends_outpoint(ptx, gen_op)
                    or (gen_out is not None and gen_out.get("spent_by_txid") == cur_op["txid"])
                )
            next_prev_op: dict[str, Any] | None = None
            for inp in ptx.get("inputs", []):
                if int(inp.get("prev_vout", -1)) != 1:
                    continue
                cand_tid = inp.get("prev_txid")
                cand_tx = chain.get_tx(cand_tid) if isinstance(cand_tid, str) else None
                if self._decode_opreturn_tx(cand_tx, expected_action="0x14") is not None:
                    next_prev_op = {"txid": cand_tid, "vout": 1}
                    break
            if next_prev_op is None:
                for tx_k, tx_v in chain.raw.get("txs", {}).items():
                    if not isinstance(tx_v, dict) or self._decode_opreturn_tx(tx_v, expected_action="0x14") is None:
                        continue
                    ov1 = (tx_v.get("outputs") or {}).get("1")
                    if isinstance(ov1, dict) and ov1.get("spent_by_txid") == cur_op["txid"]:
                        next_prev_op = {"txid": tx_k, "vout": 1}
                        break
            if next_prev_op is None:
                return False
            cur_op = next_prev_op
            rem -= 1
        return False

    def verify_log_checkpoint(
        self,
        cp_env: dict[str, Any],
        cp_txid: str | None,
        chain: ChainView,
        *,
        prev_cp_env: dict[str, Any] | None = None,
        prev_cp_txid: str | None = None,
        genesis_seal: dict[str, Any] | None = None,
        predecessor_terminal_checkpoint: dict[str, Any] | None = None,
        predecessor_chain: list[dict[str, Any]] | None = None,
        journal: FencedJournal | None = None,
        required_depth: int | None = None,
        is_head: bool = True,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Verify a confirmed 0x14 seallink-log-checkpoint/1 with unconditional log_id binding, canonical vout=1 / terminal-len=1 seal chain, mempool-safe head liveness, authenticated handover & reorg-safe log-head."""
        ok_w, w_res = self._verify_object_wire(cp_env, expected_type="seallink-log-checkpoint/1")
        if not ok_w:
            return VerifierResult("REFUSE", w_res)
        p = w_res["payload"]
        if p["network"] != self.pinned_network or p["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        log_id = p["log_id"]
        # B1 / BLK-5: Unconditionally bind log_id -> (issuer.name, issuer.registration, genesis_seal_outpoint[, predecessor_log_id]) for EVERY seq >= 1!
        gen_op = p["genesis_seal_outpoint"]
        pred_lid_opt = p.get("predecessor_log_id")
        exp_lid = sl.compute_log_id(
            p["network"], p["genesis"], p["role"], p["issuer"]["name"], p["issuer"]["registration"], gen_op,
            predecessor_log_id=pred_lid_opt,
        )
        if log_id != exp_lid:
            return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
        if journal is not None:
            jerr = journal.check_continuity()
            if jerr:
                return VerifierResult("REFUSE", jerr)
            if journal.lookup_closure({"log_id": log_id, "role": p["role"], "subject_kind": "log"}) is not None:
                return VerifierResult("REFUSE", "NOTARY_LOG_COMPROMISED")
        cp_caddr = sl.content_addr(cp_env)
        cp_oid = sl.object_id(p)
        cp_tx = chain.get_tx(cp_txid) if isinstance(cp_txid, str) else None
        if self._decode_opreturn_tx(cp_tx, expected_action="0x14", expected_commitment=cp_caddr) is None:
            return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
        assert cp_tx is not None and cp_txid is not None
        h_cp = int(cp_tx["confirmed_height"])
        min_d = required_depth if required_depth is not None else self.operator_min_depth
        if chain.tip_height - h_cp + 1 < min_d:
            return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
        prev_op = p["prev_log_outpoint"]
        prev_out = chain.get_output(prev_op["txid"], prev_op["vout"])
        spent_ok = (
            bool(prev_out)
            and ((prev_out.get("spent_by_txid") == cp_txid) or self._tx_spends_outpoint(cp_tx, prev_op))
            and not (prev_out.get("spent_by_txid") and prev_out["spent_by_txid"] != cp_txid)
            and not (cp_tx.get("inputs") and not self._tx_spends_outpoint(cp_tx, prev_op))
        )
        if not spent_ok:
            return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
        assert prev_out is not None
        i_err = self.verify_issuer_role_at_height(p["issuer"], cp_env, p["role"], h_cp, chain, journal=journal, origin_bundle=origin_bundle)
        if i_err:
            return VerifierResult("REFUSE", i_err)
        if p["batch_count"] == 0 and (p["batch_root"] != sl.EMPTY_BATCH_ROOT or p["denials_delta_root"] != sl.EMPTY_BATCH_ROOT):
            return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")

        valid_pred_lids: set[str] = set()
        ex_head = journal.log_heads.get(log_id) if journal is not None else None
        if pred_lid_opt is not None:
            exp_first_dr = p["predecessor_terminal_denials_root"] if p["seq"] == 1 else None
            valid_pred_lids, pred_err = self._authenticate_predecessor_chain(
                pred_lid_opt,
                p["role"],
                p["issuer"],
                chain,
                predecessor_chain=predecessor_chain,
                predecessor_terminal_checkpoint=predecessor_terminal_checkpoint,
                journal=journal,
                origin_bundle=origin_bundle,
                expected_first_denials_root=exp_first_dr,
            )
            if pred_err:
                return VerifierResult("REFUSE", pred_err)

        if p["seq"] == 1:
            if (
                prev_op != gen_op
                or p["checkpoints_root"] != sl.EMPTY_CHECKPOINTS_ROOT
                or p["cumulative_entries_count"] != p["batch_count"]
            ):
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
            if genesis_seal is not None:
                gs_spk = sl.compile_script_policy(genesis_seal["script_policy"])[0]
                if prev_op != {"txid": genesis_seal["txid"], "vout": genesis_seal["vout"]} or prev_out.get("script_pubkey_hex") != gs_spk.hex():
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
            if pred_lid_opt is not None:
                if p["denials_root"] != p["predecessor_terminal_denials_root"] or p["denials_delta_root"] != sl.EMPTY_BATCH_ROOT:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
        else:
            if prev_cp_env is not None:
                ok_p, p_res = self._verify_object_wire(prev_cp_env, expected_type="seallink-log-checkpoint/1")
                prev_ok = False
                if ok_p:
                    pp = p_res["payload"]
                    prev_caddr = sl.content_addr(prev_cp_env)
                    prev_ok = (
                        pp["log_id"] == log_id
                        and pp["role"] == p["role"]
                        and pp["seq"] + 1 == p["seq"]
                        and pp["terminal"] is False
                        and p["prev_checkpoint_id"] == prev_caddr
                        and p["cumulative_entries_count"] == pp["cumulative_entries_count"] + p["batch_count"]
                        and (
                            prev_cp_txid is None
                            or (
                                prev_op == {"txid": prev_cp_txid, "vout": pp["next_log_vout"]}
                                and prev_out.get("script_pubkey_hex") == sl.compile_script_policy(pp["next_log_policy"])[0].hex()
                            )
                        )
                        and (pp["seq"] != 1 or p["checkpoints_root"] == sl.ckpt_leaf(1, prev_caddr).hex())
                    )
                if not prev_ok:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
            # H03 / H-7b: Detect whether persisted ex_head's block/tx was genuinely orphaned in a reorg.
            blocks_map = chain.raw.get("blocks")
            ex_tx_live = chain.get_tx(ex_head["checkpoint_txid"]) if ex_head is not None else None
            ex_head_orphaned = (
                ex_head is not None
                and isinstance(ex_head.get("block_hash"), str)
                and not (isinstance(blocks_map, dict) and ex_head["block_hash"] in blocks_map)
                and not (
                    isinstance(ex_tx_live, dict)
                    and ex_tx_live.get("confirmed_height") is not None
                    and ex_tx_live.get("block_hash") == ex_head["block_hash"]
                )
            )
            same_as_journal_head = (
                ex_head is not None
                and p["seq"] == ex_head["max_seq"]
                and cp_oid == ex_head["checkpoint_object_id"]
                and not ex_head_orphaned
            )
            if not same_as_journal_head:
                eff_ex_head = None if ex_head_orphaned else ex_head
                if not self._verify_0x14_utxo_chain(p["seq"], prev_op, p["prev_checkpoint_id"], gen_op, chain, ex_head=eff_ex_head):
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")

        if p["terminal"] is False:
            # BLK-2: Canonical non-terminal layout: vout 1 is ALWAYS next_log_outpoint (schema const: 1)
            nxt_out = chain.get_output(cp_txid, 1)
            exp_nxt_spk = sl.compile_script_policy(p["next_log_policy"])[0]
            if not nxt_out or nxt_out.get("script_pubkey_hex") != exp_nxt_spk.hex():
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
            # B2 / M-4 (R12-M5): When verifying as current head (is_head=True), next_log_vout MUST NOT be spent by a
            # matured (>= min_d) or non-0x14 spend; an unconfirmed or < min_d maturing 0x14 successor permits grace acceptance of previous head!
            if is_head:
                nxt_op = {"txid": cp_txid, "vout": 1}
                sp_tid = nxt_out.get("spent_by_txid")
                if not sp_tid:
                    for tk_o, tx_o in chain.raw.get("txs", {}).items():
                        if isinstance(tx_o, dict) and self._tx_spends_outpoint(tx_o, nxt_op):
                            sp_tid = tk_o
                            break
                if sp_tid:
                    stx_nxt = chain.get_tx(sp_tid)
                    is_maturing_0x14 = (
                        stx_nxt is not None
                        and self._decode_opreturn_tx(stx_nxt, require_confirmed=False, expected_action="0x14") is not None
                        and (stx_nxt.get("confirmed_height") is None or chain.tip_height - int(stx_nxt["confirmed_height"]) + 1 < min_d)
                    )
                    if not is_maturing_0x14:
                        return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                elif nxt_out.get("absent_from_utxo"):
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
        else:
            # BLK-2: Canonical terminal layout — physically destroys the UTXO seal on-chain with NO vout 1 successor output!
            outs_map = cp_tx.get("outputs")
            if isinstance(outs_map, dict) and "1" in outs_map:
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")

        if journal is not None and is_head:
            blocks_map_j = chain.raw.get("blocks")
            ex_tx_live_j = chain.get_tx(ex_head["checkpoint_txid"]) if ex_head is not None else None
            ex_head_orphaned_j = (
                ex_head is not None
                and isinstance(ex_head.get("block_hash"), str)
                and not (isinstance(blocks_map_j, dict) and ex_head["block_hash"] in blocks_map_j)
                and not (
                    isinstance(ex_tx_live_j, dict)
                    and ex_tx_live_j.get("confirmed_height") is not None
                    and ex_tx_live_j.get("block_hash") == ex_head["block_hash"]
                )
            )
            if ex_head is not None:
                if p["seq"] == ex_head["max_seq"] and cp_oid != ex_head["checkpoint_object_id"]:
                    # H-7a (H-4 / M-1 / F-08): Durably persist NOTARY_LOG_COMPROMISED on detected equivocation!
                    journal.record_closure(
                        {"log_id": log_id, "role": p["role"], "subject_kind": "log"},
                        "NOTARY_LOG_COMPROMISED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                    )
                    return VerifierResult("REFUSE", "NOTARY_LOG_COMPROMISED")
                if p["seq"] < ex_head["max_seq"]:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
            need_persist = (
                ex_head is None
                or p["seq"] > ex_head["max_seq"]
                or (
                    p["seq"] == ex_head["max_seq"]
                    and cp_oid == ex_head["checkpoint_object_id"]
                    and ex_head_orphaned_j
                    and (cp_txid != ex_head["checkpoint_txid"] or cp_tx.get("block_hash") != ex_head.get("block_hash"))
                )
            )
            if need_persist:
                if not isinstance(cp_tx.get("block_hash"), str) or len(cp_tx["block_hash"]) != 64:
                    return VerifierResult("REFUSE", "CHAIN_UNHEALTHY")
                lh_body: dict[str, Any] = {
                    "block_hash": cp_tx["block_hash"],
                    "checkpoint_id": cp_caddr,
                    "checkpoint_object_id": cp_oid,
                    "checkpoint_txid": cp_txid,
                    "checkpoints_root": p["checkpoints_root"],
                    "confirmed_height": h_cp,
                    "denials_root": p["denials_root"],
                    "issuer_name": p["issuer"]["name"],
                    "issuer_registration": copy.deepcopy(p["issuer"]["registration"]),
                    "log_id": log_id,
                    "max_seq": p["seq"],
                    "role": p["role"],
                    "terminal": p["terminal"],
                }
                if pred_lid_opt is not None:
                    lh_body["predecessor_log_id"] = pred_lid_opt
                if p["terminal"] is False:
                    lh_body["next_log_outpoint"] = {"txid": cp_txid, "vout": 1}
                    lh_body["next_log_policy"] = p["next_log_policy"]
                _, jw_err = _append_journal_checked(journal, "log-head", lh_body)
                if jw_err:
                    return VerifierResult("REFUSE", jw_err)
        return VerifierResult(
            "ADMIT",
            None,
            outcome="executed",
            details={
                "checkpoint_id": cp_caddr,
                "confirmed_height": h_cp,
                "denials_root": p["denials_root"],
                "log_id": log_id,
                "seq": p["seq"],
                "terminal": p["terminal"],
                "valid_log_ids": sorted({log_id} | valid_pred_lids),
            },
        )

    def verify_log_fraud(
        self,
        fraud_obj: dict[str, Any],
        chain: ChainView,
        *,
        journal: FencedJournal | None = None,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Verify 4-mode seallink-log-fraud/1 (BLK-1 zero false kill-switch, BLK-5 handover inheritance, B1 genesis_seal_outpoint binding) & record unified 100% CLOSE."""
        ok_w, f_res = self._verify_object_wire(fraud_obj, expected_type="seallink-log-fraud/1")
        if not ok_w:
            return VerifierResult("REFUSE", f_res)
        if f_res["network"] != self.pinned_network or f_res["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        if journal is not None:
            jerr = journal.check_continuity()
            if jerr:
                return VerifierResult("REFUSE", jerr)
        log_id = f_res["log_id"]
        role = f_res["role"]
        mode = f_res["fraud_mode"]
        fraud_gen_op = f_res["genesis_seal_outpoint"]
        fraud_pred_lid = f_res.get("predecessor_log_id")

        def _auth_cp(cp_e: dict[str, Any], txid: str | None, *, require_confirmed: bool) -> tuple[int | None, str | None]:
            cp_p = cp_e["payload"]
            if (
                cp_p["network"] != self.pinned_network
                or cp_p["genesis"] != self.pinned_genesis
                or cp_p["role"] != role
                or cp_p["log_id"] != log_id
                or cp_p["genesis_seal_outpoint"] != fraud_gen_op
                or cp_p.get("predecessor_log_id") != fraud_pred_lid
                or sl.compute_log_id(
                    cp_p["network"], cp_p["genesis"], role, cp_p["issuer"]["name"], cp_p["issuer"]["registration"], fraud_gen_op,
                    predecessor_log_id=fraud_pred_lid,
                ) != log_id
            ):
                return None, "CHAIN_FRAME_INVALID"
            if txid is not None:
                tx = chain.get_tx(txid)
                if self._decode_opreturn_tx(tx, expected_action="0x14", expected_commitment=sl.content_addr(cp_e)) is not None:
                    assert tx is not None
                    h_c = int(tx["confirmed_height"])
                    if chain.tip_height - h_c + 1 < self.operator_min_depth:
                        return None, "CHAIN_DEPTH_INSUFFICIENT"
                    i_e = self.verify_issuer_role_at_height(cp_p["issuer"], cp_e, role, h_c, chain, journal=journal, origin_bundle=origin_bundle)
                    return (None, i_e) if i_e else (h_c, None)
            if require_confirmed:
                return None, "CRED_ANCHOR_MISSING"
            i_e = self.verify_issuer_role_at_height(cp_p["issuer"], cp_e, role, chain.tip_height, chain, resolve_at_tip=True, journal=journal, origin_bundle=origin_bundle)
            return (None, i_e) if i_e else (None, None)

        if mode == "equivocation":
            cp_a, cp_b = f_res["cp_a"], f_res["cp_b"]
            _, e_a = _auth_cp(cp_a, f_res.get("cp_a_txid"), require_confirmed=False)
            if e_a:
                return VerifierResult("REFUSE", e_a)
            _, e_b = _auth_cp(cp_b, f_res.get("cp_b_txid"), require_confirmed=False)
            if e_b:
                return VerifierResult("REFUSE", e_b)
            if cp_a["payload"]["seq"] != cp_b["payload"]["seq"] or sl.object_id(cp_a["payload"]) == sl.object_id(cp_b["payload"]):
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")

        elif mode == "revocation_omission":
            cp_a, cp_b = f_res["cp_a"], f_res["cp_b"]
            h_a, e_a = _auth_cp(cp_a, f_res["cp_a_txid"], require_confirmed=True)
            if e_a:
                return VerifierResult("REFUSE", e_a)
            assert h_a is not None
            _, e_b = _auth_cp(cp_b, f_res["cp_b_txid"], require_confirmed=True)
            if e_b:
                return VerifierResult("REFUSE", e_b)
            rev = f_res["revocation"]
            rp = rev["payload"]
            r_err = self.verify_issuer_role_at_height(rp["issuer"], rev, role, h_a, chain, journal=journal, origin_bundle=origin_bundle)
            if r_err:
                return VerifierResult("REFUSE", r_err)
            bp = f_res["batch_proof"]
            exp_leaf = sl.log_entry_digest(0x02, sl.content_addr(rev))
            seq_a, seq_b = cp_a["payload"]["seq"], cp_b["payload"]["seq"]
            cpr = f_res.get("checkpoints_proof")
            link_ok = (
                (seq_b == seq_a and "checkpoints_proof" not in f_res and sl.content_addr(cp_a) == sl.content_addr(cp_b))
                or (
                    isinstance(cpr, dict)
                    and cpr["leaf_index"] == seq_a - 1
                    and cpr["tree_size"] == seq_b - 1
                    and sl.rfc9162_verify_inclusion(sl.ckpt_leaf(seq_a, sl.content_addr(cp_a)), cpr["leaf_index"], cpr["tree_size"], cpr["hashes"], cp_b["payload"]["checkpoints_root"])
                )
            )
            sp = f_res["smt_proof"]
            smt_omitted = False
            if sp["state"] == "absent":
                smt_omitted = "rec_b" not in f_res
            else:
                # H4: Hidden re-revocation omitted after earlier reinstatement -> cp_b holds stale rec_b.state_seq < rev.state_seq!
                rec_b = f_res.get("rec_b")
                if isinstance(rec_b, dict) and sl.content_addr(rec_b) == sp["value"]:
                    rbp = rec_b["payload"]
                    smt_omitted = (
                        rbp["network"] == self.pinned_network
                        and rbp["genesis"] == self.pinned_genesis
                        and rbp["role"] == role
                        and rbp["log_id"] == log_id
                        and rbp["denial_key"] == rp["denial_key"]
                        and _same_actor_reg(rbp["issuer"], rp["issuer"])
                        and rbp["state_seq"] < rp["state_seq"]
                    )
            om_ok = (
                rp["network"] == self.pinned_network
                and rp["genesis"] == self.pinned_genesis
                and rp["role"] == role
                and rp["log_id"] == log_id
                and _same_actor_reg(rp["issuer"], cp_a["payload"]["issuer"])
                and bp["root"] == cp_a["payload"]["batch_root"]
                and bp["leaf_digest"] == exp_leaf
                and sl.verify_merkle_proof(bp)
                and link_ok
                and sp["root"] == cp_b["payload"]["denials_root"]
                and sp["key_str"] == rp["denial_key"]
                and sl.smt_verify_proof(sp)
                and smt_omitted
            )
            if not om_ok:
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")

        elif mode == "illegal_reversion":
            cp_a, cp_b = f_res["cp_a"], f_res["cp_b"]
            h_a, e_a = _auth_cp(cp_a, f_res["cp_a_txid"], require_confirmed=True)
            if e_a:
                return VerifierResult("REFUSE", e_a)
            assert h_a is not None
            h_b, e_b = _auth_cp(cp_b, f_res["cp_b_txid"], require_confirmed=True)
            if e_b:
                return VerifierResult("REFUSE", e_b)
            assert h_b is not None
            # BLK-5: Authenticate optional predecessor_chain so inherited SMT records from O(1) handover are provable!
            valid_lids: set[str] = {log_id}
            if fraud_pred_lid is not None:
                pred_lids_f, p_err_f = self._authenticate_predecessor_chain(
                    fraud_pred_lid, role, cp_a["payload"]["issuer"], chain,
                    predecessor_chain=f_res.get("predecessor_chain"),
                    journal=journal, origin_bundle=origin_bundle,
                )
                if p_err_f:
                    return VerifierResult("REFUSE", p_err_f)
                valid_lids |= pred_lids_f
            # BLK-1: rec_a is already cryptographically committed in signed on-chain cp_a.denials_root (smt_proof_a) —
            # no redundant signature check on rec_a (survives arbitrary key rotations & O(1) handovers without rec_a_inclusion!).
            rec_a = f_res["rec_a"]
            rap = rec_a["payload"]
            seq_a, seq_b = cp_a["payload"]["seq"], cp_b["payload"]["seq"]
            cpr = f_res["checkpoints_proof"]
            rec_a_ca = sl.content_addr(rec_a)
            spa, spb = f_res["smt_proof_a"], f_res["smt_proof_b"]
            base_ok = (
                cpr["leaf_index"] == seq_a - 1
                and cpr["tree_size"] == seq_b - 1
                and sl.rfc9162_verify_inclusion(sl.ckpt_leaf(seq_a, sl.content_addr(cp_a)), cpr["leaf_index"], cpr["tree_size"], cpr["hashes"], cp_b["payload"]["checkpoints_root"])
                and rap["network"] == self.pinned_network
                and rap["genesis"] == self.pinned_genesis
                and rap["role"] == role
                and rap["log_id"] in valid_lids
                and _same_actor_reg(rap["issuer"], cp_a["payload"]["issuer"])
                and spa["root"] == cp_a["payload"]["denials_root"]
                and spa["key_str"] == rap["denial_key"]
                and spa["state"] == "included"
                and spa["value"] == rec_a_ca
                and sl.smt_verify_proof(spa)
                and spb["root"] == cp_b["payload"]["denials_root"]
                and spb["key_str"] == rap["denial_key"]
                and sl.smt_verify_proof(spb)
            )
            rev_ok = False
            if base_ok:
                if spb["state"] == "absent":
                    rev_ok = "rec_b" not in f_res
                else:
                    rec_b = f_res.get("rec_b")
                    if isinstance(rec_b, dict) and sl.content_addr(rec_b) == spb["value"]:
                        rec_b_ca = sl.content_addr(rec_b)
                        # BLK-1: Unchanged SMT record (rec_b == rec_a) MUST NEVER trigger false fraud!
                        if rec_b_ca != rec_a_ca:
                            rbp = rec_b["payload"]
                            inc_b = f_res.get("rec_b_inclusion")
                            h_rb_chk: int | None = None
                            if inc_b is not None:
                                # BLK-1: Invalid rec_b_inclusion MUST IMMEDIATELY REFUSE the fraud proof (NEVER set invalid_succ=True / close log!)
                                h_ib, err_ib, seq_ib = self._verify_state_record_inclusion_height(
                                    rec_b, rbp["type"], inc_b, log_id, role, cp_b["payload"]["issuer"], cp_b, chain,
                                    journal=journal, valid_log_ids=valid_lids, origin_bundle=origin_bundle,
                                )
                                if err_ib or h_ib is None or seq_ib is None or not (seq_a < seq_ib <= seq_b):
                                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                                h_rb_chk = h_ib
                            elif seq_b == seq_a + 1:
                                # BLK-1 induction: adjacent seq_b == seq_a + 1 with rec_b != rec_a guarantees rec_b entered at exact h_b!
                                h_rb_chk = h_b
                            # Height-independent structural/domain violations work at any seq_b > seq_a
                            struct_bad = (
                                rbp["network"] != self.pinned_network
                                or rbp["genesis"] != self.pinned_genesis
                                or rbp["role"] != role
                                or rbp["log_id"] not in valid_lids
                                or rbp["denial_key"] != rap["denial_key"]
                                or not _same_actor_reg(rbp["issuer"], rap["issuer"])
                            )
                            # Mode (3d) signature/key/0x0b check ONLY when h_rb_chk is proven (seq_b==seq_a+1 OR valid rec_b_inclusion)!
                            sig_bad = (
                                h_rb_chk is not None
                                and self.verify_issuer_role_at_height(rbp["issuer"], rec_b, role, h_rb_chk, chain, journal=journal, origin_bundle=origin_bundle) is not None
                            )
                            rollback = rbp["state_seq"] <= rap["state_seq"]
                            broken_adj = rbp["state_seq"] == rap["state_seq"] + 1 and rbp.get("prev_record_id") != rec_a_ca
                            rev_ok = struct_bad or sig_bad or rollback or broken_adj
            if not rev_ok:
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")

        else:  # "invalid_checkpoint_chain"
            cp_next = f_res["cp_next"]
            _, e_n = _auth_cp(cp_next, f_res["cp_next_txid"], require_confirmed=True)
            if e_n:
                return VerifierResult("REFUSE", e_n)
            np_c = cp_next["payload"]
            if np_c["seq"] == 1:
                bad_1 = "cp_prev" not in f_res and (
                    np_c["checkpoints_root"] != sl.EMPTY_CHECKPOINTS_ROOT
                    or np_c["cumulative_entries_count"] != np_c["batch_count"]
                    or (
                        "predecessor_log_id" in np_c
                        and (np_c["denials_root"] != np_c["predecessor_terminal_denials_root"] or np_c["denials_delta_root"] != sl.EMPTY_BATCH_ROOT)
                    )
                )
                if not bad_1:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
            else:
                if "cp_prev" not in f_res:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                cp_prev = f_res["cp_prev"]
                _, e_p = _auth_cp(cp_prev, f_res["cp_prev_txid"], require_confirmed=True)
                if e_p:
                    return VerifierResult("REFUSE", e_p)
                pp_c = cp_prev["payload"]
                prev_ca = sl.content_addr(cp_prev)
                k = np_c["seq"]
                peaks = f_res["peaks"]
                chain_proven = (
                    pp_c["seq"] == k - 1
                    and np_c.get("prev_checkpoint_id") == prev_ca
                    and sl.rfc9162_root_from_peaks(peaks, k - 2) == pp_c["checkpoints_root"]
                    and (
                        np_c["checkpoints_root"] != sl.rfc9162_append_leaf_to_peaks(peaks, k - 2, sl.ckpt_leaf(k - 1, prev_ca))
                        or np_c["cumulative_entries_count"] != pp_c["cumulative_entries_count"] + np_c["batch_count"]
                    )
                )
                if not chain_proven:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")

        # Unified 100% CLOSE across all modes upon proven fraud!
        if journal is not None:
            journal.record_closure(
                {"log_id": log_id, "role": role, "subject_kind": "log"},
                "NOTARY_LOG_COMPROMISED",
                observed_at=chain.now,
                observed_height=chain.tip_height,
            )
        return VerifierResult(
            "ADMIT",
            None,
            outcome="executed",
            details={"closure_cause": "NOTARY_LOG_COMPROMISED", "fraud_mode": mode, "fraud_proven": True, "log_id": log_id},
        )

    def _verify_log_tracked_item(
        self,
        item_env: dict[str, Any],
        log_id: str,
        role: str,
        issuer_pin: dict[str, Any],
        denial_key: str,
        log_ctx: dict[str, Any] | None,
        chain: ChainView,
        *,
        journal: FencedJournal | None = None,
        allow_reinstatement: bool = True,
        proof_err: str = "CHAIN_FRAME_INVALID",
        revoked_err: str = "CRED_REVOKED_FOR_CAUSE",
        heartbeat_max_blocks: int | None = None,
        heartbeat_err: str = "CRED_WINDOW_CLOSED",
        origin_bundle: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None, dict[str, Any]]:
        """Verify inclusion & SMT non-revocation of a log_tracked release or notary act inside a 0x14 log (with O(1) handover predecessor_chain)."""
        if journal is not None:
            jerr = journal.check_continuity()
            if jerr:
                return False, jerr, {}
            if journal.lookup_closure({"log_id": log_id, "role": role, "subject_kind": "log"}) is not None:
                return False, "NOTARY_LOG_COMPROMISED", {}
        if not isinstance(log_ctx, dict):
            return False, proof_err, {}
        cp = log_ctx.get("checkpoint")
        cp_txid = log_ctx.get("checkpoint_txid")
        bp = log_ctx.get("batch_proof")
        sp = log_ctx.get("smt_proof")
        pred_chain = log_ctx.get("predecessor_chain")
        pred_term = log_ctx.get("predecessor_terminal_checkpoint")
        if not isinstance(cp, dict) or not isinstance(cp_txid, str) or not isinstance(bp, dict) or not isinstance(sp, dict):
            return False, proof_err, {}
        head_cp = log_ctx.get("head_checkpoint", cp)
        head_cp_txid = log_ctx.get("head_checkpoint_txid", cp_txid)
        is_cp_head = head_cp is cp and head_cp_txid == cp_txid
        c_res = self.verify_log_checkpoint(
            cp, cp_txid, chain, journal=journal, is_head=is_cp_head,
            predecessor_chain=pred_chain, predecessor_terminal_checkpoint=pred_term, origin_bundle=origin_bundle,
        )
        if c_res.verdict != "ADMIT":
            if c_res.refusal_code in ("NOTARY_LOG_COMPROMISED", "CHAIN_DEPTH_INSUFFICIENT", "CRED_ISSUER_CLOSED", "CHAIN_MISMATCH", "JOURNAL_LOST", "JOURNAL_FENCED", "ORIGIN_STATUS_INCOMPLETE", "ORIGIN_BINDING_INVALID"):
                return False, c_res.refusal_code, {}
            return False, proof_err, {}
        cp_p = cp["payload"]
        if cp_p["log_id"] != log_id or cp_p["role"] != role or not _same_actor_reg(cp_p["issuer"], issuer_pin):
            return False, proof_err, {}
        exp_leaf = sl.log_entry_digest(0x01, sl.content_addr(item_env))
        if bp.get("root") != cp_p["batch_root"] or bp.get("leaf_digest") != exp_leaf or not sl.verify_merkle_proof(bp):
            return False, proof_err, {}
        h_cp = int(c_res.details["confirmed_height"])
        i_err = self.verify_issuer_role_at_height(issuer_pin, item_env, role, h_cp, chain, journal=journal, origin_bundle=origin_bundle)
        if i_err:
            return False, i_err, {}
        valid_lids: set[str] = set(c_res.details.get("valid_log_ids", [log_id]))
        if is_cp_head:
            h_head = h_cp
        else:
            prev_hint_env = (
                cp
                if isinstance(head_cp, dict)
                and isinstance(head_cp.get("payload"), dict)
                and head_cp["payload"].get("log_id") == log_id
                and head_cp["payload"].get("seq") == cp_p["seq"] + 1
                else None
            )
            prev_hint_txid = cp_txid if prev_hint_env is not None else None
            hc_res = self.verify_log_checkpoint(
                head_cp, head_cp_txid, chain, prev_cp_env=prev_hint_env, prev_cp_txid=prev_hint_txid,
                journal=journal, predecessor_chain=pred_chain, predecessor_terminal_checkpoint=pred_term, origin_bundle=origin_bundle,
            )
            if hc_res.verdict != "ADMIT":
                if hc_res.refusal_code in ("NOTARY_LOG_COMPROMISED", "CHAIN_DEPTH_INSUFFICIENT", "CRED_ISSUER_CLOSED", "CHAIN_MISMATCH", "JOURNAL_LOST", "JOURNAL_FENCED", "ORIGIN_STATUS_INCOMPLETE", "ORIGIN_BINDING_INVALID"):
                    return False, hc_res.refusal_code, {}
                return False, proof_err, {}
            hp = head_cp["payload"]
            hc_valid_lids: set[str] = set(hc_res.details.get("valid_log_ids", [hp["log_id"]]))
            if log_id not in hc_valid_lids or hp["role"] != role or not _same_actor_reg(hp["issuer"], issuer_pin):
                return False, proof_err, {}
            # Anchor cp either directly inside head_cp (same log) OR inside log_id's authenticated terminal checkpoint (O(1) handover, BLK-5)!
            anchor_target_cp: dict[str, Any] | None = None
            if hp["log_id"] == log_id:
                anchor_target_cp = head_cp
            else:
                for p_it in (pred_chain if isinstance(pred_chain, list) else []) + ([pred_term] if isinstance(pred_term, dict) else []):
                    if isinstance(p_it, dict) and isinstance(p_it.get("checkpoint"), dict):
                        if p_it["checkpoint"].get("payload", {}).get("log_id") == log_id:
                            anchor_target_cp = p_it["checkpoint"]
                            break
                if anchor_target_cp is None and journal is not None and log_id in journal.log_heads:
                    jh = journal.log_heads[log_id]
                    anchor_target_cp = {
                        "_journal_head": True,
                        "payload": {"checkpoints_root": jh["checkpoints_root"], "seq": jh["max_seq"]},
                        "_checkpoint_id": jh["checkpoint_id"],
                    }
            if anchor_target_cp is None:
                return False, proof_err, {}
            atp = anchor_target_cp["payload"]
            atp_ca = anchor_target_cp["_checkpoint_id"] if anchor_target_cp.get("_journal_head") else sl.content_addr(anchor_target_cp)
            if atp["seq"] == cp_p["seq"]:
                if atp_ca != sl.content_addr(cp):
                    return False, proof_err, {}
            else:
                cpr = log_ctx.get("checkpoints_proof")
                if (
                    not isinstance(cpr, dict)
                    or cpr.get("leaf_index") != cp_p["seq"] - 1
                    or cpr.get("tree_size") != atp["seq"] - 1
                    or not sl.rfc9162_verify_inclusion(sl.ckpt_leaf(cp_p["seq"], sl.content_addr(cp)), cpr["leaf_index"], cpr["tree_size"], cpr.get("hashes", []), atp["checkpoints_root"])
                ):
                    return False, proof_err, {}
            h_head = int(hc_res.details["confirmed_height"])
            valid_lids |= hc_valid_lids
        hp_final = head_cp["payload"]
        if heartbeat_max_blocks is not None and not hp_final["terminal"] and (chain.tip_height - h_head) > heartbeat_max_blocks:
            return False, heartbeat_err, {}
        d_err = self._check_smt_denial(
            sp,
            hp_final["denials_root"],
            denial_key,
            log_ctx.get("state_record"),
            log_id,
            role,
            issuer_pin,
            h_head,
            chain,
            journal=journal,
            allow_reinstatement=allow_reinstatement,
            proof_err=proof_err,
            revoked_err=revoked_err,
            state_record_inclusion=log_ctx.get("state_record_inclusion"),
            head_cp=head_cp,
            valid_log_ids=valid_lids,
            origin_bundle=origin_bundle,
        )
        if d_err:
            return False, d_err, {}
        return True, None, {"head_denials_root": hp_final["denials_root"], "head_height": h_head, "log_id": log_id, "valid_log_ids": sorted(valid_lids)}

    def verify_release(
        self,
        rel_env: dict[str, Any],
        chain: ChainView,
        *,
        anchor_txid: str | None = None,
        log_ctx: dict[str, Any] | None = None,
        journal: FencedJournal | None = None,
        allow_reinstatement: bool = True,
        heartbeat_max_blocks: int | None = None,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Verify a Core seallink-release/1 record (eternal 0x09 or log_tracked 0x14, link.release, canonical target_id)."""
        ok_w, w_res = self._verify_object_wire(rel_env, expected_type="seallink-release/1")
        if not ok_w:
            return VerifierResult("REFUSE", w_res)
        rp = w_res["payload"]
        if rp["network"] != self.pinned_network or rp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        if rp["target_sha256"] != sl.artifact_target_id(rp["artifact_identity"]):
            return VerifierResult("REFUSE", "WIRE_MEMBER")
        rel_id = sl.object_id(rp)
        if rp["lifecycle"] == "eternal":
            atx = chain.get_tx(anchor_txid) if isinstance(anchor_txid, str) else None
            if self._decode_opreturn_tx(atx, expected_action="0x09", expected_commitment=sl.content_addr(rel_env)) is None:
                return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
            assert atx is not None
            h_anchor = int(atx["confirmed_height"])
            if chain.tip_height - h_anchor + 1 < self.operator_min_depth:
                return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
            i_err = self.verify_issuer_role_at_height(rp["issuer"], rel_env, "release", h_anchor, chain, journal=journal, origin_bundle=origin_bundle)
            if i_err:
                return VerifierResult("REFUSE", i_err)
        else:
            ok_lt, lt_err, _ = self._verify_log_tracked_item(
                rel_env,
                rp["log_id"],
                "release",
                rp["issuer"],
                f"rel:{rel_id}|*",
                log_ctx,
                chain,
                journal=journal,
                allow_reinstatement=allow_reinstatement,
                heartbeat_max_blocks=heartbeat_max_blocks,
                origin_bundle=origin_bundle,
            )
            if not ok_lt:
                return VerifierResult("REFUSE", lt_err)
        return VerifierResult(
            "ADMIT",
            None,
            outcome="executed",
            details={"product_id": rp["product_id"], "release_id": rel_id, "release_seq": rp["release_seq"], "target_sha256": rp["target_sha256"]},
        )

    # ------------------------------------------------------------------
    # PROFILE-artifact-v1 Gatekeeper & Tier-2 SPV Name History (Optional Module)
    # ------------------------------------------------------------------

    def verify_artifact_ticket(
        self,
        ticket_obj: dict[str, Any],
        policy: dict[str, Any],
        chain: ChainView,
        *,
        journal: FencedJournal | None = None,
        provisional_revocations: list[dict[str, Any]] | None = None,
        origin_bundles_by_oid: dict[str, dict[str, Any]] | None = None,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Execute PROFILE-artifact-v1 Gatekeeper admission (m-of-n, inconclusive, absent-notary veto, release_floor, global deny-wins, O(1) handover)."""
        ok_t, tp = self._verify_object_wire(ticket_obj, expected_type="seallink-ticket/1")
        if not ok_t:
            return VerifierResult("REFUSE", tp)
        if self.enforce_schemas:
            perr = validate_against_schema("schemas/profile-artifact.schema.json#/$defs/GatekeeperPolicy", policy, require_jsonschema=self.require_jsonschema)
            if perr:
                return VerifierResult("REFUSE", perr)
        if tp["network"] != self.pinned_network or tp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        # M07: Check journal continuity BEFORE chain observation (aligned with PROFILE-artifact-v1)
        if journal is not None:
            jerr = journal.check_continuity()
            if jerr:
                return VerifierResult("REFUSE", jerr)
        obs_err = self.check_chain_observation(chain, risk_class=2)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        target_id = sl.artifact_target_id(tp["artifact_identity"])
        if tp["target_sha256"] != target_id:
            return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
        if "bootstrap_expires_at" in policy and chain.now >= policy["bootstrap_expires_at"]:
            return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")

        trusted_notaries = policy["trusted_notaries"]
        # M08: Policy trusted_notaries MUST be unique by (name, registration) so config order can never flip verdicts
        seen_tn_policy_keys: set[str] = set()
        for tn_p in trusted_notaries:
            pk_tn = f"{tn_p['notary_pin']['name']}:{_outpoint_key(tn_p['notary_pin']['registration'])}"
            if pk_tn in seen_tn_policy_keys:
                return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
            seen_tn_policy_keys.add(pk_tn)

        trusted_rel_issuers = policy.get("trusted_release_issuers", [])
        req_claims = set(policy["required_claims"])
        allow_reinst = policy["allow_reinstatement"]
        rel_id_opt = sl.object_id(tp["release"]["payload"]) if "release" in tp else None
        trusted_present_act_ids: set[str] = set()
        for ne_pre in tp["notarizations"]:
            np_pre = ne_pre["notary_act"]["payload"]
            if any(_same_actor_reg(np_pre["notary"], tn["notary_pin"]) for tn in trusted_notaries):
                trusted_present_act_ids.add(sl.object_id(np_pre))

        def _pick_ob_for_actor(actor_pin: dict[str, Any]) -> dict[str, Any] | None:
            if origin_bundle is not None:
                return origin_bundle
            if origin_bundles_by_oid:
                anrec = chain.get_name_for_registration(actor_pin["name"], actor_pin["registration"], historical=True)
                if isinstance(anrec, dict):
                    for u_a in anrec.get("updates", []):
                        uv_a, ue_a = self._parse_update_value(u_a, actor_pin["name"])
                        if ue_a is None and isinstance(uv_a, dict):
                            oid_a = uv_a.get("link", {}).get("origin")
                            if isinstance(oid_a, str) and oid_a in origin_bundles_by_oid:
                                return origin_bundles_by_oid[oid_a]
            return None

        # Provisional gossip deny-wins check (role-scoped target:/act:/rel: over closed 3-key universe, zero log-head mutation; R2 N-1)
        for prev in (provisional_revocations or []):
            ok_pr, pr_res = self._verify_object_wire(prev, expected_type="seallink-log-revocation/1")
            if not ok_pr:
                continue
            prp = pr_res["payload"]
            if prp["network"] != self.pinned_network or prp["genesis"] != self.pinned_genesis:
                continue
            dk = prp["denial_key"]
            matched_trust = False
            if prp["role"] == "notary":
                if not (dk.startswith("act:") or dk.startswith("target:")):
                    continue
                matched_trust = any(
                    _same_actor_reg(prp["issuer"], tn["notary_pin"]) and (tn.get("log_id") is None or tn["log_id"] == prp["log_id"])
                    for tn in trusted_notaries
                )
            elif prp["role"] == "release":
                if not dk.startswith("rel:"):
                    continue
                matched_trust = any(
                    _same_actor_reg(prp["issuer"], tr["issuer_pin"]) and (tr.get("log_id") is None or tr["log_id"] == prp["log_id"])
                    for tr in trusted_rel_issuers
                )
            if not matched_trust:
                continue
            if self.verify_issuer_role_at_height(
                prp["issuer"], pr_res, prp["role"], chain.tip_height, chain, resolve_at_tip=True, journal=journal,
                origin_bundle=_pick_ob_for_actor(prp["issuer"]),
            ) is not None:
                continue
            if (
                dk == f"target:{target_id}|*"
                or (rel_id_opt is not None and dk == f"rel:{rel_id_opt}|*")
                or any(dk == f"act:{aid}|*" for aid in trusted_present_act_ids)
            ):
                return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")

        # Optional / required release verification + release_floor check
        if "release" in tp:
            rel_env = tp["release"]
            rel_p = rel_env["payload"]
            if rel_p["target_sha256"] != target_id:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            tr_match = next(
                (
                    tr for tr in trusted_rel_issuers
                    if _same_actor_reg(rel_p["issuer"], tr["issuer_pin"])
                    and any(rel_p["product_id"].startswith(pref) for pref in tr["allowed_product_prefixes"])
                    and (tr.get("log_id") is None or rel_p.get("log_id") == tr["log_id"])
                ),
                None,
            )
            if tr_match is None:
                return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
            floor_map = policy.get("release_floor", {})
            if rel_p["product_id"] in floor_map and rel_p["release_seq"] < floor_map[rel_p["product_id"]]:
                return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
            rel_log_ctx = None
            if rel_p["lifecycle"] == "log_tracked":
                rel_log_ctx = {
                    "batch_proof": tp.get("release_batch_proof"),
                    "checkpoint": tp.get("release_checkpoint"),
                    "checkpoint_txid": tp.get("release_checkpoint_txid"),
                    "checkpoints_proof": tp.get("release_checkpoints_proof"),
                    "head_checkpoint": tp.get("release_head_checkpoint", tp.get("release_checkpoint")),
                    "head_checkpoint_txid": tp.get("release_head_checkpoint_txid", tp.get("release_checkpoint_txid")),
                    "predecessor_chain": tp.get("release_predecessor_chain"),
                    "smt_proof": tp.get("release_smt_proof"),
                    "state_record": tp.get("release_state_record"),
                    "state_record_inclusion": tp.get("release_state_inclusion"),
                }
            r_res = self.verify_release(
                rel_env,
                chain,
                anchor_txid=tp.get("release_anchor_txid"),
                log_ctx=rel_log_ctx,
                journal=journal,
                allow_reinstatement=allow_reinst,
                heartbeat_max_blocks=tr_match.get("heartbeat_max_blocks"),
                origin_bundle=_pick_ob_for_actor(rel_p["issuer"]),
            )
            if r_res.verdict != "ADMIT":
                if r_res.refusal_code in ("NOTARY_LOG_COMPROMISED", "CRED_ISSUER_CLOSED", "JOURNAL_LOST", "JOURNAL_FENCED"):
                    return VerifierResult("REFUSE", r_res.refusal_code)
                if r_res.refusal_code in ("CRED_REVOKED_FOR_CAUSE", "CRED_WINDOW_CLOSED"):
                    return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
        elif policy.get("require_release"):
            return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")

        # Present notarizations: skip untrusted FIRST, verify all trusted entries, enforcing global deny-wins for verified "fail"
        # regardless of notarizations[] ordering (R12-L5 / M-5)!
        passed_claims_by_notary: dict[str, set[str]] = {}
        seen_trusted_notaries: set[str] = set()
        seen_trusted_log_ids: set[str] = set()
        first_non_veto_err: str | None = None
        for ne in tp["notarizations"]:
            n_env = ne["notary_act"]
            np = n_env["payload"]
            tn_match = next((tn for tn in trusted_notaries if _same_actor_reg(np["notary"], tn["notary_pin"])), None)
            if tn_match is None:
                continue
            if np["network"] != self.pinned_network or np["genesis"] != self.pinned_genesis:
                if first_non_veto_err is None:
                    first_non_veto_err = "CHAIN_MISMATCH"
                continue
            if (
                np.get("act_kind") != "artifact-notarization"
                or np["target_sha256"] != target_id
                or sl.artifact_target_id(np["details"]["artifact_identity"]) != target_id
            ):
                if first_non_veto_err is None:
                    first_non_veto_err = "TICKET_PROOF_INVALID"
                continue
            n_key = f"{np['notary']['name']}:{_outpoint_key(np['notary']['registration'])}"
            if n_key in seen_trusted_notaries:
                if first_non_veto_err is None:
                    first_non_veto_err = "TICKET_PROOF_INVALID"
                continue
            seen_trusted_notaries.add(n_key)
            if tn_match.get("log_id") is not None:
                seen_trusted_log_ids.add(tn_match["log_id"])
            if tn_match.get("log_id") is not None and np.get("log_id") != tn_match["log_id"]:
                if first_non_veto_err is None:
                    first_non_veto_err = "TICKET_PROOF_INVALID"
                continue
            act_id = sl.object_id(np)
            if journal is not None:
                acl = journal.lookup_closure({"subject_id": act_id, "subject_kind": "credential"}, legacy_key=act_id)
                if acl is not None:
                    return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
            ob_notary = _pick_ob_for_actor(np["notary"])
            if np["lifecycle"] == "log_tracked":
                n_log_ctx = {
                    "batch_proof": ne.get("batch_proof"),
                    "checkpoint": ne.get("checkpoint"),
                    "checkpoint_txid": ne.get("checkpoint_txid"),
                    "checkpoints_proof": ne.get("checkpoints_proof"),
                    "head_checkpoint": ne.get("head_checkpoint", ne.get("checkpoint")),
                    "head_checkpoint_txid": ne.get("head_checkpoint_txid", ne.get("checkpoint_txid")),
                    "predecessor_chain": ne.get("predecessor_chain"),
                    "smt_proof": ne.get("act_smt_proof"),
                    "state_record": ne.get("act_state_record"),
                    "state_record_inclusion": ne.get("act_state_inclusion"),
                }
                ok_lt, lt_err, lt_det = self._verify_log_tracked_item(
                    n_env,
                    np["log_id"],
                    "notary",
                    np["notary"],
                    f"act:{act_id}|*",
                    n_log_ctx,
                    chain,
                    journal=journal,
                    allow_reinstatement=allow_reinst,
                    proof_err="TICKET_PROOF_INVALID",
                    revoked_err="ARTIFACT_POLICY_DENIED",
                    heartbeat_max_blocks=tn_match.get("heartbeat_max_blocks"),
                    heartbeat_err="ARTIFACT_POLICY_DENIED",
                    origin_bundle=ob_notary,
                )
                if not ok_lt:
                    if lt_err in ("NOTARY_LOG_COMPROMISED", "CRED_ISSUER_CLOSED", "JOURNAL_LOST", "JOURNAL_FENCED", "ARTIFACT_POLICY_DENIED"):
                        return VerifierResult("REFUSE", lt_err)
                    if first_non_veto_err is None:
                        first_non_veto_err = lt_err
                    continue
                # Mandatory target:<target_id>|* SMT denial check against head_denials_root
                td_err = self._check_smt_denial(
                    ne.get("target_smt_proof"),
                    lt_det["head_denials_root"],
                    f"target:{target_id}|*",
                    ne.get("target_state_record"),
                    np["log_id"],
                    "notary",
                    np["notary"],
                    lt_det["head_height"],
                    chain,
                    journal=journal,
                    allow_reinstatement=allow_reinst,
                    proof_err="TICKET_PROOF_INVALID",
                    revoked_err="ARTIFACT_POLICY_DENIED",
                    state_record_inclusion=ne.get("target_state_inclusion"),
                    head_cp=n_log_ctx["head_checkpoint"],
                    valid_log_ids=set(lt_det.get("valid_log_ids", [np["log_id"]])),
                    origin_bundle=ob_notary,
                )
                if td_err:
                    if td_err in ("NOTARY_LOG_COMPROMISED", "CRED_ISSUER_CLOSED", "JOURNAL_LOST", "JOURNAL_FENCED", "ARTIFACT_POLICY_DENIED"):
                        return VerifierResult("REFUSE", td_err)
                    if first_non_veto_err is None:
                        first_non_veto_err = td_err
                    continue
            else:
                n_res = self.verify_notary_act(n_env, ne.get("anchor_txid"), chain, journal=journal, origin_bundle=ob_notary)
                if n_res.verdict != "ADMIT":
                    if n_res.refusal_code in ("CRED_ISSUER_CLOSED", "JOURNAL_LOST", "JOURNAL_FENCED"):
                        return VerifierResult("REFUSE", n_res.refusal_code)
                    if n_res.refusal_code in ("CRED_REVOKED_FOR_CAUSE", "SEAL_SPENT"):
                        return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
                    if first_non_veto_err is None:
                        first_non_veto_err = "TICKET_PROOF_INVALID"
                    continue
            passed_here: set[str] = set()
            for cl in np["details"]["claims"]:
                if cl["verdict"] == "fail":
                    # Immediate global deny-wins veto (never masked by earlier malformed notarizations!)
                    return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
                if cl["verdict"] == "pass":
                    passed_here.add(cl["claim_id"])
            passed_claims_by_notary[n_key] = passed_here

        if first_non_veto_err is not None:
            return VerifierResult("REFUSE", first_non_veto_err)

        # Absent-notary target: veto proofs (reject duplicate log_id AND overlap with present notarizations; M08!)
        absent_by_log: dict[str, dict[str, Any]] = {}
        for ap_item in tp.get("absent_notary_proofs", []):
            ap_lid = ap_item["log_id"]
            if ap_lid in absent_by_log or ap_lid in seen_trusted_log_ids:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            absent_by_log[ap_lid] = ap_item
        for tn in trusted_notaries:
            tn_key = f"{tn['notary_pin']['name']}:{_outpoint_key(tn['notary_pin']['registration'])}"
            tn_lid = tn.get("log_id")
            if tn_key in seen_trusted_notaries or tn_lid is None:
                continue
            ap_item = absent_by_log.get(tn_lid)
            if ap_item is None:
                if policy["mode"] == "hardened":
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
                continue
            ob_abs = _pick_ob_for_actor(tn["notary_pin"])
            h_res = self.verify_log_checkpoint(
                ap_item["head_checkpoint"], ap_item["head_checkpoint_txid"], chain,
                journal=journal, predecessor_chain=ap_item.get("predecessor_chain"), origin_bundle=ob_abs,
            )
            if h_res.verdict != "ADMIT":
                if h_res.refusal_code in ("NOTARY_LOG_COMPROMISED", "CRED_ISSUER_CLOSED", "JOURNAL_LOST", "JOURNAL_FENCED"):
                    return VerifierResult("REFUSE", h_res.refusal_code)
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            hp_a = ap_item["head_checkpoint"]["payload"]
            if hp_a["log_id"] != tn_lid or hp_a["role"] != "notary" or not _same_actor_reg(hp_a["issuer"], tn["notary_pin"]):
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            hb_max = tn.get("heartbeat_max_blocks")
            if hb_max is not None and not hp_a["terminal"] and (chain.tip_height - int(h_res.details["confirmed_height"])) > hb_max:
                return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
            ad_err = self._check_smt_denial(
                ap_item["target_smt_proof"],
                hp_a["denials_root"],
                f"target:{target_id}|*",
                ap_item.get("target_state_record"),
                tn_lid,
                "notary",
                tn["notary_pin"],
                int(h_res.details["confirmed_height"]),
                chain,
                journal=journal,
                allow_reinstatement=allow_reinst,
                proof_err="TICKET_PROOF_INVALID",
                revoked_err="ARTIFACT_POLICY_DENIED",
                state_record_inclusion=ap_item.get("target_state_inclusion"),
                head_cp=ap_item["head_checkpoint"],
                valid_log_ids=set(h_res.details.get("valid_log_ids", [tn_lid])),
                origin_bundle=ob_abs,
            )
            if ad_err:
                return VerifierResult("REFUSE", ad_err)

        # Quorum m-of-n evaluation over required_claims (inconclusive abstains even when required_claims == []!)
        quorum_m = policy["quorum_m"]
        if req_claims:
            for rc in sorted(req_claims):
                cnt = sum(1 for cs in passed_claims_by_notary.values() if rc in cs)
                if cnt < quorum_m:
                    return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")
        elif sum(1 for cs in passed_claims_by_notary.values() if cs) < quorum_m:
            return VerifierResult("REFUSE", "ARTIFACT_POLICY_DENIED")

        return VerifierResult(
            "ADMIT",
            None,
            outcome="executed",
            details={"target_sha256": target_id, "verified_notaries": sorted(passed_claims_by_notary.keys())},
        )

    def verify_tier2_name_history_page(
        self,
        page_obj: dict[str, Any],
        expected_owner_policy: dict[str, Any],
        *,
        trusted_checkpoint: dict[str, Any] | None = None,
        current_time: int | None = None,
        allow_unresolved_voluntary_rebind: bool = False,
    ) -> VerifierResult:
        """Verify PROFILE-artifact-v1 Tier-2 SPV seallink-tier2-name-history/1 page (wire headers[], trusted_checkpoint, nc28.0 AuxPoW/version/MTP/H-2017 retarget, P2WPKH & P2WSH rotation, 0x0b/0x13/name-value schema; BLK-8)."""
        ok_p, pp = self._verify_object_wire(page_obj, expected_type="seallink-tier2-name-history/1")
        if not ok_p:
            return VerifierResult("REFUSE", pp)
        if pp["network"] != self.pinned_network or pp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        if expected_owner_policy.get("kind") == "branch":
            return VerifierResult("REFUSE", "CHAIN_SCRIPT_UNSUPPORTED")
        if len(pp["updates"]) > pp["limit"]:
            return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")

        headers = pp["headers"]
        if trusted_checkpoint is not None and self.enforce_schemas:
            tc_err = validate_against_schema("schemas/profile-artifact.schema.json#/$defs/TrustedHeaderCheckpoint", trusted_checkpoint, require_jsonschema=self.require_jsonschema)
            if tc_err:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")

        header_hashes_by_h: dict[int, str] = {}
        header_times_by_h: dict[int, int] = {}
        recent_times: list[int] = []
        prev_h: int | None = None
        prev_hash_le: bytes | None = None
        prev_bits: int | None = None
        prev_ntime: int | None = None
        pinned_epoch_start_time: int | None = int(trusted_checkpoint["epoch_start_time"]) if trusted_checkpoint is not None else None
        for h_idx, h_ent in enumerate(headers):
            hdr = bytes.fromhex(h_ent["header_hex"])
            h_num = int(h_ent["height"])
            ver, ntime, nbits = struct.unpack("<I", hdr[0:4])[0], struct.unpack("<I", hdr[68:72])[0], struct.unpack("<I", hdr[72:76])[0]
            bhash_le = sl.dsha256(hdr)
            bhash_hex = bhash_le[::-1].hex()
            if h_idx == 0 and trusted_checkpoint is not None:
                if (
                    h_num != int(trusted_checkpoint["height"])
                    or bhash_hex != trusted_checkpoint["block_hash"]
                    or f"{nbits:08x}" != trusted_checkpoint["nbits_hex"]
                ):
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            if ver & 0x00000100:
                if "auxpow" not in h_ent or not sl.verify_namecoin_auxpow(h_ent["header_hex"], h_ent["auxpow"], network=pp["network"], height=h_num):
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            else:
                if not sl.verify_namecoin_header_pow(h_ent["header_hex"], network=pp["network"], height=h_num):
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            # nc28.0 ContextualCheckBlockHeader: MTP(11) & +2h future timestamp checks (R12-H2)
            if len(recent_times) >= 11:
                mtp11 = sorted(recent_times[-11:])[5]
                if ntime <= mtp11:
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            if current_time is not None and ntime > current_time + 7200:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            if prev_h is not None:
                if h_num != prev_h + 1 or hdr[4:36] != prev_hash_le:
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
                if pp["network"] in ("regtest", "main"):
                    exp_bits: int | None = prev_bits
                    if pp["network"] == "main" and h_num % 2016 == 0:
                        anc_h = sl.namecoin_retarget_ancestor_height(h_num, network="main")
                        ep_start = header_times_by_h.get(anc_h, pinned_epoch_start_time)
                        exp_bits = (
                            sl.compute_namecoin_next_bits(prev_bits, int(ep_start), prev_ntime, network="main")
                            if (ep_start is not None and prev_bits is not None and prev_ntime is not None)
                            else None
                        )
                        # Next epoch's retarget ancestor on post-AuxPoW mainnet is H - 1 (prev_ntime)
                        pinned_epoch_start_time = prev_ntime
                    if exp_bits is None or nbits != exp_bits:
                        return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            header_hashes_by_h[h_num] = bhash_hex
            header_times_by_h[h_num] = ntime
            recent_times.append(ntime)
            prev_h, prev_hash_le, prev_bits, prev_ntime = h_num, bhash_le, nbits, ntime

        name_expiry = 30 if pp["network"] == "regtest" else 36000
        verified_updates: list[dict[str, Any]] = []
        cur_owner_pol = copy.deepcopy(expected_owner_policy)
        cur_owner_spk = sl.compile_script_policy(cur_owner_pol)[0].hex()
        if "cursor_txid" in pp:
            if "cursor_owner_policy" in pp and sl.compile_script_policy(pp["cursor_owner_policy"])[0].hex() != cur_owner_spk:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            expected_prev: tuple[str, int] = (pp["cursor_txid"], int(pp["cursor_vout"]))
            prev_h_u: int | None = int(pp["cursor_height"])
            allow_fu_match = False
        else:
            expected_prev = (pp["registration"]["txid"], int(pp["registration"]["vout"]))
            prev_h_u = None
            allow_fu_match = True
        prev_bhash_u: str | None = None
        prev_tx_index_u: int = -1

        for idx, upd_p in enumerate(pp["updates"]):
            uh = int(upd_p["block_height"])
            if prev_h_u is not None:
                if uh < prev_h_u or uh >= prev_h_u + name_expiry:
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
                if idx > 0 and uh == prev_h_u and (upd_p["block_hash"] != prev_bhash_u or int(upd_p["tx_index"]) < prev_tx_index_u + 1):
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            if header_hashes_by_h.get(uh) != upd_p["block_hash"]:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            ok_spv, spv_res = sl.verify_segwit_name_update_proof(upd_p, cur_owner_pol, pp["name"])
            if not ok_spv or not isinstance(spv_res, dict):
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            pu = spv_res["parsed_update"]
            is_fu0 = idx == 0 and allow_fu_match and pu["op"] == "NAME_FIRSTUPDATE"
            chain_link_ok = (
                (spv_res["txid"], spv_res["name_vout"]) == expected_prev
                if is_fu0
                else (pu["op"] == "NAME_UPDATE" and (spv_res["spent_prev_txid"], spv_res["spent_prev_vout"]) == expected_prev)
            )
            if not chain_link_ok:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            # H-1d: Validate 520-byte Restricted JCS value AND closed schemas/name-value.schema.json!
            if pu["value"] != "":
                ok_v, v_obj_t2 = sl.jcs_validate(pu["value"].encode("utf-8"), max_bytes=520)
                if not ok_v or (
                    self.enforce_schemas
                    and validate_against_schema("schemas/name-value.schema.json", v_obj_t2, require_jsonschema=self.require_jsonschema) is not None
                ):
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            slnk_b, bad_slnk = self._extract_slnk_bytes_strict({"opreturns": spv_res["opreturns"]})
            slnk_decoded: dict[str, Any] | None = None
            if bad_slnk or slnk_b is not None:
                try:
                    if bad_slnk or slnk_b is None:
                        raise ValueError("CHAIN_FRAME_INVALID")
                    dec_s = sl.decode_opreturn_with_criticality(slnk_b)
                except ValueError:
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
                if dec_s.get("critical_scope") in ("forward_only", "retroactive"):
                    return VerifierResult("REFUSE", "ORIGIN_STATUS_INCOMPLETE")
                if dec_s.get("action") == "0x0b" and dec_s["h_c"] > uh:
                    return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
                if dec_s.get("action") == "0x13" and not allow_unresolved_voluntary_rebind:
                    return VerifierResult("REFUSE", "ORIGIN_STATUS_INCOMPLETE")
                slnk_decoded = dec_s
            # BLK-8 / H-1b / H05: Evolve expected owner_policy on authorized cold P2WPKH OR P2WSH m-of-n rotation!
            new_spk = spv_res["new_trailing_script_pubkey"]
            owner_rotated = new_spk != cur_owner_spk
            if owner_rotated and idx + 1 != len(pp["updates"]):
                try:
                    nxt_tx = sl.parse_raw_tx(bytes.fromhex(pp["updates"][idx + 1]["tx_hex"]))
                    for vin_n in nxt_tx["vin"]:
                        if vin_n["prev_txid"] == spv_res["txid"] and vin_n["prev_vout"] == spv_res["name_vout"]:
                            wit_n = vin_n["witness"]
                            cand_pol: dict[str, Any] | None = None
                            if len(wit_n) == 2 and len(wit_n[1]) == 33 and sl.is_valid_compressed_pubkey(wit_n[1].hex()):
                                cand_pol = {"kind": "key", "pk": wit_n[1].hex()}
                            elif len(wit_n) >= 3 and len(new_spk) == 68 and new_spk.startswith("0020") and sl.sha256(wit_n[-1]).hex() == new_spk[4:]:
                                cand_pol = sl.parse_p2wsh_multisig_script(wit_n[-1])
                            if cand_pol is not None and sl.compile_script_policy(cand_pol)[0].hex() == new_spk:
                                cur_owner_pol = cand_pol
                                cur_owner_spk = new_spk
                            break
                except (ValueError, KeyError, TypeError):
                    pass
            vu_entry: dict[str, Any] = {
                "block_height": uh,
                "name_vout": spv_res["name_vout"],
                "new_trailing_script_pubkey": new_spk,
                "op": pu["op"],
                "owner_authored": spv_res["owner_authored"],
                "owner_policy": copy.deepcopy(cur_owner_pol),
                "owner_rotated": owner_rotated,
                "txid": spv_res["txid"],
                "value": pu["value"],
            }
            if slnk_decoded is not None:
                vu_entry["slnk_frame"] = slnk_decoded
            verified_updates.append(vu_entry)
            expected_prev = (spv_res["txid"], spv_res["name_vout"])
            prev_h_u = uh
            prev_bhash_u = upd_p["block_hash"]
            prev_tx_index_u = int(upd_p["tx_index"])

        if "next_cursor" in pp:
            nc = pp["next_cursor"]
            if not verified_updates or nc["height"] != prev_h_u or nc["txid"] != expected_prev[0] or nc["vout"] != expected_prev[1]:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            nc_spk = sl.compile_script_policy(nc["owner_policy"])[0].hex()
            if nc_spk != verified_updates[-1]["new_trailing_script_pubkey"]:
                return VerifierResult("REFUSE", "TICKET_PROOF_INVALID")
            cur_owner_pol = copy.deepcopy(nc["owner_policy"])
            cur_owner_spk = nc_spk

        return VerifierResult(
            "ADMIT",
            None,
            outcome="executed",
            details={
                "final_owner_policy": cur_owner_pol,
                "name": pp["name"],
                "verified_tip_height": prev_h,
                "verified_updates": verified_updates,
            },
        )

    def verify_verdict(
        self,
        verdict_env: dict[str, Any],
        contract_obj: dict[str, Any],
        chain: ChainView,
        *,
        prev_verdict_env: dict[str, Any] | None = None,
        anchor_txid: str | None = None,
    ) -> VerifierResult:
        """Verify seallink-verdict/1 against contract.moderation & optional 0x03 frame (SPEC-05 §3, H-24)."""
        ok_v, v_res = self._verify_object_wire(verdict_env, expected_type="seallink-verdict/1")
        if not ok_v:
            return VerifierResult("REFUSE", v_res)
        ok_c, c_res = self._verify_object_wire(contract_obj, expected_type="seallink-contract/1")
        if not ok_c:
            return VerifierResult("REFUSE", c_res)
        vp = v_res["payload"]
        if vp["network"] != self.pinned_network or vp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        mod = c_res.get("moderation")
        if not mod or vp["contract_id"] != sl.object_id(c_res) or vp["rules_sha256"] != mod["rules_sha256"]:
            return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
        if vp["ordinal"] >= 2:
            if prev_verdict_env is None or vp.get("prev_verdict_id") != sl.object_id(prev_verdict_env["payload"]):
                return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
        ok_s, scode = sl.verify_signature_set(
            sl.signing_digest(vp),
            verdict_env["signatures"],
            expected_policy={"m": 1, "pks": [mod["moderator_key"]]},
            obj_type="seallink-verdict/1",
        )
        if not ok_s:
            return VerifierResult("REFUSE", scode)
        if anchor_txid is not None:
            atx = chain.get_tx(anchor_txid)
            if self._decode_opreturn_tx(atx, require_confirmed=False, expected_action="0x03", expected_commitment=sl.signing_digest(vp).hex()) is None:
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
        return VerifierResult("ADMIT", None, outcome="executed", details={"verdict_id": sl.object_id(vp)})

    def verify_termination(
        self,
        term_env: dict[str, Any],
        contract_obj: dict[str, Any],
        chain: ChainView,
        *,
        spend_txid: str | None = None,
        origin_bundle: dict[str, Any] | None = None,
        origin_bundles_by_oid: dict[str, dict[str, Any]] | None = None,
        journal: FencedJournal | None = None,
    ) -> VerifierResult:
        """Verify seallink-termination/1 (autonomous party, arbiter, or ward guardian_approvals[]) and optional 0x08 contract-seal spend frame (SPEC-05 §2.3, M-10 / F-21)."""
        ok_t, t_res = self._verify_object_wire(term_env, expected_type="seallink-termination/1")
        if not ok_t:
            return VerifierResult("REFUSE", t_res)
        ok_c, c_res = self._verify_object_wire(contract_obj, expected_type="seallink-contract/1")
        if not ok_c:
            return VerifierResult("REFUSE", c_res)
        tp = t_res["payload"]
        if tp["network"] != self.pinned_network or tp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        if tp["contract_id"] != sl.object_id(c_res):
            return VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH")
        # Ward guardian_approvals[] termination path (F-21)
        if "guardian_approvals" in term_env:
            gc = tp["guardian_context"]
            ward_pt = next((pt for pt in c_res.get("parties", []) if pt.get("ward_origin_id") == gc["origin_id"]), None)
            if ward_pt is None:
                return VerifierResult("REFUSE", "WIRE_SIGNATURE")
            ob_w = self._pick_origin_bundle_for_oid(gc["origin_id"], origin_bundle, origin_bundles_by_oid)
            wstate, oerr = self.verify_origin_and_status(ob_w, chain, journal=journal)
            if oerr:
                return VerifierResult("REFUSE", oerr)
            assert wstate is not None
            if wstate["capacity"] != "ward":
                return VerifierResult("REFUSE", "GUARDIAN_QUORUM_UNMET")
            ok_g, gerr, gdet = self.verify_ward_approvals(
                term_env, wstate, chain, journal=journal, origin_bundles_by_oid=origin_bundles_by_oid
            )
            if not ok_g:
                return VerifierResult("REFUSE", gerr)
            if spend_txid is not None:
                stx = chain.get_tx(spend_txid)
                if self._decode_opreturn_tx(stx, require_confirmed=False, expected_action="0x08", expected_commitment=sl.signing_digest(tp).hex()) is None:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
            return VerifierResult("ADMIT", None, outcome="executed", details={"termination_id": sl.object_id(tp), **gdet})

        # Autonomous party OR arbiter signing policy (F-21)
        allowed_pols: list[dict[str, Any]] = []
        for pt in c_res.get("parties", []):
            if "signing_policy" in pt:
                allowed_pols.append(pt["signing_policy"])
        if tp["termination_branch"] == "arbiter":
            seal_pol = c_res.get("seal", {}).get("script_policy", {})
            if isinstance(seal_pol, dict) and seal_pol.get("template") == "arbiter_or_both":
                arb_spec = seal_pol.get("keys", {}).get("arbiter")
                if isinstance(arb_spec, str) and len(arb_spec) == 66:
                    allowed_pols.append({"m": 1, "pks": [arb_spec[2:]]})
                elif isinstance(arb_spec, dict) and isinstance(arb_spec.get("pks"), list) and "m" in arb_spec:
                    allowed_pols.append({"m": int(arb_spec["m"]), "pks": sorted(pk[2:] for pk in arb_spec["pks"] if isinstance(pk, str) and len(pk) == 66)})
            mod = c_res.get("moderation")
            if isinstance(mod, dict) and isinstance(mod.get("moderator_key"), str):
                allowed_pols.append({"m": 1, "pks": [mod["moderator_key"]]})
        sig_norm = _normalize_policy(term_env["signatures"]["policy"])
        matched_pol = next((pol for pol in allowed_pols if _normalize_policy(pol) == sig_norm), None)
        if matched_pol is None:
            return VerifierResult("REFUSE", "WIRE_SIGNATURE")
        ok_s, scode = sl.verify_signature_set(
            sl.signing_digest(tp), term_env["signatures"], expected_policy=matched_pol, obj_type="seallink-termination/1"
        )
        if not ok_s:
            return VerifierResult("REFUSE", scode)
        if spend_txid is not None:
            stx = chain.get_tx(spend_txid)
            if self._decode_opreturn_tx(stx, require_confirmed=False, expected_action="0x08", expected_commitment=sl.signing_digest(tp).hex()) is None:
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
        return VerifierResult("ADMIT", None, outcome="executed", details={"termination_id": sl.object_id(tp)})

    def verify_certset_head(
        self,
        head_obj: dict[str, Any],
        statements: list[dict[str, Any]],
        owner_manifest: dict[str, Any],
    ) -> VerifierResult:
        """Verify seallink-certset-head/1 set_sha256 = SHA256(JCS(sorted_content_addrs)) & manifest pin (SPEC-03 §3.1, S-19, H-24)."""
        ok_h, h_res = self._verify_object_wire(head_obj, expected_type="seallink-certset-head/1")
        if not ok_h:
            return VerifierResult("REFUSE", h_res)
        pin = owner_manifest.get("sets", {}).get("certs")
        if not pin or sl.content_addr(h_res) != pin.get("sha256") or h_res.get("seq") != pin.get("seq"):
            return VerifierResult("REFUSE", "MANIFEST_MISMATCH")
        caddrs: list[str] = []
        for st in statements:
            ok_s, s_res = self._verify_object_wire(st, expected_type="seallink-statement/1")
            if not ok_s:
                return VerifierResult("REFUSE", s_res)
            caddrs.append(sl.content_addr(s_res))
        sorted_caddrs = sorted(set(caddrs))
        expected_set_sha = sl.sha256(sl._jcs_serialize(sorted_caddrs, None, (), 0).encode("utf-8")).hex()
        if len(sorted_caddrs) != h_res["count"] or expected_set_sha != h_res["set_sha256"]:
            return VerifierResult("REFUSE", "MANIFEST_MISMATCH")
        return VerifierResult("ADMIT", None, outcome="executed", details={"count": len(sorted_caddrs), "set_sha256": expected_set_sha})

    def verify_statement(
        self,
        stmt_env: dict[str, Any],
        chain: ChainView,
        *,
        expected_policy: dict[str, Any] | None = None,
        device_list: dict[str, Any] | None = None,
        owner_manifest: dict[str, Any] | None = None,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
        journal: FencedJournal | None = None,
        origin_bundle: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Verify seallink-statement/1 against issuer's link.grant, pinned policy, or confirmed manifest-enrolled device key (SPEC-03 §3.1, H-6 / H01)."""
        ok_s, s_res = self._verify_object_wire(stmt_env, expected_type="seallink-statement/1")
        if not ok_s:
            return VerifierResult("REFUSE", s_res)
        sp = s_res["payload"]
        if sp["network"] != self.pinned_network or sp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        if not (sp["not_before"] <= chain.now < sp["not_after"]):
            return VerifierResult("REFUSE", "INVOKE_TIME_INVALID")
        sig_pol = stmt_env["signatures"]["policy"]
        if expected_policy is not None:
            ok_sig, scode = sl.verify_signature_set(
                sl.signing_digest(sp), stmt_env["signatures"], expected_policy=expected_policy, obj_type="seallink-statement/1"
            )
            if not ok_sig:
                return VerifierResult("REFUSE", scode)
            return VerifierResult("ADMIT", None, outcome="executed", details={"statement_id": sl.object_id(sp), "kind": sp["statement_kind"]})
        iss = sp["issuer"]
        nrec, nerr = self.resolve_name(
            iss["name"],
            chain,
            expected_owner_policy=iss["owner_policy"],
            expected_registration=iss["registration"],
            allow_unresolved_voluntary_rebind=(origin_bundle is not None),
        )
        if nerr:
            return VerifierResult("REFUSE", nerr)
        assert nrec is not None
        if nrec.get("_voluntary_rebinds"):
            rb_err = self._verify_rebound_pin(nrec, iss, origin_bundle, chain, journal)
            if rb_err:
                return VerifierResult("REFUSE", rb_err)
        if device_list is not None and (sig_pol.get("alg") in ("p256", "ed25519") or sp["statement_kind"] == "config-section"):
            ok_dl, dl_res = self._verify_object_wire(device_list, expected_type="seallink-device-list/1")
            if not ok_dl or dl_res.get("owner") != iss["name"]:
                return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
            # H01 / H-6: Establish chain of trust from confirmed name m.h -> owner_manifest -> sets.devices!
            pres_m: dict[str, dict[str, Any]] = (
                {iss["name"]: owner_manifest} if owner_manifest is not None else dict(presented_manifests or {})
            )
            man, merr = self.resolve_manifest(iss["name"], nrec, pres_m, chain, journal)
            if merr:
                return VerifierResult("REFUSE", merr)
            assert man is not None
            dev_pin = man.get("sets", {}).get("devices")
            if not dev_pin or sl.content_addr(dl_res) != dev_pin.get("sha256") or dl_res.get("seq") != dev_pin.get("seq"):
                return VerifierResult("REFUSE", "MANIFEST_MISMATCH")
            alg = sig_pol.get("alg", "bip340")
            matched = (
                next((d for d in dl_res["devices"] if d["alg"] == alg and d["key"] == sig_pol["pks"][0]), None)
                if (sig_pol["m"] == 1 and len(sig_pol["pks"]) == 1)
                else None
            )
            if matched is None:
                return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
            _, serr, _ = self.evaluate_seal(matched["seal"], chain, required_depth=1)
            if serr:
                return VerifierResult("REFUSE", serr)
            return VerifierResult("ADMIT", None, outcome="executed", details={"statement_id": sl.object_id(sp), "kind": sp["statement_kind"]})
        # Default: verify against issuer's live link.grant policy (+ 0x0b compromise cutoff)
        rpol, rerr = self.resolve_role_policy(nrec, "grant", sig_pol)
        if rerr:
            return VerifierResult("REFUSE", rerr)
        assert rpol is not None
        if self._is_policy_compromised_at(nrec, iss, "grant", rpol, chain.tip_height, chain):
            return VerifierResult("REFUSE", "CRED_ISSUER_CLOSED")
        ok_sig, scode = sl.verify_signature_set(
            sl.signing_digest(sp), stmt_env["signatures"], expected_policy=rpol, obj_type="seallink-statement/1"
        )
        if not ok_sig:
            return VerifierResult("REFUSE", scode)
        return VerifierResult("ADMIT", None, outcome="executed", details={"statement_id": sl.object_id(sp), "kind": sp["statement_kind"]})

    # ------------------------------------------------------------------
    # SPEC-06 §4 Deterministic 12-Step Two-Phase Invocation Admission Pipeline
    # ------------------------------------------------------------------

    @staticmethod
    def _capability_narrows(ccap: dict[str, Any], pcap: dict[str, Any]) -> bool:
        """Check SL-WIRE-017 mechanical capability attenuation (ccap <= pcap)."""
        if ccap["action"] != pcap["action"] or ccap["target"] != pcap["target"]:
            return False
        for pk_name, ppred in pcap.get("where", {}).items():
            cpred = ccap.get("where", {}).get(pk_name)
            if cpred is None or not sl.narrows_predicate(cpred, ppred):
                return False
        p_quotas = {(q["kind"], q["resource"], q["unit"], q["window"]): int(q["max"]) for q in pcap.get("quotas", [])}
        c_quotas = {(q["kind"], q["resource"], q["unit"], q["window"]): int(q["max"]) for q in ccap.get("quotas", [])}
        return all(k in c_quotas and c_quotas[k] <= v for k, v in p_quotas.items())

    @staticmethod
    def _party_matches_actor(
        party: dict[str, Any],
        actor_pin: dict[str, Any],
        *,
        is_recipient: bool = False,
        actor_origin_id: str | None = None,
    ) -> bool:
        """Check whether a grant issuer or recipient corresponds to a party in contract.parties[] (D-5)."""
        if not is_recipient:
            # Root grant issuer has {name, registration, owner_policy} (and optional ward origin_id)
            if "ward_origin_id" in party and actor_origin_id is not None and party["ward_origin_id"] == actor_origin_id:
                return True
            if "name_pin" in party:
                return _name_pin_equal(party["name_pin"], actor_pin)
            if "signing_policy" in party and "role_policy" in actor_pin:
                return _normalize_policy(party["signing_policy"]) == _normalize_policy(actor_pin["role_policy"])
            return False
        # Leaf grant recipient has mode: key | name | group
        rmode = actor_pin.get("mode")
        if rmode == "name":
            if "name_pin" in party:
                return _name_pin_equal(party["name_pin"], actor_pin)
            return False
        if rmode == "key":
            return "signing_policy" in party and _normalize_policy(party["signing_policy"]) == {"m": 1, "pks": [actor_pin["key"]]}
        if rmode == "group":
            return "signing_policy" in party and _normalize_policy(party["signing_policy"]) == _normalize_policy(actor_pin["threshold"])
        return False

    @staticmethod
    def _party_identity_key(party: dict[str, Any]) -> str:
        """Canonical identity key for enforcing distinct contract parties (D-5 / R2-15)."""
        if "ward_origin_id" in party:
            return f"ward:{party['ward_origin_id']}"
        if "name_pin" in party:
            np = party["name_pin"]
            return f"name:{np['name']}:{_outpoint_key(np['registration'])}:{sl.jcs_encode(np['owner_policy']).decode('utf-8')}"
        if "signing_policy" in party:
            return f"pol:{sl.jcs_encode(_normalize_policy(party['signing_policy'])).decode('utf-8')}"
        return f"id:{party.get('party_id', '')}"

    def _check_target_authority(
        self,
        target_str: str,
        act_meta: dict[str, Any],
        iss_pin: dict[str, Any],
        nrec: dict[str, Any],
        leaf_gp: dict[str, Any],
        bundle: dict[str, Any],
        chain: ChainView,
        journal: FencedJournal,
        executor_cfg: dict[str, Any],
        *,
        wstate: dict[str, Any] | None = None,
        ward_details: dict[str, Any] | None = None,
    ) -> str | None:
        """Enforce fail-closed target authority & concrete-executor provider binding (B-1, B-3, G7-01, G7-08, G7-17)."""
        t_regex = act_meta.get("target_pattern") or act_meta.get("target_regex")
        if t_regex and not re.match(t_regex, target_str):
            return "GRANT_TARGET_UNAUTHORIZED"
        t_auth = act_meta.get("target_authority")
        if t_auth == "mailbox_owner":
            rest = target_str[len("mailbox:") :]
            m_owner, m_label = rest.rsplit(":", 1)
            if iss_pin["name"] != m_owner:
                return "GRANT_TARGET_UNAUTHORIZED"
            # G7-08 / M-7: Concrete-executor mailbox grants MUST verify holder manifest provider binding using full NamePin
            # (fail closed unless explicitly self_hosted AND executor_cfg.pin NamePin equals root issuer NamePin)!
            exec_pin = executor_cfg.get("pin")
            is_self_hosted = (
                bool(executor_cfg.get("self_hosted"))
                and isinstance(exec_pin, dict)
                and _name_pin_equal(iss_pin, exec_pin)
            )
            if "executor_ref" not in leaf_gp and not is_self_hosted:
                bound = False
                if isinstance(exec_pin, dict):
                    o_man, o_merr = self.resolve_manifest(m_owner, nrec, bundle.get("manifests", {}), chain, journal)
                    if o_merr is not None or o_man is None:
                        return "SERVICE_PROVIDER_UNBOUND" if o_merr == "MANIFEST_UNAVAILABLE" else (o_merr or "SERVICE_PROVIDER_UNBOUND")
                    bound = any(
                        p.get("service_type") == "mail"
                        and p.get("label") == m_label
                        and isinstance(p.get("provider"), dict)
                        and _name_pin_equal(p["provider"], exec_pin)
                        for p in o_man.get("providers", [])
                    )
                if not bound:
                    return "SERVICE_PROVIDER_UNBOUND"
        elif t_auth in ("station_host", "station_host_and_contract"):
            rest = target_str[len("station:") :]
            s_host, s_slot = rest.rsplit(":", 1)
            # G7-01 / M-7: Fail-closed station slot authority! Strict full NamePin ONLY (zero bare string fallbacks)!
            station_bindings = executor_cfg.get("station_slot_bindings")
            if isinstance(station_bindings, dict):
                raw_pins = station_bindings.get(target_str) or station_bindings.get(s_slot) or []
                pins = [raw_pins] if isinstance(raw_pins, dict) else (raw_pins if isinstance(raw_pins, list) else [])
                slot_ok = any(_name_pin_equal(iss_pin, p) for p in pins if isinstance(p, dict))
            else:
                host_pin = executor_cfg.get("pin")
                slot_ok = isinstance(host_pin, dict) and _name_pin_equal(iss_pin, host_pin)
            if s_host != executor_cfg["name"] or not slot_ok:
                return "GRANT_TARGET_UNAUTHORIZED"
        elif t_auth in ("pinned_ward", "ward_origin"):
            # B-3: Mandatory pinned_ward_origin_id, ward capacity, and target == ward:<pinned_oid>!
            pinned_oid = executor_cfg.get("pinned_ward_origin_id")
            if not pinned_oid:
                return "ORIGIN_UNVERIFIED"
            if not ward_details or wstate is None or wstate.get("capacity") != "ward":
                return "WARD_AUTONOMOUS_FORBIDDEN"
            if target_str != f"ward:{pinned_oid}" or wstate["origin_id"] != pinned_oid:
                return "GRANT_TARGET_UNAUTHORIZED"
        return None

    def admit_and_reserve(
        self,
        inv_env: dict[str, Any] | bytes,
        bundle: dict[str, Any],
        chain: ChainView,
        journal: FencedJournal,
        executor_cfg: dict[str, Any],
        *,
        use_txid: str | None = None,
        raw_message_bytes: bytes | None = None,
        actual_message_meta: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Phase 1 of SPEC-06 §4 (R1-A, B-7, R3 B4): full 12-step admission + ONE atomic `reservation` journal entry."""
        # Step 1: Invocation wire + Draft 2020-12 closed schema + profile action args schema check
        ok_w, res_w = self._verify_object_wire(inv_env, expected_type="seallink-invocation/1")
        if not ok_w:
            return VerifierResult("REFUSE", res_w)
        inv_env = res_w
        inv_p = res_w["payload"]
        inv_id = sl.object_id(inv_p)
        inv_caddr = sl.content_addr(inv_env)

        # Step 2: Early local request checks (pre-chain)
        if inv_p["network"] != self.pinned_network or inv_p["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        now = chain.now
        if not (inv_p["iat"] <= now < inv_p["exp"]):
            return VerifierResult("REFUSE", "INVOKE_TIME_INVALID")
        if inv_p["executor"]["name"] != executor_cfg.get("name") or inv_p["executor"]["key"] != executor_cfg.get("key"):
            return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")

        # Step 3: Presented bundle wire, early recipient auth, and pre-chain replay/crash recovery
        grants_by_id: dict[str, dict[str, Any]] = {}
        for g in bundle.get("grants", []):
            ok_g, res_g = self._verify_object_wire(g, expected_type="seallink-grant/1")
            if not ok_g:
                return VerifierResult("REFUSE", res_g)
            gp_chk = res_g["payload"]
            if gp_chk["network"] != self.pinned_network or gp_chk["genesis"] != self.pinned_genesis:
                return VerifierResult("REFUSE", "CHAIN_MISMATCH")
            grants_by_id[sl.object_id(gp_chk)] = res_g

        ppath = inv_p["proof_path"]
        root_gid = ppath[0]["grant_id"]
        leaf_gid = ppath[-1]["grant_id"]
        if root_gid not in grants_by_id or leaf_gid not in grants_by_id:
            return VerifierResult("REFUSE", "WIRE_MEMBER")
        root_grant = grants_by_id[root_gid]
        leaf_grant = grants_by_id[leaf_gid]
        root_gp = root_grant["payload"]
        leaf_gp = leaf_grant["payload"]
        if "issuer" not in root_gp:
            return VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE")

        # Step 3b: Early recipient authentication for key/group BEFORE cached-receipt lookup!
        rcpt_spec = leaf_gp["recipient"]
        if rcpt_spec["mode"] == "key":
            ok_r, rcode = sl.verify_signature_set(
                sl.signing_digest(inv_p),
                inv_env["signatures"],
                expected_policy={"m": 1, "pks": [rcpt_spec["key"]]},
                obj_type="seallink-invocation/1",
            )
            if not ok_r:
                return VerifierResult("REFUSE", rcode)
        elif rcpt_spec["mode"] == "group":
            ok_r, rcode = sl.verify_signature_set(
                sl.signing_digest(inv_p),
                inv_env["signatures"],
                expected_policy=rcpt_spec["threshold"],
                obj_type="seallink-invocation/1",
            )
            if not ok_r:
                return VerifierResult("REFUSE", rcode)

        def check_local_replay_or_crash() -> VerifierResult | None:
            # M-4: Check unsettled reservations BEFORE cached receipts so unreconciled `uncertain` ALWAYS returns UNCERTAIN!
            if inv_id in journal.unsettled_reservations:
                unsettled_rec = journal.unsettled_reservations[inv_id]
                return VerifierResult(
                    "UNCERTAIN",
                    None,
                    outcome="uncertain",
                    details={
                        "reservation_retained": True,
                        "zero_second_effect": True,
                        "unsettled_count": len(unsettled_rec.get("reservations", [])),
                    },
                )
            if inv_id in journal.receipts:
                cached = journal.receipts[inv_id]
                return VerifierResult(
                    "ADMIT",
                    None,
                    outcome=cached["payload"]["outcome"],
                    cached_receipt_content_addr=sl.content_addr(cached),
                    details={"cached_receipt": True},
                )
            # R1-A / B-7: Terminal settlement committed but receipt blob missing -> NEVER re-execute!
            if inv_id in journal.terminal_invocations:
                return VerifierResult("REFUSE", "INVOKE_REPLAY")
            if inv_p["nonce"] in journal.nonces and journal.nonces[inv_p["nonce"]] != inv_id:
                return VerifierResult("REFUSE", "INVOKE_REPLAY")
            return None

        if rcpt_spec["mode"] in ("key", "group"):
            early_rep = check_local_replay_or_crash()
            if early_rep is not None:
                return early_rep

        # Step 4: Consistent chain observation (resolve action profile from registry/actions.json + optional local overrides)
        action = inv_p["action"]
        local_action_profiles = executor_cfg.get("action_profiles") or {}
        act_meta = ACTION_PROFILES.get(action) or local_action_profiles.get(action)
        risk_cls = act_meta["risk_class"] if act_meta is not None else 1
        obs_err = self.check_chain_observation(chain, risk_class=risk_cls)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)

        # Step 5: Journal continuity
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)

        # Step 6..10d via unified backing-grant verification helper (shared with verify_session_open, G7-03)
        ok_bg, err_bg, bg = self._verify_backing_grant_chain(
            ppath=ppath,
            grants_by_id=grants_by_id,
            bundle=bundle,
            chain=chain,
            journal=journal,
            executor_cfg=executor_cfg,
            local_action_profiles=local_action_profiles,
            act_meta=act_meta,
            inv_action=action,
            inv_arguments=inv_p["arguments"],
            inv_caddr=inv_caddr,
            use_txid=use_txid,
            for_session_open=False,
        )
        if not ok_bg:
            assert err_bg is not None
            return err_bg
        iss_pin = bg["iss_pin"]
        nrec = bg["nrec"]
        wstate = bg["wstate"]
        ward_details = bg["ward_details"]
        matched_parent_template = bg["matched_parent_template"]
        journal_writes = bg["journal_writes"]
        resolved_use_txid = bg.get("resolved_use_txid") or use_txid

        # Step 11: Named recipient, action, text ban, target authority (B-1, G7-01, G7-08), and constraints
        # 11a. Named recipient (B-9: pin exact registration!; H-1a: support 0x13 origin_bundle!)
        if rcpt_spec["mode"] == "name":
            r_ob = bundle.get("recipient_origin_bundle") or bundle.get("origin_bundle")
            r_obs = bundle.get("origin_bundles_by_oid")
            r_nrec, r_nerr = self.resolve_name(
                rcpt_spec["name"],
                chain,
                expected_owner_policy=rcpt_spec["owner_policy"],
                expected_registration=rcpt_spec["registration"],
                allow_unresolved_voluntary_rebind=(r_ob is not None or bool(r_obs)),
            )
            if r_nerr:
                return VerifierResult("REFUSE", r_nerr)
            assert r_nrec is not None
            if r_nrec.get("_voluntary_rebinds"):
                rb_err_r = self._verify_rebound_pin(
                    r_nrec, rcpt_spec, r_ob, chain, journal, origin_bundles_by_oid=r_obs
                )
                if rb_err_r:
                    return VerifierResult("REFUSE", rb_err_r)
            nostr_val = r_nrec.get("_value_obj", {}).get("nostr")
            req_pk = nostr_val if isinstance(nostr_val, str) else (nostr_val.get("names", {}).get("_") if isinstance(nostr_val, dict) else None)
            ok_rsig, rscode = (
                (False, "WIRE_SIGNATURE")
                if not req_pk
                else sl.verify_signature_set(
                    sl.signing_digest(inv_p),
                    inv_env["signatures"],
                    expected_policy={"m": 1, "pks": [req_pk]},
                    obj_type="seallink-invocation/1",
                )
            )
            if not ok_rsig:
                return VerifierResult("REFUSE", rscode)
            named_rep = check_local_replay_or_crash()
            if named_rep is not None:
                return named_rep

        # 11b. Action registered, supported by executor, and present in capabilities (R3 M6)
        action_caps = [c for c in leaf_gp["capabilities"] if c["action"] == action]
        if act_meta is None or (executor_cfg.get("actions") is not None and action not in executor_cfg["actions"]) or not action_caps:
            return VerifierResult("REFUSE", "INVOKE_ACTION_DENIED")

        # 11c. Mechanical effect text ban
        if act_meta.get("mechanical", True) and "terms_text" in leaf_gp:
            return VerifierResult("REFUSE", "GRANT_TEXT_FORBIDDEN")

        # 11d. Target Authority Verification (B-1, B-3, G7-01, G7-08)
        target_str = inv_p["target"]
        t_err = self._check_target_authority(
            target_str,
            act_meta,
            iss_pin,
            nrec,
            leaf_gp,
            bundle,
            chain,
            journal,
            executor_cfg,
            wstate=wstate,
            ward_details=ward_details,
        )
        if t_err is not None:
            return VerifierResult("REFUSE", t_err)

        # 11e. Target match, 7-predicate where evaluation, and profile server-side checks (H-15: mail/read folder/sender_domain/max_bytes ALL require actual_message_meta!)
        matched_cap = None
        for cap in action_caps:
            if cap["target"] != target_str:
                continue
            if self._match_capability_where(action, cap, inv_p["arguments"], actual_message_meta):
                matched_cap = cap
                break
        if matched_cap is None:
            return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")

        frame_details: dict[str, Any] = dict(ward_details)
        if action == "agent/guardian-message":
            args = inv_p["arguments"]
            pinned_oid = executor_cfg["pinned_ward_origin_id"]
            if args["origin_id"] != pinned_oid or args["subject_ward_name"] != iss_pin["name"]:
                return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")
            if args["revision"] != ward_details.get("verified_revision"):
                return VerifierResult("REFUSE", "GUARDIAN_QUORUM_UNMET")
            if raw_message_bytes is None or sl.sha256(raw_message_bytes).hex() != args["message_sha256"]:
                return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")
            # Construct canonical AuthorityFrame (G-10, schemas/profile-agent.schema.json#/$defs/AuthorityFrame)
            authority_frame = {
                "channel": args["channel"],
                "grant_id": leaf_gid,
                "invocation_id": inv_id,
                "message_sha256": args["message_sha256"],
                "origin_id": pinned_oid,
                "recorded_at": chain.now,
                "revision": args["revision"],
                "subject_ward_name": args["subject_ward_name"],
                "verified_guardians": list(ward_details["verified_guardians"]),
                "verified_slots": list(ward_details["verified_slots"]),
            }
            frame_details["authority_frame"] = authority_frame
            frame_details["frame_sha256"] = sl.sha256(sl.jcs_encode(authority_frame)).hex()

        # Step 12: Pre-effect recheck (R1-B unified decision clock) & ONE atomic Phase-1 `reservation` entry
        rb_err = self.check_rebracket(chain, risk_class=act_meta["risk_class"])
        if rb_err:
            return VerifierResult("REFUSE", rb_err)
        rb_tip = chain.raw.get("rebracket_tip")
        decision_now = int(rb_tip["now"]) if isinstance(rb_tip, dict) and "now" in rb_tip else chain.now
        if not (inv_p["iat"] <= decision_now < inv_p["exp"]):
            return VerifierResult("REFUSE", "INVOKE_TIME_INVALID")

        quotas = matched_cap.get("quotas", [])
        # B-8 + G7-02: Enforce mandatory profile quotas from registry/actions.json INCLUDING exact resource == target!
        for rq in act_meta.get("required_quotas", []):
            exp_res = target_str if rq.get("resource") == "{target}" else rq.get("resource")
            has_req = any(
                q.get("kind") == rq["kind"]
                and q.get("unit") == rq["unit"]
                and (exp_res is None or q.get("resource") == exp_res)
                for q in quotas
            )
            if not has_req:
                return VerifierResult("REFUSE", "QUOTA_EXCEEDED")

        # Build parent template row caps when executing a depth-2 child grant
        parent_row_caps: dict[tuple[str, str, str, str], int] = {}
        if len(ppath) == 2 and matched_parent_template is not None:
            for pcap in matched_parent_template.get("capabilities", []):
                if pcap["action"] == action and pcap["target"] == target_str:
                    for pq in pcap.get("quotas", []):
                        pk_t = (pq["kind"], pq["resource"], pq["unit"], pq["window"])
                        parent_row_caps[pk_t] = max(parent_row_caps.get(pk_t, 0), int(pq["max"]))

        # Validate ALL accounts & quotas BEFORE mutating journal or watermarks (atomic batch!)
        pending_ops: list[dict[str, Any]] = []
        watermark_updates: dict[str, int] = {}
        planned_usage_delta: dict[tuple[str, str, str], int] = {}

        for q in quotas:
            qkey = f"{q['kind']}|{q['resource']}|{q['unit']}|{q['window']}"
            if q["window"].startswith("seconds:"):
                wm = journal.quota_watermarks.get(qkey, 0)
                if decision_now < wm:
                    return VerifierResult("REFUSE", "QUOTA_CLOCK_REGRESSION")
                watermark_updates[qkey] = decision_now
                sec_s = int(q["window"].split(":", 1)[1])
                own_bucket = f"sec:{(decision_now // sec_s) * sec_s}"
                row_bucket = own_bucket
            elif q["window"].startswith("blocks:"):
                blk_n = int(q["window"].split(":", 1)[1])
                k_own = (chain.tip_height - leaf_gp["not_before_height"]) // blk_n
                own_bucket = f"blk:{leaf_gp['not_before_height'] + k_own * blk_n}"
                # R3 B2: Parent row account blocks:N buckets anchor strictly at parent.not_before_height!
                k_row = (chain.tip_height - root_gp["not_before_height"]) // blk_n
                row_bucket = f"blk:{root_gp['not_before_height'] + k_row * blk_n}"
            else:
                own_bucket = "term"
                row_bucket = "term"

            reserve_amt, _ = compute_quota_debit(action, inv_p["arguments"], q)
            account_targets: list[tuple[str, str, int | None, int, str]] = [
                ("own", leaf_gid, None, int(q["max"]), own_bucket)
            ]
            if len(ppath) == 2:
                pk_t = (q["kind"], q["resource"], q["unit"], q["window"])
                row_max = parent_row_caps.get(pk_t, int(q["max"]))
                account_targets.append(("row", root_gid, int(leaf_gp["parent"]["ordinal"]), row_max, row_bucket))

            for acct, gid_acct, row_ord, ceiling, bucket_id in account_targets:
                scope = f"row:{gid_acct}:{row_ord}" if acct == "row" else f"{acct}:{gid_acct}"
                bkey = (scope, qkey, bucket_id)
                used = journal.quotas_used.get(bkey, 0) + planned_usage_delta.get(bkey, 0)
                if ceiling == 0 or used + reserve_amt > ceiling:
                    return VerifierResult("REFUSE", "QUOTA_EXCEEDED")
                planned_usage_delta[bkey] = planned_usage_delta.get(bkey, 0) + reserve_amt
                pending_ops.append({
                    "account": acct,
                    "grant_id": gid_acct,
                    "row_ordinal": row_ord,
                    "quota": q,
                    "bucket_id": bucket_id,
                    "reserve": reserve_amt,
                })

        j_err2 = journal.check_continuity()
        if j_err2:
            return VerifierResult("REFUSE", j_err2)

        # Commit ONE single atomic `reservation` entry binding invocation_id, nonce, and ALL reservations[] (empty [] if quota-free)!
        res_lines: list[dict[str, Any]] = []
        for op_rec in pending_ops:
            q = op_rec["quota"]
            ln: dict[str, Any] = {
                "account": op_rec["account"],
                "amount": str(op_rec["reserve"]),
                "bucket_id": op_rec["bucket_id"],
                "grant_id": op_rec["grant_id"],
                "quota_kind": q["kind"],
                "resource": q["resource"],
                "unit": q["unit"],
                "window": q["window"],
            }
            if op_rec["row_ordinal"] is not None:
                ln["row_ordinal"] = op_rec["row_ordinal"]
            res_lines.append(ln)

        res_body: dict[str, Any] = {
            "action": action,
            "expires_at": inv_p["exp"],
            "grant_id": leaf_gid,
            "invocation_id": inv_id,
            "nonce": inv_p["nonce"],
            "recorded_at": decision_now,
            "reservations": res_lines,
        }
        if leaf_gp["revocation"].get("kind") == "single_use":
            res_body["single_use"] = True
            res_body["use_txid"] = resolved_use_txid
        jw_res, j_aerr = _append_journal_checked(journal, "reservation", res_body)
        if j_aerr is not None:
            return VerifierResult("REFUSE", j_aerr)
        assert jw_res is not None
        for wk, wv in watermark_updates.items():
            journal.quota_watermarks[wk] = max(journal.quota_watermarks.get(wk, 0), wv)
        journal_writes.append(jw_res)

        frame_details.update({
            "action": action,
            "grant_id": leaf_gid,
            "invocation_id": inv_id,
            "recorded_at": decision_now,
            "reserved_ops": pending_ops,
            "single_use": (leaf_gp["revocation"].get("kind") == "single_use"),
            "tip_height": chain.tip_height,
            "use_txid": resolved_use_txid,
        })
        return VerifierResult("ADMIT", None, outcome="reserved", journal_writes=journal_writes, details=frame_details)

    @staticmethod
    def _match_capability_where(
        action: str,
        cap: dict[str, Any],
        arguments: dict[str, Any],
        actual_message_meta: dict[str, Any] | None = None,
    ) -> bool:
        """Evaluate all 7-predicate `where` constraints + mandatory server-side mail/read metadata checks (H-9, H-15)."""
        for arg_k, pred in cap.get("where", {}).items():
            if action == "mail/read" and arg_k in ("sender_domain", "max_bytes", "folder"):
                if arg_k == "folder":
                    if arg_k not in arguments or not sl.match_predicate(pred, arguments[arg_k]):
                        return False
                meta_key = (
                    "size_bytes"
                    if (arg_k == "max_bytes" and actual_message_meta is not None and "size_bytes" in actual_message_meta)
                    else arg_k
                )
                if actual_message_meta is None or meta_key not in actual_message_meta:
                    return False
                if not sl.match_predicate(pred, actual_message_meta[meta_key]):
                    return False
                continue
            if arg_k not in arguments:
                return False
            if not sl.match_predicate(pred, arguments[arg_k]):
                return False
            if actual_message_meta is not None and arg_k in actual_message_meta:
                if not sl.match_predicate(pred, actual_message_meta[arg_k]):
                    return False
        return True

    def _verify_backing_grant_chain(
        self,
        *,
        ppath: list[dict[str, Any]],
        grants_by_id: dict[str, dict[str, Any]],
        bundle: dict[str, Any],
        chain: ChainView,
        journal: FencedJournal,
        executor_cfg: dict[str, Any],
        local_action_profiles: dict[str, dict[str, Any]],
        act_meta: dict[str, Any] | None,
        inv_action: str | None,
        inv_arguments: dict[str, Any] | None,
        inv_caddr: str | None,
        use_txid: str | None,
        for_session_open: bool = False,
    ) -> tuple[bool, VerifierResult | None, dict[str, Any]]:
        """Shared SPEC-06 §4 Steps 6–10d backing-grant chain verification (used by BOTH admit_and_reserve & verify_session_open, G7-03)."""
        root_gid = ppath[0]["grant_id"]
        leaf_gid = ppath[-1]["grant_id"]
        root_grant = grants_by_id[root_gid]
        leaf_grant = grants_by_id[leaf_gid]
        root_gp = root_grant["payload"]
        leaf_gp = leaf_grant["payload"]
        rcpt_spec = leaf_gp["recipient"]

        # Step 6: Durable closure check across grant, row, role, seal, & contract (H-4, G7-06)
        for pe in ppath:
            gid = pe["grant_id"]
            cl = journal.lookup_closure({"subject_id": gid, "subject_kind": "grant"}, legacy_key=gid)
            if cl is not None:
                if cl.get("cause") == "SINGLE_USE_CONSUMED":
                    return False, VerifierResult("REFUSE", "INVOKE_REPLAY"), {}
                return False, VerifierResult("REFUSE", "GRANT_CLOSED"), {}
        if len(ppath) == 2 and "parent" in leaf_gp:
            ord_i = leaf_gp["parent"]["ordinal"]
            rcl = journal.lookup_closure(
                {"grant_id": root_gid, "ordinal": ord_i, "subject_kind": "row"},
                legacy_key=f"{root_gid}:{ord_i}",
            )
            if rcl is not None and rcl.get("cause") == "GRANT_ROW_STOPPED":
                return False, VerifierResult("REFUSE", "GRANT_ROW_STOPPED"), {}
        iss_pin = root_gp["issuer"]
        iss_name = iss_pin["name"]
        root_recent_h = chain.raw.get("blocks", {}).get(root_gp["recent_block"])
        presented_rpol = iss_pin.get("role_policy") or (
            root_grant.get("signatures", {}).get("policy")
            if isinstance(root_grant.get("signatures"), dict)
            else None
        )
        if isinstance(presented_rpol, dict):
            role_subj_6c = {
                "name": iss_name,
                "policy_sha256": _policy_sha256(presented_rpol),
                "registration": iss_pin["registration"],
                "role": "grant",
                "subject_kind": "role",
            }
            role_cl_comp = journal.lookup_closure(role_subj_6c, cause="CRED_ISSUER_CLOSED")
            if role_cl_comp is not None:
                ex_hc = role_cl_comp.get("subject", {}).get("cutoff_height")
                if ex_hc is None or chain.tip_height >= int(ex_hc):
                    return False, VerifierResult("REFUSE", "CRED_ISSUER_CLOSED"), {}
            role_cl_rot = journal.lookup_closure(role_subj_6c, cause="NAME_ROLE_CHANGED")
            if role_cl_rot is not None:
                ex_rbh = role_cl_rot.get("subject", {}).get("retired_before_height")
                if ex_rbh is None or (root_recent_h is not None and root_recent_h < int(ex_rbh)):
                    return False, VerifierResult("REFUSE", "NAME_ROLE_CHANGED"), {}
        if "contract_id" in leaf_gp:
            c_cl = journal.lookup_closure(
                {"subject_id": leaf_gp["contract_id"], "subject_kind": "contract"},
                legacy_key=leaf_gp["contract_id"],
            )
            if c_cl is not None:
                return False, VerifierResult("REFUSE", c_cl["cause"]), {}
        for g in (root_grant, leaf_grant):
            rev = g["payload"]["revocation"]
            if rev["mode"] == "seal":
                s_op = {"txid": rev["seal"]["txid"], "vout": rev["seal"]["vout"]}
                scl = journal.lookup_closure(
                    {"outpoint": s_op, "subject_kind": "seal"},
                    legacy_key=_outpoint_key(s_op),
                )
                if scl is not None:
                    return False, VerifierResult("REFUSE", "SEAL_SPENT"), {}

        # Step 7: Issuer identity, permanent origin/ward detection (history + 0x0c registered_bindings + presented bundle, B-12), & guardianship
        nrec, nerr = self.resolve_name(
            iss_pin["name"],
            chain,
            expected_owner_policy=iss_pin["owner_policy"],
            expected_registration=iss_pin["registration"],
            allow_unresolved_voluntary_rebind=True,
        )
        if nerr:
            return False, VerifierResult("REFUSE", nerr), {}
        assert nrec is not None

        root_recent_h = chain.raw.get("blocks", {}).get(root_gp["recent_block"])
        origin_bundle = bundle.get("origin_bundle")
        origin_bundles_by_oid = bundle.get("origin_bundles_by_oid")
        ward_details: dict[str, Any] = {}
        hist_oid = nrec.get("_historical_origin_id")
        if not hist_oid:
            reg_bound = chain.raw.get("registered_bindings", {}).get(_outpoint_key(iss_pin["registration"]))
            if isinstance(reg_bound, str):
                hist_oid = reg_bound
        if not hist_oid and isinstance(origin_bundle, dict):
            ob_nb = origin_bundle.get("name_binding")
            ob_op = origin_bundle.get("origin", {}).get("payload") if isinstance(origin_bundle.get("origin"), dict) else None
            if (
                isinstance(ob_nb, dict)
                and ob_nb.get("registration") == iss_pin["registration"]
                and isinstance(ob_op, dict)
                and ob_op.get("type") == "seallink-origin/1"
            ):
                try:
                    hist_oid = sl.object_id(ob_op)
                except Exception:
                    pass
        is_origin_cert = bool(hist_oid)
        if not is_origin_cert and nrec.get("_voluntary_rebinds"):
            return False, VerifierResult("REFUSE", "ORIGIN_STATUS_INCOMPLETE"), {}
        wstate: dict[str, Any] | None = None
        if is_origin_cert:
            assert hist_oid is not None
            ob_iss = self._pick_origin_bundle_for_oid(hist_oid, origin_bundle, origin_bundles_by_oid)
            wstate, oerr = self.verify_origin_and_status(ob_iss, chain, journal=journal)
            if oerr:
                return False, VerifierResult("REFUSE", oerr), {}
            assert wstate is not None
            # R2G-04 / Decision 1B: Match State-4 emancipated issuer against wstate["effective_binding"] (State 1 uses binding)!
            if not _name_pin_equal(wstate.get("effective_binding", wstate["binding"]), iss_pin):
                return False, VerifierResult("REFUSE", "ORIGIN_BINDING_INVALID"), {}
            if wstate["capacity"] == "ward":
                ok_wa, werr, ward_details = self.verify_ward_approvals(
                    root_grant, wstate, chain, journal=journal, origin_bundles_by_oid=origin_bundles_by_oid
                )
                if not ok_wa:
                    return False, VerifierResult("REFUSE", werr), {}
        if wstate is None or wstate["capacity"] != "ward":
            # M-8: Check confirmed on-chain 0x0b compromise on presented_rpol BEFORE role-rotation check so fresh & stateful verifiers
            # ALWAYS return CRED_ISSUER_CLOSED (never diverging on A -> B -> A + 0x0b between Step 6c and Step 7)!
            if isinstance(presented_rpol, dict):
                min_hc_pre = self._policy_compromised_cutoff(nrec, iss_pin, "grant", presented_rpol, chain)
                if min_hc_pre is not None:
                    journal.record_closure(
                        {
                            "cutoff_height": min_hc_pre,
                            "name": iss_name,
                            "policy_sha256": _policy_sha256(presented_rpol),
                            "registration": iss_pin["registration"],
                            "role": "grant",
                            "subject_kind": "role",
                        },
                        "CRED_ISSUER_CLOSED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                    )
                    return False, VerifierResult("REFUSE", "CRED_ISSUER_CLOSED"), {}
            rpol, rerr = self.resolve_role_policy(nrec, "grant", iss_pin.get("role_policy"), recent_block_height=root_recent_h)
            if rerr:
                if rerr == "NAME_ROLE_CHANGED":
                    # H-4 / D9-B1: Authenticate root_grant against the historical link.grant policy active at root_recent_h
                    # BEFORE writing a cause- & epoch-scoped role closure! Forged/unauthenticated grants write ZERO closures!
                    hist_pol = self._resolve_historical_role_policy(nrec, "grant", iss_pin.get("role_policy"), at_height=root_recent_h)
                    if hist_pol is not None and sl.verify_signature_set(
                        sl.signing_digest(root_gp),
                        root_grant.get("signatures", {}),
                        expected_policy=hist_pol,
                        obj_type="seallink-grant/1",
                    )[0]:
                        rbh = self._first_role_change_height(nrec, "grant", root_recent_h, chain)
                        rot_subj: dict[str, Any] = {
                            "name": iss_name,
                            "policy_sha256": _policy_sha256(hist_pol),
                            "registration": iss_pin["registration"],
                            "role": "grant",
                            "subject_kind": "role",
                        }
                        if rbh is not None:
                            rot_subj["retired_before_height"] = rbh
                        journal.record_closure(
                            rot_subj,
                            "NAME_ROLE_CHANGED",
                            observed_at=chain.now,
                            observed_height=chain.tip_height,
                        )
                        return False, VerifierResult("REFUSE", "NAME_ROLE_CHANGED"), {}
                    if hist_pol is None and nrec.get("_value_obj", {}).get("link", {}).get("grant") is None:
                        return False, VerifierResult("REFUSE", "NAME_ROLE_CHANGED"), {}
                    return False, VerifierResult("REFUSE", "WIRE_SIGNATURE"), {}
                return False, VerifierResult("REFUSE", rerr), {}
            assert rpol is not None
            ok_rs, rscode = sl.verify_signature_set(
                sl.signing_digest(root_gp), root_grant.get("signatures", {}), expected_policy=rpol, obj_type="seallink-grant/1"
            )
            if not ok_rs:
                return False, VerifierResult("REFUSE", rscode), {}

        # Step 8: Contract and framework checks (R1 #1, R1-C, R2-01/02/04, R3 B5, H-4, H-5, H-18, D-5/R2-15)
        resolved_contract_cfg: str | None = None
        if act_meta is not None and act_meta.get("requires_contract", False) and "contract_id" not in leaf_gp:
            return False, VerifierResult("REFUSE", "GRANT_CONTRACT_REQUIRED"), {}
        if "contract_id" in leaf_gp:
            c_obj = bundle.get("contract")
            if c_obj is None:
                return False, VerifierResult("REFUSE", "CONTRACT_NOT_PRESENTED"), {}
            ok_co, co_res = self._verify_object_wire(c_obj, expected_type="seallink-contract/1")
            if not ok_co:
                return False, VerifierResult("REFUSE", co_res), {}
            c_obj = co_res
            if c_obj["network"] != self.pinned_network or c_obj["genesis"] != self.pinned_genesis:
                return False, VerifierResult("REFUSE", "CHAIN_MISMATCH"), {}
            if sl.object_id(c_obj) != leaf_gp["contract_id"]:
                return False, VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH"), {}
            if "framework_id" in c_obj:
                fw_cl = journal.lookup_closure(
                    {"subject_id": c_obj["framework_id"], "subject_kind": "contract"},
                    legacy_key=c_obj["framework_id"],
                )
                if fw_cl is not None:
                    return False, VerifierResult("REFUSE", fw_cl["cause"]), {}
                fw_obj = bundle.get("framework_contract")
                if fw_obj is None:
                    return False, VerifierResult("REFUSE", "CONTRACT_NOT_PRESENTED"), {}
                ok_fw, fw_res = self._verify_object_wire(fw_obj, expected_type="seallink-contract/1")
                if not ok_fw:
                    return False, VerifierResult("REFUSE", fw_res), {}
                fw_obj = fw_res
                if fw_obj["network"] != self.pinned_network or fw_obj["genesis"] != self.pinned_genesis:
                    return False, VerifierResult("REFUSE", "CHAIN_MISMATCH"), {}
                if sl.object_id(fw_obj) != c_obj["framework_id"]:
                    return False, VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH"), {}
                if "framework_id" in fw_obj:
                    return False, VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH"), {}
                if "seal" not in fw_obj:
                    return False, VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING"), {}
                _, fw_serr, _ = self.evaluate_seal(
                    fw_obj["seal"], chain, required_depth=1, journal=journal, subject_id=c_obj["framework_id"], subject_kind="contract"
                )
                if fw_serr:
                    return False, VerifierResult("REFUSE", fw_serr), {}
                # H-18: Enforce contract window nests inside framework window AND framework not_after_unix!
                fww = fw_obj["window"]
                cw_chk = c_obj["window"]
                if cw_chk["not_before_height"] < fww["not_before_height"] or (
                    "not_after_height" in fww
                    and ("not_after_height" not in cw_chk or cw_chk["not_after_height"] > fww["not_after_height"])
                ):
                    return False, VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH"), {}
                if "not_after_unix" in fww and chain.now >= fww["not_after_unix"]:
                    return False, VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED"), {}

            # R2-02 / H-5 / R1 #1: Resolve confirmed 0x07 anchor timestamp (or confirmed 0x01 grant anchor fallback);
            # NEVER silently fall back to wall-clock when contract_anchor_txid is supplied without block_time!
            c_anchor_time: int | None = None
            c_anchor_height: int | None = None
            c_atxid = bundle.get("contract_anchor_txid")
            if c_atxid:
                c_atx = chain.get_tx(c_atxid)
                if (
                    self._decode_opreturn_tx(c_atx, expected_action="0x07", expected_commitment=leaf_gp["contract_id"]) is None
                    or c_atx is None
                    or "block_time" not in c_atx
                    or c_atx["block_time"] is None
                ):
                    return False, VerifierResult("REFUSE", "CHAIN_FRAME_INVALID"), {}
                c_anchor_height = c_atx["confirmed_height"]
                c_anchor_time = int(c_atx["block_time"])
            else:
                g_itxid = ppath[-1].get("issuance_txid") or ppath[0].get("issuance_txid")
                g_itx = chain.get_tx(g_itxid) if g_itxid else None
                if g_itx is not None and g_itx.get("confirmed_height") is not None and g_itx.get("block_time") is not None:
                    c_anchor_height = g_itx["confirmed_height"]
                    c_anchor_time = int(g_itx["block_time"])
            ca_res = self.verify_contract_assents(
                c_obj,
                bundle.get("contract_assents", []),
                origin_bundle,
                chain,
                origin_bundles_by_oid=origin_bundles_by_oid,
                anchor_time=c_anchor_time,
                anchor_height=c_anchor_height,
                journal=journal,
            )
            if ca_res.verdict != "ADMIT":
                return False, VerifierResult("REFUSE", ca_res.refusal_code), {}
            if "seal" not in c_obj:
                return False, VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING"), {}
            _, c_serr, _ = self.evaluate_seal(
                c_obj["seal"], chain, required_depth=1, journal=journal, subject_id=leaf_gp["contract_id"], subject_kind="contract"
            )
            if c_serr:
                return False, VerifierResult("REFUSE", c_serr), {}
            cw = c_obj["window"]
            if leaf_gp["not_before_height"] < cw["not_before_height"] or (
                "not_after_height" in cw and leaf_gp["not_after_height"] > cw["not_after_height"]
            ):
                return False, VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH"), {}
            if "not_after_unix" in cw and chain.now >= cw["not_after_unix"]:
                return False, VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED"), {}
            # D-5 / R2-15: Bind root grant issuer AND leaf grant recipient to distinct contract party identities!
            parties = c_obj.get("parties", [])
            iss_oid_match = wstate["origin_id"] if wstate is not None else None
            issuer_pts = [pt for pt in parties if self._party_matches_actor(pt, iss_pin, is_recipient=False, actor_origin_id=iss_oid_match)]
            rcpt_pts = [pt for pt in parties if self._party_matches_actor(pt, rcpt_spec, is_recipient=True)]
            if not issuer_pts or not rcpt_pts or not any(
                ipt["party_id"] != rpt["party_id"] and self._party_identity_key(ipt) != self._party_identity_key(rpt)
                for ipt in issuer_pts
                for rpt in rcpt_pts
            ):
                return False, VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH"), {}
            # R3 B5 / R2-01: Closed MachineClauseTerms validation, mechanical narrowing, & config_sha256!
            disclosed = bundle.get("disclosed_clauses", {})
            declared_machine_caps: list[dict[str, Any]] = []
            clause_cfg_hashes: set[str] = set()
            terms_ok = True
            for idx in c_obj.get("machine_clause_indices", []):
                d = (disclosed.get(str(idx)) or disclosed.get(idx)) if isinstance(disclosed, dict) else None
                if not isinstance(d, dict) or "salt_hex" not in d or "clause" not in d:
                    terms_ok = False
                    break
                try:
                    ok_cm = sl.clause_commit(d["salt_hex"], d["clause"]) == c_obj["clause_commitments"][idx]
                except (ValueError, TypeError, IndexError):
                    ok_cm = False
                cl_err = (
                    validate_against_schema("schemas/contract.schema.json#/$defs/ClauseObject", d["clause"], require_jsonschema=self.require_jsonschema)
                    if (ok_cm and self.enforce_schemas)
                    else None
                )
                mterms = d["clause"].get("machine_terms") if (ok_cm and cl_err is None) else None
                if (
                    not isinstance(mterms, dict)
                    or ("not_before_height" in mterms and leaf_gp["not_before_height"] < mterms["not_before_height"])
                    or ("not_after_height" in mterms and leaf_gp["not_after_height"] > mterms["not_after_height"])
                ):
                    terms_ok = False
                    break
                if "capabilities" in mterms:
                    declared_machine_caps.extend(mterms["capabilities"])
                if "config_sha256" in mterms:
                    clause_cfg_hashes.add(mterms["config_sha256"])
            if not terms_ok or (
                declared_machine_caps and any(not any(self._capability_narrows(gcap, mcap) for mcap in declared_machine_caps) for gcap in leaf_gp["capabilities"])
            ):
                return False, VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH"), {}
            rt_cfg = executor_cfg.get("runtime_config_sha256")
            arg_cfg = inv_arguments.get("config_sha256") if isinstance(inv_arguments, dict) else None
            req_cfg = c_obj.get("config_sha256")
            cfg_ok = True
            if clause_cfg_hashes:
                cl_cfg = next(iter(clause_cfg_hashes))
                if len(clause_cfg_hashes) != 1 or (req_cfg is not None and req_cfg != cl_cfg):
                    cfg_ok = False
                req_cfg = cl_cfg
            if req_cfg is not None:
                if (rt_cfg is not None and rt_cfg != req_cfg) or (arg_cfg is not None and arg_cfg != req_cfg):
                    cfg_ok = False
            elif inv_action == "agent/session" and isinstance(inv_arguments, dict) and inv_arguments.get("op") == "start":
                cfg_ok = False
            if not cfg_ok:
                return False, VerifierResult("REFUSE", "CONTRACT_CONFIG_MISMATCH"), {}
            resolved_contract_cfg = req_cfg

        # Step 9: Depth-2 Re-delegation checks (R8.5, R8.6, row-coin spend, fail-closed stop coin M-3, notary B-4, recipient_rule B-6, narrowing)
        matched_parent_template: dict[str, Any] | None = None
        if len(ppath) == 2:
            if "delegate" not in root_gp or "parent" not in leaf_gp or "delegate" in leaf_gp:
                return False, VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE"), {}
            if leaf_gp["parent"]["grant_id"] != root_gid:
                return False, VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE"), {}
            del_spec = root_gp["delegate"]
            ok_r85, _ = sl.check_whole_parent_budget_r85(del_spec, parent_capabilities=root_gp["capabilities"])
            if not ok_r85:
                return False, VerifierResult("REFUSE", "GRANT_CHILD_WIDER"), {}
            if not sl.check_disjoint_ranges_r86(root_gp):
                return False, VerifierResult("REFUSE", "GRANT_ROW_INVALID"), {}
            ordinal = leaf_gp["parent"]["ordinal"]
            cur_ord = 0
            matched_group = None
            row_outpoint = None
            row_script_policy = None
            stop_outpoint = None
            for gspec in del_spec["groups"]:
                for rng in gspec["ranges"]:
                    if cur_ord + 1 <= ordinal <= cur_ord + rng["count"]:
                        offset = ordinal - cur_ord - 1
                        matched_group = gspec
                        row_outpoint = {"txid": rng["txid"], "vout": rng["first"] + offset}
                        row_script_policy = rng["script_policy"]
                        if "stop_txid" in rng:
                            stop_outpoint = {
                                "txid": rng["stop_txid"],
                                "vout": rng["stop_first"] + offset,
                                "script_policy": rng["stop_script_policy"],
                            }
                        break
                    cur_ord += rng["count"]
                if matched_group is not None:
                    break
            if matched_group is None or row_outpoint is None:
                return False, VerifierResult("REFUSE", "GRANT_ROW_INVALID"), {}
            # H-8 / F-11b: Fail-closed verification that row coin creation tx & output exist, pre-confirmed <= parent.recent_block, and match script_policy!
            row_cre_tx = chain.get_tx(row_outpoint["txid"])
            r_out_obj = chain.get_output(row_outpoint["txid"], row_outpoint["vout"])
            exp_rspk = sl.compile_script_policy(row_script_policy)[0] if row_script_policy is not None else None
            row_valid = (
                row_cre_tx is not None
                and row_cre_tx.get("confirmed_height") is not None
                and (root_recent_h is None or row_cre_tx["confirmed_height"] <= root_recent_h)
                and r_out_obj is not None
                and (exp_rspk is None or r_out_obj.get("script_pubkey_hex") == exp_rspk.hex())
            )
            # Derive row-coin spend directly from child issuance tx inputs[]!
            c_itxid = ppath[1].get("issuance_txid")
            c_itx = chain.get_tx(c_itxid) if c_itxid else None
            spent_set = {f"{i['prev_txid']}:{i['prev_vout']}" for i in (c_itx.get("inputs", []) if c_itx else [])}
            if not row_valid or not c_itx or _outpoint_key(row_outpoint) not in spent_set:
                return False, VerifierResult("REFUSE", "GRANT_ROW_INVALID"), {}
            # M-3: Fail closed on declared stop_outpoint when UTXO is missing, unconfirmed, or script-mismatched!
            if stop_outpoint is not None:
                exp_stop_spk, _ = sl.compile_script_policy(stop_outpoint["script_policy"])
                s_tx = chain.get_tx(stop_outpoint["txid"])
                sout = chain.get_output(stop_outpoint["txid"], stop_outpoint["vout"])
                if not s_tx or s_tx.get("confirmed_height") is None or not sout or sout.get("script_pubkey_hex") != exp_stop_spk.hex():
                    return False, VerifierResult("REFUSE", "SEAL_UNAVAILABLE"), {}
                if sout.get("spent_by_txid") or sout.get("absent_from_utxo"):
                    journal.record_closure(
                        {"grant_id": root_gid, "ordinal": ordinal, "subject_kind": "row"},
                        "GRANT_ROW_STOPPED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                        spend_txid=sout.get("spent_by_txid", "0" * 64),
                    )
                    return False, VerifierResult("REFUSE", "GRANT_ROW_STOPPED"), {}
            tpl = matched_group["template"]
            matched_parent_template = tpl
            # B-4: Full cryptographic + chain verification of seallink-notary/1 when notary_mode == "required_act"!
            if tpl["notary_mode"] == "required_act":
                n_res = self.verify_notary_act(
                    bundle.get("notary_act"),
                    bundle.get("notary_anchor_txid"),
                    chain,
                    journal=journal,
                    allowed_notaries=del_spec.get("notaries"),
                    expected_notary_name=tpl.get("notary_name"),
                    expected_child_binding={"parent_grant_id": root_gid, "child_grant_id": leaf_gid, "ordinal": ordinal},
                )
                if n_res.verdict != "ADMIT":
                    return False, VerifierResult("REFUSE", n_res.refusal_code if n_res.refusal_code in ("CRED_ISSUER_CLOSED", "CRED_REVOKED_FOR_CAUSE", "SEAL_SPENT", "SEAL_UNAVAILABLE") else "NOTARY_REQUIRED"), {}
            ok_cs, cscode = sl.verify_signature_set(
                sl.signing_digest(leaf_gp),
                leaf_grant.get("signatures", {}),
                expected_policy={"m": 1, "pks": [del_spec["key"]]},
                obj_type="seallink-grant/1",
            )
            if not ok_cs:
                return False, VerifierResult("REFUSE", cscode), {}
            if (
                leaf_gp["genesis"] != root_gp["genesis"]
                or leaf_gp.get("contract_id") != root_gp.get("contract_id")
                or leaf_gp.get("executor") != tpl["executor"]
                or leaf_gp["not_before_height"] < root_gp["not_before_height"]
                or leaf_gp["not_after_height"] > root_gp["not_after_height"]
            ):
                return False, VerifierResult("REFUSE", "GRANT_CHILD_WIDER"), {}
            # B-6: Enforce template.recipient_rule (exact_key, exact_name with registration, member_class) + child_seal_key + capabilities!
            rrule = tpl["recipient_rule"]
            rmode_rule = rrule["mode"]
            rcpt_ok = False
            if rmode_rule == "exact_key":
                rcpt_ok = rcpt_spec.get("mode") == "key" and rcpt_spec.get("key") == rrule["key"]
            elif rmode_rule == "exact_name":
                rcpt_ok = rcpt_spec.get("mode") == "name" and _name_pin_equal(rcpt_spec, rrule)
            elif rmode_rule == "member_class" and rcpt_spec.get("mode") == "name":
                manifests_b = bundle.get("manifests", {})
                mlists_b = bundle.get("members_lists", {})
                for op_pin in rrule.get("operators", []):
                    op_nrec, op_err = self.resolve_name(
                        op_pin["name"],
                        chain,
                        expected_owner_policy=op_pin["owner_policy"],
                        expected_registration=op_pin["registration"],
                        allow_unresolved_voluntary_rebind=(origin_bundle is not None or bool(origin_bundles_by_oid)),
                    )
                    if op_err or op_nrec is None:
                        continue
                    if op_nrec.get("_voluntary_rebinds") and self._verify_rebound_pin(
                        op_nrec, op_pin, origin_bundle, chain, journal, origin_bundles_by_oid=origin_bundles_by_oid
                    ) is not None:
                        continue
                    op_man, op_merr = self.resolve_manifest(op_pin["name"], op_nrec, manifests_b, chain, journal)
                    if op_merr or op_man is None:
                        continue
                    mset_pin = op_man.get("sets", {}).get("members")
                    if not mset_pin:
                        continue
                    mlist = mlists_b.get(mset_pin["sha256"]) or mlists_b.get(op_pin["name"])
                    if mlist is None:
                        continue
                    ok_ml, ml_res = self._verify_object_wire(mlist, expected_type="seallink-members-list/1")
                    if not ok_ml or sl.content_addr(ml_res) != mset_pin["sha256"] or ml_res.get("seq") != mset_pin["seq"]:
                        continue
                    for ment in ml_res.get("entries", []):
                        if _name_pin_equal(ment, rcpt_spec) and self.evaluate_seal(ment["seal"], chain, required_depth=1)[1] is None:
                            rcpt_ok = True
                            break
                    if rcpt_ok:
                        break
            c_spol = leaf_gp["revocation"]["seal"]["script_policy"]
            seal_key_ok = (
                (c_spol["kind"] == "key" and c_spol["pk"] == del_spec["child_seal_key"])
                or (c_spol["kind"] == "branch" and c_spol["template"] == "single_use_1_of_2" and c_spol["keys"]["issuer"] == del_spec["child_seal_key"])
            )
            caps_ok = all(any(self._capability_narrows(ccap, pcap) for pcap in tpl["capabilities"]) for ccap in leaf_gp["capabilities"])
            if not (rcpt_ok and seal_key_ok and caps_ok):
                return False, VerifierResult("REFUSE", "GRANT_CHILD_WIDER"), {}

        # Step 10: Grant window, SL-GRNT-004 issuer expiry bound, revocation/single-use seal, linkage on BOTH root & child (R3 Blocker #1, H-6)
        journal_writes: list[dict[str, Any]] = []
        resolved_use_txid: str | None = use_txid
        for idx_pe, pe in enumerate(ppath):
            g = grants_by_id[pe["grant_id"]]
            gp = g["payload"]
            gid = pe["grant_id"]
            if not (gp["not_before_height"] <= chain.tip_height < gp["not_after_height"]):
                return False, VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED"), {}
            rev = gp["revocation"]
            if for_session_open and (rev["mode"] != "seal" or rev["kind"] != "revocable"):
                return False, VerifierResult("REFUSE", "SESSION_INVALID"), {}
            if rev["mode"] == "window_only":
                if not self.allow_window_only or (act_meta is not None and act_meta.get("require_seal", True)):
                    return False, VerifierResult("REFUSE", "GRANT_SEAL_REQUIRED"), {}
            else:
                itxid = pe.get("issuance_txid")
                itx = chain.get_tx(itxid) if itxid else None
                dec_i = self._decode_opreturn_tx(itx, require_confirmed=False)
                if dec_i is None:
                    return False, VerifierResult("REFUSE", "CHAIN_FRAME_INVALID"), {}
                assert itx is not None
                iss_prep: dict[str, Any] = {
                    "genesis": gp["genesis"],
                    "grant_content_addr": sl.content_addr(g),
                    "grant_id": gid,
                    "type": "seallink-issuance/1",
                }
                if "contract_id" in gp:
                    iss_prep["contract_id"] = gp["contract_id"]
                expected_iss_digest = sl.signing_digest(iss_prep).hex()
                if dec_i["action"] == "0x01":
                    if dec_i["commitment"] != expected_iss_digest:
                        return False, VerifierResult("REFUSE", "CHAIN_FRAME_INVALID"), {}
                elif dec_i["action"] == "0x02":
                    # R3 B1 / Decision A1: 0x02 Merkle batch anchor is FORBIDDEN for depth-2 child grants!
                    if idx_pe == 1 or "parent" in gp:
                        return False, VerifierResult("REFUSE", "CHAIN_FRAME_INVALID"), {}
                    bp = pe.get("batch_proof")
                    if not bp or bp.get("leaf_digest") != expected_iss_digest or bp.get("root") != dec_i["commitment"] or not sl.verify_merkle_proof(bp):
                        return False, VerifierResult("REFUSE", "CHAIN_FRAME_INVALID"), {}
                else:
                    return False, VerifierResult("REFUSE", "CHAIN_FRAME_INVALID"), {}
                r_height = chain.raw.get("blocks", {}).get(gp["recent_block"])
                a_height = itx.get("confirmed_height")
                if r_height is None:
                    return False, VerifierResult("REFUSE", "CHAIN_RECENCY_INVALID"), {}
                if a_height is not None:
                    k_lim = self.recency_k
                    if not (r_height < a_height <= r_height + k_lim):
                        return False, VerifierResult("REFUSE", "CHAIN_RECENCY_INVALID"), {}
                    # H-6: Non-linkage funding inputs present in chain MUST be confirmed strictly before a_height (linkage T & A may confirm in the same block, SPEC-02 §5.1)
                    seal_obj_h6 = rev["seal"]
                    linkage_op_h6 = (seal_obj_h6["txid"], seal_obj_h6["vout"] + 1)
                    for inp_i in itx.get("inputs", []):
                        if isinstance(inp_i, dict) and "prev_txid" in inp_i:
                            ptx_i = chain.get_tx(inp_i["prev_txid"])
                            if ptx_i is not None:
                                ph_i = ptx_i.get("confirmed_height")
                                is_linkage = (inp_i["prev_txid"], inp_i.get("prev_vout")) == linkage_op_h6
                                if (is_linkage and ph_i is not None and ph_i > a_height) or (not is_linkage and (ph_i is None or ph_i >= a_height)):
                                    return False, VerifierResult("REFUSE", "CHAIN_TX_CONSTRUCTION"), {}
                    # SL-GRNT-004: Root sealed grant not_after_height MUST NOT exceed issuer_name_expiry_at_issuance (B-9)
                    if idx_pe == 0:
                        iss_upd_at_a = [
                            u["confirmed_height"]
                            for u in nrec.get("updates", [])
                            if u.get("confirmed_height") is not None and u["confirmed_height"] <= a_height
                        ]
                        if iss_upd_at_a:
                            iss_exp_at_iss = max(iss_upd_at_a) + chain.name_expiry_blocks
                            if gp["not_after_height"] > iss_exp_at_iss:
                                return False, VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED"), {}
                # Witness Profile W on anchor tx `itx`, seal-creation tx T, & exact linkage `(seal_txid, seal_vout + 1)` on BOTH root & child (R3 Blocker #1, H-6)
                seal_obj = rev["seal"]
                seal_tx = chain.get_tx(seal_obj["txid"])
                itx_in_ops = {(i["prev_txid"], i["prev_vout"]) for i in itx.get("inputs", []) if isinstance(i, dict)}
                if (
                    rev["construction"] != "W"
                    or not self._tx_satisfies_witness_w(itx)
                    or (seal_tx is not None and seal_tx.get("inputs") and not self._tx_satisfies_witness_w(seal_tx))
                    or (seal_obj["txid"], seal_obj["vout"]) in itx_in_ops
                    or (seal_obj["txid"], seal_obj["vout"] + 1) not in itx_in_ops
                ):
                    return False, VerifierResult("REFUSE", "CHAIN_TX_CONSTRUCTION"), {}
                req_depth = max(gp.get("min_depth", 1), self.operator_min_depth)
                if a_height is None or (chain.tip_height - a_height + 1) < req_depth:
                    return False, VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT"), {}
                if rev["kind"] == "revocable":
                    _, serr, jw = self.evaluate_seal(
                        seal_obj, chain, required_depth=req_depth, journal=journal, subject_id=gid, subject_kind="grant"
                    )
                    if jw:
                        journal_writes.append(jw)
                    if serr:
                        return False, VerifierResult("REFUSE", serr, journal_writes=journal_writes), {}
                else:
                    assert inv_caddr is not None
                    _, serr, jw = self.evaluate_single_use_seal(
                        seal_obj, use_txid, inv_caddr, req_depth, chain, journal=journal, grant_id=gid
                    )
                    if jw:
                        journal_writes.append(jw)
                    if serr:
                        return False, VerifierResult("REFUSE", serr, journal_writes=journal_writes), {}
                    if resolved_use_txid is None:
                        s_out_su = chain.get_output(seal_obj["txid"], seal_obj["vout"])
                        if s_out_su and isinstance(s_out_su.get("spent_by_txid"), str):
                            resolved_use_txid = s_out_su["spent_by_txid"]

        # 10d. Executor binding: evaluate executor_ref strictly against leaf_gp["capabilities"] (G7-17: provider_of == iss_pin!)
        if "executor_ref" in leaf_gp:
            for cap in leaf_gp["capabilities"]:
                cmeta = ACTION_PROFILES.get(cap["action"]) or local_action_profiles.get(cap["action"]) or {"allows_executor_ref": False, "external_mutation": True}
                if cmeta.get("external_mutation", True) or not cmeta.get("allows_executor_ref", False):
                    return False, VerifierResult("REFUSE", "GRANT_EXECUTOR_REF_FORBIDDEN"), {}
            eref = leaf_gp["executor_ref"]
            if eref["provider_of"] != iss_pin["name"]:
                return False, VerifierResult("REFUSE", "GRANT_TARGET_UNAUTHORIZED"), {}
            holder_rec, herr = self.resolve_name(
                eref["provider_of"],
                chain,
                expected_owner_policy=iss_pin["owner_policy"],
                expected_registration=iss_pin["registration"],
                allow_unresolved_voluntary_rebind=True,
            )
            if herr:
                return False, VerifierResult("REFUSE", herr), {}
            assert holder_rec is not None
            holder_man, merr = self.resolve_manifest(eref["provider_of"], holder_rec, bundle.get("manifests", {}), chain, journal)
            if merr:
                return False, VerifierResult("REFUSE", merr), {}
            assert holder_man is not None
            matched_prov = None
            for pe_prov in holder_man.get("providers", []):
                if pe_prov["service_type"] == eref["service_type"] and pe_prov["label"] == eref["label"]:
                    matched_prov = pe_prov["provider"]
                    break
            if matched_prov is None:
                return False, VerifierResult("REFUSE", "SERVICE_PROVIDER_UNBOUND"), {}
            prov_ob = bundle.get("provider_origin_bundle") or origin_bundle
            prov_rec, perr = self.resolve_name(
                matched_prov["name"],
                chain,
                expected_owner_policy=matched_prov["owner_policy"],
                expected_registration=matched_prov["registration"],
                allow_unresolved_voluntary_rebind=(prov_ob is not None or bool(origin_bundles_by_oid)),
            )
            if perr:
                return False, VerifierResult("REFUSE", perr), {}
            assert prov_rec is not None
            if prov_rec.get("_voluntary_rebinds"):
                rb_err_p = self._verify_rebound_pin(
                    prov_rec, matched_prov, prov_ob, chain, journal, origin_bundles_by_oid=origin_bundles_by_oid
                )
                if rb_err_p:
                    return False, VerifierResult("REFUSE", rb_err_p), {}
            prov_man, pmerr = self.resolve_manifest(matched_prov["name"], prov_rec, bundle.get("manifests", {}), chain, journal)
            if pmerr:
                return False, VerifierResult("REFUSE", pmerr), {}
            assert prov_man is not None
            svc = prov_man.get("service", {})
            if matched_prov["name"] != executor_cfg["name"] or svc.get("receipt_key") != executor_cfg["key"]:
                return False, VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH"), {}
        else:
            if leaf_gp["executor"]["name"] != executor_cfg["name"] or leaf_gp["executor"]["key"] != executor_cfg["key"]:
                return False, VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH"), {}

        return True, None, {
            "iss_pin": iss_pin,
            "nrec": nrec,
            "root_recent_h": root_recent_h,
            "wstate": wstate,
            "ward_details": ward_details,
            "matched_parent_template": matched_parent_template,
            "journal_writes": journal_writes,
            "resolved_use_txid": resolved_use_txid,
            "contract_config_sha256": resolved_contract_cfg,
        }

    def commit_result(
        self,
        receipt_env: dict[str, Any],
        journal: FencedJournal,
        executor_cfg: dict[str, Any],
        *,
        invocation_id: str,
        grant_id: str,
        actual_quota_usage: dict[str, int] | None = None,
    ) -> VerifierResult:
        """Phase 2 of SPEC-06 §2.2 (H-7, H-8, M-2, M-4, M-5, L-10..L-12): verify signed receipt, reconcile 1-to-1 strictly against durable reservation, idempotent on identical retry, ONE atomic settlement entry (+1 witness)."""
        ok_r, r_res = self._verify_object_wire(receipt_env, expected_type="seallink-receipt/1")
        if not ok_r:
            return VerifierResult("REFUSE", r_res)
        rp = r_res["payload"]
        if rp["network"] != self.pinned_network or rp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        if rp["executor_name"] != executor_cfg.get("name"):
            return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")
        if rp["invocation_id"] != invocation_id or rp["grant_id"] != grant_id:
            return VerifierResult("REFUSE", "WIRE_MEMBER")
        ok_sig, scode = sl.verify_signature_set(
            sl.signing_digest(rp),
            r_res["signatures"],
            expected_policy={"m": 1, "pks": [executor_cfg["key"]]},
            obj_type="seallink-receipt/1",
        )
        if not ok_sig:
            return VerifierResult("REFUSE", scode)
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)

        rcpt_caddr = sl.content_addr(r_res)

        # R1 #2 / G7-07 / M-4: Strict idempotency on retry with identical receipt_sha256 (0 writes! — BOTH terminal AND uncertain!);
        # refuse conflicting receipt or missing Phase-1 reservation (INVOKE_REPLAY); allow uncertain -> executed|refused reconciliation!
        res_rec: dict[str, Any] | None = None
        if invocation_id in journal.terminal_invocations:
            if journal.terminal_invocations[invocation_id].get("receipt_sha256") == rcpt_caddr:
                journal.receipt_store[rcpt_caddr] = copy.deepcopy(r_res)
                journal.receipts[invocation_id] = copy.deepcopy(r_res)
                return VerifierResult(
                    "ADMIT",
                    None,
                    outcome=rp["outcome"],
                    cached_receipt_content_addr=rcpt_caddr,
                    journal_writes=[],
                    details={"invocation_id": invocation_id, "receipt_sha256": rcpt_caddr, "idempotent_retry": True},
                )
        elif invocation_id in journal.unsettled_reservations:
            res_rec = journal.unsettled_reservations[invocation_id]
            prev_u_sha = res_rec.get("uncertain_receipt_sha256")
            if rp["outcome"] == "uncertain" and prev_u_sha is not None:
                if prev_u_sha == rcpt_caddr:
                    journal.receipt_store[rcpt_caddr] = copy.deepcopy(r_res)
                    return VerifierResult(
                        "ADMIT",
                        None,
                        outcome="uncertain",
                        cached_receipt_content_addr=rcpt_caddr,
                        journal_writes=[],
                        details={"invocation_id": invocation_id, "receipt_sha256": rcpt_caddr, "idempotent_retry": True},
                    )
                return VerifierResult("REFUSE", "INVOKE_REPLAY")
        if res_rec is None:
            return VerifierResult("REFUSE", "INVOKE_REPLAY")
        # H-7 / L-10: Action, single_use, and use_txid are derived STRICTLY from durable Phase-1 reservation!
        is_single_use = bool(res_rec.get("single_use", False))
        eff_use_txid = res_rec.get("use_txid")
        if (
            res_rec.get("grant_id") != grant_id
            or "action" not in res_rec
            or rp["action"] != res_rec["action"]
            or (is_single_use and (not isinstance(eff_use_txid, str) or not re.fullmatch(r"[0-9a-f]{64}", eff_use_txid)))
        ):
            return VerifierResult("REFUSE", "WIRE_MEMBER")
        durable_res_lines = res_rec.get("reservations", [])

        # R1 #2 / M-2 / L-12: Reconcile strictly 1-to-1 against durable reservation in verified receipt.payload.settlements[] order
        # with GLOBAL two-pass refusal precedence: Pass 1 checks ALL QUOTA_EXCEEDED overruns across all lines, Pass 2 checks ALL WIRE_MEMBER!
        rcpt_settlements = rp.get("settlements", [])
        if len(rcpt_settlements) != len(durable_res_lines):
            return VerifierResult("REFUSE", "WIRE_MEMBER")

        res_by_key: dict[tuple[str, int | None, str, str, str, str], dict[str, Any]] = {}
        reserved_qkeys: set[str] = set()
        for ln in durable_res_lines:
            k = (ln["account"], ln.get("row_ordinal"), ln["quota_kind"], ln["resource"], ln["unit"], ln["window"])
            res_by_key[k] = ln
            reserved_qkeys.add(f"{ln['quota_kind']}|{ln['resource']}|{ln['unit']}|{ln['window']}")

        seen_keys: set[tuple[str, int | None, str, str, str, str]] = set()
        paired_lines: list[tuple[dict[str, Any], dict[str, Any], str]] = []
        for rs in rcpt_settlements:
            k = (rs["account"], rs.get("row_ordinal"), rs["kind"], rs["resource"], rs["unit"], rs["window"])
            if k not in res_by_key or k in seen_keys:
                return VerifierResult("REFUSE", "WIRE_MEMBER")
            seen_keys.add(k)
            qkey = f"{rs['kind']}|{rs['resource']}|{rs['unit']}|{rs['window']}"
            paired_lines.append((rs, res_by_key[k], qkey))

        # Pass 1 (M-2): Global QUOTA_EXCEEDED precedence across EVERY settlement line and actual_quota_usage entry!
        for rs, rln, qkey in paired_lines:
            res_amt = int(rln["amount"])
            set_amt = int(rs["settled"])
            if set_amt > res_amt:
                return VerifierResult("REFUSE", "QUOTA_EXCEEDED")
            if actual_quota_usage is not None and qkey in actual_quota_usage:
                act_val = int(actual_quota_usage[qkey])
                if act_val < 0 or act_val > res_amt:
                    return VerifierResult("REFUSE", "QUOTA_EXCEEDED")

        # Pass 2 (M-2 / L-12): Extra actual_quota_usage keys, conservation arithmetic, meter match, and own-vs-row equality!
        if actual_quota_usage is not None:
            if any(qk not in reserved_qkeys for qk in actual_quota_usage):
                return VerifierResult("REFUSE", "WIRE_MEMBER")

        settled_by_qkey: dict[str, int] = {}
        settle_lines: list[dict[str, Any]] = []
        for rs, rln, qkey in paired_lines:
            res_amt = int(rln["amount"])
            rcpt_res = int(rs["reserved"])
            set_amt = int(rs["settled"])
            rel_amt = int(rs["released"])
            if (
                rcpt_res != res_amt
                or set_amt + rel_amt != res_amt
                or set_amt < 0
                or (rp["outcome"] == "uncertain" and rel_amt != 0)
                or (actual_quota_usage is not None and qkey in actual_quota_usage and int(actual_quota_usage[qkey]) != set_amt)
                or (qkey in settled_by_qkey and settled_by_qkey[qkey] != set_amt)
            ):
                return VerifierResult("REFUSE", "WIRE_MEMBER")
            settled_by_qkey[qkey] = set_amt
            sln: dict[str, Any] = {
                "account": rln["account"],
                "bucket_id": rln["bucket_id"],
                "grant_id": rln["grant_id"],
                "quota_kind": rln["quota_kind"],
                "released": str(rel_amt),
                "resource": rln["resource"],
                "settled": str(set_amt),
                "unit": rln["unit"],
                "window": rln["window"],
            }
            if rln.get("row_ordinal") is not None:
                sln["row_ordinal"] = rln["row_ordinal"]
            settle_lines.append(sln)

        # M-5 / H-8: settlement.recorded_at is ALWAYS rp["recorded_at"] from the verified signed receipt!
        rec_ts = rp["recorded_at"]
        # Persist verified signed receipt blob FIRST before committing ONE atomic settlement entry (+1 witness)!
        journal.receipt_store[rcpt_caddr] = copy.deepcopy(r_res)
        set_body: dict[str, Any] = {
            "grant_id": grant_id,
            "invocation_id": invocation_id,
            "outcome": rp["outcome"],
            "receipt_sha256": rcpt_caddr,
            "recorded_at": rec_ts,
            "settlements": settle_lines,
        }
        # L-11: Record single_use_consumed ONCE across uncertain -> terminal reconciliation!
        if is_single_use and not res_rec.get("single_use_consumed_recorded", False):
            set_body["single_use_consumed"] = True
            set_body["use_txid"] = eff_use_txid
            set_body["closes_grant_id"] = grant_id
        jw_set, j_aerr = _append_journal_checked(journal, "settlement", set_body)
        if j_aerr is not None:
            return VerifierResult("REFUSE", j_aerr)
        assert jw_set is not None

        return VerifierResult(
            "ADMIT",
            None,
            outcome=rp["outcome"],
            cached_receipt_content_addr=rcpt_caddr,
            journal_writes=[jw_set],
            details={"invocation_id": invocation_id, "receipt_sha256": rcpt_caddr},
        )

    def verify_invocation(
        self,
        inv_env: dict[str, Any] | bytes,
        bundle: dict[str, Any],
        chain: ChainView,
        journal: FencedJournal,
        executor_cfg: dict[str, Any],
        *,
        use_txid: str | None = None,
        simulate_crash_before_settlement: bool = False,
        receipt_env_for_cache: dict[str, Any] | None = None,
        raw_message_bytes: bytes | None = None,
        actual_message_meta: dict[str, Any] | None = None,
        actual_quota_usage: dict[str, int] | None = None,
    ) -> VerifierResult:
        """Convenience wrapper executing Phase 1 (`admit_and_reserve`) and, when a verified receipt is provided, Phase 2 (`commit_result`)."""
        p1 = self.admit_and_reserve(
            inv_env,
            bundle,
            chain,
            journal,
            executor_cfg,
            use_txid=use_txid,
            raw_message_bytes=raw_message_bytes,
            actual_message_meta=actual_message_meta,
        )
        if p1.verdict != "ADMIT" or p1.details.get("cached_receipt"):
            return p1

        if simulate_crash_before_settlement:
            return VerifierResult(
                "UNCERTAIN",
                None,
                outcome="uncertain",
                journal_writes=p1.journal_writes,
                details={
                    **p1.details,
                    "crashed_in_effect_window": True,
                    "reservation_retained": True,
                    "unsettled_count": len(p1.details.get("reserved_ops", [])),
                },
            )

        if receipt_env_for_cache is not None:
            p2 = self.commit_result(
                receipt_env_for_cache,
                journal,
                executor_cfg,
                invocation_id=p1.details["invocation_id"],
                grant_id=p1.details["grant_id"],
                actual_quota_usage=actual_quota_usage,
            )
            if p2.verdict != "ADMIT":
                return p2
            return VerifierResult(
                "ADMIT",
                None,
                outcome=p2.outcome,
                cached_receipt_content_addr=p2.cached_receipt_content_addr,
                journal_writes=p1.journal_writes + p2.journal_writes,
                details={**p1.details, **p2.details},
            )

        return VerifierResult("ADMIT", None, outcome="reserved", journal_writes=p1.journal_writes, details=p1.details)

    # ------------------------------------------------------------------
    # SPEC-06 §5 Bearer Sessions, SPEC-07 §2 Migration, SPEC-07 §3 Federation (Decision 2A / 6B)
    # ------------------------------------------------------------------

    def verify_session_open(
        self,
        open_env: dict[str, Any],
        bundle: dict[str, Any],
        chain: ChainView,
        journal: FencedJournal,
        executor_cfg: dict[str, Any],
        *,
        bearer_token: str | None = None,
    ) -> VerifierResult:
        """Verify seallink-session-open/1 (`open` | `extend` | `close`) via full SPEC-06 §4 backing-grant admission (2A, G7-03, R1 §3, D8-B3, D8-M7)."""
        ok_o, o_res = self._verify_object_wire(open_env, expected_type="seallink-session-open/1")
        if not ok_o:
            return VerifierResult("REFUSE", o_res)
        sp = o_res["payload"]
        if sp["network"] != self.pinned_network or sp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=2)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)

        op = sp["op"]
        if sp["nonce"] in journal.nonces:
            return VerifierResult("REFUSE", "INVOKE_REPLAY")
        if (
            sp["iat"] > chain.now
            or sp["exp"] <= chain.now
            or (op in ("open", "extend") and sp["exp"] > chain.now + 3600)
        ):
            return VerifierResult("REFUSE", "SESSION_INVALID")
        if sp["executor"].get("name") != executor_cfg.get("name") or sp["executor"].get("key") != executor_cfg.get("key"):
            return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")

        grants_by_id: dict[str, dict[str, Any]] = {}
        for g in bundle.get("grants", []):
            ok_g, rg = self._verify_object_wire(g, expected_type="seallink-grant/1")
            if not ok_g:
                return VerifierResult("REFUSE", rg)
            if rg["payload"]["network"] != self.pinned_network or rg["payload"]["genesis"] != self.pinned_genesis:
                return VerifierResult("REFUSE", "CHAIN_MISMATCH")
            grants_by_id[sl.object_id(rg["payload"])] = rg
        ppath = sp["proof_path"]
        root_gid = ppath[0]["grant_id"]
        grant_id = ppath[-1]["grant_id"]
        if root_gid not in grants_by_id or grant_id not in grants_by_id:
            return VerifierResult("REFUSE", "SESSION_INVALID")
        root_gp = grants_by_id[root_gid]["payload"]
        leaf_gp = grants_by_id[grant_id]["payload"]
        if "issuer" not in root_gp:
            return VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE")

        # G7-03: Full SPEC-06 §4 Steps 6–10d backing-grant chain verification (issuer, ward, contract, delegation, 0x01/0x02 anchor, seal, executor)!
        local_action_profiles = executor_cfg.get("action_profiles") or {}
        ok_bg, err_bg, bg = self._verify_backing_grant_chain(
            ppath=ppath,
            grants_by_id=grants_by_id,
            bundle=bundle,
            chain=chain,
            journal=journal,
            executor_cfg=executor_cfg,
            local_action_profiles=local_action_profiles,
            act_meta=None,
            inv_action=None,
            inv_arguments=None,
            inv_caddr=None,
            use_txid=None,
            for_session_open=True,
        )
        if not ok_bg:
            assert err_bg is not None
            return err_bg

        # Verify every capability on leaf_gp is registered, supported, allows bearer sessions, satisfies required_quotas/config_sha256, & satisfies target authority (H-3 / F-10)!
        for cap in leaf_gp.get("capabilities", []):
            c_act = cap["action"]
            c_meta = ACTION_PROFILES.get(c_act) or local_action_profiles.get(c_act)
            if c_meta is None or (executor_cfg.get("actions") is not None and c_act not in executor_cfg["actions"]):
                return VerifierResult("REFUSE", "INVOKE_ACTION_DENIED")
            if not c_meta.get("allows_bearer_session", False):
                return VerifierResult("REFUSE", "SESSION_INVALID")
            if c_meta.get("requires_contract", False) and "contract_id" not in leaf_gp:
                return VerifierResult("REFUSE", "GRANT_CONTRACT_REQUIRED")
            if c_act == "agent/session" and bg.get("contract_config_sha256") is None:
                return VerifierResult("REFUSE", "CONTRACT_CONFIG_MISMATCH")
            if c_meta.get("mechanical", True) and "terms_text" in leaf_gp:
                return VerifierResult("REFUSE", "GRANT_TEXT_FORBIDDEN")
            cap_quotas = cap.get("quotas", [])
            for rq in c_meta.get("required_quotas", []):
                exp_res = cap["target"] if rq.get("resource") == "{target}" else rq.get("resource")
                has_req = any(
                    q.get("kind") == rq["kind"]
                    and q.get("unit") == rq["unit"]
                    and (exp_res is None or q.get("resource") == exp_res)
                    for q in cap_quotas
                )
                if not has_req:
                    return VerifierResult("REFUSE", "QUOTA_EXCEEDED")
            t_err = self._check_target_authority(
                cap["target"],
                c_meta,
                bg["iss_pin"],
                bg["nrec"],
                leaf_gp,
                bundle,
                chain,
                journal,
                executor_cfg,
                wstate=bg["wstate"],
                ward_details=bg["ward_details"],
            )
            if t_err is not None:
                return VerifierResult("REFUSE", t_err)

        # Verify session-open signature matches grant recipient (H-1a: support 0x13 origin_bundle for named recipient!)
        rcpt = leaf_gp["recipient"]
        if rcpt["mode"] == "key":
            exp_pol = {"m": 1, "pks": [rcpt["key"]]}
        elif rcpt["mode"] == "group":
            exp_pol = rcpt["threshold"]
        else:
            r_ob_s = bundle.get("recipient_origin_bundle") or bundle.get("origin_bundle")
            r_obs_s = bundle.get("origin_bundles_by_oid")
            r_nrec, r_nerr = self.resolve_name(
                rcpt["name"],
                chain,
                expected_owner_policy=rcpt["owner_policy"],
                expected_registration=rcpt["registration"],
                allow_unresolved_voluntary_rebind=(r_ob_s is not None or bool(r_obs_s)),
            )
            if r_nerr:
                return VerifierResult("REFUSE", r_nerr)
            assert r_nrec is not None
            if r_nrec.get("_voluntary_rebinds"):
                rb_err_rs = self._verify_rebound_pin(
                    r_nrec, rcpt, r_ob_s, chain, journal, origin_bundles_by_oid=r_obs_s
                )
                if rb_err_rs:
                    return VerifierResult("REFUSE", rb_err_rs)
            nv = r_nrec.get("_value_obj", {}).get("nostr")
            rpk = nv if isinstance(nv, str) else (nv.get("names", {}).get("_") if isinstance(nv, dict) else None)
            exp_pol = {"m": 1, "pks": [rpk]} if rpk else None
        ok_s, scode = (
            (False, "WIRE_SIGNATURE")
            if exp_pol is None
            else sl.verify_signature_set(sl.signing_digest(sp), o_res["signatures"], expected_policy=exp_pol, obj_type="seallink-session-open/1")
        )
        # D8-M7: op == "close" MAY also be signed by the root grant issuer's live link.grant policy!
        if not ok_s and op == "close" and (bg["wstate"] is None or bg["wstate"].get("capacity") != "ward"):
            iss_pol, iss_rerr = self.resolve_role_policy(bg["nrec"], "grant", o_res["signatures"].get("policy"))
            if iss_rerr is None and iss_pol is not None:
                ok_s, scode = sl.verify_signature_set(
                    sl.signing_digest(sp), o_res["signatures"], expected_policy=iss_pol, obj_type="seallink-session-open/1"
                )
        if not ok_s:
            return VerifierResult("REFUSE", scode)

        # Verify session quotas <= backing grant quotas & open/extend/close state transitions (non-widening extend!)
        grant_q_caps: dict[tuple[str, str, str, str], int] = {}
        for cap in leaf_gp.get("capabilities", []):
            for q in cap.get("quotas", []):
                k = (q["kind"], q["resource"], q["unit"], q["window"])
                grant_q_caps[k] = max(grant_q_caps.get(k, 0), int(q["max"]))
        quotas_ok = all(
            (sq["kind"], sq["resource"], sq["unit"], sq["window"]) in grant_q_caps
            and int(sq["max"]) <= grant_q_caps[(sq["kind"], sq["resource"], sq["unit"], sq["window"])]
            for sq in sp.get("quotas", [])
        )
        sid = sl.object_id(sp) if op == "open" else sp["session_id"]
        existing = journal.sessions_by_id.get(sid)
        state_ok = (
            (sid not in journal.sessions_by_id)
            if op == "open"
            else (
                existing is not None
                and not existing.get("closed")
                and existing.get("grant_id") == grant_id
                and existing.get("slot_binding") == sp["slot_binding"]
            )
        )
        # Non-widening extend: cannot increase quota ceilings or drop previously configured session quotas!
        if state_ok and op == "extend" and existing is not None:
            prev_q = {
                (q["kind"], q["resource"], q["unit"], q["window"]): int(q["max"])
                for q in existing.get("quotas", [])
            }
            new_q = {
                (q["kind"], q["resource"], q["unit"], q["window"]): int(q["max"])
                for q in sp.get("quotas", [])
            }
            if any(k not in new_q or new_q[k] > v for k, v in prev_q.items()):
                quotas_ok = False
        if not quotas_ok or not state_ok:
            return VerifierResult("REFUSE", "SESSION_INVALID")

        # Persist ONE atomic `session-state` journal entry carrying nonce AND (on open) CSPRNG token_sha256 (2A, R1 §3)!
        body: dict[str, Any] = {
            "expires_at": sp["exp"],
            "grant_id": grant_id,
            "nonce": sp["nonce"],
            "op": op,
            "recorded_at": chain.now,
            "session_id": sid,
            "slot_binding": sp["slot_binding"],
        }
        if "quotas" in sp:
            body["quotas"] = sp["quotas"]
        t_hash: str | None = None
        if op == "open":
            if bearer_token is not None:
                if not isinstance(bearer_token, str) or not re.fullmatch(r"[0-9a-f]{64}", bearer_token):
                    return VerifierResult("REFUSE", "SESSION_INVALID")
                tok = bearer_token
            else:
                tok = secrets.token_hex(32)
            t_hash = sl.sha256(tok.encode("utf-8")).hex()
            body["token_sha256"] = t_hash
            body["proof_path"] = copy.deepcopy(ppath)
            if bg.get("root_recent_h") is not None:
                body["root_recent_height"] = int(bg["root_recent_h"])
        jw, j_aerr = _append_journal_checked(journal, "session-state", body)
        if j_aerr is not None:
            return VerifierResult("REFUSE", j_aerr)
        assert jw is not None
        if op == "open":
            return VerifierResult(
                "ADMIT",
                None,
                outcome="executed",
                journal_writes=[jw],
                details={"bearer_token": tok, "session_id": sid, "token_sha256": t_hash},
            )
        return VerifierResult("ADMIT", None, outcome="executed", journal_writes=[jw], details={"session_id": sid, "op": op})

    def _validate_session_contract_env(
        self,
        contract_env: dict[str, Any] | None,
        expected_cid: str,
        chain: ChainView,
        journal: FencedJournal,
    ) -> dict[str, Any] | None:
        """Validate a mandatory contract or framework contract envelope, live seal, and window for bearer sessions (H-10)."""
        if (
            contract_env is None
            or journal.lookup_closure({"subject_id": expected_cid, "subject_kind": "contract"}, legacy_key=expected_cid) is not None
        ):
            return None
        ok_c, rc = self._verify_object_wire(contract_env, expected_type="seallink-contract/1")
        if (
            not ok_c
            or rc["network"] != self.pinned_network
            or rc["genesis"] != self.pinned_genesis
            or sl.object_id(rc) != expected_cid
            or "seal" not in rc
            or self.evaluate_seal(rc["seal"], chain, required_depth=1, journal=journal, subject_id=expected_cid, subject_kind="contract")[1] is not None
        ):
            return None
        cw = rc["window"]
        if (
            chain.tip_height < cw["not_before_height"]
            or ("not_after_height" in cw and chain.tip_height >= cw["not_after_height"])
            or ("not_after_unix" in cw and chain.now >= cw["not_after_unix"])
        ):
            return None
        return rc

    def _verify_issuance_anchor_live(
        self,
        grant_env: dict[str, Any],
        pe: dict[str, Any],
        chain: ChainView,
        *,
        allow_batch: bool = True,
    ) -> bool:
        """Re-verify a confirmed active-chain 0x01/0x02 issuance anchor, recency, and confirmation depth against reorgs (SPEC-06 §5)."""
        gp = grant_env["payload"]
        gid = sl.object_id(gp)
        itx = chain.get_tx(pe.get("issuance_txid")) if isinstance(pe.get("issuance_txid"), str) else None
        dec_i = self._decode_opreturn_tx(itx, require_confirmed=True)
        if dec_i is None or itx is None:
            return False
        iss_prep: dict[str, Any] = {
            "genesis": gp["genesis"],
            "grant_content_addr": sl.content_addr(grant_env),
            "grant_id": gid,
            "type": "seallink-issuance/1",
        }
        if "contract_id" in gp:
            iss_prep["contract_id"] = gp["contract_id"]
        exp_digest = sl.signing_digest(iss_prep).hex()
        if dec_i["action"] == "0x01":
            if dec_i["commitment"] != exp_digest:
                return False
        elif dec_i["action"] == "0x02" and allow_batch:
            bp = pe.get("batch_proof")
            if not isinstance(bp, dict) or bp.get("leaf_digest") != exp_digest or bp.get("root") != dec_i["commitment"] or not sl.verify_merkle_proof(bp):
                return False
        else:
            return False
        a_h = int(itx["confirmed_height"])
        r_h = chain.raw.get("blocks", {}).get(gp["recent_block"])
        req_d = max(gp.get("min_depth", 1), self.operator_min_depth)
        return r_h is not None and r_h < a_h <= r_h + self.recency_k and (chain.tip_height - a_h + 1) >= req_d

    def _validate_session_backing_grant(
        self,
        gid: str,
        grant_env: dict[str, Any] | None,
        parent_grant_env: dict[str, Any] | None,
        chain: ChainView,
        journal: FencedJournal,
        contract_env: dict[str, Any] | None = None,
        framework_contract_env: dict[str, Any] | None = None,
        origin_bundle: dict[str, Any] | None = None,
        proof_path: list[dict[str, Any]] | None = None,
        root_recent_height: int | None = None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None, dict[tuple[str, str, str, str], int]]:
        """Online live SPEC-06 §4 re-check of a bearer session's backing grant, persisted proof_path anchors, root issuer link.grant & 0x0b, depth-2 parent + stop_coin, and mandatory contract/framework seals (B-2, H-10)."""
        empty_caps: dict[tuple[str, str, str, str], int] = {}
        if grant_env is None:
            return None, None, None, empty_caps
        ok_g, rg = self._verify_object_wire(grant_env, expected_type="seallink-grant/1")
        gp = rg["payload"] if (ok_g and sl.object_id(rg["payload"]) == gid) else None
        if (
            gp is None
            or gp["network"] != self.pinned_network
            or gp["genesis"] != self.pinned_genesis
            or gp["revocation"]["mode"] != "seal"
            or gp["revocation"]["kind"] != "revocable"
            or not (gp["not_before_height"] <= chain.tip_height < gp["not_after_height"])
        ):
            return None, None, None, empty_caps

        # H-10: When backing grant binds contract_id, contract_env (and framework_contract_env if present) is MANDATORY!
        if "contract_id" in gp:
            rc = self._validate_session_contract_env(contract_env, gp["contract_id"], chain, journal)
            if rc is None:
                return None, None, None, empty_caps
            if "framework_id" in rc and self._validate_session_contract_env(framework_contract_env, rc["framework_id"], chain, journal) is None:
                return None, None, None, empty_caps

        s_op = {"txid": gp["revocation"]["seal"]["txid"], "vout": gp["revocation"]["seal"]["vout"]}
        leaf_req_depth = max(gp.get("min_depth", 1), self.operator_min_depth)
        if (
            journal.lookup_closure({"outpoint": s_op, "subject_kind": "seal"}, legacy_key=_outpoint_key(s_op)) is not None
            or self.evaluate_seal(gp["revocation"]["seal"], chain, required_depth=leaf_req_depth, journal=journal, subject_id=gid, subject_kind="grant")[1] is not None
        ):
            return None, None, None, empty_caps

        parent_gp: dict[str, Any] | None = None
        parent_gid: str | None = None
        parent_row_caps: dict[tuple[str, str, str, str], int] = {}
        root_env = rg
        root_gp = gp
        if "parent" in gp:
            parent_gid = gp["parent"]["grant_id"]
            row_ord = gp["parent"]["ordinal"]
            if (
                parent_grant_env is None
                or journal.lookup_closure({"subject_id": parent_gid, "subject_kind": "grant"}, legacy_key=parent_gid) is not None
                or journal.lookup_closure({"grant_id": parent_gid, "ordinal": row_ord, "subject_kind": "row"}, legacy_key=f"{parent_gid}:{row_ord}") is not None
            ):
                return None, None, None, empty_caps
            ok_pg, rpg = self._verify_object_wire(parent_grant_env, expected_type="seallink-grant/1")
            if not ok_pg or sl.object_id(rpg["payload"]) != parent_gid:
                return None, None, None, empty_caps
            parent_gp = rpg["payload"]
            if (
                parent_gp["network"] != self.pinned_network
                or parent_gp["genesis"] != self.pinned_genesis
                or "delegate" not in parent_gp
                or not (parent_gp["not_before_height"] <= chain.tip_height < parent_gp["not_after_height"])
            ):
                return None, None, None, empty_caps
            if parent_gp["revocation"]["mode"] == "seal":
                p_op = {"txid": parent_gp["revocation"]["seal"]["txid"], "vout": parent_gp["revocation"]["seal"]["vout"]}
                parent_req_depth = max(parent_gp.get("min_depth", 1), self.operator_min_depth)
                if (
                    journal.lookup_closure({"outpoint": p_op, "subject_kind": "seal"}, legacy_key=_outpoint_key(p_op)) is not None
                    or self.evaluate_seal(parent_gp["revocation"]["seal"], chain, required_depth=parent_req_depth, journal=journal, subject_id=parent_gid, subject_kind="grant")[1] is not None
                ):
                    return None, None, None, empty_caps
            # B-2: Locate row_ord in parent_gp.delegate.groups and verify live stop_outpoint + extract row caps!
            cur_ord = 0
            matched_group = None
            stop_outpoint = None
            for gspec in parent_gp["delegate"]["groups"]:
                for rng in gspec["ranges"]:
                    if cur_ord + 1 <= row_ord <= cur_ord + rng["count"]:
                        offset = row_ord - cur_ord - 1
                        matched_group = gspec
                        if "stop_txid" in rng:
                            stop_outpoint = {
                                "txid": rng["stop_txid"],
                                "vout": rng["stop_first"] + offset,
                                "script_policy": rng["stop_script_policy"],
                            }
                        break
                    cur_ord += rng["count"]
                if matched_group is not None:
                    break
            if matched_group is None:
                return None, None, None, empty_caps
            if stop_outpoint is not None:
                try:
                    exp_stop_spk, _ = sl.compile_script_policy(stop_outpoint["script_policy"])
                except ValueError:
                    return None, None, None, empty_caps
                stx = chain.get_tx(stop_outpoint["txid"])
                sout = chain.get_output(stop_outpoint["txid"], stop_outpoint["vout"])
                if not stx or stx.get("confirmed_height") is None or not sout or sout.get("script_pubkey_hex") != exp_stop_spk.hex():
                    return None, None, None, empty_caps
                if sout.get("spent_by_txid") or sout.get("absent_from_utxo"):
                    journal.record_closure(
                        {"grant_id": parent_gid, "ordinal": row_ord, "subject_kind": "row"},
                        "GRANT_ROW_STOPPED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                        spend_txid=sout.get("spent_by_txid", "0" * 64),
                    )
                    return None, None, None, empty_caps
            for pcap in matched_group["template"].get("capabilities", []):
                for pq in pcap.get("quotas", []):
                    pk_t = (pq["kind"], pq["resource"], pq["unit"], pq["window"])
                    parent_row_caps[pk_t] = max(parent_row_caps.get(pk_t, 0), int(pq["max"]))
            root_env = rpg
            root_gp = parent_gp

        # Re-verify persisted issuance anchor(s), recency, and confirmation depth against active chain reorgs (SPEC-06 §5)
        if isinstance(proof_path, list) and proof_path:
            exp_chain = (
                [(parent_gid, root_env, True), (gid, rg, False)]
                if ("parent" in gp and parent_gid is not None)
                else [(gid, rg, True)]
            )
            if len(proof_path) != len(exp_chain) or any(
                pe.get("grant_id") != e_gid or not self._verify_issuance_anchor_live(e_env, pe, chain, allow_batch=allow_b)
                for pe, (e_gid, e_env, allow_b) in zip(proof_path, exp_chain)
            ):
                return None, None, None, empty_caps

        # B-2 / H5: Mandatory active-chain recent_block, live root issuer identity, link.grant rotation, cause-/epoch-scoped role closure, 0x0b break, & origin/ward check!
        iss_pin = root_gp.get("issuer")
        if not isinstance(iss_pin, dict):
            return None, None, None, empty_caps
        iss_name = iss_pin["name"]
        root_recent_h = chain.raw.get("blocks", {}).get(root_gp["recent_block"])
        if root_recent_h is None or (root_recent_height is not None and int(root_recent_h) != int(root_recent_height)):
            return None, None, None, empty_caps
        presented_rpol = iss_pin.get("role_policy") or (
            root_env.get("signatures", {}).get("policy")
            if isinstance(root_env.get("signatures"), dict)
            else None
        )
        if isinstance(presented_rpol, dict):
            role_subj_bs = {
                "name": iss_name,
                "policy_sha256": _policy_sha256(presented_rpol),
                "registration": iss_pin["registration"],
                "role": "grant",
                "subject_kind": "role",
            }
            role_cl_comp = journal.lookup_closure(role_subj_bs, cause="CRED_ISSUER_CLOSED")
            if role_cl_comp is not None:
                ex_hc = role_cl_comp.get("subject", {}).get("cutoff_height")
                if ex_hc is None or chain.tip_height >= int(ex_hc):
                    return None, None, None, empty_caps
            role_cl_rot = journal.lookup_closure(role_subj_bs, cause="NAME_ROLE_CHANGED")
            if role_cl_rot is not None:
                ex_rbh = role_cl_rot.get("subject", {}).get("retired_before_height")
                if ex_rbh is None or root_recent_h < int(ex_rbh):
                    return None, None, None, empty_caps

        nrec, nerr = self.resolve_name(
            iss_name,
            chain,
            expected_owner_policy=iss_pin["owner_policy"],
            expected_registration=iss_pin["registration"],
            allow_unresolved_voluntary_rebind=True,
        )
        if nerr or nrec is None:
            return None, None, None, empty_caps
        hist_oid = nrec.get("_historical_origin_id")
        if not hist_oid:
            reg_bound = chain.raw.get("registered_bindings", {}).get(_outpoint_key(iss_pin["registration"]))
            if isinstance(reg_bound, str):
                hist_oid = reg_bound
        if not hist_oid and nrec.get("_voluntary_rebinds"):
            return None, None, None, empty_caps
        wstate: dict[str, Any] | None = None
        if hist_oid:
            ob_iss = self._pick_origin_bundle_for_oid(hist_oid, origin_bundle, None)
            wstate, oerr = self.verify_origin_and_status(ob_iss, chain, journal=journal)
            if oerr or wstate is None:
                return None, None, None, empty_caps
            if not _name_pin_equal(wstate.get("effective_binding", wstate["binding"]), iss_pin):
                return None, None, None, empty_caps
            if wstate["capacity"] == "ward":
                ok_wa, _, _ = self.verify_ward_approvals(root_env, wstate, chain, journal=journal)
                if not ok_wa:
                    return None, None, None, empty_caps
        if wstate is None or wstate["capacity"] != "ward":
            # M-8: Check confirmed on-chain 0x0b compromise on presented_rpol BEFORE role-rotation check!
            if isinstance(presented_rpol, dict):
                min_hc_pre = self._policy_compromised_cutoff(nrec, iss_pin, "grant", presented_rpol, chain)
                if min_hc_pre is not None:
                    journal.record_closure(
                        {
                            "cutoff_height": min_hc_pre,
                            "name": iss_name,
                            "policy_sha256": _policy_sha256(presented_rpol),
                            "registration": iss_pin["registration"],
                            "role": "grant",
                            "subject_kind": "role",
                        },
                        "CRED_ISSUER_CLOSED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                    )
                    return None, None, None, empty_caps
            rpol, rerr = self.resolve_role_policy(nrec, "grant", iss_pin.get("role_policy"), recent_block_height=root_recent_h)
            if rerr:
                if rerr == "NAME_ROLE_CHANGED":
                    hist_pol = self._resolve_historical_role_policy(nrec, "grant", iss_pin.get("role_policy"), at_height=root_recent_h)
                    if hist_pol is not None:
                        ok_hist, _ = sl.verify_signature_set(
                            sl.signing_digest(root_gp),
                            root_env.get("signatures", {}),
                            expected_policy=hist_pol,
                            obj_type="seallink-grant/1",
                        )
                        if ok_hist:
                            rbh = self._first_role_change_height(nrec, "grant", root_recent_h, chain)
                            rot_subj: dict[str, Any] = {
                                "name": iss_name,
                                "policy_sha256": _policy_sha256(hist_pol),
                                "registration": iss_pin["registration"],
                                "role": "grant",
                                "subject_kind": "role",
                            }
                            if rbh is not None:
                                rot_subj["retired_before_height"] = rbh
                            journal.record_closure(
                                rot_subj,
                                "NAME_ROLE_CHANGED",
                                observed_at=chain.now,
                                observed_height=chain.tip_height,
                            )
                return None, None, None, empty_caps
            assert rpol is not None
            ok_rs, _ = sl.verify_signature_set(
                sl.signing_digest(root_gp),
                root_env.get("signatures", {}),
                expected_policy=rpol,
                obj_type="seallink-grant/1",
            )
            if not ok_rs:
                return None, None, None, empty_caps

        return gp, parent_gp, parent_gid, parent_row_caps

    def verify_bearer_session(
        self,
        token: str,
        slot_binding: str,
        chain: ChainView,
        journal: FencedJournal,
        *,
        grant_env: dict[str, Any] | None = None,
        parent_grant_env: dict[str, Any] | None = None,
        contract_env: dict[str, Any] | None = None,
        framework_contract_env: dict[str, Any] | None = None,
        origin_bundle: dict[str, Any] | None = None,
        action: str | None = None,
        target: str | None = None,
        arguments: dict[str, Any] | None = None,
        actual_message_meta: dict[str, Any] | None = None,
        executor_cfg: dict[str, Any] | None = None,
        disclosed_clauses: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Per-use bearer session verification: strict 64-hex token, action-derived risk_class freshness, mandatory live §4 backing-grant + anchor recheck, full capability/required_quotas/config_sha256/mail-meta enforcement, and deterministic per-capability `session-use` debits (B-2, H-3, H-9, H-10, M-10, M-16, L-6)."""
        if "bearer-sessions" not in self.enabled_modules:
            return VerifierResult("REFUSE", "ACTION_UNSUPPORTED")
        local_action_profiles = (executor_cfg.get("action_profiles") or {}) if isinstance(executor_cfg, dict) else {}
        act_meta = (ACTION_PROFILES.get(action) or local_action_profiles.get(action)) if isinstance(action, str) else None
        risk_cls = act_meta["risk_class"] if act_meta is not None else 1
        obs_err = self.check_chain_observation(chain, risk_class=risk_cls)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)
        # M-16: Strictly enforce 64 lowercase hexadecimal ASCII bearer token format!
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            return VerifierResult("REFUSE", "SESSION_INVALID")
        t_hash = sl.sha256(token.encode("utf-8")).hex()
        sess = None
        for k_hash, s_obj in journal.sessions.items():
            if hmac.compare_digest(k_hash, t_hash):
                sess = s_obj
                break
        gid = sess.get("grant_id") if sess else None
        sess_ok = (
            bool(sess)
            and not sess.get("closed")
            and sess.get("slot_binding") == slot_binding
            and chain.now < sess.get("exp", 0)
            and bool(gid)
            and journal.lookup_closure({"subject_id": gid, "subject_kind": "grant"}, legacy_key=gid) is None
        )
        gp, parent_gp, parent_gid, parent_row_caps = (
            self._validate_session_backing_grant(
                gid,
                grant_env,
                parent_grant_env,
                chain,
                journal,
                contract_env=contract_env,
                framework_contract_env=framework_contract_env,
                origin_bundle=origin_bundle,
                proof_path=sess.get("proof_path") if isinstance(sess, dict) else None,
                root_recent_height=sess.get("root_recent_height") if isinstance(sess, dict) else None,
            )
            if (sess_ok and gid is not None)
            else (None, None, None, {})
        )
        if (
            gp is None
            or not isinstance(action, str)
            or act_meta is None
            or not act_meta.get("allows_bearer_session", False)
            or not isinstance(target, str)
            or not isinstance(arguments, dict)
        ):
            return VerifierResult("REFUSE", "SESSION_INVALID")
        assert sess is not None and gid is not None
        if isinstance(executor_cfg, dict) and "executor" in gp:
            if gp["executor"]["name"] != executor_cfg.get("name") or gp["executor"]["key"] != executor_cfg.get("key"):
                return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")

        # H-9: Enforce profile args_schema, exact target match, and ALL 7-predicate where + mail/read actual_message_meta checks!
        if self.enforce_schemas and "args_schema" in act_meta:
            aerr = validate_against_schema(act_meta["args_schema"], arguments, require_jsonschema=self.require_jsonschema)
            if aerr is not None:
                return VerifierResult("REFUSE", aerr)

        sid = sess["session_id"]
        matched_cap: dict[str, Any] | None = None
        for cap in gp.get("capabilities", []):
            if cap["action"] != action or cap["target"] != target:
                continue
            if self._match_capability_where(action, cap, arguments, actual_message_meta):
                matched_cap = cap
                break
        if matched_cap is None:
            return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")

        # H-3 / F-10: Enforce mandatory profile required_quotas AND contract config_sha256 parity with admit_and_reserve!
        for rq in act_meta.get("required_quotas", []):
            exp_res = target if rq.get("resource") == "{target}" else rq.get("resource")
            has_req = any(
                q.get("kind") == rq["kind"]
                and q.get("unit") == rq["unit"]
                and (exp_res is None or q.get("resource") == exp_res)
                for q in matched_cap.get("quotas", [])
            )
            if not has_req:
                return VerifierResult("REFUSE", "QUOTA_EXCEEDED")
        if "contract_id" in gp and isinstance(contract_env, dict):
            req_cfg = contract_env.get("config_sha256")
            clause_cfg_hashes: set[str] = set()
            cfg_ok = True
            if contract_env.get("machine_clause_indices") and isinstance(disclosed_clauses, dict):
                for idx in contract_env["machine_clause_indices"]:
                    d = disclosed_clauses.get(str(idx)) or disclosed_clauses.get(idx)
                    if not isinstance(d, dict) or "salt_hex" not in d or "clause" not in d:
                        cfg_ok = False
                        break
                    try:
                        ok_cm = sl.clause_commit(d["salt_hex"], d["clause"]) == contract_env["clause_commitments"][idx]
                    except (ValueError, TypeError, IndexError):
                        ok_cm = False
                    if not ok_cm or not isinstance(d["clause"].get("machine_terms"), dict):
                        cfg_ok = False
                        break
                    if "config_sha256" in d["clause"]["machine_terms"]:
                        clause_cfg_hashes.add(d["clause"]["machine_terms"]["config_sha256"])
            if clause_cfg_hashes:
                cl_cfg = next(iter(clause_cfg_hashes))
                if len(clause_cfg_hashes) != 1 or (req_cfg is not None and req_cfg != cl_cfg):
                    cfg_ok = False
                req_cfg = cl_cfg
            rt_cfg = executor_cfg.get("runtime_config_sha256") if isinstance(executor_cfg, dict) else None
            arg_cfg = arguments.get("config_sha256")
            if req_cfg is not None:
                if (rt_cfg is not None and rt_cfg != req_cfg) or (arg_cfg is not None and arg_cfg != req_cfg):
                    cfg_ok = False
            elif action == "agent/session" and arguments.get("op") == "start":
                cfg_ok = False
            if not cfg_ok:
                return VerifierResult("REFUSE", "CONTRACT_CONFIG_MISMATCH")

        def _bucket_for(window: str, anchor_nb: int) -> str:
            if window.startswith("seconds:"):
                sec_s = int(window.split(":", 1)[1])
                return f"sec:{(chain.now // sec_s) * sec_s}"
            if window.startswith("blocks:"):
                blk_n = int(window.split(":", 1)[1])
                k_b = (chain.tip_height - anchor_nb) // blk_n
                return f"blk:{anchor_nb + k_b * blk_n}"
            return "term"

        # M-10 / L-6: Debit ONLY matched_cap's quotas (and matching session quotas) in deterministic per-quota order: session -> own -> row!
        sess_q_by_key = {
            (sq["kind"], sq["resource"], sq["unit"], sq["window"]): sq
            for sq in sess.get("quotas", [])
        }
        debit_lines: list[dict[str, Any]] = []
        planned_delta: dict[tuple[str, str, str], int] = {}
        watermark_updates: dict[str, int] = {}

        for q in matched_cap.get("quotas", []):
            qk_t = (q["kind"], q["resource"], q["unit"], q["window"])
            qkey = f"{q['kind']}|{q['resource']}|{q['unit']}|{q['window']}"
            if q["window"].startswith("seconds:"):
                if chain.now < journal.quota_watermarks.get(qkey, 0):
                    return VerifierResult("REFUSE", "QUOTA_CLOCK_REGRESSION")
                watermark_updates[qkey] = chain.now
            amt, _ = compute_quota_debit(action, arguments, q)
            targets_for_q: list[tuple[str, str, str, int | None, int, int]] = []
            if qk_t in sess_q_by_key:
                targets_for_q.append(("session", f"session:{sid}", gid, None, int(sess_q_by_key[qk_t]["max"]), gp["not_before_height"]))
            targets_for_q.append(("own", f"own:{gid}", gid, None, int(q["max"]), gp["not_before_height"]))
            if "parent" in gp and parent_gid is not None and parent_gp is not None:
                r_ord = int(gp["parent"]["ordinal"])
                row_cap = parent_row_caps.get(qk_t, int(q["max"]))
                targets_for_q.append(("row", f"row:{parent_gid}:{r_ord}", parent_gid, r_ord, row_cap, parent_gp["not_before_height"]))

            for acct_kind, scope_id, g_ref, r_ord_opt, ceiling, nb_h in targets_for_q:
                b_id = _bucket_for(q["window"], nb_h)
                bkey = (scope_id, qkey, b_id)
                used = journal.quotas_used.get(bkey, 0) + planned_delta.get(bkey, 0)
                if ceiling == 0 or used + amt > ceiling:
                    return VerifierResult("REFUSE", "QUOTA_EXCEEDED")
                planned_delta[bkey] = planned_delta.get(bkey, 0) + amt
                dln: dict[str, Any] = {
                    "account": acct_kind,
                    "amount": str(amt),
                    "bucket_id": b_id,
                    "grant_id": g_ref,
                    "quota_kind": q["kind"],
                    "resource": q["resource"],
                    "unit": q["unit"],
                    "window": q["window"],
                }
                if r_ord_opt is not None:
                    dln["row_ordinal"] = r_ord_opt
                debit_lines.append(dln)

        journal_writes: list[dict[str, Any]] = []
        if debit_lines:
            jw_u, j_aerr = _append_journal_checked(
                journal,
                "session-use",
                {
                    "action": action,
                    "debits": debit_lines,
                    "grant_id": gid,
                    "recorded_at": chain.now,
                    "session_id": sid,
                },
            )
            if j_aerr is not None:
                return VerifierResult("REFUSE", j_aerr)
            assert jw_u is not None
            for wk, wv in watermark_updates.items():
                journal.quota_watermarks[wk] = max(journal.quota_watermarks.get(wk, 0), wv)
            journal_writes.append(jw_u)
        return VerifierResult(
            "ADMIT",
            None,
            outcome="executed",
            journal_writes=journal_writes,
            details={"grant_id": gid, "session_id": sid},
        )

    def verify_migration(
        self,
        migration_env: dict[str, Any],
        export_bundle: dict[str, Any],
        journal: FencedJournal,
        chain: ChainView | None = None,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
        *,
        holder_assent: dict[str, Any] | None = None,
        dest_accept_stmt: dict[str, Any] | None = None,
        origin_bundle: dict[str, Any] | None = None,
        origin_bundles_by_oid: dict[str, dict[str, Any]] | None = None,
        mode: str = "activate",
        local_executor_pin: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Verify exclusive service migration (`stage` vs mandatory-proof `activate`) per SPEC-07 §2 (H-14, M-14, L-13)."""
        ok_w, res = self._verify_object_wire(migration_env, expected_type="seallink-migration/1")
        if not ok_w:
            return VerifierResult("REFUSE", res)
        if mode not in ("stage", "activate"):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        mp = res["payload"]
        if mp["network"] != self.pinned_network or mp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        if chain is None or not isinstance(export_bundle, dict):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)
        manifests = presented_manifests or {}
        dest = mp["dest_executor"]

        # Proof (a1) [M-14 / L-13]: Local executor pin check runs FIRST so executor mismatches always refuse GRANT_EXECUTOR_MISMATCH!
        if (mode == "activate" and local_executor_pin is None) or (
            local_executor_pin is not None and not _name_pin_equal(local_executor_pin, dest)
        ):
            return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")

        # H-14: Validate export_bundle against closed MigrationExportBundle schema!
        if self.enforce_schemas:
            eb_err = validate_against_schema(
                "schemas/invocation.schema.json#/$defs/MigrationExportBundle",
                export_bundle,
                require_jsonschema=self.require_jsonschema,
            )
            if eb_err is not None:
                return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")

        # Proof (a2): Verify source_executor signature against its confirmed manifest service.receipt_key (H-1a: support 0x13 origin_bundle!)
        src = mp["source_executor"]
        has_ob_any = origin_bundle is not None or bool(origin_bundles_by_oid)
        s_nrec, s_nerr = self.resolve_name(
            src["name"],
            chain,
            expected_owner_policy=src["owner_policy"],
            expected_registration=src["registration"],
            allow_unresolved_voluntary_rebind=has_ob_any,
        )
        if s_nerr:
            return VerifierResult("REFUSE", s_nerr)
        assert s_nrec is not None
        if s_nrec.get("_voluntary_rebinds"):
            rb_err_s = self._verify_rebound_pin(
                s_nrec, src, origin_bundle, chain, journal, origin_bundles_by_oid=origin_bundles_by_oid
            )
            if rb_err_s:
                return VerifierResult("REFUSE", rb_err_s)
        s_man, s_merr = self.resolve_manifest(src["name"], s_nrec, manifests, chain, journal)
        if s_merr:
            return VerifierResult("REFUSE", s_merr)
        assert s_man is not None
        rcpt_key = s_man.get("service", {}).get("receipt_key")
        if not rcpt_key:
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        ok_sig, scode = sl.verify_signature_set(
            sl.signing_digest(mp),
            migration_env["signatures"],
            expected_policy={"m": 1, "pks": [rcpt_key]},
            obj_type="seallink-migration/1",
        )
        if not ok_sig:
            return VerifierResult("REFUSE", scode)

        # Proof (a3): Verify canonical MigrationInventory allowlist + inventory_sha256 (zero execution secrets)
        inv_obj = export_bundle.get("inventory")
        inv_dict = inv_obj if isinstance(inv_obj, dict) else {}
        inv_err = (
            validate_against_schema("schemas/invocation.schema.json#/$defs/MigrationInventory", inv_dict, require_jsonschema=self.require_jsonschema)
            if (self.enforce_schemas and isinstance(inv_obj, dict))
            else None
        )
        has_forbidden_item = any(
            _is_forbidden_export_item(it)
            for it in inv_dict.get("items", [])
            if isinstance(it, dict)
        )
        inv_ok = (
            isinstance(inv_obj, dict)
            and inv_err is None
            and not has_forbidden_item
            and inv_dict.get("migration_id") == mp["migration_id"]
            and inv_dict.get("holder_name") == mp["holder"]["name"]
            and inv_dict.get("service_type") == mp["service_type"]
            and sl.sha256(sl.jcs_encode(inv_dict)).hex() == mp["inventory_sha256"]
        )
        mid = mp["migration_id"]
        if not inv_ok:
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")

        # L-13: Stage mode runs BEFORE source fencing (does not require journal_pos equality or fencing_statement) and performs ZERO journal writes!
        if mode == "stage":
            return VerifierResult("ADMIT", None, outcome="reserved", journal_writes=[], details={"mode": "stage", "migration_id": mid})

        # Proof (a4) [H-14]: ACTIVATE mode requires matching journal coordinates, unique migration_id, source-signed migration-fence Statement,
        # AND cryptographic on-chain verification that EVERY declared predecessor_grant_seals[] is spent!
        if (
            export_bundle.get("source_journal_pos") != mp["journal_pos"]
            or export_bundle.get("source_journal_commitment") != mp["journal_commitment"]
            or mid in journal.migrations_applied
        ):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        f_stmt = export_bundle.get("fencing_statement")
        f_res = (
            self.verify_statement(f_stmt, chain, expected_policy={"m": 1, "pks": [rcpt_key]})
            if isinstance(f_stmt, dict)
            else None
        )
        fsp = f_stmt.get("payload", {}) if isinstance(f_stmt, dict) else {}
        fsubj = fsp.get("subject", {}) if isinstance(fsp, dict) else {}
        if (
            f_res is None
            or f_res.verdict != "ADMIT"
            or fsp.get("statement_kind") != "migration-fence"
            or not _name_pin_equal(fsp.get("issuer"), src)
            or fsubj.get("migration_id") != mid
            or not _name_pin_equal(fsubj.get("holder"), mp["holder"])
            or not _name_pin_equal(fsubj.get("dest_executor"), dest)
            or fsubj.get("source_journal_pos") != mp["journal_pos"]
            or fsubj.get("source_journal_commitment") != mp["journal_commitment"]
            or fsubj.get("inventory_sha256") != mp["inventory_sha256"]
        ):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        for p_seal in fsubj.get("predecessor_grant_seals", []):
            p_spk, _ = sl.compile_script_policy(p_seal["script_policy"])
            p_cre = chain.get_tx(p_seal["txid"])
            p_out = chain.get_output(p_seal["txid"], p_seal["vout"])
            p_sp_id = p_out.get("spent_by_txid") if isinstance(p_out, dict) else None
            p_sp_tx = chain.get_tx(p_sp_id) if isinstance(p_sp_id, str) else None
            p_sp_h = p_sp_tx.get("confirmed_height") if isinstance(p_sp_tx, dict) else None
            if (
                not p_cre
                or p_cre.get("confirmed_height") is None
                or not p_out
                or p_out.get("script_pubkey_hex") != p_spk.hex()
                or not p_sp_tx
                or p_sp_h is None
                or (chain.tip_height - int(p_sp_h) + 1) < self.operator_min_depth
                or (p_sp_tx.get("inputs") and not self._tx_spends_outpoint(p_sp_tx, p_seal))
            ):
                return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")

        # Proof (b): Mandatory holder_assent (with ward custody_change quorum when holder is a ward!)
        h_assent = holder_assent if holder_assent is not None else export_bundle.get("holder_assent")
        ok_ha, ha_res = self._verify_object_wire(h_assent, expected_type="seallink-assent/1") if h_assent is not None else (False, None)
        hap = ha_res["payload"] if ok_ha else {}
        if (
            not ok_ha
            or hap.get("target_type") != "seallink-migration/1"
            or hap.get("target_id") != sl.object_id(mp)
            or hap.get("party_name") != mp["holder"]["name"]
            or hap.get("network") != self.pinned_network
            or hap.get("genesis") != self.pinned_genesis
            or chain.now < hap["issued_at"]
            or chain.now >= hap["expires_at"]
        ):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        h_nrec, h_nerr = self.resolve_name(
            mp["holder"]["name"],
            chain,
            expected_owner_policy=mp["holder"]["owner_policy"],
            expected_registration=mp["holder"]["registration"],
            allow_unresolved_voluntary_rebind=has_ob_any,
        )
        if h_nerr:
            return VerifierResult("REFUSE", h_nerr)
        assert h_nrec is not None
        wstate_h: dict[str, Any] | None = None
        hist_oid_h = h_nrec.get("_historical_origin_id")
        if not hist_oid_h:
            reg_b_h = chain.raw.get("registered_bindings", {}).get(_outpoint_key(mp["holder"]["registration"]))
            if isinstance(reg_b_h, str):
                hist_oid_h = reg_b_h
        ob_h = (
            self._pick_origin_bundle_for_oid(hist_oid_h, origin_bundle, origin_bundles_by_oid)
            if hist_oid_h
            else origin_bundle
        )
        if hist_oid_h or ob_h is not None:
            wstate_h, woerr = self.verify_origin_and_status(ob_h, chain, journal=journal)
            if woerr:
                return VerifierResult("REFUSE", woerr)
            assert wstate_h is not None
            if (hist_oid_h and wstate_h["origin_id"] != hist_oid_h) or not _name_pin_equal(
                wstate_h.get("effective_binding", wstate_h["binding"]), mp["holder"]
            ):
                return VerifierResult("REFUSE", "ORIGIN_BINDING_INVALID")
            if wstate_h["capacity"] == "ward":
                ok_wg, wgerr, _ = self.verify_ward_approvals(
                    ha_res, wstate_h, chain, journal=journal, origin_bundles_by_oid=origin_bundles_by_oid
                )
                if not ok_wg:
                    return VerifierResult("REFUSE", wgerr)
        elif h_nrec.get("_voluntary_rebinds"):
            rb_err_h = self._verify_rebound_pin(
                h_nrec, mp["holder"], origin_bundle, chain, journal, origin_bundles_by_oid=origin_bundles_by_oid
            )
            if rb_err_h:
                return VerifierResult("REFUSE", rb_err_h)
        if wstate_h is None or wstate_h["capacity"] != "ward":
            hpol, hrerr = self.resolve_role_policy(h_nrec, "grant", ha_res.get("signatures", {}).get("policy"))
            ok_hs = (
                hrerr is None
                and hpol is not None
                and not self._is_policy_compromised_at(h_nrec, mp["holder"], "grant", hpol, chain.tip_height, chain)
                and sl.verify_signature_set(sl.signing_digest(hap), ha_res.get("signatures", {}), expected_policy=hpol, obj_type="seallink-assent/1")[0]
            )
            if not ok_hs:
                return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")

        # Proof (c): Mandatory confirmed holder manifest pinning dest_executor for mp["service_type"]!
        h_man, h_merr = self.resolve_manifest(mp["holder"]["name"], h_nrec, manifests, chain, journal)
        if h_merr and h_merr != "MANIFEST_UNAVAILABLE":
            return VerifierResult("REFUSE", h_merr)
        if h_man is None or not any(
            p.get("service_type") == mp["service_type"] and _name_pin_equal(p.get("provider"), dest)
            for p in h_man.get("providers", [])
        ):
            return VerifierResult("REFUSE", "SERVICE_PROVIDER_UNBOUND")

        # Proof (d): Mandatory destination acceptance statement (`migration-accept`) signed by dest_executor's receipt_key (H-1a: support 0x13 origin_bundle!)
        d_stmt = dest_accept_stmt if dest_accept_stmt is not None else export_bundle.get("dest_accept_stmt")
        d_nrec, d_nerr = (
            self.resolve_name(
                dest["name"],
                chain,
                expected_owner_policy=dest["owner_policy"],
                expected_registration=dest["registration"],
                allow_unresolved_voluntary_rebind=has_ob_any,
            )
            if d_stmt is not None
            else (None, "SERVICE_MIGRATION_INVALID")
        )
        if d_nerr is None and d_nrec is not None and d_nrec.get("_voluntary_rebinds"):
            rb_err_d = self._verify_rebound_pin(
                d_nrec, dest, origin_bundle, chain, journal, origin_bundles_by_oid=origin_bundles_by_oid
            )
            if rb_err_d:
                return VerifierResult("REFUSE", rb_err_d)
        d_man, d_merr = (
            self.resolve_manifest(dest["name"], d_nrec, manifests, chain, journal)
            if (d_nerr is None and d_nrec is not None)
            else (None, d_nerr)
        )
        d_rkey = d_man.get("service", {}).get("receipt_key") if d_man else None
        s_res = (
            self.verify_statement(d_stmt, chain, expected_policy={"m": 1, "pks": [d_rkey]} if d_rkey else None)
            if (d_stmt is not None and d_merr is None)
            else VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        )
        dsp = d_stmt.get("payload", {}) if isinstance(d_stmt, dict) else {}
        dsubj = dsp.get("subject", {}) if isinstance(dsp, dict) else {}
        if (
            d_merr is not None
            or s_res.verdict != "ADMIT"
            or dsp.get("statement_kind") != "migration-accept"
            or not _name_pin_equal(dsp.get("issuer"), dest)
            or dsubj.get("migration_id") != mp["migration_id"]
            or dsubj.get("inventory_sha256") != mp["inventory_sha256"]
            or not _name_pin_equal(dsubj.get("holder"), mp["holder"])
            or not _name_pin_equal(dsubj.get("source_executor"), src)
        ):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")

        jw_m, j_aerr = _append_journal_checked(
            journal,
            "migration-applied",
            {
                "holder_name": mp["holder"]["name"],
                "inventory_sha256": mp["inventory_sha256"],
                "migration_id": mid,
                "recorded_at": chain.now,
                "source_name": src["name"],
            },
        )
        if j_aerr is not None:
            return VerifierResult("REFUSE", j_aerr)
        assert jw_m is not None
        return VerifierResult("ADMIT", None, outcome="executed", journal_writes=[jw_m])

    def verify_federation_disclosure(
        self,
        policy: dict[str, Any],
        peer_ctx: dict[str, Any],
        grant_env: dict[str, Any],
        chain: ChainView | None = None,
        *,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
        journal: FencedJournal | None = None,
    ) -> VerifierResult:
        """Verify two-phase federated screening and L2-gated Contour A direct PII disclosure (SPEC-07 §3, D10-1, H-11, H-12, M-13, M-15)."""
        if "federated-screening" not in self.enabled_modules:
            return VerifierResult("REFUSE", "ACTION_UNSUPPORTED")
        ok_g, g_res = self._verify_object_wire(grant_env, expected_type="seallink-grant/1")
        if not ok_g:
            return VerifierResult("REFUSE", g_res)
        gp = g_res["payload"]
        if gp["network"] != self.pinned_network or gp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        # M-15: Fail closed if chain or journal is omitted!
        if chain is None or journal is None:
            return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)
        gid = sl.object_id(gp)
        if journal.lookup_closure({"subject_id": gid, "subject_kind": "grant"}, legacy_key=gid) is not None:
            return VerifierResult("REFUSE", "GRANT_CLOSED")

        phase = peer_ctx.get("phase")
        if phase not in ("screening", "pii_disclosure"):
            return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
        obs_err = self.check_chain_observation(chain, risk_class=2 if phase == "screening" else 1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        # D10-1 / H-12 / H5: Mandatory grant height window, revocable UTXO seal (forbidding single_use) + journal seal closure across BOTH phases!
        if not (gp["not_before_height"] <= chain.tip_height < gp["not_after_height"]):
            return VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED")
        if gp["revocation"]["mode"] != "seal" or gp["revocation"]["kind"] != "revocable" or not isinstance(gp.get("issuer"), dict):
            return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
        fed_seal_op = {"txid": gp["revocation"]["seal"]["txid"], "vout": gp["revocation"]["seal"]["vout"]}
        if journal.lookup_closure({"outpoint": fed_seal_op, "subject_kind": "seal"}, legacy_key=_outpoint_key(fed_seal_op)) is not None:
            return VerifierResult("REFUSE", "SEAL_SPENT")
        fed_req_depth = max(gp.get("min_depth", 1), self.operator_min_depth)
        _, serr, _ = self.evaluate_seal(
            gp["revocation"]["seal"], chain, required_depth=fed_req_depth, journal=journal, subject_id=gid, subject_kind="grant"
        )
        if serr:
            return VerifierResult("REFUSE", serr)

        # D10-1 / H5: Authenticate root issuer identity, active-chain recent_block, durable role closures, link.grant continuity, 0x0b cutoff, & origin/ward status!
        iss_pin = gp["issuer"]
        h_nrec, h_nerr = self.resolve_name(
            iss_pin["name"],
            chain,
            expected_owner_policy=iss_pin["owner_policy"],
            expected_registration=iss_pin["registration"],
            allow_unresolved_voluntary_rebind=(peer_ctx.get("origin_bundle") is not None),
        )
        if h_nerr:
            return VerifierResult("REFUSE", h_nerr)
        assert h_nrec is not None
        hist_oid_f = h_nrec.get("_historical_origin_id")
        if not hist_oid_f:
            reg_b_f = chain.raw.get("registered_bindings", {}).get(_outpoint_key(iss_pin["registration"]))
            if isinstance(reg_b_f, str):
                hist_oid_f = reg_b_f
        wstate_f: dict[str, Any] | None = None
        if hist_oid_f or peer_ctx.get("origin_bundle") is not None:
            wstate_f, woerr_f = self.verify_origin_and_status(peer_ctx.get("origin_bundle"), chain, journal=journal)
            if woerr_f:
                return VerifierResult("REFUSE", woerr_f)
            assert wstate_f is not None
            if (hist_oid_f is not None and wstate_f["origin_id"] != hist_oid_f) or not _name_pin_equal(wstate_f.get("effective_binding", wstate_f["binding"]), iss_pin):
                return VerifierResult("REFUSE", "ORIGIN_BINDING_INVALID")
            if wstate_f["capacity"] == "ward":
                # SPEC-07 §3: Ward PII disclosure is explicitly deferred to a post-v1.0 SLIP; screening accepts verified guardian approvals.
                if phase == "pii_disclosure":
                    return VerifierResult("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN")
                ok_wf, werr_f, _ = self.verify_ward_approvals(
                    g_res, wstate_f, chain, journal=journal, origin_bundles_by_oid=peer_ctx.get("origin_bundles_by_oid")
                )
                if not ok_wf:
                    return VerifierResult("REFUSE", werr_f)
        if wstate_f is None or wstate_f["capacity"] != "ward":
            f_recent_h = chain.raw.get("blocks", {}).get(gp["recent_block"])
            if f_recent_h is None:
                return VerifierResult("REFUSE", "CHAIN_RECENCY_INVALID")
            fed_pres_rpol = iss_pin.get("role_policy") or (
                g_res.get("signatures", {}).get("policy") if isinstance(g_res.get("signatures"), dict) else None
            )
            if isinstance(fed_pres_rpol, dict):
                fed_rsubj = {
                    "name": iss_pin["name"],
                    "policy_sha256": _policy_sha256(fed_pres_rpol),
                    "registration": iss_pin["registration"],
                    "role": "grant",
                    "subject_kind": "role",
                }
                fed_rcl_comp = journal.lookup_closure(fed_rsubj, cause="CRED_ISSUER_CLOSED")
                if fed_rcl_comp is not None:
                    ex_fhc = fed_rcl_comp.get("subject", {}).get("cutoff_height")
                    if ex_fhc is None or chain.tip_height >= int(ex_fhc):
                        return VerifierResult("REFUSE", "CRED_ISSUER_CLOSED")
                fed_rcl_rot = journal.lookup_closure(fed_rsubj, cause="NAME_ROLE_CHANGED")
                if fed_rcl_rot is not None:
                    ex_frbh = fed_rcl_rot.get("subject", {}).get("retired_before_height")
                    if ex_frbh is None or int(f_recent_h) < int(ex_frbh):
                        return VerifierResult("REFUSE", "NAME_ROLE_CHANGED")
                min_hc_f_pre = self._policy_compromised_cutoff(h_nrec, iss_pin, "grant", fed_pres_rpol, chain)
                if min_hc_f_pre is not None:
                    return VerifierResult("REFUSE", "CRED_ISSUER_CLOSED")
            rpol_f, rerr_f = self.resolve_role_policy(h_nrec, "grant", iss_pin.get("role_policy"), recent_block_height=f_recent_h)
            if rerr_f:
                return VerifierResult("REFUSE", rerr_f)
            assert rpol_f is not None
            ok_gs, gscode = sl.verify_signature_set(
                sl.signing_digest(gp), g_res.get("signatures", {}), expected_policy=rpol_f, obj_type="seallink-grant/1"
            )
            if not ok_gs:
                return VerifierResult("REFUSE", gscode)
        if isinstance(peer_ctx.get("issuance_txid"), str):
            fed_pe: dict[str, Any] = {"grant_id": gid, "issuance_txid": peer_ctx["issuance_txid"]}
            if isinstance(peer_ctx.get("batch_proof"), dict):
                fed_pe["batch_proof"] = peer_ctx["batch_proof"]
            if not self._verify_issuance_anchor_live(g_res, fed_pe, chain, allow_batch=True):
                return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")

        if phase == "screening":
            peer_id = peer_ctx.get("peer_id")
            rcpt_ok = gp["recipient"].get("mode") != "name" or peer_id == gp["recipient"].get("name")
            scr_ok = (
                rcpt_ok
                and any(bool(c.get("quotas")) for c in gp.get("capabilities", []))
                and peer_id in set(policy.get("trusted_peers", []))
            )
            if scr_ok:
                return VerifierResult("ADMIT", None, outcome="executed")
        else:
            # H-11: Strict single direct hop TO exact recipient_name (forbid screening_agent / hub / relay / wrong actor)!
            hops = peer_ctx.get("route_hops", [])
            approval_cmd = peer_ctx.get("approval_command")
            dev_list = peer_ctx.get("device_list")
            forbidden_roles = {"screening_agent", "hub", "relay"}
            if (
                gp["recipient"].get("mode") != "name"
                or not isinstance(hops, list)
                or len(hops) != 1
                or not isinstance(hops[0], dict)
                or hops[0].get("role") in forbidden_roles
                or hops[0].get("actor") != gp["recipient"]["name"]
                or approval_cmd is None
                or not isinstance(peer_ctx.get("fields_sha256"), str)
            ):
                return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
            manifests = presented_manifests or peer_ctx.get("manifests") or {}
            o_man, o_merr = self.resolve_manifest(iss_pin["name"], h_nrec, manifests, chain, journal)
            if o_merr:
                return VerifierResult("REFUSE", o_merr)
            assert o_man is not None
            # M-13: Missing sets.devices or missing device_list MUST return DEVICE_UNAUTHORIZED (not FEDERATION_POLICY_DENIED)!
            if not isinstance(o_man.get("sets", {}).get("devices"), dict) or dev_list is None:
                return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
            cmd_res = self.verify_owner_command(
                approval_cmd,
                dev_list,
                is_foreign_service=False,
                chain=chain,
                owner_manifest=o_man,
                origin_bundle=peer_ctx.get("origin_bundle"),
            )
            if cmd_res.verdict != "ADMIT":
                return cmd_res
            cp = approval_cmd["payload"]
            if cp["nonce"] in journal.nonces:
                return VerifierResult("REFUSE", "INVOKE_REPLAY")
            cargs = cp.get("arguments", {})
            cmd_ok = (
                cp.get("level") == 2
                and cp.get("command") == "approve-pii-disclosure"
                and cargs.get("grant_id") == gid
                and cargs.get("route_mode") == "direct"
                and cargs.get("recipient_name") == gp["recipient"]["name"]
                and cargs.get("fields_sha256") == peer_ctx["fields_sha256"]
            )
            if cmd_ok:
                jw_n, j_aerr = _append_journal_checked(
                    journal,
                    "nonce",
                    {
                        "expires_at": cp["exp"],
                        "invocation_id": sl.object_id(cp),
                        "nonce": cp["nonce"],
                        "scope": "owner-command",
                    },
                )
                if j_aerr is not None:
                    return VerifierResult("REFUSE", j_aerr)
                assert jw_n is not None
                return VerifierResult(
                    "ADMIT",
                    None,
                    outcome="executed",
                    journal_writes=[jw_n],
                    details={"grant_id": gid, "route_mode": "direct"},
                )
        return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
