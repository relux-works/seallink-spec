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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import seallink_ref as sl

ROOT = Path(__file__).resolve().parent.parent

# Deterministic fixed precedence order for schema refusal codes (SPEC-01 §7, B-11)
SCHEMA_REFUSAL_PRECEDENCE: dict[str, int] = {
    "WIRE_TYPE": 0,
    "WIRE_MEMBER": 1,
    "WIRE_INTEGER": 2,
    "WIRE_KEY": 3,
    "WIRE_SIGNATURE": 4,
    "WIRE_CONSTRAINT": 5,
    "CHAIN_SCRIPT_UNSUPPORTED": 6,
}

# Load standard action profiles authoritatively from registry/actions.json (B-8, R3 M6)
def _load_action_profiles() -> dict[str, dict[str, Any]]:
    raw = json.loads((ROOT / "registry" / "actions.json").read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for entry in raw.get("actions", []):
        out[entry["action"]] = copy.deepcopy(entry)
    return out


ACTION_PROFILES: dict[str, dict[str, Any]] = _load_action_profiles()

FORBIDDEN_EXPORT_KINDS = frozenset({
    "private_key",
    "execution_credential",
    "bearer_token",
    "dkim_key",
    "tls_private_key",
    "active_grant",
})

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
    for sp in sorted((ROOT / "schemas").glob("*.schema.json")):
        sdoc = json.loads(sp.read_text(encoding="utf-8"))
        uri = sdoc.get("$id", f"https://seallink.org/schemas/{sp.name}")
        id_by_name[sp.name] = uri
        resources.append((uri, Resource.from_contents(sdoc, default_specification=DRAFT202012)))
    registry = Registry().with_resources(resources)
    _SCHEMA_REGISTRY_STATE = {
        "available": True,
        "registry": registry,
        "id_by_name": id_by_name,
        "validator_cls": Draft202012Validator,
        "validators": {},
    }
    return _SCHEMA_REGISTRY_STATE


def jsonschema_available() -> bool:
    return bool(_init_schema_store()["available"])


def _map_schema_error_to_refusal(err: Any) -> str:
    """Deterministically map a Draft 2020-12 ValidationError to its SealLink refusal code via x-seallink-refusal (B-11)."""
    schema = getattr(err, "schema", None)
    if isinstance(schema, dict):
        ann = schema.get("x-seallink-refusal")
        if isinstance(ann, str) and ann in SCHEMA_REFUSAL_PRECEDENCE:
            return ann
    validator = getattr(err, "validator", "")
    # For oneOf / anyOf without a top-level x-seallink-refusal, pick the matching discriminated branch
    # (deepest error path — e.g. RootGrant failing payload.min_depth vs ChildGrant failing top-level required 'parent').
    ctx = getattr(err, "context", None)
    if validator in ("oneOf", "anyOf") and ctx:
        by_branch: dict[Any, list[Any]] = {}
        for sub in ctx:
            sp = list(getattr(sub, "schema_path", []))
            br = sp[0] if sp else 0
            by_branch.setdefault(br, []).append(sub)
        # Score each branch: prefer branches that did NOT fail a top-level 'const' / 'required' discriminator,
        # breaking ties by deepest matched path length.
        def _branch_rank(subs: list[Any]) -> tuple[int, int, int]:
            base_len = len(list(getattr(err, "path", [])))
            has_shallow_disc = any(
                len(list(getattr(s, "path", []))) in (base_len, base_len + 1)
                and getattr(s, "validator", "") in ("const", "required", "not")
                for s in subs
            )
            max_depth = max(len(list(getattr(s, "path", []))) for s in subs)
            return (0 if not has_shallow_disc else 1, -max_depth, len(subs))

        best_subs = min(by_branch.values(), key=_branch_rank)
        sub_codes = [_map_schema_error_to_refusal(s) for s in best_subs]
        sub_codes.sort(key=lambda c: SCHEMA_REFUSAL_PRECEDENCE.get(c, 99))
        return sub_codes[0]
    fallback = "WIRE_MEMBER"
    if validator in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        fallback = "WIRE_INTEGER"
    elif validator == "const" and list(getattr(err, "path", []))[-1:] == ["type"]:
        fallback = "WIRE_TYPE"
    return fallback


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
        codes.append(_map_schema_error_to_refusal(err))
    if not codes:
        return None
    codes.sort(key=lambda c: SCHEMA_REFUSAL_PRECEDENCE.get(c, 99))
    return codes[0]


def _outpoint_key(op: dict[str, Any]) -> str:
    return f"{op['txid']}:{op['vout']}"


def _name_pin_equal(a: dict[str, Any] | None, b: dict[str, Any] | None) -> bool:
    """Exact NamePin equality (name, registration, compiled owner_policy) (B-14)."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False
    if a.get("name") != b.get("name") or a.get("registration") != b.get("registration"):
        return False
    try:
        spk_a, _ = sl.compile_script_policy(a["owner_policy"])
        spk_b, _ = sl.compile_script_policy(b["owner_policy"])
    except (ValueError, KeyError, TypeError):
        return False
    return spk_a == spk_b


def _normalize_policy(p: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"m": p["m"], "pks": list(p["pks"])}
    if "alg" in p and p["alg"] != "bip340":
        out["alg"] = p["alg"]
    return out


def _closure_subject_key(subject: dict[str, Any]) -> str:
    sk = subject.get("subject_kind")
    if sk in ("grant", "contract", "credential", "origin"):
        return f"{sk}:{subject['subject_id']}"
    if sk == "seal":
        return f"seal:{_outpoint_key(subject['outpoint'])}"
    if sk == "row":
        return f"row:{subject['grant_id']}:{subject['ordinal']}"
    if sk == "role":
        return f"role:{subject['name']}:{_outpoint_key(subject['registration'])}:{subject['role']}"
    if sk == "guardian_slot":
        return f"guardian_slot:{subject['origin_id']}:{subject['slot']}:{_outpoint_key(subject['outpoint'])}"
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


def _collect_curve_key_errors(obj: Any, parent_key: str | None = None) -> tuple[bool, bool]:
    """Return `(bad_wire_key, bad_script_policy)` across every key / ScriptPolicy / BranchKeySpec in `obj` (SPEC-01 §7, H-21)."""
    if isinstance(obj, list):
        for item in obj:
            bk, bs = _collect_curve_key_errors(item, parent_key)
            if bk or bs:
                return bk, bs
        return False, False
    if not isinstance(obj, dict):
        return False, False

    bad_key = False
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
        return bad_key, bad_script

    # 2. ThresholdPolicy / DeviceThresholdPolicy / BranchKeySpec multisig
    if "m" in obj and "pks" in obj and "kind" not in obj:
        if parent_key in _BRANCH_KEY_FIELDS:
            bad_key = any(not isinstance(pk, str) or not sl.is_valid_compressed_pubkey(pk) for pk in obj.get("pks", []))
            bad_script = (not bad_key) and (not sl.is_valid_branch_key_spec(obj))
            return bad_key, bad_script
        fn = _CURVE_VALIDATORS.get(obj.get("alg", "bip340"))
        bad_key = fn is None or any(not isinstance(pk, str) or not fn(pk) for pk in obj.get("pks", []))
        return bad_key, False

    # 3. DeviceList entry & transport-binding statement subject
    if "alg" in obj and "key" in obj and "ceiling" in obj:
        fn = _CURVE_VALIDATORS.get(obj["alg"])
        if fn is not None and not fn(obj["key"]):
            return True, False
    if "key_alg" in obj and "key_hex" in obj:
        fn = _CURVE_VALIDATORS.get(obj["key_alg"])
        if fn is not None and not fn(obj["key_hex"]):
            return True, False

    # 4. Single named key fields & BranchKeySpec fields
    for k, v in obj.items():
        if k in _XONLY_KEY_FIELDS or (k == "key" and isinstance(v, str) and "alg" not in obj):
            if isinstance(v, str) and not sl.is_valid_xonly_pubkey(v):
                return True, False
        elif k in _COMP_KEY_FIELDS:
            if isinstance(v, str) and not sl.is_valid_compressed_pubkey(v):
                return True, False
        elif k in _BRANCH_KEY_FIELDS:
            if isinstance(v, str):
                if not sl.is_valid_compressed_pubkey(v):
                    return True, False
                continue
        bk, bs = _collect_curve_key_errors(v, k)
        if bk or bs:
            return bk, bs
    return False, False


def _validate_all_curve_keys(obj: Any, parent_key: str | None = None) -> str | None:
    """Step 9 wire check: validate curve-point validity on EVERY key field in an object (SPEC-01 §7, H-21)."""
    bad_key, bad_script = _collect_curve_key_errors(obj, parent_key)
    if bad_key:
        return "WIRE_KEY"
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
    bad_sighash: bool = False,
    extra_updates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a structured Namecoin name update history with exact encoded prefix scripts."""
    val_bytes = value_obj.encode("utf-8") if isinstance(value_obj, str) else sl.jcs_encode(value_obj)
    spk, _ = sl.compile_script_policy(owner_policy)
    rand_b = sl.sha256(f"seallink-rand:{name}:{registration['txid']}".encode("utf-8"))[:20]
    s_first = sl.encode_name_output("NAME_FIRSTUPDATE", spk, name=name.encode("utf-8"), rand=rand_b, value=val_bytes)
    updates: list[dict[str, Any]] = [
        {
            "op": "NAME_FIRSTUPDATE",
            "txid": registration["txid"],
            "vout": registration["vout"],
            "confirmed_height": first_height,
            "owner_policy": copy.deepcopy(owner_policy),
            "output_script_hex": s_first.hex(),
            "prev_input": None,
        }
    ]
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

    def __init__(self, journal_id: str) -> None:
        self.journal_id = journal_id
        self.pos = 0
        self.commitment = sl.journal_commit_init(journal_id)
        self.entries: list[dict[str, Any]] = []
        # External witness state
        self.witness_readable = True
        self.store_readable = True
        self.witness_journal_id = journal_id
        self.witness_pos = 0
        self.witness_commitment = self.commitment
        self.write_token_active = True
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

    @classmethod
    def from_dict(cls, cfg: dict[str, Any]) -> "FencedJournal":
        j = cls(cfg["journal_id"])
        j.witness_readable = cfg.get("witness_readable", True)
        j.store_readable = cfg.get("store_readable", True)
        j.witness_journal_id = cfg.get("witness_journal_id", j.journal_id)
        j.write_token_active = cfg.get("write_token_active", True)
        for k, v in cfg.get("receipt_store", {}).items():
            j.receipt_store[k] = copy.deepcopy(v)
        for item in cfg.get("initial_entries", []):
            j.append(item["kind"], item["body"])
        if "witness_pos" in cfg:
            j.witness_pos = cfg["witness_pos"]
        if "witness_commitment" in cfg:
            j.witness_commitment = cfg["witness_commitment"]
        for k, v in cfg.get("closures", {}).items():
            j.closures[k] = copy.deepcopy(v)
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
        session_token_map: dict[str, str] | None = None,
    ) -> "FencedJournal":
        """Reconstruct a fresh FencedJournal strictly by replaying persisted journal entries (ZERO asserts; H-8).

        Verifies hash-chain integrity and binds external CAS witness state (`witness_pos`,
        `witness_commitment`, `write_token_active`) so `check_continuity()` detects truncated
        rollbacks (`JOURNAL_LOST`), equal-position forks (`JOURNAL_LOST`), and stale write tokens
        (`JOURNAL_FENCED`). Restores closures, nonces, unsettled reservations, terminal invocations,
        verified cached receipts, quota balances, `seconds:*` watermarks, sessions, and migrations.
        """
        j = cls(journal_id)
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
                j.append(e["kind"], e["body"])
            except Exception:
                j.store_readable = False
                break
        # Bind external CAS witness snapshot (if provided) AFTER replay so check_continuity() verifies it!
        if witness_pos is not None:
            j.witness_pos = int(witness_pos)
        if witness_commitment is not None:
            j.witness_commitment = str(witness_commitment)
        if session_token_map:
            for sid, thash in session_token_map.items():
                if sid in j.sessions_by_id:
                    j.sessions_by_id[sid]["token_sha256"] = thash
                    j.sessions[thash] = j.sessions_by_id[sid]
        return j

    def check_continuity(self) -> str | None:
        """Check SPEC-06 §6 continuity precedence."""
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
    ) -> dict[str, Any]:
        """Append a schema-valid ClosureSubject closure entry (SPEC-06 §6, H-4)."""
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

    def lookup_closure(self, subject: dict[str, Any], legacy_key: str | None = None) -> dict[str, Any] | None:
        ckey = _closure_subject_key(subject)
        if ckey in self.closures:
            return self.closures[ckey]
        if legacy_key is not None and legacy_key in self.closures:
            return self.closures[legacy_key]
        return None

    def append(self, kind: str, body: dict[str, Any]) -> dict[str, Any]:
        c_before = self.commitment
        entry = {
            "body": copy.deepcopy(body),
            "journal_id": self.journal_id,
            "kind": kind,
            "pos": self.pos + 1,
            "prev_commitment": c_before,
            "type": "seallink-journal-entry/1",
        }
        c_after = sl.journal_commit_step(c_before, entry)
        self.pos += 1
        self.commitment = c_after
        self.witness_pos = self.pos
        self.witness_commitment = c_after
        self.entries.append(entry)
        # Update materialized indices
        if kind == "closure":
            if "subject" in body and isinstance(body["subject"], dict):
                ckey = _closure_subject_key(body["subject"])
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
            self.unsettled_reservations[inv_id] = {
                "grant_id": body["grant_id"],
                "invocation_id": inv_id,
                "recorded_at": body.get("recorded_at", 0),
                "reservations": copy.deepcopy(lines),
            }
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
            if rsha and rsha in self.receipt_store:
                try:
                    if sl.content_addr(self.receipt_store[rsha]) == rsha:
                        self.receipts[inv_id] = copy.deepcopy(self.receipt_store[rsha])
                except Exception:
                    pass
        elif kind == "single-use-consumed":
            inv_id = body["invocation_id"]
            rsha = body.get("receipt_sha256")
            self.unsettled_reservations.pop(inv_id, None)
            self.terminal_invocations[inv_id] = {"outcome": "executed", "receipt_sha256": rsha}
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
            self.sessions_by_id[sid] = updated
            if "token_sha256" in updated:
                self.sessions[updated["token_sha256"]] = updated
        elif kind == "migration-applied":
            self.migrations_applied.add(body["migration_id"])
        return {"entry": entry, "c_before": c_before, "c_after": c_after}


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
        return 36000 if self.network == "main" else 30

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
        """Select current active name record, or a pinned historical registration lineage for at_height lookups."""
        cur = self.get_name(name)
        if not historical or expected_registration is None:
            return cur
        if cur is not None and cur.get("registration") == expected_registration:
            return cur
        for cand in self.raw.get("name_registrations", {}).get(name, []):
            if isinstance(cand, dict) and cand.get("registration") == expected_registration:
                return cand
        return cur

    def get_tx(self, txid: str) -> dict[str, Any] | None:
        return self.raw.get("txs", {}).get(txid)

    def get_output(self, txid: str, vout: int) -> dict[str, Any] | None:
        tx = self.get_tx(txid)
        if not tx:
            return None
        return tx.get("outputs", {}).get(str(vout)) or tx.get("outputs", {}).get(vout)


class Tier1Verifier:
    """Reference Verifier Core implementing SPEC-01 through SPEC-07."""

    def __init__(
        self,
        pinned_network: str = "main",
        pinned_genesis: str = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
        operator_min_depth: int = 1,
        allow_window_only: bool = False,
        trusted_origin_issuers: set[str] | None = None,
        enforce_schemas: bool = True,
        require_jsonschema: bool = True,
        max_history_steps: int = 500,
        require_observation_bracket: bool = False,
    ) -> None:
        self.pinned_network = pinned_network
        self.pinned_genesis = pinned_genesis
        self.operator_min_depth = operator_min_depth
        self.allow_window_only = allow_window_only
        self.trusted_origin_issuers = set(trusted_origin_issuers) if trusted_origin_issuers is not None else set()
        self.enforce_schemas = enforce_schemas
        self.require_jsonschema = require_jsonschema
        self.max_history_steps = max_history_steps
        self.require_observation_bracket = require_observation_bracket

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
            type_max = reg[obj_type]["max_bytes"]
            if len(raw) > type_max:
                return False, "WIRE_SIZE"
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
                if isinstance(where, dict) and any(not isinstance(pred, dict) or not sl.validate_predicate(pred) for pred in where.values()):
                    return "WIRE_CONSTRAINT"
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
                    exp_rec_spk, _ = sl.compile_script_policy({"kind": "branch", "template": "both_of_2", "keys": {"a": nr["disposer_pk"], "b": nr["arbiter_pk"]}})
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
        # If rich opreturns[] list is present (from nc_rpc_adapter), enforce strictly 1 zero-value SLNK frame!
        if "opreturns" in tx and isinstance(tx["opreturns"], list):
            slnk_frames = []
            for item in tx["opreturns"]:
                if not isinstance(item, dict):
                    continue
                spk_hex = item.get("script_pubkey_hex", "")
                if spk_hex.startswith("6a"):
                    try:
                        sb = bytes.fromhex(spk_hex)
                    except ValueError:
                        continue
                    if sb[2:6] == b"SLNK":
                        slnk_frames.append(item)
            if len(slnk_frames) != 1:
                return None
            if slnk_frames[0].get("value_sat", 0) != 0:
                return None
            opret_hex = slnk_frames[0]["script_pubkey_hex"]
        else:
            opret_hex = tx.get("opreturn_hex")
            if not opret_hex:
                return None
            if tx.get("opreturn_value_sat", 0) != 0:
                return None
        try:
            dec = sl.decode_opreturn(bytes.fromhex(opret_hex))
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
        if isinstance(ob, dict) and ob.get("consistent") is False:
            return False
        rb = c.get("rebracket_tip")
        if not rb:
            return not self.require_observation_bracket
        return rb.get("height") == chain.tip_height and rb.get("hash") == chain.tip_hash

    def check_chain_observation(self, chain: ChainView, risk_class: int = 1) -> str | None:
        c = chain.raw
        # Step 4a: Snapshot bracket consistency FIRST (before peer comparison! SPEC-02 §4, M-1, R1-B)
        if (self.require_observation_bracket or c.get("observation_bracket") is not None) and not self._is_bracket_consistent(chain):
            return "CHAIN_OBSERVATION_VOID"
        # Step 4b: Chain/genesis pin
        if chain.network != self.pinned_network or chain.genesis != self.pinned_genesis:
            return "CHAIN_MISMATCH"
        # Step 4c: Reading node health (!IBD, txindex=1, header lag <= LAG)
        lag_limit = c.get("lag_limit", 1)
        if c.get("in_ibd", False) or not c.get("txindex", True) or not c.get("node_reachable", True):
            return "CHAIN_UNHEALTHY"
        best_hdr = c.get("best_header_height", chain.tip_height)
        if best_hdr - chain.tip_height > lag_limit:
            return "CHAIN_UNHEALTHY"
        # Step 4d: Require >= 1 healthy independent comparison peer; single disagreeing peer vetoes
        healthy_peers = [p for p in c.get("comparison_peers", []) if isinstance(p, dict) and p.get("healthy", True)]
        if not healthy_peers:
            return "CHAIN_UNHEALTHY"
        for peer in healthy_peers:
            if peer.get("height", chain.tip_height) > chain.tip_height:
                return "CHAIN_NODE_DISAGREEMENT"
            if peer.get("hash_at_tip", chain.tip_hash) != chain.tip_hash:
                return "CHAIN_NODE_DISAGREEMENT"
        # Step 4e: Monotonic UTC clock watermark & future header bound S (also reject non-operational clock on main, A-9)
        now = chain.now
        watermark = c.get("clock_watermark", 0)
        if now < watermark or (chain.network == "main" and c.get("clock_source") == "regtest_deterministic"):
            return "CHAIN_CLOCK_ERROR"
        hdr_time = c.get("tip_header_time", now - 60)
        future_s = c.get("future_bound_s", 600)
        if hdr_time - now > future_s:
            return "CHAIN_CLOCK_ERROR"
        # Step 4f: Dual tip-age freshness (evaluated at unified decision clock & closing bracket)
        first_sight = c.get("tip_first_sight", hdr_time)
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
        """Evaluate standard revocable seal (SPEC-02 §6.1)."""
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
        """Evaluate single_use_1_of_2 seal deriving spend branch strictly from witness (SPEC-02 §6.2)."""
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
        if branch == 1 or out.get("absent_from_utxo") or branch != 0:
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

        # Branch 0 (grantee): verify use_txid match & OP_RETURN 0x11 == invocation_content_addr
        assert spend_tx is not None
        if (use_txid is not None and spent_by != use_txid) or self._decode_opreturn_tx(
            spend_tx, require_confirmed=False, expected_action="0x11", expected_commitment=invocation_content_addr
        ) is None:
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
        valid_val = ok_j and (
            not self.enforce_schemas
            or validate_against_schema("schemas/name-value.schema.json", val_obj, require_jsonschema=self.require_jsonschema) is None
        )
        if valid_val:
            used_keys: set[str] = set()
            link = val_obj.get("link", {})
            if isinstance(link, dict):
                for r in ("grant", "cred", "notary"):
                    rk = link.get(r)
                    if isinstance(rk, str):
                        if not sl.is_valid_xonly_pubkey(rk) or rk in used_keys:
                            valid_val = False
                            break
                        used_keys.add(rk)
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
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Resolve a Namecoin name strictly by walking its structured updates[] history (B-9, B-12, A-5, A-7)."""
        rec = chain.get_name_for_registration(name, expected_registration, historical=(at_height is not None or historical))
        if not rec:
            return None, "NAME_NOT_FOUND"
        if expected_registration is not None and rec.get("registration") != expected_registration:
            return None, "NAME_OWNER_MISMATCH"
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

        # Derive SIGHASH_ALL owner authorship across ALL updates up to target_idx AND confirm
        # the CURRENT owner authored target_upd itself (not a departing previous owner in a transfer; SL-LDGR-007, B-9, A-7)
        if require_writer:
            writer_ok = (
                target_idx > 0
                and all(self._is_owner_authored_update(updates[idx], updates[idx - 1]) for idx in range(1, target_idx + 1))
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

        # History-based permanent origin detection across ALL confirmed updates (B-12)
        hist_origins: set[str] = set()
        for u in updates:
            try:
                parsed_u = sl.parse_name_output(bytes.fromhex(u["output_script_hex"]))
                ok_uj, u_vobj = sl.jcs_validate(parsed_u["value"].encode("utf-8"), max_bytes=520)
                if ok_uj and isinstance(u_vobj.get("link"), dict):
                    oid_u = u_vobj["link"].get("origin")
                    if isinstance(oid_u, str):
                        hist_origins.add(oid_u)
            except (ValueError, KeyError, TypeError):
                continue
        if len(hist_origins) > 1:
            return None, "ORIGIN_UNVERIFIED"
        historical_origin_id = next(iter(hist_origins)) if hist_origins else None

        # Derive 0x0b compromise breaks & 0x10 recovery cancels from owner-authored updates in history (H-22, H-29)
        compromised_breaks: list[dict[str, Any]] = []
        recovery_cancels: list[dict[str, Any]] = []
        for idx in range(1, len(updates)):
            u = updates[idx]
            if not self._is_owner_authored_update(u, updates[idx - 1]):
                continue
            opret_hex = u.get("opreturn_hex")
            if not opret_hex:
                continue
            try:
                dec = sl.decode_opreturn(bytes.fromhex(opret_hex))
            except ValueError:
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
                    "inclusion_height": u["confirmed_height"],
                    "name_input": {"txid": pinp["txid"], "vout": pinp["vout"]},
                    "prev_owner_spk_hex": prev_owner_spk,
                })
            elif dec["action"] == "0x10":
                recovery_cancels.append({
                    "binding_id": dec["commitment"],
                    "confirmed_height": u["confirmed_height"],
                    "prev_owner_spk_hex": prev_owner_spk,
                })

        return {
            **rec,
            "owner_policy": target_upd["owner_policy"],
            "_value_obj": val_obj,
            "_target_update_idx": target_idx,
            "_target_confirmed_height": target_h,
            "_name": name,
            "_historical_origin_id": historical_origin_id,
            "_compromised_breaks": compromised_breaks,
            "_recovery_cancels": recovery_cancels,
            "_mempool_updates": list(rec.get("mempool_updates", [])),
        }, None

    def resolve_role_policy(
        self,
        name_rec: dict[str, Any],
        role: str,
        presented_role_policy: dict[str, Any] | None = None,
        recent_block_height: int | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Resolve link.<role> and derive owner_policy + role continuity across updates[] & mempool since recent_block_height (B-9, A-5, H-25)."""
        updates = name_rec.get("updates", [])
        target_name = name_rec.get("_name", "")
        if recent_block_height is not None and updates:
            baseline_entry = None
            baseline_owner_spk: bytes | None = None
            has_baseline = False
            owner_changed = False
            role_changed = False
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
                if uh <= recent_block_height:
                    baseline_entry = cur_entry
                    baseline_owner_spk = cur_ospk
                    has_baseline = True
                elif has_baseline:
                    if cur_ospk != baseline_owner_spk:
                        owner_changed = True
                    elif cur_entry != baseline_entry:
                        role_changed = True
            # Check locally observed mempool OP_NAME_UPDATE accelerator for role/owner change (A-5)
            last_confirmed = updates[-1]
            for mu in name_rec.get("_mempool_updates", []):
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

    def _is_policy_compromised_at(
        self,
        nrec: dict[str, Any],
        issuer_pin: dict[str, Any],
        role: str,
        resolved_policy: dict[str, Any],
        anchor_height: int,
        chain: ChainView,
    ) -> bool:
        """Reconstruct seallink-credential-break/1 from on-chain 0x0b frames and check exact owner & policy scope (H-22)."""
        if role not in ("cred", "notary"):
            return False
        issuer_name_pin = {
            "name": issuer_pin["name"],
            "owner_policy": issuer_pin["owner_policy"],
            "registration": issuer_pin["registration"],
        }
        try:
            exp_owner_spk_hex = sl.compile_script_policy(issuer_pin["owner_policy"])[0].hex()
        except (ValueError, KeyError, TypeError):
            return False
        norm_pol = _normalize_policy(resolved_policy)
        min_hc: int | None = None
        for brk in nrec.get("_compromised_breaks", []):
            if brk["h_c"] > brk["inclusion_height"]:
                continue
            if brk.get("prev_owner_spk_hex") is not None and brk["prev_owner_spk_hex"] != exp_owner_spk_hex:
                continue
            cand_break = {
                "compromised_policy": norm_pol,
                "genesis": chain.genesis,
                "h_c": brk["h_c"],
                "issuer": issuer_name_pin,
                "name_input": brk["name_input"],
                "role": role,
                "type": "seallink-credential-break/1",
            }
            if sl.signing_digest(cand_break).hex() == brk["commitment"]:
                min_hc = brk["h_c"] if min_hc is None else min(min_hc, brk["h_c"])
        return min_hc is not None and anchor_height >= min_hc

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
    ) -> str | None:
        """Authoritatively verify an object's signatures against issuer's link.<role> + policy-scoped 0x0b h_c cutoff."""
        nrec, nerr = self.resolve_name(
            issuer_pin["name"],
            chain,
            expected_owner_policy=issuer_pin["owner_policy"],
            expected_registration=issuer_pin["registration"],
            require_writer=True,
            require_history=True,
            at_height=None if resolve_at_tip else anchor_height,
        )
        if nerr:
            return nerr
        assert nrec is not None
        rpol, rerr = self.resolve_role_policy(nrec, role, issuer_pin.get("role_policy"))
        if rerr:
            return rerr
        assert rpol is not None
        if self._is_policy_compromised_at(nrec, issuer_pin, role, rpol, anchor_height, chain):
            if journal is not None:
                journal.record_closure(
                    {"name": issuer_pin["name"], "registration": issuer_pin["registration"], "role": role, "subject_kind": "role"},
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
        for rname in ("grant", "cred", "notary"):
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
        return man, None

    def verify_auth_challenge(
        self,
        challenge_env: dict[str, Any],
        chain: ChainView,
        journal: FencedJournal,
        service_id: str,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
    ) -> VerifierResult:
        ok, res = self._verify_object_wire(challenge_env, expected_type="seallink-auth-challenge/1")
        if not ok:
            return VerifierResult("REFUSE", res)
        p = res["payload"]
        nonce = p["nonce"]
        rec = journal.auth_nonces.get(nonce)
        # Service-recorded service_id, issued_at, expires_at exact equality check (H-26)
        if (
            p["service_id"] != service_id
            or rec is None
            or rec.get("used", False)
            or rec.get("service_id") != service_id
            or ("issued_at" in rec and p["issued_at"] != int(rec["issued_at"]))
            or ("expires_at" in rec and p["expires_at"] != int(rec["expires_at"]))
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
            nrec, nerr = self.resolve_name(p["name"], chain)
            if nerr:
                return VerifierResult("REFUSE", nerr)
            assert nrec is not None
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
        return VerifierResult("ADMIT", None, outcome="executed")

    def verify_auth_upgrade(
        self,
        upgrade_env: dict[str, Any],
        expected_service_id: str,
        expected_provisional_auth_pubkey: str,
        chain: ChainView,
        journal: FencedJournal,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
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
        nrec, nerr = self.resolve_name(p["name"], chain)
        if nerr:
            return VerifierResult("REFUSE", nerr)
        assert nrec is not None
        if nrec.get("registration", {}).get("txid") != p["firstupdate_txid"]:
            return VerifierResult("REFUSE", "NAME_REREGISTERED")
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
        if not (p["iat"] <= chain.now < p["exp"]):
            return VerifierResult("REFUSE", "INVOKE_TIME_INVALID")
        if dl_res.get("owner") != p["owner"]:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        if owner_manifest is not None:
            dev_set_pin = owner_manifest.get("sets", {}).get("devices")
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

    def _check_emancipation_handover(
        self,
        ward_name: str,
        registration: dict[str, Any],
        initial_owner_policy: dict[str, Any],
        subject_new_owner_policy: dict[str, Any] | None,
        chain: ChainView,
        *,
        active_binding: dict[str, Any] | None = None,
    ) -> bool:
        """Derive SL-ORIG-011 emancipation handover strictly from ward name.updates[] (Path A & Path B, B-13)."""
        init_spk, _ = sl.compile_script_policy(initial_owner_policy)
        target_spk = sl.compile_script_policy(subject_new_owner_policy)[0] if subject_new_owner_policy else None
        # Case 1: Confirmed handover transfer within the current registration lineage
        rec = chain.get_name_for_registration(ward_name, registration, historical=False)
        if rec and rec.get("registration") == registration and isinstance(rec.get("updates"), list):
            updates = rec["updates"]
            # If the registration itself was created fresh by dual_party_delayed recovery (seq >= 2) with fresh owner_policy
            if active_binding is not None and active_binding.get("seq", 1) >= 2 and len(updates) >= 2:
                try:
                    b_spk, _ = sl.compile_script_policy(active_binding["owner_policy"])
                except (ValueError, KeyError, TypeError):
                    b_spk = b""
                if b_spk and b_spk != init_spk and (target_spk is None or b_spk == target_spk):
                    for j in range(1, len(updates)):
                        if self._is_owner_authored_update(updates[j], updates[j - 1]):
                            try:
                                s_spk, _ = sl.compile_script_policy(updates[j]["owner_policy"])
                            except (ValueError, KeyError, TypeError):
                                continue
                            if s_spk == b_spk:
                                return True
            if len(updates) >= 3:
                for idx in range(1, len(updates)):
                    u_xfer = updates[idx]
                    try:
                        u_spk, _ = sl.compile_script_policy(u_xfer["owner_policy"])
                    except (ValueError, KeyError, TypeError):
                        continue
                    if u_spk == init_spk:
                        continue
                    if target_spk is not None and u_spk != target_spk:
                        continue
                    if not self._is_owner_authored_update(u_xfer, updates[idx - 1]):
                        continue
                    # Require at least one subsequent owner-authored NAME_UPDATE signed by the subject's new owner_policy
                    for j in range(idx + 1, len(updates)):
                        u_subj = updates[j]
                        if self._is_owner_authored_update(u_subj, updates[j - 1]):
                            try:
                                s_spk, _ = sl.compile_script_policy(u_subj["owner_policy"])
                            except (ValueError, KeyError, TypeError):
                                continue
                            if s_spk == u_spk:
                                return True
        return False

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
        """Verify 0x0e spends pending_outpoint via the CSV-unlocked <guardian> branch (both OP_IF selectors FALSE, R3 H4)."""
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
            # If nSequence is present on input, verify BIP-68 block-based relative locktime >= delay_blocks
            if "sequence" in inp:
                seq = int(inp["sequence"])
                if (seq & (1 << 31)) != 0 or (seq & (1 << 22)) != 0 or (seq & 0xFFFF) < delay_blocks:
                    return False
            wit = inp.get("witness")
            if not isinstance(wit, list) or not wit:
                return False
            # If full P2WSH witness stack is present (len == 4: [sig, inner_sel, outer_sel, ws]), verify exact selectors!
            if wit[-1] == exp_ws_hex:
                if len(wit) != 4 or not Tier1Verifier._is_der_sighash_all(wit[0]):
                    return False
                try:
                    return not (sl.cast_to_bool(bytes.fromhex(wit[-2])) or sl.cast_to_bool(bytes.fromhex(wit[-3])))
                except ValueError:
                    return False
            # Compact test-fixture witness (without ws): still require SIGHASH_ALL sig
            return any(Tier1Verifier._is_der_sighash_all(item) for item in wit)
        return False

    def verify_origin_and_status(
        self,
        origin_bundle: dict[str, Any],
        chain: ChainView,
        *,
        assert_binding_id: str | None = None,
        journal: FencedJournal | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Walk origin/1, name-binding/1, status_seal, majority, name_recovery spine, roster_seal, and per-slot states."""
        origin_env = origin_bundle.get("origin") if isinstance(origin_bundle, dict) else None
        if not origin_env:
            return None, "ORIGIN_UNVERIFIED"
        ok_o, o_res = self._verify_object_wire(origin_env, expected_type="seallink-origin/1")
        if not ok_o:
            return None, o_res
        op = o_res["payload"]
        if op["network"] != self.pinned_network or op["genesis"] != self.pinned_genesis:
            return None, "CHAIN_MISMATCH"
        # Fail-closed trusted_origin_issuers (empty set trusts NOBODY per SL-ORIG-002 item 1)
        if op["issuer"]["name"] not in self.trusted_origin_issuers:
            return None, "ORIGIN_UNVERIFIED"
        if "card" in origin_bundle:
            ok_cd, _ = self._verify_object_wire(origin_bundle["card"], expected_type="seallink-card/1")
            if not ok_cd or origin_bundle["card"].get("kind") != op["origin_class"]:
                return None, "ORIGIN_UNVERIFIED"
        if "guardian_policy" in op:
            ok_c, code_c = sl.check_guardian_policy_consistency(op["guardian_policy"])
            if not ok_c:
                return None, code_c

        # Verify origin 0x09 anchor & confirmation depth
        origin_txid = origin_bundle.get("origin_anchor_txid")
        origin_tx = chain.get_tx(origin_txid) if origin_txid else None
        dec_o = self._decode_opreturn_tx(origin_tx, expected_action="0x09", expected_commitment=sl.content_addr(origin_env))
        if dec_o is None:
            return None, "ORIGIN_UNVERIFIED"
        assert origin_tx is not None
        h_origin = origin_tx["confirmed_height"]
        if chain.tip_height - h_origin + 1 < self.operator_min_depth:
            return None, "CHAIN_DEPTH_INSUFFICIENT"
        origin_id = sl.object_id(op)

        # Authoritatively bind origin/1 signature to issuer's link.cred at h_origin + policy-scoped 0x0b h_c cutoff!
        iss_err = self.verify_issuer_role_at_height(op["issuer"], origin_env, "cred", h_origin, chain, journal=journal)
        if iss_err:
            if iss_err in ("CRED_ISSUER_CLOSED", "WIRE_SIGNATURE"):
                return None, iss_err
            return None, "ORIGIN_UNVERIFIED"

        # Verify initial NameBinding (0x0c) + binding_seal spend + intended_* + h_origin < h_firstupdate (B-5, R3 B3)
        binding = origin_bundle.get("name_binding")
        bind_txid = origin_bundle.get("name_binding_txid")
        if (
            binding is None
            or not bind_txid
            or not self._verify_object_wire(binding, expected_type="seallink-name-binding/1")[0]
            or binding.get("origin_id") != origin_id
            or binding.get("seq") != 1
        ):
            return None, "ORIGIN_BINDING_INVALID"
        if binding["network"] != self.pinned_network or binding["genesis"] != self.pinned_genesis:
            return None, "CHAIN_MISMATCH"
        # Match claims.intended_name & claims.intended_owner_policy + binding_seal spend + h_origin < h_firstupdate (B-5, R3 B3)
        int_spk, _ = sl.compile_script_policy(op["claims"]["intended_owner_policy"])
        bnd_spk, _ = sl.compile_script_policy(binding["owner_policy"])
        bs_spk, _ = sl.compile_script_policy(op["binding_seal"]["script_policy"])
        bind_tx = chain.get_tx(bind_txid)
        dec_b = self._decode_opreturn_tx(bind_tx, expected_action="0x0c", expected_commitment=sl.object_id(binding))
        if (
            binding["name"] != op["claims"]["intended_name"]
            or bnd_spk != int_spk
            or dec_b is None
            or bind_tx["confirmed_height"] <= h_origin
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
        b_nrec = chain.get_name_for_registration(binding["name"], binding["registration"], historical=True)
        if b_nrec is not None and isinstance(b_nrec.get("updates"), list) and b_nrec["updates"]:
            h_fu = b_nrec["updates"][0].get("confirmed_height")
            if h_fu is None or h_fu <= h_origin or bind_tx["confirmed_height"] < h_fu:
                return None, "ORIGIN_BINDING_INVALID"
        reg_key = _outpoint_key(binding["registration"])
        existing_oid = chain.raw.get("registered_bindings", {}).get(reg_key)
        if existing_oid is not None and existing_oid != origin_id:
            return None, "ORIGIN_BINDING_INVALID"

        # Expected exact NamePins for institutional authorities (B-14)
        exp_cap_auth = op.get("capacity_authority", op["issuer"])
        exp_end_auth = op.get("end_authority", exp_cap_auth)
        allowed_guard_issuers = [op["issuer"]] + ([op["capacity_authority"]] if "capacity_authority" in op else [])

        # Walk status_seal spine FIRST so emancipation trigger is known for D-2 recovery 0x10 lockout!
        cur_status_seal = op["status_seal"]
        emancipated = False
        emancipated_by_majority = False
        subject_new_owner_policy: dict[str, Any] | None = None
        cap_rec = origin_bundle.get("capacity_record")
        end_rec = origin_bundle.get("end_record")
        seen_status_ops: set[str] = set()
        status_terminal_ok = False
        while True:
            cur_s_key = _outpoint_key(cur_status_seal)
            cur_s_spk, _ = sl.compile_script_policy(cur_status_seal["script_policy"])
            st_tx = chain.get_tx(cur_status_seal["txid"])
            sout = chain.get_output(cur_status_seal["txid"], cur_status_seal["vout"])
            if cur_s_key in seen_status_ops or len(seen_status_ops) == 256 or not st_tx or st_tx.get("confirmed_height") is None or not sout or sout.get("script_pubkey_hex") != cur_s_spk.hex():
                return None, "ORIGIN_STATUS_INCOMPLETE"
            seen_status_ops.add(cur_s_key)
            spend_txid = sout.get("spent_by_txid")
            if not spend_txid:
                if not sout.get("absent_from_utxo"):
                    status_terminal_ok = True
                break
            stx = chain.get_tx(spend_txid)
            dec_s = self._decode_opreturn_tx(stx, expected_action="0x09")
            if dec_s is None or (stx.get("inputs") and not self._tx_spends_outpoint(stx, cur_status_seal)):
                break
            assert stx is not None
            h_spend = stx["confirmed_height"]
            if chain.tip_height - h_spend + 1 < self.operator_min_depth:
                return None, "CHAIN_DEPTH_INSUFFICIENT"
            if end_rec is not None and sl.content_addr(end_rec) == dec_s["commitment"]:
                ok_e, _ = self._verify_object_wire(end_rec, expected_type="seallink-end/1")
                if not ok_e or end_rec["payload"]["origin_id"] != origin_id or not _name_pin_equal(end_rec["payload"]["issuer"], exp_end_auth):
                    break
                ep = end_rec["payload"]
                if ep["network"] != self.pinned_network or ep["genesis"] != self.pinned_genesis:
                    return None, "CHAIN_MISMATCH"
                e_iss_err = self.verify_issuer_role_at_height(ep["issuer"], end_rec, "cred", h_spend, chain, journal=journal)
                if e_iss_err:
                    return None, "CRED_ISSUER_CLOSED" if e_iss_err == "CRED_ISSUER_CLOSED" else "ORIGIN_STATUS_INCOMPLETE"
                if journal is not None:
                    journal.record_closure(
                        {"subject_id": origin_id, "subject_kind": "origin"},
                        "SUBJECT_ENDED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                        spend_txid=spend_txid,
                    )
                return None, "SUBJECT_ENDED"
            if cap_rec is not None and sl.content_addr(cap_rec) == dec_s["commitment"]:
                ok_cp, _ = self._verify_object_wire(cap_rec, expected_type="seallink-capacity/1")
                if not ok_cp or cap_rec["payload"]["origin_id"] != origin_id or not _name_pin_equal(cap_rec["payload"]["issuer"], exp_cap_auth):
                    break
                cp = cap_rec["payload"]
                if cp["network"] != self.pinned_network or cp["genesis"] != self.pinned_genesis:
                    return None, "CHAIN_MISMATCH"
                c_iss_err = self.verify_issuer_role_at_height(cp["issuer"], cap_rec, "cred", h_spend, chain, journal=journal)
                if c_iss_err:
                    return None, "CRED_ISSUER_CLOSED" if c_iss_err == "CRED_ISSUER_CLOSED" else "ORIGIN_STATUS_INCOMPLETE"
                nxt_out = chain.get_output(spend_txid, cp["next_status_vout"])
                nxt_spk, _ = sl.compile_script_policy(cp["next_status_policy"])
                if nxt_out and nxt_out.get("script_pubkey_hex") == nxt_spk.hex():
                    emancipated = True
                    subject_new_owner_policy = cp["subject_new_owner_policy"]
                    cur_status_seal = {"txid": spend_txid, "vout": cp["next_status_vout"], "script_policy": cp["next_status_policy"]}
                    continue
            break
        if not status_terminal_ok:
            return None, "ORIGIN_STATUS_INCOMPLETE"

        # Check majority_commitment (MANDATORY off-chain disclosure ONLY when committed in origin.claims! B-13, SL-ORIG-010)
        opened_majority = origin_bundle.get("opened_majority_unix")
        salt_m = origin_bundle.get("majority_salt_hex")
        if "majority_commitment" in op["claims"]:
            if opened_majority is None or not isinstance(salt_m, str):
                return None, "ORIGIN_STATUS_INCOMPLETE"
            try:
                got_mc = sl.clause_commit(salt_m, {"majority_unix": opened_majority})
            except ValueError:
                got_mc = None
            if got_mc != op["claims"]["majority_commitment"]:
                return None, "ORIGIN_UNVERIFIED"
            interval = chain.raw.get("credible_utc_interval")
            if interval is None or not isinstance(interval, list) or len(interval) != 2:
                return None, "GUARDIAN_TIME_BOUNDARY"
            t_low, t_high = interval[0], interval[1]
            mtp = chain.raw.get("tip_median_time_past")
            if (t_low < opened_majority <= t_high) or (t_low < opened_majority and mtp is not None and int(mtp) >= opened_majority):
                return None, "GUARDIAN_TIME_BOUNDARY"
            if t_low >= opened_majority:
                emancipated = True
                emancipated_by_majority = True

        # Walk full name_recovery continuation spine (SPEC-04 §6, Decisions D-1 & D-2, G-6, H-28, H-29)
        active_binding = binding
        active_recovery_seal: dict[str, Any] | None = None
        recovery_events: list[dict[str, Any]] = []
        recovery_burned = False
        nr = op["name_recovery"]
        rec_candidates_list: list[dict[str, Any]] = list(origin_bundle.get("recovery_bindings", []))
        if origin_bundle.get("pending_recovery_binding") is not None:
            rec_candidates_list.append(origin_bundle["pending_recovery_binding"])
        rec_by_id: dict[str, dict[str, Any]] = {}
        for rb in rec_candidates_list:
            ok_rb, _ = self._verify_object_wire(rb, expected_type="seallink-name-binding/1")
            if ok_rb:
                rec_by_id[sl.object_id(rb)] = rb

        if nr["mode"] == "none":
            if rec_candidates_list:
                return None, "RECOVERY_FORBIDDEN"
        else:
            cur_rec_seal = nr["recovery_seal"]
            exp_rec_pol = {"kind": "branch", "template": "both_of_2", "keys": {"a": nr["disposer_pk"], "b": nr["arbiter_pk"]}}
            exp_rec_spk, _ = sl.compile_script_policy(exp_rec_pol)
            active_recovery_seal = cur_rec_seal
            seen_rec_ops: set[str] = set()
            while True:
                cur_r_key = _outpoint_key(cur_rec_seal)
                r_tx_cre = chain.get_tx(cur_rec_seal["txid"])
                rout = chain.get_output(cur_rec_seal["txid"], cur_rec_seal["vout"])
                if cur_r_key in seen_rec_ops or len(seen_rec_ops) == 256 or not r_tx_cre or r_tx_cre.get("confirmed_height") is None or not rout or rout.get("script_pubkey_hex") != exp_rec_spk.hex():
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                seen_rec_ops.add(cur_r_key)
                rspend = rout.get("spent_by_txid")
                if not rspend:
                    if rout.get("absent_from_utxo"):
                        # Decision D-1: malformed / unattributable recovery_seal spend burns ONLY recovery line; B_k survives!
                        recovery_burned = True
                        recovery_events.append({"outcome": "recovery_burned"})
                    break
                rtx = chain.get_tx(rspend)
                dec_r = self._decode_opreturn_tx(rtx, expected_action="0x0c")
                if dec_r is None or (rtx is not None and rtx.get("inputs") and not self._tx_spends_outpoint(rtx, cur_rec_seal)):
                    # Decision D-1: malformed spend of recovery_seal burns ONLY recovery line; B_k survives!
                    recovery_burned = True
                    recovery_events.append({"outcome": "recovery_burned", "spend_txid": rspend})
                    break
                assert rtx is not None
                cand_id = dec_r["commitment"]
                cand = rec_by_id.get(cand_id)
                bad_cand = (
                    cand is None
                    or cand["origin_id"] != origin_id
                    or cand["network"] != self.pinned_network
                    or cand["genesis"] != self.pinned_genesis
                    or cand.get("supersedes_binding_id") != sl.object_id(active_binding)
                    or cand["seq"] != active_binding["seq"] + 1  # G-6: exact seq = prev + 1
                    or "next_recovery_vout" not in cand
                    or "next_recovery_policy" not in cand
                )
                if not bad_cand:
                    assert cand is not None
                    try:
                        bad_cand = sl.compile_script_policy(cand["next_recovery_policy"])[0] != exp_rec_spk
                    except (ValueError, KeyError, TypeError):
                        bad_cand = True
                if bad_cand:
                    recovery_burned = True
                    recovery_events.append({"outcome": "recovery_burned", "spend_txid": rspend})
                    break
                assert cand is not None
                next_seal_out = chain.get_output(rspend, cand["next_recovery_vout"])
                if not next_seal_out or next_seal_out.get("script_pubkey_hex") != exp_rec_spk.hex():
                    recovery_burned = True
                    recovery_events.append({"outcome": "recovery_burned", "spend_txid": rspend})
                    break
                next_rec_seal = {
                    "txid": rspend,
                    "vout": cand["next_recovery_vout"],
                    "script_policy": cand["next_recovery_policy"],
                }
                h_rec = rtx["confirmed_height"]
                deadline = h_rec + nr["delay_blocks"]
                # Check derived owner-authored 0x10 RECOVERY_CANCEL strictly on active_binding's pinned registration (H-29)
                # AND enforce D-2 former-guardian 0x10 lockout once emancipated (T reached or capacity/1 confirmed)!
                former_guardian_locked_out = (
                    emancipated
                    and "guardian_policy" in op
                    and sl.compile_script_policy(active_binding["owner_policy"])[0] == int_spk
                )
                cancelled = False
                if not former_guardian_locked_out:
                    old_nrec, _ = self.resolve_name(
                        active_binding["name"],
                        chain,
                        expected_owner_policy=active_binding["owner_policy"],
                        expected_registration=active_binding["registration"],
                        require_writer=False,
                        require_history=False,
                        historical=True,
                    )
                    if old_nrec is not None:
                        for c_ev in old_nrec.get("_recovery_cancels", []):
                            if c_ev["binding_id"] == cand_id and c_ev["confirmed_height"] < deadline:
                                cancelled = True
                                break
                if cancelled:
                    recovery_events.append({"candidate_id": cand_id, "outcome": "cancelled_restored", "next_recovery_seal": next_rec_seal})
                    if assert_binding_id is not None and assert_binding_id == cand_id:
                        return None, "RECOVERY_FORBIDDEN"
                    cur_rec_seal = next_rec_seal
                    active_recovery_seal = next_rec_seal
                    continue
                if chain.tip_height < deadline:
                    return None, "RECOVERY_FORBIDDEN"
                # Delay elapsed without valid 0x10 cancel -> B_{k+1} promoted!
                prev_id = sl.object_id(active_binding)
                recovery_events.append({"candidate_id": cand_id, "outcome": "promoted", "superseded_id": prev_id, "next_recovery_seal": next_rec_seal})
                if assert_binding_id is not None and assert_binding_id == prev_id:
                    return None, "ORIGIN_BINDING_INVALID"
                active_binding = cand
                cur_rec_seal = next_rec_seal
                active_recovery_seal = next_rec_seal
            if recovery_burned and assert_binding_id is not None and assert_binding_id != sl.object_id(active_binding):
                return None, "RECOVERY_FORBIDDEN"

        if emancipated:
            if not self._check_emancipation_handover(
                active_binding["name"],
                active_binding["registration"],
                op["claims"]["intended_owner_policy"],
                subject_new_owner_policy,
                chain,
                active_binding=active_binding,
            ):
                return None, "GUARDIAN_TRANSFER_PENDING"
            return {
                "origin_id": origin_id,
                "capacity": "autonomous",
                "binding": active_binding,
                "active_recovery_seal": active_recovery_seal,
                "recovery_burned": recovery_burned,
                "recovery_events": recovery_events,
                "emancipated_by_majority": emancipated_by_majority,
            }, None

        if "guardian_policy" not in op:
            return {
                "origin_id": origin_id,
                "capacity": "autonomous",
                "binding": active_binding,
                "active_recovery_seal": active_recovery_seal,
                "recovery_burned": recovery_burned,
                "recovery_events": recovery_events,
            }, None

        # Walk roster_seal chain & per-slot UTXO chains
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
        roster_records_by_caddr = {sl.content_addr(r): r for r in origin_bundle.get("roster_records", [])}
        slot_states: dict[int, dict[str, Any]] = {}
        init_vac_pol = {"kind": "branch", "template": "both_of_2", "keys": {"a": gp["disposer_pk"], "b": gp["arbiter_pk"]}}
        for s in gp["slots"]:
            slot_states[s["slot"]] = {
                "state": "initial_vacant",
                "vacant_outpoint": {"txid": s["vacant_utxo"]["txid"], "vout": s["vacant_utxo"]["vout"]},
                "vacant_policy": s["vacant_utxo"].get("script_policy", init_vac_pol),
                "initial_guardian_commitment": s["initial_guardian_commitment"],
            }

        g_by_caddr = {sl.content_addr(g): g for g in origin_bundle.get("guardian_records", [])}
        g_by_id = {sl.object_id(g["payload"]): g for g in origin_bundle.get("guardian_records", [])}
        init_disclosures = origin_bundle.get("initial_guardian_disclosures", {})
        g_assents_by_target: dict[str, dict[str, Any]] = {}
        for ga in origin_bundle.get("guardian_assents", []):
            if isinstance(ga, dict) and isinstance(ga.get("payload"), dict) and "target_id" in ga["payload"]:
                g_assents_by_target[ga["payload"]["target_id"]] = ga

        def _is_allowed_guard_issuer(iss_pin: dict[str, Any]) -> bool:
            return any(_name_pin_equal(iss_pin, allow) for allow in allowed_guard_issuers)

        def trace_slot(slot_num: int, st: dict[str, Any], roster_ctx: dict[str, Any]) -> dict[str, Any]:
            cur = copy.deepcopy(st)
            exp_vac_spk, _ = sl.compile_script_policy(
                {"kind": "branch", "template": "both_of_2", "keys": {"a": roster_ctx["disposer_pk"], "b": roster_ctx["arbiter_pk"]}}
            )
            for _ in range(256):
                if cur["state"] in ("initial_vacant", "vacant"):
                    op_u = cur["vacant_outpoint"]
                    u_tx = chain.get_tx(op_u["txid"])
                    uout = chain.get_output(op_u["txid"], op_u["vout"])
                    if not u_tx or u_tx.get("confirmed_height") is None or not uout or uout.get("script_pubkey_hex") != exp_vac_spk.hex():
                        cur["state"] = "contested_burned"
                        return cur
                    if not uout.get("spent_by_txid"):
                        if uout.get("absent_from_utxo"):
                            cur["state"] = "contested_burned"
                        return cur
                    stxid = uout["spent_by_txid"]
                    stx = chain.get_tx(stxid)
                    dec = self._decode_opreturn_tx(stx, require_confirmed=True)
                    if dec is None:
                        cur["state"] = "contested_burned"
                        return cur
                    assert stx is not None
                    if stx.get("inputs") and not self._tx_spends_outpoint(stx, op_u):
                        cur["state"] = "contested_burned"
                        return cur
                    h_stx = stx["confirmed_height"]
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
                        if not disc or sl.clause_commit(disc["salt_hex"], gp_rec["guardian"]) != cur["initial_guardian_commitment"]:
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
                        # Compare active_policy keys safely even when disposer_pk is a BranchKeySpec dict!
                        exp_act_pol = {"kind": "branch", "template": "either_of_2", "keys": {"a": pp["keys"]["guardian"], "b": roster_ctx["disposer_pk"]}}
                        try:
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
                    if not stx or stx.get("confirmed_height") is None:
                        return cur
                    dec = self._decode_opreturn_tx(stx, require_confirmed=True)
                    grec = cur["guardian_record"]
                    gp_rec = grec["payload"]
                    gid = sl.object_id(gp_rec)
                    if dec is not None and dec.get("action") == "0x0e" and dec.get("commitment") == gid:
                        # R3 H4: verify height delay, depth, AND CSV guardian witness branch!
                        if stx["confirmed_height"] < cur["pending_height"] + cur["delay_blocks"]:
                            cur["state"] = "contested_burned"
                            return cur
                        if chain.tip_height - stx["confirmed_height"] + 1 < self.operator_min_depth:
                            return cur
                        if stx.get("inputs") and not self._is_0x0e_guardian_csv_branch(
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
                    vout0 = chain.get_output(stxid, 0)
                    # Mempool halt acts immediately -> slot is no longer active!
                    if stx and stx.get("confirmed_height") is not None and vout0 and vout0.get("script_pubkey_hex") == exp_vac_spk.hex():
                        cur = {"state": "vacant", "vacant_outpoint": {"txid": stxid, "vout": 0}}
                        continue
                    cur["state"] = "contested_burned"
                    return cur
                else:
                    return cur
            # Walk depth exhausted without reaching an unspent terminal state -> fail closed (H-28)
            cur["state"] = "contested_burned"
            return cur

        for snum in list(slot_states.keys()):
            slot_states[snum] = trace_slot(snum, slot_states[snum], active_roster)

        # Walk roster_seal transitions (0x0f) (B-14, B-15, H-27, H-28, H-31, H-33)
        seen_roster_ops: set[str] = set()
        while True:
            cur_rk = _outpoint_key(cur_roster_seal)
            exp_r_spk, _ = sl.compile_script_policy(
                {"kind": "branch", "template": "both_of_2", "keys": {"a": active_roster["disposer_pk"], "b": active_roster["arbiter_pk"]}}
            )
            r_cre_tx = chain.get_tx(cur_roster_seal["txid"])
            rout = chain.get_output(cur_roster_seal["txid"], cur_roster_seal["vout"])
            if cur_rk in seen_roster_ops or len(seen_roster_ops) == 256 or not r_cre_tx or r_cre_tx.get("confirmed_height") is None or not rout or rout.get("script_pubkey_hex") != exp_r_spk.hex():
                return None, "ORIGIN_STATUS_INCOMPLETE"
            seen_roster_ops.add(cur_rk)
            rspend = rout.get("spent_by_txid")
            if not rspend:
                if rout.get("absent_from_utxo"):
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                break
            rtx = chain.get_tx(rspend)
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
            if chain.tip_height < roster_eff_h:
                break
            prev_slot_states = slot_states
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
                        new_slot_states[sn] = trace_slot(sn, prev_s, active_roster)
                elif act == "retain_vacant":
                    opk = _outpoint_key(sspec["vacant_outpoint"])
                    prev_v = prev_vacant_by_op.get(opk)
                    if opk in used_carried_ops or not prev_v:
                        new_slot_states[sn] = {"state": "contested_burned"}
                    else:
                        used_carried_ops.add(opk)
                        new_slot_states[sn] = trace_slot(
                            sn, {"state": "vacant", "vacant_outpoint": sspec["vacant_outpoint"]}, active_roster
                        )
                elif act == "new_vacant":
                    nv_out = chain.get_output(rspend, sspec["new_vacant_vout"])
                    nv_spk, _ = sl.compile_script_policy(sspec["new_vacant_policy"])
                    if not nv_out or nv_out.get("script_pubkey_hex") != nv_spk.hex():
                        new_slot_states[sn] = {"state": "contested_burned"}
                    else:
                        new_slot_states[sn] = trace_slot(
                            sn,
                            {
                                "state": "vacant",
                                "vacant_outpoint": {"txid": rspend, "vout": sspec["new_vacant_vout"]},
                                "min_appoint_height": roster_eff_h,
                            },
                            active_roster,
                        )
            slot_states = new_slot_states

        return {
            "origin_id": origin_id,
            "capacity": "ward",
            "binding": active_binding,
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
    ) -> tuple[bool, str | None, dict[str, Any]]:
        """Enforce SL-ORIG-006 + SL-WIRE-013 guardian_approvals[] verification in single canonical precedence (H-34, H-35)."""
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

        digest = sl.signing_digest(payload)
        verified_slots: list[int] = []
        verified_guardians: list[str] = []
        seen_guardian_regs: set[str] = set()
        opened_maj = ward_state.get("opened_majority_unix")

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
                if chain.tip_height >= term["ceiling_height"] or chain.now >= term["not_after_unix"]:
                    return False, "GUARDIAN_INACTIVE", {}
            gpin = st["guardian_pin"]
            greg = _outpoint_key(gpin["registration"])
            if greg in seen_guardian_regs:
                return False, "GUARDIAN_INACTIVE", {}
            seen_guardian_regs.add(greg)
            # Resolve guardian's live link.grant policy at tip (SL-ORIG-006 item 4: broken guardian identity -> GUARDIAN_INACTIVE, H-35)
            gnrec, gerr = self.resolve_name(
                gpin["name"],
                chain,
                expected_owner_policy=gpin["owner_policy"],
                expected_registration=gpin["registration"],
            )
            if gerr:
                return False, "GUARDIAN_INACTIVE", {}
            assert gnrec is not None
            gpol, rerr = self.resolve_role_policy(gnrec, "grant", item["signatures"]["policy"])
            if rerr:
                return False, "WIRE_SIGNATURE" if rerr == "WIRE_SIGNATURE" else "GUARDIAN_INACTIVE", {}
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
        # H-5: Check 72h freshness at contract/issuance anchor_time when anchored, else chain.now!
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
            wstate, oerr = self.verify_origin_and_status(ob, chain)
            if oerr:
                return VerifierResult("REFUSE", oerr)
            assert wstate is not None
            if "name_pin" in party and not _name_pin_equal(wstate["binding"], party["name_pin"]):
                return VerifierResult("REFUSE", "ORIGIN_BINDING_INVALID")
            if wstate["capacity"] == "ward":
                ok_g, gerr, details = self.verify_ward_approvals(assent_env, wstate, chain)
                if not ok_g:
                    return VerifierResult("REFUSE", gerr)
                return VerifierResult("ADMIT", None, outcome="executed", details={**details, "party_id": party["party_id"]})
        if "signing_policy" not in party:
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        # H-32 / D-5: If autonomous party declares name_pin, verify name_pin, link.grant, & history-based ward check!
        if "name_pin" in party:
            npin = party["name_pin"]
            pnrec, pnerr = self.resolve_name(
                npin["name"],
                chain,
                expected_owner_policy=npin["owner_policy"],
                expected_registration=npin["registration"],
                at_height=anchor_height,
            )
            if pnerr:
                return VerifierResult("REFUSE", pnerr)
            assert pnrec is not None
            # Reject ward masquerading as an autonomous party (B-12 / H-32)
            hist_oid = pnrec.get("_historical_origin_id")
            if hist_oid:
                ob_p = self._pick_origin_bundle_for_oid(hist_oid, origin_bundle, origin_bundles_by_oid)
                pwstate, pwoerr = self.verify_origin_and_status(ob_p, chain)
                if pwoerr:
                    return VerifierResult("REFUSE", pwoerr)
                assert pwstate is not None
                if pwstate["capacity"] == "ward":
                    return VerifierResult("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN")
            rpol_p, rerr_p = self.resolve_role_policy(pnrec, "grant", party["signing_policy"])
            if rerr_p or rpol_p != _normalize_policy(party["signing_policy"]):
                return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
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
    ) -> VerifierResult:
        """Verify strict 1-to-1 signatory coverage across every distinct party_id (supports multi-ward contracts, R1-C)."""
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
            )
            if ares.verdict != "ADMIT":
                if ares.refusal_code in ("WARD_AUTONOMOUS_FORBIDDEN", "ORIGIN_UNVERIFIED", "GUARDIAN_INACTIVE", "GUARDIAN_QUORUM_UNMET"):
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
    ) -> VerifierResult:
        """Execute SPEC-05 §4.2 deterministic 8-step credential verification order (D-6, R3 H8)."""
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
        # 5. Subject verification: eternal name_pin checked at h_anchor (D-6); revocable at tip; mode='origin' supported
        subj = cp["subject"]
        if subj.get("mode") == "name":
            _, serr = self.resolve_name(
                subj["name_pin"]["name"],
                chain,
                expected_owner_policy=subj["name_pin"]["owner_policy"],
                expected_registration=subj["name_pin"]["registration"],
                at_height=h_anchor if cp["lifecycle"] == "eternal" else None,
            )
            if serr:
                return VerifierResult("REFUSE", serr)
        elif subj.get("mode") == "origin" and origin_bundle is not None:
            wstate, oerr = self.verify_origin_and_status(origin_bundle, chain, journal=journal)
            if oerr:
                return VerifierResult("REFUSE", oerr)
            assert wstate is not None
            if wstate["origin_id"] != subj["origin_id"]:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
        # 6. Issuer history, owner_policy, link.cred policy (at tip for revocable, at h_anchor for eternal), policy-scoped 0x0b h_c break
        iss = cp["issuer"]
        i_err = self.verify_issuer_role_at_height(
            iss, cred_env, "cred", h_anchor, chain, resolve_at_tip=(cp["lifecycle"] != "eternal"), journal=journal
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
        # 8. Revocable seal state (derived 0x0a frame on spend_tx -> CRED_REVOKED_FOR_CAUSE; verify optional withdrawal_doc)
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
    ) -> VerifierResult:
        """Execute SPEC-05 §5 deterministic seallink-notary/1 verification (0x04/0x05/0x0b, B-4, H-24)."""
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
        atx = chain.get_tx(anchor_txid) if anchor_txid else None
        if self._decode_opreturn_tx(atx, expected_action="0x04", expected_commitment=sl.content_addr(notary_env)) is None:
            return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
        assert atx is not None
        h_anchor = atx["confirmed_height"]
        if chain.tip_height - h_anchor + 1 < self.operator_min_depth:
            return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
        notary_pin = np["notary"]
        if expected_notary_name is not None and notary_pin["name"] != expected_notary_name:
            return VerifierResult("REFUSE", "NOTARY_REQUIRED")
        if allowed_notaries is not None and not any(_name_pin_equal(notary_pin, an) for an in allowed_notaries):
            return VerifierResult("REFUSE", "NOTARY_REQUIRED")
        n_err = self.verify_issuer_role_at_height(
            notary_pin, notary_env, "notary", h_anchor, chain, resolve_at_tip=(np["lifecycle"] != "eternal"), journal=journal
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
        if expected_child_binding is not None:
            det = np.get("details", {})
            if (
                np.get("act_kind") != "child-within-parent"
                or det.get("parent_grant_id") != expected_child_binding["parent_grant_id"]
                or det.get("child_grant_id") != expected_child_binding["child_grant_id"]
                or det.get("ordinal") != expected_child_binding["ordinal"]
            ):
                return VerifierResult("REFUSE", "NOTARY_REQUIRED")
        return VerifierResult("ADMIT", None, outcome="executed", details={"notary_act_id": act_id, "act_kind": np["act_kind"]})

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
    ) -> VerifierResult:
        """Verify seallink-termination/1 and optional 0x08 contract-seal spend frame (SPEC-05 §2.3, H-24)."""
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
        # Signer must match an autonomous party's signing_policy OR contract seal arbiter/issuer key
        matched_pol = None
        for pt in c_res.get("parties", []):
            if "signing_policy" in pt and _normalize_policy(pt["signing_policy"]) == _normalize_policy(term_env["signatures"]["policy"]):
                matched_pol = pt["signing_policy"]
                break
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
    ) -> VerifierResult:
        """Verify seallink-statement/1 against issuer's link.grant, pinned policy, or registered device key (SPEC-03 §3.1, H-24)."""
        ok_s, s_res = self._verify_object_wire(stmt_env, expected_type="seallink-statement/1")
        if not ok_s:
            return VerifierResult("REFUSE", s_res)
        sp = s_res["payload"]
        if sp["network"] != self.pinned_network or sp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
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
        if device_list is not None and (sig_pol.get("alg") in ("p256", "ed25519") or sp["statement_kind"] == "config-section"):
            ok_dl, dl_res = self._verify_object_wire(device_list, expected_type="seallink-device-list/1")
            alg = sig_pol.get("alg", "bip340")
            matched = (
                next((d for d in dl_res["devices"] if d["alg"] == alg and d["key"] == sig_pol["pks"][0]), None)
                if (ok_dl and dl_res.get("owner") == sp["issuer"]["name"] and sig_pol["m"] == 1 and len(sig_pol["pks"]) == 1)
                else None
            )
            if matched is None:
                return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
            _, serr, _ = self.evaluate_seal(matched["seal"], chain, required_depth=1)
            if serr:
                return VerifierResult("REFUSE", serr)
            return VerifierResult("ADMIT", None, outcome="executed", details={"statement_id": sl.object_id(sp), "kind": sp["statement_kind"]})
        # Default: verify against issuer's live link.grant policy
        iss = sp["issuer"]
        nrec, nerr = self.resolve_name(
            iss["name"], chain, expected_owner_policy=iss["owner_policy"], expected_registration=iss["registration"]
        )
        if nerr:
            return VerifierResult("REFUSE", nerr)
        assert nrec is not None
        rpol, rerr = self.resolve_role_policy(nrec, "grant", sig_pol)
        if rerr:
            return VerifierResult("REFUSE", rerr)
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
    def _party_matches_actor(party: dict[str, Any], actor_pin: dict[str, Any], *, is_recipient: bool = False) -> bool:
        """Check whether a grant issuer or recipient corresponds to a party in contract.parties[] (D-5)."""
        if not is_recipient:
            # Root grant issuer has {name, registration, owner_policy}
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

        # Step 6: Durable closure check (supports both canonical ClosureSubject & legacy keys)
        for pe in ppath:
            gid = pe["grant_id"]
            cl = journal.lookup_closure({"subject_id": gid, "subject_kind": "grant"}, legacy_key=gid)
            if cl is not None:
                if cl.get("cause") == "SINGLE_USE_CONSUMED":
                    return VerifierResult("REFUSE", "INVOKE_REPLAY")
                return VerifierResult("REFUSE", "GRANT_CLOSED")
        if len(ppath) == 2 and "parent" in leaf_gp:
            ord_i = leaf_gp["parent"]["ordinal"]
            rcl = journal.lookup_closure(
                {"grant_id": root_gid, "ordinal": ord_i, "subject_kind": "row"},
                legacy_key=f"{root_gid}:{ord_i}",
            )
            if rcl is not None and rcl.get("cause") == "GRANT_ROW_STOPPED":
                return VerifierResult("REFUSE", "GRANT_ROW_STOPPED")
        iss_pin = root_gp["issuer"]
        iss_name = iss_pin["name"]
        role_cl = journal.lookup_closure(
            {"name": iss_name, "registration": iss_pin["registration"], "role": "grant", "subject_kind": "role"},
            legacy_key=f"role:{iss_name}:grant",
        )
        if role_cl is not None:
            return VerifierResult("REFUSE", "NAME_ROLE_CHANGED")
        for g in (root_grant, leaf_grant):
            rev = g["payload"]["revocation"]
            if rev["mode"] == "seal":
                s_op = {"txid": rev["seal"]["txid"], "vout": rev["seal"]["vout"]}
                scl = journal.lookup_closure(
                    {"outpoint": s_op, "subject_kind": "seal"},
                    legacy_key=_outpoint_key(s_op),
                )
                if scl is not None:
                    return VerifierResult("REFUSE", "SEAL_SPENT")

        # Step 7: Issuer identity, history-based permanent origin detection, and guardianship (B-2, B-12)
        nrec, nerr = self.resolve_name(
            iss_pin["name"],
            chain,
            expected_owner_policy=iss_pin["owner_policy"],
            expected_registration=iss_pin["registration"],
        )
        if nerr:
            return VerifierResult("REFUSE", nerr)
        assert nrec is not None

        root_recent_h = chain.raw.get("blocks", {}).get(root_gp["recent_block"])
        origin_bundle = bundle.get("origin_bundle")
        origin_bundles_by_oid = bundle.get("origin_bundles_by_oid")
        ward_details: dict[str, Any] = {}
        hist_oid = nrec.get("_historical_origin_id")
        is_origin_cert = bool(hist_oid)
        wstate: dict[str, Any] | None = None
        if is_origin_cert:
            ob_iss = self._pick_origin_bundle_for_oid(hist_oid, origin_bundle, origin_bundles_by_oid)
            wstate, oerr = self.verify_origin_and_status(ob_iss, chain, journal=journal)
            if oerr:
                return VerifierResult("REFUSE", oerr)
            assert wstate is not None
            if not _name_pin_equal(wstate["binding"], iss_pin):
                return VerifierResult("REFUSE", "ORIGIN_BINDING_INVALID")
            if wstate["capacity"] == "ward":
                ok_wa, werr, ward_details = self.verify_ward_approvals(root_grant, wstate, chain)
                if not ok_wa:
                    return VerifierResult("REFUSE", werr)
        if wstate is None or wstate["capacity"] != "ward":
            rpol, rerr = self.resolve_role_policy(nrec, "grant", iss_pin.get("role_policy"), recent_block_height=root_recent_h)
            if rerr:
                if rerr == "NAME_ROLE_CHANGED":
                    journal.record_closure(
                        {"name": iss_name, "registration": iss_pin["registration"], "role": "grant", "subject_kind": "role"},
                        "NAME_ROLE_CHANGED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                    )
                return VerifierResult("REFUSE", rerr)
            ok_rs, rscode = sl.verify_signature_set(
                sl.signing_digest(root_gp), root_grant.get("signatures", {}), expected_policy=rpol, obj_type="seallink-grant/1"
            )
            if not ok_rs:
                return VerifierResult("REFUSE", rscode)

        # Step 8: Contract and framework checks (R1-C, R3 B5, H-5, H-18, D-5)
        if act_meta is not None and act_meta.get("requires_contract", False) and "contract_id" not in leaf_gp:
            return VerifierResult("REFUSE", "GRANT_CONTRACT_REQUIRED")
        if "contract_id" in leaf_gp:
            c_obj = bundle.get("contract")
            if c_obj is None:
                return VerifierResult("REFUSE", "CONTRACT_NOT_PRESENTED")
            ok_co, co_res = self._verify_object_wire(c_obj, expected_type="seallink-contract/1")
            if not ok_co:
                return VerifierResult("REFUSE", co_res)
            c_obj = co_res
            if c_obj["network"] != self.pinned_network or c_obj["genesis"] != self.pinned_genesis:
                return VerifierResult("REFUSE", "CHAIN_MISMATCH")
            if sl.object_id(c_obj) != leaf_gp["contract_id"]:
                return VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH")
            if "framework_id" in c_obj:
                fw_obj = bundle.get("framework_contract")
                if fw_obj is None:
                    return VerifierResult("REFUSE", "CONTRACT_NOT_PRESENTED")
                ok_fw, fw_res = self._verify_object_wire(fw_obj, expected_type="seallink-contract/1")
                if not ok_fw:
                    return VerifierResult("REFUSE", fw_res)
                fw_obj = fw_res
                if fw_obj["network"] != self.pinned_network or fw_obj["genesis"] != self.pinned_genesis:
                    return VerifierResult("REFUSE", "CHAIN_MISMATCH")
                if sl.object_id(fw_obj) != c_obj["framework_id"]:
                    return VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH")
                if "framework_id" in fw_obj:
                    return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
                if "seal" not in fw_obj:
                    return VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING")
                _, fw_serr, _ = self.evaluate_seal(
                    fw_obj["seal"], chain, required_depth=1, journal=journal, subject_id=c_obj["framework_id"], subject_kind="contract"
                )
                if fw_serr:
                    return VerifierResult("REFUSE", fw_serr)
                # H-18: Enforce contract window nests inside framework window AND framework not_after_unix!
                fww = fw_obj["window"]
                cw_chk = c_obj["window"]
                if cw_chk["not_before_height"] < fww["not_before_height"] or (
                    "not_after_height" in fww
                    and ("not_after_height" not in cw_chk or cw_chk["not_after_height"] > fww["not_after_height"])
                ):
                    return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
                if "not_after_unix" in fww and chain.now >= fww["not_after_unix"]:
                    return VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED")

            # H-5: Resolve contract 0x07 anchor timestamp (if present) for 72h assent freshness check
            c_anchor_time: int | None = None
            c_anchor_height: int | None = None
            c_atxid = bundle.get("contract_anchor_txid")
            if c_atxid:
                c_atx = chain.get_tx(c_atxid)
                if self._decode_opreturn_tx(c_atx, expected_action="0x07", expected_commitment=leaf_gp["contract_id"]) is None:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                assert c_atx is not None
                c_anchor_height = c_atx["confirmed_height"]
                if "block_time" in c_atx:
                    c_anchor_time = int(c_atx["block_time"])
            ca_res = self.verify_contract_assents(
                c_obj,
                bundle.get("contract_assents", []),
                origin_bundle,
                chain,
                origin_bundles_by_oid=origin_bundles_by_oid,
                anchor_time=c_anchor_time,
                anchor_height=c_anchor_height,
            )
            if ca_res.verdict != "ADMIT":
                return VerifierResult("REFUSE", ca_res.refusal_code)
            if "seal" not in c_obj:
                return VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING")
            _, c_serr, _ = self.evaluate_seal(
                c_obj["seal"], chain, required_depth=1, journal=journal, subject_id=leaf_gp["contract_id"], subject_kind="contract"
            )
            if c_serr:
                return VerifierResult("REFUSE", c_serr)
            cw = c_obj["window"]
            if leaf_gp["not_before_height"] < cw["not_before_height"] or (
                "not_after_height" in cw and leaf_gp["not_after_height"] > cw["not_after_height"]
            ):
                return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
            if "not_after_unix" in cw and chain.now >= cw["not_after_unix"]:
                return VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED")
            # D-5: Bind root grant issuer AND leaf grant recipient to distinct contract parties
            parties = c_obj.get("parties", [])
            issuer_pids = {pt["party_id"] for pt in parties if self._party_matches_actor(pt, iss_pin, is_recipient=False)}
            rcpt_pids = {pt["party_id"] for pt in parties if self._party_matches_actor(pt, rcpt_spec, is_recipient=True)}
            if not issuer_pids or not rcpt_pids or not any(ip != rp for ip in issuer_pids for rp in rcpt_pids):
                return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
            # R3 B5: Closed MachineClauseTerms validation & mechanical narrowing against bound grant!
            disclosed = bundle.get("disclosed_clauses", {})
            declared_machine_caps: list[dict[str, Any]] = []
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
            if not terms_ok or (
                declared_machine_caps and any(not any(self._capability_narrows(gcap, mcap) for mcap in declared_machine_caps) for gcap in leaf_gp["capabilities"])
            ):
                return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
            if "config_sha256" in c_obj:
                rt_cfg = executor_cfg.get("runtime_config_sha256")
                arg_cfg = inv_p["arguments"].get("config_sha256")
                if (rt_cfg is not None and rt_cfg != c_obj["config_sha256"]) or (arg_cfg is not None and arg_cfg != c_obj["config_sha256"]):
                    return VerifierResult("REFUSE", "CONTRACT_CONFIG_MISMATCH")
            elif action == "agent/session" and inv_p["arguments"].get("op") == "start":
                return VerifierResult("REFUSE", "CONTRACT_CONFIG_MISMATCH")

        # Step 9: Depth-2 Re-delegation checks (R8.5, R8.6, row-coin spend, stop coin, notary B-4, recipient_rule B-6, narrowing)
        matched_parent_template: dict[str, Any] | None = None
        if len(ppath) == 2:
            if "delegate" not in root_gp or "parent" not in leaf_gp or "delegate" in leaf_gp:
                return VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE")
            if leaf_gp["parent"]["grant_id"] != root_gid:
                return VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE")
            del_spec = root_gp["delegate"]
            ok_r85, _ = sl.check_whole_parent_budget_r85(del_spec, parent_capabilities=root_gp["capabilities"])
            if not ok_r85:
                return VerifierResult("REFUSE", "GRANT_CHILD_WIDER")
            if not sl.check_disjoint_ranges_r86(root_gp):
                return VerifierResult("REFUSE", "GRANT_ROW_INVALID")
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
                return VerifierResult("REFUSE", "GRANT_ROW_INVALID")
            # Verify row coin pre-confirmed <= parent.recent_block when creation tx is present in chain
            row_cre_tx = chain.get_tx(row_outpoint["txid"])
            row_valid = True
            if row_cre_tx is not None:
                rc_h = row_cre_tx.get("confirmed_height")
                r_out_obj = chain.get_output(row_outpoint["txid"], row_outpoint["vout"])
                exp_rspk = sl.compile_script_policy(row_script_policy)[0] if row_script_policy is not None else None
                if (
                    rc_h is None
                    or (root_recent_h is not None and rc_h > root_recent_h)
                    or (r_out_obj is not None and exp_rspk is not None and r_out_obj.get("script_pubkey_hex") != exp_rspk.hex())
                ):
                    row_valid = False
            # Derive row-coin spend directly from child issuance tx inputs[]!
            c_itxid = ppath[1].get("issuance_txid")
            c_itx = chain.get_tx(c_itxid) if c_itxid else None
            spent_set = {f"{i['prev_txid']}:{i['prev_vout']}" for i in (c_itx.get("inputs", []) if c_itx else [])}
            if not row_valid or not c_itx or _outpoint_key(row_outpoint) not in spent_set:
                return VerifierResult("REFUSE", "GRANT_ROW_INVALID")
            if stop_outpoint is not None:
                sout = chain.get_output(stop_outpoint["txid"], stop_outpoint["vout"])
                if sout and (sout.get("spent_by_txid") or sout.get("absent_from_utxo")):
                    journal.record_closure(
                        {"grant_id": root_gid, "ordinal": ordinal, "subject_kind": "row"},
                        "GRANT_ROW_STOPPED",
                        observed_at=chain.now,
                        observed_height=chain.tip_height,
                        spend_txid=sout.get("spent_by_txid", "0" * 64),
                    )
                    return VerifierResult("REFUSE", "GRANT_ROW_STOPPED")
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
                    return VerifierResult("REFUSE", n_res.refusal_code if n_res.refusal_code in ("CRED_ISSUER_CLOSED", "CRED_REVOKED_FOR_CAUSE", "SEAL_SPENT", "SEAL_UNAVAILABLE") else "NOTARY_REQUIRED")
            ok_cs, cscode = sl.verify_signature_set(
                sl.signing_digest(leaf_gp),
                leaf_grant.get("signatures", {}),
                expected_policy={"m": 1, "pks": [del_spec["key"]]},
                obj_type="seallink-grant/1",
            )
            if not ok_cs:
                return VerifierResult("REFUSE", cscode)
            if (
                leaf_gp["genesis"] != root_gp["genesis"]
                or leaf_gp.get("contract_id") != root_gp.get("contract_id")
                or leaf_gp.get("executor") != tpl["executor"]
                or leaf_gp["not_before_height"] < root_gp["not_before_height"]
                or leaf_gp["not_after_height"] > root_gp["not_after_height"]
            ):
                return VerifierResult("REFUSE", "GRANT_CHILD_WIDER")
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
                        op_pin["name"], chain, expected_owner_policy=op_pin["owner_policy"], expected_registration=op_pin["registration"]
                    )
                    if op_err or op_nrec is None:
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
                return VerifierResult("REFUSE", "GRANT_CHILD_WIDER")

        # Step 10: Grant window, SL-GRNT-004 issuer expiry bound, revocation/single-use seal, linkage (H-6, R3 B1/H1)
        journal_writes: list[dict[str, Any]] = []
        for idx_pe, pe in enumerate(ppath):
            g = grants_by_id[pe["grant_id"]]
            gp = g["payload"]
            gid = pe["grant_id"]
            if not (gp["not_before_height"] <= chain.tip_height < gp["not_after_height"]):
                return VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED")
            rev = gp["revocation"]
            if rev["mode"] == "window_only":
                if not self.allow_window_only or (act_meta is not None and act_meta.get("require_seal", True)):
                    return VerifierResult("REFUSE", "GRANT_SEAL_REQUIRED")
            else:
                itxid = pe.get("issuance_txid")
                itx = chain.get_tx(itxid) if itxid else None
                dec_i = self._decode_opreturn_tx(itx, require_confirmed=False)
                if dec_i is None:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
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
                        return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                elif dec_i["action"] == "0x02":
                    # R3 B1 / Decision A1: 0x02 Merkle batch anchor is FORBIDDEN for depth-2 child grants!
                    if idx_pe == 1 or "parent" in gp:
                        return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                    bp = pe.get("batch_proof")
                    if not bp or bp.get("leaf_digest") != expected_iss_digest or bp.get("root") != dec_i["commitment"] or not sl.verify_merkle_proof(bp):
                        return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                else:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                r_height = chain.raw.get("blocks", {}).get(gp["recent_block"])
                a_height = itx.get("confirmed_height")
                if r_height is None:
                    return VerifierResult("REFUSE", "CHAIN_RECENCY_INVALID")
                if a_height is not None:
                    k_lim = chain.raw.get("recency_k", 432)
                    if not (r_height < a_height <= r_height + k_lim):
                        return VerifierResult("REFUSE", "CHAIN_RECENCY_INVALID")
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
                                return VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED")
                # Witness Profile W on anchor tx `itx`, seal-creation tx T, & exact linkage `(seal_txid, seal_vout + 1)` (H-6, R3 H1)
                seal_obj = rev["seal"]
                seal_tx = chain.get_tx(seal_obj["txid"])
                itx_in_ops = {(i["prev_txid"], i["prev_vout"]) for i in itx.get("inputs", []) if isinstance(i, dict)}
                if (
                    rev["construction"] != "W"
                    or not self._tx_satisfies_witness_w(itx)
                    or (seal_tx is not None and seal_tx.get("inputs") and not self._tx_satisfies_witness_w(seal_tx))
                    or (seal_obj["txid"], seal_obj["vout"]) in itx_in_ops
                    or (idx_pe == 0 and (seal_obj["txid"], seal_obj["vout"] + 1) not in itx_in_ops)
                ):
                    return VerifierResult("REFUSE", "CHAIN_TX_CONSTRUCTION")
                req_depth = max(gp.get("min_depth", 1), self.operator_min_depth)
                if a_height is None or (chain.tip_height - a_height + 1) < req_depth:
                    return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
                if rev["kind"] == "revocable":
                    _, serr, jw = self.evaluate_seal(
                        seal_obj, chain, required_depth=req_depth, journal=journal, subject_id=gid, subject_kind="grant"
                    )
                    if jw:
                        journal_writes.append(jw)
                    if serr:
                        return VerifierResult("REFUSE", serr, journal_writes=journal_writes)
                else:
                    _, serr, jw = self.evaluate_single_use_seal(
                        seal_obj, use_txid, inv_caddr, req_depth, chain, journal=journal, grant_id=gid
                    )
                    if jw:
                        journal_writes.append(jw)
                    if serr:
                        return VerifierResult("REFUSE", serr, journal_writes=journal_writes)

        # 10d. Executor binding: evaluate executor_ref strictly against leaf_gp["capabilities"] (NOT inv_p["action"]!)
        if "executor_ref" in leaf_gp:
            for cap in leaf_gp["capabilities"]:
                cmeta = ACTION_PROFILES.get(cap["action"]) or local_action_profiles.get(cap["action"]) or {"allows_executor_ref": False, "external_mutation": True}
                if cmeta.get("external_mutation", True) or not cmeta.get("allows_executor_ref", False):
                    return VerifierResult("REFUSE", "GRANT_EXECUTOR_REF_FORBIDDEN")
            eref = leaf_gp["executor_ref"]
            holder_rec, herr = self.resolve_name(eref["provider_of"], chain)
            if herr:
                return VerifierResult("REFUSE", herr)
            assert holder_rec is not None
            holder_man, merr = self.resolve_manifest(eref["provider_of"], holder_rec, bundle.get("manifests", {}), chain, journal)
            if merr:
                return VerifierResult("REFUSE", merr)
            assert holder_man is not None
            matched_prov = None
            for pe_prov in holder_man.get("providers", []):
                if pe_prov["service_type"] == eref["service_type"] and pe_prov["label"] == eref["label"]:
                    matched_prov = pe_prov["provider"]
                    break
            if matched_prov is None:
                return VerifierResult("REFUSE", "SERVICE_PROVIDER_UNBOUND")
            prov_rec, perr = self.resolve_name(
                matched_prov["name"],
                chain,
                expected_owner_policy=matched_prov["owner_policy"],
                expected_registration=matched_prov["registration"],
            )
            if perr:
                return VerifierResult("REFUSE", perr)
            assert prov_rec is not None
            prov_man, pmerr = self.resolve_manifest(matched_prov["name"], prov_rec, bundle.get("manifests", {}), chain, journal)
            if pmerr:
                return VerifierResult("REFUSE", pmerr)
            assert prov_man is not None
            svc = prov_man.get("service", {})
            if matched_prov["name"] != executor_cfg["name"] or svc.get("receipt_key") != executor_cfg["key"]:
                return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")
        else:
            if leaf_gp["executor"]["name"] != executor_cfg["name"] or leaf_gp["executor"]["key"] != executor_cfg["key"]:
                return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")

        # Step 11: Named recipient, action, text ban, target authority (B-1), and constraints
        # 11a. Named recipient (B-9: pin exact registration!)
        if rcpt_spec["mode"] == "name":
            r_nrec, r_nerr = self.resolve_name(
                rcpt_spec["name"],
                chain,
                expected_owner_policy=rcpt_spec["owner_policy"],
                expected_registration=rcpt_spec["registration"],
            )
            if r_nerr:
                return VerifierResult("REFUSE", r_nerr)
            assert r_nrec is not None
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

        # 11d. Target Authority Verification (B-1: GRANT_TARGET_UNAUTHORIZED)
        target_str = inv_p["target"]
        t_regex = act_meta.get("target_pattern") or act_meta.get("target_regex")
        target_auth_ok = not (t_regex and not re.match(t_regex, target_str))
        t_auth = act_meta.get("target_authority")
        if target_auth_ok and t_auth == "mailbox_owner":
            rest = target_str[len("mailbox:") :]
            m_owner, m_label = rest.rsplit(":", 1)
            if iss_pin["name"] != m_owner:
                target_auth_ok = False
            elif "executor_ref" not in leaf_gp and nrec.get("_value_obj", {}).get("m") is not None:
                o_man, o_merr = self.resolve_manifest(m_owner, nrec, bundle.get("manifests", {}), chain, journal)
                if o_merr is None and o_man is not None:
                    bound = any(
                        p.get("service_type") == "mail"
                        and p.get("label") == m_label
                        and p.get("provider", {}).get("name") == executor_cfg["name"]
                        for p in o_man.get("providers", [])
                    )
                    if not bound:
                        return VerifierResult("REFUSE", "SERVICE_PROVIDER_UNBOUND")
        elif target_auth_ok and t_auth in ("station_host", "station_host_and_contract"):
            rest = target_str[len("station:") :]
            s_host, s_slot = rest.rsplit(":", 1)
            if s_host != executor_cfg["name"]:
                target_auth_ok = False
            else:
                slot_owners = executor_cfg.get("slot_owners")
                auth_issuers = executor_cfg.get("authorized_issuers")
                if isinstance(slot_owners, dict):
                    allowed_for_slot = slot_owners.get(s_slot)
                    allowed_set = {allowed_for_slot} if isinstance(allowed_for_slot, str) else (set(allowed_for_slot) if isinstance(allowed_for_slot, list) else set())
                    if iss_pin["name"] not in allowed_set:
                        target_auth_ok = False
                elif isinstance(auth_issuers, (list, set)) and iss_pin["name"] not in auth_issuers:
                    target_auth_ok = False
        elif target_auth_ok and t_auth in ("pinned_ward", "ward_origin"):
            # B-3: Mandatory pinned_ward_origin_id, ward capacity, and target == ward:<pinned_oid>!
            pinned_oid = executor_cfg.get("pinned_ward_origin_id")
            if not pinned_oid:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
            if not ward_details or wstate is None or wstate.get("capacity") != "ward":
                return VerifierResult("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN")
            if target_str != f"ward:{pinned_oid}" or wstate["origin_id"] != pinned_oid:
                target_auth_ok = False
        if not target_auth_ok:
            return VerifierResult("REFUSE", "GRANT_TARGET_UNAUTHORIZED")

        # 11e. Target match, 7-predicate where evaluation, and profile server-side checks
        matched_cap = None
        for cap in action_caps:
            if cap["target"] != target_str:
                continue
            ok_where = True
            for arg_k, pred in cap.get("where", {}).items():
                if action == "mail/read" and arg_k in ("sender_domain", "max_bytes"):
                    # Server-side message metadata predicates not carried in MailReadArgs
                    meta_key = "size_bytes" if (arg_k == "max_bytes" and actual_message_meta is not None and "size_bytes" in actual_message_meta) else arg_k
                    if actual_message_meta is None or meta_key not in actual_message_meta:
                        ok_where = False
                        break
                    if not sl.match_predicate(pred, actual_message_meta[meta_key]):
                        ok_where = False
                        break
                    continue
                if arg_k not in inv_p["arguments"]:
                    ok_where = False
                    break
                if not sl.match_predicate(pred, inv_p["arguments"][arg_k]):
                    ok_where = False
                    break
                if actual_message_meta is not None and arg_k in actual_message_meta:
                    if not sl.match_predicate(pred, actual_message_meta[arg_k]):
                        ok_where = False
                        break
            if ok_where:
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
        # B-8: Enforce mandatory profile quotas from registry/actions.json!
        for rq in act_meta.get("required_quotas", []):
            has_req = any(
                q.get("kind") == rq["kind"] and q.get("unit") == rq["unit"]
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
        for wk, wv in watermark_updates.items():
            journal.quota_watermarks[wk] = wv
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

        jw_res = journal.append(
            "reservation",
            {
                "expires_at": inv_p["exp"],
                "grant_id": leaf_gid,
                "invocation_id": inv_id,
                "nonce": inv_p["nonce"],
                "recorded_at": decision_now,
                "reservations": res_lines,
            },
        )
        journal_writes.append(jw_res)

        frame_details.update({
            "grant_id": leaf_gid,
            "invocation_id": inv_id,
            "recorded_at": decision_now,
            "reserved_ops": pending_ops,
            "single_use": (leaf_gp["revocation"].get("kind") == "single_use"),
            "tip_height": chain.tip_height,
            "use_txid": use_txid,
        })
        return VerifierResult("ADMIT", None, outcome="reserved", journal_writes=journal_writes, details=frame_details)

    def commit_result(
        self,
        receipt_env: dict[str, Any],
        journal: FencedJournal,
        executor_cfg: dict[str, Any],
        *,
        invocation_id: str,
        grant_id: str,
        reserved_ops: list[dict[str, Any]] | None = None,
        actual_quota_usage: dict[str, int] | None = None,
        single_use: bool = False,
        use_txid: str | None = None,
        recorded_at: int | None = None,
        tip_height: int = 0,
    ) -> VerifierResult:
        """Phase 2 of SPEC-06 §2.2 (R1-A, B-7, R3 B4): verify signed receipt, persist blob FIRST, commit ONE atomic settlement."""
        ok_r, r_res = self._verify_object_wire(receipt_env, expected_type="seallink-receipt/1")
        if not ok_r:
            return VerifierResult("REFUSE", r_res)
        rp = r_res["payload"]
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

        # Build settlement lines from either explicit reserved_ops or the unsettled reservation already in journal
        ops_src = reserved_ops
        if ops_src is None and invocation_id in journal.unsettled_reservations:
            ops_src = []
            for ln in journal.unsettled_reservations[invocation_id].get("reservations", []):
                ops_src.append({
                    "account": ln["account"],
                    "bucket_id": ln["bucket_id"],
                    "grant_id": ln["grant_id"],
                    "quota": {
                        "kind": ln["quota_kind"],
                        "resource": ln["resource"],
                        "unit": ln["unit"],
                        "window": ln["window"],
                    },
                    "reserve": int(ln["amount"]),
                    "row_ordinal": ln.get("row_ordinal"),
                })
        ops_src = ops_src or []

        settle_lines: list[dict[str, Any]] = []
        for op_rec in ops_src:
            q = op_rec["quota"]
            qkey = f"{q['kind']}|{q['resource']}|{q['unit']}|{q['window']}"
            res_amt = int(op_rec["reserve"])
            if actual_quota_usage is not None and qkey in actual_quota_usage:
                set_amt = int(actual_quota_usage[qkey])
                if set_amt < 0 or set_amt > res_amt:
                    return VerifierResult("REFUSE", "QUOTA_EXCEEDED")
            else:
                set_amt = res_amt
            rel_amt = res_amt - set_amt
            sln: dict[str, Any] = {
                "account": op_rec["account"],
                "bucket_id": op_rec["bucket_id"],
                "grant_id": op_rec["grant_id"],
                "quota_kind": q["kind"],
                "released": str(rel_amt),
                "resource": q["resource"],
                "settled": str(set_amt),
                "unit": q["unit"],
                "window": q["window"],
            }
            if op_rec.get("row_ordinal") is not None:
                sln["row_ordinal"] = op_rec["row_ordinal"]
            settle_lines.append(sln)

        rcpt_caddr = sl.content_addr(r_res)
        rec_ts = recorded_at if recorded_at is not None else rp["recorded_at"]
        # Persist verified signed receipt blob FIRST before committing terminal journal entry!
        journal.receipt_store[rcpt_caddr] = copy.deepcopy(r_res)
        journal_writes: list[dict[str, Any]] = []
        jw_set = journal.append(
            "settlement",
            {
                "grant_id": grant_id,
                "invocation_id": invocation_id,
                "outcome": rp["outcome"],
                "receipt_sha256": rcpt_caddr,
                "recorded_at": rec_ts,
                "settlements": settle_lines,
            },
        )
        journal_writes.append(jw_set)
        if single_use:
            jw_su = journal.append(
                "single-use-consumed",
                {
                    "grant_id": grant_id,
                    "invocation_id": invocation_id,
                    "receipt_sha256": rcpt_caddr,
                    "recorded_at": rec_ts,
                    "use_txid": use_txid or ("0" * 64),
                },
            )
            journal_writes.append(jw_su)
            jw_cl = journal.record_closure(
                {"subject_id": grant_id, "subject_kind": "grant"},
                "SINGLE_USE_CONSUMED",
                observed_at=rec_ts,
                observed_height=tip_height or rp.get("tip_height", 0),
                spend_txid=use_txid or ("0" * 64),
            )
            journal_writes.append(jw_cl)

        return VerifierResult(
            "ADMIT",
            None,
            outcome=rp["outcome"],
            cached_receipt_content_addr=rcpt_caddr,
            journal_writes=journal_writes,
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
                reserved_ops=p1.details["reserved_ops"],
                actual_quota_usage=actual_quota_usage,
                single_use=p1.details["single_use"],
                use_txid=p1.details["use_txid"],
                recorded_at=p1.details["recorded_at"],
                tip_height=p1.details["tip_height"],
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

        # No receipt provided yet: NEVER synthesize a fake sha256(inv_id) settlement!
        # Caller may now execute the effect and invoke `commit_result(real_receipt_env, ...)`.
        if p1.details.get("single_use"):
            # For single_use without an upfront receipt, still record single-use closure only on commit_result;
            # leave reservation pending so retries before commit_result return UNCERTAIN (never double-execute).
            pass
        return VerifierResult("ADMIT", None, outcome="reserved", journal_writes=p1.journal_writes, details=p1.details)

    # ------------------------------------------------------------------
    # SPEC-06 §5 Bearer Sessions, SPEC-07 §2 Migration, SPEC-07 §3 Federation (Decision 6B)
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
        """Verify seallink-session-open/1 (`open` | `extend` | `close`) per SPEC-06 §5 (H-12)."""
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
        grant_id = sp["proof_path"][-1]["grant_id"]
        grants_by_id: dict[str, dict[str, Any]] = {}
        for g in bundle.get("grants", []):
            ok_g, rg = self._verify_object_wire(g, expected_type="seallink-grant/1")
            if not ok_g:
                return VerifierResult("REFUSE", rg)
            grants_by_id[sl.object_id(rg["payload"])] = rg
        grant_env = grants_by_id.get(grant_id)
        gp = grant_env["payload"] if grant_env is not None else None
        if (
            gp is None
            or sp["iat"] > chain.now
            or sp["exp"] <= chain.now
            or (op in ("open", "extend") and sp["exp"] > chain.now + 3600)
            or gp["revocation"]["mode"] != "seal"
            or gp["revocation"]["kind"] != "revocable"
        ):
            return VerifierResult("REFUSE", "SESSION_INVALID")
        if (
            sp["executor"].get("name") != executor_cfg.get("name")
            or sp["executor"].get("key") != executor_cfg.get("key")
            or gp.get("executor", {}).get("name") != executor_cfg.get("name")
            or gp.get("executor", {}).get("key") != executor_cfg.get("key")
        ):
            return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")
        if not (gp["not_before_height"] <= chain.tip_height < gp["not_after_height"]):
            return VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED")
        if journal.lookup_closure({"subject_id": grant_id, "subject_kind": "grant"}, legacy_key=grant_id) is not None:
            return VerifierResult("REFUSE", "GRANT_CLOSED")
        _, serr, _ = self.evaluate_seal(gp["revocation"]["seal"], chain, required_depth=self.operator_min_depth, journal=journal, subject_id=grant_id, subject_kind="grant")
        if serr:
            return VerifierResult("REFUSE", serr)

        # Verify session-open signature matches grant recipient
        rcpt = gp["recipient"]
        if rcpt["mode"] == "key":
            exp_pol = {"m": 1, "pks": [rcpt["key"]]}
        elif rcpt["mode"] == "group":
            exp_pol = rcpt["threshold"]
        else:
            r_nrec, r_nerr = self.resolve_name(
                rcpt["name"], chain, expected_owner_policy=rcpt["owner_policy"], expected_registration=rcpt["registration"]
            )
            if r_nerr:
                return VerifierResult("REFUSE", r_nerr)
            assert r_nrec is not None
            nv = r_nrec.get("_value_obj", {}).get("nostr")
            rpk = nv if isinstance(nv, str) else (nv.get("names", {}).get("_") if isinstance(nv, dict) else None)
            exp_pol = {"m": 1, "pks": [rpk]} if rpk else None
        ok_s, scode = (
            (False, "WIRE_SIGNATURE")
            if exp_pol is None
            else sl.verify_signature_set(sl.signing_digest(sp), o_res["signatures"], expected_policy=exp_pol, obj_type="seallink-session-open/1")
        )
        if not ok_s:
            return VerifierResult("REFUSE", scode)

        # Verify session quotas <= backing grant quotas & open/extend/close state transitions
        grant_q_caps: dict[tuple[str, str, str, str], int] = {}
        for cap in gp.get("capabilities", []):
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
            else (existing is not None and not existing.get("closed") and existing.get("grant_id") == grant_id and existing.get("slot_binding") == sp["slot_binding"])
        )
        if not quotas_ok or not state_ok:
            return VerifierResult("REFUSE", "SESSION_INVALID")

        # Persist single-use session-open nonce so identical open/extend/close cannot be replayed
        jw_n = journal.append(
            "nonce",
            {"expires_at": sp["exp"], "invocation_id": sl.object_id(sp), "nonce": sp["nonce"], "scope": "auth"},
        )
        body: dict[str, Any] = {
            "expires_at": sp["exp"],
            "grant_id": grant_id,
            "op": op,
            "recorded_at": chain.now,
            "session_id": sid,
            "slot_binding": sp["slot_binding"],
        }
        if "quotas" in sp:
            body["quotas"] = sp["quotas"]
        jw = journal.append("session-state", body)
        if op == "open":
            tok = bearer_token or sl.sha256(f"seallink-session:{sid}:{chain.now}".encode("utf-8")).hex()
            t_hash = sl.sha256(tok.encode("utf-8")).hex()
            journal.sessions_by_id[sid]["token_sha256"] = t_hash
            journal.sessions[t_hash] = journal.sessions_by_id[sid]
            return VerifierResult("ADMIT", None, outcome="executed", journal_writes=[jw_n, jw], details={"session_id": sid, "token_sha256": t_hash})
        return VerifierResult("ADMIT", None, outcome="executed", journal_writes=[jw_n, jw], details={"session_id": sid, "op": op})

    def verify_bearer_session(
        self,
        token: str,
        slot_binding: str,
        chain: ChainView,
        journal: FencedJournal,
        *,
        grant_env: dict[str, Any] | None = None,
        action: str | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> VerifierResult:
        """Per-use bearer session verification: live chain, seal, closure, and session quota check (SPEC-06 §5, H-12)."""
        obs_err = self.check_chain_observation(chain, risk_class=2)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)
        t_hash = sl.sha256(token.encode("utf-8")).hex()
        # Constant-time lookup across session token hashes
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
            and not (gid and journal.lookup_closure({"subject_id": gid, "subject_kind": "grant"}, legacy_key=gid) is not None)
        )
        # If backing grant supplied, re-verify live window & seal on every use!
        if sess_ok and grant_env is not None:
            ok_g, rg = self._verify_object_wire(grant_env, expected_type="seallink-grant/1")
            gp = rg["payload"] if (ok_g and sl.object_id(rg["payload"]) == gid) else None
            if (
                gp is None
                or not (gp["not_before_height"] <= chain.tip_height < gp["not_after_height"])
                or (
                    gp["revocation"]["mode"] == "seal"
                    and self.evaluate_seal(gp["revocation"]["seal"], chain, required_depth=1, journal=journal, subject_id=gid, subject_kind="grant")[1] is not None
                )
            ):
                sess_ok = False
        if not sess_ok:
            return VerifierResult("REFUSE", "SESSION_INVALID")
        # Enforce session-scoped quotas if configured on the session
        if action is not None and sess.get("quotas"):
            sid = sess.get("session_id", t_hash)
            for sq in sess["quotas"]:
                qkey = f"{sq['kind']}|{sq['resource']}|{sq['unit']}|{sq['window']}"
                res_amt, _ = compute_quota_debit(action, arguments or {}, sq)
                bkey = (f"session:{sid}", qkey, "term")
                used = journal.quotas_used.get(bkey, 0)
                if used + res_amt > int(sq["max"]):
                    return VerifierResult("REFUSE", "QUOTA_EXCEEDED")
                journal.quotas_used[bkey] = used + res_amt
        return VerifierResult("ADMIT", None, outcome="executed", details={"grant_id": gid, "session_id": sess.get("session_id")})

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
    ) -> VerifierResult:
        """Verify full 4-step exclusive service migration cut-over (SPEC-07 §2, H-13, Decision 6B)."""
        ok_w, res = self._verify_object_wire(migration_env, expected_type="seallink-migration/1")
        if not ok_w:
            return VerifierResult("REFUSE", res)
        mp = res["payload"]
        if mp["network"] != self.pinned_network or mp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        if chain is None:
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)
        manifests = presented_manifests or {}

        # 1. Verify source_executor signature against its confirmed manifest service.receipt_key
        src = mp["source_executor"]
        s_nrec, s_nerr = self.resolve_name(
            src["name"], chain, expected_owner_policy=src["owner_policy"], expected_registration=src["registration"]
        )
        if s_nerr:
            return VerifierResult("REFUSE", s_nerr)
        assert s_nrec is not None
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

        # 2. Verify export boundary compliance: strict MigrationInventory schema OR legacy export_bundle["files"]
        inv_ok = False
        if "inventory" in export_bundle and isinstance(export_bundle["inventory"], dict):
            inv_obj = export_bundle["inventory"]
            inv_err = (
                validate_against_schema("schemas/invocation.schema.json#/$defs/MigrationInventory", inv_obj, require_jsonschema=self.require_jsonschema)
                if self.enforce_schemas
                else None
            )
            inv_ok = (
                inv_err is None
                and inv_obj.get("migration_id") == mp["migration_id"]
                and inv_obj.get("holder_name") == mp["holder"]["name"]
                and inv_obj.get("service_type") == mp["service_type"]
                and sl.sha256(sl.jcs_encode(inv_obj)).hex() == mp["inventory_sha256"]
            )
        else:
            files = export_bundle.get("files")
            if isinstance(files, list) and all(isinstance(f, dict) for f in files):
                has_forbidden = any(
                    f.get("kind") in FORBIDDEN_EXPORT_KINDS
                    or (isinstance(f.get("object"), dict) and (any(k in f["object"] for k in ("private_key", "secret_key", "bearer_token")) or f["object"].get("payload", {}).get("type") == "seallink-grant/1"))
                    for f in files
                )
                inv_ok = (not has_forbidden) and (sl.sha256(sl.jcs_encode({"files": files})).hex() == mp["inventory_sha256"])

        # 3. Require fenced source journal matching pos/commitment & zero unclosed predecessor grants
        if (
            not inv_ok
            or export_bundle.get("source_journal_pos") != mp["journal_pos"]
            or export_bundle.get("source_journal_commitment") != mp["journal_commitment"]
            or not export_bundle.get("source_write_token_fenced", False)
            or bool(export_bundle.get("open_predecessor_grants", []))
        ):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")

        # 4. Holder assent (with ward custody_change quorum & autonomous holder sig check!), holder manifest binding, & dest accept stmt
        h_assent = holder_assent if holder_assent is not None else export_bundle.get("holder_assent")
        if h_assent is not None:
            ok_ha, ha_res = self._verify_object_wire(h_assent, expected_type="seallink-assent/1")
            hap = ha_res["payload"] if ok_ha else {}
            if (
                not ok_ha
                or hap.get("target_type") != "seallink-migration/1"
                or hap.get("target_id") != sl.object_id(mp)
                or hap.get("party_name") != mp["holder"]["name"]
            ):
                return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
            h_nrec, h_nerr = self.resolve_name(
                mp["holder"]["name"], chain, expected_owner_policy=mp["holder"]["owner_policy"], expected_registration=mp["holder"]["registration"]
            )
            if h_nerr:
                return VerifierResult("REFUSE", h_nerr)
            assert h_nrec is not None
            wstate_h: dict[str, Any] | None = None
            if h_nrec.get("_historical_origin_id") or origin_bundle is not None:
                wstate_h, woerr = self.verify_origin_and_status(origin_bundle, chain)
                if woerr:
                    return VerifierResult("REFUSE", woerr)
                assert wstate_h is not None
                if wstate_h["capacity"] == "ward":
                    ok_wg, wgerr, _ = self.verify_ward_approvals(ha_res, wstate_h, chain)
                    if not ok_wg:
                        return VerifierResult("REFUSE", wgerr)
            if wstate_h is None or wstate_h["capacity"] != "ward":
                hpol, hrerr = self.resolve_role_policy(h_nrec, "grant", ha_res.get("signatures", {}).get("policy"))
                ok_hs = (
                    hrerr is None
                    and sl.verify_signature_set(sl.signing_digest(hap), ha_res.get("signatures", {}), expected_policy=hpol, obj_type="seallink-assent/1")[0]
                )
                if not ok_hs:
                    return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
            if h_nrec.get("_value_obj", {}).get("m") is not None and (mp["holder"]["name"] in manifests or h_nrec["_value_obj"]["m"]["h"] in manifests):
                h_man, h_merr = self.resolve_manifest(mp["holder"]["name"], h_nrec, manifests, chain, journal)
                if h_merr:
                    return VerifierResult("REFUSE", h_merr)
                assert h_man is not None
                dest = mp["dest_executor"]
                if not any(
                    p.get("service_type") == mp["service_type"] and _name_pin_equal(p.get("provider"), dest)
                    for p in h_man.get("providers", [])
                ):
                    return VerifierResult("REFUSE", "SERVICE_PROVIDER_UNBOUND")

        d_stmt = dest_accept_stmt if dest_accept_stmt is not None else export_bundle.get("dest_accept_stmt")
        if d_stmt is not None:
            dest = mp["dest_executor"]
            d_nrec, d_nerr = self.resolve_name(
                dest["name"], chain, expected_owner_policy=dest["owner_policy"], expected_registration=dest["registration"]
            )
            d_man, d_merr = (
                self.resolve_manifest(dest["name"], d_nrec, manifests, chain, journal)
                if (d_nerr is None and d_nrec is not None)
                else (None, d_nerr)
            )
            d_rkey = d_man.get("service", {}).get("receipt_key") if d_man else None
            s_res = self.verify_statement(d_stmt, chain, expected_policy={"m": 1, "pks": [d_rkey]} if d_rkey else None) if d_merr is None else VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
            dsp = d_stmt.get("payload", {}) if isinstance(d_stmt, dict) else {}
            dsubj = dsp.get("subject", {}) if isinstance(dsp, dict) else {}
            if (
                d_merr is not None
                or s_res.verdict != "ADMIT"
                or dsp.get("statement_kind") != "migration-accept"
                or dsubj.get("migration_id") != mp["migration_id"]
                or dsubj.get("inventory_sha256") != mp["inventory_sha256"]
                or not _name_pin_equal(dsubj.get("holder"), mp["holder"])
                or not _name_pin_equal(dsubj.get("source_executor"), src)
            ):
                return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")

        mid = mp["migration_id"]
        if mid in journal.migrations_applied:
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        jw_m = journal.append(
            "migration-applied",
            {
                "holder_name": mp["holder"]["name"],
                "inventory_sha256": mp["inventory_sha256"],
                "migration_id": mid,
                "recorded_at": chain.now,
                "source_name": src["name"],
            },
        )
        return VerifierResult("ADMIT", None, outcome="executed", journal_writes=[jw_m])

    def verify_federation_disclosure(
        self,
        policy: dict[str, Any],
        peer_ctx: dict[str, Any],
        grant_env: dict[str, Any],
        chain: ChainView | None = None,
        *,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
    ) -> VerifierResult:
        """Verify two-phase federated screening and L2-gated Contour A PII disclosure (SPEC-07 §3, H-14, Decision 6B)."""
        ok_g, g_res = self._verify_object_wire(grant_env, expected_type="seallink-grant/1")
        if not ok_g:
            return VerifierResult("REFUSE", g_res)
        gp = g_res["payload"]
        if peer_ctx.get("phase") == "screening":
            has_quota = any(bool(c.get("quotas")) for c in gp.get("capabilities", []))
            if not has_quota or peer_ctx.get("peer_id") not in set(policy.get("trusted_peers", [])):
                return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
            return VerifierResult("ADMIT", None, outcome="executed")
        if peer_ctx.get("phase") == "pii_disclosure":
            # Derive route safety strictly from route_hops[] & L2 approve-pii-disclosure bound to manifest sets.devices (Contour A, H-14)
            hops = peer_ctx.get("route_hops", [])
            approval_cmd = peer_ctx.get("approval_command")
            dev_list = peer_ctx.get("device_list")
            route_and_inputs_ok = (
                isinstance(hops, list)
                and bool(hops)
                and not any(not isinstance(h, dict) or h.get("role") == "screening_agent" for h in hops)
                and approval_cmd is not None
                and dev_list is not None
                and chain is not None
            )
            owner_man = None
            man_ok = True
            if route_and_inputs_ok:
                manifests = presented_manifests or peer_ctx.get("manifests") or {}
                iss_pin = gp.get("issuer")
                if isinstance(iss_pin, dict):
                    h_nrec, h_nerr = self.resolve_name(
                        iss_pin["name"], chain, expected_owner_policy=iss_pin["owner_policy"], expected_registration=iss_pin["registration"]
                    )
                    if h_nerr is None and h_nrec is not None and h_nrec.get("_value_obj", {}).get("m") is not None:
                        o_man, o_merr = self.resolve_manifest(iss_pin["name"], h_nrec, manifests, chain)
                        if o_merr is not None:
                            man_ok = False
                        else:
                            owner_man = o_man
            cmd_ok = False
            if route_and_inputs_ok and man_ok:
                cmd_res = self.verify_owner_command(
                    approval_cmd, dev_list, is_foreign_service=False, chain=chain, owner_manifest=owner_man
                )
                cp = approval_cmd["payload"] if cmd_res.verdict == "ADMIT" else {}
                cargs = cp.get("arguments", {}) if isinstance(cp, dict) else {}
                cmd_ok = (
                    cmd_res.verdict == "ADMIT"
                    and cp.get("level") == 2
                    and cp.get("command") == "approve-pii-disclosure"
                    and cargs.get("grant_id") == sl.object_id(gp)
                    and cargs.get("route_mode") == "direct"
                    and not (gp["recipient"].get("mode") == "name" and cargs.get("recipient_name") != gp["recipient"]["name"])
                    and not ("fields_sha256" in peer_ctx and cargs.get("fields_sha256") != peer_ctx["fields_sha256"])
                )
            if cmd_ok:
                return VerifierResult("ADMIT", None, outcome="executed", details={"grant_id": sl.object_id(gp), "route_mode": "direct"})
        return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
