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
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import seallink_ref as sl

ROOT = Path(__file__).resolve().parent.parent

# Action profile metadata (SPEC-07 §4.1, PROFILE-mail-v1 §3, PROFILE-agent-v1 §3)
ACTION_PROFILES: dict[str, dict[str, Any]] = {
    "mail/list": {
        "service_type": "mail",
        "mechanical": True,
        "external_mutation": False,
        "discloses_data": True,
        "quota_consuming": False,
        "allows_executor_ref": True,
        "requires_contract": False,
        "require_seal": True,
        "risk_class": 2,
        "args_schema": "schemas/profile-mail.schema.json#/$defs/MailListArgs",
    },
    "mail/read": {
        "service_type": "mail",
        "mechanical": True,
        "external_mutation": False,
        "discloses_data": True,
        "quota_consuming": False,
        "allows_executor_ref": True,
        "requires_contract": False,
        "require_seal": True,
        "risk_class": 2,
        "args_schema": "schemas/profile-mail.schema.json#/$defs/MailReadArgs",
    },
    "mail/send": {
        "service_type": "mail",
        "mechanical": True,
        "external_mutation": True,
        "discloses_data": False,
        "quota_consuming": True,
        "allows_executor_ref": False,
        "requires_contract": False,
        "require_seal": True,
        "risk_class": 1,
        "args_schema": "schemas/profile-mail.schema.json#/$defs/MailSendArgs",
    },
    "agent/brief": {
        "service_type": "agent-session",
        "mechanical": False,
        "external_mutation": False,
        "discloses_data": False,
        "quota_consuming": True,
        "allows_executor_ref": False,
        "requires_contract": False,
        "require_seal": False,
        "risk_class": 2,
        "args_schema": "schemas/profile-agent.schema.json#/$defs/AgentBriefArgs",
    },
    "agent/tool": {
        "service_type": "agent-session",
        "mechanical": True,
        "external_mutation": True,
        "discloses_data": True,
        "quota_consuming": True,
        "allows_executor_ref": False,
        "requires_contract": False,
        "require_seal": True,
        "risk_class": 1,
        "args_schema": "schemas/profile-agent.schema.json#/$defs/AgentToolArgs",
    },
    "agent/session": {
        "service_type": "agent-session",
        "mechanical": True,
        "external_mutation": True,
        "discloses_data": False,
        "quota_consuming": True,
        "allows_executor_ref": False,
        "requires_contract": True,
        "require_seal": True,
        "risk_class": 1,
        "args_schema": "schemas/profile-agent.schema.json#/$defs/AgentSessionArgs",
    },
    "agent/guardian-message": {
        "service_type": "agent-session",
        "mechanical": True,
        "external_mutation": False,
        "discloses_data": False,
        "quota_consuming": False,
        "allows_executor_ref": False,
        "requires_contract": False,
        "require_seal": True,
        "risk_class": 1,
        "args_schema": "schemas/profile-agent.schema.json#/$defs/AgentGuardianMessageArgs",
    },
}

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


def validate_against_schema(schema_ref: str, obj: Any, *, require_jsonschema: bool = True) -> str | None:
    """Validate `obj` against a Draft 2020-12 schema ref. Fail-closed if jsonschema is unavailable."""
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
    for _err in val.iter_errors(obj):
        return "WIRE_MEMBER"
    return None


def _outpoint_key(op: dict[str, Any]) -> str:
    return f"{op['txid']}:{op['vout']}"


def _normalize_policy(p: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"m": p["m"], "pks": list(p["pks"])}
    if "alg" in p and p["alg"] != "bip340":
        out["alg"] = p["alg"]
    return out


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
    actual_usage: dict[str, int] | None = None,
) -> tuple[int, int]:
    """Compute profile-driven (reserve_amount, settle_amount) using exact integer arithmetic."""
    qkey = f"{quota['kind']}|{quota['resource']}|{quota['unit']}|{quota['window']}"
    kind = quota["kind"]
    if kind == "seallink/count":
        reserve = 1
    elif kind == "seallink/bytes":
        raw = arguments.get("max_output_bytes") or arguments.get("size_bytes") or arguments.get("max_bytes") or "1"
        reserve = int(raw)
    elif kind == "seallink/duration":
        raw = arguments.get("max_duration_sec") or arguments.get("max_wall_sec") or "1"
        reserve = int(raw)
    elif kind in ("seallink/tokens", "seallink/cost"):
        raw = arguments.get("max_tokens") or arguments.get("max_cost") or "1"
        reserve = int(raw)
    else:
        reserve = 1
    if actual_usage is not None and qkey in actual_usage:
        settle = int(actual_usage[qkey])
        if settle < 0 or settle > reserve:
            settle = reserve
    else:
        settle = reserve
    return reserve, settle


@dataclass
class VerifierResult:
    verdict: str  # "ADMIT", "REFUSE", "UNCERTAIN"
    refusal_code: str | None = None
    outcome: str = "refused"  # "executed", "refused", "uncertain"
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
        self.unsettled_reservations: dict[str, list[dict[str, Any]]] = {}
        self.quotas_used: dict[tuple[str, str, str], int] = {}
        self.quota_watermarks: dict[str, int] = {}
        self.manifest_heads: dict[tuple[str, str], dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.auth_nonces: dict[str, dict[str, Any]] = {}
        self.migrations_applied: set[str] = set()

    @classmethod
    def from_dict(cls, cfg: dict[str, Any]) -> "FencedJournal":
        j = cls(cfg["journal_id"])
        j.witness_readable = cfg.get("witness_readable", True)
        j.store_readable = cfg.get("store_readable", True)
        j.witness_journal_id = cfg.get("witness_journal_id", j.journal_id)
        j.write_token_active = cfg.get("write_token_active", True)
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
        for k, v in cfg.get("unsettled_reservations", {}).items():
            j.unsettled_reservations[k] = copy.deepcopy(v) if isinstance(v, list) else [copy.deepcopy(v)]
        for item in cfg.get("quotas_used", []):
            j.quotas_used[(item["scope"], item["quota_key"], item["bucket_id"])] = int(item["used"])
        for k, v in cfg.get("quota_watermarks", {}).items():
            j.quota_watermarks[k] = int(v)
        for item in cfg.get("manifest_heads", []):
            j.manifest_heads[(item["name"], item["reg_key"])] = copy.deepcopy(item)
        for k, v in cfg.get("sessions", {}).items():
            j.sessions[k] = copy.deepcopy(v)
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
    ) -> "FencedJournal":
        """Reconstruct a fresh FencedJournal strictly by replaying persisted journal entries.

        Restores hash-chain commitment, closures, nonces, per-account/per-row_ordinal quota balances,
        monotonic per-quota clock watermarks (for seconds:* windows), manifest heads, and—when a
        content-addressed `receipt_store` is supplied—the verified cached receipt index.
        """
        j = cls(journal_id)
        if receipt_store is not None:
            j.receipt_store = {k: copy.deepcopy(v) for k, v in receipt_store.items()}
        for e in persisted_entries:
            assert e["journal_id"] == journal_id and e["pos"] == j.pos + 1 and e["prev_commitment"] == j.commitment
            j.append(e["kind"], e["body"])
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
            self.closures[body["subject_id"]] = copy.deepcopy(body)
        elif kind == "nonce":
            self.nonces[body["nonce"]] = body["invocation_id"]
        elif kind == "reservation":
            scope = f"row:{body['grant_id']}:{body['row_ordinal']}" if body["account"] == "row" else f"{body['account']}:{body['grant_id']}"
            qkey = f"{body['quota_kind']}|{body['resource']}|{body['unit']}|{body['window']}"
            bkey = (scope, qkey, body["bucket_id"])
            self.quotas_used[bkey] = self.quotas_used.get(bkey, 0) + int(body["amount"])
            self.unsettled_reservations.setdefault(body["invocation_id"], []).append(copy.deepcopy(body))
            if body["window"].startswith("seconds:") and "recorded_at" in body:
                self.quota_watermarks[qkey] = max(self.quota_watermarks.get(qkey, 0), int(body["recorded_at"]))
        elif kind == "settlement":
            inv_id = body["invocation_id"]
            if body.get("window", "").startswith("seconds:") and "recorded_at" in body and "quota_kind" in body:
                sqkey = f"{body['quota_kind']}|{body['resource']}|{body['unit']}|{body['window']}"
                self.quota_watermarks[sqkey] = max(self.quota_watermarks.get(sqkey, 0), int(body["recorded_at"]))
            rsha = body.get("receipt_sha256")
            if rsha and rsha in self.receipt_store and sl.content_addr(self.receipt_store[rsha]) == rsha:
                self.receipts[inv_id] = copy.deepcopy(self.receipt_store[rsha])
            pending = self.unsettled_reservations.get(inv_id)
            if pending:
                match_idx = 0
                if "account" in body and "quota_kind" in body:
                    for idx, r in enumerate(pending):
                        if (
                            r["account"] == body["account"]
                            and r["grant_id"] == body["grant_id"]
                            and r.get("row_ordinal") == body.get("row_ordinal")
                            and r["quota_kind"] == body["quota_kind"]
                            and r["resource"] == body["resource"]
                            and r["unit"] == body["unit"]
                            and r["window"] == body["window"]
                            and r["bucket_id"] == body["bucket_id"]
                        ):
                            match_idx = idx
                            break
                res = pending.pop(match_idx)
                if not pending:
                    del self.unsettled_reservations[inv_id]
                released = int(body.get("released", "0"))
                if released:
                    scope = f"row:{res['grant_id']}:{res['row_ordinal']}" if res["account"] == "row" else f"{res['account']}:{res['grant_id']}"
                    qkey = f"{res['quota_kind']}|{res['resource']}|{res['unit']}|{res['window']}"
                    bkey = (scope, qkey, res["bucket_id"])
                    self.quotas_used[bkey] = max(0, self.quotas_used.get(bkey, 0) - released)
        elif kind == "single-use-consumed":
            rsha = body.get("receipt_sha256")
            if rsha and rsha in self.receipt_store and sl.content_addr(self.receipt_store[rsha]) == rsha:
                self.receipts[body["invocation_id"]] = copy.deepcopy(self.receipt_store[rsha])
        elif kind == "manifest-head":
            self.manifest_heads[(body["name"], _outpoint_key(body["registration"]))] = {
                "seq": int(body["seq"]),
                "sha256": body["manifest_sha256"],
            }
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
    ) -> None:
        self.pinned_network = pinned_network
        self.pinned_genesis = pinned_genesis
        self.operator_min_depth = operator_min_depth
        self.allow_window_only = allow_window_only
        self.trusted_origin_issuers = set(trusted_origin_issuers) if trusted_origin_issuers is not None else set()
        self.enforce_schemas = enforce_schemas
        self.require_jsonschema = require_jsonschema
        self.max_history_steps = max_history_steps

    # ------------------------------------------------------------------
    # SPEC-01 §7 Wire Pipeline (steps 1..10, closed Draft 2020-12 schemas)
    # ------------------------------------------------------------------

    def verify_wire_bytes(
        self,
        raw: bytes,
        schema_validator_fn: Any = None,
        max_bytes_override: int | None = None,
    ) -> tuple[bool, Any]:
        """Execute SPEC-01 §7 steps 1..10 on raw bytes. Returns (True, obj) or (False, refusal_code)."""
        max_b = max_bytes_override if max_bytes_override is not None else 1048576
        ok, res = sl.jcs_validate(raw, max_bytes=max_b)
        if not ok:
            return False, res
        obj = res
        reg = registered_types()
        # Extract type
        if "payload" in obj:
            if not isinstance(obj["payload"], dict):
                return False, "WIRE_MEMBER"
            obj_type = obj["payload"].get("type")
        else:
            obj_type = obj.get("type")
        if obj_type is not None:
            if not isinstance(obj_type, str) or obj_type not in reg:
                return False, "WIRE_TYPE"
            type_max = reg[obj_type]["max_bytes"]
            if len(raw) > type_max:
                return False, "WIRE_SIZE"
        # Check domain-specific wire semantics before generic schema mapping so WIRE_CONSTRAINT / WIRE_INTEGER win
        code = self._check_wire_semantics(obj)
        if code:
            return False, code
        # Closed Draft 2020-12 JSON Schema validation (object + profile action args)
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
        # Key & signature verification for signed envelopes (enforces BIP-340, Ed25519, low-S P-256 & SL-WIRE-013)
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
            if isinstance(nb, int) and isinstance(na, int):
                if nb >= na:
                    return "WIRE_INTEGER"
                rev = payload.get("revocation", {})
                if isinstance(rev, dict) and rev.get("mode") == "window_only" and (na - nb) > 12:
                    return "WIRE_INTEGER"
            caps = payload.get("capabilities", [])
            if isinstance(caps, list):
                for cap in caps:
                    if not isinstance(cap, dict):
                        continue
                    if "extensions" in cap:
                        return "WIRE_CONSTRAINT"
                    where = cap.get("where", {})
                    if isinstance(where, dict):
                        for pred in where.values():
                            if not isinstance(pred, dict) or not sl.validate_predicate(pred):
                                return "WIRE_CONSTRAINT"
                    for q in cap.get("quotas", []):
                        if not isinstance(q, dict):
                            continue
                        mx = q.get("max")
                        if not isinstance(mx, str) or not sl.UINT64_STR_RE.match(mx) or int(mx) > sl.MAX_UINT64:
                            return "WIRE_INTEGER"
            if "delegate" in payload and isinstance(payload["delegate"], dict):
                for g in payload["delegate"].get("groups", []):
                    if not isinstance(g, dict):
                        continue
                    for cap in g.get("template", {}).get("capabilities", []):
                        if not isinstance(cap, dict):
                            continue
                        if "extensions" in cap:
                            return "WIRE_CONSTRAINT"
                        for pred in cap.get("where", {}).values():
                            if not isinstance(pred, dict) or not sl.validate_predicate(pred):
                                return "WIRE_CONSTRAINT"
        elif t == "seallink-origin/1":
            if "guardian_policy" in payload and isinstance(payload["guardian_policy"], dict):
                ok_g, code_g = sl.check_guardian_policy_consistency(payload["guardian_policy"])
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
        return None

    @staticmethod
    def _decode_opreturn_tx(
        tx: dict[str, Any] | None,
        *,
        require_confirmed: bool = True,
        expected_action: str | None = None,
        expected_commitment: str | None = None,
    ) -> dict[str, Any] | None:
        """Decode and validate an SLNK OP_RETURN frame on `tx`. Returns decoded dict or None."""
        if not tx or not tx.get("opreturn_hex"):
            return None
        if require_confirmed and tx.get("confirmed_height") is None:
            return None
        try:
            dec = sl.decode_opreturn(bytes.fromhex(tx["opreturn_hex"]))
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

    def check_chain_observation(self, chain: ChainView, risk_class: int = 1) -> str | None:
        if chain.network != self.pinned_network or chain.genesis != self.pinned_genesis:
            return "CHAIN_MISMATCH"
        c = chain.raw
        lag_limit = c.get("lag_limit", 1)
        if c.get("in_ibd", False) or not c.get("txindex", True) or not c.get("node_reachable", True):
            return "CHAIN_UNHEALTHY"
        best_hdr = c.get("best_header_height", chain.tip_height)
        if best_hdr - chain.tip_height > lag_limit:
            return "CHAIN_UNHEALTHY"
        # Require >= 1 healthy independent comparison peer (SL-LDGR-008 item 2)
        healthy_peers = [p for p in c.get("comparison_peers", []) if isinstance(p, dict) and p.get("healthy", True)]
        if not healthy_peers:
            return "CHAIN_UNHEALTHY"
        for peer in healthy_peers:
            if peer.get("height", chain.tip_height) > chain.tip_height:
                return "CHAIN_NODE_DISAGREEMENT"
            if peer.get("hash_at_tip", chain.tip_hash) != chain.tip_hash:
                return "CHAIN_NODE_DISAGREEMENT"
        # Clock watermark & future header bound S
        now = chain.now
        watermark = c.get("clock_watermark", 0)
        if now < watermark:
            return "CHAIN_CLOCK_ERROR"
        hdr_time = c.get("tip_header_time", now - 60)
        future_s = c.get("future_bound_s", 600)
        if hdr_time - now > future_s:
            return "CHAIN_CLOCK_ERROR"
        first_sight = c.get("tip_first_sight", hdr_time)
        tip_age = max(now - hdr_time, now - first_sight)
        cutoff = 3600 if risk_class == 1 else 5400
        if tip_age > cutoff:
            return "CHAIN_TIP_STALE"
        return None

    def check_rebracket(self, chain: ChainView, risk_class: int = 1) -> str | None:
        rb = chain.raw.get("rebracket_tip")
        if not rb:
            return None
        if rb.get("height") != chain.tip_height or rb.get("hash") != chain.tip_hash:
            return "CHAIN_OBSERVATION_VOID"
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
                if len(item) >= 16 and item.startswith("30"):
                    saw_sig = True
                    if not item.endswith("01"):
                        return False
            if not saw_sig:
                return False
        return True

    def _extract_single_use_branch(self, seal: dict[str, Any], spend_tx: dict[str, Any]) -> int | None:
        """Derive single_use_1_of_2 spend branch (0=grantee, 1=issuer) strictly from spend_tx.inputs[].witness."""
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
                if ws_hex != exp_ws_hex:
                    return None
                if not (isinstance(sig_hex, str) and len(sig_hex) >= 16 and sig_hex.endswith("01")):
                    return None
                if selector == "01":
                    return 1
                if selector == "":
                    return 0
                return None
        return None

    def evaluate_seal(
        self,
        seal: dict[str, Any],
        chain: ChainView,
        required_depth: int = 1,
        journal: FencedJournal | None = None,
        subject_id: str | None = None,
        subject_kind: str = "grant",
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
            if journal is not None and subject_id is not None:
                jw = journal.append(
                    "closure",
                    {
                        "cause": "SEAL_SPENT",
                        "observed_at": chain.now,
                        "observed_height": chain.tip_height,
                        "spend_txid": out.get("spent_by_txid", "0" * 64),
                        "subject_id": subject_id,
                        "subject_kind": subject_kind,
                    },
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
                jw = journal.append(
                    "closure",
                    {
                        "cause": "SEAL_SPENT",
                        "observed_at": chain.now,
                        "observed_height": chain.tip_height,
                        "spend_txid": spent_by or ("0" * 64),
                        "subject_id": grant_id,
                        "subject_kind": "grant",
                    },
                )
            return "revoked", "SEAL_SPENT", jw

        # Branch 0 (grantee): verify use_txid match & OP_RETURN 0x11 == invocation_content_addr
        assert spend_tx is not None
        if (use_txid is not None and spent_by != use_txid) or self._decode_opreturn_tx(
            spend_tx, require_confirmed=False, expected_action="0x11", expected_commitment=invocation_content_addr
        ) is None:
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
        """Parse exact Namecoin output script and validate 520B JCS name value & role disjointness."""
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
            return None, "NAME_VALUE_INVALID"
        # Role key disjointness check (SL-IDEN-003)
        used_keys: set[str] = set()
        link = val_obj.get("link", {})
        if isinstance(link, dict):
            for r in ("grant", "cred", "notary"):
                rk = link.get(r)
                if isinstance(rk, str):
                    if rk in used_keys:
                        return None, "NAME_VALUE_INVALID"
                    used_keys.add(rk)
        nostr = val_obj.get("nostr")
        if isinstance(nostr, str):
            if nostr in used_keys:
                return None, "NAME_VALUE_INVALID"
            used_keys.add(nostr)
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
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Resolve a Namecoin name strictly by walking its structured updates[] history."""
        rec = chain.get_name_for_registration(name, expected_registration, historical=(at_height is not None))
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

        # Derive SIGHASH_ALL owner authorship (SL-LDGR-007)
        if require_writer:
            if target_idx == 0 or not self._is_owner_authored_update(target_upd, updates[target_idx - 1]):
                return None, "NAME_WRITER_UNVERIFIED"

        # Check expected owner_policy byte-for-byte via ScriptPolicy compilation
        if expected_owner_policy is not None:
            try:
                exp_spk, _ = sl.compile_script_policy(expected_owner_policy)
                got_spk, _ = sl.compile_script_policy(target_upd["owner_policy"])
            except (ValueError, KeyError, TypeError):
                return None, "CHAIN_SCRIPT_UNSUPPORTED"
            if exp_spk != got_spk:
                return None, "NAME_OWNER_MISMATCH"

        val_obj, val_err = self._parse_update_value(target_upd, name)
        if val_err:
            return None, val_err

        # Derive 0x0b compromise breaks & 0x10 recovery cancels from owner-authored updates in history
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
            if dec["action"] == "0x0b":
                pinp = u["prev_input"]
                compromised_breaks.append({
                    "h_c": dec["h_c"],
                    "commitment": dec["commitment"],
                    "inclusion_height": u["confirmed_height"],
                    "name_input": {"txid": pinp["txid"], "vout": pinp["vout"]},
                })
            elif dec["action"] == "0x10":
                recovery_cancels.append({
                    "binding_id": dec["commitment"],
                    "confirmed_height": u["confirmed_height"],
                })

        return {
            **rec,
            "owner_policy": target_upd["owner_policy"],
            "_value_obj": val_obj,
            "_target_update_idx": target_idx,
            "_name": name,
            "_compromised_breaks": compromised_breaks,
            "_recovery_cancels": recovery_cancels,
        }, None

    def resolve_role_policy(
        self,
        name_rec: dict[str, Any],
        role: str,
        presented_role_policy: dict[str, Any] | None = None,
        recent_block_height: int | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Resolve link.<role> and derive role continuity across updates[] since recent_block_height."""
        updates = name_rec.get("updates", [])
        target_name = name_rec.get("_name", "")
        if recent_block_height is not None and updates:
            baseline_entry = None
            has_baseline = False
            for u in updates:
                uh = u.get("confirmed_height")
                if uh is None:
                    continue
                vobj, verr = self._parse_update_value(u, target_name)
                if verr:
                    return None, verr
                assert vobj is not None
                cur_entry = vobj.get("link", {}).get(role)
                if uh <= recent_block_height:
                    baseline_entry = cur_entry
                    has_baseline = True
                elif has_baseline and cur_entry != baseline_entry:
                    return None, "NAME_ROLE_CHANGED"

        link = name_rec.get("_value_obj", {}).get("link", {})
        entry = link.get(role)
        if entry is None:
            return None, "NAME_ROLE_CHANGED"
        if isinstance(entry, str):
            resolved = {"m": 1, "pks": [entry]}
        elif isinstance(entry, dict) and "p" in entry:
            if presented_role_policy is None:
                return None, "WIRE_SIGNATURE"
            if sl.sha256(sl.jcs_encode(presented_role_policy)).hex() != entry["p"]:
                return None, "WIRE_SIGNATURE"
            resolved = _normalize_policy(presented_role_policy)
        else:
            return None, "NAME_VALUE_INVALID"
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
        """Reconstruct seallink-credential-break/1 from on-chain 0x0b frames and check exact policy scope."""
        if role not in ("cred", "notary"):
            return False
        issuer_name_pin = {
            "name": issuer_pin["name"],
            "owner_policy": issuer_pin["owner_policy"],
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
        if p["expires_at"] <= p["issued_at"] or (p["expires_at"] - p["issued_at"]) > 120 or chain.now >= p["expires_at"]:
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_EXPIRED")
        if p["service_id"] != service_id:
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_INVALID")
        nonce = p["nonce"]
        rec = journal.auth_nonces.get(nonce)
        if rec is None or rec.get("used", False) or rec.get("service_id") != service_id:
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_INVALID")
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

    def verify_owner_command(
        self,
        cmd_env: dict[str, Any],
        device_list: dict[str, Any],
        is_foreign_service: bool,
        chain: ChainView,
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
        if p["command"] in ("policy-apply", "keyholder-halt") and (matched["ceiling"] < 2 or not matched.get("presence", False)):
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
        initial_owner_policy: dict[str, Any],
        subject_new_owner_policy: dict[str, Any] | None,
        chain: ChainView,
    ) -> bool:
        """Derive SL-ORIG-011 emancipation handover strictly from ward name.updates[]."""
        rec = chain.get_name(ward_name)
        if not rec or not isinstance(rec.get("updates"), list) or len(rec["updates"]) < 3:
            return False
        updates = rec["updates"]
        init_spk, _ = sl.compile_script_policy(initial_owner_policy)
        target_spk = sl.compile_script_policy(subject_new_owner_policy)[0] if subject_new_owner_policy else None
        # Find confirmed transfer to fresh subject_new_owner_policy followed by subject-authored SIGHASH_ALL NAME_UPDATE
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

    def verify_origin_and_status(
        self,
        origin_bundle: dict[str, Any],
        chain: ChainView,
        *,
        assert_binding_id: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Walk origin/1, name-binding/1 + full recovery spine, status_seal, roster_seal, and per-slot states."""
        origin_env = origin_bundle.get("origin")
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

        # Verify origin 0x09 anchor
        origin_txid = origin_bundle.get("origin_anchor_txid")
        origin_tx = chain.get_tx(origin_txid) if origin_txid else None
        dec_o = self._decode_opreturn_tx(origin_tx, expected_action="0x09", expected_commitment=sl.content_addr(origin_env))
        if dec_o is None:
            return None, "ORIGIN_UNVERIFIED"
        assert origin_tx is not None
        h_origin = origin_tx["confirmed_height"]
        origin_id = sl.object_id(op)

        # Authoritatively bind origin/1 signature to issuer's link.cred at h_origin + policy-scoped 0x0b h_c cutoff!
        iss_err = self.verify_issuer_role_at_height(op["issuer"], origin_env, "cred", h_origin, chain)
        if iss_err:
            if iss_err in ("CRED_ISSUER_CLOSED", "WIRE_SIGNATURE"):
                return None, iss_err
            return None, "ORIGIN_UNVERIFIED"

        # Verify initial NameBinding (0x0c)
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
        bind_tx = chain.get_tx(bind_txid)
        dec_b = self._decode_opreturn_tx(bind_tx, expected_action="0x0c", expected_commitment=sl.object_id(binding))
        if dec_b is None or bind_tx["confirmed_height"] <= h_origin:
            return None, "ORIGIN_BINDING_INVALID"
        reg_key = _outpoint_key(binding["registration"])
        existing_oid = chain.raw.get("registered_bindings", {}).get(reg_key)
        if existing_oid is not None and existing_oid != origin_id:
            return None, "ORIGIN_BINDING_INVALID"

        # Walk full name_recovery continuation spine (SPEC-04 §6)
        active_binding = binding
        active_recovery_seal: dict[str, Any] | None = None
        recovery_events: list[dict[str, Any]] = []
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
            if sl.compile_script_policy(cur_rec_seal["script_policy"])[0] != exp_rec_spk:
                return None, "CHAIN_SCRIPT_UNSUPPORTED"
            active_recovery_seal = cur_rec_seal
            for _ in range(16):
                rout = chain.get_output(cur_rec_seal["txid"], cur_rec_seal["vout"])
                if not rout:
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                rspend = rout.get("spent_by_txid")
                if not rspend:
                    break
                rtx = chain.get_tx(rspend)
                dec_r = self._decode_opreturn_tx(rtx, expected_action="0x0c")
                if dec_r is None:
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                assert rtx is not None
                cand_id = dec_r["commitment"]
                cand = rec_by_id.get(cand_id)
                if (
                    cand is None
                    or cand["origin_id"] != origin_id
                    or cand.get("supersedes_binding_id") != sl.object_id(active_binding)
                    or cand["seq"] <= active_binding["seq"]
                    or "next_recovery_vout" not in cand
                    or "next_recovery_policy" not in cand
                    or sl.compile_script_policy(cand["next_recovery_policy"])[0] != exp_rec_spk
                ):
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                next_seal_out = chain.get_output(rspend, cand["next_recovery_vout"])
                if not next_seal_out or next_seal_out.get("script_pubkey_hex") != exp_rec_spk.hex():
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                next_rec_seal = {
                    "txid": rspend,
                    "vout": cand["next_recovery_vout"],
                    "script_policy": cand["next_recovery_policy"],
                }
                h_rec = rtx["confirmed_height"]
                deadline = h_rec + nr["delay_blocks"]
                # Check derived owner-authored 0x10 RECOVERY_CANCEL in active_binding["name"] updates[]
                old_nrec, _ = self.resolve_name(
                    active_binding["name"],
                    chain,
                    expected_owner_policy=active_binding["owner_policy"],
                    require_writer=False,
                    require_history=False,
                )
                cancelled = False
                if old_nrec is not None:
                    for c_ev in old_nrec.get("_recovery_cancels", []):
                        if c_ev["binding_id"] == cand_id and c_ev["confirmed_height"] < deadline:
                            cancelled = True
                            break
                if cancelled:
                    recovery_events.append({"candidate_id": cand_id, "outcome": "cancelled_restored", "next_recovery_seal": next_rec_seal})
                    if assert_binding_id is not None and assert_binding_id == cand_id:
                        return None, "RECOVERY_FORBIDDEN"
                    # B_k restored immediately; recovery seal advances to (T_rec, next_recovery_vout)!
                    cur_rec_seal = next_rec_seal
                    active_recovery_seal = next_rec_seal
                    continue
                if chain.tip_height < deadline:
                    return None, "RECOVERY_FORBIDDEN"
                # Delay elapsed without 0x10 cancel -> B_{k+1} promoted!
                prev_id = sl.object_id(active_binding)
                recovery_events.append({"candidate_id": cand_id, "outcome": "promoted", "superseded_id": prev_id, "next_recovery_seal": next_rec_seal})
                if assert_binding_id is not None and assert_binding_id == prev_id:
                    return None, "ORIGIN_BINDING_INVALID"
                active_binding = cand
                cur_rec_seal = next_rec_seal
                active_recovery_seal = next_rec_seal

        # Walk status_seal spine (verifying authoritative issuer link.cred at anchor height on capacity/1 & end/1!)
        cur_status_seal = op["status_seal"]
        emancipated = False
        subject_new_owner_policy: dict[str, Any] | None = None
        cap_rec = origin_bundle.get("capacity_record")
        end_rec = origin_bundle.get("end_record")
        for _ in range(3):
            sout = chain.get_output(cur_status_seal["txid"], cur_status_seal["vout"])
            if not sout:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            spend_txid = sout.get("spent_by_txid")
            if not spend_txid:
                break
            stx = chain.get_tx(spend_txid)
            dec_s = self._decode_opreturn_tx(stx, expected_action="0x09")
            if dec_s is None:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            assert stx is not None
            h_spend = stx["confirmed_height"]
            if end_rec is not None and sl.content_addr(end_rec) == dec_s["commitment"]:
                ok_e, _ = self._verify_object_wire(end_rec, expected_type="seallink-end/1")
                if not ok_e or end_rec["payload"]["origin_id"] != origin_id:
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                e_iss_err = self.verify_issuer_role_at_height(end_rec["payload"]["issuer"], end_rec, "cred", h_spend, chain)
                if e_iss_err:
                    return None, "CRED_ISSUER_CLOSED" if e_iss_err == "CRED_ISSUER_CLOSED" else "ORIGIN_STATUS_INCOMPLETE"
                return None, "SUBJECT_ENDED"
            if cap_rec is not None and sl.content_addr(cap_rec) == dec_s["commitment"]:
                ok_cp, _ = self._verify_object_wire(cap_rec, expected_type="seallink-capacity/1")
                if not ok_cp or cap_rec["payload"]["origin_id"] != origin_id:
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                cp = cap_rec["payload"]
                if "capacity_authority" in op and cp["issuer"]["name"] != op["capacity_authority"]["name"]:
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                c_iss_err = self.verify_issuer_role_at_height(cp["issuer"], cap_rec, "cred", h_spend, chain)
                if c_iss_err:
                    return None, "CRED_ISSUER_CLOSED" if c_iss_err == "CRED_ISSUER_CLOSED" else "ORIGIN_STATUS_INCOMPLETE"
                nxt_out = chain.get_output(spend_txid, cp["next_status_vout"])
                try:
                    nxt_spk, _ = sl.compile_script_policy(cp["next_status_policy"])
                except ValueError:
                    nxt_spk = b""
                if not nxt_out or not nxt_spk or nxt_out.get("script_pubkey_hex") != nxt_spk.hex():
                    return None, "ORIGIN_STATUS_INCOMPLETE"
                emancipated = True
                subject_new_owner_policy = cp["subject_new_owner_policy"]
                cur_status_seal = {"txid": spend_txid, "vout": cp["next_status_vout"], "script_policy": cp["next_status_policy"]}
                continue
            return None, "ORIGIN_STATUS_INCOMPLETE"

        # Check majority boundary & derived emancipation handover transfer
        opened_majority = origin_bundle.get("opened_majority_unix")
        if opened_majority is not None:
            salt_m = origin_bundle.get("majority_salt_hex")
            if salt_m and "majority_commitment" in op["claims"]:
                if sl.clause_commit(salt_m, {"majority_unix": opened_majority}) != op["claims"]["majority_commitment"]:
                    return None, "ORIGIN_UNVERIFIED"
            interval = chain.raw.get("credible_utc_interval")
            if interval is None or len(interval) != 2:
                return None, "GUARDIAN_TIME_BOUNDARY"
            t_low, t_high = interval[0], interval[1]
            if t_low < opened_majority <= t_high:
                return None, "GUARDIAN_TIME_BOUNDARY"
            if t_low >= opened_majority:
                emancipated = True

        if emancipated:
            if not self._check_emancipation_handover(
                active_binding["name"], op["claims"]["intended_owner_policy"], subject_new_owner_policy, chain
            ):
                return None, "GUARDIAN_TRANSFER_PENDING"
            return {
                "origin_id": origin_id,
                "capacity": "autonomous",
                "binding": active_binding,
                "active_recovery_seal": active_recovery_seal,
                "recovery_events": recovery_events,
            }, None

        if "guardian_policy" not in op:
            return {
                "origin_id": origin_id,
                "capacity": "autonomous",
                "binding": active_binding,
                "active_recovery_seal": active_recovery_seal,
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
        for s in gp["slots"]:
            slot_states[s["slot"]] = {
                "state": "initial_vacant",
                "vacant_outpoint": s["vacant_utxo"],
                "initial_guardian_commitment": s["initial_guardian_commitment"],
            }

        g_by_caddr = {sl.content_addr(g): g for g in origin_bundle.get("guardian_records", [])}
        g_by_id = {sl.object_id(g["payload"]): g for g in origin_bundle.get("guardian_records", [])}
        init_disclosures = origin_bundle.get("initial_guardian_disclosures", {})
        g_assents_by_target: dict[str, dict[str, Any]] = {}
        for ga in origin_bundle.get("guardian_assents", []):
            if isinstance(ga, dict) and isinstance(ga.get("payload"), dict) and "target_id" in ga["payload"]:
                g_assents_by_target[ga["payload"]["target_id"]] = ga

        def trace_slot(slot_num: int, st: dict[str, Any], roster_ctx: dict[str, Any]) -> dict[str, Any]:
            cur = copy.deepcopy(st)
            for _ in range(16):
                if cur["state"] in ("initial_vacant", "vacant"):
                    op_u = cur["vacant_outpoint"]
                    uout = chain.get_output(op_u["txid"], op_u["vout"])
                    if not uout or not uout.get("spent_by_txid"):
                        return cur
                    stxid = uout["spent_by_txid"]
                    stx = chain.get_tx(stxid)
                    if not stx or not stx.get("opreturn_hex") or stx.get("confirmed_height") is None:
                        cur["state"] = "contested_burned"
                        return cur
                    try:
                        dec = sl.decode_opreturn(bytes.fromhex(stx["opreturn_hex"]))
                    except ValueError:
                        cur["state"] = "contested_burned"
                        return cur
                    h_stx = stx["confirmed_height"]

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
                        if gp_rec["origin_id"] != origin_id or gp_rec["slot"] != slot_num or gp_rec["revision"] != 1:
                            cur["state"] = "contested_burned"
                            return cur
                        # Authoritative issuer link.cred verification at h_stx + 0x0b h_c cutoff!
                        if self.verify_issuer_role_at_height(gp_rec["issuer"], grec, "cred", h_stx, chain) is not None:
                            cur["state"] = "contested_burned"
                            return cur
                        # Mandatory incoming guardian assent verification (SL-ORIG-007)!
                        if not self._verify_guardian_incoming_assent(grec, g_assents_by_target, chain, at_height=h_stx):
                            cur["state"] = "contested_burned"
                            return cur
                        disc = init_disclosures.get(str(slot_num)) or init_disclosures.get(slot_num)
                        if not disc or sl.clause_commit(disc["salt_hex"], gp_rec["guardian"]) != cur["initial_guardian_commitment"]:
                            cur["state"] = "contested_burned"
                            return cur
                        ap_pol = gp_rec["active_policy"]
                        if ap_pol.get("template") != "either_of_2" or roster_ctx["disposer_pk"] not in (ap_pol["keys"]["a"], ap_pol["keys"]["b"]):
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
                            "guardian_name": gp_rec["guardian"]["name"],
                            "guardian_pin": gp_rec["guardian"],
                            "guardian_id": sl.object_id(gp_rec),
                            "term": gp_rec["term"],
                        }
                        continue

                    # Stage 1 appointment (0x0d)
                    if dec["action"] == "0x0d":
                        grec = g_by_caddr.get(dec["commitment"])
                        if not grec:
                            cur["state"] = "contested_burned"
                            return cur
                        ok_gw, _ = self._verify_object_wire(grec, expected_type="seallink-guardian/1")
                        if not ok_gw or grec["payload"].get("activation_mode") != "appointed":
                            cur["state"] = "contested_burned"
                            return cur
                        gp_rec = grec["payload"]
                        if gp_rec["origin_id"] != origin_id or gp_rec["slot"] != slot_num or gp_rec["revision"] != roster_ctx["revision"]:
                            cur["state"] = "contested_burned"
                            return cur
                        # Authoritative issuer link.cred verification at h_stx + 0x0b h_c cutoff!
                        if self.verify_issuer_role_at_height(gp_rec["issuer"], grec, "cred", h_stx, chain) is not None:
                            cur["state"] = "contested_burned"
                            return cur
                        # Mandatory incoming guardian assent verification (SL-ORIG-007)!
                        if not self._verify_guardian_incoming_assent(grec, g_assents_by_target, chain, at_height=h_stx):
                            cur["state"] = "contested_burned"
                            return cur
                        pp = gp_rec["pending_policy"]
                        ap_pol = gp_rec["active_policy"]
                        if (
                            pp.get("template") != "guardian_slot_pending"
                            or pp["keys"]["disposer"] != roster_ctx["disposer_pk"]
                            or pp["keys"]["challenger"] != roster_ctx["challenger_pk"]
                            or pp["delay_blocks"] != gp_rec["effective_delay_blocks"]
                            or gp_rec["effective_delay_blocks"] < roster_ctx["appointment_delay_blocks"]
                            or ap_pol.get("template") != "either_of_2"
                            or set([ap_pol["keys"]["a"], ap_pol["keys"]["b"]]) != {pp["keys"]["guardian"], roster_ctx["disposer_pk"]}
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
                    if not pout or not pout.get("spent_by_txid"):
                        return cur
                    stxid = pout["spent_by_txid"]
                    stx = chain.get_tx(stxid)
                    if not stx or stx.get("confirmed_height") is None:
                        return cur
                    opret_hex = stx.get("opreturn_hex")
                    if opret_hex:
                        try:
                            dec = sl.decode_opreturn(bytes.fromhex(opret_hex))
                        except ValueError:
                            dec = {}
                        grec = cur["guardian_record"]
                        gp_rec = grec["payload"]
                        gid = sl.object_id(gp_rec)
                        if dec.get("action") == "0x0e" and dec.get("commitment") == gid:
                            if stx["confirmed_height"] < cur["pending_height"] + cur["delay_blocks"]:
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
                                "guardian_name": gp_rec["guardian"]["name"],
                                "guardian_pin": gp_rec["guardian"],
                                "guardian_id": gid,
                                "term": gp_rec["term"],
                            }
                            continue
                    vout0 = chain.get_output(stxid, 0)
                    vac_spk, _ = sl.compile_script_policy(
                        {"kind": "branch", "template": "both_of_2", "keys": {"a": roster_ctx["disposer_pk"], "b": roster_ctx["arbiter_pk"]}}
                    )
                    if vout0 and vout0.get("script_pubkey_hex") == vac_spk.hex():
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
                        return cur
                    stxid = aout["spent_by_txid"]
                    vout0 = chain.get_output(stxid, 0)
                    vac_spk, _ = sl.compile_script_policy(
                        {"kind": "branch", "template": "both_of_2", "keys": {"a": roster_ctx["disposer_pk"], "b": roster_ctx["arbiter_pk"]}}
                    )
                    if vout0 and vout0.get("script_pubkey_hex") == vac_spk.hex():
                        cur = {"state": "vacant", "vacant_outpoint": {"txid": stxid, "vout": 0}}
                        continue
                    cur["state"] = "contested_burned"
                    return cur
                else:
                    return cur
            return cur

        for snum in list(slot_states.keys()):
            slot_states[snum] = trace_slot(snum, slot_states[snum], active_roster)

        # Walk roster_seal transitions (0x0f)
        for _ in range(16):
            rout = chain.get_output(cur_roster_seal["txid"], cur_roster_seal["vout"])
            if not rout:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            rspend = rout.get("spent_by_txid")
            if not rspend:
                break
            rtx = chain.get_tx(rspend)
            dec_r = self._decode_opreturn_tx(rtx, expected_action="0x0f")
            if dec_r is None:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            assert rtx is not None
            rrec = roster_records_by_caddr.get(dec_r["commitment"])
            ok_rw = self._verify_object_wire(rrec, expected_type="seallink-guardian-roster/1")[0] if rrec else False
            if not rrec or not ok_rw:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            rp = rrec["payload"]
            if rp["origin_id"] != origin_id or rp["prev_revision"] != active_roster["revision"] or rp["revision"] != active_roster["revision"] + 1:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            # Authoritative issuer link.cred verification at h_rtx + policy-scoped 0x0b h_c cutoff!
            r_iss_err = self.verify_issuer_role_at_height(rp["issuer"], rrec, "cred", rtx["confirmed_height"], chain)
            if r_iss_err:
                if r_iss_err in ("CRED_ISSUER_CLOSED", "WIRE_SIGNATURE"):
                    return None, r_iss_err
                return None, "ORIGIN_STATUS_INCOMPLETE"
            # Enforce SL-ORIG-015/016 including FORBIDDEN retain_active/retain_vacant on disposer_pk/arbiter_pk change!
            ok_rc, code_rc = sl.check_guardian_policy_consistency(rp, prev_roster=active_roster)
            if not ok_rc:
                return None, code_rc
            nxt_rout = chain.get_output(rspend, rp["next_roster_vout"])
            exp_nr_spk, _ = sl.compile_script_policy(rp["next_roster_policy"])
            if not nxt_rout or nxt_rout.get("script_pubkey_hex") != exp_nr_spk.hex():
                return None, "ORIGIN_STATUS_INCOMPLETE"
            if chain.tip_height < rtx["confirmed_height"] + rp["effective_delay_blocks"]:
                break
            prev_slot_states = slot_states
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
                    # Must reference an already-verified active slot from previous revision!
                    prev_s = prev_slot_states.get(sn)
                    grec = g_by_id.get(sspec["guardian_id"])
                    if (
                        not prev_s
                        or prev_s.get("state") != "active"
                        or prev_s.get("guardian_id") != sspec["guardian_id"]
                        or prev_s.get("active_outpoint") != sspec["active_outpoint"]
                        or not grec
                    ):
                        new_slot_states[sn] = {"state": "contested_burned"}
                    else:
                        new_slot_states[sn] = trace_slot(sn, prev_s, active_roster)
                elif act == "retain_vacant":
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
                            {"state": "vacant", "vacant_outpoint": {"txid": rspend, "vout": sspec["new_vacant_vout"]}},
                            active_roster,
                        )
            slot_states = new_slot_states

        return {
            "origin_id": origin_id,
            "capacity": "ward",
            "binding": active_binding,
            "active_recovery_seal": active_recovery_seal,
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
        """Enforce SL-ORIG-006 + SL-WIRE-013 guardian_approvals[] verification in exact precedence."""
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
            # Resolve guardian's live link.grant policy at tip (intentional fail-safe halt on key rotation)
            gnrec, gerr = self.resolve_name(
                gpin["name"],
                chain,
                expected_owner_policy=gpin["owner_policy"],
                expected_registration=gpin["registration"],
            )
            if gerr:
                return False, gerr, {}
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
    # SPEC-05 Assent (party_id 1-to-1), Contract, Credential, Notary
    # ------------------------------------------------------------------

    def verify_assent(
        self,
        assent_env: dict[str, Any],
        contract_obj: dict[str, Any],
        origin_bundle: dict[str, Any] | None,
        chain: ChainView,
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
        if ap["target_type"] != "seallink-contract/1" or ap["target_id"] != sl.object_id(contract_obj):
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        if ap["expires_at"] <= ap["issued_at"] or (ap["expires_at"] - ap["issued_at"]) > 259200 or chain.now >= ap["expires_at"]:
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
            if origin_bundle is None:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
            wstate, oerr = self.verify_origin_and_status(origin_bundle, chain)
            if oerr:
                return VerifierResult("REFUSE", oerr)
            assert wstate is not None
            if wstate["origin_id"] != party["ward_origin_id"]:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
            if wstate["capacity"] == "ward":
                ok_g, gerr, details = self.verify_ward_approvals(assent_env, wstate, chain)
                if not ok_g:
                    return VerifierResult("REFUSE", gerr)
                return VerifierResult("ADMIT", None, outcome="executed", details={**details, "party_id": party["party_id"]})
        if "signing_policy" not in party:
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
    ) -> VerifierResult:
        """Verify strict 1-to-1 signatory coverage across every distinct party_id in contract.parties[]."""
        ok_c, c_res = self._verify_object_wire(contract_obj, expected_type="seallink-contract/1")
        if not ok_c:
            return VerifierResult("REFUSE", c_res)
        expected_ids = {pt["party_id"] for pt in contract_obj["parties"]}
        covered: set[str] = set()
        for a in assents:
            ares = self.verify_assent(a, contract_obj, origin_bundle, chain)
            if ares.verdict != "ADMIT":
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
    ) -> VerifierResult:
        """Execute SPEC-05 §4.2 deterministic 7-step credential verification order."""
        # 1. Wire & closed Draft 2020-12 schema check
        ok_w, w_res = self._verify_object_wire(cred_env, expected_type="seallink-credential/1")
        if not ok_w:
            return VerifierResult("REFUSE", w_res)
        cp = w_res["payload"]
        # 2. Supported kind
        if supported_kinds is not None and cp["credential_kind"] not in supported_kinds:
            return VerifierResult("REFUSE", "WIRE_TYPE")
        # 3. Chain match & subject name_pin owner match
        if cp["network"] != self.pinned_network or cp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        obs_err = self.check_chain_observation(chain, risk_class=2)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        subj = cp["subject"]
        if subj.get("mode") == "name":
            _, serr = self.resolve_name(
                subj["name_pin"]["name"],
                chain,
                expected_owner_policy=subj["name_pin"]["owner_policy"],
                expected_registration=subj["name_pin"]["registration"],
            )
            if serr:
                return VerifierResult("REFUSE", serr)
        # 4. Signed-form 0x09 anchor
        atx = chain.get_tx(anchor_txid) if anchor_txid else None
        if self._decode_opreturn_tx(atx, expected_action="0x09", expected_commitment=sl.content_addr(cred_env)) is None:
            return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
        assert atx is not None
        h_anchor = atx["confirmed_height"]
        if chain.tip_height - h_anchor + 1 < self.operator_min_depth:
            return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
        # 5. Issuer history, owner_policy, link.cred policy (at tip for revocable, at h_anchor for eternal), policy-scoped 0x0b h_c break
        iss = cp["issuer"]
        i_err = self.verify_issuer_role_at_height(
            iss, cred_env, "cred", h_anchor, chain, resolve_at_tip=(cp["lifecycle"] != "eternal")
        )
        if i_err:
            return VerifierResult("REFUSE", i_err)
        # 6. Height window check
        if chain.tip_height < cp["not_before_height"]:
            return VerifierResult("REFUSE", "CRED_WINDOW_CLOSED")
        if "not_after_height" in cp and chain.tip_height >= cp["not_after_height"]:
            return VerifierResult("REFUSE", "CRED_WINDOW_CLOSED")
        # 7. Revocable seal state (derived 0x0a frame on spend_tx -> CRED_REVOKED_FOR_CAUSE)
        if cp["lifecycle"] == "revocable":
            seal = cp["revocation_seal"]
            out = chain.get_output(seal["txid"], seal["vout"])
            if out and out.get("spent_by_txid"):
                stx = chain.get_tx(out["spent_by_txid"])
                if stx and stx.get("opreturn_hex"):
                    try:
                        dec_w = sl.decode_opreturn(bytes.fromhex(stx["opreturn_hex"]))
                        if dec_w["action"] == "0x0a":
                            return VerifierResult("REFUSE", "CRED_REVOKED_FOR_CAUSE")
                    except ValueError:
                        pass
            _, serr, _ = self.evaluate_seal(seal, chain, required_depth=1)
            if serr:
                return VerifierResult("REFUSE", serr)
        return VerifierResult("ADMIT", None, outcome="executed")

    # ------------------------------------------------------------------
    # SPEC-06 §4 Deterministic 12-Step Invocation Admission Pipeline
    # ------------------------------------------------------------------

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
        """Execute SPEC-06 §4 Steps 1..12 deterministically and return computed VerifierResult."""
        # Step 1: Invocation wire + Draft 2020-12 closed schema + profile action args schema check
        ok_w, res_w = self._verify_object_wire(inv_env, expected_type="seallink-invocation/1")
        if not ok_w:
            return VerifierResult("REFUSE", res_w)
        inv_env = res_w
        inv_p = res_w["payload"]
        inv_id = sl.object_id(inv_p)
        inv_caddr = sl.content_addr(inv_env)

        # Step 2: Early local request checks (pre-chain)
        now = chain.now
        if not (inv_p["iat"] <= now < inv_p["exp"]):
            return VerifierResult("REFUSE", "INVOKE_TIME_INVALID")
        if inv_p["executor"]["name"] != executor_cfg["name"] or inv_p["executor"]["key"] != executor_cfg["key"]:
            return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")

        # Step 3: Presented bundle wire, early recipient auth, and pre-chain replay/crash recovery
        grants_by_id: dict[str, dict[str, Any]] = {}
        for g in bundle.get("grants", []):
            ok_g, res_g = self._verify_object_wire(g, expected_type="seallink-grant/1")
            if not ok_g:
                return VerifierResult("REFUSE", res_g)
            grants_by_id[sl.object_id(res_g["payload"])] = res_g

        ppath = inv_p["proof_path"]
        root_gid = ppath[0]["grant_id"]
        leaf_gid = ppath[-1]["grant_id"]
        if root_gid not in grants_by_id or leaf_gid not in grants_by_id:
            return VerifierResult("REFUSE", "WIRE_MEMBER")
        root_grant = grants_by_id[root_gid]
        leaf_grant = grants_by_id[leaf_gid]
        root_gp = root_grant["payload"]
        leaf_gp = leaf_grant["payload"]

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
            if inv_id in journal.unsettled_reservations:
                return VerifierResult(
                    "UNCERTAIN",
                    None,
                    outcome="uncertain",
                    details={
                        "reservation_retained": True,
                        "zero_second_effect": True,
                        "unsettled_count": len(journal.unsettled_reservations[inv_id]),
                    },
                )
            if inv_p["nonce"] in journal.nonces and journal.nonces[inv_p["nonce"]] != inv_id:
                return VerifierResult("REFUSE", "INVOKE_REPLAY")
            return None

        if rcpt_spec["mode"] in ("key", "group"):
            early_rep = check_local_replay_or_crash()
            if early_rep is not None:
                return early_rep

        # Step 4: Consistent chain observation
        action = inv_p["action"]
        act_meta = ACTION_PROFILES.get(
            action,
            {
                "risk_class": 1,
                "mechanical": True,
                "external_mutation": True,
                "allows_executor_ref": False,
                "requires_contract": False,
                "require_seal": True,
            },
        )
        obs_err = self.check_chain_observation(chain, risk_class=act_meta["risk_class"])
        if obs_err:
            return VerifierResult("REFUSE", obs_err)

        # Step 5: Journal continuity
        j_err = journal.check_continuity()
        if j_err:
            return VerifierResult("REFUSE", j_err)

        # Step 6: Durable closure check
        for pe in ppath:
            gid = pe["grant_id"]
            if gid in journal.closures:
                cl = journal.closures[gid]
                if cl.get("cause") == "SINGLE_USE_CONSUMED":
                    return VerifierResult("REFUSE", "INVOKE_REPLAY")
                return VerifierResult("REFUSE", "GRANT_CLOSED")
        if len(ppath) == 2:
            row_key = f"{root_gid}:{leaf_gp['parent']['ordinal']}"
            if row_key in journal.closures and journal.closures[row_key].get("cause") == "GRANT_ROW_STOPPED":
                return VerifierResult("REFUSE", "GRANT_ROW_STOPPED")
        iss_name = root_gp["issuer"]["name"]
        if f"role:{iss_name}:grant" in journal.closures:
            return VerifierResult("REFUSE", "NAME_ROLE_CHANGED")
        for g in (root_grant, leaf_grant):
            rev = g["payload"]["revocation"]
            if rev["mode"] == "seal":
                skey = _outpoint_key(rev["seal"])
                if skey in journal.closures:
                    return VerifierResult("REFUSE", "SEAL_SPENT")

        # Step 7: Issuer identity, origin, and guardianship
        iss_pin = root_gp["issuer"]
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
        ward_details: dict[str, Any] = {}
        is_origin_cert = bool(nrec.get("_value_obj", {}).get("link", {}).get("origin")) or (origin_bundle is not None)
        if is_origin_cert:
            if origin_bundle is None:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
            wstate, oerr = self.verify_origin_and_status(origin_bundle, chain)
            if oerr:
                return VerifierResult("REFUSE", oerr)
            assert wstate is not None
            if wstate["capacity"] == "ward":
                ok_wa, werr, ward_details = self.verify_ward_approvals(root_grant, wstate, chain)
                if not ok_wa:
                    return VerifierResult("REFUSE", werr)
            else:
                rpol, rerr = self.resolve_role_policy(nrec, "grant", iss_pin.get("role_policy"), recent_block_height=root_recent_h)
                if rerr:
                    return VerifierResult("REFUSE", rerr)
                ok_rs, rscode = sl.verify_signature_set(
                    sl.signing_digest(root_gp), root_grant.get("signatures", {}), expected_policy=rpol, obj_type="seallink-grant/1"
                )
                if not ok_rs:
                    return VerifierResult("REFUSE", rscode)
        else:
            rpol, rerr = self.resolve_role_policy(nrec, "grant", iss_pin.get("role_policy"), recent_block_height=root_recent_h)
            if rerr:
                return VerifierResult("REFUSE", rerr)
            ok_rs, rscode = sl.verify_signature_set(
                sl.signing_digest(root_gp), root_grant.get("signatures", {}), expected_policy=rpol, obj_type="seallink-grant/1"
            )
            if not ok_rs:
                return VerifierResult("REFUSE", rscode)

        # Step 8: Contract and framework checks (1-to-1 party_id signatory coverage!)
        if act_meta.get("requires_contract", False) and "contract_id" not in leaf_gp:
            return VerifierResult("REFUSE", "GRANT_CONTRACT_REQUIRED")
        if "contract_id" in leaf_gp:
            c_obj = bundle.get("contract")
            if c_obj is None:
                return VerifierResult("REFUSE", "CONTRACT_NOT_PRESENTED")
            ok_co, co_res = self._verify_object_wire(c_obj, expected_type="seallink-contract/1")
            if not ok_co:
                return VerifierResult("REFUSE", co_res)
            if sl.object_id(c_obj) != leaf_gp["contract_id"]:
                return VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH")
            if "framework_id" in c_obj:
                fw_obj = bundle.get("framework_contract")
                if fw_obj is None:
                    return VerifierResult("REFUSE", "CONTRACT_NOT_PRESENTED")
                ok_fw, fw_res = self._verify_object_wire(fw_obj, expected_type="seallink-contract/1")
                if not ok_fw:
                    return VerifierResult("REFUSE", fw_res)
                if sl.object_id(fw_obj) != c_obj["framework_id"]:
                    return VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH")
                if "framework_id" in fw_obj:
                    return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
                if "seal" not in fw_obj:
                    return VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING")
                _, fw_serr, _ = self.evaluate_seal(fw_obj["seal"], chain, required_depth=1)
                if fw_serr:
                    return VerifierResult("REFUSE", fw_serr)
            # Strict 1-to-1 party_id assent coverage
            ca_res = self.verify_contract_assents(c_obj, bundle.get("contract_assents", []), origin_bundle, chain)
            if ca_res.verdict != "ADMIT":
                return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
            if "seal" not in c_obj:
                return VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING")
            _, c_serr, _ = self.evaluate_seal(c_obj["seal"], chain, required_depth=1)
            if c_serr:
                return VerifierResult("REFUSE", c_serr)
            cw = c_obj["window"]
            if leaf_gp["not_before_height"] < cw["not_before_height"] or (
                "not_after_height" in cw and leaf_gp["not_after_height"] > cw["not_after_height"]
            ):
                return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
            disclosed = bundle.get("disclosed_clauses", {})
            for idx in c_obj.get("machine_clause_indices", []):
                d = disclosed.get(str(idx)) or disclosed.get(idx)
                if not d or sl.clause_commit(d["salt_hex"], d["clause"]) != c_obj["clause_commitments"][idx]:
                    return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
            if "config_sha256" in c_obj:
                rt_cfg = executor_cfg.get("runtime_config_sha256")
                arg_cfg = inv_p["arguments"].get("config_sha256")
                if (rt_cfg is not None and rt_cfg != c_obj["config_sha256"]) or (arg_cfg is not None and arg_cfg != c_obj["config_sha256"]):
                    return VerifierResult("REFUSE", "CONTRACT_CONFIG_MISMATCH")

        # Step 9: Depth-2 Re-delegation checks (R8.5, R8.6, derived row-coin spend, stop coin, notary, narrowing)
        matched_parent_template: dict[str, Any] | None = None
        if len(ppath) == 2:
            if "delegate" not in root_gp or "parent" not in leaf_gp or "delegate" in leaf_gp:
                return VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE")
            if leaf_gp["parent"]["grant_id"] != root_gid:
                return VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE")
            del_spec = root_gp["delegate"]
            ok_r85, _ = sl.check_whole_parent_budget_r85(del_spec)
            if not ok_r85:
                return VerifierResult("REFUSE", "GRANT_CHILD_WIDER")
            if not sl.check_disjoint_ranges_r86(root_gp):
                return VerifierResult("REFUSE", "GRANT_ROW_INVALID")
            ordinal = leaf_gp["parent"]["ordinal"]
            cur_ord = 0
            matched_group = None
            row_outpoint = None
            stop_outpoint = None
            for gspec in del_spec["groups"]:
                for rng in gspec["ranges"]:
                    if cur_ord + 1 <= ordinal <= cur_ord + rng["count"]:
                        offset = ordinal - cur_ord - 1
                        matched_group = gspec
                        row_outpoint = {"txid": rng["txid"], "vout": rng["first"] + offset}
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
            # Derive row-coin spend directly from child issuance tx inputs[]!
            c_itxid = ppath[1].get("issuance_txid")
            c_itx = chain.get_tx(c_itxid) if c_itxid else None
            spent_set = {f"{i['prev_txid']}:{i['prev_vout']}" for i in (c_itx.get("inputs", []) if c_itx else [])}
            if not c_itx or _outpoint_key(row_outpoint) not in spent_set:
                return VerifierResult("REFUSE", "GRANT_ROW_INVALID")
            if stop_outpoint is not None:
                sout = chain.get_output(stop_outpoint["txid"], stop_outpoint["vout"])
                if sout and (sout.get("spent_by_txid") or sout.get("absent_from_utxo")):
                    return VerifierResult("REFUSE", "GRANT_ROW_STOPPED")
            tpl = matched_group["template"]
            matched_parent_template = tpl
            if tpl["notary_mode"] == "required_act":
                if not bundle.get("notary_act"):
                    return VerifierResult("REFUSE", "NOTARY_REQUIRED")
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
            # Verify child seal issuer key binds parent.delegate.child_seal_key (revocation.mode='seal' enforced by ChildGrant schema)
            c_spol = leaf_gp["revocation"]["seal"]["script_policy"]
            if c_spol["kind"] == "key":
                if c_spol["pk"] != del_spec["child_seal_key"]:
                    return VerifierResult("REFUSE", "GRANT_CHILD_WIDER")
            elif c_spol["kind"] == "branch" and c_spol["template"] == "single_use_1_of_2":
                if c_spol["keys"]["issuer"] != del_spec["child_seal_key"]:
                    return VerifierResult("REFUSE", "GRANT_CHILD_WIDER")
            for ccap in leaf_gp["capabilities"]:
                narrowed_any = False
                for pcap in tpl["capabilities"]:
                    if ccap["action"] != pcap["action"] or ccap["target"] != pcap["target"]:
                        continue
                    ok_w = True
                    for pk_name, ppred in pcap.get("where", {}).items():
                        cpred = ccap.get("where", {}).get(pk_name)
                        if cpred is None or not sl.narrows_predicate(cpred, ppred):
                            ok_w = False
                            break
                    if not ok_w:
                        continue
                    p_quotas = {(q["kind"], q["resource"], q["unit"], q["window"]): int(q["max"]) for q in pcap.get("quotas", [])}
                    c_quotas = {(q["kind"], q["resource"], q["unit"], q["window"]): int(q["max"]) for q in ccap.get("quotas", [])}
                    if all(k in c_quotas and c_quotas[k] <= v for k, v in p_quotas.items()):
                        narrowed_any = True
                        break
                if not narrowed_any:
                    return VerifierResult("REFUSE", "GRANT_CHILD_WIDER")

        # Step 10: Grant window, revocation / single-use seal, and executor binding
        journal_writes: list[dict[str, Any]] = []
        for pe in ppath:
            g = grants_by_id[pe["grant_id"]]
            gp = g["payload"]
            gid = pe["grant_id"]
            if not (gp["not_before_height"] <= chain.tip_height < gp["not_after_height"]):
                return VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED")
            rev = gp["revocation"]
            if rev["mode"] == "window_only":
                if not self.allow_window_only or act_meta.get("require_seal", True):
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
                # Derive Witness Profile W strictly from itx.inputs[]!
                if rev["construction"] != "W" or not self._tx_satisfies_witness_w(itx):
                    return VerifierResult("REFUSE", "CHAIN_TX_CONSTRUCTION")
                req_depth = max(gp.get("min_depth", 1), self.operator_min_depth)
                if a_height is None or (chain.tip_height - a_height + 1) < req_depth:
                    return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
                if rev["kind"] == "revocable":
                    _, serr, jw = self.evaluate_seal(
                        rev["seal"], chain, required_depth=req_depth, journal=journal, subject_id=gid, subject_kind="grant"
                    )
                    if jw:
                        journal_writes.append(jw)
                    if serr:
                        return VerifierResult("REFUSE", serr, journal_writes=journal_writes)
                else:
                    _, serr, jw = self.evaluate_single_use_seal(
                        rev["seal"], use_txid, inv_caddr, req_depth, chain, journal=journal, grant_id=gid
                    )
                    if jw:
                        journal_writes.append(jw)
                    if serr:
                        return VerifierResult("REFUSE", serr, journal_writes=journal_writes)

        # 10d. Executor binding: evaluate executor_ref strictly against leaf_gp["capabilities"] (NOT inv_p["action"]!)
        # (delegate, single_use, and quotas on executor_ref are already forbidden by closed Grant schema)
        if "executor_ref" in leaf_gp:
            for cap in leaf_gp["capabilities"]:
                cmeta = ACTION_PROFILES.get(cap["action"], {"allows_executor_ref": False, "external_mutation": True})
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

        # Step 11: Named recipient, action, text ban, and constraints
        if rcpt_spec["mode"] == "name":
            r_nrec, r_nerr = self.resolve_name(rcpt_spec["name"], chain, expected_owner_policy=rcpt_spec["owner_policy"])
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

        # 11b. Action supported and present in capabilities
        if executor_cfg.get("actions") is not None and action not in executor_cfg["actions"]:
            return VerifierResult("REFUSE", "INVOKE_ACTION_DENIED")
        action_caps = [c for c in leaf_gp["capabilities"] if c["action"] == action]
        if not action_caps:
            return VerifierResult("REFUSE", "INVOKE_ACTION_DENIED")

        # 11c. Mechanical effect text ban
        if act_meta.get("mechanical", True) and "terms_text" in leaf_gp:
            return VerifierResult("REFUSE", "GRANT_TEXT_FORBIDDEN")

        # 11d. Target match, 7-predicate where evaluation, and profile checks
        matched_cap = None
        for cap in action_caps:
            if cap["target"] != inv_p["target"]:
                continue
            ok_where = True
            for arg_k, pred in cap.get("where", {}).items():
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

        if action == "agent/guardian-message":
            args = inv_p["arguments"]
            pinned_oid = executor_cfg.get("pinned_ward_origin_id")
            if pinned_oid and (inv_p["target"] != f"ward:{pinned_oid}" or args["origin_id"] != pinned_oid):
                return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")
            if ward_details and args["revision"] != ward_details.get("verified_revision"):
                return VerifierResult("REFUSE", "GUARDIAN_QUORUM_UNMET")
            if raw_message_bytes is not None and sl.sha256(raw_message_bytes).hex() != args["message_sha256"]:
                return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")

        # Step 12: Pre-effect recheck & ATOMIC dual-account multi-quota reservation/settlement
        rb_err = self.check_rebracket(chain, risk_class=act_meta["risk_class"])
        if rb_err:
            return VerifierResult("REFUSE", rb_err)

        quotas = matched_cap.get("quotas", [])
        if quotas:
            # Build parent template row caps when executing a depth-2 child grant
            parent_row_caps: dict[tuple[str, str, str, str], int] = {}
            if len(ppath) == 2 and matched_parent_template is not None:
                for pcap in matched_parent_template.get("capabilities", []):
                    if pcap["action"] == action and pcap["target"] == inv_p["target"]:
                        for pq in pcap.get("quotas", []):
                            pk_t = (pq["kind"], pq["resource"], pq["unit"], pq["window"])
                            parent_row_caps[pk_t] = max(parent_row_caps.get(pk_t, 0), int(pq["max"]))

            # Phase 1: Validate ALL accounts & quotas BEFORE mutating journal or watermarks (atomic batch!)
            pending_ops: list[dict[str, Any]] = []
            watermark_updates: dict[str, int] = {}
            planned_usage_delta: dict[tuple[str, str, str], int] = {}

            for q in quotas:
                qkey = f"{q['kind']}|{q['resource']}|{q['unit']}|{q['window']}"
                if q["window"].startswith("seconds:"):
                    wm = journal.quota_watermarks.get(qkey, 0)
                    if chain.now < wm:
                        return VerifierResult("REFUSE", "QUOTA_CLOCK_REGRESSION")
                    watermark_updates[qkey] = chain.now
                    sec_s = int(q["window"].split(":", 1)[1])
                    bucket_id = f"sec:{(chain.now // sec_s) * sec_s}"
                elif q["window"].startswith("blocks:"):
                    blk_n = int(q["window"].split(":", 1)[1])
                    k = (chain.tip_height - leaf_gp["not_before_height"]) // blk_n
                    bucket_id = f"blk:{leaf_gp['not_before_height'] + k * blk_n}"
                else:
                    bucket_id = "term"

                reserve_amt, settle_amt = compute_quota_debit(action, inv_p["arguments"], q, actual_quota_usage)
                # Build target accounts: root -> [own(leaf_gid)]; child -> [own(leaf_gid), row(root_gid, row_ordinal)]
                account_targets: list[tuple[str, str, int | None, int]] = [("own", leaf_gid, None, int(q["max"]))]
                if len(ppath) == 2:
                    pk_t = (q["kind"], q["resource"], q["unit"], q["window"])
                    row_max = parent_row_caps.get(pk_t, int(q["max"]))
                    account_targets.append(("row", root_gid, int(leaf_gp["parent"]["ordinal"]), row_max))

                for acct, gid_acct, row_ord, ceiling in account_targets:
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
                        "settle": settle_amt,
                        "release": reserve_amt - settle_amt,
                    })

            j_err2 = journal.check_continuity()
            if j_err2:
                return VerifierResult("REFUSE", j_err2)

            # Phase 2: Commit watermarks & ALL reservation entries atomically
            for wk, wv in watermark_updates.items():
                journal.quota_watermarks[wk] = wv
            for op_rec in pending_ops:
                q = op_rec["quota"]
                res_body: dict[str, Any] = {
                    "account": op_rec["account"],
                    "amount": str(op_rec["reserve"]),
                    "bucket_id": op_rec["bucket_id"],
                    "grant_id": op_rec["grant_id"],
                    "invocation_id": inv_id,
                    "quota_kind": q["kind"],
                    "recorded_at": chain.now,
                    "resource": q["resource"],
                    "unit": q["unit"],
                    "window": q["window"],
                }
                if op_rec["row_ordinal"] is not None:
                    res_body["row_ordinal"] = op_rec["row_ordinal"]
                jw_res = journal.append("reservation", res_body)
                journal_writes.append(jw_res)

            if simulate_crash_before_settlement:
                return VerifierResult(
                    "UNCERTAIN",
                    None,
                    outcome="uncertain",
                    journal_writes=journal_writes,
                    details={
                        "crashed_in_effect_window": True,
                        "reservation_retained": True,
                        "unsettled_count": len(journal.unsettled_reservations.get(inv_id, [])),
                    },
                )

            # Phase 3: Write one matching settlement entry per reservation
            rcpt_caddr = sl.content_addr(receipt_env_for_cache) if receipt_env_for_cache else sl.sha256(inv_id.encode()).hex()
            for op_rec in pending_ops:
                q = op_rec["quota"]
                set_body: dict[str, Any] = {
                    "account": op_rec["account"],
                    "bucket_id": op_rec["bucket_id"],
                    "grant_id": op_rec["grant_id"],
                    "invocation_id": inv_id,
                    "outcome": "executed",
                    "quota_kind": q["kind"],
                    "receipt_sha256": rcpt_caddr,
                    "recorded_at": chain.now,
                    "released": str(op_rec["release"]),
                    "resource": q["resource"],
                    "settled": str(op_rec["settle"]),
                    "unit": q["unit"],
                    "window": q["window"],
                }
                if op_rec["row_ordinal"] is not None:
                    set_body["row_ordinal"] = op_rec["row_ordinal"]
                jw_set = journal.append("settlement", set_body)
                journal_writes.append(jw_set)
        else:
            jw_n = journal.append(
                "nonce",
                {
                    "expires_at": inv_p["exp"],
                    "invocation_id": inv_id,
                    "nonce": inv_p["nonce"],
                    "scope": "invocation",
                },
            )
            journal_writes.append(jw_n)

        if leaf_gp["revocation"].get("kind") == "single_use":
            su_rcpt_caddr = sl.content_addr(receipt_env_for_cache) if receipt_env_for_cache else sl.sha256(inv_id.encode()).hex()
            jw_su = journal.append(
                "single-use-consumed",
                {
                    "grant_id": leaf_gid,
                    "invocation_id": inv_id,
                    "receipt_sha256": su_rcpt_caddr,
                    "recorded_at": chain.now,
                    "use_txid": use_txid or ("0" * 64),
                },
            )
            journal_writes.append(jw_su)
            jw_cl = journal.append(
                "closure",
                {
                    "cause": "SINGLE_USE_CONSUMED",
                    "observed_at": chain.now,
                    "observed_height": chain.tip_height,
                    "spend_txid": use_txid or ("0" * 64),
                    "subject_id": leaf_gid,
                    "subject_kind": "grant",
                },
            )
            journal_writes.append(jw_cl)

        if receipt_env_for_cache is not None:
            journal.receipts[inv_id] = copy.deepcopy(receipt_env_for_cache)
            journal.receipt_store[sl.content_addr(receipt_env_for_cache)] = copy.deepcopy(receipt_env_for_cache)

        return VerifierResult("ADMIT", None, outcome="executed", journal_writes=journal_writes, details=ward_details)

    # ------------------------------------------------------------------
    # SPEC-06 §5 Bearer Sessions, SPEC-07 Migration & Federation
    # ------------------------------------------------------------------

    def verify_bearer_session(
        self,
        token: str,
        slot_binding: str,
        chain: ChainView,
        journal: FencedJournal,
    ) -> VerifierResult:
        obs_err = self.check_chain_observation(chain, risk_class=2)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        t_hash = sl.sha256(token.encode("utf-8")).hex()
        sess = journal.sessions.get(t_hash)
        if not sess or sess.get("closed") or sess.get("slot_binding") != slot_binding or chain.now >= sess.get("exp", 0):
            return VerifierResult("REFUSE", "SESSION_INVALID")
        if sess.get("grant_id") in journal.closures:
            return VerifierResult("REFUSE", "SESSION_INVALID")
        return VerifierResult("ADMIT", None, outcome="executed")

    def verify_migration(
        self,
        migration_env: dict[str, Any],
        export_bundle: dict[str, Any],
        journal: FencedJournal,
        chain: ChainView | None = None,
        presented_manifests: dict[str, dict[str, Any]] | None = None,
    ) -> VerifierResult:
        """Verify seallink-migration/1 binding source_executor signature & inspecting export files (SPEC-07 §2)."""
        ok_w, res = self._verify_object_wire(migration_env, expected_type="seallink-migration/1")
        if not ok_w:
            return VerifierResult("REFUSE", res)
        mp = res["payload"]
        if mp["network"] != self.pinned_network or mp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        # Authoritatively bind migration signature to source_executor's service.receipt_key!
        if chain is None:
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        src = mp["source_executor"]
        s_nrec, s_nerr = self.resolve_name(
            src["name"], chain, expected_owner_policy=src["owner_policy"], expected_registration=src["registration"]
        )
        if s_nerr:
            return VerifierResult("REFUSE", s_nerr)
        assert s_nrec is not None
        s_man, s_merr = self.resolve_manifest(src["name"], s_nrec, presented_manifests or {}, chain, journal)
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

        # Derive export boundary compliance by inspecting export_bundle["files"]
        files = export_bundle.get("files")
        if not isinstance(files, list) or not all(isinstance(f, dict) for f in files):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        for f in files:
            fobj = f.get("object")
            if (
                f.get("kind") in FORBIDDEN_EXPORT_KINDS
                or (isinstance(fobj, dict) and (any(k in fobj for k in ("private_key", "secret_key", "bearer_token")) or fobj.get("payload", {}).get("type") == "seallink-grant/1"))
            ):
                return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        computed_inv_sha = sl.sha256(sl.jcs_encode({"files": files})).hex()
        if computed_inv_sha != mp["inventory_sha256"]:
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        # Require fenced source journal matching manifest pos/commitment & zero unclosed predecessor grants
        if (
            export_bundle.get("source_journal_pos") != mp["journal_pos"]
            or export_bundle.get("source_journal_commitment") != mp["journal_commitment"]
            or not export_bundle.get("source_write_token_fenced", False)
            or bool(export_bundle.get("open_predecessor_grants", []))
        ):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        mid = mp["migration_id"]
        if mid in journal.migrations_applied:
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        journal.migrations_applied.add(mid)
        return VerifierResult("ADMIT", None, outcome="executed")

    def verify_federation_disclosure(
        self,
        policy: dict[str, Any],
        peer_ctx: dict[str, Any],
        grant_env: dict[str, Any],
        chain: ChainView | None = None,
    ) -> VerifierResult:
        """Verify two-phase federated screening and L2-gated Contour A disclosure (SPEC-07 §3)."""
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
            # Derive route safety strictly from route_hops[]
            hops = peer_ctx.get("route_hops", [])
            if not isinstance(hops, list) or not hops or any(not isinstance(h, dict) or h.get("role") == "screening_agent" for h in hops):
                return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
            # Derive L2 human approval strictly by verifying signed L2 seallink-owner-command/1!
            approval_cmd = peer_ctx.get("approval_command")
            dev_list = peer_ctx.get("device_list")
            if (
                approval_cmd is None
                or dev_list is None
                or chain is None
                or self.verify_owner_command(approval_cmd, dev_list, is_foreign_service=False, chain=chain).verdict != "ADMIT"
                or approval_cmd["payload"].get("level") != 2
            ):
                return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
            return VerifierResult("ADMIT", None, outcome="executed")
        return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
