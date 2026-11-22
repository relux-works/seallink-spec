#!/usr/bin/env python3
"""
SealLink v1.0 Executable Pure-Python Reference Tier 1 Verifier.

Implements the normative verification state machines of SPEC-01 through SPEC-07
and PROFILE-mail-v1 / PROFILE-agent-v1 over a declarative in-memory ChainView
and stateful hash-chained FencedJournal.

CRITICAL DESIGN PROPERTY:
  This verifier computes every verdict, refusal code, receipt outcome, and
  journal hash-chain delta strictly from protocol inputs and chain/journal state.
  It NEVER reads any `expected_*` field from test vectors.
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
    },
}

_REGISTERED_TYPES_CACHE: dict[str, dict[str, Any]] | None = None


def registered_types() -> dict[str, dict[str, Any]]:
    global _REGISTERED_TYPES_CACHE
    if _REGISTERED_TYPES_CACHE is None:
        reg = json.loads((ROOT / "registry" / "object-types.json").read_text(encoding="utf-8"))
        _REGISTERED_TYPES_CACHE = {e["type"]: e for e in reg["types"]}
    return _REGISTERED_TYPES_CACHE


def _outpoint_key(op: dict[str, Any]) -> str:
    return f"{op['txid']}:{op['vout']}"


def _normalize_policy(p: dict[str, Any]) -> dict[str, Any]:
    out = {"m": p["m"], "pks": list(p["pks"])}
    if "alg" in p and p["alg"] != "bip340":
        out["alg"] = p["alg"]
    return out


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
        self.unsettled_reservations: dict[str, dict[str, Any]] = {}
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
            j.unsettled_reservations[k] = copy.deepcopy(v)
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
            # Pending completion recovery: advance witness
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
            scope = f"{body['account']}:{body['grant_id']}"
            qkey = f"{body['quota_kind']}|{body['resource']}|{body['unit']}|{body['window']}"
            bkey = (scope, qkey, body["bucket_id"])
            self.quotas_used[bkey] = self.quotas_used.get(bkey, 0) + int(body["amount"])
            self.unsettled_reservations[body["invocation_id"]] = copy.deepcopy(body)
        elif kind == "settlement":
            inv_id = body["invocation_id"]
            if inv_id in self.unsettled_reservations:
                res = self.unsettled_reservations.pop(inv_id)
                released = int(body.get("released", "0"))
                if released > 0:
                    scope = f"{res['account']}:{res['grant_id']}"
                    qkey = f"{res['quota_kind']}|{res['resource']}|{res['unit']}|{res['window']}"
                    bkey = (scope, qkey, res["bucket_id"])
                    self.quotas_used[bkey] = max(0, self.quotas_used.get(bkey, 0) - released)
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

    def apply_patch(self, patch: dict[str, Any]) -> None:
        """Apply a declarative chain state transition (e.g., new block, mempool seal spend)."""
        for k, v in patch.items():
            if k in ("names", "txs", "blocks", "manifests", "registered_bindings") and isinstance(v, dict):
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

    def get_tx(self, txid: str) -> dict[str, Any] | None:
        return self.raw.get("txs", {}).get(txid)

    def get_output(self, txid: str, vout: int) -> dict[str, Any] | None:
        tx = self.get_tx(txid)
        if not tx:
            return None
        return tx.get("outputs", {}).get(str(vout)) or tx.get("outputs", {}).get(vout)


class Tier1Verifier:
    """Reference Tier 1 Verifier implementing SPEC-01 through SPEC-07."""

    def __init__(
        self,
        pinned_network: str = "main",
        pinned_genesis: str = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
        operator_min_depth: int = 1,
        allow_window_only: bool = False,
        trusted_origin_issuers: set[str] | None = None,
    ) -> None:
        self.pinned_network = pinned_network
        self.pinned_genesis = pinned_genesis
        self.operator_min_depth = operator_min_depth
        self.allow_window_only = allow_window_only
        self.trusted_origin_issuers = trusted_origin_issuers if trusted_origin_issuers is not None else set()

    # ------------------------------------------------------------------
    # SPEC-01 §7 Wire Pipeline (steps 1..10)
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
        if "payload" in obj and isinstance(obj["payload"], dict):
            obj_type = obj["payload"].get("type")
        else:
            obj_type = obj.get("type")
        if obj_type is not None:
            if not isinstance(obj_type, str) or obj_type not in reg:
                return False, "WIRE_TYPE"
            type_max = reg[obj_type]["max_bytes"]
            if len(raw) > type_max:
                return False, "WIRE_SIZE"
        # Check capability constraints & integer bounds
        code = self._check_wire_semantics(obj)
        if code:
            return False, code
        # Optional Draft 2020-12 schema check
        if schema_validator_fn is not None and obj_type in reg:
            err = schema_validator_fn(reg[obj_type]["schema"], obj)
            if err is not None:
                return False, err
        # Key & signature verification for signed envelopes
        if "signatures" in obj or "guardian_approvals" in obj:
            ok_sig, sig_code = sl.verify_envelope_signatures(obj)
            if not ok_sig:
                return False, sig_code
        return True, obj

    def _check_wire_semantics(self, obj: dict[str, Any]) -> str | None:
        payload = obj["payload"] if ("payload" in obj and isinstance(obj["payload"], dict)) else obj
        t = payload.get("type")
        if t == "seallink-grant/1":
            # Check heights
            nb = payload.get("not_before_height")
            na = payload.get("not_after_height")
            if isinstance(nb, int) and isinstance(na, int):
                if nb >= na:
                    return "WIRE_INTEGER"
                rev = payload.get("revocation", {})
                if rev.get("mode") == "window_only" and (na - nb) > 12:
                    return "WIRE_INTEGER"
            # Check capabilities constraints & extensions
            caps = payload.get("capabilities", [])
            if isinstance(caps, list):
                for cap in caps:
                    if not isinstance(cap, dict):
                        return "WIRE_MEMBER"
                    if "extensions" in cap:
                        return "WIRE_CONSTRAINT"
                    where = cap.get("where", {})
                    if isinstance(where, dict):
                        for pred in where.values():
                            if not isinstance(pred, dict) or not sl.validate_predicate(pred):
                                return "WIRE_CONSTRAINT"
                    for q in cap.get("quotas", []):
                        mx = q.get("max")
                        if not isinstance(mx, str) or not sl.UINT64_STR_RE.match(mx) or int(mx) > sl.MAX_UINT64:
                            return "WIRE_INTEGER"
            if "delegate" in payload and isinstance(payload["delegate"], dict):
                for g in payload["delegate"].get("groups", []):
                    for cap in g.get("template", {}).get("capabilities", []):
                        if "extensions" in cap:
                            return "WIRE_CONSTRAINT"
                        for pred in cap.get("where", {}).values():
                            if not sl.validate_predicate(pred):
                                return "WIRE_CONSTRAINT"
        elif t == "seallink-origin/1":
            if "guardian_policy" in payload:
                ok_g, code_g = sl.check_guardian_policy_consistency(payload["guardian_policy"])
                if not ok_g:
                    return code_g
        elif t == "seallink-guardian-roster/1":
            ok_g, code_g = sl.check_guardian_policy_consistency(payload)
            if not ok_g:
                return code_g
        return None

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
        # Single healthy comparison node veto
        for peer in c.get("comparison_peers", []):
            if not peer.get("healthy", True):
                continue
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
    # SPEC-02 §5 & §6 Seals & Anchors
    # ------------------------------------------------------------------

    def evaluate_seal(
        self,
        seal: dict[str, Any],
        chain: ChainView,
        required_depth: int = 1,
        journal: FencedJournal | None = None,
        subject_id: str | None = None,
        subject_kind: str = "grant",
    ) -> tuple[str, str | None, dict[str, Any] | None]:
        """Evaluate standard revocable seal (SPEC-02 §6.1).
        Returns (state: unspent|revoked|unavailable, refusal_code_or_None, journal_write_or_None).
        """
        try:
            exp_spk, _ = sl.compile_script_policy(seal["script_policy"])
        except ValueError:
            return "unavailable", "CHAIN_SCRIPT_UNSUPPORTED", None
        tx = chain.get_tx(seal["txid"])
        if not tx:
            return "unavailable", "SEAL_UNAVAILABLE", None
        conf_h = tx.get("confirmed_height")
        if conf_h is None:
            return "unavailable", "SEAL_UNAVAILABLE", None
        out = chain.get_output(seal["txid"], seal["vout"])
        if not out:
            return "unavailable", "SEAL_UNAVAILABLE", None
        if out.get("script_pubkey_hex") != exp_spk.hex():
            return "unavailable", "SEAL_UNAVAILABLE", None
        # Check spend (mempool OR confirmed OR absent from UTXO set)
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
        """Evaluate single_use_1_of_2 seal (SPEC-02 §6.2)."""
        try:
            exp_spk, _ = sl.compile_script_policy(seal["script_policy"])
        except ValueError:
            return "unavailable", "CHAIN_SCRIPT_UNSUPPORTED", None
        if seal["script_policy"].get("template") != "single_use_1_of_2":
            return "unavailable", "CHAIN_SCRIPT_UNSUPPORTED", None
        tx = chain.get_tx(seal["txid"])
        out = chain.get_output(seal["txid"], seal["vout"]) if tx else None
        if not tx or tx.get("confirmed_height") is None or not out or out.get("script_pubkey_hex") != exp_spk.hex():
            return "unavailable", "SEAL_UNAVAILABLE", None

        spent_by = out.get("spent_by_txid")
        if not spent_by and not out.get("absent_from_utxo"):
            return "awaiting_spend", "SEAL_UNAVAILABLE", None

        branch = out.get("spend_branch")
        # Branch 1 (issuer) or unknown absent spend -> revoked
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

        # Branch 0 (grantee): verify OP_RETURN 0x11 matches invocation_content_addr
        spend_tx = chain.get_tx(spent_by)
        if not spend_tx or (use_txid is not None and spent_by != use_txid):
            return "revoked", "SEAL_SPENT", None
        opret_hex = spend_tx.get("opreturn_hex")
        if not opret_hex:
            return "revoked", "SEAL_SPENT", None
        try:
            dec = sl.decode_opreturn(bytes.fromhex(opret_hex))
        except ValueError:
            return "revoked", "SEAL_SPENT", None
        if dec["action"] != "0x11" or dec["commitment"] != invocation_content_addr:
            return "revoked", "SEAL_SPENT", None

        spend_h = spend_tx.get("confirmed_height")
        if spend_h is None:
            return "pending_confirm", "CHAIN_DEPTH_INSUFFICIENT", None
        depth = chain.tip_height - spend_h + 1
        if depth < required_depth:
            return "pending_confirm", "CHAIN_DEPTH_INSUFFICIENT", None
        return "ready_once", None, None

    # ------------------------------------------------------------------
    # SPEC-03 Name, Role Policy, Manifest, Auth, Device
    # ------------------------------------------------------------------

    def resolve_name(
        self,
        name: str,
        chain: ChainView,
        expected_owner_policy: dict[str, Any] | None = None,
        require_writer: bool = True,
        require_history: bool = True,
    ) -> tuple[dict[str, Any] | None, str | None]:
        rec = chain.get_name(name)
        if not rec:
            return None, "NAME_NOT_FOUND"
        if chain.tip_height >= rec.get("expiry_height", chain.tip_height + 1):
            return None, "NAME_EXPIRED"
        if require_history and not rec.get("history_available", True):
            return None, "NAME_HISTORY_UNAVAILABLE"
        if require_writer and not rec.get("writer_verified", True):
            return None, "NAME_WRITER_UNVERIFIED"
        if expected_owner_policy is not None:
            try:
                exp_spk, _ = sl.compile_script_policy(expected_owner_policy)
                got_spk, _ = sl.compile_script_policy(rec["owner_policy"])
            except ValueError:
                return None, "CHAIN_SCRIPT_UNSUPPORTED"
            if exp_spk != got_spk:
                return None, "NAME_OWNER_MISMATCH"
        # Validate 520B name value grammar
        val_raw = rec.get("value_raw")
        if val_raw is not None:
            raw_b = val_raw.encode("utf-8") if isinstance(val_raw, str) else val_raw
            if len(raw_b) > 520:
                return None, "NAME_VALUE_INVALID"
            ok_j, val_obj = sl.jcs_validate(raw_b, max_bytes=520)
            if not ok_j:
                return None, "NAME_VALUE_INVALID"
            # Role key disjointness check (SL-IDEN-003)
            used_keys: set[str] = set()
            link = val_obj.get("link", {})
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
            rec = {**rec, "_value_obj": val_obj}
        else:
            rec = {**rec, "_value_obj": rec.get("value", {})}
        return rec, None

    def resolve_role_policy(
        self,
        name_rec: dict[str, Any],
        role: str,
        presented_role_policy: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        if role in set(name_rec.get("role_changed_since_recent", [])):
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
        # Channel 0 (inline) -> Channel 1 (chain/local store)
        man = presented_manifests.get(target_h) or presented_manifests.get(name) or chain.raw.get("manifests", {}).get(target_h)
        if man is None:
            return None, "MANIFEST_UNAVAILABLE"
        if sl.content_addr(man) != target_h:
            return None, "MANIFEST_MISMATCH"
        if man.get("owner") != name or man.get("network") != chain.network or man.get("seq") != target_s:
            return None, "MANIFEST_MISMATCH"
        # Rollback check against journal (SL-IDEN-008)
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
        ok, code = sl.verify_envelope_signatures(challenge_env)
        if not ok:
            return VerifierResult("REFUSE", code)
        p = challenge_env["payload"]
        if p.get("type") != "seallink-auth-challenge/1":
            return VerifierResult("REFUSE", "WIRE_TYPE")
        if p["expires_at"] <= p["issued_at"] or (p["expires_at"] - p["issued_at"]) > 120 or chain.now >= p["expires_at"]:
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_EXPIRED")
        if p["service_id"] != service_id:
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_INVALID")
        nonce = p["nonce"]
        rec = journal.auth_nonces.get(nonce)
        if rec is None or rec.get("used", False) or rec.get("service_id") != service_id:
            return VerifierResult("REFUSE", "AUTH_CHALLENGE_INVALID")
        # Verify signature matches auth_pubkey
        ok_sig, code_sig = sl.verify_signature_set(
            sl.signing_digest(p), challenge_env["signatures"], expected_policy={"m": 1, "pks": [p["auth_pubkey"]]}
        )
        if not ok_sig:
            return VerifierResult("REFUSE", code_sig)
        if "name" in p:
            nrec, nerr = self.resolve_name(p["name"], chain)
            if nerr:
                return VerifierResult("REFUSE", nerr)
            man, merr = self.resolve_manifest(p["name"], nrec, presented_manifests or {}, chain, journal)
            if merr:
                return VerifierResult("REFUSE", merr)
            if man.get("auth_key") != p["auth_pubkey"] or "auth_seal" not in man:
                return VerifierResult("REFUSE", "AUTH_KEY_UNPINNED")
            sstate, serr, _ = self.evaluate_seal(man["auth_seal"], chain, required_depth=1)
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
        if is_foreign_service:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        ok, code = sl.verify_envelope_signatures(cmd_env)
        if not ok:
            return VerifierResult("REFUSE", code)
        p = cmd_env["payload"]
        if p.get("type") != "seallink-owner-command/1":
            return VerifierResult("REFUSE", "WIRE_TYPE")
        sig_pks = cmd_env["signatures"]["policy"]["pks"]
        if len(sig_pks) != 1:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        dev_pk = sig_pks[0]
        matched = None
        for d in device_list.get("devices", []):
            if d["key"] == dev_pk:
                matched = d
                break
        if matched is None:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        if p["level"] > matched["ceiling"]:
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        if p["command"] in ("policy-apply", "keyholder-halt") and (matched["ceiling"] < 2 or not matched.get("presence", False)):
            return VerifierResult("REFUSE", "DEVICE_UNAUTHORIZED")
        sstate, serr, _ = self.evaluate_seal(matched["seal"], chain, required_depth=1)
        if serr:
            return VerifierResult("REFUSE", serr)
        return VerifierResult("ADMIT", None, outcome="executed")

    # ------------------------------------------------------------------
    # SPEC-04 Origin, Status Spine, Guardianship, and Recovery
    # ------------------------------------------------------------------

    def verify_origin_and_status(
        self,
        origin_bundle: dict[str, Any],
        chain: ChainView,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Walk origin/1, name-binding/1, status_seal, roster_seal, and per-slot states."""
        origin_env = origin_bundle.get("origin")
        if not origin_env:
            return None, "ORIGIN_UNVERIFIED"
        ok_sig, code_sig = sl.verify_envelope_signatures(origin_env)
        if not ok_sig:
            return None, code_sig
        op = origin_env["payload"]
        if op.get("type") != "seallink-origin/1":
            return None, "ORIGIN_UNVERIFIED"
        if self.trusted_origin_issuers and op["issuer"]["name"] not in self.trusted_origin_issuers:
            return None, "ORIGIN_UNVERIFIED"
        # Check origin card kind match if card present
        if "card" in origin_bundle and origin_bundle["card"].get("kind") != op["origin_class"]:
            return None, "ORIGIN_UNVERIFIED"
        # Check SL-ORIG-016 consistency on initial guardian_policy
        if "guardian_policy" in op:
            ok_c, code_c = sl.check_guardian_policy_consistency(op["guardian_policy"])
            if not ok_c:
                return None, code_c
        # Verify origin 0x09 anchor
        origin_txid = origin_bundle.get("origin_anchor_txid")
        origin_tx = chain.get_tx(origin_txid) if origin_txid else None
        if not origin_tx or origin_tx.get("confirmed_height") is None or not origin_tx.get("opreturn_hex"):
            return None, "ORIGIN_UNVERIFIED"
        try:
            dec_o = sl.decode_opreturn(bytes.fromhex(origin_tx["opreturn_hex"]))
        except ValueError:
            return None, "ORIGIN_UNVERIFIED"
        if dec_o["action"] != "0x09" or dec_o["commitment"] != sl.content_addr(origin_env):
            return None, "ORIGIN_UNVERIFIED"
        h_origin = origin_tx["confirmed_height"]
        origin_id = sl.object_id(op)

        # Verify NameBinding (0x0c) & recovery spine
        binding = origin_bundle.get("name_binding")
        bind_txid = origin_bundle.get("name_binding_txid")
        if binding is None or not bind_txid:
            return None, "ORIGIN_BINDING_INVALID"
        if binding.get("origin_id") != origin_id:
            return None, "ORIGIN_BINDING_INVALID"
        bind_tx = chain.get_tx(bind_txid)
        if not bind_tx or bind_tx.get("confirmed_height") is None or bind_tx["confirmed_height"] <= h_origin:
            return None, "ORIGIN_BINDING_INVALID"
        reg_key = _outpoint_key(binding["registration"])
        existing_oid = chain.raw.get("registered_bindings", {}).get(reg_key)
        if existing_oid is not None and existing_oid != origin_id:
            return None, "ORIGIN_BINDING_INVALID"

        # Check recovery if pending/requested
        rec_pending = origin_bundle.get("pending_recovery_binding")
        if rec_pending is not None:
            nr = op["name_recovery"]
            if nr["mode"] == "none":
                return None, "RECOVERY_FORBIDDEN"
            rec_txid = origin_bundle.get("pending_recovery_txid")
            rec_tx = chain.get_tx(rec_txid) if rec_txid else None
            if not rec_tx or rec_tx.get("confirmed_height") is None:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            pending_id = sl.object_id(rec_pending)
            # Check live-owner 0x10 cancel
            old_name_rec = chain.get_name(binding["name"])
            if old_name_rec and pending_id in set(old_name_rec.get("recovery_cancel_ids", [])):
                return None, "RECOVERY_FORBIDDEN"
            if chain.tip_height < rec_tx["confirmed_height"] + nr["delay_blocks"]:
                return None, "RECOVERY_FORBIDDEN"

        # Walk status_seal spine
        cur_status_seal = op["status_seal"]
        emancipated = False
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
            if not stx or not stx.get("opreturn_hex"):
                return None, "ORIGIN_STATUS_INCOMPLETE"
            try:
                dec_s = sl.decode_opreturn(bytes.fromhex(stx["opreturn_hex"]))
            except ValueError:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            if dec_s["action"] != "0x09":
                return None, "ORIGIN_STATUS_INCOMPLETE"
            if end_rec is not None and sl.content_addr(end_rec) == dec_s["commitment"]:
                return None, "SUBJECT_ENDED"
            if cap_rec is not None and sl.content_addr(cap_rec) == dec_s["commitment"]:
                emancipated = True
                cp = cap_rec["payload"]
                cur_status_seal = {"txid": spend_txid, "vout": cp["next_status_vout"], "script_policy": cp["next_status_policy"]}
                continue
            return None, "ORIGIN_STATUS_INCOMPLETE"

        # Check majority boundary & emancipation handover state
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
            if not origin_bundle.get("handover_transfer_completed", False):
                return None, "GUARDIAN_TRANSFER_PENDING"
            return {"origin_id": origin_id, "capacity": "autonomous", "binding": binding}, None

        if "guardian_policy" not in op:
            return {"origin_id": origin_id, "capacity": "autonomous", "binding": binding}, None

        # Walk roster_seal chain to active revision
        gp = op["guardian_policy"]
        active_roster = {
            "revision": gp["revision"],
            "revision_size": gp["revision_size"],
            "disposer_pk": gp["disposer_pk"],
            "arbiter_pk": gp["arbiter_pk"],
            "challenger_pk": gp["challenger_pk"],
            "quorums": gp["quorums"],
            "appointment_delay_blocks": gp["appointment_delay_blocks"],
        }
        cur_roster_seal = gp["roster_seal"]
        roster_records_by_caddr = {
            sl.content_addr(r): r for r in origin_bundle.get("roster_records", [])
        }
        # Track active slots: slot -> {state, guardian_name, guardian_reg, active_outpoint, term, guardian_id}
        slot_states: dict[int, dict[str, Any]] = {}
        for s in gp["slots"]:
            slot_states[s["slot"]] = {
                "state": "initial_vacant",
                "vacant_outpoint": s["vacant_utxo"],
                "initial_guardian_commitment": s["initial_guardian_commitment"],
            }

        # Index guardian records by content_addr and id
        g_by_caddr = {sl.content_addr(g): g for g in origin_bundle.get("guardian_records", [])}
        g_by_id = {sl.object_id(g["payload"]): g for g in origin_bundle.get("guardian_records", [])}
        init_disclosures = origin_bundle.get("initial_guardian_disclosures", {})

        # Replay each slot's UTXO chain from initial_vacant / vacant
        def trace_slot(slot_num: int, st: dict[str, Any]) -> dict[str, Any]:
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
                    # Direct initial activation (0x12) ONLY from initial_vacant
                    if dec["action"] == "0x12":
                        if cur["state"] != "initial_vacant":
                            cur["state"] = "contested_burned"
                            return cur
                        grec = g_by_caddr.get(dec["commitment"])
                        if not grec or grec["payload"].get("activation_mode") != "initial":
                            cur["state"] = "contested_burned"
                            return cur
                        ok_gs, _ = sl.verify_envelope_signatures(grec)
                        if not ok_gs:
                            cur["state"] = "contested_burned"
                            return cur
                        gp_rec = grec["payload"]
                        disc = init_disclosures.get(str(slot_num)) or init_disclosures.get(slot_num)
                        if not disc or sl.clause_commit(disc["salt_hex"], gp_rec["guardian"]) != cur["initial_guardian_commitment"]:
                            cur["state"] = "contested_burned"
                            return cur
                        act_op = {"txid": stxid, "vout": gp_rec["active_vout"]}
                        aout = chain.get_output(act_op["txid"], act_op["vout"])
                        exp_act_spk, _ = sl.compile_script_policy(gp_rec["active_policy"])
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
                        if not grec or grec["payload"].get("activation_mode") != "appointed":
                            cur["state"] = "contested_burned"
                            return cur
                        ok_gs, _ = sl.verify_envelope_signatures(grec)
                        if not ok_gs:
                            cur["state"] = "contested_burned"
                            return cur
                        gp_rec = grec["payload"]
                        # Verify pending_policy binds disposer_pk, challenger_pk, delay_blocks
                        pp = gp_rec["pending_policy"]
                        if (
                            pp.get("template") != "guardian_slot_pending"
                            or pp["keys"]["disposer"] != active_roster["disposer_pk"]
                            or pp["keys"]["challenger"] != active_roster["challenger_pk"]
                            or pp["delay_blocks"] != gp_rec["effective_delay_blocks"]
                            or gp_rec["effective_delay_blocks"] < active_roster["appointment_delay_blocks"]
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
                            "pending_height": stx["confirmed_height"],
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
                    # Otherwise vetoed by disposer/challenger
                    vout0 = chain.get_output(stxid, 0)
                    vac_spk, _ = sl.compile_script_policy(
                        {"kind": "branch", "template": "both_of_2", "keys": {"a": active_roster["disposer_pk"], "b": active_roster["arbiter_pk"]}}
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
                        {"kind": "branch", "template": "both_of_2", "keys": {"a": active_roster["disposer_pk"], "b": active_roster["arbiter_pk"]}}
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
            slot_states[snum] = trace_slot(snum, slot_states[snum])

        # Walk roster_seal transitions (0x0f)
        for _ in range(16):
            rout = chain.get_output(cur_roster_seal["txid"], cur_roster_seal["vout"])
            if not rout:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            rspend = rout.get("spent_by_txid")
            if not rspend:
                break
            rtx = chain.get_tx(rspend)
            if not rtx or not rtx.get("opreturn_hex") or rtx.get("confirmed_height") is None:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            try:
                dec_r = sl.decode_opreturn(bytes.fromhex(rtx["opreturn_hex"]))
            except ValueError:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            if dec_r["action"] != "0x0f":
                return None, "ORIGIN_STATUS_INCOMPLETE"
            rrec = roster_records_by_caddr.get(dec_r["commitment"])
            if not rrec:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            ok_rs, _ = sl.verify_envelope_signatures(rrec)
            if not ok_rs:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            rp = rrec["payload"]
            ok_rc, code_rc = sl.check_guardian_policy_consistency(rp)
            if not ok_rc:
                return None, code_rc
            if rp["revision"] != active_roster["revision"] + 1:
                return None, "ORIGIN_STATUS_INCOMPLETE"
            # Effective delay check
            if chain.tip_height < rtx["confirmed_height"] + rp["effective_delay_blocks"]:
                break
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
                    grec = g_by_id.get(sspec["guardian_id"])
                    if not grec:
                        new_slot_states[sn] = {"state": "contested_burned"}
                    else:
                        gp_rec = grec["payload"]
                        new_slot_states[sn] = trace_slot(
                            sn,
                            {
                                "state": "active",
                                "active_outpoint": sspec["active_outpoint"],
                                "guardian_name": gp_rec["guardian"]["name"],
                                "guardian_pin": gp_rec["guardian"],
                                "guardian_id": sspec["guardian_id"],
                                "term": gp_rec["term"],
                            },
                        )
                elif act == "retain_vacant":
                    new_slot_states[sn] = trace_slot(sn, {"state": "vacant", "vacant_outpoint": sspec["vacant_outpoint"]})
                elif act == "new_vacant":
                    new_slot_states[sn] = trace_slot(
                        sn,
                        {"state": "vacant", "vacant_outpoint": {"txid": rspend, "vout": sspec["new_vacant_vout"]}},
                    )
            slot_states = new_slot_states

        return {
            "origin_id": origin_id,
            "capacity": "ward",
            "binding": binding,
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
        # 1. Must carry guardian_context AND guardian_approvals[] (not signatures)
        if "guardian_context" not in payload or "guardian_approvals" not in env or "signatures" in env:
            return False, "WARD_AUTONOMOUS_FORBIDDEN", {}
        gc = payload["guardian_context"]
        if gc["origin_id"] != ward_state["origin_id"] or gc["ward_name"] != ward_state["binding"]["name"]:
            return False, "ORIGIN_UNVERIFIED", {}
        roster = ward_state["roster"]
        if gc["revision"] != roster["revision"]:
            return False, "GUARDIAN_QUORUM_UNMET", {}

        approvals = env["guardian_approvals"]
        # Ascending slot order checked at wire level
        prev_slot = 0
        for item in approvals:
            if item["slot"] <= prev_slot:
                return False, "WIRE_SIGNATURE", {}
            prev_slot = item["slot"]
            if item["revision"] != gc["revision"]:
                return False, "GUARDIAN_QUORUM_UNMET", {}

        digest = sl.signing_digest(payload)
        verified_slots: list[int] = []
        verified_guardians: list[str] = []
        seen_guardian_regs: set[tuple[str, str]] = set()
        opened_maj = ward_state.get("opened_majority_unix")

        for item in approvals:
            sn = item["slot"]
            st = ward_state["slots"].get(sn)
            if not st or st.get("state") != "active":
                return False, "GUARDIAN_INACTIVE", {}
            if st["guardian_name"] != item["guardian_name"]:
                return False, "GUARDIAN_INACTIVE", {}
            # Check term bounds (SL-ORIG-009, SL-ORIG-016)
            term = st.get("term", {"mode": "indefinite"})
            if term.get("mode") == "calendar":
                if opened_maj is not None and term["not_after_unix"] > opened_maj:
                    return False, "GUARDIAN_INACTIVE", {}
                if chain.tip_height >= term["ceiling_height"] or chain.now >= term["not_after_unix"]:
                    return False, "GUARDIAN_INACTIVE", {}
            # Distinct (name, registration) check
            gpin = st["guardian_pin"]
            greg = (gpin["name"], _outpoint_key(gpin["registration"]))
            if greg in seen_guardian_regs:
                return False, "GUARDIAN_INACTIVE", {}
            seen_guardian_regs.add(greg)
            # Resolve guardian's live link.grant policy at tip
            gnrec, gerr = self.resolve_name(gpin["name"], chain, expected_owner_policy=gpin["owner_policy"])
            if gerr:
                return False, gerr, {}
            gpol, rerr = self.resolve_role_policy(gnrec, "grant", item["signatures"]["policy"])
            if rerr:
                return False, "WIRE_SIGNATURE" if rerr == "WIRE_SIGNATURE" else "GUARDIAN_INACTIVE", {}
            ok_s, code_s = sl.verify_signature_set(digest, item["signatures"], expected_policy=gpol)
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
    # SPEC-05 Assent, Contract, Credential, Notary
    # ------------------------------------------------------------------

    def verify_assent(
        self,
        assent_env: dict[str, Any],
        contract_obj: dict[str, Any],
        origin_bundle: dict[str, Any] | None,
        chain: ChainView,
    ) -> VerifierResult:
        obs_err = self.check_chain_observation(chain, risk_class=1)
        if obs_err:
            return VerifierResult("REFUSE", obs_err)
        ok_w, wcode = sl.verify_envelope_signatures(assent_env)
        if not ok_w:
            return VerifierResult("REFUSE", wcode)
        ap = assent_env["payload"]
        if ap.get("type") != "seallink-assent/1":
            return VerifierResult("REFUSE", "WIRE_TYPE")
        if ap["target_id"] != sl.object_id(contract_obj):
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        if ap["expires_at"] <= ap["issued_at"] or (ap["expires_at"] - ap["issued_at"]) > 259200 or chain.now >= ap["expires_at"]:
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        # Locate party in contract
        party = None
        for pt in contract_obj.get("parties", []):
            if pt["role"] == ap["party_role"]:
                party = pt
                break
        if party is None:
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        if "ward_origin_id" in party:
            if origin_bundle is None:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
            wstate, oerr = self.verify_origin_and_status(origin_bundle, chain)
            if oerr:
                return VerifierResult("REFUSE", oerr)
            if wstate["origin_id"] != party["ward_origin_id"]:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
            if wstate["capacity"] == "ward":
                ok_g, gerr, details = self.verify_ward_approvals(assent_env, wstate, chain)
                if not ok_g:
                    return VerifierResult("REFUSE", gerr)
                return VerifierResult("ADMIT", None, outcome="executed", details=details)
        # Autonomous party
        if "signing_policy" not in party:
            return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
        ok_s, scode = sl.verify_signature_set(sl.signing_digest(ap), assent_env.get("signatures", {}), expected_policy=party["signing_policy"])
        if not ok_s:
            return VerifierResult("REFUSE", scode)
        return VerifierResult("ADMIT", None, outcome="executed")

    def verify_credential(
        self,
        cred_env: dict[str, Any],
        anchor_txid: str | None,
        chain: ChainView,
        supported_kinds: set[str] | None = None,
    ) -> VerifierResult:
        """Execute SPEC-05 §4.2 deterministic 7-step credential verification order."""
        # 1. Wire check
        ok_sig, scode = sl.verify_envelope_signatures(cred_env)
        if not ok_sig:
            return VerifierResult("REFUSE", scode)
        cp = cred_env["payload"]
        if cp.get("type") != "seallink-credential/1":
            return VerifierResult("REFUSE", "WIRE_TYPE")
        # 2. Supported kind
        if supported_kinds is not None and cp["credential_kind"] not in supported_kinds:
            return VerifierResult("REFUSE", "WIRE_TYPE")
        # 3. Chain match & subject name_pin owner match
        if cp["network"] != self.pinned_network or cp["genesis"] != self.pinned_genesis:
            return VerifierResult("REFUSE", "CHAIN_MISMATCH")
        subj = cp["subject"]
        if subj.get("mode") == "name_pin":
            _, serr = self.resolve_name(subj["name_pin"]["name"], chain, expected_owner_policy=subj["name_pin"]["owner_policy"])
            if serr:
                return VerifierResult("REFUSE", serr)
        # 4. Signed-form 0x09 anchor
        atx = chain.get_tx(anchor_txid) if anchor_txid else None
        if not atx or atx.get("confirmed_height") is None or not atx.get("opreturn_hex"):
            return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
        try:
            dec = sl.decode_opreturn(bytes.fromhex(atx["opreturn_hex"]))
        except ValueError:
            return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
        if dec["action"] != "0x09" or dec["commitment"] != sl.content_addr(cred_env):
            return VerifierResult("REFUSE", "CRED_ANCHOR_MISSING")
        h_anchor = atx["confirmed_height"]
        if chain.tip_height - h_anchor + 1 < self.operator_min_depth:
            return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
        # 5. Issuer history, owner_policy, role_policy, 0x0b h_c break
        iss = cp["issuer"]
        nrec, nerr = self.resolve_name(iss["name"], chain, expected_owner_policy=iss["owner_policy"])
        if nerr:
            return VerifierResult("REFUSE", nerr)
        for brk in nrec.get("compromised_breaks", []):
            if brk.get("role") == "cred" and h_anchor >= brk["h_c"]:
                return VerifierResult("REFUSE", "CRED_ISSUER_CLOSED")
        if cp["lifecycle"] == "revocable":
            rpol, rerr = self.resolve_role_policy(nrec, "cred", iss["role_policy"])
            if rerr:
                return VerifierResult("REFUSE", rerr)
            ok_p, pcode = sl.verify_signature_set(sl.signing_digest(cp), cred_env["signatures"], expected_policy=rpol)
            if not ok_p:
                return VerifierResult("REFUSE", pcode)
        else:
            ok_p, pcode = sl.verify_signature_set(sl.signing_digest(cp), cred_env["signatures"], expected_policy=iss["role_policy"])
            if not ok_p:
                return VerifierResult("REFUSE", pcode)
        # 6. Height window check
        if chain.tip_height < cp["not_before_height"]:
            return VerifierResult("REFUSE", "CRED_WINDOW_CLOSED")
        if "not_after_height" in cp and chain.tip_height >= cp["not_after_height"]:
            return VerifierResult("REFUSE", "CRED_WINDOW_CLOSED")
        # 7. Revocable seal state (0x0a -> CRED_REVOKED_FOR_CAUSE)
        if cp["lifecycle"] == "revocable":
            seal = cp["revocation_seal"]
            out = chain.get_output(seal["txid"], seal["vout"])
            if out and out.get("spend_has_0x0a"):
                return VerifierResult("REFUSE", "CRED_REVOKED_FOR_CAUSE")
            _, serr, _ = self.evaluate_seal(seal, chain, required_depth=1)
            if serr:
                return VerifierResult("REFUSE", serr)
        return VerifierResult("ADMIT", None, outcome="executed")

    # ------------------------------------------------------------------
    # SPEC-06 §4 Deterministic 12-Step Invocation Admission Pipeline
    # ------------------------------------------------------------------

    def verify_invocation(
        self,
        inv_env: dict[str, Any],
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
    ) -> VerifierResult:
        """Execute SPEC-06 §4 Steps 1..12 deterministically and return computed VerifierResult."""
        # Step 1: Invocation wire check
        try:
            raw_inv = sl.jcs_encode(inv_env)
        except ValueError as exc:
            return VerifierResult("REFUSE", str(exc))
        ok_w, res_w = self.verify_wire_bytes(raw_inv)
        if not ok_w:
            return VerifierResult("REFUSE", res_w)
        inv_p = inv_env["payload"]
        if inv_p.get("type") != "seallink-invocation/1":
            return VerifierResult("REFUSE", "WIRE_TYPE")
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
            try:
                raw_g = sl.jcs_encode(g)
            except ValueError as exc:
                return VerifierResult("REFUSE", str(exc))
            ok_g, res_g = self.verify_wire_bytes(raw_g)
            if not ok_g:
                return VerifierResult("REFUSE", res_g)
            grants_by_id[sl.object_id(g["payload"])] = g

        ppath = inv_p["proof_path"]
        if not ppath:
            return VerifierResult("REFUSE", "WIRE_MEMBER")
        if len(ppath) > 2:
            return VerifierResult("REFUSE", "GRANT_NOT_DELEGABLE")
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
                sl.signing_digest(inv_p), inv_env["signatures"], expected_policy={"m": 1, "pks": [rcpt_spec["key"]]}
            )
            if not ok_r:
                return VerifierResult("REFUSE", rcode)
        elif rcpt_spec["mode"] == "group":
            ok_r, rcode = sl.verify_signature_set(
                sl.signing_digest(inv_p), inv_env["signatures"], expected_policy=rcpt_spec["threshold"]
            )
            if not ok_r:
                return VerifierResult("REFUSE", rcode)

        # Helper for Step 3c (and deferred Step 11a for recipient.mode == "name")
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
                    details={"reservation_retained": True, "zero_second_effect": True},
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
        act_meta = ACTION_PROFILES.get(action, {"risk_class": 1, "mechanical": True, "external_mutation": True, "allows_executor_ref": False, "requires_contract": False, "require_seal": True})
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
        nrec, nerr = self.resolve_name(iss_pin["name"], chain, expected_owner_policy=iss_pin["owner_policy"])
        if nerr:
            return VerifierResult("REFUSE", nerr)

        origin_bundle = bundle.get("origin_bundle")
        ward_details: dict[str, Any] = {}
        is_origin_cert = bool(nrec.get("_value_obj", {}).get("link", {}).get("origin")) or (origin_bundle is not None)
        if is_origin_cert:
            if origin_bundle is None:
                return VerifierResult("REFUSE", "ORIGIN_UNVERIFIED")
            wstate, oerr = self.verify_origin_and_status(origin_bundle, chain)
            if oerr:
                return VerifierResult("REFUSE", oerr)
            if wstate["capacity"] == "ward":
                ok_wa, werr, ward_details = self.verify_ward_approvals(root_grant, wstate, chain)
                if not ok_wa:
                    return VerifierResult("REFUSE", werr)
            else:
                rpol, rerr = self.resolve_role_policy(nrec, "grant", iss_pin.get("role_policy"))
                if rerr:
                    return VerifierResult("REFUSE", rerr)
                ok_rs, rscode = sl.verify_signature_set(sl.signing_digest(root_gp), root_grant.get("signatures", {}), expected_policy=rpol)
                if not ok_rs:
                    return VerifierResult("REFUSE", rscode)
        else:
            rpol, rerr = self.resolve_role_policy(nrec, "grant", iss_pin.get("role_policy"))
            if rerr:
                return VerifierResult("REFUSE", rerr)
            ok_rs, rscode = sl.verify_signature_set(sl.signing_digest(root_gp), root_grant.get("signatures", {}), expected_policy=rpol)
            if not ok_rs:
                return VerifierResult("REFUSE", rscode)

        # Step 8: Contract and framework checks
        if act_meta.get("requires_contract", False) and "contract_id" not in leaf_gp:
            return VerifierResult("REFUSE", "GRANT_CONTRACT_REQUIRED")
        if "contract_id" in leaf_gp:
            c_obj = bundle.get("contract")
            if c_obj is None:
                return VerifierResult("REFUSE", "CONTRACT_NOT_PRESENTED")
            if sl.object_id(c_obj) != leaf_gp["contract_id"]:
                return VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH")
            # Framework check if declared
            if "framework_id" in c_obj:
                fw_obj = bundle.get("framework_contract")
                if fw_obj is None:
                    return VerifierResult("REFUSE", "CONTRACT_NOT_PRESENTED")
                if sl.object_id(fw_obj) != c_obj["framework_id"]:
                    return VerifierResult("REFUSE", "CONTRACT_ID_MISMATCH")
                if "framework_id" in fw_obj:
                    return VerifierResult("REFUSE", "CONTRACT_TERMS_MISMATCH")
                if "seal" not in fw_obj:
                    return VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING")
                _, fw_serr, _ = self.evaluate_seal(fw_obj["seal"], chain, required_depth=1)
                if fw_serr:
                    return VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING" if fw_serr == "CHAIN_SCRIPT_UNSUPPORTED" else fw_serr)
            # Party assents
            assents = bundle.get("contract_assents", [])
            if len(assents) < len(c_obj["parties"]):
                return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
            for a in assents:
                ares = self.verify_assent(a, c_obj, origin_bundle, chain)
                if ares.verdict != "ADMIT":
                    return VerifierResult("REFUSE", "CONTRACT_ASSENT_INVALID")
            # Contract seal check
            if "seal" not in c_obj:
                return VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING")
            _, c_serr, _ = self.evaluate_seal(c_obj["seal"], chain, required_depth=1)
            if c_serr:
                if c_serr in ("SEAL_SPENT", "SEAL_UNAVAILABLE"):
                    return VerifierResult("REFUSE", c_serr)
                return VerifierResult("REFUSE", "CONTRACT_SEAL_MISSING")
            # Machine clause disclosures & window nesting
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
            # Agreed config_sha256 check
            if "config_sha256" in c_obj:
                rt_cfg = executor_cfg.get("runtime_config_sha256")
                arg_cfg = inv_p["arguments"].get("config_sha256")
                if (rt_cfg is not None and rt_cfg != c_obj["config_sha256"]) or (arg_cfg is not None and arg_cfg != c_obj["config_sha256"]):
                    return VerifierResult("REFUSE", "CONTRACT_CONFIG_MISMATCH")

        # Step 9: Depth-2 Re-delegation checks (R8.5, R8.6, row coin, stop coin, notary, narrowing)
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
            # Locate ordinal's group, row coin, and optional stop coin
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
            # Verify child issuance tx spent the exact row coin
            c_itxid = ppath[1].get("issuance_txid")
            c_itx = chain.get_tx(c_itxid) if c_itxid else None
            if not c_itx or _outpoint_key(row_outpoint) not in set(c_itx.get("spent_outpoints", [])):
                return VerifierResult("REFUSE", "GRANT_ROW_INVALID")
            # Stop coin check
            if stop_outpoint is not None:
                sout = chain.get_output(stop_outpoint["txid"], stop_outpoint["vout"])
                if sout and (sout.get("spent_by_txid") or sout.get("absent_from_utxo")):
                    return VerifierResult("REFUSE", "GRANT_ROW_STOPPED")
            # Notary check
            tpl = matched_group["template"]
            if tpl["notary_mode"] == "required_act":
                if not bundle.get("notary_act"):
                    return VerifierResult("REFUSE", "NOTARY_REQUIRED")
            # Verify child signature against parent.delegate.key
            ok_cs, cscode = sl.verify_signature_set(
                sl.signing_digest(leaf_gp), leaf_grant.get("signatures", {}), expected_policy={"m": 1, "pks": [del_spec["key"]]}
            )
            if not ok_cs:
                return VerifierResult("REFUSE", cscode)
            # Mechanical narrowing check
            if (
                leaf_gp["genesis"] != root_gp["genesis"]
                or leaf_gp.get("contract_id") != root_gp.get("contract_id")
                or leaf_gp.get("executor") != tpl["executor"]
                or leaf_gp["not_before_height"] < root_gp["not_before_height"]
                or leaf_gp["not_after_height"] > root_gp["not_after_height"]
            ):
                return VerifierResult("REFUSE", "GRANT_CHILD_WIDER")
            if leaf_gp["revocation"]["mode"] != "seal":
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
        for idx, pe in enumerate(ppath):
            g = grants_by_id[pe["grant_id"]]
            gp = g["payload"]
            gid = pe["grant_id"]
            # 10a. Height window
            if not (gp["not_before_height"] <= chain.tip_height < gp["not_after_height"]):
                return VerifierResult("REFUSE", "GRANT_WINDOW_CLOSED")
            # 10b/10c. Revocation mode
            rev = gp["revocation"]
            if rev["mode"] == "window_only":
                if gp["not_after_height"] - gp["not_before_height"] > 12:
                    return VerifierResult("REFUSE", "WIRE_INTEGER")
                if not self.allow_window_only or act_meta.get("require_seal", True):
                    return VerifierResult("REFUSE", "GRANT_SEAL_REQUIRED")
            else:
                itxid = pe.get("issuance_txid")
                itx = chain.get_tx(itxid) if itxid else None
                if not itx or not itx.get("opreturn_hex"):
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                try:
                    dec_i = sl.decode_opreturn(bytes.fromhex(itx["opreturn_hex"]))
                except ValueError:
                    return VerifierResult("REFUSE", "CHAIN_FRAME_INVALID")
                # Check issuance commitment (0x01 direct or 0x02 Merkle batch)
                iss_prep = {
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
                # Recency check (R < A <= R + K)
                r_height = chain.raw.get("blocks", {}).get(gp["recent_block"])
                a_height = itx.get("confirmed_height")
                if r_height is None:
                    return VerifierResult("REFUSE", "CHAIN_RECENCY_INVALID")
                if a_height is not None:
                    k_lim = chain.raw.get("recency_k", 432)
                    if not (r_height < a_height <= r_height + k_lim):
                        return VerifierResult("REFUSE", "CHAIN_RECENCY_INVALID")
                # Witness W construction check
                if rev["construction"] != "W" or not itx.get("segwit_w", True):
                    return VerifierResult("REFUSE", "CHAIN_TX_CONSTRUCTION")
                req_depth = max(gp.get("min_depth", 1), self.operator_min_depth)
                if a_height is None or (chain.tip_height - a_height + 1) < req_depth:
                    return VerifierResult("REFUSE", "CHAIN_DEPTH_INSUFFICIENT")
                # Seal evaluation
                if rev["kind"] == "revocable":
                    _, serr, jw = self.evaluate_seal(rev["seal"], chain, required_depth=req_depth, journal=journal, subject_id=gid, subject_kind="grant")
                    if jw:
                        journal_writes.append(jw)
                    if serr:
                        return VerifierResult("REFUSE", serr, journal_writes=journal_writes)
                else:
                    # single_use on leaf grant
                    _, serr, jw = self.evaluate_single_use_seal(
                        rev["seal"], use_txid, inv_caddr, req_depth, chain, journal=journal, grant_id=gid
                    )
                    if jw:
                        journal_writes.append(jw)
                    if serr:
                        return VerifierResult("REFUSE", serr, journal_writes=journal_writes)

        # 10d. Executor binding (concrete executor vs executor_ref)
        if "executor_ref" in leaf_gp:
            if not act_meta.get("allows_executor_ref", False) or "delegate" in leaf_gp or leaf_gp["revocation"].get("kind") == "single_use":
                return VerifierResult("REFUSE", "GRANT_EXECUTOR_REF_FORBIDDEN")
            for cap in leaf_gp["capabilities"]:
                if cap.get("quotas"):
                    return VerifierResult("REFUSE", "GRANT_EXECUTOR_REF_FORBIDDEN")
            eref = leaf_gp["executor_ref"]
            holder_rec, herr = self.resolve_name(eref["provider_of"], chain)
            if herr:
                return VerifierResult("REFUSE", herr)
            holder_man, merr = self.resolve_manifest(eref["provider_of"], holder_rec, bundle.get("manifests", {}), chain, journal)
            if merr:
                return VerifierResult("REFUSE", merr)
            matched_prov = None
            for pe_prov in holder_man.get("providers", []):
                if pe_prov["service_type"] == eref["service_type"] and pe_prov["label"] == eref["label"]:
                    matched_prov = pe_prov["provider"]
                    break
            if matched_prov is None:
                return VerifierResult("REFUSE", "SERVICE_PROVIDER_UNBOUND")
            prov_rec, perr = self.resolve_name(matched_prov["name"], chain, expected_owner_policy=matched_prov["owner_policy"])
            if perr:
                return VerifierResult("REFUSE", perr)
            prov_man, pmerr = self.resolve_manifest(matched_prov["name"], prov_rec, bundle.get("manifests", {}), chain, journal)
            if pmerr:
                return VerifierResult("REFUSE", pmerr)
            svc = prov_man.get("service", {})
            if matched_prov["name"] != executor_cfg["name"] or svc.get("receipt_key") != executor_cfg["key"]:
                return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")
        else:
            if leaf_gp["executor"]["name"] != executor_cfg["name"] or leaf_gp["executor"]["key"] != executor_cfg["key"]:
                return VerifierResult("REFUSE", "GRANT_EXECUTOR_MISMATCH")

        # Step 11: Named recipient, action, text ban, and constraints
        # 11a. recipient.mode == "name"
        if rcpt_spec["mode"] == "name":
            r_nrec, r_nerr = self.resolve_name(rcpt_spec["name"], chain, expected_owner_policy=rcpt_spec["owner_policy"])
            if r_nerr:
                return VerifierResult("REFUSE", r_nerr)
            nostr_val = r_nrec.get("_value_obj", {}).get("nostr")
            req_pk = nostr_val if isinstance(nostr_val, str) else (nostr_val.get("names", {}).get("_") if isinstance(nostr_val, dict) else None)
            if not req_pk:
                return VerifierResult("REFUSE", "WIRE_SIGNATURE")
            ok_rsig, rscode = sl.verify_signature_set(
                sl.signing_digest(inv_p), inv_env["signatures"], expected_policy={"m": 1, "pks": [req_pk]}
            )
            if not ok_rsig:
                return VerifierResult("REFUSE", rscode)
            # Deferred Step 3c replay / crash-recovery check for named recipient
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
                # Server-side mail/read message metadata enforcement (SL-MAIL-004)
                if actual_message_meta is not None and arg_k in actual_message_meta:
                    if not sl.match_predicate(pred, actual_message_meta[arg_k]):
                        ok_where = False
                        break
            if ok_where:
                matched_cap = cap
                break
        if matched_cap is None:
            return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")

        # Profile-specific checks for agent/guardian-message (PROFILE-agent-v1 §5)
        if action == "agent/guardian-message":
            args = inv_p["arguments"]
            pinned_oid = executor_cfg.get("pinned_ward_origin_id")
            if pinned_oid and (inv_p["target"] != f"ward:{pinned_oid}" or args["origin_id"] != pinned_oid):
                return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")
            if ward_details and args["revision"] != ward_details.get("verified_revision"):
                return VerifierResult("REFUSE", "GUARDIAN_QUORUM_UNMET")
            if raw_message_bytes is not None and sl.sha256(raw_message_bytes).hex() != args["message_sha256"]:
                return VerifierResult("REFUSE", "INVOKE_CONSTRAINT_FAILED")

        # Step 12: Pre-effect recheck & atomic journal reservation/settlement
        rb_err = self.check_rebracket(chain, risk_class=act_meta["risk_class"])
        if rb_err:
            return VerifierResult("REFUSE", rb_err)

        # Check quotas & seconds watermark
        quotas = matched_cap.get("quotas", [])
        if quotas:
            account = "row" if len(ppath) == 2 else "own"
            for q in quotas:
                qkey = f"{q['kind']}|{q['resource']}|{q['unit']}|{q['window']}"
                if q["window"].startswith("seconds:"):
                    wm = journal.quota_watermarks.get(qkey, 0)
                    if chain.now < wm:
                        return VerifierResult("REFUSE", "QUOTA_CLOCK_REGRESSION")
                    journal.quota_watermarks[qkey] = chain.now
                    sec_s = int(q["window"].split(":", 1)[1])
                    bucket_id = f"sec:{(chain.now // sec_s) * sec_s}"
                elif q["window"].startswith("blocks:"):
                    blk_n = int(q["window"].split(":", 1)[1])
                    k = (chain.tip_height - leaf_gp["not_before_height"]) // blk_n
                    bucket_id = f"blk:{leaf_gp['not_before_height'] + k * blk_n}"
                else:
                    bucket_id = "term"
                scope = f"{account}:{leaf_gid}"
                used = journal.quotas_used.get((scope, qkey, bucket_id), 0)
                debit = 1
                if used + debit > int(q["max"]):
                    return VerifierResult("REFUSE", "QUOTA_EXCEEDED")
                # Check journal continuity immediately before write
                j_err2 = journal.check_continuity()
                if j_err2:
                    return VerifierResult("REFUSE", j_err2)
                jw_res = journal.append(
                    "reservation",
                    {
                        "account": account,
                        "amount": str(debit),
                        "bucket_id": bucket_id,
                        "grant_id": leaf_gid,
                        "invocation_id": inv_id,
                        "quota_kind": q["kind"],
                        "recorded_at": chain.now,
                        "resource": q["resource"],
                        "unit": q["unit"],
                        "window": q["window"],
                    },
                )
                journal_writes.append(jw_res)
            if simulate_crash_before_settlement:
                return VerifierResult(
                    "UNCERTAIN",
                    None,
                    outcome="uncertain",
                    journal_writes=journal_writes,
                    details={"crashed_in_effect_window": True, "reservation_retained": True},
                )
            rcpt_caddr = sl.content_addr(receipt_env_for_cache) if receipt_env_for_cache else sl.sha256(inv_id.encode()).hex()
            jw_set = journal.append(
                "settlement",
                {
                    "grant_id": leaf_gid,
                    "invocation_id": inv_id,
                    "outcome": "executed",
                    "receipt_sha256": rcpt_caddr,
                    "recorded_at": chain.now,
                    "released": "0",
                    "settled": "1",
                },
            )
            journal_writes.append(jw_set)
            if leaf_gp["revocation"].get("kind") == "single_use":
                jw_su = journal.append(
                    "single-use-consumed",
                    {
                        "grant_id": leaf_gid,
                        "invocation_id": inv_id,
                        "receipt_sha256": rcpt_caddr,
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
        else:
            # Stateless / non-quota invocation writes nonce entry
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

        if receipt_env_for_cache is not None:
            journal.receipts[inv_id] = copy.deepcopy(receipt_env_for_cache)

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
    ) -> VerifierResult:
        ok, code = sl.verify_envelope_signatures(migration_env)
        if not ok:
            return VerifierResult("REFUSE", code)
        mp = migration_env["payload"]
        if mp.get("type") != "seallink-migration/1":
            return VerifierResult("REFUSE", "WIRE_TYPE")
        # Reject leaked execution credentials, rollback, unclosed old grants, or conflicting migration_id
        if export_bundle.get("contains_execution_credentials", False):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        if not export_bundle.get("source_fenced", True) or not export_bundle.get("predecessor_grants_closed", True):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        if export_bundle.get("inventory_sha256") != mp.get("inventory_sha256"):
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        mid = sl.object_id(mp)
        if mid in journal.migrations_applied:
            return VerifierResult("REFUSE", "SERVICE_MIGRATION_INVALID")
        journal.migrations_applied.add(mid)
        return VerifierResult("ADMIT", None, outcome="executed")

    def verify_federation_disclosure(
        self,
        policy: dict[str, Any],
        peer_ctx: dict[str, Any],
        grant_env: dict[str, Any],
    ) -> VerifierResult:
        gp = grant_env["payload"]
        # Phase 1: per-peer quotas required
        if peer_ctx.get("phase") == "screening":
            has_quota = any(bool(c.get("quotas")) for c in gp.get("capabilities", []))
            if not has_quota or peer_ctx.get("peer_trusted") is False:
                return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
            return VerifierResult("ADMIT", None, outcome="executed")
        # Phase 2: Contour A routing & L2 human gate (screening agent must never receive PII or self-issue)
        if peer_ctx.get("phase") == "pii_disclosure":
            if peer_ctx.get("routed_through_screening_agent", False) or not peer_ctx.get("l2_human_approved", False):
                return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
            return VerifierResult("ADMIT", None, outcome="executed")
        return VerifierResult("REFUSE", "FEDERATION_POLICY_DENIED")
