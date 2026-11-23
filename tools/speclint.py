#!/usr/bin/env python3
"""
SealLink Specification Consistency, Schema, Cryptography, and Executable Tier 1 Verifier Linter.

Validates:
  1. All JSON files in registry/, schemas/, and vectors/ are valid JSON.
  2. Every cross-file and local $ref in schemas/*.schema.json resolves.
  3. Every schema target in registry/object-types.json resolves and matches its type const.
  4. Cross-registry signer coherence between object-types.json and key-roles.json.
  5. Every SL-<AREA>-<NNN> rule ID across spec/ and profiles/ is uniquely declared,
     and every referenced SL-* ID is declared.
  6. Every seallink-*/1 type and refusal code cited in spec/ and profiles/ is registered.
  7. Every SPEC-*.md carries Status, Evidence / Maturity, References, and Security Considerations.
  8. Full cryptographic & structural re-verification of all vectors/*.json via seallink_ref.py.
  9. LIVE EXECUTION of trace-01, trace-02, trace-03, trace-04, negative semantic & SL-ORIG-016
     fixtures, and ALL 84/84 refusal codes in refusal-coverage-matrix.json through
     tools/seallink_verifier.py — asserting computed verdicts, refusal codes, and journal
     hash-chain commitments match expected values.
 10. Full Draft 2020-12 metaschema + instance validation of all vectors (required in CI).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_refusal_matrix as rm
import build_security_suite as sec
import seallink_ref as sl
import seallink_verifier as sv

REFUSAL_PREFIXES = (
    "WIRE_",
    "CHAIN_",
    "SEAL_",
    "NAME_",
    "MANIFEST_",
    "AUTH_",
    "DEVICE_",
    "ORIGIN_",
    "WARD_",
    "GUARDIAN_",
    "SUBJECT_",
    "RECOVERY_",
    "CONTRACT_",
    "CRED_",
    "NOTARY_",
    "GRANT_",
    "INVOKE_",
    "QUOTA_",
    "SESSION_",
    "JOURNAL_",
    "SERVICE_",
    "FEDERATION_",
)

RULE_ID_RE = re.compile(r"`(SL-[A-Z]+-\d{3})`")
TYPE_RE = re.compile(r"\b(seallink-[a-z0-9-]+/\d+)\b")
CODE_RE = re.compile(r"\b((?:" + "|".join(REFUSAL_PREFIXES) + r")[A-Z0-9_]+)\b")
DOMAIN_ONLY_TAGS = frozenset({
    "seallink-clause/1",
    "seallink-journal/1",
    "seallink-merkle-leaf/1",
    "seallink-merkle-node/1",
})
BASE_NON_REFUSAL_IDENTIFIERS = frozenset({
    "NAME_NEW",
    "NAME_FIRSTUPDATE",
    "NAME_UPDATE",
})


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        errors.append(f"Invalid JSON in {path.relative_to(ROOT)}: {exc}")
        return None


def resolve_node(doc: dict[str, Any], pointer: str) -> Any:
    if not pointer or pointer == "#":
        return doc
    if not pointer.startswith("#/"):
        return None
    cur: Any = doc
    for part in pointer[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def find_type_consts(node: Any, doc: dict[str, Any], seen: set[str] | None = None) -> set[str]:
    found: set[str] = set()
    if seen is None:
        seen = set()
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/") and ref not in seen:
            seen.add(ref)
            target = resolve_node(doc, ref)
            if target is not None:
                found |= find_type_consts(target, doc, seen)
        props = node.get("properties", {})
        if "type" in props and isinstance(props["type"], dict) and "const" in props["type"]:
            found.add(props["type"]["const"])
        if "payload" in props:
            found |= find_type_consts(props["payload"], doc, seen)
        for k in ("oneOf", "anyOf", "allOf"):
            for sub in node.get(k, []):
                found |= find_type_consts(sub, doc, seen)
    return found


def resolve_pointer(doc: dict[str, Any], pointer: str) -> bool:
    return resolve_node(doc, pointer) is not None


def walk_refs(obj: Any, refs: list[str]) -> None:
    if isinstance(obj, dict):
        if "$ref" in obj and isinstance(obj["$ref"], str):
            refs.append(obj["$ref"])
        for v in obj.values():
            walk_refs(v, refs)
    elif isinstance(obj, list):
        for item in obj:
            walk_refs(item, refs)


def check_cross_registry_coherence(registries: dict[str, Any], errors: list[str]) -> None:
    if "object-types.json" not in registries or "key-roles.json" not in registries:
        return
    roles = {r["role"]: r for r in registries["key-roles.json"].get("roles", [])}
    for entry in registries["object-types.json"].get("types", []):
        obj_type = entry["type"]
        if not entry.get("signed", False):
            continue
        signer_roles = entry.get("signer_roles", [])
        if not signer_roles:
            errors.append(f"Signed type '{obj_type}' has empty signer_roles in object-types.json")
        for role in signer_roles:
            if role not in roles:
                errors.append(f"object-types.json type '{obj_type}' references unknown role '{role}' missing from key-roles.json")
                continue
            rdef = roles[role]
            allowed = rdef.get("allowed_operations", [])
            forbidden = rdef.get("forbidden_operations", [])
            if obj_type in forbidden:
                errors.append(f"Cross-registry conflict: '{obj_type}' permits role '{role}' in object-types.json, but key-roles.json forbids it")
            if obj_type not in allowed:
                errors.append(f"Cross-registry mismatch: '{obj_type}' permits role '{role}' in object-types.json, but '{obj_type}' is absent from key-roles.json allowed_operations")


def collect_schema_instances(obj: Any, out: list[tuple[str, dict[str, Any], str]]) -> None:
    """Recursively collect (schema_ref, instance_obj, path_hint) pairs for positive vector objects."""
    if isinstance(obj, dict):
        if "schema" in obj and "object" in obj and "expected_refusal" not in obj:
            out.append((obj["schema"], obj["object"], obj.get("id", obj["schema"])))
        if "profile_args_schema" in obj and "invocation" in obj:
            inv_obj = obj["invocation"]["object"]
            out.append((obj["profile_args_schema"], inv_obj["payload"]["arguments"], obj["profile_args_schema"]))
        for k, v in obj.items():
            if k in ("negative_schema_fixtures", "negative_semantic_fixtures", "negative_signaturesets", "cases"):
                continue
            collect_schema_instances(v, out)
    elif isinstance(obj, list):
        for item in obj:
            collect_schema_instances(item, out)


def verify_envelope_record(rec: dict[str, Any], label: str, errors: list[str]) -> None:
    obj = rec["object"]
    raw = sl.jcs_encode(obj).decode("utf-8")
    if raw != rec["canonical_jcs"]:
        errors.append(f"Vector {label}: canonical_jcs mismatch")
    if sl.object_id(obj["payload"]) != rec["object_id"]:
        errors.append(f"Vector {label}: object_id mismatch")
    if sl.signing_digest(obj["payload"]).hex() != rec["signing_digest"]:
        errors.append(f"Vector {label}: signing_digest mismatch")
    if sl.content_addr(obj) != rec["content_addr"]:
        errors.append(f"Vector {label}: content_addr mismatch")
    ok, code = sl.verify_envelope_signatures(obj)
    if not ok:
        errors.append(f"Vector {label}: BIP-340 signature verification failed ({code})")


def verify_unsigned_record(rec: dict[str, Any], label: str, errors: list[str]) -> None:
    obj = rec["object"]
    raw = sl.jcs_encode(obj).decode("utf-8")
    if raw != rec["canonical_jcs"]:
        errors.append(f"Vector {label}: canonical_jcs mismatch")
    if sl.object_id(obj) != rec["object_id"]:
        errors.append(f"Vector {label}: object_id mismatch")
    if sl.content_addr(obj) != rec["content_addr"]:
        errors.append(f"Vector {label}: content_addr mismatch")


def _assert_journal_write(got_jw: dict[str, Any], exp_jw: dict[str, Any], label: str, errors: list[str]) -> None:
    if got_jw["c_before"] != exp_jw["c_before"] or got_jw["c_after"] != exp_jw["c_after"]:
        errors.append(f"Verifier {label}: journal commitment mismatch (got {got_jw['c_before'][:12]}->{got_jw['c_after'][:12]})")
    if got_jw["entry"] != exp_jw["entry"]["object"]:
        errors.append(f"Verifier {label}: journal entry object mismatch")


def execute_traces_and_matrix(
    vectors: dict[str, dict[str, Any]],
    registered_codes: set[str],
    require_jsonschema: bool,
    errors: list[str],
) -> tuple[int, int, int]:
    """Execute ALL traces (trace-01..04), ALL 84/84 refusal-coverage-matrix cases,
    ALL security-conformance cases, and 10 live verifier-mutation tests via Tier1Verifier.
    """
    exec_checks = 0
    covered_refusals: set[str] = set()

    # --- Execute trace-01-mail-offline-revoke.json ---
    if "trace-01-mail-offline-revoke.json" in vectors:
        t1 = vectors["trace-01-mail-offline-revoke.json"]
        v = sv.Tier1Verifier(require_jsonschema=require_jsonschema)
        ch = sv.ChainView(t1["initial_chain_state"])
        jr = sv.FencedJournal.from_dict(t1["initial_journal_state"])
        exec_cfg = t1["executor_config"]
        alice_man = t1["ledger_state"]["alice_manifest"]["object"]
        host_man = t1["ledger_state"]["host_manifest"]["object"]
        bundle = {
            "grants": [t1["grant"]["object"]],
            "manifests": {sl.content_addr(alice_man): alice_man, sl.content_addr(host_man): host_man},
        }
        mime_b = bytes.fromhex(t1["ledger_state"]["mime_bytes_hex"])
        s1_res_obj = t1["steps"][0]["result_object"]["object"]
        if s1_res_obj["size_bytes"] != str(len(mime_b)) or s1_res_obj["mime_sha256"] != sl.sha256(mime_b).hex():
            errors.append("trace-01: MailReadResult size_bytes/mime_sha256 disagrees with mime_bytes_hex")
        exec_checks += 1

        for st in t1["steps"]:
            if "chain_patch" in st:
                ch.apply_patch(st["chain_patch"])
            if "invocation" in st:
                rcpt_cache = st["receipt"]["object"] if "receipt" in st else None
                res = v.verify_invocation(st["invocation"]["object"], bundle, ch, jr, exec_cfg, receipt_env_for_cache=rcpt_cache)
                if res.verdict != st["expected_verdict"]:
                    errors.append(f"trace-01 step {st['step']}: expected verdict {st['expected_verdict']}, got {res.verdict} ({res.refusal_code})")
                if st.get("expected_refusal") != res.refusal_code:
                    errors.append(f"trace-01 step {st['step']}: expected refusal {st.get('expected_refusal')}, got {res.refusal_code}")
                if res.refusal_code:
                    covered_refusals.add(res.refusal_code)
                if "journal_write" in st:
                    if not res.journal_writes:
                        errors.append(f"trace-01 step {st['step']}: expected journal write, got none")
                    else:
                        _assert_journal_write(res.journal_writes[0], st["journal_write"], f"trace-01/step-{st['step']}", errors)
                exec_checks += 1
            else:
                _, serr, jw = v.evaluate_seal(
                    t1["grant"]["object"]["payload"]["revocation"]["seal"],
                    ch,
                    required_depth=1,
                    journal=jr,
                    subject_id=t1["grant"]["object_id"],
                    subject_kind="grant",
                )
                if serr != st["expected_seal_refusal"] or jw is None:
                    errors.append(f"trace-01 step {st['step']}: expected seal refusal {st['expected_seal_refusal']}, got {serr}")
                else:
                    covered_refusals.add(serr)
                    _assert_journal_write(jw, st["journal_write"], f"trace-01/step-{st['step']}", errors)
                exec_checks += 1

    # --- Execute trace-02-guardian-succession-assent.json ---
    if "trace-02-guardian-succession-assent.json" in vectors:
        t2 = vectors["trace-02-guardian-succession-assent.json"]
        v = sv.Tier1Verifier(trusted_origin_issuers=set(t2["trusted_origin_issuers"]), require_jsonschema=require_jsonschema)
        ch = sv.ChainView(t2["chain_state"])
        origin_bundle = {
            "origin": t2["origin"]["object"],
            "origin_anchor_txid": t2["origin_anchor_txid"],
            "name_binding": t2["name_binding"]["object"],
            "name_binding_txid": t2["name_binding_txid"],
            "guardian_records": [
                t2["stage_0_initial_activation"]["guardian_record"]["object"],
                t2["stage_1_appointment"]["guardian_record"]["object"],
            ],
            "guardian_assents": [
                t2["stage_0_initial_activation"]["guardian_assent"]["object"],
                t2["stage_1_appointment"]["guardian_assent"]["object"],
            ],
            "roster_records": [t2["roster_transition"]["roster_record"]["object"]],
            "initial_guardian_disclosures": {"1": t2["initial_guardian_1_disclosure"]},
            "opened_majority_unix": t2["majority_disclosure"]["majority_obj"]["majority_unix"],
            "majority_salt_hex": t2["majority_disclosure"]["salt_hex"],
        }
        contract_obj = t2["contract"]["object"]
        for av in t2["assent_verdicts"]:
            res = v.verify_assent(av["assent"]["object"], contract_obj, origin_bundle, ch)
            if res.verdict != av["expected_verdict"] or res.refusal_code != av.get("expected_refusal"):
                errors.append(f"trace-02 '{av['id']}': expected ({av['expected_verdict']}, {av.get('expected_refusal')}), got ({res.verdict}, {res.refusal_code})")
            elif av["expected_verdict"] == "ADMIT":
                if res.details.get("verified_slots") != av.get("verified_slots") or res.details.get("verified_revision") != av.get("verified_revision") or res.details.get("derived_event_class") != av.get("derived_event_class"):
                    errors.append(f"trace-02 '{av['id']}': details mismatch {res.details}")
            if res.refusal_code:
                covered_refusals.add(res.refusal_code)
            exec_checks += 1

        # Execute co-tenant same-role party_id contract coverage check
        ct = t2["co_tenant_same_role_contract"]
        res_ct = v.verify_contract_assents(
            ct["contract"]["object"],
            [a["object"] for a in ct["assents"]],
            None,
            ch,
        )
        if res_ct.verdict != ct["expected_verdict"] or res_ct.details.get("covered_party_ids") != ct["expected_covered_party_ids"]:
            errors.append(f"trace-02 co_tenant_same_role_contract failed: got {(res_ct.verdict, res_ct.refusal_code, res_ct.details)}")
        exec_checks += 1

        # Execute BOTH positive name_recovery continuation branches!
        nr = t2["name_recovery_positive_traces"]
        b2_obj = nr["candidate_b2"]["object"]
        b3_obj = nr["candidate_b3"]["object"]
        ba = nr["branch_a_timely_0x10_cancel_restores_b1"]
        ob_a = {**origin_bundle, "recovery_bindings": [b2_obj]}
        st_a, err_a = v.verify_origin_and_status(ob_a, sv.ChainView(ba["chain_state"]))
        if err_a is not None or st_a is None or sl.object_id(st_a["binding"]) != ba["expected_active_binding_id"]:
            errors.append(f"trace-02 recovery branch A restore B1 failed: got {(st_a, err_a)}")
        elif st_a["active_recovery_seal"]["txid"] != ba["expected_active_recovery_seal"]["txid"] or st_a["active_recovery_seal"]["vout"] != ba["expected_active_recovery_seal"]["vout"]:
            errors.append(f"trace-02 recovery branch A next_recovery_seal mismatch: {st_a['active_recovery_seal']}")
        _, err_a_b2 = v.verify_origin_and_status(ob_a, sv.ChainView(ba["chain_state"]), assert_binding_id=sl.object_id(b2_obj))
        if err_a_b2 != ba["expected_cancelled_b2_refusal"]:
            errors.append(f"trace-02 recovery branch A cancelled B2 check failed: got {err_a_b2}")
        exec_checks += 2

        bb = nr["branch_b_post_delay_recovery_promotes_b3"]
        ob_b = {**origin_bundle, "recovery_bindings": [b2_obj, b3_obj]}
        st_b, err_b = v.verify_origin_and_status(ob_b, sv.ChainView(bb["chain_state"]))
        if err_b is not None or st_b is None or sl.object_id(st_b["binding"]) != bb["expected_active_binding_id"]:
            errors.append(f"trace-02 recovery branch B promote B3 failed: got {(st_b, err_b)}")
        elif st_b["active_recovery_seal"]["txid"] != bb["expected_active_recovery_seal"]["txid"] or st_b["active_recovery_seal"]["vout"] != bb["expected_active_recovery_seal"]["vout"]:
            errors.append(f"trace-02 recovery branch B next_recovery_seal mismatch: {st_b['active_recovery_seal']}")
        _, err_b_old = v.verify_origin_and_status(ob_b, sv.ChainView(bb["chain_state"]), assert_binding_id=sl.object_id(t2["name_binding"]["object"]))
        if err_b_old != bb["expected_superseded_b1_refusal"]:
            errors.append(f"trace-02 recovery branch B superseded B1 check failed: got {err_b_old}")
        exec_checks += 2

    # --- Execute trace-03-delegation-pool-single-use.json ---
    if "trace-03-delegation-pool-single-use.json" in vectors:
        t3 = vectors["trace-03-delegation-pool-single-use.json"]
        v = sv.Tier1Verifier(require_jsonschema=require_jsonschema)
        ch_a = sv.ChainView(t3["initial_chain_state"])
        jr_a = sv.FencedJournal.from_dict({"journal_id": t3["station_a_journal_id"]})
        exec_a = t3["station_a_config"]
        c1t = t3["child_1_trace"]
        bundle_c1 = {"grants": [t3["parent_grant"]["object"], t3["child_1_single_use"]["object"]]}
        use_txid = c1t["use_txid_wrapper"]
        inv1 = c1t["invocation"]["object"]
        actual_usage = c1t.get("actual_quota_usage")

        # Step A: mempool unconfirmed
        ra = v.verify_invocation(inv1, bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid, actual_quota_usage=actual_usage)
        if ra.verdict != c1t["step_a_mempool_unconfirmed"]["expected_verdict"] or ra.refusal_code != c1t["step_a_mempool_unconfirmed"]["expected_refusal"]:
            errors.append(f"trace-03 step_a failed: got {(ra.verdict, ra.refusal_code)}")
        exec_checks += 1

        ch_a.apply_patch(t3["confirm_use_tx_patch"])

        # Step B: crash-in-effect-window (4 dual-account reservations) + replay_persisted_entries restart!
        jr_crash = sv.FencedJournal.from_dict({"journal_id": t3["station_a_crash_journal_id"]})
        rb1 = v.verify_invocation(inv1, bundle_c1, ch_a, jr_crash, exec_a, use_txid=use_txid, simulate_crash_before_settlement=True, actual_quota_usage=actual_usage)
        jr_restarted = sv.FencedJournal.replay_persisted_entries(t3["station_a_crash_journal_id"], [w["entry"] for w in rb1.journal_writes])
        rb2 = v.verify_invocation(inv1, bundle_c1, ch_a, jr_restarted, exec_a, use_txid=use_txid, actual_quota_usage=actual_usage)
        exp_b = c1t["step_b_crash_in_effect_window"]
        if (
            rb1.verdict != "UNCERTAIN"
            or len(rb1.journal_writes) != len(exp_b["crash_journal_writes"])
            or rb2.verdict != exp_b["expected_verdict_after_restart"]
            or rb2.outcome != exp_b["expected_outcome"]
            or rb2.details.get("unsettled_count") != exp_b["expected_unsettled_count"]
            or rb2.journal_writes
        ):
            errors.append(f"trace-03 step_b crash recovery failed: rb1={(rb1.verdict, len(rb1.journal_writes))} rb2={(rb2.verdict, rb2.outcome, rb2.details)}")
        else:
            for idx, (got_jw, exp_jw) in enumerate(zip(rb1.journal_writes, exp_b["crash_journal_writes"])):
                _assert_journal_write(got_jw, exp_jw, f"trace-03/step_b[{idx}]", errors)
        exec_checks += 2

        # Step C: confirmed execution -> ADMIT + exact 10-entry dual-account multi-quota journal chain + exact settled balances!
        exp_c = c1t["step_c_confirmed_execute"]
        rc = v.verify_invocation(inv1, bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid, receipt_env_for_cache=exp_c["receipt"]["object"], actual_quota_usage=actual_usage)
        if rc.verdict != exp_c["expected_verdict"] or len(rc.journal_writes) != len(exp_c["journal_chain"]) or jr_a.unsettled_reservations:
            errors.append(f"trace-03 step_c failed: got {(rc.verdict, rc.refusal_code, len(rc.journal_writes), len(jr_a.unsettled_reservations))}")
        else:
            for idx, (got_jw, exp_jw) in enumerate(zip(rc.journal_writes, exp_c["journal_chain"])):
                _assert_journal_write(got_jw, exp_jw, f"trace-03/step_c[{idx}]", errors)
            for bal_k, exp_bal in exp_c["expected_settled_balances"].items():
                sc, qk = bal_k.split("|", 1)
                got_bal = jr_a.quotas_used.get((sc, qk, "term"))
                if got_bal != exp_bal:
                    errors.append(f"trace-03 step_c balance {bal_k}: expected {exp_bal}, got {got_bal}")
        exec_checks += 1

        # Step D: unauthenticated forged replay -> WIRE_SIGNATURE
        exp_d = c1t["step_d_unauthenticated_replay_rejected"]
        rd = v.verify_invocation(exp_d["invocation"]["object"], bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid)
        if rd.verdict != exp_d["expected_verdict"] or rd.refusal_code != exp_d["expected_refusal"]:
            errors.append(f"trace-03 step_d forged replay failed: got {(rd.verdict, rd.refusal_code)}")
        exec_checks += 1

        # Step E: authenticated replay same invocation_id -> cached receipt
        exp_e = c1t["step_e_authenticated_replay_same_invocation_id"]
        re_res = v.verify_invocation(inv1, bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid)
        if re_res.verdict != exp_e["expected_verdict"] or re_res.cached_receipt_content_addr != exp_e["cached_receipt_content_addr"] or re_res.journal_writes:
            errors.append(f"trace-03 step_e cached replay failed: got {(re_res.verdict, re_res.cached_receipt_content_addr)}")
        exec_checks += 1

        # Step F: new nonce replay -> INVOKE_REPLAY
        exp_f = c1t["step_f_new_nonce_replay"]
        if "chain_patch" in exp_f:
            ch_a.apply_patch(exp_f["chain_patch"])
        rf = v.verify_invocation(exp_f["invocation"]["object"], bundle_c1, ch_a, jr_a, exec_a, use_txid=use_txid)
        if rf.verdict != exp_f["expected_verdict"] or rf.refusal_code != exp_f["expected_refusal"]:
            errors.append(f"trace-03 step_f new nonce replay failed: got {(rf.verdict, rf.refusal_code)}")
        exec_checks += 1

        # Atomic multi-quota rollback check
        rb_case = t3["atomic_quota_rollback"]
        jr_rb = sv.FencedJournal.from_dict({"journal_id": t3["station_a_rollback_journal_id"]})
        r_rb = v.verify_invocation(
            rb_case["invocation"]["object"],
            {"grants": [t3["parent_grant"]["object"], rb_case["grant"]["object"]]},
            sv.ChainView(t3["initial_chain_state"]),
            jr_rb,
            exec_a,
        )
        if (
            r_rb.verdict != rb_case["expected_verdict"]
            or r_rb.refusal_code != rb_case["expected_refusal"]
            or len(r_rb.journal_writes) != rb_case["expected_journal_writes"]
            or bool(jr_rb.quotas_used)
        ):
            errors.append(f"trace-03 atomic_quota_rollback failed: got {(r_rb.verdict, r_rb.refusal_code, len(r_rb.journal_writes), jr_rb.quotas_used)}")
        exec_checks += 1

        # Child 2 issuer branch-1 revocation -> SEAL_SPENT then GRANT_CLOSED
        c2 = t3["child_2_issuer_revocation"]
        ch_b = sv.ChainView(t3["initial_chain_state"])
        jr_b = sv.FencedJournal.from_dict({"journal_id": t3["station_b_journal_id"]})
        bundle_c2 = {"grants": [t3["parent_grant"]["object"], c2["grant"]["object"]]}
        r2a = v.verify_invocation(c2["first_invocation"]["object"], bundle_c2, ch_b, jr_b, t3["station_b_config"])
        r2b = v.verify_invocation(c2["subsequent_invocation"]["object"], bundle_c2, ch_b, jr_b, t3["station_b_config"])
        if r2a.refusal_code != c2["first_observation_refusal"] or r2b.refusal_code != c2["subsequent_request_refusal"]:
            errors.append(f"trace-03 child_2 revocation failed: got {(r2a.refusal_code, r2b.refusal_code)}")
        else:
            _assert_journal_write(r2a.journal_writes[0], c2["closure_journal_write"], "trace-03/child_2_closure", errors)
        exec_checks += 2

    # --- Execute trace-04-agent-guardian-intake.json ---
    if "trace-04-agent-guardian-intake.json" in vectors:
        t4 = vectors["trace-04-agent-guardian-intake.json"]
        v = sv.Tier1Verifier(trusted_origin_issuers=set(t4["trusted_origin_issuers"]), require_jsonschema=require_jsonschema)
        ch = sv.ChainView(t4["initial_chain_state"])
        jr = sv.FencedJournal.from_dict(t4["initial_journal_state"])
        exec_cfg = t4["executor_config"]
        raw_msg = t4["raw_message_utf8"].encode("utf-8")
        origin_bundle = {
            "origin": t4["origin"]["object"],
            "origin_anchor_txid": t4["origin_anchor_txid"],
            "name_binding": t4["name_binding"]["object"],
            "name_binding_txid": t4["name_binding_txid"],
            "guardian_records": [g["object"] for g in t4["guardian_records"]],
            "guardian_assents": [ga["object"] for ga in t4["guardian_assents"]],
            "roster_records": [],
            "initial_guardian_disclosures": t4["initial_guardian_disclosures"],
        }
        for st in t4["steps"]:
            if "chain_patch" in st:
                ch.apply_patch(st["chain_patch"])
            grant_obj = t4[st["grant_ref"]]["object"]
            bundle = {"grants": [grant_obj], "origin_bundle": origin_bundle}
            rcpt_cache = st["receipt"]["object"] if "receipt" in st else None
            res = v.verify_invocation(st["invocation"]["object"], bundle, ch, jr, exec_cfg, receipt_env_for_cache=rcpt_cache, raw_message_bytes=raw_msg)
            if res.verdict != st["expected_verdict"] or res.refusal_code != st.get("expected_refusal"):
                errors.append(f"trace-04 step {st['step']}: expected ({st['expected_verdict']}, {st.get('expected_refusal')}), got ({res.verdict}, {res.refusal_code})")
            elif st["expected_verdict"] == "ADMIT":
                if res.details.get("derived_event_class") != st.get("derived_event_class") or res.details.get("verified_slots") != st.get("verified_slots") or res.details.get("verified_guardians") != st.get("verified_guardians"):
                    errors.append(f"trace-04 step {st['step']}: verified details mismatch {res.details}")
                if res.journal_writes and "journal_write" in st:
                    _assert_journal_write(res.journal_writes[0], st["journal_write"], f"trace-04/step-{st['step']}", errors)
            exec_checks += 1

    # --- Execute refusal-coverage-matrix.json (MUST cover 100% = 84/84 refusal codes!) ---
    if "refusal-coverage-matrix.json" not in vectors:
        errors.append("Missing vectors/refusal-coverage-matrix.json")
    else:
        mat = vectors["refusal-coverage-matrix.json"]
        for case in mat.get("cases", []):
            got = rm.execute_matrix_case(case, require_jsonschema=require_jsonschema)
            if got != case["expected_refusal"]:
                errors.append(f"refusal-coverage-matrix '{case['code']}': expected {case['expected_refusal']}, verifier computed {got!r}")
            else:
                covered_refusals.add(got)
            exec_checks += 1

    # --- Execute security-conformance.json (all adversarial false-admit & interop cases!) ---
    mutations_killed = 0
    if "security-conformance.json" not in vectors:
        errors.append("Missing vectors/security-conformance.json")
    else:
        ss = vectors["security-conformance.json"]
        for case in ss.get("cases", []):
            got_v, got_c = sec.execute_security_case(case, require_jsonschema=require_jsonschema)
            if (got_v, got_c) != (case["expected_verdict"], case.get("expected_refusal")):
                errors.append(f"security-conformance '{case['id']}': expected {(case['expected_verdict'], case.get('expected_refusal'))}, got {(got_v, got_c)}")
            exec_checks += 1
        if "refusal-coverage-matrix.json" in vectors:
            mutations_killed, mut_errs = sec.run_verifier_mutation_tests(
                ss, vectors["refusal-coverage-matrix.json"], require_jsonschema=require_jsonschema
            )
            errors.extend(mut_errs)

    missing_exec = sorted(registered_codes - covered_refusals)
    if missing_exec:
        errors.append(f"Incomplete executable refusal coverage ({len(covered_refusals)}/{len(registered_codes)}): missing {', '.join(missing_exec)}")

    return exec_checks, len(covered_refusals), mutations_killed


def verify_all_vectors(
    vectors: dict[str, dict[str, Any]],
    registered_codes: set[str],
    require_jsonschema: bool,
    errors: list[str],
) -> tuple[int, int, int, int]:
    checked = 0
    # 1. wire-jcs-and-hashes.json
    if "wire-jcs-and-hashes.json" in vectors:
        v = vectors["wire-jcs-and-hashes.json"]
        for c in v["jcs_positive"]:
            ok, res = sl.jcs_validate(c["input_utf8"].encode("utf-8"))
            if not ok:
                errors.append(f"wire positive JCS '{c['id']}' failed: {res}")
            checked += 1
        for c in v["jcs_negative"]:
            ok, code = sl.jcs_validate(bytes.fromhex(c["input_hex"]))
            if ok or code != c["expected_refusal"]:
                errors.append(f"wire negative JCS '{c['id']}' expected {c['expected_refusal']}, got {(ok, code)}")
            checked += 1
        cc = v["clause_commitment"]
        got_cc = sl.clause_commit(cc["salt_hex"], cc["clause_obj"])
        if got_cc != cc["commitment_hex"]:
            errors.append(f"clause_commitment mismatch: {got_cc} != {cc['commitment_hex']}")
        checked += 1
        th = v["three_hashes_and_signatureset"]
        verify_envelope_record(th["envelope_2of3_subset_ab"], "wire/2of3_ab", errors)
        verify_envelope_record(th["envelope_2of3_subset_ac"], "wire/2of3_ac", errors)
        if th["envelope_2of3_subset_ab"]["object_id"] != th["envelope_2of3_subset_ac"]["object_id"]:
            errors.append("wire/2of3 object_id invariance failed")
        for neg in th["negative_signaturesets"]:
            ok, code = sl.verify_envelope_signatures(neg["object"])
            if ok or code != neg["expected_refusal"]:
                errors.append(f"wire negative sigset '{neg['id']}' expected {neg['expected_refusal']}, got {(ok, code)}")
            checked += 1
        if "device_signature_algorithms" in v:
            dsa = v["device_signature_algorithms"]
            verify_envelope_record(dsa["owner_command_ed25519"], "wire/ed25519", errors)
            verify_envelope_record(dsa["owner_command_p256_low_s"], "wire/p256_low_s", errors)
            checked += 2

    # 2. ledger-scripts-and-opreturn.json
    if "ledger-scripts-and-opreturn.json" in vectors:
        v = vectors["ledger-scripts-and-opreturn.json"]
        for item in v["script_policies"]:
            spk, ws = sl.compile_script_policy(item["policy"])
            if spk.hex() != item["script_pubkey_hex"] or (ws.hex() if ws else "") != item["witness_script_hex"]:
                errors.append(f"ledger script_policy '{item['id']}' mismatch")
            checked += 1
        for item in v["namecoin_prefix_scripts"]["positive"]:
            parsed = sl.parse_name_output(bytes.fromhex(item["script_hex"]))
            if parsed != item["parsed"]:
                errors.append(f"ledger namecoin positive '{item['id']}' parse mismatch")
            checked += 1
        for item in v["namecoin_prefix_scripts"]["negative"]:
            try:
                sl.parse_name_output(bytes.fromhex(item["script_hex"]))
                errors.append(f"ledger namecoin negative '{item['id']}' unexpectedly parsed")
            except ValueError as exc:
                if str(exc) != item["expected_refusal"]:
                    errors.append(f"ledger namecoin negative '{item['id']}' wrong refusal: {exc}")
            checked += 1
        for item in v["opreturn_frames"]:
            dec = sl.decode_opreturn(bytes.fromhex(item["script_hex"]))
            if dec != item["decoded"]:
                errors.append(f"ledger opreturn '{item['id']}' decode mismatch")
            checked += 1
        for item in v["opreturn_negative"]:
            try:
                sl.decode_opreturn(bytes.fromhex(item["script_hex"]))
                errors.append(f"ledger opreturn negative '{item['id']}' unexpectedly decoded")
            except ValueError as exc:
                if str(exc) != item["expected_refusal"]:
                    errors.append(f"ledger opreturn negative '{item['id']}' wrong refusal: {exc}")
            checked += 1
        mb = v["merkle_batch_0x02"]
        root, _ = sl.build_merkle_tree(mb["unsorted_input_digests"])
        if root != mb["merkle_root"]:
            errors.append("ledger merkle_batch_0x02 root mismatch")
        for pf in mb["proofs"]:
            if not sl.verify_merkle_proof(pf):
                errors.append("ledger merkle_batch_0x02 valid proof failed verification")
            checked += 1
        if sl.verify_merkle_proof(mb["negative_tampered_proof"]):
            errors.append("ledger merkle_batch_0x02 tampered proof unexpectedly verified")
        checked += 1

    # 3. constraints-and-schemas.json (including LIVE semantic & SL-ORIG-016 checks!)
    if "constraints-and-schemas.json" in vectors:
        v = vectors["constraints-and-schemas.json"]
        for c in v["predicate_matches"]:
            if sl.match_predicate(c["pred"], c["arg"]) is not c["expected"]:
                errors.append(f"constraint match '{c['id']}' failed")
            checked += 1
        for c in v["predicate_narrowing"]:
            if sl.narrows_predicate(c["child"], c["parent"]) is not c["expected"]:
                errors.append(f"constraint narrowing '{c['id']}' failed")
            checked += 1
        t1v = sv.Tier1Verifier()
        for neg in v.get("negative_semantic_fixtures", []):
            ok_w, code_w = t1v.verify_wire_bytes(sl.jcs_encode(neg["object"]))
            if neg["expected_refusal"] == "GRANT_TEXT_FORBIDDEN":
                # Wire-valid; text ban enforced at Step 11c by mechanical effect executors
                if not ok_w or "terms_text" not in neg["object"]["payload"]:
                    errors.append(f"semantic fixture '{neg['id']}' unexpected wire failure {code_w}")
            else:
                if ok_w or code_w != neg["expected_refusal"]:
                    errors.append(f"semantic fixture '{neg['id']}' expected {neg['expected_refusal']}, got {(ok_w, code_w)}")
            checked += 1
        for gc in v.get("negative_guardian_consistency_fixtures", []):
            ok_gc, code_gc = sl.check_guardian_policy_consistency(gc["guardian_policy"], prev_roster=gc.get("prev_roster"))
            if ok_gc or code_gc != gc["expected_refusal"]:
                errors.append(f"guardian consistency fixture '{gc['id']}' expected {gc['expected_refusal']}, got {(ok_gc, code_gc)}")
            checked += 1

    # 4. Walk all trace files: verify every signed/unsigned record, journal chain, disclosures, and R8.5/R8.6
    def walk_records(node: Any, prefix: str) -> None:
        nonlocal checked
        if isinstance(node, dict):
            if "canonical_jcs" in node and "object" in node:
                if "signing_digest" in node:
                    verify_envelope_record(node, prefix, errors)
                else:
                    verify_unsigned_record(node, prefix, errors)
                checked += 1
            if "c_before" in node and "c_after" in node and "entry" in node:
                got_after = sl.journal_commit_step(node["c_before"], node["entry"]["object"])
                if got_after != node["c_after"]:
                    errors.append(f"Journal hash chain mismatch at {prefix}: {got_after} != {node['c_after']}")
                checked += 1
            if "salt_hex" in node and "commitment_hex" in node:
                target_obj = node.get("name_pin") or node.get("clause") or node.get("majority_obj")
                if target_obj is not None:
                    got_c = sl.clause_commit(node["salt_hex"], target_obj)
                    if got_c != node["commitment_hex"]:
                        errors.append(f"Salted disclosure mismatch at {prefix}")
                    checked += 1
            for k, val in node.items():
                walk_records(val, f"{prefix}.{k}")
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                walk_records(item, f"{prefix}[{idx}]")

    for tname in (
        "trace-01-mail-offline-revoke.json",
        "trace-02-guardian-succession-assent.json",
        "trace-03-delegation-pool-single-use.json",
        "trace-04-agent-guardian-intake.json",
    ):
        if tname in vectors:
            walk_records(vectors[tname], tname)

    if "trace-03-delegation-pool-single-use.json" in vectors:
        t3 = vectors["trace-03-delegation-pool-single-use.json"]
        p_payload = t3["parent_grant"]["object"]["payload"]
        if not sl.check_whole_parent_budget_r85(p_payload["delegate"])[0]:
            errors.append("trace-03 positive R8.5 failed")
        if not sl.check_disjoint_ranges_r86(p_payload):
            errors.append("trace-03 positive R8.6 failed")
        if sl.check_whole_parent_budget_r85(t3["r85_negative_parent"]["object"]["payload"]["delegate"])[0]:
            errors.append("trace-03 negative R8.5 unexpectedly passed")
        if sl.check_disjoint_ranges_r86(t3["r86_negative_parent"]["object"]["payload"]):
            errors.append("trace-03 negative R8.6 unexpectedly passed")
        checked += 4

    # 5. Live executable Reference Verifier Core replay + security conformance + verifier mutations!
    exec_checks, covered_cnt, mutations_killed = execute_traces_and_matrix(
        vectors, registered_codes, require_jsonschema, errors
    )
    return checked, exec_checks, covered_cnt, mutations_killed


def _collect_typed_objects(node: Any, reg_types: dict[str, dict[str, Any]], out: list[tuple[str, dict[str, Any], str]], path: str) -> None:
    """Recursively collect every recognizable SealLink typed object inside semantic matrix/security inputs."""
    if isinstance(node, dict):
        obj_type = node["payload"].get("type") if isinstance(node.get("payload"), dict) else node.get("type")
        if isinstance(obj_type, str) and obj_type in reg_types:
            out.append((reg_types[obj_type]["schema"], node, f"{path}({obj_type})"))
            # Also validate invocation profile arguments!
            if obj_type == "seallink-invocation/1":
                act = node["payload"].get("action")
                aprof = sv.ACTION_PROFILES.get(act)
                if aprof and "args_schema" in aprof:
                    out.append((aprof["args_schema"], node["payload"]["arguments"], f"{path}.arguments({act})"))
            return  # Don't recurse inside a validated object's payload
        for k, v in node.items():
            _collect_typed_objects(v, reg_types, out, f"{path}.{k}")
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            _collect_typed_objects(item, reg_types, out, f"{path}[{idx}]")


def verify_jsonschema(
    schemas: dict[str, dict[str, Any]],
    vectors: dict[str, dict[str, Any]],
    require: bool,
    errors: list[str],
    warnings: list[str],
) -> tuple[bool, int]:
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError:
        msg = "Python package 'jsonschema' not installed; Draft 2020-12 metaschema/instance checks skipped."
        if require:
            errors.append(msg)
        else:
            warnings.append(msg)
        return False, 0

    resources = []
    id_by_name: dict[str, str] = {}
    for sname, sdoc in schemas.items():
        try:
            Draft202012Validator.check_schema(sdoc)
        except Exception as exc:
            errors.append(f"Metaschema failure in schemas/{sname}: {exc}")
        uri = sdoc.get("$id", f"https://seallink.org/schemas/{sname}")
        id_by_name[sname] = uri
        resources.append((uri, Resource.from_contents(sdoc, default_specification=DRAFT202012)))
    registry = Registry().with_resources(resources)

    def get_validator(schema_ref: str) -> Draft202012Validator:
        if "#" in schema_ref:
            spath, ptr = schema_ref.split("#", 1)
            base_uri = id_by_name[Path(spath).name]
            sub = {"$ref": f"{base_uri}#{ptr}"}
        else:
            base_uri = id_by_name[Path(schema_ref).name]
            sub = {"$ref": base_uri}
        return Draft202012Validator(sub, registry=registry)

    validated = 0
    reg_types = sv.registered_types()
    for vname, vdoc in vectors.items():
        pos_instances: list[tuple[str, dict[str, Any], str]] = []
        collect_schema_instances(vdoc, pos_instances)
        for sref, inst, hint in pos_instances:
            val = get_validator(sref)
            errs = list(val.iter_errors(inst))
            if errs:
                errors.append(f"Schema validation failed for {vname} ({hint} against {sref}): {errs[0].message}")
            validated += 1
        for neg in vdoc.get("negative_schema_fixtures", []):
            val = get_validator(neg["schema"])
            errs = list(val.iter_errors(neg["object"]))
            if not errs:
                errors.append(f"Negative schema fixture '{neg['id']}' in {vname} unexpectedly PASSED {neg['schema']}")
            validated += 1
        # Validate EVERY recognizable typed object inside non-WIRE_* refusal-coverage-matrix cases!
        if vname == "refusal-coverage-matrix.json":
            for case in vdoc.get("cases", []):
                if case["code"].startswith("WIRE_"):
                    continue
                typed_objs: list[tuple[str, dict[str, Any], str]] = []
                _collect_typed_objects(case["inputs"], reg_types, typed_objs, f"matrix[{case['code']}]")
                for sref, inst, hint in typed_objs:
                    val = get_validator(sref)
                    errs = list(val.iter_errors(inst))
                    if errs:
                        errors.append(f"Semantic refusal case {hint} FAILED Draft 2020-12 schema {sref}: {errs[0].message}")
                    validated += 1
        # Validate EVERY recognizable typed object inside non-wire-syntax security-conformance cases!
        if vname == "security-conformance.json":
            for case in vdoc.get("cases", []):
                exp_r = case.get("expected_refusal") or ""
                if exp_r.startswith("WIRE_") and exp_r not in ("WIRE_SIGNATURE", "WIRE_KEY"):
                    continue
                typed_objs = []
                _collect_typed_objects(case["inputs"], reg_types, typed_objs, f"security[{case['id']}]")
                for sref, inst, hint in typed_objs:
                    val = get_validator(sref)
                    errs = list(val.iter_errors(inst))
                    if errs:
                        errors.append(f"Security conformance case {hint} FAILED Draft 2020-12 schema {sref}: {errs[0].message}")
                    validated += 1
    return True, validated


def main() -> int:
    parser = argparse.ArgumentParser(description="SealLink specification consistency, schema, and executable verifier linter.")
    parser.add_argument("--require-jsonschema", action="store_true", help="Fail if 'jsonschema' package is unavailable.")
    args = parser.parse_args()

    errors: list[str] = []
    warnings: list[str] = []

    # 0. Reference crypto self-test
    sl.self_test()

    # 1. Load registries
    registries: dict[str, Any] = {}
    for p in sorted((ROOT / "registry").glob("*.json")):
        data = load_json(p, errors)
        if data is not None:
            registries[p.name] = data

    # Build NON_REFUSAL_IDENTIFIERS dynamically from opreturn-actions.json
    non_refusal_ids = set(BASE_NON_REFUSAL_IDENTIFIERS)
    if "opreturn-actions.json" in registries:
        for act in registries["opreturn-actions.json"].get("actions", []):
            non_refusal_ids.add(act["name"])

    # 2. Load schemas & validate all $refs
    schemas: dict[str, dict[str, Any]] = {}
    for p in sorted((ROOT / "schemas").glob("*.schema.json")):
        data = load_json(p, errors)
        if data is not None:
            schemas[p.name] = data

    for name, schema in schemas.items():
        refs: list[str] = []
        walk_refs(schema, refs)
        for ref in refs:
            if "#" in ref:
                file_part, ptr = ref.split("#", 1)
                ptr = "#" + ptr
            else:
                file_part, ptr = ref, "#"
            target_name = file_part if file_part else name
            if target_name not in schemas:
                errors.append(f"Unresolved schema $ref '{ref}' in schemas/{name}")
                continue
            if not resolve_pointer(schemas[target_name], ptr):
                errors.append(f"Unresolved JSON pointer '{ref}' in schemas/{name}")

    # 3. Validate object-types.json schema links & cross-registry coherence
    registered_types: set[str] = set()
    if "object-types.json" in registries:
        for entry in registries["object-types.json"].get("types", []):
            t = entry["type"]
            if t in registered_types:
                errors.append(f"Duplicate object type in registry/object-types.json: {t}")
            registered_types.add(t)
            sref = entry.get("schema", "")
            if "#" in sref:
                spath, ptr = sref.split("#", 1)
                ptr = "#" + ptr
            else:
                spath, ptr = sref, "#"
            sname = Path(spath).name
            if sname not in schemas or not resolve_pointer(schemas[sname], ptr):
                errors.append(f"object-types.json type '{t}' points to missing schema '{sref}'")
            else:
                target_node = resolve_node(schemas[sname], ptr)
                consts = find_type_consts(target_node, schemas[sname])
                if consts != {t}:
                    errors.append(f"object-types.json type '{t}' schema '{sref}' has mismatched type consts: {sorted(consts)}")

    check_cross_registry_coherence(registries, errors)

    # 4. Load registered refusal codes
    registered_codes: set[str] = set()
    if "refusal-codes.json" in registries:
        for entry in registries["refusal-codes.json"].get("codes", []):
            c = entry["code"]
            if c in registered_codes:
                errors.append(f"Duplicate refusal code in registry/refusal-codes.json: {c}")
            registered_codes.add(c)

    # 5. Scan normative spec/ and profiles/ markdown files
    rule_locations: dict[str, str] = {}
    referenced_rules: list[tuple[str, str]] = []
    used_codes: set[str] = set()
    used_types: set[str] = set()

    normative_files = sorted((ROOT / "spec").glob("SPEC-*.md")) + sorted(
        (ROOT / "profiles").glob("PROFILE-*.md")
    )

    for path in normative_files:
        rel = str(path.relative_to(ROOT))
        text = path.read_text(encoding="utf-8")

        if path.name.startswith("SPEC-"):
            for req in ("**Status:**", "**Evidence / Maturity:**", "## "):
                if req not in text:
                    errors.append(f"{rel}: missing required section/header '{req}'")
            if "Security Considerations" not in text and "Threat Model" not in text:
                errors.append(f"{rel}: missing Security Considerations / Threat Model section")
            if "References" not in text:
                errors.append(f"{rel}: missing References section")

        for line_no, line in enumerate(text.splitlines(), 1):
            table_match = re.match(r"^\|\s*`(SL-[A-Z]+-\d{3})`\s*\|", line)
            declared: list[str] = [table_match.group(1)] if table_match else []
            for paren_group in re.findall(r"\(([^()\n]+?)\)", line):
                if re.search(r",\s*`(?:decided|open)`", paren_group):
                    for rid in RULE_ID_RE.findall(paren_group):
                        if rid not in declared:
                            declared.append(rid)

            for rid in declared:
                if rid in rule_locations:
                    errors.append(f"Duplicate Rule ID declaration {rid}: {rule_locations[rid]} and {rel}:{line_no}")
                else:
                    rule_locations[rid] = f"{rel}:{line_no}"

            for rid in RULE_ID_RE.findall(line):
                referenced_rules.append((rid, f"{rel}:{line_no}"))

        for t in TYPE_RE.findall(text):
            if t in DOMAIN_ONLY_TAGS:
                continue
            used_types.add(t)
            if t not in registered_types:
                errors.append(f"{rel}: unregistered object type '{t}'")

        for c in CODE_RE.findall(text):
            if c.endswith("_") or c in non_refusal_ids:
                continue
            used_codes.add(c)
            if c not in registered_codes:
                errors.append(f"{rel}: unregistered refusal code '{c}'")

    for rid, loc in referenced_rules:
        if rid not in rule_locations:
            errors.append(f"Undeclared Rule ID referenced: {rid} at {loc}")

    # 5b. Check archive/rule-inventory.md Section 1 indexes 100% of declared SL-* rule IDs AND cites only registered refusal codes
    inv_path = ROOT / "archive" / "rule-inventory.md"
    if inv_path.exists():
        inv_text = inv_path.read_text(encoding="utf-8")
        inv_indexed: set[str] = set()
        for line in inv_text.splitlines():
            m = re.match(r"^\|\s*`(SL-[A-Z]+-\d{3})`\s*\|", line)
            if m:
                inv_indexed.add(m.group(1))
        missing_inv = sorted(set(rule_locations.keys()) - inv_indexed)
        extra_inv = sorted(inv_indexed - set(rule_locations.keys()))
        if missing_inv:
            errors.append(f"archive/rule-inventory.md missing per-rule rows for {len(missing_inv)} rule(s): {', '.join(missing_inv)}")
        if extra_inv:
            errors.append(f"archive/rule-inventory.md lists undeclared rule(s): {', '.join(extra_inv)}")
        for c in CODE_RE.findall(inv_text):
            if c.endswith("_") or c in non_refusal_ids:
                continue
            if c not in registered_codes:
                errors.append(f"archive/rule-inventory.md: unregistered refusal code '{c}'")

    # 6. Check all registry files share the same protocol version string
    reg_versions = {name: data.get("version") for name, data in registries.items() if "version" in data}
    if len(set(reg_versions.values())) > 1:
        errors.append(f"Inconsistent version strings across registry/*.json: {reg_versions}")

    # 7. Load, cryptographically verify, and LIVE-EXECUTE all vectors/
    vectors: dict[str, dict[str, Any]] = {}
    for p in sorted((ROOT / "vectors").glob("*.json")):
        data = load_json(p, errors)
        if data is not None:
            vectors[p.name] = data
    if not vectors:
        errors.append("No conformance vector files found under vectors/")
    vector_checks, exec_checks, covered_cnt, mutations_killed = verify_all_vectors(
        vectors, registered_codes, args.require_jsonschema, errors
    )

    # 8. Draft 2020-12 metaschema & instance validation (including all semantic matrix/security fixtures!)
    js_ok, schema_checks = verify_jsonschema(schemas, vectors, args.require_jsonschema, errors, warnings)

    unused_codes = sorted(registered_codes - used_codes)
    if unused_codes:
        warnings.append(f"Registered refusal codes not cited in SPEC/PROFILE prose ({len(unused_codes)}): {', '.join(unused_codes)}")
    unused_types = sorted(registered_types - used_types)
    if unused_types:
        warnings.append(f"Registered object types not cited in SPEC/PROFILE prose ({len(unused_types)}): {', '.join(unused_types)}")

    print(
        f"SealLink speclint: {len(normative_files)} normative docs | "
        f"{len(rule_locations)} unique rule IDs | "
        f"{len(registered_types)} object types | "
        f"{len(registered_codes)} refusal codes ({covered_cnt}/{len(registered_codes)} executed) | "
        f"{len(schemas)} schemas | "
        f"{len(vectors)} vector suites ({vector_checks} crypto/logic checks, {exec_checks} live verifier checks, "
        f"{mutations_killed}/10 verifier mutations killed"
        + (f", {schema_checks} Draft 2020-12 schema checks)" if js_ok else ")")
    )
    for w in warnings:
        print(f"WARN:  {w}")
    for e in errors:
        print(f"ERROR: {e}")

    if errors:
        print(f"FAILED with {len(errors)} error(s).")
        return 1
    print("PASS: 0 errors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
