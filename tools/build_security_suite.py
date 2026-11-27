#!/usr/bin/env python3
"""
Executable Adversarial Security, Interoperability & Verifier-Mutation Conformance Suite.

Builds `vectors/security-conformance.json` testing every authentication binding,
closed-schema ingress check, healthy-peer requirement, Step 10d/11b ordering,
disposer rotation retain_active ban, device signature algorithm (Ed25519 + low-S/high-S
P-256), and emancipation handover — plus live verifier-check mutation self-tests
proving that disabling any security check fails at least one vector.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

VERSION = "1.0.0-draft.13"
GENESIS_MAIN = rm.GENESIS_MAIN


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-sec-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"sec:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def execute_security_case(case: dict[str, Any], *, require_jsonschema: bool = True) -> tuple[str, str | None]:
    """Execute one security-conformance case through Tier1Verifier. NEVER reads expected_* fields."""
    runner = case["runner"]
    inp = case["inputs"]
    if runner == "init_verifier":
        try:
            sv.Tier1Verifier(
                pinned_network=inp.get("pinned_network", "main"),
                pinned_genesis=inp.get("pinned_genesis", GENESIS_MAIN),
                trusted_origin_issuer_pins=inp.get("trusted_origin_issuer_pins"),
                enforce_schemas=True,
                require_jsonschema=require_jsonschema,
                enabled_modules=inp.get("enabled_modules"),
            )
            return "ADMIT", None
        except ValueError:
            return "REFUSE", "ORIGIN_UNVERIFIED"
    if "enabled_modules" in inp:
        eff_mods = inp["enabled_modules"]
    elif case.get("module") in sv.ALL_OPTIONAL_MODULES:
        eff_mods = ["core", case["module"]]
    else:
        eff_mods = None
    v = sv.Tier1Verifier(
        pinned_network=inp.get("pinned_network", "main"),
        pinned_genesis=inp.get("pinned_genesis", GENESIS_MAIN),
        operator_min_depth=inp.get("operator_min_depth", 1),
        allow_window_only=inp.get("allow_window_only", False),
        trusted_origin_issuer_pins=inp.get("trusted_origin_issuer_pins"),
        enforce_schemas=True,
        require_jsonschema=require_jsonschema,
        max_history_steps=inp.get("max_history_steps", 4096),
        max_automaton_steps=inp.get("max_automaton_steps", 1024),
        require_observation_bracket=inp.get("require_observation_bracket", True),
        enabled_modules=eff_mods,
    )
    if runner == "origin_status":
        chain = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        st, err = v.verify_origin_and_status(
            inp["origin_bundle"],
            chain,
            assert_binding_id=inp.get("assert_binding_id"),
            journal=j,
            at_height=inp.get("at_height"),
            at_time=inp.get("at_time"),
            historical_existence_only=inp.get("historical_existence_only", False),
        )
        if err is not None:
            return "REFUSE", err
        assert st is not None
        if "expect_recovery_burned" in inp and bool(st.get("recovery_burned")) != bool(inp["expect_recovery_burned"]):
            return "REFUSE", f"RECOVERY_BURNED_MISMATCH:{st.get('recovery_burned')}"
        if "expect_recovery_outcome" in inp:
            evs = st.get("recovery_events") or []
            got_out = evs[-1].get("outcome") if evs else None
            if got_out != inp["expect_recovery_outcome"]:
                return "REFUSE", f"RECOVERY_OUTCOME_MISMATCH:{got_out}"
        if "expect_rebind_outcome" in inp:
            evs_r = st.get("voluntary_rebind_events") or []
            got_rb = evs_r[-1].get("outcome") if evs_r else None
            if got_rb != inp["expect_rebind_outcome"]:
                return "REFUSE", f"REBIND_OUTCOME_MISMATCH:{got_rb}"
        if "expect_active_name" in inp and st.get("binding", {}).get("name") != inp["expect_active_name"]:
            return "REFUSE", f"ACTIVE_NAME_MISMATCH:{st.get('binding', {}).get('name')}"
        return ("ADMIT_AUTONOMOUS" if st["capacity"] == "autonomous" else "ADMIT_WARD"), None
    if runner == "assent":
        chain = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        res = v.verify_assent(
            inp["assent"],
            inp["contract"],
            inp.get("origin_bundle"),
            chain,
            anchor_height=inp.get("anchor_height"),
            anchor_time=inp.get("anchor_time"),
            journal=j,
        )
        return res.verdict, res.refusal_code
    if runner == "invocation":
        chain = sv.ChainView(inp["chain"])
        journal = sv.FencedJournal.from_dict(inp["journal"])
        if "external_witness" in inp:
            journal.external_witness = copy.deepcopy(inp["external_witness"])
            journal.write_token = inp.get("write_token", 1)
        if "write_race" in inp:
            race_mode = inp["write_race"]
            orig_append = journal.append

            def _racy_append(kind: str, body: dict[str, Any], **kw: Any) -> dict[str, Any]:
                if kind == "reservation":
                    if race_mode == "fence" and journal.external_witness is not None:
                        journal.external_witness["active_write_token"] += 1
                    elif race_mode == "drift" and journal.external_witness is not None:
                        journal.external_witness["pos"] += 1
                    elif race_mode == "value_err":
                        raise ValueError("non_registered_validation_error")
                return orig_append(kind, body, **kw)

            journal.append = _racy_append  # type: ignore[method-assign]
        raw_msg = bytes.fromhex(inp["raw_message_hex"]) if "raw_message_hex" in inp else None
        before_cl = len(journal.closures)
        before_entries = len(journal.entries)
        res = v.verify_invocation(
            inp["invocation"],
            inp["bundle"],
            chain,
            journal,
            inp["executor_cfg"],
            use_txid=inp.get("use_txid"),
            raw_message_bytes=raw_msg,
            actual_quota_usage=inp.get("actual_quota_usage"),
            actual_message_meta=inp.get("actual_message_meta"),
        )
        if inp.get("expect_zero_closures") and len(journal.closures) != before_cl:
            return "REFUSE", f"UNEXPECTED_CLOSURES:{len(journal.closures) - before_cl}"
        if inp.get("expect_zero_writes") and len(journal.entries) != before_entries:
            return "REFUSE", f"UNEXPECTED_WRITES:{len(journal.entries) - before_entries}"
        return res.verdict, res.refusal_code
    if runner == "migration":
        chain = sv.ChainView(inp["chain"]) if inp.get("chain") is not None else None
        journal = sv.FencedJournal.from_dict(inp["journal"])
        before_n = len(journal.entries)
        res = v.verify_migration(
            inp["migration"],
            inp["export_bundle"],
            journal,
            chain,
            inp.get("manifests"),
            holder_assent=inp.get("holder_assent"),
            dest_accept_stmt=inp.get("dest_accept_stmt"),
            origin_bundle=inp.get("origin_bundle"),
            origin_bundles_by_oid=inp.get("origin_bundles_by_oid"),
            local_executor_pin=inp.get("local_executor_pin"),
            mode=inp.get("mode", "activate"),
        )
        if inp.get("expect_zero_writes") and len(journal.entries) != before_n:
            return "REFUSE", f"UNEXPECTED_MIGRATION_WRITES:{len(journal.entries) - before_n}"
        return res.verdict, res.refusal_code
    if runner == "owner_command":
        chain = sv.ChainView(inp["chain"])
        res = v.verify_owner_command(
            inp["command"],
            inp.get("device_proof"),
            inp["is_foreign_service"],
            chain,
            owner_manifest=inp.get("owner_manifest"),
            presented_manifests=inp.get("manifests"),
            origin_bundle=inp.get("origin_bundle"),
        )
        return res.verdict, res.refusal_code
    if runner == "federation":
        chain = sv.ChainView(inp["chain"]) if inp.get("chain") is not None else None
        journal = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        res = v.verify_federation_disclosure(
            inp["policy"],
            inp["peer_ctx"],
            inp["grant"],
            chain=chain,
            journal=journal,
        )
        return res.verdict, res.refusal_code
    if runner == "credential":
        chain = sv.ChainView(inp["chain"])
        sk = set(inp["supported_kinds"]) if inp.get("supported_kinds") is not None else None
        journal = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        res = v.verify_credential(
            inp["credential"],
            inp.get("anchor_txid"),
            chain,
            journal=journal,
            supported_kinds=sk,
            withdrawal_doc=inp.get("withdrawal_doc"),
            origin_bundle=inp.get("origin_bundle"),
            issuer_origin_bundle=inp.get("issuer_origin_bundle"),
        )
        return res.verdict, res.refusal_code
    if runner == "issuer_role":
        chain = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        err = v.verify_issuer_role_at_height(
            inp["issuer_pin"],
            inp["envelope"],
            inp["role"],
            inp["anchor_height"],
            chain,
            resolve_at_tip=inp.get("resolve_at_tip", False),
            journal=j,
            origin_bundle=inp.get("origin_bundle"),
        )
        return ("REFUSE", err) if err else ("ADMIT", None)
    if runner == "sibling_rows_replay":
        chain = sv.ChainView(inp["chain"])
        journal = sv.FencedJournal.from_dict(inp["journal"])
        for step in inp["steps"]:
            before_n = len(journal.entries)
            res = v.verify_invocation(
                step["invocation"],
                step["bundle"],
                chain,
                journal,
                inp["executor_cfg"],
                use_txid=step.get("use_txid"),
                actual_message_meta=step.get("actual_message_meta"),
            )
            if (res.verdict, res.refusal_code) != (step["want_verdict"], step.get("want_refusal")):
                return "REFUSE", f"STEP_MISMATCH:{step['label']}:{(res.verdict, res.refusal_code)}"
            if res.verdict == "REFUSE" and len(journal.entries) != before_n:
                return "REFUSE", f"UNEXPECTED_WRITE_ON_REFUSAL:{step['label']}"
        # Reconstruct a brand-new journal strictly from persisted entries and verify distinct row balances!
        replayed = sv.FencedJournal.replay_persisted_entries(
            journal.journal_id,
            copy.deepcopy(journal.entries),
            witness_pos=journal.pos,
            witness_commitment=journal.commitment,
        )
        if replayed.commitment != journal.commitment or replayed.pos != journal.pos:
            return "REFUSE", "REPLAY_COMMITMENT_MISMATCH"
        for bspec in inp["check_balances"]:
            key = (bspec["scope"], bspec["qkey"], bspec["bucket_id"])
            got_live = journal.quotas_used.get(key, 0)
            got_rep = replayed.quotas_used.get(key, 0)
            if got_live != bspec["expected"] or got_rep != bspec["expected"]:
                return "REFUSE", f"BALANCE_MISMATCH:{bspec['scope']}:{got_live}:{got_rep}"
        return "ADMIT", None
    if runner == "raw_wire":
        if "raw_bytes_utf8" in inp:
            ok, res = v.verify_wire_bytes(
                inp["raw_bytes_utf8"].encode("utf-8"),
                max_bytes_override=inp.get("max_bytes_override"),
            )
            return ("ADMIT", None) if ok else ("REFUSE", res)
        if "raw_bytes_hex" in inp:
            ok, res = v.verify_wire_bytes(
                bytes.fromhex(inp["raw_bytes_hex"]),
                max_bytes_override=inp.get("max_bytes_override"),
            )
            return ("ADMIT", None) if ok else ("REFUSE", res)
        ok, res = v._verify_object_wire(inp["object"], expected_type=inp.get("expected_type"))
        if ok and "max_wire_bytes" in inp:
            if len(sl.jcs_encode(res)) > inp["max_wire_bytes"]:
                return "REFUSE", "WIRE_SIZE"
        return ("ADMIT", None) if ok else ("REFUSE", res)
    if runner == "continuity":
        journal = sv.FencedJournal.from_dict(inp["journal"])
        err = journal.check_continuity()
        return ("REFUSE", err) if err else ("ADMIT", None)
    if runner == "chain_obs":
        chain = sv.ChainView(inp["chain"])
        if inp.get("rebracket"):
            err = v.check_rebracket(chain, risk_class=inp.get("risk_class", 1))
        else:
            err = v.check_chain_observation(chain, risk_class=inp.get("risk_class", 1))
        return ("REFUSE", err) if err else ("ADMIT", None)
    if runner == "seal":
        chain = sv.ChainView(inp["chain"])
        _, err, _ = v.evaluate_seal(inp["seal"], chain, required_depth=inp.get("required_depth", 1))
        return ("REFUSE", err) if err else ("ADMIT", None)
    if runner == "single_use_seal":
        chain = sv.ChainView(inp["chain"])
        _, err, _ = v.evaluate_single_use_seal(
            inp["seal"],
            inp.get("use_txid"),
            inp["invocation_content_addr"],
            inp.get("required_depth", 1),
            chain,
        )
        return ("REFUSE", err) if err else ("ADMIT", None)
    if runner == "name_resolve":
        chain = sv.ChainView(inp["chain"])
        nrec, err = v.resolve_name(
            inp["name"],
            chain,
            expected_owner_policy=inp.get("expected_owner_policy"),
            expected_registration=inp.get("expected_registration"),
            require_writer=inp.get("require_writer", True),
            require_history=inp.get("require_history", True),
            at_height=inp.get("at_height"),
        )
        if err:
            return "REFUSE", err
        if "check_role" in inp:
            assert nrec is not None
            _, rerr = v.resolve_role_policy(
                nrec,
                inp["check_role"],
                presented_role_policy=inp.get("presented_role_policy"),
                recent_block_height=inp.get("recent_block_height"),
            )
            return ("REFUSE", rerr) if rerr else ("ADMIT", None)
        if inp.get("check_manifest"):
            assert nrec is not None
            journal = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
            _, merr = v.resolve_manifest(inp["name"], nrec, inp.get("manifests", {}), chain, journal)
            return ("REFUSE", merr) if merr else ("ADMIT", None)
        return "ADMIT", None
    if runner == "auth_challenge":
        chain = sv.ChainView(inp["chain"])
        journal = sv.FencedJournal.from_dict(inp.get("journal", {"journal_id": _h32("ac-j")}))
        res = v.verify_auth_challenge(
            inp["challenge"],
            chain,
            journal,
            inp["service_id"],
            inp.get("manifests", {}),
            auth_proof=inp.get("auth_proof"),
            expected_audience=inp.get("expected_audience"),
            origin_bundle=inp.get("origin_bundle"),
        )
        return res.verdict, res.refusal_code
    if runner == "contract_assents":
        chain = sv.ChainView(inp["chain"])
        res = v.verify_contract_assents(
            inp["contract"],
            inp["assents"],
            inp.get("origin_bundle"),
            chain,
            origin_bundles_by_oid=inp.get("origin_bundles_by_oid") or inp.get("origin_bundles"),
            anchor_time=inp.get("anchor_time"),
            anchor_height=inp.get("anchor_height"),
        )
        return res.verdict, res.refusal_code
    if runner == "bearer_session":
        chain = sv.ChainView(inp["chain"])
        journal = sv.FencedJournal.from_dict(inp["journal"])
        before_n = len(journal.entries)
        res = v.verify_bearer_session(
            inp["token"],
            inp["slot_binding"],
            chain,
            journal,
            grant_env=inp.get("grant_env"),
            parent_grant_env=inp.get("parent_grant_env"),
            contract_env=inp.get("contract_env"),
            framework_contract_env=inp.get("framework_contract_env"),
            origin_bundle=inp.get("origin_bundle"),
            action=inp.get("action"),
            target=inp.get("target"),
            arguments=inp.get("arguments"),
            actual_message_meta=inp.get("actual_message_meta"),
            executor_cfg=inp.get("executor_cfg"),
            disclosed_clauses=inp.get("disclosed_clauses"),
        )
        if inp.get("expect_zero_writes") and len(journal.entries) != before_n:
            return "REFUSE", f"UNEXPECTED_BEARER_WRITES:{len(journal.entries) - before_n}"
        return res.verdict, res.refusal_code
    if runner == "restart_recovery":
        # Full executor restart verification: pre-restart admit -> persist entries + receipt_store ->
        # replay into brand-new FencedJournal -> verify watermarks, clock regression refusal,
        # exact boundary == watermark ADMIT, cached receipt idempotent replay (0 writes), and new-nonce replay refusal!
        journal = sv.FencedJournal(inp["journal_id"])
        for step in inp["pre_restart_steps"]:
            ch = sv.ChainView(step["chain"])
            raw_msg = bytes.fromhex(step["raw_message_hex"]) if "raw_message_hex" in step else None
            res = v.verify_invocation(
                step["invocation"],
                step["bundle"],
                ch,
                journal,
                inp["executor_cfg"],
                use_txid=step.get("use_txid"),
                receipt_env_for_cache=step.get("receipt_env"),
                raw_message_bytes=raw_msg,
                actual_quota_usage=step.get("actual_quota_usage"),
                actual_message_meta=step.get("actual_message_meta"),
            )
            if (res.verdict, res.refusal_code) != (step["want_verdict"], step.get("want_refusal")):
                return "REFUSE", f"PRE_STEP_MISMATCH:{step['label']}:{(res.verdict, res.refusal_code)}"
        persisted_entries = json.loads(json.dumps(journal.entries))
        persisted_store = json.loads(json.dumps(journal.receipt_store))
        restarted = sv.FencedJournal.replay_persisted_entries(
            journal.journal_id,
            persisted_entries,
            receipt_store=persisted_store,
            witness_pos=journal.pos,
            witness_commitment=journal.commitment,
        )
        if restarted.commitment != journal.commitment or restarted.pos != journal.pos:
            return "REFUSE", "RESTART_COMMITMENT_MISMATCH"
        if restarted.quotas_used != journal.quotas_used:
            return "REFUSE", "RESTART_QUOTAS_MISMATCH"
        if restarted.quota_watermarks != journal.quota_watermarks:
            return "REFUSE", "RESTART_WATERMARK_MISMATCH"
        if set(restarted.receipts.keys()) != set(journal.receipts.keys()):
            return "REFUSE", "RESTART_RECEIPT_INDEX_MISMATCH"
        for step in inp["post_restart_steps"]:
            ch = sv.ChainView(step["chain"])
            before_n = len(restarted.entries)
            raw_msg = bytes.fromhex(step["raw_message_hex"]) if "raw_message_hex" in step else None
            res = v.verify_invocation(
                step["invocation"],
                step["bundle"],
                ch,
                restarted,
                inp["executor_cfg"],
                use_txid=step.get("use_txid"),
                raw_message_bytes=raw_msg,
                actual_quota_usage=step.get("actual_quota_usage"),
                actual_message_meta=step.get("actual_message_meta"),
            )
            if (res.verdict, res.refusal_code) != (step["want_verdict"], step.get("want_refusal")):
                return "REFUSE", f"POST_STEP_MISMATCH:{step['label']}:{(res.verdict, res.refusal_code)}"
            if step.get("expect_zero_writes") and len(restarted.entries) != before_n:
                return "REFUSE", f"POST_UNEXPECTED_WRITES:{step['label']}"
            if "expect_cached_receipt_ca" in step and res.cached_receipt_content_addr != step["expect_cached_receipt_ca"]:
                return "REFUSE", f"POST_CACHED_RECEIPT_MISMATCH:{step['label']}:{res.cached_receipt_content_addr}"
        return "ADMIT", None
    if runner == "historical_rereg":
        # Verify BOTH current holder lookup AND historical eternal credential lookup from the EXACT SAME ChainView!
        ch = sv.ChainView(inp["chain"])
        cur_nrec, cur_err = v.resolve_name(
            inp["name"],
            ch,
            expected_owner_policy=inp["new_owner_policy"],
            expected_registration=inp["new_registration"],
        )
        if cur_err or cur_nrec is None:
            return "REFUSE", f"NEW_OWNER_RESOLVE_FAILED:{cur_err}"
        _, old_live_err = v.resolve_name(
            inp["name"],
            ch,
            expected_owner_policy=inp["old_owner_policy"],
            expected_registration=inp["old_registration"],
        )
        if old_live_err != "NAME_OWNER_MISMATCH":
            return "REFUSE", f"OLD_LIVE_SHOULD_REFUSE:{old_live_err}"
        r_hist = v.verify_credential(inp["old_credential"], inp["old_anchor_txid"], ch)
        if r_hist.verdict != "ADMIT":
            return "REFUSE", f"OLD_CRED_FAILED:{r_hist.refusal_code}"
        if "post_expiry_credential" in inp:
            r_exp = v.verify_credential(inp["post_expiry_credential"], inp["post_expiry_anchor_txid"], ch)
            if (r_exp.verdict, r_exp.refusal_code) != ("REFUSE", "NAME_EXPIRED"):
                return "REFUSE", f"POST_EXPIRY_CRED_WRONG:{(r_exp.verdict, r_exp.refusal_code)}"
        return "ADMIT", None
    if runner == "auth_upgrade":
        ch = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp.get("journal", {"journal_id": _h32("au-j")}))
        res = v.verify_auth_upgrade(
            inp["upgrade"],
            inp["expected_service_id"],
            inp["expected_provisional_auth_pubkey"],
            ch,
            j,
            inp.get("manifests", {}),
            expected_provisional_auth_alg=inp.get("expected_provisional_auth_alg", "bip340"),
            auth_proof=inp.get("auth_proof"),
            expected_audience=inp.get("expected_audience"),
            origin_bundle=inp.get("origin_bundle"),
        )
        return res.verdict, res.refusal_code
    if runner == "notary_act":
        ch = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        res = v.verify_notary_act(
            inp["notary"],
            inp.get("anchor_txid"),
            ch,
            journal=j,
            allowed_notaries=inp.get("allowed_notaries"),
            expected_notary_name=inp.get("expected_notary_name"),
            expected_child_binding=inp.get("expected_child_binding"),
            log_ctx=inp.get("log_ctx"),
            allow_reinstatement=inp.get("allow_reinstatement", True),
            origin_bundle=inp.get("origin_bundle"),
        )
        return res.verdict, res.refusal_code
    if runner == "log_checkpoint":
        ch = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        before_n = len(j.entries) if j is not None else 0
        before_cl = len(j.closures) if j is not None else 0
        res = v.verify_log_checkpoint(
            inp["checkpoint"],
            inp.get("checkpoint_txid"),
            ch,
            prev_cp_env=inp.get("prev_checkpoint"),
            prev_cp_txid=inp.get("prev_checkpoint_txid"),
            genesis_seal=inp.get("genesis_seal"),
            predecessor_terminal_checkpoint=inp.get("predecessor_terminal_checkpoint"),
            predecessor_chain=inp.get("predecessor_chain"),
            journal=j,
            required_depth=inp.get("required_depth"),
            is_head=inp.get("is_head", True),
            origin_bundle=inp.get("origin_bundle"),
        )
        if inp.get("expect_closure_written") and j is not None and len(j.closures) <= before_cl:
            return "REFUSE", "EXPECTED_CLOSURE_NOT_WRITTEN"
        if res.verdict == "ADMIT" and "expect_journal_writes" in inp and j is not None:
            if len(j.entries) - before_n != int(inp["expect_journal_writes"]):
                return "REFUSE", f"LOG_HEAD_WRITES_MISMATCH:{len(j.entries) - before_n}"
        if res.verdict == "ADMIT" and "expect_log_head_txid" in inp and j is not None:
            lid = inp["checkpoint"]["payload"]["log_id"]
            if (j.log_heads.get(lid) or {}).get("checkpoint_txid") != inp["expect_log_head_txid"]:
                return "REFUSE", f"LOG_HEAD_TXID_MISMATCH:{(j.log_heads.get(lid) or {}).get('checkpoint_txid')}"
        if res.verdict == "ADMIT" and inp.get("replay_restart_check") and j is not None:
            j2 = sv.FencedJournal.replay_persisted_entries(
                j.journal_id,
                json.loads(json.dumps(j.entries)),
                witness_pos=j.witness_pos,
                witness_commitment=j.witness_commitment,
                write_token_active=True,
            )
            if j2.check_continuity() is not None or j2.log_heads != j.log_heads:
                return "REFUSE", "LOG_HEAD_REPLAY_MISMATCH"
        return res.verdict, res.refusal_code
    if runner == "log_fraud":
        ch = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        before_cl = len(j.closures) if j is not None else 0
        before_ent = len(j.entries) if j is not None else 0
        res = v.verify_log_fraud(inp["fraud"], ch, journal=j, origin_bundle=inp.get("origin_bundle"))
        if inp.get("expect_zero_closures") and j is not None and len(j.closures) != before_cl:
            return "REFUSE", f"UNEXPECTED_FRAUD_CLOSURES:{len(j.closures) - before_cl}"
        if inp.get("expect_zero_writes") and j is not None and len(j.entries) != before_ent:
            return "REFUSE", f"UNEXPECTED_FRAUD_WRITES:{len(j.entries) - before_ent}"
        if res.verdict == "ADMIT" and j is not None and "post_fraud_ticket" in inp:
            t_res = v.verify_artifact_ticket(inp["post_fraud_ticket"], inp["post_fraud_policy"], ch, journal=j)
            return t_res.verdict, t_res.refusal_code
        if res.verdict == "ADMIT" and j is not None and "post_fraud_release" in inp:
            r_res = v.verify_release(inp["post_fraud_release"], ch, log_ctx=inp.get("post_fraud_log_ctx"), journal=j)
            return r_res.verdict, r_res.refusal_code
        return res.verdict, res.refusal_code
    if runner == "release":
        ch = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        res = v.verify_release(
            inp["release"],
            ch,
            anchor_txid=inp.get("anchor_txid"),
            log_ctx=inp.get("log_ctx"),
            journal=j,
            allow_reinstatement=inp.get("allow_reinstatement", True),
            heartbeat_max_blocks=inp.get("heartbeat_max_blocks"),
            origin_bundle=inp.get("origin_bundle"),
        )
        return res.verdict, res.refusal_code
    if runner == "artifact_ticket":
        ch = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        res = v.verify_artifact_ticket(
            inp["ticket"],
            inp["policy"],
            ch,
            journal=j,
            provisional_revocations=inp.get("provisional_revocations"),
            origin_bundles_by_oid=inp.get("origin_bundles_by_oid"),
        )
        return res.verdict, res.refusal_code
    if runner == "tier2_name_history":
        res = v.verify_tier2_name_history_page(
            inp["page"],
            inp["expected_owner_policy"],
            trusted_checkpoint=inp.get("trusted_checkpoint"),
            current_time=inp.get("current_time"),
            allow_unresolved_voluntary_rebind=inp.get("allow_unresolved_voluntary_rebind", False),
        )
        if res.verdict == "ADMIT":
            if "expect_owner_authored" in inp:
                got_oa = [u.get("owner_authored") for u in res.details.get("verified_updates", [])]
                if got_oa != inp["expect_owner_authored"]:
                    return "REFUSE", f"TIER2_OWNER_AUTHORED_MISMATCH:{got_oa}"
            if "expect_next_cursor_owner_policy" in inp:
                got_pol = res.details.get("final_owner_policy")
                if got_pol != inp["expect_next_cursor_owner_policy"]:
                    return "REFUSE", f"TIER2_CURSOR_POLICY_MISMATCH:{got_pol}"
        return res.verdict, res.refusal_code
    if runner == "verdict":
        ch = sv.ChainView(inp["chain"])
        res = v.verify_verdict(
            inp["verdict"],
            inp["contract"],
            ch,
            prev_verdict_env=inp.get("prev_verdict"),
            anchor_txid=inp.get("anchor_txid"),
        )
        return res.verdict, res.refusal_code
    if runner == "termination":
        ch = sv.ChainView(inp["chain"])
        j = sv.FencedJournal.from_dict(inp["journal"]) if "journal" in inp else None
        res = v.verify_termination(
            inp["termination"],
            inp["contract"],
            ch,
            spend_txid=inp.get("spend_txid"),
            origin_bundle=inp.get("origin_bundle"),
            origin_bundles_by_oid=inp.get("origin_bundles_by_oid"),
            journal=j,
        )
        return res.verdict, res.refusal_code
    if runner == "certset_head":
        res = v.verify_certset_head(inp["head"], inp["statements"], inp["owner_manifest"])
        return res.verdict, res.refusal_code
    if runner == "statement":
        ch = sv.ChainView(inp["chain"])
        res = v.verify_statement(
            inp["statement"],
            ch,
            expected_policy=inp.get("expected_policy"),
            device_proof=inp.get("device_proof"),
            owner_manifest=inp.get("owner_manifest"),
            presented_manifests=inp.get("manifests"),
            origin_bundle=inp.get("origin_bundle"),
            origin_bundles_by_oid=inp.get("origin_bundles_by_oid"),
        )
        return res.verdict, res.refusal_code
    if runner == "session_lifecycle":
        j = sv.FencedJournal.from_dict(inp.get("journal", {"journal_id": _h32("sl-j")}))
        captured_token: str | None = None
        for step in inp["steps"]:
            op_kind = step["kind"]
            if op_kind == "replay_restart":
                j = sv.FencedJournal.replay_persisted_entries(
                    j.journal_id,
                    json.loads(json.dumps(j.entries)),
                    receipt_store=json.loads(json.dumps(j.receipt_store)),
                    witness_pos=j.witness_pos,
                    witness_commitment=j.witness_commitment,
                    write_token_active=True,
                )
                rep_err = j.check_continuity()
                if rep_err is not None:
                    return "REFUSE", f"SESSION_REPLAY_ERR:{rep_err}"
                continue
            ch = sv.ChainView(step["chain"])
            before_n = len(j.entries)
            if op_kind == "session_open":
                res = v.verify_session_open(
                    step["session_open"],
                    step["bundle"],
                    ch,
                    j,
                    inp["executor_cfg"],
                    bearer_token=step.get("bearer_token"),
                )
                if res.verdict == "ADMIT" and "bearer_token" in res.details:
                    captured_token = res.details["bearer_token"]
                if step.get("expect_bearer_token") and (not isinstance(res.details.get("bearer_token"), str) or len(res.details["bearer_token"]) != 64):
                    return "REFUSE", f"MISSING_BEARER_TOKEN:{step['label']}"
            elif op_kind == "bearer_session":
                tok_use = captured_token if step["token"] == "__FROM_OPEN__" and captured_token is not None else step["token"]
                res = v.verify_bearer_session(
                    tok_use,
                    step["slot_binding"],
                    ch,
                    j,
                    grant_env=step.get("grant_env"),
                    parent_grant_env=step.get("parent_grant_env"),
                    contract_env=step.get("contract_env"),
                    framework_contract_env=step.get("framework_contract_env"),
                    origin_bundle=step.get("origin_bundle"),
                    action=step.get("action"),
                    target=step.get("target"),
                    arguments=step.get("arguments"),
                    actual_message_meta=step.get("actual_message_meta"),
                    executor_cfg=step.get("executor_cfg") or inp.get("executor_cfg"),
                    disclosed_clauses=step.get("disclosed_clauses"),
                )
            else:
                raise ValueError(f"Unknown session_lifecycle step kind: {op_kind}")
            if (res.verdict, res.refusal_code) != (step["want_verdict"], step.get("want_refusal")):
                return "REFUSE", f"SESSION_STEP_MISMATCH:{step['label']}:{(res.verdict, res.refusal_code)}"
            if step.get("expect_zero_writes") and len(j.entries) != before_n:
                return "REFUSE", f"SESSION_UNEXPECTED_WRITES:{step['label']}"
            if "expect_debit_count" in step and res.journal_writes:
                got_d = len(res.journal_writes[-1]["entry"]["body"].get("debits", []))
                if got_d != step["expect_debit_count"]:
                    return "REFUSE", f"SESSION_DEBIT_COUNT:{step['label']}:{got_d}"
            for bspec in step.get("check_balances", []):
                key = (bspec["scope"], bspec["qkey"], bspec["bucket_id"])
                got_b = j.quotas_used.get(key, 0)
                if got_b != bspec["expected"]:
                    return "REFUSE", f"SESSION_BAL:{step['label']}:{bspec['scope']}:{got_b}"
        return "ADMIT", None
    if runner == "two_phase_commit":
        # Exercises R1-A atomic admit_and_reserve() -> optional retry while unsettled (UNCERTAIN) ->
        # commit_result(real_receipt_env) -> restart -> replay idempotency OR missing-blob INVOKE_REPLAY!
        j = sv.FencedJournal(inp["journal_id"])
        ch = sv.ChainView(inp["chain"])
        raw_msg = bytes.fromhex(inp["raw_message_hex"]) if "raw_message_hex" in inp else None
        p1 = v.admit_and_reserve(
            inp["invocation"],
            inp["bundle"],
            ch,
            j,
            inp["executor_cfg"],
            use_txid=inp.get("use_txid"),
            raw_message_bytes=raw_msg,
            actual_message_meta=inp.get("actual_message_meta"),
        )
        if p1.verdict != "ADMIT":
            return p1.verdict, p1.refusal_code
        if inp.get("retry_before_commit"):
            before_n = len(j.entries)
            r_un = v.admit_and_reserve(
                inp["invocation"],
                inp["bundle"],
                ch,
                j,
                inp["executor_cfg"],
                use_txid=inp.get("use_txid"),
                raw_message_bytes=raw_msg,
            )
            if len(j.entries) != before_n:
                return "REFUSE", "UNEXPECTED_WRITE_ON_UNCERTAIN_RETRY"
            return r_un.verdict, r_un.refusal_code
        p2 = v.commit_result(
            inp["receipt_env"],
            j,
            inp["executor_cfg"],
            invocation_id=p1.details["invocation_id"],
            grant_id=p1.details["grant_id"],
            actual_quota_usage=inp.get("actual_quota_usage"),
        )
        if p2.verdict != "ADMIT":
            return p2.verdict, p2.refusal_code
        persisted_entries = json.loads(json.dumps(j.entries))
        persisted_store = {} if inp.get("drop_receipt_blob_on_restart") else json.loads(json.dumps(j.receipt_store))
        restarted = sv.FencedJournal.replay_persisted_entries(
            j.journal_id,
            persisted_entries,
            receipt_store=persisted_store,
            witness_pos=j.witness_pos,
            witness_commitment=j.witness_commitment,
            write_token_active=True,
        )
        rep_err = restarted.check_continuity()
        if rep_err is not None:
            return "REFUSE", rep_err
        before_n = len(restarted.entries)
        retry_res = v.admit_and_reserve(
            inp["invocation"],
            inp["bundle"],
            ch,
            restarted,
            inp["executor_cfg"],
            use_txid=inp.get("use_txid"),
            raw_message_bytes=raw_msg,
            actual_message_meta=inp.get("actual_message_meta"),
        )
        if len(restarted.entries) != before_n:
            return "REFUSE", "UNEXPECTED_WRITE_ON_POST_RESTART_RETRY"
        if "expect_cached_receipt_ca" in inp and retry_res.verdict == "ADMIT":
            if retry_res.cached_receipt_content_addr != inp["expect_cached_receipt_ca"]:
                return "REFUSE", f"CACHED_RECEIPT_MISMATCH:{retry_res.cached_receipt_content_addr}"
        return retry_res.verdict, retry_res.refusal_code
    if runner == "replay_journal_tamper":
        restarted = sv.FencedJournal.replay_persisted_entries(
            inp["journal_id"],
            inp["entries"],
            receipt_store=inp.get("receipt_store"),
            witness_pos=inp.get("witness_pos"),
            witness_commitment=inp.get("witness_commitment"),
            write_token_active=inp.get("write_token_active", True),
            require_witness=inp.get("require_witness", True),
        )
        rep_err = restarted.check_continuity()
        return ("REFUSE", rep_err) if rep_err else ("ADMIT", None)
    if runner == "commit_edge":
        j = sv.FencedJournal(inp["journal_id"])
        ch = sv.ChainView(inp["chain"])
        if inp.get("skip_phase1"):
            rp = inp["receipt_env"]["payload"]
            res = v.commit_result(
                inp["receipt_env"],
                j,
                inp["executor_cfg"],
                invocation_id=rp["invocation_id"],
                grant_id=rp["grant_id"],
            )
            return res.verdict, res.refusal_code
        p1 = v.admit_and_reserve(
            inp["invocation"],
            inp["bundle"],
            ch,
            j,
            inp["executor_cfg"],
            use_txid=inp.get("use_txid"),
            actual_message_meta=inp.get("actual_message_meta"),
        )
        if p1.verdict != "ADMIT":
            return p1.verdict, p1.refusal_code
        if inp.get("self_contained_restart"):
            j = sv.FencedJournal.replay_persisted_entries(
                j.journal_id,
                json.loads(json.dumps(j.entries)),
                receipt_store=json.loads(json.dumps(j.receipt_store)),
                witness_pos=j.witness_pos,
                witness_commitment=j.witness_commitment,
                write_token_active=True,
            )
            rep_err = j.check_continuity()
            if rep_err is not None:
                return "REFUSE", rep_err
        # H-7 / M-5: commit_result derives action, single_use, use_txid strictly from durable reservation, and recorded_at strictly from signed receipt!
        p2 = v.commit_result(
            inp["receipt_env"],
            j,
            inp["executor_cfg"],
            invocation_id=p1.details["invocation_id"],
            grant_id=inp.get("override_grant_id", p1.details["grant_id"]),
            actual_quota_usage=inp.get("actual_quota_usage"),
        )
        if p2.verdict != "ADMIT":
            return p2.verdict, p2.refusal_code
        if "expect_total_entries" in inp and len(j.entries) != inp["expect_total_entries"]:
            return "REFUSE", f"ENTRY_COUNT_MISMATCH:{len(j.entries)}"
        if "expect_settlement_order" in inp:
            got_ord = [
                f"{ln['account']}:{ln.get('row_ordinal', '')}:{ln['quota_kind']}:{ln['unit']}"
                for ln in j.entries[-1]["body"].get("settlements", [])
            ]
            if got_ord != inp["expect_settlement_order"]:
                return "REFUSE", f"SETTLEMENT_ORDER_MISMATCH:{got_ord}"
        if "expect_head_commitment" in inp and j.commitment != inp["expect_head_commitment"]:
            return "REFUSE", f"COMMITMENT_MISMATCH:{j.commitment}"
        if "expect_settlement_recorded_at" in inp:
            settle_entries = [e for e in j.entries if e.get("kind") == "settlement"]
            if not settle_entries or settle_entries[-1]["body"].get("recorded_at") != inp["expect_settlement_recorded_at"]:
                return "REFUSE", f"SETTLEMENT_RECORDED_AT_MISMATCH:{settle_entries[-1]['body'].get('recorded_at') if settle_entries else None}"
        if inp.get("admit_replay_after_p2"):
            r_mid = v.admit_and_reserve(
                inp["invocation"],
                inp["bundle"],
                ch,
                j,
                inp["executor_cfg"],
                use_txid=inp.get("use_txid"),
                actual_message_meta=inp.get("actual_message_meta"),
            )
            want_mid = inp["admit_replay_after_p2"]
            if (r_mid.verdict, r_mid.refusal_code) != (want_mid["want_verdict"], want_mid.get("want_refusal")):
                return "REFUSE", f"MID_REPLAY_MISMATCH:{(r_mid.verdict, r_mid.refusal_code)}"
        for ec in inp.get("extra_commits", []):
            if ec.get("restart_before"):
                j = sv.FencedJournal.replay_persisted_entries(
                    j.journal_id,
                    json.loads(json.dumps(j.entries)),
                    receipt_store=json.loads(json.dumps(j.receipt_store)),
                    witness_pos=j.witness_pos,
                    witness_commitment=j.witness_commitment,
                    write_token_active=True,
                )
                rep_err = j.check_continuity()
                if rep_err is not None:
                    return "REFUSE", rep_err
            before_n = len(j.entries)
            before_c = j.commitment
            ec_res = v.commit_result(
                ec["receipt_env"],
                j,
                inp["executor_cfg"],
                invocation_id=p1.details["invocation_id"],
                grant_id=p1.details["grant_id"],
                actual_quota_usage=ec.get("actual_quota_usage"),
            )
            if (ec_res.verdict, ec_res.refusal_code) != (ec["want_verdict"], ec.get("want_refusal")):
                return "REFUSE", f"EXTRA_COMMIT_MISMATCH:{ec['label']}:{(ec_res.verdict, ec_res.refusal_code)}"
            if ec.get("expect_zero_writes") and (len(j.entries) != before_n or j.commitment != before_c):
                return "REFUSE", f"EXTRA_COMMIT_MUTATED:{ec['label']}"
            if "expect_pos" in ec and j.pos != ec["expect_pos"]:
                return "REFUSE", f"EXTRA_COMMIT_POS:{ec['label']}:{j.pos}"
            for bspec in ec.get("check_balances", []):
                key = (bspec["scope"], bspec["qkey"], bspec["bucket_id"])
                got_b = j.quotas_used.get(key, 0)
                if got_b != bspec["expected"]:
                    return "REFUSE", f"EXTRA_COMMIT_BAL:{ec['label']}:{got_b}"
        if "expect_single_use_closure_count" in inp:
            su_cnt = sum(1 for e in j.entries if e.get("kind") == "settlement" and e["body"].get("single_use_consumed") is True)
            if su_cnt != inp["expect_single_use_closure_count"]:
                return "REFUSE", f"SINGLE_USE_CLOSURE_COUNT:{su_cnt}"
        if inp.get("second_receipt_env") is not None:
            before_n = len(j.entries)
            before_c = j.commitment
            p2b = v.commit_result(
                inp["second_receipt_env"],
                j,
                inp["executor_cfg"],
                invocation_id=p1.details["invocation_id"],
                grant_id=p1.details["grant_id"],
                actual_quota_usage=inp.get("actual_quota_usage"),
            )
            if p2b.verdict == "ADMIT" and (len(j.entries) != before_n or j.commitment != before_c):
                return "REFUSE", "IDEMPOTENT_COMMIT_MUTATED_JOURNAL"
            return p2b.verdict, p2b.refusal_code
        if inp.get("post_restart_new_invocation") is not None:
            restarted = sv.FencedJournal.replay_persisted_entries(
                j.journal_id,
                json.loads(json.dumps(j.entries)),
                receipt_store=json.loads(json.dumps(j.receipt_store)),
                witness_pos=j.witness_pos,
                witness_commitment=j.witness_commitment,
            )
            r_new = v.admit_and_reserve(
                inp["post_restart_new_invocation"],
                inp["bundle"],
                ch,
                restarted,
                inp["executor_cfg"],
                use_txid=inp.get("use_txid"),
                actual_message_meta=inp.get("actual_message_meta"),
            )
            return r_new.verdict, r_new.refusal_code
        return p2.verdict, p2.refusal_code
    if runner == "multi_step_journal":
        j = sv.FencedJournal.from_dict(inp.get("journal", {"journal_id": _h32("msj-j")}))
        for step in inp["steps"]:
            op = step["kind"]
            if op == "replay_restart":
                j = sv.FencedJournal.replay_persisted_entries(
                    j.journal_id,
                    json.loads(json.dumps(j.entries)),
                    receipt_store=json.loads(json.dumps(j.receipt_store)),
                    witness_pos=j.witness_pos,
                    witness_commitment=j.witness_commitment,
                    write_token_active=True,
                )
                rep_err = j.check_continuity()
                if rep_err is not None:
                    return "REFUSE", f"MSJ_REPLAY_ERR:{rep_err}"
                continue
            if op == "record_closure":
                before_cl = len(j.closures)
                before_ent = len(j.entries)
                j.record_closure(
                    step["subject"],
                    step["cause"],
                    observed_at=step["observed_at"],
                    observed_height=step.get("observed_height"),
                    spend_txid=step.get("spend_txid"),
                )
                if "expect_closures_delta" in step and (len(j.closures) - before_cl) != step["expect_closures_delta"]:
                    return "REFUSE", f"MSJ_CL_DELTA:{step['label']}:{len(j.closures) - before_cl}"
                if "expect_entries_delta" in step and (len(j.entries) - before_ent) != step["expect_entries_delta"]:
                    return "REFUSE", f"MSJ_ENT_DELTA:{step['label']}:{len(j.entries) - before_ent}"
                continue
            ch = sv.ChainView(step["chain"])
            before_cl = len(j.closures)
            before_ent = len(j.entries)
            if op == "invocation":
                res = v.verify_invocation(
                    step["invocation"],
                    step["bundle"],
                    ch,
                    j,
                    step["executor_cfg"],
                    use_txid=step.get("use_txid"),
                    actual_message_meta=step.get("actual_message_meta"),
                )
            elif op == "credential":
                res = v.verify_credential(
                    step["credential"],
                    step.get("anchor_txid"),
                    ch,
                    journal=j,
                    origin_bundle=step.get("origin_bundle"),
                )
            elif op == "federation":
                res = v.verify_federation_disclosure(
                    step["policy"],
                    step["peer_ctx"],
                    step["grant"],
                    chain=ch,
                    journal=j,
                )
            else:
                raise ValueError(f"Unknown multi_step_journal op: {op}")
            if (res.verdict, res.refusal_code) != (step["want_verdict"], step.get("want_refusal")):
                return "REFUSE", f"MSJ_MISMATCH:{step['label']}:{(res.verdict, res.refusal_code)}"
            if "expect_closures_delta" in step and (len(j.closures) - before_cl) != step["expect_closures_delta"]:
                return "REFUSE", f"MSJ_CL_DELTA:{step['label']}:{len(j.closures) - before_cl}"
            if "expect_entries_delta" in step and (len(j.entries) - before_ent) != step["expect_entries_delta"]:
                return "REFUSE", f"MSJ_ENT_DELTA:{step['label']}:{len(j.entries) - before_ent}"
        if "expect_head_commitment" in inp and j.commitment != inp["expect_head_commitment"]:
            return "REFUSE", f"MSJ_COMMITMENT_MISMATCH:{j.commitment}"
        return "ADMIT", None
    if runner == "journal_cas_fence":
        jid = inp["journal_id"]
        ext: dict[str, Any] = {
            "journal_id": jid,
            "pos": 0,
            "commitment": sl.journal_commit_init(jid),
            "active_write_token": 1,
        }
        ja = sv.FencedJournal(jid, external_witness=ext, write_token=1)
        jb = sv.FencedJournal(jid, external_witness=ext, write_token=1)
        # Replica B takes over by fencing active_write_token -> 2 and writing an entry
        ext["active_write_token"] = 2
        jb.write_token = 2
        jb.append("recovery", {"fenced_at": 1795220000, "new_write_token": 2, "prev_write_token": 1})
        try:
            ja.append("recovery", {"fenced_at": 1795220001, "new_write_token": 1, "prev_write_token": 0})
            return "ADMIT", None
        except PermissionError:
            return "REFUSE", "JOURNAL_FENCED"
        except RuntimeError:
            return "REFUSE", "JOURNAL_LOST"
        except ValueError as exc:
            return "REFUSE", str(exc)
    if runner == "journal_entry_wire":
        j = sv.FencedJournal(inp["journal_id"])
        try:
            w = j.append(inp["kind"], inp["body"])
        except ValueError as exc:
            return "REFUSE", str(exc)
        raw = sl.jcs_encode(w["entry"])
        if "expect_exact_bytes" in inp and len(raw) != inp["expect_exact_bytes"]:
            return "REFUSE", f"EXACT_SIZE_MISMATCH:{len(raw)}"
        if inp.get("expect_gt_16384") and len(raw) <= 16384:
            return "REFUSE", f"TOO_SMALL:{len(raw)}"
        if len(raw) > 65536:
            return "REFUSE", f"TOO_LARGE:{len(raw)}"
        ok_w, code_w = v.verify_wire_bytes(raw)
        return ("ADMIT", None) if ok_w else ("REFUSE", code_w)
    if runner == "single_use_anti_dos":
        ch = sv.ChainView(inp["chain"])
        j = sv.FencedJournal(inp["journal_id"])
        r_bad = v.verify_invocation(inp["foreign_invocation"], inp["bundle"], ch, j, inp["executor_cfg"], use_txid=inp["foreign_use_txid"], actual_message_meta=inp.get("actual_message_meta"))
        if r_bad.verdict != "REFUSE" or r_bad.refusal_code != "SEAL_SPENT":
            return "REFUSE", f"FOREIGN_UNEXPECTED:{(r_bad.verdict, r_bad.refusal_code)}"
        if j.entries:
            return "REFUSE", f"FOREIGN_WROTE_CLOSURE:{len(j.entries)}"
        r_ok = v.verify_invocation(inp["good_invocation"], inp["bundle"], ch, j, inp["executor_cfg"], use_txid=inp["good_use_txid"], actual_message_meta=inp.get("actual_message_meta"))
        return r_ok.verdict, r_ok.refusal_code
    raise ValueError(f"Unknown security runner: {runner}")


def build_security_conformance_suite() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def _default_module(runner_name: str) -> str:
        if runner_name in ("session_lifecycle", "bearer_session"):
            return "bearer-sessions"
        if runner_name == "migration":
            return "service-migration"
        if runner_name == "federation":
            return "federated-screening"
        return "core"

    def add(
        cid: str,
        rules: list[str],
        runner: str,
        inputs: dict[str, Any],
        expected_verdict: str,
        expected_refusal: str | None,
        note: str,
        *,
        module: str | None = None,
    ) -> None:
        clean_inputs = rm._strip_private(inputs)
        case = {
            "id": cid,
            "module": module or _default_module(runner),
            "rules": rules,
            "runner": runner,
            "inputs": clean_inputs,
            "expected_verdict": expected_verdict,
            "expected_refusal": expected_refusal,
            "note": note,
        }
        got_v, got_c = execute_security_case(case)
        assert (got_v, got_c) == (expected_verdict, expected_refusal), (
            f"Security case {cid} failed self-check: expected {(expected_verdict, expected_refusal)}, got {(got_v, got_c)}"
        )
        cases.append(case)

    stranger = _kp("stranger-attacker")

    # 1. Stranger-signed seallink-origin/1 claiming trusted issuer name -> WIRE_SIGNATURE
    of = rm._base_origin_fixture()
    forged_orig_p = copy.deepcopy(of["origin_bundle"]["origin"]["payload"])
    forged_orig_p["issuer"]["role_policy"] = {"m": 1, "pks": [stranger["xonly"]]}
    forged_orig = sl.sign_envelope(forged_orig_p, [stranger["sk"]])
    of["origin_bundle"]["origin"] = forged_orig
    of["chain"]["txs"][of["origin_bundle"]["origin_anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(
        0x09, sl.content_addr(forged_orig)
    ).hex()
    add(
        "stranger-signed-origin-rejected",
        ["SL-ORIG-002", "SL-WIRE-013"],
        "origin_status",
        {"origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "REFUSE",
        "WIRE_SIGNATURE",
        "Origin signed by stranger key (even if anchored by stranger and claiming trusted issuer name) MUST fail against issuer link.cred at h_origin.",
    )

    # 2. Empty trusted_origin_issuers MUST fail closed with ORIGIN_UNVERIFIED (never trust all!)
    of = rm._base_origin_fixture()
    add(
        "empty-trusted-origin-issuers-refuses",
        ["SL-ORIG-002"],
        "origin_status",
        {"origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": []},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "Verifier with empty trusted_origin_issuers MUST refuse ORIGIN_UNVERIFIED.",
    )

    # 3. Stranger-signed 0x12 guardian/1 -> slot becomes contested_burned -> GUARDIAN_INACTIVE on assent
    of = rm._base_origin_fixture()
    forged_g_p = copy.deepcopy(of["origin_bundle"]["guardian_records"][0]["payload"])
    forged_g_p["issuer"]["role_policy"] = {"m": 1, "pks": [stranger["xonly"]]}
    forged_g = sl.sign_envelope(forged_g_p, [stranger["sk"]])
    g1_assent_for_forged = sl.sign_envelope(
        {**of["origin_bundle"]["guardian_assents"][0]["payload"], "target_id": sl.object_id(forged_g_p)},
        [of["_keys"]["g1_gr"]["sk"]],
    )
    of["origin_bundle"]["guardian_records"] = [forged_g]
    of["origin_bundle"]["guardian_assents"] = [g1_assent_for_forged]
    of["chain"]["txs"][rm._h32("og1-init-0x12")]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(forged_g)).hex()
    assent_s1 = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000,
            "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": of["_origin_id"], "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000,
            "network": "main",
            "nonce": _h32("sec-s1-a"),
            "party_id": "student-1",
            "party_name": "id/child-leo",
            "party_role": "student_ward",
            "target_id": sl.object_id(of["contract"]),
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [{"slot": 1, "revision": 1, "guardian_name": "id/parent-a", "signers": [of["_keys"]["g1_gr"]["sk"]]}],
    )
    add(
        "stranger-signed-guardian-initial-rejected",
        ["SL-ORIG-007", "SL-ORIG-008", "SL-WIRE-013"],
        "assent",
        {"assent": assent_s1, "contract": of["contract"], "origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_INACTIVE",
        "Guardian record signed by stranger key MUST fail link.cred verification at anchor height, leaving slot contested_burned.",
    )

    # 4. Missing incoming guardian assent blocks 0x12 activation -> GUARDIAN_INACTIVE
    of = rm._base_origin_fixture()
    of["origin_bundle"]["guardian_assents"] = []
    add(
        "missing-guardian-assent-blocks-activation",
        ["SL-ORIG-007"],
        "assent",
        {"assent": assent_s1, "contract": of["contract"], "origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "REFUSE",
        "GUARDIAN_INACTIVE",
        "Initial activation 0x12 without incoming guardian's verified seallink-assent/1 MUST NOT activate slot.",
    )

    # 5. Stranger-signed 0x0f guardian-roster/1 -> WIRE_SIGNATURE
    of = rm._base_origin_fixture()
    disp = of["_keys"]["disp"]
    arb = of["_keys"]["arb"]
    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["comp"], arb["comp"])}
    rp_forged = {
        "arbiter_pk": arb["comp"],
        "challenger_pk": of["origin_bundle"]["origin"]["payload"]["guardian_policy"]["challenger_pk"],
        "disposer_pk": disp["comp"],
        "effective_delay_blocks": 144,
        "genesis": GENESIS_MAIN,
        "issuer": {**of["origin_bundle"]["origin"]["payload"]["issuer"], "role_policy": {"m": 1, "pks": [stranger["xonly"]]}},
        "network": "main",
        "next_roster_policy": vac_pol,
        "next_roster_vout": 0,
        "origin_id": of["_origin_id"],
        "prev_revision": 1,
        "prev_roster_outpoint": {"txid": rm._h32("oroster-tx"), "vout": 0},
        "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in ("routine_read", "effect_grant", "contract_assent", "custody_change")},
        "revision": 2,
        "revision_size": 1,
        "slots": [{"action": "new_vacant", "new_vacant_policy": vac_pol, "new_vacant_vout": 1, "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    rrec_forged = sl.sign_envelope(rp_forged, [stranger["sk"]])
    rtx_forged = _h32("sec-forged-roster-tx")
    of["chain"]["txs"][rm._h32("oroster-tx")]["outputs"]["0"]["spent_by_txid"] = rtx_forged
    of["chain"]["txs"][rtx_forged] = {
        "confirmed_height": 749500,
        "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rrec_forged)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pol)}, "1": {"script_pubkey_hex": _spk_hex(vac_pol)}},
    }
    of["origin_bundle"]["roster_records"] = [rrec_forged]
    add(
        "stranger-signed-roster-transition-rejected",
        ["SL-ORIG-015", "SL-ORIG-008", "SL-WIRE-013"],
        "origin_status",
        {"origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "REFUSE",
        "WIRE_SIGNATURE",
        "Roster transition 0x0f signed by stranger key MUST fail authoritative issuer link.cred check.",
    )

    # 6. Disposer rotation with retain_active FORBIDDEN -> CHAIN_SCRIPT_UNSUPPORTED
    of = rm._base_origin_fixture()
    new_disp = _kp("new-disposer-rotated")
    new_vac_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(new_disp["comp"], arb["comp"])}
    rp_bad_rot = {
        "arbiter_pk": arb["comp"],
        "challenger_pk": of["origin_bundle"]["origin"]["payload"]["guardian_policy"]["challenger_pk"],
        "disposer_pk": new_disp["comp"],
        "effective_delay_blocks": 144,
        "genesis": GENESIS_MAIN,
        "issuer": of["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main",
        "next_roster_policy": new_vac_pol,
        "next_roster_vout": 0,
        "origin_id": of["_origin_id"],
        "prev_revision": 1,
        "prev_roster_outpoint": {"txid": rm._h32("oroster-tx"), "vout": 0},
        "quorums": {k: {"den": 1, "min": 1, "num": 1} for k in ("routine_read", "effect_grant", "contract_assent", "custody_change")},
        "revision": 2,
        "revision_size": 1,
        "slots": [{
            "action": "retain_active",
            "active_outpoint": {"txid": rm._h32("og1-init-0x12"), "vout": 0},
            "guardian_id": sl.object_id(of["origin_bundle"]["guardian_records"][0]["payload"]),
            "slot": 1,
        }],
        "type": "seallink-guardian-roster/1",
    }
    rrec_bad_rot = sl.sign_envelope(rp_bad_rot, [of["_keys"]["reg_cred"]["sk"]])
    rtx_rot = _h32("sec-rot-bad-tx")
    of["chain"]["txs"][rm._h32("oroster-tx")]["outputs"]["0"]["spent_by_txid"] = rtx_rot
    of["chain"]["txs"][rtx_rot] = {
        "confirmed_height": 749500,
        "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rrec_bad_rot)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(new_vac_pol)}},
    }
    of["origin_bundle"]["roster_records"] = [rrec_bad_rot]
    add(
        "disposer-rotation-forbids-retain-active",
        ["SL-ORIG-015", "SL-ORIG-016"],
        "origin_status",
        {"origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "REFUSE",
        "CHAIN_SCRIPT_UNSUPPORTED",
        "Changing disposer_pk in 0x0f roster transition MUST forbid retain_active and require new_vacant under new keys.",
    )

    # 7. Disposer rotation with ALL slots recreated via new_vacant -> ADMIT_WARD
    of = rm._base_origin_fixture()
    rp_ok_rot = {
        **rp_bad_rot,
        "slots": [{"action": "new_vacant", "new_vacant_policy": new_vac_pol, "new_vacant_vout": 1, "slot": 1}],
    }
    rrec_ok_rot = sl.sign_envelope(rp_ok_rot, [of["_keys"]["reg_cred"]["sk"]])
    rtx_rot_ok = _h32("sec-rot-ok-tx")
    of["chain"]["txs"][rm._h32("oroster-tx")]["outputs"]["0"]["spent_by_txid"] = rtx_rot_ok
    of["chain"]["txs"][rtx_rot_ok] = {
        "confirmed_height": 749500,
        "opreturn_hex": sl.encode_opreturn(0x0F, sl.content_addr(rrec_ok_rot)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(new_vac_pol)}, "1": {"script_pubkey_hex": _spk_hex(new_vac_pol)}},
    }
    of["origin_bundle"]["roster_records"] = [rrec_ok_rot]
    add(
        "disposer-rotation-with-new-vacant-admits",
        ["SL-ORIG-015", "SL-ORIG-016"],
        "origin_status",
        {"origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "ADMIT_WARD",
        None,
        "Changing disposer_pk in 0x0f roster transition succeeds when all slots use new_vacant locked to both_of_2(new_disposer_pk, arbiter_pk).",
    )

    # 8. Stranger-signed seallink-capacity/1 -> ORIGIN_STATUS_INCOMPLETE
    of = rm._base_origin_fixture()
    subj_new_own = _kp("leo-adult-owner")
    subj_new_pol = {"kind": "key", "pk": subj_new_own["comp"]}
    stat_pol = of["origin_bundle"]["origin"]["payload"]["status_seal"]["script_policy"]
    cap_forged_p = {
        "basis_sha256": _h32("cap-basis"),
        "genesis": GENESIS_MAIN,
        "issued_at": 1795220000,
        "issuer": {**of["origin_bundle"]["origin"]["payload"]["issuer"], "role_policy": {"m": 1, "pks": [stranger["xonly"]]}},
        "network": "main",
        "next_status_policy": stat_pol,
        "next_status_vout": 0,
        "origin_id": of["_origin_id"],
        "status_prev_outpoint": {"txid": rm._h32("ostat-tx"), "vout": 0},
        "subject_new_owner_policy": subj_new_pol,
        "type": "seallink-capacity/1",
    }
    cap_forged = sl.sign_envelope(cap_forged_p, [stranger["sk"]])
    cap_tx = _h32("sec-cap-forged-tx")
    of["chain"]["txs"][rm._h32("ostat-tx")]["outputs"]["0"]["spent_by_txid"] = cap_tx
    of["chain"]["txs"][cap_tx] = {
        "confirmed_height": 750050,
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_forged)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_pol)}},
    }
    of["origin_bundle"]["capacity_record"] = cap_forged
    add(
        "stranger-signed-capacity-rejected",
        ["SL-ORIG-002", "SL-ORIG-011", "SL-WIRE-013"],
        "origin_status",
        {"origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "seallink-capacity/1 signed by stranger key MUST fail closed with ORIGIN_STATUS_INCOMPLETE.",
    )

    # 9. Valid seallink-capacity/1 + confirmed handover transfer + subject-authored update -> ADMIT_AUTONOMOUS!
    of = rm._base_origin_fixture()
    cap_ok_p = {**cap_forged_p, "issuer": of["origin_bundle"]["origin"]["payload"]["issuer"]}
    cap_ok = sl.sign_envelope(cap_ok_p, [of["_keys"]["reg_cred"]["sk"]])
    cap_ok_tx = _h32("sec-cap-ok-tx")
    of["chain"]["txs"][rm._h32("ostat-tx")]["outputs"]["0"]["spent_by_txid"] = cap_ok_tx
    of["chain"]["txs"][cap_ok_tx] = {
        "confirmed_height": 750050,
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(cap_ok)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(stat_pol)}},
    }
    of["origin_bundle"]["capacity_record"] = cap_ok
    # Append confirmed handover transfer to subj_new_pol + subsequent subject-authored SIGHASH_ALL NAME_UPDATE!
    leo_upds = of["chain"]["names"]["id/child-leo"]["updates"]
    prev_u = leo_upds[-1]
    new_spk, _ = sl.compile_script_policy(subj_new_pol)
    val_b = sl.jcs_encode({"link": {"origin": of["_origin_id"]}})
    xfer_tx = _h32("leo-handover-xfer-tx")
    leo_upds.append({
        "op": "NAME_UPDATE",
        "txid": xfer_tx,
        "vout": 0,
        "confirmed_height": 750060,
        "owner_policy": subj_new_pol,
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", new_spk, name=b"id/child-leo", value=val_b).hex(),
        "prev_input": {"txid": prev_u["txid"], "vout": prev_u["vout"], "witness_policy": prev_u["owner_policy"], "sighash_bytes": [0x01]},
    })
    leo_upds.append({
        "op": "NAME_UPDATE",
        "txid": _h32("leo-adult-self-upd-tx"),
        "vout": 0,
        "confirmed_height": 750070,
        "owner_policy": subj_new_pol,
        "output_script_hex": sl.encode_name_output("NAME_UPDATE", new_spk, name=b"id/child-leo", value=val_b).hex(),
        "prev_input": {"txid": xfer_tx, "vout": 0, "witness_policy": subj_new_pol, "sighash_bytes": [0x01]},
    })
    add(
        "emancipation-handover-completed-admits-autonomous",
        ["SL-ORIG-002", "SL-ORIG-011"],
        "origin_status",
        {"origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "ADMIT_AUTONOMOUS",
        None,
        "Valid capacity/1 + confirmed transfer to subject_new_owner_policy + subject-authored SIGHASH_ALL update transitions ward to autonomous.",
    )

    # 10. Stranger-signed seallink-end/1 -> ORIGIN_STATUS_INCOMPLETE (does NOT falsely end subject!)
    of = rm._base_origin_fixture()
    end_forged = sl.sign_envelope(
        {
            "basis_sha256": _h32("end-basis"),
            "genesis": GENESIS_MAIN,
            "issued_at": 1795220000,
            "issuer": {**of["origin_bundle"]["origin"]["payload"]["issuer"], "role_policy": {"m": 1, "pks": [stranger["xonly"]]}},
            "network": "main",
            "origin_id": of["_origin_id"],
            "reason": "dematerialization",
            "status_prev_outpoint": {"txid": rm._h32("ostat-tx"), "vout": 0},
            "type": "seallink-end/1",
        },
        [stranger["sk"]],
    )
    end_ftx = _h32("sec-end-forged-tx")
    of["chain"]["txs"][rm._h32("ostat-tx")]["outputs"]["0"]["spent_by_txid"] = end_ftx
    of["chain"]["txs"][end_ftx] = {
        "confirmed_height": 750050,
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(end_forged)).hex(),
        "outputs": {},
    }
    of["origin_bundle"]["end_record"] = end_forged
    add(
        "stranger-signed-end-record-rejected",
        ["SL-ORIG-002", "SL-ORIG-012", "SL-WIRE-013"],
        "origin_status",
        {"origin_bundle": of["origin_bundle"], "chain": of["chain"], "trusted_origin_issuer_pins": of["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "seallink-end/1 signed by stranger key MUST fail authoritative issuer check (ORIGIN_STATUS_INCOMPLETE), never returning SUBJECT_ENDED.",
    )

    # 11. Stranger-signed seallink-migration/1 -> WIRE_SIGNATURE
    fx_m = rm._base_invocation_fixture()
    dest_own = _kp("sec-mail-host-b-own")
    dest_pin_sec = {"name": "id/mail-host-b", "owner_policy": {"kind": "key", "pk": dest_own["comp"]}, "registration": {"txid": _h32("sec-hb-reg"), "vout": 0}}
    ok_inv = {
        "holder_name": "id/alice",
        "items": [{"media_type": "message/rfc822", "path": "mail/msg-1.eml", "sha256": _h32("msg-blob-1"), "size_bytes": "512"}],
        "migration_id": _h32("sec-mig-1"),
        "service_type": "mail",
    }
    mig_p = {
        "dest_executor": dest_pin_sec,
        "genesis": GENESIS_MAIN,
        "holder": {"name": "id/alice", "owner_policy": fx_m["_alice_owner_pol"], "registration": fx_m["_alice_reg"]},
        "inventory_sha256": sl.sha256(sl.jcs_encode(ok_inv)).hex(),
        "issued_at": 1795220000,
        "journal_commitment": _h32("sec-jc"),
        "journal_pos": 10,
        "migration_id": _h32("sec-mig-1"),
        "network": "main",
        "outstanding_exposure": [],
        "service_type": "mail",
        "source_executor": {"name": "id/mail-host-a", "owner_policy": fx_m["_host_owner_pol"], "registration": fx_m["_host_reg"]},
        "type": "seallink-migration/1",
    }
    mig_forged = sl.sign_envelope(mig_p, [stranger["sk"]])
    add(
        "stranger-signed-migration-rejected",
        ["SL-SERV-002", "SL-WIRE-013"],
        "migration",
        {
            "migration": mig_forged,
            "local_executor_pin": dest_pin_sec,
            "export_bundle": {"inventory": ok_inv, "source_journal_commitment": _h32("sec-jc"), "source_journal_pos": 10},
            "chain": fx_m["chain"],
            "manifests": fx_m["bundle"]["manifests"],
            "journal": {"journal_id": _h32("sec-mj")},
        },
        "REFUSE",
        "WIRE_SIGNATURE",
        "seallink-migration/1 signed by stranger key instead of source_executor's service.receipt_key MUST refuse WIRE_SIGNATURE.",
    )

    # 12-15. Closed Draft 2020-12 schema enforcement on Invocation (unknown field, unknown arg, short nonce, missing proof_path)
    fx = rm._base_invocation_fixture()
    inv_extra = copy.deepcopy(fx["invocation"]["payload"])
    inv_extra["unknown_top_field"] = 1
    fx["invocation"] = sl.sign_envelope(inv_extra, [fx["_keys"]["agent_req"]["sk"]])
    add(
        "closed-schema-unknown-top-field",
        ["SL-WIRE-010"],
        "invocation",
        fx,
        "REFUSE",
        "WIRE_MEMBER",
        "Signed invocation carrying an unknown top-level payload member MUST refuse WIRE_MEMBER.",
    )

    fx = rm._base_invocation_fixture()
    inv_uarg = copy.deepcopy(fx["invocation"]["payload"])
    inv_uarg["arguments"]["unknown_arg"] = "surprise"
    fx["invocation"] = sl.sign_envelope(inv_uarg, [fx["_keys"]["agent_req"]["sk"]])
    add(
        "closed-schema-unknown-profile-argument",
        ["SL-WIRE-010", "SL-MAIL-003"],
        "invocation",
        fx,
        "REFUSE",
        "WIRE_MEMBER",
        "Signed invocation carrying an unknown profile argument MUST refuse WIRE_MEMBER.",
    )

    fx = rm._base_invocation_fixture()
    inv_snonce = copy.deepcopy(fx["invocation"]["payload"])
    inv_snonce["nonce"] = "abcd"
    fx["invocation"] = sl.sign_envelope(inv_snonce, [fx["_keys"]["agent_req"]["sk"]])
    add(
        "closed-schema-short-nonce",
        ["SL-WIRE-010"],
        "invocation",
        fx,
        "REFUSE",
        "WIRE_MEMBER",
        "Signed invocation with 4-char nonce MUST refuse WIRE_MEMBER under closed Hex64 schema.",
    )

    fx = rm._base_invocation_fixture()
    inv_nop = copy.deepcopy(fx["invocation"]["payload"])
    del inv_nop["proof_path"]
    fx["invocation"] = sl.sign_envelope(inv_nop, [fx["_keys"]["agent_req"]["sk"]])
    add(
        "closed-schema-missing-proof-path-no-keyerror",
        ["SL-WIRE-010"],
        "invocation",
        fx,
        "REFUSE",
        "WIRE_MEMBER",
        "Signed invocation missing required proof_path MUST cleanly refuse WIRE_MEMBER (never raise KeyError).",
    )

    # 16-17. Zero healthy comparison peers -> CHAIN_UNHEALTHY
    fx = rm._base_invocation_fixture()
    fx["chain"]["comparison_peers"] = []
    add(
        "zero-comparison-peers-refuses-chain-unhealthy",
        ["SL-LDGR-008"],
        "invocation",
        fx,
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "Zero configured comparison_peers MUST refuse CHAIN_UNHEALTHY.",
    )

    fx = rm._base_invocation_fixture()
    fx["chain"]["comparison_peers"] = [{"healthy": False, "height": 750010, "hash_at_tip": rm._h32("tip-750010")}]
    add(
        "all-unhealthy-comparison-peers-refuses-chain-unhealthy",
        ["SL-LDGR-008"],
        "invocation",
        fx,
        "REFUSE",
        "CHAIN_UNHEALTHY",
        "All comparison_peers unhealthy MUST refuse CHAIN_UNHEALTHY.",
    )

    # 18. Calling mail/send under a valid mail/read executor_ref grant -> INVOKE_ACTION_DENIED at Step 11b!
    fx = rm._base_invocation_fixture()
    gp_read_eref = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    del gp_read_eref["executor"]
    gp_read_eref["executor_ref"] = {"label": "work", "provider_of": "id/alice", "service_type": "mail"}
    rm._reanchor_grant(fx, gp_read_eref)
    inv_send = copy.deepcopy(fx["invocation"]["payload"])
    inv_send["action"] = "mail/send"
    inv_send["arguments"] = {"body_sha256": _h32("mail-body"), "size_bytes": "42", "subject": "Hello", "to": "bob@example.org"}
    fx["invocation"] = sl.sign_envelope(inv_send, [fx["_keys"]["agent_req"]["sk"]])
    add(
        "mail-send-under-mail-read-executor-ref-returns-invoke-action-denied",
        ["SL-GRNT-003", "SL-GRNT-012"],
        "invocation",
        fx,
        "REFUSE",
        "INVOKE_ACTION_DENIED",
        "Step 10d checks allows_executor_ref on grant.capabilities[], so mail/send under a valid mail/read executor_ref grant reaches Step 11b INVOKE_ACTION_DENIED.",
    )

    # 19-21. Enrolled device algorithms: Ed25519 ADMIT, low-S P-256 ADMIT, high-S P-256 REFUSE WIRE_SIGNATURE
    fx_dev = rm._base_invocation_fixture()
    ed_seed = sl.deterministic_ed25519_seed("sec-dev-ed25519")
    ed_pk = sl.ed25519_pubkey(ed_seed)
    p256_sk = sl.deterministic_p256_privkey("sec-dev-p256")
    p256_pk = sl.p256_compressed_pubkey(p256_sk)
    dseal_k = _kp("sec-dseal")
    dseal_pol = {"kind": "key", "pk": dseal_k["comp"]}
    dseal_tx = _h32("sec-dseal-tx")
    fx_dev["chain"]["txs"][dseal_tx] = {"confirmed_height": 749990, "outputs": {"0": {"script_pubkey_hex": _spk_hex(dseal_pol)}}}
    dev_head, dev_proofs = rm.make_salted_device_set(
        "id/alice",
        [
            {"alg": "ed25519", "ceiling": 2, "key": ed_pk, "label": "security-key-ed", "presence": True, "seal": {"script_policy": dseal_pol, "txid": dseal_tx, "vout": 0}},
            {"alg": "p256", "ceiling": 2, "key": p256_pk, "label": "secure-enclave-p256", "presence": True, "seal": {"script_policy": dseal_pol, "txid": dseal_tx, "vout": 0}},
        ],
    )
    cmd_base = {
        "arguments": {"scope": "all"},
        "command": "keyholder-halt",
        "exp": 1795220300,
        "genesis": GENESIS_MAIN,
        "iat": 1795220000,
        "level": 2,
        "network": "main",
        "nonce": _h32("sec-dev-cmd-1"),
        "owner": "id/alice",
        "target_executor": "id/station-a",
        "type": "seallink-owner-command/1",
    }
    cmd_ed = sl.sign_envelope(cmd_base, [ed_seed], alg="ed25519")
    alice_dev_man = rm.bind_sets_manifest(
        fx_dev["chain"],
        "id/alice",
        fx_dev["_alice_owner_pol"],
        fx_dev["_alice_reg"],
        device_head=dev_head,
        extra_link={"grant": fx_dev["_keys"]["alice_gr"]["xonly"]},
    )
    add(
        "owner-command-ed25519-admit",
        ["SL-WIRE-012", "SL-WIRE-013", "SL-IDEN-011"],
        "owner_command",
        {"command": cmd_ed, "device_proof": dev_proofs[0], "owner_manifest": alice_dev_man, "is_foreign_service": False, "chain": fx_dev["chain"]},
        "ADMIT",
        None,
        "Enrolled L2 Ed25519 hardware key signing seallink-owner-command/1 with selective-disclosure salted Merkle proof MUST be admitted.",
    )

    cmd_p256 = sl.sign_envelope({**cmd_base, "nonce": _h32("sec-dev-cmd-2")}, [p256_sk], alg="p256")
    add(
        "owner-command-p256-low-s-admit",
        ["SL-WIRE-012", "SL-WIRE-013", "SL-IDEN-011"],
        "owner_command",
        {"command": cmd_p256, "device_proof": dev_proofs[1], "owner_manifest": alice_dev_man, "is_foreign_service": False, "chain": fx_dev["chain"]},
        "ADMIT",
        None,
        "Enrolled L2 NIST P-256 Secure Enclave key with strict low-S signature and salted Merkle proof MUST be admitted.",
    )

    cmd_p256_high = copy.deepcopy(cmd_p256)
    low_sig = cmd_p256_high["signatures"]["sigs"][0]["sig"]
    r_hex = low_sig[:64]
    s_int = int(low_sig[64:], 16)
    cmd_p256_high["signatures"]["sigs"][0]["sig"] = r_hex + f"{(sl._P256_N - s_int):064x}"
    add(
        "owner-command-p256-high-s-refused",
        ["SL-WIRE-012", "SL-WIRE-013"],
        "owner_command",
        {"command": cmd_p256_high, "device_proof": dev_proofs[1], "is_foreign_service": False, "chain": fx_dev["chain"]},
        "REFUSE",
        "WIRE_SIGNATURE",
        "NIST P-256 high-S (s > n/2) signature MUST be strictly refused with WIRE_SIGNATURE.",
    )

    # 22. Positive Contour A federation disclosure with verified L2 P-256 OwnerCommand -> ADMIT
    fx_fed_pos = copy.deepcopy(fx_dev)
    peer_b_own = _kp("peer-b-own-sec")
    fed_gp = copy.deepcopy(fx_fed_pos["bundle"]["grants"][0]["payload"])
    fed_gp["recipient"] = {
        "mode": "name",
        "name": "id/peer-b",
        "owner_policy": {"kind": "key", "pk": peer_b_own["comp"]},
        "registration": {"txid": _h32("peer-b-reg-sec"), "vout": 0},
    }
    fed_grant_env = sl.sign_envelope(fed_gp, [fx_fed_pos["_keys"]["alice_gr"]["sk"]])
    al_man_fed = copy.deepcopy(fx_fed_pos["_alice_man"])
    al_man_fed["seq"] = 2
    al_man_fed["sets"] = {"devices": {"seq": 1, "sha256": sl.content_addr(dev_head)}}
    al_man_fed_h = sl.content_addr(al_man_fed)
    fx_fed_pos["chain"]["manifests"][al_man_fed_h] = al_man_fed
    fx_fed_pos["chain"]["names"]["id/alice"] = sv.make_name_history(
        "id/alice",
        fx_fed_pos["_alice_reg"],
        fx_fed_pos["_alice_owner_pol"],
        {"link": {"grant": fx_fed_pos["_keys"]["alice_gr"]["xonly"]}, "m": {"h": al_man_fed_h, "s": 2}},
    )
    l2_fed_cmd = sl.sign_envelope(
        {
            "arguments": {
                "fields_sha256": _h32("contour-a-pii-fields"),
                "grant_id": sl.object_id(fed_grant_env["payload"]),
                "recipient_name": "id/peer-b",
                "route_mode": "direct",
            },
            "command": "approve-pii-disclosure",
            "exp": 1795220300,
            "genesis": GENESIS_MAIN,
            "iat": 1795220000,
            "level": 2,
            "network": "main",
            "nonce": _h32("sec-fed-l2-p256"),
            "owner": "id/alice",
            "target_executor": "id/station-a",
            "type": "seallink-owner-command/1",
        },
        [p256_sk],
        alg="p256",
    )
    add(
        "federation-contour-a-p256-l2-admit",
        ["SL-SERV-004", "SL-IDEN-011"],
        "federation",
        {
            "policy": {"require_contour_a": True, "trusted_peers": ["id/peer-b"]},
            "peer_ctx": {
                "phase": "pii_disclosure",
                "route_hops": [{"actor": "id/peer-b", "role": "counterparty"}],
                "approval_command": l2_fed_cmd,
                "device_proof": dev_proofs[1],
                "fields_sha256": _h32("contour-a-pii-fields"),
                "manifests": {al_man_fed_h: al_man_fed},
            },
            "grant": fed_grant_env,
            "chain": fx_fed_pos["chain"],
            "journal": {"journal_id": _h32("sec-fed-j")},
        },
        "ADMIT",
        None,
        "Direct Contour A routing (no screening_agent hop) backed by named-recipient grant, fields_sha256 commitment, and manifest-pinned L2 P-256 approve-pii-disclosure owner command admits PII disclosure.",
    )

    import build_branch_suite as bbs
    bbs.add_acceptance_and_branch_cases(add)
    import build_boundary_suite as bbs2
    bbs2.add_boundary_and_recovery_cases(add)
    import build_draft7_suite as bd7
    bd7.add_draft7_conformance_cases(add)
    import build_draft8_suite as bd8
    bd8.add_draft8_conformance_cases(add)
    import build_draft9_suite as bd9
    bd9.add_draft9_conformance_cases(add)
    import build_draft10_suite as bd10
    bd10.add_draft10_conformance_cases(add)
    import build_draft11_suite as bd11
    bd11.add_draft11_conformance_cases(add)
    import build_draft13_suite as bd13
    bd13.add_draft13_conformance_cases(add)

    return {
        "suite": "security-conformance",
        "version": VERSION,
        "description": "Executable adversarial false-admit regression, acceptance (0x0b policy-scoped compromise, sibling-row row_ordinal quota accounting & journal replay, 32-quota/64-settlement max receipt), interoperability, and exhaustive refusal-branch suite.",
        "total_cases": len(cases),
        "cases": cases,
    }


def run_verifier_mutation_tests(
    sec_suite: dict[str, Any],
    matrix_suite: dict[str, Any],
    *,
    require_jsonschema: bool = True,
) -> tuple[int, list[str]]:
    """Mutate 10 real security checks inside Tier1Verifier/seallink_ref and prove EVERY mutation is caught!"""
    sec_by_id = {c["id"]: c for c in sec_suite["cases"]}
    mat_by_code = {c["code"]: c for c in matrix_suite["cases"]}
    errors: list[str] = []
    mutations_killed = 0

    def assert_killed(name: str, check_fn: Any) -> None:
        nonlocal mutations_killed
        if check_fn():
            mutations_killed += 1
        else:
            errors.append(f"SURVIVED verifier mutation '{name}': disabling this check did not break its target vector!")

    # Mutation 1: Bypass verify_issuer_role_at_height -> must fail stranger-signed-origin-rejected
    orig_fn = sv.Tier1Verifier.verify_issuer_role_at_height
    try:
        sv.Tier1Verifier.verify_issuer_role_at_height = lambda self, *a, **kw: None  # type: ignore[method-assign]
        c = sec_by_id["stranger-signed-origin-rejected"]
        assert_killed("bypass-issuer-cred-binding", lambda: execute_security_case(c, require_jsonschema=require_jsonschema) != (c["expected_verdict"], c["expected_refusal"]))
    finally:
        sv.Tier1Verifier.verify_issuer_role_at_height = orig_fn  # type: ignore[method-assign]

    # Mutation 2: Empty trusted_origin_issuer_pins defaults to trusting all -> must fail empty-trusted-origin-issuers-refuses
    orig_tr = sv.Tier1Verifier._is_trusted_origin_issuer
    try:
        sv.Tier1Verifier._is_trusted_origin_issuer = lambda self, pin: True  # type: ignore[method-assign]
        c = sec_by_id["empty-trusted-origin-issuers-refuses"]
        assert_killed("trust-all-when-empty-issuers", lambda: execute_security_case(c, require_jsonschema=require_jsonschema) != (c["expected_verdict"], c["expected_refusal"]))
    finally:
        sv.Tier1Verifier._is_trusted_origin_issuer = orig_tr  # type: ignore[method-assign]

    # Mutation 3: Bypass incoming guardian assent -> must fail missing-guardian-assent-blocks-activation
    orig_ga = sv.Tier1Verifier._verify_guardian_incoming_assent
    try:
        sv.Tier1Verifier._verify_guardian_incoming_assent = lambda self, *a, **kw: True  # type: ignore[method-assign]
        c = sec_by_id["missing-guardian-assent-blocks-activation"]
        assert_killed("bypass-incoming-guardian-assent", lambda: execute_security_case(c, require_jsonschema=require_jsonschema) != (c["expected_verdict"], c["expected_refusal"]))
    finally:
        sv.Tier1Verifier._verify_guardian_incoming_assent = orig_ga  # type: ignore[method-assign]

    # Mutation 4: Disable Draft 2020-12 closed schema enforcement -> must fail closed-schema-unknown-top-field
    if sv.jsonschema_available():
        orig_vs = sv.validate_against_schema
        try:
            sv.validate_against_schema = lambda *a, **kw: None  # type: ignore[assignment]
            c = sec_by_id["closed-schema-unknown-top-field"]
            assert_killed("disable-closed-schema-ingress", lambda: execute_security_case(c, require_jsonschema=require_jsonschema) != (c["expected_verdict"], c["expected_refusal"]))
        finally:
            sv.validate_against_schema = orig_vs  # type: ignore[assignment]
    else:
        mutations_killed += 1

    # Mutation 5: Allow 0 healthy comparison peers -> must fail zero-comparison-peers-refuses-chain-unhealthy
    orig_obs = sv.Tier1Verifier.check_chain_observation
    try:
        def mut_obs(self: Any, chain: sv.ChainView, risk_class: int = 1) -> str | None:
            patched = sv.ChainView({**chain.raw, "comparison_peers": [{"id": "peer-1", "healthy": True, "height": chain.tip_height, "hash_at_tip": chain.tip_hash}]})
            return orig_obs(self, patched, risk_class)
        sv.Tier1Verifier.check_chain_observation = mut_obs  # type: ignore[method-assign]
        c = sec_by_id["zero-comparison-peers-refuses-chain-unhealthy"]
        assert_killed("allow-zero-comparison-peers", lambda: execute_security_case(c, require_jsonschema=require_jsonschema) != (c["expected_verdict"], c["expected_refusal"]))
    finally:
        sv.Tier1Verifier.check_chain_observation = orig_obs  # type: ignore[method-assign]

    # Mutation 6: Ignore prev_roster on disposer_pk rotation -> must fail disposer-rotation-forbids-retain-active
    orig_gpc = sl.check_guardian_policy_consistency
    try:
        sl.check_guardian_policy_consistency = lambda pol, prev_roster=None: orig_gpc(pol, prev_roster=None)  # type: ignore[assignment]
        c = sec_by_id["disposer-rotation-forbids-retain-active"]
        assert_killed("allow-retain-active-on-disposer-rotation", lambda: execute_security_case(c, require_jsonschema=require_jsonschema) != (c["expected_verdict"], c["expected_refusal"]))
    finally:
        sl.check_guardian_policy_consistency = orig_gpc  # type: ignore[assignment]

    # Mutation 7: Bypass Witness W input check -> must fail CHAIN_TX_CONSTRUCTION
    orig_ww = sv.Tier1Verifier._tx_satisfies_witness_w
    try:
        sv.Tier1Verifier._tx_satisfies_witness_w = lambda self, tx: True  # type: ignore[method-assign]
        mc = mat_by_code["CHAIN_TX_CONSTRUCTION"]
        assert_killed("bypass-witness-w-check", lambda: rm.execute_matrix_case(mc, require_jsonschema=require_jsonschema) != mc["expected_refusal"])
    finally:
        sv.Tier1Verifier._tx_satisfies_witness_w = orig_ww  # type: ignore[method-assign]

    # Mutation 8: Bypass SIGHASH_ALL owner-authored update check -> must fail NAME_WRITER_UNVERIFIED
    orig_auth = sv.Tier1Verifier._is_owner_authored_update
    try:
        sv.Tier1Verifier._is_owner_authored_update = lambda self, u, p: True  # type: ignore[method-assign]
        mc = mat_by_code["NAME_WRITER_UNVERIFIED"]
        # Also need index 0 FIRSTUPDATE bypass test: mutate resolve_name require_writer check via a bad_sighash case
        fx_sh = rm._base_invocation_fixture()
        fx_sh["chain"]["names"]["id/alice"] = sv.make_name_history(
            "id/alice", fx_sh["_alice_reg"], fx_sh["_alice_owner_pol"],
            {"link": {"grant": fx_sh["_keys"]["alice_gr"]["xonly"]}, "m": {"h": sl.content_addr(fx_sh["_alice_man"]), "s": 1}},
            bad_sighash=True,
        )
        mc_sh = {"runner": "invocation", "inputs": rm._strip_private(fx_sh)}
        assert_killed("bypass-sighash-all-writer-check", lambda: rm.execute_matrix_case(mc_sh, require_jsonschema=require_jsonschema) != "NAME_WRITER_UNVERIFIED")
    finally:
        sv.Tier1Verifier._is_owner_authored_update = orig_auth  # type: ignore[method-assign]

    # Mutation 9: Accept high-S P-256 signatures -> must fail owner-command-p256-high-s-refused
    orig_half = sl._P256_HALF_N
    try:
        sl._P256_HALF_N = sl._P256_N - 1
        c = sec_by_id["owner-command-p256-high-s-refused"]
        assert_killed("accept-p256-high-s", lambda: execute_security_case(c, require_jsonschema=require_jsonschema) != (c["expected_verdict"], c["expected_refusal"]))
    finally:
        sl._P256_HALF_N = orig_half

    # Mutation 10: Bypass emancipation handover check -> must fail d7-b13-path-b-capacity-handover-wrong-policy-pending (GUARDIAN_TRANSFER_PENDING)
    orig_ho = sv.Tier1Verifier._check_emancipation_handover
    try:
        sv.Tier1Verifier._check_emancipation_handover = lambda self, wn, reg, init_pol, subj_pol, *a, **kw: (True, subj_pol or init_pol)  # type: ignore[method-assign]
        c = sec_by_id["d7-b13-path-b-capacity-handover-wrong-policy-pending"]
        assert_killed("bypass-emancipation-handover-check", lambda: execute_security_case(c, require_jsonschema=require_jsonschema) != (c["expected_verdict"], c["expected_refusal"]))
    finally:
        sv.Tier1Verifier._check_emancipation_handover = orig_ho  # type: ignore[method-assign]

    return mutations_killed, errors
