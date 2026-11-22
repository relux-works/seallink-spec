#!/usr/bin/env python3
"""
SealLink Specification Consistency, Schema, and Cryptographic Vector Linter.

Validates:
  1. All JSON files in registry/, schemas/, and vectors/ are valid JSON.
  2. Every cross-file and local $ref in schemas/*.schema.json resolves.
  3. Every schema target in registry/object-types.json resolves.
  4. Cross-registry signer coherence between object-types.json and key-roles.json.
  5. Every SL-<AREA>-<NNN> rule ID across spec/ and profiles/ is uniquely declared,
     and every referenced SL-* ID is declared.
  6. Every seallink-*/1 type and refusal code cited in spec/ and profiles/ is registered.
  7. Every SPEC-*.md carries Status, Evidence / Maturity, References, and Security Considerations.
  8. Every object-types.json schema target defines the matching type const discriminator.
  9. Full cryptographic & structural re-verification of all vectors/*.json via seallink_ref.py.
 10. Full Draft 2020-12 metaschema + instance validation of all vectors (when jsonschema is
     installed, or required when --require-jsonschema is passed in CI).
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

import seallink_ref as sl

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
NON_REFUSAL_IDENTIFIERS = frozenset({
    "NAME_NEW",
    "NAME_FIRSTUPDATE",
    "NAME_UPDATE",
    "NAME_BINDING",
    "RECOVERY_CANCEL",
    "GRANT_ISSUANCE",
    "GRANT_VIOLATION_TERMINATION",
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


def find_type_consts(node: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        props = node.get("properties", {})
        if "type" in props and isinstance(props["type"], dict) and "const" in props["type"]:
            found.add(props["type"]["const"])
        if "payload" in props:
            found |= find_type_consts(props["payload"])
        for k in ("oneOf", "anyOf", "allOf"):
            for sub in node.get(k, []):
                found |= find_type_consts(sub)
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
            if k in ("negative_schema_fixtures", "negative_semantic_fixtures", "negative_signaturesets"):
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


def verify_all_vectors(vectors: dict[str, dict[str, Any]], errors: list[str]) -> int:
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

    # 3. constraints-and-schemas.json
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
                target_obj = node.get("name_pin") or node.get("clause")
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

    for tname in ("trace-01-mail-offline-revoke.json", "trace-02-guardian-succession-assent.json", "trace-03-delegation-pool-single-use.json"):
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

    return checked


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
    for sname, sdoc in schemas.items():
        try:
            Draft202012Validator.check_schema(sdoc)
        except Exception as exc:
            errors.append(f"Metaschema failure in schemas/{sname}: {exc}")
        uri = sdoc.get("$id", f"https://seallink.org/schemas/v1/{sname}")
        resources.append((uri, Resource.from_contents(sdoc, default_specification=DRAFT202012)))
    registry = Registry().with_resources(resources)

    def get_validator(schema_ref: str) -> Draft202012Validator:
        if "#" in schema_ref:
            spath, ptr = schema_ref.split("#", 1)
            sub = {"$ref": f"https://seallink.org/schemas/v1/{Path(spath).name}#{ptr}"}
        else:
            sub = {"$ref": f"https://seallink.org/schemas/v1/{Path(schema_ref).name}"}
        return Draft202012Validator(sub, registry=registry)

    validated = 0
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
    return True, validated


def main() -> int:
    parser = argparse.ArgumentParser(description="SealLink specification consistency, schema, and vector linter.")
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
                consts = find_type_consts(target_node)
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
            # Declaration pattern 1: first column of a rule table
            table_match = re.match(r"^\|\s*`(SL-[A-Z]+-\d{3})`\s*\|", line)
            declared: list[str] = [table_match.group(1)] if table_match else []
            # Declaration pattern 2: parenthesized group ending with `, `decided`` or `, `open``
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
            if c.endswith("_") or c in NON_REFUSAL_IDENTIFIERS:
                continue
            used_codes.add(c)
            if c not in registered_codes:
                errors.append(f"{rel}: unregistered refusal code '{c}'")

    for rid, loc in referenced_rules:
        if rid not in rule_locations:
            errors.append(f"Undeclared Rule ID referenced: {rid} at {loc}")

    # 6. Check all registry files share the same protocol version string
    reg_versions = {name: data.get("version") for name, data in registries.items() if "version" in data}
    if len(set(reg_versions.values())) > 1:
        errors.append(f"Inconsistent version strings across registry/*.json: {reg_versions}")

    # 7. Load and cryptographically verify vectors/
    vectors: dict[str, dict[str, Any]] = {}
    for p in sorted((ROOT / "vectors").glob("*.json")):
        data = load_json(p, errors)
        if data is not None:
            vectors[p.name] = data
    if not vectors:
        errors.append("No conformance vector files found under vectors/")
    vector_checks = verify_all_vectors(vectors, errors)

    # 8. Draft 2020-12 metaschema & instance validation
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
        f"{len(registered_codes)} refusal codes | "
        f"{len(schemas)} schemas | "
        f"{len(vectors)} vector suites ({vector_checks} crypto/logic checks"
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
