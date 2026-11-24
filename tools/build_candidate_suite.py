#!/usr/bin/env python3
"""
Review-candidate negative vectors for the v1.0.0-draft.7 Blocker findings of the second review round.

Builds and checks `conformance/review-candidates/draft7-blockers.json`. Every case has the exact shape of a
`vectors/security-conformance.json` case (same runners, executed by `build_security_suite.execute_security_case`,
which never reads `expected_*`) plus a `candidate` block describing its role.

Findings (ids of the second-round report): R2G-01, R2G-02, R2G-03, G7-01, G7-02, G7-03, R2-03 and R2-01 (also N-1).

The suite is NOT normative and deliberately lives outside `vectors/`: every witness is still admitted (or refused with
another code) by the draft.7 Reference Verifier Core, and several items need an authors' decision before a single
expected result exists.

Case roles (`candidate.role`):
  control   passes on the reference today and must keep passing; pairs every witness with a nearby valid case so that
            an implementation refusing everything cannot satisfy the suite.
  witness   `expected_*` is what the cited specification text requires (`candidate.also_acceptable` lists other results
            the text equally permits); `candidate.reference_result` is what the draft.7 reference returns today (a false
            ADMIT, or a refusal with a different code).
  decision  the specification text and published vectors (or two readings of the text) require different results;
            `candidate.readings` lists them. Counted separately, never as open or closed.

Modes:
  --check   (default) regenerate in memory, require byte equality with the committed JSON, INDEX.md and SHA256SUMS,
            execute every committed case, require every control to pass and every witness/decision to behave exactly as
            recorded (ratchet: a behaviour change must be acknowledged by promoting or updating the case).
  --strict  target state instead of the ratchet: every control passes and every witness returns an accepted result;
            decision records are executed and listed but not judged. Fails while any witness is open.
  --write   regenerate the JSON, INDEX.md and SHA256SUMS.
  --list    only execute the committed cases and print the per-case table.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

import build_refusal_matrix as rm
import build_security_suite as sec
import seallink_ref as sl
import seallink_verifier as sv

ROOT = Path(__file__).resolve().parent.parent
SUITE_DIR = ROOT / "conformance" / "review-candidates"
SUITE_NAME = "draft7-blockers.json"
SUITE_PATH = SUITE_DIR / SUITE_NAME
INDEX_PATH = SUITE_DIR / "INDEX.md"
SUMS_PATH = SUITE_DIR / "SHA256SUMS"
SUMMED_FILES = ("INDEX.md", "README.md", SUITE_NAME)
VERSION = rm.VERSION
G = rm.GENESIS_MAIN
REFERENCE_TAG = "v1.0.0-draft.7"
REFERENCE_LABEL = "draft.7"
REFERENCE_COMMIT = "6a5ab8107fcf0be8091252a26c11529fe60a5ee6"

ROLES = ("control", "witness", "decision")
CODE_STATUS = {
    "text": "The refusal code is named by the cited rule or by its registry description for exactly this condition.",
    "derived": (
        "No rule names a code for this exact condition, but the text makes the result equal to that of a paired control: "
        "the varied element cannot change the subject's state (a presenter-supplied or presenter-withheld element, while "
        "the state is defined by chain events), or the same admission pipeline runs on the same grant. The expected result "
        "is therefore the paired control's. Where failing closed on the element itself is equally defensible, that result "
        "is listed in also_acceptable."
    ),
    "undefined": (
        f"{REFERENCE_LABEL} defines no admission step or refusal code for this condition: expected_refusal is null, only "
        "the verdict is compared, and candidate.proposed_refusal is informative."
    ),
}

Verdict = tuple[str, str | None]

# Published inputs and fixtures used below.
TRACE_02 = "trace-02-guardian-succession-assent.json"
TRACE_03 = "trace-03-delegation-pool-single-use.json"
WARD_NAME = "id/child-leo"  # the ward of rm._base_origin_fixture()


# ---------------------------------------------------------------------------
# Deterministic helpers
# ---------------------------------------------------------------------------

def _h32(label: str) -> str:
    return sl.sha256(f"seallink-candidate-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    """A key that exists only in this suite."""
    sk = sl.deterministic_privkey(f"candidate:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _key_pol(kp: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "key", "pk": kp["comp"]}


def _spk(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


_VECTOR_CACHE: dict[str, Any] = {}


def _vector(name: str) -> Any:
    """A deep copy of a published `vectors/*.json` suite."""
    if name not in _VECTOR_CACHE:
        _VECTOR_CACHE[name] = json.loads((ROOT / "vectors" / name).read_text(encoding="utf-8"))
    return copy.deepcopy(_VECTOR_CACHE[name])


def _published_case(case_id: str) -> dict[str, Any]:
    for case in _vector("security-conformance.json")["cases"]:
        if case["id"] == case_id:
            return case
    raise KeyError(case_id)


def _published_ids(predicate: Callable[[dict[str, Any], str], bool]) -> list[str]:
    """Ids of published security-conformance cases matching `predicate(case, json_of_inputs)`, in file order."""
    out = []
    for case in _vector("security-conformance.json")["cases"]:
        if predicate(case, json.dumps(case["inputs"], sort_keys=True)):
            out.append(case["id"])
    assert out, "a decision record must name at least one published case it conflicts with"
    return out


_RULES: set[str] = set()


def _declared_rules() -> set[str]:
    """Rule ids declared in spec/ and profiles/, with the declaration grammar of `speclint.py`."""
    if not _RULES:
        rid = re.compile(r"`(SL-[A-Z]+-\d{3})`")
        files = sorted((ROOT / "spec").glob("SPEC-*.md")) + sorted((ROOT / "profiles").glob("PROFILE-*.md"))
        for path in files:
            for line in path.read_text(encoding="utf-8").splitlines():
                row = re.match(r"^\|\s*`(SL-[A-Z]+-\d{3})`\s*\|", line)
                if row:
                    _RULES.add(row.group(1))
                for group in re.findall(r"\(([^()\n]+?)\)", line):
                    if re.search(r",\s*`(?:decided|open)`", group):
                        _RULES.update(rid.findall(group))
    return _RULES


def _issuance_opret(grant_env: dict[str, Any]) -> str:
    """The 0x01 commitment exactly as the reference reconstructs it (`seallink_verifier.py`, step 10c)."""
    p = grant_env["payload"]
    prep = {
        "genesis": p["genesis"],
        "grant_content_addr": sl.content_addr(grant_env),
        "grant_id": sl.object_id(p),
        "type": "seallink-issuance/1",
    }
    if "contract_id" in p:
        prep["contract_id"] = p["contract_id"]
    return sl.encode_opreturn(0x01, sl.signing_digest(prep).hex(), 0x00).hex()


def _anchor_root_grant(chain: dict[str, Any], grant_env: dict[str, Any], tag: str) -> str:
    """Materialise the seal UTXO (vout 0), its linkage output (vout 1) and a Witness-W 0x01 anchor spending the linkage."""
    seal = grant_env["payload"]["revocation"]["seal"]
    assert seal["vout"] == 0
    itx = _h32(f"{tag}-issuance-tx")
    chain["txs"][seal["txid"]] = {
        "confirmed_height": 749995,
        "inputs": [sv.make_segwit_input(_h32(f"{tag}-funding-tx"), 0)],
        "outputs": {
            "0": {"script_pubkey_hex": _spk(seal["script_policy"])},
            "1": {"script_pubkey_hex": _spk(seal["script_policy"])},
        },
    }
    chain["txs"][itx] = {
        "confirmed_height": 749998,
        "inputs": [sv.make_segwit_input(seal["txid"], 1)],
        "opreturn_hex": _issuance_opret(grant_env),
        "outputs": {},
    }
    return itx


def _revocation(seal_kp: dict[str, Any], tag: str) -> dict[str, Any]:
    return {
        "construction": "W",
        "kind": "revocable",
        "mode": "seal",
        "seal": {"script_policy": _key_pol(seal_kp), "txid": _h32(f"{tag}-seal-tx"), "vout": 0},
    }


def _root_grant(chain: dict[str, Any], payload: dict[str, Any], signer: dict[str, Any], tag: str) -> tuple[dict[str, Any], str, str]:
    """Sign a root grant with a fresh revocation seal and anchor it; returns (envelope, grant_id, issuance_txid)."""
    payload = copy.deepcopy(payload)
    payload["revocation"] = _revocation(_kp(f"{tag}-seal"), tag)
    env = sl.sign_envelope(payload, [signer["sk"]])
    return env, sl.object_id(payload), _anchor_root_grant(chain, env, tag)


def _add_name(chain: dict[str, Any], name: str, tag: str) -> dict[str, Any]:
    """Register an unrelated autonomous name (owner key + one grant-role key) and return its issuer pin."""
    owner, grant_key = _kp(f"{tag}-owner"), _kp(f"{tag}-grant")
    policy = _key_pol(owner)
    registration = {"txid": _h32(f"{tag}-registration"), "vout": 0}
    chain["names"][name] = sv.make_name_history(
        name, registration, policy, {"link": {"grant": grant_key["xonly"]}}, first_height=748000, update_height=749000
    )
    pin = {"name": name, "owner_policy": policy, "registration": registration, "role_policy": {"m": 1, "pks": [grant_key["xonly"]]}}
    return {"pin": pin, "grant_key": grant_key}


def _invocation(
    fx: dict[str, Any],
    grant_id: str,
    issuance_txid: str,
    action: str,
    target: str,
    arguments: dict[str, Any],
    signer: dict[str, Any],
    tag: str,
    *,
    exp: int = 1795220300,
) -> dict[str, Any]:
    cfg = fx["executor_cfg"]
    return sl.sign_envelope(
        {
            "action": action,
            "arguments": arguments,
            "executor": {"key": cfg["key"], "name": cfg["name"]},
            "exp": exp,
            "genesis": G,
            "iat": 1795220000,
            "network": "main",
            "nonce": _h32(f"{tag}-nonce"),
            "proof_path": [{"grant_id": grant_id, "issuance_txid": issuance_txid}],
            "target": target,
            "type": "seallink-invocation/1",
        },
        [signer["sk"]],
    )


def _trace02_origin_bundle(t2: dict[str, Any]) -> dict[str, Any]:
    """The origin bundle of the published trace-02, exactly as `speclint.py` presents it."""
    return {
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


# ---------------------------------------------------------------------------
# Suite builder
# ---------------------------------------------------------------------------

class CandidateSuite:
    """Collects cases. With `verify` (the `--write` path) every case is executed through the reference at build time and
    must match its record; `--check` rebuilds the bytes with `verify=False` and classifies the committed cases instead,
    so that a behaviour change is reported per case rather than as the first failed assertion."""

    def __init__(self, *, verify: bool = True) -> None:
        self.verify = verify
        self.cases: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self._ids: set[str] = set()
        self._finding: str | None = None

    def finding(self, fid: str, title: str, where: list[str]) -> None:
        self._finding = fid
        self.findings.append({"id": fid, "title": title, "where": where})

    def _add(self, cid: str, rules: list[str], runner: str, inputs: dict[str, Any], expected: Verdict, note: str, candidate: dict[str, Any]) -> dict[str, Any]:
        assert self._finding is not None
        assert cid.startswith("cand-") and cid not in self._ids, cid
        assert rules and set(rules) <= _declared_rules(), (cid, sorted(set(rules) - _declared_rules()))
        self._ids.add(cid)
        case = {
            "id": cid,
            "rules": rules,
            "runner": runner,
            "inputs": rm._strip_private(inputs),
            "expected_verdict": expected[0],
            "expected_refusal": expected[1],
            "note": note,
            "candidate": {"finding": self._finding, **candidate},
        }
        json.dumps(case)  # must be plain JSON
        self.cases.append(case)
        return case

    def control(self, cid: str, rules: list[str], runner: str, inputs: dict[str, Any], expected: Verdict, note: str) -> str:
        case = self._add(cid, rules, runner, inputs, expected, note, {"role": "control"})
        if self.verify:
            observed = sec.execute_security_case(case)
            assert observed == expected, f"control {cid}: expected {expected}, reference returned {observed}"
        return cid

    def witness(
        self,
        cid: str,
        rules: list[str],
        runner: str,
        inputs: dict[str, Any],
        expected: Verdict,
        note: str,
        *,
        reference: Verdict,
        code_status: str,
        basis: str,
        controls: list[str],
        proposed_refusal: str | None = None,
        also_acceptable: list[tuple[str, str | None, str]] | None = None,
    ) -> str:
        assert code_status in CODE_STATUS, code_status
        assert (expected[1] is None) == (code_status == "undefined" or expected[0] != "REFUSE"), (cid, expected, code_status)
        assert (proposed_refusal is not None) == (code_status == "undefined"), (cid, "proposed_refusal goes with status undefined")
        assert controls and all(c in self._ids for c in controls), (cid, controls)
        cand: dict[str, Any] = {
            "role": "witness",
            "refusal_code_status": code_status,
            "basis": basis,
            "control_ids": controls,
            "reference_result": {"verdict": reference[0], "refusal": reference[1]},
        }
        if proposed_refusal is not None:
            cand["proposed_refusal"] = proposed_refusal
        if also_acceptable:
            assert code_status != "undefined" and all((v, c) != expected for v, c, _ in also_acceptable), cid
            cand["also_acceptable"] = [{"verdict": v, "refusal": c, "why": why} for v, c, why in also_acceptable]
        case = self._add(cid, rules, runner, inputs, expected, note, cand)
        assert not is_satisfied(case, reference), f"witness {cid}: the recorded reference behaviour already satisfies the expectation"
        if self.verify:
            observed = sec.execute_security_case(case)
            assert observed == reference, (
                f"witness {cid}: recorded reference behaviour {reference}, reference returned {observed}"
                + ("; the finding looks fixed: promote the case to vectors/ and remove it here" if is_satisfied(case, observed) else "")
            )
        return cid

    def decision(
        self,
        cid: str,
        rules: list[str],
        runner: str,
        inputs: dict[str, Any],
        note: str,
        *,
        reference: Verdict,
        question: str,
        readings: list[dict[str, Any]],
        conflicts_with: list[str] | None = None,
    ) -> str:
        assert len(readings) >= 2 and all({"reading", "source", "verdict", "refusal"} <= set(r) for r in readings), cid
        assert len({(r["verdict"], r["refusal"]) for r in readings}) == len(readings), f"decision {cid}: readings must differ in result"
        cand: dict[str, Any] = {
            "role": "decision",
            "question": question,
            "readings": readings,
            "reference_result": {"verdict": reference[0], "refusal": reference[1]},
        }
        if conflicts_with:
            cand["conflicts_with"] = conflicts_with
        case = self._add(cid, rules, runner, inputs, (readings[0]["verdict"], readings[0]["refusal"]), note, cand)
        if self.verify:
            observed = sec.execute_security_case(case)
            assert observed == reference, f"decision {cid}: recorded reference behaviour {reference}, reference returned {observed}"
        return cid


def is_satisfied(case: dict[str, Any], observed: Verdict) -> bool:
    """Does a result meet the case expectation? Accepted: `expected_*` or any `also_acceptable` entry; a witness with an
    `undefined` code status compares the verdict only."""
    cand = case["candidate"]
    if cand.get("refusal_code_status") == "undefined":
        return observed[0] == case["expected_verdict"]
    accepted = [(case["expected_verdict"], case["expected_refusal"])]
    accepted += [(alt["verdict"], alt["refusal"]) for alt in cand.get("also_acceptable", [])]
    return observed in accepted


# ---------------------------------------------------------------------------
# R2G-01  withheld recovery candidate (regression of D-1)
# ---------------------------------------------------------------------------

def build_r2g01(s: CandidateSuite) -> None:
    s.finding(
        "R2G-01",
        "A withheld recovery candidate keeps the superseded (or recovery-frozen) name binding B1 in force: regression of D-1",
        [
            "spec/SPEC-04 §6 Recovery Seal State Transition Table (SL-ORIG-013, SL-ORIG-014)",
            "CONFORMANCE.md §2 item 5",
            f"tools/seallink_verifier.py:2316-2356 ({REFERENCE_LABEL})",
        ],
    )
    rules = ["SL-ORIG-013", "SL-ORIG-014"]
    t2 = _vector(TRACE_02)
    bundle = _trace02_origin_bundle(t2)
    nr = t2["name_recovery_positive_traces"]
    branch_b = nr["branch_b_post_delay_recovery_promotes_b3"]
    candidates = [nr["candidate_b2"]["object"], nr["candidate_b3"]["object"]]
    b1 = sl.object_id(t2["name_binding"]["object"])
    trusted = t2["trusted_origin_issuers"]
    post_delay = branch_b["chain_state"]

    # The same branch observed while the B3 recovery is still pending: tip between the last 0x0c record and h_rec + delay.
    def action(tx: dict[str, Any]) -> str | None:
        return sl.decode_opreturn(bytes.fromhex(tx["opreturn_hex"]))["action"] if tx.get("opreturn_hex") else None

    h_rec = max(tx["confirmed_height"] for tx in post_delay["txs"].values() if action(tx) == "0x0c")
    delay = t2["origin"]["object"]["payload"]["name_recovery"]["delay_blocks"]
    pending_tip = h_rec + delay // 2
    assert h_rec < pending_tip < h_rec + delay <= post_delay["tip_height"], (h_rec, delay, post_delay["tip_height"])
    pending = copy.deepcopy(post_delay)
    pending["tip_height"] = pending_tip
    for peer in pending["comparison_peers"]:
        peer["height"] = pending_tip
    pending["txs"] = {txid: tx for txid, tx in pending["txs"].items() if (tx.get("confirmed_height") or 0) <= pending_tip}

    def status(chain: dict[str, Any], *, presented: bool, assert_b1: bool) -> dict[str, Any]:
        ob = {**bundle, "recovery_bindings": candidates} if presented else dict(bundle)
        inputs: dict[str, Any] = {"chain": chain, "origin_bundle": ob, "trusted_origin_issuers": trusted}
        if assert_b1:
            inputs["assert_binding_id"] = b1
        return inputs

    basis = (
        "SPEC-04 §6 Recovery Seal State Transition Table: a valid 0x0c spend of recovery_seal moves the origin to "
        "pending_recovery (RECOVERY_FORBIDDEN); once h_rec + delay_blocks passes without a valid 0x10 cancel, B_{k+1} is active "
        "and B_k is superseded (ORIGIN_BINDING_INVALID); only a malformed spend or a recovery_seal 'absent from UTXO without "
        "valid 0x0c record' burns the recovery line and lets B_k continue. The 0x0c record here is the one the paired control "
        "verifies; whether it is valid is a property of the chain, and CONFORMANCE.md §2 item 5 says a verifier 'MUST NOT "
        "accept ledger state, block heights, or UTXO spend status from the presenter or issuer'. Withholding the candidate "
        "document therefore cannot turn the recovery into a burned one: the expected result is the paired control's."
    )
    fail_closed = (
        "Fail closed on the withheld document: recovery_seal was spent by a 0x0c record whose committed candidate binding is "
        "not presented. draft.6 returned this code here, and the registry description of ORIGIN_STATUS_INCOMPLETE covers the "
        "analogous spent status_seal / roster_seal whose record is not presented."
    )

    c_b3 = s.control(
        "cand-r2g01-control-branch-b-candidates-presented-b3-active",
        rules,
        "origin_status",
        status(post_delay, presented=True, assert_b1=False),
        ("ADMIT_WARD", None),
        "Published trace-02 branch B exactly as speclint.py executes it: both candidates presented, the 0x0c recovery to B3 "
        "has passed its delay, B3 is the active binding.",
    )
    c_b1 = s.control(
        "cand-r2g01-control-branch-b-assert-b1-candidates-presented-refuses",
        rules,
        "origin_status",
        status(post_delay, presented=True, assert_b1=True),
        ("REFUSE", "ORIGIN_BINDING_INVALID"),
        "Published trace-02 branch B, asserting the superseded B1: expected_superseded_b1_refusal of the trace.",
    )
    s.witness(
        "cand-r2g01-branch-b-assert-b1-candidates-withheld",
        rules,
        "origin_status",
        status(post_delay, presented=False, assert_b1=True),
        ("REFUSE", "ORIGIN_BINDING_INVALID"),
        "The same chain and the same assertion of B1, but the presenter leaves recovery_bindings out of the origin bundle. "
        "The reference classifies the spent recovery_seal as burned and treats B1 as still active.",
        reference=("ADMIT_WARD", None),
        code_status="derived",
        basis=basis,
        controls=[c_b1, c_b3],
        also_acceptable=[("REFUSE", "ORIGIN_STATUS_INCOMPLETE", fail_closed)],
    )
    c_pending = s.control(
        "cand-r2g01-control-pending-recovery-assert-b1-candidates-presented-refuses",
        rules,
        "origin_status",
        status(pending, presented=True, assert_b1=True),
        ("REFUSE", "RECOVERY_FORBIDDEN"),
        f"Published trace-02 branch B observed at tip {pending_tip} (peers moved with it, later transactions dropped): "
        f"{pending_tip - h_rec} blocks after the 0x0c record at {h_rec}, before h_rec + delay_blocks = {h_rec + delay}. "
        "The recovery is pending and B1 is frozen.",
    )
    s.witness(
        "cand-r2g01-pending-recovery-assert-b1-candidates-withheld",
        rules,
        "origin_status",
        status(pending, presented=False, assert_b1=True),
        ("REFUSE", "RECOVERY_FORBIDDEN"),
        "The pending state of the previous control with recovery_bindings withheld: the reference lets B1 act while its "
        "recovery is pending.",
        reference=("ADMIT_WARD", None),
        code_status="derived",
        basis=basis,
        controls=[c_pending, c_b3],
        also_acceptable=[("REFUSE", "ORIGIN_STATUS_INCOMPLETE", fail_closed)],
    )

    assent_rules = rules + ["SL-CONT-004"]
    verdict = t2["assent_verdicts"][2]
    assert verdict["id"] == "active-successor-guardian-admitted" and verdict["expected_verdict"] == "ADMIT", verdict["id"]

    def assent(chain: dict[str, Any], *, presented: bool) -> dict[str, Any]:
        ob = {**bundle, "recovery_bindings": candidates} if presented else dict(bundle)
        return {"assent": verdict["assent"]["object"], "contract": t2["contract"]["object"], "origin_bundle": ob, "chain": chain, "trusted_origin_issuers": trusted}

    c_assent = s.control(
        "cand-r2g01-control-assent-before-recovery-admits",
        assent_rules,
        "assent",
        assent(t2["chain_state"], presented=False),
        ("ADMIT", None),
        "Published trace-02 assent 'active-successor-guardian-admitted' on the trace's main chain, where B1 is active.",
    )
    c_assent_b3 = s.control(
        "cand-r2g01-control-assent-after-recovery-candidates-presented-refuses",
        assent_rules,
        "assent",
        assent(post_delay, presented=True),
        ("REFUSE", "ORIGIN_BINDING_INVALID"),
        "The same guardian assent for the ward bound by B1, evaluated on the branch B chain with both candidates presented.",
    )
    s.witness(
        "cand-r2g01-assent-after-recovery-candidates-withheld",
        assent_rules,
        "assent",
        assent(post_delay, presented=False),
        ("REFUSE", "ORIGIN_BINDING_INVALID"),
        "The same assent on the branch B chain with recovery_bindings withheld: the guardians of the superseded binding still "
        "assent for the ward.",
        reference=("ADMIT", None),
        code_status="derived",
        basis=basis,
        controls=[c_assent_b3, c_assent],
        also_acceptable=[("REFUSE", "ORIGIN_STATUS_INCOMPLETE", fail_closed)],
    )


# ---------------------------------------------------------------------------
# R2G-02  Path A emancipation without a handover
# ---------------------------------------------------------------------------

def build_r2g02(s: CandidateSuite) -> None:
    s.finding(
        "R2G-02",
        "Path A: a round trip of the ward name through another key before T makes the origin autonomous at T, while the name "
        "is held by the guardians' owner_policy again",
        [
            "spec/SPEC-04 §5.1 states 3 and 4 (SL-ORIG-011)",
            "spec/SPEC-04 §4 asymmetric safety rule (SL-ORIG-010)",
            f"tools/seallink_verifier.py:1975-2030, 2407-2415 ({REFERENCE_LABEL})",
        ],
    )
    rules = ["SL-ORIG-010", "SL-ORIG-011"]
    of = rm._base_origin_fixture()
    t_majority = of["_maj_unix"]
    base_chain = of["chain"]
    ward = base_chain["names"][WARD_NAME]
    ward_policy = ward["updates"][-1]["owner_policy"]
    value = {"link": {"origin": of["_origin_id"]}}
    other = _key_pol(_kp("r2g02-other-owner"))
    subject = _key_pol(_kp("r2g02-subject-owner"))

    def chain_with(extra: list[dict[str, Any]] | None, *, at_t: bool) -> dict[str, Any]:
        chain = copy.deepcopy(base_chain)
        if extra is not None:
            chain["names"][WARD_NAME] = sv.make_name_history(
                WARD_NAME, ward["registration"], ward_policy, value, first_height=749005, update_height=749015, extra_updates=extra
            )
        if at_t:  # the trigger is reached at the tip: t_low = T
            chain["credible_utc_interval"] = [t_majority, t_majority + 20]
            chain["now"] = t_majority + 10
            chain["tip_header_time"] = t_majority
            chain["tip_first_sight"] = t_majority + 5
        return chain

    def update(tag: str, height: int, policy: dict[str, Any]) -> dict[str, Any]:
        return {"txid": _h32(tag), "confirmed_height": height, "owner_policy": policy, "value": value}

    round_trip = [
        update("r2g02-round-trip-1", 749030, other),
        update("r2g02-round-trip-2", 749040, other),
        update("r2g02-round-trip-3", 749050, ward_policy),
        update("r2g02-round-trip-4", 749060, ward_policy),
    ]
    handover = [update("r2g02-handover-1", 750050, subject), update("r2g02-handover-2", 750060, subject)]

    def inputs(chain: dict[str, Any]) -> dict[str, Any]:
        return {"chain": chain, "origin_bundle": of["origin_bundle"], "trusted_origin_issuers": of["trusted_origin_issuers"]}

    c_ward = s.control(
        "cand-r2g02-control-round-trip-before-t-ward",
        rules,
        "origin_status",
        inputs(chain_with(round_trip, at_t=False)),
        ("ADMIT_WARD", None),
        "Ward fixture of the refusal matrix (person, opened majority commitment T) before T, after the holders of the ward "
        "name's owner_policy moved the name to a key X, updated it with X and moved it back (heights 749030-749060).",
    )
    c_pending = s.control(
        "cand-r2g02-control-at-t-no-transfer-pending",
        rules,
        "origin_status",
        inputs(chain_with(None, at_t=True)),
        ("REFUSE", "GUARDIAN_TRANSFER_PENDING"),
        f"The same ward with t_low = T = {t_majority} at the tip and no name transfer: state 3.",
    )
    c_auto = s.control(
        "cand-r2g02-control-at-t-handover-to-fresh-policy-autonomous",
        rules,
        "origin_status",
        inputs(chain_with(handover, at_t=True)),
        ("ADMIT_AUTONOMOUS", None),
        "At T after a transfer to a fresh policy S and an S-authored update (heights 750050/750060); the name is held by S at "
        "the tip: state 4.",
    )
    s.witness(
        "cand-r2g02-at-t-round-trip-back-to-guardian-policy",
        rules,
        "origin_status",
        inputs(chain_with(round_trip, at_t=True)),
        ("REFUSE", "GUARDIAN_TRANSFER_PENDING"),
        "At T after the round trip of the first control: the name output at the tip is held by the ward owner_policy again. "
        "The reference counts the earlier transfer to X followed by an X-signed update as the handover and ignores both the "
        "current owner and that the transfer was made, and undone, about 1000 blocks before the tip whose header time is T.",
        reference=("ADMIT_AUTONOMOUS", None),
        code_status="text",
        basis=(
            "SPEC-04 §5.1 state 3 (Transfer Pending): 'Emancipation trigger reached — either (Path A) calendar majority t_low >= T "
            "... — but the name output has NOT yet been confirmed-transferred to a fresh subject ScriptPolicy (distinct from the "
            "prior guardian owner_policy ...)' -> GUARDIAN_TRANSFER_PENDING. State 4 (Path A) requires 'confirmed transfer to "
            "fresh subject ScriptPolicy (distinct from ward owner_policy)'. The name output here is held by the prior guardian "
            "owner_policy."
        ),
        controls=[c_pending, c_auto, c_ward],
    )


# ---------------------------------------------------------------------------
# R2G-03  mismatched majority opening: two codes
# ---------------------------------------------------------------------------

def build_r2g03(s: CandidateSuite) -> None:
    s.finding(
        "R2G-03",
        "A mismatched majority opening: the text requires ORIGIN_STATUS_INCOMPLETE, the published vector and the reference "
        "return ORIGIN_UNVERIFIED",
        [
            "spec/SPEC-04 §2.1 item 5 (SL-ORIG-002)",
            "vectors/security-conformance.json#branch-origin-bad-majority-salt",
            f"tools/seallink_verifier.py:2260-2271 ({REFERENCE_LABEL})",
        ],
    )
    rules = ["SL-ORIG-002", "SL-ORIG-009"]
    of = rm._base_origin_fixture()
    base = {"chain": of["chain"], "origin_bundle": of["origin_bundle"], "trusted_origin_issuers": of["trusted_origin_issuers"]}
    withheld = copy.deepcopy(base)
    del withheld["origin_bundle"]["opened_majority_unix"], withheld["origin_bundle"]["majority_salt_hex"]
    wrong_value = copy.deepcopy(base)
    wrong_value["origin_bundle"]["opened_majority_unix"] = of["_maj_unix"] + 1
    published = _published_case("branch-origin-bad-majority-salt")
    assert published["expected_refusal"] == "ORIGIN_UNVERIFIED", published["expected_refusal"]

    s.control(
        "cand-r2g03-control-valid-majority-opening-ward",
        rules,
        "origin_status",
        base,
        ("ADMIT_WARD", None),
        "Ward fixture of the refusal matrix with the salted majority opening (salt, T) that matches claims.majority_commitment.",
    )
    s.control(
        "cand-r2g03-control-majority-opening-withheld-incomplete",
        rules,
        "origin_status",
        withheld,
        ("REFUSE", "ORIGIN_STATUS_INCOMPLETE"),
        "The same ward with the opening withheld: text and reference agree on ORIGIN_STATUS_INCOMPLETE.",
    )
    question = (
        "Which code does a majority opening that fails claims.majority_commitment return: ORIGIN_STATUS_INCOMPLETE as SPEC-04 "
        "§2.1 item 5 says for 'withheld or mismatched', or ORIGIN_UNVERIFIED as the published vector branch-origin-bad-majority-"
        "salt and its note say? CONFORMANCE.md requires identical codes, so one of the two has to change."
    )
    readings = [
        {
            "reading": "text",
            "source": "SPEC-04 §2.1 item 5: verifiers MUST require the opening 'matching the commitment before admitting any "
            "guardian action (ORIGIN_STATUS_INCOMPLETE if withheld or mismatched)'",
            "verdict": "REFUSE",
            "refusal": "ORIGIN_STATUS_INCOMPLETE",
        },
        {
            "reading": "published vector",
            "source": "vectors/security-conformance.json#branch-origin-bad-majority-salt ('Opened majority_unix failing salted "
            "commitment MUST refuse ORIGIN_UNVERIFIED') and the reference",
            "verdict": "REFUSE",
            "refusal": "ORIGIN_UNVERIFIED",
        },
    ]
    s.decision(
        "cand-r2g03-published-bad-majority-salt",
        rules,
        "origin_status",
        published["inputs"],
        "Inputs of the published case branch-origin-bad-majority-salt, unchanged: the opened salt does not match the commitment.",
        reference=("REFUSE", "ORIGIN_UNVERIFIED"),
        question=question,
        readings=readings,
        conflicts_with=["branch-origin-bad-majority-salt"],
    )
    s.decision(
        "cand-r2g03-opened-majority-value-mismatch",
        rules,
        "origin_status",
        wrong_value,
        "The valid control with the right salt but an opened majority_unix of T + 1: the other way an opening can mismatch.",
        reference=("REFUSE", "ORIGIN_UNVERIFIED"),
        question=question,
        readings=readings,
        conflicts_with=["branch-origin-bad-majority-salt"],
    )


# ---------------------------------------------------------------------------
# G7-01  station target authority is default-open
# ---------------------------------------------------------------------------

def build_g701(s: CandidateSuite) -> None:
    s.finding(
        "G7-01",
        "Station target authority is default-open: on a host without configuration any root issuer may grant agent/tool on "
        "station:<host>:<slot>",
        [
            "spec/SPEC-06 §4 step 11d (SL-GRNT-012)",
            "profiles/PROFILE-agent-v1 §4 (SL-AGNT-002)",
            f"tools/seallink_verifier.py:4122-4136 ({REFERENCE_LABEL})",
        ],
    )
    rules = ["SL-GRNT-012", "SL-AGNT-002"]
    fx = rm._base_invocation_fixture()
    host = fx["executor_cfg"]["name"]
    target = f"station:{host}:tools"
    base_grant = fx["bundle"]["grants"][0]["payload"]
    owner_pin = copy.deepcopy(base_grant["issuer"])
    assert owner_pin["name"] == "id/alice", owner_pin["name"]
    worker = _kp("g701-worker")
    chain = copy.deepcopy(fx["chain"])
    mallory = _add_name(chain, "id/mallory", "g701-mallory")

    def tool_grant(issuer: dict[str, Any]) -> dict[str, Any]:
        return {
            "capabilities": [
                {"action": "agent/tool", "target": target, "quotas": [{"kind": "seallink/count", "max": "3", "resource": target, "unit": "calls", "window": "term"}]}
            ],
            "executor": {"key": fx["executor_cfg"]["key"], "name": host},
            "genesis": G,
            "issuer": issuer,
            "network": "main",
            "not_after_height": 760000,
            "not_before_height": 750000,
            "recent_block": base_grant["recent_block"],
            "recipient": {"key": worker["xonly"], "mode": "key"},
            "revocation": {},
            "type": "seallink-grant/1",
        }

    owner_env, owner_gid, owner_itx = _root_grant(chain, tool_grant(owner_pin), fx["_keys"]["alice_gr"], "g701-owner")
    mallory_env, mallory_gid, mallory_itx = _root_grant(chain, tool_grant(mallory["pin"]), mallory["grant_key"], "g701-mallory")
    arguments = {"input_sha256": _h32("g701-input"), "max_output_bytes": "10", "tool_name": "pytest"}
    unconfigured = fx["executor_cfg"]
    assert "slot_owners" not in unconfigured and "authorized_issuers" not in unconfigured
    configured = dict(unconfigured, slot_owners={"tools": "id/alice"})

    def case(env: dict[str, Any], gid: str, itx: str, cfg: dict[str, Any], tag: str) -> dict[str, Any]:
        return {
            "invocation": _invocation(fx, gid, itx, "agent/tool", target, arguments, worker, tag, exp=1795221000),
            "bundle": {"grants": [env]},
            "chain": chain,
            "journal": {"journal_id": _h32(f"{tag}-journal")},
            "executor_cfg": cfg,
        }

    harness = (
        "executor_cfg.slot_owners (like executor_cfg.authorized_issuers) is a configuration key of the reference harness only; "
        "no specification text, schema or published vector names it."
    )
    c_owner = s.control(
        "cand-g701-control-configured-slot-owner-admits",
        rules,
        "invocation",
        case(owner_env, owner_gid, owner_itx, configured, "g701-owner-configured"),
        ("ADMIT", None),
        f"Root agent/tool grant by id/alice on {target} (the host is the executor) with the host's slot 'tools' bound to "
        f"id/alice. {harness}",
    )
    c_foreign = s.control(
        "cand-g701-control-configured-slot-foreign-issuer-refuses",
        rules,
        "invocation",
        case(mallory_env, mallory_gid, mallory_itx, configured, "g701-mallory-configured"),
        ("REFUSE", "GRANT_TARGET_UNAUTHORIZED"),
        "The same grant issued by id/mallory, an unrelated name registered by the attacker, on the configured host.",
    )
    s.witness(
        "cand-g701-unconfigured-host-foreign-issuer",
        rules,
        "invocation",
        case(mallory_env, mallory_gid, mallory_itx, unconfigured, "g701-mallory-unconfigured"),
        ("REFUSE", "GRANT_TARGET_UNAUTHORIZED"),
        "id/mallory's grant on a host that has no slot binding at all (the executor_cfg of every published vector). If the "
        "authors decide that an unconfigured host accepts every root issuer (decision cand-g701-unconfigured-host-owner-"
        "issuer), this witness goes with that decision.",
        reference=("ADMIT", None),
        code_status="text",
        basis=(
            "SPEC-06 §4 step 11d: 'station:<host>:<slot> -> <host> == executor.name and root issuer authorized for <slot> ... -> "
            "GRANT_TARGET_UNAUTHORIZED'; PROFILE-agent-v1 §4: the host MUST verify 'that the root grant's issuer is authorized "
            "for <workspace_or_slot> under local host binding (GRANT_TARGET_UNAUTHORIZED otherwise)'. No binding authorizes "
            "id/mallory."
        ),
        controls=[c_foreign, c_owner],
    )
    s.decision(
        "cand-g701-unconfigured-host-owner-issuer",
        rules,
        "invocation",
        case(owner_env, owner_gid, owner_itx, unconfigured, "g701-owner-unconfigured"),
        "id/alice's grant of the first control on the unconfigured host.",
        reference=("ADMIT", None),
        question=(
            "Is a station host without a local host binding closed (no root issuer is authorized for any slot) or open (every "
            "root issuer is)? The text gives the binding no data model, so an independent implementation cannot configure one "
            "either; every published station vector runs on an unconfigured host and expects ADMIT."
        ),
        readings=[
            {
                "reading": "fail-closed host binding",
                "source": "SPEC-06 §4 step 11d and PROFILE-agent-v1 §4 ('authorized for <workspace_or_slot> under local host "
                "binding (GRANT_TARGET_UNAUTHORIZED otherwise)')",
                "verdict": "REFUSE",
                "refusal": "GRANT_TARGET_UNAUTHORIZED",
                "comment": "Needs a normative binding (slot -> NamePin[], e.g. in the station manifest) and regenerated vectors.",
            },
            {
                "reading": "default-open host",
                "source": f"vectors/{TRACE_03} and the published station cases listed in conflicts_with, all on executor "
                "configurations without a binding; the reference",
                "verdict": "ADMIT",
                "refusal": None,
                "comment": "Then cand-g701-unconfigured-host-foreign-issuer is admitted by design and an unrelated name may "
                "grant any slot of any unconfigured host.",
            },
        ],
        conflicts_with=[f"vectors/{TRACE_03}"]
        + _published_ids(
            lambda c, blob: c["expected_verdict"] == "ADMIT" and '"target": "station:' in blob and "slot_owners" not in blob and "authorized_issuers" not in blob
        ),
    )


# ---------------------------------------------------------------------------
# G7-02  required quota on another resource
# ---------------------------------------------------------------------------

def build_g702(s: CandidateSuite) -> None:
    s.finding(
        "G7-02",
        "A required profile quota that counts another resource is accepted: the registry and profiles say resource = target, "
        "the reference compares only kind and unit, and the published trace-03 relies on that",
        [
            'registry/actions.json required_quotas ("resource": "{target}")',
            "profiles/PROFILE-mail-v1 §4.1 (SL-MAIL-004)",
            "profiles/PROFILE-agent-v1 §6 item 2 (SL-AGNT-005)",
            "spec/SPEC-06 §2.2 (SL-GRNT-007)",
            f"vectors/{TRACE_03}",
            f"tools/seallink_verifier.py:4217-4225 ({REFERENCE_LABEL})",
        ],
    )
    mail_rules = ["SL-GRNT-007", "SL-MAIL-004"]

    def mail_send(resource: str, unit: str, tag: str) -> dict[str, Any]:
        f = rm._base_invocation_fixture()
        gp = copy.deepcopy(f["bundle"]["grants"][0]["payload"])
        gp["capabilities"] = [
            {"action": "mail/send", "target": "mailbox:id/alice:work", "quotas": [{"kind": "seallink/count", "max": "5", "resource": resource, "unit": unit, "window": "term"}]}
        ]
        rm._reanchor_grant(f, gp)
        p = copy.deepcopy(f["invocation"]["payload"])
        p["action"] = "mail/send"
        p["arguments"] = {"body_sha256": _h32(f"{tag}-body"), "size_bytes": "100", "subject": "hi", "to": "bob@example.com"}
        p["nonce"] = _h32(f"{tag}-nonce")
        f["invocation"] = sl.sign_envelope(p, [f["_keys"]["agent_req"]["sk"]])
        return f

    c_match = s.control(
        "cand-g702-control-mail-send-quota-on-target-admits",
        mail_rules,
        "invocation",
        mail_send("mailbox:id/alice:work", "messages", "g702-match"),
        ("ADMIT", None),
        "Mail fixture of the refusal matrix: id/alice grants mail/send on mailbox:id/alice:work with a seallink/count quota on "
        "the same mailbox in unit messages.",
    )
    c_unit = s.control(
        "cand-g702-control-mail-send-quota-wrong-unit-refuses",
        mail_rules,
        "invocation",
        mail_send("mailbox:id/alice:work", "requests", "g702-unit"),
        ("REFUSE", "QUOTA_EXCEEDED"),
        "The same grant with the quota in unit requests instead of messages.",
    )
    s.witness(
        "cand-g702-mail-send-quota-on-other-mailbox",
        mail_rules,
        "invocation",
        mail_send("mailbox:id/bob:private", "messages", "g702-other"),
        ("REFUSE", "QUOTA_EXCEEDED"),
        "The same grant whose only quota counts mailbox:id/bob:private: nothing limits the messages sent from "
        "mailbox:id/alice:work.",
        reference=("ADMIT", None),
        code_status="text",
        basis=(
            "PROFILE-mail-v1 §4.1: 'Every mail/send capability MUST carry a matching {\"kind\":\"seallink/count\",\"resource\":"
            "\"mailbox:<owner>:<label>\",\"unit\":\"messages\"} quota (refusing QUOTA_EXCEEDED if omitted)'; registry/actions.json "
            "gives mail/send required_quotas with \"resource\": \"{target}\"."
        ),
        controls=[c_unit, c_match],
    )

    agent_rules = ["SL-GRNT-007", "SL-AGNT-005"]
    df = rm._delegation_fx("none")
    assert df["invocation"]["payload"]["target"] == "station:id/station-a:tools"

    def quotas(obj: Any) -> list[dict[str, Any]]:
        if isinstance(obj, dict):
            own = [obj] if str(obj.get("kind", "")).startswith("seallink/") and "resource" in obj and "unit" in obj else []
            return own + [q for v in obj.values() for q in quotas(v)]
        if isinstance(obj, list):
            return [q for v in obj for q in quotas(v)]
        return []

    def fleet_quotas(f: dict[str, Any]) -> dict[str, Any]:
        """Every quota of the parent and the child grant counts station:fleet:tools (trace-03 style); both re-signed and re-anchored."""
        f = copy.deepcopy(f)
        parent_env, child_env = f["bundle"]["grants"]
        pp, cp = copy.deepcopy(parent_env["payload"]), copy.deepcopy(child_env["payload"])
        touched = quotas(pp) + quotas(cp)
        assert touched
        for q in touched:
            q["resource"] = "station:fleet:tools"
        p_itx, c_itx = (e["issuance_txid"] for e in f["invocation"]["payload"]["proof_path"])
        parent2 = sl.sign_envelope(pp, [f["_keys"]["alice_gr"]["sk"]])
        cp["parent"]["grant_id"] = sl.object_id(pp)
        child2 = sl.sign_envelope(cp, [f["_del_k"]["sk"]])
        f["chain"]["txs"][p_itx]["opreturn_hex"] = _issuance_opret(parent2)
        f["chain"]["txs"][c_itx]["opreturn_hex"] = _issuance_opret(child2)
        ip = copy.deepcopy(f["invocation"]["payload"])
        ip["proof_path"][0]["grant_id"] = sl.object_id(pp)
        ip["proof_path"][1]["grant_id"] = sl.object_id(cp)
        f["invocation"] = sl.sign_envelope(ip, [f["_keys"]["agent_req"]["sk"]])
        f["bundle"]["grants"] = [parent2, child2]
        return f

    s.control(
        "cand-g702-control-delegation-quota-on-target-admits",
        agent_rules,
        "invocation",
        df,
        ("ADMIT", None),
        "Depth-2 delegation fixture of the refusal matrix (notary_mode none): agent/tool on station:id/station-a:tools, every "
        "quota of parent and child on that same resource.",
    )
    s.decision(
        "cand-g702-delegation-quota-on-fleet-resource",
        agent_rules,
        "invocation",
        fleet_quotas(df),
        "The same delegation with every quota of parent and child on station:fleet:tools, the resource trace-03 uses for its "
        "station:id/station-a:tools and station:id/station-b:tools targets.",
        reference=("ADMIT", None),
        question=(
            "Does a required profile quota have to count the invocation target (registry/actions.json \"resource\": \"{target}\", "
            "PROFILE-agent-v1 §6 '{\"resource\":\"<target>\",\"unit\":\"calls\"}'), or may it count any resource, as trace-03's "
            "fleet-wide pool does? Either remove resource from required_quotas and the profiles, or check it and regenerate "
            "trace-03; the placeholder syntax {target} is not defined either."
        ),
        readings=[
            {
                "reading": "registry and profile",
                "source": "registry/actions.json agent/tool required_quotas; PROFILE-agent-v1 §6 item 2 ('agent/tool reserves 1 "
                "unit from {\"kind\":\"seallink/count\",\"resource\":\"<target>\",\"unit\":\"calls\"}'); SPEC-06 §2.2 (a missing "
                "required profile quota refuses QUOTA_EXCEEDED)",
                "verdict": "REFUSE",
                "refusal": "QUOTA_EXCEEDED",
            },
            {
                "reading": "published trace",
                "source": f"vectors/{TRACE_03} (targets station:id/station-a:tools and station:id/station-b:tools, quotas on "
                "station:fleet:tools) and the reference, which matches required quotas by kind and unit only",
                "verdict": "ADMIT",
                "refusal": None,
                "comment": "Then the witness cand-g702-mail-send-quota-on-other-mailbox needs the same decision for mail/send.",
            },
        ],
        conflicts_with=[f"vectors/{TRACE_03}"],
    )


# ---------------------------------------------------------------------------
# G7-03  Bearer Sessions open on grants the pipeline refuses
# ---------------------------------------------------------------------------

def build_g703(s: CandidateSuite) -> None:
    s.finding(
        "G7-03",
        "Bearer Sessions: seallink-session-open/1 is admitted on a backing grant that the §4 pipeline refuses (forged and never "
        "anchored, or issued by a stranger over another owner's mailbox)",
        [
            "spec/SPEC-06 §5 item 1 (SL-GRNT-013)",
            "spec/SPEC-06 §4 (SL-GRNT-012)",
            f"tools/seallink_verifier.py:4543-4601 ({REFERENCE_LABEL})",
        ],
    )
    rules = ["SL-GRNT-013", "SL-GRNT-012"]
    fx = rm._base_invocation_fixture()
    request_quota = {"kind": "seallink/count", "max": "10", "resource": "mailbox:id/alice:work", "unit": "requests", "window": "term"}
    gp = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    gp["capabilities"][0]["quotas"] = [request_quota]
    rm._reanchor_grant(fx, gp)
    grant = fx["bundle"]["grants"][0]
    gid = sl.object_id(grant["payload"])
    itx = fx["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    now = fx["chain"]["now"]
    recipient = fx["_keys"]["agent_req"]
    stranger = _kp("g703-stranger")
    read_args = {"folder": "Invoices", "message_id": "m1"}

    def session_open(signer: dict[str, Any], grant_id: str, issuance_txid: str, tag: str) -> dict[str, Any]:
        return sl.sign_envelope(
            {
                "executor": copy.deepcopy(fx["invocation"]["payload"]["executor"]),
                "exp": now + 1200,
                "genesis": G,
                "iat": now - 10,
                "network": "main",
                "nonce": _h32(f"{tag}-session-nonce"),
                "op": "open",
                "proof_path": [{"grant_id": grant_id, "issuance_txid": issuance_txid}],
                "quotas": [dict(request_quota, max="5")],
                "slot_binding": "tls-slot-a",
                "type": "seallink-session-open/1",
            },
            [signer["sk"]],
        )

    def lifecycle(steps: list[dict[str, Any]], tag: str) -> dict[str, Any]:
        return {"executor_cfg": fx["executor_cfg"], "journal": {"journal_id": _h32(f"{tag}-journal")}, "steps": steps}

    def open_step(label: str, envelope: dict[str, Any], bundle: dict[str, Any], chain: dict[str, Any], token: str, want: Verdict) -> dict[str, Any]:
        return {"label": label, "kind": "session_open", "session_open": envelope, "bundle": bundle, "chain": chain, "bearer_token": token, "want_verdict": want[0], "want_refusal": want[1]}

    # A grant nobody issued: alice's payload with the stranger as recipient and seal, signed by the stranger, never anchored.
    fp = copy.deepcopy(grant["payload"])
    fp["recipient"] = {"key": stranger["xonly"], "mode": "key"}
    forged_seal = _key_pol(_kp("g703-stranger-seal"))
    forged_seal_tx = _h32("g703-stranger-seal-tx")
    fp["revocation"]["seal"] = {"script_policy": forged_seal, "txid": forged_seal_tx, "vout": 0}
    forged = sl.sign_envelope(fp, [stranger["sk"]])
    forged_gid = sl.object_id(fp)
    forged_chain = copy.deepcopy(fx["chain"])
    forged_chain["txs"][forged_seal_tx] = {"confirmed_height": 749990, "outputs": {"0": {"script_pubkey_hex": _spk(forged_seal)}}}

    # A valid, anchored grant by an unrelated name over alice's mailbox.
    foreign_chain = copy.deepcopy(fx["chain"])
    mallory = _add_name(foreign_chain, "id/mallory", "g703-mallory")
    mp = copy.deepcopy(grant["payload"])
    mp["issuer"] = mallory["pin"]
    mp["recipient"] = {"key": stranger["xonly"], "mode": "key"}
    foreign, foreign_gid, foreign_itx = _root_grant(foreign_chain, mp, mallory["grant_key"], "g703-mallory")

    c_valid = s.control(
        "cand-g703-control-valid-session-open-and-use",
        rules,
        "session_lifecycle",
        lifecycle(
            [
                open_step("open", session_open(recipient, gid, itx, "g703-valid"), fx["bundle"], fx["chain"], "tok-valid", ("ADMIT", None)),
                {"label": "use", "kind": "bearer_session", "token": "tok-valid", "slot_binding": "tls-slot-a", "chain": fx["chain"], "want_verdict": "ADMIT", "want_refusal": None},
            ],
            "g703-valid",
        ),
        ("ADMIT", None),
        "Mail fixture of the refusal matrix with a requests quota: the grant's recipient opens a session (quota 5 <= 10) and "
        "uses it once with the bearer token.",
    )
    c_forged = s.control(
        "cand-g703-control-forged-grant-invocation-refuses",
        rules,
        "invocation",
        {
            "invocation": _invocation(fx, forged_gid, itx, "mail/read", "mailbox:id/alice:work", read_args, stranger, "g703-forged-invocation"),
            "bundle": {"grants": [forged], "manifests": fx["bundle"]["manifests"]},
            "chain": forged_chain,
            "journal": {"journal_id": _h32("g703-forged-invocation-journal")},
            "executor_cfg": fx["executor_cfg"],
        },
        ("REFUSE", "WIRE_SIGNATURE"),
        "The forged grant (id/alice as issuer, signed by the stranger, never anchored; proof_path names alice's genuine "
        "issuance transaction) presented in a signed mail/read invocation.",
    )
    c_foreign = s.control(
        "cand-g703-control-foreign-issuer-invocation-refuses",
        rules,
        "invocation",
        {
            "invocation": _invocation(fx, foreign_gid, foreign_itx, "mail/read", "mailbox:id/alice:work", read_args, stranger, "g703-foreign-invocation"),
            "bundle": {"grants": [foreign], "manifests": fx["bundle"]["manifests"]},
            "chain": foreign_chain,
            "journal": {"journal_id": _h32("g703-foreign-invocation-journal")},
            "executor_cfg": fx["executor_cfg"],
        },
        ("REFUSE", "GRANT_TARGET_UNAUTHORIZED"),
        "A validly signed and anchored grant by id/mallory over mailbox:id/alice:work, presented in a signed mail/read invocation.",
    )
    basis = (
        "SPEC-06 §5 item 1 (op = \"open\"): 'Executor runs the full admission pipeline (§4) on the backing grant' before it binds "
        "a session and returns a bearer token. On the same grant the §4 pipeline returns the paired invocation control's code. "
        "By the scenario-runner convention the case verdict is ADMIT when the open step returns exactly that refusal."
    )
    s.witness(
        "cand-g703-session-open-on-forged-grant",
        rules,
        "session_lifecycle",
        lifecycle(
            [open_step("open-forged", session_open(stranger, forged_gid, itx, "g703-forged"), {"grants": [forged]}, forged_chain, "tok-forged", ("REFUSE", "WIRE_SIGNATURE"))],
            "g703-forged",
        ),
        ("ADMIT", None),
        "The stranger opens a session on the forged grant; the step requires the refusal of the paired invocation control. The "
        "reference opens the session.",
        reference=("REFUSE", "SESSION_STEP_MISMATCH:open-forged:('ADMIT', None)"),
        code_status="derived",
        basis=basis,
        controls=[c_forged, c_valid],
    )
    s.witness(
        "cand-g703-session-open-on-foreign-issuer-grant",
        rules,
        "session_lifecycle",
        lifecycle(
            [
                open_step(
                    "open-foreign-issuer",
                    session_open(stranger, foreign_gid, foreign_itx, "g703-foreign"),
                    {"grants": [foreign]},
                    foreign_chain,
                    "tok-foreign",
                    ("REFUSE", "GRANT_TARGET_UNAUTHORIZED"),
                )
            ],
            "g703-foreign",
        ),
        ("ADMIT", None),
        "The stranger opens a session on id/mallory's grant over alice's mailbox; the step requires the refusal of the paired "
        "invocation control. The reference opens the session.",
        reference=("REFUSE", "SESSION_STEP_MISMATCH:open-foreign-issuer:('ADMIT', None)"),
        code_status="derived",
        basis=basis,
        controls=[c_foreign, c_valid],
    )


# ---------------------------------------------------------------------------
# R2-03  credential subject origin unchecked without a bundle
# ---------------------------------------------------------------------------

def build_r203(s: CandidateSuite) -> None:
    s.finding(
        "R2-03",
        'Credential subject.mode = "origin" is verified only when the presenter volunteers an origin bundle',
        [
            "spec/SPEC-05 §4.2 step 5 (SL-CONT-010)",
            f"tools/seallink_verifier.py:3117-3135 ({REFERENCE_LABEL})",
        ],
    )
    rules = ["SL-CONT-010", "SL-ORIG-002"]
    base = _published_case("d7-d6-credential-subject-origin-mode-admit")["inputs"]
    assert base["credential"]["payload"]["subject"]["mode"] == "origin"
    issuer_key = rm._kp("o-reg-cred")

    def unknown_origin(with_bundle: bool) -> dict[str, Any]:
        inputs = copy.deepcopy(base)
        payload = copy.deepcopy(inputs["credential"]["payload"])
        payload["subject"]["origin_id"] = _h32("r203-no-such-origin")
        env = sl.sign_envelope(payload, [issuer_key["sk"]])
        inputs["credential"] = env
        inputs["chain"]["txs"][inputs["anchor_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x09, sl.content_addr(env)).hex()
        if not with_bundle:
            del inputs["origin_bundle"]
        return inputs

    without_bundle = copy.deepcopy(base)
    del without_bundle["origin_bundle"]
    untrusted = copy.deepcopy(base)
    untrusted["trusted_origin_issuers"] = []

    c_published = s.control(
        "cand-r203-control-published-origin-subject-admits",
        rules,
        "credential",
        base,
        ("ADMIT", None),
        "Inputs of the published case d7-d6-credential-subject-origin-mode-admit: an anchored credential about the subject of "
        "a presented, trusted origin.",
    )
    c_other = s.control(
        "cand-r203-control-unknown-origin-other-bundle-refuses",
        rules,
        "credential",
        unknown_origin(True),
        ("REFUSE", "ORIGIN_UNVERIFIED"),
        "The same credential re-signed by its issuer and re-anchored with subject.origin_id = a value no origin has, presented "
        "with the published origin bundle (which certifies another origin).",
    )
    c_untrusted = s.control(
        "cand-r203-control-untrusted-origin-issuer-refuses",
        rules,
        "credential",
        untrusted,
        ("REFUSE", "ORIGIN_UNVERIFIED"),
        "The published case with an empty trusted_origin_issuers set.",
    )
    basis = "SPEC-05 §4.2 step 5: 'if subject.mode = \"origin\", verify subject.origin_id -> ORIGIN_UNVERIFIED'. Without an origin document nothing verifies it."
    s.witness(
        "cand-r203-origin-subject-bundle-withheld",
        rules,
        "credential",
        without_bundle,
        ("REFUSE", "ORIGIN_UNVERIFIED"),
        "The published case with origin_bundle left out: the presenter decides whether subject.origin_id is checked.",
        reference=("ADMIT", None),
        code_status="text",
        basis=basis,
        controls=[c_published, c_untrusted],
    )
    s.witness(
        "cand-r203-unknown-origin-subject-bundle-withheld",
        rules,
        "credential",
        unknown_origin(False),
        ("REFUSE", "ORIGIN_UNVERIFIED"),
        "The credential about the non-existent origin of the second control, presented without an origin bundle.",
        reference=("ADMIT", None),
        code_status="text",
        basis=basis,
        controls=[c_other, c_published],
    )


# ---------------------------------------------------------------------------
# R2-01 / N-1  two definitions of MachineClauseTerms
# ---------------------------------------------------------------------------

def build_r201(s: CandidateSuite) -> None:
    s.finding(
        "R2-01",
        "MachineClauseTerms has two definitions (also N-1): the prose has a clause member machine {capabilities?, config_sha256?, "
        "window?}, the schema and the reference machine_terms {capabilities, not_before_height?, not_after_height?}, so the "
        "bytes of a committed clause are undefined",
        [
            "spec/SPEC-05 §2.1 items 2-3 (SL-CONT-002)",
            "schemas/contract.schema.json#/$defs/ClauseObject and #/$defs/MachineClauseTerms",
            f"tools/seallink_verifier.py:3764-3773 ({REFERENCE_LABEL})",
            f"vectors/{TRACE_02}#/machine_clause_0_disclosure",
        ],
    )
    rules = ["SL-CONT-002"]
    cf = rm._contract_fx()
    capability = copy.deepcopy(cf["bundle"]["grants"][0]["payload"]["capabilities"][0])

    def rebind(clause: dict[str, Any], tag: str) -> dict[str, Any]:
        """Commit `clause` as clause 0 of the matrix contract fixture, re-sign both assents, re-bind and re-anchor the grant."""
        f = copy.deepcopy(cf)
        contract = copy.deepcopy(f["bundle"]["contract"])
        salt = _h32(f"{tag}-salt")
        contract["clause_commitments"] = [sl.clause_commit(salt, clause)]
        assert contract.get("machine_clause_indices") == [0], contract.get("machine_clause_indices")
        cid = sl.object_id(contract)
        keys = {"client-1": f["_keys"]["alice_gr"]["sk"], "worker-1": f["_keys"]["agent_req"]["sk"]}
        old = {a["payload"]["party_id"]: a["payload"] for a in f["bundle"]["contract_assents"]}
        assert set(old) == set(keys), sorted(old)
        f["bundle"]["contract_assents"] = [sl.sign_envelope(dict(old[pid], target_id=cid), [keys[pid]]) for pid in sorted(old)]
        f["bundle"]["contract"] = contract
        f["bundle"]["disclosed_clauses"] = {"0": {"salt_hex": salt, "clause": clause}}
        gp = copy.deepcopy(f["bundle"]["grants"][0]["payload"])
        gp["contract_id"] = cid
        keep = copy.deepcopy(f["invocation"]["payload"])
        rm._reanchor_grant(f, gp)
        keep["proof_path"] = f["invocation"]["payload"]["proof_path"]
        f["invocation"] = sl.sign_envelope(keep, [f["_keys"]["agent_req"]["sk"]])
        return f

    question = (
        "Which member carries the machine terms of a clause, with which sub-members? SPEC-05 §2.1 item 2 says a closed typed "
        "'machine' object (MachineClauseTerms: optional capabilities[], optional config_sha256, optional window) and item 3 "
        "requires clause_i.machine; schemas/contract.schema.json and the reference use machine_terms with required "
        "capabilities, flat not_before_height / not_after_height and no config_sha256. The clause is hashed into "
        "clause_commitments, so the two readings commit different bytes. The disclosed clause 0 of the published trace-02 "
        "({max_tuition_eur, text}) is valid under neither: the closed ClauseObject rejects max_tuition_eur."
    )
    schema_reading = {
        "reading": "schema and reference",
        "source": "schemas/contract.schema.json#/$defs/ClauseObject (closed: title, text, machine_terms) and "
        "#/$defs/MachineClauseTerms; tools/seallink_verifier.py",
    }
    prose_reading = {
        "reading": "prose",
        "source": "SPEC-05 §2.1 item 2 (closed typed machine object) and item 3 ('require clause_i.machine to be present and "
        "valid under MachineClauseTerms', CONTRACT_TERMS_MISMATCH)",
    }
    text = "Isolated session terms"
    s.decision(
        "cand-r201-clause-in-schema-form",
        rules,
        "invocation",
        rebind({"machine_terms": {"capabilities": [capability]}, "text": text}, "r201-schema"),
        "Contract fixture of the refusal matrix (machine_clause_indices = [0]) whose clause 0 is "
        "{machine_terms: {capabilities: [the grant capability]}, text}; the grant binds the re-committed contract.",
        reference=("ADMIT", None),
        question=question,
        readings=[
            {**schema_reading, "verdict": "ADMIT", "refusal": None},
            {**prose_reading, "verdict": "REFUSE", "refusal": "CONTRACT_TERMS_MISMATCH", "comment": "clause_i.machine is missing."},
        ],
        conflicts_with=_published_ids(lambda c, blob: c["expected_verdict"] == "ADMIT" and '"machine_terms"' in blob),
    )
    s.decision(
        "cand-r201-clause-in-prose-form",
        rules,
        "invocation",
        rebind({"machine": {"capabilities": [capability]}, "text": text}, "r201-prose"),
        "The same contract with clause 0 = {machine: {capabilities: [the grant capability]}, text}, the form of SPEC-05 §2.1.",
        reference=("REFUSE", "CONTRACT_TERMS_MISMATCH"),
        question=question,
        readings=[
            {
                **schema_reading,
                "verdict": "REFUSE",
                "refusal": "CONTRACT_TERMS_MISMATCH",
                "comment": "The reference reports CONTRACT_TERMS_MISMATCH; whether a closed-schema failure of a disclosed clause is "
                "WIRE_MEMBER first is not stated either.",
            },
            {**prose_reading, "verdict": "ADMIT", "refusal": None},
        ],
    )


FINDING_BUILDERS: list[Callable[[CandidateSuite], None]] = [
    build_r2g01,
    build_r2g02,
    build_r2g03,
    build_g701,
    build_g702,
    build_g703,
    build_r203,
    build_r201,
]


# ---------------------------------------------------------------------------
# Suite assembly, rendering and checking
# ---------------------------------------------------------------------------

def build_candidate_suite(*, verify: bool = True) -> dict[str, Any]:
    s = CandidateSuite(verify=verify)
    for build in FINDING_BUILDERS:
        build(s)
    by_finding: dict[str, list[dict[str, Any]]] = {}
    for case in s.cases:
        by_finding.setdefault(case["candidate"]["finding"], []).append(case)
    findings = []
    for f in s.findings:
        cases = by_finding.get(f["id"], [])
        counts = {role: sum(1 for c in cases if c["candidate"]["role"] == role) for role in ROLES}
        assert counts["witness"] + counts["decision"] >= 1, f["id"]
        findings.append({**f, "case_ids": [c["id"] for c in cases], "controls": counts["control"], "witnesses": counts["witness"], "decisions": counts["decision"]})
    totals = {role: sum(1 for c in s.cases if c["candidate"]["role"] == role) for role in ROLES}
    return {
        "suite": "review-candidates-draft7-blockers",
        "version": VERSION,
        "status": "candidate (non-normative; not part of vectors/, not required by CONFORMANCE.md)",
        "description": (
            "Executable candidate negative vectors for the Blocker findings of the second round of the independent engineering "
            f"review of SealLink {REFERENCE_TAG} (R2G-01, R2G-02, R2G-03, G7-01, G7-02, G7-03, R2-03, R2-01). Each witness is "
            f"paired with controls; `candidate.reference_result` records the verdict of tools/seallink_verifier.py at {REFERENCE_TAG}."
        ),
        "reference": {"tag": REFERENCE_TAG, "commit": REFERENCE_COMMIT, "executor": "tools/build_security_suite.py::execute_security_case"},
        "role_semantics": {
            "control": "Passes on the reference and must keep passing.",
            "witness": "expected_* follows the cited specification text; reference_result is what the reference returns today.",
            "decision": "Text and published vectors (or two readings) differ; expected_* mirrors readings[0]. Needs an authors' decision.",
        },
        "refusal_code_status_semantics": CODE_STATUS,
        "totals": {"cases": len(s.cases), **totals},
        "findings": findings,
        "cases": s.cases,
    }


def render(suite: dict[str, Any]) -> str:
    return json.dumps(suite, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _fmt(verdict: str, refusal: str | None) -> str:
    return f"{verdict} `{refusal}`" if refusal else verdict


def _md(text: str) -> str:
    """Keep literal angle brackets (e.g. <owner_name>) visible in rendered Markdown."""
    return text.replace("<", "\\<")


def render_index(suite: dict[str, Any]) -> str:
    """Human-readable index of the suite (generated; `--check` requires it to match the JSON)."""
    by_id = {c["id"]: c for c in suite["cases"]}
    totals = suite["totals"]
    out = [
        "# Review-candidate vectors — index",
        "",
        f"Generated by `python3 tools/build_candidate_suite.py --write` from [`{SUITE_NAME}`]({SUITE_NAME}). Do not edit by hand.",
        "",
        f"`{totals['cases']}` cases: `{totals['control']}` controls, `{totals['witness']}` witnesses (all open at `{suite['reference']['tag']}`), "
        f"`{totals['decision']}` decision records. Roles, code statuses and the promotion workflow are described in [README.md](README.md).",
        "",
        "| Finding | Defect | Controls | Witnesses | Decisions |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for f in suite["findings"]:
        out.append(f"| [{f['id']}](#{f['id'].lower()}) | {_md(f['title'])} | {f['controls']} | {f['witnesses']} | {f['decisions']} |")
    for f in suite["findings"]:
        cases = [by_id[cid] for cid in f["case_ids"]]
        out += ["", f"## {f['id']}", "", f"**{_md(f['title'])}.**", "", "Where: " + "; ".join(f"`{w}`" for w in f["where"]) + ".", ""]
        out += [f"| Case | Role | Runner | Expected | Reference at {REFERENCE_LABEL} | Code status |", "| --- | --- | --- | --- | --- | --- |"]
        for c in cases:
            cand = c["candidate"]
            expected = _fmt(c["expected_verdict"], c["expected_refusal"])
            if cand["role"] == "control":
                reference, status = "as expected", ""
            else:
                reference = _fmt(cand["reference_result"]["verdict"], cand["reference_result"]["refusal"])
                status = cand.get("refusal_code_status", "see readings")
                if status == "undefined":
                    expected += f" (any code; proposed `{cand['proposed_refusal']}`)"
                for alt in cand.get("also_acceptable", []):
                    expected += f"; or {_fmt(alt['verdict'], alt['refusal'])}"
                if cand["role"] == "decision":
                    expected += " (reading 1)"
            out.append(f"| `{c['id']}` | {cand['role']} | `{c['runner']}` | {expected} | {reference} | {status} |")
        for basis in dict.fromkeys(c["candidate"]["basis"] for c in cases if c["candidate"]["role"] == "witness"):
            out += ["", f"Basis: {_md(basis)}"]
        for c in cases:
            for alt in c["candidate"].get("also_acceptable", []):
                out += ["", f"Also acceptable for `{c['id']}` — {_fmt(alt['verdict'], alt['refusal'])}: {_md(alt['why'])}"]
        seen_questions: set[str] = set()
        for c in cases:
            cand = c["candidate"]
            if cand["role"] != "decision":
                continue
            if cand["question"] not in seen_questions:
                seen_questions.add(cand["question"])
                out += ["", f"Decision needed: {_md(cand['question'])}"]
            out += ["", f"- `{c['id']}`:"]
            for n, r in enumerate(cand["readings"], start=1):
                line = f"  - reading {n} — {_md(r['reading'])} ({_md(r['source'])}): {_fmt(r['verdict'], r['refusal'])}"
                if r.get("comment"):
                    line += f". {_md(r['comment'])}"
                out.append(line)
            if cand.get("conflicts_with"):
                out.append("  - conflicts with: " + ", ".join(f"`{x}`" for x in cand["conflicts_with"]))
    return "\n".join(out) + "\n"


def render_sums(files: dict[str, bytes]) -> str:
    return "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files.items()))


def classify(case: dict[str, Any], observed: Verdict, *, strict: bool = False) -> tuple[str, str | None]:
    """Return (status, error). Status is one of pass / fail / open / closed / decision.

    Ratchet (default): a witness or decision must behave exactly as recorded; a witness that became satisfied is an
    error too, because it has to be promoted. Target state (`strict`): a witness must be satisfied; decision records
    are not judged."""
    cand = case["candidate"]
    expected = (case["expected_verdict"], case["expected_refusal"])
    if cand["role"] == "control":
        return ("pass", None) if observed == expected else ("fail", f"control expected {expected}, got {observed}")
    recorded = (cand["reference_result"]["verdict"], cand["reference_result"]["refusal"])
    if cand["role"] == "decision":
        if strict or observed == recorded:
            return "decision", None
        return "fail", f"decision case recorded {recorded}, got {observed}"
    satisfied = is_satisfied(case, observed)
    if strict:
        return ("closed", None) if satisfied else ("open", f"open witness: expected {expected}, got {observed}")
    if satisfied:
        return "closed", f"witness is now satisfied ({observed}); promote it to vectors/security-conformance.json and remove it here"
    if observed != recorded:
        return "open", f"witness still open but its behaviour changed: recorded {recorded}, got {observed}"
    return "open", None


def self_test() -> None:
    """Negative controls for the classifier itself: a changed result must never be reported as a clean pass."""
    def case(role: str, expected: Verdict, recorded: Verdict | None = None, code_status: str | None = None, also: list[Verdict] | None = None) -> dict[str, Any]:
        cand: dict[str, Any] = {"role": role}
        if recorded is not None:
            cand["reference_result"] = {"verdict": recorded[0], "refusal": recorded[1]}
        if code_status is not None:
            cand["refusal_code_status"] = code_status
        if also:
            cand["also_acceptable"] = [{"verdict": v, "refusal": c, "why": "self-test"} for v, c in also]
        return {"expected_verdict": expected[0], "expected_refusal": expected[1], "candidate": cand}

    control = case("control", ("ADMIT", None))
    assert classify(control, ("ADMIT", None)) == ("pass", None)
    assert classify(control, ("REFUSE", "WIRE_SIGNATURE"))[0] == "fail"
    assert classify(control, ("REFUSE", "WIRE_SIGNATURE"), strict=True)[0] == "fail", "controls are judged in both modes"
    refusing_control = case("control", ("REFUSE", "QUOTA_EXCEEDED"))
    assert classify(refusing_control, ("REFUSE", "WIRE_MEMBER"))[0] == "fail", "a control refusing with another code must fail"
    witness = case("witness", ("REFUSE", "ORIGIN_BINDING_INVALID"), ("ADMIT_WARD", None), "derived", also=[("REFUSE", "ORIGIN_STATUS_INCOMPLETE")])
    assert classify(witness, ("ADMIT_WARD", None)) == ("open", None)
    assert classify(witness, ("ADMIT_WARD", None), strict=True)[0] == "open" and classify(witness, ("ADMIT_WARD", None), strict=True)[1]
    for accepted in (("REFUSE", "ORIGIN_BINDING_INVALID"), ("REFUSE", "ORIGIN_STATUS_INCOMPLETE")):
        assert classify(witness, accepted)[0] == "closed" and classify(witness, accepted)[1], "ratchet: a closed witness must be promoted"
        assert classify(witness, accepted, strict=True) == ("closed", None)
    assert classify(witness, ("REFUSE", "WIRE_MEMBER"))[0] == "open" and classify(witness, ("REFUSE", "WIRE_MEMBER"))[1], "an unlisted code is not closure"
    assert classify(witness, ("REFUSE", "WIRE_MEMBER"), strict=True)[0] == "open"
    assert classify(witness, ("ADMIT_AUTONOMOUS", None))[0] == "open", "another admit verdict is not closure"
    verdict_only = case("witness", ("REFUSE", None), ("ADMIT", None), "undefined")
    assert classify(verdict_only, ("REFUSE", "ANY_CODE"))[0] == "closed"
    assert classify(verdict_only, ("ADMIT", None)) == ("open", None)
    wrong_code = case("witness", ("REFUSE", "WIRE_INTEGER"), ("REFUSE", "WIRE_MEMBER"), "text")
    assert classify(wrong_code, ("REFUSE", "WIRE_MEMBER")) == ("open", None)
    assert classify(wrong_code, ("ADMIT", None))[1], "a refusal that turns into ADMIT must be reported"
    scenario = case("witness", ("ADMIT", None), ("REFUSE", "SESSION_STEP_MISMATCH:open:('ADMIT', None)"), "derived")
    assert classify(scenario, ("ADMIT", None))[0] == "closed"
    assert classify(scenario, ("REFUSE", "SESSION_STEP_MISMATCH:open:('REFUSE', 'WIRE_MEMBER')"))[0] == "open", "a step refusing with another code is not closure"
    decision = case("decision", ("REFUSE", "ORIGIN_STATUS_INCOMPLETE"), ("REFUSE", "ORIGIN_UNVERIFIED"))
    assert classify(decision, ("REFUSE", "ORIGIN_UNVERIFIED")) == ("decision", None)
    assert classify(decision, ("REFUSE", "ORIGIN_STATUS_INCOMPLETE"))[0] == "fail"
    assert classify(decision, ("REFUSE", "ORIGIN_STATUS_INCOMPLETE"), strict=True) == ("decision", None)


def run_cases(suite: dict[str, Any], *, strict: bool, quiet: bool) -> list[str]:
    errors: list[str] = []
    rows = []
    for case in suite["cases"]:
        observed = sec.execute_security_case(case)
        status, err = classify(case, observed, strict=strict)
        if err:
            errors.append(f"{case['id']}: {err}")
        rows.append((case["candidate"]["finding"], case["candidate"]["role"], status, case["id"], observed))
    if not quiet:
        for finding, role, status, cid, observed in rows:
            print(f"{finding:<6} {role:<8} {status:<8} {cid:<76} -> {observed[0]}{'/' + observed[1] if observed[1] else ''}")
    counts = {st: sum(1 for r in rows if r[2] == st) for st in ("pass", "open", "closed", "decision", "fail")}
    print(
        f"review-candidates: {len(rows)} cases | controls pass {counts['pass']} | witnesses open {counts['open']}, closed {counts['closed']} | "
        f"decisions {counts['decision']} | failures {counts['fail']}"
    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Build and check the {REFERENCE_LABEL} review-candidate negative vectors (non-normative).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Verify the committed suite (default).")
    mode.add_argument("--write", action="store_true", help="Regenerate the suite JSON, INDEX.md and SHA256SUMS.")
    mode.add_argument("--list", action="store_true", help="Only execute the committed cases and print the per-case table.")
    parser.add_argument("--strict", action="store_true", help="Target state: every witness must return an accepted result (decision records are not judged).")
    parser.add_argument("--quiet", action="store_true", help="Print only the summary line.")
    args = parser.parse_args()
    self_test()

    def sums() -> str:
        return render_sums({name: (SUITE_DIR / name).read_bytes() for name in SUMMED_FILES})

    if args.write:
        try:
            suite = build_candidate_suite()
        except AssertionError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        text = render(suite)
        SUITE_DIR.mkdir(parents=True, exist_ok=True)
        SUITE_PATH.write_text(text, encoding="utf-8")
        INDEX_PATH.write_text(render_index(suite), encoding="utf-8")
        missing = [name for name in SUMMED_FILES if not (SUITE_DIR / name).is_file()]
        if missing:
            print(f"FAIL: {', '.join(missing)} missing in {SUITE_DIR.relative_to(ROOT)}", file=sys.stderr)
            return 1
        SUMS_PATH.write_text(sums(), encoding="utf-8")
        print(f"Wrote {SUITE_PATH.relative_to(ROOT)} ({len(text.encode('utf-8'))} bytes), {INDEX_PATH.relative_to(ROOT)} and {SUMS_PATH.relative_to(ROOT)}")
        return 0

    missing = [name for name in (*SUMMED_FILES, SUMS_PATH.name) if not (SUITE_DIR / name).is_file()]
    if missing:
        print(f"FAIL: {', '.join(missing)} missing in {SUITE_DIR.relative_to(ROOT)}; run with --write", file=sys.stderr)
        return 1
    committed = SUITE_PATH.read_text(encoding="utf-8")
    suite = json.loads(committed)
    errors: list[str] = []
    if not args.list:
        try:
            regenerated = render(build_candidate_suite(verify=False))
        except AssertionError as exc:
            errors.append(f"the generator could not rebuild its fixtures: {exc}")
        else:
            if regenerated != committed:
                errors.append(f"{SUITE_PATH.relative_to(ROOT)} differs from the generator output; run with --write and review the diff")
        if INDEX_PATH.read_text(encoding="utf-8") != render_index(suite):
            errors.append(f"{INDEX_PATH.relative_to(ROOT)} is not the index of the committed suite; run with --write")
        if SUMS_PATH.read_text(encoding="utf-8") != sums():
            errors.append(f"{SUMS_PATH.relative_to(ROOT)} does not match the files in {SUITE_DIR.relative_to(ROOT)}; run with --write")
    errors.extend(run_cases(suite, strict=args.strict, quiet=args.quiet))
    if errors:
        for e in errors:
            print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print("PASS" + (" (strict: every witness closed)" if args.strict else " (recorded behaviour; use --strict to require every witness closed)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
