#!/usr/bin/env python3
"""
Review-candidate negative vectors for the v1.0.0-draft.6 Blocker findings (B-1 .. B-15).

Builds and checks `conformance/review-candidates/draft6-blockers.json`. Every case has the exact shape of a
`vectors/security-conformance.json` case (same runners, executed by `build_security_suite.execute_security_case`,
which never reads `expected_*`) plus a `candidate` block describing its role.

The suite is NOT normative and deliberately lives outside `vectors/`: most witnesses are still ADMITted by the
draft.6 Reference Verifier Core, and several items need an authors' decision before a single expected result exists.

Case roles (`candidate.role`):
  control   passes on the reference today and must keep passing; pairs every witness with a nearby valid case so that
            an implementation refusing everything cannot satisfy the suite.
  witness   `expected_*` is what the cited specification text requires (`candidate.also_acceptable` lists other results
            the text equally permits); `candidate.reference_draft6` is what the draft.6 reference returns today (a false
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
import sys
from pathlib import Path
from typing import Any, Callable

import build_branch_suite as bs
import build_refusal_matrix as rm
import build_security_suite as sec
import seallink_ref as sl
import seallink_verifier as sv

ROOT = Path(__file__).resolve().parent.parent
SUITE_DIR = ROOT / "conformance" / "review-candidates"
SUITE_NAME = "draft6-blockers.json"
SUITE_PATH = SUITE_DIR / SUITE_NAME
INDEX_PATH = SUITE_DIR / "INDEX.md"
SUMS_PATH = SUITE_DIR / "SHA256SUMS"
SUMMED_FILES = ("INDEX.md", "README.md", SUITE_NAME)
VERSION = rm.VERSION
G = rm.GENESIS_MAIN
REFERENCE_TAG = "v1.0.0-draft.6"

ROLES = ("control", "witness", "decision")
CODE_STATUS = {
    "text": "The refusal code is named by the cited rule or by its registry description for exactly this condition.",
    "derived": (
        "No rule names a code for this exact condition, but the text says that the varied element does not change the "
        "subject's status (an unauthenticated presenter-supplied element, or an update the text says 'NEVER unbinds'), so the "
        "expected result equals the paired control's. Where failing closed on the element itself is equally defensible, that "
        "result is listed in also_acceptable."
    ),
    "undefined": (
        "draft.6 defines no admission step or refusal code for this condition: expected_refusal is null, only the verdict "
        "is compared, and candidate.proposed_refusal is informative."
    ),
}

Verdict = tuple[str, str | None]

# Controls shared by several findings (referenced by id from later builders, so every fixture exists once).
CTL_OWNER_ISSUED_MAIL_GRANT_ADMITS = "cand-b01-control-owner-issued-grant-admits"  # published trace-01 step 1
CTL_PUBLISHED_WARD_GRANT_ADMITS = "cand-b02-control-published-ward-grant-admits"  # published trace-04 step 4
CTL_DELEGATION_WITHOUT_NOTARY_ADMITS = "cand-b04-control-notary-mode-none-admits"  # depth-2 fixture, notary_mode = none


# ---------------------------------------------------------------------------
# Deterministic helpers
# ---------------------------------------------------------------------------

def _h32(label: str) -> str:
    return sl.sha256(f"seallink-candidate-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    """A key that exists only in this suite."""
    sk = sl.deterministic_privkey(f"candidate:{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _vkp(label: str) -> dict[str, Any]:
    """A key of a published `tools/gen_vectors.py` fixture (same derivation as `gen_vectors.make_keypair`)."""
    sk = sl.deterministic_privkey(label)
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


def _published_matrix_case(code: str) -> dict[str, Any]:
    for case in _vector("refusal-coverage-matrix.json")["cases"]:
        if case["code"] == code:
            return case
    raise KeyError(code)


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
            "reference_draft6": {"verdict": reference[0], "refusal": reference[1]},
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
        cand: dict[str, Any] = {
            "role": "decision",
            "question": question,
            "readings": readings,
            "reference_draft6": {"verdict": reference[0], "refusal": reference[1]},
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
# Shared worlds built from the published traces
# ---------------------------------------------------------------------------

def _mail_world() -> dict[str, Any]:
    """Published trace-01: autonomous id/alice, provider id/mail-host-a bound by alice's manifest."""
    t1 = _vector("trace-01-mail-offline-revoke.json")
    alice_man = t1["ledger_state"]["alice_manifest"]["object"]
    host_man = t1["ledger_state"]["host_manifest"]["object"]
    return {
        "t1": t1,
        "chain": t1["initial_chain_state"],
        "journal": t1["initial_journal_state"],
        "executor_cfg": t1["executor_config"],
        "manifests": {sl.content_addr(alice_man): alice_man, sl.content_addr(host_man): host_man},
        "alice_manifest": alice_man,
        "grant": t1["grant"]["object"],
        "invocation": t1["steps"][0]["invocation"]["object"],
        "recent_block": t1["grant"]["object"]["payload"]["recent_block"],
    }


def _mail_read_invocation(world: dict[str, Any], grant_id: str, issuance_txid: str, target: str, signer: dict[str, Any], tag: str) -> dict[str, Any]:
    cfg = world["executor_cfg"]
    return sl.sign_envelope(
        {
            "action": "mail/read",
            "arguments": {"folder": "Personal", "message_id": "msg-private-1"},
            "executor": {"key": cfg["key"], "name": cfg["name"]},
            "exp": 1795220300,
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


def _agent_world() -> dict[str, Any]:
    """Published trace-04 after its slot-2 activation patch: ward agent id/agent-nova, guardians A + B, station id/station-nova."""
    t4 = _vector("trace-04-agent-guardian-intake.json")
    view = sv.ChainView(t4["initial_chain_state"])
    for step in t4["steps"]:
        if "chain_patch" in step:
            view.apply_patch(step["chain_patch"])
    origin_bundle = {
        "origin": t4["origin"]["object"],
        "origin_anchor_txid": t4["origin_anchor_txid"],
        "name_binding": t4["name_binding"]["object"],
        "name_binding_txid": t4["name_binding_txid"],
        "guardian_records": [g["object"] for g in t4["guardian_records"]],
        "guardian_assents": [g["object"] for g in t4["guardian_assents"]],
        "roster_records": [],
        "initial_guardian_disclosures": t4["initial_guardian_disclosures"],
    }
    raw_message = t4["raw_message_utf8"].encode("utf-8")
    return {
        "t4": t4,
        "chain": copy.deepcopy(view.raw),
        "journal": t4["initial_journal_state"],
        "executor_cfg": t4["executor_config"],
        "origin_bundle": origin_bundle,
        "origin_payload": t4["origin"]["object"]["payload"],
        "origin_id": sl.object_id(t4["origin"]["object"]["payload"]),
        "binding": t4["name_binding"]["object"],
        "trusted_origin_issuers": t4["trusted_origin_issuers"],
        "raw_message_hex": raw_message.hex(),
        "message_sha256": sl.sha256(raw_message).hex(),
        "grant": t4["ward_grant_valid"]["object"],
        "invocation": t4["steps"][3]["invocation"]["object"],
        "recent_block": t4["ward_grant_valid"]["object"]["payload"]["recent_block"],
        "guardian_a": _vkp("t4-ga-gr"),
        "guardian_b": _vkp("t4-gb-gr"),
        "bridge": _vkp("t4-bridge-req"),
    }


def _agent_inputs(world: dict[str, Any], *, grant: dict[str, Any], invocation: dict[str, Any], chain: dict[str, Any] | None = None,
                  origin_bundle: dict[str, Any] | None | bool = True, executor_cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    bundle: dict[str, Any] = {"grants": [grant]}
    if origin_bundle is True:
        bundle["origin_bundle"] = world["origin_bundle"]
    elif origin_bundle:
        bundle["origin_bundle"] = origin_bundle
    return {
        "invocation": invocation,
        "bundle": bundle,
        "chain": chain if chain is not None else world["chain"],
        "journal": world["journal"],
        "executor_cfg": executor_cfg if executor_cfg is not None else world["executor_cfg"],
        "trusted_origin_issuers": world["trusted_origin_issuers"],
        "raw_message_hex": world["raw_message_hex"],
    }


def _guardian_message_grant(world: dict[str, Any], tag: str, issuer: dict[str, Any], target_origin_id: str, ward_name_arg: str,
                            seal_kp: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    cfg = world["executor_cfg"]
    return {
        "capabilities": [
            {
                "action": "agent/guardian-message",
                "target": f"ward:{target_origin_id}",
                "where": {
                    "channel": {"eq": "nostr-dm"},
                    "delivery_mode": {"eq": "strict_drop"},
                    "message_sha256": {"hash_eq": world["message_sha256"]},
                    "origin_id": {"eq": target_origin_id},
                    "subject_ward_name": {"eq": ward_name_arg},
                },
            }
        ],
        "executor": {"key": cfg["key"], "name": cfg["name"]},
        "genesis": G,
        "issuer": issuer,
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 750000,
        "recent_block": world["recent_block"],
        "recipient": {"key": world["bridge"]["xonly"], "mode": "key"},
        "revocation": _revocation(seal_kp, tag),
        "type": "seallink-grant/1",
        **extra,
    }


def _guardian_message_invocation(world: dict[str, Any], tag: str, grant_id: str, issuance_txid: str, target_origin_id: str, ward_name_arg: str) -> dict[str, Any]:
    cfg = world["executor_cfg"]
    return sl.sign_envelope(
        {
            "action": "agent/guardian-message",
            "arguments": {
                "channel": "nostr-dm",
                "delivery_mode": "strict_drop",
                "message_sha256": world["message_sha256"],
                "origin_id": target_origin_id,
                "revision": 1,
                "subject_ward_name": ward_name_arg,
            },
            "executor": {"key": cfg["key"], "name": cfg["name"]},
            "exp": 1795220500,
            "genesis": G,
            "iat": 1795220000,
            "network": "main",
            "nonce": _h32(f"{tag}-nonce"),
            "proof_path": [{"grant_id": grant_id, "issuance_txid": issuance_txid}],
            "target": f"ward:{target_origin_id}",
            "type": "seallink-invocation/1",
        },
        [world["bridge"]["sk"]],
    )


def _both_guardians(world: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"slot": 1, "revision": 1, "guardian_name": "id/guardian-a", "signers": [world["guardian_a"]["sk"]]},
        {"slot": 2, "revision": 1, "guardian_name": "id/guardian-b", "signers": [world["guardian_b"]["sk"]]},
    ]


# ---------------------------------------------------------------------------
# B-1  issuer <-> target authority
# ---------------------------------------------------------------------------

def build_b01(s: CandidateSuite) -> None:
    s.finding(
        "B-1",
        "No binding between the grant issuer and the owner of the target resource: a foreign grant opens another owner's mailbox",
        ["spec/SPEC-06 §4 (SL-GRNT-012)", "profiles/PROFILE-mail-v1.md §4 (SL-MAIL-003)", "spec/SPEC-07 §1 (SL-SERV-001)"],
    )
    rules = ["SL-GRNT-012", "SL-MAIL-003", "SL-SERV-001"]
    basis = (
        "PROFILE-mail-v1 §4 (SL-MAIL-003): the provider MUST verify 'that the root grant was issued by <owner_name>' of "
        "mailbox:<owner_name>:<label>. The 12-step order of SPEC-06 §4 has no step for it. The closest registered code is "
        "INVOKE_CONSTRAINT_FAILED ('Signed invocation target or arguments violate a grant capability where-predicate or profile "
        "check'); a dedicated code would be the alternative."
    )
    w = _mail_world()
    host_pin = w["alice_manifest"]["providers"][0]["provider"]
    m_owner, m_grant, m_seal, m_req = _kp("b01-mallory-owner"), _kp("b01-mallory-grant"), _kp("b01-mallory-seal"), _kp("b01-mallory-request")
    m_reg = {"txid": _h32("b01-mallory-registration"), "vout": 0}
    m_manifest = {
        "network": "main",
        "owner": "id/mallory",
        "providers": [{"label": "work", "provider": host_pin, "service_type": "mail"}],
        "seq": 1,
        "type": "seallink-manifest/1",
    }
    m_value = {"link": {"grant": m_grant["xonly"]}, "m": {"h": sl.content_addr(m_manifest), "s": 1}}

    def mallory_case(tag: str, target: str, executor_part: dict[str, Any]) -> dict[str, Any]:
        chain = copy.deepcopy(w["chain"])
        chain["names"]["id/mallory"] = sv.make_name_history("id/mallory", m_reg, _key_pol(m_owner), m_value, first_height=748000, update_height=749000)
        payload = {
            "capabilities": [{"action": "mail/read", "target": target}],
            **executor_part,
            "genesis": G,
            "issuer": {"name": "id/mallory", "owner_policy": _key_pol(m_owner), "registration": m_reg, "role_policy": {"m": 1, "pks": [m_grant["xonly"]]}},
            "network": "main",
            "not_after_height": 760000,
            "not_before_height": 750000,
            "recent_block": w["recent_block"],
            "recipient": {"key": m_req["xonly"], "mode": "key"},
            "revocation": _revocation(m_seal, tag),
            "type": "seallink-grant/1",
        }
        grant = sl.sign_envelope(payload, [m_grant["sk"]])
        itx = _anchor_root_grant(chain, grant, tag)
        manifests = dict(w["manifests"])
        manifests[sl.content_addr(m_manifest)] = m_manifest
        return {
            "invocation": _mail_read_invocation(w, sl.object_id(payload), itx, target, m_req, tag),
            "bundle": {"grants": [grant], "manifests": manifests},
            "chain": chain,
            "journal": w["journal"],
            "executor_cfg": w["executor_cfg"],
        }

    def ref(provider_of: str) -> dict[str, Any]:
        return {"executor_ref": {"label": "work", "provider_of": provider_of, "service_type": "mail"}}

    concrete = {"executor": {"key": w["executor_cfg"]["key"], "name": w["executor_cfg"]["name"]}}

    c_owner = s.control(
        CTL_OWNER_ISSUED_MAIL_GRANT_ADMITS,
        rules,
        "invocation",
        {"invocation": w["invocation"], "bundle": {"grants": [w["grant"]], "manifests": w["manifests"]}, "chain": w["chain"], "journal": w["journal"], "executor_cfg": w["executor_cfg"]},
        ("ADMIT", None),
        "Published trace-01 step 1: id/alice issues mail/read over her own mailbox:id/alice:work.",
    )
    c_own_mailbox = s.control(
        "cand-b01-control-mallory-own-mailbox-admits",
        rules,
        "invocation",
        mallory_case("b01-own", "mailbox:id/mallory:work", ref("id/mallory")),
        ("ADMIT", None),
        "id/mallory (own link.grant, own manifest binding the same provider, own seal and 0x01 anchor) issues mail/read over her "
        "OWN mailbox through executor_ref. Shows that the Mallory world is fully valid; the witnesses below change only the mailbox owner.",
    )
    c_own_concrete = s.control(
        "cand-b01-control-mallory-own-mailbox-concrete-executor-admits",
        rules,
        "invocation",
        mallory_case("b01-own-exec", "mailbox:id/mallory:work", concrete),
        ("ADMIT", None),
        "The same over her own mailbox with a concrete executor (id/mail-host-a, which her manifest binds) instead of executor_ref.",
    )
    s.witness(
        "cand-b01-foreign-issuer-executor-ref-of-victim",
        rules,
        "invocation",
        mallory_case("b01-ref", "mailbox:id/alice:work", ref("id/alice")),
        ("REFUSE", None),
        "Same Mallory-issued grant, but over mailbox:id/alice:work with executor_ref.provider_of = id/alice. Alice signed nothing.",
        reference=("ADMIT", None),
        code_status="undefined",
        proposed_refusal="INVOKE_CONSTRAINT_FAILED",
        basis=basis,
        controls=[c_owner, c_own_mailbox],
    )
    s.witness(
        "cand-b01-foreign-issuer-concrete-executor",
        rules,
        "invocation",
        mallory_case("b01-exec", "mailbox:id/alice:work", concrete),
        ("REFUSE", None),
        "Same, with a concrete executor (id/mail-host-a) instead of executor_ref: no manifest of the mailbox owner is consulted at all.",
        reference=("ADMIT", None),
        code_status="undefined",
        proposed_refusal="INVOKE_CONSTRAINT_FAILED",
        basis=basis,
        controls=[c_owner, c_own_concrete],
    )


# ---------------------------------------------------------------------------
# B-2  origin bundle not bound to the issuer
# ---------------------------------------------------------------------------

def build_b02(s: CandidateSuite) -> None:
    s.finding(
        "B-2",
        "The issuer signature is not verified when the presenter attaches the origin bundle of any ward: arbitrary issuer impersonation",
        ["spec/SPEC-06 §4 steps 7a/7b", "spec/SPEC-04 §3.3 (SL-ORIG-006)"],
    )
    rules = ["SL-GRNT-012", "SL-ORIG-006", "SL-IDEN-003"]
    basis = (
        "SPEC-06 §4: step 7b applies only 'If origin-certified (link.origin or pinned origin)'; the issuer here has neither, so "
        "step 7a requires issuer.role_policy == link.grant == root_grant.signatures.policy (WIRE_SIGNATURE). A presenter-supplied "
        "origin bundle of an unrelated subject must not change that: the expected code is the one returned without the bundle."
    )
    mail, agent = _mail_world(), _agent_world()
    chain = copy.deepcopy(mail["chain"])
    for key in ("names", "txs", "blocks"):
        chain[key].update(copy.deepcopy(agent["chain"][key]))
    atk_req, atk_seal = _kp("b02-attacker-request"), _kp("b02-attacker-seal")
    alice_pin = copy.deepcopy(mail["grant"]["payload"]["issuer"])
    alice_pin.pop("role_policy")
    payload = {
        "capabilities": [{"action": "mail/read", "target": "mailbox:id/alice:work"}],
        "executor_ref": {"label": "work", "provider_of": "id/alice", "service_type": "mail"},
        "genesis": G,
        "guardian_context": {"event_class": "routine_read", "origin_id": agent["origin_id"], "revision": 1, "ward_name": "id/agent-nova"},
        "issuer": alice_pin,
        "network": "main",
        "not_after_height": 760000,
        "not_before_height": 750000,
        "recent_block": mail["recent_block"],
        "recipient": {"key": atk_req["xonly"], "mode": "key"},
        "revocation": _revocation(atk_seal, "b02-alice"),
        "type": "seallink-grant/1",
    }
    payload["guardian_context"]["event_class"] = sl.derive_guardian_event_class(payload)
    grant = sl.sign_guardian_envelope(payload, _both_guardians(agent))
    itx = _anchor_root_grant(chain, grant, "b02-alice")
    invocation = _mail_read_invocation(mail, sl.object_id(payload), itx, "mailbox:id/alice:work", atk_req, "b02-alice")

    def inputs(with_bundle: bool) -> dict[str, Any]:
        bundle: dict[str, Any] = {"grants": [grant], "manifests": mail["manifests"]}
        if with_bundle:
            bundle["origin_bundle"] = agent["origin_bundle"]
        return {
            "invocation": invocation,
            "bundle": bundle,
            "chain": chain,
            "journal": mail["journal"],
            "executor_cfg": mail["executor_cfg"],
            "trusted_origin_issuers": agent["trusted_origin_issuers"],
        }

    c_no_bundle = s.control(
        "cand-b02-control-same-grant-without-origin-bundle-refuses",
        rules,
        "invocation",
        inputs(False),
        ("REFUSE", "WIRE_SIGNATURE"),
        "A grant naming autonomous id/alice as issuer but carrying guardian_approvals of an unrelated ward's guardians, presented "
        "WITHOUT any origin bundle: the autonomous path (step 7a) refuses.",
    )
    c_ward = s.control(
        CTL_PUBLISHED_WARD_GRANT_ADMITS,
        rules,
        "invocation",
        _agent_inputs(agent, grant=agent["grant"], invocation=agent["invocation"]),
        ("ADMIT", None),
        "Published trace-04 step 4: the ward id/agent-nova's own grant, approved 2-of-2 by its guardians, with its own origin bundle.",
    )
    s.witness(
        "cand-b02-autonomous-issuer-impersonated-via-foreign-ward-bundle",
        rules,
        "invocation",
        inputs(True),
        ("REFUSE", "WIRE_SIGNATURE"),
        "The identical presentation plus the attacker's own ward origin bundle (id/agent-nova, issued by the trusted id/agent-registry). "
        "id/alice has no link.origin, is pinned nowhere as a ward, and never signs; her mailbox is read.",
        reference=("ADMIT", None),
        code_status="derived",
        basis=basis,
        controls=[c_no_bundle, CTL_OWNER_ISSUED_MAIL_GRANT_ADMITS, c_ward],
    )

    # Same defect on the published trace-04 fixture: only grant.payload.issuer changes.
    chain4 = copy.deepcopy(agent["chain"])
    other = chain4["names"]["id/guardian-a"]
    p4 = copy.deepcopy(agent["grant"]["payload"])
    p4["issuer"] = {"name": "id/guardian-a", "owner_policy": other["updates"][-1]["owner_policy"], "registration": other["registration"]}
    p4["revocation"] = _revocation(atk_seal, "b02-swapped")
    g4 = sl.sign_guardian_envelope(p4, _both_guardians(agent))
    itx4 = _anchor_root_grant(chain4, g4, "b02-swapped")
    inv4 = _guardian_message_invocation(agent, "b02-swapped", sl.object_id(p4), itx4, agent["origin_id"], "id/agent-nova")
    c_no_bundle4 = s.control(
        "cand-b02-control-swapped-issuer-without-origin-bundle-refuses",
        rules,
        "invocation",
        _agent_inputs(agent, grant=g4, invocation=inv4, chain=chain4, origin_bundle=None),
        ("REFUSE", "WIRE_SIGNATURE"),
        "Published trace-04 ward grant with ONLY payload.issuer replaced by another existing autonomous name (id/guardian-a, which has "
        "its own link.grant), re-approved by the same two guardians, presented without the origin bundle.",
    )
    s.witness(
        "cand-b02-ward-bundle-accepted-for-a-different-issuer-name",
        rules,
        "invocation",
        _agent_inputs(agent, grant=g4, invocation=inv4, chain=chain4),
        ("REFUSE", "WIRE_SIGNATURE"),
        "The same grant with the ward's genuine origin bundle: guardian_context.ward_name and binding.name are id/agent-nova, the grant "
        "issuer is id/guardian-a. Nothing compares the verified binding with grant.issuer.",
        reference=("ADMIT", None),
        code_status="derived",
        basis=(
            basis + " In this case the bundle is the pinned ward's own; what is unrelated is the grant issuer (id/guardian-a), and the "
            "issuer name is resolved first (step 7a precedes every ward check of step 7b)."
        ),
        controls=[c_no_bundle4, c_ward],
    )


# ---------------------------------------------------------------------------
# B-3  agent/guardian-message without / across ward mode
# ---------------------------------------------------------------------------

def build_b03(s: CandidateSuite) -> None:
    s.finding(
        "B-3",
        "agent/guardian-message is admitted with the quorum of an unrelated ward, or with no ward mode at all",
        ["profiles/PROFILE-agent-v1.md §5 (SL-AGNT-004 steps 1 and 3)", "spec/SPEC-04 §3.3 (SL-ORIG-006)"],
    )
    rules = ["SL-AGNT-004", "SL-ORIG-006"]
    profile = (
        "PROFILE-agent-v1 §5 (SL-AGNT-004): the host loads the agent's locally pinned seallink-origin/1 (step 1) and executes SPEC-06 §4 'on "
        "the seallink-invocation/1 and its ward seallink-grant/1', verifying guardian_approvals[] 'per SL-WIRE-013 and SL-ORIG-006' (step 3). "
        "Read with the pinned ward as the subject of SL-ORIG-006 (the profile does not say so in as many words): "
    )
    a = _agent_world()
    atk_seal = _kp("b03-attacker-seal")
    published = a["invocation"]["payload"]["proof_path"][0]
    c_target = s.control(
        "cand-b03-control-target-names-another-ward-refuses",
        rules,
        "invocation",
        _agent_inputs(
            a,
            grant=a["grant"],
            invocation=_guardian_message_invocation(
                a, "b03-target", published["grant_id"], published["issuance_txid"], _h32("b03-other-ward-origin-id"), "id/agent-nova"
            ),
        ),
        ("REFUSE", "INVOKE_CONSTRAINT_FAILED"),
        "Station pins ward X; the published grant of X is presented with X's own bundle and approvals. Only the invocation target and "
        "arguments.origin_id name another ward: the target check is live. Grant origin and pin agree here, so this control does not move "
        "when the defect below is fixed.",
    )

    victim_origin_id = _h32("b03-victim-origin-id")
    cfg_victim = dict(a["executor_cfg"], pinned_ward_origin_id=victim_origin_id)
    chain = copy.deepcopy(a["chain"])
    issuer_x = {"name": "id/agent-nova", "owner_policy": a["binding"]["owner_policy"], "registration": a["binding"]["registration"]}
    px = _guardian_message_grant(
        a, "b03-cross", issuer_x, victim_origin_id, "id/victim-agent", atk_seal,
        {"guardian_context": {"event_class": "effect_grant", "origin_id": a["origin_id"], "revision": 1, "ward_name": "id/agent-nova"}},
    )
    gx = sl.sign_guardian_envelope(px, _both_guardians(a))
    itx = _anchor_root_grant(chain, gx, "b03-cross")
    s.witness(
        "cand-b03-guardians-of-ward-x-authorise-message-into-pinned-ward-y",
        rules,
        "invocation",
        _agent_inputs(a, grant=gx, invocation=_guardian_message_invocation(a, "b03-cross", sl.object_id(px), itx, victim_origin_id, "id/victim-agent"),
                      chain=chain, executor_cfg=cfg_victim),
        ("REFUSE", "ORIGIN_UNVERIFIED"),
        "Station pins ward Y. The grant is issued by ward X, approved by X's guardians, accompanied by X's origin bundle; only the capability "
        "target and the invocation arguments name Y. The verified origin_id is never compared with the pin.",
        reference=("ADMIT", None),
        code_status="text",
        basis=profile + "SL-ORIG-006.2: 'payload.guardian_context.origin_id or ward_name mismatch -> ORIGIN_UNVERIFIED' (the context names X, the pinned ward is Y).",
        controls=[CTL_PUBLISHED_WARD_GRANT_ADMITS, c_target],
        also_acceptable=[
            (
                "REFUSE",
                "INVOKE_CONSTRAINT_FAILED",
                "Profile step 3: 'Confirm invocation.target == \"ward:\" + origin_id, arguments.origin_id == origin_id', with origin_id taken "
                "from the verified grant origin (X) rather than from the pin; the published branch-agm-wrong-ward-target uses this code for a "
                "target that mismatches the pinned ward.",
            ),
        ],
    )

    chain2 = copy.deepcopy(a["chain"])
    ga_name = chain2["names"]["id/guardian-a"]
    issuer_ga = {
        "name": "id/guardian-a",
        "owner_policy": ga_name["updates"][-1]["owner_policy"],
        "registration": ga_name["registration"],
        "role_policy": {"m": 1, "pks": [a["guardian_a"]["xonly"]]},
    }
    p2 = _guardian_message_grant(a, "b03-plain", issuer_ga, a["origin_id"], "id/agent-nova", atk_seal, {})
    g2 = sl.sign_envelope(p2, [a["guardian_a"]["sk"]])
    itx2 = _anchor_root_grant(chain2, g2, "b03-plain")
    s.witness(
        "cand-b03-single-guardian-plain-grant-no-ward-context",
        rules,
        "invocation",
        _agent_inputs(a, grant=g2, invocation=_guardian_message_invocation(a, "b03-plain", sl.object_id(p2), itx2, a["origin_id"], "id/agent-nova"),
                      chain=chain2, origin_bundle=None),
        ("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN"),
        "One guardian of a 2-of-2 effect_grant roster issues an ORDINARY grant in its own name (no guardian_context, no approvals, no origin "
        "bundle) for agent/guardian-message on the pinned ward. The message enters the Authority Frame with zero verified slots.",
        reference=("ADMIT", None),
        code_status="text",
        basis=profile + "SL-ORIG-006.1: 'Missing payload.guardian_context or carrying top-level signatures instead of guardian_approvals[] -> WARD_AUTONOMOUS_FORBIDDEN'.",
        controls=[CTL_PUBLISHED_WARD_GRANT_ADMITS, c_target],
        also_acceptable=[
            ("REFUSE", "GUARDIAN_QUORUM_UNMET", "Profile step 3: the count of approving slots (zero) does not meet required(\"effect_grant\")."),
        ],
    )


# ---------------------------------------------------------------------------
# Depth-2 world: the published NOTARY_REQUIRED matrix fixture (parent by id/alice, one child on row 1)
# ---------------------------------------------------------------------------

def _delegated_base() -> dict[str, Any]:
    return _published_matrix_case("NOTARY_REQUIRED")["inputs"]


def _rebuild_delegated(
    inputs: dict[str, Any],
    *,
    mutate_parent: Callable[[dict[str, Any]], None] | None = None,
    mutate_child: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Re-sign parent (issuer key), child (delegate key) and invocation (recipient key) and re-anchor both 0x01 frames."""
    out = copy.deepcopy(inputs)
    parent_env, child_env = out["bundle"]["grants"]
    inv_p = copy.deepcopy(out["invocation"]["payload"])
    p_itx, c_itx = (entry["issuance_txid"] for entry in inv_p["proof_path"])
    pp = copy.deepcopy(parent_env["payload"])
    if mutate_parent:
        mutate_parent(pp)
    penv = sl.sign_envelope(pp, [rm._kp("alice-grant")["sk"]])
    cp = copy.deepcopy(child_env["payload"])
    cp["parent"]["grant_id"] = sl.object_id(pp)
    if mutate_child:
        mutate_child(cp)
    cenv = sl.sign_envelope(cp, [rm._kp("del-key")["sk"]])
    out["chain"]["txs"][p_itx]["opreturn_hex"] = _issuance_opret(penv)
    out["chain"]["txs"][c_itx]["opreturn_hex"] = _issuance_opret(cenv)
    inv_p["proof_path"][0]["grant_id"] = sl.object_id(pp)
    inv_p["proof_path"][1]["grant_id"] = sl.object_id(cp)
    out["invocation"] = sl.sign_envelope(inv_p, [rm._kp("agent-req")["sk"]])
    out["bundle"]["grants"] = [penv, cenv]
    return out


def _template(pp: dict[str, Any]) -> dict[str, Any]:
    return pp["delegate"]["groups"][0]["template"]


# ---------------------------------------------------------------------------
# B-4  notary_mode = required_act
# ---------------------------------------------------------------------------

def build_b04(s: CandidateSuite) -> None:
    s.finding(
        "B-4",
        'notary_mode = "required_act" is satisfied by any truthy bundle value; notary acts are verified nowhere',
        ["spec/SPEC-06 §3 item 4 (SL-GRNT-011)", "spec/SPEC-06 §4 step 9", "spec/SPEC-05 §5 (SL-CONT-011)"],
    )
    rules = ["SL-GRNT-011", "SL-CONT-011"]
    basis = (
        "SPEC-06 §3 item 4 (SL-GRNT-011): required_act 'additionally requires a verified seallink-notary/1 (act_kind = "
        "\"child-within-parent\") act (NOTARY_REQUIRED)'; registry: NOTARY_REQUIRED = 'Missing or invalid notary act where required by "
        "parent policy'. SPEC-05 §5 defines the act, its 0x04 anchor and its verification against link.notary; what draft.6 leaves open is "
        "how a grant designates the notary (schema members only) and how the act is presented."
    )
    base = _delegated_base()
    parent_env, child_env = base["bundle"]["grants"]
    assert _template(parent_env["payload"])["notary_mode"] == "required_act"
    rebuilt = sec.execute_security_case({"runner": "invocation", "inputs": _rebuild_delegated(base)})
    assert rebuilt == ("REFUSE", "NOTARY_REQUIRED"), f"B-4 fixture: an unchanged rebuild of the published NOTARY_REQUIRED case returned {rebuilt}"

    def no_notary(pp: dict[str, Any]) -> None:
        _template(pp)["notary_mode"] = "none"

    c_none = s.control(
        CTL_DELEGATION_WITHOUT_NOTARY_ADMITS,
        rules,
        "invocation",
        _rebuild_delegated(base, mutate_parent=no_notary),
        ("ADMIT", None),
        "The published NOTARY_REQUIRED matrix fixture rebuilt with template.notary_mode = \"none\": the delegation is otherwise valid "
        "(template.recipient_rule = {exact_key, K} and the child recipient is {key, K}).",
    )
    c_missing = s.control(
        "cand-b04-control-required-act-without-act-refuses",
        rules,
        "invocation",
        base,
        ("REFUSE", "NOTARY_REQUIRED"),
        "The published matrix fixture unchanged: required_act and no notary act in the presentation.",
    )

    def with_act(act: Any) -> dict[str, Any]:
        inputs = copy.deepcopy(base)
        inputs["bundle"]["notary_act"] = act
        return inputs

    wire = sv.Tier1Verifier()
    for tag, act, what in (
        ("junk-object", {"junk": True}, "an arbitrary JSON object {\"junk\": true}"),
        ("bare-type-object", {"type": "seallink-notary/1"}, "an unsigned object carrying only the type string"),
        ("string", "x", "the JSON string \"x\""),
    ):
        ok, wire_code = wire._verify_object_wire(act, expected_type="seallink-notary/1")
        assert not ok and wire_code.startswith("WIRE_"), f"B-4 fixture: {tag} unexpectedly passes the wire pipeline"
        s.witness(
            f"cand-b04-required-act-satisfied-by-{tag}",
            rules,
            "invocation",
            with_act(act),
            ("REFUSE", "NOTARY_REQUIRED"),
            f"The same presentation with bundle.notary_act = {what}: not a verified seallink-notary/1 in any sense.",
            reference=("ADMIT", None),
            code_status="text",
            basis=basis,
            controls=[c_none, c_missing],
            also_acceptable=[
                (
                    "REFUSE",
                    wire_code,
                    "An implementation that runs the SPEC-01 §7 wire pipeline on the presented act reports the wire failure of this object "
                    "first; SPEC-06 §4 step 3a does not list notary acts among the presented objects, so the text does not settle it.",
                ),
            ],
        )

    notary_owner, notary_key = _kp("b04-notary-owner"), _kp("b04-notary-role")
    act = sl.sign_envelope(
        {
            "act_kind": "child-within-parent",
            "attested_at": base["chain"]["now"],
            "details": {
                "child_grant_id": _h32("b04-another-child-grant"),
                "kind": "child-within-parent",
                "ordinal": 1,
                "parent_grant_id": sl.object_id(parent_env["payload"]),
            },
            "genesis": G,
            "lifecycle": "eternal",
            "network": "main",
            "notary": {
                "name": "id/notary-nowhere",
                "owner_policy": _key_pol(notary_owner),
                "registration": {"txid": _h32("b04-notary-registration"), "vout": 0},
                "role_policy": {"m": 1, "pks": [notary_key["xonly"]]},
            },
            "target_sha256": sl.content_addr(child_env),
            "tip_hash": base["chain"]["tip_hash"],
            "tip_height": base["chain"]["tip_height"],
            "type": "seallink-notary/1",
        },
        [notary_key["sk"]],
    )
    ok, why = wire._verify_object_wire(act, expected_type="seallink-notary/1")
    assert ok, f"B-4 fixture: the well-formed notary act must pass the wire pipeline ({why})"
    assert act["payload"]["details"]["child_grant_id"] != sl.object_id(child_env["payload"])
    s.witness(
        "cand-b04-required-act-satisfied-by-well-formed-act-for-another-child",
        rules,
        "invocation",
        with_act(act),
        ("REFUSE", "NOTARY_REQUIRED"),
        "bundle.notary_act = a schema-valid, correctly signed seallink-notary/1 (act_kind child-within-parent) that passes the wire "
        "pipeline but attests a DIFFERENT child_grant_id, is issued by a notary name that is not registered, and has no 0x04 anchor. "
        "No wire code applies, so NOTARY_REQUIRED is the only result.",
        reference=("ADMIT", None),
        code_status="text",
        basis=basis,
        controls=[c_none, c_missing],
    )


# ---------------------------------------------------------------------------
# B-5  unsigned name-binding without the binding seal
# ---------------------------------------------------------------------------

def build_b05(s: CandidateSuite) -> None:
    s.finding(
        "B-5",
        "Origin hijack: an unsigned seallink-name-binding/1 is accepted without a spend of origin.binding_seal",
        ["spec/SPEC-04 §2.1 item 4", "spec/SPEC-04 §2.2 (SL-ORIG-003)"],
    )
    rules = ["SL-ORIG-003", "SL-ORIG-002"]
    basis = (
        "SPEC-04 §2.2 (SL-ORIG-003.2): 'the registrar spends binding_seal (SIGHASH_ALL) with OP_RETURN 0x0c committing "
        "id(seallink-name-binding/1)'; SPEC-06 §4 step 7b: 'name-binding/1 validity (ORIGIN_BINDING_INVALID)'; registry: "
        "ORIGIN_BINDING_INVALID = 'Single-use name binding seal missing, out of height order, or registration already bound'. The binding "
        "object is unsigned, so the seal spend is its only authentication."
    )
    of = rm._base_origin_fixture()
    seal = of["origin_bundle"]["origin"]["payload"]["binding_seal"]
    claims = of["origin_bundle"]["origin"]["payload"]["claims"]
    genuine = of["origin_bundle"]["name_binding"]
    assert seal["txid"] not in of["chain"]["txs"], "B-5 fixture: the base origin fixture now materialises binding_seal; rebuild on top of it"
    assert genuine["name"] == claims["intended_name"] and genuine["owner_policy"] == claims["intended_owner_policy"], "B-5 fixture: base binding changed"

    def world(*, spend_seal: bool, binding: dict[str, Any] | None = None, anchor_height: int | None = None) -> dict[str, Any]:
        chain = copy.deepcopy(of["chain"])
        bundle = copy.deepcopy(of["origin_bundle"])
        chain["txs"][seal["txid"]] = {"confirmed_height": 748990, "outputs": {str(seal["vout"]): {"script_pubkey_hex": _spk(seal["script_policy"])}}}
        if binding is None:
            txid = bundle["name_binding_txid"]
        else:
            txid = _h32("b05-forged-binding-tx")
            bundle["name_binding"] = binding
            bundle["name_binding_txid"] = txid
            chain["txs"][txid] = {"confirmed_height": 749500, "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(binding)).hex(), "outputs": {}}
        if anchor_height is not None:
            chain["txs"][txid]["confirmed_height"] = anchor_height
        if spend_seal:
            chain["txs"][txid]["inputs"] = [sv.make_segwit_input(seal["txid"], seal["vout"])]
            chain["txs"][seal["txid"]]["outputs"][str(seal["vout"])]["spent_by_txid"] = txid
        else:
            chain["txs"][txid]["inputs"] = [sv.make_segwit_input(_h32("b05-unrelated-funding-tx"), 0)]
        return {"chain": chain, "origin_bundle": bundle, "trusted_origin_issuers": of["trusted_origin_issuers"]}

    c_spent = s.control(
        "cand-b05-control-binding-spends-binding-seal",
        rules,
        "origin_status",
        world(spend_seal=True),
        ("ADMIT_WARD", None),
        "Base origin fixture with origin.binding_seal materialised and spent by the 0x0c transaction that commits the genuine binding "
        "(name and owner_policy equal claims.intended_*).",
    )
    s.witness(
        "cand-b05-binding-anchored-without-spending-binding-seal",
        rules,
        "origin_status",
        world(spend_seal=False),
        ("REFUSE", "ORIGIN_BINDING_INVALID"),
        "The same genuine binding, but the 0x0c transaction spends an unrelated outpoint instead of origin.binding_seal; the seal UTXO is "
        "confirmed and still unspent. Anyone can broadcast such a frame.",
        reference=("ADMIT_WARD", None),
        code_status="text",
        basis=basis,
        controls=[c_spent],
    )
    m_owner = _kp("b05-mallory-owner")
    m_reg = {"txid": _h32("b05-mallory-registration"), "vout": 0}
    forged = dict(genuine, name="id/mallory", owner_policy=_key_pol(m_owner), registration=m_reg)

    def with_mallory(inputs: dict[str, Any]) -> dict[str, Any]:
        inputs["chain"]["names"]["id/mallory"] = sv.make_name_history(
            "id/mallory", m_reg, _key_pol(m_owner), {"link": {"origin": forged["origin_id"]}}, first_height=749005, update_height=749015
        )
        return inputs

    c_early = s.control(
        "cand-b05-control-forged-binding-anchored-before-origin-refuses",
        rules,
        "origin_status",
        with_mallory(world(spend_seal=False, binding=forged, anchor_height=748999)),
        ("REFUSE", "ORIGIN_BINDING_INVALID"),
        "A forged binding of the same origin to id/mallory anchored BEFORE h_origin: the height-order check is live.",
    )
    s.witness(
        "cand-b05-origin-hijacked-to-foreign-name-by-forged-binding",
        rules,
        "origin_status",
        with_mallory(world(spend_seal=False, binding=forged)),
        ("REFUSE", "ORIGIN_BINDING_INVALID"),
        "A third party who merely holds a copy of the origin document binds it to its own name id/mallory (!= claims.intended_name, "
        "own owner_policy) with a plain 0x0c transaction after h_origin. binding_seal stays unspent.",
        reference=("ADMIT_WARD", None),
        code_status="text",
        basis=basis,
        controls=[c_spent, c_early],
    )


# ---------------------------------------------------------------------------
# B-6  delegation template recipient_rule
# ---------------------------------------------------------------------------

def build_b06(s: CandidateSuite) -> None:
    s.finding(
        "B-6",
        "The delegation template recipient_rule is never enforced: a child grant can be written for any key",
        ["spec/SPEC-06 §3 item 3 (SL-GRNT-010)", "spec/SPEC-06 §4 step 9"],
    )
    rules = ["SL-GRNT-010", "SL-GRNT-009"]
    basis = (
        "SPEC-06 §3 item 3 (SL-GRNT-010): 'C.recipient satisfies template.recipient_rule (exact_key matches mode=\"key\"; exact_name "
        "matches mode=\"name\" with equal name and owner_policy; ...)'; §4 step 9: mechanical child narrowing against the group "
        "template -> GRANT_CHILD_WIDER."
    )
    base = _delegated_base()
    child_recipient = base["bundle"]["grants"][1]["payload"]["recipient"]
    assert _template(base["bundle"]["grants"][0]["payload"])["recipient_rule"] == {"key": child_recipient["key"], "mode": "exact_key"}, (
        "B-6 fixture: the published template no longer pins the child's recipient key"
    )

    def with_rule(rule: dict[str, Any] | None) -> Callable[[dict[str, Any]], None]:
        def mutate(pp: dict[str, Any]) -> None:
            _template(pp)["notary_mode"] = "none"
            if rule is not None:
                _template(pp)["recipient_rule"] = rule
        return mutate

    parent_not_after = base["bundle"]["grants"][0]["payload"]["not_after_height"]

    def wider_window(cp: dict[str, Any]) -> None:
        cp["not_after_height"] = parent_not_after + 1

    c_ok = CTL_DELEGATION_WITHOUT_NOTARY_ADMITS  # template.recipient_rule = {exact_key, K}, child recipient = {key, K}
    c_wider = s.control(
        "cand-b06-control-child-window-wider-than-parent-refuses",
        rules,
        "invocation",
        _rebuild_delegated(base, mutate_parent=with_rule(None), mutate_child=wider_window),
        ("REFUSE", "GRANT_CHILD_WIDER"),
        "The same fixture with the child window one block past the parent's: mechanical narrowing is live for other axes.",
    )
    s.witness(
        "cand-b06-exact-key-rule-names-a-different-key",
        rules,
        "invocation",
        _rebuild_delegated(base, mutate_parent=with_rule({"key": _kp("b06-intended-recipient")["xonly"], "mode": "exact_key"})),
        ("REFUSE", "GRANT_CHILD_WIDER"),
        "Only template.recipient_rule.key changes: the parent now pins a key that is NOT the child's recipient key.",
        reference=("ADMIT", None),
        code_status="text",
        basis=basis,
        controls=[c_ok, c_wider],
    )
    s.witness(
        "cand-b06-exact-name-rule-with-key-mode-recipient",
        rules,
        "invocation",
        _rebuild_delegated(base, mutate_parent=with_rule({"mode": "exact_name", "name": "id/alice-acct-agent", "owner_policy": _key_pol(rm._kp("agent-owner"))})),
        ("REFUSE", "GRANT_CHILD_WIDER"),
        "template.recipient_rule = {exact_name, id/alice-acct-agent, owner_policy}; the child recipient is still mode = \"key\".",
        reference=("ADMIT", None),
        code_status="text",
        basis=basis,
        controls=[c_ok, c_wider],
    )


# ---------------------------------------------------------------------------
# Quota-bearing mail/send world (base invocation fixture of the refusal matrix)
# ---------------------------------------------------------------------------

MAIL_QUOTA = {"kind": "seallink/count", "resource": "mailbox:id/alice:work", "unit": "messages", "window": "term"}


def _send_fixture(quotas: list[dict[str, Any]] | None) -> dict[str, Any]:
    fx = rm._base_invocation_fixture()
    gp = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
    cap: dict[str, Any] = {"action": "mail/send", "target": "mailbox:id/alice:work"}
    if quotas is not None:
        cap["quotas"] = quotas
    gp["capabilities"] = [cap]
    rm._reanchor_grant(fx, gp)
    return fx


def _send_invocation(fx: dict[str, Any], tag: str, *, nonce_tag: str | None = None, to: str = "bob@example.com") -> dict[str, Any]:
    p = copy.deepcopy(fx["invocation"]["payload"])
    p["action"] = "mail/send"
    p["arguments"] = {"body_sha256": _h32(f"{tag}-body"), "size_bytes": "100", "subject": "hi", "to": to}
    p["nonce"] = _h32(f"{nonce_tag or tag}-nonce")
    return sl.sign_envelope(p, [fx["_keys"]["agent_req"]["sk"]])


def _receipt(fx: dict[str, Any], inv_env: dict[str, Any]) -> dict[str, Any]:
    """A schema-valid executed receipt signed by the executor's receipt key."""
    p = inv_env["payload"]
    return sl.sign_envelope(
        {
            "action": p["action"],
            "executor_name": p["executor"]["name"],
            "genesis": p["genesis"],
            "grant_id": p["proof_path"][-1]["grant_id"],
            "invocation_id": sl.object_id(p),
            "network": p["network"],
            "outcome": "executed",
            "recorded_at": fx["chain"]["now"],
            "tip_hash": fx["chain"]["tip_hash"],
            "tip_height": fx["chain"]["tip_height"],
            "type": "seallink-receipt/1",
        },
        [fx["_keys"]["host_rcpt"]["sk"]],
    )


def _step(label: str, fx: dict[str, Any], invocation: dict[str, Any], want: Verdict, **extra: Any) -> dict[str, Any]:
    return {"label": label, "chain": fx["chain"], "invocation": invocation, "bundle": fx["bundle"], "want_verdict": want[0], "want_refusal": want[1], **extra}


SCENARIO_NOTE = (
    " (Scenario runner: the case verdict is ADMIT iff every step returns exactly its want_verdict / want_refusal and the "
    "post-conditions hold; otherwise the harness reports REFUSE with a *_STEP_MISMATCH pseudo-code.)"
)


# ---------------------------------------------------------------------------
# B-7  replay barrier
# ---------------------------------------------------------------------------

def build_b07(s: CandidateSuite) -> None:
    s.finding(
        "B-7",
        "The replay barrier relies on the receipt cache alone; the quota path records no nonce",
        ["spec/SPEC-06 §2.2 item 5 (SL-GRNT-007)", "spec/SPEC-06 §4 steps 3c and 12", "spec/SPEC-06 §6"],
    )
    rules = ["SL-GRNT-007", "SL-GRNT-012", "SL-GRNT-014"]
    basis = (
        "SPEC-06 §2.2 item 5: 'A repeated identical invocation_id MUST perform no second effect; the executor returns its stored signed "
        "receipt or refuses INVOKE_REPLAY per profile. A reused nonce with a different payload MUST refuse INVOKE_REPLAY.' "
        "§4 step 12 writes nonce + reservation entries atomically."
    )
    fx = _send_fixture([dict(MAIL_QUOTA, max="5")])
    inv = _send_invocation(fx, "b07-first")
    receipt = _receipt(fx, inv)

    c_cached = s.control(
        "cand-b07-control-restart-with-receipt-returns-cached-receipt",
        rules,
        "restart_recovery",
        {
            "executor_cfg": fx["executor_cfg"],
            "journal_id": _h32("b07-journal-cached"),
            "pre_restart_steps": [_step("first-send", fx, inv, ("ADMIT", None), receipt_env=receipt)],
            "post_restart_steps": [
                _step("same-invocation-after-restart", fx, inv, ("ADMIT", None), expect_zero_writes=True, expect_cached_receipt_ca=sl.content_addr(receipt)),
            ],
        },
        ("ADMIT", None),
        "Quota-bearing mail/send admitted, terminal settlement and receipt blob persisted, journal replayed after restart: the identical "
        "invocation returns the cached receipt and writes nothing." + SCENARIO_NOTE,
    )
    # The journal for that first send: the reservation and the terminal settlement (carrying receipt_sha256) exactly as the
    # reference persists them, preceded by the nonce entry that SPEC-06 §4 step 12 requires (the reference omits it on the
    # quota path: second witness). Replayed WITHOUT the receipt blob.
    scratch = sv.FencedJournal(_h32("b07-journal-no-blob"))
    first_run = sv.Tier1Verifier().verify_invocation(inv, fx["bundle"], sv.ChainView(fx["chain"]), scratch, fx["executor_cfg"], receipt_env_for_cache=receipt)
    kinds = [e["kind"] for e in scratch.entries]
    assert first_run.verdict == "ADMIT" and kinds[-1] == "settlement", (
        f"B-7 fixture: the first quota-bearing send returned {(first_run.verdict, first_run.refusal_code)} with journal entries {kinds}"
    )
    assert scratch.entries[-1]["body"]["invocation_id"] == sl.object_id(inv["payload"]) and scratch.entries[-1]["body"]["receipt_sha256"] == sl.content_addr(receipt)
    nonce_entry = {
        "kind": "nonce",
        "body": {"expires_at": inv["payload"]["exp"], "invocation_id": sl.object_id(inv["payload"]), "nonce": inv["payload"]["nonce"], "scope": "invocation"},
    }
    persisted = {"journal_id": scratch.journal_id, "initial_entries": [nonce_entry] + [{"kind": e["kind"], "body": e["body"]} for e in scratch.entries]}
    s.witness(
        "cand-b07-terminal-settlement-without-receipt-blob-reexecutes",
        rules,
        "invocation",
        {"invocation": inv, "bundle": fx["bundle"], "chain": fx["chain"], "journal": persisted, "executor_cfg": fx["executor_cfg"]},
        ("REFUSE", "INVOKE_REPLAY"),
        "The identical invocation presented again to a journal that already holds its nonce, reservation and terminal settlement (with "
        "receipt_sha256), while the receipt blob itself is unavailable (lost, corrupted, or the process crashed before it became "
        "durable). The reference reserves and settles a second time.",
        reference=("ADMIT", None),
        code_status="text",
        basis=(
            basis + " No stored receipt can be returned here, so INVOKE_REPLAY is the only response the sentence leaves; outcome = "
            "uncertain is defined for an unsettled reservation only (§4 step 3c). (PROFILE-mail-v1 §4 demands the original stored receipt "
            "for a duplicate mail/send and names no fallback when its bytes are gone.)"
        ),
        controls=[c_cached],
    )

    free = rm._base_invocation_fixture()
    free_second_p = copy.deepcopy(free["invocation"]["payload"])
    free_second_p["arguments"]["message_id"] = "msg-2"
    free_second = sl.sign_envelope(free_second_p, [free["_keys"]["agent_req"]["sk"]])
    c_free = s.control(
        "cand-b07-control-nonce-reuse-on-quota-free-path-refuses",
        rules,
        "sibling_rows_replay",
        {
            "chain": free["chain"],
            "journal": {"journal_id": _h32("b07-journal-free")},
            "executor_cfg": free["executor_cfg"],
            "steps": [
                {"label": "first-read", "invocation": free["invocation"], "bundle": free["bundle"], "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "same-nonce-different-arguments", "invocation": free_second, "bundle": free["bundle"], "want_verdict": "REFUSE", "want_refusal": "INVOKE_REPLAY"},
            ],
            "check_balances": [],
        },
        ("ADMIT", None),
        "Quota-free mail/read: a second invocation reusing the nonce with different arguments refuses INVOKE_REPLAY." + SCENARIO_NOTE,
    )
    first = _send_invocation(fx, "b07-shared", to="bob@example.com")
    second = _send_invocation(fx, "b07-shared", to="carol@example.com")
    differing = {k for k in first["payload"]["arguments"] if first["payload"]["arguments"][k] != second["payload"]["arguments"][k]}
    assert first["payload"]["nonce"] == second["payload"]["nonce"] and differing == {"to"}, "B-7 fixture: the two sends must differ in `to` only"
    grant_id = sl.object_id(fx["bundle"]["grants"][0]["payload"])
    s.witness(
        "cand-b07-nonce-reuse-on-quota-path-admitted",
        rules,
        "sibling_rows_replay",
        {
            "chain": fx["chain"],
            "journal": {"journal_id": _h32("b07-journal-quota")},
            "executor_cfg": fx["executor_cfg"],
            "steps": [
                {"label": "first-send", "invocation": first, "bundle": fx["bundle"], "want_verdict": "ADMIT", "want_refusal": None},
                {"label": "same-nonce-different-recipient", "invocation": second, "bundle": fx["bundle"], "want_verdict": "REFUSE", "want_refusal": "INVOKE_REPLAY"},
            ],
            "check_balances": [
                {"scope": f"own:{grant_id}", "qkey": "seallink/count|mailbox:id/alice:work|messages|term", "bucket_id": "term", "expected": 1},
            ],
        },
        ("ADMIT", None),
        "Quota-bearing mail/send: the second invocation reuses the nonce with a different recipient. The quota path writes no nonce "
        "entry, so the reference admits it and charges a second unit." + SCENARIO_NOTE,
        reference=("REFUSE", "STEP_MISMATCH:same-nonce-different-recipient:('ADMIT', None)"),
        code_status="text",
        basis=basis,
        controls=[c_free],
    )


# ---------------------------------------------------------------------------
# B-8  quota accounting
# ---------------------------------------------------------------------------

def build_b08(s: CandidateSuite) -> None:
    s.finding(
        "B-8",
        "Quota accounting is under-specified: required quotas, debit formulas and the blocks:N bucket anchor are undefined",
        ["spec/SPEC-06 §2.2 (SL-GRNT-007)", "spec/SPEC-06 §3 item 3 (R8.5)", "profiles/PROFILE-mail-v1.md §4.1", "registry/constraints.json"],
    )
    rules = ["SL-GRNT-007", "SL-GRNT-010", "SL-MAIL-004"]
    basis = (
        "SPEC-06 §2.2 item 1: 'A zero ceiling authorizes nothing; missing required quota refuses.' PROFILE-mail-v1 §4.1: mail/send 'MUST "
        "reserve 1 unit from {kind: seallink/count, resource: mailbox:<owner>:<label>, unit: messages}'. The text names no refusal "
        "code for a missing required quota and no machine-readable list of required quota keys per action."
    )

    def single(tag: str, quotas: list[dict[str, Any]] | None) -> dict[str, Any]:
        fx = _send_fixture(quotas)
        fx["invocation"] = _send_invocation(fx, tag)
        return fx

    c_one = s.control(
        "cand-b08-control-send-with-required-quota-admits",
        rules,
        "invocation",
        single("b08-max-1", [dict(MAIL_QUOTA, max="1")]),
        ("ADMIT", None),
        "mail/send under a capability carrying the profile's required quota key (messages, max 1).",
    )
    c_zero = s.control(
        "cand-b08-control-zero-ceiling-refuses",
        rules,
        "invocation",
        single("b08-max-0", [dict(MAIL_QUOTA, max="0")]),
        ("REFUSE", "QUOTA_EXCEEDED"),
        "The same capability with max = 0: 'A zero ceiling authorizes nothing'.",
    )
    s.witness(
        "cand-b08-quota-consuming-action-without-any-quota",
        rules,
        "invocation",
        single("b08-none", None),
        ("REFUSE", None),
        "mail/send (quota_consuming = true) under a capability with NO quotas member: unlimited sends.",
        reference=("ADMIT", None),
        code_status="undefined",
        proposed_refusal="QUOTA_EXCEEDED",
        basis=basis,
        controls=[c_one, c_zero],
    )
    s.witness(
        "cand-b08-quota-consuming-action-with-unrelated-quota-key",
        rules,
        "invocation",
        single("b08-unrelated", [dict(MAIL_QUOTA, max="1000000", unit="requests")]),
        ("REFUSE", None),
        "mail/send under a capability whose only quota is a registered but different key (same resource, unit requests instead of "
        "messages): the required messages quota is still missing.",
        reference=("ADMIT", None),
        code_status="undefined",
        proposed_refusal="QUOTA_EXCEEDED",
        basis=basis,
        controls=[c_one, c_zero],
    )

    # blocks:N bucket anchor of the parent's per-row account.
    window = "blocks:1000"
    d = bs._build_delegation_base()
    pp = copy.deepcopy(d["parent_env"]["payload"])
    template_cap = _template(pp)["capabilities"][0]
    for cap in (pp["capabilities"][0], template_cap):
        cap["quotas"][0]["window"] = window
    pp["delegate"]["pools"][0].update(window=window, max="3")
    template_cap["quotas"][0]["max"] = "1"
    penv = sl.sign_envelope(pp, [d["keys"]["org_gr"]["sk"]])
    parent_id = sl.object_id(pp)
    chain = copy.deepcopy(d["chain"])
    chain["txs"][d["parent_iss_tx"]]["opreturn_hex"] = _issuance_opret(penv)
    child_quota = {"kind": "seallink/count", "max": "1", "resource": template_cap["quotas"][0]["resource"], "unit": template_cap["quotas"][0]["unit"], "window": window}
    children = []
    for ordinal in (1, 2, 3):
        cp = copy.deepcopy(d["c1_env"]["payload"])
        cp["parent"] = {"grant_id": parent_id, "ordinal": ordinal}
        cp["revocation"]["seal"]["txid"] = _h32(f"b08-child-{ordinal}-seal-tx")
        cp["capabilities"][0]["quotas"] = [child_quota]
        cenv = sl.sign_envelope(cp, [d["keys"]["del_k"]["sk"]])
        seal = cp["revocation"]["seal"]
        itx = _h32(f"b08-child-{ordinal}-issuance-tx")
        chain["txs"][seal["txid"]] = {
            "confirmed_height": 750101,
            "inputs": [sv.make_segwit_input(_h32(f"b08-child-{ordinal}-funding-tx"), 0)],
            "outputs": {str(seal["vout"]): {"script_pubkey_hex": _spk(seal["script_policy"])}, str(seal["vout"] + 1): {"script_pubkey_hex": _spk(seal["script_policy"])}},
        }
        chain["txs"][itx] = {
            "confirmed_height": 750102,
            "inputs": [sv.make_segwit_input(d["rows_tx"], ordinal - 1), sv.make_segwit_input(seal["txid"], seal["vout"] + 1)],
            "opreturn_hex": _issuance_opret(cenv),
            "outputs": {},
        }
        children.append((ordinal, cenv, sl.object_id(cp), itx, cp["not_before_height"]))
    parent_nb = pp["not_before_height"]
    child_nb = children[0][4]
    tips = (parent_nb + 1050, parent_nb + 1150)
    assert child_nb > parent_nb and all((t - parent_nb) // 1000 == 1 for t in tips), "both tips share one parent-anchored bucket"
    assert (tips[0] - child_nb) // 1000 != (tips[1] - child_nb) // 1000, "the tips fall into different child-anchored buckets"

    def call(tip: int, ordinal: int, cenv: dict[str, Any], cid: str, itx: str, want: Verdict) -> dict[str, Any]:
        view = copy.deepcopy(chain)
        view["tip_height"] = tip
        view["comparison_peers"][0]["height"] = tip
        inv = sl.sign_envelope(
            {
                "action": "agent/tool",
                "arguments": {"input_sha256": _h32(f"b08-args-{tip}-{ordinal}"), "max_output_bytes": "1024", "tool_name": "pytest"},
                "executor": {"key": d["executor_cfg"]["key"], "name": d["executor_cfg"]["name"]},
                "exp": 1795221000,
                "genesis": G,
                "iat": 1795220000,
                "network": "main",
                "nonce": _h32(f"b08-nonce-{tip}-{ordinal}"),
                "proof_path": [{"grant_id": parent_id, "issuance_txid": d["parent_iss_tx"]}, {"grant_id": cid, "issuance_txid": itx}],
                "target": child_quota["resource"],
                "type": "seallink-invocation/1",
            },
            [d["keys"]["w1_k"]["sk"]],
        )
        return {"label": f"tip-{tip}-row-{ordinal}", "chain": view, "invocation": inv, "bundle": {"grants": [penv, cenv]}, "want_verdict": want[0], "want_refusal": want[1]}

    s.decision(
        "cand-b08-decision-blocks-window-row-account-bucket-anchor",
        rules,
        "restart_recovery",
        {
            "executor_cfg": d["executor_cfg"],
            "journal_id": _h32("b08-journal-blocks"),
            "pre_restart_steps": [call(tips[0], o, env, cid, itx, ("ADMIT", None)) for o, env, cid, itx, _ in children],
            "post_restart_steps": [call(tips[1], o, env, cid, itx, ("REFUSE", "QUOTA_EXCEEDED")) for o, env, cid, itx, _ in children],
        },
        f"Parent not_before = {parent_nb}, pool 3 per {window}, row cap 1 per {window}, three children (rows 1..3, not_before = {child_nb}). "
        f"Three calls at tip {tips[0]} and three more at tip {tips[1]}: both tips lie in the parent-anchored bucket "
        f"[{parent_nb + 1000}, {parent_nb + 2000}), but in different child-anchored buckets. The steps encode reading 1 "
        "(the three later calls refuse QUOTA_EXCEEDED). No published vector exercises blocks:* quota accounting (two raw_wire receipt "
        "cases merely carry such a window). The scenario does not distinguish 'both accounts at the parent' from 'own at the child, "
        "row at the parent'." + SCENARIO_NOTE,
        reference=("REFUSE", f"POST_STEP_MISMATCH:tip-{tips[1]}-row-1:('ADMIT', None)"),
        question=(
            "SPEC-06 §2.2 item 2 defines blocks:<N> buckets as [not_before_height + k*N, ...) without saying whose not_before_height anchors "
            "the parent's per-row account; registry/constraints.json says only 'anchored at grant not_before_height'. Is the row account "
            "(keyed by grant_id = parent_grant_id, §2.2 item 1) bucketed from the parent's not_before_height or from the child's?"
        ),
        readings=[
            {
                "reading": "row account anchored at the parent's not_before_height",
                "source": "spec/SPEC-06 §2.2 item 1 (row account keyed by the parent grant) + §3 item 3 R8.5 (pool bound per window)",
                "verdict": "ADMIT",
                "refusal": None,
                "comment": "All want_* hold: 3 calls in the parent bucket, the next 3 refuse QUOTA_EXCEEDED; the pool of 3 is respected.",
            },
            {
                "reading": "both accounts anchored at the child's not_before_height (reference behaviour)",
                "source": "tools/seallink_verifier.py (bucket_id derived from the leaf grant)",
                "verdict": "REFUSE",
                "refusal": f"POST_STEP_MISMATCH:tip-{tips[1]}-row-1:('ADMIT', None)",
                "comment": "All six calls are admitted inside one parent window whose pool is 3.",
            },
        ],
    )


# ---------------------------------------------------------------------------
# B-9  name value authored by the previous owner
# ---------------------------------------------------------------------------

def build_b09(s: CandidateSuite) -> None:
    s.finding(
        "B-9",
        "A name value written by the PREVIOUS owner counts as authored by the pinned owner_policy",
        ["spec/SPEC-02 §3.3 (SL-LDGR-007)", "spec/SPEC-06 §4 steps 7a and 11a"],
    )
    rules = ["SL-LDGR-007", "SL-IDEN-004", "SL-GRNT-012"]
    basis = (
        "SPEC-02 §3.3 (SL-LDGR-007): 'Receiving a name output proves neither authorship nor consent. To prove a name value was authored "
        "by owner_policy: 1. The spent previous name input MUST satisfy owner_policy'. In the transfer transaction the spent input "
        "satisfies the previous owner's policy, not the pinned one. SPEC-06 §4 step 7a: SIGHASH_ALL writer check -> NAME_WRITER_UNVERIFIED."
    )
    base = rm._base_invocation_fixture()
    registrant, pinned = _key_pol(_kp("b09-registrant-owner")), _key_pol(_kp("b09-pinned-owner"))
    k_registrant, k_pinned = _kp("b09-registrant-role"), _kp("b09-pinned-role")
    reg = {"txid": _h32("b09-registration"), "vout": 0}
    v_registrant = {"link": {"grant": k_registrant["xonly"]}}

    def resolve(own_update: bool) -> dict[str, Any]:
        extra = [{"txid": _h32("b09-transfer"), "confirmed_height": 749500, "owner_policy": pinned, "value": v_registrant}]
        if own_update:
            extra.append({"txid": _h32("b09-own-update"), "confirmed_height": 749600, "owner_policy": pinned, "value": {"link": {"grant": k_pinned["xonly"]}}})
        chain = copy.deepcopy(base["chain"])
        chain["names"]["id/n"] = sv.make_name_history("id/n", reg, registrant, v_registrant, first_height=748000, update_height=749000, extra_updates=extra)
        return {"chain": chain, "name": "id/n", "expected_owner_policy": pinned, "expected_registration": reg}

    c_resolve = s.control(
        "cand-b09-control-pinned-owner-authored-its-own-update",
        rules,
        "name_resolve",
        resolve(True),
        ("ADMIT", None),
        "X registers id/n and transfers it to script B; B then signs one NAME_UPDATE of its own (SIGHASH_ALL). Pin: owner_policy = B.",
    )
    s.witness(
        "cand-b09-value-written-by-previous-owner-in-transfer",
        rules,
        "name_resolve",
        resolve(False),
        ("REFUSE", "NAME_WRITER_UNVERIFIED"),
        "The same history without B's own update: the current value (link.grant = X's key) was written by X in the transaction that "
        "hands the name to B. B never signed anything.",
        reference=("ADMIT", None),
        code_status="text",
        basis=basis,
        controls=[c_resolve],
    )

    # End to end, issuer side (step 7a).
    def issuer_case(endorsed: bool) -> dict[str, Any]:
        fx = rm._base_invocation_fixture()
        value = {"link": {"grant": k_registrant["xonly"]}}
        extra = [{"txid": _h32("b09-alice-transfer"), "confirmed_height": 748900, "owner_policy": fx["_alice_owner_pol"], "value": value}]
        if endorsed:
            extra.append({"txid": _h32("b09-alice-own-update"), "confirmed_height": 749000, "owner_policy": fx["_alice_owner_pol"], "value": value})
        fx["chain"]["names"]["id/alice"] = sv.make_name_history(
            "id/alice", fx["_alice_reg"], registrant, value, first_height=747000, update_height=747500, extra_updates=extra
        )
        gp = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
        gp["issuer"]["role_policy"] = {"m": 1, "pks": [k_registrant["xonly"]]}
        rm._reanchor_grant(fx, gp, signer_sk=k_registrant["sk"])
        return fx

    c_issuer = s.control(
        "cand-b09-control-issuer-owner-endorsed-the-role-key",
        rules,
        "invocation",
        issuer_case(True),
        ("ADMIT", None),
        "X registered id/alice at the pinned registration outpoint and transferred it to Alice's owner_policy; Alice then signed her own "
        "update keeping link.grant = X's key. A grant signed with that key is issued by id/alice.",
    )
    s.witness(
        "cand-b09-issuer-pin-whose-owner-never-signed",
        rules,
        "invocation",
        issuer_case(False),
        ("REFUSE", "NAME_WRITER_UNVERIFIED"),
        "The same without Alice's own update: the issuer pin (id/alice, registration, Alice's owner_policy) matches the chain, but the "
        "link.grant key was written by X. The grant 'issued by id/alice' is signed by X.",
        reference=("ADMIT", None),
        code_status="text",
        basis=basis,
        controls=[c_issuer],
    )

    # End to end, named recipient (step 11a names no writer-check code).
    bob_policy = _key_pol(_kp("b09-bob-owner"))
    bob_key, attacker_key = _kp("b09-bob-request"), _kp("b09-attacker-request")
    bob_reg = {"txid": _h32("b09-bob-registration"), "vout": 0}

    def recipient_case(*, hijacked: bool, signer: dict[str, Any]) -> dict[str, Any]:
        fx = rm._base_invocation_fixture()
        gp = copy.deepcopy(fx["bundle"]["grants"][0]["payload"])
        gp["recipient"] = {"mode": "name", "name": "id/bob", "owner_policy": bob_policy}
        rm._reanchor_grant(fx, gp)
        if hijacked:
            value = {"nostr": attacker_key["xonly"]}
            fx["chain"]["names"]["id/bob"] = sv.make_name_history(
                "id/bob", bob_reg, registrant, value, first_height=748000, update_height=749000,
                extra_updates=[{"txid": _h32("b09-bob-transfer"), "confirmed_height": 749500, "owner_policy": bob_policy, "value": value}],
            )
        else:
            fx["chain"]["names"]["id/bob"] = sv.make_name_history("id/bob", bob_reg, bob_policy, {"nostr": bob_key["xonly"]}, first_height=748000, update_height=749000)
        fx["invocation"] = sl.sign_envelope(copy.deepcopy(fx["invocation"]["payload"]), [signer["sk"]])
        return fx

    c_bob = s.control(
        "cand-b09-control-named-recipient-authored-its-request-key",
        rules,
        "invocation",
        recipient_case(hijacked=False, signer=bob_key),
        ("ADMIT", None),
        "Grant recipient = {name: id/bob, owner_policy}. Bob owns the name and authored its value (nostr = Bob's key); Bob invokes.",
    )
    c_stranger = s.control(
        "cand-b09-control-stranger-key-against-genuine-recipient-name-refuses",
        rules,
        "invocation",
        recipient_case(hijacked=False, signer=attacker_key),
        ("REFUSE", "WIRE_SIGNATURE"),
        "The same genuine name; the invocation is signed by a key that is not in the name value.",
    )
    s.witness(
        "cand-b09-named-recipient-request-key-written-by-previous-owner",
        rules,
        "invocation",
        recipient_case(hijacked=True, signer=attacker_key),
        ("REFUSE", None),
        "The attacker registers id/bob, writes nostr = attacker key and transfers the name to Bob's owner_policy. The recipient pin "
        "(name + owner_policy; the schema has no registration member) matches; the attacker invokes. Step 11a of SPEC-06 §4 lists no "
        "writer check for named recipients, hence no code.",
        reference=("ADMIT", None),
        code_status="undefined",
        proposed_refusal="NAME_WRITER_UNVERIFIED",
        basis=(
            basis + " SPEC-06 §1.2 (mode = \"name\"): the verifier 'accepts signatures from the name's current authorized nostr/request "
            "key' — it does not say the key must be owner-authored, and step 11a lists no writer check."
        ),
        controls=[c_bob, c_stranger],
    )


# ---------------------------------------------------------------------------
# B-10  seallink-issuance/1 preimage
# ---------------------------------------------------------------------------

def build_b10(s: CandidateSuite) -> None:
    s.finding(
        "B-10",
        "The preimage of the on-chain 0x01 commitment (seallink-issuance/1) has no normative member rule",
        ["spec/SPEC-06 §1.4", "spec/SPEC-05 §2.2", "schemas/grant.schema.json#/$defs/IssuancePrep", "registry/object-types.json (seallink-issuance/1)"],
    )
    rules = ["SL-GRNT-004", "SL-LDGR-008"]
    published_id = "bnd-grant-exact-window-recency-rk-depth-admit"
    inputs = _published_case(published_id)["inputs"]
    grant = inputs["bundle"]["grants"][0]
    p = grant["payload"]
    itx = inputs["invocation"]["payload"]["proof_path"][0]["issuance_txid"]
    presented = [sl.content_addr(a) for a in inputs["bundle"]["contract_assents"]]
    assert len(presented) == 2 and presented != sorted(presented), (
        "B-10 fixture: the published case must carry two assents whose presentation order differs from the ascending order"
    )
    core = {"genesis": p["genesis"], "grant_content_addr": sl.content_addr(grant), "grant_id": sl.object_id(p), "type": "seallink-issuance/1"}
    with_contract = {**core, "contract_id": p["contract_id"]}
    forms = {
        "reference-form": with_contract,
        "with-assents-sorted": {**with_contract, "assent_content_addrs": sorted(presented)},
        "with-assents-in-presentation-order": {**with_contract, "assent_content_addrs": presented},
        "without-contract-id": dict(core),
    }

    def opret(obj: dict[str, Any]) -> str:
        return sl.encode_opreturn(0x01, sl.signing_digest(obj).hex(), 0x00).hex()

    assert inputs["chain"]["txs"][itx]["opreturn_hex"] == opret(forms["reference-form"]), (
        "B-10 fixture: the published 0x01 commitment is no longer the reference-form preimage; revisit the decision records"
    )
    wire = sv.Tier1Verifier()
    for tag, obj in forms.items():
        ok, why = wire._verify_object_wire(obj, expected_type="seallink-issuance/1")
        assert ok, f"B-10 fixture: issuance form {tag} is no longer wire/schema valid ({why})"

    def anchored(obj: dict[str, Any]) -> dict[str, Any]:
        case_inputs = copy.deepcopy(inputs)
        case_inputs["chain"]["txs"][itx]["opreturn_hex"] = opret(obj)
        return case_inputs

    question = (
        "Which members does the seallink-issuance/1 preimage contain for a contract-bound grant, and in which order are assent content "
        "addresses listed? SPEC-06 §1.4 gives no member table; the schema makes contract_id and assent_content_addrs optional for every "
        "grant, so all the objects below are schema-valid for the same grant; the registry describes the object as 'binding grant_id, grant "
        "signatures, and optional contract assents'; SPEC-05 §2.2 calls an assent 'single-use per issuance', which a verifier can check only "
        "if the commitment binds it."
    )
    readings = [
        (
            "reference-form",
            "published vector and reference: contract_id iff the grant has one; assent_content_addrs never",
            f"vectors/security-conformance.json#{published_id} (its 0x01 commitment is exactly this form); tools/seallink_verifier.py step 10c",
        ),
        (
            "with-assents-sorted",
            "the commitment binds the contract assents, content addresses in ascending order",
            "registry/object-types.json; spec/SPEC-05 §2.2; ascending order is the convention for SignatureSet pks and Merkle leaves",
        ),
        (
            "with-assents-in-presentation-order",
            "the commitment binds the contract assents, in presentation (contract party) order",
            "registry/object-types.json; spec/SPEC-05 §2.2; no order is stated anywhere",
        ),
    ]
    notes = {
        "reference-form": "Inputs identical to the published contract-bound ADMIT case; the 0x01 commitment is {genesis, grant_content_addr, grant_id, type} + contract_id.",
        "with-assents-sorted": "The same published case; only the 0x01 commitment changes: + assent_content_addrs in ascending order.",
        "with-assents-in-presentation-order": "The same published case; only the 0x01 commitment changes: + assent_content_addrs in the order of bundle.contract_assents.",
    }
    for tag, _, _ in readings:
        obj = forms[tag]
        s.decision(
            f"cand-b10-decision-issuance-{tag}",
            rules,
            "invocation",
            anchored(obj),
            f"{notes[tag]} typed digest = {sl.signing_digest(obj).hex()}.",
            reference=("ADMIT", None) if tag == "reference-form" else ("REFUSE", "CHAIN_FRAME_INVALID"),
            question=question,
            readings=[
                {"reading": reading, "source": source, "verdict": "ADMIT" if admitted == tag else "REFUSE", "refusal": None if admitted == tag else "CHAIN_FRAME_INVALID"}
                for admitted, reading, source in readings
            ],
            conflicts_with=[f"vectors/security-conformance.json#{published_id}"],
        )
    s.control(
        "cand-b10-control-issuance-without-contract-id-refuses",
        rules,
        "invocation",
        anchored(forms["without-contract-id"]),
        ("REFUSE", "CHAIN_FRAME_INVALID"),
        "The same published case with a 0x01 commitment whose preimage omits contract_id although the grant is contract-bound. The object "
        "is schema-valid, yet no reading listed above admits it: under each of them the commitment binds contract_id.",
    )


# ---------------------------------------------------------------------------
# B-11  refusal code of schema-level violations
# ---------------------------------------------------------------------------

def build_b11(s: CandidateSuite) -> None:
    s.finding(
        "B-11",
        "The refusal code of a schema-level violation is undefined; text, schemas, reference and two published vector files disagree",
        ["spec/SPEC-01 §7 steps 8-10 (SL-WIRE-018)", "spec/SPEC-06 §1.3 and §4 step 10d", "CONFORMANCE.md §2.1"],
    )
    rules = ["SL-WIRE-018", "SL-WIRE-007", "SL-WIRE-012", "SL-WIRE-010"]
    fx = rm._base_invocation_fixture()
    payload = fx["bundle"]["grants"][0]["payload"]
    signer = fx["_keys"]["alice_gr"]["sk"]

    def wire(mutate: Callable[[dict[str, Any]], None] | None) -> dict[str, Any]:
        p = copy.deepcopy(payload)
        if mutate:
            mutate(p)
        return {"object": sl.sign_envelope(p, [signer]), "expected_type": "seallink-grant/1"}

    c_valid = s.control(
        "cand-b11-control-valid-grant-passes-wire",
        rules,
        "raw_wire",
        wire(None),
        ("ADMIT", None),
        "The base root grant of the refusal matrix passes the wire pipeline.",
    )
    c_member = s.control(
        "cand-b11-control-unknown-member-is-wire-member",
        rules,
        "raw_wire",
        wire(lambda p: p.__setitem__("unknown_member", 1)),
        ("REFUSE", "WIRE_MEMBER"),
        "An unknown member violates the closed schema: step 8, WIRE_MEMBER.",
    )
    c_bound = s.control(
        "cand-b11-control-integer-at-schema-maximum-passes-wire",
        rules,
        "raw_wire",
        wire(lambda p: p.__setitem__("min_depth", 144)),
        ("ADMIT", None),
        "payload.min_depth = 144, the schema maximum: min_depth is a defined member and the bound is inclusive.",
    )
    s.witness(
        "cand-b11-integer-above-schema-maximum-reported-as-wire-member",
        rules,
        "raw_wire",
        wire(lambda p: p.__setitem__("min_depth", 145)),
        ("REFUSE", "WIRE_INTEGER"),
        "payload.min_depth = 145 with schema maximum 144: a well-formed uint53 that violates a schema bound.",
        reference=("REFUSE", "WIRE_MEMBER"),
        code_status="text",
        basis=(
            "SPEC-01 §7 step 8: 'integer bounds (SL-WIRE-007..009) -> WIRE_INTEGER'; registry: WIRE_INTEGER = 'Number-form or string-form "
            "integer violates grammar or schema bound'. The reference maps every schema error to WIRE_MEMBER."
        ),
        controls=[c_bound, c_member],
    )
    s.witness(
        "cand-b11-recipient-key-not-on-curve-passes-wire",
        rules,
        "raw_wire",
        wire(lambda p: p["recipient"].__setitem__("key", "ff" * 32)),
        ("REFUSE", "WIRE_KEY"),
        "payload.recipient.key = ff..ff: 64 lowercase hex characters that are not the x coordinate of a secp256k1 point.",
        reference=("ADMIT", None),
        code_status="text",
        basis="SPEC-01 §7 step 9: 'Public key syntax and curve-point validation (SL-WIRE-012) -> WIRE_KEY'.",
        controls=[c_valid, c_member],
    )
    published = next(f for f in _vector("constraints-and-schemas.json")["negative_schema_fixtures"] if f["id"] == "grant-executor-ref-with-quota")
    sibling = _published_case("branch-exec-ref-single-use-forbidden")
    assert published["expected_refusal"] == "GRANT_EXECUTOR_REF_FORBIDDEN" and sibling["expected_refusal"] == "WIRE_MEMBER", (
        "B-11: the published case changed; update or drop this decision record"
    )
    s.decision(
        "cand-b11-decision-executor-ref-with-quota-refusal-code",
        ["SL-GRNT-003", "SL-WIRE-010", "SL-WIRE-018"],
        "raw_wire",
        {"object": published["object"], "expected_type": "seallink-grant/1"},
        "The object of vectors/constraints-and-schemas.json#negative_schema_fixtures[grant-executor-ref-with-quota], run through the wire "
        "pipeline only. speclint checks that the schema rejects this fixture but does not compare its expected_refusal.",
        reference=("REFUSE", "WIRE_MEMBER"),
        question=(
            "A grant combining executor_ref with quotas / single_use / delegate is rejected by a conditional in grant.schema.json (wire "
            "step 8) and by SPEC-06 §4 step 10d. What does the wire pipeline return for such an object, and with which code? Two published "
            "files give two answers for this class, while CONFORMANCE.md requires identical refusal codes across implementations."
        ),
        readings=[
            {
                "reading": "the conditional is a closed-schema rule: wire step 8",
                "source": (
                    "spec/SPEC-01 §7 step 8 and SL-WIRE-010; vectors/security-conformance.json#branch-exec-ref-single-use-forbidden "
                    "(same class, executor_ref + single_use)"
                ),
                "verdict": "REFUSE",
                "refusal": "WIRE_MEMBER",
            },
            {
                "reading": "the schema rejects, and the code is the semantic one",
                "source": "vectors/constraints-and-schemas.json#negative_schema_fixtures[grant-executor-ref-with-quota] (expected_refusal as published)",
                "verdict": "REFUSE",
                "refusal": "GRANT_EXECUTOR_REF_FORBIDDEN",
            },
            {
                "reading": "the rule lives in the admission pipeline only: the object passes the wire pipeline",
                "source": "spec/SPEC-06 §1.3 and §4 step 10d (GRANT_EXECUTOR_REF_FORBIDDEN is returned there; the schema conditional would have to go)",
                "verdict": "ADMIT",
                "refusal": None,
            },
        ],
        conflicts_with=[
            "vectors/constraints-and-schemas.json#negative_schema_fixtures[grant-executor-ref-with-quota]",
            "vectors/security-conformance.json#branch-exec-ref-single-use-forbidden",
        ],
    )


# ---------------------------------------------------------------------------
# B-12  ward status discoverable only through mutable link.origin
# ---------------------------------------------------------------------------

def build_b12(s: CandidateSuite) -> None:
    s.finding(
        "B-12",
        "Ward status is discovered only through the mutable link.origin: removing it lifts non-autonomy",
        ["spec/SPEC-04 §2.2 (SL-ORIG-003.3)", "spec/SPEC-06 §4 step 7b"],
    )
    rules = ["SL-ORIG-003", "SL-ORIG-006", "SL-GRNT-012"]
    basis = (
        "SPEC-04 §2.2 (SL-ORIG-003.3): 'Removing or altering link.origin in a later update NEVER unbinds an already confirmed "
        "registration.' The verdict therefore must equal the one returned while link.origin is still present. (SPEC-06 §4 7b words the "
        "trigger as 'link.origin or pinned origin' without saying how a removed link.origin is discovered.)"
    )
    a = _agent_world()
    atk, atk_seal = _kp("b12-attacker-grant"), _kp("b12-attacker-seal")
    issuer = {
        "name": "id/agent-nova",
        "owner_policy": a["binding"]["owner_policy"],
        "registration": a["binding"]["registration"],
        "role_policy": {"m": 1, "pks": [atk["xonly"]]},
    }
    payload = _guardian_message_grant(a, "b12-strip", issuer, a["origin_id"], "id/agent-nova", atk_seal, {})
    grant = sl.sign_envelope(payload, [atk["sk"]])

    def presentation(stripped: bool) -> dict[str, Any]:
        chain = copy.deepcopy(a["chain"])
        if stripped:
            chain["names"]["id/agent-nova"] = sv.make_name_history(
                "id/agent-nova", a["binding"]["registration"], a["binding"]["owner_policy"], {"link": {"origin": a["origin_id"]}},
                first_height=749005, update_height=749015,
                extra_updates=[{"txid": _h32("b12-strip-update"), "confirmed_height": 749980, "value": {"link": {"grant": atk["xonly"]}}}],
            )
        itx = _anchor_root_grant(chain, grant, "b12-strip")
        invocation = _guardian_message_invocation(a, "b12-strip", sl.object_id(payload), itx, a["origin_id"], "id/agent-nova")
        return _agent_inputs(a, grant=grant, invocation=invocation, chain=chain, origin_bundle=None)

    c_present = s.control(
        "cand-b12-control-self-signed-grant-while-link-origin-present-refuses",
        rules,
        "invocation",
        presentation(False),
        ("REFUSE", "ORIGIN_UNVERIFIED"),
        "A grant self-signed with a plain key in the ward's name (no guardian_context, no approvals, no origin bundle) while the name value "
        "still carries link.origin: the ward path is taken and refuses. (In this harness model the origin document reaches the verifier "
        "only through the presented bundle, hence ORIGIN_UNVERIFIED.)",
    )
    s.witness(
        "cand-b12-link-origin-stripped-by-name-custodians",
        rules,
        "invocation",
        presentation(True),
        ("REFUSE", "ORIGIN_UNVERIFIED"),
        "The same grant after the holders of the ward name's owner_policy publish one more update that drops link.origin and writes "
        "link.grant = their key. The station still pins the ward's origin; the subject is treated as an ordinary autonomous name.",
        reference=("ADMIT", None),
        code_status="derived",
        basis=basis,
        controls=[c_present, CTL_PUBLISHED_WARD_GRANT_ADMITS],
        also_acceptable=[
            (
                "REFUSE",
                "WARD_AUTONOMOUS_FORBIDDEN",
                "PROFILE-agent-v1 §5 step 1 has the host load the pinned origin document itself; with the ward origin verified that way, "
                "SL-ORIG-006.1 applies to this self-signed grant.",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# B-13  majority / emancipation
# ---------------------------------------------------------------------------

def build_b13(s: CandidateSuite) -> None:
    s.finding(
        "B-13",
        "Majority and emancipation: unauthenticated opened_majority_unix, autonomy without capacity/1, text contradicts three published vectors",
        ["spec/SPEC-04 §2.1 item 5", "spec/SPEC-04 §4 (SL-ORIG-010)", "spec/SPEC-04 §5.1 (SL-ORIG-011)"],
    )
    rules = ["SL-ORIG-010", "SL-ORIG-011", "SL-ORIG-002"]
    basis = (
        "SPEC-04 §2.1 item 5: majority exists only as claims.majority_commitment, opened with its salt (SL-WIRE-014). This origin "
        "(origin_class = agent) has no majority_commitment, and the bundle supplies opened_majority_unix without majority_salt_hex. "
        "An unverifiable opening cannot make the subject autonomous. The text does not say whether it is ignored (expected: the result of "
        "the control without the field) or refuses the presentation (also acceptable)."
    )
    a = _agent_world()
    assert "majority_commitment" not in a["origin_payload"]["claims"] and a["origin_payload"]["origin_class"] == "agent"
    atk, atk_owner, atk_seal = _kp("b13-attacker-grant"), _kp("b13-attacker-owner"), _kp("b13-attacker-seal")
    new_policy = _key_pol(atk_owner)
    value = {"link": {"grant": atk["xonly"], "origin": a["origin_id"]}}
    chain = copy.deepcopy(a["chain"])
    chain["credible_utc_interval"] = [chain["now"] - 5, chain["now"] + 5]
    chain["names"]["id/agent-nova"] = sv.make_name_history(
        "id/agent-nova", a["binding"]["registration"], a["binding"]["owner_policy"], {"link": {"origin": a["origin_id"]}},
        first_height=749005, update_height=749015,
        extra_updates=[
            {"txid": _h32("b13-transfer"), "confirmed_height": 749970, "owner_policy": new_policy, "value": value},
            {"txid": _h32("b13-own-update"), "confirmed_height": 749980, "owner_policy": new_policy, "value": value},
        ],
    )
    issuer = {"name": "id/agent-nova", "owner_policy": new_policy, "registration": a["binding"]["registration"], "role_policy": {"m": 1, "pks": [atk["xonly"]]}}
    payload = _guardian_message_grant(a, "b13-majority", issuer, a["origin_id"], "id/agent-nova", atk_seal, {})
    grant = sl.sign_envelope(payload, [atk["sk"]])
    itx = _anchor_root_grant(chain, grant, "b13-majority")
    invocation = _guardian_message_invocation(a, "b13-majority", sl.object_id(payload), itx, a["origin_id"], "id/agent-nova")
    forged_bundle = dict(a["origin_bundle"], opened_majority_unix=1)
    fail_closed = (
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "Failing closed on the unverifiable opening itself, as the published branch-origin-bad-majority-salt does for an opening that fails "
        "its commitment; origin validity precedes the ward checks (SPEC-06 §4 step 7b).",
    )

    c_inv = s.control(
        "cand-b13-control-name-moved-without-majority-claim-refuses",
        rules,
        "invocation",
        _agent_inputs(a, grant=grant, invocation=invocation, chain=chain),
        ("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN"),
        "The ward name was moved to a fresh key by its custodians (no capacity/1, status_seal unspent) and the new holder signs alone. "
        "With the genuine origin bundle the subject is still a ward.",
    )
    c_status = s.control(
        "cand-b13-control-status-is-ward-without-majority-claim",
        rules,
        "origin_status",
        {"chain": chain, "origin_bundle": a["origin_bundle"], "trusted_origin_issuers": a["trusted_origin_issuers"]},
        ("ADMIT_WARD", None),
        "Origin status for the same chain view and the genuine bundle: capacity = ward.",
    )
    s.witness(
        "cand-b13-unsalted-opened-majority-unix-makes-agent-ward-autonomous",
        rules,
        "invocation",
        _agent_inputs(a, grant=grant, invocation=invocation, chain=chain, origin_bundle=forged_bundle),
        ("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN"),
        "The identical presentation, but the presenter adds opened_majority_unix = 1 to the bundle (no salt; the origin commits to no majority).",
        reference=("ADMIT", None),
        code_status="derived",
        basis=basis,
        controls=[c_inv, CTL_PUBLISHED_WARD_GRANT_ADMITS],
        also_acceptable=[fail_closed],
    )
    s.witness(
        "cand-b13-unsalted-opened-majority-unix-status-autonomous",
        rules,
        "origin_status",
        {"chain": chain, "origin_bundle": forged_bundle, "trusted_origin_issuers": a["trusted_origin_issuers"]},
        ("ADMIT_WARD", None),
        "Origin status for the same forged bundle: the forbidden outcome is capacity = autonomous.",
        reference=("ADMIT_AUTONOMOUS", None),
        code_status="derived",
        basis=basis,
        controls=[c_status],
        also_acceptable=[fail_closed],
    )

    # State 4 (Autonomous) of SL-ORIG-011: two passages of the same specification, and three published vectors.
    stale = "the published case changed; update or drop this decision record"
    question = (
        "SPEC-04 §5.1 state 4 reads 'capacity/1 (+ t_low >= T for human) verified, confirmed name transfer to subject_new_owner_policy, "
        "confirmed subject-authored update, and binding line updated'. §4 says 'Independent adult admission requires t_low >= T plus "
        "confirmed emancipation transfer', and state 3 begins at 'Calendar T reached OR verified seallink-capacity/1'. Is a verified "
        "capacity/1 required for autonomy after calendar majority, and does a human emancipated by capacity/1 also need t_low >= T?"
    )
    for cid, has_capacity in (
        ("bnd-majority-interval-t-low-eq-T-autonomous", False),
        ("bnd-emancipation-exact-3-updates-handover-autonomous", False),
        ("emancipation-handover-completed-admits-autonomous", True),
    ):
        pub = _published_case(cid)
        ob = pub["inputs"]["origin_bundle"]
        majority = ob["opened_majority_unix"]
        t_low = pub["inputs"]["chain"]["credible_utc_interval"][0]
        now = pub["inputs"]["chain"]["now"]
        assert pub["expected_verdict"] == "ADMIT_AUTONOMOUS" and ("capacity_record" in ob) == has_capacity, f"B-13 {cid}: {stale}"
        assert ob["origin"]["payload"]["origin_class"] == "person", f"B-13 {cid}: {stale}"
        published_source = f"vectors/security-conformance.json#{cid}"
        if has_capacity:
            assert t_low < majority, f"B-13 {cid}: {stale}"
            readings = [
                {
                    "reading": "a human needs t_low >= T even with a verified capacity/1",
                    "source": "spec/SPEC-04 §5.1 state 4 ('capacity/1 (+ t_low >= T for human) verified'); §4 ('Independent adult admission requires t_low >= T')",
                    "verdict": "REFUSE",
                    "refusal": None,
                    "comment": f"capacity/1 is verified but t_low = {t_low} < T = {majority}; no state of the table matches, so no code follows.",
                },
                {
                    "reading": "a verified capacity/1 emancipates; only the handover is required",
                    "source": f"spec/SPEC-04 §2.1 item 6 status spine (initial -> emancipated on a verified capacity/1); {published_source}",
                    "verdict": "ADMIT_AUTONOMOUS",
                    "refusal": None,
                },
            ]
        else:
            assert t_low >= majority > now, f"B-13 {cid}: {stale}"
            readings = [
                {
                    "reading": "state 4 row read literally: autonomy needs a verified capacity/1",
                    "source": "spec/SPEC-04 §5.1 state 4",
                    "verdict": "REFUSE",
                    "refusal": "GUARDIAN_TRANSFER_PENDING",
                    "comment": "No capacity/1 is presented, so there is no subject_new_owner_policy to transfer to: state 3 persists.",
                },
                {
                    "reading": "calendar majority alone ends guardianship: t_low >= T plus a confirmed transfer suffices",
                    "source": (
                        "spec/SPEC-04 §4 ('Guardianship ends automatically at calendar majority T'; 'Independent adult admission requires "
                        f"t_low >= T plus confirmed emancipation transfer'); §5.1 state 3 ('Calendar T reached OR ...'); {published_source}"
                    ),
                    "verdict": "ADMIT_AUTONOMOUS",
                    "refusal": None,
                    "comment": (
                        f"The fixture's credible interval starts at {t_low} while chain.now = {now}; with the time-interval oracle still "
                        "open (OPEN-QUESTIONS.md OQ-001), GUARDIAN_TIME_BOUNDARY is a conceivable third outcome."
                    ),
                },
            ]
        s.decision(
            f"cand-b13-decision-{cid}",
            pub["rules"],
            pub["runner"],
            pub["inputs"],
            f"Inputs copied unchanged from {published_source} (published expectation: ADMIT_AUTONOMOUS).",
            reference=("ADMIT_AUTONOMOUS", None),
            question=question,
            readings=readings,
            conflicts_with=[published_source],
        )


# ---------------------------------------------------------------------------
# B-14  self-declared issuer of status and guardian records
# ---------------------------------------------------------------------------

def build_b14(s: CandidateSuite) -> None:
    s.finding(
        "B-14",
        "The issuer of end/1, capacity/1, guardian/1 and guardian-roster/1 is self-declared: any name with link.cred is accepted",
        ["spec/SPEC-04 §2.1 item 6", "spec/SPEC-04 §3.4 (SL-ORIG-007)", "spec/SPEC-04 §3.5 (SL-ORIG-015)", "spec/SPEC-04 §5.1 (SL-ORIG-012)"],
    )
    rules = ["SL-ORIG-002", "SL-ORIG-007", "SL-ORIG-012"]
    a = _agent_world()
    op = a["origin_payload"]
    stat = op["status_seal"]
    assert "capacity_authority" not in op
    registry_cred = _vkp("t4-reg-cred")
    rogue_owner, rogue_cred = _kp("b14-rogue-owner"), _kp("b14-rogue-cred")
    rogue_pin = {
        "name": "id/rogue-registry",
        "owner_policy": _key_pol(rogue_owner),
        "registration": {"txid": _h32("b14-rogue-registration"), "vout": 0},
        "role_policy": {"m": 1, "pks": [rogue_cred["xonly"]]},
    }

    def chain_with_rogue() -> dict[str, Any]:
        chain = copy.deepcopy(a["chain"])
        chain["names"]["id/rogue-registry"] = sv.make_name_history(
            "id/rogue-registry", rogue_pin["registration"], rogue_pin["owner_policy"], {"link": {"cred": rogue_cred["xonly"]}},
            first_height=748000, update_height=748500,
        )
        return chain

    def status_case(kind: str, issuer_pin: dict[str, Any], signer: dict[str, Any], tag: str) -> dict[str, Any]:
        chain = chain_with_rogue()
        spend = _h32(f"b14-{kind}-{tag}-spend-tx")
        chain["txs"][stat["txid"]]["outputs"][str(stat["vout"])]["spent_by_txid"] = spend
        common = {
            "basis_sha256": _h32("b14-basis"),
            "genesis": G,
            "issued_at": 1795220000,
            "issuer": issuer_pin,
            "network": "main",
            "origin_id": a["origin_id"],
            "status_prev_outpoint": {"txid": stat["txid"], "vout": stat["vout"]},
        }
        if kind == "end":
            record = sl.sign_envelope({**common, "reason": "death", "type": "seallink-end/1"}, [signer["sk"]])
            outputs: dict[str, Any] = {}
            bundle = dict(a["origin_bundle"], end_record=record)
        else:
            record = sl.sign_envelope(
                {**common, "next_status_policy": stat["script_policy"], "next_status_vout": 0,
                 "subject_new_owner_policy": _key_pol(_kp("b14-subject-new-owner")), "type": "seallink-capacity/1"},
                [signer["sk"]],
            )
            outputs = {"0": {"script_pubkey_hex": _spk(stat["script_policy"])}}
            bundle = dict(a["origin_bundle"], capacity_record=record)
        chain["txs"][spend] = {"confirmed_height": 750000, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(record)).hex(), "outputs": outputs}
        return {"chain": chain, "origin_bundle": bundle, "trusted_origin_issuers": a["trusted_origin_issuers"]}

    status_basis = (
        "SPEC-04 §2.1 item 6: status_seal keys 'belong exclusively to the designated capacity_authority and end authority (or issuer when "
        "capacity_authority is omitted)'; the verifier checks capacity/1 and end/1 'against the authorizing issuer's link.cred'. Status "
        "spine table: a spend with an 'invalid issuer' -> incomplete -> ORIGIN_STATUS_INCOMPLETE. This origin has no capacity_authority, "
        "so the authorizing issuer is origin.issuer (id/agent-registry)."
    )
    c_unspent = s.control(
        "cand-b14-control-status-seal-unspent-is-ward",
        rules,
        "origin_status",
        {"chain": chain_with_rogue(), "origin_bundle": a["origin_bundle"], "trusted_origin_issuers": a["trusted_origin_issuers"]},
        ("ADMIT_WARD", None),
        "The same chain view with status_seal unspent and no status record: the subject is an ordinary ward.",
    )
    for kind, legit_code, what in (
        ("end", "SUBJECT_ENDED", "seallink-end/1 (terminal: every guardianship slot is closed and all admission ends)"),
        ("capacity", "GUARDIAN_TRANSFER_PENDING", "seallink-capacity/1 (emancipation: guardian admission stops, handover to subject_new_owner_policy begins)"),
    ):
        control = s.control(
            f"cand-b14-control-{kind}-record-by-origin-issuer",
            rules,
            "origin_status",
            status_case(kind, op["issuer"], registry_cred, "issuer"),
            ("REFUSE", legit_code),
            f"status_seal spent with 0x09 committing a {what}, issued and signed by the origin's issuer.",
        )
        s.witness(
            f"cand-b14-{kind}-record-by-unrelated-issuer-accepted",
            rules,
            "origin_status",
            status_case(kind, rogue_pin, rogue_cred, "rogue"),
            ("REFUSE", "ORIGIN_STATUS_INCOMPLETE"),
            "The same spend, but the record names id/rogue-registry as issuer and is signed with that unrelated name's link.cred. The "
            f"reference applies the state change ({legit_code}); the holder of the status_seal key alone decides.",
            reference=("REFUSE", legit_code),
            code_status="text",
            basis=status_basis,
            controls=[control, c_unspent],
        )

    # seallink-guardian/1 issued by an unrelated name activates a slot.
    target = next(r for r in a["origin_bundle"]["guardian_records"] if r["payload"]["slot"] == 2)
    old_id = sl.object_id(target["payload"])
    old_opret = sl.encode_opreturn(0x12, sl.content_addr(target)).hex()
    forged_p = copy.deepcopy(target["payload"])
    forged_p["issuer"] = rogue_pin
    forged = sl.sign_envelope(forged_p, [rogue_cred["sk"]])
    chain = chain_with_rogue()
    anchors = [txid for txid, tx in chain["txs"].items() if tx.get("opreturn_hex") == old_opret]
    assert len(anchors) == 1
    chain["txs"][anchors[0]]["opreturn_hex"] = sl.encode_opreturn(0x12, sl.content_addr(forged)).hex()
    bundle = copy.deepcopy(a["origin_bundle"])
    bundle["guardian_records"] = [forged if sl.object_id(r["payload"]) == old_id else r for r in bundle["guardian_records"]]
    assents = []
    for assent in bundle["guardian_assents"]:
        if assent["payload"]["target_id"] == old_id:
            ap = dict(assent["payload"], target_id=sl.object_id(forged_p))
            assent = sl.sign_envelope(ap, [a["guardian_b"]["sk"]])
        assents.append(assent)
    bundle["guardian_assents"] = assents
    s.witness(
        "cand-b14-guardian-record-by-unrelated-issuer-activates-slot",
        rules,
        "invocation",
        _agent_inputs(a, grant=a["grant"], invocation=a["invocation"], chain=chain, origin_bundle=bundle),
        ("REFUSE", "GUARDIAN_INACTIVE"),
        "Published trace-04 step 4, but the slot-2 seallink-guardian/1 (activation_mode = initial, anchored by 0x12) is issued by "
        "id/rogue-registry and signed with its link.cred; the incoming guardian's assent targets that record. The slot is treated as "
        "active and its approval completes the 2-of-2 effect_grant quorum.",
        reference=("ADMIT", None),
        code_status="text",
        basis=(
            "SPEC-04 §3.4 (SL-ORIG-007.1): 'issuer signs seallink-guardian/1 with activation_mode = \"initial\"' — the origin's issuer, "
            "verified against link.cred at the anchor height (§3.5 item 5). Slot state table: from initial_vacant only a 'Valid 0x12 tx' "
            "leads to active; 'Any other spend of vacant_utxo' -> contested_burned (guardian authority: none). SL-ORIG-006.4: slot state "
            "!= active -> GUARDIAN_INACTIVE."
        ),
        controls=[CTL_PUBLISHED_WARD_GRANT_ADMITS],
    )


# ---------------------------------------------------------------------------
# B-15  roster effective delay
# ---------------------------------------------------------------------------

def build_b15(s: CandidateSuite) -> None:
    s.finding(
        "B-15",
        "Roster revision delay: the text requires effective_delay_blocks >= appointment_delay_blocks, two published vectors use less and expect ADMIT",
        ["spec/SPEC-04 §3.5 item 4 (SL-ORIG-015)", "spec/SPEC-04 §3.2 (SL-ORIG-016)"],
    )
    question = (
        "SPEC-04 §3.5 item 4: 'The new roster takes effect after effective_delay_blocks confirmations (>= "
        "origin.guardian_policy.appointment_delay_blocks).' Is a guardian-roster/1 with a smaller effective_delay_blocks invalid, clamped "
        "to appointment_delay_blocks, or valid as written? Two published cases and the live regtest harness "
        "(conformance/traces-regtest/run_traces_regtest.py) rely on 'valid as written'; the reference enforces no lower bound."
    )
    for cid in ("bnd-roster-exact-effective-delay-admit", "bnd-guardian-pending-exact-csv-delay-admit"):
        pub = _published_case(cid)
        bundle, chain = pub["inputs"]["origin_bundle"], pub["inputs"]["chain"]
        floor = bundle["origin"]["payload"]["guardian_policy"]["appointment_delay_blocks"]
        stale = f"B-15 {cid}: the published case changed; update or drop this decision record"
        assert pub["expected_verdict"] == "ADMIT" and len(bundle["roster_records"]) == 1, stale
        record = bundle["roster_records"][0]
        delay = record["payload"]["effective_delay_blocks"]
        frame = sl.encode_opreturn(0x0F, sl.content_addr(record)).hex()
        anchors = [tx["confirmed_height"] for tx in chain["txs"].values() if tx.get("opreturn_hex") == frame]
        assert delay < floor and len(anchors) == 1, stale
        anchor, tip = anchors[0], chain["tip_height"]
        clamped_effective = anchor + floor <= tip
        clamp_comment = f"0x0f anchored at {anchor}; a clamped revision takes effect at {anchor + floor}; the tip is {tip}."
        if clamped_effective:
            clamp_comment += " Revision 2 is effective, so the case admits — unless a 0x0d anchored on a new_vacant output before that height is void, which the text does not say."
        else:
            clamp_comment += " Revision 2 is not yet the latest effective roster, so approvals citing it fail (SL-ORIG-006.3)."
        s.decision(
            f"cand-b15-decision-{cid}",
            pub["rules"],
            pub["runner"],
            pub["inputs"],
            f"Inputs copied unchanged from vectors/security-conformance.json#{cid}: the roster record carries effective_delay_blocks = "
            f"{delay} while origin.guardian_policy.appointment_delay_blocks = {floor}; the published expectation is ADMIT.",
            reference=("ADMIT", None),
            question=question,
            readings=[
                {
                    "reading": "the lower bound is a validity rule: the record is invalid",
                    "source": (
                        "spec/SPEC-04 §3.5 item 4: '(>= origin.guardian_policy.appointment_delay_blocks)' and 'While roster_seal is spent and "
                        "seallink-guardian-roster/1 is not presented (or fails verification), verifiers fail closed with ORIGIN_STATUS_INCOMPLETE'"
                    ),
                    "verdict": "REFUSE",
                    "refusal": "ORIGIN_STATUS_INCOMPLETE",
                },
                {
                    "reading": "the lower bound is a clamp: the revision takes effect after max(effective_delay_blocks, appointment_delay_blocks)",
                    "source": "spec/SPEC-04 §3.5 item 4",
                    "verdict": "ADMIT" if clamped_effective else "REFUSE",
                    "refusal": None if clamped_effective else "GUARDIAN_QUORUM_UNMET",
                    "comment": clamp_comment,
                },
                {
                    "reading": "valid as written: no lower bound applies to a roster record",
                    "source": (
                        f"vectors/security-conformance.json#{cid}; conformance/traces-regtest/run_traces_regtest.py; the roster invariants of "
                        "spec/SPEC-04 §3.5 item 3 (SL-ORIG-016) list no delay floor, and §3.2 item 3 names a refusal code for a delay shortfall only for a "
                        "Stage 1 pending_policy"
                    ),
                    "verdict": "ADMIT",
                    "refusal": None,
                },
            ],
            conflicts_with=[f"vectors/security-conformance.json#{cid}"],
        )


FINDING_BUILDERS: list[Callable[[CandidateSuite], None]] = [
    build_b01,
    build_b02,
    build_b03,
    build_b04,
    build_b05,
    build_b06,
    build_b07,
    build_b08,
    build_b09,
    build_b10,
    build_b11,
    build_b12,
    build_b13,
    build_b14,
    build_b15,
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
        "suite": "review-candidates-draft6-blockers",
        "version": VERSION,
        "status": "candidate (non-normative; not part of vectors/, not required by CONFORMANCE.md)",
        "description": (
            "Executable candidate negative vectors for the Blocker findings B-1..B-15 of the independent engineering review of "
            f"SealLink {REFERENCE_TAG}. Each witness is paired with controls; `candidate.reference_draft6` records the verdict of "
            f"tools/seallink_verifier.py at {REFERENCE_TAG}."
        ),
        "reference": {"tag": REFERENCE_TAG, "executor": "tools/build_security_suite.py::execute_security_case"},
        "role_semantics": {
            "control": "Passes on the reference and must keep passing.",
            "witness": "expected_* follows the cited specification text; reference_draft6 is what the reference returns today.",
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
        out += ["| Case | Role | Runner | Expected | Reference at draft.6 | Code status |", "| --- | --- | --- | --- | --- | --- |"]
        for c in cases:
            cand = c["candidate"]
            expected = _fmt(c["expected_verdict"], c["expected_refusal"])
            if cand["role"] == "control":
                reference, status = "as expected", ""
            else:
                reference = _fmt(cand["reference_draft6"]["verdict"], cand["reference_draft6"]["refusal"])
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
    recorded = (cand["reference_draft6"]["verdict"], cand["reference_draft6"]["refusal"])
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
            cand["reference_draft6"] = {"verdict": recorded[0], "refusal": recorded[1]}
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
    witness = case("witness", ("REFUSE", "NOTARY_REQUIRED"), ("ADMIT", None), "text", also=[("REFUSE", "WIRE_TYPE")])
    assert classify(witness, ("ADMIT", None)) == ("open", None)
    assert classify(witness, ("ADMIT", None), strict=True)[0] == "open" and classify(witness, ("ADMIT", None), strict=True)[1]
    for accepted in (("REFUSE", "NOTARY_REQUIRED"), ("REFUSE", "WIRE_TYPE")):
        assert classify(witness, accepted)[0] == "closed" and classify(witness, accepted)[1], "ratchet: a closed witness must be promoted"
        assert classify(witness, accepted, strict=True) == ("closed", None)
    assert classify(witness, ("REFUSE", "WIRE_MEMBER"))[0] == "open" and classify(witness, ("REFUSE", "WIRE_MEMBER"))[1], "an unlisted code is not closure"
    assert classify(witness, ("REFUSE", "WIRE_MEMBER"), strict=True)[0] == "open"
    verdict_only = case("witness", ("REFUSE", None), ("ADMIT", None), "undefined")
    assert classify(verdict_only, ("REFUSE", "ANY_CODE"))[0] == "closed"
    assert classify(verdict_only, ("ADMIT", None)) == ("open", None)
    wrong_code = case("witness", ("REFUSE", "WIRE_INTEGER"), ("REFUSE", "WIRE_MEMBER"), "text")
    assert classify(wrong_code, ("REFUSE", "WIRE_MEMBER")) == ("open", None)
    assert classify(wrong_code, ("ADMIT", None))[1], "a refusal that turns into ADMIT must be reported"
    decision = case("decision", ("REFUSE", None), ("ADMIT", None))
    assert classify(decision, ("ADMIT", None)) == ("decision", None)
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
            print(f"{finding:<5} {role:<8} {status:<8} {cid:<78} -> {observed[0]}{'/' + observed[1] if observed[1] else ''}")
    counts = {st: sum(1 for r in rows if r[2] == st) for st in ("pass", "open", "closed", "decision", "fail")}
    print(
        f"review-candidates: {len(rows)} cases | controls pass {counts['pass']} | witnesses open {counts['open']}, closed {counts['closed']} | "
        f"decisions {counts['decision']} | failures {counts['fail']}"
    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and check the draft.6 review-candidate negative vectors (non-normative).")
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
