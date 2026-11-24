# Review-Candidate Negative Vectors for SealLink `v1.0.0-draft.7`

**Status: candidate, non-normative.** This directory is not part of `vectors/`, is not listed in `CONFORMANCE.md`, and is not included in the release bundle or the published site.

It holds executable candidate vectors for the eight `Blocker` findings of the second round of the independent engineering review of `v1.0.0-draft.7` (commit `6a5ab81`): `R2G-01`, `R2G-02`, `R2G-03`, `G7-01`, `G7-02`, `G7-03`, `R2-03` and `R2-01` (also reported as `N-1`). Each finding is a place where the Reference Verifier Core admits something the specification text forbids, or where no single expected result exists yet — because the text contradicts a published vector, or the prose and the schema define different bytes.

The cases live here, and not in `vectors/security-conformance.json`, for two reasons:

1. Every witness is still admitted (or refused with another code) by `tools/seallink_verifier.py`. Adding them to `vectors/` would turn `speclint.py` red, and `CONFORMANCE.md` would then require every implementation to pass vectors the reference itself fails.
2. Some records need an authors' decision before a single expected result exists.

## Files

| File | Content |
| --- | --- |
| [`draft7-blockers.json`](draft7-blockers.json) | The suite. Every case has the shape of a `vectors/security-conformance.json` case (same runners and `inputs`) plus a `candidate` block. |
| [`INDEX.md`](INDEX.md) | Generated index: per finding, the cited specification text, every case with its expected result, the result of the draft.7 reference, and the open decisions. Case counts are stated there. |
| [`SHA256SUMS`](SHA256SUMS) | Integrity pins for the three files above (including this README). |

Generator and checker: [`tools/build_candidate_suite.py`](../../tools/build_candidate_suite.py). It builds every fixture from the published traces, the published security cases and the refusal-matrix fixtures with deterministic keys, and executes cases through the same `execute_security_case` function that `speclint.py` uses for `vectors/security-conformance.json`.

## Run

Requires Python 3.11+ with `jsonschema>=4.23`, like `speclint.py`.

```sh
python3 tools/build_candidate_suite.py            # --check: the ratchet (default)
python3 tools/build_candidate_suite.py --strict   # the target state: every witness must return an accepted result
python3 tools/build_candidate_suite.py --list     # only execute the committed cases and print the table
python3 tools/build_candidate_suite.py --write    # regenerate draft7-blockers.json, INDEX.md and SHA256SUMS
```

Both checking modes regenerate the suite in memory and require byte equality with the committed files, and both require every `control` to return exactly its `expected_verdict` / `expected_refusal`. They differ in how they judge the rest:

| Mode | `witness` | `decision` | Use |
| --- | --- | --- | --- |
| `--check` (ratchet) | must behave exactly as recorded in `candidate.reference_result`; a witness that has become satisfied is reported too, because it has to be promoted | must behave exactly as recorded | CI of this repository: passes while witnesses are open, fails as soon as the verifier's behaviour on any case changes, in either direction |
| `--strict` (target state) | must return an accepted result | executed and listed, not judged | evaluating a fixed verifier before the cases are promoted; fails while any witness is open |

## Case roles

| `candidate.role` | Meaning |
| --- | --- |
| `control` | A nearby valid (or validly refused) case that passes on the reference today. Every witness names its controls in `candidate.control_ids`. Controls are judged in both modes, so an implementation that refuses everything fails the suite. |
| `witness` | The defect. `expected_*` is the result required by the specification text quoted in `candidate.basis`. `candidate.also_acceptable` lists other results the text equally permits, each with its reason. |
| `decision` | No single expected result exists yet. `candidate.readings` lists each reading with its source and result; `expected_*` mirrors `readings[0]` and carries no preference. `candidate.conflicts_with` names the published cases or vector files that at least one reading contradicts. |

A witness is **closed** when the verifier returns `expected_*` or one of the `also_acceptable` results. If its code status is `undefined`, only the verdict is compared.

### Refusal-code status of a witness

| `candidate.refusal_code_status` | Meaning |
| --- | --- |
| `text` | The code is named by the cited rule, or by its `registry/refusal-codes.json` description, for exactly this condition. |
| `derived` | No rule names a code for this exact condition, but the text makes the result equal to that of a paired control: the varied element cannot change the subject's state (a presenter-supplied or presenter-withheld element, while the state is defined by chain events), or the same admission pipeline runs on the same grant. Where failing closed on the element itself is equally defensible, that result is listed in `also_acceptable`. |
| `undefined` | draft.7 defines neither an admission step nor a refusal code for the condition. `expected_refusal` is `null`, only the verdict is compared, and `candidate.proposed_refusal` is a suggestion. (No case of this suite uses it.) |

### Scenario runners

Cases using the `session_lifecycle` runner follow the convention of the published suite: the case verdict is `ADMIT` if and only if every step returns exactly its `want_verdict` / `want_refusal`; otherwise the harness reports `REFUSE` with the pseudo-code `SESSION_STEP_MISMATCH:<label>:<result>` (see `execute_security_case`). For such a witness the expected case verdict is therefore `ADMIT`, and the recorded reference result is the mismatch.

## When a finding is fixed

1. `--check` fails with `witness is now satisfied … promote it`; `--strict` shows which witnesses are still open.
2. Move the case (and the controls that are not already covered) into `tools/build_security_suite.py`, regenerate `vectors/` with `tools/gen_vectors.py`, and delete the builder call here. For a witness whose code status was `derived`, or which lists `also_acceptable` results, first write the rule and fix one code, then record that code in the promoted case.
3. For a `decision` record: write the decision into the specification, then either correct the published vectors named in `conflicts_with` or drop the record.
4. Run `--write`, then `speclint.py --require-jsonschema`.

## Boundaries

- Inputs use the reference harness model (`ChainView`, presentation bundle, `FencedJournal.from_dict`, and slots such as `origin_bundle.recovery_bindings`, `origin_bundle.opened_majority_unix`, `assert_binding_id` and `executor_cfg.slot_owners`) exactly as the published security suite does. That model is defined by `tools/`, not by the prose. `executor_cfg.slot_owners` in particular exists only in the reference: no text, schema or published vector names it (`G7-01`).
- `expected_*` of a witness is a reading of the text by the reviewer, with the cited sentence in `candidate.basis`. Only `text` statuses claim that the code is spelled out. Two findings use `derived`: `R2G-01` (a withheld candidate cannot change a recovery state defined by chain events; failing closed with `ORIGIN_STATUS_INCOMPLETE`, the draft.6 behaviour, is also acceptable) and `G7-03` (the open step returns the first failure of the `§4` pipeline on the same grant, as the paired invocation does).
- The `G7-01` witness presupposes that a host without a binding is closed; the decision record of the same finding asks exactly that question. The `G7-02` witness (`mail/send`) rests on the explicit `MUST` of `PROFILE-mail-v1 §4.1`; for `agent/tool` the same question is a decision record, because the published `trace-03` relies on the opposite.
- The `R2G-02` witness rests on "the name output" in `SPEC-04 §5.1` state 3 meaning the output at the tip. Its round trip is confirmed about 1000 blocks below a tip whose header time is `T`, so the name left and re-entered the guardians' `owner_policy` while the subject was still a ward, whichever moment a handover is measured at.
- Each finding is demonstrated by a few minimal cases, not by its whole class. Not covered, among others: a `0x10` cancel or a partially withheld candidate list (`R2G-01`); a planned rotation of the custodians' key before `T`, and an `agent`-class origin with a majority commitment taking Path A (`R2G-02`); a re-registered name inheriting a configured slot (`G7-01`); the `extend` and `close` session operations (`G7-03`); and the other differing members of the two `MachineClauseTerms` definitions (`config_sha256`, `window` versus flat heights) (`R2-01`).
- `R2G-03` consists of decision records plus controls, and `R2-01` of decision records only: no clause form is valid under both readings, so no control can pass under both.
- `--strict` passing shows that every witness returns an accepted result. It says nothing about the decision records, and it is not sufficient evidence that a finding is fixed for its whole class.
