# Review-Candidate Negative Vectors for SealLink `v1.0.0-draft.6`

**Status: candidate, non-normative.** This directory is not part of `vectors/`, is not listed in `CONFORMANCE.md`, and is not included in the release bundle or the published site.

It holds executable candidate vectors for the fifteen `Blocker` findings (`B-1` … `B-15`) of the independent engineering review of `v1.0.0-draft.6` (commit `b027a49`). Each finding is a place where the Reference Verifier Core admits something the specification text forbids, returns a different refusal code than the text names, or where no single expected result exists yet — because the text says two things, contradicts a published vector, or is silent while the schema, the registry and the reference differ.

The cases live here, and not in `vectors/security-conformance.json`, for two reasons:

1. Most witnesses are still admitted by `tools/seallink_verifier.py`. Adding them to `vectors/` would turn `speclint.py` red, and `CONFORMANCE.md` would then require every implementation to pass vectors the reference itself fails.
2. Some records need an authors' decision before a single expected result exists.

## Files

| File | Content |
| --- | --- |
| [`draft6-blockers.json`](draft6-blockers.json) | The suite. Every case has the shape of a `vectors/security-conformance.json` case (same runners and `inputs`) plus a `candidate` block. |
| [`INDEX.md`](INDEX.md) | Generated index: per finding, the cited specification text, every case with its expected result, the result of the draft.6 reference, and the open decisions. Case counts are stated there. |
| [`SHA256SUMS`](SHA256SUMS) | Integrity pins for the three files above (including this README). |

Generator and checker: [`tools/build_candidate_suite.py`](../../tools/build_candidate_suite.py). It builds every fixture from the published traces and matrix fixtures with deterministic keys, and executes cases through the same `execute_security_case` function that `speclint.py` uses for `vectors/security-conformance.json`.

## Run

Requires Python 3.11+ with `jsonschema>=4.23`, like `speclint.py`.

```sh
python3 tools/build_candidate_suite.py            # --check: the ratchet (default)
python3 tools/build_candidate_suite.py --strict   # the target state: every witness must return an accepted result
python3 tools/build_candidate_suite.py --list     # only execute the committed cases and print the table
python3 tools/build_candidate_suite.py --write    # regenerate draft6-blockers.json, INDEX.md and SHA256SUMS
```

Both checking modes regenerate the suite in memory and require byte equality with the committed files, and both require every `control` to return exactly its `expected_verdict` / `expected_refusal`. They differ in how they judge the rest:

| Mode | `witness` | `decision` | Use |
| --- | --- | --- | --- |
| `--check` (ratchet) | must behave exactly as recorded in `candidate.reference_draft6`; a witness that has become satisfied is reported too, because it has to be promoted | must behave exactly as recorded | CI of this repository: passes while witnesses are open, fails as soon as the verifier's behaviour on any case changes, in either direction |
| `--strict` (target state) | must return an accepted result | executed and listed, not judged | evaluating a fixed verifier before the cases are promoted; fails while any witness is open |

## Case roles

| `candidate.role` | Meaning |
| --- | --- |
| `control` | A nearby valid (or validly refused) case that passes on the reference today. Every witness names its controls in `candidate.control_ids`; a control may belong to another finding when the same fixture serves both. Controls are judged in both modes, so an implementation that refuses everything fails the suite. |
| `witness` | The defect. `expected_*` is the result required by the specification text quoted in `candidate.basis`. `candidate.also_acceptable` lists other results the text equally permits, each with its reason. |
| `decision` | No single expected result exists yet. `candidate.readings` lists each reading with its source and result; `expected_*` mirrors `readings[0]` and carries no preference. `candidate.conflicts_with` names the published cases that at least one reading contradicts. |

A witness is **closed** when the verifier returns `expected_*` or one of the `also_acceptable` results. If its code status is `undefined`, only the verdict is compared.

### Refusal-code status of a witness

| `candidate.refusal_code_status` | Meaning |
| --- | --- |
| `text` | The code is named by the cited rule, or by its `registry/refusal-codes.json` description, for exactly this condition. |
| `derived` | No rule names a code for this exact condition, but the text says that the varied element does not change the subject's status (an unauthenticated presenter-supplied element, or an update the text says "NEVER unbinds"), so the expected result equals the paired control's. Where failing closed on the element itself is equally defensible, that result is listed in `also_acceptable`. |
| `undefined` | draft.6 defines neither an admission step nor a refusal code for the condition. `expected_refusal` is `null`, only the verdict is compared, and `candidate.proposed_refusal` is a suggestion. |

### Scenario runners

Cases using the `restart_recovery` and `sibling_rows_replay` runners follow the convention of the published suite: the case verdict is `ADMIT` if and only if every step returns exactly its `want_verdict` / `want_refusal` and the post-conditions hold; otherwise the harness reports `REFUSE` with a pseudo-code that names the failed step or post-condition (for example `POST_STEP_MISMATCH:<label>:<result>`; see `execute_security_case`). For such a witness the expected case verdict is therefore `ADMIT`, and the recorded reference result is the mismatch.

## When a finding is fixed

1. `--check` fails with `witness is now satisfied … promote it`; `--strict` shows which witnesses are still open.
2. Move the case (and the controls that are not already covered) into `tools/build_security_suite.py`, regenerate `vectors/` with `tools/gen_vectors.py`, and delete the builder call here. For a witness whose code status was `derived` or `undefined`, or which lists `also_acceptable` results, first write the rule and fix one code, then record that code in the promoted case.
3. For a `decision` record: write the decision into the specification, then either correct the published vector named in `conflicts_with` or drop the record.
4. Run `--write`, then `speclint.py --require-jsonschema`.

## Boundaries

- Inputs use the reference harness model (`ChainView`, presentation bundle, `FencedJournal.from_dict`, and slots such as `bundle.notary_act`, `origin_bundle.opened_majority_unix` and `executor_cfg.pinned_ward_origin_id`) exactly as the published security suite does. That model is defined by `tools/`, not by the prose.
- `expected_*` of a witness is a reading of the text by the reviewer, with the cited sentence in `candidate.basis`. Only `text` statuses claim that the code is spelled out. Three readings depend on intent the text does not state and are therefore paired with `also_acceptable` results: whether the pinned ward is the subject of `SL-ORIG-006` for guardian messages (`B-3`), whether an unverifiable disclosure is ignored or refused (`B-13`), and whether a presented notary act first goes through the wire pipeline (`B-4`).
- Each finding is demonstrated by a few minimal cases, not by its whole class. Not covered, among others: `recipient_rule.mode = "member_class"` (`B-6`), roster records and name-recycled authorities (`B-14`), debit formulas, additive pools and batch-anchored siblings (`B-8`), and any schema-level code conflict beyond the three cases of `B-11`.
- `B-4` has no positive control with a notary act that every reading accepts. `SPEC-05 §5` defines the act, its `0x04` anchor and its verification, but draft.6 does not say in prose how a grant designates its notary or how the act is presented; and such a control would be vacuous today, because the reference accepts any truthy value.
- `B-15` consists of decision records only, and `B-10` of decision records plus one control. For `B-10` the specification prose gives no member rule at all; the only pin is a published vector whose `0x01` commitment equals the reference reconstruction.
- `--strict` passing shows that every witness returns an accepted result. It says nothing about the decision records, and it is not sufficient evidence that a finding is fixed for its whole class.
