# PROFILE-compute-v1: Metered LLM, GPU, and Compute Proxy Execution

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — Reserved `open` standard service type (`registry/service-types.json`, `OPEN-QUESTIONS.md §3`); requires full SLIP + Draft 2020-12 schema + conformance vectors per `SPEC-07 §4.1` before promotion.
- **Service Type:** `compute`

---

## 1. Scope & Bearer Session Ergonomics

Enables sovereign actors and AI agents to consume metered inference APIs (OpenAI/Anthropic/vLLM-compatible proxies) and batch GPU compute using bounded SealLink grants:
- **Bearer Session Support (`SPEC-06 §5`, optional module `bearer-sessions`):** Standard LLM SDKs that only accept a base URL + HTTP `Authorization: Bearer <64hex>` header open a short-lived (`<= 3600s`) `seallink-session-open/1` session backed by a concrete-executor grant, while the proxy re-verifies the backing seal and debits `session -> own -> row` quotas atomically on every request.
- **Optional Root `window_only` Mode:** For low-budget ephemeral micro-grants (`<= 12` blocks, zero ledger tx fee), executors MAY opt in to `revocation.mode = "window_only"` (`SPEC-06 §1.4`) under strict operator ceilings.
- **Conservative Pre-Effect Reservation & Late Settlement (`SPEC-06 §2.2`):** Phase 1 (`admit_and_reserve`) reserves upper-bound cost/tokens (`max_tokens * max_rate_microusd`); Phase 2 (`commit_result`) settles exact actual token/cost usage and releases unused reserve (`reserved == settled + released`).

---

## 2. Candidate Action Leaves & Orthogonal Flags (`SPEC-07 §4.1`)

| Action | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `allows_bearer_session` | `requires_contract` | `require_seal` | Risk Class |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `compute/infer` | `false` | `false` | `true` | `false` | `true` | `false` | `false` *(policy opt-in `window_only`)* | Class 2 (`5400s`) |
| `compute/job-submit` | `true` | `false` | `true` | `false` | `true` | `false` | `true` | Class 1 (`3600s`) |

- **Target grammar:** `^compute:id/[a-z0-9][a-z0-9._-]{0,63}:[a-z0-9._-]{1,64}$` (e.g., `compute:id/gpu-cloud:llm-pool`).
- **Required quotas:** `seallink/tokens` (`tokens`) and/or `seallink/cost` (`microusd` / atomic unit, `resource == target`).
- **Candidate `where` predicates:** `model_id` (`eq`/`in`/`prefix`), `max_output_tokens` (`range`), `max_cost_microusd` (`range`), `data_retention` (`eq` `"zero"`).
- **Mechanical `terms_text` ban:** All `compute/*` actions refuse `terms_text` (`GRANT_TEXT_FORBIDDEN`).

---

## 3. Open SLIP Checklist Items (`SPEC-07 §4.1`)
1. Formal `schemas/profile-compute.schema.json` covering deterministic worst-case token/cost reservation math (zero floats) and streaming settlement rules.
2. Exact `result_sha256` binding over completion digests + usage meters.
3. Conformance vectors for `session-use` triple-account (`session -> own -> row`) debits, streaming `uncertain` timeout retention, and `window_only` opt-in policy.
