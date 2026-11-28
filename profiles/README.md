# SealLink Standard Profiles

Pluggable domain profiles extending the SealLink v1.0 Core (`spec/SPEC-00` through `spec/SPEC-07`) under the extension rules of `SPEC-07 §4`.

| Profile | `service_type` | Status | Evidence / Maturity | Schemas | Summary |
| --- | --- | :-: | :-: | --- | --- |
| [`PROFILE-mail-v1.md`](PROFILE-mail-v1.md) | `mail` | `decided` | `vectors` | `schemas/profile-mail.schema.json` | Sovereign email hosting decoupled from identity: `mail/list`, `mail/read`, `mail/send`, folder/sender Constraint Algebra predicates, snapshot pagination, pinned TLS SPKI mutual auth, offline issuer & UTXO seal revocation. |
| [`PROFILE-agent-v1.md`](PROFILE-agent-v1.md) | `agent-session` | `decided` | `vectors` | `schemas/profile-agent.schema.json` | Bounded autonomous agent task briefs (`agent/brief`), mechanical tool execution (`agent/tool`), contract-bound isolated sessions with `config_sha256` (`agent/session`), and normative guardian message intake (`agent/guardian-message`). |
| [`PROFILE-artifact-v1.md`](PROFILE-artifact-v1.md) | *(optional module `artifact-notarization`)* | `decided` | `vectors` | `schemas/profile-artifact.schema.json`, `schemas/log.schema.json` | Decentralized artifact notarization & release Gatekeeper (`seallink-ticket/1`, `m-of-n`, `inconclusive`, absent-notary `target:` veto, `release_floor`, `fsverity-sha256`) and consensus-exact Tier-2 SPV (`seallink-tier2-name-history/1`, `SegWitNameUpdateProof`, Namecoin AuxPoW & retarget). |

## Exploratory Draft Extension Profiles (Non-Normative)

Non-normative exploratory drafts (`Status: exploratory-draft (non-normative)`) illustrating how real-world domains compose over SealLink v1.0 Core — including **SSH (`PROFILE-ssh-v1.md`)**, **SSO (`PROFILE-sso-v1.md`)**, **Payment Endpoints (`PROFILE-payment-v1.md` + `registry/payment-schemes.json`)**, **E2EE Messaging (`PROFILE-e2ee-messaging-v1.md`)**, **SealLink Social / Nostr (`PROFILE-social-v1.md`)**, **Domain Binding (`PROFILE-domain-binding-v1.md`)**, and draft skeletons for the six reserved `open` service types (`xmpp`, `blob`, `wallet`, `names`, `compute`, `rental`) — live in [`profiles/drafts/`](drafts/README.md). They are NOT part of v1.0 Core conformance requirements and do not alter v1.0 wire schemas.
