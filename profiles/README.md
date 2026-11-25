# SealLink Standard Profiles

Pluggable domain profiles extending the SealLink v1.0 Core (`spec/SPEC-00` through `spec/SPEC-07`) under the extension rules of `SPEC-07 §4`.

| Profile | `service_type` | Status | Evidence / Maturity | Schemas | Summary |
| --- | --- | :-: | :-: | --- | --- |
| [`PROFILE-mail-v1.md`](PROFILE-mail-v1.md) | `mail` | `decided` | `vectors` | `schemas/profile-mail.schema.json` | Sovereign email hosting decoupled from identity: `mail/list`, `mail/read`, `mail/send`, folder/sender Constraint Algebra predicates, snapshot pagination, pinned TLS SPKI mutual auth, offline issuer & UTXO seal revocation. |
| [`PROFILE-agent-v1.md`](PROFILE-agent-v1.md) | `agent-session` | `decided` | `vectors` | `schemas/profile-agent.schema.json` | Bounded autonomous agent task briefs (`agent/brief`), mechanical tool execution (`agent/tool`), contract-bound isolated sessions with `config_sha256` (`agent/session`), and normative guardian message intake (`agent/guardian-message`). |
| [`PROFILE-artifact-v1.md`](PROFILE-artifact-v1.md) | *(optional module `artifact-notarization`)* | `decided` | `vectors` | `schemas/profile-artifact.schema.json`, `schemas/log.schema.json` | Decentralized artifact notarization & release Gatekeeper (`seallink-ticket/1`, `m-of-n`, `inconclusive`, absent-notary `target:` veto, `release_floor`, `fsverity-sha256`) and consensus-exact Tier-2 SPV (`seallink-tier2-name-history/1`, `SegWitNameUpdateProof`, Namecoin AuxPoW & retarget). |

Planned profiles (registered in `registry/service-types.json` and `OPEN-QUESTIONS.md` as `open`):
- `PROFILE-xmpp-v1.md` (`xmpp`)
- `PROFILE-blob-v1.md` (`blob` — grant-aware Blossom BUD-01/02/04)
- `PROFILE-wallet-v1.md` (`wallet` — `seallink/coins` spend & budget)
- `PROFILE-names-v1.md` (`names` — delegated update-only name operations)
- `PROFILE-compute-v1.md` (`compute` — `seallink/cost` & `seallink/tokens`, root `window_only` + bearer sessions)
- `PROFILE-rental-v1.md` (`rental` — contract-bound physical/digital asset lease)
