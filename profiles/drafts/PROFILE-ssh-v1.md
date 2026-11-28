# PROFILE-ssh-v1: Sovereign SSH Host Authentication (Zero-MITM) and Grant-Gated Access Control

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — NOT part of the frozen v1.0 Core conformance bar; candidate for a post-v1.0 Standard Profile SLIP (`SPEC-07 §4`).
- **Service Type (proposed):** `ssh` *(or reverse-domain `org.seallink/ssh` prior to `Registry Update`)*
- **Core Primitives Used:** `SPEC-01` (`ssh-ed25519` `PROTOCOL.sshsig`, `fido2-es256` / `fido2-eddsa` `UP`/`UV`), `SPEC-02` (`ChainView`, mempool `SEAL_SPENT`), `SPEC-03` (`sets.auth` depth-16, `sets.devices` depth-16, `sets.certs` depth-20 `transport-binding` / `config-section`, `sets.members` depth-34 `MemberEntryProof`), `SPEC-06` (`seallink-grant/1` with `not_after_unix`, `single_use_1_of_2` break-glass, `DeviceSignatureSet` recipients).

---

## 1. Problem Statement & Zero-MITM Guarantee

Traditional OpenSSH operations suffer from three chronic structural failures:
1. **Trust-On-First-Use (TOFU) host key verification:** Operators blindly type `yes` on first login (`~/.ssh/known_hosts`), leaving ephemeral cloud VMs, fresh bare-metal installs, and rotating bastions exposed to Man-in-the-Middle (MITM) interception.
2. **Stale `authorized_keys` sprawl & slow offboarding:** Static `~/.ssh/authorized_keys` files drift across hundreds or thousands of servers; revoking a lost laptop or departing contractor requires pushing config changes to every host (which fails on temporarily unreachable hosts).
3. **Centralized SSH CA single point of failure:** Enterprise SSH Certificate Authorities (Vault, Teleport, Smallstep) solve TOFU and expiry only by introducing a single centralized online signing authority and identity provider.

**`PROFILE-ssh-v1`** eliminates all three failure modes using unmodified OpenSSH (`AuthorizedKeysCommand`, `KnownHostsCommand`, `ProxyCommand`) backed by a Tier-1 SealLink verifier (`nc28.0` read-only node + `>= 1` comparison peer):
- **Zero-MITM host identity:** Every server (or host cluster) publishes its SSH host public key(s) in a signed `seallink-statement/1 (statement_kind = "transport-binding", transport = "ssh")` committed in its confirmed `manifest.sets.certs` (depth-20 `CertEntryProof`), with an optional disposable UTXO `seal` for mempool-speed emergency key revocation.
- **Mempool-speed offboarding across an entire fleet:** Removing an engineer or revoking a lost YubiKey spends ONE UTXO (`entry.seal` in `sets.members`, `sets.devices`, `sets.auth`, or a contractor's `grant.revocation.seal`). Every SSH server watching the ledger rejects the key within seconds — with zero central SSH CA and zero fleet push!
- **Hardware-attested physical presence (`UP`/`UV`):** Using `fido2-es256`, `fido2-eddsa`, or `ssh-ed25519` (`SPEC-01 §4.1`), production hosts can cryptographically enforce hardware touch (`UP`) or PIN/biometric (`UV`) on every privileged session or break-glass grant.

---

## 2. Host Identity & Zero-MITM Client Verification

### 2.1 Publishing a Server's SSH Host Key on SealLink

Each managed SSH host (e.g., `id/prod-eu-01`) holds a ledger registration `(name, registration, owner_policy)` — or a fleet organization (`id/acme-infra`) issues per-host `transport-binding` statements inside `sets.certs` keyed by `endpoint`:

```json
{
  "payload": {
    "genesis": "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
    "issuer": {
      "name": "id/prod-eu-01",
      "owner_policy": { "kind": "multisig", "m": 2, "pks": ["02...", "03...", "02..."] },
      "registration": { "txid": "<64hex>", "vout": 0 }
    },
    "network": "main",
    "not_after": 1826755200,
    "not_before": 1795219200,
    "seal": {
      "script_policy": { "kind": "key", "pk": "02<disposable_csprng_pk>" },
      "txid": "<64hex>",
      "vout": 0
    },
    "seq": 4,
    "statement_kind": "transport-binding",
    "subject": {
      "endpoint": "ssh://prod-eu-01.infra.example:22",
      "key_alg": "ed25519",
      "key_hex": "<64hex_host_ed25519_pubkey>",
      "transport": "ssh"
    },
    "type": "seallink-statement/1"
  },
  "signatures": {
    "policy": { "m": 1, "pks": ["<64hex_host_grant_key>"] },
    "sigs": [{ "pk": "<64hex_host_grant_key>", "sig": "<128hex_bip340>" }]
  }
}
```

- **Signer authority:** Signed by the host's (or fleet authority's) `link.grant` key (or an enrolled `sets.devices` L1/L2 key for owner-managed hosts, `SPEC-03 §3.1`), pinned inside the confirmed depth-20 sparse Merkle tree `manifest.sets.certs` (`seallink-cert-set-head/1` + `seallink-cert-entry/1`).
- **Compromise response:** If `/etc/ssh/ssh_host_ed25519_key` is compromised, broadcasting the pre-signed TRUC v3 `P2A` `tx_revoke` for `statement.seal` invalidates the host key across all connecting clients at mempool speed (`SEAL_SPENT`) — even before rotating the manifest on chain!

### 2.2 Client-Side Zero-MITM (`KnownHostsCommand` + `~/.ssh/config`)

Operators connect using familiar OpenSSH UX (`ssh deploy@id/prod-eu-01` or `ssh prod-eu-01.sl`):

```sshconfig
# ~/.ssh/config
Host *.sl
    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    KnownHostsCommand /usr/local/bin/seallink-ssh-knownhosts %H %p %t
    # Optional: resolve IP/port from verified SealLink card/DNS & wrap transport
    # ProxyCommand /usr/local/bin/seallink-ssh-proxy %h %p
```

**Execution flow of `seallink-ssh-knownhosts`:**
1. Maps host target (`%H`, e.g., `prod-eu-01.sl` -> `id/prod-eu-01`) against local pin configuration (`network`, `genesis`, optional `registration`/`owner_policy` pin).
2. Resolves `id/prod-eu-01` via local Tier-1 verifier (or Tier-2 SPV client with `seallink-tier2-name-history/1`), verifying `m.h` -> `seallink-manifest/1` -> `sets.certs` depth-20 `CertEntryProof`.
3. Validates the `seallink-statement/1 (transport-binding, transport="ssh")`: signature, `not_before <= now < not_after`, monotonic `seq`, matching `endpoint`, and **unspent `statement.seal`** (`SEAL_SPENT` -> exit non-zero, aborting connection immediately!).
4. Emits the verified OpenSSH `known_hosts` line (`<host> ssh-ed25519 <base64_wire_pubkey>`) to stdout. OpenSSH performs standard cryptographic handshake verification against that exact key with **zero TOFU prompts and zero possibility of MITM**.

---

## 3. Expressing Host Access Policy (Two Deployment Models)

How does a server know **who** is allowed to log in as `root`, `deploy`, or `readonly`? SealLink supports two composable, cryptographically verifiable host policy models:

### 3.1 Model A — Owner-Managed Host (`config-section` + `policy-apply`)
Ideal for personal servers, sovereign infrastructure, and small teams where one owner `id/alice` controls the host:
1. The host pins its **Trust-Root** (`SPEC-03 §6`, `SL-IDEN-012`) in admin-owned read-only storage (`/etc/seallink/trust-root.json`): `(network, genesis, root_name = "id/alice", registration, owner_policy, pinned_grant_policy)`.
2. Policy updates are authored as a canonical JSON `ssh-host-policy/1` document hashed into a `seallink-statement/1 (statement_kind = "config-section", subject = {"host_id": "id/prod-eu-01", "section": "ssh-access"})` and applied via an L2 `seallink-owner-command/1 (command = "policy-apply", level = 2)` signed by an enrolled `sets.devices` hardware key (`presence = true`, optionally `presence_attestation = "uv"`).
3. Direct owner logins authenticate any active `sets.devices` key (`alg ∈ {"ssh-ed25519", "ed25519", "fido2-es256", "fido2-eddsa"}`) whose `ceiling` meets the mapped principal level (e.g., `root` requires `ceiling = 2` + `presence = true`, `deploy` requires `ceiling >= 1`) and whose disposable `entry.seal` is unspent.

### 3.2 Model B — Organization / Fleet RBAC (`sets.members` Depth-34 Roles)
Ideal for fleets of 10 to 100,000 servers managed by an organization `id/acme`:
1. Every host in the `prod-eu` fleet shares one signed `ssh-host-policy/1` pinning `org = NamePin(id/acme)` and mapping organization `roles[]` tags to OS principals and OpenSSH options:
   ```json
   {
     "policy_version": 1,
     "host_id": "id/prod-eu-01",
     "trusted_orgs": [
       {
         "org_pin": { "name": "id/acme", "owner_policy": { "kind": "multisig", "m": 2, "pks": ["..."] }, "registration": { "txid": "...", "vout": 0 } },
         "require_reciprocal_identity_link": true,
         "role_mappings": {
           "ssh.prod.root": { "principals": ["root"], "min_presence_attestation": "uv", "options": ["no-agent-forwarding"] },
           "ssh.prod.sre":  { "principals": ["sre", "deploy"], "min_presence_attestation": "up", "options": ["no-port-forwarding"] },
           "ssh.prod.ro":   { "principals": ["audit"], "min_presence_attestation": "declared", "options": ["restrict", "command=\"/usr/local/bin/audit-shell\""] }
         }
       }
     ],
     "allow_grants_from": ["id/acme", "id/acme-oncall-lead"]
   }
   ```
2. **Selective-disclosure fleet authentication:** Because `id/acme`'s `sets.members` is a depth-34 sparse masked salted Merkle tree (`seallink-member-set-head/1` + `seallink-member-entry/1`, `SPEC-03 §3.1`), proving that `id/bob` holds role `"ssh.prod.sre"` takes only ~1.5 KiB (`MemberEntryProof`) without revealing any other employee or total headcount.
3. **Instant fleet-wide offboarding:** Spending `id/bob`'s single disposable `seallink-member-entry/1.seal` UTXO immediately terminates `id/bob`'s SSH access across **every** `id/acme` server on Earth at mempool speed (`SEAL_SPENT`)!

---

## 4. Time-Bounded Contractor & Break-Glass Access (`seallink-grant/1`)

For temporary contractor access, incident-response escalation, or automated CI/CD deploy jobs, the host owner or authorized org issues a **`seallink-grant/1`** directly to the contractor's hardware key (`recipient.mode = "key"` with `alg: "ssh-ed25519"` or `fido2-es256`/`fido2-eddsa` + `presence_attestation: "up"|"uv"`) or SealLink name (`recipient.mode = "name"`):

### 4.1 Proposed Action Leaves (`SPEC-07 §4.1` Matrix)

| Action | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `allows_bearer_session` | `requires_contract` | `require_seal` | Risk Class |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `ssh/session` | `true` | `true` | `true` | `false` | `false` | `false` | `true` | Class 1 (`3600s`) |
| `ssh/exec` | `true` | `true` | `true` | `false` | `false` | `false` | `true` | Class 1 (`3600s`) |
| `ssh/port-forward` | `true` | `true` | `true` | `false` | `false` | `false` | `true` | Class 1 (`3600s`) |

- **Target grammar:** `^ssh:id/[a-z0-9][a-z0-9._-]{0,63}:[a-z_][a-z0-9_-]{0,31}$` (e.g., `ssh:id/prod-eu-01:deploy`).
- **Mechanical `terms_text` ban:** All `ssh/*` actions are mechanical effect leaves and MUST refuse grants carrying `terms_text` (`GRANT_TEXT_FORBIDDEN`).
- **Calendar & block bounds:** Combines Namecoin block window `[not_before_height, not_after_height)` with exact wall-clock **`not_after_unix`** (`SPEC-06 §1.4`, e.g., a 4-hour maintenance window!), plus `quotas` (`seallink/count` `sessions`) and `where` constraints:
  - `principal`: `eq` / `in` (OS user account, e.g., `"deploy"`)
  - `command_prefix`: `prefix` / `eq` (forced command restriction for `ssh/exec`, e.g., `"systemctl restart app"`)
  - `allow_pty`: `eq` (`true` / `false`)
  - `allow_port_forwarding`: `eq` (`true` / `false`)
  - `source_cidr`: `in` / `eq` (optional source network restriction)
- **Single-use emergency break-glass (`0x11`):** Setting `revocation.kind = "single_use"` (`single_use_1_of_2`) requires the on-call engineer to broadcast `0x11 SINGLE_USE_CONSUMPTION` committing to their signed `seallink-invocation/1` — creating an immutable, publicly timestamped on-chain audit record of exactly one emergency root login!

---

## 5. Server-Side OpenSSH Integration (`AuthorizedKeysCommand`)

```sshdconfig
# /etc/ssh/sshd_config.d/90-seallink.conf
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile none
AuthorizedKeysCommand /usr/local/bin/seallink-sshd-auth %u %k %t %f
AuthorizedKeysCommandUser seallink-auth
```

**Verification flow of `seallink-sshd-auth`:**
1. Receives OS principal `%u`, presented SSH public key `%k`, key type `%t`, and fingerprint `%f`.
2. Looks up matching proof bundle from local session cache, client pre-auth staging endpoint, or Channel 0–3 resolver (never trusting unverified bundles!).
3. Runs the **full Tier-1 SealLink verification pipeline** against its local read-only `nc28.0` node (+ `>= 1` comparison peer) and `FencedJournal`:
   - Path 1 (*Owner / Org Member*): verifies `DeviceEntryProof` (depth 16) or `AuthEntryProof` (depth 16) + `MemberEntryProof` (depth 34) + reciprocal `identity-link` (if required) + all live seals + `min_presence_attestation` (rejecting non-FIDO2 keys when `"up"`/`"uv"` is required!).
   - Path 2 (*Contractor / Delegated Grant*): verifies full 12-step `seallink-invocation/1` admission (`SPEC-06 §4`, including `not_after_unix`, `revocation.seal`, depth-2 `row_coin`/`stop_coin`, `where` predicates, `quotas`, and `pre_effect_recheck`).
4. On `ADMIT`, outputs a single locked-down OpenSSH `authorized_keys` line with synthesized restrictions (`restrict,no-port-forwarding,command="..."`, plus `verify-required` when `presence_attestation == "uv"` on OpenSSH FIDO2 `sk-*` keys) so `sshd` enforces the exact admitted capabilities at OS level.
5. On ANY refusal (`SEAL_SPENT`, `GRANT_WINDOW_CLOSED`, `DEVICE_UNAUTHORIZED`, `CHAIN_UNHEALTHY`), emits **zero output** and logs the structured SealLink refusal code to the host audit log.

---

## 6. Operational Security Boundaries & Failure Modes

- **No lockout on ledger outage (break-glass):** Operators SHOULD retain an out-of-band console / IPMI / serial recovery path (never relying exclusively on online ledger reachability for physical host recovery), while keeping network SSH strictly fail-closed (`CHAIN_UNHEALTHY` / `CHAIN_TIP_STALE` MUST NEVER degrade to open SSH!).
- **SSH session revocation:** Spending a seal blocks all *new* SSH authentications and `AuthorizedKeysCommand` calls immediately; optionally, a lightweight local watchdog daemon (`seallink-sshd-reaper`) subscribes to `FencedJournal` closure events (`SEAL_SPENT` / `GRANT_WINDOW_CLOSED`) and sends `SIGTERM`/`SIGKILL` to active `sshd` session PIDs mapped to that revoked seal or expired `not_after_unix`!
- **Forwarding hygiene:** Hosts SHOULD disable `AllowAgentForwarding` by default so a compromised bastion cannot proxy `ssh-ed25519` or `fido2-*` signatures to downstream hosts.
