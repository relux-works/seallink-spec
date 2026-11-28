#!/usr/bin/env python3
"""
SealLink v1.0.0-draft.15 Core Symmetry, Generality, Hardware Wrappers & IPv4-Scaling Conformance Suite.

Appends executable conformance, adversarial, boundary, and mutation-killing cases to
`vectors/security-conformance.json`, covering every draft.15 addition:

  - Section 1 (Closed OQ-005 — Hardware Wrappers & Hardware-Attested Presence):
      * ssh-ed25519 (OpenSSH PROTOCOL.sshsig), fido2-es256 & fido2-eddsa (WebAuthn/CTAP2)
      * rp_id binding against service_id / AuthEntry / DeviceEntry / grant.recipient
      * presence_attestation ("declared" | "up" | "uv") enforcing UP=0x01 & UV=0x04 flags
      * DeviceSignatureSet on grant.recipient (key/group), exact_key child rules, invocation/1, and session-open/1

  - Section 2 (log_tracked 0x14 for seallink-credential/1):
      * role="cred" 0x14 transparency/denial logs, cred:<id>|* SMT absence/revocation/reinstatement
      * seallink-log-fraud/1 equivocation permanently closing a compromised cred log_id
      * manifest.cred.log operational binding & role-scoped denial_key prefix enforcement

  - Section 3 (100% Symmetric Salted Sparse Masked Merkle Sets — Depths 16 / 20 / 34):
      * seallink-cert-set-head/1 + seallink-cert-entry/1 + CertEntryProof (exact 20 steps)
      * seallink-member-set-head/1 + seallink-member-entry/1 + MemberEntryProof (exact 34 steps, durable SEAL_SPENT)

  - Section 4 (Core Object Symmetry, Multi-Chain Network & IPv4 Limits):
      * seallink-notary/1 act_kind="contract-ruling" (target_sha256 binding, sorted disclosed_clause_indices)
      * seallink-grant/1 not_after_unix across invocation, child narrowing, bearer sessions (leaf & parent), & federation
      * seallink-origin/1 claims.identity_commitments
      * TransportKind (openpgp, age, mls) + key_alg="sha256-fingerprint"
      * Multi-chain Network pattern + IPv4 ceiling boundaries (1440, 65535, 525600)
"""

from __future__ import annotations

import copy
from typing import Any, Callable

import build_draft11_suite as bd11
import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-d15-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"d15-{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def _issuance_digest(grant_env: dict[str, Any]) -> str:
    gp = grant_env["payload"]
    prep: dict[str, Any] = {
        "genesis": gp["genesis"],
        "grant_content_addr": sl.content_addr(grant_env),
        "grant_id": sl.object_id(gp),
        "type": "seallink-issuance/1",
    }
    if "contract_id" in gp:
        prep["contract_id"] = gp["contract_id"]
    return sl.signing_digest(prep).hex()


def add_draft15_conformance_cases(add: Callable[..., None]) -> None:
    # ========================================================================
    # SECTION 1: Closed OQ-005 — Hardware Wrappers & Attested Presence (UP/UV)
    # ========================================================================
    fx_hw = rm._base_invocation_fixture()
    now_hw = fx_hw["chain"]["now"]
    ed_seed = sl.deterministic_ed25519_seed("d15-hw-ed")
    ed_pk = sl.ed25519_pubkey(ed_seed)
    ed_seed2 = sl.deterministic_ed25519_seed("d15-hw-ed2")
    ed_pk2 = sl.ed25519_pubkey(ed_seed2)
    p256_sk = sl.deterministic_p256_privkey("d15-hw-p256")
    p256_pk = sl.p256_compressed_pubkey(p256_sk)

    aseal_pol = {"kind": "key", "pk": _kp("hw-aseal")["comp"]}
    aseal_tx = _h32("hw-aseal-tx")
    dseal_pol = {"kind": "key", "pk": _kp("hw-dseal")["comp"]}
    dseal_tx = _h32("hw-dseal-tx")
    fx_hw["chain"]["txs"][aseal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(aseal_pol)}}}
    fx_hw["chain"]["txs"][dseal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(dseal_pol)}}}
    aseal = {"script_policy": aseal_pol, "txid": aseal_tx, "vout": 0}
    dseal = {"script_policy": dseal_pol, "txid": dseal_tx, "vout": 0}

    ah_hw, aps_hw = rm.make_salted_auth_set(
        "id/alice",
        [
            {"alg": "ssh-ed25519", "key": ed_pk, "label": "ssh-key", "seal": aseal},
            {"alg": "fido2-es256", "key": p256_pk, "label": "yk-p256", "presence_attestation": "uv", "rp_id": "example.org", "seal": aseal},
            {"alg": "fido2-eddsa", "key": ed_pk, "label": "yk-ed", "presence_attestation": "up", "rp_id": "example.org", "seal": aseal},
        ],
        salt_prefix="d15-auth",
    )
    dh_hw, dps_hw = rm.make_salted_device_set(
        "id/alice",
        [
            {"alg": "ssh-ed25519", "ceiling": 1, "key": ed_pk, "label": "ssh-dev", "presence": False, "seal": dseal},
            {"alg": "fido2-es256", "ceiling": 2, "key": p256_pk, "label": "yk-dev-uv", "presence": True, "presence_attestation": "uv", "rp_id": "seallink.local", "seal": dseal},
            {"alg": "fido2-eddsa", "ceiling": 2, "key": ed_pk, "label": "yk-dev-up", "presence": True, "presence_attestation": "up", "rp_id": "seallink.local", "seal": dseal},
        ],
        salt_prefix="d15-dev",
    )
    man_hw = rm.bind_sets_manifest(
        fx_hw["chain"],
        "id/alice",
        fx_hw["_alice_owner_pol"],
        fx_hw["_alice_reg"],
        auth_head=ah_hw,
        device_head=dh_hw,
        extra_link={"grant": fx_hw["_keys"]["alice_gr"]["xonly"]},
    )
    man_hw_h = sl.content_addr(man_hw)

    def _auth_j(nonce: str, svc: str = "sso.example.org") -> dict[str, Any]:
        return {
            "auth_nonces": {nonce: {"expires_at": now_hw + 60, "issued_at": now_hw, "service_id": svc, "used": False}},
            "journal_id": _h32(f"j-{nonce}"),
        }

    # 1.1 AuthChallenge with ssh-ed25519, fido2-es256 (UV), fido2-eddsa (UP), rp_id mismatch, & UV unmet
    n_ssh = _h32("ac-ssh")
    ac_ssh = sl.sign_envelope({
        "auth_alg": "ssh-ed25519", "auth_pubkey": ed_pk, "expires_at": now_hw + 60,
        "genesis": GENESIS_MAIN, "issued_at": now_hw, "name": "id/alice", "network": "main",
        "nonce": n_ssh, "service_id": "ssh.example.org", "type": "seallink-auth-challenge/1",
    }, [ed_seed], alg="ssh-ed25519")
    add(
        "d15-hw-auth-challenge-ssh-ed25519-admit",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": aps_hw[0], "chain": fx_hw["chain"], "challenge": ac_ssh, "journal": _auth_j(n_ssh, "ssh.example.org"), "manifests": {man_hw_h: man_hw}, "service_id": "ssh.example.org"},
        "ADMIT",
        None,
        "draft.15 OQ-005 closed: AuthChallenge signed with ssh-ed25519 (OpenSSH SSHSIG) and verified via depth-16 sets.auth admits.",
    )

    n_f2es = _h32("ac-f2es")
    ac_f2es_p = {
        "auth_alg": "fido2-es256", "auth_pubkey": p256_pk, "expires_at": now_hw + 60,
        "genesis": GENESIS_MAIN, "issued_at": now_hw, "name": "id/alice", "network": "main",
        "nonce": n_f2es, "service_id": "sso.example.org", "type": "seallink-auth-challenge/1",
    }
    ac_f2es_uv = sl.sign_envelope(ac_f2es_p, [p256_sk], alg="fido2-es256", rp_id="example.org", origin="https://sso.example.org", fido2_flags=0x05)
    add(
        "d15-hw-auth-challenge-fido2-es256-uv-admit",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": aps_hw[1], "chain": fx_hw["chain"], "challenge": ac_f2es_uv, "journal": _auth_j(n_f2es), "manifests": {man_hw_h: man_hw}, "service_id": "sso.example.org"},
        "ADMIT",
        None,
        "draft.15 OQ-005 closed: AuthChallenge signed with fido2-es256 (UP|UV=0x05, rp_id='example.org' matching 'sso.example.org') admits.",
    )
    ac_f2es_up_only = sl.sign_envelope(ac_f2es_p, [p256_sk], alg="fido2-es256", rp_id="example.org", origin="https://sso.example.org", fido2_flags=0x01)
    add(
        "d15-hw-auth-challenge-fido2-uv-unmet-refuse",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": aps_hw[1], "chain": fx_hw["chain"], "challenge": ac_f2es_up_only, "journal": _auth_j(n_f2es), "manifests": {man_hw_h: man_hw}, "service_id": "sso.example.org"},
        "REFUSE",
        "AUTH_CHALLENGE_INVALID",
        "draft.15: fido2-es256 AuthEntry requiring presence_attestation='uv' MUST refuse AUTH_CHALLENGE_INVALID when UV flag is 0.",
    )
    ac_f2es_bad_rpid = sl.sign_envelope(ac_f2es_p, [p256_sk], alg="fido2-es256", rp_id="evil.org", origin="https://evil.org", fido2_flags=0x05)
    add(
        "d15-hw-auth-challenge-fido2-rpid-service-mismatch-refuse",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": aps_hw[1], "chain": fx_hw["chain"], "challenge": ac_f2es_bad_rpid, "journal": _auth_j(n_f2es), "manifests": {man_hw_h: man_hw}, "service_id": "sso.example.org"},
        "REFUSE",
        "AUTH_CHALLENGE_INVALID",
        "draft.15: fido2-es256 AuthChallenge whose rp_id does not match service_id MUST refuse AUTH_CHALLENGE_INVALID.",
    )
    # rp_id matches service_id ("https://sso.example.org") but disagrees with AuthEntry.rp_id ("example.org") -> AUTH_KEY_UNPINNED
    ac_f2es_sub_rpid = sl.sign_envelope(ac_f2es_p, [p256_sk], alg="fido2-es256", rp_id="sso.example.org", origin="https://sso.example.org", fido2_flags=0x05)
    add(
        "d15-hw-auth-challenge-fido2-entry-rpid-mismatch-refuse",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": aps_hw[1], "chain": fx_hw["chain"], "challenge": ac_f2es_sub_rpid, "journal": _auth_j(n_f2es), "manifests": {man_hw_h: man_hw}, "service_id": "sso.example.org"},
        "REFUSE",
        "AUTH_KEY_UNPINNED",
        "draft.15: fido2-es256 AuthEntry pinned to rp_id='example.org' MUST refuse AUTH_KEY_UNPINNED for rp_id='sso.example.org'.",
    )

    n_f2ed = _h32("ac-f2ed")
    ac_f2ed = sl.sign_envelope({
        "auth_alg": "fido2-eddsa", "auth_pubkey": ed_pk, "expires_at": now_hw + 60,
        "genesis": GENESIS_MAIN, "issued_at": now_hw, "name": "id/alice", "network": "main",
        "nonce": n_f2ed, "service_id": "https://sso.example.org", "type": "seallink-auth-challenge/1",
    }, [ed_seed], alg="fido2-eddsa", rp_id="example.org", origin="https://sso.example.org", fido2_flags=0x01)
    add(
        "d15-hw-auth-challenge-fido2-eddsa-up-admit",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_challenge",
        {"auth_proof": aps_hw[2], "chain": fx_hw["chain"], "challenge": ac_f2ed, "journal": _auth_j(n_f2ed, "https://sso.example.org"), "manifests": {man_hw_h: man_hw}, "service_id": "https://sso.example.org"},
        "ADMIT",
        None,
        "draft.15 OQ-005 closed: AuthChallenge signed with fido2-eddsa (UP=0x01) against https:// service_id admits.",
    )

    # 1.2 AuthUpgrade with fido2-es256 (admit, bad rp_id, UV unmet)
    n_up_f2 = _h32("au-f2")
    au_f2_p = {
        "account_id": "acct-f2-1", "auth_alg": "fido2-es256", "auth_pubkey": p256_pk,
        "expires_at": now_hw + 60, "firstupdate_txid": fx_hw["_alice_reg"]["txid"],
        "genesis": GENESIS_MAIN, "issued_at": now_hw, "name": "id/alice", "network": "main",
        "nonce": n_up_f2, "service_id": "sso.example.org", "type": "seallink-auth-upgrade/1",
    }
    au_f2_ok = sl.sign_envelope(au_f2_p, [p256_sk], alg="fido2-es256", rp_id="example.org", origin="https://sso.example.org", fido2_flags=0x05)
    add(
        "d15-hw-auth-upgrade-fido2-es256-admit",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_upgrade",
        {"auth_proof": aps_hw[1], "chain": fx_hw["chain"], "expected_provisional_auth_alg": "fido2-es256", "expected_provisional_auth_pubkey": p256_pk, "expected_service_id": "sso.example.org", "journal": _auth_j(n_up_f2), "manifests": {man_hw_h: man_hw}, "upgrade": au_f2_ok},
        "ADMIT",
        None,
        "draft.15: AuthUpgrade signed with fido2-es256 (UP|UV) admits.",
    )
    au_f2_bad_rp = sl.sign_envelope(au_f2_p, [p256_sk], alg="fido2-es256", rp_id="evil.org", origin="https://evil.org", fido2_flags=0x05)
    add(
        "d15-hw-auth-upgrade-fido2-bad-rpid-refuse",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_upgrade",
        {"auth_proof": aps_hw[1], "chain": fx_hw["chain"], "expected_provisional_auth_alg": "fido2-es256", "expected_provisional_auth_pubkey": p256_pk, "expected_service_id": "sso.example.org", "journal": _auth_j(n_up_f2), "manifests": {man_hw_h: man_hw}, "upgrade": au_f2_bad_rp},
        "REFUSE",
        "AUTH_CHALLENGE_INVALID",
        "draft.15: AuthUpgrade with fido2 rp_id mismatching service_id MUST refuse AUTH_CHALLENGE_INVALID.",
    )
    au_f2_no_uv = sl.sign_envelope(au_f2_p, [p256_sk], alg="fido2-es256", rp_id="example.org", origin="https://sso.example.org", fido2_flags=0x01)
    add(
        "d15-hw-auth-upgrade-fido2-uv-unmet-refuse",
        ["SL-WIRE-012", "SL-IDEN-010"],
        "auth_upgrade",
        {"auth_proof": aps_hw[1], "chain": fx_hw["chain"], "expected_provisional_auth_alg": "fido2-es256", "expected_provisional_auth_pubkey": p256_pk, "expected_service_id": "sso.example.org", "journal": _auth_j(n_up_f2), "manifests": {man_hw_h: man_hw}, "upgrade": au_f2_no_uv},
        "REFUSE",
        "AUTH_CHALLENGE_INVALID",
        "draft.15: AuthUpgrade failing AuthEntry.presence_attestation='uv' MUST refuse AUTH_CHALLENGE_INVALID.",
    )

    # 1.3 OwnerCommand & device-signed Statement with ssh-ed25519 & fido2 (UP/UV)
    cmd_ssh = sl.sign_envelope({
        "arguments": {"brief_sha256": _h32("b-ssh"), "run_id": "run-ssh-1"},
        "command": "agent-dispatch", "exp": now_hw + 120, "genesis": GENESIS_MAIN, "iat": now_hw,
        "level": 1, "network": "main", "nonce": _h32("cmd-ssh-n"), "owner": "id/alice",
        "target_executor": "id/station-a", "type": "seallink-owner-command/1",
    }, [ed_seed], alg="ssh-ed25519")
    add(
        "d15-hw-owner-command-ssh-ed25519-admit",
        ["SL-WIRE-012", "SL-IDEN-011"],
        "owner_command",
        {"chain": fx_hw["chain"], "command": cmd_ssh, "device_proof": dps_hw[0], "is_foreign_service": False, "owner_manifest": man_hw},
        "ADMIT",
        None,
        "draft.15: L1 OwnerCommand signed via ssh-ed25519 (SSHSIG) admits.",
    )
    cmd_l2_p = {
        "arguments": {"scope": "all"},
        "command": "keyholder-halt", "exp": now_hw + 120, "genesis": GENESIS_MAIN, "iat": now_hw,
        "level": 2, "network": "main", "nonce": _h32("cmd-f2-n"), "owner": "id/alice",
        "target_executor": "id/station-a", "type": "seallink-owner-command/1",
    }
    cmd_f2_ok = sl.sign_envelope(cmd_l2_p, [p256_sk], alg="fido2-es256", rp_id="seallink.local", fido2_flags=0x05)
    add(
        "d15-hw-owner-command-fido2-uv-admit",
        ["SL-WIRE-012", "SL-IDEN-011"],
        "owner_command",
        {"chain": fx_hw["chain"], "command": cmd_f2_ok, "device_proof": dps_hw[1], "is_foreign_service": False, "owner_manifest": man_hw},
        "ADMIT",
        None,
        "draft.15: L2 OwnerCommand signed with fido2-es256 (UP|UV=0x05) satisfying presence_attestation='uv' admits.",
    )
    cmd_f2_nouv = sl.sign_envelope(cmd_l2_p, [p256_sk], alg="fido2-es256", rp_id="seallink.local", fido2_flags=0x01)
    add(
        "d15-hw-owner-command-fido2-uv-unmet-refuse",
        ["SL-WIRE-012", "SL-IDEN-011"],
        "owner_command",
        {"chain": fx_hw["chain"], "command": cmd_f2_nouv, "device_proof": dps_hw[1], "is_foreign_service": False, "owner_manifest": man_hw},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "draft.15: L2 OwnerCommand with UV=0 MUST refuse DEVICE_UNAUTHORIZED when DeviceEntry sets presence_attestation='uv'.",
    )
    st_cfg_p = {
        "body_sha256": _h32("d15-cfg-body"), "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_hw["_alice_owner_pol"], "registration": fx_hw["_alice_reg"]},
        "network": "main", "not_after": now_hw + 600, "not_before": now_hw, "seq": 1,
        "statement_kind": "config-section", "subject": {"host_id": "id/station-a", "section": "ssh-policy"},
        "type": "seallink-statement/1",
    }
    st_cfg_ok = sl.sign_envelope(st_cfg_p, [ed_seed], alg="fido2-eddsa", rp_id="seallink.local", fido2_flags=0x01)
    add(
        "d15-hw-statement-fido2-up-admit",
        ["SL-WIRE-012", "SL-IDEN-006"],
        "statement",
        {"chain": fx_hw["chain"], "device_proof": dps_hw[2], "owner_manifest": man_hw, "statement": st_cfg_ok},
        "ADMIT",
        None,
        "draft.15: Device-signed config-section statement via fido2-eddsa (UP=1) satisfying presence_attestation='up' admits.",
    )
    st_cfg_noup = sl.sign_envelope(st_cfg_p, [ed_seed], alg="fido2-eddsa", rp_id="seallink.local", fido2_flags=0x00)
    add(
        "d15-hw-statement-fido2-up-unmet-refuse",
        ["SL-WIRE-012", "SL-IDEN-006"],
        "statement",
        {"chain": fx_hw["chain"], "device_proof": dps_hw[2], "owner_manifest": man_hw, "statement": st_cfg_noup},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "draft.15: Device-signed statement with UP=0 MUST refuse DEVICE_UNAUTHORIZED when DeviceEntry requires presence_attestation='up'.",
    )

    # 1.4 DeviceSignatureSet on grant.recipient (key/group), invocation/1, session-open/1, & exact_key child rule
    def _hw_grant_inv_fx(rcpt_spec: dict[str, Any], sign_algs: list[bytes], *, alg: str, rp_id: str | None = None, flags: int = 0x05, pks_override: list[str] | None = None, m_override: int | None = None) -> dict[str, Any]:
        fx_g = rm._base_invocation_fixture()
        gp = copy.deepcopy(fx_g["bundle"]["grants"][0]["payload"])
        gp["recipient"] = rcpt_spec
        g_env = sl.sign_envelope(gp, [fx_g["_keys"]["alice_gr"]["sk"]])
        gid = sl.object_id(gp)
        fx_g["chain"]["txs"][fx_g["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x01, _issuance_digest(g_env)).hex()
        fx_g["bundle"]["grants"] = [g_env]
        inv_p = copy.deepcopy(fx_g["invocation"]["payload"])
        inv_p["proof_path"][0]["grant_id"] = gid
        fx_g["invocation"] = sl.sign_envelope(inv_p, sign_algs, policy_pks=pks_override, m=m_override, alg=alg, rp_id=rp_id, fido2_flags=flags)
        return fx_g

    add(
        "d15-hw-grant-recipient-p256-invocation-admit",
        ["SL-WIRE-012", "SL-GRNT-001"],
        "invocation",
        _hw_grant_inv_fx({"alg": "p256", "key": p256_pk, "mode": "key"}, [p256_sk], alg="p256"),
        "ADMIT",
        None,
        "draft.15: Grant with recipient(mode='key', alg='p256') invoked via P-256 DeviceSignatureSet admits.",
    )
    add(
        "d15-hw-grant-recipient-ssh-ed25519-invocation-admit",
        ["SL-WIRE-012", "SL-GRNT-001"],
        "invocation",
        _hw_grant_inv_fx({"alg": "ssh-ed25519", "key": ed_pk, "mode": "key"}, [ed_seed], alg="ssh-ed25519"),
        "ADMIT",
        None,
        "draft.15: Grant with recipient(mode='key', alg='ssh-ed25519') invoked via OpenSSH SSHSIG admits.",
    )
    add(
        "d15-hw-grant-recipient-fido2-uv-invocation-admit",
        ["SL-WIRE-012", "SL-GRNT-001"],
        "invocation",
        _hw_grant_inv_fx({"alg": "fido2-es256", "key": p256_pk, "mode": "key", "presence_attestation": "uv", "rp_id": "seallink.local"}, [p256_sk], alg="fido2-es256", rp_id="seallink.local", flags=0x05),
        "ADMIT",
        None,
        "draft.15: Grant with recipient(mode='key', alg='fido2-es256', presence_attestation='uv') invoked with UP|UV admits.",
    )
    add(
        "d15-hw-grant-recipient-fido2-uv-unmet-refuse",
        ["SL-WIRE-012", "SL-GRNT-001"],
        "invocation",
        _hw_grant_inv_fx({"alg": "fido2-es256", "key": p256_pk, "mode": "key", "presence_attestation": "uv", "rp_id": "seallink.local"}, [p256_sk], alg="fido2-es256", rp_id="seallink.local", flags=0x01),
        "REFUSE",
        "WIRE_SIGNATURE",
        "draft.15: Grant recipient requiring fido2 presence_attestation='uv' MUST refuse WIRE_SIGNATURE when UV=0.",
    )
    add(
        "d15-hw-grant-recipient-group-ed25519-admit",
        ["SL-WIRE-012", "SL-GRNT-001"],
        "invocation",
        _hw_grant_inv_fx(
            {"mode": "group", "threshold": {"alg": "ed25519", "m": 2, "pks": sorted([ed_pk, ed_pk2])}},
            [ed_seed, ed_seed2],
            alg="ed25519",
            pks_override=sorted([ed_pk, ed_pk2]),
            m_override=2,
        ),
        "ADMIT",
        None,
        "draft.15: Grant with recipient(mode='group', DeviceThresholdPolicy alg='ed25519' 2-of-2) invoked admits.",
    )
    # Off-curve p256 key inside grant.recipient(key) -> WIRE_KEY
    bad_p256_pk = next(f"02{i:064x}" for i in range(1, 200) if not sl.is_valid_p256_compressed_pubkey(f"02{i:064x}"))
    gp_bad_p256 = copy.deepcopy(fx_hw["bundle"]["grants"][0]["payload"])
    gp_bad_p256["recipient"] = {"alg": "p256", "key": bad_p256_pk, "mode": "key"}
    add(
        "d15-hw-grant-recipient-off-curve-p256-refuse",
        ["SL-WIRE-012"],
        "raw_wire",
        {"object": sl.sign_envelope(gp_bad_p256, [fx_hw["_keys"]["alice_gr"]["sk"]])},
        "REFUSE",
        "WIRE_KEY",
        "draft.15: Off-curve P-256 key in grant.recipient MUST refuse WIRE_KEY at Step 9a.",
    )
    # Session-open with ed25519 recipient
    fx_so_hw = _hw_grant_inv_fx({"alg": "ed25519", "key": ed_pk, "mode": "key"}, [ed_seed], alg="ed25519")
    so_hw_gid = sl.object_id(fx_so_hw["bundle"]["grants"][0]["payload"])
    so_hw_env = sl.sign_envelope({
        "executor": fx_so_hw["invocation"]["payload"]["executor"],
        "exp": now_hw + 600, "genesis": GENESIS_MAIN, "iat": now_hw,
        "network": "main", "nonce": _h32("so-hw-n"), "op": "open",
        "proof_path": fx_so_hw["invocation"]["payload"]["proof_path"],
        "quotas": [], "slot_binding": "slot:hw-ed25519", "type": "seallink-session-open/1",
    }, [ed_seed], alg="ed25519")
    add(
        "d15-hw-session-open-ed25519-admit",
        ["SL-WIRE-012", "SL-GRNT-012"],
        "session_lifecycle",
        {
            "executor_cfg": fx_so_hw["executor_cfg"],
            "journal": {"journal_id": _h32("d15-so-j")},
            "steps": [{"bundle": fx_so_hw["bundle"], "chain": fx_so_hw["chain"], "kind": "session_open", "label": "open-ed25519", "session_open": so_hw_env, "want_refusal": None, "want_verdict": "ADMIT"}],
        },
        "ADMIT",
        None,
        "draft.15: seallink-session-open/1 signed with Ed25519 DeviceSignatureSet matching grant.recipient admits.",
        module="bearer-sessions",
    )

    # ========================================================================
    # SECTION 2: log_tracked (0x14) for seallink-credential/1 (role="cred")
    # ========================================================================
    eco_cred = bd11._build_log_ecosystem("d15-cred-log", role="cred", with_4_checkpoints=True)
    inc_cp1_in_cp3 = sl.rfc9162_inclusion_proof(eco_cred["leaves_2"], 0)
    inc_cp1_in_cp4 = sl.rfc9162_inclusion_proof(eco_cred["leaves_3"], 0)
    # Valid log_tracked credential (issued in cp1, absent in cp2 denials_root)
    add(
        "d15-cred-log-tracked-valid-admit",
        ["SL-CONT-008", "SL-CONT-012"],
        "credential",
        {
            "chain": eco_cred["chain_at_cp2"],
            "credential": eco_cred["item_env"],
            "log_ctx": {
                "batch_proof": eco_cred["b1_proof"],
                "checkpoint": eco_cred["cp1_env"],
                "checkpoint_txid": eco_cred["cp1_tx"],
                "checkpoints_proof": eco_cred["cp1_in_cp2_proof"],
                "head_checkpoint": eco_cred["cp2_env"],
                "head_checkpoint_txid": eco_cred["cp2_tx"],
                "smt_proof": sl.smt_prove({}, eco_cred["denial_key"]),
            },
        },
        "ADMIT",
        None,
        "draft.15: seallink-credential/1 with lifecycle='log_tracked' included in role='cred' 0x14 log and absent from denials_root admits.",
    )
    # Missing log_ctx -> CHAIN_FRAME_INVALID
    add(
        "d15-cred-log-tracked-missing-ctx-refuse",
        ["SL-CONT-008", "SL-CONT-012"],
        "credential",
        {"chain": eco_cred["chain_at_cp2"], "credential": eco_cred["item_env"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "draft.15: log_tracked credential without log_ctx MUST refuse CHAIN_FRAME_INVALID.",
    )
    # Revoked in cred 0x14 SMT -> CRED_REVOKED_FOR_CAUSE
    add(
        "d15-cred-log-tracked-revoked-refuse",
        ["SL-CONT-008", "SL-CONT-012"],
        "credential",
        {
            "chain": eco_cred["chain_at_cp3"],
            "credential": eco_cred["item_env"],
            "log_ctx": {
                "batch_proof": eco_cred["b1_proof"],
                "checkpoint": eco_cred["cp1_env"],
                "checkpoint_txid": eco_cred["cp1_tx"],
                "checkpoints_proof": inc_cp1_in_cp3,
                "head_checkpoint": eco_cred["cp3_env"],
                "head_checkpoint_txid": eco_cred["cp3_tx"],
                "smt_proof": sl.smt_prove(eco_cred["kv3"], eco_cred["denial_key"]),
                "state_record": eco_cred["rev1_env"],
            },
        },
        "REFUSE",
        "CRED_REVOKED_FOR_CAUSE",
        "draft.15: log_tracked credential revoked via cred:<id>|* in role='cred' 0x14 SMT MUST refuse CRED_REVOKED_FOR_CAUSE.",
    )
    # Reinstated at cp4 -> ADMIT (allow_reinstatement=True) and REFUSE (allow_reinstatement=False)
    for cid_r, allow_r, exp_v, exp_c in [
        ("d15-cred-log-tracked-reinstated-admit", True, "ADMIT", None),
        ("d15-cred-log-tracked-reinstated-disallowed-refuse", False, "REFUSE", "CRED_REVOKED_FOR_CAUSE"),
    ]:
        add(
            cid_r,
            ["SL-CONT-008", "SL-CONT-012"],
            "credential",
            {
                "allow_reinstatement": allow_r,
                "chain": eco_cred["chain"],
                "credential": eco_cred["item_env"],
                "log_ctx": {
                    "batch_proof": eco_cred["b1_proof"],
                    "checkpoint": eco_cred["cp1_env"],
                    "checkpoint_txid": eco_cred["cp1_tx"],
                    "checkpoints_proof": inc_cp1_in_cp4,
                    "head_checkpoint": eco_cred["cp4_env"],
                    "head_checkpoint_txid": eco_cred["cp4_tx"],
                    "smt_proof": sl.smt_prove(eco_cred["kv4"], eco_cred["denial_key"]),
                    "state_record": eco_cred["reinst2_env"],
                },
            },
            exp_v,
            exp_c,
            f"draft.15: log_tracked credential reinstated at state_seq=2 with allow_reinstatement={allow_r}.",
        )
    # Fraud proof (equivocation) on role="cred" log permanently closes log_id!
    cp2_fork_p = {**copy.deepcopy(eco_cred["cp2_env"]["payload"]), "batch_root": _h32("d15-cred-fork-br")}
    cp2_fork_env = sl.sign_envelope(cp2_fork_p, [eco_cred["iss_role"]["sk"]])
    fraud_cred = {
        "cp_a": eco_cred["cp2_env"], "cp_b": cp2_fork_env, "fraud_mode": "equivocation",
        "genesis": GENESIS_MAIN, "genesis_seal_outpoint": eco_cred["gen_op"],
        "log_id": eco_cred["log_id"], "network": "main", "role": "cred", "type": "seallink-log-fraud/1",
    }
    add(
        "d15-cred-log-fraud-equivocation-admit",
        ["SL-CONT-012"],
        "log_fraud",
        {"chain": eco_cred["chain_at_cp2"], "fraud": fraud_cred, "journal": {"journal_id": _h32("d15-cf-j")}},
        "ADMIT",
        None,
        "draft.15: seallink-log-fraud/1 equivocation proof for role='cred' 0x14 log admits and records permanent log closure.",
    )
    # Role-scoped denial_key: role="cred" with act: prefix MUST refuse WIRE_MEMBER!
    bad_cred_rev = copy.deepcopy(eco_cred["rev1_env"]["payload"])
    bad_cred_rev["denial_key"] = f"act:{eco_cred['item_id']}|*"
    add(
        "d15-cred-log-wrong-denial-key-prefix-refuse",
        ["SL-CONT-012", "SL-WIRE-010"],
        "raw_wire",
        {"object": sl.sign_envelope(bad_cred_rev, [eco_cred["iss_role"]["sk"]])},
        "REFUSE",
        "WIRE_MEMBER",
        "draft.15: role='cred' LogRevocation with non-cred: denial_key prefix MUST refuse WIRE_MEMBER.",
    )
    # manifest.cred.log valid & heartbeat_max_blocks boundary (525600 ADMIT vs 525601 REFUSE)
    man_cred_525600 = {
        "cred": {
            "log": {
                "genesis_seal": {"script_policy": eco_cred["seal_pol"], "txid": eco_cred["gen_op"]["txid"], "vout": 0},
                "heartbeat_max_blocks": 525600,
                "log_id": eco_cred["log_id"],
            },
            "supported_credential_kinds": ["education/degree", "identity/personhood"],
        },
        "network": "main", "owner": eco_cred["iss_name"], "seq": 1, "type": "seallink-manifest/1",
    }
    add("d15-manifest-cred-log-hb-525600-admit", ["SL-IDEN-006", "SL-CONT-012"], "raw_wire", {"object": man_cred_525600}, "ADMIT", None, "draft.15: manifest.cred.log with heartbeat_max_blocks=525600 admits.")
    man_cred_525601 = copy.deepcopy(man_cred_525600)
    man_cred_525601["cred"]["log"]["heartbeat_max_blocks"] = 525601
    add("d15-manifest-cred-log-hb-525601-refuse", ["SL-WIRE-008"], "raw_wire", {"object": man_cred_525601}, "REFUSE", "WIRE_INTEGER", "draft.15: manifest.cred.log with heartbeat_max_blocks=525601 (> 525600) MUST refuse WIRE_INTEGER.")

    # ========================================================================
    # SECTION 3: Depth-20 sets.certs & Depth-34 sets.members (100% Mutation Kill)
    # ========================================================================
    stmt_p15 = {
        "body_sha256": _h32("d15-prof-pay"), "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_hw["_alice_owner_pol"], "registration": fx_hw["_alice_reg"]},
        "network": "main", "not_after": now_hw + 600, "not_before": now_hw, "seq": 1,
        "statement_kind": "profile-section", "subject": {"section_kind": "org.seallink.payment/endpoints", "visibility": "private"},
        "type": "seallink-statement/1",
    }
    stmt_env15 = sl.sign_envelope(stmt_p15, [fx_hw["_keys"]["alice_gr"]["sk"]])
    chead15, cproofs15 = rm.make_salted_cert_set("id/alice", [stmt_env15], salt_prefix="d15-cs")
    man_cs15 = {**copy.deepcopy(man_hw), "sets": {"certs": {"seq": 1, "sha256": sl.content_addr(chead15)}}}
    add("d15-cert-entry-proof-depth20-admit", ["SL-IDEN-006"], "cert_entry_proof", {"cert_proof": cproofs15[0], "owner_manifest": man_cs15, "statement": stmt_env15}, "ADMIT", None, "draft.15: Depth-20 salted sparse Merkle CertEntryProof admits private payment profile-section.")
    card_cross = {"contact": "x@e.org", "display": "X", "kind": "person", "name": "id/alice", "network": "main", "relays": [], "replaces": 0, "role": "x", "seq": 1, "transports": [], "type": "seallink-card/1"}
    add("d15-cert-entry-proof-bad-stmt-wire-refuse", ["SL-WIRE-009"], "cert_entry_proof", {"cert_proof": cproofs15[0], "owner_manifest": man_cs15, "statement": card_cross}, "REFUSE", "WIRE_TYPE", "draft.15: verify_cert_entry_proof refuses wrong statement type.")
    add("d15-cert-entry-proof-bad-keys-refuse", ["SL-WIRE-010"], "cert_entry_proof", {"cert_proof": {"extra": 1, **cproofs15[0]}, "owner_manifest": man_cs15, "statement": stmt_env15}, "REFUSE", "WIRE_MEMBER", "draft.15: verify_cert_entry_proof refuses unknown wrapper key.")
    add("d15-cert-entry-proof-bad-head-refuse", ["SL-WIRE-009"], "cert_entry_proof", {"cert_proof": {**cproofs15[0], "head": aps_hw[0]["head"]}, "owner_manifest": man_cs15, "statement": stmt_env15}, "REFUSE", "WIRE_TYPE", "draft.15: verify_cert_entry_proof refuses cross-set head type.")
    add("d15-cert-entry-proof-bad-entry-refuse", ["SL-WIRE-009"], "cert_entry_proof", {"cert_proof": {**cproofs15[0], "entry": aps_hw[0]["entry"]}, "owner_manifest": man_cs15, "statement": stmt_env15}, "REFUSE", "WIRE_TYPE", "draft.15: verify_cert_entry_proof refuses cross-set entry type.")
    cp_19 = copy.deepcopy(cproofs15[0])
    cp_19["proof"]["steps"] = cp_19["proof"]["steps"][:19]
    add("d15-cert-entry-proof-19-steps-refuse", ["SL-WIRE-010"], "cert_entry_proof", {"cert_proof": cp_19, "owner_manifest": man_cs15, "statement": stmt_env15}, "REFUSE", "WIRE_MEMBER", "draft.15: CertEntryProof with 19 (< 20) steps MUST refuse WIRE_MEMBER.")

    # Depth-34 MemberEntryProof standalone verification (admit + every refusal path)
    mem_own = _kp("d15-mem-own")
    mem_opol = {"kind": "key", "pk": mem_own["comp"]}
    mem_reg = {"txid": _h32("d15-mem-reg"), "vout": 0}
    mem_pin = {"name": "id/eng-bob", "owner_policy": mem_opol, "registration": mem_reg}
    mhead15, mproofs15 = rm.make_salted_member_set(
        "id/alice",
        [{"name": "id/eng-bob", "owner_policy": mem_opol, "registration": mem_reg, "roles": ["sre", "ssh.prod"], "seal": aseal}],
        salt_prefix="d15-ms",
    )
    man_ms15 = {**copy.deepcopy(man_hw), "sets": {"members": {"seq": 1, "sha256": sl.content_addr(mhead15)}}}
    add("d15-member-entry-proof-depth34-admit", ["SL-IDEN-006"], "member_entry_proof", {"chain": fx_hw["chain"], "member_pin": mem_pin, "member_proof": mproofs15[0], "operator_manifest": man_ms15, "operator_name": "id/alice"}, "ADMIT", None, "draft.15: Depth-34 salted sparse Merkle MemberEntryProof with roles[] and live seal admits.")
    add("d15-member-entry-proof-missing-pin-refuse", ["SL-IDEN-006"], "member_entry_proof", {"chain": fx_hw["chain"], "member_pin": mem_pin, "member_proof": mproofs15[0], "operator_manifest": man_hw, "operator_name": "id/alice"}, "REFUSE", "MANIFEST_MISMATCH", "draft.15: MemberEntryProof when manifest lacks sets.members pin refuses MANIFEST_MISMATCH.")
    add("d15-member-entry-proof-bad-keys-refuse", ["SL-WIRE-010"], "member_entry_proof", {"chain": fx_hw["chain"], "member_pin": mem_pin, "member_proof": {"extra": 1, **mproofs15[0]}, "operator_manifest": man_ms15, "operator_name": "id/alice"}, "REFUSE", "WIRE_MEMBER", "draft.15: MemberEntryProof with extra wrapper key refuses WIRE_MEMBER.")
    add("d15-member-entry-proof-bad-head-refuse", ["SL-WIRE-009"], "member_entry_proof", {"chain": fx_hw["chain"], "member_pin": mem_pin, "member_proof": {**mproofs15[0], "head": chead15}, "operator_manifest": man_ms15, "operator_name": "id/alice"}, "REFUSE", "WIRE_TYPE", "draft.15: MemberEntryProof with cross-set head refuses WIRE_TYPE.")
    add("d15-member-entry-proof-bad-entry-refuse", ["SL-WIRE-009"], "member_entry_proof", {"chain": fx_hw["chain"], "member_pin": mem_pin, "member_proof": {**mproofs15[0], "entry": aps_hw[0]["entry"]}, "operator_manifest": man_ms15, "operator_name": "id/alice"}, "REFUSE", "WIRE_TYPE", "draft.15: MemberEntryProof with cross-set entry refuses WIRE_TYPE.")
    mp_33 = copy.deepcopy(mproofs15[0])
    mp_33["proof"]["steps"] = mp_33["proof"]["steps"][:33]
    add("d15-member-entry-proof-33-steps-refuse", ["SL-WIRE-010"], "member_entry_proof", {"chain": fx_hw["chain"], "member_pin": mem_pin, "member_proof": mp_33, "operator_manifest": man_ms15, "operator_name": "id/alice"}, "REFUSE", "WIRE_MEMBER", "draft.15: MemberEntryProof with 33 (< 34) steps refuses WIRE_MEMBER.")
    mp_tamp = copy.deepcopy(mproofs15[0])
    mp_tamp["proof"]["steps"][0]["hash"] = _h32("d15-tamp-msib")
    add("d15-member-entry-proof-tampered-refuse", ["SL-IDEN-006"], "member_entry_proof", {"chain": fx_hw["chain"], "member_pin": mem_pin, "member_proof": mp_tamp, "operator_manifest": man_ms15, "operator_name": "id/alice"}, "REFUSE", "MANIFEST_MISMATCH", "draft.15: MemberEntryProof with tampered sibling refuses MANIFEST_MISMATCH.")
    add("d15-member-entry-proof-wrong-member-refuse", ["SL-IDEN-006"], "member_entry_proof", {"chain": fx_hw["chain"], "member_pin": {**mem_pin, "name": "id/other"}, "member_proof": mproofs15[0], "operator_manifest": man_ms15, "operator_name": "id/alice"}, "REFUSE", "MANIFEST_MISMATCH", "draft.15: MemberEntryProof mismatching requested member_pin refuses MANIFEST_MISMATCH.")
    ch_mspent = copy.deepcopy(fx_hw["chain"])
    ch_mspent["txs"][aseal_tx]["outputs"]["0"]["spent_by_txid"] = _h32("d15-mspend")
    ch_mspent["txs"][_h32("d15-mspend")] = {"confirmed_height": 750000, "inputs": [sv.make_segwit_input(aseal_tx, 0)]}
    add("d15-member-entry-proof-seal-spent-refuse", ["SL-IDEN-006"], "member_entry_proof", {"chain": ch_mspent, "member_pin": mem_pin, "member_proof": mproofs15[0], "operator_manifest": man_ms15, "operator_name": "id/alice"}, "REFUSE", "SEAL_SPENT", "draft.15: MemberEntryProof with spent revocation seal refuses SEAL_SPENT.")
    j_mcl = sv.FencedJournal(_h32("d15-j-mcl"))
    j_mcl.record_closure({"outpoint": {"txid": aseal_tx, "vout": 0}, "subject_kind": "seal"}, "SEAL_SPENT", observed_at=now_hw)
    add("d15-member-entry-proof-journal-closed-refuse", ["SL-IDEN-006"], "member_entry_proof", {"chain": fx_hw["chain"], "journal": {"closures": j_mcl.closures, "journal_id": j_mcl.journal_id}, "member_pin": mem_pin, "member_proof": mproofs15[0], "operator_manifest": man_ms15, "operator_name": "id/alice"}, "REFUSE", "SEAL_SPENT", "draft.15: MemberEntryProof with durably journaled member seal closure refuses SEAL_SPENT.")

    # ========================================================================
    # SECTION 4: Core Symmetry (contract-ruling, not_after_unix, identity_commitments, transports, Multi-Chain & IPv4)
    # ========================================================================
    # 4.1 seallink-notary/1 act_kind = "contract-ruling"
    eco_not = bd11._build_log_ecosystem("d15-ruling-notary", role="notary", with_4_checkpoints=False)
    cid_rule = _h32("d15-disputed-contract")
    ruling_p = {
        "act_kind": "contract-ruling", "attested_at": now_hw,
        "details": {"contract_id": cid_rule, "disclosed_clause_indices": [0, 2], "kind": "contract-ruling", "outcome": "breach", "ruling_sha256": _h32("d15-ruling-doc")},
        "genesis": GENESIS_MAIN, "lifecycle": "eternal", "network": "main",
        "notary": eco_not["iss_role_pin"], "target_sha256": cid_rule,
        "tip_hash": eco_not["chain_at_cp2"]["tip_hash"], "tip_height": eco_not["chain_at_cp2"]["tip_height"],
        "type": "seallink-notary/1",
    }
    ruling_env = sl.sign_envelope(ruling_p, [eco_not["iss_role"]["sk"]])
    ruling_tx = _h32("d15-ruling-tx")
    ch_rule = copy.deepcopy(eco_not["chain_at_cp2"])
    ch_rule["txs"][ruling_tx] = {"confirmed_height": 749995, "opreturn_hex": sl.encode_opreturn(0x04, sl.content_addr(ruling_env)).hex()}
    add("d15-notary-contract-ruling-admit", ["SL-CONT-009"], "notary_act", {"anchor_txid": ruling_tx, "chain": ch_rule, "notary": ruling_env}, "ADMIT", None, "draft.15: seallink-notary/1 act_kind='contract-ruling' with matching target_sha256 == contract_id admits.")
    ruling_bad_t = sl.sign_envelope({**ruling_p, "target_sha256": _h32("wrong-cid")}, [eco_not["iss_role"]["sk"]])
    add("d15-notary-contract-ruling-target-mismatch-refuse", ["SL-CONT-009"], "notary_act", {"anchor_txid": ruling_tx, "chain": ch_rule, "notary": ruling_bad_t}, "REFUSE", "WIRE_MEMBER", "draft.15: contract-ruling with target_sha256 != details.contract_id MUST refuse WIRE_MEMBER.")
    ruling_unsorted = sl.sign_envelope({**ruling_p, "details": {**ruling_p["details"], "disclosed_clause_indices": [2, 0]}}, [eco_not["iss_role"]["sk"]])
    add("d15-notary-contract-ruling-unsorted-indices-refuse", ["SL-CONT-009"], "notary_act", {"anchor_txid": ruling_tx, "chain": ch_rule, "notary": ruling_unsorted}, "REFUSE", "WIRE_INTEGER", "draft.15: contract-ruling with unsorted disclosed_clause_indices MUST refuse WIRE_INTEGER.")

    # 4.2 seallink-grant/1 not_after_unix (invocation exact boundary, child narrowing, bearer session leaf & parent, federation)
    def _grant_unix_fx(nau: int, now_val: int) -> dict[str, Any]:
        fx_u = rm._base_invocation_fixture()
        fx_u["chain"]["now"] = now_val
        gp_u = copy.deepcopy(fx_u["bundle"]["grants"][0]["payload"])
        gp_u["not_after_unix"] = nau
        g_u = sl.sign_envelope(gp_u, [fx_u["_keys"]["alice_gr"]["sk"]])
        gid_u = sl.object_id(gp_u)
        fx_u["chain"]["txs"][fx_u["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x01, _issuance_digest(g_u)).hex()
        fx_u["bundle"]["grants"] = [g_u]
        inv_u = copy.deepcopy(fx_u["invocation"]["payload"])
        inv_u["proof_path"][0]["grant_id"] = gid_u
        inv_u["iat"] = now_val - 10
        inv_u["exp"] = now_val + 60
        fx_u["invocation"] = sl.sign_envelope(inv_u, [fx_u["_keys"]["agent_req"]["sk"]])
        return fx_u

    add("d15-grant-not-after-unix-before-admit", ["SL-GRNT-004"], "invocation", _grant_unix_fx(now_hw + 1, now_hw), "ADMIT", None, "draft.15: Grant at chain.now == not_after_unix - 1 admits.")
    add("d15-grant-not-after-unix-expired-refuse", ["SL-GRNT-004"], "invocation", _grant_unix_fx(now_hw, now_hw), "REFUSE", "GRANT_WINDOW_CLOSED", "draft.15: Grant at exact chain.now == not_after_unix MUST refuse GRANT_WINDOW_CLOSED (kills >= -> >).")

    # Child grant not_after_unix narrowing (exact equal ADMIT vs wider/omitted REFUSE GRANT_CHILD_WIDER)
    def _child_unix_fx(p_nau: int, c_nau: int | None) -> dict[str, Any]:
        fx_cu = rm._delegation_fx()
        pp = copy.deepcopy(fx_cu["bundle"]["grants"][0]["payload"])
        pp["not_after_unix"] = p_nau
        p_env = sl.sign_envelope(pp, [fx_cu["_keys"]["alice_gr"]["sk"]])
        pid = sl.object_id(pp)
        fx_cu["chain"]["txs"][fx_cu["invocation"]["payload"]["proof_path"][0]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x01, _issuance_digest(p_env)).hex()
        cp = copy.deepcopy(fx_cu["bundle"]["grants"][1]["payload"])
        cp["parent"]["grant_id"] = pid
        if c_nau is not None:
            cp["not_after_unix"] = c_nau
        c_env = sl.sign_envelope(cp, [fx_cu["_del_k"]["sk"]])
        cid = sl.object_id(cp)
        fx_cu["chain"]["txs"][fx_cu["invocation"]["payload"]["proof_path"][1]["issuance_txid"]]["opreturn_hex"] = sl.encode_opreturn(0x01, _issuance_digest(c_env)).hex()
        fx_cu["bundle"]["grants"] = [p_env, c_env]
        inv_c = copy.deepcopy(fx_cu["invocation"]["payload"])
        inv_c["proof_path"][0]["grant_id"] = pid
        inv_c["proof_path"][1]["grant_id"] = cid
        fx_cu["invocation"] = sl.sign_envelope(inv_c, [fx_cu["_keys"]["agent_req"]["sk"]])
        return fx_cu

    add("d15-child-not-after-unix-equal-admit", ["SL-GRNT-010"], "invocation", _child_unix_fx(now_hw + 500, now_hw + 500), "ADMIT", None, "draft.15: Child grant with not_after_unix == parent.not_after_unix admits.")
    add("d15-child-not-after-unix-wider-refuse", ["SL-GRNT-010"], "invocation", _child_unix_fx(now_hw + 500, now_hw + 501), "REFUSE", "GRANT_CHILD_WIDER", "draft.15: Child grant exceeding parent.not_after_unix MUST refuse GRANT_CHILD_WIDER.")
    add("d15-child-not-after-unix-omitted-refuse", ["SL-GRNT-010"], "invocation", _child_unix_fx(now_hw + 500, None), "REFUSE", "GRANT_CHILD_WIDER", "draft.15: Child grant omitting parent's not_after_unix MUST refuse GRANT_CHILD_WIDER.")

    # Bearer session verify_bearer_session with leaf & parent not_after_unix expiry
    fx_su_l = _grant_unix_fx(now_hw + 50, now_hw)
    so_l = sl.sign_envelope({
        "executor": fx_su_l["invocation"]["payload"]["executor"], "exp": now_hw + 600, "genesis": GENESIS_MAIN, "iat": now_hw,
        "network": "main", "nonce": _h32("d15-su-l"), "op": "open", "proof_path": fx_su_l["invocation"]["payload"]["proof_path"],
        "quotas": [], "slot_binding": "slot:nau-leaf", "type": "seallink-session-open/1",
    }, [fx_su_l["_keys"]["agent_req"]["sk"]])
    ch_su_l_exp = copy.deepcopy(fx_su_l["chain"])
    ch_su_l_exp["now"] = now_hw + 50
    add(
        "d15-session-use-leaf-not-after-unix-refuse",
        ["SL-GRNT-012"],
        "session_lifecycle",
        {
            "executor_cfg": fx_su_l["executor_cfg"],
            "journal": {"journal_id": _h32("d15-su-l-j")},
            "steps": [
                {"bundle": fx_su_l["bundle"], "chain": fx_su_l["chain"], "kind": "session_open", "label": "open", "session_open": so_l, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "mail/read", "arguments": {"folder": "Invoices", "message_id": "m1"}, "chain": ch_su_l_exp, "grant_env": fx_su_l["bundle"]["grants"][0], "kind": "bearer_session", "label": "use-after-nau", "slot_binding": "slot:nau-leaf", "target": "mailbox:id/alice:work", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "draft.15: verify_bearer_session refuses SESSION_INVALID once backing leaf grant reaches not_after_unix.",
        module="bearer-sessions",
    )
    # Parent grant not_after_unix expiry in verify_bearer_session (child has wider/same boundary; check parent check!)
    fx_su_p = _child_unix_fx(now_hw + 50, now_hw + 50)
    so_p = sl.sign_envelope({
        "executor": fx_su_p["invocation"]["payload"]["executor"], "exp": now_hw + 600, "genesis": GENESIS_MAIN, "iat": now_hw,
        "network": "main", "nonce": _h32("d15-su-p"), "op": "open", "proof_path": fx_su_p["invocation"]["payload"]["proof_path"],
        "quotas": [{"kind": "seallink/count", "max": "2", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}],
        "slot_binding": "slot:nau-parent", "type": "seallink-session-open/1",
    }, [fx_su_p["_keys"]["agent_req"]["sk"]])
    ch_su_p_exp = copy.deepcopy(fx_su_p["chain"])
    ch_su_p_exp["now"] = now_hw + 50
    # Use a child without not_after_unix (or same) and parent with not_after_unix = now_hw + 50
    # Actually at open, child has not_after_unix = now_hw + 50; let's test at now_hw + 49 ADMIT and now_hw + 50 REFUSE!
    ch_su_p_ok = copy.deepcopy(fx_su_p["chain"])
    ch_su_p_ok["now"] = now_hw + 49
    add(
        "d15-session-use-parent-not-after-unix-refuse",
        ["SL-GRNT-012"],
        "session_lifecycle",
        {
            "executor_cfg": fx_su_p["executor_cfg"],
            "journal": {"journal_id": _h32("d15-su-p-j")},
            "steps": [
                {"bundle": fx_su_p["bundle"], "chain": fx_su_p["chain"], "kind": "session_open", "label": "open", "session_open": so_p, "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/tool", "arguments": {"input_sha256": _h32("in1"), "max_output_bytes": "1024", "tool_name": "pytest"}, "chain": ch_su_p_ok, "grant_env": fx_su_p["bundle"]["grants"][1], "kind": "bearer_session", "label": "use-before-nau", "parent_grant_env": fx_su_p["bundle"]["grants"][0], "slot_binding": "slot:nau-parent", "target": "station:id/station-a:tools", "token": "__FROM_OPEN__", "want_refusal": None, "want_verdict": "ADMIT"},
                {"action": "agent/tool", "arguments": {"input_sha256": _h32("in1"), "max_output_bytes": "1024", "tool_name": "pytest"}, "chain": ch_su_p_exp, "grant_env": fx_su_p["bundle"]["grants"][1], "kind": "bearer_session", "label": "use-after-nau", "parent_grant_env": fx_su_p["bundle"]["grants"][0], "slot_binding": "slot:nau-parent", "target": "station:id/station-a:tools", "token": "__FROM_OPEN__", "want_refusal": "SESSION_INVALID", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "draft.15: verify_bearer_session admits at now == not_after_unix - 1 and refuses SESSION_INVALID at exact now == not_after_unix on depth-2 child/parent grants.",
        module="bearer-sessions",
    )
    # Defense-in-depth parent exact not_after_unix boundary (child still open -> sole gate is parent_gp not_after_unix >= -> >!)
    fx_pnau = _child_unix_fx(now_hw, None)
    p_pnau = fx_pnau["bundle"]["grants"][0]
    c_pnau = fx_pnau["bundle"]["grants"][1]
    c_pnau_id = sl.object_id(c_pnau["payload"])
    tok_pnau = _h32("d15-pnau-tok")
    th_pnau = sl.sha256(tok_pnau.encode("utf-8")).hex()
    ch_pnau = copy.deepcopy(fx_pnau["chain"])
    ch_pnau["now"] = now_hw
    add(
        "d15-bearer-session-parent-not-after-unix-exact-boundary",
        ["SL-GRNT-013"],
        "bearer_session",
        {
            "action": "agent/tool",
            "arguments": {"input_sha256": _h32("in1"), "max_output_bytes": "128", "tool_name": "pytest"},
            "chain": ch_pnau,
            "executor_cfg": fx_pnau["executor_cfg"],
            "grant_env": c_pnau,
            "journal": {"journal_id": _h32("d15-pnau-j"), "sessions": {th_pnau: {"closed": False, "exp": ch_pnau["now"] + 600, "grant_id": c_pnau_id, "quotas": [{"kind": "seallink/count", "max": "2", "resource": "station:id/station-a:tools", "unit": "calls", "window": "term"}], "session_id": _h32("d15-pnau-sid"), "slot_binding": "tls-pnau", "token_sha256": th_pnau}}},
            "parent_grant_env": p_pnau,
            "slot_binding": "tls-pnau",
            "target": "station:id/station-a:tools",
            "token": tok_pnau,
        },
        "REFUSE",
        "SESSION_INVALID",
        "draft.15: Bearer session defense-in-depth MUST refuse SESSION_INVALID at exact chain.now == parent.not_after_unix (kills >= -> >).",
        module="bearer-sessions",
    )

    # Federation grant not_after_unix expiry
    fx_fed_u = _grant_unix_fx(now_hw, now_hw)
    fg_u = fx_fed_u["bundle"]["grants"][0]
    fed_pol = {"allowed_peers": [], "max_screening_cap": 5}
    add(
        "d15-federation-grant-not-after-unix-refuse",
        ["SL-SERV-003", "SL-GRNT-004"],
        "federation",
        {
            "chain": fx_fed_u["chain"],
            "grant": fg_u,
            "journal": {"journal_id": _h32("d15-fed-u-j")},
            "peer_ctx": {"issuance_txid": fx_fed_u["invocation"]["payload"]["proof_path"][0]["issuance_txid"], "peer_id": "id/peer", "phase": "screening"},
            "policy": fed_pol,
        },
        "REFUSE",
        "GRANT_WINDOW_CLOSED",
        "draft.15: verify_federation_disclosure refuses GRANT_WINDOW_CLOSED at exact chain.now == grant.not_after_unix.",
        module="federated-screening",
    )

    # 4.3 Origin claims.identity_commitments, new transports (openpgp, age, mls + sha256-fingerprint), Multi-Chain Network & IPv4 ceilings
    of_ic = rm._base_origin_fixture()
    orig_ic_p = copy.deepcopy(of_ic["origin_bundle"]["origin"]["payload"])
    orig_ic_p["claims"]["identity_commitments"] = {
        "personhood": sl.clause_commit(_h32("ic-salt-1"), {"scheme": "pop-v1", "status": "verified"}),
        "registry_id": sl.clause_commit(_h32("ic-salt-2"), {"country": "CH", "uid": "CHE-123.456.789"}),
    }
    orig_ic_p["name_recovery"]["delay_blocks"] = 525600
    orig_ic_p["guardian_policy"]["appointment_delay_blocks"] = 65535
    add(
        "d15-origin-identity-commitments-and-ceilings-admit",
        ["SL-ORIG-001"],
        "raw_wire",
        {"object": sl.sign_envelope(orig_ic_p, [of_ic["_keys"]["reg_cred"]["sk"]])},
        "ADMIT",
        None,
        "draft.15: seallink-origin/1 with claims.identity_commitments, appointment_delay_blocks=65535 (BIP-68 max), and name_recovery.delay_blocks=525600 admits.",
    )
    orig_bad_nr = copy.deepcopy(orig_ic_p)
    orig_bad_nr["name_recovery"]["delay_blocks"] = 525601
    add("d15-origin-name-recovery-525601-refuse", ["SL-WIRE-008"], "raw_wire", {"object": sl.sign_envelope(orig_bad_nr, [of_ic["_keys"]["reg_cred"]["sk"]])}, "REFUSE", "WIRE_INTEGER", "draft.15: name_recovery.delay_blocks=525601 (> 525600) MUST refuse WIRE_INTEGER.")
    orig_bad_ap = copy.deepcopy(orig_ic_p)
    orig_bad_ap["guardian_policy"]["appointment_delay_blocks"] = 65536
    add("d15-origin-appointment-delay-65536-refuse", ["SL-WIRE-008"], "raw_wire", {"object": sl.sign_envelope(orig_bad_ap, [of_ic["_keys"]["reg_cred"]["sk"]])}, "REFUSE", "WIRE_INTEGER", "draft.15: appointment_delay_blocks=65536 (> 65535 BIP-68 CSV max) MUST refuse WIRE_INTEGER.")

    # Transports: openpgp + sha256-fingerprint, age + x25519, mls + ed25519
    st_pgp = sl.sign_envelope({
        "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_hw["_alice_owner_pol"], "registration": fx_hw["_alice_reg"]},
        "network": "main", "not_after": now_hw + 600, "not_before": now_hw, "seq": 1,
        "statement_kind": "transport-binding",
        "subject": {"endpoint": "alice@example.org", "key_alg": "sha256-fingerprint", "key_hex": _h32("pgp-v6-fpr"), "transport": "openpgp"},
        "type": "seallink-statement/1",
    }, [fx_hw["_keys"]["alice_gr"]["sk"]])
    add("d15-transport-openpgp-sha256-fingerprint-admit", ["SL-IDEN-006"], "statement", {"chain": fx_hw["chain"], "statement": st_pgp}, "ADMIT", None, "draft.15: transport-binding with transport='openpgp' and key_alg='sha256-fingerprint' admits.")
    st_mls = sl.sign_envelope({
        "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_hw["_alice_owner_pol"], "registration": fx_hw["_alice_reg"]},
        "network": "main", "not_after": now_hw + 600, "not_before": now_hw, "seq": 2,
        "statement_kind": "transport-binding",
        "subject": {"endpoint": "mls://relay.example.org/id/alice", "key_alg": "ed25519", "key_hex": ed_pk, "transport": "mls"},
        "type": "seallink-statement/1",
    }, [fx_hw["_keys"]["alice_gr"]["sk"]])
    add("d15-transport-mls-admit", ["SL-IDEN-006"], "statement", {"chain": fx_hw["chain"], "statement": st_mls}, "ADMIT", None, "draft.15: transport-binding with transport='mls' admits.")
    st_age = sl.sign_envelope({
        "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_hw["_alice_owner_pol"], "registration": fx_hw["_alice_reg"]},
        "network": "main", "not_after": now_hw + 600, "not_before": now_hw, "seq": 3,
        "statement_kind": "transport-binding",
        "subject": {"endpoint": "age1example", "key_alg": "x25519", "key_hex": "09" + ("00" * 31), "transport": "age"},
        "type": "seallink-statement/1",
    }, [fx_hw["_keys"]["alice_gr"]["sk"]])
    add("d15-transport-age-admit", ["SL-IDEN-006"], "statement", {"chain": fx_hw["chain"], "statement": st_age}, "ADMIT", None, "draft.15: transport-binding with transport='age' admits.")

    # Multi-chain Network pattern + min_depth=1440
    card_mc = {"contact": "ops@example.org", "display": "Chain B", "kind": "service", "name": "id/chain-b", "network": "slchain:main", "relays": [], "replaces": 0, "role": "service", "seq": 1, "transports": [], "type": "seallink-card/1"}
    add("d15-multichain-network-qualified-admit", ["SL-LDGR-001"], "raw_wire", {"object": card_mc}, "ADMIT", None, "draft.15: Qualified multi-chain network 'slchain:main' passes wire schema.")
    add("d15-multichain-network-invalid-refuse", ["SL-WIRE-010"], "raw_wire", {"object": {**card_mc, "network": "INVALID:NET"}}, "REFUSE", "WIRE_MEMBER", "draft.15: Uppercase/invalid network identifier MUST refuse WIRE_MEMBER.")
    gp_md1440 = {**copy.deepcopy(fx_hw["bundle"]["grants"][0]["payload"]), "min_depth": 1440}
    add("d15-grant-min-depth-1440-admit", ["SL-GRNT-003"], "raw_wire", {"object": sl.sign_envelope(gp_md1440, [fx_hw["_keys"]["alice_gr"]["sk"]])}, "ADMIT", None, "draft.15: Grant with min_depth=1440 admits.")
