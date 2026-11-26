# Security Policy

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Instead, report vulnerabilities privately using either of the following channels:

- **GitHub Security Advisories:** Submit a confidential report at [https://github.com/sshcast/sshcast-server/security/advisories/new](https://github.com/sshcast/sshcast-server/security/advisories/new).
- **Email:** Send details to **security@sshcast.net**.

When reporting a vulnerability, please include:

- Affected repository/component (`sshcast-server`), version or commit hash, and deployment configuration (for example, standalone TLS vs. `h2c` behind Nginx or Cloudflare Tunnel).
- Steps to reproduce, proof-of-concept details, or relevant logs.
- An assessment of potential impact (for example, denial of service, authorization bypass, or routing manipulation).

We aim to acknowledge reports promptly and coordinate remediation and disclosure before publishing advisories.

---

## Stateless Zero-Trust Coordinator Security Model

`sshcast-server` is designed as a **stateless, zero-trust routing coordinator**. Even a fully compromised coordinator (or an intermediate TLS-terminating reverse proxy such as Nginx or Cloudflare) cannot access SSH private keys or forge valid signing requests.

### 1. Why the Coordinator Cannot Decrypt or Access SSH Keys

- **Private Keys Never Leave the Workstation:** SSH private keys and hardware token credentials remain strictly on user workstations (`sshcast-client`, local `ssh-agent`, or FIDO2/TouchID authenticators). `sshcast-server` has no access to SSH private keys or passphrases and performs no decryption or signing operations on SSH key material.
- **Public Metadata Only:** In memory (`internal/hub.Registry`), `sshcast-server` stores only ephemeral routing state partitioned by derived `user_id` (`sc_u_<hex>`), active gRPC/WebSocket streams, and cached `PublicKey` entries (`key_blob`, `comment`, `fingerprint_sha256`, `key_type`) so `GetIdentities` can answer when workstations are temporarily asleep.
- **Zero-Database Footprint:** `sshcast-server` persists no database, user key material, or signing history on disk.
- **Default-Deny Authorization:** Unless `allow_any_user = true` is explicitly configured for isolated testing, callers are rejected unless their `NodeGrant` `user_pubkey` matches `allowed_user_pubkeys` or carries a valid `UserCert` signed by a key in `trusted_operator_pubkeys`.

### 2. Why the Coordinator Cannot Forge `SignRequest`s

Sshcast enforces **application-layer Ed25519 cryptography** end-to-end between the user's nodes, independent of transport TLS termination:

1. **User-Signed Node Delegation (`NodeGrant`):**
   - Each user holds an offline/local Ed25519 root keypair (`user_privkey`, `user_pubkey`).
   - Each enrolled relay (`NODE_ROLE_RELAY`) and workstation (`NODE_ROLE_CLIENT`) holds its own Ed25519 node keypair and a `NodeGrant` signed by `user_privkey` (domain-separated with `sshcast-node-grant-v1\x00`), binding `user_id`, `user_pubkey`, `node_id`, `role`, `node_pubkey`, and validity timestamps.
   - `sshcast-server` only ever receives public keys and signed grants/certificates (`NodeAuth`, domain-separated with `sshcast-rpc-auth-v1\x00`, timestamp-checked within `max_clock_skew_ms`); it never holds `user_privkey` or any node's `node_privkey`.

2. **End-to-End Relay Signatures on `SignRequest`:**
   - Before sending a `SignRequest`, the originating `sshcast-relay` signs the canonical request payload (domain-separated with `sshcast-sign-request-v1\x00`) using its own `node_privkey`.
   - The `relay_signature` covers `request_id`, `timestamp_unix_ms`, `key_blob`, challenge `data`, `flags`, full `process_context` (`hostname`, `uid`, `pid`, `comm`, `cmdline`, `cwd`, `ancestors`), `ssh_auth_context`, and `relay_grant.user_signature`.
   - Both `sshcast-server` (via `auth.VerifySignRequest` in `internal/server/grpc.go`) and the receiving `sshcast-client` independently verify:
     1. That `relay_grant` has a valid `user_signature` under the expected `user_pubkey` (and is within its validity window and `NODE_ROLE_RELAY`).
     2. That `process_context.hostname` matches `relay_grant.node_id`.
     3. That `relay_signature` verifies against `relay_grant.node_pubkey`.
   - Because the coordinator lacks `user_privkey` and every relay's `node_privkey`, it cannot mint an accepted `NodeGrant`, forge a `SignRequest`, tamper with the SSH challenge `data`, or spoof caller `process_context`.

### 3. Host Hardening

- Under `systemd`, `sshcast-server.service` runs with `DynamicUser=yes`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, and read-only configuration (`ConfigurationDirectory=sshcast::ro`).
- By default, `sshcast-server.socket` binds only a local Unix domain socket (`/run/sshcast-server/server.sock`) with zero listening TCP ports.

---

## Release Integrity & Provenance Verification

Before deploying release binaries, tarballs, or RPM packages, verify both their SHA-256 checksums and their GitHub build provenance attestations.

### 1. SHA-256 Checksum Verification

Download the release artifact alongside the published `SHA256SUMS` file from [GitHub Releases](https://github.com/sshcast/sshcast-server/releases) and verify the digest:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

### 2. GitHub Artifact Attestation / Build Provenance Verification

Official release artifacts built on GitHub Actions include signed SLSA build provenance attestations. Verify them with the [GitHub CLI](https://cli.github.com/):

```bash
gh attestation verify <artifact-file> --repo sshcast/sshcast-server
```

To verify against the organization policy as a whole:

```bash
gh attestation verify <artifact-file> --owner sshcast
```

### 3. Verifying Source Builds

When building from source or packaging RPMs (`sshcast-server.spec`), build with read-only module verification and stripped local paths:

```bash
go test -mod=readonly ./...
go build -mod=readonly -trimpath -ldflags="-s -w" -o sshcast-server ./cmd/sshcast-server
```
