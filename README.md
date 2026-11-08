# sockcast-server

Stateless active-active coordinator server for **Sockcast** (Roaming SSH Agent Router).

## Features
- **Nginx & Cloudflare Friendly (`h2c` + TLS):** Listens on cleartext HTTP/2 (`h2c`) behind `grpc_pass` or Cloudflare, or native TLS.
- **Multi-User Partitioned:** Isolates public key caches and workstation streams per cryptographic `user_pubkey` (`user_id`).
- **Zero-Trust Edge Authentication:** Verifies Ed25519 `NodeGrant` and `NodeAuth` signatures plus end-to-end signed `SignRequest` payloads.
- **Fast 1.5s `SignAck` Failover:** Routes `SignRequest` to the most recently active workstation, fails over within 1.5s if no `SignAck` arrives (e.g., laptop lid closed), and waits up to 60s for human approval once acknowledged.
