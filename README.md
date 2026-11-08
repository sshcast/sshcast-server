# `sockcast-server`

Stateless, zero-database, active-active gRPC Coordinator Server for the **Sockcast** Roaming SSH Agent architecture.

## Key Features
- **HTTP/2 Cleartext (`h2c`) & Native TLS:** Listens on `h2c` when deployed behind Nginx (`grpc_pass`) or Cloudflare tunnels over port 443, or native TLS when exposed directly.
- **Multi-User Partitioned (`internal/hub`):** Partitioned in memory by `user_id` (`sc_u_<hex>`), with per-user public key caching so `GetIdentities` succeeds instantaneously even when all workstations are offline.
- **Fast 1.5s `SignAck` Workstation Failover:**
  1. Orders a user's connected workstations by `force_active == true` first, then by highest `last_input_epoch_ms`.
  2. Pushes `SignRequest` to the primary workstation and starts a **1.5-second `SignAck` timer**.
  3. If `SignAck` is not received within 1.5s (e.g., laptop lid closed before TCP keepalive expiry), automatically fails over to the next active workstation.
  4. Broadcasts `CancelSignRequest` to dismiss stale prompts on other workstations once answered.

## Nginx `grpc_pass` Reverse Proxy Example

```nginx
server {
    listen 443 ssl http2;
    server_name sockcast.example.com;

    ssl_certificate     /etc/letsencrypt/live/sockcast.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sockcast.example.com/privkey.pem;

    location /sockcast.v1.SockcastService/ {
        grpc_pass grpc://127.0.0.1:8080;
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
         grpc_set_header Host $host;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## Building & Fedora RPM Packaging (`tito`)

```bash
# Run tests
go test -mod=vendor ./...

# Build Fedora RPM via tito
tito build --test --rpm
```
