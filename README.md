# `sockcast-server`

Stateless, zero-database, active-active gRPC Coordinator Server for the **Sockcast** Roaming SSH Agent architecture.

## Key Features
- **`systemd` Multi-Socket Activation (`LISTEN_FDS`):**
  - Ships with `sockcast-server.socket` listening on `/run/sockcast/server.sock` by default — zero TCP ports opened out of the box and zero port collision risk.
  - Also ships with template unit `sockcast-server-tcp@.socket` (`ListenStream=127.0.0.1:%i` with `Service=sockcast-server.service`), allowing any local TCP port to be socket-activated on demand for Cloudflare Tunnel (`cloudflared`) via `systemctl enable --now sockcast-server-tcp@8123.socket`.
  - Loops over all file descriptors passed via `LISTEN_FDS` (`fd = 3 .. 3+N-1`), serving HTTP/2 (`h2c` or TLS) across Unix sockets and TCP sockets simultaneously.
- **Multi-User Partitioned (`internal/hub`):** Partitioned in memory by `user_id` (`sc_u_<hex>`), with per-user public key caching so `GetIdentities` succeeds instantaneously even when all workstations are offline.
- **Fast 1.5s `SignAck` Workstation Failover:**
  1. Orders a user's connected workstations by `force_active == true` first, then by highest `last_input_epoch_ms`.
  2. Pushes `SignRequest` to the primary workstation and starts a **1.5-second `SignAck` timer**.
  3. If `SignAck` is not received within 1.5s (e.g., laptop lid closed before TCP keepalive expiry), automatically fails over to the next active workstation.
  4. Broadcasts `CancelSignRequest` to dismiss stale prompts on other workstations once answered.

## Deployment Modes (`systemd` Socket Activation)

### Mode 1: Nginx Reverse Proxy over Unix Domain Socket (Zero TCP Ports)
```bash
sudo systemctl enable --now sockcast-server.socket
```
Nginx configuration (`/etc/nginx/conf.d/sockcast.conf`):
```nginx
server {
    listen 443 ssl http2;
    server_name sockcast.example.com;

    ssl_certificate     /etc/letsencrypt/live/sockcast.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sockcast.example.com/privkey.pem;

    location /sockcast.v1.SockcastService/ {
        grpc_pass grpc://unix:/run/sockcast/server.sock;
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
        grpc_set_header Host $host;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Mode 2: Cloudflare Tunnel (`cloudflared`) via `@.socket` Template Unit
Activate any unprivileged localhost TCP port via the template socket unit:
```bash
sudo systemctl enable --now sockcast-server-tcp@8123.socket
```
Cloudflare Tunnel configuration (`/etc/cloudflared/config.yml`):
```yaml
ingress:
  - hostname: sockcast.example.com
    service: http://127.0.0.1:8123
    originRequest:
      http2Origin: true
  - service: http_status:404
```

## Building & Fedora RPM Packaging (`tito`)

```bash
# Run tests
go test ./...

# Build Fedora RPM via tito
tito build --test --rpm
```
