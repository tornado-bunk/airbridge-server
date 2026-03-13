# Sync Relay Server

A standalone Signaling and E2EE Relay server built in Go for the AirSync project.

## Purpose

1. **Signaling (Discovery):** Allows Mac and Android devices on the same local network to discover each other's IP addresses and Ports, bypassing mDNS/Bonjour sleep issues typically encountered on macOS.
2. **Relay (Tunnel):** Acts as a high-performance "dumb pipe" to relay End-to-End Encrypted (E2EE) traffic between devices if a direct local connection cannot be established or drops. The server cannot read the AES-encrypted data.

## Server Architecture
- Written in **Go (Golang)** for high concurrency.
- Uses **Gorilla WebSockets** for persistent full-duplex communication.
- Maintains in-memory sessions using thread-safe maps (`sync.RWMutex`).
- Features **Heartbeat Monitoring** to automatically prune dead connections.

## Security & Deployment

This server is designed to be easily self-hostable. 

### TLS / WSS
**IMPORTANT:** The application exchanges sensitive clipboard, text, and file data. While the application payloads are End-to-End Encrypted using AES, the WebSocket protocol metadata (roles, actions) is not. **You must run this server over WSS (Secure WebSocket) in production.**

### Recommended Setup: Reverse Proxy (Nginx Proxy Manager / Caddy)
We strongly recommend **not** embedding SSL certificates directly into the Go application. Instead, run the Go server locally (e.g., `localhost:8080`) and expose it to the internet using a Reverse Proxy like **Nginx, Nginx Proxy Manager (NPM), or Caddy**.

The proxy will handle:
- TLS Termination (Auto-renewing Let's Encrypt Certificates).
- HTTP/2 Upgrade headers required for WSS.
- Rate Limiting and DDoS protection.

#### Example Nginx Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name relay.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /ws {
        proxy_pass http://127.0.0.1:8080;
        
        # Required to upgrade the connection to WebSocket
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;

        # Optional: Increase timeouts for long-lived Relay Tunnels
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

## Running the Server Locally
To start the server on `localhost:8080`:

```bash
go run ./cmd/server
```

## Run with Docker

### Build image
```bash
docker build -t airbridge-server .
```

### Run container
```bash
docker run --rm -p 8080:8080 -e PORT=8080 --name airbridge-server airbridge-server
```

### Run with Docker Compose
```bash
docker compose up --build -d
```

### Quick health checks
```bash
curl http://localhost:8080/
```

Expected response:
```text
Sync Relay Server is running
```

WebSocket endpoint (behind reverse proxy/Cloudflare): `/ws`

### Running Tests
Unit tests model the Mac and Android behavior locally without opening TCP ports. To run the Go unit tests:

```bash
go test -v ./tests
```

A Python mock script is also provided for visual, E2E WebSocket payload tracing:
```bash
python3 tests/simulate_clients.py
```
