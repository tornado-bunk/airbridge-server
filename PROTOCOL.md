# AirBridge Relay Protocol

Complete documentation of authentication, message flow, and encryption between the Mac client, Android client, and the AirBridge relay server.


## Architecture Overview

```
┌──────────┐          ┌──────────────────┐          ┌──────────────┐
│  Mac App │◄── WSS ──►  AirBridge Relay  ◄── WSS ──►  Android App │
│ (Swift)  │          │   Server (Go)    │          │  (Kotlin)    │
└──────────┘          └──────────────────┘          └──────────────┘
```

The server is a **dumb pipe**: it authenticates clients and forwards messages verbatim. It never inspects, decrypts, or modifies payload data.


## 1. Shared Secrets (Setup via QR Code)

During initial pairing, the Mac generates two independent secrets:

| Secret | Purpose | Who knows it |
|---|---|---|
| `secret_raw` | Auth credential (passphrase) | Mac, Android — **never leaves the devices** |
| `K` = SHA256(`secret_raw`) | HMAC auth key | Mac, Android, **Server** (received via `kInit` at bootstrap, stored in RAM) |
| `symmetricKey` | AES-GCM E2E encryption of all data messages | Mac, Android — **never sent to server** |

### QR Code Pairing Format
The Mac encodes the bootstrap config into a URI for Android to scan:
`airbridge://<relay_server_url_encoded>/<pairingId>/<secret_raw>`

`secret_raw` never leaves the client devices — its hash `K` is sent as `kInit` in registration messages. `K` is an authentication credential: anyone who obtains it can generate valid registration signatures. `symmetricKey` is completely independent and is never sent to the server. Even if the server is compromised and `K` is leaked, an attacker **cannot** decrypt any relayed data because that requires `symmetricKey`.

## 2. Authentication: HMAC Challenge-Response

A 2-step handshake that prevents replay attacks. Happens every time a client connects (or reconnects).

### Flow

```
Client                          Server
  │                                 │
  │───── WebSocket connect ───────► │
  │                                 │
  │◄──── challenge ─────────────────│  Server generates a random 32-byte nonce
  │     { action: "challenge",      │  (sent as exactly 64 hex characters)
  │       nonce: "<64 hex chars>"}  │
  │                                 │
  │───── register ────────────────► │  Client computes HMAC and sends:
  │     { action: "register",       │
  │       role: "mac"|"android",    │
  │       pairingId: "...",         │
  │       sig: "<HMAC hex>",        │    sig = HMAC-SHA256(K, nonce|pairingId|role)
  │       kInit: "<K hex>",         │    kInit = hex(K), sent for bootstrap
  │       localIp: "...",           │
  │       port: 8375 }              │    (Mac sends its LAN port, Android sends 0)
  │                                 │
  │  Server verifies sig using      │
  │  stored K (constant-time).      │
  │  If valid → client registered   │
  │  If invalid → connection closed │
```

### Key Derivation

```
K = SHA256(secret_raw)          // 32 bytes, used as HMAC key
sig = HMAC-SHA256(K, "nonce|pairingId|role")
kInit = hex(K)                  // sent to server for bootstrap
```

### Bootstrap (Server Restart)

After a server restart, `K` is lost (it's only in RAM). The first client to connect provides `kInit` in the register message. The server stores it and uses it to verify subsequent connections.

| Scenario | What happens |
|---|---|
| **New session** (no K stored) | Server stores `kInit` from first client, verifies sig against it |
| **Existing session** (K in RAM) | Server ignores `kInit`, verifies sig against stored K |
| **Wrong secret** | sig won't match → connection closed |
| **Replay (old sig reused)** | nonce is different each time → sig won't match |


## 3. Relay Activation

Once **both** Mac and Android are registered on the same `pairingId`:

```
Server ──► Mac:     { action: "relay_started" }
Server ──► Android: { action: "relay_started" }
```

From this point, any message sent by Mac is forwarded to Android and vice versa. The server does not inspect or modify the content.

If a client reconnects and the other is still connected, the server sends `relay_started` immediately after registration.


## 4. Message Routing & Fast Paths

### The Binary Fast Path
If the Mac or Android sends a WebSocket frame of type `BinaryMessage`, the Relay Server immediately routes it to the peer without acquiring read/write locks or parsing JSON. The server acts as a true raw pipe with a 2048-message buffer threshold to prevent blocking.

### Text Routing (JSON)
For `TextMessage`, the server parses the message briefly just to check the `action` field. If it's a known Server Control Action (`challenge`, `register`, `query_status`), the server consumes it. If the `action` is unknown or missing, the server assumes it is an E2E payload and blindly forwards it to the peer.

## 5. LAN Fallback (Transport Negotiation)

Even when connected to AirBridge, clients continuously probe for a direct local (LAN) connection. They achieve this by tunneling ICE-like negotiation messages through the relay to each other:
- `transport_offer`
- `transport_answer`
- `transport_check` / `transport_check_ack`
- `transport_nominate`

**Negotiation Rate Limiting**: Since negotiation can be chatty, the Go server strictly limits these specific 5 actions to a maximum of **20 messages per second** per client to prevent queue flooding.

## 6. Message Encryption (E2E)
All data messages are encrypted by the sender and decrypted by the receiver using `symmetricKey` (AES-256-GCM). The server only sees ciphertext.

```
Sender:   plaintext → AES-GCM-Encrypt(symmetricKey, plaintext) → ciphertext
Server:   ciphertext → forward as-is → ciphertext
Receiver: ciphertext → AES-GCM-Decrypt(symmetricKey, plaintext) → plaintext
```

### AB1 authenticated application framing (updated clients)

Both clients must be updated together. The server protocol and binary are unchanged.
Legacy application ciphertext without an AB1 frame is rejected; there is no downgrade.
BLE framing is unchanged. Updated LAN clients also require the trusted-network
verification described below.

After each `relay_started`, each client generates a fresh random 128-bit UUID challenge
(122 random bits), resets its sequence counters, and sends its encrypted hello:

```text
AB1|hello|<sender role>|<32 lowercase hex challenge>
```

On receiving an authenticated hello with a changed peer challenge, reply with the
local hello. A duplicate hello never resets counters. The sender frames each payload
before encrypting the entire frame with the independent AES-GCM key:

```text
AB1|data|<sender role>|<sender challenge>|<receiver challenge>|<positive sequence>|<application JSON>
```

Split data frames at the first six `|` separators only. Receivers require the opposite
role, the current peer challenge, their own current challenge, and a sequence strictly
greater than the last accepted sequence. The challenge rejects messages recorded in
prior sessions; the counter rejects duplicates and previously delivered out-of-order
messages in this session. All fields, including the role and challenges, are covered by
the AES-GCM authentication tag. Relay control messages remain unauthenticated by the
E2E layer and can interrupt availability; they cannot bypass application framing.

### Trusted-network LAN handoff

Updated clients maintain an encrypted, pairing-key-scoped catalog of authorized
networks. A new local pairing registers its current network automatically.
Additional networks require an explicit enrollment with both devices on the LAN.
The Mac and Android can manage names and removals and synchronize them through
AirBridge. Enrolling an already known network updates its name without duplicating it.

Before promoting a local socket, Android sends an encrypted `trustedNetworks`
proof with a fresh nonce. The Mac checks its local gateway identity, subnet,
the claimed phone address against the actual socket peer, and the catalog or
pending enrollment request. A proof arriving through the relay cannot authorize LAN.
Ethernet and Wi-Fi can share a Mac gateway identity; Android also binds recognition
to Wi-Fi name and security family so guest networks remain distinct. Unknown or
ambiguous observations use AirBridge. This is conservative network recognition,
not cryptographic attestation of router hardware. The relay server needs no change.

### What gets encrypted

All application messages: `ping`, `pong`, `status`, `macInfo`, `device`, `remoteControl`, `clipboardUpdate`, `notification`, `mediaControl`, `fileTransfer*`, `peerTransport`, etc.

### What does NOT get encrypted

Server control messages (these are generated by the Go relay server itself, which does not possess the `symmetricKey`):
- `challenge` / `register` (auth handshake)
- `relay_started`
- `query_status` / `status_reply`
- `error`
- `mac_info` (legacy hint; updated Android clients ignore it and use authenticated application transport offers)

**`macInfo` vs `mac_info`**

- `macInfo` is an **Application Message** generated by the Mac app containing device details (OS version, name, etc.). It is E2E encrypted before reaching the server.
- `mac_info` is a **Server Control Message** generated by the Go relay server, telling Android what IP/port the Mac is using on the local network. Since the server generates it, it is plaintext.

## 5. Status Polling

Android polls the server every 5 seconds for session health:

```
Android ──► Server:  { action: "query_status" }
Server  ──► Android: { action: "status_reply",
                       macActive: true,
                       androidActive: true,
                       bothConnected: true }
```

Used by the Android UI to show whether the Mac peer is online.

## 8. Connection Drops & Replacement

If an Android or Mac client connects and successfully authenticates with HMAC, but the server already has an active connection for that role (e.g., an old connection from before the device went to sleep), the server instantly terminates the old connection and replaces it with the new one. This ensures seamless handoffs when switching from 4G to Wi-Fi.

## 9. Reconnection

Both clients implement automatic reconnection with exponential backoff:

| Attempt | Delay |
|---|---|
| 1 | 1s |
| 2 | 2s |
| 3 | 4s |
| 4 | 8s |
| 5+ | capped at 30s |

On reconnect, the full challenge-response handshake repeats. If the server was restarted, the first reconnecting client re-bootstraps `K`.

## 10. Server Defenses (DoS & Abuse)

The AirBridge server implements several layers of connection defense:
- **Phantom Handshake Timeout**: A client has exactly 10 seconds to respond to the `challenge` with a valid `register` message, otherwise they are disconnected.
- **Handshake Payload Limit**: The `register` message cannot exceed 64KB, preventing RAM exhaustion attacks during auth.
- **Connection Rate Limiting**: Maximum 100 new connections per Minute per IP.
- **Brute-Force Lockout**: 20 failed HMAC attempts will instantly lock out the `pairingId` for 2 minutes.
- **Dead Session Cleanup**: An internal Heartbeat Monitor sweeps RAM periodically, instantly destroying any session that has been empty (0 clients attached) for too long.

## 11. Connection State Machine

```
              ┌──────────────┐
              │ DISCONNECTED │
              └──────┬───────┘
                     │ connect()
              ┌──────▼───────┐
              │  CONNECTING  │
              └──────┬───────┘
                     │ onOpen + challenge received
         ┌───────────▼────────────┐
         │  CHALLENGE_RECEIVED    │
         └───────────┬────────────┘
                     │ HMAC computed, register sent
              ┌──────▼───────┐
              │  REGISTERING │
              └──────┬───────┘
                     │ server accepts (no error)
          ┌──────────▼──────────┐
          │  WAITING_FOR_PEER   │
          └──────────┬──────────┘
                     │ relay_started (both peers connected)
              ┌──────▼───────┐
              │ RELAY_ACTIVE │
              └──────┬───────┘
                     │ socket error / close
              ┌──────▼───────┐
              │    FAILED    │──── backoff ────► CONNECTING
              └──────────────┘
```

## 12. File Reference

| Component | File | Role |
|---|---|---|
| **Server** | `internal/models/messages.go` | Message structs (`ChallengeMessage`, `RegisterMessage`) |
| **Server** | `internal/models/models.go` | `Session` struct, `VerifyHMAC()`, `SetKey()` |
| **Server** | `internal/server/handlers.go` | `ServeWs` — handshake + message routing |
| **Server** | `internal/server/hub.go` | Session registry (`GetOrCreateSession`) |
| **Mac** | `Core/AirBridge/AirBridgeModels.swift` | Swift message types |
| **Mac** | `Core/AirBridge/AirBridgeClient.swift` | `computeHMAC()`, connection lifecycle |
| **Android** | `utils/AirBridgeClient.kt` | `computeHmac()`, connection lifecycle |
