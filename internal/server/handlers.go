package server

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tornado-bunk/airbridge-server/internal/models"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096 * 8, // 32KB for high-throughput binary relays
	WriteBufferSize: 4096 * 8, // 32KB for high-throughput binary relays
	// Only allow connections from native clients (no Origin header) or
	// explicitly allowed origins set via ALLOWED_ORIGINS env var.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Native app clients (Swift/Kotlin) don't send Origin
		}
		// Check against allowed origins from environment variable
		allowed := os.Getenv("ALLOWED_ORIGINS") // comma-separated, e.g. "https://airbridge.tornado.ovh,https://example.com"
		if allowed == "" {
			// If no allowed origins configured, reject all browser-originated requests
			slog.Warn("WebSocket connection rejected: browser Origin present but no ALLOWED_ORIGINS configured", "origin", origin)
			return false
		}
		for _, a := range strings.Split(allowed, ",") {
			if strings.TrimSpace(a) == origin {
				return true
			}
		}
		slog.Warn("WebSocket connection rejected: Origin not in ALLOWED_ORIGINS", "origin", origin)
		return false
	},
}

// realClientIP extracts the true client IP from the request.
// When TRUST_PROXY=true, it reads X-Forwarded-For (set by any standard
// reverse proxy like Nginx, NPM, Traefik, Caddy, etc.).
// Otherwise it uses the direct TCP RemoteAddr.
func realClientIP(r *http.Request) string {
	if strings.EqualFold(os.Getenv("TRUST_PROXY"), "true") {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
	}

	// Direct connection or no proxy header — use TCP peer address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ServeWs handles websocket requests from the peer.
func ServeWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	// Extract real client IP (Cloudflare / reverse-proxy aware)
	clientIP := realClientIP(r)

	// Rate limit: reject excessive connections from the same IP
	if !hub.RateLimiter.AllowConnection(clientIP) {
		slog.Warn("Rate limited connection attempt", "remote_addr", clientIP)
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Failed to upgrade websocket", "error", err)
		return
	}

	// We don't know the exact Role/PairingID yet until the first message.
	// We create a temporary client just to listen to the first message.

	// Require the first packet within 10 seconds to prevent Phantom Client attacks (DoS)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// Prevent an OOM attack where the client sends a multi-gigabyte text frame as the handshake
	conn.SetReadLimit(64 * 1024)

	// Read first message (handshake/registration)
	_, initialMsgBytes, err := conn.ReadMessage()
	if err != nil {
		slog.Error("Failed to read initial handshake message", "error", err)
		conn.Close()
		return
	}

	// Remove the temporary handshake deadline
	conn.SetReadDeadline(time.Time{})

	baseMsg, err := models.ParseIncomingMessage(initialMsgBytes)
	if err != nil || baseMsg.PairingID == "" {
		slog.Error("Invalid initial message format", "error", err)
		conn.Close()
		return
	}

	// Validate that the client declared a known Role
	if baseMsg.Role != models.RoleMac && baseMsg.Role != models.RoleAndroid {
		slog.Warn("Connection rejected: Unknown or missing role", "role", baseMsg.Role)
		conn.Close()
		return
	}

	// Check if this pairing ID is locked out due to too many failed auth attempts
	if !hub.RateLimiter.AllowAuth(baseMsg.PairingID) {
		slog.Warn("Connection rejected: pairing ID locked out", "pairing_id", models.TruncateID(baseMsg.PairingID))
		conn.Close()
		return
	}

	session := hub.GetOrCreateSession(baseMsg.PairingID, baseMsg.Secret)

	client := &models.Client{
		ID:        string(baseMsg.Role) + "-" + baseMsg.PairingID, // e.g. "mac-abc"
		Role:      baseMsg.Role,
		PairingID: baseMsg.PairingID,
		Conn:      conn,
		// Buffer set to 2048 to prevent blocking the sender when relaying large binary files
		Send: make(chan models.Envelope, 2048),
		Done: make(chan struct{}),
	}

	if !session.AttachClient(client, baseMsg.Secret) {
		hub.RateLimiter.RecordAuthFailure(baseMsg.PairingID)
		slog.Warn("Connection rejected: Invalid secret", "role", baseMsg.Role, "pairing_id", models.TruncateID(baseMsg.PairingID))
		conn.Close()
		return
	}

	// Auth succeeded — clear any prior failure tracking for this pairing ID
	hub.RateLimiter.RecordAuthSuccess(baseMsg.PairingID)

	// Handle the initial message immediately (it's always JSON/Text)
	handleMessage(hub, client, session, websocket.TextMessage, initialMsgBytes)

	// Start Go routines for reading and writing pumps
	go WritePump(client)
	go ReadPump(client, hub, session, func(c *models.Client, s *models.Session, msgType int, msg []byte) {
		handleMessage(hub, c, s, msgType, msg)
	})
}

// handleMessage routes messages depending on their parsed action
func handleMessage(hub *Hub, client *models.Client, session *models.Session, messageType int, message []byte) {
	slog.Debug("Received message", "role", client.Role, "len", len(message))

	// If it's a binary payload (e.g., encrypted file relay), route it directly without parsing
	// Fast path: no locks, no JSON parsing
	if messageType == websocket.BinaryMessage {
		handleRelayMessage(session, client, models.Envelope{Type: messageType, Data: message})
		return
	}

	// Refresh the session timeout so the Heartbeat monitor knows it's active
	session.Lock()
	session.UpdatedAt = time.Now()
	session.Unlock()

	// Try parsing it as JSON to see if it's a control message
	baseMsg, err := models.ParseIncomingMessage(message)
	if err != nil || baseMsg.Action == "" {
		// Not a valid control message. If the tunnel is active, route it to the peer.
		if session.HasBothClients() {
			handleRelayMessage(session, client, models.Envelope{Type: messageType, Data: message})
		} else {
			slog.Warn("Failed to parse incoming text message (relay not active, dropping)", "error", err)
		}
		return
	}

	switch baseMsg.Action {
	case models.ActionRegister:
		slog.Info("Client registered", "role", client.Role, "pairing_id", models.TruncateID(session.PairingID))

		// Auto-start relay when both clients are connected
		if session.HasBothClients() {
			resp := models.BaseMessage{
				Action:    models.ActionRelayStarted,
				PairingID: session.PairingID,
			}
			b, _ := json.Marshal(resp)
			env := models.Envelope{Type: websocket.TextMessage, Data: b}

			session.RLock()
			mac := session.Mac
			android := session.Android
			session.RUnlock()

			if mac != nil {
				select {
				case mac.Send <- env:
				default:
					slog.Warn("Send buffer full for Mac, dropping relay_started", "pairing_id", models.TruncateID(session.PairingID))
				}
			}
			if android != nil {
				select {
				case android.Send <- env:
				default:
					slog.Warn("Send buffer full for Android, dropping relay_started", "pairing_id", models.TruncateID(session.PairingID))
				}
			}
			slog.Info("Relay auto-started (both clients connected)", "pairing_id", models.TruncateID(session.PairingID))
		}
	case models.ActionTransportOffer, models.ActionTransportAnswer, models.ActionTransportCheck, models.ActionTransportCheckAck, models.ActionTransportNominate:
		// Relay-assisted LAN negotiation messages are transparently forwarded to the peer.
		if session.HasBothClients() {
			slog.Debug("Relaying transport negotiation message", "action", baseMsg.Action, "pairing_id", models.TruncateID(session.PairingID), "from", client.Role)
			handleRelayMessage(session, client, models.Envelope{Type: messageType, Data: message})
		} else {
			slog.Warn("Dropping transport negotiation message (peer not connected)", "action", baseMsg.Action, "pairing_id", models.TruncateID(session.PairingID))
		}

	default:
		// Any other message (JSON or otherwise) is relayed to the peer
		if session.HasBothClients() {
			handleRelayMessage(session, client, models.Envelope{Type: messageType, Data: message})
		} else {
			slog.Warn("Dropping message (relay not active, peer not connected)", "action", baseMsg.Action, "pairing_id", models.TruncateID(session.PairingID))
		}
	case models.ActionQueryStatus:
		// Health-check style query: report which roles are currently attached.
		session.RLock()
		macActive := session.Mac != nil
		androidActive := session.Android != nil
		session.RUnlock()

		status := models.StatusReplyMessage{
			Action:        models.ActionStatusReply,
			PairingID:     session.PairingID,
			MacActive:     macActive,
			AndroidActive: androidActive,
			BothConnected: macActive && androidActive,
		}

		b, err := json.Marshal(status)
		if err != nil {
			slog.Error("Failed to marshal status_reply", "error", err, "pairing_id", models.TruncateID(session.PairingID))
			return
		}

		env := models.Envelope{Type: websocket.TextMessage, Data: b}
		select {
		case client.Send <- env:
			slog.Info("Status reply sent", "pairing_id", models.TruncateID(session.PairingID), "role", client.Role, "mac_active", macActive, "android_active", androidActive)
		default:
			slog.Warn("Send buffer full when sending status_reply", "pairing_id", models.TruncateID(session.PairingID), "role", client.Role)
		}
	}
}

// handleRelayMessage blindly routes the `message` from the current client to its peer (Android -> Mac, Mac -> Android)
func handleRelayMessage(session *models.Session, sender *models.Client, env models.Envelope) {
	session.RLock()
	var target *models.Client
	if sender.Role == models.RoleAndroid {
		target = session.Mac
	} else if sender.Role == models.RoleMac {
		target = session.Android
	}
	session.RUnlock()

	if target != nil {
		// Raw backpressure. If target reader is slow, target.Send blocks.
		// Sender's ReadPump will block, filling Sender's TCP buffer.
		// This forces the Sender client (Mac/Android) to physically slow down.
		// No ephemeral memory allocations are created here.
		select {
		case target.Send <- env:
		case <-target.Done:
			// Target disconnected. Unblock sender immediately to prevent goroutine deadlock.
			slog.Warn("Target disconnected during relay, dropping packet", "pairing_id", models.TruncateID(session.PairingID))
			return
		}
	}
}
