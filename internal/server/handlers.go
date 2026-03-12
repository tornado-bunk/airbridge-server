package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tornado-bunk/airbridge-server/internal/models"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Allowing all origins for simple self-hosted usage.
	// NOTE: In a strictly public production environment, this should be restricted
	// to known origins or domains!
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// ServeWs handles websocket requests from the peer.
func ServeWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Failed to upgrade websocket", "error", err)
		return
	}

	// We don't know the exact Role/PairingID yet until the first message.
	// We create a temporary client just to listen to the first message.

	// Require the first packet within 10 seconds to prevent Phantom Client attacks (DoS)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

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

	session := hub.GetOrCreateSession(baseMsg.PairingID, baseMsg.Secret)

	client := &models.Client{
		ID:        string(baseMsg.Role) + "-" + baseMsg.PairingID, // e.g. "mac-abc"
		Role:      baseMsg.Role,
		PairingID: baseMsg.PairingID,
		Conn:      conn,
		// Buffer set to 2048 to prevent blocking the sender when relaying large binary files
		Send: make(chan []byte, 2048),
	}

	if !session.AttachClient(client, baseMsg.Secret) {
		slog.Warn("Connection rejected: Invalid secret", "role", baseMsg.Role, "pairing_id", baseMsg.PairingID)
		conn.Close()
		return
	}

	// Handle the initial message immediately
	handleMessage(hub, client, session, initialMsgBytes)

	// Start Go routines for reading and writing pumps
	go WritePump(client)
	go ReadPump(client, hub, session, func(c *models.Client, s *models.Session, msg []byte) {
		handleMessage(hub, c, s, msg)
	})
}

// handleMessage routes messages depending on their parsed action
func handleMessage(hub *Hub, client *models.Client, session *models.Session, message []byte) {
	slog.Debug("Received message", "role", client.Role, "len", len(message))

	// Refresh the session timeout so the Heartbeat monitor knows it's active
	session.Lock()
	session.UpdatedAt = time.Now()
	session.Unlock()

	// Try parsing it as JSON to see if it's a control message
	baseMsg, err := models.ParseIncomingMessage(message)
	if err != nil {
		// If it's not JSON, it could be a raw binary relay stream
		handleRelayMessage(session, client, message)
		return
	}

	switch baseMsg.Action {
	case models.ActionRegister:
		var regMsg models.RegisterMessage
		if err := json.Unmarshal(message, &regMsg); err == nil {
			slog.Info("Mac Registered", "pairing_id", session.PairingID, "ip", regMsg.LocalIP, "port", regMsg.Port)
			session.Lock()
			session.MacLocalIP = regMsg.LocalIP
			session.MacPort = regMsg.Port
			session.Unlock()
		}

	case models.ActionQuery:
		session.RLock()
		ip := session.MacLocalIP
		port := session.MacPort
		session.RUnlock()

		if ip != "" && port != 0 {
			resp := models.MacInfoMessage{
				Action:  models.ActionMacInfo,
				LocalIP: ip,
				Port:    port,
			}
			b, _ := json.Marshal(resp)
			select {
			case client.Send <- b:
				slog.Info("Android Queried. Sent Mac Info", "pairing_id", session.PairingID)
			default:
				slog.Warn("Send buffer full, dropping mac_info response", "pairing_id", session.PairingID)
			}
		} else {
			resp := models.ErrorMessage{
				Action:  models.ActionError,
				Message: "Mac not registered yet or IP unknown",
			}
			b, _ := json.Marshal(resp)
			select {
			case client.Send <- b:
			default:
				slog.Warn("Send buffer full, dropping error response", "pairing_id", session.PairingID)
			}
			slog.Warn("Android Queried but Mac unknown", "pairing_id", session.PairingID)
		}

	case models.ActionRequestRelay:
		if session.HasBothClients() {
			resp := models.BaseMessage{
				Action:    models.ActionRelayStarted,
				PairingID: session.PairingID,
			}
			b, _ := json.Marshal(resp)
			// notify both (non-blocking to avoid deadlock under RLock)
			session.RLock()
			mac := session.Mac
			android := session.Android
			session.RUnlock()

			select {
			case mac.Send <- b:
			default:
				slog.Warn("Send buffer full for Mac, dropping relay_started", "pairing_id", session.PairingID)
			}
			select {
			case android.Send <- b:
			default:
				slog.Warn("Send buffer full for Android, dropping relay_started", "pairing_id", session.PairingID)
			}
			slog.Info("Relay Tunnel Established", "pairing_id", session.PairingID)
		} else {
			resp := models.ErrorMessage{
				Action:  models.ActionError,
				Message: "Cannot start relay, missing peer",
			}
			b, _ := json.Marshal(resp)
			select {
			case client.Send <- b:
			default:
				slog.Warn("Send buffer full, dropping relay error", "pairing_id", session.PairingID)
			}
		}

	default:
		// Unknown action, probably an encrypted payload looking like a json text frame
		handleRelayMessage(session, client, message)
	}
}

// handleRelayMessage blindly routes the `message` from the current client to its peer (Android -> Mac, Mac -> Android)
func handleRelayMessage(session *models.Session, sender *models.Client, message []byte) {
	session.RLock()
	var target *models.Client
	if sender.Role == models.RoleAndroid {
		target = session.Mac
	} else if sender.Role == models.RoleMac {
		target = session.Android
	}
	session.RUnlock()

	if target != nil {
		// Recover from panic if Send channel was closed (client replaced mid-flight)
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("Recovered from send on closed channel", "pairing_id", session.PairingID, "sender", sender.Role)
			}
		}()
		select {
		case target.Send <- message:
		default:
			slog.Warn("Send buffer full, dropping relay message", "pairing_id", session.PairingID, "sender", sender.Role)
		}
	}
}
