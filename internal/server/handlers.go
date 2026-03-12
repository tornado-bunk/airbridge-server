package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/tornado-bunk/airbridge-server/internal/models"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Allowing all origins for simple self-hosted usage
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

	// Read first message (handshake/registration)
	_, initialMsgBytes, err := conn.ReadMessage()
	if err != nil {
		slog.Error("Failed to read initial handshake message", "error", err)
		conn.Close()
		return
	}

	baseMsg, err := models.ParseIncomingMessage(initialMsgBytes)
	if err != nil || baseMsg.PairingID == "" {
		slog.Error("Invalid initial message format", "error", err)
		conn.Close()
		return
	}

	session := hub.GetOrCreateSession(baseMsg.PairingID)

	client := &models.Client{
		ID:        string(baseMsg.Role) + "-" + baseMsg.PairingID, // e.g. "mac-abc"
		Role:      baseMsg.Role,
		PairingID: baseMsg.PairingID,
		Conn:      conn,
		Send:      make(chan []byte, 256),
	}

	session.AttachClient(client)

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
			client.Send <- b
			slog.Info("Android Queried. Sent Mac Info", "pairing_id", session.PairingID)
		} else {
			resp := models.ErrorMessage{
				Action:  models.ActionError,
				Message: "Mac not registered yet or IP unknown",
			}
			b, _ := json.Marshal(resp)
			client.Send <- b
			slog.Warn("Android Queried but Mac unknown", "pairing_id", session.PairingID)
		}

	case models.ActionRequestRelay:
		if session.HasBothClients() {
			resp := models.BaseMessage{
				Action:    models.ActionRelayStarted,
				PairingID: session.PairingID,
			}
			b, _ := json.Marshal(resp)
			// notify both
			session.RLock()
			session.Mac.Send <- b
			session.Android.Send <- b
			session.RUnlock()
			slog.Info("Relay Tunnel Established", "pairing_id", session.PairingID)
		} else {
			resp := models.ErrorMessage{
				Action:  models.ActionError,
				Message: "Cannot start relay, missing peer",
			}
			b, _ := json.Marshal(resp)
			client.Send <- b
		}

	default:
		// Unknown action, probably an encrypted payload looking like a json text frame
		handleRelayMessage(session, client, message)
	}
}

// handleRelayMessage blindly routes the `message` from the current client to its peer (Android -> Mac, Mac -> Android)
func handleRelayMessage(session *models.Session, sender *models.Client, message []byte) {
	session.RLock()
	defer session.RUnlock()

	if sender.Role == models.RoleAndroid && session.Mac != nil {
		session.Mac.Send <- message
	} else if sender.Role == models.RoleMac && session.Android != nil {
		session.Android.Send <- message
	}
}
