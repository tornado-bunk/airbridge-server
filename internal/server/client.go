package server

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/gorilla/websocket"
	"github.com/tornado-bunk/airbridge-server/internal/models"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 30 * time.Second

	// Send pings to peer with this period
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer (64MB for now)
	maxMessageSize = 1024 * 1024 * 64
)

// ReadPump pumps messages from the websocket connection to the hub.
func ReadPump(c *models.Client, hub *Hub, session *models.Session, messageHandler func(*models.Client, *models.Session, int, []byte)) {
	defer func() {
		c.CloseDone() // Signal WritePump to exit immediately
		session.DetachClient(c)
		c.Conn.Close()
		slog.Info("ReadPump closed, client detached", "client_role", c.Role, "pairing_id", models.TruncateID(c.PairingID))

		// Notify the remaining peer that this client detached
		session.RLock()
		var peer *models.Client
		if c.Role == models.RoleMac {
			peer = session.Android
		} else if c.Role == models.RoleAndroid {
			peer = session.Mac
		}
		macActive := session.Mac != nil
		androidActive := session.Android != nil
		session.RUnlock()

		if peer != nil {
			status := models.StatusReplyMessage{
				Action:        models.ActionStatusReply,
				PairingID:     session.PairingID,
				MacActive:     macActive,
				AndroidActive: androidActive,
				BothConnected: macActive && androidActive,
			}
			b, _ := json.Marshal(status)
			env := models.Envelope{Type: websocket.TextMessage, Data: b}
			select {
			case peer.Send <- env:
				slog.Info("Sent status_reply notification to peer", "role", peer.Role, "pairing_id", models.TruncateID(session.PairingID))
			default:
				slog.Warn("Send buffer full when notifying peer of disconnect", "role", peer.Role, "pairing_id", models.TruncateID(session.PairingID))
			}
		}
	}()

	c.Conn.SetReadLimit(maxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(pongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		messageType, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Error("Unexpected websocket close error", "error", err)
			}
			break
		}

		// Delegate message handling to the router
		messageHandler(c, session, messageType, message)
	}
}

// WritePump pumps messages from the hub to the websocket connection.
func WritePump(c *models.Client) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
		slog.Info("WritePump closed", "client_role", c.Role, "pairing_id", models.TruncateID(c.PairingID))
	}()

	for {
		select {
		case <-c.Done:
			return // Expected exit triggered by ReadPump closing
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				slog.Debug("Send channel closed by hub", "client_role", c.Role)
				return
			}

			w, err := c.Conn.NextWriter(message.Type)
			if err != nil {
				return
			}
			w.Write(message.Data)

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
