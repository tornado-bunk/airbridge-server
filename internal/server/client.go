package server

import (
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

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer. (e.g., 64MB for large file relays)
	maxMessageSize = 1024 * 1024 * 64
)

// ReadPump pumps messages from the websocket connection to the hub.
func ReadPump(c *models.Client, hub *Hub, session *models.Session, messageHandler func(*models.Client, *models.Session, int, []byte)) {
	defer func() {
		session.DetachClient(c)
		c.Conn.Close()
		slog.Info("ReadPump closed, client detached", "client_role", c.Role, "pairing_id", c.PairingID)
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
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
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
		slog.Info("WritePump closed", "client_role", c.Role, "pairing_id", c.PairingID)
	}()

	for {
		select {
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
