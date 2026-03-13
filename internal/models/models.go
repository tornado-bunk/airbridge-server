package models

import (
	"crypto/subtle"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Role defines whether a client is a Mac or an Android device
type Role string

const (
	RoleMac     Role = "mac"
	RoleAndroid Role = "android"
)

// Envelope carries both the payload and the websocket message type
type Envelope struct {
	Type int
	Data []byte
}

// Client represents a single connected WebSocket device
type Client struct {
	ID        string
	Role      Role
	Conn      *websocket.Conn
	PairingID string
	Send      chan Envelope // Buffered channel for outbound messages
	Done      chan struct{} // Channel to signal WritePump to exit
	CloseOnce sync.Once     // Ensures Done is closed at most once (prevents panic)
}

// CloseDone safely closes the Done channel exactly once.
func (c *Client) CloseDone() {
	c.CloseOnce.Do(func() {
		close(c.Done)
	})
}

// Session represents an active pairing between a Mac and an Android device
type Session struct {
	PairingID string
	Secret    string // The authentication secret establishing this session

	Mac     *Client
	Android *Client

	// IP and Port reported by the Mac
	MacLocalIP string
	MacPort    int

	CreatedAt time.Time
	UpdatedAt time.Time

	// Mutex to protect concurrent access to session data
	sync.RWMutex
}

// NewSession creates and returns a new session
func NewSession(pairingID string, secret string) *Session {
	return &Session{
		PairingID: pairingID,
		Secret:    secret,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// AttachClient safely attaches a client to the appropriate role in the session.
// Returns false if the provided secret doesn't match (auth failure).
// If the role slot is already occupied by a stale connection, the old one is
// replaced (the new client has already proven it knows the secret).
func (s *Session) AttachClient(c *Client, providedSecret string) bool {
	s.Lock()

	// If the session was already created, the incoming client MUST match the initial secret.
	// Use constant-time comparison to prevent timing side-channel attacks.
	if s.Secret != "" && subtle.ConstantTimeCompare([]byte(s.Secret), []byte(providedSecret)) != 1 {
		s.Unlock()
		slog.Warn("Client attempted to join session with invalid secret", "pairing_id", s.PairingID, "role", c.Role)
		return false
	}

	// If the role slot is already occupied, replace the old (stale) connection.
	// The new client has already proven it knows the secret, so this is a legitimate
	// reconnection (e.g., after a network blip), not a hijack attempt.
	// We close the old connection gracefully to free resources.
	if c.Role == RoleMac {
		if old := s.Mac; old != nil && old != c {
			slog.Info("Replacing stale Mac connection with new one", "pairing_id", s.PairingID)
			old.CloseDone()
			old.Conn.Close()
		}
		s.Mac = c
	} else if c.Role == RoleAndroid {
		if old := s.Android; old != nil && old != c {
			slog.Info("Replacing stale Android connection with new one", "pairing_id", s.PairingID)
			old.CloseDone()
			old.Conn.Close()
		}
		s.Android = c
	}
	s.UpdatedAt = time.Now()
	s.Unlock()

	return true
}

// DetachClient safely removes a client from the session if it matches the current one
func (s *Session) DetachClient(c *Client) {
	s.Lock()
	defer s.Unlock()

	if c.Role == RoleMac && s.Mac == c {
		s.Mac = nil
	} else if c.Role == RoleAndroid && s.Android == c {
		s.Android = nil
	}
	s.UpdatedAt = time.Now()
}

// HasBothClients returns true if both Mac and Android are currently connected
func (s *Session) HasBothClients() bool {
	s.RLock()
	defer s.RUnlock()
	return s.Mac != nil && s.Android != nil
}
