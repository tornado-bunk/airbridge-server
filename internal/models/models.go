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
// Returns a boolean indicating whether the attachment was successful (secret matches).
// If the role slot is already occupied, the new connection is rejected to prevent session hijacking.
func (s *Session) AttachClient(c *Client, providedSecret string) bool {
	s.Lock()

	// If the session was already created, the incoming client MUST match the initial secret.
	// Use constant-time comparison to prevent timing side-channel attacks.
	if s.Secret != "" && subtle.ConstantTimeCompare([]byte(s.Secret), []byte(providedSecret)) != 1 {
		s.Unlock()
		slog.Warn("Client attempted to join session with invalid secret", "pairing_id", s.PairingID, "role", c.Role)
		return false
	}

	// Reject the connection if the role slot is already occupied (prevents session hijacking).
	if c.Role == RoleMac && s.Mac != nil {
		s.Unlock()
		slog.Warn("Connection rejected: Mac slot already occupied (session hijacking prevention)", "pairing_id", s.PairingID)
		return false
	} else if c.Role == RoleAndroid && s.Android != nil {
		s.Unlock()
		slog.Warn("Connection rejected: Android slot already occupied (session hijacking prevention)", "pairing_id", s.PairingID)
		return false
	}

	if c.Role == RoleMac {
		s.Mac = c
	} else if c.Role == RoleAndroid {
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
