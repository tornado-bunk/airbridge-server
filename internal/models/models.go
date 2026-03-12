package models

import (
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

// AttachClient safely attaches a client to the appropriate role in the session
// Returns a boolean indicating whether the attachment was successful (secret matches).
func (s *Session) AttachClient(c *Client, providedSecret string) bool {
	s.Lock()

	// If the session was already created, the incoming client MUST match the initial secret
	if s.Secret != "" && s.Secret != providedSecret {
		s.Unlock()
		slog.Warn("Client attempted to join session with invalid secret", "pairing_id", s.PairingID, "role", c.Role)
		return false
	}

	var oldClient *Client
	if c.Role == RoleMac {
		if s.Mac != nil {
			oldClient = s.Mac
		}
		s.Mac = c
	} else if c.Role == RoleAndroid {
		if s.Android != nil {
			oldClient = s.Android
		}
		s.Android = c
	}
	s.UpdatedAt = time.Now()
	s.Unlock()

	// Perform I/O outside of the lock
	if oldClient != nil {
		slog.Info("Replacing existing client in session", "pairing_id", s.PairingID, "role", oldClient.Role)
		oldClient.Conn.Close()
	}
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
