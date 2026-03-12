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

// Client represents a single connected WebSocket device
type Client struct {
	ID        string
	Role      Role
	Conn      *websocket.Conn
	PairingID string
	Send      chan []byte // Buffered channel for outbound messages
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
	defer s.Unlock()

	// If the session was already created, the incoming client MUST match the initial secret
	if s.Secret != "" && s.Secret != providedSecret {
		slog.Warn("Client attempted to join session with invalid secret", "pairing_id", s.PairingID, "role", c.Role)
		return false
	}

	if c.Role == RoleMac {
		if s.Mac != nil {
			slog.Info("Replacing existing Mac client in session", "pairing_id", s.PairingID)
			close(s.Mac.Send) // Signal old WritePump to exit immediately
			s.Mac.Conn.Close()
		}
		s.Mac = c
	} else if c.Role == RoleAndroid {
		if s.Android != nil {
			slog.Info("Replacing existing Android client in session", "pairing_id", s.PairingID)
			close(s.Android.Send) // Signal old WritePump to exit immediately
			s.Android.Conn.Close()
		}
		s.Android = c
	}
	s.UpdatedAt = time.Now()
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
