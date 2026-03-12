package server

import (
	"log/slog"
	"sync"
	"time"

	"github.com/tornado-bunk/airbridge-server/internal/models"
)

// Hub maintains the set of active sessions and distributes messages.
type Hub struct {
	// Active sessions mapped by PairingID
	sessions map[string]*models.Session

	// Mutex to protect concurrent access to the sessions map
	mu sync.RWMutex
}

// NewHub creates and returns a new Hub
func NewHub() *Hub {
	return &Hub{
		sessions: make(map[string]*models.Session),
	}
}

// GetOrCreateSession retrieves an existing session from the hub or creates a new one
func (h *Hub) GetOrCreateSession(pairingID string) *models.Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	if session, exists := h.sessions[pairingID]; exists {
		return session
	}

	slog.Info("Creating new session", "pairing_id", pairingID)
	newSession := models.NewSession(pairingID)
	h.sessions[pairingID] = newSession
	return newSession
}

// GetSession retrieves a session or returns nil if it doesn't exist
func (h *Hub) GetSession(pairingID string) *models.Session {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.sessions[pairingID]
}

// RemoveSession deletes a session from the hub
func (h *Hub) RemoveSession(pairingID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	slog.Info("Removing session", "pairing_id", pairingID)
	delete(h.sessions, pairingID)
}

// CleanupStaleSessions Periodically called to remove sessions that have been abandoned
func (h *Hub) CleanupStaleSessions(maxIdleTime time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	for id, session := range h.sessions {
		session.RLock()
		updatedAt := session.UpdatedAt
		macPresent := session.Mac != nil
		androidPresent := session.Android != nil
		session.RUnlock()

		// If the session has been empty (no clients) for too long, remove it
		if !macPresent && !androidPresent && now.Sub(updatedAt) > maxIdleTime {
			slog.Debug("Cleaning up stale session", "pairing_id", id)
			delete(h.sessions, id)
		}
	}
}
