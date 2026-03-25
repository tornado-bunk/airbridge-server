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

	// Rate limiter for connection and auth throttling
	RateLimiter *rateLimiter
}

// NewHub creates and returns a new Hub
func NewHub() *Hub {
	return &Hub{
		sessions: make(map[string]*models.Session),
		// Permissive rate limiting:
		// - 100 connections per IP per minute (prevents DDoS/reconnection floods)
		// - 20 failed auth attempts before locking out a pairing ID
		// - 2-minute lockout duration (short enough to be a minor annoyance for users, long enough to stop bots)
		RateLimiter: newRateLimiter(100, 1*time.Minute, 20, 2*time.Minute),
	}
}

// GetOrCreateSession retrieves an existing session from the hub or creates a new one.
// Returns the session and a boolean indicating whether it was newly created (for bootstrap).
func (h *Hub) GetOrCreateSession(pairingID string) (*models.Session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if session, exists := h.sessions[pairingID]; exists {
		return session, false
	}

	slog.Info("Creating new session (pending key bootstrap)", "pairing_id", models.TruncateID(pairingID))
	// Create session without a key — the first client's kInit will set it
	newSession := &models.Session{
		PairingID: pairingID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	h.sessions[pairingID] = newSession
	return newSession, true
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

	slog.Info("Removing session", "pairing_id", models.TruncateID(pairingID))
	delete(h.sessions, pairingID)
}

// CleanupStaleSessions Periodically called to remove sessions that have been abandoned
func (h *Hub) CleanupStaleSessions(maxIdleTime time.Duration) {
	now := time.Now()

	// Step 1: Collect IDs to delete using a short Read Lock
	var staleIDs []string

	h.mu.RLock()
	for id, session := range h.sessions {
		session.RLock()
		updatedAt := session.UpdatedAt
		macPresent := session.Mac != nil
		androidPresent := session.Android != nil
		session.RUnlock()

		// If the session has been empty (no clients) for too long, mark it to remove
		if !macPresent && !androidPresent && now.Sub(updatedAt) > maxIdleTime {
			staleIDs = append(staleIDs, id)
		}
	}
	h.mu.RUnlock()

	// Step 2: Delete collected IDs using a short Write Lock
	// Re-verify each session is still empty to avoid a TOCTOU race
	if len(staleIDs) > 0 {
		h.mu.Lock()
		for _, id := range staleIDs {
			session := h.sessions[id]
			if session == nil {
				continue
			}
			session.RLock()
			stillEmpty := session.Mac == nil && session.Android == nil
			session.RUnlock()
			if stillEmpty {
				slog.Debug("Cleaning up stale session", "pairing_id", models.TruncateID(id))
				delete(h.sessions, id)
			} else {
				slog.Debug("Session revived before cleanup, skipping", "pairing_id", models.TruncateID(id))
			}
		}
		h.mu.Unlock()
	}
}

// RunHeartbeat starts a background ticker to clean up dead sessions automatically
func (h *Hub) RunHeartbeat(interval time.Duration, maxIdleTime time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			h.CleanupStaleSessions(maxIdleTime)
		}
	}()
}
