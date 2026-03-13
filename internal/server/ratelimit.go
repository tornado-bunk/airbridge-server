package server

import (
	"net"
	"sync"
	"time"
)

// rateLimiter implements a per-IP token bucket rate limiter with
// per-pairing-ID failed-authentication tracking and lockout.
type rateLimiter struct {
	mu sync.Mutex

	// Per-IP connection rate limiting
	visitors    map[string]*visitor
	rate        int           // max requests per window
	window      time.Duration // window duration
	cleanupTick time.Duration

	// Per-pairing-ID auth failure tracking
	authFailures    map[string]*authTracker
	maxAuthFailures int
	authLockoutTime time.Duration
}

type visitor struct {
	count       int
	windowStart time.Time
}

type authTracker struct {
	failures    int
	lastFailure time.Time
	lockedUntil time.Time
}

// newRateLimiter creates a rate limiter.
//   - rate: max connections per IP per window
//   - window: time window for the rate counter
//   - maxAuthFailures: lock out a pairing ID after this many failed auth attempts
//   - authLockoutTime: how long to lock out a pairing ID after max failures
func newRateLimiter(rate int, window time.Duration, maxAuthFailures int, authLockoutTime time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors:        make(map[string]*visitor),
		rate:            rate,
		window:          window,
		cleanupTick:     window * 2,
		authFailures:    make(map[string]*authTracker),
		maxAuthFailures: maxAuthFailures,
		authLockoutTime: authLockoutTime,
	}

	// Background cleanup of stale entries
	go rl.cleanupLoop()

	return rl
}

// AllowConnection checks whether a connection from the given IP should be allowed.
func (rl *rateLimiter) AllowConnection(remoteAddr string) bool {
	ip := extractIP(remoteAddr)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]

	if !exists || now.Sub(v.windowStart) > rl.window {
		// New window
		rl.visitors[ip] = &visitor{count: 1, windowStart: now}
		return true
	}

	v.count++
	return v.count <= rl.rate
}

// AllowAuth checks whether authentication attempts for a pairing ID are allowed.
// Returns false if the pairing ID is currently locked out due to too many failures.
func (rl *rateLimiter) AllowAuth(pairingID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	tracker, exists := rl.authFailures[pairingID]
	if !exists {
		return true
	}

	now := time.Now()

	// Check if lockout has expired
	if !tracker.lockedUntil.IsZero() && now.Before(tracker.lockedUntil) {
		return false
	}

	// If lockout expired, reset
	if !tracker.lockedUntil.IsZero() && now.After(tracker.lockedUntil) {
		delete(rl.authFailures, pairingID)
		return true
	}

	return true
}

// RecordAuthFailure records a failed authentication attempt for a pairing ID.
func (rl *rateLimiter) RecordAuthFailure(pairingID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	tracker, exists := rl.authFailures[pairingID]
	if !exists {
		tracker = &authTracker{}
		rl.authFailures[pairingID] = tracker
	}

	// Reset counter if last failure was long ago (double the lockout time)
	if now.Sub(tracker.lastFailure) > rl.authLockoutTime*2 {
		tracker.failures = 0
	}

	tracker.failures++
	tracker.lastFailure = now

	if tracker.failures >= rl.maxAuthFailures {
		tracker.lockedUntil = now.Add(rl.authLockoutTime)
	}
}

// RecordAuthSuccess clears the failure counter for a pairing ID after successful auth.
func (rl *rateLimiter) RecordAuthSuccess(pairingID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.authFailures, pairingID)
}

// cleanupLoop periodically removes stale visitor and auth tracker entries.
func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupTick)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()

		for ip, v := range rl.visitors {
			if now.Sub(v.windowStart) > rl.window*2 {
				delete(rl.visitors, ip)
			}
		}

		for pid, tracker := range rl.authFailures {
			// Remove trackers that haven't had failures recently and aren't locked
			if tracker.lockedUntil.IsZero() && now.Sub(tracker.lastFailure) > rl.authLockoutTime*2 {
				delete(rl.authFailures, pid)
			}
			// Remove expired lockouts
			if !tracker.lockedUntil.IsZero() && now.After(tracker.lockedUntil) {
				delete(rl.authFailures, pid)
			}
		}

		rl.mu.Unlock()
	}
}

// extractIP extracts the IP portion from a "host:port" remote address.
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
