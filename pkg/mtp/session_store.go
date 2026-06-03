package mtp

import (
	"sync"
	"time"

	"meridian/pkg/crypto"
)

type SessionEntry struct {
	Keys         *crypto.KeyMaterial
	ExpiresAt    time.Time
	ClientRandom [32]byte
	ServerRandom [32]byte
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[[16]byte]*SessionEntry
}

func NewSessionStore() *SessionStore {
	ss := &SessionStore{
		sessions: make(map[[16]byte]*SessionEntry),
	}
	go ss.cleanupLoop()
	return ss
}

func (ss *SessionStore) Store(id [16]byte, entry *SessionEntry) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.sessions[id] = entry
}

func (ss *SessionStore) Lookup(id [16]byte) (*SessionEntry, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	entry, ok := ss.sessions[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}
	return entry, true
}

func (ss *SessionStore) Cleanup() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	now := time.Now()
	for id, entry := range ss.sessions {
		if now.After(entry.ExpiresAt) {
			delete(ss.sessions, id)
		}
	}
}

func (ss *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ss.Cleanup()
	}
}
