package server

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

// TODO: do we want persistant storage? right now everything is tracked in memory in a request id -> state map

type Storage interface {
	Put(requestID []byte, state *RequestState) error
	Get(requestID []byte) (*RequestState, error)
	Delete(requestID []byte) error
	List() ([][]byte, error)
	CleanExpired() (int, error)
}

type MemoryStorage struct {
	mu    sync.RWMutex
	store map[string]*RequestState
}

func NewMemoryStorage() *MemoryStorage {
	s := &MemoryStorage{
		store: make(map[string]*RequestState),
	}

	go s.cleanupLoop()
	return s
}

func (m *MemoryStorage) Put(requestID []byte, state *RequestState) error {
	if requestID == nil {
		return fmt.Errorf("requestID cannot be nil")
	}
	if state == nil {
		return fmt.Errorf("state cannot be nil")
	}

	key := string(requestID)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.store[key] = state
	return nil
}

func (m *MemoryStorage) Get(requestID []byte) (*RequestState, error) {
	if requestID == nil {
		return nil, fmt.Errorf("requestID cannot be nil")
	}

	key := string(requestID)

	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.store[key]
	if !ok {
		return nil, nil
	}

	if state.IsExpired() {
		return nil, nil
	}

	return state, nil
}

func (m *MemoryStorage) Delete(requestID []byte) error {
	if requestID == nil {
		return fmt.Errorf("requestID cannot be nil")
	}

	key := string(requestID)

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.store, key)
	return nil
}

func (m *MemoryStorage) List() ([][]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([][]byte, 0, len(m.store))
	for key := range m.store {
		ids = append(ids, []byte(key))
	}

	return ids, nil
}

func (m *MemoryStorage) CleanExpired() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	deleted := 0

	for key, state := range m.store {
		if now.After(state.ExpiresAt) {
			delete(m.store, key)
			deleted++
		}
	}

	return deleted, nil
}

func (m *MemoryStorage) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// log.Printf("ndncert cleanup: %d", m.Count())
		m.CleanExpired()
	}
}

// byte-wise lookup since map keys are strings
func (m *MemoryStorage) FindByRequestID(requestID []byte) (*RequestState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for key, state := range m.store {
		if bytes.Equal([]byte(key), requestID) {
			if !state.IsExpired() {
				return state, nil
			}
			return nil, nil
		}
	}

	return nil, nil
}

func (m *MemoryStorage) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.store)
}
