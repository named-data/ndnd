package server

import (
	"crypto/ecdh"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/security/ndncert"
)

const (
	StatusBeforeChallenge = uint64(0)
	StatusChallenge       = uint64(1)
	StatusPending         = uint64(2)
	StatusSuccess         = uint64(3)
	StatusFailure         = uint64(4)
)

type RequestState struct {
	RequestID []byte
	CaPrefix  enc.Name
	Status    uint64

	ChallengeType        string
	ChallengeStatus      string
	ChallengeAttempts    int
	MaxChallengeAttempts int
	ChallengeState       map[string][]byte

	CertRequest       enc.Wire
	RequestedCertName enc.Name

	ClientEcdhPub []byte
	CaEcdhKey     *ecdh.PrivateKey
	Salt          []byte
	AesKey        [16]byte
	AeadCounter   *ndncert.AeadCounter

	IssuedCert enc.Wire

	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
}

func NewRequestState(requestID []byte, caPrefix enc.Name) *RequestState {
	now := time.Now()
	return &RequestState{
		RequestID:            requestID,
		CaPrefix:             caPrefix,
		Status:               StatusBeforeChallenge,
		ChallengeAttempts:    0,
		MaxChallengeAttempts: 3,
		ChallengeState:       make(map[string][]byte),
		CreatedAt:            now,
		UpdatedAt:            now,
		ExpiresAt:            now.Add(24 * time.Hour),
	}
}

func (r *RequestState) IncrementAttempts() bool {
	r.ChallengeAttempts++
	r.UpdatedAt = time.Now()
	return r.ChallengeAttempts >= r.MaxChallengeAttempts
}

func (r *RequestState) RemainingAttempts() int {
	remaining := r.MaxChallengeAttempts - r.ChallengeAttempts
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (r *RequestState) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

func (r *RequestState) SetChallengeStateValue(key string, value []byte) {
	r.ChallengeState[key] = value
	r.UpdatedAt = time.Now()
}

func (r *RequestState) GetChallengeStateValue(key string) ([]byte, bool) {
	val, ok := r.ChallengeState[key]
	return val, ok
}

func (r *RequestState) MarkSuccess(issuedCert enc.Wire) {
	r.Status = StatusSuccess
	r.IssuedCert = issuedCert
	r.UpdatedAt = time.Now()
}

func (r *RequestState) MarkFailure(reason string) {
	r.Status = StatusFailure
	r.ChallengeStatus = reason
	r.UpdatedAt = time.Now()
}
