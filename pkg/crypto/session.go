package crypto

import (
	"math/big"
	"sync"
	"time"

	"github.com/marpit19/tinySSH-go/pkg/crypto/dh"
)

// Session contains the key exchange and encryption state for an SSH session
type Session struct {
	ID                []byte        // Session identifier
	ClientKeyExchange []byte        // Client key exchange message
	ServerKeyExchange []byte        // Server key exchange message
	DH                *dh.DH        // Diffie-Hellman state
	Keys              *Keys         // Current session keys
	NextKeys          *Keys         // Next keys (for rekeying)
	LastRekey         time.Time     // Time of last rekey
	RekeyInterval     time.Duration // Time between rekeys
	mu                sync.Mutex    // Mutex for thread safety
}

// NewSession creates a new SSH session
func NewSession() (*Session, error) {
	// Create Diffie-Hellman instance
	dhInstance, err := dh.New()
	if err != nil {
		return nil, err
	}

	return &Session{
		DH:            dhInstance,
		LastRekey:     time.Now(),
		RekeyInterval: 60 * time.Minute, // Rekey every hour by default
	}, nil
}

// NeedsRekey checks if it's time to rekey
func (s *Session) NeedsRekey() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return time.Since(s.LastRekey) > s.RekeyInterval
}

// SetKeys sets the session keys
func (s *Session) SetKeys(keys *Keys) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Keys = keys
	s.LastRekey = time.Now()
}

// PrepareRekey starts the rekeying process by generating new DH parameters
func (s *Session) PrepareRekey() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate new DH parameters
	dhInstance, err := dh.New()
	if err != nil {
		return err
	}

	s.DH = dhInstance
	return nil
}

// CompleteRekey finalizes the rekeying process
func (s *Session) CompleteRekey(newKeys *Keys) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Keys = newKeys
	s.LastRekey = time.Now()
}

// GetPublicKey returns our public key for key exchange
func (s *Session) GetPublicKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.DH.PublicKey.Bytes()
}

// ComputeSharedSecret calculates the shared secret from the other party's public key
func (s *Session) ComputeSharedSecret(otherPublicKeyBytes []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert bytes to big.Int
	otherPublicKey := new(big.Int).SetBytes(otherPublicKeyBytes)

	// Compute shared secret
	sharedSecret := s.DH.ComputeSharedSecret(otherPublicKey)

	return sharedSecret.Bytes()
}
