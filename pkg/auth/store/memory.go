package store

import (
	"sync"

	"github.com/marpit19/tinySSH-go/pkg/auth"
	"github.com/marpit19/tinySSH-go/pkg/auth/methods"
)

// MemoryAuthStore implements in-memory authentication storage
type MemoryAuthStore struct {
	passwordAuth   methods.PasswordAuthenticator
	allowedMethods map[string][]string // Maps username to allowed auth methods
	mu             sync.RWMutex
}

// NewMemoryAuthStore creates a new in-memory authentication store
func NewMemoryAuthStore() *MemoryAuthStore {
	return &MemoryAuthStore{
		passwordAuth:   methods.NewPlaintextPasswordAuthenticator(),
		allowedMethods: make(map[string][]string),
	}
}

// AddUser adds a user with a plaintext password
func (s *MemoryAuthStore) AddUser(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Add to password authenticator
	s.passwordAuth.(*methods.PlaintextPasswordAuthenticator).AddCredential(username, password)

	// By default, allow password auth for new users
	s.allowedMethods[username] = []string{auth.AuthMethodPassword}
}

// SetAllowedMethods sets the allowed authentication methods for a user
func (s *MemoryAuthStore) SetAllowedMethods(username string, methods []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.allowedMethods[username] = methods
}

// AuthenticatePassword verifies a username and password
func (s *MemoryAuthStore) AuthenticatePassword(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.passwordAuth.Authenticate(username, password)
}

// GetAllowedMethods returns the allowed authentication methods for a user
func (s *MemoryAuthStore) GetAllowedMethods(username string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	methods, exists := s.allowedMethods[username]
	if !exists {
		return []string{}
	}

	return methods
}
