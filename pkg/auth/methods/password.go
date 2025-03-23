package methods

import (
	"crypto/subtle"

	"golang.org/x/crypto/bcrypt"
)

// PasswordAuthenticator defines the interface for password authentication
type PasswordAuthenticator interface {
	Authenticate(username, password string) bool
}

// PlaintextPasswordAuthenticator implements simple plaintext password authentication
type PlaintextPasswordAuthenticator struct {
	credentials map[string]string // Maps username to password
}

// NewPlaintextPasswordAuthenticator creates a new plaintext password authenticator
func NewPlaintextPasswordAuthenticator() *PlaintextPasswordAuthenticator {
	return &PlaintextPasswordAuthenticator{
		credentials: make(map[string]string),
	}
}

// AddCredential adds a username and password
func (a *PlaintextPasswordAuthenticator) AddCredential(username, password string) {
	a.credentials[username] = password
}

// Authenticate checks if the username and password match stored credentials
func (a *PlaintextPasswordAuthenticator) Authenticate(username, password string) bool {
	storedPassword, exists := a.credentials[username]
	if !exists {
		return false
	}

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(storedPassword), []byte(password)) == 1
}

// HashedPasswordAuthenticator implements password authentication with bcrypt hashes
type HashedPasswordAuthenticator struct {
	hashedCredentials map[string]string // Maps username to bcrypt hash
}

// NewHashedPasswordAuthenticator creates a new bcrypt hashed password authenticator
func NewHashedPasswordAuthenticator() *HashedPasswordAuthenticator {
	return &HashedPasswordAuthenticator{
		hashedCredentials: make(map[string]string),
	}
}

// AddCredential adds a username and bcrypt hashed password
func (a *HashedPasswordAuthenticator) AddCredential(username, hashedPassword string) {
	a.hashedCredentials[username] = hashedPassword
}

// AddPlaintextCredential adds a username and plaintext password (hashing it first)
func (a *HashedPasswordAuthenticator) AddPlaintextCredential(username, password string) error {
	// Hash the password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	a.hashedCredentials[username] = string(hashedPassword)
	return nil
}

// Authenticate checks if the username and password match stored hashed credentials
func (a *HashedPasswordAuthenticator) Authenticate(username, password string) bool {
	hashedPassword, exists := a.hashedCredentials[username]
	if !exists {
		return false
	}

	// Compare with bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
