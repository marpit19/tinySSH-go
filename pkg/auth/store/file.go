package store

import (
	"bufio"
	"os"
	"strings"
	"sync"

	"github.com/marpit19/tinySSH-go/pkg/auth"
	"github.com/marpit19/tinySSH-go/pkg/auth/methods"
	"github.com/marpit19/tinySSH-go/pkg/common/logging"
)

// FileAuthStore implements authentication storage using a file
type FileAuthStore struct {
	filePath       string
	passwordAuth   methods.PasswordAuthenticator
	allowedMethods map[string][]string // Maps username to allowed auth methods
	logger         *logging.Logger
	mu             sync.RWMutex
}

// NewFileAuthStore creates a new file-based authentication store
func NewFileAuthStore(filePath string, logger *logging.Logger) (*FileAuthStore, error) {
	store := &FileAuthStore{
		filePath:       filePath,
		passwordAuth:   methods.NewPlaintextPasswordAuthenticator(),
		allowedMethods: make(map[string][]string),
		logger:         logger,
	}

	// Load credentials from file
	if err := store.loadCredentials(); err != nil {
		return nil, err
	}

	return store, nil
}

// loadCredentials loads credentials from the credentials file
func (s *FileAuthStore) loadCredentials() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if file exists
	_, err := os.Stat(s.filePath)
	if os.IsNotExist(err) {
		s.logger.Warning("Credentials file %s does not exist", s.filePath)
		return nil
	}

	// Open file
	file, err := os.Open(s.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line as username:password
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			s.logger.Warning("Invalid credential format in line: %s", line)
			continue
		}

		username := strings.TrimSpace(parts[0])
		password := strings.TrimSpace(parts[1])

		// Add to password authenticator
		s.passwordAuth.(*methods.PlaintextPasswordAuthenticator).AddCredential(username, password)

		// By default, allow password authentication
		s.allowedMethods[username] = []string{auth.AuthMethodPassword}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	s.logger.Info("Loaded credentials from %s", s.filePath)
	return nil
}

// saveCredentials saves credentials to the credentials file
func (s *FileAuthStore) saveCredentials() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create or truncate file
	file, err := os.Create(s.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// TODO: Implement save functionality if needed
	// This is not fully implemented in this phase

	s.logger.Info("Saved credentials to %s", s.filePath)
	return nil
}

// AuthenticatePassword verifies a username and password
func (s *FileAuthStore) AuthenticatePassword(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.passwordAuth.Authenticate(username, password)
}

// GetAllowedMethods returns the allowed authentication methods for a user
func (s *FileAuthStore) GetAllowedMethods(username string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	methods, exists := s.allowedMethods[username]
	if !exists {
		return []string{}
	}

	return methods
}
