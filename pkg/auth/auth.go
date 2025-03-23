package auth

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/marpit19/tinySSH-go/pkg/common/logging"
)

// Constants for authentication
const (
	AuthMethodPassword = "password"
	AuthMethodNone     = "none"

	MaxAuthAttempts   = 5               // Maximum allowed authentication attempts
	AuthLockoutPeriod = 5 * time.Minute // Time period to lock out after too many attempts
)

// Authenticator defines the interface for authentication providers
type Authenticator interface {
	// AuthenticatePassword verifies a username and password
	AuthenticatePassword(username, password string) bool

	// GetAllowedMethods returns the allowed authentication methods for a user
	GetAllowedMethods(username string) []string
}

// BruteForceProtector tracks failed authentication attempts
type BruteForceProtector struct {
	failedAttempts map[string]int       // Maps IP address to failed attempt count
	lockoutTime    map[string]time.Time // Maps IP address to lockout expiry time
	mu             sync.Mutex           // Mutex for thread safety
	logger         *logging.Logger      // Logger for security events
}

// NewBruteForceProtector creates a new protector
func NewBruteForceProtector(logger *logging.Logger) *BruteForceProtector {
	return &BruteForceProtector{
		failedAttempts: make(map[string]int),
		lockoutTime:    make(map[string]time.Time),
		logger:         logger,
	}
}

// RecordFailedAttempt records a failed authentication attempt
func (p *BruteForceProtector) RecordFailedAttempt(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip := conn.RemoteAddr().String()

	// Check if currently locked out
	if lockoutExpiry, exists := p.lockoutTime[ip]; exists {
		if time.Now().Before(lockoutExpiry) {
			p.logger.Warning("Authentication attempt from locked out IP: %s", ip)
			return false // IP is locked out
		}
		// Lockout period has expired
		delete(p.lockoutTime, ip)
		p.failedAttempts[ip] = 0
	}

	// Increment failed attempts
	p.failedAttempts[ip]++
	p.logger.Warning("Failed authentication attempt from %s (%d/%d)",
		ip, p.failedAttempts[ip], MaxAuthAttempts)

	// Check if we need to lock out this IP
	if p.failedAttempts[ip] >= MaxAuthAttempts {
		p.lockoutTime[ip] = time.Now().Add(AuthLockoutPeriod)
		p.logger.Warning("IP %s locked out for %v due to too many failed attempts",
			ip, AuthLockoutPeriod)
		return false // IP is now locked out
	}

	return true // Not locked out
}

// RecordSuccessfulAttempt clears the failed attempt counter
func (p *BruteForceProtector) RecordSuccessfulAttempt(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip := conn.RemoteAddr().String()
	delete(p.failedAttempts, ip)
	delete(p.lockoutTime, ip)
}

// IsLockedOut checks if an IP is currently locked out
func (p *BruteForceProtector) IsLockedOut(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip := conn.RemoteAddr().String()

	// Check if currently locked out
	if lockoutExpiry, exists := p.lockoutTime[ip]; exists {
		if time.Now().Before(lockoutExpiry) {
			remainingTime := time.Until(lockoutExpiry).Round(time.Second)
			p.logger.Warning("IP %s is locked out for another %v", ip, remainingTime)
			return true // IP is locked out
		}
		// Lockout period has expired
		delete(p.lockoutTime, ip)
		delete(p.failedAttempts, ip)
	}

	return false // Not locked out
}

// Authentication errors
var (
	ErrAuthFailed       = fmt.Errorf("authentication failed")
	ErrTooManyAttempts  = fmt.Errorf("too many failed authentication attempts")
	ErrNoSuchUser       = fmt.Errorf("no such user")
	ErrMethodNotAllowed = fmt.Errorf("authentication method not allowed")
)
