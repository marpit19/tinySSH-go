package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
)

// Keys contains the encryption and integrity keys for a session
type Keys struct {
	IV           []byte // initialize vector
	EncryptKey   []byte // key for encryption
	IntegrityKey []byte // key for HMAC: Hash-Based Message Authentication Code
}

// DeriveKeys derives the session keys from the shared secret
func DeriveKeys(sharedSecret, sessionID []byte) *Keys {
	// We're implementing a simplified key derivation for educational purposes
	// In a real implementation, we would use more sophisticated key derivation
	
	keys := &Keys{
		IV:            deriveKey(sharedSecret, sessionID, 'A'),
		EncryptKey:    deriveKey(sharedSecret, sessionID, 'C'),
		IntegrityKey:  deriveKey(sharedSecret, sessionID, 'E'),
	}
	
	return keys
}

// deriveKey derives a specific key using HMAC-SHA1
func deriveKey(sharedSecret, sessionID []byte, purpose byte) []byte {
	h := hmac.New(sha1.New, sharedSecret)
	
	h.Write(sessionID)
	h.Write([]byte{purpose})
	h.Write(sharedSecret)
	
	return h.Sum(nil)[:16] // Return 16 bytes (128 bits) for AES-128
}

// NewHMAC creates a new HMAC instance using the integrity key
func (k *Keys) NewHMAC() hash.Hash {
	return hmac.New(sha1.New, k.IntegrityKey)
}

// GenerateSessionID generates a session ID from various component
func GenerateSessionID(clientKexInit, serverKexInit, clientPublicKey, serverPublicKey, sharedSecret []byte) []byte {
	h := sha1.New()

	// write all compoenets to the hash
	h.Write(clientKexInit)
	h.Write(serverKexInit)
	h.Write(clientPublicKey)
	h.Write(serverPublicKey)
	h.Write(sharedSecret)

	return h.Sum(nil)
}
