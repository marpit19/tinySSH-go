package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// HostKey represents a server host key
type HostKey struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyBlob    []byte // SSH wire format
}

// GenerateHostKey generates a new RSA host key
func GenerateHostKey() (*HostKey, error) {
	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}

	// Create host key structure
	hk := &HostKey{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}

	// Generate SSH wire format for the public key
	hk.KeyBlob, err = marshalPublicKey(hk.PublicKey)
	if err != nil {
		return nil, err
	}

	return hk, nil
}

// LoadOrGenerateHostKey loads a host key from file or generates a new one
func LoadOrGenerateHostKey(keyPath string) (*HostKey, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %v", err)
	}

	// Check if key file exists
	if _, err := os.Stat(keyPath); err == nil {
		// Load existing key
		return loadHostKey(keyPath)
	}

	// Generate new key
	hostKey, err := GenerateHostKey()
	if err != nil {
		return nil, err
	}

	// Save the key
	if err := saveHostKey(hostKey, keyPath); err != nil {
		return nil, err
	}

	return hostKey, nil
}

// loadHostKey loads a host key from a file
func loadHostKey(keyPath string) (*HostKey, error) {
	// Read key file
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %v", err)
	}

	// Create host key structure
	hk := &HostKey{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}

	// Generate SSH wire format for the public key
	hk.KeyBlob, err = marshalPublicKey(hk.PublicKey)
	if err != nil {
		return nil, err
	}

	return hk, nil
}

// saveHostKey saves a host key to a file
func saveHostKey(hostKey *HostKey, keyPath string) error {
	// Encode private key to PKCS1 DER format
	derBytes := x509.MarshalPKCS1PrivateKey(hostKey.PrivateKey)

	// Create PEM block
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}

	// Encode to PEM and write to file
	return ioutil.WriteFile(keyPath, pem.EncodeToMemory(block), 0600)
}

// marshalPublicKey converts an RSA public key to SSH wire format
func marshalPublicKey(pubKey *rsa.PublicKey) ([]byte, error) {
	// For a simplified version, we'll just create a placeholder
	// In a real implementation, this would properly format the key according to RFC 4253
	var buf bytes.Buffer

	// Write key type
	WriteString(&buf, "ssh-rsa")

	// Write RSA exponent
	e := make([]byte, 4)
	binary.BigEndian.PutUint32(e, uint32(pubKey.E))
	WriteBytes(&buf, e)

	// Write RSA modulus
	WriteBytes(&buf, pubKey.N.Bytes())

	return buf.Bytes(), nil
}

// SignHash signs a hash with the host key
func (hk *HostKey) SignHash(hash []byte) ([]byte, error) {
	// For a simplified version, we'll just create a placeholder signature
	// In a real implementation, this would use the proper signature algorithm
	var buf bytes.Buffer

	// Write signature format
	WriteString(&buf, "ssh-rsa")

	// Generate a dummy signature
	signature := []byte("dummy-signature")
	WriteBytes(&buf, signature)

	return buf.Bytes(), nil
}

// Helper functions similar to those in the messages package

// WriteString writes a string as a length-prefixed byte array
func WriteString(buf *bytes.Buffer, s string) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	buf.Write(b)
	buf.WriteString(s)
}

// WriteBytes writes a byte slice as a length-prefixed array
func WriteBytes(buf *bytes.Buffer, b []byte) {
	bb := make([]byte, 4)
	binary.BigEndian.PutUint32(bb, uint32(len(b)))
	buf.Write(bb)
	buf.Write(b)
}
