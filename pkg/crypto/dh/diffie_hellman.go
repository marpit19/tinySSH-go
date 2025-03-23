package dh

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"math/big"
)

// DH contains the parameters for Diffie-Hellman key exchange
type DH struct {
	P          *big.Int // large prime
	G          *big.Int // generator
	PrivateKey *big.Int // our private key
	PublicKey  *big.Int // our public key
}

// New creates a new DH key exchange
// using group14 (2048-bit MODP Group) parameters from RFC 3526
func New() (*DH, error) {
	// Group 14 parameters (2048-bit MODP Group)
	// P is a large prime number (2^2048 - 2^1984 - 1 + 2^64 * floor(2^1918 * Pi) + 124476)
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

	// G is the greator (usually 2 or 5)
	g := big.NewInt(2)

	// generate private key (random number b/w 1 and P-1)
	max := new(big.Int).Sub(p, big.NewInt(1))
	privateKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// ensure private key is atleast 1
	if privateKey.Cmp(big.NewInt(1)) < 0 {
		privateKey.Set(big.NewInt(1))
	}

	// calculate public key: G^private_key mod P
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return &DH{
		P:          p,
		G:          g,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// ComputeSharedSecret calcultes the shared secret from the other party's public key
func (dh *DH) ComputeSharedSecret(otherPublicKey *big.Int) *big.Int {
	// shared secret = other_public_key^private_key mod P
	return new(big.Int).Exp(otherPublicKey, dh.PrivateKey, dh.P)
}

// GenerateHash creates a SHA-1 hash of the shared secret
func (dh *DH) GenerateHash(sharedSecret *big.Int) []byte {
	h := sha1.New()
	h.Write(sharedSecret.Bytes())
	return h.Sum(nil)
}
