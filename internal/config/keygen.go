package config

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

// KeyPair holds a WireGuard private/public key pair.
type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// GenerateKeyPair creates a new WireGuard key pair (Curve25519).
func GenerateKeyPair() (*KeyPair, error) {
	// Generate random 32 bytes for private key
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return nil, err
	}

	// Clamp the private key per WireGuard spec
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	// Derive public key
	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
	}, nil
}
