package config

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if kp.PrivateKey == "" || kp.PublicKey == "" {
		t.Fatal("keys should not be empty")
	}

	// Verify Base64 + 32 bytes
	privBytes, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil || len(privBytes) != 32 {
		t.Errorf("private key invalid: len=%d err=%v", len(privBytes), err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(kp.PublicKey)
	if err != nil || len(pubBytes) != 32 {
		t.Errorf("public key invalid: len=%d err=%v", len(pubBytes), err)
	}

	// Verify keys validate with our validator
	if !isValidWireGuardKey(kp.PrivateKey) {
		t.Error("generated private key fails validation")
	}
	if !isValidWireGuardKey(kp.PublicKey) {
		t.Error("generated public key fails validation")
	}
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	if kp1.PrivateKey == kp2.PrivateKey {
		t.Error("two generated keys should not be identical")
	}
}
