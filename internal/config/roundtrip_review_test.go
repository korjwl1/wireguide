package config

import (
	"strings"
	"testing"
)

func TestInlineCommentsAndRepeatedUnknownKeysRoundTrip(t *testing.T) {
	cfg, err := Parse("[Interface] # local\nPrivateKey = key # inline\nExtra = first\nExtra = second\n[Peer]\nPublicKey = peer\nUnknown = a\nUnknown = b\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interface.PrivateKey != "key" {
		t.Fatal("inline comment entered private key")
	}
	text := Serialize(cfg)
	if strings.Count(text, "Extra = ") != 2 || strings.Count(text, "Unknown = ") != 2 {
		t.Fatalf("repeated unknown entries lost: %s", text)
	}
	for range 50 {
		if Serialize(cfg) != text {
			t.Fatal("config export order changed")
		}
	}
}
