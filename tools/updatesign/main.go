// Command updatesign generates, uses, and verifies the Ed25519 key that
// signs each release's SHA256SUMS (see internal/update: the client
// downloads SHA256SUMS.sig — the raw 64-byte signature over the
// SHA256SUMS file bytes — and verifies it against the hex public key
// baked into production builds via
//
//	-ldflags "-X github.com/korjwl1/wireguide/internal/update.expectedPublicKey=<hex>"
//
// The private key is stored as its 32-byte seed, hex-encoded (64 hex
// chars) — e.g. in the UPDATE_SIGNING_KEY GitHub Actions secret.
//
//	updatesign gen  -out <seed-file>          # new key; prints PUBLIC hex
//	updatesign pub                            # seed from $UPDATE_SIGNING_KEY (or -key <file>); prints public hex
//	updatesign sign -in SHA256SUMS -sig SHA256SUMS.sig
//	updatesign verify -pub <hex> -in SHA256SUMS -sig SHA256SUMS.sig
//
// Stdlib-only so CI needs nothing beyond the Go toolchain, and the
// sign/verify pair matches internal/update's verification exactly.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		die("usage: updatesign <gen|pub|sign|verify> [flags]")
	}
	switch os.Args[1] {
	case "gen":
		cmdGen(os.Args[2:])
	case "pub":
		cmdPub(os.Args[2:])
	case "sign":
		cmdSign(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	default:
		die("unknown subcommand %q (want gen, pub, sign, or verify)", os.Args[1])
	}
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// loadSeed reads the hex seed from -key <file> if given, else from the
// UPDATE_SIGNING_KEY environment variable, and returns the private key.
func loadSeed(keyFile string) ed25519.PrivateKey {
	var hexSeed string
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			die("read key file: %v", err)
		}
		hexSeed = string(b)
	} else {
		hexSeed = os.Getenv("UPDATE_SIGNING_KEY")
		if hexSeed == "" {
			die("no key: pass -key <seed-file> or set UPDATE_SIGNING_KEY")
		}
	}
	seed, err := hex.DecodeString(strings.TrimSpace(hexSeed))
	if err != nil {
		die("key is not valid hex: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		die("key seed size: got %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func pubHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// cmdGen writes a NEW hex seed to -out (0600, refusing to overwrite) and
// prints only the public key to stdout — the seed never touches stdout
// so shell transcripts/CI logs can't leak it.
func cmdGen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	out := fs.String("out", "", "file to write the hex seed to (required)")
	fs.Parse(args)
	if *out == "" {
		die("gen: -out <seed-file> is required")
	}
	if _, err := os.Stat(*out); err == nil {
		die("gen: %s already exists — refusing to overwrite a signing key", *out)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		die("gen: %v", err)
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		die("gen: %v", err)
	}
	fmt.Println(pubHex(ed25519.NewKeyFromSeed(seed)))
}

func cmdPub(args []string) {
	fs := flag.NewFlagSet("pub", flag.ExitOnError)
	key := fs.String("key", "", "seed file (default: $UPDATE_SIGNING_KEY)")
	fs.Parse(args)
	fmt.Println(pubHex(loadSeed(*key)))
}

func cmdSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	key := fs.String("key", "", "seed file (default: $UPDATE_SIGNING_KEY)")
	in := fs.String("in", "SHA256SUMS", "file to sign")
	sig := fs.String("sig", "", "signature output (default: <in>.sig)")
	fs.Parse(args)
	if *sig == "" {
		*sig = *in + ".sig"
	}
	msg, err := os.ReadFile(*in)
	if err != nil {
		die("sign: %v", err)
	}
	priv := loadSeed(*key)
	if err := os.WriteFile(*sig, ed25519.Sign(priv, msg), 0o644); err != nil {
		die("sign: %v", err)
	}
	fmt.Printf("signed %s → %s (pub %s)\n", *in, *sig, pubHex(priv))
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pub := fs.String("pub", "", "hex public key (required)")
	in := fs.String("in", "SHA256SUMS", "signed file")
	sig := fs.String("sig", "", "signature file (default: <in>.sig)")
	fs.Parse(args)
	if *sig == "" {
		*sig = *in + ".sig"
	}
	pk, err := hex.DecodeString(strings.TrimSpace(*pub))
	if err != nil || len(pk) != ed25519.PublicKeySize {
		die("verify: -pub must be %d hex-encoded bytes", ed25519.PublicKeySize)
	}
	msg, err := os.ReadFile(*in)
	if err != nil {
		die("verify: %v", err)
	}
	sg, err := os.ReadFile(*sig)
	if err != nil {
		die("verify: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pk), msg, sg) {
		die("verify: SIGNATURE INVALID")
	}
	fmt.Println("signature OK")
}
