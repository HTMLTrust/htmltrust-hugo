package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
)

// hashSHA256B64 returns the unpadded base64 SHA-256 of the input, prefixed with
// "sha256:" per HTMLTrust spec §2.1 (hash encoding rules: unpadded Base64).
func hashSHA256B64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ContentHash returns the spec-conformant content-hash for the inner HTML of a
// signed-section. The inner HTML is run through ExtractCanonicalText (which
// strips <meta>/<script>/etc. and applies the 8-phase canonicalization) before
// hashing.
func ContentHash(innerHTML string) (string, error) {
	canonical, err := canon.ExtractCanonicalText(innerHTML)
	if err != nil {
		return "", fmt.Errorf("ContentHash: extract: %w", err)
	}
	return hashSHA256B64(canonical), nil
}

// ClaimsHash returns the spec-conformant claims-hash for a map of claim
// name->value pairs. Claims are canonicalized (sorted by name, normalized,
// joined with newlines) before hashing.
func ClaimsHash(claims map[string]string) string {
	return hashSHA256B64(canon.CanonicalizeClaims(claims))
}

// SignEd25519 signs the binding string with an Ed25519 private key and returns
// the unpadded-base64-encoded signature per spec §2.1.
func SignEd25519(binding string, key ed25519.PrivateKey) string {
	sig := ed25519.Sign(key, []byte(binding))
	return base64.RawStdEncoding.EncodeToString(sig)
}

// LoadEd25519PrivateKey parses a PEM-encoded PKCS#8 Ed25519 private key.
func LoadEd25519PrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("LoadEd25519PrivateKey: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("LoadEd25519PrivateKey: parse PKCS8: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("LoadEd25519PrivateKey: PEM contains %T, not ed25519.PrivateKey", key)
	}
	return ed, nil
}
