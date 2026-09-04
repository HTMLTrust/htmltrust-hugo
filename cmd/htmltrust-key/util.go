package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func hexPrefix(b []byte, n int) string {
	enc := hex.EncodeToString(b)
	if len(enc) < n {
		return enc
	}
	return enc[:n]
}

// didWebDocumentURL derives the default served document URL of a did:web
// identity: did:web:example.com -> https://example.com/.well-known/did.json,
// did:web:example.com:user:alice -> https://example.com/user/alice/did.json.
func didWebDocumentURL(identity string) (string, error) {
	const prefix = "did:web:"
	if !strings.HasPrefix(identity, prefix) {
		return "", fmt.Errorf("not a did:web identity: %q (pass --did-document explicitly for other identity forms)", identity)
	}
	rest := strings.TrimPrefix(identity, prefix)
	if rest == "" {
		return "", fmt.Errorf("empty did:web identity")
	}
	parts := strings.Split(rest, ":")
	for i, p := range parts {
		decoded, err := url.PathUnescape(p)
		if err != nil {
			return "", fmt.Errorf("invalid did:web percent-encoding in %q: %w", identity, err)
		}
		parts[i] = decoded
	}
	host := parts[0]
	if len(parts) == 1 {
		return "https://" + host + "/.well-known/did.json", nil
	}
	return "https://" + host + "/" + strings.Join(parts[1:], "/") + "/did.json", nil
}
