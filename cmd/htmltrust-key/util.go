package main

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
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
// identity. See perioddid.DidWebDocumentURL, shared with cmd/htmltrust-sign.
func didWebDocumentURL(identity string) (string, error) {
	return perioddid.DidWebDocumentURL(identity)
}
