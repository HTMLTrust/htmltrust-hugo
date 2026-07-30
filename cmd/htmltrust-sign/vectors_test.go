package main

import (
	"encoding/json"
	"os"
	"testing"
)

// TestSignerReproducesVector proves the Hugo CLI signer produces the same
// content-hash and claims-hash as the shared reference test vector — i.e. it
// now interoperates with the browser-client / Go verifiers (P0 fix).
func TestSignerReproducesVector(t *testing.T) {
	const path = "../../../htmltrust-canonicalization/conformance/vectors/vector-01.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("vector not found (%v); skipping cross-repo interop check", err)
	}
	var v struct {
		Input struct {
			HTML    string `json:"html"`
			BaseURL string `json:"baseURL"`
		} `json:"input"`
		Claims      map[string]string `json:"claims"`
		ContentHash string            `json:"contentHash"`
		ClaimsHash  string            `json:"claimsHash"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	got, err := ContentHash(v.Input.HTML, v.Input.BaseURL)
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if got != v.ContentHash {
		t.Errorf("contentHash: signer produced %s, verifiers expect %s", got, v.ContentHash)
	}
	if ch := ClaimsHash(v.Claims); ch != v.ClaimsHash {
		t.Errorf("claimsHash: signer produced %s, verifiers expect %s", ch, v.ClaimsHash)
	}
}
