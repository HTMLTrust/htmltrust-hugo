package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSignerReproducesVector proves the Hugo CLI signer produces the same
// content-hash and claims-hash as the shared reference test vector — i.e. it
// now interoperates with the browser-client / Go verifiers (P0 fix).
func TestSignerReproducesVector(t *testing.T) {
	// The optional checkout is a sibling of htmltrust-hugo. Go may run the test
	// binary from either the module root or the package directory, so try both
	// locations rather than baking in one working-directory assumption.
	candidates := []string{
		filepath.Join("..", "htmltrust-canonicalization", "conformance", "vectors", "vector-01.json"),
		filepath.Join("..", "..", "htmltrust-canonicalization", "conformance", "vectors", "vector-01.json"),
		filepath.Join("..", "..", "..", "htmltrust-canonicalization", "conformance", "vectors", "vector-01.json"),
	}
	var raw []byte
	var err error
	for _, candidate := range candidates {
		raw, err = os.ReadFile(candidate)
		if err == nil {
			break
		}
	}
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
	ch, err := ClaimsHash(v.Claims)
	if err != nil {
		t.Fatalf("ClaimsHash: %v", err)
	}
	if ch != v.ClaimsHash {
		t.Errorf("claimsHash: signer produced %s, verifiers expect %s", ch, v.ClaimsHash)
	}
}
