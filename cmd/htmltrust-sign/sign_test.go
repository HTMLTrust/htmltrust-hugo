package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
)

func TestHashSHA256B64_PrefixedAndUnpadded(t *testing.T) {
	h := hashSHA256B64("hello world")
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("hash missing sha256: prefix: %q", h)
	}
	body := strings.TrimPrefix(h, "sha256:")
	if strings.ContainsRune(body, '=') {
		t.Fatalf("hash body must be unpadded base64, got %q", body)
	}
	// Decode and verify length is 32 bytes.
	raw, err := base64.RawStdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("body not valid raw base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32-byte SHA-256, got %d bytes", len(raw))
	}
}

func TestContentHash_StripsMetaAndCanonicalizes(t *testing.T) {
	// The inner HTML of a signed-section includes <meta> claim tags and the
	// actual content. ExtractCanonicalText must strip the <meta> tags so they
	// don't end up in the content hash. Different meta tags must yield the
	// SAME content hash if the body text is identical.
	html1 := `<meta name="claim:License" content="MIT"><p>Hello world.</p>`
	html2 := `<meta name="claim:License" content="CC-BY-4.0"><p>Hello world.</p>`
	h1, err := ContentHash(html1)
	if err != nil {
		t.Fatalf("ContentHash(html1) error: %v", err)
	}
	h2, err := ContentHash(html2)
	if err != nil {
		t.Fatalf("ContentHash(html2) error: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("meta tags affected content hash:\n  h1=%s\n  h2=%s", h1, h2)
	}
}

func TestContentHash_NormalizesQuotesAndDashes(t *testing.T) {
	// Curly vs straight quotes, em dash vs hyphen — must hash identically per
	// the canonicalization spec.
	htmlCurly := `<p>“Hello” — world.</p>`
	htmlStraight := `<p>"Hello" - world.</p>`
	hc, err := ContentHash(htmlCurly)
	if err != nil {
		t.Fatalf("curly: %v", err)
	}
	hs, err := ContentHash(htmlStraight)
	if err != nil {
		t.Fatalf("straight: %v", err)
	}
	if hc != hs {
		t.Fatalf("curly vs straight quotes hashed differently:\n  curly=%s\n  straight=%s", hc, hs)
	}
}

func TestClaimsHash_OrderIndependent(t *testing.T) {
	a := map[string]string{"License": "MIT", "ContentType": "Article"}
	b := map[string]string{"ContentType": "Article", "License": "MIT"}
	if ClaimsHash(a) != ClaimsHash(b) {
		t.Fatalf("ClaimsHash should be order-independent")
	}
}

func TestClaimsHash_EmptyMap(t *testing.T) {
	// An empty map should still produce a well-formed hash, not error.
	h := ClaimsHash(map[string]string{})
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("empty claims hash malformed: %q", h)
	}
}

func TestSignAndVerifyRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	binding := "sha256:abc:sha256:def:example.com:2026-05-12T20:00:00Z"
	sigB64 := SignEd25519(binding, priv)
	if strings.ContainsRune(sigB64, '=') {
		t.Fatalf("signature must be unpadded base64, got %q", sigB64)
	}
	// Roundtrip through the canonicalize library's verifier to confirm
	// cross-implementation compatibility.
	pubPEM, err := encodePublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("encode pub: %v", err)
	}
	ok, err := canon.VerifySignature(binding, sigB64, pubPEM, "ed25519")
	if err != nil {
		t.Fatalf("VerifySignature err: %v", err)
	}
	if !ok {
		t.Fatalf("VerifySignature returned false on valid signature")
	}
}

func TestLoadEd25519PrivateKey_Roundtrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	loaded, err := LoadEd25519PrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKey: %v", err)
	}
	if !loaded.Equal(priv) {
		t.Fatalf("loaded key does not match generated key")
	}
}

// encodePublicKeyPEM is a test helper.
func encodePublicKeyPEM(pub ed25519.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})), nil
}
