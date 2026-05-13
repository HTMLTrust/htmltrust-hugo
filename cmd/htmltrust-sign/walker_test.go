package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("spki: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	return pub, priv, pubPEM
}

func TestSignHTML_FillsAllRequiredAttrs(t *testing.T) {
	_, priv, pubPEM := testKey(t)
	input := []byte(`<html><body><signed-section content-hash="" signature="" keyid="" algorithm="ed25519">
<meta name="signed-at" content="2026-05-12T20:00:00Z">
<meta name="claim:ContentType" content="Article">
<p>Hello world.</p>
</signed-section></body></html>`)

	out, n, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Algorithm:  "ed25519",
		Domain:     "www.htmltrust.org",
	})
	if err != nil {
		t.Fatalf("SignHTML: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 signed section, got %d", n)
	}

	s := string(out)
	for _, want := range []string{
		`keyid="did:web:jason-grey.com"`,
		`algorithm="ed25519"`,
		`content-hash="sha256:`,
		`signature="`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("output missing %q\nfull output:\n%s", want, s)
		}
	}
	if strings.Contains(s, `data-htmltrust-placeholder`) {
		t.Fatalf("placeholder marker not removed")
	}

	// Pull out attrs and verify the signature actually validates against the
	// binding we expect.
	contentHash := mustGrepAttr(t, s, "content-hash")
	signature := mustGrepAttr(t, s, "signature")
	claims := map[string]string{"ContentType": "Article"}
	claimsHash := ClaimsHash(claims)
	binding, err := canon.BuildSignatureBinding(contentHash, claimsHash, "www.htmltrust.org", "2026-05-12T20:00:00Z")
	if err != nil {
		t.Fatalf("BuildSignatureBinding: %v", err)
	}
	ok, err := canon.VerifySignature(binding, signature, pubPEM, "ed25519")
	if err != nil {
		t.Fatalf("VerifySignature err: %v", err)
	}
	if !ok {
		t.Fatalf("VerifySignature returned false for the just-signed binding")
	}
}

func TestSignHTML_MultipleSectionsInOnePage(t *testing.T) {
	_, priv, _ := testKey(t)
	input := []byte(`<html><body>
<signed-section>
<meta name="signed-at" content="2026-05-12T20:00:00Z">
<p>First.</p>
</signed-section>
<signed-section>
<meta name="signed-at" content="2026-05-12T20:00:00Z">
<p>Second.</p>
</signed-section>
</body></html>`)
	out, n, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Algorithm:  "ed25519",
		Domain:     "www.htmltrust.org",
	})
	if err != nil {
		t.Fatalf("SignHTML: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 signed sections, got %d", n)
	}
	if strings.Count(string(out), `signature="`) < 2 {
		t.Fatalf("expected at least 2 signature attributes; got:\n%s", out)
	}
}

func TestSignHTML_FallbackSignedAtInserted(t *testing.T) {
	_, priv, _ := testKey(t)
	input := []byte(`<html><body><signed-section><p>Body without signed-at meta.</p></signed-section></body></html>`)
	fallback := time.Date(2026, 5, 12, 20, 0, 0, 0, time.UTC)
	out, _, err := SignHTML(input, SignerConfig{
		PrivateKey:       priv,
		Keyid:            "did:web:jason-grey.com",
		Domain:           "www.htmltrust.org",
		SignedAtFallback: fallback,
	})
	if err != nil {
		t.Fatalf("SignHTML: %v", err)
	}
	if !strings.Contains(string(out), `<meta name="signed-at" content="2026-05-12T20:00:00Z"`) {
		t.Fatalf("fallback signed-at not inserted:\n%s", out)
	}
}

func TestSignHTML_ErrorsWhenSignedAtMissingAndNoFallback(t *testing.T) {
	_, priv, _ := testKey(t)
	input := []byte(`<html><body><signed-section><p>x</p></signed-section></body></html>`)
	_, _, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "www.htmltrust.org",
	})
	if err == nil {
		t.Fatalf("expected error when signed-at is missing and no fallback set")
	}
}

func TestSignHTML_IgnoresPagesWithoutSignedSection(t *testing.T) {
	_, priv, _ := testKey(t)
	input := []byte(`<html><body><p>No signed sections here.</p></body></html>`)
	out, n, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "www.htmltrust.org",
	})
	if err != nil {
		t.Fatalf("SignHTML on plain page: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 signed sections, got %d", n)
	}
	if !strings.Contains(string(out), "No signed sections here.") {
		t.Fatalf("body content lost during render")
	}
}

func mustGrepAttr(t *testing.T, s, attr string) string {
	t.Helper()
	prefix := attr + `="`
	i := strings.Index(s, prefix)
	if i < 0 {
		t.Fatalf("attr %q not found in %s", attr, s)
	}
	rest := s[i+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("attr %q unterminated", attr)
	}
	return rest[:end]
}
