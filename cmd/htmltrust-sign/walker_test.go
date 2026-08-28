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
<meta name="author" content="Alice Example">
<meta name="signed-at" content="2026-05-12T20:00:00Z">
<meta name="claim:ContentType" content="Article">
<p>Hello world.</p>
</signed-section></body></html>`)

	out, n, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Algorithm:  "ed25519",
		Domain:     "https://www.htmltrust.org",
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
		`profile="htmltrust-signature-v1"`,
		`signature-scope="url"`,
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
	claims := map[string]string{
		"author":            "Alice Example",
		"signed-at":         "2026-05-12T20:00:00Z",
		"claim:ContentType": "Article",
	}
	claimsHash, err := ClaimsHash(claims)
	if err != nil {
		t.Fatalf("ClaimsHash: %v", err)
	}
	binding, err := canon.BuildSigningPayloadV1(canon.SigningProfileV1Input{ContentHash: contentHash, ClaimsHash: claimsHash, DocumentURL: "https://www.htmltrust.org/", Scope: "url", KeyID: "did:web:jason-grey.com", Algorithm: "ed25519", SignedAt: "2026-05-12T20:00:00Z"})
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
		Domain:     "https://www.htmltrust.org",
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
		Domain:           "https://www.htmltrust.org",
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
		Domain:     "https://www.htmltrust.org",
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
		Domain:     "https://www.htmltrust.org",
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

func TestSignHTML_NormalizesBareDomainToOrigin(t *testing.T) {
	_, priv, pubPEM := testKey(t)
	input := []byte(`<html><body><signed-section>
<meta name="signed-at" content="2026-05-12T20:00:00Z">
<p>Hello world.</p>
</signed-section></body></html>`)

	out, _, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "WWW.HTMLTRUST.ORG",
	})
	if err != nil {
		t.Fatalf("SignHTML: %v", err)
	}
	s := string(out)
	contentHash := mustGrepAttr(t, s, "content-hash")
	signature := mustGrepAttr(t, s, "signature")
	claimsHash, err := ClaimsHash(map[string]string{"signed-at": "2026-05-12T20:00:00Z"})
	if err != nil {
		t.Fatalf("ClaimsHash: %v", err)
	}
	binding, err := canon.BuildSigningPayloadV1(canon.SigningProfileV1Input{ContentHash: contentHash, ClaimsHash: claimsHash, DocumentURL: "https://www.htmltrust.org/", Scope: "url", KeyID: "did:web:jason-grey.com", Algorithm: "ed25519", SignedAt: "2026-05-12T20:00:00Z"})
	if err != nil {
		t.Fatalf("BuildSignatureBinding: %v", err)
	}
	ok, err := canon.VerifySignature(binding, signature, pubPEM, "ed25519")
	if err != nil {
		t.Fatalf("VerifySignature err: %v", err)
	}
	if !ok {
		t.Fatalf("signature did not verify against normalized origin")
	}
}

func TestSignHTML_RejectsOriginWithPath(t *testing.T) {
	_, priv, _ := testKey(t)
	input := []byte(`<html><body><signed-section><meta name="signed-at" content="2026-05-12T20:00:00Z"><p>x</p></signed-section></body></html>`)
	_, _, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "https://www.htmltrust.org/posts",
	})
	if err == nil {
		t.Fatalf("expected origin with path to fail")
	}
}

func TestSignHTML_RejectsHTTPOriginForV1(t *testing.T) {
	_, priv, _ := testKey(t)
	input := []byte(`<html><body><signed-section><meta name="signed-at" content="2026-05-12T20:00:00Z"><p>x</p></signed-section></body></html>`)
	_, _, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "http://www.htmltrust.org",
	})
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("expected an HTTPS requirement error, got %v", err)
	}
}

func TestSignHTML_SupportsOriginScope(t *testing.T) {
	_, priv, pubPEM := testKey(t)
	input := []byte(`<html><body><signed-section><meta name="signed-at" content="2026-05-12T20:00:00Z"><p>x</p></signed-section></body></html>`)
	out, _, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "https://www.htmltrust.org",
		BaseURL:    "https://www.htmltrust.org/posts/one/",
		Scope:      "origin",
	})
	if err != nil {
		t.Fatalf("SignHTML: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `signature-scope="origin"`) {
		t.Fatalf("output missing origin scope: %s", s)
	}
	contentHash := mustGrepAttr(t, s, "content-hash")
	claimsHash, err := ClaimsHash(map[string]string{"signed-at": "2026-05-12T20:00:00Z"})
	if err != nil {
		t.Fatalf("ClaimsHash: %v", err)
	}
	payload, err := canon.BuildSigningPayloadV1(canon.SigningProfileV1Input{
		ContentHash: contentHash, ClaimsHash: claimsHash,
		DocumentURL: "https://www.htmltrust.org/posts/one/", Scope: "origin",
		KeyID: "did:web:jason-grey.com", Algorithm: "ed25519", SignedAt: "2026-05-12T20:00:00Z",
	})
	if err != nil {
		t.Fatalf("BuildSigningPayloadV1: %v", err)
	}
	ok, err := canon.VerifySignature(payload, mustGrepAttr(t, s, "signature"), pubPEM, "ed25519")
	if err != nil || !ok {
		t.Fatalf("origin-scope signature verification = %v, %v", ok, err)
	}
}

func TestSignHTML_SignsAuthorSignedAtAndClaimMeta(t *testing.T) {
	_, priv, pubPEM := testKey(t)
	input := []byte(`<html><body><signed-section>
<meta name="author" content="Alice Example">
<meta name="signed-at" content="2026-05-12T20:00:00Z">
<meta name="claim:License" content="CC-BY-4.0">
<p>Hello world.</p>
</signed-section></body></html>`)

	out, _, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "https://www.htmltrust.org",
	})
	if err != nil {
		t.Fatalf("SignHTML: %v", err)
	}
	s := string(out)
	contentHash := mustGrepAttr(t, s, "content-hash")
	signature := mustGrepAttr(t, s, "signature")
	claimsHash, err := ClaimsHash(map[string]string{
		"author":        "Alice Example",
		"signed-at":     "2026-05-12T20:00:00Z",
		"claim:License": "CC-BY-4.0",
	})
	if err != nil {
		t.Fatalf("ClaimsHash: %v", err)
	}
	binding, err := canon.BuildSigningPayloadV1(canon.SigningProfileV1Input{ContentHash: contentHash, ClaimsHash: claimsHash, DocumentURL: "https://www.htmltrust.org/", Scope: "url", KeyID: "did:web:jason-grey.com", Algorithm: "ed25519", SignedAt: "2026-05-12T20:00:00Z"})
	if err != nil {
		t.Fatalf("BuildSignatureBinding: %v", err)
	}
	ok, err := canon.VerifySignature(binding, signature, pubPEM, "ed25519")
	if err != nil {
		t.Fatalf("VerifySignature err: %v", err)
	}
	if !ok {
		t.Fatalf("signature did not verify with all direct child meta claims")
	}
}

func TestSignHTML_RejectsMalformedClaimMeta(t *testing.T) {
	_, priv, _ := testKey(t)
	input := []byte(`<html><body><signed-section>
<meta name="signed-at" content="2026-05-12T20:00:00Z">
<meta name="author">
<p>Hello world.</p>
</signed-section></body></html>`)
	_, _, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "https://www.htmltrust.org",
	})
	if err == nil {
		t.Fatalf("expected malformed claim meta to fail")
	}
}

func TestSignHTML_RejectsNonUTCSignedAt(t *testing.T) {
	_, priv, _ := testKey(t)
	input := []byte(`<html><body><signed-section>
<meta name="signed-at" content="2026-05-12T15:00:00-05:00">
<p>Hello world.</p>
</signed-section></body></html>`)
	_, _, err := SignHTML(input, SignerConfig{
		PrivateKey: priv,
		Keyid:      "did:web:jason-grey.com",
		Domain:     "https://www.htmltrust.org",
	})
	if err == nil {
		t.Fatalf("expected non-UTC signed-at to fail")
	}
}

func TestContentHash_IncludesSignedSemanticAttributes(t *testing.T) {
	body := `<p><a href="/docs">Read</a><img src="hero.png" alt="Hero" aria-label="Hero image"></p>`
	withoutAttrs := `<p><a href="/docs">Read</a><img></p>`
	withHash, err := ContentHash(body, "https://www.htmltrust.org/posts/one/")
	if err != nil {
		t.Fatalf("ContentHash with attrs: %v", err)
	}
	withoutHash, err := ContentHash(withoutAttrs, "https://www.htmltrust.org/posts/one/")
	if err != nil {
		t.Fatalf("ContentHash without attrs: %v", err)
	}
	if withHash == withoutHash {
		t.Fatalf("semantic attributes did not affect content hash: %s", withHash)
	}

	canonical, err := canon.ExtractCanonicalText(body, canon.Options{BaseURL: "https://www.htmltrust.org/posts/one/"})
	if err != nil {
		t.Fatalf("ExtractCanonicalText: %v", err)
	}
	for _, want := range []string{
		"@attr:a:href:https://www.htmltrust.org/docs\n",
		"@attr:img:src:https://www.htmltrust.org/posts/one/hero.png\n",
		"@attr:img:alt:Hero\n",
		"@attr:img:aria-label:Hero image",
	} {
		if !strings.Contains(canonical, want) {
			t.Fatalf("canonical content missing %q in %q", want, canonical)
		}
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
