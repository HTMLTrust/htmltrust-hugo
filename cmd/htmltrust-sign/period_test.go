package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

// buildTestDocument renders an in-memory DID document with one anchor and
// the given period public keys (period -> revoked).
func buildTestDocument(t *testing.T, identity string, anchorPub ed25519.PublicKey, periods map[int]ed25519.PublicKey, revoked map[int]bool) *perioddid.Document {
	t.Helper()
	anchorPem, err := perioddid.PublicKeySPKIPEM(anchorPub)
	if err != nil {
		t.Fatal(err)
	}
	var specs []perioddid.PeriodSpec
	for n, pub := range periods {
		pem, err := perioddid.PublicKeySPKIPEM(pub)
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, perioddid.PeriodSpec{N: uint32(n), PublicKeyPem: pem, Revoked: revoked[n]})
	}
	doc, err := perioddid.RenderDocument(perioddid.RenderInput{
		Identity: identity,
		Anchors:  []perioddid.AnchorSpec{{Fragment: "#key-1", PublicKeyPem: anchorPem}},
		Periods:  specs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// writeTestDocument writes an in-memory document to a local file, the form
// --did-document accepts for tests.
func writeTestDocument(t *testing.T, doc *perioddid.Document) string {
	t.Helper()
	raw, err := doc.MarshalPretty()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "did.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverPeriod_PeriodMatch(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p3Pub, p3Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDocument(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub, 3: p3Pub}, nil)
	docPath := writeTestDocument(t, doc)

	disc, err := DiscoverPeriod(p3Priv, identity, docPath)
	if err != nil {
		t.Fatalf("DiscoverPeriod: %v", err)
	}
	if disc.Period != 3 {
		t.Errorf("Period = %d, want 3", disc.Period)
	}
	want := identity + "#p3"
	if disc.Keyid != want {
		t.Errorf("Keyid = %q, want %q", disc.Keyid, want)
	}
}

func TestDiscoverPeriod_AnchorFallback(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, anchorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDocument(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub}, nil)
	docPath := writeTestDocument(t, doc)

	disc, err := DiscoverPeriod(anchorPriv, identity, docPath)
	if err != nil {
		t.Fatalf("DiscoverPeriod: %v", err)
	}
	if disc.Period != 0 {
		t.Errorf("Period = %d, want 0", disc.Period)
	}
	if disc.Keyid != identity {
		t.Errorf("Keyid = %q, want bare identity %q", disc.Keyid, identity)
	}
}

func TestDiscoverPeriod_NoMatchRefusal(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDocument(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub}, nil)
	docPath := writeTestDocument(t, doc)

	_, unrelatedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverPeriod(unrelatedPriv, identity, docPath); err == nil {
		t.Fatal("expected an error for a private key matching no verificationMethod")
	}
}

func TestDiscoverPeriod_MissingDocumentRefusal(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := DiscoverPeriod(priv, "did:web:example.com", missing); err == nil {
		t.Fatal("expected an error when the DID document cannot be loaded")
	}
}
