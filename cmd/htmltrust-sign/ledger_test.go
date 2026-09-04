package main

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"golang.org/x/net/html"
)

// extractLedgerEntryForTest reads the signed attributes off the first
// signed-section in htmlBytes and rebuilds the LedgerEntry a real run would
// have written for it, so tests can seed a ledger from a prior signing
// pass without hand-computing hashes.
func extractLedgerEntryForTest(t *testing.T, htmlBytes []byte, location string) LedgerEntry {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(htmlBytes))
	if err != nil {
		t.Fatal(err)
	}
	var found *html.Node
	walk(doc, func(n *html.Node) {
		if found != nil {
			return
		}
		if isSignedSection(n) {
			found = n
		}
	})
	if found == nil {
		t.Fatal("no signed-section found in signed output")
	}
	claims, err := collectDirectClaims(found)
	if err != nil {
		t.Fatal(err)
	}
	claimsNoSignedAt := make(map[string]string, len(claims))
	for k, v := range claims {
		if k != "signed-at" {
			claimsNoSignedAt[k] = v
		}
	}
	claimsHashNoSignedAt, err := ClaimsHash(claimsNoSignedAt)
	if err != nil {
		t.Fatal(err)
	}
	claimsHash, err := ClaimsHash(claims)
	if err != nil {
		t.Fatal(err)
	}
	return LedgerEntry{
		Location:             location,
		ContentHash:          getAttr(found, "content-hash"),
		ClaimsHash:           claimsHash,
		ClaimsHashNoSignedAt: claimsHashNoSignedAt,
		SignedAt:             claims["signed-at"],
		Keyid:                getAttr(found, "keyid"),
		Algorithm:            getAttr(found, "algorithm"),
		Scope:                getAttr(found, "signature-scope"),
		Profile:              getAttr(found, "profile"),
		Signature:            getAttr(found, "signature"),
	}
}

func TestSignHTML_LedgerReplaysUnchangedSection(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1Pub, p1Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDocument(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub}, nil)

	src := []byte(sprintfHTML("Hello world"))
	cfg := SignerConfig{
		PrivateKey:  p1Priv,
		Keyid:       identity + "#p1",
		Algorithm:   "ed25519",
		Scope:       "url",
		Domain:      "https://example.com",
		BaseURL:     "https://example.com/page/",
		DIDDocument: doc,
	}

	firstOut, n, err := SignHTML(src, cfg)
	if err != nil || n != 1 {
		t.Fatalf("first sign: n=%d err=%v", n, err)
	}
	entry := extractLedgerEntryForTest(t, firstOut, cfg.BaseURL)

	ledger := NewLedger()
	ledger.Set(entry)
	counts := &LedgerCounts{}
	replayCfg := cfg
	replayCfg.Ledger = ledger
	replayCfg.Counts = counts

	secondOut, n2, err := SignHTML(src, replayCfg)
	if err != nil || n2 != 1 {
		t.Fatalf("second sign: n=%d err=%v", n2, err)
	}
	if !bytes.Equal(secondOut, firstOut) {
		t.Fatalf("replayed output differs from the original:\n got  %s\nwant %s", secondOut, firstOut)
	}
	if counts.Replayed != 1 || counts.Signed() != 0 || counts.Replaced != 0 {
		t.Fatalf("counts = %+v, want Replayed=1 Signed=0 Replaced=0", counts)
	}
}

func TestSignHTML_LedgerSignsFreshOnChangedContent(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1Pub, p1Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDocument(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub}, nil)

	cfg := SignerConfig{
		PrivateKey:  p1Priv,
		Keyid:       identity + "#p1",
		Algorithm:   "ed25519",
		Scope:       "url",
		Domain:      "https://example.com",
		BaseURL:     "https://example.com/page/",
		DIDDocument: doc,
	}

	firstOut, _, err := SignHTML([]byte(sprintfHTML("Hello world")), cfg)
	if err != nil {
		t.Fatal(err)
	}
	entry := extractLedgerEntryForTest(t, firstOut, cfg.BaseURL)

	ledger := NewLedger()
	ledger.Set(entry)
	counts := &LedgerCounts{}
	cfg2 := cfg
	cfg2.Ledger = ledger
	cfg2.Counts = counts

	secondOut, n, err := SignHTML([]byte(sprintfHTML("Hello world, updated")), cfg2)
	if err != nil || n != 1 {
		t.Fatalf("second sign: n=%d err=%v", n, err)
	}
	if counts.Replayed != 0 {
		t.Errorf("counts.Replayed = %d, want 0 (content changed)", counts.Replayed)
	}
	if counts.Replaced != 1 {
		t.Errorf("counts.Replaced = %d, want 1", counts.Replaced)
	}
	newEntry := extractLedgerEntryForTest(t, secondOut, cfg.BaseURL)
	if newEntry.ContentHash == entry.ContentHash {
		t.Error("expected a different content hash for changed content")
	}
	if newEntry.Signature == entry.Signature {
		t.Error("expected a different signature for changed content")
	}
}

func TestSignHTML_LedgerStruckPeriodForcesResign(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1Pub, p1Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p2Pub, p2Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	docBefore := buildTestDocument(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub, 2: p2Pub}, nil)

	src := []byte(sprintfHTML("Hello world"))
	cfg1 := SignerConfig{
		PrivateKey:  p1Priv,
		Keyid:       identity + "#p1",
		Algorithm:   "ed25519",
		Scope:       "url",
		Domain:      "https://example.com",
		BaseURL:     "https://example.com/page/",
		DIDDocument: docBefore,
	}
	firstOut, _, err := SignHTML(src, cfg1)
	if err != nil {
		t.Fatal(err)
	}
	entry := extractLedgerEntryForTest(t, firstOut, cfg1.BaseURL)

	// Period 1 is now struck; period 2 is the currently active key. The
	// content is UNCHANGED, but replay must still be refused because the
	// entry's period is revoked in the DID document.
	docAfter := buildTestDocument(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub, 2: p2Pub}, map[int]bool{1: true})

	ledger := NewLedger()
	ledger.Set(entry)
	counts := &LedgerCounts{}
	cfg2 := SignerConfig{
		PrivateKey:  p2Priv,
		Keyid:       identity + "#p2",
		Algorithm:   "ed25519",
		Scope:       "url",
		Domain:      "https://example.com",
		BaseURL:     cfg1.BaseURL,
		DIDDocument: docAfter,
		Ledger:      ledger,
		Counts:      counts,
	}
	secondOut, n, err := SignHTML(src, cfg2)
	if err != nil || n != 1 {
		t.Fatalf("second sign: n=%d err=%v", n, err)
	}
	if counts.Replayed != 0 {
		t.Errorf("counts.Replayed = %d, want 0 (period struck)", counts.Replayed)
	}
	if counts.Replaced != 1 {
		t.Errorf("counts.Replaced = %d, want 1", counts.Replaced)
	}
	newEntry := extractLedgerEntryForTest(t, secondOut, cfg2.BaseURL)
	want := identity + "#p2"
	if newEntry.Keyid != want {
		t.Errorf("re-signed keyid = %q, want %q", newEntry.Keyid, want)
	}
	if newEntry.Signature == entry.Signature {
		t.Error("expected a different signature after forced re-sign under a new key")
	}
}

func TestReplayEligible_ForceResignRange(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p2Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDocument(t, identity, anchorPub, map[int]ed25519.PublicKey{2: p2Pub}, nil)

	entry := LedgerEntry{
		Location: "https://example.com/page/", Keyid: identity + "#p2",
		ContentHash: "sha256:x", ClaimsHashNoSignedAt: "sha256:y",
	}
	// Without a forced range, content/claims match but there is no
	// signature to verify, so eligibility fails for an unrelated reason;
	// what we're checking here is that a forced range short-circuits
	// eligibility before that point.
	ok, reason := replayEligible(entry, "sha256:x", "sha256:y", doc, 1, 3)
	if ok {
		t.Fatal("expected replay to be refused: period 2 is inside the forced --resign-periods range")
	}
	if reason != "forced re-sign (--resign-periods)" {
		t.Errorf("reason = %q, want the forced-resign reason", reason)
	}
}

func sprintfHTML(text string) string {
	return "<html><body><signed-section data-htmltrust-placeholder=\"true\"><meta name=\"signed-at\" content=\"2026-01-15T12:00:00Z\"><p>" + text + "</p></signed-section></body></html>"
}
