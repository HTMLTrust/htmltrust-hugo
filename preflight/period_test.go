package preflight

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

func buildTestDoc(t *testing.T, identity string, anchorPub ed25519.PublicKey, periods map[int]ed25519.PublicKey, revoked map[int]bool) *perioddid.Document {
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

func writeTestDoc(t *testing.T, doc *perioddid.Document) string {
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

func TestWithPeriodReport_MatchAndPublishedAhead(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p2Pub, p2Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p3Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p5Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDoc(t, identity, anchorPub, map[int]ed25519.PublicKey{2: p2Pub, 3: p3Pub, 5: p5Pub}, nil)
	docPath := writeTestDoc(t, doc)

	report := DirectoryReport{Profile: profile, Root: "public", Domain: "https://example.com"}
	out, err := WithPeriodReport(report, Options{PrivateKey: p2Priv, Identity: identity, DIDDocument: docPath})
	if err != nil {
		t.Fatalf("WithPeriodReport: %v", err)
	}
	if out.Period == nil {
		t.Fatal("Period is nil")
	}
	if out.Period.PeriodKeyMatched == nil || !*out.Period.PeriodKeyMatched {
		t.Fatal("PeriodKeyMatched = false or nil, want true")
	}
	if out.Period.PeriodIndex == nil || *out.Period.PeriodIndex != 2 {
		t.Fatalf("PeriodIndex = %v, want 2", out.Period.PeriodIndex)
	}
	// Periods 3 and 5 are ahead of 2; period 2 itself is not "ahead".
	if out.Period.PeriodsPublishedAhead == nil || *out.Period.PeriodsPublishedAhead != 2 {
		t.Fatalf("PeriodsPublishedAhead = %v, want 2", out.Period.PeriodsPublishedAhead)
	}
	if out.Period.LedgerReplayed != nil {
		t.Fatal("LedgerReplayed should be nil when no ledger was given")
	}

	// Round-trips through JSON with the field present.
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonHasKey(t, encoded, "period") {
		t.Fatal("encoded report has no \"period\" member")
	}
}

func TestWithPeriodReport_NoKeyLeavesPeriodNil(t *testing.T) {
	report := DirectoryReport{Profile: profile, Root: "public", Domain: "https://example.com"}
	out, err := WithPeriodReport(report, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Period != nil {
		t.Fatal("Period should be nil when no private key was given")
	}
}

func TestWithPeriodReport_NoMatch(t *testing.T) {
	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDoc(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub}, nil)
	docPath := writeTestDoc(t, doc)

	_, unrelatedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	report := DirectoryReport{Profile: profile, Root: "public", Domain: "https://example.com"}
	out, err := WithPeriodReport(report, Options{PrivateKey: unrelatedPriv, Identity: identity, DIDDocument: docPath})
	if err != nil {
		t.Fatalf("WithPeriodReport: %v", err)
	}
	if out.Period == nil || out.Period.PeriodKeyMatched == nil || *out.Period.PeriodKeyMatched {
		t.Fatal("PeriodKeyMatched should be false for an unrelated key")
	}
}

func TestWithPeriodReport_LedgerReplayedCount(t *testing.T) {
	dir := t.TempDir()
	pageDir := filepath.Join(dir, "essay")
	if err := os.MkdirAll(pageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pageHTML := `<!DOCTYPE html><html><body>
<signed-section>
<meta name="signed-at" content="2026-01-15T12:00:00Z">
<p>Stable content that will not change.</p>
</signed-section>
</body></html>`
	if err := os.WriteFile(filepath.Join(pageDir, "index.html"), []byte(pageHTML), 0o644); err != nil {
		t.Fatal(err)
	}

	identity := "did:web:example.com"
	anchorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p1Pub, p1Priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := buildTestDoc(t, identity, anchorPub, map[int]ed25519.PublicKey{1: p1Pub}, nil)
	docPath := writeTestDoc(t, doc)

	report, err := PreflightDirectory(dir, "https://example.com")
	if err != nil {
		t.Fatalf("PreflightDirectory: %v", err)
	}
	if len(report.Files) != 1 || len(report.Files[0].Document.Regions) != 1 {
		t.Fatalf("unexpected report shape: %+v", report)
	}
	region := report.Files[0].Document.Regions[0]
	pageURL := report.Files[0].Document.URL

	contentHash := "sha256:" + perioddid.HashSHA256B64([]byte(region.CanonicalText))
	claimsNoSignedAt := map[string]string{}
	claimsHashNoSignedAt := "sha256:" + perioddid.HashSHA256B64([]byte(mustCanonicalizeClaims(t, claimsNoSignedAt)))

	ledgerJSON := `[{"location":"` + pageURL + `","contentHash":"` + contentHash + `","claimsHashNoSignedAt":"` + claimsHashNoSignedAt + `","keyid":"` + identity + `#p1"}]`
	ledgerPath := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(ledgerPath, []byte(ledgerJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := WithPeriodReport(report, Options{PrivateKey: p1Priv, Identity: identity, DIDDocument: docPath, Ledger: ledgerPath})
	if err != nil {
		t.Fatalf("WithPeriodReport: %v", err)
	}
	if out.Period.LedgerReplayed == nil || *out.Period.LedgerReplayed != 1 {
		t.Fatalf("LedgerReplayed = %v, want 1", out.Period.LedgerReplayed)
	}
}

func mustCanonicalizeClaims(t *testing.T, claims map[string]string) string {
	t.Helper()
	s, err := canon.CanonicalizeClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jsonHasKey(t *testing.T, data []byte, key string) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	_, ok := m[key]
	return ok
}
