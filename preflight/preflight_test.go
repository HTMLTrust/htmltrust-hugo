package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreflightHTMLUsesFirstBaseAndFallsBackForOpaqueURL(t *testing.T) {
	page := `<!doctype html><html><head>
<base href="data:text/html,unsafe"><base href="/assets/"><base href="/later/">
</head><body><signed-section><meta name="author" content="Ada"><p><a href="story">Hello</a></p></signed-section></body></html>`
	report := PreflightHTML([]byte(page), "https://example.org/articles/page.html")
	if !report.OK {
		t.Fatalf("expected report to pass: %#v", report)
	}
	if report.BaseURL != "https://example.org/articles/page.html" {
		t.Fatalf("base URL = %q", report.BaseURL)
	}
	if len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != "base-invalid" || report.Diagnostics[0].Severity != "warning" {
		t.Fatalf("base diagnostics = %#v", report.Diagnostics)
	}
	if len(report.Regions) != 1 || report.Regions[0].CanonicalText != "@attr:a:href:https://example.org/articles/story\nHello" {
		t.Fatalf("regions = %#v", report.Regions)
	}
	if report.Regions[0].CanonicalClaims != "author:Ada\n" {
		t.Fatalf("canonical claims = %q", report.Regions[0].CanonicalClaims)
	}
}

func TestPreflightHTMLKeepsUnsafeHTTPBase(t *testing.T) {
	page := `<html><head><base href="http://unsafe.example/"><base href="https://later.example/"></head><body><signed-section><p><a href="story">bad</a></p></signed-section></body></html>`
	report := PreflightHTML([]byte(page), "https://example.org/page.html")
	if report.BaseURL != "http://unsafe.example/" {
		t.Fatalf("base URL = %q", report.BaseURL)
	}
	if report.OK || len(report.Regions) != 1 || report.Regions[0].Diagnostics[0].Code != "url-policy-violation" {
		t.Fatalf("report = %#v", report)
	}
}

func TestPreflightHTMLKeepsRegionFailuresActionable(t *testing.T) {
	page := `<main><signed-section><p><a href="http://unsafe.example/">bad</a></p></signed-section><signed-section><p>good</p></signed-section></main>`
	report := PreflightHTML([]byte(page), "https://example.org/page.html")
	if report.OK {
		t.Fatal("expected one invalid region to fail the report")
	}
	if len(report.Regions) != 2 || report.Regions[0].Status != "fail" || report.Regions[1].Status != "pass" {
		t.Fatalf("regions = %#v", report.Regions)
	}
	diagnostic := report.Regions[0].Diagnostics[0]
	if diagnostic.Code != "url-policy-violation" || diagnostic.Region != 0 || diagnostic.Hint == "" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestPreflightRejectsRecoveredSignedRegionSource(t *testing.T) {
	for _, page := range []string{
		`<html><body><signed-section><p>unclosed</signed-section></body></html>`,
		`<html><body><signed-section><p title="one" title="two">duplicate</p></signed-section></body></html>`,
		`<html><body><signed-section title="unterminated><p>malformed</p></signed-section></body></html>`,
	} {
		report := PreflightHTML([]byte(page), "https://example.org/page.html")
		if report.OK || len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != "parser-profile-unsupported" {
			t.Fatalf("expected parser rejection, got %#v", report)
		}
	}
}

func TestPreflightClaimsStayWithTheirDirectSection(t *testing.T) {
	page := `<html><body><signed-section><meta name="author" content="outer"><signed-section><meta name="author" content="inner"><p>inner</p></signed-section><meta name="license" content="CC-BY"></signed-section></body></html>`
	report := PreflightHTML([]byte(page), "https://example.org/page.html")
	if !report.OK || len(report.Regions) != 2 {
		t.Fatalf("report = %#v", report)
	}
	if report.Regions[0].CanonicalClaims != "author:outer\nlicense:CC-BY\n" {
		t.Fatalf("outer claims = %q", report.Regions[0].CanonicalClaims)
	}
	if report.Regions[1].CanonicalClaims != "author:inner\n" {
		t.Fatalf("inner claims = %q", report.Regions[1].CanonicalClaims)
	}
}

func TestPreflightEnforcesCompleteDocumentByteCeiling(t *testing.T) {
	opening := `<html><body>`
	section := `<signed-section><p>x</p></signed-section>`
	closing := `</body></html>`
	padding := strings.Repeat("x", maxDocumentBytes-len(opening)-len(section)-len(closing))
	exact := opening + section + padding + closing
	if len(exact) != maxDocumentBytes {
		t.Fatalf("test document size = %d", len(exact))
	}
	if report := PreflightHTML([]byte(exact), "https://example.org/page.html"); !report.OK {
		t.Fatalf("exact-limit document rejected: %#v", report)
	}
	over := opening + section + strings.Repeat("x", maxDocumentBytes-len(opening)-len(section)-len(closing)+1) + closing
	report := PreflightHTML([]byte(over), "https://example.org/page.html")
	if report.OK || len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != "resource-limit-exceeded" {
		t.Fatalf("over-limit report = %#v", report)
	}
}

func TestPreflightDirectoryAndPageURL(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "posts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(`<signed-section><p>home</p></signed-section>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "posts", "index.html"), []byte(`<p>plain page</p>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := PageURL("https://example.org", root, filepath.Join(root, "posts", "index.html")); err != nil || got != "https://example.org/posts/" {
		t.Fatalf("PageURL = %q, %v", got, err)
	}
	if got, err := PageURL("https://example.org", root, filepath.Join(root, "post#?.html")); err != nil || got != "https://example.org/post%23%3F.html" {
		t.Fatalf("escaped PageURL = %q, %v", got, err)
	}
	report, err := PreflightDirectory(root, "https://example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Files) != 2 {
		t.Fatalf("directory report = %#v", report)
	}
}

func TestPreflightRejectsInvalidDocumentURL(t *testing.T) {
	report := PreflightHTML([]byte(`<signed-section><p>x</p></signed-section>`), "http://example.org/page.html")
	if report.OK || len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != "document-url-invalid" {
		t.Fatalf("report = %#v", report)
	}
}
