package preflight

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

// PeriodReport carries period-key and signature-ledger information for a
// preflight run (spec draft §9.10 tooling). Every field is a pointer so it
// is omitted from JSON entirely, rather than reported as a misleading zero
// value, when the corresponding input was not supplied.
type PeriodReport struct {
	// PeriodKeyMatched reports whether Options.PrivateKey's public half
	// matched a verificationMethod in the DID document at all.
	PeriodKeyMatched *bool `json:"periodKeyMatched,omitempty"`
	// PeriodIndex is the matched period (0 for an anchor match).
	PeriodIndex *int `json:"periodIndex,omitempty"`
	// PeriodsPublishedAhead counts published period methods with an index
	// greater than PeriodIndex (every published period, when the match was
	// an anchor or there was no match).
	PeriodsPublishedAhead *int `json:"periodsPublishedAhead,omitempty"`
	// LedgerReplayed counts signed regions whose content and claims (apart
	// from signed-at) match an entry in Options.Ledger for their page,
	// whose entry's keyid resolves to a method that is not struck. This
	// approximates htmltrust-sign's own replay decision but, unlike the
	// signer, does not re-verify the stored signature; only present when
	// Options.Ledger was given.
	LedgerReplayed *int `json:"ledgerReplayed,omitempty"`
}

// Options configures optional period-key and signature-ledger reporting for
// WithPeriodReport.
type Options struct {
	// PrivateKey, if set, enables PeriodKeyMatched, PeriodIndex, and
	// PeriodsPublishedAhead by matching its public half against the
	// identity's DID document exactly as htmltrust-sign's period discovery
	// does.
	PrivateKey ed25519.PrivateKey
	// Identity is the --keyid identity string. Required with PrivateKey.
	Identity string
	// DIDDocument is a URL or local path. Empty derives the default
	// location from Identity, for a did:web identity only.
	DIDDocument string
	// Ledger, if set together with PrivateKey, enables LedgerReplayed: a
	// URL or local path to the signature ledger.
	Ledger string
}

// WithPeriodReport computes a PeriodReport for an already-built
// DirectoryReport and returns a copy with Period set. It is separate from
// PreflightDirectory so a caller with no key material keeps using the
// original, unmodified report shape.
func WithPeriodReport(report DirectoryReport, opts Options) (DirectoryReport, error) {
	if opts.PrivateKey == nil {
		return report, nil
	}
	if opts.Identity == "" {
		return report, errors.New("preflight: Options.Identity is required with Options.PrivateKey")
	}
	pub, ok := opts.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return report, errors.New("preflight: could not derive an Ed25519 public key from Options.PrivateKey")
	}

	source := opts.DIDDocument
	if source == "" {
		derived, err := perioddid.DidWebDocumentURL(opts.Identity)
		if err != nil {
			return report, fmt.Errorf("derive DID document location for %q: %w (pass Options.DIDDocument explicitly)", opts.Identity, err)
		}
		source = derived
	}
	doc, err := perioddid.LoadDocument(source)
	if err != nil {
		return report, fmt.Errorf("load DID document from %s: %w", source, err)
	}

	matched := false
	period := 0
	if m, ok := doc.FindByPublicKey(pub); ok {
		matched = true
		if m.IsPeriod {
			period = int(m.Period)
		}
	}
	ahead := 0
	for _, m := range doc.VerificationMethod {
		frag := strings.TrimPrefix(fragmentOfMethodID(m.ID, doc.ID), "#")
		if n, isPeriod := perioddid.ParsePeriodFragment(frag); isPeriod && int(n) > period {
			ahead++
		}
	}

	pr := &PeriodReport{PeriodKeyMatched: &matched, PeriodIndex: &period, PeriodsPublishedAhead: &ahead}

	if opts.Ledger != "" {
		n, err := countLedgerReplayable(report, opts.Ledger, doc)
		if err != nil {
			return report, fmt.Errorf("ledger: %w", err)
		}
		pr.LedgerReplayed = &n
	}

	report.Period = pr
	return report, nil
}

func fragmentOfMethodID(id, docID string) string {
	if strings.HasPrefix(id, "#") {
		return id
	}
	if strings.HasPrefix(id, docID) {
		return strings.TrimPrefix(id, docID)
	}
	return ""
}

func resolveLedgerMethod(doc *perioddid.Document, keyid string) (*perioddid.Method, bool) {
	if strings.Contains(keyid, "#") {
		return doc.FindMethodByID(keyid)
	}
	if keyid == doc.ID {
		return doc.FirstAnchor()
	}
	return nil, false
}

type ledgerEntry struct {
	Location             string `json:"location"`
	ContentHash          string `json:"contentHash"`
	ClaimsHashNoSignedAt string `json:"claimsHashNoSignedAt"`
	Keyid                string `json:"keyid"`
}

var errLedgerNotFound = errors.New("preflight: ledger not found")

func loadLedgerSource(source string) ([]byte, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s: %w", source, errLedgerNotFound)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: HTTP %d", source, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	}
	b, err := os.ReadFile(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", source, errLedgerNotFound)
		}
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	return b, nil
}

// countLedgerReplayable counts signed regions in report whose page has a
// ledger entry with matching contentHash and claimsHashNoSignedAt, and
// whose entry's keyid resolves to a non-struck method in doc.
func countLedgerReplayable(report DirectoryReport, ledgerSource string, doc *perioddid.Document) (int, error) {
	raw, err := loadLedgerSource(ledgerSource)
	if err != nil {
		if errors.Is(err, errLedgerNotFound) {
			return 0, nil
		}
		return 0, err
	}
	var entries []ledgerEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return 0, fmt.Errorf("parse ledger: %w", err)
	}
	byLocation := make(map[string]ledgerEntry, len(entries))
	for _, e := range entries {
		byLocation[e.Location] = e
	}

	count := 0
	for _, file := range report.Files {
		entry, ok := byLocation[file.Document.URL]
		if !ok {
			continue
		}
		method, ok := resolveLedgerMethod(doc, entry.Keyid)
		if !ok || method.Revoked {
			continue
		}
		for _, region := range file.Document.Regions {
			if region.Status != "pass" {
				continue
			}
			contentHash := "sha256:" + perioddid.HashSHA256B64([]byte(region.CanonicalText))
			if entry.ContentHash != contentHash {
				continue
			}
			claimsNoSignedAt := make(map[string]string, len(region.Claims))
			for k, v := range region.Claims {
				if k != "signed-at" {
					claimsNoSignedAt[k] = v
				}
			}
			canonicalClaims, err := canon.CanonicalizeClaims(claimsNoSignedAt)
			if err != nil {
				continue
			}
			claimsHashNoSignedAt := "sha256:" + perioddid.HashSHA256B64([]byte(canonicalClaims))
			if entry.ClaimsHashNoSignedAt == claimsHashNoSignedAt {
				count++
			}
		}
	}
	return count, nil
}
