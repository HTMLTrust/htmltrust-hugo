package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
	"golang.org/x/net/html"
)

// LedgerEntry is one page's signature record. ClaimsHash matches the actual
// signed payload exactly (it includes signed-at, per the base v1 profile);
// ClaimsHashNoSignedAt is a second hash, over the same claims with
// signed-at removed, that exists solely so a later run can tell "claims
// unchanged, only signed-at would differ" apart from "claims changed"
// using only stored hashes -- the tooling spec describes this replay
// condition but not a wire format for it, so this is this signer's own
// choice, private to this file's read/write round trip.
type LedgerEntry struct {
	Location             string `json:"location"`
	ContentHash          string `json:"contentHash"`
	ClaimsHash           string `json:"claimsHash"`
	ClaimsHashNoSignedAt string `json:"claimsHashNoSignedAt"`
	SignedAt             string `json:"signedAt"`
	Keyid                string `json:"keyid"`
	Algorithm            string `json:"algorithm"`
	Scope                string `json:"scope"`
	Profile              string `json:"profile"`
	Signature            string `json:"signature"`
}

// Ledger is the in-memory form of the signature ledger, keyed by location
// (a page carrying more than one signed-section shares one ledger entry
// across them, keyed by the last one processed; every shipped template
// signs exactly one section per page).
type Ledger struct {
	entries map[string]LedgerEntry
}

func NewLedger() *Ledger {
	return &Ledger{entries: map[string]LedgerEntry{}}
}

func (l *Ledger) Get(location string) (LedgerEntry, bool) {
	e, ok := l.entries[location]
	return e, ok
}

func (l *Ledger) Set(e LedgerEntry) {
	l.entries[e.Location] = e
}

func (l *Ledger) Len() int {
	return len(l.entries)
}

// ParseLedger parses a ledger file: a JSON array of LedgerEntry.
func ParseLedger(raw []byte) (*Ledger, error) {
	var list []LedgerEntry
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parse ledger: %w", err)
	}
	l := NewLedger()
	for _, e := range list {
		l.entries[e.Location] = e
	}
	return l, nil
}

// MarshalIndent renders the ledger as an indented JSON array, sorted by
// location for a deterministic, diff-friendly file.
func (l *Ledger) MarshalIndent() ([]byte, error) {
	list := make([]LedgerEntry, 0, len(l.entries))
	for _, e := range l.entries {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Location < list[j].Location })
	return json.MarshalIndent(list, "", "  ")
}

// LedgerCounts accumulates the run's replay/sign counts across every file
// and section processed, for the final "replayed R, signed S, replaced X"
// line and the mass-resign guard.
type LedgerCounts struct {
	Replayed int
	FreshNew int
	Replaced int
}

// Signed is the total number of sections signed fresh this run (both those
// with no prior ledger entry and those replacing one).
func (c *LedgerCounts) Signed() int { return c.FreshNew + c.Replaced }

// errLedgerNotFound distinguishes "no ledger has ever been published" (a
// local 404, or a missing local file) from every other fetch failure.
var errLedgerNotFound = errors.New("ledger not found")

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

// LoadLedger fetches and parses the ledger at source. allowFresh governs
// what happens on a non-404 failure: exit with that error unless
// allowFresh is true, in which case start fresh exactly as on a 404.
func LoadLedger(source string, allowFresh bool) (l *Ledger, wasFresh bool, err error) {
	raw, err := loadLedgerSource(source)
	if err != nil {
		if errors.Is(err, errLedgerNotFound) {
			return NewLedger(), true, nil
		}
		if allowFresh {
			fmt.Fprintf(os.Stderr, "htmltrust-sign: warning: could not fetch ledger %s (%v); starting from an empty ledger because --allow-fresh-ledger was given\n", source, err)
			return NewLedger(), true, nil
		}
		return nil, false, err
	}
	l, err = ParseLedger(raw)
	if err != nil {
		return nil, false, err
	}
	return l, false, nil
}

// resolveLedgerMethod resolves a stored entry's keyid against a DID
// document: an exact verificationMethod id for a fragment keyid, or the
// first anchor for a bare-identity keyid (spec §9.10 verifier algorithm,
// kinds "period"/"anchor" and "bare").
func resolveLedgerMethod(doc *perioddid.Document, keyid string) (*perioddid.Method, bool) {
	if strings.Contains(keyid, "#") {
		return doc.FindMethodByID(keyid)
	}
	if keyid == doc.ID {
		return doc.FirstAnchor()
	}
	return nil, false
}

func keyidPeriod(keyid string) (int, bool) {
	idx := strings.LastIndexByte(keyid, '#')
	if idx == -1 {
		return 0, false
	}
	n, ok := perioddid.ParsePeriodFragment(keyid[idx+1:])
	if !ok {
		return 0, false
	}
	return int(n), true
}

// ParseResignRange parses --resign-periods "c-d". An empty string returns
// (0, 0, nil), which forceReplayRange below treats as "no forced range".
func ParseResignRange(s string) (from, to int, err error) {
	if s == "" {
		return 0, 0, nil
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("--resign-periods must be c-d, got %q", s)
	}
	from, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	to, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || from < 1 || to < from {
		return 0, 0, fmt.Errorf("--resign-periods must be c-d with 1 <= c <= d, got %q", s)
	}
	return from, to, nil
}

// replayEligible reports whether a stored ledger entry may be replayed
// (tooling spec, "htmltrust-sign: signature ledger"): content and claims
// apart from signed-at are unchanged, the entry is not inside a forced
// --resign-periods range, its period is not struck, and its signature
// verifies under that period's public key from the DID document.
func replayEligible(entry LedgerEntry, freshContentHash, freshClaimsHashNoSignedAt string, doc *perioddid.Document, forceFrom, forceTo int) (bool, string) {
	if entry.ContentHash != freshContentHash {
		return false, "content changed"
	}
	if entry.ClaimsHashNoSignedAt != freshClaimsHashNoSignedAt {
		return false, "claims changed"
	}
	if forceTo > 0 {
		if p, ok := keyidPeriod(entry.Keyid); ok && p >= forceFrom && p <= forceTo {
			return false, "forced re-sign (--resign-periods)"
		}
	}
	method, ok := resolveLedgerMethod(doc, entry.Keyid)
	if !ok {
		return false, "keyid no longer resolves in the DID document"
	}
	if method.Revoked {
		return false, "period struck"
	}
	pub, err := perioddid.ParseSPKIPEMEd25519(method.PublicKeyPem)
	if err != nil {
		return false, "malformed public key"
	}
	payload, err := canon.BuildSigningPayloadV1(canon.SigningProfileV1Input{
		ContentHash: entry.ContentHash, ClaimsHash: entry.ClaimsHash, DocumentURL: entry.Location,
		Scope: entry.Scope, KeyID: entry.Keyid, Algorithm: entry.Algorithm, SignedAt: entry.SignedAt,
	})
	if err != nil {
		return false, "could not rebuild signing payload"
	}
	sig, err := base64.RawStdEncoding.DecodeString(entry.Signature)
	if err != nil {
		return false, "malformed stored signature"
	}
	if !ed25519.Verify(pub, []byte(payload), sig) {
		return false, "stored signature does not verify"
	}
	return true, ""
}

// BootstrapEntry fetches a page's live copy and, if it already carries a
// signed-section whose signature verifies under doc, returns it as a
// ledger entry seed (--ledger-bootstrap, only reached when the ledger
// itself 404s -- there was never a ledger, but the live site may already
// carry valid signatures worth preserving instead of re-signing on sight).
func BootstrapEntry(location string, doc *perioddid.Document) (*LedgerEntry, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(location)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	parsed, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var found *html.Node
	walk(parsed, func(n *html.Node) {
		if found != nil {
			return
		}
		if isSignedSection(n) {
			found = n
		}
	})
	if found == nil {
		return nil, fmt.Errorf("no signed-section found on the live page")
	}
	contentHash := getAttr(found, "content-hash")
	signature := getAttr(found, "signature")
	keyid := getAttr(found, "keyid")
	algorithm := getAttr(found, "algorithm")
	profile := getAttr(found, "profile")
	scope := getAttr(found, "signature-scope")
	if contentHash == "" || signature == "" || keyid == "" {
		return nil, fmt.Errorf("live section is unsigned")
	}
	claims, err := collectDirectClaims(found)
	if err != nil {
		return nil, err
	}
	signedAt := claims["signed-at"]
	claimsNoSignedAt := make(map[string]string, len(claims))
	for k, v := range claims {
		if k != "signed-at" {
			claimsNoSignedAt[k] = v
		}
	}
	claimsHashNoSignedAt, err := ClaimsHash(claimsNoSignedAt)
	if err != nil {
		return nil, err
	}
	claimsHash, err := ClaimsHash(claims)
	if err != nil {
		return nil, err
	}
	entry := LedgerEntry{
		Location: location, ContentHash: contentHash, ClaimsHash: claimsHash,
		ClaimsHashNoSignedAt: claimsHashNoSignedAt, SignedAt: signedAt, Keyid: keyid,
		Algorithm: algorithm, Scope: scope, Profile: profile, Signature: signature,
	}
	if ok, reason := replayEligible(entry, contentHash, claimsHashNoSignedAt, doc, 0, 0); !ok {
		return nil, fmt.Errorf("live signature does not verify: %s", reason)
	}
	return &entry, nil
}
