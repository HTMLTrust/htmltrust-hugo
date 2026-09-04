package perioddid

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrDocumentNotFound is returned by LoadDocument when the source names no
// document: a local path that does not exist, or a URL that answers 404.
// Callers such as `htmltrust-key init` treat it as "no document served
// yet" rather than a fatal error.
var ErrDocumentNotFound = errors.New("perioddid: DID document not found")

// Method is one entry of a DID document's verificationMethod array (spec
// §9.10: an anchor method or a period method).
type Method struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyPem string `json:"publicKeyPem"`
	Revoked      bool   `json:"revoked,omitempty"`
}

// Schedule is the optional top-level `htmltrust` display/tooling object
// (spec §9.10 rule 8). A verifier MUST NOT use it to accept or reject
// anything.
type Schedule struct {
	PeriodScheme string `json:"periodScheme"`
	PeriodEpoch  string `json:"periodEpoch"`
	PeriodLength string `json:"periodLength"`
}

// Document is a period-scoped did:web DID document.
type Document struct {
	Context            []string  `json:"@context"`
	ID                 string    `json:"id"`
	VerificationMethod []Method  `json:"verificationMethod"`
	AssertionMethod    []string  `json:"assertionMethod"`
	Authentication     []string  `json:"authentication,omitempty"`
	Deactivated        bool      `json:"deactivated,omitempty"`
	Htmltrust          *Schedule `json:"htmltrust,omitempty"`
}

// AnchorSpec is one anchor method to render (an entry preceding every period
// method; spec §9.10 rule 3).
type AnchorSpec struct {
	Fragment     string // e.g. "#key-1" or "#rev"
	PublicKeyPem string
	Revoked      bool
}

// PeriodSpec is one period method to render. Callers may pass Periods in any
// order; RenderDocument sorts them ascending by N (spec §9.10 rule 3).
type PeriodSpec struct {
	N            uint32
	PublicKeyPem string
	Revoked      bool
}

// RenderInput is the input to RenderDocument.
type RenderInput struct {
	Identity       string
	PeriodScheme   string
	PeriodEpoch    string
	PeriodLength   string
	Anchors        []AnchorSpec
	Periods        []PeriodSpec
	Authentication []string // relative fragments, e.g. "#key-1"; expanded on render
	Deactivated    bool
}

// RenderDocument deterministically builds a Document from state: every
// anchor method first in the given order, then every period method in
// ascending index order, assertionMethod mirroring verificationMethod order,
// and the optional htmltrust schedule object. No method ever carries
// `expires` (spec §9.10 rule 5).
func RenderDocument(in RenderInput) (*Document, error) {
	if in.Identity == "" {
		return nil, fmt.Errorf("perioddid: identity is required to render a DID document")
	}
	if len(in.Anchors) == 0 {
		return nil, fmt.Errorf("perioddid: at least one anchor method is required")
	}
	periods := append([]PeriodSpec(nil), in.Periods...)
	sort.Slice(periods, func(i, j int) bool { return periods[i].N < periods[j].N })

	doc := &Document{
		Context:     []string{"https://www.w3.org/ns/did/v1"},
		ID:          in.Identity,
		Deactivated: in.Deactivated,
	}
	seen := map[string]bool{}
	addMethod := func(fragment, publicKeyPem string, revoked bool) error {
		if publicKeyPem == "" {
			return fmt.Errorf("perioddid: method %s has no publicKeyPem", fragment)
		}
		id := in.Identity + fragment
		if seen[id] {
			return fmt.Errorf("malformed-key-document: duplicate method id %s", id)
		}
		seen[id] = true
		doc.VerificationMethod = append(doc.VerificationMethod, Method{
			ID:           id,
			Type:         "Ed25519VerificationKey2020",
			Controller:   in.Identity,
			PublicKeyPem: publicKeyPem,
			Revoked:      revoked,
		})
		doc.AssertionMethod = append(doc.AssertionMethod, id)
		return nil
	}
	for _, a := range in.Anchors {
		if err := addMethod(a.Fragment, a.PublicKeyPem, a.Revoked); err != nil {
			return nil, err
		}
	}
	for _, p := range periods {
		if !ValidPeriod(p.N) {
			return nil, fmt.Errorf("perioddid: period index %d out of range [%d, %d]", p.N, MinPeriod, MaxPeriod)
		}
		if err := addMethod(fmt.Sprintf("#p%d", p.N), p.PublicKeyPem, p.Revoked); err != nil {
			return nil, err
		}
	}
	for _, frag := range in.Authentication {
		doc.Authentication = append(doc.Authentication, in.Identity+frag)
	}
	if in.PeriodScheme != "" {
		doc.Htmltrust = &Schedule{
			PeriodScheme: in.PeriodScheme,
			PeriodEpoch:  in.PeriodEpoch,
			PeriodLength: in.PeriodLength,
		}
	}
	return doc, nil
}

// MarshalPretty renders the document as two-space-indented JSON, matching
// the exact hand-formatted wire form of spec §9.10's worked example: single
// string-array fields (`@context`, `authentication`) inline on one line,
// `verificationMethod` and `assertionMethod` one entry per line. Go's
// standard library json.MarshalIndent always expands every array regardless
// of length, so it cannot reproduce that example byte for byte; this writer
// builds the JSON by hand field by field instead, using encoding/json only
// to quote and escape individual string values.
func (d *Document) MarshalPretty() ([]byte, error) {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString("  \"@context\": ")
	b.WriteString(jsonInlineStringArray(d.Context))
	b.WriteString(",\n")
	b.WriteString("  \"id\": ")
	b.WriteString(jstr(d.ID))
	b.WriteString(",\n")

	b.WriteString("  \"verificationMethod\": [\n")
	for i, m := range d.VerificationMethod {
		b.WriteString("    {\n")
		b.WriteString("      \"id\": " + jstr(m.ID) + ",\n")
		b.WriteString("      \"type\": " + jstr(m.Type) + ",\n")
		b.WriteString("      \"controller\": " + jstr(m.Controller) + ",\n")
		if m.Revoked {
			b.WriteString("      \"publicKeyPem\": " + jstr(m.PublicKeyPem) + ",\n")
			b.WriteString("      \"revoked\": true\n")
		} else {
			b.WriteString("      \"publicKeyPem\": " + jstr(m.PublicKeyPem) + "\n")
		}
		if i == len(d.VerificationMethod)-1 {
			b.WriteString("    }\n")
		} else {
			b.WriteString("    },\n")
		}
	}
	b.WriteString("  ],\n")

	b.WriteString("  \"assertionMethod\": [\n")
	for i, id := range d.AssertionMethod {
		sep := ",\n"
		if i == len(d.AssertionMethod)-1 {
			sep = "\n"
		}
		b.WriteString("    " + jstr(id) + sep)
	}
	b.WriteString("  ]")

	hasMore := len(d.Authentication) > 0 || d.Deactivated || d.Htmltrust != nil
	if hasMore {
		b.WriteString(",\n")
	} else {
		b.WriteString("\n")
	}

	if len(d.Authentication) > 0 {
		b.WriteString("  \"authentication\": ")
		b.WriteString(jsonInlineStringArray(d.Authentication))
		if d.Deactivated || d.Htmltrust != nil {
			b.WriteString(",\n")
		} else {
			b.WriteString("\n")
		}
	}
	if d.Deactivated {
		b.WriteString("  \"deactivated\": true")
		if d.Htmltrust != nil {
			b.WriteString(",\n")
		} else {
			b.WriteString("\n")
		}
	}
	if d.Htmltrust != nil {
		b.WriteString("  \"htmltrust\": {\n")
		b.WriteString("    \"periodScheme\": " + jstr(d.Htmltrust.PeriodScheme) + ",\n")
		b.WriteString("    \"periodEpoch\": " + jstr(d.Htmltrust.PeriodEpoch) + ",\n")
		b.WriteString("    \"periodLength\": " + jstr(d.Htmltrust.PeriodLength) + "\n")
		b.WriteString("  }\n")
	}
	b.WriteString("}")
	return []byte(b.String()), nil
}

// jstr returns s as a quoted, escaped JSON string literal.
func jstr(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string cannot fail.
		panic(err)
	}
	return string(b)
}

// jsonInlineStringArray renders items as a single-line JSON array of quoted
// strings, e.g. ["a", "b"].
func jsonInlineStringArray(items []string) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = jstr(it)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// ParseDocument parses a DID document from raw JSON bytes.
func ParseDocument(raw []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("perioddid: parse DID document: %w", err)
	}
	return &doc, nil
}

// LoadDocument reads a DID document from an http(s):// URL or a local file
// path. A local path is what tests and --did-document overrides use.
func LoadDocument(source string) (*Document, error) {
	raw, err := readSource(source)
	if err != nil {
		return nil, err
	}
	return ParseDocument(raw)
}

func readSource(source string) ([]byte, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return fetchHTTP(source)
	}
	b, err := os.ReadFile(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", source, ErrDocumentNotFound)
		}
		return nil, fmt.Errorf("perioddid: read %s: %w", source, err)
	}
	return b, nil
}

// maxDocumentBytes generously bounds a fetched DID document above the spec's
// 64 KiB remote key document budget (§12.10), which is a publisher-side
// sizing target, not a hard wire limit this loader enforces exactly.
const maxDocumentBytes = 256 * 1024

func fetchHTTP(u string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("perioddid: fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %w", u, ErrDocumentNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("perioddid: fetch %s: HTTP %d", u, resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxDocumentBytes+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("perioddid: read %s: %w", u, err)
	}
	if len(b) > maxDocumentBytes {
		return nil, fmt.Errorf("perioddid: %s exceeds %d bytes", u, maxDocumentBytes)
	}
	return b, nil
}

var periodFragmentRe = regexp.MustCompile(`^p([1-9][0-9]{0,9})$`)

// ParsePeriodFragment reports whether fragment matches the period fragment
// grammar `^p([1-9][0-9]{0,9})$` with a value in range, and if so returns
// its period index.
func ParsePeriodFragment(fragment string) (uint32, bool) {
	m := periodFragmentRe.FindStringSubmatch(fragment)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil || n < uint64(MinPeriod) || n > uint64(MaxPeriod) {
		return 0, false
	}
	return uint32(n), true
}

func fragmentOf(id string) string {
	idx := strings.IndexByte(id, '#')
	if idx == -1 {
		return ""
	}
	return id[idx+1:]
}

// ExpandID expands a relative `#fragment` id against the document's own id
// (spec §9.10 rule 1). An already-absolute id is returned unchanged.
func (d *Document) ExpandID(id string) string {
	if strings.HasPrefix(id, "#") {
		return d.ID + id
	}
	return id
}

// Validate checks rule 9: no two verificationMethod entries may share an id
// after relative ids are expanded.
func (d *Document) Validate() error {
	seen := map[string]bool{}
	for _, m := range d.VerificationMethod {
		id := d.ExpandID(m.ID)
		if seen[id] {
			return fmt.Errorf("malformed-key-document: duplicate verificationMethod id %s", id)
		}
		seen[id] = true
	}
	return nil
}

// FindMethodByID selects the single verificationMethod entry whose expanded
// id equals id exactly (verifier algorithm step 3, kind period or anchor).
func (d *Document) FindMethodByID(id string) (*Method, bool) {
	for i := range d.VerificationMethod {
		if d.ExpandID(d.VerificationMethod[i].ID) == id {
			return &d.VerificationMethod[i], true
		}
	}
	return nil, false
}

// FirstAnchor returns the first verificationMethod entry, in array order,
// whose fragment is not a period fragment (verifier algorithm step 3, kind
// bare; spec §9.10 rule 4).
func (d *Document) FirstAnchor() (*Method, bool) {
	for i := range d.VerificationMethod {
		frag := fragmentOf(d.ExpandID(d.VerificationMethod[i].ID))
		if _, ok := ParsePeriodFragment(frag); !ok {
			return &d.VerificationMethod[i], true
		}
	}
	return nil, false
}

// KeyMatch is the result of matching a public key against a document's
// verification methods.
type KeyMatch struct {
	Method   *Method
	MethodID string // absolute
	IsPeriod bool
	Period   uint32 // 0 for an anchor match
}

// FindByPublicKey finds the verificationMethod entry whose publicKeyPem
// decodes to the given Ed25519 public key. Used by the online signer to
// discover its own period by matching its loaded private key's public half
// against the served DID document (tooling spec, "htmltrust-sign: period
// discovery").
func (d *Document) FindByPublicKey(pub ed25519.PublicKey) (KeyMatch, bool) {
	for i := range d.VerificationMethod {
		m := &d.VerificationMethod[i]
		candidate, err := ParseSPKIPEMEd25519(m.PublicKeyPem)
		if err != nil || !candidate.Equal(pub) {
			continue
		}
		id := d.ExpandID(m.ID)
		if n, ok := ParsePeriodFragment(fragmentOf(id)); ok {
			return KeyMatch{Method: m, MethodID: id, IsPeriod: true, Period: n}, true
		}
		return KeyMatch{Method: m, MethodID: id, IsPeriod: false}, true
	}
	return KeyMatch{}, false
}

// Diff reports every difference between a locally rendered document and a
// served one, for `htmltrust-key did check`. An empty result means the two
// documents are identical where it matters (method identity, key material,
// order, and revocation flags).
func Diff(local, served *Document) []string {
	var diffs []string
	if local.ID != served.ID {
		diffs = append(diffs, fmt.Sprintf("id: local %q, served %q", local.ID, served.ID))
	}
	diffs = append(diffs, diffMethods(local.VerificationMethod, served.VerificationMethod)...)
	diffs = append(diffs, diffStringSlice("assertionMethod", local.AssertionMethod, served.AssertionMethod)...)
	diffs = append(diffs, diffStringSlice("authentication", local.Authentication, served.Authentication)...)
	if local.Deactivated != served.Deactivated {
		diffs = append(diffs, fmt.Sprintf("deactivated: local %v, served %v", local.Deactivated, served.Deactivated))
	}
	diffs = append(diffs, diffSchedule(local.Htmltrust, served.Htmltrust)...)
	return diffs
}

func diffMethods(local, served []Method) []string {
	var diffs []string
	max := len(local)
	if len(served) > max {
		max = len(served)
	}
	for i := 0; i < max; i++ {
		switch {
		case i >= len(served):
			diffs = append(diffs, fmt.Sprintf("verificationMethod[%d] (%s): missing from served document", i, local[i].ID))
		case i >= len(local):
			diffs = append(diffs, fmt.Sprintf("verificationMethod[%d] (%s): present in served document but not locally", i, served[i].ID))
		case local[i] != served[i]:
			diffs = append(diffs, fmt.Sprintf("verificationMethod[%d]: local %+v, served %+v", i, local[i], served[i]))
		}
	}
	return diffs
}

func diffStringSlice(name string, local, served []string) []string {
	var diffs []string
	max := len(local)
	if len(served) > max {
		max = len(served)
	}
	for i := 0; i < max; i++ {
		var l, s string
		if i < len(local) {
			l = local[i]
		}
		if i < len(served) {
			s = served[i]
		}
		if l != s {
			diffs = append(diffs, fmt.Sprintf("%s[%d]: local %q, served %q", name, i, l, s))
		}
	}
	return diffs
}

func diffSchedule(local, served *Schedule) []string {
	if local == nil && served == nil {
		return nil
	}
	if local == nil || served == nil || *local != *served {
		return []string{fmt.Sprintf("htmltrust: local %+v, served %+v", local, served)}
	}
	return nil
}
