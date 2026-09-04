// Package preflight checks generated Hugo pages before publication.
package preflight

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
	"golang.org/x/net/html"
)

const profile = "htmltrust-portable-authoring-v1"

const maxDocumentBytes = 1024 * 1024

var hints = map[string]string{
	"document-url-invalid":              "Pass the final HTTPS page URL without credentials.",
	"base-invalid":                      "Fix the base href or remove it so the final page URL is used.",
	"signed-section-not-found":          "Add the htmltrust-signed-section partial to this page template.",
	"signed-section-unclosed":           "Close the signed-section element before publishing.",
	"parser-profile-unsupported":        "Use well-formed HTML in the HTMLTrust v1 portable profile.",
	"resource-limit-exceeded":           "Reduce the document, signed region, or claim field size.",
	"url-policy-violation":              "Use HTTPS URLs without credentials in signed URL attributes.",
	"attribute-canonicalization-failed": "Fix the signed href or src attribute and its base URL.",
	"claim-malformed":                   "Give every direct claim meta element name and content attributes.",
	"claim-duplicate":                   "Keep one direct claim meta element for each normalized claim name.",
}

// Diagnostic is stable machine-readable output for a page or signed region.
type Diagnostic struct {
	Code     string         `json:"code"`
	Severity string         `json:"severity"`
	Message  string         `json:"message"`
	Hint     string         `json:"hint"`
	Region   int            `json:"region"`
	Context  map[string]any `json:"context,omitempty"`
}

// Region is the result of running the shared v1 canonicalization checks on a
// single signed-section.
type Region struct {
	Index           int               `json:"index"`
	Status          string            `json:"status"`
	NodePath        string            `json:"nodePath"`
	BaseURL         string            `json:"baseURL,omitempty"`
	CanonicalText   string            `json:"canonicalText,omitempty"`
	CanonicalClaims string            `json:"canonicalClaims,omitempty"`
	Claims          map[string]string `json:"claims,omitempty"`
	Diagnostics     []Diagnostic      `json:"diagnostics"`
}

// Document is the JSON-compatible report for one generated HTML page.
type Document struct {
	Profile     string       `json:"profile"`
	URL         string       `json:"url"`
	BaseURL     string       `json:"baseURL,omitempty"`
	OK          bool         `json:"ok"`
	Diagnostics []Diagnostic `json:"diagnostics"`
	Regions     []Region     `json:"regions"`
}

// FileReport associates a generated file with its publication URL.
type FileReport struct {
	Path     string   `json:"path"`
	Document Document `json:"document"`
}

// DirectoryReport is the result of checking every .html file below a Hugo
// public directory. Pages without a signed section remain successful and
// carry a signed-section-not-found warning.
type DirectoryReport struct {
	Profile     string       `json:"profile"`
	Root        string       `json:"root"`
	Domain      string       `json:"domain"`
	OK          bool         `json:"ok"`
	Files       []FileReport `json:"files"`
	Diagnostics []Diagnostic `json:"diagnostics"`

	// Period carries period-key and signature-ledger information (spec
	// draft §9.10). It is nil unless the caller supplied a private key via
	// Options to WithPeriodReport (the CLI's --keyid/--keyfile flags), so a
	// caller that never asks for it sees no "period" member at all.
	Period *PeriodReport `json:"period,omitempty"`
}

func diagnostic(code, severity, message string, region int, context map[string]any) Diagnostic {
	hint := hints[code]
	if hint == "" {
		hint = "Inspect the generated page at the reported region."
	}
	return Diagnostic{Code: code, Severity: severity, Message: message, Hint: hint, Region: region, Context: context}
}

func codeFor(err error) string {
	message := ""
	if err != nil {
		message = err.Error()
	}
	for code := range hints {
		if message == code || strings.HasPrefix(message, code+":") || strings.Contains(message, code) {
			return code
		}
	}
	return "parser-profile-unsupported"
}

func safeURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("document-url-invalid: URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("document-url-invalid: URL must be HTTPS without credentials")
	}
	return u.String(), nil
}

func attrs(node *html.Node) map[string]string {
	out := make(map[string]string, len(node.Attr))
	for _, attr := range node.Attr {
		out[strings.ToLower(attr.Key)] = attr.Val
	}
	return out
}

type baseResult struct {
	url         string
	diagnostics []Diagnostic
}

func resolveBase(doc *html.Node, finalURL string) baseResult {
	result := baseResult{url: finalURL}
	var firstHref string
	found := false
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if found || node == nil {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "base") {
			href, ok := attrs(node)["href"]
			if ok {
				firstHref, found = href, true
				return
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
			if found {
				return
			}
		}
	}
	visit(doc)
	if !found {
		return result
	}
	context := map[string]any{"href": firstHref}
	candidate, err := url.Parse(firstHref)
	if err != nil {
		result.diagnostics = append(result.diagnostics, diagnostic("base-invalid", "warning", "The first base href could not be resolved; the final response URL is used.", -1, context))
		return result
	}
	base, _ := url.Parse(finalURL)
	candidate = base.ResolveReference(candidate)
	if candidate.Scheme == "data" || candidate.Scheme == "javascript" {
		result.diagnostics = append(result.diagnostics, diagnostic("base-invalid", "warning", "The first base href cannot become a document base; the final response URL is used.", -1, context))
		return result
	}
	result.url = candidate.String()
	if candidate.Scheme != "https" || candidate.Host == "" || candidate.User != nil {
		result.diagnostics = append(result.diagnostics, diagnostic("base-invalid", "warning", "The document base is outside the HTMLTrust HTTPS profile; relative signed URLs will fail preflight.", -1, context))
	}
	return result
}

func isSignedSection(node *html.Node) bool {
	return node.Type == html.ElementNode && strings.EqualFold(node.Data, "signed-section")
}

type section struct {
	node *html.Node
	path string
}

func collectSections(doc *html.Node) []section {
	var sections []section
	var visit func(*html.Node, string)
	visit = func(node *html.Node, path string) {
		if isSignedSection(node) {
			sections = append(sections, section{node: node, path: path})
		}
		for i, child := 0, node.FirstChild; child != nil; i, child = i+1, child.NextSibling {
			name := child.Data
			if child.Type != html.ElementNode {
				name = "#node"
			}
			visit(child, fmt.Sprintf("%s/%s[%d]", path, name, i))
		}
	}
	visit(doc, "document")
	return sections
}

func renderChildren(node *html.Node) (string, error) {
	var output bytes.Buffer
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if err := html.Render(&output, child); err != nil {
			return "", err
		}
	}
	return output.String(), nil
}

var portableVoidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

// duplicateAttribute performs the same source-level check as the portable
// parser. x/net/html drops duplicate attributes while tokenizing, so checking
// the parsed DOM alone would silently accept a source that other bindings
// reject.
func duplicateAttribute(raw string) bool {
	seen := map[string]bool{}
	i := 1 // '<'
	if i < len(raw) && raw[i] == '/' {
		i++
	}
	for i < len(raw) && isHTMLSpace(raw[i]) {
		i++
	}
	for i < len(raw) && !isHTMLSpace(raw[i]) && raw[i] != '/' && raw[i] != '>' {
		i++
	}
	for i < len(raw) {
		for i < len(raw) && (isHTMLSpace(raw[i]) || raw[i] == '/') {
			i++
		}
		if i >= len(raw) || raw[i] == '>' {
			return false
		}
		start := i
		for i < len(raw) && !isHTMLSpace(raw[i]) && raw[i] != '=' && raw[i] != '/' && raw[i] != '>' {
			i++
		}
		if start == i {
			i++
			continue
		}
		name := strings.ToLower(raw[start:i])
		if seen[name] {
			return true
		}
		seen[name] = true
		for i < len(raw) && isHTMLSpace(raw[i]) {
			i++
		}
		if i < len(raw) && raw[i] == '=' {
			i++
			for i < len(raw) && isHTMLSpace(raw[i]) {
				i++
			}
			if i < len(raw) && (raw[i] == '\'' || raw[i] == '"') {
				quote := raw[i]
				i++
				for i < len(raw) && raw[i] != quote {
					i++
				}
				if i < len(raw) {
					i++
				}
			} else {
				for i < len(raw) && !isHTMLSpace(raw[i]) && raw[i] != '>' {
					i++
				}
			}
		}
	}
	return false
}

func isHTMLSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\f' || value == '\r'
}

// validateSignedRegionSource rejects parser recovery inside or around every
// signed-section. It intentionally scopes the stack to signed sections so
// ordinary document-level HTML can retain Hugo/browser recovery behavior.
func validateSignedRegionSource(input []byte) error {
	tokenizer := html.NewTokenizer(bytes.NewReader(input))
	stack := []string{}
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			raw := string(tokenizer.Raw())
			if tokenizer.Err() != io.EOF && len(stack) > 0 {
				return fmt.Errorf("parser-profile-unsupported")
			}
			if len(stack) > 0 {
				return fmt.Errorf("parser-profile-unsupported")
			}
			// A malformed signed-section start tag can prevent the tokenizer
			// from ever producing a start token, leaving no stack entry to
			// validate. Preserve the portable parser profile's rejection in
			// that case instead of reporting a misleading not-found warning.
			if containsSignedSectionStart(raw) {
				return fmt.Errorf("parser-profile-unsupported")
			}
			return nil
		}
		raw := string(tokenizer.Raw())
		if tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken {
			nameBytes, _ := tokenizer.TagName()
			name := strings.ToLower(string(nameBytes))
			if (len(stack) > 0 || name == "signed-section") && duplicateAttribute(raw) {
				return fmt.Errorf("parser-profile-unsupported")
			}
			if name == "signed-section" || len(stack) > 0 {
				if tokenType == html.SelfClosingTagToken && !portableVoidElements[name] {
					return fmt.Errorf("parser-profile-unsupported")
				}
				if tokenType == html.StartTagToken && !portableVoidElements[name] {
					stack = append(stack, name)
				}
			}
			continue
		}
		if tokenType == html.EndTagToken && len(stack) > 0 {
			nameBytes, _ := tokenizer.TagName()
			name := strings.ToLower(string(nameBytes))
			if stack[len(stack)-1] != name {
				return fmt.Errorf("parser-profile-unsupported")
			}
			stack = stack[:len(stack)-1]
		}
	}
}

func containsSignedSectionStart(raw string) bool {
	lower := strings.ToLower(raw)
	const tag = "<signed-section"
	for offset := 0; offset < len(lower); {
		index := strings.Index(lower[offset:], tag)
		if index < 0 {
			return false
		}
		index += offset + len(tag)
		if index == len(raw) || isHTMLSpace(raw[index]) || raw[index] == '/' || raw[index] == '>' {
			return true
		}
		offset = index
	}
	return false
}

func directClaims(node *html.Node) (map[string]string, error) {
	claims := map[string]string{}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type != html.ElementNode || !strings.EqualFold(child.Data, "meta") {
			continue
		}
		attrs := attrs(child)
		name, hasName := attrs["name"]
		content, hasContent := attrs["content"]
		if !hasName || !hasContent {
			return nil, fmt.Errorf("claim-malformed")
		}
		normalizedName, err := canon.NormalizeTextChecked(name)
		if err != nil {
			return nil, err
		}
		normalizedContent, err := canon.NormalizeTextChecked(content)
		if err != nil {
			return nil, err
		}
		normalizedName = strings.TrimSpace(normalizedName)
		normalizedContent = strings.TrimSpace(normalizedContent)
		if normalizedName == "" {
			return nil, fmt.Errorf("claim-malformed")
		}
		if _, duplicate := claims[normalizedName]; duplicate {
			return nil, fmt.Errorf("claim-duplicate")
		}
		claims[normalizedName] = normalizedContent
	}
	return claims, nil
}

func inspectRegion(index int, item section, baseURL string) Region {
	result := Region{Index: index, Status: "fail", NodePath: item.path, BaseURL: baseURL, Diagnostics: []Diagnostic{}}
	inner, err := renderChildren(item.node)
	if err == nil {
		result.CanonicalText, err = canon.ExtractCanonicalText(inner, canon.Options{BaseURL: baseURL})
	}
	if err == nil {
		result.Claims, err = directClaims(item.node)
	}
	if err == nil {
		result.CanonicalClaims, err = canon.CanonicalizeClaims(result.Claims)
	}
	if err != nil {
		code := codeFor(err)
		result.Diagnostics = append(result.Diagnostics, diagnostic(code, "error", err.Error(), index, map[string]any{"nodePath": item.path}))
		return result
	}
	result.Status = "pass"
	return result
}

// PreflightHTML inspects one complete generated HTML document. finalURL is
// the URL at which the page will be published and is used when no valid base
// element exists.
func PreflightHTML(input []byte, finalURL string) Document {
	result := Document{Profile: profile, URL: finalURL, Regions: []Region{}, Diagnostics: []Diagnostic{}}
	if len(input) > maxDocumentBytes {
		result.Diagnostics = append(result.Diagnostics, diagnostic("resource-limit-exceeded", "error", "generated document exceeds the 1 MiB v1 limit", -1, map[string]any{"bytes": len(input), "limit": maxDocumentBytes}))
		return result
	}
	if !utf8.Valid(input) {
		result.Diagnostics = append(result.Diagnostics, diagnostic("parser-profile-unsupported", "error", "generated document is not valid UTF-8", -1, nil))
		return result
	}
	urlValue, err := safeURL(finalURL)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, diagnostic(codeFor(err), "error", err.Error(), -1, nil))
		return result
	}
	result.URL = urlValue
	if err := validateSignedRegionSource(input); err != nil {
		result.Diagnostics = append(result.Diagnostics, diagnostic(codeFor(err), "error", err.Error(), -1, nil))
		return result
	}
	doc, err := html.Parse(bytes.NewReader(input))
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, diagnostic("parser-profile-unsupported", "error", err.Error(), -1, nil))
		return result
	}
	base := resolveBase(doc, urlValue)
	result.BaseURL = base.url
	result.Diagnostics = append(result.Diagnostics, base.diagnostics...)
	sections := collectSections(doc)
	for index, item := range sections {
		result.Regions = append(result.Regions, inspectRegion(index, item, base.url))
	}
	if len(sections) == 0 {
		result.Diagnostics = append(result.Diagnostics, diagnostic("signed-section-not-found", "warning", "No signed-section was found in the generated page.", -1, nil))
		result.OK = true
		return result
	}
	result.OK = true
	for _, region := range result.Regions {
		if region.Status != "pass" {
			result.OK = false
			break
		}
	}
	return result
}

// PageURL derives the publication URL for a generated Hugo file. index.html
// maps to the directory URL, matching Hugo's pretty URL output.
func PageURL(domain, root, path string) (string, error) {
	base, err := safeURL(strings.TrimRight(domain, "/") + "/")
	if err != nil {
		return "", err
	}
	domainURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if domainURL.Path != "/" {
		return "", fmt.Errorf("document-url-invalid: domain must be an origin")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("document-url-invalid: cannot derive relative path: %w", err)
	}
	rel = filepath.ToSlash(rel)
	if rel == "index.html" {
		rel = ""
	} else if strings.HasSuffix(rel, "/index.html") {
		rel = strings.TrimSuffix(rel, "index.html")
	}
	// Set Path instead of parsing rel as a URL reference. This keeps '#', '?',
	// and other filename bytes in the path, where URL.String percent-encodes
	// them instead of treating them as fragment/query delimiters.
	return domainURL.ResolveReference(&url.URL{Path: rel}).String(), nil
}

// PreflightDirectory checks generated HTML files below root. The returned
// report is suitable for a strict publication gate when report.OK is false.
func PreflightDirectory(root, domain string) (DirectoryReport, error) {
	report := DirectoryReport{Profile: profile, Root: root, Domain: domain, Files: []FileReport{}, Diagnostics: []Diagnostic{}, OK: true}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".html") {
			return nil
		}
		input, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		pageURL, err := PageURL(domain, root, path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		document := PreflightHTML(input, pageURL)
		report.Files = append(report.Files, FileReport{Path: path, Document: document})
		if !document.OK {
			report.OK = false
		}
		return nil
	})
	if err != nil {
		return report, err
	}
	return report, nil
}

// MarshalJSON is provided as a convenience for callers embedding reports.
func (d Document) MarshalJSON() ([]byte, error) {
	type alias Document
	return json.Marshal(alias(d))
}
