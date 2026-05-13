package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// SignerConfig holds the inputs the walker needs to fill in signed-section
// attributes. Keyid and Algorithm override any values already on the element;
// SignedAtFallback supplies a timestamp if the page didn't set one. Domain is
// required by the spec binding.
type SignerConfig struct {
	PrivateKey       ed25519.PrivateKey
	Keyid            string
	Algorithm        string // "ed25519" only for now
	Domain           string
	SignedAtFallback time.Time // used if <meta name="signed-at"> absent
}

// SignHTML parses the given HTML, signs every <signed-section> in place, and
// returns the rewritten HTML. Sections already carrying a non-empty
// content-hash and signature are re-signed (idempotent for the same inputs).
//
// Returns the number of sections signed, or an error if any section is
// structurally invalid (e.g. cannot determine signed-at) or if signing fails.
func SignHTML(input []byte, cfg SignerConfig) ([]byte, int, error) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = "ed25519"
	}
	if cfg.Algorithm != "ed25519" {
		return nil, 0, fmt.Errorf("SignHTML: unsupported algorithm %q (only ed25519 supported)", cfg.Algorithm)
	}
	if cfg.PrivateKey == nil {
		return nil, 0, errors.New("SignHTML: PrivateKey is required")
	}
	if cfg.Keyid == "" {
		return nil, 0, errors.New("SignHTML: Keyid is required")
	}
	if cfg.Domain == "" {
		return nil, 0, errors.New("SignHTML: Domain is required")
	}

	doc, err := html.Parse(bytes.NewReader(input))
	if err != nil {
		return nil, 0, fmt.Errorf("SignHTML: parse: %w", err)
	}

	signed := 0
	var walkErr error
	walk(doc, func(n *html.Node) {
		if walkErr != nil {
			return
		}
		if !isSignedSection(n) {
			return
		}
		if err := signNode(n, cfg); err != nil {
			walkErr = err
			return
		}
		signed++
	})
	if walkErr != nil {
		return nil, signed, walkErr
	}

	var out bytes.Buffer
	if err := html.Render(&out, doc); err != nil {
		return nil, signed, fmt.Errorf("SignHTML: render: %w", err)
	}
	return out.Bytes(), signed, nil
}

// signNode rewrites a single <signed-section> element's required attributes.
func signNode(n *html.Node, cfg SignerConfig) error {
	// Extract inner <meta> claims and signed-at.
	claims := map[string]string{}
	signedAt := ""
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode || strings.ToLower(c.Data) != "meta" {
			continue
		}
		name := getAttr(c, "name")
		content := getAttr(c, "content")
		switch {
		case name == "signed-at":
			signedAt = content
		case strings.HasPrefix(name, "claim:"):
			claims[strings.TrimPrefix(name, "claim:")] = content
		}
	}
	if signedAt == "" {
		if cfg.SignedAtFallback.IsZero() {
			return errors.New("signNode: section has no <meta name=\"signed-at\"> and no fallback configured")
		}
		signedAt = cfg.SignedAtFallback.UTC().Format(time.RFC3339)
		// Insert a meta tag so the verifier can see it.
		setSignedAtMeta(n, signedAt)
	}

	innerHTML, err := renderChildren(n)
	if err != nil {
		return fmt.Errorf("signNode: render children: %w", err)
	}
	contentHash, err := ContentHash(innerHTML)
	if err != nil {
		return fmt.Errorf("signNode: content hash: %w", err)
	}
	claimsHash := ClaimsHash(claims)
	binding, err := canon.BuildSignatureBinding(contentHash, claimsHash, cfg.Domain, signedAt)
	if err != nil {
		return fmt.Errorf("signNode: build binding: %w", err)
	}
	signature := SignEd25519(binding, cfg.PrivateKey)

	setAttr(n, "content-hash", contentHash)
	setAttr(n, "signature", signature)
	setAttr(n, "keyid", cfg.Keyid)
	setAttr(n, "algorithm", cfg.Algorithm)
	delAttr(n, "data-htmltrust-placeholder")
	return nil
}

// === DOM helpers ===

func walk(n *html.Node, visit func(*html.Node)) {
	visit(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, visit)
	}
}

func isSignedSection(n *html.Node) bool {
	if n.Type != html.ElementNode {
		return false
	}
	// `signed-section` is a custom element; html.Parse keeps it as ElementNode
	// with Data="signed-section" and DataAtom=0.
	return n.DataAtom == 0 && strings.ToLower(n.Data) == "signed-section"
}

func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func setAttr(n *html.Node, key, val string) {
	for i, a := range n.Attr {
		if a.Key == key {
			n.Attr[i].Val = val
			return
		}
	}
	n.Attr = append(n.Attr, html.Attribute{Key: key, Val: val})
}

func delAttr(n *html.Node, key string) {
	out := n.Attr[:0]
	for _, a := range n.Attr {
		if a.Key != key {
			out = append(out, a)
		}
	}
	n.Attr = out
}

// setSignedAtMeta inserts a <meta name="signed-at" content="..."> as the first
// child of n (so verifiers can find it when extracting claims).
func setSignedAtMeta(n *html.Node, signedAt string) {
	meta := &html.Node{
		Type:     html.ElementNode,
		Data:     "meta",
		DataAtom: atom.Meta,
		Attr: []html.Attribute{
			{Key: "name", Val: "signed-at"},
			{Key: "content", Val: signedAt},
		},
	}
	n.InsertBefore(meta, n.FirstChild)
}

// renderChildren renders the inner HTML of n (everything between its tags) as
// a string. We feed this string to ExtractCanonicalText for content hashing.
func renderChildren(n *html.Node) (string, error) {
	var buf bytes.Buffer
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if err := html.Render(&buf, c); err != nil {
			return "", err
		}
	}
	return buf.String(), nil
}
