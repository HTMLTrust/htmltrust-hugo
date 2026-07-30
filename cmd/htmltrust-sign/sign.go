package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	canon "github.com/HTMLTrust/htmltrust-canonicalization/go"
	"golang.org/x/net/html"
	"golang.org/x/net/idna"
)

// hashSHA256B64 returns the unpadded base64 SHA-256 of the input, prefixed with
// "sha256:" per HTMLTrust spec §2.1 (hash encoding rules: unpadded Base64).
func hashSHA256B64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ContentHash returns the spec-conformant content-hash for the inner HTML of a
// signed-section. The inner HTML is canonicalized as signed text plus the
// current signed semantic attribute set before hashing.
func ContentHash(innerHTML string, baseURL ...string) (string, error) {
	canonical, err := canon.ExtractCanonicalText(innerHTML, canon.Options{BaseURL: firstString(baseURL)})
	if err != nil {
		return "", fmt.Errorf("ContentHash: canonical content: %w", err)
	}
	return hashSHA256B64(canonical), nil
}

// ClaimsHash returns the spec-conformant claims-hash for a map of claim
// name->value pairs. Claims are canonicalized (sorted by name, normalized,
// joined with newlines) before hashing.
func ClaimsHash(claims map[string]string) string {
	return hashSHA256B64(CanonicalizeClaims(claims))
}

// SignEd25519 signs the binding string with an Ed25519 private key and returns
// the unpadded-base64-encoded signature per spec §2.1.
func SignEd25519(binding string, key ed25519.PrivateKey) string {
	sig := ed25519.Sign(key, []byte(binding))
	return base64.RawStdEncoding.EncodeToString(sig)
}

// LoadEd25519PrivateKey parses a PEM-encoded PKCS#8 Ed25519 private key.
func LoadEd25519PrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("LoadEd25519PrivateKey: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("LoadEd25519PrivateKey: parse PKCS8: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("LoadEd25519PrivateKey: PEM contains %T, not ed25519.PrivateKey", key)
	}
	return ed, nil
}

// CanonicalizeClaims serializes direct child meta claim pairs as
// "name:content\n", sorted by normalized claim name. It delegates to the
// shared canonicalization library so the signer and the reference verifiers
// produce byte-identical claims bytes.
func CanonicalizeClaims(claims map[string]string) string {
	return canon.CanonicalizeClaims(claims)
}

func normalizePlainText(text string) string {
	return strings.TrimSpace(canon.NormalizeText(text))
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func normalizeOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("origin is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("origin must include scheme and host")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported origin scheme %q", u.Scheme)
	}
	if u.User != nil {
		return "", errors.New("origin must not include credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("origin must not include path, query, or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("origin host is required")
	}
	if ip := net.ParseIP(host); ip == nil {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("origin host IDNA: %w", err)
		}
		host = strings.ToLower(ascii)
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			return "", fmt.Errorf("invalid origin port %q", port)
		}
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			port = ""
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	return scheme + "://" + host, nil
}

func documentBaseURL(origin, root, path string) (string, error) {
	origin, err := normalizeOrigin(origin)
	if err != nil {
		return "", err
	}
	rel, err := filepathRelSlash(root, path)
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(rel, "/index.html") {
		rel = strings.TrimSuffix(rel, "index.html")
	} else if rel == "index.html" {
		rel = ""
	}
	base, err := url.Parse(origin + "/")
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(rel)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

func filepathRelSlash(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

func getAttrOK(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}
