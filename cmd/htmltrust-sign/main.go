// htmltrust-sign — post-build CLI that fills in the cryptographic attributes
// on every <signed-section> element in a directory of HTML files, per the
// HTMLTrust spec §2.1.
//
// Pairs with the companion Hugo Module (github.com/HTMLTrust/htmltrust-hugo)
// whose partial emits structural <signed-section> placeholders during
// `hugo build`. This CLI runs afterwards to compute content-hash and signature
// using the spec-conformant canonicalization library.
//
// Usage:
//
//	htmltrust-sign --dir public --keyid did:web:jason-grey.com \
//	    --domain www.htmltrust.org --keyfile /path/to/key.pem
//
// The private key may also come from the HTMLTRUST_SIGNING_KEY environment
// variable (PEM-encoded PKCS#8 Ed25519) which is what CI typically uses.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "htmltrust-sign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("htmltrust-sign", flag.ContinueOnError)
	var (
		dir       = fs.String("dir", "public", "directory of built HTML files to scan")
		keyid     = fs.String("keyid", "", "keyid to embed (e.g. did:web:jason-grey.com) — required")
		domain    = fs.String("domain", "", "publication domain for the signature binding (e.g. www.htmltrust.org) — required")
		algorithm = fs.String("algorithm", "ed25519", "signature algorithm (only ed25519 supported)")
		keyfile   = fs.String("keyfile", "", "PEM-encoded PKCS#8 Ed25519 private key file (or set HTMLTRUST_SIGNING_KEY env var)")
		dryRun    = fs.Bool("dry-run", false, "parse and report what would change, but don't write")
		verbose   = fs.Bool("v", false, "print each file as it's processed")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyid == "" {
		return fmt.Errorf("--keyid is required")
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required")
	}

	pemBytes, err := loadKeyMaterial(*keyfile)
	if err != nil {
		return err
	}
	priv, err := LoadEd25519PrivateKey(pemBytes)
	if err != nil {
		return err
	}

	cfg := SignerConfig{
		PrivateKey:       priv,
		Keyid:            *keyid,
		Algorithm:        *algorithm,
		Domain:           *domain,
		SignedAtFallback: time.Now().UTC(),
	}

	htmlFiles, err := findHTMLFiles(*dir)
	if err != nil {
		return err
	}
	if len(htmlFiles) == 0 {
		return fmt.Errorf("no .html files under %s", *dir)
	}

	totalSigned := 0
	totalFiles := 0
	for _, path := range htmlFiles {
		in, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		// Fast path: skip files that don't even mention signed-section.
		if !strings.Contains(string(in), "<signed-section") {
			continue
		}
		out, n, err := SignHTML(in, cfg)
		if err != nil {
			return fmt.Errorf("sign %s: %w", path, err)
		}
		if n == 0 {
			continue
		}
		totalSigned += n
		totalFiles++
		if *verbose || *dryRun {
			fmt.Printf("  %s: signed %d section(s)\n", path, n)
		}
		if !*dryRun {
			if err := os.WriteFile(path, out, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
	}
	fmt.Printf("htmltrust-sign: signed %d section(s) across %d file(s)\n", totalSigned, totalFiles)
	if totalSigned == 0 {
		return fmt.Errorf("no <signed-section> elements found — is the Hugo partial wired up?")
	}
	return nil
}

func loadKeyMaterial(keyfile string) ([]byte, error) {
	if env := os.Getenv("HTMLTRUST_SIGNING_KEY"); env != "" {
		return []byte(env), nil
	}
	if keyfile == "" {
		return nil, fmt.Errorf("no key material: pass --keyfile or set HTMLTRUST_SIGNING_KEY")
	}
	return os.ReadFile(keyfile)
}

func findHTMLFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(path), ".html") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
