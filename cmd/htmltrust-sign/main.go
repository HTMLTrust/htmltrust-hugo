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
//	    --domain https://www.htmltrust.org --keyfile /path/to/key.pem
//
// The private key may also come from the HTMLTRUST_SIGNING_KEY environment
// variable (PEM-encoded PKCS#8 Ed25519) which is what CI typically uses.
//
// Period discovery (spec draft §9.10). --keyid stays the identity, not a
// keyid with a period fragment: this CLI loads the identity's DID document
// (--did-document, or derived from --keyid for a did:web identity), matches
// the loaded private key's public half against it, and signs every section
// with whichever keyid that match implies. A private key that matches no
// verificationMethod is a fatal error before anything is written.
//
// Signature ledger. Enabled by default (--ledger-url defaults from
// --domain, --ledger-out defaults to public/.well-known/htmltrust-signatures.json):
// an unchanged section whose stored signature still verifies is replayed
// with its original signed-at rather than re-signed, so a struck period
// invalidates only what actually changed during it. See README.md.
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
		dir              = fs.String("dir", "public", "directory of built HTML files to scan")
		keyid            = fs.String("keyid", "", "required identity to embed (for example, did:web:jason-grey.com); the actual signed keyid is resolved by period discovery")
		domain           = fs.String("domain", "", "required HTTPS publication origin (for example, https://www.htmltrust.org); bare hosts are normalized to HTTPS")
		scope            = fs.String("scope", "url", "signature location scope: url or origin")
		algorithm        = fs.String("algorithm", "ed25519", "signature algorithm (only ed25519 supported)")
		keyfile          = fs.String("keyfile", "", "PEM-encoded PKCS#8 Ed25519 private key file (or set HTMLTRUST_SIGNING_KEY env var)")
		didDocument      = fs.String("did-document", "", "URL or local path of the identity's DID document (default: derived from --keyid for a did:web identity)")
		ledgerURL        = fs.String("ledger-url", "", "URL or local path of the live signature ledger to seed replay from (default: derived from --domain)")
		ledgerOut        = fs.String("ledger-out", "public/.well-known/htmltrust-signatures.json", "where to write the merged signature ledger, so it deploys with the site")
		ledgerBootstrap  = fs.Bool("ledger-bootstrap", false, "when the ledger has never been published (404), seed it by importing each page's live signature after verifying it")
		allowFreshLedger = fs.Bool("allow-fresh-ledger", false, "start from an empty ledger on any ledger fetch failure, not only a 404")
		allowMassResign  = fs.Bool("allow-mass-resign", false, "proceed even if more than 10 sections and more than 25% of the previous ledger are being re-signed")
		resignPeriods    = fs.String("resign-periods", "", "force fresh signatures for ledger entries in this period range, for example 2-3")
		dryRun           = fs.Bool("dry-run", false, "parse and report what would change, but don't write")
		verbose          = fs.Bool("v", false, "print each file as it's processed")
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
	origin, err := normalizeOrigin(*domain)
	if err != nil {
		return fmt.Errorf("--domain must be a serialized Web origin or bare host: %w", err)
	}
	if !strings.HasPrefix(origin, "https://") {
		return fmt.Errorf("--domain must use HTTPS for the v1 signing profile")
	}
	resignFrom, resignTo, err := ParseResignRange(*resignPeriods)
	if err != nil {
		return err
	}

	pemBytes, err := loadKeyMaterial(*keyfile)
	if err != nil {
		return err
	}
	priv, err := LoadEd25519PrivateKey(pemBytes)
	if err != nil {
		return err
	}

	// Period discovery. A failure here means we sign nothing: exit before
	// touching any file, per spec draft §9.10 tooling.
	discovery, err := DiscoverPeriod(priv, *keyid, *didDocument)
	if err != nil {
		return fmt.Errorf("period discovery: %w", err)
	}
	if *verbose {
		if discovery.Period > 0 {
			fmt.Printf("htmltrust-sign: signing as %s (period %d)\n", discovery.Keyid, discovery.Period)
		} else {
			fmt.Printf("htmltrust-sign: signing as %s (anchor)\n", discovery.Keyid)
		}
	}

	effectiveLedgerURL := *ledgerURL
	if effectiveLedgerURL == "" {
		effectiveLedgerURL = origin + "/.well-known/htmltrust-signatures.json"
	}
	ledger, wasFresh, err := LoadLedger(effectiveLedgerURL, *allowFreshLedger)
	if err != nil {
		return fmt.Errorf("load signature ledger from %s: %w", effectiveLedgerURL, err)
	}
	previousLedgerLen := ledger.Len()

	counts := &LedgerCounts{}
	cfg := SignerConfig{
		PrivateKey:       priv,
		Keyid:            discovery.Keyid,
		Algorithm:        *algorithm,
		Scope:            *scope,
		Domain:           origin,
		SignedAtFallback: time.Now().UTC(),
		Ledger:           ledger,
		DIDDocument:      discovery.Document,
		ForceResignFrom:  resignFrom,
		ForceResignTo:    resignTo,
		Counts:           counts,
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
		baseURL, err := documentBaseURL(origin, *dir, path)
		if err != nil {
			return fmt.Errorf("base URL for %s: %w", path, err)
		}
		cfg.BaseURL = baseURL

		if wasFresh && *ledgerBootstrap {
			if _, ok := ledger.Get(baseURL); !ok {
				if entry, err := BootstrapEntry(baseURL, discovery.Document); err == nil {
					ledger.Set(*entry)
				} else if *verbose {
					fmt.Fprintf(os.Stderr, "htmltrust-sign: bootstrap %s: %v\n", baseURL, err)
				}
			}
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
		return fmt.Errorf("no <signed-section> elements found; is the Hugo partial wired up?")
	}
	fmt.Printf("htmltrust-sign: replayed %d, signed %d, replaced %d\n", counts.Replayed, counts.Signed(), counts.Replaced)

	if !*dryRun {
		merged, err := ledger.MarshalIndent()
		if err != nil {
			return fmt.Errorf("encode signature ledger: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(*ledgerOut), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(*ledgerOut), err)
		}
		merged = append(merged, '\n')
		if err := os.WriteFile(*ledgerOut, merged, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", *ledgerOut, err)
		}
	}

	if counts.Replaced > 10 && float64(counts.Replaced) > 0.25*float64(previousLedgerLen) && !*allowMassResign {
		return fmt.Errorf("mass resign guard: %d of %d previously ledgered sections were re-signed (>10 and >25%%); pass --allow-mass-resign if this is expected (for example, a template change that re-hashes every page)", counts.Replaced, previousLedgerLen)
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
