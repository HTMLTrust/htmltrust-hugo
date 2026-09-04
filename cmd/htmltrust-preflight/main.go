// htmltrust-preflight checks Hugo's generated HTML before publication.
//
// With --keyid and a private key (--keyfile or HTMLTRUST_SIGNING_KEY), the
// report also carries period-key and signature-ledger fields (spec draft
// §9.10): periodKeyMatched, periodIndex, and periodsPublishedAhead come
// from matching the key against the identity's DID document exactly as
// htmltrust-sign's period discovery does; ledgerReplayed, present only with
// --ledger, approximates how many signed regions would replay from it. A
// deploy can gate on any of these before signing runs.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
	"github.com/HTMLTrust/htmltrust-hugo/preflight"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "htmltrust-preflight:", err)
		if errors.Is(err, errStrictFailure) {
			os.Exit(1)
		}
		os.Exit(2)
	}
}

var errStrictFailure = errors.New("strict preflight failed")

func run(args []string) error {
	flags := flag.NewFlagSet("htmltrust-preflight", flag.ContinueOnError)
	dir := flags.String("dir", "public", "directory of Hugo-generated HTML files")
	domain := flags.String("domain", "", "required HTTPS publication origin")
	jsonOutput := flags.Bool("json", false, "emit the complete machine-readable report as JSON")
	strict := flags.Bool("strict", false, "exit 1 when any signed region fails")
	keyid := flags.String("keyid", "", "identity to check period-key discovery against (optional; enables periodKeyMatched, periodIndex, periodsPublishedAhead)")
	keyfile := flags.String("keyfile", "", "PEM-encoded PKCS#8 Ed25519 private key file (or set HTMLTRUST_SIGNING_KEY); required with --keyid")
	didDocument := flags.String("did-document", "", "URL or local path of the identity's DID document (default: derived from --keyid for a did:web identity)")
	ledger := flags.String("ledger", "", "URL or local path of the signature ledger (optional, requires --keyid; enables ledgerReplayed)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required")
	}
	if *ledger != "" && *keyid == "" {
		return fmt.Errorf("--ledger requires --keyid")
	}

	report, err := preflight.PreflightDirectory(*dir, *domain)
	if err != nil {
		return err
	}

	if *keyid != "" {
		pemBytes, err := loadKeyMaterial(*keyfile)
		if err != nil {
			return fmt.Errorf("--keyid given but no key material: %w", err)
		}
		priv, err := perioddid.ParsePKCS8PEMEd25519(pemBytes)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
		report, err = preflight.WithPeriodReport(report, preflight.Options{
			PrivateKey:  priv,
			Identity:    *keyid,
			DIDDocument: *didDocument,
			Ledger:      *ledger,
		})
		if err != nil {
			return fmt.Errorf("period report: %w", err)
		}
	}

	if *jsonOutput {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
		fmt.Println(string(encoded))
	} else {
		failed := 0
		regions := 0
		for _, file := range report.Files {
			regions += len(file.Document.Regions)
			if !file.Document.OK {
				failed++
				fmt.Printf("FAIL %s (%s)\n", file.Path, file.Document.URL)
			}
		}
		fmt.Printf("htmltrust-preflight: checked %d HTML file(s), %d signed region(s), %d failed file(s)\n", len(report.Files), regions, failed)
		if p := report.Period; p != nil {
			matched := "false"
			if p.PeriodKeyMatched != nil && *p.PeriodKeyMatched {
				matched = "true"
			}
			fmt.Printf("htmltrust-preflight: periodKeyMatched=%s", matched)
			if p.PeriodIndex != nil {
				fmt.Printf(" periodIndex=%d", *p.PeriodIndex)
			}
			if p.PeriodsPublishedAhead != nil {
				fmt.Printf(" periodsPublishedAhead=%d", *p.PeriodsPublishedAhead)
			}
			if p.LedgerReplayed != nil {
				fmt.Printf(" ledgerReplayed=%d", *p.LedgerReplayed)
			}
			fmt.Println()
		}
	}
	if *strict && !report.OK {
		return errStrictFailure
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
