// htmltrust-preflight checks Hugo's generated HTML before publication.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

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
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required")
	}
	report, err := preflight.PreflightDirectory(*dir, *domain)
	if err != nil {
		return err
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
	}
	if *strict && !report.OK {
		return errStrictFailure
	}
	return nil
}
