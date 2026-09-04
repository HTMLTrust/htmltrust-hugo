package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

func cmdDidRender(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key did render", flag.ContinueOnError)
	out := fs.String("out", "", "write the rendered document to this path instead of stdout, for example static/.well-known/did.json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		return fmt.Errorf("did render: %w", err)
	}
	doc, err := id.Render()
	if err != nil {
		return fmt.Errorf("did render: %w", err)
	}
	raw, err := doc.MarshalPretty()
	if err != nil {
		return fmt.Errorf("did render: %w", err)
	}
	raw = append(raw, '\n')

	if *out == "" {
		_, err := os.Stdout.Write(raw)
		return err
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		return fmt.Errorf("did render: write %s: %w", *out, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes).\n", *out, len(raw))
	return nil
}

// errDidCheckMismatch is returned by cmdDidCheck when the served document
// differs from local state, so main can still exit 1 while printing a
// specific diff rather than a generic error message.
var errDidCheckMismatch = errors.New("did check: served document does not match local state")

func cmdDidCheck(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key did check", flag.ContinueOnError)
	didDocument := fs.String("did-document", "", "URL or local path of the served DID document (default: https://<identity host>/.well-known/did.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		return fmt.Errorf("did check: %w", err)
	}
	local, err := id.Render()
	if err != nil {
		return fmt.Errorf("did check: %w", err)
	}

	source := *didDocument
	if source == "" {
		source, err = didWebDocumentURL(id.Identity)
		if err != nil {
			return fmt.Errorf("did check: %w", err)
		}
	}
	served, err := perioddid.LoadDocument(source)
	if err != nil {
		return fmt.Errorf("did check: load %s: %w", source, err)
	}

	diffs := perioddid.Diff(local, served)
	if len(diffs) == 0 {
		fmt.Printf("OK: %s matches local state (%s).\n", source, IdentityStatePath)
		return nil
	}
	fmt.Fprintf(os.Stderr, "MISMATCH: %s differs from local state (%s):\n", source, IdentityStatePath)
	for _, d := range diffs {
		fmt.Fprintf(os.Stderr, "  - %s\n", d)
	}
	return errDidCheckMismatch
}
