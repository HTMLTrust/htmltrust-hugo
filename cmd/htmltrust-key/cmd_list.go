package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

func cmdListSign(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key list sign", flag.ContinueOnError)
	out := fs.String("out", "", "write the signed list here instead of overwriting the input file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("list sign: usage: htmltrust-key list sign <file> [--out <path>]")
	}
	path := fs.Arg(0)

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		return fmt.Errorf("list sign: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("list sign: %w", err)
	}
	list, err := perioddid.ParseRevocationList(raw)
	if err != nil {
		return fmt.Errorf("list sign: %w", err)
	}

	anchorEntry, err := id.SigningAnchorEntry()
	if err != nil {
		return fmt.Errorf("list sign: %w", err)
	}
	list.Signer = id.Identity + anchorEntry.ID
	if list.Algorithm == "" {
		list.Algorithm = "ed25519"
	}

	passphrase, err := ReadPassphraseOnce("Passphrase for " + SecretStatePath + ": ")
	if err != nil {
		return fmt.Errorf("list sign: %w", err)
	}
	secret, err := LoadSecret(SecretStatePath, passphrase)
	if err != nil {
		return fmt.Errorf("list sign: %w", err)
	}
	if secret.Identity != id.Identity {
		return fmt.Errorf("list sign: secret file identity %q does not match state file identity %q", secret.Identity, id.Identity)
	}
	anchorPriv, err := secret.AnchorPrivateKey()
	if err != nil {
		return fmt.Errorf("list sign: %w", err)
	}
	if err := perioddid.SignRevocationList(list, anchorPriv); err != nil {
		return fmt.Errorf("list sign: %w", err)
	}

	dest := *out
	if dest == "" {
		dest = path
	}
	signed, err := list.MarshalPretty()
	if err != nil {
		return fmt.Errorf("list sign: %w", err)
	}
	signed = append(signed, '\n')
	if err := os.WriteFile(dest, signed, 0o644); err != nil {
		return fmt.Errorf("list sign: write %s: %w", dest, err)
	}
	fmt.Fprintf(os.Stderr, "Signed by %s. Wrote %s.\n", list.Signer, dest)
	return nil
}
