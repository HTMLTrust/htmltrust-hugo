package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

func cmdRekey(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key rekey", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		return fmt.Errorf("rekey: %w", err)
	}
	oldPassphrase, err := ReadPassphraseOnce("Current passphrase for " + SecretStatePath + ": ")
	if err != nil {
		return fmt.Errorf("rekey: %w", err)
	}
	secret, err := LoadSecret(SecretStatePath, oldPassphrase)
	if err != nil {
		return fmt.Errorf("rekey: %w", err)
	}
	if secret.Identity != id.Identity {
		return fmt.Errorf("rekey: secret file identity %q does not match state file identity %q", secret.Identity, id.Identity)
	}

	newMaster, err := perioddid.GenerateMaster()
	if err != nil {
		return fmt.Errorf("rekey: %w", err)
	}
	secret.Master = base64.RawStdEncoding.EncodeToString(newMaster)

	newPassphrase, err := ReadPassphraseTwice(
		"New passphrase for "+SecretStatePath+": ",
		"Confirm new passphrase: ",
	)
	if err != nil {
		return fmt.Errorf("rekey: %w", err)
	}

	// The next valid index under the new master is publishedThrough + 1:
	// nothing between the old derivedThrough and publishedThrough was ever
	// derived under the new master, and there is no reason to derive it --
	// those indices are either already covered by a `revoke` of the old
	// master's range, or were never delivered anywhere.
	id.DerivedThrough = id.PublishedThrough

	if err := SaveSecret(SecretStatePath, secret, newPassphrase); err != nil {
		return fmt.Errorf("rekey: %w", err)
	}
	if err := id.Save(IdentityStatePath); err != nil {
		return fmt.Errorf("rekey: %w", err)
	}

	fmt.Printf("New master generated (fingerprint %s). Anchor key unchanged.\n", masterFingerprint(newMaster))
	fmt.Fprintf(os.Stderr, "Next valid period is %d. If any period through %d may have been derived under the old master and delivered online, run `htmltrust-key revoke` to strike it before continuing.\n", id.DerivedThrough+1, id.PublishedThrough)
	return nil
}
