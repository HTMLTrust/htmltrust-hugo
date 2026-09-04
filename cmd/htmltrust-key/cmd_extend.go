package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

func cmdExtend(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key extend", flag.ContinueOnError)
	ahead := fs.Int("ahead", 12, "number of additional period public keys to publish")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ahead < 1 {
		return fmt.Errorf("extend: --ahead must be at least 1")
	}

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		return fmt.Errorf("extend: %w", err)
	}

	passphrase, err := ReadPassphraseOnce("Passphrase for " + SecretStatePath + ": ")
	if err != nil {
		return fmt.Errorf("extend: %w", err)
	}
	secret, err := LoadSecret(SecretStatePath, passphrase)
	if err != nil {
		return fmt.Errorf("extend: %w", err)
	}
	master, err := secret.MasterBytes()
	if err != nil {
		return fmt.Errorf("extend: %w", err)
	}
	if secret.Identity != id.Identity {
		return fmt.Errorf("extend: secret file identity %q does not match state file identity %q", secret.Identity, id.Identity)
	}

	from := id.PublishedThrough + 1
	to := id.PublishedThrough + *ahead
	for n := from; n <= to; n++ {
		priv, derr := perioddid.DerivePeriodKey(master, id.Identity, uint32(n))
		if derr != nil {
			return fmt.Errorf("extend: derive period %d public key: %w", n, derr)
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("extend: could not derive period %d public key", n)
		}
		pem, perr := perioddid.PublicKeySPKIPEM(pub)
		if perr != nil {
			return fmt.Errorf("extend: %w", perr)
		}
		id.Periods = append(id.Periods, Period{N: n, PublicKeyPem: pem})
	}
	id.PublishedThrough = to

	if _, err := id.Render(); err != nil {
		return fmt.Errorf("extend: rendered state is invalid: %w", err)
	}
	if err := id.Save(IdentityStatePath); err != nil {
		return fmt.Errorf("extend: %w", err)
	}

	fmt.Printf("Published periods %d..%d (publishedThrough=%d).\n", from, to, id.PublishedThrough)
	fmt.Fprintln(os.Stderr, "Next: `htmltrust-key did render --out <path>` and deploy the updated document.")
	return nil
}
