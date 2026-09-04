package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

func cmdDerive(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key derive", flag.ContinueOnError)
	period := fs.Int("period", 0, "required period index to deliver")
	asJWK := fs.Bool("jwk", false, "print the browser-custody JWK instead of PKCS#8 PEM")
	out := fs.String("out", "", "write the key to this path (mode 0600) instead of stdout")
	skip := fs.Bool("skip", false, "allow skipping past derivedThrough+1 (a mishandled index)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *period < 1 {
		return fmt.Errorf("derive: --period is required and must be at least 1")
	}
	n := *period

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		return fmt.Errorf("derive: %w", err)
	}
	if n <= id.DerivedThrough {
		return fmt.Errorf("derive: period %d was already delivered (derivedThrough=%d); indices must not be reused", n, id.DerivedThrough)
	}
	if n > id.DerivedThrough+1 && !*skip {
		return fmt.Errorf("derive: period %d skips past derivedThrough+1 (%d); pass --skip to confirm you intend to skip a mishandled index", n, id.DerivedThrough+1)
	}
	if p, ok := id.Period(n); !ok {
		fmt.Fprintf(os.Stderr, "htmltrust-key: warning: period %d is not yet published in %s (publishedThrough=%d); its public key is not on the DID document\n", n, IdentityStatePath, id.PublishedThrough)
	} else if p.Revoked {
		fmt.Fprintf(os.Stderr, "htmltrust-key: warning: period %d is marked revoked in local state; delivering it anyway because you asked to\n", n)
	}

	passphrase, err := ReadPassphraseOnce("Passphrase for " + SecretStatePath + ": ")
	if err != nil {
		return fmt.Errorf("derive: %w", err)
	}
	secret, err := LoadSecret(SecretStatePath, passphrase)
	if err != nil {
		return fmt.Errorf("derive: %w", err)
	}
	master, err := secret.MasterBytes()
	if err != nil {
		return fmt.Errorf("derive: %w", err)
	}
	if secret.Identity != id.Identity {
		return fmt.Errorf("derive: secret file identity %q does not match state file identity %q", secret.Identity, id.Identity)
	}

	priv, err := perioddid.DerivePeriodKey(master, id.Identity, uint32(n))
	if err != nil {
		return fmt.Errorf("derive: %w", err)
	}
	if p, ok := id.Period(n); ok {
		pub, ok2 := priv.Public().(ed25519.PublicKey)
		want, perr := perioddid.ParseSPKIPEMEd25519(p.PublicKeyPem)
		if ok2 && perr == nil && !pub.Equal(want) {
			return fmt.Errorf("derive: derived period %d public key does not match the one published in %s; refusing to hand out a key that would not verify", n, IdentityStatePath)
		}
	}

	if err := deliverKey(priv, n, *asJWK, *out); err != nil {
		return fmt.Errorf("derive: %w", err)
	}

	id.DerivedThrough = n
	if err := id.Save(IdentityStatePath); err != nil {
		return fmt.Errorf("derive: %w", err)
	}

	dest := "stdout"
	if *out != "" {
		dest = *out
	}
	fmt.Fprintf(os.Stderr, "Delivered period %d's private key to %s. Delete it from every online location as soon as the next period's key replaces it -- that deletion is the entire security property.\n", n, dest)
	return nil
}

func deliverKey(priv ed25519.PrivateKey, period int, asJWK bool, out string) error {
	var payload []byte
	if asJWK {
		jwk, err := perioddid.PrivateKeyJWK(priv)
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(jwk, "", "  ")
		if err != nil {
			return err
		}
		payload = append(encoded, '\n')
	} else {
		pem, err := perioddid.PrivateKeyPKCS8PEM(priv)
		if err != nil {
			return err
		}
		payload = []byte(pem)
	}
	if out != "" {
		if err := os.WriteFile(out, payload, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", out, err)
		}
		return nil
	}
	_, err := os.Stdout.Write(payload)
	return err
}
