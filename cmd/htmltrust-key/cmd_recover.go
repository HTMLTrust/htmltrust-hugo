package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

// cmdRecover rebuilds .htmltrust/identity.json from a served DID document
// and the still-present encrypted secret file, for when the state file
// alone was lost or corrupted. It writes nothing until every published
// period public key has been reproduced byte for byte from the decrypted
// master; any mismatch means the wrong master (or a served document this
// identity did not produce) and the command refuses.
func cmdRecover(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key recover", flag.ContinueOnError)
	didDocument := fs.String("did-document", "", "required URL or local path of the served DID document to rebuild from")
	force := fs.Bool("force", false, "overwrite an existing "+IdentityStatePath)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *didDocument == "" {
		return fmt.Errorf("recover: --did-document is required")
	}
	if !*force {
		if _, err := os.Stat(IdentityStatePath); err == nil {
			return fmt.Errorf("recover: %s already exists; pass --force to rebuild it anyway", IdentityStatePath)
		}
	}

	doc, err := perioddid.LoadDocument(*didDocument)
	if err != nil {
		return fmt.Errorf("recover: load %s: %w", *didDocument, err)
	}
	if err := doc.Validate(); err != nil {
		return fmt.Errorf("recover: %s: %w", *didDocument, err)
	}

	passphrase, err := ReadPassphraseOnce("Passphrase for " + SecretStatePath + ": ")
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	secret, err := LoadSecret(SecretStatePath, passphrase)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	if secret.Identity != doc.ID {
		return fmt.Errorf("recover: secret file identity %q does not match served document id %q", secret.Identity, doc.ID)
	}
	master, err := secret.MasterBytes()
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	anchorPriv, err := secret.AnchorPrivateKey()
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	anchorPub, ok := anchorPriv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("recover: could not derive anchor public key")
	}

	var (
		anchors       []Anchor
		periods       []Period
		signingAnchor string
		published     int
	)
	for _, m := range doc.VerificationMethod {
		frag := docFragment(m.ID, doc.ID)
		if frag == "" {
			return fmt.Errorf("recover: served document method %q has no fragment", m.ID)
		}
		if n, isPeriod := perioddid.ParsePeriodFragment(fragmentTail(frag)); isPeriod {
			want, perr := perioddid.ParseSPKIPEMEd25519(m.PublicKeyPem)
			if perr != nil {
				return fmt.Errorf("recover: parse %s: %w", m.ID, perr)
			}
			got, derr := perioddid.DerivePeriodKey(master, doc.ID, n)
			if derr != nil {
				return fmt.Errorf("recover: derive period %d: %w", n, derr)
			}
			gotPub, ok := got.Public().(ed25519.PublicKey)
			if !ok || !gotPub.Equal(want) {
				return fmt.Errorf("recover: period %d's served public key does not match the key this master derives; refusing to write anything (wrong master, or a document this identity did not produce)", n)
			}
			periods = append(periods, Period{N: int(n), PublicKeyPem: m.PublicKeyPem, Revoked: m.Revoked})
			if int(n) > published {
				published = int(n)
			}
			continue
		}
		role := "legacy"
		pub, perr := perioddid.ParseSPKIPEMEd25519(m.PublicKeyPem)
		if perr == nil && pub.Equal(anchorPub) {
			signingAnchor = frag
			role = "revocation"
		}
		anchors = append(anchors, Anchor{ID: frag, PublicKeyPem: m.PublicKeyPem, Role: role, Revoked: m.Revoked})
	}
	if signingAnchor == "" {
		return fmt.Errorf("recover: no anchor method in the served document matches the secret file's anchor key; cannot determine which anchor signs the revocation list")
	}

	var authentication []string
	for _, a := range doc.Authentication {
		if frag := docFragment(a, doc.ID); frag != "" {
			authentication = append(authentication, frag)
		}
	}

	id := &Identity{
		Identity:         doc.ID,
		Anchors:          anchors,
		Periods:          periods,
		Authentication:   authentication,
		DerivedThrough:   0,
		PublishedThrough: published,
		SigningAnchor:    signingAnchor,
	}
	if doc.Htmltrust != nil {
		id.PeriodScheme = doc.Htmltrust.PeriodScheme
		id.PeriodEpoch = doc.Htmltrust.PeriodEpoch
		id.PeriodLength = doc.Htmltrust.PeriodLength
	} else {
		id.PeriodScheme = perioddid.PeriodScheme
	}

	rebuilt, err := id.Render()
	if err != nil {
		return fmt.Errorf("recover: rebuilt state does not render a valid document: %w", err)
	}
	if diffs := perioddid.Diff(rebuilt, doc); len(diffs) > 0 {
		fmt.Fprintln(os.Stderr, "htmltrust-key: warning: rebuilt state renders a document that differs from the served one (informational fields only, since every key matched):")
		for _, d := range diffs {
			fmt.Fprintf(os.Stderr, "  - %s\n", d)
		}
	}

	if err := id.Save(IdentityStatePath); err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	fmt.Printf("Rebuilt %s from %s: %d anchor(s), periods 1..%d, signing anchor %s.\n", IdentityStatePath, *didDocument, len(anchors), published, signingAnchor)
	fmt.Fprintln(os.Stderr, "derivedThrough was set to 0: the document reveals which periods are PUBLISHED, not which were ever DELIVERED to an online signer. If you know the last period actually in use, edit derivedThrough in "+IdentityStatePath+" before running `derive` again, so a stale key cannot be handed out silently.")
	return nil
}

// fragmentTail strips the leading '#' from a fragment string, e.g. "#p3" ->
// "p3", so it can be matched against the period fragment grammar.
func fragmentTail(fragment string) string {
	if len(fragment) > 0 && fragment[0] == '#' {
		return fragment[1:]
	}
	return fragment
}
