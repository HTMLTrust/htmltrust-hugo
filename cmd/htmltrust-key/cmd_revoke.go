package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("htmltrust-key revoke", flag.ContinueOnError)
	from := fs.Int("from", 0, "inclusive lower bound of the struck period range")
	to := fs.Int("to", 0, "exclusive upper bound of the struck period range (default: from+1)")
	unbounded := fs.Bool("unbounded", false, "leave to-period unset, striking every period from --from onward")
	since := fs.String("since", "", "RFC3339 or YYYY-MM-DD date the compromise may have started; maps to a period and steps back one, per spec guidance for uncertain compromise dates")
	reason := fs.String("reason", "", "free-text note printed alongside the entry (not written to the signed list; the spec defines no such field)")
	anchor := fs.String("anchor", "", "fragment of an anchor key to revoke and replace (the DID-document route, for an anchor compromise), instead of a period range")
	listIn := fs.String("list", "", "existing revocation list to extend (default: start a fresh one)")
	listOut := fs.String("list-out", "", "write the updated revocation list here instead of stdout")
	didOut := fs.String("did-out", "", "write the updated DID document here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	passphrase, err := ReadPassphraseOnce("Passphrase for " + SecretStatePath + ": ")
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	secret, err := LoadSecret(SecretStatePath, passphrase)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if secret.Identity != id.Identity {
		return fmt.Errorf("revoke: secret file identity %q does not match state file identity %q", secret.Identity, id.Identity)
	}

	if *anchor != "" {
		return revokeAnchor(id, secret, passphrase, *anchor, *didOut)
	}
	return revokeRange(id, secret, *from, *to, *unbounded, *since, *reason, *listIn, *listOut, *didOut)
}

func revokeRange(id *Identity, secret *Secret, fromFlag, toFlag int, unbounded bool, since, reason, listIn, listOut, didOut string) error {
	fromN := fromFlag
	if since != "" {
		when, err := parseFlexibleTime(since)
		if err != nil {
			return fmt.Errorf("revoke: --since: %w", err)
		}
		p, err := periodAtDate(id.PeriodEpoch, id.PeriodLength, when)
		if err != nil {
			return fmt.Errorf("revoke: --since: %w", err)
		}
		if p > 1 {
			p--
		}
		if fromN == 0 {
			fromN = p
		}
	}
	if fromN < 1 {
		return fmt.Errorf("revoke: --from (or --since) is required and must resolve to a period of at least 1")
	}
	var toN *uint32
	switch {
	case unbounded:
		toN = nil
	case toFlag != 0:
		v := uint32(toFlag)
		toN = &v
	default:
		v := uint32(fromN + 1)
		toN = &v
	}

	period, ok := id.Period(fromN)
	if !ok {
		return fmt.Errorf("revoke: period %d is not published in %s; cannot compute its key hash", fromN, IdentityStatePath)
	}
	struckPub, err := perioddid.ParseSPKIPEMEd25519(period.PublicKeyPem)
	if err != nil {
		return fmt.Errorf("revoke: parse period %d public key: %w", fromN, err)
	}

	revokedAt := time.Now().UTC().Format(time.RFC3339)
	entry, err := perioddid.NewRangeEntry(id.Identity, uint32(fromN), toN, struckPub, revokedAt)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	list, err := loadOrNewRevocationList(listIn, id)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	list.Revocations = append(list.Revocations, entry)
	list.Timestamp = revokedAt

	anchorEntry, err := id.SigningAnchorEntry()
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	anchorPriv, err := secret.AnchorPrivateKey()
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	list.Signer = id.Identity + anchorEntry.ID
	if err := perioddid.SignRevocationList(list, anchorPriv); err != nil {
		return fmt.Errorf("revoke: sign revocation list: %w", err)
	}

	toN2 := fromN
	if toN != nil {
		toN2 = int(*toN) - 1
	} else {
		toN2 = id.PublishedThrough
	}
	for n := fromN; n <= toN2; n++ {
		if p, ok := id.Period(n); ok {
			p.Revoked = true
		}
	}
	// Resume past every published index regardless of how the strike is
	// bounded: a bounded strike could in principle resume as early as
	// *toN, but restarting only after publishedThrough keeps "what is safe
	// to derive next" a single number the operator never has to compute.
	resumeFrom := id.PublishedThrough + 1

	if reason != "" {
		fmt.Fprintf(os.Stderr, "Reason: %s\n", reason)
	}

	if err := id.Save(IdentityStatePath); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if err := emitDID(id, didOut); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if err := emitList(list, listOut); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Struck periods %d..%s. Resume with `htmltrust-key derive --period %d`.\n", fromN, rangeUpper(toN), resumeFrom)
	return nil
}

func revokeAnchor(id *Identity, secret *Secret, passphrase, fragment, didOut string) error {
	old, ok := id.Anchor(fragment)
	if !ok {
		return fmt.Errorf("revoke: %q is not a known anchor", fragment)
	}
	if old.Revoked {
		return fmt.Errorf("revoke: anchor %q is already revoked", fragment)
	}
	old.Revoked = true

	newPriv, err := perioddid.GenerateAnchorKey()
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	newPub, ok := newPriv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("revoke: could not derive new anchor public key")
	}
	newPem, err := perioddid.PublicKeySPKIPEM(newPub)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	newFragment := nextAnchorFragment(id, fragment)
	newAnchor := Anchor{ID: newFragment, PublicKeyPem: newPem, Role: "revocation"}

	inserted := make([]Anchor, 0, len(id.Anchors)+1)
	for _, a := range id.Anchors {
		inserted = append(inserted, a)
		if a.ID == fragment {
			inserted = append(inserted, newAnchor)
		}
	}
	id.Anchors = inserted
	id.SigningAnchor = newFragment

	newAnchorKeyB64, err := perioddid.PrivateKeyPKCS8Base64(newPriv)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	secret.AnchorKey = newAnchorKeyB64
	if err := SaveSecret(SecretStatePath, secret, passphrase); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if err := id.Save(IdentityStatePath); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if err := emitDID(id, didOut); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Revoked anchor %s; %s now signs the revocation list. Deploy the updated DID document, then re-sign the revocation list with `htmltrust-key list sign` under the new anchor.\n", fragment, newFragment)
	return nil
}

func nextAnchorFragment(id *Identity, base string) string {
	candidate := base + "2"
	for i := 2; ; i++ {
		if _, ok := id.Anchor(candidate); !ok {
			return candidate
		}
		candidate = fmt.Sprintf("%s%d", base, i+1)
	}
}

func loadOrNewRevocationList(path string, id *Identity) (*perioddid.RevocationList, error) {
	if path == "" {
		return &perioddid.RevocationList{Algorithm: "ed25519"}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	list, err := perioddid.ParseRevocationList(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return list, nil
}

func emitDID(id *Identity, out string) error {
	doc, err := id.Render()
	if err != nil {
		return err
	}
	raw, err := doc.MarshalPretty()
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if out == "" {
		fmt.Println("--- DID document ---")
		os.Stdout.Write(raw)
		return nil
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote DID document to %s.\n", out)
	return nil
}

func emitList(list *perioddid.RevocationList, out string) error {
	raw, err := list.MarshalPretty()
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if out == "" {
		fmt.Println("--- revocation list ---")
		os.Stdout.Write(raw)
		return nil
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote revocation list to %s.\n", out)
	return nil
}

func rangeUpper(to *uint32) string {
	if to == nil {
		return "(unbounded)"
	}
	return fmt.Sprintf("%d", *to-1)
}

func parseFlexibleTime(raw string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid date %q: want RFC3339 or YYYY-MM-DD", raw)
}

// periodAtDate maps a calendar date to the period index whose nominal
// window (spec §9.10: display/tooling metadata only) contains it, using a
// fixed-length approximation of the ISO 8601 period length. This is Layer 2
// convenience, never a cryptographic boundary: periods carry no time.
func periodAtDate(epoch, length string, when time.Time) (int, error) {
	epochTime, err := time.Parse(time.RFC3339, epoch)
	if err != nil {
		return 0, fmt.Errorf("parse periodEpoch %q: %w", epoch, err)
	}
	dur, err := parseISODuration(length)
	if err != nil {
		return 0, fmt.Errorf("parse periodLength %q: %w", length, err)
	}
	days := dur.approxDays()
	if days <= 0 {
		return 0, fmt.Errorf("periodLength %q resolves to zero days", length)
	}
	elapsedDays := when.Sub(epochTime).Hours() / 24
	idx := int(elapsedDays/float64(days)) + 1
	if idx < 1 {
		idx = 1
	}
	return idx, nil
}
