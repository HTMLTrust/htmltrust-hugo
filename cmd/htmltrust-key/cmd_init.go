package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

const backupInstruction = `IMPORTANT: back up ` + SecretStatePath + ` and its passphrase now, together,
somewhere durable (a password manager entry, an encrypted archive off this
machine). That file plus the passphrase is the complete backup of this
identity's offline tier: the period master seed and the revocation anchor
private key. There is no other copy. Losing both means the identity can
only continue from its next unpublished period, under a new anchor, via the
DID-document recovery route -- every already-published period stays
verifiable, but nothing yet-unpublished can ever be signed with the old
anchor again.

`

func cmdInit(args []string) error {
	fmt.Fprint(os.Stderr, backupInstruction)

	fs := flag.NewFlagSet("htmltrust-key init", flag.ContinueOnError)
	identity := fs.String("identity", "", "required identity, for example did:web:jason-grey.com")
	didDocument := fs.String("did-document", "", "URL or local path of an existing served DID document to migrate from")
	anchorKeyPath := fs.String("anchor-key", "", "PEM-encoded PKCS#8 Ed25519 private key to import as the migrated identity's revocation anchor (required with --did-document when a served document exists)")
	periodLength := fs.String("period-length", "P1M", "ISO 8601 period length, for example P1M or P3M")
	epochFlag := fs.String("epoch", "", "RFC3339 or YYYY-MM-DD nominal start of period 1 (default: today, UTC midnight)")
	ahead := fs.Int("ahead", 12, "number of period public keys to pre-publish")
	allowShort := fs.Bool("allow-short-period", false, "allow a period shorter than one month")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *identity == "" {
		return fmt.Errorf("init: --identity is required")
	}
	if *ahead < 1 {
		return fmt.Errorf("init: --ahead must be at least 1")
	}
	dur, err := parseISODuration(*periodLength)
	if err != nil {
		return fmt.Errorf("init: --period-length: %w", err)
	}
	if !*allowShort && dur.approxDays() < 28 {
		return fmt.Errorf("init: --period-length %q is shorter than one month; pass --allow-short-period to override", *periodLength)
	}
	epoch, err := parseEpochFlag(*epochFlag)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if epoch == "" {
		epoch = time.Now().UTC().Truncate(24 * time.Hour).Format(time.RFC3339)
	}

	if _, err := os.Stat(IdentityStatePath); err == nil {
		return fmt.Errorf("init: %s already exists; this identity is already initialized", IdentityStatePath)
	}

	if err := EnsureGitIgnored(".", SecretStatePath); err != nil {
		return fmt.Errorf("init: %w", err)
	}

	var (
		anchors        []Anchor
		signingFrag    string
		anchorPrivKey  ed25519.PrivateKey
		anchorKeyFile  string
		authentication []string
	)

	if *didDocument != "" {
		doc, loadErr := perioddid.LoadDocument(*didDocument)
		switch {
		case loadErr == nil:
			if doc.ID != *identity {
				return fmt.Errorf("init: served document id %q does not match --identity %q", doc.ID, *identity)
			}
			if len(doc.VerificationMethod) == 0 {
				return fmt.Errorf("init: served document at %s has no verificationMethod entries", *didDocument)
			}
			if *anchorKeyPath == "" {
				return fmt.Errorf("init: %s already serves a DID document; pass --anchor-key with the private key for %s to migrate it", *didDocument, doc.VerificationMethod[0].ID)
			}
			anchorPEMBytes, readErr := os.ReadFile(*anchorKeyPath)
			if readErr != nil {
				return fmt.Errorf("init: read --anchor-key: %w", readErr)
			}
			priv, parseErr := perioddid.ParsePKCS8PEMEd25519(anchorPEMBytes)
			if parseErr != nil {
				return fmt.Errorf("init: parse --anchor-key: %w", parseErr)
			}
			firstPub, parseErr := perioddid.ParseSPKIPEMEd25519(doc.VerificationMethod[0].PublicKeyPem)
			if parseErr != nil {
				return fmt.Errorf("init: parse served document's first method: %w", parseErr)
			}
			privPub, ok := priv.Public().(ed25519.PublicKey)
			if !ok || !privPub.Equal(firstPub) {
				return fmt.Errorf("init: --anchor-key does not match %s's public key", doc.VerificationMethod[0].ID)
			}
			for _, m := range doc.VerificationMethod {
				frag := docFragment(m.ID, doc.ID)
				if frag == "" {
					return fmt.Errorf("init: served document method %q has no fragment", m.ID)
				}
				anchors = append(anchors, Anchor{ID: frag, PublicKeyPem: m.PublicKeyPem, Role: "legacy", Revoked: m.Revoked})
			}
			signingFrag = anchors[0].ID
			anchorPrivKey = priv
			anchorKeyFile = *anchorKeyPath
			authentication = []string{signingFrag}
			for _, a := range doc.Authentication {
				if frag := docFragment(a, doc.ID); frag != "" && frag != signingFrag {
					authentication = append(authentication, frag)
				}
			}
		case errors.Is(loadErr, perioddid.ErrDocumentNotFound):
			// No document served yet: fall through to the fresh-identity path.
		default:
			return fmt.Errorf("init: load --did-document: %w", loadErr)
		}
	}

	if len(anchors) == 0 {
		priv, genErr := perioddid.GenerateAnchorKey()
		if genErr != nil {
			return fmt.Errorf("init: %w", genErr)
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("init: could not derive anchor public key")
		}
		pem, pemErr := perioddid.PublicKeySPKIPEM(pub)
		if pemErr != nil {
			return fmt.Errorf("init: %w", pemErr)
		}
		anchors = []Anchor{{ID: "#rev", PublicKeyPem: pem, Role: "revocation"}}
		signingFrag = "#rev"
		anchorPrivKey = priv
	}

	master, err := perioddid.GenerateMaster()
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}

	var periods []Period
	for n := 1; n <= *ahead; n++ {
		priv, derr := perioddid.DerivePeriodKey(master, *identity, uint32(n))
		if derr != nil {
			return fmt.Errorf("init: derive period %d public key: %w", n, derr)
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("init: could not derive period %d public key", n)
		}
		pem, perr := perioddid.PublicKeySPKIPEM(pub)
		if perr != nil {
			return fmt.Errorf("init: %w", perr)
		}
		periods = append(periods, Period{N: n, PublicKeyPem: pem})
	}

	id := &Identity{
		Identity:         *identity,
		PeriodScheme:     perioddid.PeriodScheme,
		PeriodEpoch:      epoch,
		PeriodLength:     *periodLength,
		Anchors:          anchors,
		Periods:          periods,
		Authentication:   authentication,
		DerivedThrough:   0,
		PublishedThrough: *ahead,
		SigningAnchor:    signingFrag,
	}
	if _, err := id.Render(); err != nil {
		return fmt.Errorf("init: rendered state is invalid: %w", err)
	}

	passphrase, err := ReadPassphraseTwice(
		"New passphrase for "+SecretStatePath+": ",
		"Confirm passphrase: ",
	)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}

	anchorKeyB64, err := perioddid.PrivateKeyPKCS8Base64(anchorPrivKey)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	secret := &Secret{
		Scheme:    perioddid.PeriodScheme,
		Identity:  *identity,
		Master:    base64.RawStdEncoding.EncodeToString(master),
		AnchorKey: anchorKeyB64,
	}

	if err := id.Save(IdentityStatePath); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if err := SaveSecret(SecretStatePath, secret, passphrase); err != nil {
		return fmt.Errorf("init: %w", err)
	}

	if anchorKeyFile != "" {
		if err := os.Remove(anchorKeyFile); err != nil {
			fmt.Fprintf(os.Stderr, "htmltrust-key: warning: could not delete imported plaintext key %s: %v\n", anchorKeyFile, err)
		} else {
			fmt.Fprintf(os.Stderr, "Deleted the plaintext imported key %s; its private half now lives only inside %s.\n", anchorKeyFile, SecretStatePath)
		}
	}

	fmt.Printf("Initialized %s.\n", *identity)
	fmt.Printf("  anchor:             %s (%s)\n", signingFrag, anchors[0].Role)
	fmt.Printf("  master fingerprint: %s\n", masterFingerprint(master))
	fmt.Printf("  periods published:  1..%d\n", *ahead)
	fmt.Printf("  state files:        %s, %s\n", IdentityStatePath, SecretStatePath)
	fmt.Println("Next: `htmltrust-key did render --out <path>`, deploy it, then `htmltrust-key derive --period 1` to deliver the first period key.")
	return nil
}

func docFragment(id, docID string) string {
	if strings.HasPrefix(id, "#") {
		return id
	}
	if strings.HasPrefix(id, docID) {
		return strings.TrimPrefix(id, docID)
	}
	return ""
}

var isoDurationRe = regexp.MustCompile(`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?$`)

type isoDuration struct {
	Years, Months, Weeks, Days int
}

func (d isoDuration) approxDays() int {
	return d.Years*365 + d.Months*30 + d.Weeks*7 + d.Days
}

func parseISODuration(s string) (isoDuration, error) {
	if s == "" || s == "P" {
		return isoDuration{}, fmt.Errorf("invalid ISO 8601 duration %q", s)
	}
	m := isoDurationRe.FindStringSubmatch(s)
	if m == nil {
		return isoDuration{}, fmt.Errorf("invalid ISO 8601 duration %q", s)
	}
	atoi := func(v string) int {
		if v == "" {
			return 0
		}
		n, _ := strconv.Atoi(v)
		return n
	}
	d := isoDuration{Years: atoi(m[1]), Months: atoi(m[2]), Weeks: atoi(m[3]), Days: atoi(m[4])}
	if d.approxDays() == 0 {
		return isoDuration{}, fmt.Errorf("invalid ISO 8601 duration %q", s)
	}
	return d, nil
}

func parseEpochFlag(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("invalid --epoch %q: want RFC3339 or YYYY-MM-DD", raw)
}
