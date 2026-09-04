package main

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

// PeriodDiscovery is the result of matching the signer's loaded private key
// against the identity's DID document (tooling spec, "htmltrust-sign:
// period discovery"). Keyid is what every signature this run embeds:
// "<identity>#p<N>" on a period match, or the bare identity on an anchor
// match.
type PeriodDiscovery struct {
	Keyid    string
	Period   int // 0 for an anchor match (period keys not in use)
	Document *perioddid.Document
}

// DiscoverPeriod resolves period discovery for identity, using priv's
// public half. didDocumentSource is --did-document; when empty, it is
// derived from identity (did:web only -- any other identity form requires
// --did-document explicitly). A load failure or a private key that matches
// no verificationMethod is a fatal error: the caller must sign nothing.
func DiscoverPeriod(priv ed25519.PrivateKey, identity, didDocumentSource string) (*PeriodDiscovery, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("could not derive an Ed25519 public key from the loaded private key")
	}

	source := didDocumentSource
	if source == "" {
		derived, err := perioddid.DidWebDocumentURL(identity)
		if err != nil {
			return nil, fmt.Errorf("cannot derive a default DID document location for --keyid %q: %w (pass --did-document explicitly)", identity, err)
		}
		source = derived
	}

	doc, err := perioddid.LoadDocument(source)
	if err != nil {
		return nil, fmt.Errorf("load DID document from %s: %w", source, err)
	}
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}

	match, ok := doc.FindByPublicKey(pub)
	if !ok {
		return nil, fmt.Errorf("no verificationMethod in %s matches the loaded private key; is the wrong key installed, or has the DID document not been deployed yet?", source)
	}

	if match.IsPeriod {
		return &PeriodDiscovery{Keyid: match.MethodID, Period: int(match.Period), Document: doc}, nil
	}

	fmt.Fprintf(os.Stderr, "htmltrust-sign: warning: the loaded private key matches anchor %s, not a period method; period keys are not in use for this run\n", match.MethodID)
	return &PeriodDiscovery{Keyid: identity, Period: 0, Document: doc}, nil
}
