package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

// IdentityStatePath is the default path of the public state file relative
// to the working directory.
const IdentityStatePath = ".htmltrust/identity.json"

// SecretStatePath is the default path of the encrypted secret file relative
// to the working directory.
const SecretStatePath = ".htmltrust/identity.secret.age"

// Anchor is one anchor method the CLI's local state tracks. Role is
// informational ("legacy" for a migrated identity's original key, or
// "revocation" for a freshly generated one); the field that governs
// behaviour is Identity.SigningAnchor, which names the anchor fragment that
// currently signs the revocation list.
type Anchor struct {
	ID           string `json:"id"` // fragment form, e.g. "#key-1" or "#rev"
	PublicKeyPem string `json:"publicKeyPem"`
	Role         string `json:"role"` // "legacy" or "revocation"
	Revoked      bool   `json:"revoked,omitempty"`
}

// Period is one period method the CLI's local state tracks. Only the public
// key is ever stored here; private key material lives solely in the
// encrypted secret file (for the master) or is never written to disk at all
// (a derived period key, unless the operator passes --out to `derive`).
type Period struct {
	N            int    `json:"n"`
	PublicKeyPem string `json:"publicKeyPem"`
	Revoked      bool   `json:"revoked,omitempty"`
}

// Identity is the public state file .htmltrust/identity.json: the
// publisher's record of every published public key. `did render` emits the
// DID document from it and `did check` compares the served document against
// it. It carries no private key material.
type Identity struct {
	Identity         string   `json:"identity"`
	PeriodScheme     string   `json:"periodScheme"`
	PeriodEpoch      string   `json:"periodEpoch"`
	PeriodLength     string   `json:"periodLength"`
	Anchors          []Anchor `json:"anchors"`
	Periods          []Period `json:"periods"`
	Authentication   []string `json:"authentication,omitempty"`
	DerivedThrough   int      `json:"derivedThrough"`
	PublishedThrough int      `json:"publishedThrough"`

	// SigningAnchor is the fragment (e.g. "#key-1") of the anchor that
	// currently signs the revocation list. It starts as the first anchor
	// and moves only when `revoke --anchor` rotates it (spec §9.10,
	// "Range revocation" -> Signer rule; design decision 10).
	SigningAnchor string `json:"signingAnchor"`
}

// LoadIdentity reads and parses the state file at path.
func LoadIdentity(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &id, nil
}

// Save writes the state file to path, creating its directory if needed.
func (id *Identity) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Anchor looks up an anchor by its fragment (e.g. "#key-1").
func (id *Identity) Anchor(fragment string) (*Anchor, bool) {
	for i := range id.Anchors {
		if id.Anchors[i].ID == fragment {
			return &id.Anchors[i], true
		}
	}
	return nil, false
}

// SigningAnchorEntry returns the anchor that currently signs the revocation
// list.
func (id *Identity) SigningAnchorEntry() (*Anchor, error) {
	a, ok := id.Anchor(id.SigningAnchor)
	if !ok {
		return nil, fmt.Errorf("state: signingAnchor %q does not name a known anchor", id.SigningAnchor)
	}
	return a, nil
}

// Period looks up a period entry by index.
func (id *Identity) Period(n int) (*Period, bool) {
	for i := range id.Periods {
		if id.Periods[i].N == n {
			return &id.Periods[i], true
		}
	}
	return nil, false
}

// RenderInput converts the state into perioddid.RenderInput for `did
// render`.
func (id *Identity) RenderInput() perioddid.RenderInput {
	in := perioddid.RenderInput{
		Identity:       id.Identity,
		PeriodScheme:   id.PeriodScheme,
		PeriodEpoch:    id.PeriodEpoch,
		PeriodLength:   id.PeriodLength,
		Authentication: id.Authentication,
	}
	for _, a := range id.Anchors {
		in.Anchors = append(in.Anchors, perioddid.AnchorSpec{
			Fragment:     a.ID,
			PublicKeyPem: a.PublicKeyPem,
			Revoked:      a.Revoked,
		})
	}
	for _, p := range id.Periods {
		in.Periods = append(in.Periods, perioddid.PeriodSpec{
			N:            uint32(p.N),
			PublicKeyPem: p.PublicKeyPem,
			Revoked:      p.Revoked,
		})
	}
	return in
}

// Render builds the DID document for this identity's current state.
func (id *Identity) Render() (*perioddid.Document, error) {
	return perioddid.RenderDocument(id.RenderInput())
}
