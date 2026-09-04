package perioddid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// RevocationEntry is a Section 9.6 revocation-list entry, extended with the
// three OPTIONAL range members of spec §9.10 "Range revocation".
type RevocationEntry struct {
	Keyid         string `json:"keyid"`
	Status        string `json:"status"`
	RevokedAt     string `json:"revokedAt,omitempty"`
	SupersededBy  string `json:"supersededBy,omitempty"`
	PublicKeyHash string `json:"publicKeyHash,omitempty"`
	FromPeriod    *int   `json:"from-period,omitempty"`
	ToPeriod      *int   `json:"to-period,omitempty"`
	Identity      string `json:"identity,omitempty"`
}

// RevocationList is an identity's signed revocation list.
type RevocationList struct {
	Signer      string            `json:"signer"`
	Algorithm   string            `json:"algorithm"`
	Timestamp   string            `json:"timestamp"`
	Revocations []RevocationEntry `json:"revocations"`
	Signature   string            `json:"signature,omitempty"`
}

// NewRangeEntry builds a range-revocation entry for a did: identity per spec
// §9.10: by convention, `keyid` is the keyid of the first struck period and
// `publicKeyHash` is that period's key hash, so a verifier that does not
// implement range revocation still strikes that one period by exact match.
func NewRangeEntry(identity string, from uint32, to *uint32, struckPublicKey ed25519.PublicKey, revokedAt string) (RevocationEntry, error) {
	if !ValidPeriod(from) {
		return RevocationEntry{}, fmt.Errorf("perioddid: from-period %d out of range [%d, %d]", from, MinPeriod, MaxPeriod)
	}
	hash, err := PublicKeyHash(struckPublicKey)
	if err != nil {
		return RevocationEntry{}, err
	}
	fromInt := int(from)
	entry := RevocationEntry{
		Keyid:         fmt.Sprintf("%s#p%d", identity, from),
		Status:        "revoked",
		RevokedAt:     revokedAt,
		PublicKeyHash: hash,
		FromPeriod:    &fromInt,
	}
	if to != nil {
		if *to <= from {
			return RevocationEntry{}, fmt.Errorf("perioddid: to-period %d must be greater than from-period %d", *to, from)
		}
		toInt := int(*to)
		entry.ToPeriod = &toInt
	}
	return entry, nil
}

// SigningPayload returns the JCS (RFC 8785) canonicalization of the list
// with its `signature` member omitted entirely — the exact bytes an anchor
// key signs and a verifier re-derives to check that signature.
func (l *RevocationList) SigningPayload() ([]byte, error) {
	unsigned := *l
	unsigned.Signature = ""
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("perioddid: marshal revocation list: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("perioddid: JCS canonicalize revocation list: %w", err)
	}
	return canonical, nil
}

// SignRevocationList signs l with the anchor private key, setting l.Signature
// to the unpadded standard Base64 Ed25519 signature over the JCS signing
// payload. The signer of a revocation list MUST be an anchor key, never a
// period key (spec §9.10 "Signer"); this function does not itself enforce
// that, since it has no document to check the key's role against — callers
// resolve the signer method and confirm it is an anchor before calling this.
func SignRevocationList(l *RevocationList, anchor ed25519.PrivateKey) error {
	payload, err := l.SigningPayload()
	if err != nil {
		return err
	}
	l.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(anchor, payload))
	return nil
}

// VerifyRevocationList reports whether l's signature verifies under the
// anchor public key.
func VerifyRevocationList(l *RevocationList, anchor ed25519.PublicKey) (bool, error) {
	if l.Signature == "" {
		return false, fmt.Errorf("perioddid: revocation list has no signature")
	}
	payload, err := l.SigningPayload()
	if err != nil {
		return false, err
	}
	sig, err := base64.RawStdEncoding.DecodeString(l.Signature)
	if err != nil {
		return false, fmt.Errorf("perioddid: decode signature: %w", err)
	}
	return ed25519.Verify(anchor, payload, sig), nil
}

// MarshalPretty renders the list as indented JSON (two-space indent) in
// declaration field order (signer, algorithm, timestamp, revocations,
// signature), matching spec §9.10's worked example.
func (l *RevocationList) MarshalPretty() ([]byte, error) {
	return json.MarshalIndent(l, "", "  ")
}

// ParseRevocationList parses a revocation list from raw JSON bytes.
func ParseRevocationList(raw []byte) (*RevocationList, error) {
	var list RevocationList
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("perioddid: parse revocation list: %w", err)
	}
	return &list, nil
}
