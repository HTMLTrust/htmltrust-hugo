package perioddid

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// PublicKeySPKIDER returns the SubjectPublicKeyInfo DER encoding of an
// Ed25519 public key (44 bytes: the constant 12-byte Ed25519 SPKI prefix plus
// the 32 raw key bytes).
func PublicKeySPKIDER(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("perioddid: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// PublicKeySPKIBase64 returns the unpadded standard Base64 of the public
// key's SPKI DER, the encoding used for the `publicKey` member of an HTTPS
// period key document (spec §9.10).
func PublicKeySPKIBase64(pub ed25519.PublicKey) (string, error) {
	der, err := PublicKeySPKIDER(pub)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(der), nil
}

// PublicKeySPKIPEM returns the PEM encoding of the public key's SPKI DER,
// with no trailing newline after the END line, matching the exact string
// form stored in a DID document's `publicKeyPem` member.
func PublicKeySPKIPEM(pub ed25519.PublicKey) (string, error) {
	der, err := PublicKeySPKIDER(pub)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return strings.TrimRight(string(pem.EncodeToMemory(block)), "\n"), nil
}

// ParseSPKIPEMEd25519 parses a PEM-encoded Ed25519 SubjectPublicKeyInfo
// (`publicKeyPem` from a DID document or key document) and returns the raw
// 32-byte public key.
func ParseSPKIPEMEd25519(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("perioddid: no PEM block found in publicKeyPem")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("perioddid: parse SPKI: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("perioddid: publicKeyPem contains %T, not Ed25519", key)
	}
	return pub, nil
}

// ParsePKCS8PEMEd25519 parses a PEM-encoded PKCS#8 Ed25519 private key (the
// form htmltrust-sign's --keyfile, HTMLTRUST_SIGNING_KEY, and an imported
// --anchor-key file all use).
func ParsePKCS8PEMEd25519(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("perioddid: no PEM block found")
	}
	return ParsePKCS8DEREd25519(block.Bytes)
}

// ParsePKCS8DEREd25519 parses a raw (non-PEM) PKCS#8 DER-encoded Ed25519
// private key, the form the encrypted secret file's `master`-adjacent
// `anchorKey` member stores (as unpadded Base64 of this DER).
func ParsePKCS8DEREd25519(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("perioddid: parse PKCS8: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("perioddid: PEM contains %T, not Ed25519", key)
	}
	return priv, nil
}

// PublicKeyHash returns the unpadded standard Base64 SHA-256 of the public
// key's SPKI DER, the encoding used for a revocation entry's
// `publicKeyHash` (spec §9.7/§9.10).
func PublicKeyHash(pub ed25519.PublicKey) (string, error) {
	der, err := PublicKeySPKIDER(pub)
	if err != nil {
		return "", err
	}
	return hashSHA256B64(der), nil
}

// PrivateKeyPKCS8DER returns the PKCS#8 DER encoding of an Ed25519 private
// key (48 bytes: a constant 16-byte prefix plus the 32-byte seed).
func PrivateKeyPKCS8DER(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("perioddid: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	return x509.MarshalPKCS8PrivateKey(priv)
}

// PrivateKeyPKCS8Base64 returns the unpadded standard Base64 of the private
// key's PKCS#8 DER.
func PrivateKeyPKCS8Base64(priv ed25519.PrivateKey) (string, error) {
	der, err := PrivateKeyPKCS8DER(priv)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(der), nil
}

// PrivateKeyPKCS8PEM returns the PEM encoding (`BEGIN PRIVATE KEY`) of an
// Ed25519 private key's PKCS#8 DER, the form htmltrust-sign's --keyfile and
// HTMLTRUST_SIGNING_KEY already accept.
func PrivateKeyPKCS8PEM(priv ed25519.PrivateKey) (string, error) {
	der, err := PrivateKeyPKCS8DER(priv)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// JWK is the browser custody encoding of an Ed25519 private key: an OKP JSON
// Web Key with base64url (unpadded) `d` (seed) and `x` (public key), the
// shape `crypto.subtle.importKey("jwk", ...)` accepts for Ed25519.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	D   string `json:"d"`
	X   string `json:"x"`
}

// PrivateKeyJWK returns the JWK encoding of an Ed25519 private key.
func PrivateKeyJWK(priv ed25519.PrivateKey) (JWK, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return JWK{}, fmt.Errorf("perioddid: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	seed := priv.Seed()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return JWK{}, fmt.Errorf("perioddid: could not derive public key")
	}
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		D:   base64.RawURLEncoding.EncodeToString(seed),
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}, nil
}

// GenerateMaster returns MasterSize cryptographically secure random bytes,
// suitable as a period master seed or an independently generated anchor key
// seed. It MUST NOT be derived from a passphrase (spec §9.10).
func GenerateMaster() ([]byte, error) {
	buf := make([]byte, MasterSize)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("perioddid: generate random bytes: %w", err)
	}
	return buf, nil
}

// GenerateAnchorKey generates a fresh Ed25519 key pair for a revocation
// anchor. It MUST NOT be derived from the period master (spec §9.10, Decision
// 9): deriving it from the master would let theft of the master also take
// the revocation list.
func GenerateAnchorKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("perioddid: generate anchor key: %w", err)
	}
	return priv, nil
}
