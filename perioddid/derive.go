// Package perioddid implements the HTMLTrust period-scoped signing key
// scheme (htmltrust-period-v1, spec draft §9.10): HKDF-SHA-256 derivation of
// one Ed25519 key per period from an offline master seed, rendering and
// parsing of period-scoped DID documents, and signing/verification of
// range-revocation lists. It is shared by cmd/htmltrust-key (the offline
// ceremony) and cmd/htmltrust-sign (online period discovery).
package perioddid

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// PeriodSalt is the constant HKDF-Extract salt for scheme htmltrust-period-v1.
const PeriodSalt = "htmltrust-period-key-v1"

// PeriodScheme is the periodScheme constant this package implements.
const PeriodScheme = "htmltrust-period-v1"

// MinPeriod and MaxPeriod bound the wire range of a period index (spec §9.10,
// "Terms": a period fragment's value is 1 through 2147483647; 0 is reserved).
const (
	MinPeriod uint32 = 1
	MaxPeriod uint32 = 2147483647
)

// MasterSize is the required length in bytes of a period master seed.
const MasterSize = 32

// ValidPeriod reports whether n falls in the wire range 1 through 2147483647.
func ValidPeriod(n uint32) bool {
	return n >= MinPeriod && n <= MaxPeriod
}

// periodInfo builds the HKDF-Expand info parameter:
//
//	info = UTF-8 "ed25519" || 0x00 || UTF-8 identity || 0x00 || uint32be(N)
func periodInfo(identity string, n uint32) ([]byte, error) {
	if !ValidPeriod(n) {
		return nil, fmt.Errorf("perioddid: period index %d out of range [%d, %d]", n, MinPeriod, MaxPeriod)
	}
	if strings.IndexByte(identity, 0) != -1 {
		return nil, fmt.Errorf("perioddid: identity must not contain U+0000")
	}
	if identity == "" {
		return nil, fmt.Errorf("perioddid: identity must not be empty")
	}
	info := make([]byte, 0, len("ed25519")+1+len(identity)+1+4)
	info = append(info, "ed25519"...)
	info = append(info, 0x00)
	info = append(info, identity...)
	info = append(info, 0x00)
	info = binary.BigEndian.AppendUint32(info, n)
	return info, nil
}

// DerivePRK computes the HKDF-Extract pseudorandom key from a 32-byte master
// seed. It is exposed so tooling can print/cross-check the intermediate PRK
// value against the Appendix A vector.
func DerivePRK(master []byte) ([]byte, error) {
	if len(master) != MasterSize {
		return nil, fmt.Errorf("perioddid: master must be exactly %d bytes, got %d", MasterSize, len(master))
	}
	prk, err := hkdf.Extract(sha256.New, master, []byte(PeriodSalt))
	if err != nil {
		return nil, fmt.Errorf("perioddid: HKDF-Extract: %w", err)
	}
	return prk, nil
}

// DerivePeriodSeed derives the 32-byte Ed25519 private key seed for period n
// of identity, from the 32-byte master seed, per spec §9.10 "Key derivation".
func DerivePeriodSeed(master []byte, identity string, n uint32) ([]byte, error) {
	prk, err := DerivePRK(master)
	if err != nil {
		return nil, err
	}
	return ExpandPeriodSeed(prk, identity, n)
}

// ExpandPeriodSeed derives the 32-byte Ed25519 seed for period n of identity
// from an already-extracted PRK. Split out from DerivePeriodSeed so callers
// deriving many periods pay the HKDF-Extract cost once.
func ExpandPeriodSeed(prk []byte, identity string, n uint32) ([]byte, error) {
	info, err := periodInfo(identity, n)
	if err != nil {
		return nil, err
	}
	seed, err := hkdf.Expand(sha256.New, prk, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("perioddid: HKDF-Expand: %w", err)
	}
	return seed, nil
}

// DerivePeriodKey derives the Ed25519 private key for period n of identity
// from the 32-byte master seed.
func DerivePeriodKey(master []byte, identity string, n uint32) (ed25519.PrivateKey, error) {
	seed, err := DerivePeriodSeed(master, identity, n)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
