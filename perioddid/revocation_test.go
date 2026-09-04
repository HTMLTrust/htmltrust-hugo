package perioddid

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// TestSignRevocationList_AppendixVector reproduces "Alice's revocation
// list" from the spec appendix ("Period-scoped signature and range
// revocation"): a range entry striking period 2 of did:web:example.com,
// signed by the anchor #key-1. It checks the JCS signing payload and the
// resulting signature match the appendix vector byte for byte, and that the
// signature verifies under the anchor's public key.
func TestSignRevocationList_AppendixVector(t *testing.T) {
	v := loadVector(t)
	master, err := hex.DecodeString(v.MasterHex)
	if err != nil {
		t.Fatal(err)
	}
	p2Priv, err := DerivePeriodKey(master, v.Identity, 2)
	if err != nil {
		t.Fatal(err)
	}
	p2Pub := p2Priv.Public().(ed25519.PublicKey)

	entry, err := NewRangeEntry(v.Identity, 2, uint32Ptr(3), p2Pub, "2026-11-20T00:00:00Z")
	if err != nil {
		t.Fatalf("NewRangeEntry: %v", err)
	}
	const wantHash = "u9pFP1f7hN0ZLr5o7CeoCDMBPKtsL8wWDRytzwK+p/w"
	if entry.Keyid != v.Identity+"#p2" {
		t.Errorf("entry.Keyid = %q, want %q", entry.Keyid, v.Identity+"#p2")
	}
	if entry.PublicKeyHash != wantHash {
		t.Errorf("entry.PublicKeyHash = %q, want %q", entry.PublicKeyHash, wantHash)
	}
	if entry.FromPeriod == nil || *entry.FromPeriod != 2 {
		t.Errorf("entry.FromPeriod = %v, want 2", entry.FromPeriod)
	}
	if entry.ToPeriod == nil || *entry.ToPeriod != 3 {
		t.Errorf("entry.ToPeriod = %v, want 3", entry.ToPeriod)
	}

	list := &RevocationList{
		Signer:      v.Identity + "#key-1",
		Algorithm:   "ed25519",
		Timestamp:   "2026-12-01T00:00:00Z",
		Revocations: []RevocationEntry{entry},
	}

	payload, err := list.SigningPayload()
	if err != nil {
		t.Fatalf("SigningPayload: %v", err)
	}
	const wantPayload = `{"algorithm":"ed25519","revocations":[{"from-period":2,"keyid":"did:web:example.com#p2","publicKeyHash":"u9pFP1f7hN0ZLr5o7CeoCDMBPKtsL8wWDRytzwK+p/w","revokedAt":"2026-11-20T00:00:00Z","status":"revoked","to-period":3}],"signer":"did:web:example.com#key-1","timestamp":"2026-12-01T00:00:00Z"}`
	if string(payload) != wantPayload {
		t.Fatalf("JCS signing payload mismatch:\n got  %s\n want %s", payload, wantPayload)
	}

	anchorPriv := ed25519.NewKeyFromSeed([]byte(anchorSeedASCII))
	anchorPub := anchorPriv.Public().(ed25519.PublicKey)

	if err := SignRevocationList(list, anchorPriv); err != nil {
		t.Fatalf("SignRevocationList: %v", err)
	}
	const wantSignature = "d9N66Ugr/gGPS1G9+D32LoeHss1LiBXiIF1hwT2JWn7a9ct2TMuWntLzZHGC5HyiWGdUUDrDqO0LyM2FLVgaAw"
	if list.Signature != wantSignature {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", list.Signature, wantSignature)
	}

	ok, err := VerifyRevocationList(list, anchorPub)
	if err != nil {
		t.Fatalf("VerifyRevocationList: %v", err)
	}
	if !ok {
		t.Fatal("revocation list signature did not verify under the anchor public key")
	}

	// A different key must not verify it.
	other, err := DerivePeriodKey(master, v.Identity, 1)
	if err != nil {
		t.Fatal(err)
	}
	otherPub := other.Public().(ed25519.PublicKey)
	ok, err = VerifyRevocationList(list, otherPub)
	if err != nil {
		t.Fatalf("VerifyRevocationList(wrong key): %v", err)
	}
	if ok {
		t.Fatal("revocation list signature verified under the wrong public key")
	}
}

func TestNewRangeEntry_Refusals(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRangeEntry("did:web:example.com", 0, nil, pub, "2026-01-01T00:00:00Z"); err == nil {
		t.Fatal("expected error for from-period 0")
	}
	to := uint32(2)
	if _, err := NewRangeEntry("did:web:example.com", 2, &to, pub, "2026-01-01T00:00:00Z"); err == nil {
		t.Fatal("expected error when to-period <= from-period")
	}
	to = 5
	if _, err := NewRangeEntry("did:web:example.com", 5, &to, pub, "2026-01-01T00:00:00Z"); err == nil {
		t.Fatal("expected error when to-period equals from-period")
	}
}

func uint32Ptr(n uint32) *uint32 { return &n }
