package perioddid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vectorFile mirrors the machine-readable derivation vector
// testdata/period-keys-v1.json, copied verbatim from the draft's Appendix A
// vector (ietf-draft/vectors/period-keys-v1.json).
type vectorFile struct {
	Scheme    string `json:"scheme"`
	MasterHex string `json:"master_hex"`
	Identity  string `json:"identity"`
	Salt      string `json:"salt"`
	PRKHex    string `json:"prk_hex"`
	Periods   []struct {
		Period               int    `json:"period"`
		InfoHex              string `json:"info_hex"`
		SeedHex              string `json:"seed_hex"`
		PublicKeyHex         string `json:"publicKey_hex"`
		PublicKeySPKIB64     string `json:"publicKey_spki_b64"`
		PrivateKeyPKCS8B64   string `json:"privateKey_pkcs8_b64"`
		PublicKeyPem         string `json:"publicKeyPem"`
		PublicKeyHash        string `json:"publicKeyHash"`
		SignatureTestMessage string `json:"signature_test_message"`
		SignatureB64         string `json:"signature_b64"`
	} `json:"periods"`
}

func loadVector(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/period-keys-v1.json")
	if err != nil {
		t.Fatalf("read vector fixture: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector fixture: %v", err)
	}
	return v
}

// TestDerivePeriodKey_Vector reproduces every value of the Appendix A
// derivation vector (master, identity did:web:example.com) for N = 1, 2, 3,
// 12: the HKDF PRK, each period's info bytes, seed, public key, SPKI and
// PKCS#8 encodings, and (for N=1) the test signature.
func TestDerivePeriodKey_Vector(t *testing.T) {
	v := loadVector(t)
	if v.Scheme != PeriodScheme {
		t.Fatalf("vector scheme %q != PeriodScheme %q", v.Scheme, PeriodScheme)
	}
	if v.Salt != PeriodSalt {
		t.Fatalf("vector salt %q != PeriodSalt %q", v.Salt, PeriodSalt)
	}
	master, err := hex.DecodeString(v.MasterHex)
	if err != nil {
		t.Fatalf("decode master: %v", err)
	}

	prk, err := DerivePRK(master)
	if err != nil {
		t.Fatalf("DerivePRK: %v", err)
	}
	wantPRK, err := hex.DecodeString(v.PRKHex)
	if err != nil {
		t.Fatalf("decode prk_hex: %v", err)
	}
	if !bytes.Equal(prk, wantPRK) {
		t.Fatalf("PRK mismatch:\n got  %x\n want %x", prk, wantPRK)
	}

	for _, p := range v.Periods {
		n := uint32(p.Period)

		wantInfo, err := hex.DecodeString(p.InfoHex)
		if err != nil {
			t.Fatalf("period %d: decode info_hex: %v", n, err)
		}
		gotInfo, err := periodInfo(v.Identity, n)
		if err != nil {
			t.Fatalf("period %d: periodInfo: %v", n, err)
		}
		if !bytes.Equal(gotInfo, wantInfo) {
			t.Errorf("period %d: info mismatch:\n got  %x\n want %x", n, gotInfo, wantInfo)
		}

		seed, err := DerivePeriodSeed(master, v.Identity, n)
		if err != nil {
			t.Fatalf("period %d: DerivePeriodSeed: %v", n, err)
		}
		wantSeed, err := hex.DecodeString(p.SeedHex)
		if err != nil {
			t.Fatalf("period %d: decode seed_hex: %v", n, err)
		}
		if !bytes.Equal(seed, wantSeed) {
			t.Errorf("period %d: seed mismatch:\n got  %x\n want %x", n, seed, wantSeed)
		}

		priv := ed25519.NewKeyFromSeed(seed)
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatalf("period %d: Public() did not return ed25519.PublicKey", n)
		}
		wantPub, err := hex.DecodeString(p.PublicKeyHex)
		if err != nil {
			t.Fatalf("period %d: decode publicKey_hex: %v", n, err)
		}
		if !bytes.Equal(pub, wantPub) {
			t.Errorf("period %d: public key mismatch:\n got  %x\n want %x", n, pub, wantPub)
		}

		spkiB64, err := PublicKeySPKIBase64(pub)
		if err != nil {
			t.Fatalf("period %d: PublicKeySPKIBase64: %v", n, err)
		}
		if spkiB64 != p.PublicKeySPKIB64 {
			t.Errorf("period %d: SPKI base64 mismatch:\n got  %s\n want %s", n, spkiB64, p.PublicKeySPKIB64)
		}

		pkcs8B64, err := PrivateKeyPKCS8Base64(priv)
		if err != nil {
			t.Fatalf("period %d: PrivateKeyPKCS8Base64: %v", n, err)
		}
		if pkcs8B64 != p.PrivateKeyPKCS8B64 {
			t.Errorf("period %d: PKCS8 base64 mismatch:\n got  %s\n want %s", n, pkcs8B64, p.PrivateKeyPKCS8B64)
		}

		if p.PublicKeyPem != "" {
			pemStr, err := PublicKeySPKIPEM(pub)
			if err != nil {
				t.Fatalf("period %d: PublicKeySPKIPEM: %v", n, err)
			}
			if pemStr != p.PublicKeyPem {
				t.Errorf("period %d: publicKeyPem mismatch:\n got  %q\n want %q", n, pemStr, p.PublicKeyPem)
			}
		}

		if p.PublicKeyHash != "" {
			hash, err := PublicKeyHash(pub)
			if err != nil {
				t.Fatalf("period %d: PublicKeyHash: %v", n, err)
			}
			if hash != p.PublicKeyHash {
				t.Errorf("period %d: publicKeyHash mismatch:\n got  %s\n want %s", n, hash, p.PublicKeyHash)
			}
		}

		if p.SignatureTestMessage != "" {
			sig := ed25519.Sign(priv, []byte(p.SignatureTestMessage))
			gotSig := base64.RawStdEncoding.EncodeToString(sig)
			if gotSig != p.SignatureB64 {
				t.Errorf("period %d: test signature mismatch:\n got  %s\n want %s", n, gotSig, p.SignatureB64)
			}
		}

		// DerivePeriodKey (the master->key convenience path) must produce
		// exactly the same key as the seed-derived key above.
		priv2, err := DerivePeriodKey(master, v.Identity, n)
		if err != nil {
			t.Fatalf("period %d: DerivePeriodKey: %v", n, err)
		}
		if !bytes.Equal(priv2, priv) {
			t.Errorf("period %d: DerivePeriodKey produced a different key than seed derivation", n)
		}
	}
}

func TestDerivePeriodSeed_Refusals(t *testing.T) {
	master := bytes.Repeat([]byte{0x01}, 32)

	t.Run("period zero", func(t *testing.T) {
		if _, err := DerivePeriodSeed(master, "did:web:example.com", 0); err == nil {
			t.Fatal("expected error for period 0")
		}
	})
	t.Run("period above max", func(t *testing.T) {
		if _, err := DerivePeriodSeed(master, "did:web:example.com", MaxPeriod+1); err == nil {
			t.Fatal("expected error for period above 2147483647")
		}
	})
	t.Run("period at max is valid", func(t *testing.T) {
		if _, err := DerivePeriodSeed(master, "did:web:example.com", MaxPeriod); err != nil {
			t.Fatalf("period 2147483647 should be valid: %v", err)
		}
	})
	t.Run("wrong master length", func(t *testing.T) {
		if _, err := DerivePeriodSeed(master[:31], "did:web:example.com", 1); err == nil {
			t.Fatal("expected error for 31-byte master")
		}
		if _, err := DerivePeriodSeed(append(master, 0x02), "did:web:example.com", 1); err == nil {
			t.Fatal("expected error for 33-byte master")
		}
	})
	t.Run("identity contains NUL", func(t *testing.T) {
		if _, err := DerivePeriodSeed(master, "did:web:example.com\x00evil", 1); err == nil {
			t.Fatal("expected error for identity containing U+0000")
		}
	})
	t.Run("empty identity", func(t *testing.T) {
		if _, err := DerivePeriodSeed(master, "", 1); err == nil {
			t.Fatal("expected error for empty identity")
		}
	})
	t.Run("different identities yield different seeds", func(t *testing.T) {
		a, err := DerivePeriodSeed(master, "did:web:example.com", 1)
		if err != nil {
			t.Fatal(err)
		}
		b, err := DerivePeriodSeed(master, "did:web:example.org", 1)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a, b) {
			t.Fatal("different identities must derive different seeds")
		}
	})
}
