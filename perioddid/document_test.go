package perioddid

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// anchorSeedASCII is the Appendix A test-vector anchor key's seed: the
// migrated `#key-1` of the spec §9.10 worked example is "now the anchor" of
// the identity did:web:example.com.
const anchorSeedASCII = "htmltrust-test-vector-ed25519-01"

// wantSection910Document is the exact worked example from spec draft §9.10
// "DID document rules", copied verbatim (including its hand-formatted
// single-line @context and authentication arrays) from
// spec-9.10-period-keys.md.
const wantSection910Document = `{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:example.com",
  "verificationMethod": [
    {
      "id": "did:web:example.com#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAro5HTnkh3VG+ZQ3PaEerRS3uY0ITOe/D1rBBsuhfTBk=\n-----END PUBLIC KEY-----"
    },
    {
      "id": "did:web:example.com#p1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA/k+i5VWXMm69GkGvF3Ip4zpLTn66V3Lx+eMOHrdtxrU=\n-----END PUBLIC KEY-----"
    },
    {
      "id": "did:web:example.com#p2",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAbo8f8MEwNhvAXQ+3ij7WIqX8Gh5Lp+5zUPEBivixS/A=\n-----END PUBLIC KEY-----"
    },
    {
      "id": "did:web:example.com#p3",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPS60r09fcjnJn03s0q30yzXguUU/Fx8X/6GfUX04NRo=\n-----END PUBLIC KEY-----"
    },
    {
      "id": "did:web:example.com#p12",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:example.com",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAisijcdb4iHjrqASJxmN6JxZF/2ALWJFGV2E6yQ2HqY8=\n-----END PUBLIC KEY-----"
    }
  ],
  "assertionMethod": [
    "did:web:example.com#key-1",
    "did:web:example.com#p1",
    "did:web:example.com#p2",
    "did:web:example.com#p3",
    "did:web:example.com#p12"
  ],
  "authentication": ["did:web:example.com#key-1"],
  "htmltrust": {
    "periodScheme": "htmltrust-period-v1",
    "periodEpoch": "2026-10-01T00:00:00Z",
    "periodLength": "P1M"
  }
}`

// TestRenderDocument_Section910Example reproduces the spec §9.10 worked
// example byte for byte, seeded with the Appendix A derivation vector's
// master (periods 1, 2, 3, 12 of did:web:example.com) and the Appendix A
// anchor key (seed ASCII "htmltrust-test-vector-ed25519-01", now the anchor
// #key-1 of the migrated identity).
func TestRenderDocument_Section910Example(t *testing.T) {
	if len(anchorSeedASCII) != ed25519.SeedSize {
		t.Fatalf("anchor seed is %d bytes, want %d", len(anchorSeedASCII), ed25519.SeedSize)
	}
	anchorPriv := ed25519.NewKeyFromSeed([]byte(anchorSeedASCII))
	anchorPub, ok := anchorPriv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("anchor Public() did not return ed25519.PublicKey")
	}
	anchorPem, err := PublicKeySPKIPEM(anchorPub)
	if err != nil {
		t.Fatalf("PublicKeySPKIPEM(anchor): %v", err)
	}
	const wantAnchorSPKI = "MCowBQYDK2VwAyEAro5HTnkh3VG+ZQ3PaEerRS3uY0ITOe/D1rBBsuhfTBk="
	wantAnchorPem := "-----BEGIN PUBLIC KEY-----\n" + wantAnchorSPKI + "\n-----END PUBLIC KEY-----"
	if anchorPem != wantAnchorPem {
		t.Fatalf("anchor public key from seed %q does not match Appendix A #key-1:\n got  %s\n want %s",
			anchorSeedASCII, anchorPem, wantAnchorPem)
	}

	v := loadVector(t)
	master, err := hex.DecodeString(v.MasterHex)
	if err != nil {
		t.Fatalf("decode master: %v", err)
	}
	identity := v.Identity // did:web:example.com

	periodPems := map[uint32]string{}
	for _, n := range []uint32{1, 2, 3, 12} {
		priv, err := DerivePeriodKey(master, identity, n)
		if err != nil {
			t.Fatalf("DerivePeriodKey(%d): %v", n, err)
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatalf("period %d: Public() did not return ed25519.PublicKey", n)
		}
		pemStr, err := PublicKeySPKIPEM(pub)
		if err != nil {
			t.Fatalf("period %d: PublicKeySPKIPEM: %v", n, err)
		}
		periodPems[n] = pemStr
	}

	doc, err := RenderDocument(RenderInput{
		Identity:     identity,
		PeriodScheme: PeriodScheme,
		PeriodEpoch:  "2026-10-01T00:00:00Z",
		PeriodLength: "P1M",
		Anchors: []AnchorSpec{
			{Fragment: "#key-1", PublicKeyPem: anchorPem},
		},
		Periods: []PeriodSpec{
			{N: 1, PublicKeyPem: periodPems[1]},
			{N: 2, PublicKeyPem: periodPems[2]},
			{N: 3, PublicKeyPem: periodPems[3]},
			{N: 12, PublicKeyPem: periodPems[12]},
		},
		Authentication: []string{"#key-1"},
	})
	if err != nil {
		t.Fatalf("RenderDocument: %v", err)
	}

	got, err := doc.MarshalPretty()
	if err != nil {
		t.Fatalf("MarshalPretty: %v", err)
	}
	if string(got) != wantSection910Document {
		t.Fatalf("rendered document does not match spec §9.10 example byte for byte.\n\n--- got ---\n%s\n\n--- want ---\n%s", got, wantSection910Document)
	}
}

func TestRenderDocument_Refusals(t *testing.T) {
	t.Run("no anchors", func(t *testing.T) {
		_, err := RenderDocument(RenderInput{Identity: "did:web:example.com"})
		if err == nil {
			t.Fatal("expected error for a document with no anchor methods")
		}
	})
	t.Run("period out of range", func(t *testing.T) {
		_, err := RenderDocument(RenderInput{
			Identity: "did:web:example.com",
			Anchors:  []AnchorSpec{{Fragment: "#key-1", PublicKeyPem: "x"}},
			Periods:  []PeriodSpec{{N: 0, PublicKeyPem: "x"}},
		})
		if err == nil {
			t.Fatal("expected error for period 0")
		}
	})
	t.Run("duplicate id", func(t *testing.T) {
		_, err := RenderDocument(RenderInput{
			Identity: "did:web:example.com",
			Anchors: []AnchorSpec{
				{Fragment: "#key-1", PublicKeyPem: "x"},
				{Fragment: "#key-1", PublicKeyPem: "y"},
			},
		})
		if err == nil {
			t.Fatal("expected error for duplicate method id")
		}
	})
}

func TestDocument_FindByPublicKeyAndFirstAnchor(t *testing.T) {
	v := loadVector(t)
	master, err := hex.DecodeString(v.MasterHex)
	if err != nil {
		t.Fatal(err)
	}
	anchorPriv := ed25519.NewKeyFromSeed([]byte(anchorSeedASCII))
	anchorPub := anchorPriv.Public().(ed25519.PublicKey)
	anchorPem, err := PublicKeySPKIPEM(anchorPub)
	if err != nil {
		t.Fatal(err)
	}
	p3Priv, err := DerivePeriodKey(master, v.Identity, 3)
	if err != nil {
		t.Fatal(err)
	}
	p3Pub := p3Priv.Public().(ed25519.PublicKey)
	p3Pem, err := PublicKeySPKIPEM(p3Pub)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := RenderDocument(RenderInput{
		Identity: v.Identity,
		Anchors:  []AnchorSpec{{Fragment: "#key-1", PublicKeyPem: anchorPem}},
		Periods:  []PeriodSpec{{N: 3, PublicKeyPem: p3Pem}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	m, ok := doc.FindByPublicKey(p3Pub)
	if !ok || !m.IsPeriod || m.Period != 3 || m.MethodID != v.Identity+"#p3" {
		t.Fatalf("FindByPublicKey(p3) = %+v, ok=%v", m, ok)
	}
	m, ok = doc.FindByPublicKey(anchorPub)
	if !ok || m.IsPeriod || m.MethodID != v.Identity+"#key-1" {
		t.Fatalf("FindByPublicKey(anchor) = %+v, ok=%v", m, ok)
	}
	unrelated, _, err := ed25519.GenerateKey(nil)
	_ = err
	if unrelated != nil {
		if _, ok := doc.FindByPublicKey(unrelated); ok {
			t.Fatal("FindByPublicKey matched an unrelated key")
		}
	}

	first, ok := doc.FirstAnchor()
	if !ok || doc.ExpandID(first.ID) != v.Identity+"#key-1" {
		t.Fatalf("FirstAnchor() = %+v, ok=%v", first, ok)
	}
}
