package main

import (
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

// withTestPassphrase overrides passphrase reading for the duration of a
// test, so commands that decrypt or create the secret file don't need a
// real terminal.
func withTestPassphrase(t *testing.T, passphrase string) {
	t.Helper()
	orig := readPassphraseLine
	readPassphraseLine = func(prompt string) (string, error) { return passphrase, nil }
	t.Cleanup(func() { readPassphraseLine = orig })
}

// newGitTestRepo creates a temporary Git repository, chdirs into it for the
// duration of the test, and returns its path. htmltrust-key's gitignore
// safety check shells out to `git check-ignore`, so tests that call init
// need a real repository.
func newGitTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if out, err := exec.Command("git", "-C", dir, "config", "user.email", "test@example.com").CombinedOutput(); err != nil {
		t.Fatalf("git config user.email: %v: %s", err, out)
	}
	if out, err := exec.Command("git", "-C", dir, "config", "user.name", "Test").CombinedOutput(); err != nil {
		t.Fatalf("git config user.name: %v: %s", err, out)
	}
	t.Chdir(dir)
	return dir
}

func TestCeremony_InitDeriveDidRenderCheckRevoke(t *testing.T) {
	newGitTestRepo(t)
	withTestPassphrase(t, "correct horse battery staple")

	if err := cmdInit([]string{
		"--identity", "did:web:example.com",
		"--period-length", "P1M",
		"--epoch", "2026-10-01",
		"--ahead", "3",
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	if out, err := exec.Command("git", "check-ignore", "-q", SecretStatePath).CombinedOutput(); err != nil {
		t.Fatalf("secret file is not git-ignored after init: %v: %s", err, out)
	}

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if id.DerivedThrough != 0 {
		t.Errorf("derivedThrough = %d, want 0", id.DerivedThrough)
	}
	if id.PublishedThrough != 3 {
		t.Errorf("publishedThrough = %d, want 3", id.PublishedThrough)
	}
	if len(id.Anchors) != 1 || id.Anchors[0].ID != "#rev" {
		t.Fatalf("Anchors = %+v, want a single #rev anchor", id.Anchors)
	}
	if id.SigningAnchor != "#rev" {
		t.Errorf("SigningAnchor = %q, want #rev", id.SigningAnchor)
	}

	// Calling init again must refuse rather than clobber state.
	if err := cmdInit([]string{"--identity", "did:web:example.com"}); err == nil {
		t.Fatal("expected init to refuse when identity.json already exists")
	}

	// derive: refusals.
	if err := cmdDerive([]string{"--period", "0"}); err == nil {
		t.Fatal("expected error for --period 0")
	}
	if err := cmdDerive([]string{"--period", "5"}); err == nil {
		t.Fatal("expected error deriving period 5 before period 1 (skips past derivedThrough+1 without --skip)")
	}

	// derive: happy path, period 1.
	period1Out := filepath.Join(t.TempDir(), "p1.pem")
	if err := cmdDerive([]string{"--period", "1", "--out", period1Out}); err != nil {
		t.Fatalf("derive --period 1: %v", err)
	}
	pemBytes, err := os.ReadFile(period1Out)
	if err != nil {
		t.Fatalf("read delivered key: %v", err)
	}
	priv1, err := perioddid.ParsePKCS8PEMEd25519(pemBytes)
	if err != nil {
		t.Fatalf("parse delivered key: %v", err)
	}

	id, err = LoadIdentity(IdentityStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if id.DerivedThrough != 1 {
		t.Fatalf("derivedThrough = %d, want 1 after deriving period 1", id.DerivedThrough)
	}
	period1, ok := id.Period(1)
	if !ok {
		t.Fatal("period 1 missing from state")
	}
	wantPub, err := perioddid.ParseSPKIPEMEd25519(period1.PublicKeyPem)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, ok := priv1.Public().(ed25519.PublicKey)
	if !ok || !gotPub.Equal(wantPub) {
		t.Fatal("derived period 1 private key does not match its published public key")
	}

	// derive: reuse refusal.
	if err := cmdDerive([]string{"--period", "1"}); err == nil {
		t.Fatal("expected error re-delivering period 1 (already derivedThrough)")
	}

	// derive: --skip lets an operator jump ahead past an unpublished index.
	if err := cmdDerive([]string{"--period", "5", "--skip"}); err != nil {
		t.Fatalf("derive --period 5 --skip: %v", err)
	}
	id, err = LoadIdentity(IdentityStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if id.DerivedThrough != 5 {
		t.Fatalf("derivedThrough = %d, want 5 after --skip to period 5", id.DerivedThrough)
	}

	// did render, deterministic and matching what did check expects.
	docPath := filepath.Join(t.TempDir(), "did.json")
	if err := cmdDidRender([]string{"--out", docPath}); err != nil {
		t.Fatalf("did render: %v", err)
	}
	if _, err := perioddid.LoadDocument(docPath); err != nil {
		t.Fatalf("rendered document does not parse: %v", err)
	}
	if err := cmdDidCheck([]string{"--did-document", docPath}); err != nil {
		t.Fatalf("did check against its own render: %v", err)
	}

	// revoke: strike period 1, sign the list with the anchor, and confirm
	// the signature verifies under the anchor's published public key.
	listPath := filepath.Join(t.TempDir(), "revocations.json")
	didOutPath := filepath.Join(t.TempDir(), "did-after-revoke.json")
	if err := cmdRevoke([]string{
		"--from", "1", "--to", "2",
		"--list-out", listPath,
		"--did-out", didOutPath,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	listRaw, err := os.ReadFile(listPath)
	if err != nil {
		t.Fatal(err)
	}
	list, err := perioddid.ParseRevocationList(listRaw)
	if err != nil {
		t.Fatalf("parse revocation list: %v", err)
	}
	if len(list.Revocations) != 1 {
		t.Fatalf("revocations = %d, want 1", len(list.Revocations))
	}
	entry := list.Revocations[0]
	if entry.Keyid != "did:web:example.com#p1" {
		t.Errorf("entry.Keyid = %q, want did:web:example.com#p1", entry.Keyid)
	}
	if entry.FromPeriod == nil || *entry.FromPeriod != 1 || entry.ToPeriod == nil || *entry.ToPeriod != 2 {
		t.Errorf("entry range = %+v, want from=1 to=2", entry)
	}

	id, err = LoadIdentity(IdentityStatePath)
	if err != nil {
		t.Fatal(err)
	}
	anchorPub, err := perioddid.ParseSPKIPEMEd25519(id.Anchors[0].PublicKeyPem)
	if err != nil {
		t.Fatal(err)
	}
	ok2, err := perioddid.VerifyRevocationList(list, anchorPub)
	if err != nil {
		t.Fatalf("VerifyRevocationList: %v", err)
	}
	if !ok2 {
		t.Fatal("revocation list signature does not verify under the published anchor public key")
	}

	if p, ok := id.Period(1); !ok || !p.Revoked {
		t.Fatal("period 1 was not marked revoked in local state after revoke")
	}

	// status must run without error against the post-revoke state.
	if err := cmdStatus(nil); err != nil {
		t.Fatalf("status: %v", err)
	}

	// did check must now fail against the pre-revoke document, since the
	// state has moved on (period 1 is now marked revoked).
	if err := cmdDidCheck([]string{"--did-document", docPath}); err == nil {
		t.Fatal("expected did check to detect the state has diverged from the earlier rendered document")
	}
}

func TestListSign_HandEditedList(t *testing.T) {
	newGitTestRepo(t)
	withTestPassphrase(t, "another passphrase entirely")

	if err := cmdInit([]string{"--identity", "did:web:example.org", "--ahead", "2"}); err != nil {
		t.Fatalf("init: %v", err)
	}

	handEdited := filepath.Join(t.TempDir(), "list.json")
	if err := os.WriteFile(handEdited, []byte(`{"revocations":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdListSign([]string{handEdited}); err != nil {
		t.Fatalf("list sign: %v", err)
	}

	raw, err := os.ReadFile(handEdited)
	if err != nil {
		t.Fatal(err)
	}
	list, err := perioddid.ParseRevocationList(raw)
	if err != nil {
		t.Fatal(err)
	}
	if list.Signer != "did:web:example.org#rev" {
		t.Errorf("Signer = %q, want did:web:example.org#rev", list.Signer)
	}

	id, err := LoadIdentity(IdentityStatePath)
	if err != nil {
		t.Fatal(err)
	}
	anchorPub, err := perioddid.ParseSPKIPEMEd25519(id.Anchors[0].PublicKeyPem)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := perioddid.VerifyRevocationList(list, anchorPub)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("hand-edited list signature does not verify under the anchor")
	}
}
