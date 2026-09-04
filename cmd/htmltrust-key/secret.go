package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/HTMLTrust/htmltrust-hugo/perioddid"
)

// Secret is the plaintext contents of the encrypted secret file: the offline
// tier's two secrets. It MUST never be written to disk unencrypted.
type Secret struct {
	Scheme    string `json:"scheme"`
	Identity  string `json:"identity"`
	Master    string `json:"master"`    // unpadded standard Base64, 32 bytes
	AnchorKey string `json:"anchorKey"` // unpadded standard Base64 PKCS#8 DER, the CURRENT signing anchor's private key
}

// MasterBytes decodes Master.
func (s *Secret) MasterBytes() ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s.Master)
	if err != nil {
		return nil, fmt.Errorf("secret: decode master: %w", err)
	}
	return b, nil
}

// AnchorPrivateKey decodes and parses AnchorKey.
func (s *Secret) AnchorPrivateKey() (ed25519.PrivateKey, error) {
	der, err := base64.RawStdEncoding.DecodeString(s.AnchorKey)
	if err != nil {
		return nil, fmt.Errorf("secret: decode anchorKey: %w", err)
	}
	priv, err := perioddid.ParsePKCS8DEREd25519(der)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	return priv, nil
}

// EncryptSecret encrypts secret with age in passphrase (scrypt) mode.
func EncryptSecret(secret *Secret, passphrase string) ([]byte, error) {
	raw, err := json.Marshal(secret)
	if err != nil {
		return nil, fmt.Errorf("encode secret: %w", err)
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("age: new scrypt recipient: %w", err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("age: encrypt: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return nil, fmt.Errorf("age: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("age: close: %w", err)
	}
	return buf.Bytes(), nil
}

// DecryptSecret decrypts an age-encrypted secret file with a passphrase.
func DecryptSecret(ciphertext []byte, passphrase string) (*Secret, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("age: new scrypt identity: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("age: decrypt: %w (wrong passphrase?)", err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("age: read decrypted plaintext: %w", err)
	}
	var secret Secret
	if err := json.Unmarshal(raw, &secret); err != nil {
		return nil, fmt.Errorf("parse decrypted secret: %w", err)
	}
	return &secret, nil
}

// LoadSecret reads and decrypts the secret file at path.
func LoadSecret(path, passphrase string) (*Secret, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return DecryptSecret(raw, passphrase)
}

// SaveSecret encrypts and writes the secret file at path, mode 0600.
func SaveSecret(path string, secret *Secret, passphrase string) error {
	ciphertext, err := EncryptSecret(secret, passphrase)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// readPassphraseLine reads one passphrase line from the controlling
// terminal. It is a package variable, overridden in tests, so the CLI
// commands above it never need their own test-only code path: production
// always reads a real terminal, tests substitute a canned answer.
var readPassphraseLine = func(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("stdin is not a terminal: the passphrase must be typed interactively and is never read from an environment variable")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return string(b), nil
}

// ReadPassphraseTwice prompts for a passphrase twice on the terminal (stdin
// must be a TTY; this never reads from an environment variable) and refuses
// unless both entries match and neither is empty. Used whenever a new
// secret file is written (init, rekey), so a typo does not lock the
// publisher out of their own offline tier.
func ReadPassphraseTwice(prompt1, prompt2 string) (string, error) {
	p1, err := readPassphraseLine(prompt1)
	if err != nil {
		return "", err
	}
	p2, err := readPassphraseLine(prompt2)
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("passphrases did not match")
	}
	if p1 == "" {
		return "", errors.New("passphrase must not be empty")
	}
	return p1, nil
}

// ReadPassphraseOnce prompts for a passphrase once, used to decrypt an
// existing secret file.
func ReadPassphraseOnce(prompt string) (string, error) {
	p, err := readPassphraseLine(prompt)
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("passphrase must not be empty")
	}
	return p, nil
}

// EnsureGitIgnored refuses to proceed unless `git check-ignore -q path`
// (run with dir as the working directory) reports path as ignored. If the
// repository has no rule covering it, EnsureGitIgnored appends one to
// .htmltrust/.gitignore and re-checks once. It is a fatal error, not
// silently skipped, if path is still not ignored afterward, or if dir is
// not inside a Git working tree at all.
func EnsureGitIgnored(dir, path string) error {
	ignored, err := gitCheckIgnore(dir, path)
	if err != nil {
		return err
	}
	if ignored {
		return nil
	}
	gitignorePath := filepath.Join(dir, filepath.Dir(path), ".gitignore")
	if err := os.MkdirAll(filepath.Dir(gitignorePath), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(gitignorePath), err)
	}
	line := filepath.Base(path)
	existing, _ := os.ReadFile(gitignorePath)
	if !bytes.Contains(existing, []byte(line)) {
		f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("open %s: %w", gitignorePath, err)
		}
		if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
			if _, err := f.WriteString("\n"); err != nil {
				f.Close()
				return err
			}
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			f.Close()
			return fmt.Errorf("write %s: %w", gitignorePath, err)
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	ignored, err = gitCheckIgnore(dir, path)
	if err != nil {
		return err
	}
	if !ignored {
		return fmt.Errorf("refusing to proceed: %s is still not git-ignored after adding it to %s", path, gitignorePath)
	}
	return nil
}

func gitCheckIgnore(dir, path string) (ignored bool, err error) {
	cmd := exec.Command("git", "check-ignore", "-q", path)
	cmd.Dir = dir
	runErr := cmd.Run()
	if runErr == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		if exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("git check-ignore %s: exit %d", path, exitErr.ExitCode())
	}
	return false, fmt.Errorf("run git check-ignore: %w (is git installed and %s inside a Git working tree?)", runErr, dir)
}

// masterFingerprint returns the checksum htmltrust-key prints alongside a
// password-manager line, so a truncated paste is caught: the first 4 hex
// characters of SHA-256(master).
func masterFingerprint(master []byte) string {
	return hexPrefix(sha256Sum(master), 4)
}
