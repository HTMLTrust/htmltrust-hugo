package perioddid

import (
	"crypto/sha256"
	"encoding/base64"
)

// hashSHA256B64 returns the unpadded standard Base64 SHA-256 of b.
func hashSHA256B64(b []byte) string {
	sum := sha256.Sum256(b)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

// HashSHA256B64 returns the unpadded standard Base64 SHA-256 of b. Exported
// so other packages that need to reproduce a "sha256:<...>" hash the same
// way this package's own public-key hashes are computed (for example,
// preflight's approximation of a signer's content-hash) don't need their
// own copy of the encoding rule.
func HashSHA256B64(b []byte) string {
	return hashSHA256B64(b)
}
