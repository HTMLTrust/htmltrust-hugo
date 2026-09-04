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
