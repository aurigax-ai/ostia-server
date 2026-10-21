package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"regexp"
)

var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var labelPattern = regexp.MustCompile(`^[a-z2-7]{26}$`)

var blobIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func New() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return lowerBase32.EncodeToString(b)
}

func Token() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func Hash(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func ValidID(s string) bool {
	return labelPattern.MatchString(s)
}

func ValidBlobID(s string) bool {
	return blobIDPattern.MatchString(s)
}
