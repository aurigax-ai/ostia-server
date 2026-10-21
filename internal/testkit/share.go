package testkit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/text/unicode/norm"
)

const (
	ShareFormatVersion = 1
	ShareKeyBytes      = 32
	ShareSaltBytes     = 16
	SharePBKDF2Rounds  = 600000
	shareAADPrefix     = "ostia-share/1:"
	shareCombineInfo   = "ostia-share/1/key"
	shareNonceBytes    = 12
)

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func DeriveShareKey(mode, password string, salt, fragment []byte) ([]byte, error) {
	if mode == "link" {
		return fragment, nil
	}
	stretched, err := pbkdf2.Key(sha256.New, norm.NFKC.String(password), salt, SharePBKDF2Rounds, ShareKeyBytes)
	if err != nil {
		return nil, err
	}
	if len(fragment) == 0 {
		return stretched, nil
	}
	return hkdf.Key(sha256.New, append(stretched, fragment...), nil, shareCombineInfo, ShareKeyBytes)
}

func EncryptShare(id string, key, plaintext, nonce []byte) []byte {
	if nonce == nil {
		nonce = RandomBytes(shareNonceBytes)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	out := append([]byte{ShareFormatVersion}, nonce...)
	return gcm.Seal(out, nonce, plaintext, []byte(shareAADPrefix+id))
}

func DecryptShare(id string, key, blob []byte) ([]byte, error) {
	if len(blob) < 1+shareNonceBytes+16 || blob[0] != ShareFormatVersion {
		return nil, errors.New("unsupported share format")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	return gcm.Open(nil, blob[1:1+shareNonceBytes], blob[1+shareNonceBytes:], []byte(shareAADPrefix+id))
}
