package serverkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
)

const keyBytes = 32

type Key struct {
	secret []byte
}

func Load(dir string) (*Key, error) {
	path := filepath.Join(dir, "server.key")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		raw = make([]byte, keyBytes)
		_, _ = rand.Read(raw)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return nil, err
		}
		return &Key{secret: raw}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) != keyBytes {
		return nil, errors.New("server.key has the wrong length")
	}
	return &Key{secret: raw}, nil
}

func New(secret []byte) *Key { return &Key{secret: secret} }

func (k *Key) derive(purpose string) []byte {
	out, _ := hkdf.Key(sha256.New, k.secret, nil, "ostia-server/"+purpose, keyBytes)
	return out
}

func (k *Key) MAC(purpose string, data []byte) []byte {
	m := hmac.New(sha256.New, k.derive(purpose))
	m.Write(data)
	return m.Sum(nil)
}

func (k *Key) aead(purpose string) cipher.AEAD {
	block, _ := aes.NewCipher(k.derive(purpose))
	gcm, _ := cipher.NewGCM(block)
	return gcm
}

func (k *Key) Seal(purpose string, plaintext []byte) []byte {
	gcm := k.aead(purpose)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nonce, nonce, plaintext, []byte(purpose))
}

func (k *Key) Open(purpose string, sealed []byte) ([]byte, error) {
	gcm := k.aead(purpose)
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed value too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(purpose))
}
