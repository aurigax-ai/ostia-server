package testkit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/v2"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	syncKeyBytes      = 32
	syncNonceBytes    = 12
	syncWrapVersion   = 1
	syncSaltBytes     = 16
	labelBlobKey      = "ostia-sync/blob"
	labelManifestKey  = "ostia-sync/manifest"
	labelPathKey      = "ostia-sync/path"
	aadBlob           = "ostia-sync/blob/v1\n"
	aadManifest       = "ostia-sync/manifest/v1"
	aadPassphraseWrap = "ostia-sync/wrap/passphrase/v1"
)

var ErrWrongKey = errors.New("cannot open with this key")

type ArgonParams struct {
	MemoryKiB uint32
	Passes    uint8
	Lanes     uint8
}

var ProductionArgon = ArgonParams{MemoryKiB: 64 * 1024, Passes: 3, Lanes: 4}

var FastArgon = ArgonParams{MemoryKiB: 1024, Passes: 1, Lanes: 1}

func NewProfileKey() []byte { return RandomBytes(syncKeyBytes) }

func subkey(profileKey []byte, label string) []byte {
	key, _ := hkdf.Key(sha256.New, profileKey, nil, label, syncKeyBytes)
	return key
}

func seal(key, plaintext, aad []byte) []byte {
	return sealWithNonce(key, plaintext, aad, RandomBytes(syncNonceBytes))
}

func sealWithNonce(key, plaintext, aad, nonce []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(append([]byte(nil), nonce...), nonce, plaintext, aad)
}

func open(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < syncNonceBytes+16 {
		return nil, ErrWrongKey
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, sealed[:syncNonceBytes], sealed[syncNonceBytes:], aad)
	if err != nil {
		return nil, ErrWrongKey
	}
	return plain, nil
}

func BlobID(profileKey []byte, path string, content []byte) string {
	sum := sha256.Sum256(content)
	mac := hmac.New(sha256.New, subkey(profileKey, labelPathKey))
	mac.Write([]byte(path))
	mac.Write([]byte{0})
	mac.Write(sum[:])
	return b64.EncodeToString(mac.Sum(nil))
}

func ContentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return b64.EncodeToString(sum[:])
}

func SealBlob(profileKey []byte, path string, content []byte) []byte {
	return seal(subkey(profileKey, labelBlobKey), content, []byte(aadBlob+path))
}

func OpenBlob(profileKey []byte, path string, sealed []byte) ([]byte, error) {
	return open(subkey(profileKey, labelBlobKey), sealed, []byte(aadBlob+path))
}

type ManifestFile struct {
	BlobID string `json:"blobId"`
	Hash   string `json:"hash"`
}

type Manifest struct {
	Counter int64                   `json:"counter"`
	Files   map[string]ManifestFile `json:"files"`
}

func SealManifest(profileKey []byte, m Manifest) []byte {
	raw, _ := json.Marshal(m, json.Deterministic(true))
	return seal(subkey(profileKey, labelManifestKey), raw, []byte(aadManifest))
}

func OpenManifest(profileKey, sealed []byte) (Manifest, error) {
	raw, err := open(subkey(profileKey, labelManifestKey), sealed, []byte(aadManifest))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func passphraseKey(secret string, salt []byte, p ArgonParams) []byte {
	return argon2.IDKey([]byte(secret), salt, uint32(p.Passes), p.MemoryKiB, p.Lanes, syncKeyBytes)
}

func WrapWithSecret(profileKey []byte, secret string, p ArgonParams) []byte {
	return wrapWithSecret(profileKey, secret, p, RandomBytes(syncSaltBytes), RandomBytes(syncNonceBytes))
}

func wrapWithSecret(profileKey []byte, secret string, p ArgonParams, salt, nonce []byte) []byte {
	header := make([]byte, 0, 1+4+1+1+syncSaltBytes)
	header = append(header, syncWrapVersion)
	header = binary.BigEndian.AppendUint32(header, p.MemoryKiB)
	header = append(header, p.Passes, p.Lanes)
	header = append(header, salt...)
	return append(header, sealWithNonce(passphraseKey(secret, salt, p), profileKey, append([]byte(aadPassphraseWrap), header...), nonce)...)
}

func UnwrapWithSecret(wrap []byte, secret string) ([]byte, error) {
	const headerLen = 1 + 4 + 1 + 1 + syncSaltBytes
	if len(wrap) < headerLen || wrap[0] != syncWrapVersion {
		return nil, ErrWrongKey
	}
	p := ArgonParams{MemoryKiB: binary.BigEndian.Uint32(wrap[1:5]), Passes: wrap[5], Lanes: wrap[6]}
	if p.MemoryKiB > 256*1024 || p.Passes == 0 || p.Passes > 10 || p.Lanes == 0 {
		return nil, ErrWrongKey
	}
	salt := wrap[7:headerLen]
	return open(passphraseKey(secret, salt, p), wrap[headerLen:], append([]byte(aadPassphraseWrap), wrap[:headerLen]...))
}
