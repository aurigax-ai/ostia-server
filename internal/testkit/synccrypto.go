package testkit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	syncKeyBytes      = 32
	syncNonceBytes    = 12
	syncWrapVersion   = 1
	deviceWrapVersion = 2
	syncSaltBytes     = 16
	labelBlobKey      = "ostia-sync/blob"
	labelManifestKey  = "ostia-sync/manifest"
	labelPathKey      = "ostia-sync/path"
	labelDeviceWrap   = "ostia-sync/wrap/device"
	labelWrapSig      = "ostia-sync/wrap/sig/v1\n"
	labelLinkCode     = "ostia-sync/link-code/v1\n"
	linkCodeChars     = 25
	linkCodeGroup     = 5
	aadBlob           = "ostia-sync/blob/v1\n"
	aadManifest       = "ostia-sync/manifest/v1"
	aadPassphraseWrap = "ostia-sync/wrap/passphrase/v1"
)

var (
	ErrWrongKey         = errors.New("cannot open with this key")
	ErrBadWrapSignature = errors.New("bad wrap signature")
)

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

type ManifestDevice struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SignPub   string `json:"signPub"`
	BoxPub    string `json:"boxPub"`
	CreatedAt int64  `json:"createdAt"`
}

type Manifest struct {
	Counter int64                   `json:"counter"`
	Files   map[string]ManifestFile `json:"files"`
	Devices []ManifestDevice        `json:"devices"`
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

func deviceWrapKey(shared, ephemeralPub, devicePub []byte) []byte {
	info := append(append([]byte(labelDeviceWrap), ephemeralPub...), devicePub...)
	key, _ := hkdf.Key(sha256.New, shared, nil, string(info), syncKeyBytes)
	return key
}

type WrapSigner struct {
	ID   string
	Sign ed25519.PrivateKey
}

type DeviceWrap struct {
	SignerID string
	Counter  uint64
	Key      []byte
}

func wrapSignatureMessage(slot string, signed []byte) []byte {
	return append([]byte(labelWrapSig+slot+"\n"), signed...)
}

func WrapForDevice(profileKey []byte, signer WrapSigner, counter uint64, slot string, deviceBoxPub []byte) ([]byte, error) {
	ephemeral, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return wrapForDevice(profileKey, signer, counter, slot, deviceBoxPub, ephemeral, RandomBytes(syncNonceBytes))
}

func wrapForDevice(profileKey []byte, signer WrapSigner, counter uint64, slot string, deviceBoxPub []byte, ephemeral *ecdh.PrivateKey, nonce []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(deviceBoxPub)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(pub)
	if err != nil {
		return nil, err
	}
	header := []byte{deviceWrapVersion, byte(len(signer.ID))}
	header = append(header, signer.ID...)
	header = binary.BigEndian.AppendUint64(header, counter)
	header = append(header, ephemeral.PublicKey().Bytes()...)
	header = append(header, nonce...)
	key := deviceWrapKey(shared, ephemeral.PublicKey().Bytes(), deviceBoxPub)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	body := gcm.Seal(header, nonce, profileKey, append(append([]byte(nil), header...), slot...))
	return append(body, ed25519.Sign(signer.Sign, wrapSignatureMessage(slot, body))...), nil
}

func ParseWrapSigner(wrap []byte) (string, bool) {
	if len(wrap) < 2 || wrap[0] != deviceWrapVersion || len(wrap) < 2+int(wrap[1]) {
		return "", false
	}
	return string(wrap[2 : 2+int(wrap[1])]), true
}

func UnwrapForDevice(wrap []byte, slot string, box *ecdh.PrivateKey, signerSignPub []byte) (DeviceWrap, error) {
	if len(wrap) < 2 || wrap[0] != deviceWrapVersion {
		return DeviceWrap{}, ErrWrongKey
	}
	idLen := int(wrap[1])
	headerLen := 2 + idLen + 8 + 32 + syncNonceBytes
	if idLen == 0 || len(wrap) != headerLen+syncKeyBytes+16+ed25519.SignatureSize {
		return DeviceWrap{}, ErrWrongKey
	}
	sigAt := len(wrap) - ed25519.SignatureSize
	if len(signerSignPub) != ed25519.PublicKeySize || !ed25519.Verify(signerSignPub, wrapSignatureMessage(slot, wrap[:sigAt]), wrap[sigAt:]) {
		return DeviceWrap{}, ErrBadWrapSignature
	}
	counterAt := 2 + idLen
	ephemeralBytes := wrap[counterAt+8 : counterAt+8+32]
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralBytes)
	if err != nil {
		return DeviceWrap{}, ErrWrongKey
	}
	shared, err := box.ECDH(ephemeral)
	if err != nil {
		return DeviceWrap{}, ErrWrongKey
	}
	key := deviceWrapKey(shared, ephemeralBytes, box.PublicKey().Bytes())
	plain, err := open(key, wrap[headerLen-syncNonceBytes:sigAt], append(append([]byte(nil), wrap[:headerLen]...), slot...))
	if err != nil {
		return DeviceWrap{}, err
	}
	return DeviceWrap{SignerID: string(wrap[2:counterAt]), Counter: binary.BigEndian.Uint64(wrap[counterAt:]), Key: plain}, nil
}

func LinkCode(joinerSignPub, joinerBoxPub, approverSignPub []byte) string {
	digest := sha256.New()
	digest.Write([]byte(labelLinkCode))
	digest.Write(joinerSignPub)
	digest.Write(joinerBoxPub)
	digest.Write(approverSignPub)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest.Sum(nil)[:16])[:linkCodeChars]
	groups := make([]string, 0, linkCodeChars/linkCodeGroup)
	for start := 0; start < linkCodeChars; start += linkCodeGroup {
		groups = append(groups, encoded[start:start+linkCodeGroup])
	}
	return strings.Join(groups, "-")
}
