package testkit

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/auth"
)

type syncVectors struct {
	ProfileKey     string `json:"profileKey"`
	Path           string `json:"path"`
	Content        string `json:"content"`
	BlobID         string `json:"blobId"`
	ContentHash    string `json:"contentHash"`
	BlobNonce      string `json:"blobNonce"`
	SealedBlob     string `json:"sealedBlob"`
	Manifest       string `json:"manifest"`
	ManifestNonce  string `json:"manifestNonce"`
	SealedManifest string `json:"sealedManifest"`
	Passphrase     string `json:"passphrase"`
	Argon          struct {
		MemoryKiB uint32 `json:"memoryKiB"`
		Passes    uint8  `json:"passes"`
		Lanes     uint8  `json:"lanes"`
	} `json:"argon"`
	WrapSalt       string `json:"wrapSalt"`
	WrapNonce      string `json:"wrapNonce"`
	PassphraseWrap string `json:"passphraseWrap"`
	DeviceBoxSeed  string `json:"deviceBoxPrivateKey"`
	DeviceBoxPub   string `json:"deviceBoxPublicKey"`
	EphemeralKey   string `json:"ephemeralPrivateKey"`
	DeviceNonce    string `json:"deviceWrapNonce"`
	DeviceWrap     string `json:"deviceWrap"`

	WrapSignerID       string `json:"wrapSignerId"`
	WrapSignerSeed     string `json:"wrapSignerSignSeed"`
	WrapSignerPub      string `json:"wrapSignerSignPub"`
	WrapSlot           string `json:"wrapSlot"`
	WrapCounter        uint64 `json:"wrapCounter"`
	WrapSignatureCtx   string `json:"wrapSignatureContext"`
	WrongKeySignedWrap string `json:"wrongKeySignedWrap"`
	TamperedWrap       string `json:"tamperedWrap"`
}

type linkVectors struct {
	Tag                 string `json:"tag"`
	JoinerSignPub       string `json:"joinerSignPub"`
	JoinerBoxPub        string `json:"joinerBoxPub"`
	ApproverSignPub     string `json:"approverSignPub"`
	LinkCode            string `json:"linkCode"`
	SwappedJoinerBoxPub string `json:"swappedJoinerBoxPub"`
	SwappedBoxLinkCode  string `json:"swappedBoxLinkCode"`
}

type authVectors struct {
	SignSeed          string `json:"signSeed"`
	SignPub           string `json:"signPub"`
	BoxPub            string `json:"boxPub"`
	RegistrationMsg   string `json:"registrationMessage"`
	RegistrationProof string `json:"registrationProof"`
	DeviceID          string `json:"deviceId"`
	Nonce             string `json:"nonce"`
	ChallengeMsg      string `json:"challengeMessage"`
	ChallengeSig      string `json:"challengeSignature"`
	Timestamp         int64  `json:"timestamp"`
	WrapSlot          string `json:"wrapSlot"`
	WrapReadMsg       string `json:"wrapReadMessage"`
	WrapReadSig       string `json:"wrapReadSignature"`
	IfMatch           int64  `json:"ifMatch"`
	ManifestBody      string `json:"manifestBody"`
	ManifestBodyHash  string `json:"manifestBodyHash"`
	ManifestPutMsg    string `json:"manifestPutMessage"`
	ManifestPutSig    string `json:"manifestPutSignature"`
}

func buildSyncVectors(t *testing.T) syncVectors {
	t.Helper()
	key := fixedBytes(32, 11)
	content := []byte(`{"font":"14","theme":"dark"}`)
	v := syncVectors{Path: "settings.json", Content: string(content), Passphrase: "correct horse battery staple"}
	v.ProfileKey = b64.EncodeToString(key)
	v.BlobID = BlobID(key, v.Path, content)
	v.ContentHash = ContentHash(content)
	blobNonce := fixedBytes(12, 21)
	v.BlobNonce = b64.EncodeToString(blobNonce)
	v.SealedBlob = b64.EncodeToString(sealWithNonce(subkey(key, labelBlobKey), content, []byte(aadBlob+v.Path), blobNonce))

	manifest := Manifest{Counter: 7, Files: map[string]ManifestFile{v.Path: {BlobID: v.BlobID, Hash: v.ContentHash}}, Devices: []ManifestDevice{{
		ID:        "device-1",
		Name:      "laptop",
		SignPub:   b64.EncodeToString(ed25519.NewKeyFromSeed(fixedBytes(32, 121)).Public().(ed25519.PublicKey)),
		BoxPub:    b64.EncodeToString(mustX25519(fixedBytes(32, 61)).PublicKey().Bytes()),
		CreatedAt: 1760000000000,
	}}}
	manifestJSON, _ := json.Marshal(manifest, json.Deterministic(true))
	v.Manifest = string(manifestJSON)
	manifestNonce := fixedBytes(12, 31)
	v.ManifestNonce = b64.EncodeToString(manifestNonce)
	v.SealedManifest = b64.EncodeToString(sealWithNonce(subkey(key, labelManifestKey), manifestJSON, []byte(aadManifest), manifestNonce))

	v.Argon.MemoryKiB, v.Argon.Passes, v.Argon.Lanes = 1024, 2, 1
	salt, nonce := fixedBytes(16, 41), fixedBytes(12, 51)
	v.WrapSalt, v.WrapNonce = b64.EncodeToString(salt), b64.EncodeToString(nonce)
	v.PassphraseWrap = b64.EncodeToString(wrapWithSecret(key, v.Passphrase, ArgonParams{MemoryKiB: 1024, Passes: 2, Lanes: 1}, salt, nonce))

	deviceKey, _ := ecdh.X25519().NewPrivateKey(fixedBytes(32, 61))
	ephemeral, _ := ecdh.X25519().NewPrivateKey(fixedBytes(32, 71))
	deviceNonce := fixedBytes(12, 81)
	v.DeviceBoxSeed = b64.EncodeToString(fixedBytes(32, 61))
	v.DeviceBoxPub = b64.EncodeToString(deviceKey.PublicKey().Bytes())
	v.EphemeralKey = b64.EncodeToString(fixedBytes(32, 71))
	v.DeviceNonce = b64.EncodeToString(deviceNonce)
	signSeed := fixedBytes(32, 121)
	signer := WrapSigner{ID: "abcdefghijklmnopqrstuvwxyz", Sign: ed25519.NewKeyFromSeed(signSeed)}
	v.WrapSignerID = signer.ID
	v.WrapSignerSeed = b64.EncodeToString(signSeed)
	v.WrapSignerPub = b64.EncodeToString(signer.Sign.Public().(ed25519.PublicKey))
	v.WrapSlot = "device:zyxwvutsrqponmlkjihgfedcba"
	v.WrapCounter = 7
	v.WrapSignatureCtx = labelWrapSig
	wrap, err := wrapForDevice(key, signer, v.WrapCounter, v.WrapSlot, deviceKey.PublicKey().Bytes(), ephemeral, deviceNonce)
	if err != nil {
		t.Fatal(err)
	}
	v.DeviceWrap = b64.EncodeToString(wrap)
	forger := WrapSigner{ID: signer.ID, Sign: ed25519.NewKeyFromSeed(fixedBytes(32, 131))}
	forged, err := wrapForDevice(key, forger, v.WrapCounter, v.WrapSlot, deviceKey.PublicKey().Bytes(), ephemeral, deviceNonce)
	if err != nil {
		t.Fatal(err)
	}
	v.WrongKeySignedWrap = b64.EncodeToString(forged)
	tampered := bytes.Clone(wrap)
	tampered[len(tampered)-ed25519.SignatureSize-1] ^= 1
	v.TamperedWrap = b64.EncodeToString(tampered)
	return v
}

func mustX25519(seed []byte) *ecdh.PrivateKey {
	key, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	return key
}

func buildLinkVectors() linkVectors {
	joinerSign := ed25519.NewKeyFromSeed(fixedBytes(32, 141)).Public().(ed25519.PublicKey)
	joinerBox := mustX25519(fixedBytes(32, 151)).PublicKey().Bytes()
	approverSign := ed25519.NewKeyFromSeed(fixedBytes(32, 161)).Public().(ed25519.PublicKey)
	swappedBox := mustX25519(fixedBytes(32, 171)).PublicKey().Bytes()
	return linkVectors{
		Tag:                 labelLinkCode,
		JoinerSignPub:       b64.EncodeToString(joinerSign),
		JoinerBoxPub:        b64.EncodeToString(joinerBox),
		ApproverSignPub:     b64.EncodeToString(approverSign),
		LinkCode:            LinkCode(joinerSign, joinerBox, approverSign),
		SwappedJoinerBoxPub: b64.EncodeToString(swappedBox),
		SwappedBoxLinkCode:  LinkCode(joinerSign, swappedBox, approverSign),
	}
}

func buildAuthVectors() authVectors {
	seed := fixedBytes(32, 91)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	box, _ := ecdh.X25519().NewPrivateKey(fixedBytes(32, 101))
	v := authVectors{SignSeed: b64.EncodeToString(seed), SignPub: b64.EncodeToString(pub), BoxPub: b64.EncodeToString(box.PublicKey().Bytes())}
	v.RegistrationMsg = registerContext + "\n" + v.SignPub + "\n" + v.BoxPub
	v.RegistrationProof = b64.EncodeToString(ed25519.Sign(priv, []byte(v.RegistrationMsg)))
	v.DeviceID = "abcdefghijklmnopqrstuvwxyz"
	v.Nonce = b64.EncodeToString(fixedBytes(32, 111))
	v.ChallengeMsg = challengeContext + "\n" + v.DeviceID + "\n" + v.Nonce
	v.ChallengeSig = b64.EncodeToString(ed25519.Sign(priv, []byte(v.ChallengeMsg)))
	v.Timestamp = 1767225600000
	v.WrapSlot = "passphrase"
	v.WrapReadMsg = fmt.Sprintf("%s\n%s\n%d\n%s", wrapReadContext, v.DeviceID, v.Timestamp, v.WrapSlot)
	v.WrapReadSig = b64.EncodeToString(ed25519.Sign(priv, []byte(v.WrapReadMsg)))
	v.IfMatch = 3
	v.ManifestBody = `{"blob":"c2VhbGVkIG1hbmlmZXN0"}`
	bodySum := sha256.Sum256([]byte(v.ManifestBody))
	v.ManifestBodyHash = b64.EncodeToString(bodySum[:])
	v.ManifestPutMsg = fmt.Sprintf("%s\n%s\n%d\n%d\n%s", manifestPutContext, v.DeviceID, v.Timestamp, v.IfMatch, v.ManifestBodyHash)
	v.ManifestPutSig = b64.EncodeToString(ed25519.Sign(priv, []byte(v.ManifestPutMsg)))
	return v
}

func checkVectorFile[T any](t *testing.T, path string, want T) {
	t.Helper()
	if os.Getenv("UPDATE_VECTORS") == "1" {
		raw, _ := json.Marshal(want, json.Deterministic(true))
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_VECTORS=1 to create it)", err)
	}
	var got T
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s differs from what the implementation produces", path)
	}
}

func TestSyncVectorsAreStableAndOpen(t *testing.T) {
	v := buildSyncVectors(t)
	checkVectorFile(t, "../../testdata/vectors/sync.json", v)

	key, _ := b64.DecodeString(v.ProfileKey)
	sealedBlob, _ := b64.DecodeString(v.SealedBlob)
	plain, err := OpenBlob(key, v.Path, sealedBlob)
	if err != nil || string(plain) != v.Content {
		t.Fatalf("blob: %q %v", plain, err)
	}
	if _, err := OpenBlob(key, "other.json", sealedBlob); err == nil {
		t.Fatal("a blob opens under a different path")
	}
	sealedManifest, _ := b64.DecodeString(v.SealedManifest)
	manifest, err := OpenManifest(key, sealedManifest)
	if err != nil || manifest.Counter != 7 {
		t.Fatalf("manifest: %+v %v", manifest, err)
	}
	passphraseWrap, _ := b64.DecodeString(v.PassphraseWrap)
	got, err := UnwrapWithSecret(passphraseWrap, v.Passphrase)
	if err != nil || !reflect.DeepEqual(got, key) {
		t.Fatalf("passphrase wrap: %v", err)
	}
	if _, err := UnwrapWithSecret(passphraseWrap, "wrong"); err == nil {
		t.Fatal("wrong passphrase opens the wrap")
	}
	deviceKey, _ := ecdh.X25519().NewPrivateKey(fixedBytes(32, 61))
	signPub, _ := b64.DecodeString(v.WrapSignerPub)
	deviceWrap, _ := b64.DecodeString(v.DeviceWrap)
	opened, err := UnwrapForDevice(deviceWrap, v.WrapSlot, deviceKey, signPub)
	if err != nil || !reflect.DeepEqual(opened.Key, key) || opened.Counter != v.WrapCounter || opened.SignerID != v.WrapSignerID {
		t.Fatalf("device wrap: %+v %v", opened, err)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := UnwrapForDevice(deviceWrap, v.WrapSlot, other, signPub); err == nil {
		t.Fatal("another device opens the wrap")
	}
	if _, err := UnwrapForDevice(deviceWrap, "device:other", deviceKey, signPub); !errors.Is(err, ErrBadWrapSignature) {
		t.Fatalf("a wrap moved to another slot must fail its signature: %v", err)
	}
	for name, blob := range map[string]string{"wrongKeySignedWrap": v.WrongKeySignedWrap, "tamperedWrap": v.TamperedWrap} {
		raw, _ := b64.DecodeString(blob)
		if _, err := UnwrapForDevice(raw, v.WrapSlot, deviceKey, signPub); !errors.Is(err, ErrBadWrapSignature) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestAuthVectorsAreStable(t *testing.T) {
	v := buildAuthVectors()
	checkVectorFile(t, "../../testdata/vectors/auth.json", v)

	if v.WrapReadMsg != string(auth.WrapReadMessage(v.DeviceID, v.Timestamp, v.WrapSlot)) {
		t.Fatalf("wrap read message differs from the server's: %q", v.WrapReadMsg)
	}
	if v.ManifestPutMsg != string(auth.ManifestPutMessage(v.DeviceID, v.Timestamp, v.IfMatch, []byte(v.ManifestBody))) {
		t.Fatalf("manifest put message differs from the server's: %q", v.ManifestPutMsg)
	}
	if v.WrapReadSig == v.ManifestPutSig {
		t.Fatal("the wrap read and manifest put signatures must not be interchangeable")
	}
}

func TestLinkCodeVectorsAreStableAndBindTheBoxKey(t *testing.T) {
	v := buildLinkVectors()
	checkVectorFile(t, "../../testdata/vectors/link.json", v)
	if v.LinkCode == v.SwappedBoxLinkCode {
		t.Fatal("swapping the joiner box key leaves the code unchanged")
	}
	if len(v.LinkCode) != 29 || strings.Count(v.LinkCode, "-") != 4 {
		t.Fatalf("link code shape: %q", v.LinkCode)
	}
}
