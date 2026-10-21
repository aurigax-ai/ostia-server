package testkit

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"os"
	"reflect"
	"testing"
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

	manifest := Manifest{Counter: 7, Files: map[string]ManifestFile{v.Path: {BlobID: v.BlobID, Hash: v.ContentHash}}, Devices: []ManifestDevice{{ID: "device-1", Name: "laptop"}}}
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
}
