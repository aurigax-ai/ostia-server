package testkit

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"os"
	"reflect"
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
	GCBody            string `json:"syncGcBody"`
	GCBodyHash        string `json:"syncGcBodyHash"`
	SyncGCMsg         string `json:"syncGcMessage"`
	SyncGCSig         string `json:"syncGcSignature"`
	RotateBody        string `json:"syncRotateBody"`
	RotateBodyHash    string `json:"syncRotateBodyHash"`
	SyncRotateMsg     string `json:"syncRotateMessage"`
	SyncRotateSig     string `json:"syncRotateSignature"`
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

	manifest := Manifest{Counter: 7, Files: map[string]ManifestFile{v.Path: {BlobID: v.BlobID, Hash: v.ContentHash}}}
	manifestJSON, _ := json.Marshal(manifest, json.Deterministic(true))
	v.Manifest = string(manifestJSON)
	manifestNonce := fixedBytes(12, 31)
	v.ManifestNonce = b64.EncodeToString(manifestNonce)
	v.SealedManifest = b64.EncodeToString(sealWithNonce(subkey(key, labelManifestKey), manifestJSON, []byte(aadManifest), manifestNonce))

	v.Argon.MemoryKiB, v.Argon.Passes, v.Argon.Lanes = 1024, 2, 1
	salt, nonce := fixedBytes(16, 41), fixedBytes(12, 51)
	v.WrapSalt, v.WrapNonce = b64.EncodeToString(salt), b64.EncodeToString(nonce)
	v.PassphraseWrap = b64.EncodeToString(wrapWithSecret(key, v.Passphrase, ArgonParams{MemoryKiB: 1024, Passes: 2, Lanes: 1}, salt, nonce))

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
	v.GCBody = `{"keep":["AAAAAAAAAAAAAAAA","BBBBBBBBBBBBBBBB"]}`
	gcSum := sha256.Sum256([]byte(v.GCBody))
	v.GCBodyHash = b64.EncodeToString(gcSum[:])
	v.SyncGCMsg = fmt.Sprintf("%s\n%s\n%d\n%d\n%s", syncGCContext, v.DeviceID, v.Timestamp, v.IfMatch, v.GCBodyHash)
	v.SyncGCSig = b64.EncodeToString(ed25519.Sign(priv, []byte(v.SyncGCMsg)))
	v.RotateBody = `{"manifest":"c2VhbGVkIG1hbmlmZXN0","passphrase":"cGFzc3BocmFzZSB3cmFw","recovery":"cmVjb3Zlcnkgd3JhcA"}`
	rotateSum := sha256.Sum256([]byte(v.RotateBody))
	v.RotateBodyHash = b64.EncodeToString(rotateSum[:])
	v.SyncRotateMsg = fmt.Sprintf("%s\n%s\n%d\n%d\n%s", syncRotateContext, v.DeviceID, v.Timestamp, v.IfMatch, v.RotateBodyHash)
	v.SyncRotateSig = b64.EncodeToString(ed25519.Sign(priv, []byte(v.SyncRotateMsg)))
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
	if v.SyncGCMsg != string(auth.SyncGCMessage(v.DeviceID, v.Timestamp, v.IfMatch, []byte(v.GCBody))) {
		t.Fatalf("gc message differs from the server's: %q", v.SyncGCMsg)
	}
	if v.SyncRotateMsg != string(auth.SyncRotateMessage(v.DeviceID, v.Timestamp, v.IfMatch, []byte(v.RotateBody))) {
		t.Fatalf("rotate message differs from the server's: %q", v.SyncRotateMsg)
	}
	if v.SyncRotateSig == v.SyncGCSig || v.SyncGCSig == v.ManifestPutSig || v.SyncRotateSig == v.ManifestPutSig {
		t.Fatal("the rotate, gc and manifest put signatures must not be interchangeable")
	}
	if v.WrapReadSig == v.ManifestPutSig {
		t.Fatal("the wrap read and manifest put signatures must not be interchangeable")
	}
}
