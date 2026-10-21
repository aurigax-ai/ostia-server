package testkit

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"testing"
)

type shareVector struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	Mode        string `json:"mode"`
	Password    string `json:"password,omitzero"`
	Salt        string `json:"salt,omitzero"`
	FragmentKey string `json:"fragmentKey,omitzero"`
	Nonce       string `json:"nonce"`
	Plaintext   string `json:"plaintext"`
	DerivedKey  string `json:"derivedKey"`
	Blob        string `json:"blob"`
}

type shareVectorFile struct {
	Cases []shareVector `json:"cases"`
}

func fixedBytes(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

func buildShareVector(t *testing.T, v shareVector) shareVector {
	t.Helper()
	var salt, fragment []byte
	if v.Salt != "" {
		salt, _ = b64.DecodeString(v.Salt)
	}
	if v.FragmentKey != "" {
		fragment, _ = b64.DecodeString(v.FragmentKey)
	}
	key, err := DeriveShareKey(v.Mode, v.Password, salt, fragment)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := b64.DecodeString(v.Nonce)
	v.DerivedKey = b64.EncodeToString(key)
	v.Blob = b64.EncodeToString(EncryptShare(v.ID, key, []byte(v.Plaintext), nonce))
	return v
}

func TestShareVectorsAreStableAndDecrypt(t *testing.T) {
	const path = "../../testdata/vectors/share.json"
	html := "<!doctype html><title>héllo ✓</title><p>portable artifact</p>"
	want := shareVectorFile{Cases: []shareVector{
		buildShareVector(t, shareVector{
			Name: "link", ID: "abcdefghijklmnopqrstuvwxyz", Mode: "link",
			FragmentKey: b64.EncodeToString(fixedBytes(32, 1)), Nonce: b64.EncodeToString(fixedBytes(12, 100)), Plaintext: html,
		}),
		buildShareVector(t, shareVector{
			Name: "password", ID: "abcdefghijklmnopqrstuvwxyz", Mode: "password", Password: "correct horse ü",
			Salt: b64.EncodeToString(fixedBytes(16, 50)), Nonce: b64.EncodeToString(fixedBytes(12, 120)), Plaintext: html,
		}),
		buildShareVector(t, shareVector{
			Name: "password and link key", ID: "abcdefghijklmnopqrstuvwxyz", Mode: "password", Password: "pw",
			Salt: b64.EncodeToString(fixedBytes(16, 70)), FragmentKey: b64.EncodeToString(fixedBytes(32, 9)),
			Nonce: b64.EncodeToString(fixedBytes(12, 140)), Plaintext: html,
		}),
	}}
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
	var got shareVectorFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Cases) != len(want.Cases) {
		t.Fatalf("vector count %d", len(got.Cases))
	}
	for i, c := range got.Cases {
		if c != want.Cases[i] {
			t.Errorf("vector %q differs from what the implementation produces", c.Name)
		}
		var salt, fragment []byte
		if c.Salt != "" {
			salt, _ = b64.DecodeString(c.Salt)
		}
		if c.FragmentKey != "" {
			fragment, _ = b64.DecodeString(c.FragmentKey)
		}
		key, _ := DeriveShareKey(c.Mode, c.Password, salt, fragment)
		blob, _ := b64.DecodeString(c.Blob)
		plain, err := DecryptShare(c.ID, key, blob)
		if err != nil || string(plain) != c.Plaintext {
			t.Errorf("vector %q does not decrypt: %v", c.Name, err)
		}
		if _, err := DecryptShare("wrongid", key, blob); err == nil {
			t.Errorf("vector %q decrypts under another id", c.Name)
		}
	}
}

func TestEncryptUsesFreshNonces(t *testing.T) {
	key := fixedBytes(32, 1)
	a := EncryptShare("id", key, []byte("x"), nil)
	b := EncryptShare("id", key, []byte("x"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("same ciphertext twice")
	}
}
