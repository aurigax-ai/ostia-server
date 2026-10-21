package serverkey

import (
	"bytes"
	"testing"
)

func TestLoadCreatesOnceAndReuses(t *testing.T) {
	dir := t.TempDir()
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.secret, b.secret) {
		t.Fatal("key regenerated")
	}
}

func TestSealOpenBindsPurpose(t *testing.T) {
	k, _ := Load(t.TempDir())
	sealed := k.Seal("push-token", []byte("secret"))
	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("plaintext visible")
	}
	got, err := k.Open("push-token", sealed)
	if err != nil || string(got) != "secret" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := k.Open("other", sealed); err == nil {
		t.Fatal("opened under another purpose")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := k.Open("push-token", sealed); err == nil {
		t.Fatal("tampered value opened")
	}
}

func TestMACDiffersPerPurpose(t *testing.T) {
	k, _ := Load(t.TempDir())
	if bytes.Equal(k.MAC("a", []byte("x")), k.MAC("b", []byte("x"))) {
		t.Fatal("purposes collide")
	}
}
