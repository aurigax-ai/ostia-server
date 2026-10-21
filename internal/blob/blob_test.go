package blob

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestPutCommitOpenDelete(t *testing.T) {
	d, err := NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	up, err := d.Put(t.Context(), "share/abc", strings.NewReader("hello"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Open(t.Context(), "share/abc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("blob visible before commit: %v", err)
	}
	if err := up.Commit(); err != nil {
		t.Fatal(err)
	}
	f, size, err := d.Open(t.Context(), "share/abc")
	if err != nil || size != 5 {
		t.Fatalf("open: %v size %d", err, size)
	}
	got, _ := io.ReadAll(f)
	_ = f.Close()
	if string(got) != "hello" {
		t.Fatalf("content %q", got)
	}
	if err := d.Delete(t.Context(), "share/abc"); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(t.Context(), "share/abc"); err != nil {
		t.Fatalf("deleting a missing blob must succeed: %v", err)
	}
}

func TestPutRefusesOversizeAndAbortLeavesNothing(t *testing.T) {
	d, _ := NewDisk(t.TempDir())
	if _, err := d.Put(t.Context(), "share/big", strings.NewReader("123456"), 5); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	up, err := d.Put(t.Context(), "share/x", strings.NewReader("abc"), 5)
	if err != nil {
		t.Fatal(err)
	}
	up.Abort()
	if _, _, err := d.Open(t.Context(), "share/x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("aborted upload visible: %v", err)
	}
}

func TestKeysCannotEscapeTheRoot(t *testing.T) {
	d, _ := NewDisk(t.TempDir())
	for _, key := range []string{"../etc/passwd", "share/../../x", "/abs/path", "share", "a/b/c/d", "share/a b"} {
		if _, err := d.Put(t.Context(), key, strings.NewReader("x"), 5); err == nil {
			t.Errorf("key %q accepted", key)
		}
	}
}
