package syncsvc

import (
	"bytes"
	"strings"
	"testing"
)

func wrapOf(version byte, idLen int, extra int) []byte {
	size := 2 + idLen + wrapCounterLen + wrapEphemeralLen + wrapNonceLen + wrapCiphertextLen + 64 + extra
	blob := bytes.Repeat([]byte{'x'}, size)
	blob[0] = version
	blob[1] = byte(idLen)
	return blob
}

func TestParseDeviceWrap(t *testing.T) {
	signerOf := strings.Repeat("x", 255)
	tests := []struct {
		name string
		blob []byte
		ok   bool
		id   string
	}{
		{"empty", nil, false, ""},
		{"one byte", []byte{2}, false, ""},
		{"valid", wrapOf(2, 26, 0), true, strings.Repeat("x", 26)},
		{"longest id", wrapOf(2, 255, 0), true, signerOf},
		{"id length zero", wrapOf(2, 0, 0), false, ""},
		{"one byte short", wrapOf(2, 26, -1), false, ""},
		{"one byte long", wrapOf(2, 26, 1), false, ""},
		{"id length beyond the blob", append([]byte{2, 255}, make([]byte, 40)...), false, ""},
		{"version 1", wrapOf(1, 26, 0), false, ""},
		{"version 3", wrapOf(3, 26, 0), false, ""},
	}
	for _, tc := range tests {
		got, ok := parseDeviceWrap(tc.blob)
		if ok != tc.ok || got.signerID != tc.id {
			t.Errorf("%s: ok=%v signer=%q", tc.name, ok, got.signerID)
		}
		if ok && (len(got.sig) != 64 || len(got.signed)+len(got.sig) != len(tc.blob)) {
			t.Errorf("%s: split %d + %d of %d", tc.name, len(got.signed), len(got.sig), len(tc.blob))
		}
	}
}
