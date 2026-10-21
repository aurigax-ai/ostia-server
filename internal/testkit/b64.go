package testkit

import "encoding/base64"

var b64 = base64.RawURLEncoding

func EncodeB64(b []byte) string { return b64.EncodeToString(b) }

func DecodeB64(s string) ([]byte, error) { return b64.DecodeString(s) }
