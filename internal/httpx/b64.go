package httpx

import "encoding/base64"

var encoding = base64.RawURLEncoding

func EncodeB64(b []byte) string { return encoding.EncodeToString(b) }

func DecodeB64(s string) ([]byte, error) { return encoding.DecodeString(s) }
