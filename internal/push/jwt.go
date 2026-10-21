package push

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
)

var jwtEncoding = base64.RawURLEncoding

func signingInput(header, claims any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jwtEncoding.EncodeToString(h) + "." + jwtEncoding.EncodeToString(c), nil
}

func signRS256(key *rsa.PrivateKey, header, claims any) (string, error) {
	input, err := signingInput(header, claims)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + jwtEncoding.EncodeToString(sig), nil
}

func signES256(key *ecdsa.PrivateKey, header, claims any) (string, error) {
	input, err := signingInput(header, claims)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	if size != 32 {
		return "", fmt.Errorf("APNs needs a P-256 key, got %d-bit", key.Curve.Params().BitSize)
	}
	raw := make([]byte, 2*size)
	r.FillBytes(raw[:size])
	s.FillBytes(raw[size:])
	return input + "." + jwtEncoding.EncodeToString(raw), nil
}
