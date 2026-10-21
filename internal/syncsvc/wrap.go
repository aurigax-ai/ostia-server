package syncsvc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"

	"github.com/aurigax-ai/ostia-server/internal/auth"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

const (
	deviceWrapVersion = 2
	wrapSigContext    = "ostia-sync/wrap/sig/v1\n"
	wrapEphemeralLen  = 32
	wrapNonceLen      = 12
	wrapCiphertextLen = 32 + 16
	wrapCounterLen    = 8
)

type deviceWrap struct {
	signerID string
	signed   []byte
	sig      []byte
}

func parseDeviceWrap(blob []byte) (deviceWrap, bool) {
	if len(blob) < 2 || blob[0] != deviceWrapVersion {
		return deviceWrap{}, false
	}
	idLen := int(blob[1])
	fixed := 2 + idLen + wrapCounterLen + wrapEphemeralLen + wrapNonceLen + wrapCiphertextLen
	if idLen == 0 || len(blob) != fixed+ed25519.SignatureSize {
		return deviceWrap{}, false
	}
	return deviceWrap{signerID: string(blob[2 : 2+idLen]), signed: blob[:fixed], sig: blob[fixed:]}, true
}

func (s *Service) checkDeviceWrap(ctx context.Context, p auth.Principal, slot string, blob []byte) error {
	parsed, ok := parseDeviceWrap(blob)
	if !ok {
		return httpx.Errf(http.StatusBadRequest, "bad-wrap", "a device wrap must be a well-formed version 2 wrap")
	}
	if parsed.signerID != p.DeviceID {
		return httpx.Errf(http.StatusForbidden, "wrong-signer", "a device wrap must be signed by the device that uploads it")
	}
	signer, err := s.DB.Device(ctx, p.DeviceID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && signer.RevokedAt != 0) {
		return httpx.Errf(http.StatusForbidden, "wrong-signer", "the signing device is not active")
	}
	if err != nil {
		return err
	}
	message := append([]byte(wrapSigContext+slot+"\n"), parsed.signed...)
	if !ed25519.Verify(signer.SignPub, message, parsed.sig) {
		return httpx.Errf(http.StatusBadRequest, "bad-wrap", "the wrap signature does not verify under the signing device's key")
	}
	return nil
}
