package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/aurigax-ai/ostia-server/internal/blob"
	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/ids"
	"github.com/aurigax-ai/ostia-server/internal/limit"
	"github.com/aurigax-ai/ostia-server/internal/netkey"
	"github.com/aurigax-ai/ostia-server/internal/serverkey"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

const (
	RegisterContext    = "ostia-server/register/v1"
	ChallengeContext   = "ostia-server/auth/v1"
	SyncGCContext      = "ostia-server/sync-gc/v1"
	SyncRotateContext  = "ostia-server/sync-rotate/v1"
	WrapReadContext    = "ostia-server/wrap-read/v1"
	ManifestPutContext = "ostia-server/manifest-put/v1"
	signatureHeader    = "X-Device-Signature"
	timestampHeader    = "X-Device-Timestamp"
	signatureSkew      = 2 * time.Minute

	keySize                = 32
	maxNameLength          = 64
	challengeTTL           = time.Minute
	maxChallenges          = 100000
	maxChallengesPerDevice = 5
	maxFlowsPerIP          = 5
	maxFlows               = 2000
	smallBody              = 4 << 10
	providerGitHub         = "github"
	providerIDPurpose      = "provider-id"
)

type Hooks struct {
	SessionEnded   func(tokenHash []byte)
	DeviceRevoked  func(deviceID string)
	AccountDeleted func(deviceIDs []string)
}

type Principal struct {
	DeviceID  string
	AccountID string
	TokenHash []byte
}

type Service struct {
	DB    *store.DB
	Blobs blob.Store
	Key   *serverkey.Key
	Cfg   config.Auth
	Now   func() time.Time

	InactiveAfter time.Duration
	GitHub        *GitHub
	Guard         *httpx.Guard
	Hooks         Hooks

	mu           sync.Mutex
	challenges   map[string]challenge
	challengesOf map[string][]string
	flows        map[string]*flow
	deviceLimit  *limit.Limiter
}

type challenge struct {
	deviceID string
	expires  time.Time
}

func (s *Service) init() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.challenges == nil {
		s.challenges = map[string]challenge{}
		s.challengesOf = map[string][]string{}
		s.flows = map[string]*flow{}
		s.deviceLimit = limit.New(limit.Rule{Every: 50 * time.Millisecond, Burst: 100}, s.Now)
	}
}

func (s *Service) Mount(mux *httpx.Mux) {
	s.init()
	g := s.Guard
	slow := limit.Rule{Every: 6 * time.Second, Burst: 10}
	mux.Handle("POST /v1/auth/invite", g.PerIP("auth.invite", slow, httpx.Handle(s.registerInvite)))
	mux.Handle("POST /v1/auth/challenge", g.PerIP("auth.challenge", limit.Rule{Every: time.Second, Burst: 20}, httpx.Handle(s.challenge)))
	mux.Handle("POST /v1/auth/verify", g.PerIP("auth.verify", limit.Rule{Every: time.Second, Burst: 20}, httpx.Handle(s.verify)))
	if s.GitHub != nil {
		mux.Handle("POST /v1/auth/github/device", g.PerIP("auth.github.device", slow, httpx.Handle(s.githubStart)))
		mux.Handle("POST /v1/auth/github/poll", g.PerIP("auth.github.poll", limit.Rule{Every: time.Second, Burst: 30}, httpx.Handle(s.githubPoll)))
	}
	mux.Handle("DELETE /v1/auth/session", s.Authed(s.logout))
	mux.Handle("POST /v1/devices/heartbeat", s.Authed(s.heartbeat))
}

func (s *Service) Authed(fn func(w http.ResponseWriter, r *http.Request, p Principal) error) http.Handler {
	return httpx.Handle(func(w http.ResponseWriter, r *http.Request) error {
		p, err := s.Authenticate(r)
		if err != nil {
			return err
		}
		if !s.deviceLimit.Allow(p.DeviceID) {
			w.Header().Set("Retry-After", "1")
			return httpx.ErrRateLimited
		}
		return fn(w, r, p)
	})
}

func (s *Service) Authenticate(r *http.Request) (Principal, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return Principal{}, httpx.ErrUnauthorized
	}
	hash := ids.Hash(token)
	dev, err := s.DB.SessionDevice(r.Context(), hash)
	if err != nil {
		return Principal{}, httpx.ErrUnauthorized
	}
	if s.Now().UnixMilli()-dev.LastSeenAt >= time.Hour.Milliseconds() {
		_ = s.DB.TouchDevice(r.Context(), dev.ID)
	}
	return Principal{DeviceID: dev.ID, AccountID: dev.AccountID, TokenHash: hash}, nil
}

type registration struct {
	Name    string    `json:"name"`
	SignPub httpx.B64 `json:"signPub"`
	BoxPub  httpx.B64 `json:"boxPub"`
	Proof   httpx.B64 `json:"proof"`
}

func registrationMessage(signPub, boxPub []byte) []byte {
	return []byte(RegisterContext + "\n" + httpx.EncodeB64(signPub) + "\n" + httpx.EncodeB64(boxPub))
}

func (r registration) validate() (store.NewDevice, error) {
	name := strings.TrimSpace(r.Name)
	if name == "" || len([]rune(name)) > maxNameLength || strings.ContainsFunc(name, unicode.IsControl) {
		return store.NewDevice{}, httpx.Errf(http.StatusBadRequest, "bad-request", "name must be 1-64 printable characters")
	}
	if len(r.SignPub) != keySize || len(r.BoxPub) != keySize {
		return store.NewDevice{}, httpx.Errf(http.StatusBadRequest, "bad-request", "signPub and boxPub must be 32 bytes")
	}
	if !ed25519.Verify(ed25519.PublicKey(r.SignPub), registrationMessage(r.SignPub, r.BoxPub), r.Proof) {
		return store.NewDevice{}, httpx.Errf(http.StatusBadRequest, "bad-proof", "proof must be an ed25519 signature of the registration message")
	}
	return store.NewDevice{Name: name, SignPub: r.SignPub, BoxPub: r.BoxPub}, nil
}

type registered struct {
	AccountID string `json:"accountId"`
	DeviceID  string `json:"deviceId"`
	Provider  string `json:"provider"`
}

func (s *Service) registerInvite(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		registration
		Code string `json:"code"`
	}
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	nd, err := in.registration.validate()
	if err != nil {
		return err
	}
	acct, dev, err := s.DB.RegisterWithInvite(r.Context(), ids.Hash(NormalizeCode(in.Code)), nd, s.Cfg.MaxDevices)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		return httpx.Errf(http.StatusForbidden, "invalid-invite", "the invite code is unknown, used or expired")
	case errors.Is(err, store.ErrLimit):
		return httpx.Errf(http.StatusConflict, "device-limit", "the account has reached its device limit")
	default:
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, registered{AccountID: acct.ID, DeviceID: dev.ID, Provider: acct.Provider})
	return nil
}

func (s *Service) CreateInvite(ctx context.Context, ttl time.Duration) (code string, expiresAt int64, err error) {
	code = FormatCode(ids.New()[:25])
	expiresAt, err = s.DB.CreateInvite(ctx, ids.Hash(NormalizeCode(code)), ttl, CodeHint(code))
	return code, expiresAt, err
}

func FormatCode(raw string) string {
	var parts []string
	for i := 0; i < len(raw); i += 5 {
		parts = append(parts, raw[i:i+5])
	}
	return strings.Join(parts, "-")
}

func CodeHint(code string) string {
	plain := strings.ToUpper(NormalizeCode(code))
	return plain[:4] + "-…-" + plain[len(plain)-4:]
}

func NormalizeCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, code)
}

func (s *Service) newChallenge(deviceID, ip string, registered bool) (string, error) {
	key := deviceID + "|" + ip
	nonce := ids.Token()
	if !registered {
		return nonce, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	if len(s.challenges) >= maxChallenges {
		return "", httpx.Err(http.StatusServiceUnavailable, "busy")
	}
	live := s.challengesOf[key][:0]
	for _, older := range s.challengesOf[key] {
		c, ok := s.challenges[older]
		if ok && now.Before(c.expires) {
			live = append(live, older)
		} else {
			delete(s.challenges, older)
		}
	}
	for len(live) >= maxChallengesPerDevice {
		delete(s.challenges, live[0])
		live = live[1:]
	}
	s.challenges[nonce] = challenge{deviceID: deviceID, expires: now.Add(challengeTTL)}
	s.challengesOf[key] = append(live, nonce)
	return nonce, nil
}

func (s *Service) takeChallenge(nonce, deviceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[nonce]
	delete(s.challenges, nonce)
	return ok && c.deviceID == deviceID && !s.Now().After(c.expires)
}

func (s *Service) SweepChallenges() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	for nonce, c := range s.challenges {
		if now.After(c.expires) {
			delete(s.challenges, nonce)
		}
	}
	for deviceID, nonces := range s.challengesOf {
		live := nonces[:0]
		for _, nonce := range nonces {
			if _, ok := s.challenges[nonce]; ok {
				live = append(live, nonce)
			}
		}
		if len(live) == 0 {
			delete(s.challengesOf, deviceID)
		} else {
			s.challengesOf[deviceID] = live
		}
	}
	for id, f := range s.flows {
		if now.After(f.expires) {
			delete(s.flows, id)
		}
	}
}

func (s *Service) challenge(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		DeviceID string `json:"deviceId"`
	}
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	dev, err := s.DB.Device(r.Context(), in.DeviceID)
	registered := err == nil && dev.RevokedAt == 0
	nonce, err := s.newChallenge(in.DeviceID, netkey.Of(s.Guard.IP(r)), registered)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"nonce": nonce})
	return nil
}

func ChallengeMessage(deviceID, nonce string) []byte {
	return []byte(ChallengeContext + "\n" + deviceID + "\n" + nonce)
}

func (s *Service) verify(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		DeviceID string    `json:"deviceId"`
		Nonce    string    `json:"nonce"`
		Sig      httpx.B64 `json:"sig"`
	}
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	if !s.takeChallenge(in.Nonce, in.DeviceID) {
		return httpx.ErrUnauthorized
	}
	dev, err := s.DB.Device(r.Context(), in.DeviceID)
	if err != nil || dev.RevokedAt != 0 || !ed25519.Verify(ed25519.PublicKey(dev.SignPub), ChallengeMessage(in.DeviceID, in.Nonce), in.Sig) {
		return httpx.ErrUnauthorized
	}
	token := ids.Token()
	expires, err := s.DB.CreateSession(r.Context(), ids.Hash(token), dev.ID, s.Cfg.SessionTTL.Std())
	if err != nil {
		return err
	}
	_ = s.DB.TouchDevice(r.Context(), dev.ID)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"token": token, "expiresAt": expires, "accountId": dev.AccountID})
	return nil
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request, p Principal) error {
	if err := s.DB.DeleteSession(r.Context(), p.TokenHash); err != nil {
		return err
	}
	if s.Hooks.SessionEnded != nil {
		s.Hooks.SessionEnded(p.TokenHash)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) heartbeat(w http.ResponseWriter, r *http.Request, p Principal) error {
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) RevokeInactive(ctx context.Context) error {
	if s.InactiveAfter <= 0 {
		return nil
	}
	devices, err := s.DB.InactiveDevices(ctx, s.InactiveAfter)
	if err != nil {
		return err
	}
	cutoff := s.Now().Add(-s.InactiveAfter).UnixMilli()
	for _, d := range devices {
		if err := s.DB.RevokeInactiveDevice(ctx, d.AccountID, d.ID, cutoff); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				slog.Error("revoke an inactive device", "err", err)
			}
			continue
		}
		if s.Hooks.DeviceRevoked != nil {
			s.Hooks.DeviceRevoked(d.ID)
		}
	}
	return nil
}

func StampedMessage(context, deviceID string, ms int64, fields ...string) []byte {
	message := context + "\n" + deviceID + "\n" + strconv.FormatInt(ms, 10)
	for _, field := range fields {
		message += "\n" + field
	}
	return []byte(message)
}

func WrapReadMessage(deviceID string, ms int64, slot string) []byte {
	return StampedMessage(WrapReadContext, deviceID, ms, slot)
}

func ManifestPutFields(ifMatch int64, body []byte) []string {
	sum := sha256.Sum256(body)
	return []string{strconv.FormatInt(ifMatch, 10), httpx.EncodeB64(sum[:])}
}

func ManifestPutMessage(deviceID string, ms int64, ifMatch int64, body []byte) []byte {
	return StampedMessage(ManifestPutContext, deviceID, ms, ManifestPutFields(ifMatch, body)...)
}

func (s *Service) SignedTimestamp(r *http.Request) (int64, error) {
	stamp, err := strconv.ParseInt(r.Header.Get(timestampHeader), 10, 64)
	if err != nil {
		return 0, httpx.Errf(http.StatusForbidden, "device-signature-required", "send X-Device-Timestamp (milliseconds) and sign it with the device key")
	}
	if skew := s.Now().Sub(time.UnixMilli(stamp)); skew > signatureSkew || skew < -signatureSkew {
		return 0, httpx.Errf(http.StatusForbidden, "stale-signature", "the signed timestamp is too far from the server's clock")
	}
	return stamp, nil
}

func (s *Service) RequireSignedTimestamp(r *http.Request, p Principal, context string, fields ...string) error {
	stamp, err := s.SignedTimestamp(r)
	if err != nil {
		return err
	}
	return s.RequireSignature(r, p, context, stamp, fields...)
}

func (s *Service) RequireSignature(r *http.Request, p Principal, context string, stamp int64, fields ...string) error {
	if err := s.requireDeviceSignature(r, p, StampedMessage(context, p.DeviceID, stamp, fields...)); err != nil {
		return err
	}
	fresh, err := s.DB.AdvanceSigningCounter(r.Context(), p.DeviceID, stamp)
	if err != nil {
		return err
	}
	if !fresh {
		return httpx.Errf(http.StatusForbidden, "stale-signature", "a signed request cannot be replayed")
	}
	return nil
}

func SyncGCMessage(deviceID string, ms int64, ifMatch int64, body []byte) []byte {
	return StampedMessage(SyncGCContext, deviceID, ms, ManifestPutFields(ifMatch, body)...)
}

func SyncRotateMessage(deviceID string, ms int64, ifMatch int64, body []byte) []byte {
	return StampedMessage(SyncRotateContext, deviceID, ms, ManifestPutFields(ifMatch, body)...)
}

func (s *Service) requireDeviceSignature(r *http.Request, p Principal, message []byte) error {
	signature, err := httpx.DecodeB64(r.Header.Get(signatureHeader))
	if err != nil || len(signature) == 0 {
		return httpx.Errf(http.StatusForbidden, "device-signature-required", "this action must be signed with the device's key; a session token alone is not enough")
	}
	device, err := s.DB.Device(r.Context(), p.DeviceID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(device.SignPub), message, signature) {
		return httpx.Errf(http.StatusForbidden, "bad-signature", "the device signature does not match")
	}
	return nil
}

func (s *Service) purgeIfAbandoned(ctx context.Context, accountID string) error {
	keys, _, err := s.DB.PurgeDeparted(ctx, accountID)
	if err != nil {
		return err
	}
	s.deleteBlobs(ctx, keys)
	return nil
}

func (s *Service) deleteBlobs(ctx context.Context, keys []string) {
	for _, key := range keys {
		if err := s.Blobs.Delete(ctx, key); err != nil {
			slog.Error("delete a blob of a departed account", "err", err)
		}
	}
}

func (s *Service) PurgeAbandoned(ctx context.Context) error {
	accounts, err := s.DB.AbandonedAccounts(ctx)
	if err != nil {
		return err
	}
	for _, id := range accounts {
		if err := s.purgeIfAbandoned(ctx, id); err != nil {
			slog.Error("purge an abandoned account", "err", err)
		}
	}
	return nil
}

func (s *Service) DeleteAccount(ctx context.Context, accountID string) error {
	devices, err := s.DB.DevicesOf(ctx, accountID)
	if err != nil {
		return err
	}
	keys, err := s.DB.BlobKeysOf(ctx, accountID)
	if err != nil {
		return err
	}
	if err := s.DB.DeleteAccount(ctx, accountID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}
	for _, key := range keys {
		_ = s.Blobs.Delete(ctx, key)
	}
	if s.Hooks.AccountDeleted != nil {
		deviceIDs := make([]string, 0, len(devices))
		for _, d := range devices {
			deviceIDs = append(deviceIDs, d.ID)
		}
		s.Hooks.AccountDeleted(deviceIDs)
	}
	return nil
}

func (s *Service) providerHash(provider, id string) string {
	return hex.EncodeToString(s.Key.MAC(providerIDPurpose, []byte(provider+":"+id)))
}
