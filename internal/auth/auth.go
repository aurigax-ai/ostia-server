package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	SeenContext        = "ostia-server/seen/v1"
	InviteContext      = "ostia-server/invite/v1"
	ElevateContext     = "ostia-server/elevate/v1"
	RevokeContext      = "ostia-server/revoke/v1"
	ApproveContext     = "ostia-server/approve/v1"
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
	DeviceAdded    func(accountID string, device store.Device)
	DeviceRevoked  func(deviceID string)
	AccountDeleted func(deviceIDs []string)
}

type Principal struct {
	DeviceID      string
	AccountID     string
	TokenHash     []byte
	ElevatedUntil int64
}

type Service struct {
	DB     *store.DB
	Blobs  blob.Store
	Key    *serverkey.Key
	Cfg    config.Auth
	Now    func() time.Time
	GitHub *GitHub
	Guard  *httpx.Guard
	Hooks  Hooks

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
	mux.Handle("GET /v1/devices", s.Authed(s.listDevices))
	mux.Handle("POST /v1/devices/invite", s.Authed(s.deviceInvite))
	mux.Handle("POST /v1/devices/{id}/seen", s.Authed(s.markSeen))
	mux.Handle("DELETE /v1/devices/{id}", s.Authed(s.revokeDevice))
	mux.Handle("DELETE /v1/account", s.Authed(s.deleteAccount))
	s.mountElevation(mux)
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
	sess, err := s.DB.LookupSession(r.Context(), hash)
	if err != nil {
		return Principal{}, httpx.ErrUnauthorized
	}
	dev := sess.Device
	if s.Now().UnixMilli()-dev.LastSeen >= 24*time.Hour.Milliseconds() {
		_ = s.DB.TouchDevice(r.Context(), dev.ID)
	}
	return Principal{DeviceID: dev.ID, AccountID: dev.AccountID, TokenHash: hash, ElevatedUntil: sess.ElevatedUntil}, nil
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
	s.announceDevice(r, acct.ID, dev)
	httpx.WriteJSON(w, http.StatusCreated, registered{AccountID: acct.ID, DeviceID: dev.ID, Provider: acct.Provider})
	return nil
}

func (s *Service) announceDevice(r *http.Request, accountID string, dev store.Device) {
	if s.Hooks.DeviceAdded == nil {
		return
	}
	if count, err := s.DB.ActiveDeviceCount(r.Context(), accountID); err == nil && count >= 2 {
		s.Hooks.DeviceAdded(accountID, dev)
	}
}

func (s *Service) CreateInvite(ctx context.Context, accountID string, ttl time.Duration, elevated bool) (code string, expiresAt int64, err error) {
	code = FormatCode(ids.New()[:25])
	expiresAt, err = s.DB.CreateInvite(ctx, ids.Hash(NormalizeCode(code)), accountID, ttl, elevated, CodeHint(code))
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

type deviceView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	SignPub   httpx.B64 `json:"signPub"`
	BoxPub    httpx.B64 `json:"boxPub"`
	CreatedAt int64     `json:"createdAt"`
	LastSeen  int64     `json:"lastSeen"`
	Current   bool      `json:"current,omitzero"`
	New       bool      `json:"new,omitzero"`
}

func (s *Service) listDevices(w http.ResponseWriter, r *http.Request, p Principal) error {
	devices, err := s.DB.DevicesOf(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	viewer, err := s.DB.Device(r.Context(), p.DeviceID)
	if err != nil {
		return err
	}
	unseen, err := s.DB.UnseenDevices(r.Context(), viewer)
	if err != nil {
		return err
	}
	out := make([]deviceView, 0, len(devices))
	for _, d := range devices {
		out = append(out, deviceView{ID: d.ID, Name: d.Name, SignPub: d.SignPub, BoxPub: d.BoxPub, CreatedAt: d.CreatedAt, LastSeen: d.LastSeen, Current: d.ID == p.DeviceID, New: unseen[d.ID]})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"devices": out})
	return nil
}

func (s *Service) deviceInvite(w http.ResponseWriter, r *http.Request, p Principal) error {
	if err := s.RequireSignedTimestamp(r, p, InviteContext); err != nil {
		return err
	}
	active, err := s.DB.ActiveDeviceCount(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	live, err := s.DB.LiveInvites(r.Context(), p.AccountID)
	if err != nil {
		return err
	}
	elevated := false
	if active+live >= 2 {
		if err := s.NeedElevation(p); err != nil {
			return err
		}
		elevated = true
	}
	code, expires, err := s.CreateInvite(r.Context(), p.AccountID, s.Cfg.DeviceInviteTTL.Std(), elevated)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"code": code, "expiresAt": expires})
	return nil
}

func StampedMessage(context, deviceID string, ms int64, fields ...string) []byte {
	message := context + "\n" + deviceID + "\n" + strconv.FormatInt(ms, 10)
	for _, field := range fields {
		message += "\n" + field
	}
	return []byte(message)
}

func InviteMessage(deviceID string, ms int64) []byte {
	return StampedMessage(InviteContext, deviceID, ms)
}

func ElevateMessage(deviceID string, ms int64) []byte {
	return StampedMessage(ElevateContext, deviceID, ms)
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

func RevokeMessage(signerID, targetID string) []byte {
	return []byte(RevokeContext + "\n" + signerID + "\n" + targetID)
}

func ApproveMessage(approverID, approvalID, requesterID string) []byte {
	return []byte(ApproveContext + "\n" + approverID + "\n" + approvalID + "\n" + requesterID)
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

func SeenMessage(viewerID, targetID string) []byte {
	return []byte(SeenContext + "\n" + viewerID + "\n" + targetID)
}

func (s *Service) markSeen(w http.ResponseWriter, r *http.Request, p Principal) error {
	var in struct {
		Sig httpx.B64 `json:"sig"`
	}
	if err := httpx.ReadJSON(w, r, &in, smallBody); err != nil {
		return err
	}
	target, err := s.DB.Device(r.Context(), r.PathValue("id"))
	if err != nil || target.AccountID != p.AccountID {
		return httpx.ErrNotFound
	}
	if target.ID == p.DeviceID {
		return httpx.Errf(http.StatusBadRequest, "bad-request", "a device does not acknowledge itself")
	}
	viewer, err := s.DB.Device(r.Context(), p.DeviceID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(viewer.SignPub), SeenMessage(viewer.ID, target.ID), in.Sig) {
		return httpx.Errf(http.StatusForbidden, "bad-signature", "acknowledging a device needs a signature from this device's key, which a session token alone does not give")
	}
	if err := s.DB.MarkSeen(r.Context(), p.DeviceID, target.ID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) needsElevationToRevoke(r *http.Request, p Principal, id string) (bool, error) {
	self, err := s.DB.Device(r.Context(), p.DeviceID)
	if err != nil {
		return false, err
	}
	if id == p.DeviceID {
		older, err := s.DB.OlderActiveDevices(r.Context(), self)
		return older == 0, err
	}
	min := s.Cfg.ApproverMinAge.Std()
	if min <= 0 {
		return true, nil
	}
	target, err := s.DB.Device(r.Context(), id)
	if err != nil || target.AccountID != p.AccountID {
		return true, nil
	}
	older := self.CreatedAt < target.CreatedAt || (self.CreatedAt == target.CreatedAt && self.ID < target.ID)
	probation := s.Now().Sub(time.UnixMilli(target.CreatedAt)) < min
	return !(older && probation), nil
}

func (s *Service) revokeDevice(w http.ResponseWriter, r *http.Request, p Principal) error {
	id := r.PathValue("id")
	if err := s.requireDeviceSignature(r, p, RevokeMessage(p.DeviceID, id)); err != nil {
		return err
	}
	needs, err := s.needsElevationToRevoke(r, p, id)
	if err != nil {
		return err
	}
	if needs {
		if err := s.NeedElevation(p); err != nil {
			return err
		}
	}
	if _, err := s.DB.RevokeDevice(r.Context(), p.AccountID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return httpx.ErrNotFound
		}
		return err
	}
	if s.Hooks.DeviceRevoked != nil {
		s.Hooks.DeviceRevoked(id)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) deleteAccount(w http.ResponseWriter, r *http.Request, p Principal) error {
	if err := s.NeedElevation(p); err != nil {
		return err
	}
	return s.DeleteAccount(r.Context(), p.AccountID, w)
}

func (s *Service) DeleteAccount(ctx context.Context, accountID string, w http.ResponseWriter) error {
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
	if w != nil {
		w.WriteHeader(http.StatusNoContent)
	}
	return nil
}

func (s *Service) providerHash(provider, id string) string {
	return hex.EncodeToString(s.Key.MAC(providerIDPurpose, []byte(provider+":"+id)))
}
