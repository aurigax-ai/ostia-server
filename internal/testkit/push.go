package testkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type PushRequest struct {
	Path    string
	Header  http.Header
	Body    []byte
	TokenOK bool
}

type FakePush struct {
	Server *httptest.Server

	mu            sync.Mutex
	FCM           []PushRequest
	APNs          []PushRequest
	TokenExchange int
	FCMStatus     int
	FCMBody       string
	APNsStatus    int
	APNsBody      string

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

const (
	FCMProject = "ostia-test"
	APNsKeyID  = "KEY1234567"
	APNsTeamID = "TEAM123456"
	APNsTopic  = "ai.aurigax.ostia"
)

func NewFakePush(t testing.TB) *FakePush {
	t.Helper()
	f := &FakePush{FCMStatus: http.StatusOK, APNsStatus: http.StatusOK}
	f.rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("POST /v1/projects/"+FCMProject+"/messages:send", f.fcm)
	mux.HandleFunc("POST /3/device/{token}", f.apns)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

func (f *FakePush) WriteCredentials(t testing.TB, dir string) (serviceAccountFile, p8File string) {
	t.Helper()
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(f.rsaKey)
	account := map[string]string{
		"client_email": "ostia@" + FCMProject + ".iam.gserviceaccount.com",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})),
		"project_id":   FCMProject,
		"token_uri":    f.Server.URL + "/token",
	}
	raw, _ := json.Marshal(account)
	serviceAccountFile = filepath.Join(dir, "service-account.json")
	if err := os.WriteFile(serviceAccountFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ecDER, _ := x509.MarshalPKCS8PrivateKey(f.ecKey)
	p8File = filepath.Join(dir, "AuthKey.p8")
	if err := os.WriteFile(p8File, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return serviceAccountFile, p8File
}

func (f *FakePush) ConfigTOML(serviceAccountFile, p8File string) string {
	return "[push.fcm]\nservice_account_file = \"" + serviceAccountFile + "\"\nendpoint = \"" + f.Server.URL + "\"\n" +
		"[push.apns]\nkey_file = \"" + p8File + "\"\nkey_id = \"" + APNsKeyID + "\"\nteam_id = \"" + APNsTeamID + "\"\ntopic = \"" + APNsTopic + "\"\nendpoint = \"" + f.Server.URL + "\"\n"
}

func b64Decode(s string) []byte {
	raw, _ := b64.DecodeString(s)
	return raw
}

func splitJWT(jwt string) (header, claims map[string]any, signed string, sig []byte, ok bool) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, false
	}
	if json.Unmarshal(b64Decode(parts[0]), &header) != nil || json.Unmarshal(b64Decode(parts[1]), &claims) != nil {
		return nil, nil, "", nil, false
	}
	return header, claims, parts[0] + "." + parts[1], b64Decode(parts[2]), true
}

func (f *FakePush) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	header, claims, signed, sig, ok := splitJWT(r.Form.Get("assertion"))
	sum := sha256.Sum256([]byte(signed))
	valid := ok && r.Form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer" &&
		header["alg"] == "RS256" && claims["scope"] == "https://www.googleapis.com/auth/firebase.messaging" &&
		rsa.VerifyPKCS1v15(&f.rsaKey.PublicKey, crypto.SHA256, sum[:], sig) == nil
	f.mu.Lock()
	f.TokenExchange++
	f.mu.Unlock()
	if !valid {
		http.Error(w, "invalid assertion", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"fake-access-token","expires_in":3600,"token_type":"Bearer"}`))
}

func (f *FakePush) fcm(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.FCM = append(f.FCM, PushRequest{Path: r.URL.Path, Header: r.Header.Clone(), Body: body, TokenOK: r.Header.Get("Authorization") == "Bearer fake-access-token"})
	status, reply := f.FCMStatus, f.FCMBody
	f.mu.Unlock()
	w.WriteHeader(status)
	_, _ = w.Write([]byte(reply))
}

func (f *FakePush) apns(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "bearer ")
	header, claims, signed, sig, ok := splitJWT(bearer)
	valid := false
	if ok && len(sig) == 64 && header["alg"] == "ES256" && header["kid"] == APNsKeyID && claims["iss"] == APNsTeamID {
		sum := sha256.Sum256([]byte(signed))
		valid = ecdsa.Verify(&f.ecKey.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	f.mu.Lock()
	f.APNs = append(f.APNs, PushRequest{Path: r.URL.Path, Header: r.Header.Clone(), Body: body, TokenOK: valid})
	status, reply := f.APNsStatus, f.APNsBody
	f.mu.Unlock()
	w.WriteHeader(status)
	_, _ = w.Write([]byte(reply))
}

func (f *FakePush) FCMRequests() []PushRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PushRequest(nil), f.FCM...)
}

func (f *FakePush) APNsRequests() []PushRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PushRequest(nil), f.APNs...)
}

func (f *FakePush) Exchanges() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.TokenExchange
}

func (f *FakePush) FailFCM(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.FCMStatus, f.FCMBody = status, body
}

func (f *FakePush) FailAPNs(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.APNsStatus, f.APNsBody = status, body
}
