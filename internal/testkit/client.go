package testkit

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

const registerContext = "ostia-server/register/v1"

const challengeContext = "ostia-server/auth/v1"

type Net struct {
	HTTPSAddr string
	Roots     *x509.CertPool
	APIHost   string
	Plain     bool
}

func (n Net) Transport() *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, n.HTTPSAddr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: n.Roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: false,
	}
}

func (n Net) Client() *http.Client {
	return &http.Client{Transport: n.Transport(), Timeout: 30 * time.Second}
}

func (n Net) scheme() string {
	if n.Plain {
		return "http"
	}
	return "https"
}

func (n Net) URL(path string) string { return n.scheme() + "://" + n.APIHost + path }

func (n Net) Dial(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", n.HTTPSAddr)
}

type Identity struct {
	Name      string
	Sign      ed25519.PrivateKey
	Box       *ecdh.PrivateKey
	DeviceID  string
	AccountID string
}

func NewIdentity(name string) *Identity {
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	box, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return &Identity{Name: name, Sign: sign, Box: box}
}

func (i *Identity) SignPub() []byte { return i.Sign.Public().(ed25519.PublicKey) }

func (i *Identity) BoxPub() []byte { return i.Box.PublicKey().Bytes() }

func (i *Identity) Registration() map[string]any {
	pub, box := i.SignPub(), i.BoxPub()
	message := registerContext + "\n" + b64.EncodeToString(pub) + "\n" + b64.EncodeToString(box)
	return map[string]any{
		"name":    i.Name,
		"signPub": b64.EncodeToString(pub),
		"boxPub":  b64.EncodeToString(box),
		"proof":   b64.EncodeToString(ed25519.Sign(i.Sign, []byte(message))),
	}
}

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r Response) JSON(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("response %d is not the expected JSON: %v\n%s", r.Status, err, r.Body)
	}
}

func (r Response) Map(t testing.TB) map[string]any {
	t.Helper()
	var m map[string]any
	r.JSON(t, &m)
	return m
}

func (r Response) String() string { return fmt.Sprintf("%d %s", r.Status, r.Body) }

type API struct {
	Net    Net
	ID     *Identity
	Token  string
	Client *http.Client
}

func NewAPI(n Net, id *Identity) *API {
	return &API{Net: n, ID: id, Client: n.Client()}
}

func (a *API) Raw(method, path string, headers map[string]string, body io.Reader) (Response, error) {
	req, err := http.NewRequest(method, a.Net.URL(path), body)
	if err != nil {
		return Response{}, err
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	if a.Token != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	res, err := a.Client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	return Response{Status: res.StatusCode, Header: res.Header, Body: data}, err
}

func (a *API) Do(t testing.TB, method, path string, body any, headers ...string) Response {
	t.Helper()
	var reader io.Reader
	hdr := map[string]string{}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
		hdr["Content-Type"] = "application/json"
	}
	for i := 0; i+1 < len(headers); i += 2 {
		hdr[headers[i]] = headers[i+1]
	}
	res, err := a.Raw(method, path, hdr, reader)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return res
}

func (a *API) Must(t testing.TB, want int, method, path string, body any, headers ...string) Response {
	t.Helper()
	res := a.Do(t, method, path, body, headers...)
	if res.Status != want {
		t.Fatalf("%s %s: want %d, got %s", method, path, want, res)
	}
	return res
}

func (a *API) Register(t testing.TB, code string) {
	t.Helper()
	body := a.ID.Registration()
	body["code"] = code
	res := a.Must(t, http.StatusCreated, "POST", "/v1/auth/invite", body)
	m := res.Map(t)
	a.ID.DeviceID, a.ID.AccountID = m["deviceId"].(string), m["accountId"].(string)
}

func (a *API) SignIn(t testing.TB) {
	t.Helper()
	a.Token = ""
	nonce := a.Must(t, http.StatusOK, "POST", "/v1/auth/challenge", map[string]string{"deviceId": a.ID.DeviceID}).Map(t)["nonce"].(string)
	sig := ed25519.Sign(a.ID.Sign, []byte(challengeContext+"\n"+a.ID.DeviceID+"\n"+nonce))
	res := a.Must(t, http.StatusOK, "POST", "/v1/auth/verify", map[string]string{"deviceId": a.ID.DeviceID, "nonce": nonce, "sig": b64.EncodeToString(sig)})
	a.Token = res.Map(t)["token"].(string)
}

func (a *API) Onboard(t testing.TB, code string) {
	t.Helper()
	a.Register(t, code)
	a.SignIn(t)
}

func (a *API) ElevateByApproval(t testing.TB, approver *API) {
	t.Helper()
	approvalID := a.Must(t, http.StatusCreated, "POST", "/v1/auth/elevation/approval", nil).Map(t)["approvalId"].(string)
	var list struct {
		Approvals []struct {
			ID string `json:"id"`
		} `json:"approvals"`
	}
	approver.Must(t, http.StatusOK, "GET", "/v1/auth/approvals", nil).JSON(t, &list)
	found := false
	for _, pending := range list.Approvals {
		found = found || pending.ID == approvalID
	}
	if !found {
		t.Fatalf("the approver does not see approval %s: %+v", approvalID, list.Approvals)
	}
	approver.Must(t, http.StatusNoContent, "POST", "/v1/auth/approvals/"+approvalID+"/approve", nil)
	status := a.Must(t, http.StatusOK, "GET", "/v1/auth/approvals/"+approvalID, nil).Map(t)
	if status["status"] != "approved" {
		t.Fatalf("approval status: %v", status)
	}
}

func (a *API) Elevated(t testing.TB) bool {
	t.Helper()
	return a.Must(t, http.StatusOK, "GET", "/v1/auth/elevation", nil).Map(t)["elevatedUntil"].(float64) > 0
}

func (a *API) MarkSeen(t testing.TB, deviceID string) {
	t.Helper()
	sig := ed25519.Sign(a.ID.Sign, []byte("ostia-server/seen/v1\n"+a.ID.DeviceID+"\n"+deviceID))
	a.Must(t, http.StatusNoContent, "POST", "/v1/devices/"+deviceID+"/seen", map[string]string{"sig": b64.EncodeToString(sig)})
}

func (a *API) MarkSeenExpecting(t testing.TB, deviceID string, want int) {
	t.Helper()
	sig := ed25519.Sign(a.ID.Sign, []byte("ostia-server/seen/v1\n"+a.ID.DeviceID+"\n"+deviceID))
	a.Must(t, want, "POST", "/v1/devices/"+deviceID+"/seen", map[string]string{"sig": b64.EncodeToString(sig)})
}
