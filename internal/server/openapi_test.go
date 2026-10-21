package server

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/config"
	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

const openAPIPath = "../../docs/openapi.json"

type operation struct {
	Method   string
	Path     string
	Security []any
	HasSec   bool
}

func loadOperations(t *testing.T) []operation {
	t.Helper()
	raw, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []operation
	for path, item := range doc.Paths {
		if _, shareHost := item["servers"]; shareHost {
			continue
		}
		for method, details := range item {
			fields, _ := details.(map[string]any)
			security, hasSecurity := fields["security"]
			list, _ := security.([]any)
			out = append(out, operation{Method: strings.ToUpper(method), Path: path, Security: list, HasSec: hasSecurity})
		}
	}
	return out
}

func everythingOn(t *testing.T) *Server {
	t.Helper()
	fake := testkit.NewFakePush(t)
	account, p8 := fake.WriteCredentials(t, t.TempDir())
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Domains.API, cfg.Domains.Share, cfg.Domains.Relay = "api.test", "shares.test", "r.test"
	cfg.Listen.HTTPS, cfg.Listen.HTTP = "", "127.0.0.1:0"
	cfg.Modules.Push = true
	cfg.Push.FCM.ServiceAccountFile = account
	cfg.Push.APNs = config.APNs{KeyFile: p8, KeyID: "KEY", TeamID: "TEAM", Topic: "topic"}
	cfg.Auth.GitHubClientID = "client"
	srv, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.DB.Close() })
	return srv
}

func TestOpenAPIDocumentsExactlyTheRegisteredRoutes(t *testing.T) {
	srv := everythingOn(t)
	registered := srv.Routes()
	var documented []string
	for _, op := range loadOperations(t) {
		documented = append(documented, op.Method+" "+op.Path)
	}
	slices.Sort(registered)
	slices.Sort(documented)
	if !slices.Equal(registered, documented) {
		t.Fatalf("docs/openapi.json and the registered routes differ\nregistered: %v\ndocumented: %v", registered, documented)
	}
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

func TestEveryDocumentedRouteDecidesItsAuthentication(t *testing.T) {
	srv := everythingOn(t)
	handler := srv.Handler()
	for _, op := range loadOperations(t) {
		if !op.HasSec {
			t.Errorf("%s %s does not state its security; write `security: []` for a deliberately public route", op.Method, op.Path)
			continue
		}
		if len(op.Security) == 0 {
			continue
		}
		path := pathParam.ReplaceAllString(op.Path, "aaaaaaaaaaaaaaaaaaaaaaaaaa")
		req := httptest.NewRequest(op.Method, path, nil)
		req.Host = "api.test"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s is documented as authenticated but answered %d without a bearer token", op.Method, op.Path, rec.Code)
		}
		req = httptest.NewRequest(op.Method, path, nil)
		req.Host = "api.test"
		req.Header.Set("Authorization", "Bearer not-a-session")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d to an invalid bearer token", op.Method, op.Path, rec.Code)
		}
	}
}

func TestPublicRoutesAreRateLimited(t *testing.T) {
	srv := everythingOn(t)
	handler := srv.Handler()
	for _, op := range loadOperations(t) {
		if len(op.Security) != 0 || op.Path == "/healthz" {
			continue
		}
		path := pathParam.ReplaceAllString(op.Path, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		limited := false
		for range 400 {
			req := httptest.NewRequest(op.Method, path, strings.NewReader("{}"))
			req.Host = "api.test"
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusTooManyRequests {
				limited = true
				break
			}
		}
		if !limited {
			t.Errorf("%s %s is public and not rate limited", op.Method, op.Path)
		}
	}
}
