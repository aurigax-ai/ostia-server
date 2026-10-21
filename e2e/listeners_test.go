package e2e

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

func TestPlainHTTPListenerServesAPIAndShareHostsForAReverseProxy(t *testing.T) {
	pki := testkit.NewPKI(t, t.TempDir(), apiHost)
	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, ShareDomain: shareHost, RelayDomain: relayHost, CertFile: pki.CertFile, KeyFile: pki.KeyFile,
		HTTP: "127.0.0.1:0", ClientIPHeader: "X-Forwarded-For",
	})
	plain := testkit.Net{HTTPSAddr: proc.HTTPAddr, APIHost: apiHost, Plain: true}
	owner := testkit.NewAPI(plain, testkit.NewIdentity("desktop"))
	code, _, _ := cutLine(proc.Admin(t, "invite"))
	owner.Onboard(t, code)

	sh := owner.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	if html, err := plain.OpenShare(t, shareHost, sh); err != nil || html != artifactHTML {
		t.Fatalf("share over the plain listener: %q %v", html, err)
	}

	anon := testkit.NewAPI(plain, testkit.NewIdentity("anon"))
	body := anon.ID.Registration()
	body["code"] = "nope"
	limitedFor := func(forwardedFor string) bool {
		for range 15 {
			if anon.Do(t, "POST", "/v1/auth/invite", body, "X-Forwarded-For", forwardedFor).Status == http.StatusTooManyRequests {
				return true
			}
		}
		return false
	}
	if !limitedFor("203.0.113.7") {
		t.Fatal("rate limit did not apply")
	}
	if res := anon.Do(t, "POST", "/v1/auth/invite", body, "X-Forwarded-For", "198.51.100.9"); res.Status != http.StatusForbidden {
		t.Fatalf("limits must be per forwarded client address: %s", res)
	}
}

func cutLine(s string) (string, string, bool) {
	for i := range len(s) {
		if s[i] == '\n' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func TestForwardModePassesNonRelayTrafficToAProxyAndStillRelays(t *testing.T) {
	pki := testkit.NewPKI(t, t.TempDir(), apiHost, "*."+shareHost)

	var upstream string
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, _ := url.Parse("http://" + upstream)
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}))
	proxy.TLS = pki.ServerConfig(t)
	proxy.StartTLS()
	t.Cleanup(proxy.Close)

	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, ShareDomain: shareHost, RelayDomain: relayHost, CertFile: pki.CertFile, KeyFile: pki.KeyFile,
		HTTP: "127.0.0.1:0", ForwardAddr: proxy.Listener.Addr().String(),
	})
	upstream = proc.HTTPAddr
	n := testkit.Net{HTTPSAddr: proc.HTTPSAddr, Roots: pki.Roots, APIHost: apiHost}

	code, _, _ := cutLine(proc.Admin(t, "invite"))
	api := testkit.NewAPI(n, testkit.NewIdentity("desktop"))
	api.Onboard(t, code)

	cert := testkit.NewGatewayCert(t)
	gateway := testkit.StartGateway(t, cert)
	desktop := &testkit.RelayDesktop{API: api, Gateway: gateway}
	desktop.Prepare(t)
	desktop.Listen(t)
	waitUntil(t, "relay through the forwarding server", func() bool {
		conn, err := testkit.DialPhone(t.Context(), n, desktop.Host, cert.Fingerprint)
		if err != nil {
			return false
		}
		defer conn.Close()
		reply, err := testkit.Converse(conn, "via proxy mode")
		return err == nil && reply != ""
	})

	sh := api.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	if html, err := n.OpenShare(t, shareHost, sh); err != nil || html != artifactHTML {
		t.Fatalf("share through the proxy: %q %v", html, err)
	}
}
