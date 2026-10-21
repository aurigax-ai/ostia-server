package e2e

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

func TestPlainHTTPListenerServesAPIAndShareHostsForAReverseProxy(t *testing.T) {
	pki := testkit.NewPKI(t, t.TempDir(), apiHost)
	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, ShareDomain: shareHost, RelayDomain: relayHost, CertFile: pki.CertFile, KeyFile: pki.KeyFile,
		HTTP: "127.0.0.1:0", ClientIPHeader: "X-Forwarded-For", TrustedProxies: []string{"127.0.0.1"},
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

func TestForgedForwardedHeadersAreIgnoredWithoutTrustedProxies(t *testing.T) {
	pki := testkit.NewPKI(t, t.TempDir(), apiHost)
	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, ShareDomain: shareHost, RelayDomain: relayHost, CertFile: pki.CertFile, KeyFile: pki.KeyFile,
		HTTP: "127.0.0.1:0", ClientIPHeader: "X-Forwarded-For",
	})
	anon := testkit.NewAPI(testkit.Net{HTTPSAddr: proc.HTTPAddr, APIHost: apiHost, Plain: true}, testkit.NewIdentity("anon"))
	body := anon.ID.Registration()
	body["code"] = "nope"
	limited := false
	for i := range 40 {
		res := anon.Do(t, "POST", "/v1/auth/invite", body, "X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
		if res.Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("rotating a forged X-Forwarded-For escaped the rate limit")
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
	sources := &testkit.ProxyProtocolListener{Listener: proxy.Listener}
	proxy.Listener = sources
	proxy.TLS = pki.ServerConfig(t)
	proxy.StartTLS()
	t.Cleanup(proxy.Close)

	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, ShareDomain: shareHost, RelayDomain: relayHost, CertFile: pki.CertFile, KeyFile: pki.KeyFile,
		HTTP: "127.0.0.1:0", ForwardAddr: proxy.Listener.Addr().String(), TrustedProxies: []string{"127.0.0.1"}, ClientIPHeader: "X-Forwarded-For",
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
		conn, err := testkit.DialAuthed(t.Context(), n, desktop.Host, cert.Fingerprint, gateway.Token)
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

	raw, err := n.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: apiHost, RootCAs: pki.Roots, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	local := raw.LocalAddr().(*net.TCPAddr).AddrPort()
	if !slices.Contains(sources.Sources(), local) {
		t.Fatalf("the proxy must be told the client's address with PROXY protocol: wanted %s in %v", local, sources.Sources())
	}
}

func TestRelayListenerServesOnlyRelayHostsAndReadsProxyHeadersFromTrustedProxies(t *testing.T) {
	pki := testkit.NewPKI(t, t.TempDir(), apiHost, "*."+shareHost)
	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, ShareDomain: shareHost, RelayDomain: relayHost, CertFile: pki.CertFile, KeyFile: pki.KeyFile,
		RelayListen: "127.0.0.1:0", TrustedProxies: []string{"127.0.0.1"}, ClientIPHeader: "X-Forwarded-For",
		Extra: withGenerousRelayLimits("[relay]\nconnections_per_minute_per_ip = 3\n"),
	})
	n := testkit.Net{HTTPSAddr: proc.HTTPSAddr, Roots: pki.Roots, APIHost: apiHost}
	code, _, _ := cutLine(proc.Admin(t, "invite"))
	api := testkit.NewAPI(n, testkit.NewIdentity("desktop"))
	api.Onboard(t, code)
	cert := testkit.NewGatewayCert(t)
	gateway := testkit.StartGateway(t, cert)
	desktop := &testkit.RelayDesktop{API: api, Gateway: gateway}
	desktop.Prepare(t)
	desktop.Listen(t)

	for _, version := range []byte{1, 2} {
		forwarder := testkit.StartProxyForwarder(t, proc.RelayAddr, version)
		phones := testkit.Net{HTTPSAddr: forwarder.Addr, APIHost: apiHost}
		reaches := func() bool {
			conn, err := testkit.DialAuthed(t.Context(), phones, desktop.Host, cert.Fingerprint, gateway.Token)
			if err != nil {
				return false
			}
			defer conn.Close()
			reply, err := testkit.Converse(conn, "through the relay port")
			return err == nil && reply != ""
		}
		forwarder.SetSource(fmt.Sprintf("203.0.113.%d:40000", version))
		waitUntil(t, fmt.Sprintf("a phone reaches the desktop through PROXY protocol v%d", version), reaches)
		for range 6 {
			reaches()
		}
		if reaches() {
			t.Fatalf("v%d: the per-address limit must apply to the address in the PROXY header", version)
		}
		forwarder.SetSource(fmt.Sprintf("198.51.100.%d:40000", version))
		if !reaches() {
			t.Fatalf("v%d: another client address must not share that limit", version)
		}
	}

	forwarder := testkit.StartProxyForwarder(t, proc.RelayAddr, 2)
	raw, err := testkit.Net{HTTPSAddr: forwarder.Addr}.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: apiHost, RootCAs: pki.Roots, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(t.Context()); err == nil {
		t.Fatal("the relay port must not terminate or serve the API host")
	}

	direct := testkit.Net{HTTPSAddr: proc.RelayAddr}
	if conn, err := testkit.DialPhone(t.Context(), direct, desktop.Host, cert.Fingerprint); err == nil {
		_ = conn.Close()
		t.Fatal("a trusted proxy address that sends no PROXY header must be refused")
	}
}
