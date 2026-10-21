package e2e

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

type relayFixture struct {
	env     *env
	api     *testkit.API
	gateway *testkit.FakeGateway
	cert    testkit.Gateway
	desktop *testkit.RelayDesktop
}

var generousRelayLimits = []string{"connections_per_minute = 1000\n", "connections_per_minute_per_ip = 1000\n", "unconfirmed_opens_per_minute = 100000\n", "unconfirmed_opens_per_minute_per_address = 100000\n"}

func withGenerousRelayLimits(extra string) string {
	missing := ""
	for _, line := range generousRelayLimits {
		key, _, _ := strings.Cut(line, " ")
		if !strings.Contains(extra, key+" ") {
			missing += line
		}
	}
	if strings.Contains(extra, "[relay]\n") {
		return strings.Replace(extra, "[relay]\n", "[relay]\n"+missing, 1)
	}
	return extra + "[relay]\n" + missing
}

func newRelayFixture(t *testing.T, extra string) *relayFixture {
	t.Helper()
	e := newEnv(t, withGenerousRelayLimits(extra))
	api := e.user(t, "desktop")
	cert := testkit.NewGatewayCert(t)
	gateway := testkit.StartGateway(t, cert)
	desktop := &testkit.RelayDesktop{API: api, Gateway: gateway}
	desktop.Prepare(t)
	desktop.Listen(t)
	waitUntil(t, "desktop is listening", func() bool {
		conn, err := testkit.DialPhone(t.Context(), e.net, desktop.Host, cert.Fingerprint)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
	return &relayFixture{env: e, api: api, gateway: gateway, cert: cert, desktop: desktop}
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting until %s", what)
}

func TestPhoneReachesDesktopThroughRelayWithPinnedTLS(t *testing.T) {
	f := newRelayFixture(t, "")
	secret := "phone-secret-" + t.Name()
	conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := testkit.Hello(conn, f.gateway.Token); err != nil {
		t.Fatal(err)
	}
	reply, err := testkit.Converse(conn, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, "gateway saw "+secret) {
		t.Fatalf("reply %q", reply)
	}
	phoneAddr := conn.LocalAddr().String()
	if !strings.HasSuffix(reply, "from "+phoneAddr) {
		t.Fatalf("the gateway must see the phone's address as reported by the relay: %q, phone is %s", reply, phoneAddr)
	}
	if peer := <-f.gateway.Peers; peer == "" {
		t.Fatal("no peer reported")
	}

	var searched []string
	_ = filepath.WalkDir(f.env.proc.DataDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			raw, _ := os.ReadFile(path)
			searched = append(searched, string(raw))
		}
		return nil
	})
	searched = append(searched, f.env.proc.Log())
	for _, text := range searched {
		if strings.Contains(text, secret) {
			t.Fatal("plaintext from the phone reached the server's disk or log")
		}
	}
}

func TestRelayCannotBeImpersonatedByAnotherCertificate(t *testing.T) {
	f := newRelayFixture(t, "")
	other := testkit.NewGatewayCert(t)
	_, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, other.Fingerprint)
	if !errors.Is(err, testkit.ErrPinMismatch) {
		t.Fatalf("phone pinned to a different certificate must refuse the connection, got %v", err)
	}
	conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestUnknownLabelIsHeldThenClosedSilently(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nhello_timeout = \"800ms\"\n")
	unknown := strings.Repeat("a", 26) + "." + relayHost
	start := time.Now()
	raw, err := f.env.net.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	hello := clientHelloBytes(t, unknown)
	if _, err := raw.Write(hello); err != nil {
		t.Fatal(err)
	}
	n, err := raw.Read(make([]byte, 64))
	if n != 0 || err == nil {
		t.Fatalf("the relay answered an unknown label: %d bytes", n)
	}
	if elapsed := time.Since(start); elapsed < 700*time.Millisecond {
		t.Fatalf("unknown label closed after %v, want it held for the hello timeout", elapsed)
	}
}

func TestKnownLabelWithoutListenerIsResetImmediately(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nhello_timeout = \"3s\"\n")
	f.desktop.Stop()
	waitUntil(t, "relay notices the desktop left", func() bool {
		raw, err := f.env.net.Dial(t.Context())
		if err != nil {
			return false
		}
		defer raw.Close()
		_, _ = raw.Write(clientHelloBytes(t, f.desktop.Host))
		_ = raw.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err = raw.Read(make([]byte, 1))
		var ne net.Error
		return err != nil && !(errors.As(err, &ne) && ne.Timeout())
	})
}

func stillRelayed(t *testing.T, f *relayFixture) (net.Conn, bool) {
	t.Helper()
	conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
	if err != nil {
		return nil, false
	}
	for range 4 {
		time.Sleep(60 * time.Millisecond)
		if _, err := testkit.Converse(conn, "still relayed?"); err != nil {
			_ = conn.Close()
			return nil, false
		}
	}
	return conn, true
}

func TestRelayLimitsConfirmedStreamsPerLabel(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nmax_streams_per_label = 2\nconnections_per_minute = 100\nconnections_per_minute_per_ip = 100\n")
	var held []net.Conn
	for range 2 {
		conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
		defer conn.Close()
	}
	if conn, ok := stillRelayed(t, f); ok {
		_ = conn.Close()
		t.Fatal("a third confirmed stream was relayed")
	}
	_ = held[0].Close()
	waitUntil(t, "a slot frees up after a stream closes", func() bool {
		conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
		if err != nil {
			return false
		}
		defer conn.Close()
		return true
	})
}

func TestAFullUnconfirmedPoolEvictsTheOldestInsteadOfRefusingTheRealPhone(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nmax_streams_per_label = 2\nmax_unconfirmed_per_label = 2\nunconfirmed_timeout = \"30s\"\n")
	var squatters []net.Conn
	for range 2 {
		conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		squatters = append(squatters, conn)
		defer conn.Close()
	}
	conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
	if err != nil {
		t.Fatalf("squatters holding every unconfirmed slot must not lock the real phone out: %v", err)
	}
	defer conn.Close()
	_ = squatters[0].SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := squatters[0].Read(make([]byte, 1)); err == nil {
		t.Fatal("the oldest unconfirmed stream was not evicted")
	}
	if _, err := testkit.Converse(conn, "still here"); err != nil {
		t.Fatalf("the real phone must keep working: %v", err)
	}
}

func TestUnconfirmedStreamsAreClosedAfterTheTimeout(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nunconfirmed_timeout = \"700ms\"\n")
	conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("an unconfirmed stream must be closed after the timeout: %v after %v", err, time.Since(start))
	}
}

func TestUnconfirmedOpensArePerAddressRateLimited(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nunconfirmed_opens_per_minute_per_address = 4\n")
	succeeded := 0
	for range 12 {
		if conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint); err == nil {
			succeeded++
			_ = conn.Close()
		}
	}
	if succeeded > 5 || succeeded == 0 {
		t.Fatalf("one address can open unlimited streams: %d succeeded", succeeded)
	}
}

func TestUnconfirmedOpensArePerLabelRateLimited(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nunconfirmed_opens_per_minute = 5\n")
	succeeded := 0
	for range 12 {
		if conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint); err == nil {
			succeeded++
			_ = conn.Close()
		}
	}
	if succeeded > 6 || succeeded == 0 {
		t.Fatalf("unconfirmed opens are not limited: %d succeeded", succeeded)
	}
}

func TestRefusedConfirmationsDoNotLoosenTheStreamLimit(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nmax_streams_per_label = 1\n")
	first, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	for range 4 {
		if conn, ok := stillRelayed(t, f); ok {
			_ = conn.Close()
			t.Fatal("a second confirmed stream was relayed past the limit of one")
		}
	}
	_ = first.Close()
	var held net.Conn
	waitUntil(t, "the slot frees up", func() bool {
		conn, ok := stillRelayed(t, f)
		held = conn
		return ok
	})
	defer held.Close()
	if conn, ok := stillRelayed(t, f); ok {
		_ = conn.Close()
		t.Fatal("the counter drifted and a second stream got through")
	}
}

func TestConfirmedStreamsLeaveTheUnconfirmedPool(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nmax_streams_per_label = 4\nmax_unconfirmed_per_label = 1\nconnections_per_minute = 100\nconnections_per_minute_per_ip = 100\n")
	for range 4 {
		conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
		if err != nil {
			t.Fatalf("confirmed streams must not count against the unconfirmed cap: %v", err)
		}
		defer conn.Close()
	}
}

func TestWrongTokenNeverConfirmsAStream(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nunconfirmed_timeout = \"600ms\"\n")
	conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := testkit.Hello(conn, "not-the-token"); !errors.Is(err, testkit.ErrGatewayDenied) {
		t.Fatalf("%v", err)
	}
}

func TestRelayLimitsNewConnectionsPerSourceAddress(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nconnections_per_minute_per_ip = 6\nconnections_per_minute = 100\n")
	succeeded, refused := 0, 0
	for range 12 {
		conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
		if err != nil {
			refused++
			continue
		}
		succeeded++
		_ = conn.Close()
	}
	if refused == 0 || succeeded > 8 {
		t.Fatalf("source rate limit not applied: %d succeeded, %d refused", succeeded, refused)
	}
}

func TestRelayLimitsConfirmedConnectionsPerLabel(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nconnections_per_minute = 5\nconnections_per_minute_per_ip = 100\n")
	succeeded := 0
	for range 12 {
		if conn, ok := stillRelayed(t, f); ok {
			succeeded++
			_ = conn.Close()
		}
	}
	if succeeded > 6 || succeeded == 0 {
		t.Fatalf("label rate limit not applied: %d succeeded", succeeded)
	}
	f2 := newRelayFixture(t, "[relay]\nconnections_per_minute = 2\nconnections_per_minute_per_ip = 100\n")
	for range 6 {
		if conn, err := testkit.DialPhone(t.Context(), f2.env.net, f2.desktop.Host, f2.cert.Fingerprint); err == nil {
			_ = conn.Close()
		}
	}
	if conn, err := testkit.DialAuthed(t.Context(), f2.env.net, f2.desktop.Host, f2.cert.Fingerprint, f2.gateway.Token); err != nil {
		t.Fatalf("unconfirmed connections must not spend the label's confirmed budget: %v", err)
	} else {
		_ = conn.Close()
	}
}

func TestRelayClosesIdleStreams(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nidle_timeout = \"400ms\"\n")
	conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := testkit.Converse(conn, "hi"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle stream stayed open")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("idle stream closed after %v", time.Since(start))
	}
}

func TestRelayStopsAtTheMonthlyByteQuota(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nmonthly_bytes_per_account = 6000\nconnections_per_minute = 100\nconnections_per_minute_per_ip = 100\nidle_timeout = \"400ms\"\n")
	var lastErr error
	for range 12 {
		conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
		if err != nil {
			lastErr = err
			break
		}
		_, _ = testkit.Converse(conn, strings.Repeat("x", 500))
		_ = conn.Close()
	}
	if lastErr == nil {
		t.Fatal("relay kept forwarding past the monthly byte quota")
	}
}

func TestRevokedDeviceLosesItsRelayImmediately(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nhello_timeout = \"700ms\"\n")
	other := f.env.device(t, f.api, "second desktop")
	conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	other.ElevateByApproval(t, f.api)
	other.Must(t, http.StatusNoContent, "DELETE", "/v1/devices/"+f.api.ID.DeviceID, nil)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err == nil || time.Since(start) > time.Second {
		t.Fatalf("open phone stream must close at once when the desktop is revoked: %v after %v", err, time.Since(start))
	}
	waitUntil(t, "the label stops working", func() bool {
		c, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
		if err == nil {
			_ = c.Close()
		}
		return err != nil
	})
}

func TestNewListenerReplacesTheOld(t *testing.T) {
	f := newRelayFixture(t, "")
	second := &testkit.RelayDesktop{API: f.api, Gateway: f.gateway}
	second.Prepare(t)
	if second.Label != f.desktop.Label {
		t.Fatal("a device keeps one label")
	}
	second.Listen(t)
	waitUntil(t, "the relay works through the new listener", func() bool {
		conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
		if err != nil {
			return false
		}
		defer conn.Close()
		_, err = testkit.Converse(conn, "after replace")
		return err == nil
	})
}

func TestRelayKeepsListenersAliveWithPings(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nping_interval = \"200ms\"\n")
	waitUntil(t, "pings arrive", func() bool { return f.desktop.PingCount() >= 3 })
}

func TestRelayRoutesRequireASession(t *testing.T) {
	e := newEnv(t, "")
	anon := e.anonymous()
	for _, route := range [][2]string{{"POST", "/v1/relay/label"}, {"GET", "/v1/relay/listen"}, {"GET", "/v1/relay/accept/abc"}} {
		res := anon.Do(t, route[0], route[1], nil)
		if res.Status != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: %s", route[0], route[1], res)
		}
	}
}

func TestAcceptNeedsTheStreamOfTheSameDevice(t *testing.T) {
	f := newRelayFixture(t, "")
	stranger := f.env.user(t, "stranger")
	if res := stranger.Do(t, "GET", "/v1/relay/accept/"+strings.Repeat("a", 26), nil); res.Status != http.StatusNotFound {
		t.Fatalf("accept of an unknown stream: %s", res)
	}
}

func TestRelayCanBeSwitchedOffInConfig(t *testing.T) {
	e := newEnvModules(t, "relay = false\npublish = true\nsync = true\npush = false\n", "")
	api := e.user(t, "desktop")
	if res := api.Do(t, "POST", "/v1/relay/label", nil); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
		t.Fatalf("relay route exists with the module off: %s", res)
	}
	info := api.Must(t, http.StatusOK, "GET", "/v1/info", nil).Map(t)
	if info["modules"].(map[string]any)["relay"] != false {
		t.Fatalf("info: %v", info)
	}
}

func TestListenerEndsWhenItsSessionExpires(t *testing.T) {
	f := newRelayFixture(t, "[auth]\nsession_ttl = \"2s\"\n[relay]\nping_interval = \"200ms\"\nhello_timeout = \"700ms\"\nconnections_per_minute = 1000\nconnections_per_minute_per_ip = 1000\n")
	started := time.Now()
	conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
	if err != nil {
		t.Fatalf("the listener must work while its session is valid: %v", err)
	}
	_ = conn.Close()
	t.Cleanup(func() {
		if time.Since(started) < time.Second {
			t.Error("the listener stopped before its session expired")
		}
	})
	waitUntil(t, "the listener stops with the session", func() bool {
		conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
		if err == nil {
			_ = conn.Close()
		}
		return err != nil
	})
}

func TestListenerEndsWhenTheDeviceLogsOut(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nping_interval = \"200ms\"\nhello_timeout = \"700ms\"\nconnections_per_minute = 1000\nconnections_per_minute_per_ip = 1000\n")
	conn, err := testkit.DialAuthed(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint, f.gateway.Token)
	if err != nil {
		t.Fatalf("the listener must work before logout: %v", err)
	}
	_ = conn.Close()
	f.api.Must(t, http.StatusNoContent, "DELETE", "/v1/auth/session", nil)
	waitUntil(t, "the listener stops after logout", func() bool {
		conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
		if err == nil {
			_ = conn.Close()
		}
		return err != nil
	})
}

func TestRelayLabelCarriesThePublicPort(t *testing.T) {
	e := newEnv(t, "")
	api := e.user(t, "desktop")
	label := api.Must(t, http.StatusOK, "POST", "/v1/relay/label", nil).Map(t)
	if label["port"].(float64) != 443 {
		t.Fatalf("default port: %v", label)
	}

	pki := testkit.NewPKI(t, t.TempDir(), apiHost)
	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, RelayDomain: relayHost, CertFile: pki.CertFile, KeyFile: pki.KeyFile, Port: 8443,
	})
	mapped := &env{proc: proc, net: testkit.Net{HTTPSAddr: proc.HTTPSAddr, Roots: pki.Roots, APIHost: apiHost}, accounts: map[string][]*testkit.API{}, joined: map[string]time.Time{}}
	other := mapped.user(t, "desktop")
	label = other.Must(t, http.StatusOK, "POST", "/v1/relay/label", nil).Map(t)
	if label["port"].(float64) != 8443 {
		t.Fatalf("a server reached on a mapped port must say so: %v", label)
	}
	sh := other.PublishHTML(t, testkit.ShareOptions{Mode: "link", HTML: artifactHTML})
	if !strings.HasPrefix(sh.URL, "https://"+apiHost+":8443/s/"+sh.ID) {
		t.Fatalf("share URL: %s", sh.URL)
	}
}
