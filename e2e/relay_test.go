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

func newRelayFixture(t *testing.T, extra string) *relayFixture {
	t.Helper()
	e := newEnv(t, extra)
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

func TestRelayLimitsConcurrentStreamsPerLabel(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nmax_streams_per_label = 2\nconnections_per_minute = 100\nconnections_per_minute_per_ip = 100\n")
	var held []net.Conn
	for range 2 {
		conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
		defer conn.Close()
	}
	if _, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint); err == nil {
		t.Fatal("a third concurrent stream was relayed")
	}
	_ = held[0].Close()
	waitUntil(t, "a slot frees up after a stream closes", func() bool {
		conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
		if err != nil {
			return false
		}
		defer conn.Close()
		return true
	})
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

func TestRelayLimitsNewConnectionsPerLabel(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nconnections_per_minute = 5\nconnections_per_minute_per_ip = 100\n")
	succeeded := 0
	for range 12 {
		if conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint); err == nil {
			succeeded++
			_ = conn.Close()
		}
	}
	if succeeded > 6 || succeeded == 0 {
		t.Fatalf("label rate limit not applied: %d succeeded", succeeded)
	}
}

func TestRelayClosesIdleStreams(t *testing.T) {
	f := newRelayFixture(t, "[relay]\nidle_timeout = \"400ms\"\n")
	conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
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
		conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
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
	conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
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
		conn, err := testkit.DialPhone(t.Context(), f.env.net, f.desktop.Host, f.cert.Fingerprint)
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
