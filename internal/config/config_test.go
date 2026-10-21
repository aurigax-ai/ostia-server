package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ostia-server.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimal = `
data_dir = "/var/lib/ostia-server"

[domains]
api = "api.example.com"
share = "example-share.net"
relay = "r.example.com"

[tls]
[[tls.certs]]
cert = "/etc/c.pem"
key = "/etc/k.pem"
`

func TestMinimalConfigGetsDefaults(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RelayEnabled() || !cfg.PublishEnabled() || !cfg.SyncEnabled() || cfg.PushEnabled() {
		t.Fatalf("modules: %+v", cfg.Modules)
	}
	if cfg.Relay.MaxStreamsPerLabel != 8 || cfg.Relay.IdleTimeout.Std() != 10*time.Minute || cfg.Publish.MaxFileBytes != 16*MiB {
		t.Fatalf("defaults not applied: %+v %+v", cfg.Relay, cfg.Publish)
	}
	if cfg.Publish.DefaultExpiry.Std() != 30*24*time.Hour || cfg.Publish.AllowNever || !cfg.Publish.AllowPublic {
		t.Fatalf("publish defaults: %+v", cfg.Publish)
	}
}

func TestDurationsParseFromStrings(t *testing.T) {
	cfg, err := Load(write(t, minimal+"\n[relay]\nping_interval = \"250ms\"\n[publish]\nmax_expiry = \"48h\"\ndefault_expiry = \"24h\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relay.PingInterval.Std() != 250*time.Millisecond || cfg.Publish.MaxExpiry.Std() != 48*time.Hour {
		t.Fatalf("%+v %+v", cfg.Relay, cfg.Publish)
	}
}

func TestExampleConfigLoadsAndMatchesTheDefaults(t *testing.T) {
	cfg, err := Load("../../deploy/ostia-server.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	defaults := Default()
	if cfg.Relay != defaults.Relay || cfg.Publish != defaults.Publish || cfg.Sync != defaults.Sync || cfg.Auth.SessionTTL != defaults.Auth.SessionTTL || cfg.Auth.MaxDevices != defaults.Auth.MaxDevices || cfg.Admin.Enabled != defaults.Admin.Enabled {
		t.Fatal("the example config must list the real defaults so the documentation does not drift")
	}
}

func TestAdminIsOffByDefaultAndReadsItsKeys(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil || cfg.Admin.Enabled {
		t.Fatalf("the admin UI must be off by default: %v %+v", err, cfg.Admin)
	}
	cfg, err = Load(write(t, minimal+"\n[admin]\nenabled = true\n"))
	if err != nil || !cfg.Admin.Enabled {
		t.Fatalf("%v %+v", err, cfg.Admin)
	}
}

func TestUnknownKeysAreRefused(t *testing.T) {
	_, err := Load(write(t, minimal+"\n[relay]\nmax_streams = 4\n"))
	if err == nil || !strings.Contains(err.Error(), "max_streams") {
		t.Fatalf("a mistyped key must not be silently ignored: %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"missing api":            {strings.Replace(minimal, `api = "api.example.com"`, "", 1), "domains.api"},
		"share equals api":       {strings.Replace(minimal, "example-share.net", "api.example.com", 1), "domains.share must differ"},
		"share under api":        {strings.Replace(minimal, "example-share.net", "share.api.example.com", 1), "different registrable domain"},
		"share beside api":       {strings.Replace(minimal, "example-share.net", "shares.example.com", 1), "different registrable domain"},
		"share on co.uk":         {strings.Replace(strings.Replace(minimal, "example-share.net", "a.co.uk", 1), "api.example.com", "api.b.co.uk", 1), ""},
		"api under relay":        {strings.Replace(minimal, "api.example.com", "api.r.example.com", 1), "must not sit under"},
		"no certs":               {strings.Replace(minimal, "[[tls.certs]]\ncert = \"/etc/c.pem\"\nkey = \"/etc/k.pem\"\n", "", 1), "tls.certs"},
		"bad tls mode":           {strings.Replace(minimal, "[tls]\n", "[tls]\nmode = \"acme\"\n", 1), "tls.mode"},
		"forward needs addr":     {strings.Replace(minimal, "[tls]\n", "[tls]\nmode = \"forward\"\n", 1), "forward_addr"},
		"push no creds":          {minimal + "\n[modules]\npush = true\n", "push.fcm or push.apns"},
		"bad scheme":             {strings.Replace(minimal, "[domains]\n", "[domains]\nscheme = \"ftp\"\n", 1), "domains.scheme"},
		"expiry order":           {minimal + "\n[publish]\nmax_expiry = \"1h\"\n", "max_expiry"},
		"endless invites":        {minimal + "\n[auth]\ninvite_ttl = \"0s\"\n", "auth.invite_ttl must be positive"},
		"endless device invites": {minimal + "\n[auth]\ndevice_invite_ttl = \"0s\"\n", "auth.device_invite_ttl must be positive"},
		"bad journal":            {minimal + "\n[storage]\nsqlite_journal = \"truncate\"\n", "storage.sqlite_journal"},
		"empty journal":          {minimal + "\n[storage]\nsqlite_journal = \"\"\n", "storage.sqlite_journal"},
		"no retention":           {minimal + "\n[auth]\nrevoked_device_retention = \"0s\"\n", "revoked_device_retention"},
	}
	for name, c := range cases {
		_, err := Load(write(t, c.body))
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
}

func TestRelayOffNeedsNoRelayDomain(t *testing.T) {
	body := strings.Replace(minimal, `relay = "r.example.com"`, "", 1) + "\n[modules]\nrelay = false\n"
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestPlainHTTPOnlyNeedsNoCertificates(t *testing.T) {
	body := `
data_dir = "/d"
[domains]
api = "api.example.com"
share = "example-share.net"
[listen]
https = ""
http = "127.0.0.1:8080"
[modules]
relay = false
`
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestShareDomainMayBeAPublicSuffix(t *testing.T) {
	body := strings.Replace(minimal, "example-share.net", "usercontent.example.org", 1)
	body = strings.Replace(body, "api.example.com", "api.example.net", 1)
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("%v", err)
	}
	body = strings.Replace(minimal, "example-share.net", "github.io", 1)
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("a share domain that is itself a public suffix isolates every share: %v", err)
	}
}

func TestPortDefaultsFollowTheScheme(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil || cfg.Domains.Port != 443 {
		t.Fatalf("https without a port: %d %v", cfg.Domains.Port, err)
	}
	cfg, err = Load(write(t, strings.Replace(minimal, "[domains]\n", "[domains]\nscheme = \"http\"\n", 1)))
	if err != nil || cfg.Domains.Port != 80 {
		t.Fatalf("http without a port: %d %v", cfg.Domains.Port, err)
	}
	cfg, err = Load(write(t, strings.Replace(minimal, "[domains]\n", "[domains]\nport = 8443\n", 1)))
	if err != nil || cfg.Domains.Port != 8443 {
		t.Fatalf("explicit port: %d %v", cfg.Domains.Port, err)
	}
}

func TestPortAndHostValidation(t *testing.T) {
	for name, c := range map[string]struct{ body, want string }{
		"too big":   {strings.Replace(minimal, "[domains]\n", "[domains]\nport = 65536\n", 1), "domains.port"},
		"negative":  {strings.Replace(minimal, "[domains]\n", "[domains]\nport = -1\n", 1), "domains.port"},
		"api is IP": {strings.Replace(minimal, "api.example.com", "192.0.2.1", 1), "not an IP address"},
		"api IPv6":  {strings.Replace(minimal, "api.example.com", "::1", 1), "not an IP address"},
	} {
		if _, err := Load(write(t, c.body)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSQLiteJournalDefaultsToWALAndAcceptsDelete(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil || cfg.Storage.SQLiteJournal != "wal" {
		t.Fatalf("default: %q %v", cfg.Storage.SQLiteJournal, err)
	}
	cfg, err = Load(write(t, minimal+"\n[storage]\nsqlite_journal = \"delete\"\n"))
	if err != nil || cfg.Storage.SQLiteJournal != "delete" {
		t.Fatalf("delete: %q %v", cfg.Storage.SQLiteJournal, err)
	}
}
