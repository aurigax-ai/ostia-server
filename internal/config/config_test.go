package config

import (
	"os"
	"path/filepath"
	"strconv"
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
	t.Setenv(AdminSecretEnv, "")
	cfg, err := Load(write(t, minimal))
	if err != nil || cfg.Admin.Enabled {
		t.Fatalf("the admin UI must be off by default: %v %+v", err, cfg.Admin)
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("  s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(write(t, minimal+"\n[admin]\nenabled = true\ngithub_client_id = \"Iv1.abc\"\ngithub_client_secret_file = "+strconv.Quote(secret)+"\n"))
	if err != nil || !cfg.Admin.Enabled || cfg.Admin.GitHubClientID != "Iv1.abc" || cfg.Admin.GitHubClientSecret != "s3cret" {
		t.Fatalf("%v %+v", err, cfg.Admin)
	}
}

func TestAdminGitHubSecretComesFromTheEnvironment(t *testing.T) {
	t.Setenv(AdminSecretEnv, " from-env ")
	cfg, err := Load(write(t, minimal+"\n[admin]\nenabled = true\ngithub_client_id = \"Iv1.abc\"\n"))
	if err != nil || cfg.Admin.GitHubClientSecret != "from-env" {
		t.Fatalf("%v %+v", err, cfg.Admin)
	}
}

func TestAdminNeedsAClientIDAndASecretWhenEnabled(t *testing.T) {
	t.Setenv(AdminSecretEnv, "")
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		extra string
		want  string
	}{
		"no id":          {"github_client_secret_file = " + strconv.Quote(secret), "admin.github_client_id"},
		"no secret":      {`github_client_id = "Iv1.abc"`, "client secret is required"},
		"empty file":     {"github_client_id = \"Iv1.abc\"\ngithub_client_secret_file = " + strconv.Quote(empty), "client secret is required"},
		"missing file":   {"github_client_id = \"Iv1.abc\"\ngithub_client_secret_file = \"/nonexistent/secret\"", "github_client_secret_file"},
		"secret in toml": {"github_client_id = \"Iv1.abc\"\ngithub_client_secret = \"leak\"", "github_client_secret"},
	}
	for name, c := range cases {
		body := minimal + "\n[admin]\nenabled = true\n" + c.extra + "\n"
		if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
	hosts := minimal + "\n[auth]\ngithub_base_url = \"\"\n[admin]\nenabled = true\ngithub_client_id = \"Iv1.abc\"\ngithub_client_secret_file = " + strconv.Quote(secret) + "\n"
	if _, err := Load(write(t, hosts)); err == nil || !strings.Contains(err.Error(), "auth.github_base_url") {
		t.Fatalf("the admin sign-in needs the GitHub hosts: %v", err)
	}
	both := minimal + "\n[admin]\nenabled = true\ngithub_client_id = \"Iv1.abc\"\ngithub_client_secret_file = " + strconv.Quote(secret) + "\n"
	t.Setenv(AdminSecretEnv, "also")
	if _, err := Load(write(t, both)); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("a secret in both places must be refused: %v", err)
	}
}

func TestAdminSecretFileWiderThan0600IsRefused(t *testing.T) {
	t.Setenv(AdminSecretEnv, "")
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := minimal + "\n[admin]\nenabled = true\ngithub_client_id = \"Iv1.abc\"\ngithub_client_secret_file = " + strconv.Quote(secret) + "\n"
	if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), "readable by group or others") {
		t.Fatalf("a world-readable secret file must be refused: %v", err)
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := os.Chmod(secret, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(write(t, body)); err != nil {
			t.Fatalf("mode %o: %v", mode, err)
		}
	}
}

func TestAdminSecretIsNotReadWhileAdminIsOff(t *testing.T) {
	t.Setenv(AdminSecretEnv, "")
	cfg, err := Load(write(t, minimal+"\n[admin]\ngithub_client_id = \"Iv1.abc\"\ngithub_client_secret_file = \"/nonexistent/secret\"\n"))
	if err != nil || cfg.Admin.GitHubClientSecret != "" {
		t.Fatalf("%v %+v", err, cfg.Admin)
	}
}

func TestAPIOriginFollowsSchemeAndPort(t *testing.T) {
	cfg := Default()
	cfg.Domains.API = "api.example.com"
	for _, c := range []struct {
		scheme string
		port   int
		want   string
	}{{"https", 443, "https://api.example.com"}, {"https", 8443, "https://api.example.com:8443"}, {"http", 80, "http://api.example.com"}, {"http", 8080, "http://api.example.com:8080"}, {"http", 443, "http://api.example.com:443"}} {
		cfg.Domains.Scheme, cfg.Domains.Port = c.scheme, c.port
		if got := cfg.APIOrigin(); got != c.want {
			t.Errorf("%s %d: %s", c.scheme, c.port, got)
		}
	}
}

func TestAdminGitHubUsersIsAnUnknownKey(t *testing.T) {
	t.Setenv(AdminSecretEnv, "x")
	_, err := Load(write(t, minimal+"\n[admin]\nenabled = true\ngithub_users = [4242]\n"))
	if err == nil || !strings.Contains(err.Error(), "github_users") {
		t.Fatalf("an allow-list of users does not exist, so its key must not load: %v", err)
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
