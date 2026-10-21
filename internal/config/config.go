package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/net/publicsuffix"

	"github.com/aurigax-ai/ostia-server/internal/httpx"
	"github.com/aurigax-ai/ostia-server/internal/store"
)

const (
	TLSFiles   = "files"
	TLSForward = "forward"

	AdminSecretEnv = "OSTIA_ADMIN_GITHUB_CLIENT_SECRET"
)

type Config struct {
	DataDir  string  `toml:"data_dir"`
	LogLevel string  `toml:"log_level"`
	Domains  Domains `toml:"domains"`
	Listen   Listen  `toml:"listen"`
	TLS      TLS     `toml:"tls"`
	Modules  Modules `toml:"modules"`
	Auth     Auth    `toml:"auth"`
	Admin    Admin   `toml:"admin"`
	Relay    Relay   `toml:"relay"`
	Publish  Publish `toml:"publish"`
	Sync     Sync    `toml:"sync"`
	Storage  Storage `toml:"storage"`
	Push     Push    `toml:"push"`
}

type Domains struct {
	API    string `toml:"api"`
	Share  string `toml:"share"`
	Relay  string `toml:"relay"`
	Scheme string `toml:"scheme"`
	Port   int    `toml:"port"`
}

type Listen struct {
	HTTPS          string   `toml:"https"`
	HTTP           string   `toml:"http"`
	ClientIPHeader string   `toml:"client_ip_header"`
	TrustedProxies []string `toml:"trusted_proxies"`
}

type TLS struct {
	Mode                 string     `toml:"mode"`
	ForwardAddr          string     `toml:"forward_addr"`
	ForwardProxyProtocol bool       `toml:"forward_proxy_protocol"`
	Certs                []CertPair `toml:"certs"`
}

type CertPair struct {
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type Modules struct {
	Relay   bool `toml:"relay"`
	Publish bool `toml:"publish"`
	Sync    bool `toml:"sync"`
	Push    bool `toml:"push"`
}

type Auth struct {
	GitHubClientID  string   `toml:"github_client_id"`
	GitHubBaseURL   string   `toml:"github_base_url"`
	GitHubAPIURL    string   `toml:"github_api_url"`
	SessionTTL      Duration `toml:"session_ttl"`
	MaxDevices      int      `toml:"max_devices_per_account"`
	InviteTTL       Duration `toml:"invite_ttl"`
	DeviceInviteTTL Duration `toml:"device_invite_ttl"`
	ElevationTTL    Duration `toml:"elevation_ttl"`
	ApprovalTTL     Duration `toml:"approval_ttl"`
	ApproverMinAge  Duration `toml:"approver_min_age"`

	RevokedDeviceRetention Duration `toml:"revoked_device_retention"`
}

type Admin struct {
	Enabled                bool   `toml:"enabled"`
	GitHubClientID         string `toml:"github_client_id"`
	GitHubClientSecretFile string `toml:"github_client_secret_file"`

	GitHubClientSecret string `toml:"-"`
}

type Relay struct {
	MaxStreamsPerLabel                  int      `toml:"max_streams_per_label"`
	MaxUnconfirmedPerLabel              int      `toml:"max_unconfirmed_per_label"`
	UnconfirmedOpensPerMinute           int      `toml:"unconfirmed_opens_per_minute"`
	UnconfirmedOpensPerMinutePerAddress int      `toml:"unconfirmed_opens_per_minute_per_address"`
	UnconfirmedTimeout                  Duration `toml:"unconfirmed_timeout"`
	ConnectionsPerMinute                int      `toml:"connections_per_minute"`
	ConnectionsPerMinutePerIP           int      `toml:"connections_per_minute_per_ip"`
	MonthlyBytesPerAccount              int64    `toml:"monthly_bytes_per_account"`
	IdleTimeout                         Duration `toml:"idle_timeout"`
	PingInterval                        Duration `toml:"ping_interval"`
	AcceptTimeout                       Duration `toml:"accept_timeout"`
	HelloTimeout                        Duration `toml:"hello_timeout"`
	MaxPendingHellos                    int      `toml:"max_pending_hellos"`
	MaxPendingHellosPerIP               int      `toml:"max_pending_hellos_per_ip"`
}

type Publish struct {
	MaxFileBytes        int64    `toml:"max_file_bytes"`
	MaxSharesPerAccount int      `toml:"max_shares_per_account"`
	MaxBytesPerAccount  int64    `toml:"max_bytes_per_account"`
	MinExpiry           Duration `toml:"min_expiry"`
	DefaultExpiry       Duration `toml:"default_expiry"`
	MaxExpiry           Duration `toml:"max_expiry"`
	AllowNever          bool     `toml:"allow_never"`
	AllowPublic         bool     `toml:"allow_public"`
	SweepInterval       Duration `toml:"sweep_interval"`
}

type Sync struct {
	MaxBlobBytes           int64    `toml:"max_blob_bytes"`
	MaxManifestBytes       int64    `toml:"max_manifest_bytes"`
	QuotaBytes             int64    `toml:"quota_bytes"`
	ManifestHistory        int      `toml:"manifest_history"`
	ManifestCheckpointDays int      `toml:"manifest_checkpoint_days"`
	GCGrace                Duration `toml:"gc_grace"`
}

type Storage struct {
	SQLiteJournal string `toml:"sqlite_journal"`
}

type Push struct {
	Upstream             string   `toml:"upstream"`
	MaxHandles           int      `toml:"max_handles"`
	MaxHandlesPerAccount int      `toml:"max_handles_per_account"`
	TicketTTL            Duration `toml:"ticket_ttl"`
	TicketBurst          int      `toml:"ticket_burst"`
	FCM                  FCM      `toml:"fcm"`
	APNs                 APNs     `toml:"apns"`
}

type FCM struct {
	ServiceAccountFile string `toml:"service_account_file"`
	Endpoint           string `toml:"endpoint"`
}

type APNs struct {
	KeyFile    string `toml:"key_file"`
	KeyID      string `toml:"key_id"`
	TeamID     string `toml:"team_id"`
	Topic      string `toml:"topic"`
	Production bool   `toml:"production"`
	Endpoint   string `toml:"endpoint"`
}

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

const (
	KiB = 1 << 10
	MiB = 1 << 20
	GiB = 1 << 30
)

func Default() Config {
	return Config{
		DataDir:  "./data",
		LogLevel: "info",
		Domains:  Domains{Scheme: "https"},
		Listen:   Listen{HTTPS: ":443", ClientIPHeader: "X-Forwarded-For"},
		TLS:      TLS{Mode: TLSFiles, ForwardProxyProtocol: true},
		Modules:  Modules{Relay: true, Publish: true, Sync: true},
		Auth: Auth{
			GitHubBaseURL:   "https://github.com",
			GitHubAPIURL:    "https://api.github.com",
			SessionTTL:      Duration(time.Hour),
			MaxDevices:      10,
			InviteTTL:       Duration(7 * 24 * time.Hour),
			DeviceInviteTTL: Duration(10 * time.Minute),
			ElevationTTL:    Duration(5 * time.Minute),
			ApprovalTTL:     Duration(5 * time.Minute),
			ApproverMinAge:  Duration(24 * time.Hour),

			RevokedDeviceRetention: Duration(30 * 24 * time.Hour),
		},
		Relay: Relay{
			MaxStreamsPerLabel:                  8,
			MaxUnconfirmedPerLabel:              4,
			UnconfirmedOpensPerMinute:           600,
			UnconfirmedOpensPerMinutePerAddress: 30,
			UnconfirmedTimeout:                  Duration(15 * time.Second),
			ConnectionsPerMinute:                30,
			ConnectionsPerMinutePerIP:           10,
			MonthlyBytesPerAccount:              5 * GiB,
			IdleTimeout:                         Duration(10 * time.Minute),
			PingInterval:                        Duration(25 * time.Second),
			AcceptTimeout:                       Duration(10 * time.Second),
			HelloTimeout:                        Duration(5 * time.Second),
			MaxPendingHellos:                    1024,
			MaxPendingHellosPerIP:               16,
		},
		Publish: Publish{
			MaxFileBytes:        16 * MiB,
			MaxSharesPerAccount: 100,
			MaxBytesPerAccount:  500 * MiB,
			MinExpiry:           Duration(time.Minute),
			DefaultExpiry:       Duration(30 * 24 * time.Hour),
			MaxExpiry:           Duration(365 * 24 * time.Hour),
			AllowPublic:         true,
			SweepInterval:       Duration(time.Hour),
		},
		Sync: Sync{
			MaxBlobBytes:           16 * MiB,
			MaxManifestBytes:       4 * MiB,
			QuotaBytes:             512 * MiB,
			ManifestHistory:        10,
			ManifestCheckpointDays: 14,
			GCGrace:                Duration(time.Hour),
		},
		Storage: Storage{SQLiteJournal: store.JournalWAL},
		Push:    Push{MaxHandles: 100000, MaxHandlesPerAccount: 20, TicketTTL: Duration(10 * time.Minute), TicketBurst: 3},
	}
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	dec := toml.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		if strict, ok := errors.AsType[*toml.StrictMissingError](err); ok {
			return Config{}, fmt.Errorf("%s: unknown key\n%s", path, strict.String())
		}
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	cfg.normalize()
	if err := cfg.loadAdminSecret(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) normalize() {
	c.Domains.API = strings.ToLower(strings.TrimSpace(c.Domains.API))
	c.Domains.Share = strings.ToLower(strings.TrimSpace(c.Domains.Share))
	c.Domains.Relay = strings.ToLower(strings.TrimSpace(c.Domains.Relay))
	if c.Domains.Port == 0 {
		c.Domains.Port = defaultPort(c.Domains.Scheme)
	}
}

func (c *Config) loadAdminSecret() error {
	if !c.Admin.Enabled {
		return nil
	}
	fromEnv := strings.TrimSpace(os.Getenv(AdminSecretEnv))
	switch {
	case fromEnv != "" && c.Admin.GitHubClientSecretFile != "":
		return fmt.Errorf("set the admin GitHub client secret in %s or admin.github_client_secret_file, not both", AdminSecretEnv)
	case fromEnv != "":
		c.Admin.GitHubClientSecret = fromEnv
	case c.Admin.GitHubClientSecretFile != "":
		raw, err := readPrivate(c.Admin.GitHubClientSecretFile)
		if err != nil {
			return fmt.Errorf("admin.github_client_secret_file: %w", err)
		}
		c.Admin.GitHubClientSecret = strings.TrimSpace(string(raw))
	}
	return nil
}

func readPrivate(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by group or others (mode %04o); make it 0600 or 0400", path, info.Mode().Perm())
	}
	return os.ReadFile(path)
}

func (c Config) APIOrigin() string {
	host := c.Domains.API
	if c.Domains.Port != defaultPort(c.Domains.Scheme) {
		host = net.JoinHostPort(host, strconv.Itoa(c.Domains.Port))
	}
	return c.Domains.Scheme + "://" + host
}

func (c Config) Validate() error {
	var errs []error
	need := func(ok bool, msg string) {
		if !ok {
			errs = append(errs, errors.New(msg))
		}
	}
	need(c.DataDir != "", "data_dir is required")
	need(c.Domains.Scheme == "https" || c.Domains.Scheme == "http", "domains.scheme must be https or http")
	need(c.Domains.Port >= 1 && c.Domains.Port <= 65535, "domains.port must be a port number")
	for name, host := range map[string]string{"api": c.Domains.API, "share": c.Domains.Share, "relay": c.Domains.Relay} {
		need(host == "" || net.ParseIP(host) == nil, "domains."+name+" must be a host name, not an IP address")
	}
	need(c.Domains.API != "", "domains.api is required")
	if c.Modules.Relay {
		need(c.Domains.Relay != "", "domains.relay is required when modules.relay is on")
		need(c.Listen.HTTPS != "", "listen.https is required when modules.relay is on")
	}
	if c.Modules.Publish {
		need(c.Domains.Share != "", "domains.share is required when modules.publish is on")
	}
	need(c.Listen.HTTPS != "" || c.Listen.HTTP != "", "set listen.https or listen.http")
	if c.Domains.Share != "" {
		need(c.Domains.Share != c.Domains.API, "domains.share must differ from domains.api")
		if site(c.Domains.Share) == site(c.Domains.API) {
			errs = append(errs, fmt.Errorf("domains.share must be on a different registrable domain than domains.api, both are under %s", site(c.Domains.API)))
		}
	}
	if c.Domains.Relay != "" {
		need(c.Domains.Relay != c.Domains.API && c.Domains.Relay != c.Domains.Share, "domains.relay must differ from the api and share domains")
		need(!strings.HasSuffix(c.Domains.API, "."+c.Domains.Relay), "domains.api must not sit under domains.relay")
	}
	if _, err := httpx.ParseProxies(c.Listen.TrustedProxies, c.Listen.ClientIPHeader); err != nil {
		errs = append(errs, err)
	}
	if len(c.Listen.TrustedProxies) > 0 {
		need(c.Listen.ClientIPHeader != "", "listen.client_ip_header is required when listen.trusted_proxies is set")
	}
	if c.Listen.HTTPS != "" {
		switch c.TLS.Mode {
		case TLSFiles:
			need(len(c.TLS.Certs) > 0, "tls.certs is required when tls.mode is files")
		case TLSForward:
			need(c.TLS.ForwardAddr != "", "tls.forward_addr is required when tls.mode is forward")
		default:
			errs = append(errs, fmt.Errorf("tls.mode must be %q or %q", TLSFiles, TLSForward))
		}
	}
	if c.Modules.Push {
		need(c.Push.FCM.ServiceAccountFile != "" || c.Push.APNs.KeyFile != "", "modules.push needs push.fcm or push.apns credentials")
	}
	need(store.ValidJournal(c.Storage.SQLiteJournal), fmt.Sprintf("storage.sqlite_journal must be %q or %q", store.JournalWAL, store.JournalDelete))
	need(c.Auth.SessionTTL.Std() > 0, "auth.session_ttl must be positive")
	need(c.Auth.InviteTTL.Std() > 0, "auth.invite_ttl must be positive, an invite code that never expires is not allowed")
	need(c.Auth.DeviceInviteTTL.Std() > 0, "auth.device_invite_ttl must be positive, an invite code that never expires is not allowed")
	need(c.Auth.RevokedDeviceRetention.Std() > 0, "auth.revoked_device_retention must be positive")
	need(c.Auth.ApproverMinAge == 0 || c.Auth.ApproverMinAge >= c.Auth.SessionTTL, "auth.approver_min_age must be 0 or at least auth.session_ttl, otherwise a stolen session outlives the wait")
	if c.Admin.Enabled {
		need(c.Admin.GitHubClientID != "", "admin.github_client_id is required when admin.enabled is on")
		need(c.Admin.GitHubClientSecret != "", "the admin GitHub client secret is required when admin.enabled is on: set "+AdminSecretEnv+" or admin.github_client_secret_file")
		need(c.Auth.GitHubBaseURL != "" && c.Auth.GitHubAPIURL != "", "auth.github_base_url and auth.github_api_url are required when admin.enabled is on")
	}
	need(c.Publish.MaxExpiry >= c.Publish.DefaultExpiry, "publish.max_expiry must not be below publish.default_expiry")
	return errors.Join(errs...)
}

func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

func site(host string) string {
	registrable, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return registrable
}

func (c Config) RelayEnabled() bool   { return c.Modules.Relay }
func (c Config) PublishEnabled() bool { return c.Modules.Publish }
func (c Config) SyncEnabled() bool    { return c.Modules.Sync }
func (c Config) PushEnabled() bool    { return c.Modules.Push }
