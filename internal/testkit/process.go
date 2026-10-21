package testkit

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type Config struct {
	APIDomain      string
	RelayDomain    string
	CertFile       string
	KeyFile        string
	Extra          string
	HTTP           string
	Port           int
	ForwardAddr    string
	RelayListen    string
	ClientIPHeader string
	TrustedProxies []string
	Modules        string
}

type Process struct {
	DataDir    string
	ConfigPath string
	Binary     string
	HTTPSAddr  string
	HTTPAddr   string
	RelayAddr  string
	log        *lockedBuffer
	cmd        *exec.Cmd
	exited     chan struct{}
	exitErr    error
	stopOnce   sync.Once
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func BuildBinary(dir string) (string, error) {
	out := filepath.Join(dir, "ostia-server")
	cmd := exec.Command("go", "build", "-o", out, "github.com/aurigax-ai/ostia-server/cmd/ostia-server")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build: %v\n%s", err, output)
	}
	return out, nil
}

func (c Config) TOML(dataDir string) string {
	modules := c.Modules
	if modules == "" {
		modules = "relay = true\npublish = true\nsync = true\npush = false\n"
	}
	portLine := ""
	if c.Port != 0 {
		portLine = fmt.Sprintf("port = %d\n", c.Port)
	}
	listen := "https = \"127.0.0.1:0\"\n"
	if c.HTTP != "" {
		listen += fmt.Sprintf("http = %q\n", c.HTTP)
	}
	if c.RelayListen != "" {
		listen += fmt.Sprintf("relay = %q\n", c.RelayListen)
	}
	if c.ClientIPHeader != "" {
		listen += fmt.Sprintf("client_ip_header = %q\n", c.ClientIPHeader)
	}
	if len(c.TrustedProxies) > 0 {
		quoted := make([]string, len(c.TrustedProxies))
		for i, p := range c.TrustedProxies {
			quoted[i] = fmt.Sprintf("%q", p)
		}
		listen += "trusted_proxies = [" + strings.Join(quoted, ", ") + "]\n"
	}
	tlsConfig := fmt.Sprintf("mode = \"files\"\n[[tls.certs]]\ncert = %q\nkey = %q\n", c.CertFile, c.KeyFile)
	if c.ForwardAddr != "" {
		tlsConfig = fmt.Sprintf("mode = \"forward\"\nforward_addr = %q\n", c.ForwardAddr)
	}
	return fmt.Sprintf(`data_dir = %q
log_level = "debug"

[domains]
api = %q
relay = %q
%s
[listen]
%s
[tls]
%s
[modules]
%s
%s
`, dataDir, c.APIDomain, c.RelayDomain, portLine, listen, tlsConfig, modules, c.Extra)
}

var (
	listeningHTTPS = regexp.MustCompile(`listening https=(\S+)`)
	listeningHTTP  = regexp.MustCompile(`listening http=(\S+)`)
	listeningRelay = regexp.MustCompile(`listening relay=(\S+)`)
)

func WithKey(extra, table, key, value string) string {
	if extra != "" && !strings.HasSuffix(extra, "\n") {
		extra += "\n"
	}
	if strings.Contains(extra, key+" ") {
		return extra
	}
	line := key + " = " + value + "\n"
	if strings.Contains(extra, table+"\n") {
		return strings.Replace(extra, table+"\n", table+"\n"+line, 1)
	}
	return extra + table + "\n" + line
}

func StartProcess(t testing.TB, binary string, cfg Config) *Process {
	t.Helper()
	cfg.Extra = WithKey(cfg.Extra, "[auth]", "approver_min_age", `"0s"`)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	cfgPath := filepath.Join(dir, "ostia-server.toml")
	if err := os.WriteFile(cfgPath, []byte(cfg.TOML(dataDir)), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Process{DataDir: dataDir, ConfigPath: cfgPath, Binary: binary, log: &lockedBuffer{}, exited: make(chan struct{})}
	p.cmd = exec.Command(binary, "-config", cfgPath)
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	p.cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.exitErr = p.cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() { p.Stop(t) })
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		logged := p.log.String()
		if m := listeningHTTPS.FindStringSubmatch(logged); m != nil {
			p.HTTPSAddr = m[1]
			if cfg.HTTP != "" {
				if h := listeningHTTP.FindStringSubmatch(logged); h != nil {
					p.HTTPAddr = h[1]
				}
			}
			if cfg.RelayListen != "" {
				if r := listeningRelay.FindStringSubmatch(logged); r != nil {
					p.RelayAddr = r[1]
				}
			}
			if (cfg.HTTP == "" || p.HTTPAddr != "") && (cfg.RelayListen == "" || p.RelayAddr != "") {
				return p
			}
		}
		select {
		case <-p.exited:
			t.Fatalf("server exited early: %v\n%s", p.exitErr, p.log.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("server did not start listening\n%s", p.log.String())
	return nil
}

func (p *Process) Log() string { return p.log.String() }

func (p *Process) Stop(t testing.TB) {
	p.stopOnce.Do(func() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.exited:
			if p.exitErr != nil {
				t.Errorf("server did not exit cleanly: %v\n%s", p.exitErr, p.log.String())
			}
		case <-time.After(10 * time.Second):
			_ = p.cmd.Process.Kill()
			t.Errorf("server did not stop on SIGTERM\n%s", p.log.String())
		}
	})
}

func (p *Process) Admin(t testing.TB, args ...string) string {
	t.Helper()
	cmd := exec.Command(p.Binary, append([]string{"admin", "-config", p.ConfigPath}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("admin %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
