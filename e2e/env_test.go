package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

const (
	apiHost   = "api.ostia.test"
	relayHost = "r.ostia.test"
)

var serverBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ostia-server-e2e-")
	if err != nil {
		panic(err)
	}
	serverBinary, err = testkit.BuildBinary(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	proc *testkit.Process
	net  testkit.Net
}

func newEnv(t *testing.T, extra string) *env {
	return newEnvModules(t, "", extra)
}

func newEnvModules(t *testing.T, modules, extra string) *env {
	t.Helper()
	pki := testkit.NewPKI(t, t.TempDir(), apiHost)
	proc := testkit.StartProcess(t, serverBinary, testkit.Config{
		APIDomain: apiHost, RelayDomain: relayHost,
		CertFile: pki.CertFile, KeyFile: pki.KeyFile, Modules: modules, Extra: extra,
	})
	return &env{proc: proc, net: testkit.Net{HTTPSAddr: proc.HTTPSAddr, Roots: pki.Roots, APIHost: apiHost}}
}

func githubConfig(gh *testkit.FakeGitHub, extra string) string {
	extra = testkit.WithKey(extra, "[auth]", "github_client_id", `"test-client"`)
	extra = testkit.WithKey(extra, "[auth]", "github_base_url", `"`+gh.Server.URL+`"`)
	return testkit.WithKey(extra, "[auth]", "github_api_url", `"`+gh.Server.URL+`"`)
}

func (e *env) invite(t *testing.T, args ...string) string {
	t.Helper()
	out := e.proc.Admin(t, append([]string{"invite"}, args...)...)
	code, _, _ := strings.Cut(out, "\n")
	return strings.TrimSpace(code)
}

func (e *env) user(t *testing.T, name string) *testkit.API {
	t.Helper()
	api := testkit.NewAPI(e.net, testkit.NewIdentity(name))
	api.Onboard(t, e.invite(t))
	return api
}

func (e *env) device(t *testing.T, owner *testkit.API, name string) *testkit.API {
	t.Helper()
	api := testkit.NewAPI(e.net, testkit.NewIdentity(name))
	api.Onboard(t, e.invite(t, "-account", owner.ID.AccountID))
	if api.ID.AccountID != owner.ID.AccountID {
		t.Fatalf("the second device landed in account %s, want %s", api.ID.AccountID, owner.ID.AccountID)
	}
	return api
}

func (e *env) anonymous() *testkit.API {
	return testkit.NewAPI(e.net, testkit.NewIdentity("anonymous"))
}
