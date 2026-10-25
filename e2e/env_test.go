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
	proc        *testkit.Process
	net         testkit.Net
	gh          *testkit.FakeGitHub
	githubUsers map[string]int64
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
	return &env{proc: proc, net: testkit.Net{HTTPSAddr: proc.HTTPSAddr, Roots: pki.Roots, APIHost: apiHost}, githubUsers: map[string]int64{}}
}

func githubConfig(gh *testkit.FakeGitHub, extra string) string {
	extra = testkit.WithKey(extra, "[auth]", "github_client_id", `"test-client"`)
	extra = testkit.WithKey(extra, "[auth]", "github_base_url", `"`+gh.Server.URL+`"`)
	return testkit.WithKey(extra, "[auth]", "github_api_url", `"`+gh.Server.URL+`"`)
}

func newGitHubEnv(t *testing.T, extra string) *env {
	t.Helper()
	gh := testkit.NewFakeGitHub(t, 1)
	e := newEnv(t, githubConfig(gh, extra))
	e.gh = gh
	return e
}

func (e *env) invite(t *testing.T) string {
	t.Helper()
	out := e.proc.Admin(t, "invite")
	code, _, _ := strings.Cut(out, "\n")
	return strings.TrimSpace(code)
}

func (e *env) user(t *testing.T, name string) *testkit.API {
	t.Helper()
	api := testkit.NewAPI(e.net, testkit.NewIdentity(name))
	api.Onboard(t, e.invite(t))
	return api
}

func (e *env) githubUser(t *testing.T, name string) *testkit.API {
	t.Helper()
	user := int64(len(e.githubUsers) + 1000)
	e.gh.SetUser(user)
	api, account := githubSignIn(t, e, e.gh, name)
	e.githubUsers[account] = user
	return api
}

func (e *env) device(t *testing.T, owner *testkit.API, name string) *testkit.API {
	t.Helper()
	user, ok := e.githubUsers[owner.ID.AccountID]
	if !ok {
		t.Fatal("a second device of an account signs in with the account's GitHub user; create the owner with githubUser")
	}
	e.gh.SetUser(user)
	api, account := githubSignIn(t, e, e.gh, name)
	if account != owner.ID.AccountID {
		t.Fatalf("the second device landed in account %s, want %s", account, owner.ID.AccountID)
	}
	return api
}

func (e *env) anonymous() *testkit.API {
	return testkit.NewAPI(e.net, testkit.NewIdentity("anonymous"))
}
