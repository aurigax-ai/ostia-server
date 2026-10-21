package e2e

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

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
	proc     *testkit.Process
	net      testkit.Net
	accounts map[string][]*testkit.API
	joined   map[string]time.Time
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
	return &env{proc: proc, net: testkit.Net{HTTPSAddr: proc.HTTPSAddr, Roots: pki.Roots, APIHost: apiHost}, accounts: map[string][]*testkit.API{}, joined: map[string]time.Time{}}
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
	e.accounts[api.ID.AccountID] = append(e.accounts[api.ID.AccountID], api)
	e.joined[api.ID.DeviceID] = time.Now()
	return api
}

func (e *env) device(t *testing.T, owner *testkit.API, name string) *testkit.API {
	t.Helper()
	known := e.accounts[owner.ID.AccountID]
	if len(known) >= 2 {
		for _, other := range known {
			if other != owner && other.Do(t, "GET", "/v1/devices", nil).Status == http.StatusOK {
				owner.ElevateByApproval(t, other)
				break
			}
		}
	}
	code := owner.Must(t, http.StatusCreated, "POST", "/v1/devices/invite", nil).Map(t)["code"].(string)
	api := testkit.NewAPI(e.net, testkit.NewIdentity(name))
	api.Onboard(t, code)
	e.accounts[owner.ID.AccountID] = append(e.accounts[owner.ID.AccountID], api)
	e.joined[api.ID.DeviceID] = time.Now()
	return api
}

func (e *env) anonymous() *testkit.API {
	return testkit.NewAPI(e.net, testkit.NewIdentity("anonymous"))
}

func (e *env) waitUntilOlderThan(t *testing.T, api *testkit.API, age time.Duration) {
	t.Helper()
	joined, ok := e.joined[api.ID.DeviceID]
	if !ok {
		joined = time.Now()
	}
	waitUntil(t, "the device is older than the approval age", func() bool { return time.Since(joined) > age+100*time.Millisecond })
}
