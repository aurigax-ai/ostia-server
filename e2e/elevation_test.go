package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

func requireElevation(t *testing.T, api *testkit.API, what, method, path string, body any) {
	t.Helper()
	res := api.Do(t, method, path, body)
	if res.Status != http.StatusForbidden || res.Map(t)["error"] != "elevation-required" {
		t.Errorf("%s was not refused: %s", what, res)
	}
}

func TestDestructiveAccountActionsNeedAnotherDevicesApproval(t *testing.T) {
	e := newEnv(t, "")
	laptop := e.user(t, "laptop")
	phone := e.device(t, laptop, "phone")
	requireElevation(t, laptop, "revoking another device", "DELETE", "/v1/devices/"+phone.ID.DeviceID, nil)
	requireElevation(t, laptop, "deleting the account", "DELETE", "/v1/account", nil)
	laptop.Must(t, http.StatusOK, "GET", "/v1/devices", nil)

	laptop.ElevateByApproval(t, phone)
	if !laptop.Elevated(t) {
		t.Fatal("the requester is not elevated after the approval")
	}
	if phone.Elevated(t) {
		t.Fatal("approving elevated the approver")
	}
	laptop.Must(t, http.StatusNoContent, "DELETE", "/v1/devices/"+phone.ID.DeviceID, nil)
}

func TestADeviceMayEndItsOwnSessionAndRevokeItselfWithoutApproval(t *testing.T) {
	e := newEnv(t, "")
	laptop := e.user(t, "laptop")
	phone := e.device(t, laptop, "phone")
	phone.Must(t, http.StatusNoContent, "DELETE", "/v1/devices/"+phone.ID.DeviceID, nil)
	if res := phone.Do(t, "GET", "/v1/devices", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("a revoked device kept its session: %s", res)
	}
	laptop.Must(t, http.StatusOK, "GET", "/v1/devices", nil)
}

func TestElevationBelongsToOneSessionAndExpires(t *testing.T) {
	e := newEnv(t, "[auth]\nelevation_ttl = \"1s\"\n")
	laptop := e.user(t, "laptop")
	phone := e.device(t, laptop, "phone")
	laptop.ElevateByApproval(t, phone)
	laptop.Must(t, http.StatusOK, "GET", "/v1/auth/elevation", nil)
	if !laptop.Elevated(t) {
		t.Fatal("not elevated")
	}
	time.Sleep(1200 * time.Millisecond)
	if laptop.Elevated(t) {
		t.Fatal("elevation outlived its lifetime")
	}
	requireElevation(t, laptop, "revoking a device after the elevation ended", "DELETE", "/v1/devices/"+phone.ID.DeviceID, nil)
	laptop.ElevateByApproval(t, phone)
	laptop.SignIn(t)
	if laptop.Elevated(t) {
		t.Fatal("a new session of the same device started elevated")
	}
}

func TestSingleDeviceAccountsCannotElevate(t *testing.T) {
	e := newEnv(t, "")
	laptop := e.user(t, "laptop")
	res := laptop.Do(t, "POST", "/v1/auth/elevation/approval", nil)
	if res.Status != http.StatusConflict || res.Map(t)["error"] != "no-second-device" {
		t.Fatalf("%s", res)
	}
	requireElevation(t, laptop, "deleting the account", "DELETE", "/v1/account", nil)
}

func TestApprovalsCannotBeSelfGrantedOrCrossAccounts(t *testing.T) {
	e := newEnv(t, "")
	laptop := e.user(t, "laptop")
	phone := e.device(t, laptop, "phone")
	stranger := e.user(t, "stranger")
	strangerPhone := e.device(t, stranger, "stranger phone")

	id := laptop.Must(t, http.StatusCreated, "POST", "/v1/auth/elevation/approval", nil).Map(t)["approvalId"].(string)
	if res := laptop.Do(t, "POST", "/v1/auth/approvals/"+id+"/approve", nil); res.Status != http.StatusForbidden {
		t.Fatalf("self approval: %s", res)
	}
	if res := strangerPhone.Do(t, "POST", "/v1/auth/approvals/"+id+"/approve", nil); res.Status != http.StatusNotFound {
		t.Fatalf("another account's device approved: %s", res)
	}
	var list struct {
		Approvals []any `json:"approvals"`
	}
	strangerPhone.Must(t, http.StatusOK, "GET", "/v1/auth/approvals", nil).JSON(t, &list)
	if len(list.Approvals) != 0 {
		t.Fatal("another account sees the request")
	}
	phone.Must(t, http.StatusNoContent, "DELETE", "/v1/auth/approvals/"+id, nil)
	if res := phone.Do(t, "POST", "/v1/auth/approvals/"+id+"/approve", nil); res.Status != http.StatusNotFound {
		t.Fatalf("approving a cancelled request: %s", res)
	}
}

func TestGitHubAccountsCanElevateWithAFreshGitHubSignIn(t *testing.T) {
	gh := testkit.NewFakeGitHub(t, 4242)
	e := newEnv(t, "[auth]\ngithub_client_id = \"test-client\"\ngithub_base_url = \""+gh.Server.URL+"\"\ngithub_api_url = \""+gh.Server.URL+"\"\n")
	laptop, _ := githubSignIn(t, e, gh, "laptop")
	requireElevation(t, laptop, "deleting a GitHub account", "DELETE", "/v1/account", nil)

	poll := func(flowID string) testkit.Response {
		time.Sleep(1100 * time.Millisecond)
		return laptop.Do(t, "POST", "/v1/auth/elevation/github/poll", map[string]string{"flowId": flowID})
	}
	gh.SetUser(777)
	start := laptop.Must(t, http.StatusOK, "POST", "/v1/auth/elevation/github", nil).Map(t)
	if res := poll(start["flowId"].(string)); res.Status != http.StatusForbidden || res.Map(t)["error"] != "wrong-account" {
		t.Fatalf("a different GitHub user: %s", res)
	}
	requireElevation(t, laptop, "deleting the account after a wrong GitHub user", "DELETE", "/v1/account", nil)

	gh.SetUser(4242)
	start = laptop.Must(t, http.StatusOK, "POST", "/v1/auth/elevation/github", nil).Map(t)
	res := poll(start["flowId"].(string))
	for res.Status == http.StatusAccepted {
		res = poll(start["flowId"].(string))
	}
	if res.Status != http.StatusOK {
		t.Fatalf("elevation with the owner's GitHub account: %s", res)
	}
	laptop.Must(t, http.StatusNoContent, "DELETE", "/v1/account", nil)
}

func TestInviteAccountsCannotUseGitHubElevation(t *testing.T) {
	gh := testkit.NewFakeGitHub(t, 4242)
	e := newEnv(t, "[auth]\ngithub_client_id = \"test-client\"\ngithub_base_url = \""+gh.Server.URL+"\"\ngithub_api_url = \""+gh.Server.URL+"\"\n")
	laptop := e.user(t, "laptop")
	if res := laptop.Do(t, "POST", "/v1/auth/elevation/github", nil); res.Status != http.StatusConflict {
		t.Fatalf("%s", res)
	}
}

func TestElevationRoutesRequireASession(t *testing.T) {
	e := newEnv(t, "")
	anon := e.anonymous()
	for _, route := range [][2]string{
		{"GET", "/v1/auth/elevation"}, {"POST", "/v1/auth/elevation/approval"}, {"GET", "/v1/auth/approvals"},
		{"GET", "/v1/auth/approvals/x"}, {"POST", "/v1/auth/approvals/x/approve"}, {"DELETE", "/v1/auth/approvals/x"},
	} {
		if res := anon.Do(t, route[0], route[1], nil); res.Status != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: %s", route[0], route[1], res)
		}
	}
}

func TestStolenTokenCannotTurnADeviceInviteIntoAnElevatedSession(t *testing.T) {
	e := newEnv(t, "[auth]\nsession_ttl = \"1s\"\napprover_min_age = \"2s\"\n")
	owner := e.user(t, "laptop")
	stolen := testkit.NewAPI(e.net, testkit.NewIdentity("copy of the owner"))
	stolen.ID = owner.ID
	stolen.Token = owner.Token

	code := stolen.Must(t, http.StatusCreated, "POST", "/v1/devices/invite", nil).Map(t)["code"].(string)
	attacker := testkit.NewAPI(e.net, testkit.NewIdentity("attacker"))
	attacker.Onboard(t, code)

	approval := stolen.Must(t, http.StatusCreated, "POST", "/v1/auth/elevation/approval", nil).Map(t)["approvalId"].(string)
	res := attacker.Do(t, "POST", "/v1/auth/approvals/"+approval+"/approve", nil)
	if res.Status != http.StatusForbidden || res.Map(t)["error"] != "device-too-new" {
		t.Fatalf("a device the stolen token just added approved: %s", res)
	}
	requireElevation(t, stolen, "deleting the account with a stolen token", "DELETE", "/v1/account", nil)
	requireElevation(t, stolen, "revoking the owner's device", "DELETE", "/v1/devices/"+attacker.ID.DeviceID, nil)

	time.Sleep(2300 * time.Millisecond)
	owner.SignIn(t)
	attacker.SignIn(t)
	if res := owner.Do(t, "POST", "/v1/devices/invite", nil); res.Status != http.StatusForbidden {
		t.Fatalf("with two devices an invite needs approval: %s", res)
	}
	owner.ElevateByApproval(t, attacker)
}

func TestApprovalCardsCarryTheRequestersAge(t *testing.T) {
	e := newEnv(t, "")
	laptop := e.user(t, "laptop")
	phone := e.device(t, laptop, "phone")
	laptop.Must(t, http.StatusCreated, "POST", "/v1/auth/elevation/approval", nil)
	var list struct {
		Approvals []struct {
			DeviceName      string `json:"deviceName"`
			DeviceCreatedAt int64  `json:"deviceCreatedAt"`
		} `json:"approvals"`
	}
	phone.Must(t, http.StatusOK, "GET", "/v1/auth/approvals", nil).JSON(t, &list)
	if len(list.Approvals) != 1 || list.Approvals[0].DeviceName != "laptop" || list.Approvals[0].DeviceCreatedAt == 0 {
		t.Fatalf("%+v", list.Approvals)
	}
}
