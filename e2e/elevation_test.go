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
	if res := phone.Do(t, "DELETE", "/v1/auth/approvals/"+id, nil); res.Status != http.StatusNotFound {
		t.Fatalf("only the requesting device may cancel its request: %s", res)
	}
	laptop.Must(t, http.StatusNoContent, "DELETE", "/v1/auth/approvals/"+id, nil)
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

func stolenCopy(e *env, owner *testkit.API) *testkit.API {
	stolen := testkit.NewAPI(e.net, &testkit.Identity{Name: "copy of the owner", DeviceID: owner.ID.DeviceID, AccountID: owner.ID.AccountID})
	stolen.Token = owner.Token
	stolen.Unsigned = true
	return stolen
}

func requireSignature(t *testing.T, api *testkit.API, what, method, path string, body any) {
	t.Helper()
	res := api.Do(t, method, path, body)
	if res.Status != http.StatusForbidden || res.Map(t)["error"] != "device-signature-required" {
		t.Errorf("%s without the device key was not refused: %s", what, res)
	}
}

func TestSessionTokenAloneCannotAddRemoveOrApproveDevices(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "laptop")
	phone := e.device(t, owner, "phone")
	stolen := stolenCopy(e, owner)

	requireSignature(t, stolen, "minting an invite", "POST", "/v1/devices/invite", nil)
	requireSignature(t, stolen, "revoking a device", "DELETE", "/v1/devices/"+phone.ID.DeviceID, nil)
	requireSignature(t, stolen, "revoking itself", "DELETE", "/v1/devices/"+owner.ID.DeviceID, nil)

	approval := phone.Must(t, http.StatusCreated, "POST", "/v1/auth/elevation/approval", nil).Map(t)["approvalId"].(string)
	requireSignature(t, stolen, "approving a request", "POST", "/v1/auth/approvals/"+approval+"/approve", nil)
	if phone.Elevated(t) {
		t.Fatal("the stolen token elevated another session")
	}
	owner.Must(t, http.StatusNoContent, "POST", "/v1/auth/approvals/"+approval+"/approve", nil)

	wrong := testkit.NewAPI(e.net, testkit.NewIdentity("wrong key"))
	wrong.ID.DeviceID, wrong.ID.AccountID = owner.ID.DeviceID, owner.ID.AccountID
	wrong.Token = owner.Token
	res := wrong.Do(t, "POST", "/v1/devices/invite", nil)
	if res.Status != http.StatusForbidden || res.Map(t)["error"] != "bad-signature" {
		t.Fatalf("a signature from another key: %s", res)
	}
}

func TestStolenTokenCannotElevateItselfThroughADeviceItAdded(t *testing.T) {
	e := newEnv(t, "[auth]\nsession_ttl = \"1s\"\napprover_min_age = \"2s\"\n")
	owner := e.user(t, "laptop")
	e.waitUntilOlderThan(t, owner, 2*time.Second)
	owner.SignIn(t)

	code := owner.Must(t, http.StatusCreated, "POST", "/v1/devices/invite", nil).Map(t)["code"].(string)
	attacker := testkit.NewAPI(e.net, testkit.NewIdentity("attacker"))
	attacker.Onboard(t, code)

	approval := attacker.Must(t, http.StatusCreated, "POST", "/v1/auth/elevation/approval", nil).Map(t)["approvalId"].(string)
	res := owner.Do(t, "POST", "/v1/auth/approvals/"+approval+"/approve", nil)
	if res.Status != http.StatusForbidden || res.Map(t)["error"] != "requester-too-new" {
		t.Fatalf("an approval for a device that has just joined must be refused even from an established device: %s", res)
	}
	requireElevation(t, attacker, "deleting the account with the new device", "DELETE", "/v1/account", nil)

	e.waitUntilOlderThan(t, attacker, 2*time.Second)
	attacker.SignIn(t)
	owner.SignIn(t)
	approval = attacker.Must(t, http.StatusCreated, "POST", "/v1/auth/elevation/approval", nil).Map(t)["approvalId"].(string)
	owner.Must(t, http.StatusNoContent, "POST", "/v1/auth/approvals/"+approval+"/approve", nil)
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

func TestTwoInvitesCannotBeMintedWithoutApprovalAndStaleOnesDie(t *testing.T) {
	e := newEnv(t, "[auth]\napprover_min_age = \"24h\"\n")
	owner := e.user(t, "laptop")
	first := owner.Must(t, http.StatusCreated, "POST", "/v1/devices/invite", nil).Map(t)["code"].(string)
	requireElevation(t, owner, "a second live invite", "POST", "/v1/devices/invite", nil)

	one := testkit.NewAPI(e.net, testkit.NewIdentity("first extra"))
	one.Onboard(t, first)
	requireElevation(t, owner, "a third device", "POST", "/v1/devices/invite", nil)
}

func TestAnOlderDeviceRemovesAYoungerOneOnProbationEvenWhenItIsNotEstablished(t *testing.T) {
	e := newEnv(t, "[auth]\napprover_min_age = \"24h\"\n")
	owner := e.user(t, "laptop")
	code := owner.Must(t, http.StatusCreated, "POST", "/v1/devices/invite", nil).Map(t)["code"].(string)
	intruder := testkit.NewAPI(e.net, testkit.NewIdentity("intruder"))
	intruder.Onboard(t, code)
	requireElevation(t, intruder, "the younger device revoking the older", "DELETE", "/v1/devices/"+owner.ID.DeviceID, nil)
	owner.Must(t, http.StatusNoContent, "DELETE", "/v1/devices/"+intruder.ID.DeviceID, nil)
}

func TestOwnerCanRemoveAnIntruderDuringItsProbation(t *testing.T) {
	e := newEnv(t, "[auth]\nsession_ttl = \"1s\"\napprover_min_age = \"2s\"\n")
	owner := e.user(t, "laptop")
	e.waitUntilOlderThan(t, owner, 2*time.Second)
	owner.SignIn(t)
	code := owner.Must(t, http.StatusCreated, "POST", "/v1/devices/invite", nil).Map(t)["code"].(string)
	intruder := testkit.NewAPI(e.net, testkit.NewIdentity("intruder"))
	intruder.Onboard(t, code)

	requireElevation(t, intruder, "the intruder revoking the owner's device", "DELETE", "/v1/devices/"+owner.ID.DeviceID, nil)
	owner.Must(t, http.StatusNoContent, "DELETE", "/v1/devices/"+intruder.ID.DeviceID, nil)
	if res := intruder.Do(t, "GET", "/v1/devices", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("the intruder kept its session: %s", res)
	}
}

func TestDesktopListenerIsToldWhenAnotherDeviceJoins(t *testing.T) {
	f := newRelayFixture(t, "")
	code := f.api.Must(t, http.StatusCreated, "POST", "/v1/devices/invite", nil).Map(t)["code"].(string)
	joiner := testkit.NewAPI(f.env.net, testkit.NewIdentity("new phone"))
	joiner.Onboard(t, code)
	waitUntil(t, "the desktop is told about the new device", func() bool {
		added := f.desktop.AddedDevices()
		return len(added) == 1 && added[0] == "new phone"
	})
	var list struct {
		Devices []map[string]any `json:"devices"`
	}
	f.api.Must(t, http.StatusOK, "GET", "/v1/devices", nil).JSON(t, &list)
	for _, d := range list.Devices {
		if _, flagged := d["new"]; flagged {
			t.Fatalf("the new flag is gone: %+v", d)
		}
	}
	if res := f.api.Do(t, "POST", "/v1/devices/"+joiner.ID.DeviceID+"/seen", nil); res.Status != http.StatusNotFound && res.Status != http.StatusMethodNotAllowed {
		t.Fatalf("the seen route is gone: %s", res)
	}
}

func TestADeviceLeavesWithoutElevationButNeedsItsOwnSignature(t *testing.T) {
	for _, extra := range []string{"", "[auth]\napprover_min_age = \"24h\"\n"} {
		e := newEnv(t, extra)
		owner := e.user(t, "laptop")
		stolen := stolenCopy(e, owner)
		requireSignature(t, stolen, "leaving with a bare token", "DELETE", "/v1/devices/"+owner.ID.DeviceID, nil)
		owner.Must(t, http.StatusNoContent, "DELETE", "/v1/devices/"+owner.ID.DeviceID, nil)
		if res := owner.Do(t, "GET", "/v1/devices", nil); res.Status != http.StatusUnauthorized {
			t.Fatalf("a device that left must lose its session: %s", res)
		}
	}
}

func TestSessionTokenAloneCannotRequestAnElevation(t *testing.T) {
	e := newEnv(t, "")
	owner := e.user(t, "laptop")
	e.device(t, owner, "phone")
	stolen := stolenCopy(e, owner)
	requireSignature(t, stolen, "asking the owner's other devices to approve", "POST", "/v1/auth/elevation/approval", nil)
	wrong := testkit.NewAPI(e.net, testkit.NewIdentity("wrong key"))
	wrong.ID.DeviceID, wrong.ID.AccountID = owner.ID.DeviceID, owner.ID.AccountID
	wrong.Token = owner.Token
	for name, call := range map[string][2]string{
		"an elevation request": {"POST", "/v1/auth/elevation/approval"},
		"a revoke":             {"DELETE", "/v1/devices/" + owner.ID.DeviceID},
	} {
		res := wrong.Do(t, call[0], call[1], nil)
		if res.Status != http.StatusForbidden || res.Map(t)["error"] != "bad-signature" {
			t.Errorf("%s signed with another key: %s", name, res)
		}
	}
	phoneApproval := owner.Must(t, http.StatusCreated, "POST", "/v1/auth/elevation/approval", nil).Map(t)["approvalId"].(string)
	res := wrong.Do(t, "POST", "/v1/auth/approvals/"+phoneApproval+"/approve", nil)
	if res.Status != http.StatusForbidden {
		t.Errorf("an approval signed with another key: %s", res)
	}
}
