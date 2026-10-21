package push

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aurigax-ai/ostia-server/internal/testkit"
)

func TestDeliveryErrorsNeverContainTheDeviceToken(t *testing.T) {
	fake := testkit.NewFakePush(t)
	account, p8 := fake.WriteCredentials(t, t.TempDir())
	now := func() time.Time { return time.Now() }
	const token = "device-token-that-must-not-leak-abc123"

	apns, err := NewAPNs(p8, testkit.APNsKeyID, testkit.APNsTeamID, testkit.APNsTopic, false, "http://127.0.0.1:1", http.DefaultClient, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := apns.Send(context.Background(), PlatformAPNs, token); err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("APNs error: %v", err)
	}

	fcm, err := NewFCM(account, "http://127.0.0.1:1", http.DefaultClient, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fcm.Send(context.Background(), PlatformFCM, token); err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("FCM error: %v", err)
	}
}
