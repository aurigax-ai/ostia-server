package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	apnsProduction  = "https://api.push.apple.com"
	apnsSandbox     = "https://api.sandbox.push.apple.com"
	apnsJWTLifetime = 40 * time.Minute
	apnsAlertKey    = "DESKTOP_NEEDS_YOU"
)

type APNs struct {
	key      *ecdsa.PrivateKey
	keyID    string
	teamID   string
	topic    string
	endpoint string
	client   *http.Client
	now      func() time.Time

	mu     sync.Mutex
	jwt    string
	issued time.Time
}

func NewAPNs(keyFile, keyID, teamID, topic string, production bool, endpoint string, client *http.Client, now func() time.Time) (*APNs, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", keyFile)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", keyFile)
	}
	if keyID == "" || teamID == "" || topic == "" {
		return nil, fmt.Errorf("apns key_id, team_id and topic are required")
	}
	if endpoint == "" {
		endpoint = apnsSandbox
		if production {
			endpoint = apnsProduction
		}
	}
	return &APNs{key: key, keyID: keyID, teamID: teamID, topic: topic, endpoint: strings.TrimRight(endpoint, "/"), client: client, now: now}, nil
}

func (a *APNs) bearer() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.jwt != "" && a.now().Sub(a.issued) < apnsJWTLifetime {
		return a.jwt, nil
	}
	issued := a.now()
	token, err := signES256(a.key,
		map[string]string{"alg": "ES256", "kid": a.keyID},
		map[string]any{"iss": a.teamID, "iat": issued.Unix()},
	)
	if err != nil {
		return "", err
	}
	a.jwt, a.issued = token, issued
	return token, nil
}

func (a *APNs) Send(ctx context.Context, platform, token string) error {
	bearer, err := a.bearer()
	if err != nil {
		return err
	}
	payload := `{"aps":{"alert":{"loc-key":"` + apnsAlertKey + `"},"mutable-content":1}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/3/device/"+url.PathEscape(token), strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "bearer "+bearer)
	req.Header.Set("apns-topic", a.topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, fcmMaxResponseLen))
	switch {
	case res.StatusCode == http.StatusOK:
		return nil
	case res.StatusCode == http.StatusGone || strings.Contains(string(raw), "BadDeviceToken") || strings.Contains(string(raw), "Unregistered"):
		return ErrInvalidToken
	case res.StatusCode == http.StatusForbidden && strings.Contains(string(raw), "ExpiredProviderToken"):
		a.mu.Lock()
		a.jwt = ""
		a.mu.Unlock()
	}
	return fmt.Errorf("apns answered %d", res.StatusCode)
}
