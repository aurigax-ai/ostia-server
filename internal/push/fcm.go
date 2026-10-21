package push

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
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
	fcmScope          = "https://www.googleapis.com/auth/firebase.messaging"
	fcmDefaultBase    = "https://fcm.googleapis.com"
	fcmTokenLifetime  = time.Hour
	fcmRefreshMargin  = time.Minute
	fcmMaxResponseLen = 16 << 10
)

type serviceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	ProjectID   string `json:"project_id"`
	TokenURI    string `json:"token_uri"`
}

type FCM struct {
	account  serviceAccount
	key      *rsa.PrivateKey
	endpoint string
	client   *http.Client
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func NewFCM(serviceAccountFile, endpoint string, client *http.Client, now func() time.Time) (*FCM, error) {
	raw, err := os.ReadFile(serviceAccountFile)
	if err != nil {
		return nil, err
	}
	var account serviceAccount
	if err := json.Unmarshal(raw, &account); err != nil {
		return nil, fmt.Errorf("%s: %w", serviceAccountFile, err)
	}
	if account.ClientEmail == "" || account.PrivateKey == "" || account.ProjectID == "" || account.TokenURI == "" {
		return nil, fmt.Errorf("%s: client_email, private_key, project_id and token_uri are required", serviceAccountFile)
	}
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("%s: private_key is not PEM", serviceAccountFile)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", serviceAccountFile, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: private_key is not RSA", serviceAccountFile)
	}
	if endpoint == "" {
		endpoint = fcmDefaultBase
	}
	return &FCM{account: account, key: key, endpoint: strings.TrimRight(endpoint, "/"), client: client, now: now}, nil
}

func (f *FCM) accessToken(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.token != "" && f.now().Add(fcmRefreshMargin).Before(f.expires) {
		return f.token, nil
	}
	issued := f.now()
	assertion, err := signRS256(f.key,
		map[string]string{"alg": "RS256", "typ": "JWT"},
		map[string]any{"iss": f.account.ClientEmail, "scope": fcmScope, "aud": f.account.TokenURI, "iat": issued.Unix(), "exp": issued.Add(fcmTokenLifetime).Unix()},
	)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.account.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fcm token exchange answered %d", res.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.UnmarshalRead(io.LimitReader(res.Body, fcmMaxResponseLen), &out); err != nil || out.AccessToken == "" {
		return "", errors.New("fcm token exchange returned no access token")
	}
	f.token = out.AccessToken
	f.expires = issued.Add(time.Duration(out.ExpiresIn) * time.Second)
	return f.token, nil
}

func (f *FCM) Send(ctx context.Context, platform, token string) error {
	access, err := f.accessToken(ctx)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"message": map[string]any{
		"token":   token,
		"data":    map[string]string{"v": "1"},
		"android": map[string]string{"priority": "HIGH"},
	}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint+"/v1/projects/"+f.account.ProjectID+"/messages:send", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	res, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, fcmMaxResponseLen))
	switch {
	case res.StatusCode == http.StatusOK:
		return nil
	case res.StatusCode == http.StatusNotFound || strings.Contains(string(raw), "UNREGISTERED"):
		return ErrInvalidToken
	case res.StatusCode == http.StatusUnauthorized:
		f.mu.Lock()
		f.token = ""
		f.mu.Unlock()
	}
	return fmt.Errorf("fcm answered %d", res.StatusCode)
}
