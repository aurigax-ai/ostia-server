package auth

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type GitHub struct {
	ClientID string
	BaseURL  string
	APIURL   string
	Client   *http.Client
}

type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type PollResult int

const (
	PollPending PollResult = iota
	PollSlowDown
	PollDone
	PollExpired
	PollDenied
)

var errGitHub = errors.New("github request failed")

func (g GitHub) post(ctx context.Context, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(g.BaseURL, "/")+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := g.Client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errGitHub, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", errGitHub, res.StatusCode)
	}
	return json.UnmarshalRead(res.Body, out)
}

func (g GitHub) Start(ctx context.Context) (DeviceCode, error) {
	var out DeviceCode
	err := g.post(ctx, "/login/device/code", url.Values{"client_id": {g.ClientID}}, &out)
	if err == nil && (out.DeviceCode == "" || out.UserCode == "") {
		err = fmt.Errorf("%w: incomplete device code", errGitHub)
	}
	return out, err
}

func (g GitHub) Poll(ctx context.Context, deviceCode string) (token string, result PollResult, err error) {
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	err = g.post(ctx, "/login/oauth/access_token", url.Values{
		"client_id":   {g.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}, &out)
	if err != nil {
		return "", PollPending, err
	}
	switch {
	case out.AccessToken != "":
		return out.AccessToken, PollDone, nil
	case out.Error == "authorization_pending":
		return "", PollPending, nil
	case out.Error == "slow_down":
		return "", PollSlowDown, nil
	case out.Error == "expired_token":
		return "", PollExpired, nil
	case out.Error == "access_denied":
		return "", PollDenied, nil
	}
	return "", PollPending, fmt.Errorf("%w: %s", errGitHub, out.Error)
}

func (g GitHub) UserID(ctx context.Context, token string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(g.APIURL, "/")+"/user", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := g.Client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errGitHub, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%w: user status %d", errGitHub, res.StatusCode)
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.UnmarshalRead(res.Body, &out); err != nil {
		return 0, err
	}
	if out.ID == 0 {
		return 0, fmt.Errorf("%w: no user id", errGitHub)
	}
	return out.ID, nil
}

func pollInterval(seconds int) time.Duration {
	return time.Duration(max(seconds, 1)) * time.Second
}
