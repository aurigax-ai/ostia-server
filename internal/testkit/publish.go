package testkit

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
)

type Share struct {
	ID          string
	URL         string
	DeleteToken string
	Mode        string
	Key         []byte
	Password    string
	Salt        []byte
	HTML        string
	ExpiresAt   int64
}

type ShareOptions struct {
	Mode             string
	Password         string
	HTML             string
	ExpiresInSeconds *int64
	WithFragmentKey  bool
}

func (a *API) PublishHTML(t testing.TB, o ShareOptions) Share {
	t.Helper()
	if o.Mode == "" {
		o.Mode = "link"
	}
	sh := Share{Mode: o.Mode, Password: o.Password, HTML: o.HTML}
	var payload []byte
	body := map[string]any{"mode": o.Mode}
	if o.ExpiresInSeconds != nil {
		body["expiresInSeconds"] = *o.ExpiresInSeconds
	}
	switch o.Mode {
	case "link":
		sh.Key = RandomBytes(ShareKeyBytes)
	case "password":
		sh.Salt = RandomBytes(ShareSaltBytes)
		body["salt"] = EncodeB64(sh.Salt)
		if o.WithFragmentKey {
			sh.Key = RandomBytes(ShareKeyBytes)
		}
	}
	size := int64(len(o.HTML))
	if o.Mode != "public" {
		size += 1 + 12 + 16
	}
	body["size"] = size
	res := a.Must(t, http.StatusCreated, "POST", "/v1/shares", body)
	m := res.Map(t)
	sh.ID, sh.URL, sh.DeleteToken = m["id"].(string), m["url"].(string), m["deleteToken"].(string)
	sh.ExpiresAt = int64(m["expiresAt"].(float64))
	if o.Mode == "public" {
		payload = []byte(o.HTML)
	} else {
		key, err := DeriveShareKey(o.Mode, o.Password, sh.Salt, sh.Key)
		if err != nil {
			t.Fatal(err)
		}
		payload = EncryptShare(sh.ID, key, []byte(o.HTML), nil)
	}
	if res := a.UploadShare(t, sh.ID, payload); res.Status != http.StatusNoContent {
		t.Fatalf("upload: %s", res)
	}
	return sh
}

func (a *API) UploadShare(t testing.TB, id string, payload []byte) Response {
	t.Helper()
	res, err := a.Raw("PUT", "/v1/shares/"+id+"/blob", map[string]string{"Content-Type": "application/octet-stream"}, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (n Net) ShareGet(t testing.TB, shareDomain, id, path string, headers ...string) Response {
	t.Helper()
	req, err := http.NewRequest("GET", n.scheme()+"://"+id+"."+shareDomain+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := n.Client().Do(req)
	if err != nil {
		t.Fatalf("share GET %s: %v", path, err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return Response{Status: res.StatusCode, Header: res.Header, Body: data}
}

func (n Net) SharePost(t testing.TB, shareDomain, id, path string, body any) Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", n.scheme()+"://"+id+"."+shareDomain+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := n.Client().Do(req)
	if err != nil {
		t.Fatalf("share POST %s: %v", path, err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return Response{Status: res.StatusCode, Header: res.Header, Body: data}
}

var ErrShareUnavailable = errors.New("share unavailable")

func (n Net) OpenShare(t testing.TB, shareDomain string, sh Share) (string, error) {
	t.Helper()
	if sh.Mode == "public" {
		res := n.ShareGet(t, shareDomain, sh.ID, "/")
		if res.Status != http.StatusOK {
			return "", fmt.Errorf("%w: %d", ErrShareUnavailable, res.Status)
		}
		return string(res.Body), nil
	}
	meta := n.ShareGet(t, shareDomain, sh.ID, "/meta")
	if meta.Status != http.StatusOK {
		return "", fmt.Errorf("%w: %d", ErrShareUnavailable, meta.Status)
	}
	m := meta.Map(t)
	var salt []byte
	if s, _ := m["salt"].(string); s != "" {
		salt, _ = DecodeB64(s)
	}
	blob := n.ShareGet(t, shareDomain, sh.ID, "/blob")
	if blob.Status != http.StatusOK {
		return "", fmt.Errorf("%w: %d", ErrShareUnavailable, blob.Status)
	}
	key, err := DeriveShareKey(m["mode"].(string), sh.Password, salt, sh.Key)
	if err != nil {
		return "", err
	}
	plain, err := DecryptShare(sh.ID, key, blob.Body)
	return string(plain), err
}
