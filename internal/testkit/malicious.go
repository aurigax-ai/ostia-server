package testkit

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
)

type ReplayTransport struct {
	Base http.RoundTripper

	mu       sync.Mutex
	recorded []recordedManifest
	replay   int
}

type recordedManifest struct {
	status int
	body   []byte
}

func NewReplayTransport(base http.RoundTripper) *ReplayTransport {
	return &ReplayTransport{Base: base, replay: -1}
}

func (r *ReplayTransport) ServeRecorded(index int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replay = index
}

func (r *ReplayTransport) Recorded() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.recorded)
}

func isManifestRead(req *http.Request) bool {
	return req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/v1/sync/manifest")
}

func (r *ReplayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !isManifestRead(req) {
		return r.Base.RoundTrip(req)
	}
	r.mu.Lock()
	replay := r.replay
	var old recordedManifest
	if replay >= 0 && replay < len(r.recorded) {
		old = r.recorded[replay]
	}
	r.mu.Unlock()
	if replay >= 0 {
		return &http.Response{
			Status:     http.StatusText(old.status),
			StatusCode: old.status,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(old.body)),
			Request:    req,
		}, nil
	}
	res, err := r.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	r.mu.Lock()
	if res.StatusCode == http.StatusOK {
		r.recorded = append(r.recorded, recordedManifest{status: res.StatusCode, body: body})
	}
	r.mu.Unlock()
	res.Body = io.NopCloser(bytes.NewReader(body))
	return res, nil
}
