package publish

import "testing"

func TestURLsCarryThePublicPortOnlyWhenItIsNotTheDefault(t *testing.T) {
	cases := []struct {
		scheme string
		port   int
		share  string
		upload string
	}{
		{"https", 443, "https://api.test/s/abc", "https://api.test/v1/shares/abc/blob"},
		{"https", 8443, "https://api.test:8443/s/abc", "https://api.test:8443/v1/shares/abc/blob"},
		{"http", 80, "http://api.test/s/abc", "http://api.test/v1/shares/abc/blob"},
		{"http", 8080, "http://api.test:8080/s/abc", "http://api.test:8080/v1/shares/abc/blob"},
	}
	for _, c := range cases {
		s := &Service{APIDomain: "api.test", Scheme: c.scheme, Port: c.port}
		if got := s.shareURL("abc"); got != c.share {
			t.Errorf("%s %d: share URL %s", c.scheme, c.port, got)
		}
		if got := s.uploadURL("abc"); got != c.upload {
			t.Errorf("%s %d: upload URL %s", c.scheme, c.port, got)
		}
	}
}
