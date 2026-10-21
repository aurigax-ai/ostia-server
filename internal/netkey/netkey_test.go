package netkey

import "testing"

func TestOf(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9":                      "203.0.113.9",
		"::ffff:203.0.113.9":               "203.0.113.9",
		"2001:db8:1:2:aaaa:bbbb:cccc:dddd": "2001:db8:1:2::/64",
		"2001:db8:1:2:1111:2222:3333:4444": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":                  "2001:db8:1:3::/64",
		"not-an-ip":                        "not-an-ip",
	}
	for in, want := range cases {
		if got := Of(in); got != want {
			t.Errorf("Of(%q) = %q, want %q", in, got, want)
		}
	}
}
