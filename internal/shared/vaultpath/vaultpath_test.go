package vaultpath

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"secret/cluster_a/db":   "secret/cluster_a/db",
		"/secret/cluster_a/db":  "secret/cluster_a/db",
		"/secret/cluster_a/db/": "secret/cluster_a/db",
		"":                      "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJoin(t *testing.T) {
	cases := []struct {
		mount, path, want string
	}{
		{"kv", "app/db", "kv/app/db"},
		{"kv/", "/app/db", "kv/app/db"},
		{"/kv/", "app/db/", "kv/app/db"},
		{"", "app/db", "app/db"},
		{"kv", "", "kv"},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := Join(c.mount, c.path); got != c.want {
			t.Errorf("Join(%q, %q) = %q, want %q", c.mount, c.path, got, c.want)
		}
	}
}

func TestSplit(t *testing.T) {
	cases := []struct {
		in, mount, path string
	}{
		{"kv/app/db", "kv", "app/db"},
		{"/kv/app/db/", "kv", "app/db"},
		{"kv", "kv", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		m, p := Split(c.in)
		if m != c.mount || p != c.path {
			t.Errorf("Split(%q) = (%q,%q), want (%q,%q)", c.in, m, p, c.mount, c.path)
		}
	}
}
