package policy

import (
	"reflect"
	"strings"
	"testing"
)

func samplePolicies() []Policy {
	return []Policy{
		{
			VaultPath: "kv/app/db",
			Clusters:  []string{"dev", "staging"},
		},
		{
			VaultPath: "kv/shared/demo",
			Clusters:  []string{"dev"},
		},
	}
}

func TestStore_LoadAndResolve(t *testing.T) {
	s := NewStore()
	if err := s.Load(samplePolicies()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := s.Size(); got != 2 {
		t.Fatalf("Size = %d, want 2", got)
	}

	got := s.Resolve("kv", "app/db")
	want := []string{"dev", "staging"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve(kv/app/db) = %+v, want %+v", got, want)
	}

	if got := s.Resolve("kv", "missing"); got != nil {
		t.Fatalf("Resolve(missing) = %+v, want nil", got)
	}
}

func TestStore_LoadValidation(t *testing.T) {
	cases := []struct {
		name      string
		policies  []Policy
		wantError string
	}{
		{
			name:      "empty vault_path",
			policies:  []Policy{{VaultPath: "", Clusters: []string{"c"}}},
			wantError: "vault_path is required",
		},
		{
			name:      "no clusters",
			policies:  []Policy{{VaultPath: "kv/app/db"}},
			wantError: "clusters must be non-empty",
		},
		{
			name: "empty cluster name",
			policies: []Policy{{
				VaultPath: "kv/app/db",
				Clusters:  []string{""},
			}},
			wantError: "cluster name is required",
		},
		{
			name: "duplicate vault_path",
			policies: []Policy{
				{VaultPath: "kv/app/db", Clusters: []string{"c"}},
				{VaultPath: "kv/app/db", Clusters: []string{"c2"}},
			},
			wantError: "duplicate vault_path",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			err := s.Load(tc.policies)
			if err == nil {
				t.Fatalf("Load: want error containing %q, got nil", tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Load error %q, want substring %q", err, tc.wantError)
			}
		})
	}
}

func TestStore_LoadAtomicReplace(t *testing.T) {
	s := NewStore()
	if err := s.Load(samplePolicies()); err != nil {
		t.Fatalf("Load 1: %v", err)
	}

	next := []Policy{{
		VaultPath: "kv/new/key",
		Clusters:  []string{"dev"},
	}}
	if err := s.Load(next); err != nil {
		t.Fatalf("Load 2: %v", err)
	}

	if got := s.Size(); got != 1 {
		t.Fatalf("Size after replace = %d, want 1", got)
	}
	if got := s.Resolve("kv", "app/db"); got != nil {
		t.Fatalf("old key still resolvable: %+v", got)
	}
	if got := s.Resolve("kv", "new/key"); len(got) != 1 {
		t.Fatalf("new key not resolvable: %+v", got)
	}
}

func TestStore_LoadInvalidNoMutation(t *testing.T) {
	s := NewStore()
	if err := s.Load(samplePolicies()); err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	sizeBefore := s.Size()

	bad := []Policy{{VaultPath: "", Clusters: []string{"c"}}}
	if err := s.Load(bad); err == nil {
		t.Fatal("Load: want error, got nil")
	}
	if s.Size() != sizeBefore {
		t.Fatalf("store mutated on validation error: size %d -> %d", sizeBefore, s.Size())
	}
	if got := s.Resolve("kv", "app/db"); len(got) != 2 {
		t.Fatalf("original data lost after failed Load: %+v", got)
	}
}

func TestStore_WildcardResolve(t *testing.T) {
	s := NewStore()
	policies := []Policy{
		{
			VaultPath: "secret/shared/*",
			Clusters:  []string{"cluster_a", "cluster_b"},
		},
		{
			// More specific wildcard — should win over secret/shared/*.
			VaultPath: "secret/shared/team-a/*",
			Clusters:  []string{"cluster_a"},
		},
		{
			// Exact match must beat any wildcard.
			VaultPath: "secret/shared/jwt-key",
			Clusters:  []string{"cluster_auth"},
		},
	}
	if err := s.Load(policies); err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		name        string
		mount, path string
		want        []string
	}{
		{
			name:  "exact wins over wildcard",
			mount: "secret", path: "shared/jwt-key",
			want: []string{"cluster_auth"},
		},
		{
			name:  "longest prefix wins",
			mount: "secret", path: "shared/team-a/db",
			want: []string{"cluster_a"},
		},
		{
			name:  "shorter prefix matches deep paths",
			mount: "secret", path: "shared/team-b/db",
			want: []string{"cluster_a", "cluster_b"},
		},
		{
			name:  "wildcard does not match the prefix itself without slash",
			mount: "secret", path: "shared",
			want: nil,
		},
		{
			name:  "no match outside any wildcard",
			mount: "secret", path: "cluster_a/db",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Resolve(tc.mount, tc.path)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Resolve(%s/%s) = %+v, want %+v", tc.mount, tc.path, got, tc.want)
			}
		})
	}
}

func TestStore_WildcardValidation(t *testing.T) {
	cases := []struct {
		name      string
		vaultPath string
		wantError string
	}{
		{"bare star", "*", "trailing '/*'"},
		{"leading star", "*/db", "trailing '/*'"},
		{"middle star", "secret/*/db", "trailing '/*'"},
		{"trailing star without slash", "secret/api*", "trailing '/*'"},
		{"multiple stars", "secret/*/foo/*", "multiple '*'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			err := s.Load([]Policy{{
				VaultPath: tc.vaultPath,
				Clusters:  []string{"c"},
			}})
			if err == nil {
				t.Fatalf("Load(%q): want error containing %q, got nil", tc.vaultPath, tc.wantError)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Load(%q) error %q, want substring %q", tc.vaultPath, err, tc.wantError)
			}
		})
	}
}

func TestStore_WildcardDuplicate(t *testing.T) {
	s := NewStore()
	err := s.Load([]Policy{
		{VaultPath: "secret/shared/*", Clusters: []string{"a"}},
		{VaultPath: "secret/shared/*", Clusters: []string{"b"}},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("Load: want duplicate error, got %v", err)
	}
}

func TestStore_List(t *testing.T) {
	s := NewStore()
	if err := s.Load(samplePolicies()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	list := s.List()
	want := []Summary{
		{Mount: "kv", Path: "app/db", ClusterCount: 2},
		{Mount: "kv", Path: "shared/demo", ClusterCount: 1},
	}
	if !reflect.DeepEqual(list, want) {
		t.Fatalf("List = %+v, want %+v", list, want)
	}
}
