// Package policy stores the mapping vault_path → []cluster and
// resolves audit events into the list of clusters that should receive
// them. The agent in each target cluster decides which ExternalSecret
// resources are bound to the path (via the scp.vault/path annotation),
// so the policy carries no namespace information.
//
// vault_path may be either an exact key ("secret/shared/jwt-key") or
// a prefix wildcard of the form "<prefix>/*" ("secret/shared/*"
// matches every key under "secret/shared/" at any depth). On resolve
// an exact match always wins over wildcards; among wildcards the
// longest prefix wins.
package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"secret-control-panel/internal/shared/vaultpath"
)

// wildcardSuffix is the only wildcard form supported in vault_path:
// "<prefix>/*" matches every key starting with "<prefix>/".
const wildcardSuffix = "/*"

// Policy is one routing rule: a Vault KV path and the clusters it
// should be delivered to.
type Policy struct {
	VaultPath string   `yaml:"vault_path" json:"vault_path"`
	Clusters  []string `yaml:"clusters"   json:"clusters"`
}

// Summary is a short, log-friendly view of a stored Policy.
type Summary struct {
	Mount        string
	Path         string
	ClusterCount int
	Wildcard     bool
}

// prefixRule is the in-memory form of a "<prefix>/*" wildcard policy.
type prefixRule struct {
	prefix   string // normalised, includes trailing "/"; e.g. "secret/shared/"
	raw      string // original vault_path for diagnostics
	clusters []string
}

// Store is a concurrent in-memory policy index. Exact-match rules live
// in byKey; wildcard rules live in prefixes, sorted longest-first so
// Resolve can early-return on the first match.
type Store struct {
	mu       sync.RWMutex
	byKey    map[string][]string
	prefixes []prefixRule
}

// NewStore returns an empty Store ready for Load.
func NewStore() *Store {
	return &Store{byKey: map[string][]string{}}
}

// Load atomically replaces the policy set. It validates each entry
// (non-empty path, non-empty clusters, supported wildcard syntax, no
// duplicate paths) and rejects the whole batch if any rule is
// invalid — the existing state is left untouched on error.
func (s *Store) Load(policies []Policy) error {
	nextExact := make(map[string][]string, len(policies))
	var nextPrefixes []prefixRule
	seenPrefix := map[string]struct{}{}

	for i, p := range policies {
		if p.VaultPath == "" {
			return fmt.Errorf("policy[%d]: vault_path is required", i)
		}
		if len(p.Clusters) == 0 {
			return fmt.Errorf("policy[%d] (%s): clusters must be non-empty", i, p.VaultPath)
		}
		for j, c := range p.Clusters {
			if c == "" {
				return fmt.Errorf("policy[%d] (%s) clusters[%d]: cluster name is required",
					i, p.VaultPath, j)
			}
		}

		normalized := vaultpath.Normalize(p.VaultPath)
		prefix, err := parseWildcard(normalized)
		if err != nil {
			return fmt.Errorf("policy[%d] (%s): %w", i, p.VaultPath, err)
		}

		if prefix != "" {
			if _, dup := seenPrefix[prefix]; dup {
				return fmt.Errorf("policy[%d]: duplicate vault_path %q", i, p.VaultPath)
			}
			seenPrefix[prefix] = struct{}{}
			nextPrefixes = append(nextPrefixes, prefixRule{
				prefix:   prefix,
				raw:      p.VaultPath,
				clusters: slices.Clone(p.Clusters),
			})
			continue
		}

		if _, dup := nextExact[normalized]; dup {
			return fmt.Errorf("policy[%d]: duplicate vault_path %q", i, p.VaultPath)
		}
		nextExact[normalized] = slices.Clone(p.Clusters)
	}

	sort.Slice(nextPrefixes, func(i, j int) bool {
		return len(nextPrefixes[i].prefix) > len(nextPrefixes[j].prefix)
	})

	s.mu.Lock()
	s.byKey = nextExact
	s.prefixes = nextPrefixes
	s.mu.Unlock()
	return nil
}

// parseWildcard returns the prefix part of a "<prefix>/*" wildcard
// vault_path (with the trailing "/" kept). For an exact key it returns
// an empty prefix and no error. Unsupported wildcard forms (bare "*",
// embedded "*", multiple "*", trailing "*" without "/") yield an
// error.
func parseWildcard(vaultPath string) (string, error) {
	stars := strings.Count(vaultPath, "*")
	if stars == 0 {
		return "", nil
	}
	if stars > 1 {
		return "", fmt.Errorf("multiple '*' not supported in vault_path")
	}
	if !strings.HasSuffix(vaultPath, wildcardSuffix) {
		return "", fmt.Errorf("'*' is only supported as trailing '/*'")
	}
	return strings.TrimSuffix(vaultPath, "*"), nil
}

// Resolve returns the clusters registered for (mount, path). Exact
// matches win over wildcards; among wildcards, the longest prefix
// wins. Returns nil when nothing matches.
func (s *Store) Resolve(mount, path string) []string {
	key := vaultpath.Join(mount, path)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if c, ok := s.byKey[key]; ok {
		return slices.Clone(c)
	}
	for _, r := range s.prefixes {
		if strings.HasPrefix(key, r.prefix) {
			return slices.Clone(r.clusters)
		}
	}
	return nil
}

// Size returns the total number of stored policies (exact + wildcard).
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey) + len(s.prefixes)
}

// List returns every policy as a Summary, sorted by mount then path.
// Convenient for startup diagnostics.
func (s *Store) List() []Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Summary, 0, len(s.byKey)+len(s.prefixes))
	for k, clusters := range s.byKey {
		mount, path := vaultpath.Split(k)
		out = append(out, Summary{
			Mount:        mount,
			Path:         path,
			ClusterCount: len(clusters),
		})
	}
	for _, r := range s.prefixes {
		mount, path := vaultpath.Split(r.raw)
		out = append(out, Summary{
			Mount:        mount,
			Path:         path,
			ClusterCount: len(r.clusters),
			Wildcard:     true,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Mount != out[j].Mount {
			return out[i].Mount < out[j].Mount
		}
		return out[i].Path < out[j].Path
	})
	return out
}
