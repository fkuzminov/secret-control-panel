// Package patcher describes how the agent acts on an event from the
// panel: the Patcher interface and its implementations (log-only and
// the real K8s-API-backed one).
package patcher

import "context"

// Job is the patcher's local view of an event from the panel: a
// single vault path plus the operation and version. The patcher
// discovers the ExternalSecret resources to touch by listing them
// cluster-wide and matching the SelectorAnnotation.
type Job struct {
	VaultPath string
	Operation string
	Version   int
}

// Result reports how much the patcher actually did for a Job.
type Result struct {
	Matched int // ExternalSecret resources matched by the selector
	Patched int // successfully patched (Matched minus errors)
}

// Patcher applies a Job to the cluster.
type Patcher interface {
	Patch(ctx context.Context, job Job) (Result, error)
}
