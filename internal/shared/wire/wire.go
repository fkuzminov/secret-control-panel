// Package wire defines the shared contract between the panel and
// cluster agents: event types, registration/callback payloads, and
// HTTP endpoint/header constants.
//
// Single source of truth for both services: a change here is visible
// to the panel and the agent at compile time.
package wire

import "time"

// Operation is the kind of secret change observed in a Vault audit
// record.
type Operation string

// Operations the panel reacts to. The audit parser filters out reads, list, metadata, etc..
const (
	Create Operation = "create"
	Update Operation = "update"
	Patch  Operation = "patch"
	Delete Operation = "delete"
)

// SecretEvent is a normalized Vault audit record stripped to the
// fields the panel actually uses; it is also the JSON body the panel
// POSTs to an agent.
type SecretEvent struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id"`
	Operation Operation `json:"operation"`
	Mount     string    `json:"mount"`
	Path      string    `json:"path"`
	Version   int       `json:"version"`
}

// Registration is the payload an agent POSTs to the panel on startup
// to announce itself. The panel stores it in the database and wires up
// an HTTP sink for the cluster.
type Registration struct {
	Cluster string `json:"cluster"`
	URL     string `json:"url"`
	Token   string `json:"token"`
}

// Callback is the payload an agent POSTs to the panel after it has
// confirmed that ESO reconciled the affected ExternalSecrets.
type Callback struct {
	RequestID string `json:"request_id"`
	Cluster   string `json:"cluster"`
	Synced    bool   `json:"synced"`
	Matched   int    `json:"matched"`
	Patched   int    `json:"patched"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

// HTTP contract between the panel and the agents.
const (
	// EventsPath is the agent endpoint that accepts enriched events.
	EventsPath = "/api/v1/events"
	// HealthPath is the agent's liveness/readiness probe endpoint.
	HealthPath = "/api/v1/healthz"

	// AgentRegisterPath is the panel endpoint agents POST to on startup.
	AgentRegisterPath = "/api/v1/agents/register"
	// CallbackPath is the panel endpoint agents POST callbacks to.
	CallbackPath = "/api/v1/callbacks"

	// AuthHeader is the request header that carries the bearer token.
	AuthHeader = "Authorization"
	// AuthScheme is the scheme prefix for AuthHeader values; the token
	// is appended verbatim.
	AuthScheme = "Bearer "
)
