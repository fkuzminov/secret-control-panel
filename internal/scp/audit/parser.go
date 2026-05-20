package audit

import (
	"encoding/json"
	"strings"
	"time"

	"secret-control-panel/internal/shared/wire"
)

type rawEntry struct {
	Type     string   `json:"type"`
	Time     string   `json:"time"`
	Error    string   `json:"error,omitempty"`
	Request  rawReq   `json:"request"`
	Response *rawResp `json:"response,omitempty"`
}

type rawReq struct {
	ID         string `json:"id"`
	Operation  string `json:"operation"`
	MountType  string `json:"mount_type"`
	MountPoint string `json:"mount_point"`
	Path       string `json:"path"`
}

type rawResp struct {
	Data struct {
		Version int `json:"version"`
	} `json:"data"`
}

// parseLine converts one Vault audit log line into a wire.SecretEvent.
//
// The third return value (reason) explains why a line was dropped and
// is empty on success. Listeners surface it in debug logs so we can
// see what Vault is actually sending and why entries are filtered out.
//
// Only KV v2 is supported (path begins with "<mount>/data/"); KV v1
// events are ignored.
func parseLine(s string) (wire.SecretEvent, bool, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return wire.SecretEvent{}, false, "empty line"
	}

	var raw rawEntry
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return wire.SecretEvent{}, false, "invalid json: " + err.Error()
	}

	if raw.Type != "response" {
		return wire.SecretEvent{}, false, "type=" + raw.Type + " (skip request half)"
	}
	if raw.Error != "" {
		return wire.SecretEvent{}, false, "response error: " + raw.Error
	}

	if raw.Request.MountType != "kv" {
		return wire.SecretEvent{}, false, "non-kv mount_type=" + raw.Request.MountType
	}

	op := wire.Operation(raw.Request.Operation)
	switch op {
	case wire.Create, wire.Update, wire.Patch, wire.Delete:
	default:
		return wire.SecretEvent{}, false, "operation=" + raw.Request.Operation + " (not create/update/delete)"
	}

	mount := strings.TrimSuffix(raw.Request.MountPoint, "/")
	path := strings.TrimPrefix(raw.Request.Path, mount+"/")

	if !strings.HasPrefix(path, "data/") {
		return wire.SecretEvent{}, false, "path subkey is not data/: " + raw.Request.Path
	}
	path = strings.TrimPrefix(path, "data/")

	t, _ := time.Parse(time.RFC3339Nano, raw.Time)
	var version int
	if raw.Response != nil {
		version = raw.Response.Data.Version
	}

	return wire.SecretEvent{
		Time:      t,
		RequestID: raw.Request.ID,
		Operation: op,
		Mount:     mount,
		Path:      path,
		Version:   version,
	}, true, ""
}
