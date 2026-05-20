package audit

import (
	"testing"
	"time"

	"secret-control-panel/internal/shared/wire"
)

func TestParseLine(t *testing.T) {
	const goodTime = "2026-05-04T00:00:00.123456789Z"

	cases := []struct {
		name string
		line string
		want wire.SecretEvent
		ok   bool
	}{
		{
			name: "empty",
			line: "",
		},
		{
			name: "whitespace only",
			line: "   \n\t",
		},
		{
			name: "invalid json",
			line: `{not json`,
		},
		{
			name: "request half is skipped",
			line: `{"type":"request","time":"` + goodTime + `","request":{"id":"r1","operation":"update","mount_type":"kv","mount_point":"kv/","path":"kv/data/app/db"}}`,
		},
		{
			name: "response with error is skipped",
			line: `{"type":"response","time":"` + goodTime + `","error":"permission denied","request":{"id":"r1","operation":"update","mount_type":"kv","mount_point":"kv/","path":"kv/data/app/db"}}`,
		},
		{
			name: "non-kv mount is skipped",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r1","operation":"update","mount_type":"system","mount_point":"sys/","path":"sys/foo"}}`,
		},
		{
			name: "kv read operation is skipped",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r1","operation":"read","mount_type":"kv","mount_point":"kv/","path":"kv/data/app/db"}}`,
		},
		{
			name: "kv metadata path is skipped",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r1","operation":"update","mount_type":"kv","mount_point":"kv/","path":"kv/metadata/app/db"}}`,
		},
		{
			name: "kv v1 (no data/ prefix) is skipped",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r1","operation":"create","mount_type":"kv","mount_point":"kvv1/","path":"kvv1/app/db"}}`,
		},
		{
			name: "kv v2 update — happy path",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r1","operation":"update","mount_type":"kv","mount_point":"kv/","path":"kv/data/app/db"},"response":{"data":{"version":3}}}`,
			want: wire.SecretEvent{
				Time:      mustParseTime(t, goodTime),
				RequestID: "r1",
				Operation: wire.Update,
				Mount:     "kv",
				Path:      "app/db",
				Version:   3,
			},
			ok: true,
		},
		{
			name: "kv v2 create — happy path",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r2","operation":"create","mount_type":"kv","mount_point":"kv/","path":"kv/data/app/jwt"},"response":{"data":{"version":1}}}`,
			want: wire.SecretEvent{
				Time:      mustParseTime(t, goodTime),
				RequestID: "r2",
				Operation: wire.Create,
				Mount:     "kv",
				Path:      "app/jwt",
				Version:   1,
			},
			ok: true,
		},
		{
			name: "kv v2 patch — happy path",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r-patch","operation":"patch","mount_type":"kv","mount_point":"kv/","path":"kv/data/app/db"},"response":{"data":{"version":4}}}`,
			want: wire.SecretEvent{
				Time:      mustParseTime(t, goodTime),
				RequestID: "r-patch",
				Operation: wire.Patch,
				Mount:     "kv",
				Path:      "app/db",
				Version:   4,
			},
			ok: true,
		},
		{
			name: "kv v2 delete — happy path (no version in response)",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r3","operation":"delete","mount_type":"kv","mount_point":"kv/","path":"kv/data/app/db"}}`,
			want: wire.SecretEvent{
				Time:      mustParseTime(t, goodTime),
				RequestID: "r3",
				Operation: wire.Delete,
				Mount:     "kv",
				Path:      "app/db",
				Version:   0,
			},
			ok: true,
		},
		{
			name: "kv v2 with non-default mount point",
			line: `{"type":"response","time":"` + goodTime + `","request":{"id":"r4","operation":"update","mount_type":"kv","mount_point":"team-a/","path":"team-a/data/svc/cfg"},"response":{"data":{"version":7}}}`,
			want: wire.SecretEvent{
				Time:      mustParseTime(t, goodTime),
				RequestID: "r4",
				Operation: wire.Update,
				Mount:     "team-a",
				Path:      "svc/cfg",
				Version:   7,
			},
			ok: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, reason := parseLine(tc.line)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v (got %+v, reason=%q)", ok, tc.ok, got, reason)
			}
			if !ok {
				if reason == "" {
					t.Fatalf("ok=false but reason is empty")
				}
				return
			}
			if reason != "" {
				t.Fatalf("ok=true but reason=%q (expected empty)", reason)
			}
			if got != tc.want {
				t.Fatalf("event mismatch:\n got: %+v\nwant: %+v", got, tc.want)
			}
		})
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	return v
}
