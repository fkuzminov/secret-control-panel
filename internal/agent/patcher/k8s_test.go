package patcher

import (
	"context"
	"io"
	"log/slog"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newES(namespace, name, vaultPath string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(ExternalSecretGVR.GroupVersion().WithKind("ExternalSecret"))
	u.SetNamespace(namespace)
	u.SetName(name)
	if vaultPath != "" {
		u.SetAnnotations(map[string]string{SelectorAnnotation: vaultPath})
	}
	return u
}

func newFakeClient(objs ...runtime.Object) *fake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{
		ExternalSecretGVR: "ExternalSecretList",
	}
	return fake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, objs...)
}

func TestK8sPatcher_PatchMatchingExternalSecrets(t *testing.T) {
	es1 := newES("default", "match-1", "secret/cluster_a/accounts-db")
	es2 := newES("default", "match-2", "secret/cluster_a/accounts-db")
	es3 := newES("default", "no-match", "secret/cluster_a/ledger-db")
	es4 := newES("default", "no-anno", "")

	client := newFakeClient(es1, es2, es3, es4)
	p := NewK8sPatcher(client, quietLogger())

	res, err := p.Patch(context.Background(), Job{
		VaultPath: "secret/cluster_a/accounts-db",
		Operation: "update",
		Version:   7,
	})
	if err != nil {
		t.Fatalf("Patch returned err: %v", err)
	}
	if res.Matched != 2 || res.Patched != 2 {
		t.Fatalf("expected matched=2 patched=2, got %+v", res)
	}

	got1, err := client.Resource(ExternalSecretGVR).Namespace("default").Get(context.Background(), "match-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get match-1: %v", err)
	}
	if v := got1.GetAnnotations()[TriggerAnnotation]; v == "" {
		t.Errorf("match-1: trigger annotation %q not set", TriggerAnnotation)
	}

	got3, err := client.Resource(ExternalSecretGVR).Namespace("default").Get(context.Background(), "no-match", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get no-match: %v", err)
	}
	if v := got3.GetAnnotations()[TriggerAnnotation]; v != "" {
		t.Errorf("no-match: trigger annotation should not be set, got %q", v)
	}
}

func TestK8sPatcher_PatchesAcrossAllNamespaces(t *testing.T) {
	a := newES("ns-a", "es-a", "secret/cluster_a/db")
	b := newES("ns-b", "es-b", "secret/cluster_a/db")
	c := newES("ns-c", "es-c", "secret/cluster_a/db")
	unrelated := newES("ns-d", "es-d", "secret/cluster_a/other")

	client := newFakeClient(a, b, c, unrelated)
	p := NewK8sPatcher(client, quietLogger())

	res, err := p.Patch(context.Background(), Job{VaultPath: "secret/cluster_a/db"})
	if err != nil {
		t.Fatalf("Patch err: %v", err)
	}
	if res.Matched != 3 || res.Patched != 3 {
		t.Fatalf("expected matched=3 patched=3, got %+v", res)
	}

	gotD, _ := client.Resource(ExternalSecretGVR).Namespace("ns-d").Get(context.Background(), "es-d", metav1.GetOptions{})
	if v := gotD.GetAnnotations()[TriggerAnnotation]; v != "" {
		t.Errorf("unrelated annotation should not be touched, got trigger=%q", v)
	}
}

func TestSelectorMatches(t *testing.T) {
	cases := []struct {
		name       string
		annotation string
		target     string
		want       bool
	}{
		{"single exact", "secret/cluster_a/db", "secret/cluster_a/db", true},
		{"single no match", "secret/cluster_a/db", "secret/cluster_b/db", false},
		{"comma list first", "secret/cluster_a/db,secret/shared/jwt", "secret/cluster_a/db", true},
		{"comma list second", "secret/cluster_a/db,secret/shared/jwt", "secret/shared/jwt", true},
		{"comma list with spaces", "secret/cluster_a/db , secret/shared/jwt", "secret/shared/jwt", true},
		{"newline list", "secret/cluster_a/db\nsecret/shared/jwt", "secret/shared/jwt", true},
		{"list no match", "secret/cluster_a/db,secret/shared/jwt", "secret/cluster_b/db", false},
		{"trailing slash normalised", "secret/cluster_a/db/", "secret/cluster_a/db", true},
		{"empty target", "secret/cluster_a/db", "", false},
		{"empty annotation", "", "secret/cluster_a/db", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SelectorMatches(c.annotation, c.target); got != c.want {
				t.Fatalf("SelectorMatches(%q, %q) = %v, want %v", c.annotation, c.target, got, c.want)
			}
		})
	}
}

func TestK8sPatcher_MultiPathAnnotation(t *testing.T) {
	multi := newES("default", "multi", "secret/cluster_a/accounts-db,secret/shared/jwt-key")
	single := newES("default", "single", "secret/cluster_a/accounts-db")
	other := newES("default", "other", "secret/cluster_b/db")

	client := newFakeClient(multi, single, other)
	p := NewK8sPatcher(client, quietLogger())

	res, err := p.Patch(context.Background(), Job{VaultPath: "secret/shared/jwt-key"})
	if err != nil {
		t.Fatalf("Patch err: %v", err)
	}
	if res.Matched != 1 || res.Patched != 1 {
		t.Fatalf("expected matched=1 patched=1 (only multi), got %+v", res)
	}

	gotMulti, _ := client.Resource(ExternalSecretGVR).Namespace("default").Get(context.Background(), "multi", metav1.GetOptions{})
	if v := gotMulti.GetAnnotations()[TriggerAnnotation]; v == "" {
		t.Errorf("multi: trigger annotation not set")
	}
	gotSingle, _ := client.Resource(ExternalSecretGVR).Namespace("default").Get(context.Background(), "single", metav1.GetOptions{})
	if v := gotSingle.GetAnnotations()[TriggerAnnotation]; v != "" {
		t.Errorf("single: should not be triggered for jwt-key path, got %q", v)
	}
}

func TestK8sPatcher_EmptyVaultPath(t *testing.T) {
	client := newFakeClient()
	p := NewK8sPatcher(client, quietLogger())

	_, err := p.Patch(context.Background(), Job{})
	if err == nil {
		t.Fatal("expected error for empty vault path, got nil")
	}
}
