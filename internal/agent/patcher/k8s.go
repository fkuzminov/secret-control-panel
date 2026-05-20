package patcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"

	"secret-control-panel/internal/shared/vaultpath"
)

// ExternalSecretGVR is the External Secrets Operator CRD coordinate.
var ExternalSecretGVR = schema.GroupVersionResource{
	Group:    "external-secrets.io",
	Version:  "v1",
	Resource: "externalsecrets",
}

const (
	// SelectorAnnotation is the annotation K8sPatcher uses to locate
	// ExternalSecret resources bound to a specific Vault path.
	SelectorAnnotation = "scp.vault/path"

	// TriggerAnnotation is the annotation K8sPatcher writes on an
	// ExternalSecret to force ESO to reconcile immediately
	// ("force-sync" is ESO's standard mechanism).
	TriggerAnnotation = "force-sync"
)

// SelectorMatches reports whether target is one of the Vault paths
// declared in an ExternalSecret's SelectorAnnotation value.
//
// The annotation value may list several paths separated by commas or
// newlines, so a single ExternalSecret can depend on more than one
// Vault path. Each entry is trimmed and slash-normalised before the
// comparison, so a plain single-path value keeps its previous
// exact-match behaviour.
func SelectorMatches(annotation, target string) bool {
	if target == "" {
		return false
	}
	for _, raw := range strings.FieldsFunc(annotation, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		if vaultpath.Normalize(strings.TrimSpace(raw)) == target {
			return true
		}
	}
	return false
}

// K8sPatcher talks to a real Kubernetes API via the dynamic client.
type K8sPatcher struct {
	Client dynamic.Interface
	Log    *slog.Logger
}

// NewK8sPatcher constructs a K8sPatcher.
func NewK8sPatcher(client dynamic.Interface, log *slog.Logger) *K8sPatcher {
	return &K8sPatcher{Client: client, Log: log}
}

// Patch lists ExternalSecret resources cluster-wide, picks every one
// whose SelectorAnnotation lists job.VaultPath among its paths, and
// bumps the trigger annotation to force ESO to reconcile.
func (p *K8sPatcher) Patch(ctx context.Context, job Job) (Result, error) {
	target := vaultpath.Normalize(job.VaultPath)
	if target == "" {
		return Result{}, errors.New("empty vault path in job")
	}

	list, err := p.Client.Resource(ExternalSecretGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list externalsecrets: %w", err)
	}

	// All matched ExternalSecrets receive the same patch body (one
	// timestamp per Patch call), so build it once before the loop.
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	patchBytes, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				TriggerAnnotation: ts,
			},
		},
	})

	var (
		res     Result
		errsAll []error
	)

	for _, item := range list.Items {
		if !SelectorMatches(item.GetAnnotations()[SelectorAnnotation], target) {
			continue
		}
		res.Matched++

		ns := item.GetNamespace()
		_, perr := p.Client.Resource(ExternalSecretGVR).
			Namespace(ns).
			Patch(ctx, item.GetName(), types.MergePatchType, patchBytes, metav1.PatchOptions{})
		if perr != nil {
			if apierrors.IsNotFound(perr) {
				p.Log.Warn("externalsecret disappeared between list and patch",
					"namespace", ns, "name", item.GetName())
				continue
			}
			errsAll = append(errsAll, fmt.Errorf("patch %s/%s: %w", ns, item.GetName(), perr))
			continue
		}

		res.Patched++
		p.Log.Info("patched externalsecret",
			"namespace", ns,
			"name", item.GetName(),
			"vault_path", target,
			"trigger_annotation", TriggerAnnotation,
			"trigger_value", ts,
		)
	}

	if len(errsAll) > 0 {
		return res, errors.Join(errsAll...)
	}
	return res, nil
}
