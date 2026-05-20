package patcher

import (
	"fmt"
	"log/slog"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// BuildWithClient constructs a K8sPatcher using the in-cluster
// Kubernetes config. The caller can access the underlying dynamic
// client via the returned value's Client field (e.g. for the syncer).
func BuildWithClient(log *slog.Logger) (*K8sPatcher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}

	log.Info("k8s patcher enabled",
		"selector_annotation", SelectorAnnotation,
		"trigger_annotation", TriggerAnnotation,
	)
	return NewK8sPatcher(dyn, log), nil
}
