package policy

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type fileFormat struct {
	Policies []Policy `yaml:"policies"`
}

// LoadFromFile reads and parses a policies YAML file. Unknown fields
// are rejected so typos surface as errors instead of silent drops.
func LoadFromFile(path string) ([]Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policies %q: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f fileFormat
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse policies %q: %w", path, err)
	}
	return f.Policies, nil
}
