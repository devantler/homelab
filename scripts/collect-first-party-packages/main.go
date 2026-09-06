// collect-first-party-packages inventories proposed Crossplane package images
// from a rendered YAML stream, without reading the cluster or a registry.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// collect returns sorted, distinct first-party Crossplane package references from
// rendered YAML, including Lists. It rejects malformed or empty inventories.
func collect(input io.Reader) ([]string, error) {
	images := map[string]bool{}
	var visit func(map[string]any) error
	visit = func(object map[string]any) error {
		if object["apiVersion"] == "v1" && object["kind"] == "List" {
			items, ok := object["items"].([]any)
			if !ok {
				return fmt.Errorf("list has no valid items")
			}
			for _, item := range items {
				child, ok := item.(map[string]any)
				if !ok {
					return fmt.Errorf("list contains a non-object item")
				}
				if err := visit(child); err != nil {
					return err
				}
			}
			return nil
		}
		api, _ := object["apiVersion"].(string)
		if !strings.HasPrefix(api, "pkg.crossplane.io/") {
			return nil
		}
		switch object["kind"] {
		case "Provider", "Function", "Configuration":
		default:
			return nil
		}
		spec, _ := object["spec"].(map[string]any)
		ref, ok := spec["package"].(string)
		if !ok || ref == "" || strings.ContainsAny(ref, "$\"'{}") || strings.IndexFunc(ref, unicode.IsSpace) >= 0 {
			return fmt.Errorf("%v has a missing, malformed or unresolved spec.package", object["kind"])
		}
		if strings.HasPrefix(ref, "ghcr.io/devantler-tech/") {
			images[ref] = true
		}
		return nil
	}
	decoder := yaml.NewDecoder(input)
	for {
		var object map[string]any
		if err := decoder.Decode(&object); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("read rendered manifests: %w", err)
		}
		if err := visit(object); err != nil {
			return nil, err
		}
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("no first-party Crossplane packages found; inventory is unproven")
	}
	refs := make([]string, 0, len(images))
	for ref := range images {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs, nil
}

// main reads rendered YAML from stdin and writes package references and synthetic
// verification Pods as JSON. Invalid input or output failures exit unsuccessfully.
func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: collect-first-party-packages < rendered.yaml")
		os.Exit(2)
	}
	refs, err := collect(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "UNKNOWN:", err)
		os.Exit(1)
	}
	// Crossplane providers run the package image as their controller. Synthetic
	// Pods let Kyverno evaluate the actual deployed admission expressions, not a
	// second implementation of their image-to-attestor routing.
	pods := make([]map[string]any, 0, len(refs))
	for i, ref := range refs {
		pods = append(pods, map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": fmt.Sprintf("package-signature-%d", i), "namespace": "crossplane"},
			"spec":     map[string]any{"containers": []map[string]string{{"name": "package", "image": ref}}},
		})
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"images": refs, "pods": pods}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
