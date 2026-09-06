package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Preserve the upstream document order so concatenation restores every byte.
// Explicit identities prevent an upstream addition/rename from silently creating
// an unreferenced file or overwriting a local policy/PDB during a refresh.
var certApproverResources = []struct{ identity, file string }{
	{"Namespace/kubelet-serving-cert-approver", "namespace.yaml"},
	{"ServiceAccount/kubelet-serving-cert-approver", "service-account.yaml"},
	{"Role/leader-election:kubelet-serving-cert-approver", "role.yaml"},
	{"ClusterRole/certificates:kubelet-serving-cert-approver", "cluster-role-certificates.yaml"},
	{"ClusterRole/events:kubelet-serving-cert-approver", "cluster-role-events.yaml"},
	{"RoleBinding/events:kubelet-serving-cert-approver", "role-binding-events.yaml"},
	{"RoleBinding/leader-election:kubelet-serving-cert-approver", "role-binding-leader-election.yaml"},
	{"ClusterRoleBinding/kubelet-serving-cert-approver", "cluster-role-binding.yaml"},
	{"Service/kubelet-serving-cert-approver", "service.yaml"},
	{"Deployment/kubelet-serving-cert-approver", "deployment.yaml"},
}

func splitCertApproverResources(input []byte, dir string) error {
	files := map[string][]byte{}
	documents := splitDocuments(strings.Split(string(input), "\n"))
	for index, lines := range documents {
		identity, err := readIdentity(lines)
		if err != nil {
			return err
		}
		key := identity.Kind + "/" + identity.Metadata.Name
		filename := ""
		for _, resource := range certApproverResources {
			if resource.identity == key {
				filename = resource.file
				break
			}
		}
		if filename == "" {
			return fmt.Errorf("unreviewed resource identity %s", key)
		}
		if _, exists := files[filename]; exists {
			return fmt.Errorf("duplicate resource %s", key)
		}
		files[filename] = []byte(strings.Join(lines, "\n"))
		// Restore the boundary newline removed by splitDocuments; the final
		// document already retains the exact original suffix.
		if index < len(documents)-1 {
			files[filename] = append(files[filename], '\n')
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func joinCertApproverResources(dir string) ([]byte, error) {
	var result bytes.Buffer
	for _, resource := range certApproverResources {
		data, err := os.ReadFile(filepath.Join(dir, resource.file))
		if err != nil {
			return nil, err
		}
		identity, err := readIdentity(strings.Split(string(data), "\n"))
		if err != nil {
			return nil, err
		}
		if identity.Kind+"/"+identity.Metadata.Name != resource.identity {
			return nil, fmt.Errorf("%s has wrong resource identity", resource.file)
		}
		result.Write(data)
	}
	return result.Bytes(), nil
}

func validateOriginCRD(input []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var doc manifestIdentity
	if err := decoder.Decode(&doc); err != nil {
		return fmt.Errorf("read CRD: %w", err)
	}
	if doc.Kind != "CustomResourceDefinition" || (doc.Metadata.Name != "originissuers.cert-manager.k8s.cloudflare.com" && doc.Metadata.Name != "clusteroriginissuers.cert-manager.k8s.cloudflare.com") {
		return errors.New("source must be one of the two declared origin-ca-issuer CRDs")
	}
	if err := decoder.Decode(&doc); !errors.Is(err, io.EOF) {
		return errors.New("CRD source must contain exactly one document")
	}
	return nil
}
