package cnpgnpolicy_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

const namespaceKey = "io.kubernetes.pod.namespace"

type selector struct {
	Labels      map[string]string `yaml:"matchLabels"`
	Expressions []struct {
		Key      string   `yaml:"key"`
		Operator string   `yaml:"operator"`
		Values   []string `yaml:"values"`
	} `yaml:"matchExpressions"`
}

type rule struct {
	From         []selector          `yaml:"fromEndpoints"`
	To           []selector          `yaml:"toEndpoints"`
	FromEntities []string            `yaml:"fromEntities"`
	ToEntities   []string            `yaml:"toEntities"`
	FQDNs        []map[string]string `yaml:"toFQDNs"`
	Ports        []struct {
		Ports []struct {
			Port     string `yaml:"port"`
			Protocol string `yaml:"protocol"`
		} `yaml:"ports"`
	} `yaml:"toPorts"`
}

type policySpec struct {
	Selector selector `yaml:"endpointSelector"`
	Ingress  []rule   `yaml:"ingress"`
	Egress   []rule   `yaml:"egress"`
}

type policy struct {
	Metadata struct {
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec  policySpec   `yaml:"spec"`
	Specs []policySpec `yaml:"specs"`
}

func labelKey(key string) string {
	if len(key) > 4 && key[:4] == "k8s:" {
		return key[4:]
	}
	return key
}

// This bounded model covers endpoint selectors and L4/entity rules in the
// selected CNPG policies. It is an offline regression check, not a dataplane
// probe. An explicit namespace expression permits cross-namespace matching;
// an unqualified endpoint selector stays local to its policy namespace.
func matches(t *testing.T, sel selector, labels map[string]string, namespace string) bool {
	t.Helper()
	explicitNamespace := false
	for key, value := range sel.Labels {
		key = labelKey(key)
		explicitNamespace = explicitNamespace || key == namespaceKey
		actual, present := labels[key]
		if !present || actual != value {
			return false
		}
	}
	for _, expression := range sel.Expressions {
		key := labelKey(expression.Key)
		explicitNamespace = explicitNamespace || key == namespaceKey
		value, present := labels[key]
		switch expression.Operator {
		case "Exists":
			if !present {
				return false
			}
		case "In":
			if !present || !slices.Contains(expression.Values, value) {
				return false
			}
		default:
			t.Fatalf("unsupported operator %q in bounded model", expression.Operator)
		}
	}
	return explicitNamespace || labels[namespaceKey] == namespace
}

func permitsPort(r rule, port, protocol string) bool {
	if len(r.Ports) == 0 {
		return true
	}
	for _, group := range r.Ports {
		for _, candidate := range group.Ports {
			if candidate.Port == port && (candidate.Protocol == protocol || candidate.Protocol == "ANY") {
				return true
			}
		}
	}
	return false
}

func allows(t *testing.T, policies []policy, ingress bool, local, remote map[string]string, entity, port, protocol string) bool {
	t.Helper()
	for _, p := range policies {
		for _, spec := range append([]policySpec{p.Spec}, p.Specs...) {
			if !matches(t, spec.Selector, local, p.Metadata.Namespace) {
				continue
			}
			rules := spec.Egress
			if ingress {
				rules = spec.Ingress
			}
			for _, r := range rules {
				if !permitsPort(r, port, protocol) {
					continue
				}
				endpoints, entities := r.To, r.ToEntities
				if ingress {
					endpoints, entities = r.From, r.FromEntities
				}
				if len(endpoints) == 0 && len(entities) == 0 && len(r.FQDNs) == 0 {
					return true
				}
				if remote != nil && (slices.Contains(entities, "all") || slices.Contains(entities, "cluster")) {
					return true
				}
				if entity != "" && slices.Contains(entities, entity) {
					return true
				}
				for _, endpoint := range endpoints {
					if remote != nil && matches(t, endpoint, remote, p.Metadata.Namespace) {
						return true
					}
				}
			}
		}
	}
	return false
}

func readYAML(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../..", path))
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("expected exactly one document in %s; additional document or error: %v", path, err)
	}
}

func loadPolicies(t *testing.T) []policy {
	t.Helper()
	paths := []string{
		"k8s/bases/infrastructure/controllers/cloudnative-pg/cilium-network-policy.yaml",
		"k8s/bases/infrastructure/controllers/plugin-barman-cloud/cilium-network-policy-allow-plugin-barman-cloud.yaml",
		"k8s/bases/infrastructure/controllers/plugin-barman-cloud/cilium-network-policy-allow-cnpg-to-plugin-barman-cloud.yaml",
		"k8s/bases/apps/umami/cilium-network-policy.yaml",
		"k8s/bases/apps/backstage/cilium-network-policy.yaml",
		"k8s/providers/hetzner/infrastructure/coroot/cilium-network-policy.yaml",
	}
	var policies []policy
	for _, path := range paths {
		var p policy
		readYAML(t, path, &p)
		policies = append(policies, p)
	}
	var generator struct {
		Spec struct {
			Rules []struct {
				Name     string `yaml:"name"`
				Generate struct {
					Data policy `yaml:"data"`
				} `yaml:"generate"`
			} `yaml:"rules"`
		} `yaml:"spec"`
	}
	readYAML(t, "k8s/bases/infrastructure/cluster-policies/best-practices/add-default-deny.yaml", &generator)
	found := false
	for _, r := range generator.Spec.Rules {
		if r.Name != "generate-allow-cnpg-operator" {
			continue
		}
		found = true
		for _, namespace := range []string{"tenant-example", "umami", "backstage", "observability"} {
			p := r.Generate.Data
			p.Metadata.Namespace = namespace
			policies = append(policies, p)
		}
	}
	if !found {
		t.Fatal("CNPG ingress generator missing")
	}
	return policies
}

func identity(namespace, name, instance string) map[string]string {
	labels := map[string]string{namespaceKey: namespace}
	if name != "" {
		labels["app.kubernetes.io/name"] = name
	}
	if instance != "" {
		labels["app.kubernetes.io/instance"] = instance
	}
	return labels
}

func TestDatabaseManagementBoundary(t *testing.T) {
	policies := loadPolicies(t)
	for _, namespace := range []string{"cnpg-system", "untrusted-namespace"} {
		for _, name := range []string{"cloudnative-pg", "plugin-barman-cloud", ""} {
			for _, instance := range []string{"cloudnative-pg", "other", ""} {
				source := identity(namespace, name, instance)
				operator := namespace == "cnpg-system" && name == "cloudnative-pg" && instance == "cloudnative-pg"
				for _, destinationNamespace := range []string{"tenant-example", "umami", "backstage", "observability"} {
					for _, database := range []bool{false, true} {
						destination := identity(destinationNamespace, "application", "application")
						if database {
							destination["cnpg.io/cluster"] = "coroot-db"
						}
						for _, port := range []string{"8000", "5432"} {
							t.Run(fmt.Sprintf("%s/%s/%s/to-%s/db-%t/%s", namespace, name, instance, destinationNamespace, database, port), func(t *testing.T) {
								want := operator && database
								// Assert both sides separately. A correct egress boundary must not
								// hide a redundant broad destination-side ingress grant.
								if got := allows(t, policies, true, destination, source, "", port, "TCP"); got != want {
									t.Errorf("CNPG ingress allowed=%t want=%t", got, want)
								}
								if got := allows(t, policies, false, source, destination, "", port, "TCP"); got != want {
									t.Errorf("CNPG egress allowed=%t want=%t", got, want)
								}
							})
						}
					}
				}
			}
		}
	}
}

func TestOperatorAndPluginControlPaths(t *testing.T) {
	policies := loadPolicies(t)
	operator := identity("cnpg-system", "cloudnative-pg", "cloudnative-pg")
	plugin := identity("cnpg-system", "plugin-barman-cloud", "plugin-barman-cloud")
	dns := map[string]string{namespaceKey: "kube-system", "k8s-app": "kube-dns"}
	if !allows(t, policies, false, operator, plugin, "", "9090", "TCP") || !allows(t, policies, true, plugin, operator, "", "9090", "TCP") {
		t.Error("operator to plugin gRPC path blocked")
	}
	for _, entity := range []string{"kube-apiserver", "remote-node", "host"} {
		if !allows(t, policies, true, operator, nil, entity, "9443", "TCP") {
			t.Errorf("webhook blocked from %s", entity)
		}
	}
	for _, workload := range []map[string]string{operator, plugin} {
		if !allows(t, policies, false, workload, nil, "kube-apiserver", "443", "TCP") {
			t.Error("Kubernetes API path blocked")
		}
		for _, protocol := range []string{"TCP", "UDP"} {
			if !allows(t, policies, false, workload, dns, "", "53", protocol) {
				t.Errorf("DNS %s path blocked", protocol)
			}
		}
	}
}
