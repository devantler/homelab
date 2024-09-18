# Trivy Operator

The Trivy Operator leverages Trivy to continuously scan your Kubernetes cluster for security issues. The scans are summarised in security reports as Kubernetes Custom Resource Definitions, which become accessible through the Kubernetes API. The Operator does this by watching Kubernetes for state changes and automatically triggering security scans in response.

- [Documentation](https://aquasecurity.github.io/trivy-operator/latest/)
- [Helm Chart](https://github.com/aquasecurity/trivy-operator/tree/main/deploy/helm)
