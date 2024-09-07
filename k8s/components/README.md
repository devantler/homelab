# Components

This directory contains the Kubernetes components that are used in the homelab.

Components are small, reusable pieces of Kubernetes configuration that can be used to build up more complex applications, or to share common configuration between multiple kustomize bases.

To use a component in a kustomize kustomization, add a `components` field to the kustomization file, and list the components that you want to include (relative to the current directory).

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - namespace.yaml
  - helm-release.yaml
  - helm-repository.yaml

components:
  - ../components/auth-oidc
  - ../components/ingress-traefik
```
