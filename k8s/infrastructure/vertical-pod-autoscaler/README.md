# Vertical Pod Autoscaler

A service that automatically adjusts the CPU and memory reservations for your pods to help them run more efficiently.

## Dependencies

- [Metrics Server](../metrics-server/README.md)

## CRDs

### VerticalPodAutoscaler

```yaml
apiVersion: autoscaling.k8s.io/v1beta2
kind: VerticalPodAutoscaler
metadata:
  name: <vpa-name>
spec:
  targetRef:
    apiVersion: "apps/v1"
    kind: <Deployment | StatefulSet | DaemonSet>
    name: <target-name>
```
