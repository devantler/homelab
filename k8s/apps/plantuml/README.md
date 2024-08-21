# PlantUML

A highly versatile tool that facilitates the rapid and straightforward creation of a wide array of diagrams.

- [Documentation](https://plantuml.com)
- [Helm Chart](https://github.com/stevehipwell/helm-charts/tree/main/charts/plantuml)

## Post-build variables

| Variable                 | Description                                                | Default | Required |
| ------------------------ | ---------------------------------------------------------- | :-----: | :------: |
| cluster_domain           | The domain of the cluster                                  |   -    |    ✓     |
| plantuml_ingress_enabled | Whether to enable an ingress route to the PlantUML service |  true   |    ✕     |
