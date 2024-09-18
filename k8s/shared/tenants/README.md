# Infrastructure

These are the tenants that are provisioned in or by my homelab. They provide isolated environments to allow tenants to run their own services and applications, without worrying about provisioning and managing the underlying infrastructure.

I aim to provide three types of tenants:

- **Cluster Tenant**: A tenant that is provisioned to its own Kubernetes cluster. This tenant has high isolation and control over the cluster, but also requires the most resources.
- **VCluster Tenant**: A tenant that is provisioned to a virtual cluster within this Kubernetes cluster. This tenant has medium isolation and and high control over the virtual cluster, but requires fewer resources than a cluster tenant.
- **Namespace Tenant**: A tenant that is provisioned to a namespace within this Kubernetes cluster. This tenant has low isolation and control over the namespace, but requires the fewest resources.

Besides the tenant types, I also aim to provide the tenants with opt-in addons that they can choose to enable or disable for their tenant. These addons could be GitOps, observability, or security tools that help the tenant operate their services and applications without the extra overhead, that managing these tools would require.
