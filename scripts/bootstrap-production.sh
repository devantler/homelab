#!/bin/bash

echo "🖥️ Setting up VMs"
multipass launch --n k3s-server-1
multipass launch --n k3s-server-2
multipass launch --n k3s-server-3
echo ""

echo "☸️ Provisioning Kubernetes cluster"
echo "🔗 Joining k3s-server-1 to cluster"
multipass exec k3s-server-1 -- /bin/bash -c "curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" sh -s - server --cluster-init"
multipass exec k3s-server-1 -- /bin/bash -c 'while [[ $(sudo k3s kubectl get nodes --no-headers 2>/dev/null | grep -c -v "NotReady") -eq 0 ]]; do sleep 2; done'
K3S_SERVER="https://$(multipass info k3s-server-1 | grep "IPv4" | awk -F' ' '{print $2}'):6443"
K3S_TOKEN="$(multipass exec k3s-server-1 -- /bin/bash -c "sudo cat /var/lib/rancher/k3s/server/node-token")"
echo "✅ Node is Ready on k3s-server-1" && echo ""

echo "🔗 Joining k3s-server-2 to cluster"
multipass exec k3s-server-2 -- /bin/bash -c "curl -sfL https://get.k3s.io | K3S_TOKEN=${K3S_TOKEN} K3S_URL=${K3S_SERVER} sh -s - server"
multipass exec k3s-server-2 -- /bin/bash -c 'while [[ $(sudo k3s kubectl get nodes --no-headers 2>/dev/null | grep -c -v "NotReady") -eq 0 ]]; do sleep 2; done'
echo "✅ Node is Ready on k3s-server-2" && echo ""

echo "🔗 Joining k3s-server-3 to cluster"
multipass exec k3s-server-3 -- /bin/bash -c "curl -sfL https://get.k3s.io | K3S_TOKEN=${K3S_TOKEN} K3S_URL=${K3S_SERVER} sh -s - server"
multipass exec k3s-server-3 -- /bin/bash -c 'while [[ $(sudo k3s kubectl get nodes --no-headers 2>/dev/null | grep -c -v "NotReady") -eq 0 ]]; do sleep 2; done'
echo "✅ Node is Ready on k3s-server-3" && echo ""

echo "⤵️ Add cluster to kubeconfig"
cp ~/.kube/config ~/.kube/config.bak.$(date +%Y%m%d%H%M%S)
multipass exec k3s-server-1 -- /bin/bash -c "sudo cat /etc/rancher/k3s/k3s.yaml" >k3s.orig.yaml
sed "/^[[:space:]]*server:/ s_:.*_: \"$(echo $K3S_SERVER | sed -e 's/[[:space:]]//g')\"_" k3s.orig.yaml >k3s.yaml
kubectl config --kubeconfig=./k3s.yaml rename-context default homelab
KUBECONFIG=./k3s.yaml:~/.kube/config kubectl config view --merge --flatten >~/.kube/config.merged
mv ~/.kube/config.merged ~/.kube/config
rm -f k3s.orig.yaml
rm -f k3s.yaml

echo " Set current cluster to homelab"
kubectl config use-context homelab

echo "🚀 Installing Flux"
flux check --pre
flux bootstrap github --owner=$GITHUB_USER --repository=homelab --path=./k8s/clusters/production --personal --branch=main

echo "🔐 Adding SOPS GPG key"
gpg --export-secret-keys --armor "1F1A648778E72857BD9CF481EE0834B3CEAC3061" |
    kubectl create secret generic sops-gpg \
        --namespace=flux-system \
        --from-file=sops.asc=/dev/stdin
