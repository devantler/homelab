echo "🚜 Draining talos-docker-1 node"
kubectl drain talos-docker-1 --ignore-daemonsets
echo "🗑️ Deleting talos-docker-1 node"
kubectl delete node talos-docker-1
echo "🔥 Removing talos-docker-1 node from Docker"
docker rm -f talos-docker-1
