kubectl drain talos-docker-1 --ignore-daemonsets
kubectl delete node talos-docker-1
docker rm -f talos-docker-1
