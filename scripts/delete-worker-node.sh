# Set the base name, hostname, and ports
BASE_NAME="talos-docker"
BASE_HOSTNAME="talos-docker"
BASE_PORT_1=50010
BASE_PORT_2=6453

# Check if a container with the given name already exists
i=10
while ! docker ps -a --format '{{.Names}}' | grep "${BASE_NAME}-${i}"; do
    ((i--))
    if [ $i -eq 0 ]; then
        echo "No worker nodes to delete"
        exit 1
    fi
done

# Decrement the number to the name, hostname, and ports
NAME="${BASE_NAME}-${i}"
HOSTNAME="${BASE_HOSTNAME}-${i}"
PORT_1=$((BASE_PORT_1 + i - 1))
PORT_2=$((BASE_PORT_2 + i - 1))

# Assign each new node to an address in the custom network
ADDRESS="10.0.100.$i"

# Stop and remove the container with the modified name, hostname, and ports
docker rm $NAME -f

# Remove the worker node from the cluster
kubectl delete node $HOSTNAME
