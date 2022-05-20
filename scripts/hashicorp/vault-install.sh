export SERVERS=(192.168.1.201 192.168.1.202 192.168.1.203)
export USER=devantler

# Vault
for IP in "${SERVERS[@]}"; do
    hashi-up vault install \
        --version 1.10.2 \
        --ssh-target-addr $IP \
        --ssh-target-user $USER \
        --storage consul \
        --api-addr http://$IP:8200
done
