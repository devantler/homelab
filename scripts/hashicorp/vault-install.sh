export SERVERS=(rpi1 rpi2 rpi3)
export USER=devantler

# Vault
for IP in "${SERVERS[@]}"; do
    hashi-up vault install \
        --ssh-target-addr $IP \
        --ssh-target-user $USER \
        --storage consul \
        --api-addr http://$IP:8200
done
