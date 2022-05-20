export SERVERS=(192.168.10.1 192.168.10.2 192.168.10.3)
export USER=devantler

# # Nomad
for IP in "${SERVERS[@]}"; do
    hashi-up nomad install \
        --ssh-target-addr $IP \
        --ssh-target-user $USER \
        --config-file configs/nomad.hcl
done
