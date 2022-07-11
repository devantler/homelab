export SERVERS=(10.10.10.1 10.10.10.2 10.10.10.3)
export USER=devantler

# # Nomad
for IP in "${SERVERS[@]}"; do
    hashi-up nomad install \
        --ssh-target-addr $IP \
        --ssh-target-user $USER \
        --config-file configs/nomad.hcl
done
