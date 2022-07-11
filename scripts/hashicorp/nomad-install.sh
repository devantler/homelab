export SERVERS=(rpi1 rpi2 rpi3)
export USER=devantler

# # Nomad
for IP in "${SERVERS[@]}"; do
    hashi-up nomad install \
        --ssh-target-addr $IP \
        --ssh-target-user $USER \
        --config-file configs/nomad.hcl
done
