export SERVERS=(10.10.10.1 10.10.10.2 10.10.10.3)
export USER=umbraco

#Consul
for IP in "${SERVERS[@]}"; do
    COMMAND="hashi-up consul install \
            --ssh-target-addr $IP \
            --ssh-target-user $USER \
            --server \
            --connect \
            --client-addr 0.0.0.0 \
            --bind-addr $IP \
            --bootstrap-expect ${#SERVERS[@]} "
    for IP in "${SERVERS[@]}"; do
        COMMAND+="--retry-join $IP "
    done
    bash -c "$COMMAND"
done
