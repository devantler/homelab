docker run -d \
    --name talos-docker-1 \
    --hostname talos-docker-1 \
    --read-only \
    --privileged \
    --security-opt seccomp=unconfined \
    --mount type=tmpfs,destination=/run \
    --mount type=tmpfs,destination=/system \
    --mount type=tmpfs,destination=/tmp \
    --mount type=volume,destination=/system/state \
    --mount type=volume,destination=/var \
    --mount type=volume,destination=/etc/cni \
    --mount type=volume,destination=/etc/kubernetes \
    --mount type=volume,destination=/usr/libexec/kubernetes \
    --mount type=volume,destination=/usr/etc/udev \
    --mount type=volume,destination=/opt \
    -e PLATFORM=container \
    -p 50000:50000 \
    -p 6443:6443 \
    ghcr.io/siderolabs/talos:v1.5.3

sleep 5

sops -d machine-config.talos-docker-1.sops.yaml | talosctl -n 127.0.0.1 apply-config --insecure -f /dev/stdin
