# Ansible

## How to setup

1. Install Ansible <https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html>
2. Add or update `/etc/ansible/hosts` with the IP addresses and hostnames of the nodes you want to provision. E.g.

    ```txt
    [all]
    rpi1 ip=10.10.10.1 static_ip=10.10.10.1/8
    rpi2 ip=10.10.10.2 static_ip=10.10.10.2/8
    rpi3 ip=10.10.10.3 static_ip=10.10.10.3/8
    
    [master]
    master1
    master2
    master3

    [node]
    node1
    node2

    [k3s_cluster:children]
    master
    node
    ```

    - The IP variable on [all] is used to configure hosts on individual nodes.
    - The static_ip variable on [all] is used to configure static IPs for individual nodes.
3. Make sure you have a `~/.ssh/id_rsa` ssh key. It is used to set up ssh access to all nodes.
4. Add or update `/etc/ansible/group_vars/all.yml` based on `./k3s/inventory/sample/all.yml`. It is used to configure the k3s cluster.

## How to run

- Run `bash deploy.sh` to bootstrap nodes and set up a HA k3s cluster.
- Run `bash reset.sh` to tear down the k3s cluster.
