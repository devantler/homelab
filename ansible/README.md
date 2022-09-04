# Ansible requirements

1. Install Ansible <https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html>
2. Add or update `etc/ansible/hosts` with the IP addresses and hostnames of the nodes you want to provision. E.g.

    ```txt
    [nodes-ips] 
    10.10.10.1
    10.10.10.2
    10.10.10.3

    [nodes]
    rpi1
    rpi2
    rpi3

    [servers]
    rpi1
    rpi2
    rpi3
    ```

3. Make sure you have a `~/.ssh/id_rsa` ssh key that can access your nodes. It is used for SSH connections by default.
