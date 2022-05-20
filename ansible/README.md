# Ansible requirements

1. Install Ansible <https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html>

2. Add or update `etc/ansible/hosts` with the IP addresses and hostnames of the nodes you want to provision. E.g.

    ```txt
    [nodes] 
    192.168.1.201
    192.168.1.202

    [servers]
    server1
    server2
    ```

3. Make sure you have a `~/.ssh/id_rsa` ssh key that can access your nodes. It is used for SSH connections by default.
