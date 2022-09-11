# How To

You need to first install Ansible and then run the following:

- `ansible-galaxy install geerlingguy.git`
- `ansible-galaxy install robertdebock.bootstrap`
- `ansible-galaxy install robertdebock.core_dependencies`
- `ansible-galaxy install robertdebock.hashicorp`
- `ansible-galaxy install jnv.unattended-upgrades`

Next, you can run the `setup.yaml` playbook to initialize new nodes with Git, Python and Docker.

- `ansible-playbook playbooks/setup.yaml`

After this you can use `hashi-up` to initialize new nodes in a Nomad cluster. If and when a better way to bootstrap a hashicorp cluster is found, this will be updated.
