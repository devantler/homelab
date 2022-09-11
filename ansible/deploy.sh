#!/bin/bash

ansible-playbook bootstrap/main.yaml
ansible-playbook k3s/site.yml
