#!/bin/bash

echo "🛑 Deprovisioning K3s development cluster"
k3d cluster delete cluster-development

echo -e "\n"

echo "🛑 Deprovisioning K3s production cluster"
k3d cluster delete cluster-production
