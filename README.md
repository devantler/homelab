# Welcome to Devantler's Homelab 🚀

This Homelab is a single-server setup, that focuses on ease-of-use over production-capabilities. As such, it works well for hobby projects, and small-scale hosting.

## Overview

### Infrastructure

- [Cloudflared](https://github.com/cloudflare/cloudflared): To tunnel traffic from the internet to the server securely.
- [Traefik](https://traefik.io/traefik/): Reverse proxy to route traffic to services.

### Data

- [Postgres](https://www.postgresql.org): A popular SQL Database.
- [DataHub](https://datahubproject.io): A versatile metadata platform.
- [Kafka](https://kafka.apache.org): A distributed event streaming platform.

### Apps

- [Portainer](https://www.portainer.io): Container management software for Docker, Kubernetes and Nomad.
- [Kafka UI](https://github.com/provectus/kafka-ui): Fast and lightweight web UI for managing Apache Kafka® clusters. 
- [Pi-hole](https://pi-hole.net): Network-wide Ad Blocking
- [PlantUML Server](https://github.com/plantuml/plantuml-server): A web application and server to generate PlantUML diagrams on-the-fly.

### Monitoring

- [Uptime Kuma](https://github.com/louislam/uptime-kuma): An uptime monitor for self-hosted or external services.
- [Glances](https://nicolargo.github.io/glances/): Real-time system monitoring tool. (restricted to docker-allocated resources)
- [Speedtest Tracker](https://github.com/alexjustesen/speedtest-tracker): Internet performance tracking application that runs speedtest checks against Ookla's Speedtest service.

## Getting Started

To run the Homelab you must:

1. Create and configure a domain on Cloudflare.
2. Setup Cloudflared to tunnel service access.
3. Create an `.env` file in the the 'apps/portainer' folder with the required environment variables. 
    - Check for `${NAME_OF_ENV_VAR?}` in the docker-compose file to see which environment variables are required.
4. Access Portainer on `http://localhost:9000`.
5. Add and configure stacks in Portainer, for the services you want to host.
