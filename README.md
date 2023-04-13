# Welcome to Devantler's Homelab 🚀

This Homelab is a single-server setup, that focuses on ease-of-use over production-capabilities. As such, it works well for hobby projects, and small-scale hosting.

## Overview

### Apps

- [Data Products](https://github.com/devantler/homelab): An implementation of a data product, a Platform as a Service (PaaS), that enables rich interfacing/integrations for a specific data domain.
- [PlantUML Server](https://github.com/plantuml/plantuml-server): A web application and server to generate PlantUML diagrams on-the-fly.
- [Valheim](https://github.com/lloesche/valheim-server-docker): A dedicated Valheim server.

### Infrastructure

- [Authentik](https://goauthentik.io): A modern, open-source Identity & Access Management (IAM) solution.
- [Cloudflared](https://github.com/cloudflare/cloudflared): To tunnel traffic from the internet to the server securely.
- [DataHub](https://datahubproject.io): A versatile metadata platform.
- [Elasticsearch](https://www.elastic.co/elasticsearch/): A distributed, RESTful search and analytics engine.
- [Glances](https://nicolargo.github.io/glances/): Real-time system monitoring tool. (restricted to docker-allocated resources)
- [Grafana](https://grafana.com): A popular open-source analytics and monitoring solution.
- [Jaeger](https://www.jaegertracing.io): A distributed tracing system.
- [Kafka](https://kafka.apache.org): A distributed event streaming platform.
- [Kafka UI](https://github.com/provectus/kafka-ui): Fast and lightweight web UI for managing Apache Kafka® clusters.
- [Opentelemetry Collector](https://opentelemetry.io): A vendor-agnostic open-source telemetry data collector.
- [Pi-hole](https://pi-hole.net): Network-wide Ad Blocking
- [Portainer](https://www.portainer.io): Container management software for Docker, Kubernetes and Nomad.
- [Postgres](https://www.postgresql.org): A popular SQL Database.
- [Prometheus](https://prometheus.io): A popular open-source monitoring solution.
- [Redis](https://redis.io): An in-memory data structure store.
- [Speedtest Tracker](https://github.com/alexjustesen/speedtest-tracker): Internet performance tracking application that runs speedtest checks against Ookla's Speedtest service.
- [Traefik](https://traefik.io/traefik/): Reverse proxy to route traffic to services.
- [Uptime Kuma](https://github.com/louislam/uptime-kuma): An uptime monitor for self-hosted or external services.

### Monitoring

## Getting Started

To run the Homelab you must:

1. Create and configure a domain on Cloudflare.
2. Setup Cloudflared to tunnel service access.
3. Create an `.env` file in the the 'apps/portainer' folder with the required environment variables.
    - Check for `${NAME_OF_ENV_VAR?}` in the docker-compose file to see which environment variables are required.
4. Access Portainer on `http://localhost:9000`.
5. Add and configure stacks in Portainer, for the services you want to host.
