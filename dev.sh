#!/bin/bash

# Check for podman or docker
if command -v podman &> /dev/null; then
    COMPOSE_CMD="podman compose"
    echo "Using podman compose"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker compose"
    echo "Using docker compose"
else
    echo "Error: Neither podman nor docker command found. Please install one."
    exit 1
fi

# Stop existing services, rebuild dev, start detached, and follow logs
$COMPOSE_CMD down && \
$COMPOSE_CMD -f docker-compose.dev.yml up --build --remove-orphans --force-recreate -d && \
$COMPOSE_CMD logs -f
