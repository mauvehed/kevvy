#!/bin/bash

podman compose down && podman compose -f docker-compose.dev.yml up --build --remove-orphans -d && podman compose logs -f
