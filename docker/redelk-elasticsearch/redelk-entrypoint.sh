#!/usr/bin/env bash

# Run init script in background
/usr/local/bin/init-elasticsearch.sh &

# Run original docker entrypoint
/usr/local/bin/docker-entrypoint.sh "${@}"
