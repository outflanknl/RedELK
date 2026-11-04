#!/usr/bin/env bash
#
# Part of RedELK
# Modified entrypoitn script for RedELK Elasticsearch docker image
#
# Author: Outflank B.V. / Marc Smeets
# Contributor: Lorenzo Bernardi / @fastlorenzo
#


# Run init script in background
echo "[*] Starting RedELK init script for Elasticsearch"
/usr/local/bin/init-elasticsearch.sh &

# Run original docker entrypoint
echo "[*] Running regular docker entrypoint script"
/usr/local/bin/docker-entrypoint.sh "${@}"
