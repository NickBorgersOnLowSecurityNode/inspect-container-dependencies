#!/bin/bash
# Fail hard if any problem
set -e
# Load configuration
source ${BASH_SOURCE%/*}/configuration.sh
# Stop (so remove) any past execution
docker stop vulnerable-openssl || true
# Start OpenSSL with long-running task (speed test)
docker run --rm --detach --name vulnerable-openssl \
  --mount type=bind,source=/usr/bin/osqueryi,destination=/usr/bin/osqueryi \
  ${VULNERABLE_OPENSSL_CONTAINER_IMAGE} openssl speed
# Sleep long enough for OpenSSL to start its work
sleep 2
# Run osqueryi inside the container
docker exec -it vulnerable-openssl osqueryi "${OSQUERY_QUERY}"
# Stop current execution
docker stop vulnerable-openssl
