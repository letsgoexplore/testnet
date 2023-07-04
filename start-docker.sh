#!/usr/bin/env bash

set -euo pipefail

CONTAINER_NAME=dcnet-1.1.6
DOCKER_IMAGE=bl4ck5un/sgx-rust-fork:2004-1.1.6

if docker container inspect $CONTAINER_NAME > /dev/null 2>&1; then
  docker start -ai $CONTAINER_NAME
else
  docker run \
    -v $PWD:/root/sgx \
    -ti \
    --hostname $CONTAINER_NAME \
    --name $CONTAINER_NAME \
    -e SGX_MODE=SW \
    $DOCKER_IMAGE
fi
