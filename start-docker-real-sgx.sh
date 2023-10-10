#!/usr/bin/env bash

set -euo pipefail

CONTAINER_NAME=dcnet-1.1.6-hw
DOCKER_IMAGE=bl4ck5un/sgx-rust-fork:2004-1.1.6

if docker container inspect $CONTAINER_NAME > /dev/null 2>&1; then
  docker start -ai $CONTAINER_NAME
else
  docker run \
    -v $PWD:/root/sgx \
    -ti \
    -p 18300:18300 \
    -p 28942:28942 \
    --hostname $CONTAINER_NAME \
    --name $CONTAINER_NAME \
    -e SGX_MODE=HW \
    --device /dev/sgx/enclave --device /dev/sgx/provision \
    $DOCKER_IMAGE
fi
