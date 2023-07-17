#!/usr/bin/env bash

set -euo pipefail

CONTAINER_NAME_NEW=dcnet-zzy
DOCKER_IMAGE=bl4ck5un/sgx-rust-fork:2004-1.1.6 

if docker container inspect $CONTAINER_NAME_NEW > /dev/null 2>&1; then
  docker start -ai $CONTAINER_NAME_NEW
else
  docker run \
    -v $PWD:/root/sgx \
    -ti \
    --hostname $CONTAINER_NAME_NEW \
    --name $CONTAINER_NAME_NEW \
    -e SGX_MODE=SW \
    $DOCKER_IMAGE
fi

CONTAINER_NAME=dcnet-zzy


# if docker container inspect $CONTAINER_NAME > /dev/null 2>&1; then
#   docker start -ai $CONTAINER_NAME
# else
#   docker run \
#     -v $PWD:/root/sgx \
#     -ti \
#     --hostname $CONTAINER_NAME \
#     --name $CONTAINER_NAME \
#     -e SGX_MODE=SW \
#     $DOCKER_IMAGE
# fi

docker exec -it $CONTAINER_NAME /bin/bash
