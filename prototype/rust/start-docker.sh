#!/usr/bin/env bash

set -euf pipofail


CONTAINER_NAME=rustsdk

if docker container inspect $CONTAINER_NAME > /dev/null 2>&1; then
docker start -ai $CONTAINER_NAME
else
docker run \
    -v $PWD:/root/sgx \
    -ti \
    --name $CONTAINER_NAME \
    -e SGX_MODE=SW \
    baiduxlab/sgx-rust:1804-1.1.3
fi
