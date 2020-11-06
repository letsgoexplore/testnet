#!/usr/bin/env bash

set -euf pipofail

if [[ -z "$(docker ps --filter "name=rustsdk" -qq)" ]] ; then
docker run \
    -v $PWD:/root/sgx \
    -ti \
    --name rustsdk \
    -e SGX_MODE=SW \
    baiduxlab/sgx-rust:1804-1.1.3
else
docker start -ai rustsdk
fi
