#!/usr/bin/env bash

set -euo pipefail

CONTAINER_NAME_NEW=dcnet-zzy
DOCKER_IMAGE=bl4ck5un/sgx-rust-fork:2004-1.1.6 

if docker container inspect $CONTAINER_NAME_NEW > /dev/null 2>&1; then
  docker start $CONTAINER_NAME_NEW
else
  docker run \
    -d \
    -v $PWD:/root/sgx \
    --hostname $CONTAINER_NAME_NEW \
    --name $CONTAINER_NAME_NEW \
    -e SGX_MODE=SW \
    $DOCKER_IMAGE
fi

docker exec $CONTAINER_NAME_NEW sh -c "cd /root/sgx; echo $PWD; ./time_measurement.sh test"
sleep 15
docker exec $CONTAINER_NAME_NEW sh -c "cd /root/sgx; ./time_measurement.sh send"