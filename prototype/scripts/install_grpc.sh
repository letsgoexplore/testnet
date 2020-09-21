#!/usr/bin/env bash

set -e

TEMP=$(mktemp -d /tmp/SGX.XXXXXXXX)
PREFIX=${HOME}/.local

pushd ${TEMP}

git clone --recurse-submodules -b v1.32.0 https://github.com/grpc/grpc
pushd grpc
mkdir -p cmake/build
pushd cmake/build
cmake -DgRPC_INSTALL=ON \
      -DgRPC_BUILD_TESTS=OFF \
      -DCMAKE_INSTALL_PREFIX=${PREFIX} \
      ../..
make -j $(nproc)
make install

popd
popd
popd