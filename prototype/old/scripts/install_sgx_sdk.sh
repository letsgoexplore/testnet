#!/usr/bin/env bash

set -e

SGX_SDK_URL=https://download.01.org/intel-sgx/sgx-linux/2.11/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.11.100.2.bin

sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev build-essential python

TEMP=$(mktemp -d /tmp/SGX.XXXXXXXX)

pushd $TEMP
curl $SGX_SDK_URL > sgx_linux_sdk.bin
chmod u+x sgx_linux_sdk.bin
echo -e 'no\n/opt/intel' | sudo ./sgx_linux_sdk.bin
popd
