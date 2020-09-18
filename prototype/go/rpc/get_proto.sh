#!/usr/bin/env bash

set -e

export PATH=$PATH:${GOPATH:-$HOME/go}/bin

/opt/protobuf/bin/protoc -I../../services \
 --go_out=. \
 --go-grpc_out=. \
 ../../services/enclave.proto