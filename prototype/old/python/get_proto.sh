#!/usr/bin/env bash

set -e

python -m grpc_tools.protoc \
  -I../services \
   --python_out=. \
   --grpc_python_out=. \
   ../services/enclave.proto