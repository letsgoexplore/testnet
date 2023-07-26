#!/bin/bash

# -e => Exits immediately on error
# -u => Error when using undefined vars
set -eu

cd sgx
nohup ./server_ctrl.sh start-leader &
cd ..