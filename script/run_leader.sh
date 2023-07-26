#!/bin/bash

# -e => Exits immediately on error
# -u => Error when using undefined vars
set -eu
export PATH="$HOME/.cargo/bin:$PATH"
source ~/.bashrc
cd sgx
nohup ./server_ctrl.sh start-leader &
cd ..