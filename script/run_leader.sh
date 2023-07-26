#!/bin/bash

set -eu
export PATH="$HOME/.cargo/bin:$PATH"
source ~/.bashrc
cd sgx
nohup ./server_ctrl.sh start-leader &
cd ..