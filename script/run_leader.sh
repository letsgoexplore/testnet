#!/bin/bash
set -eu

cd sgx
nohup ./server_ctrl.sh start-leader &
cd ..