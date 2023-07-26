#!/bin/bash
cd sgx
nohup ./server_ctrl.sh start-leader &
cd ..