## Main Body Code Structure 
- `client`, `aggregator`, `server` contain the running logic of each role.
    <!-- - the logic within each crate goes below: -->
    ![the logic within each crate goes below](./img/general%20structure%20of%20each%20role's%20code.png)
- `enclave` provide the function of client within the enclave.
- `common` contains the general function for all roles
- `interface` contains the parameter settings, and the interface between in-enclave and out-enclave.
- `third-party` comprises the third-party encryption library.

## Script Structure
Here we mainly talk about te structure of the [script/dc-net-control.sh](../dc-net-control.sh) and [script/server_ctrl_multithread.sh](../server_ctrl_multithread.sh).

`server_ctrl_multithread.sh` ultilizes the API function provided by each role's `main.py`, to realize the interaction between roles and the comprehensive process we desire. 

`dc-net-control.sh` is based on `server_ctrl_multithread.sh`, providing the all function needed when deploying in AWS. It's another encapsulation for deployment in WAN scenario.

In general, when deploying in WAN, you only need to use `dc-net-control.sh`.