Build instructions
==================

1. Start the docker with `./start-docker.sh`. The source code is mounted to `/root/sgx`
2. Go to the source code dir: `cd /root/sgx`
3. Build the enclave image: `make -C enclave`. This will build the enclave image and put the artifact in `/sgxdcnet/lib/enclave.signed.so`. 
4. Run the test script: `./run_tests.sh`

### Note

> Make is not smart enough to rebuild the enclave image. So always do Step 3 whenever you change the `interface` and `enclave` crates. Remember to `make clean` first.

### Tutorial
> [Tutorial](./script/tutorial/ReadMe.md) is waiting for you! 

### Code structure
- `client`, `aggregator`, `server` contain the running logic of each role.
    ![the logic within each crate goes below](./script/tutorial/img/general%20structure%20of%20each%20role's%20code.png)
- `enclave` provide the function of client within the enclave.
- `common` contains the general function for all roles
- `interface` contains the parameter settings, and the interface between in-enclave and out-enclave.
- `third-party` comprises the third-party encryption library.