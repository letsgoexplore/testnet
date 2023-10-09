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
