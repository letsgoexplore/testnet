Build instructions
==================

1. Start the docker with `./start-docker.sh`
2. The working directory is `/root` and the source code is mounted to `/root/sgx`
3. Go to the source code dir, `cd ./sgx` then run `make` there. This will build the enclave as well as the untrusted part (app) and put the artifact in `sgx/bin`
4. Go to `bin` and run `./app`. You should see things printed out without errors.
