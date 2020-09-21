## How to connec Go to docker


Fetch the enclave docker

    docker pull bl4ck5un/dcnet

In one terminal, run the following command to start the enclave docker

    docker run --rm -ti -p 12345:12345 bl4ck5un/dcnet


Now your Go/Python programs can connect to port 12345 to access the RPC methods provided by the enclave.
For example, you can run existing tests

    # in another terminal
    go test -v

