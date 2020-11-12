## How to use the enclave docker


First, fetch the enclave docker

    docker pull bl4ck5un/dcnet

To start, run the following command in the terminal (which will block until killed by Ctrl-C):

    docker run --rm -ti -p 12345:12345 bl4ck5un/dcnet


Now your Go/Python programs can connect to port 12345 to access the enclave over RPC.
For example, you can run existing tests which does a bunch of RPCs:

    # in another terminal
    go test -v
