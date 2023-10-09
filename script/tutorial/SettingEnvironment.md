## Setting up Environment

SGX is different from our CPU, so we need to run the code within docker. The reason why **./start-docker.sh** and **./start-docker-real-sgx.sh** coexist, is because the former simulates normal enviroment, and it's more friendly for debugging.

### Install Docker
You can quickly install docker by copying [./technique/InstallingDocker.md](./technique/InstallingDocker.md).

### Install numpy
```shell
# upgrade apt
sudo apt install --upgrade

# install pip
sudo apt install python3-pip

#install numpy
pip install numpy
```

### Install Bandwidth Tools
```shell
sudo apt-get install iperf
sudo apt-get install tcpdump
```