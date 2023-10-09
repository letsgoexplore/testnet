Here we talk about something deserves your attention when deploying on AWS(or other server platform).

### Locally creating `ubuntu` account
AWS only accept `ubuntu` account for accessing. 
```shell
useradd -ms /bin/bash ubuntu
```
### Creating Instances
Currently, each instance's pem key is named with `ssi.pem` and saved in the ./script/pem_key. We also recommend you doing so to simiplify other procedure. You can also changed the code in [script/dc-net-control.sh](../../dc-net-control.sh) to satisfy your need.

### After Starting Instances
![AWS_instance image](../img/AWS_instance.png)
After starting instances, please update all `Public IPv4 address`(for instance, 3.142.82.8) and `Public IPv4 DNS`(for instance, ec2-3-142-82-8.us-east-2.compute.amazonaws.com) to `SERVER_IP` and `SERVER_AWS_COMMANDS` in [script/dc-net-control.sh](../../dc-net-control.sh) and [script/server_ctrl_multithread.sh](../../server_ctrl_multithread.sh).

For example,
```shell
# script/dc-net-control.sh
SERVER_IPS=("3.142.82.8" "13.38.37.45" "54.176.5.119" "43.207.114.246" "34.221.6.203")
SERVER_AWS_COMMANDS=("ec2-3-142-82-8.us-east-2.compute.amazonaws.com" "ec2-13-38-37-45.eu-west-3.compute.amazonaws.com" "ec2-54-176-5-119.us-west-1.compute.amazonaws.com" "ec2-43-207-114-246.ap-northeast-1.compute.amazonaws.com" "ec2-34-221-6-203.us-west-2.compute.amazonaws.com")

# script/server_ctrl_multithread.sh
SERVER_IP=("3.142.82.8" "13.38.37.45" "54.176.5.119" "43.207.114.246" "34.221.6.203")
```
