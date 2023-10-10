In this part we will talk about several evaluation procedure:
1. [how to evaluate client runtime?](#how-to-evaluate-client-runtime)
2. [how to evaluate aggregator and server runtime?](#how-to-evaluate-aggregator-and-server-runtime)
3. [how to evaluate bandwidth?](#how-to-evaluate-bandwidth)

## 1 How to evaluate client runtime
Firstly, make sure code is working in Hardware(HW) mode, which simulate the real SGX environment. Run the following script in the terminal:
```shell
./start-docker-real-sgx.sh
```

then open the [script/dc-net-control.sh](../dc-net-control.sh) and find the function `client_eval()`, setting the parameter you want. After setting, you can run the instruction and the evaluation will begin:
```shell
./dc-net-control.sh eval-c
```
The client runtime will be recorded in `client/time-recorder.txt`.

## 2 How to evaluate aggregator and server runtime
Now, if we want to evaluate 1024 talking and 8000 clients in total, 5 servers in WAN, we will talk about how to conduct step by step.

### Setting Parameter
**DO**
1. setting server information as illucidated in [./technique/DeployingAWS.md](./technique/DeployingAWS.md)

2. set the `EVALUATION_FLAG = true` in [interface/src/params.rs](../../interface/src/params.rs) and `is_EVALUATION=1` in [script/dc-net-control.sh](../dc-net-control.sh).

3. set the value in [script/dc-net-control.sh](../dc-net-control.sh). For example:
```shell
num_leader=1
num_follower=4
num_server=$((num_leader + num_follower))
num_leaf_aggregator=16
dc_net_message_length=160
dc_net_n_slot=1024
num_user=8000
```
4. Done!

### Migrating files from database
Currently all data is saved at `./Zhenyu/dataset/data_saving` on OVH server. The naming of `m-5-1024-8000-160` means `multithread, 5 servers, 1024 talking and 8000 clients in total, 160 bytes per slot`.

We assume aggregator's `Public IPv4 DNS` is ec2-3-142-82-8.us-east-2.compute.amazonaws.com.

**DO**
1. Go to `./Zhenyu/dataset/` on OVH
2. typing following to terminal to migrate the file from database, to the aggregator AWS instance:
```shell
./migrate_finish_file.sh **Public IPv4 DNS** **folder name** **server number** **agg_state file number**

# for example, here
./migrate_finish_file.sh ec2-3-142-82-8.us-east-2.compute.amazonaws.com m-5-1024-8000-160 5 32
```

### Starting evaluation
Now all preparation is done, let's start evaluation!

**DO**

1. Go to `./script`. Setup local environment:
```shell
./dc-net-control.sh setup
```

2. Setup remote environment:
```shell
su ubuntu ./dc-net-control.sh set-rem
```

3. Start working:
```shell
# iteration means how many times you want to run
./dc-net-control.sh agg-eval-s **iteration**

# for example, we want to get the average of 10 times
./dc-net-control.sh agg-eval-s 10
```

4. After the previous step, fetching the recorder from the leader, the recorder is saved at `../server/time_recorder.txt`. **Make sure that there are $2\times iteration$ lines in the file.** Otherwise, re-run the process.

    Meanwhile, make sure that all timestamp in `../aggregator/time_recorder.txt` is well-recordered, in case two timestamp congest in one line.

```shell
# fetching back from leader
su ubuntu ./dc-net-control.sh send-back

```

5. calculate the result, the result is saved at `../server/result_time.txt`:
```shell
# calculating
./dc-net-control.sh cal_time
```
6. done!

### An addition question: how to generate new files instead of using existing files?
**DO**

1. Setup parameter as describe in [setting-parameter](#setting-parameter)

2. Go to `./script`. Setup local environment:
```shell
./dc-net-control.sh setup
```

3. Start working:
```shell
./dc-net-control.sh start
```

it will take long time for client to generate message. 
| slot number | running time | saving time | total file size |
| --- | --- | --- | --- |
| 2000 | 1h | 2min | 1.6G |
| 4000 | 2.5h | 6min | 6.4G |
| 8000 | 4h | 15min | 25.9G |

## 3 how to evaluate bandwidth?
### Evaluating the Physical Bandwidth
Using `ping` and `iperf` tools:
```shell
# ping
ping **target ip**
```

```shell
# server end
iperf -s

# client end
iperf -c **server_ip**
```

### Capturing the package in communication
Using `tcpdump` and `wireshark`. `tcpdump` will record all packages and save to `.pcap` file, then can use `wireshark` to analyze the package.
```shell
sudo tcpdump -i any -s 0 'port **port number**' -w **saving path or .pcap file**

# for example
sudo tcpdump -i any -s 0 'port 28942' -w ./log/output-1024.pcap
```
 