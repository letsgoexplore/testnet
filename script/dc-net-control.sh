#!/bin/bash

# SSH Info
SERVER_IPS=("3.140.248.195" "13.38.37.45" "54.176.5.119" "43.207.114.246" "34.221.6.203")
SERVER_AWS_COMMANDS=("ec2-3-140-248-195.us-east-2.compute.amazonaws.com" "ec2-13-38-37-45.eu-west-3.compute.amazonaws.com" "ec2-54-176-5-119.us-west-1.compute.amazonaws.com" "ec2-43-207-114-246.ap-northeast-1.compute.amazonaws.com" "ec2-34-221-6-203.us-west-2.compute.amazonaws.com")
AGG_AWS_COMMAND="ec2-18-218-37-219.us-east-2.compute.amazonaws.com"
SSH_PREFIX="ssh -t -i"
KEY_ADDRESS="./pem_key/dc-net-test.pem"
REMOTE_SERVER_KEY_PREFIX="./pem_key/ss"
REMOTE_SERVER_KEY_POSTFIX=".pem"

# Working File
WORKING_ADDR="./testnet"
AGG_DATA="../aggregator/data_collection.txt"
ERROR_LOG="../aggregator/error.txt"
SUCCESS_LOG="../aggregator/success.txt"

# Log
TIME_LOG_ALL="../server/time_recorder_all.txt"
TIME_LOG="server/time_recorder.txt"
CLINET_TIME_LOG="../client/time_recorder.txt"

# Settings
THREAD_NUM=16
is_WAN=1
is_EVALUATION=1
num_leader=1
num_follower=4
num_server=$((num_leader + num_follower))
num_leaf_aggregator=16
dc_net_message_length=160
dc_net_n_slot=16
num_user=16

footprint_n_slots=$(expr 4 \* $dc_net_n_slot)
export DC_NUM_USER=$num_user
export DC_NET_MESSAGE_LENGTH=$dc_net_message_length
export DC_NET_N_SLOTS=$dc_net_n_slot
export FOOTPRINT_N_SLOTS=$footprint_n_slots
export RUSTFLAGS="-Ctarget-feature=+aes,+ssse3"

# locally setup
# including:
# 1. clean the environment, setup the parameter
# 2. generating state file for client, aggregator,
setup(){
    # step 1: clean files
    rm -f $TIME_LOG_ALL || true
    rm -f $AGG_DATA || true
    ./server_ctrl_multithread.sh stop-all
    ./server_ctrl_multithread.sh clean

    # step 2: setup environment
    ./server_ctrl_multithread.sh setup-env $dc_net_message_length $dc_net_n_slot $num_server $num_user
    touch $ERROR_LOG
    touch $SUCCESS_LOG
    sleep 1
    echo "finish 3:  setup environment"
}

# setup remote AWS environment
# including deleting previous file, updating code from github, moving the server_state to AWS, starting working
setup_remote(){
    num_follower="${1:-$num_follower}"
    dc_net_message_length="${2:-$dc_net_message_length}"
    dc_net_n_slot="${3:-$dc_net_n_slot}"
    num_user="${4:-$num_user}"
    clean_remote ${#SERVER_IPS[@]}
    update_code ${#SERVER_IPS[@]}
    migrate_server_state ${#SERVER_IPS[@]}
    start_leader $dc_net_message_length $dc_net_n_slot $num_user
    start_follower $num_follower $dc_net_message_length $dc_net_n_slot $num_user
    # echo "start followers"
}

# start working
# 1. if in normal mode, the code will executing one round
# 2. if in evaluation mode, the client will send to aggregator, and aggregator will save the msg. 
#    But not doing the folloing steps.
start_working(){
    ./server_ctrl_multithread.sh start-agg $num_server
    ./server_ctrl_multithread.sh multi $num_user $dc_net_message_length $dc_net_n_slot
}

# [onlyevaluation] this is for client_evaluation
client_eval(){
    num_server=5
    # num_servers=("1" "5" "8" "10" "16" "32" "64" "128" "256" "512" "1024")
    num_leaf_aggregator=16
    num_user=1024
    dc_net_n_slot=1024
    dc_net_message_lengths=("160" "252" "500" "1000" "2000")
    # dc_net_message_lengths=("160")
    # dc_net_message_length=160
    
    for dc_net_message_length in "${dc_net_message_lengths[@]}"; do
    # for num_server in "${num_servers[@]}"; do
        ./server_ctrl_multithread.sh stop-all
        echo "dc_net_message_length: $dc_net_message_length" >> $CLINET_TIME_LOG
        # echo "num_server: $num_server" >> $CLINET_TIME_LOG
        footprint_n_slots=$(expr 4 \* $dc_net_n_slot)
        export DC_NUM_USER=$num_user
        export DC_NET_MESSAGE_LENGTH=$dc_net_message_length
        export DC_NET_N_SLOTS=$dc_net_n_slot
        export FOOTPRINT_N_SLOTS=$footprint_n_slots
        export RUSTFLAGS="-Ctarget-feature=+aes,+ssse3"
        ./server_ctrl_multithread.sh clean
        ./server_ctrl_multithread.sh client-eval $dc_net_message_length $dc_net_n_slot $num_server $num_user
    done
}

# clean up local state files and log files
clean_local(){
    ./server_ctrl_multithread.sh clean
}

# clean remote AWS state files and log files
clean_remote(){
    NUM_SERVERS="${1:-$num_server}"
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        SERVER_IP=${SERVER_IPS[$((i-1))]}
        if [ $is_WAN -eq 1 ]; then 
            KEY_ADDRESS="./pem_key/ss$i.pem"
        fi
        # ssh-keygen -R $SERVER_IP
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            cd $WORKING_ADDR/script
            chmod +x './server_ctrl_multithread.sh'
            ./server_ctrl_multithread.sh clean
            cd
            exit
        "
    done
}

# update remote AWS's code
update_code(){
    NUM_SERVERS="${1:-$num_server}"
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        if [ $is_WAN -eq 1 ]; then 
            KEY_ADDRESS="./pem_key/ss$i.pem"
        fi
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            cd $WORKING_ADDR
            git pull origin master
            # git fetch origin master
            # git reset --hard origin/master
            cd
            exit
        "
    done
}

# mitigating the server_state file to remote AWS
# this is because, the state file is generated locally
migrate_server_state(){
    NUM_SERVERS="${1:-$num_server}"
    for i in $(seq 1 $NUM_SERVERS); do 
        LOCAL_ADDR="../server/server-state$i.txt"
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        TARGET_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
        if [ $is_WAN -eq 1 ]; then 
            chmod 400 "./pem_key/ss$i.pem"
            KEY_ADDRESS="./pem_key/ss$i.pem"
        fi
        scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$TARGET_ADDR"
        echo "success! address:$TARGET_ADDR"
    done
}

start_leader(){
    dc_net_message_length=$1
    dc_net_n_slot=$2
    num_users=$3
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    if [ $is_WAN -eq 1 ]; then 
        KEY_ADDRESS="./pem_key/ss1.pem"
    fi
    $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
        source ~/.bashrc
        cd $WORKING_ADDR
        docker start dcnet-5
        docker exec -di dcnet-5 /bin/bash -c \"export PATH=/root/.cargo/bin:$PATH; cd sgx; \
        ./script/server_ctrl_multithread.sh stop-all;\
        nohup ./script/server_ctrl_multithread.sh start-leader $dc_net_message_length $dc_net_n_slot $num_users > /dev/null 2>&1 &\"
        cd
        echo \"start leader\"
    "
}

start_follower(){
    num_follower=$1
    dc_net_message_length=$2
    dc_net_n_slot=$3
    num_users=$4
    
    for i in $(seq 1 $num_follower); do
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$i]}
        if [ $is_WAN -eq 1 ]; then 
            KEY_ADDRESS="./pem_key/ss$((i+1)).pem"
        fi
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            source ~/.bashrc
            cd $WORKING_ADDR
            docker start dcnet-5
            docker exec -di dcnet-5 /bin/bash -c \"export PATH=/root/.cargo/bin:$PATH; cd sgx; \
            ./script/server_ctrl_multithread.sh stop-all;\
            nohup ./script/server_ctrl_multithread.sh start-follower $((i+1)) $dc_net_message_length $dc_net_n_slot $num_users > /dev/null 2>&1 &\"
            cd
            echo \"start follower $((i+1))\"
        "
    done
}

# [onlyevaluation] reading from existing msg-file, and output to the server
agg_eval(){
    ./server_ctrl_multithread.sh stop-all
    ./server_ctrl_multithread.sh start-agg
    sleep 3
    ./server_ctrl_multithread.sh agg-eval
}

# [onlyevaluation] iteratively executing the `agg_eval` function, to get the average
agg_eval_several(){
    iter=$1
    num_follower="${2:-$num_follower}"
    dc_net_message_length="${3:-$dc_net_message_length}"
    dc_net_n_slot="${4:-$dc_net_n_slot}"
    num_user="${5:-$num_user}"
    for i in $(seq 1 $iter); do
        agg_eval
        sleep 40
        su ubuntu ./dc-net-control.sh start_leader $dc_net_message_length $dc_net_n_slot $num_user
        su ubuntu ./dc-net-control.sh start_follower $num_follower $dc_net_message_length $dc_net_n_slot $num_user
    done
}

# [onlyevaluation] calculate the matric of a round, using python
cal_time(){
    num_server="${1:-$num_server}"
    num_aggregator="${2:-$num_leaf_aggregator}"
    num_user="${3:-$num_user}"
    dc_net_message_length="${4:-$dc_net_message_length}"
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
        cd $WORKING_ADDR/script
        echo '[settings]: aggregator: $num_aggregator, servers: $num_server, num_user: $num_user, dc_net_message_length: $dc_net_message_length' >> $TIME_LOG_ALL
        python3 -c 'from time_cal import time_cal; time_cal()'
        cd
        exit
    "
}

# [onlyevaluation] send back leader's time_log
send_back(){
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    TARGET_ADDR=../$TIME_LOG
    SOURCE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/$TIME_LOG"
    scp -i $KEY_ADDRESS "$SOURCE_ADDR" "$TARGET_ADDR"
    echo "success! address:$TARGET_ADDR"
}

# remove the time log at leader
rm_time_log_all_at_leader(){
    echo "deleting leader's time_log_all"
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
        cd $WORKING_ADDR
        rm -f $TIME_LOG_ALL || true
        echo haah
        cd
        exit
    "
}

# stop locally
stop_all(){
    ./server_ctrl_multithread.sh stop-all
}

# stop remotely
stop_remote(){
    NUM_SERVERS=$1
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        if [ $is_WAN -eq 1 ]; then 
            KEY_ADDRESS="./pem_key/ss$i.pem"
        fi
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            cd $WORKING_ADDR
            ./server_ctrl_multithread.sh stop-all
            cd
            exit
        "
    done
}

# this is to set the key being read-only
authorize_key(){
    num_server="${1:-$num_server}"
    for i in $(seq 1 $num_server); do
        KEY_ADDRESS="./pem_key/ss$i.pem"
        chmod 400 $KEY_ADDRESS
    done 
}

eval_all(){
    num_follower=$1
    num_server=$((num_follower+1))
    dc_net_message_length=$2
    dc_net_n_slot=$3
    num_users=$4

    $SSH_PREFIX $KEY_ADDRESS $AGG_AWS_COMMAND "
        source ~/.bashrc
        cd $WORKING_ADDR
        ./script/server_ctrl_multithread.sh clean;
    "

    echo "sending from database/m-$num_server-$dc_net_n_slot-$num_users-$dc_net_message_length"
    ./migrate_finish_file.sh fromdatabase $AGG_AWS_COMMAND "m-$num_server-$dc_net_n_slot-$num_users-$dc_net_message_length" $num_server $THREAD_NUM

    $SSH_PREFIX $KEY_ADDRESS $AGG_AWS_COMMAND "
        source ~/.bashrc
        cd testnet1
        git pull
        docker start dcnet-5
        docker exec -di dcnet-5 /bin/bash -c \"export PATH=/root/.cargo/bin:$PATH; cd sgx;\
        echo haha;\
        nohub su ubuntu ./dc-net-control.sh set-rem $num_follower $dc_net_message_length $dc_net_n_slot $num_users;\
        nohub for i in {1..5}
        do  
            ./dc-net-control.sh agg-eval
            if [ $num_users -gt 4000 ]; then
                sleep 40
            else
                sleep 20
            fi
        done;\
        nohub su ubuntu ./dc-net-control.sh send-back;\
        echo \"finish sending back\";\
        nohub ./server_ctrl_multithread.sh cal-time;\
        echo \"finish calculating time\" \"
    "
    sleep 120
    ./migrate_finish_file.sh send-back-recorder $AGG_AWS_COMMAND "m-$num_server-$dc_net_n_slot-$num_users-$dc_net_message_length" $num_server $THREAD_NUM
}

if [[ $1 == "setup" ]]; then
    setup
elif [[ $1 == "eval-all" ]]; then
    # follower slot_length slot_num user_num
    eval_all $2 $3 $4 $5
elif [[ $1 == "eval-c" ]]; then
    client_eval
elif [[ $1 == "set-rem" ]]; then
    # remember to "su ubuntu"
    # follower slot_length slot_num user_num(all have default)
    setup_remote $2 $3 $4 $5
elif [[ $1 == "start" ]]; then
    start_working
elif [[ $1 == "agg-eval" ]]; then
    agg_eval
elif [[ $1 == "agg-eval-s" ]]; then
    # iteration_num follower slot_length slot_num user_num(all have default)
    agg_eval_several $2 $3 $4 $5 $6
elif [[ $1 == "clean" ]]; then
    clean_local
elif [[ $1 == "clean-rem" ]]; then
    clean_remote $num_server   
elif [[ $1 == "update" ]]; then
    update_code $num_server
elif [[ $1 == "migrate" ]]; then
    migrate_server_state $num_server
elif [[ $1 == "start-leader" ]]; then
    # slot_length slot_num user_num
    start_leader $2 $3 $4
elif [[ $1 == "start-follower" ]]; then
    # follower slot_length slot_num user_num
    start_follower $2 $3 $4 $5
elif [[ $1 == "cal-time" ]]; then
    # server_num agg_num user_num slot_length
    cal_time $2 $3 $4 $5
elif [[ $1 == "cal-leader" ]]; then
    # server_num agg_num user_num slot_length
    cal_leader $2 $3 $4 $5
elif [[ $1 == "send-back" ]]; then
    send_back
elif [[ $1 == "stop-all" ]]; then
    stop_all $num_server
elif [[ $1 == "stop-rem" ]]; then
    stop_remote $num_server
elif [[ $1 == "authorize" ]]; then
    # server_num(default)
    authorize_key $2
elif [[ $1 == "rm-leader-time-log" ]]; then
    rm_time_log_all_at_leader
elif [[ $1 == "resend" ]]; then
    ./server_ctrl.sh setup-param
    ./server_ctrl.sh resend
else
    echo "no commad match"
fi
