#!/bin/bash
SERVER_IP=("18.221.165.58" "18.220.71.193" "3.145.130.160" "3.142.244.232" "18.118.14.115" "52.15.215.11" "18.218.97.222" "18.117.130.105" "3.138.173.127" "3.135.64.245")
SERVER_AWS_COMMANDS=("ec2-18-221-165-58.us-east-2.compute.amazonaws.com" "ec2-18-220-71-193.us-east-2.compute.amazonaws.com" "ec2-3-145-130-160.us-east-2.compute.amazonaws.com" "ec2-3-142-244-232.us-east-2.compute.amazonaws.com" "ec2-18-118-14-115.us-east-2.compute.amazonaws.com" "ec2-52-15-215-11.us-east-2.compute.amazonaws.com" "ec2-18-218-97-222.us-east-2.compute.amazonaws.com" "ec2-18-117-130-105.us-east-2.compute.amazonaws.com" "ec2-3-138-173-127.us-east-2.compute.amazonaws.com" "ec2-3-135-64-245.us-east-2.compute.amazonaws.com")
AGG_AWS_COMMAND="ec2-52-15-94-176.us-east-2.compute.amazonaws.com"
SSH_PREFIX="ssh -t -i"
KEY_ADDRESS="./dc-net-test.pem"
TIME_LOG_ALL="server/time_recorder_all.txt"
GIT_REPO="https://github.com/letsgoexplore/testnet"
WORKING_ADDR="./testnet"
TIME_LOG="server/time_recorder.txt"
TIME_LOG_ALL="server/time_recorder_all.txt"
AGG_DATA="aggregator/data_collection.txt"
ERROR_LOG="aggregator/error.txt"
SUCCESS_LOG="aggregator/success.txt"
CLINET_TIME_LOG="client/time_recorder.txt"
THREAD_NUM=32
is_WAN=0
# num_user=10
# num_leader=1
# # num_follower=("0" "3" "5" "7")
# num_follower=4
# num_server=$((num_leader + num_follower))
# num_aggregator=1
# dc_net_message_length=160


eval_multi(){
    # remove the log_time_all file
    su ubuntu ./dc-net-control.sh rm-leader-time-log
    rm -f $TIME_LOG_ALL || true
    rm -f $AGG_DATA || true
    # num_users=("30" "60" "90" "120" "150" "180" "210")
    num_users=("4000")
    num_leader=1
    # num_follower=("0" "3" "5" "7")
    num_follower=9
    num_server=$((num_leader + num_follower))
    num_leaf_aggregator=32
    dc_net_message_length=160
    dc_net_n_slot=1024
    # dc_net_n_slots=("10" "20" "30")
    # dc_net_n_slots=("20" "30" "40" "50")
    # dc_net_n_slots=("5" "10")
    # dc_net_message_lengths=("20" "40" "60" "80" "100" "120" "140" "160")
    
    for num_user in "${num_users[@]}"; do
        ./server_ctrl_multithread.sh stop-all
        footprint_n_slots=$(expr 4 \* $dc_net_n_slot)
        export DC_NUM_USER=$num_user
        export DC_NET_MESSAGE_LENGTH=$dc_net_message_length
        export DC_NET_N_SLOTS=$dc_net_n_slot
        export FOOTPRINT_N_SLOTS=$footprint_n_slots
        export RUSTFLAGS="-Ctarget-feature=+aes,+ssse3"
        # su ubuntu ./dc-net-control.sh update
        # su ubuntu ./dc-net-control.sh clean
        # su ubuntu ./dc-net-control.sh set-param $num_server $dc_net_message_length $dc_net_n_slot $num_user
        echo "finish 1"
        ./server_ctrl_multithread.sh clean
        ./server_ctrl_multithread.sh setup-env $dc_net_message_length $dc_net_n_slot $num_server $num_user
        touch $ERROR_LOG
        touch $SUCCESS_LOG
        echo "finish 2"
        sleep 1
        # su ubuntu ./dc-net-control.sh mitigate
        echo "finish 3"
        sleep 1
        # su - ubuntu -c ./dc-net-control.sh start-leader
        # echo "finish 4"
        # sleep 100
        # if [[ $num_follower -gt 0 ]]; then
        #     su - ubuntu -c ./dc-net-control.sh start-followers $num_follower
        #     echo "finish 5"
        # fi
        ./server_ctrl_multithread.sh start-agg $num_server
        echo "finish 6"
        ./server_ctrl_multithread.sh multi $num_user $dc_net_message_length $dc_net_n_slot
        sleep 3
        # su - ubuntu ./dc-net-control.sh cal-time $num_server $num_aggregator $num_user $dc_net_message_length
        # su - ubuntu ./dc-net-control.sh send-back
        # su - ubuntu ./dc-net-control.sh stop-all
    done
}


eval(){
    # remove the log_time_all file
    su ubuntu ./dc-net-control.sh rm-leader-time-log
    rm -f $TIME_LOG_ALL || true
    rm -f $AGG_DATA || true
    # num_users=("30" "60" "90" "120" "150" "180" "210")
    # 
    num_users=("4000")
    num_leader=1
    # num_follower=("0" "3" "5" "7")
    num_follower=4
    num_server=$((num_leader + num_follower))
    num_aggregator=1
    dc_net_message_length=160
    dc_net_n_slot=1024
    # dc_net_n_slots=("10" "20" "30")
    # dc_net_n_slots=("20" "30" "40" "50")
    # dc_net_n_slots=("5" "10")
    # dc_net_message_lengths=("20" "40" "60" "80" "100" "120" "140" "160")
    
    for num_user in "${num_users[@]}"; do
        footprint_n_slots=$(expr 4 \* $dc_net_n_slot)
        export DC_NUM_USER=$num_user
        export DC_NET_MESSAGE_LENGTH=$dc_net_message_length
        export DC_NET_N_SLOTS=$dc_net_n_slot
        export FOOTPRINT_N_SLOTS=$footprint_n_slots
        export RUSTFLAGS="-Ctarget-feature=+aes,+ssse3"
        # su ubuntu ./dc-net-control.sh update
        # su ubuntu ./dc-net-control.sh clean
        # su ubuntu ./dc-net-control.sh set-param $num_server $dc_net_message_length $dc_net_n_slot $num_user
        echo "finish 1"
        ./server_ctrl.sh clean
        ./server_ctrl.sh setup-env $dc_net_message_length $dc_net_n_slot $num_server $num_user
        touch $ERROR_LOG
        touch $SUCCESS_LOG
        echo "finish 2"
        sleep 1
        # su ubuntu ./dc-net-control.sh mitigate
        echo "finish 3"
        sleep 1
        # su - ubuntu -c ./dc-net-control.sh start-leader
        # echo "finish 4"
        # sleep 100
        # if [[ $num_follower -gt 0 ]]; then
        #     su - ubuntu -c ./dc-net-control.sh start-followers $num_follower
        #     echo "finish 5"
        # fi
        ./server_ctrl.sh start-agg $num_server
        echo "finish 6"
        ./server_ctrl.sh multi $num_user $dc_net_message_length $dc_net_n_slot
        sleep 3
        # su - ubuntu ./dc-net-control.sh cal-time $num_server $num_aggregator $num_user $dc_net_message_length
        # su - ubuntu ./dc-net-control.sh send-back
        # su - ubuntu ./dc-net-control.sh stop-all
    done
}

client_eval(){
    su ubuntu ./dc-net-control.sh rm-leader-time-log
    rm -f $TIME_LOG_ALL || true
    rm -f $AGG_DATA || true
    # num_users=("30" "60" "90" "120" "150" "180" "210")
    num_user=1024
    num_leader=1
    num_servers=("32" "64" "128" "256" "512" "1024")
    num_leaf_aggregator=32
    # dc_net_message_length=160
    dc_net_n_slot=1024
    # dc_net_message_lengths=("160" "250" "500" "1000" "2000")
    dc_net_message_length=160
    
    # for dc_net_message_length in "${dc_net_message_lengths[@]}"; do
    for num_server in "${num_servers[@]}"; do
        ./server_ctrl_multithread.sh stop-all
        # echo "dc_net_message_length: $dc_net_message_length" >> $CLINET_TIME_LOG
        echo "num_server: $num_server" >> $CLINET_TIME_LOG
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

clean_all(){
    NUM_SERVERS=$1
    ./server_ctrl.sh clean
    # update and clean server 
    clean_remote $NUM_SERVERS
}

clean_remote(){
    NUM_SERVERS=$1
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        if [ $is_WAN -eq 1 ]; then 
            KEY_ADDRESS="pem_key/ss$i.pem"
        fi
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            chmod +x '$WORKING_ADDR/server_ctrl_multithread.sh'
            cd $WORKING_ADDR
            ./server_ctrl_multithread.sh clean
            cd
            exit
        "
    done
}

update_code(){
    NUM_SERVERS=$1
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        if [ $is_WAN -eq 1 ]; then 
            KEY_ADDRESS="pem_key/ss$i.pem"
        fi
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            cd $WORKING_ADDR
            git pull
            # git fetch origin master
            # git reset --hard origin/master
            cd
            exit
        "
    done
}

mitigate_server_state(){
    NUM_SERVERS=$1

    for i in $(seq 1 $NUM_SERVERS); do 
        LOCAL_ADDR="./server/server-state$i.txt"
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        TARGET_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
        chmod 400 "pem_key/ss$i.pem"
        if [ $is_WAN -eq 1 ]; then 
            KEY_ADDRESS="pem_key/ss$i.pem"
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
            KEY_ADDRESS="pem_key/ss1.pem"
    fi
    $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
        source ~/.bashrc
        cd testnet
        docker start dcnet-5
        docker exec -di dcnet-5 /bin/bash -c \"export PATH=/root/.cargo/bin:$PATH; cd sgx; \
        ./server_ctrl_multithread.sh stop-all;\
        nohup ./server_ctrl_multithread.sh start-leader $dc_net_message_length $dc_net_n_slot $num_users > /dev/null 2>&1 &\"
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
            KEY_ADDRESS="pem_key/ss$((i+1)).pem"
        fi
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            source ~/.bashrc
            cd testnet
            docker start dcnet-5
            docker exec -di dcnet-5 /bin/bash -c \"export PATH=/root/.cargo/bin:$PATH; cd sgx; \
            ./server_ctrl_multithread.sh stop-all;\
            nohup ./server_ctrl_multithread.sh start-follower $((i+1)) $dc_net_message_length $dc_net_n_slot $num_users > /dev/null 2>&1 &\"
            cd
            echo \"start follower $((i+1))\"
        "
    done
}

cal_leader(){
    rm -f $TIME_LOG_ALL || true
    rm -f 
    su ubuntu ./dc-net-control.sh rm-leader-time-log
    num_server=$1
    num_aggregator=$2
    num_user=$3
    dc_net_message_length=$4
    cal_time $1 $2 $3 $4
    send_back
}

setup_remote(){
    num_follower=$1
    dc_net_message_length=$2
    dc_net_n_slot=$3
    num_users=$4
    clean_remote ${#SERVER_IP[@]}
    update_code ${#SERVER_IP[@]}
    mitigate_server_state ${#SERVER_IP[@]}
    start_leader $dc_net_message_length $dc_net_n_slot $num_users
    start_follower $num_follower $dc_net_message_length $dc_net_n_slot $num_users
    # echo "start followers"
}

start_exp(){
    num_follower=$1
    dc_net_message_length=$2
    dc_net_n_slot=$3
    num_users=$4
    start_leader $dc_net_message_length $dc_net_n_slot $num_users
    start_follower $num_follower $dc_net_message_length $dc_net_n_slot $num_users
    agg_eval
}

agg_eval(){
    ./server_ctrl_multithread.sh stop-all
    ./server_ctrl_multithread.sh start-agg
    sleep 3
    ./server_ctrl_multithread.sh agg-eval
}

cal_time(){
    num_server=$1
    num_aggregator=$2
    num_user=$3
    dc_net_message_length=$4
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
        cd $WORKING_ADDR
        echo '[settings]: aggregator: $num_aggregator, servers: $num_server, num_user: $num_user, dc_net_message_length: $dc_net_message_length' >> $TIME_LOG_ALL
        python3 -c 'from time_cal import time_cal; time_cal()'
        cd
        exit
    "
}

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

send_back(){
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    TARGET_ADDR=$TIME_LOG
    SOURCE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/$TIME_LOG"
    scp -i $KEY_ADDRESS "$SOURCE_ADDR" "$TARGET_ADDR"
    echo "success! address:$TARGET_ADDR"
}

stop_all(){
    NUM_SERVERS=$1
    ./server_ctrl.sh stop-all
    stop_remote $NUM_SERVERS
}

stop_remote(){
    NUM_SERVERS=$1
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        if [ $is_WAN -eq 1 ]; then 
            KEY_ADDRESS="pem_key/ss$i.pem"
        fi
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            cd $WORKING_ADDR
            ./server_ctrl_multithread.sh stop-all
            cd
            exit
        "
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
        cd testnet1
        ./server_ctrl_multithread.sh clean;
    "

    echo "sending from database/m-$num_server-$dc_net_n_slot-$num_users-$dc_net_message_length"
    ./mitigate_finish_file.sh fromdatabase $AGG_AWS_COMMAND "m-$num_server-$dc_net_n_slot-$num_users-$dc_net_message_length" $num_server $THREAD_NUM

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
    ./mitigate_finish_file.sh send-back-recorder $AGG_AWS_COMMAND "m-$num_server-$dc_net_n_slot-$num_users-$dc_net_message_length" $num_server $THREAD_NUM
}

if [[ $1 == "eval" ]]; then
    eval
elif [[ $1 == "eval-m" ]]; then
    eval_multi
elif [[ $1 == "eval-all" ]]; then
    # follower slot_length slot_num user_num
    eval_all $2 $3 $4 $5
elif [[ $1 == "eval-c" ]]; then
    client_eval
elif [[ $1 == "set-rem" ]]; then
    # follower slot_length slot_num user_num
    setup_remote $2 $3 $4 $5
elif [[ $1 == "start-exp" ]]; then
    start_exp $2 $3 $4 $5
elif [[ $1 == "agg-eval" ]]; then
    agg_eval
elif [[ $1 == "clean" ]]; then
    clean_all ${#SERVER_IP[@]}
elif [[ $1 == "clean-rem" ]]; then
    clean_remote ${#SERVER_IP[@]}    
elif [[ $1 == "update" ]]; then
    update_code ${#SERVER_IP[@]}
elif [[ $1 == "mitigate" ]]; then
    mitigate_server_state ${#SERVER_IP[@]}
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
    stop_all ${#SERVER_IP[@]}
elif [[ $1 == "stop-rem" ]]; then
    stop_remote ${#SERVER_IP[@]}
elif [[ $1 == "rm-leader-time-log" ]]; then
    rm_time_log_all_at_leader
elif [[ $1 == "resend" ]]; then
    ./server_ctrl.sh setup-param
    ./server_ctrl.sh resend
else
    echo "no commad match"
fi
