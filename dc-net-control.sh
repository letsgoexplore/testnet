#!/bin/bash
SERVER_IP=("18.188.164.240" "15.188.33.243" "54.177.208.2" "13.115.33.72" "34.222.93.229")
SERVER_AWS_COMMANDS=("ec2-18-188-164-240.us-east-2.compute.amazonaws.com" "ec2-15-188-33-243.eu-west-3.compute.amazonaws.com" "ec2-54-177-208-2.us-west-1.compute.amazonaws.com" "ec2-13-115-33-72.ap-northeast-1.compute.amazonaws.com" "ec2-34-222-93-229.us-west-2.compute.amazonaws.com")
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
    # 
    num_users=("2048")
    num_leader=1
    # num_follower=("0" "3" "5" "7")
    num_follower=4
    num_server=$((num_leader + num_follower))
    num_leaf_aggregator=32
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


step_1(){
    # remove the log_time_all file
    rm_time_log_all_at_leader
    rm -f $TIME_LOG_ALL || true
    dc_net_n_slot=$num_user
    update_code $num_server
    clean_all $num_server
    set_param $num_server $dc_net_message_length $dc_net_n_slot
    echo "finish 1"
}

step_2(){
    echo $num_user
    ./server_ctrl.sh setup-env $dc_net_message_length $dc_net_n_slot $num_server $num_user
    echo "finish 2"
}

step_3(){
    mitigate_server_state $num_server
}

step_4(){
    ./server_ctrl.sh start-agg $num_server
    # echo "finish 6"
    ./server_ctrl.sh multi $num_user $dc_net_message_length
}

step_5(){
    cal_time $num_server $num_aggregator $num_user $dc_net_message_length
    send_back
    stop_all
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
        KEY_ADDRESS="pem_key/ss$i.pem"
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            chmod +x '$WORKING_ADDR/server_ctrl_multithread.sh'
            cd $WORKING_ADDR
            ./server_ctrl_multithread.sh clean
            cd
            exit
        "
    done
}

set_param(){
    NUM_SERVERS=$1
    dc_net_message_length=$2
    dc_net_n_slot=$3
    num_user=$4
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            chmod +x '$WORKING_ADDR/server_ctrl_multithread.sh'
            cd $WORKING_ADDR
            ./server_ctrl_multithread.sh setup-param $dc_net_message_length $dc_net_n_slot $num_user
            cd
            exit
        "
    done
}

update_code(){
    NUM_SERVERS=$1
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        KEY_ADDRESS="pem_key/ss$i.pem"
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            cd $WORKING_ADDR
            git config pull.rebase true
            git pull
            cd
            exit
        "
    done
}

update_clean_and_set_param_for_all(){
    NUM_SERVERS=$1
    dc_net_message_length=$2
    dc_net_n_slot=$3
    # clean local
    ./server_ctrl.sh clean
    # update and clean server 
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            chmod +x ./dc-net/testnet/server_ctrl.sh
            echo 'before clean'
            cd ./dc-net/testnet
            ./server_ctrl.sh clean
            echo 'clean server'
            ./server_ctrl.sh setup-param $dc_net_message_length $dc_net_n_slot
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
        KEY_ADDRESS="pem_key/ss$i.pem"
        scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$TARGET_ADDR"
        echo "success! address:$TARGET_ADDR"
    done
}

start_leader(){
    dc_net_message_length=$1
    dc_net_n_slot=$2
    num_users=$3
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    KEY_ADDRESS="pem_key/ss1.pem"
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
        KEY_ADDRESS="pem_key/ss$((i+1)).pem"
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
    # start_leader $dc_net_message_length $dc_net_n_slot $num_users
    # start_follower $num_follower $dc_net_message_length $dc_net_n_slot $num_users
    # echo "start followers"
}

agg_eval(){
    ./server_ctrl_multithread.sh stop-all
    ./server_ctrl_multithread.sh start-agg
    sleep 3
    ./server_ctrl_multithread.sh agg-eval
}

# force_root_round_end() {


# }

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
    TARGET_ADDR=$TIME_LOG_ALL
    SOURCE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/$TIME_LOG_ALL"
    scp -i $KEY_ADDRESS "$SOURCE_ADDR" "$TARGET_ADDR"
    echo "success! address:$TARGET_ADDR"
}

# send_back_from_remote_aggregator(){
#     SEQ=$1
#     SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$SEQ]}
#     TARGET_ADDR=""
#     SOURCE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/$TIME_LOG_ALL"
# }

stop_all(){
    NUM_SERVERS=$1
    ./server_ctrl.sh stop-all
    stop_remote $NUM_SERVERS
}

stop_remote(){
    NUM_SERVERS=$1
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        KEY_ADDRESS="pem_key/ss$i.pem"
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND "
            cd $WORKING_ADDR
            ./server_ctrl_multithread.sh stop-all
            cd
            exit
        "
    done
}

if [[ $1 == "eval" ]]; then
    eval
elif [[ $1 == "eval-m" ]]; then
    eval_multi
elif [[ $1 == "1" ]]; then
    step_1
elif [[ $1 == "2" ]]; then
    step_2
elif [[ $1 == "3" ]]; then
    step_3
elif [[ $1 == "4" ]]; then
    step_4
elif [[ $1 == "set-rem" ]]; then
    # follower length slot user
    setup_remote $2 $3 $4 $5
elif [[ $1 == "agg-eval" ]]; then
    agg_eval
elif [[ $1 == "clean" ]]; then
    clean_all ${#SERVER_IP[@]}
elif [[ $1 == "clean-rem" ]]; then
    clean_remote ${#SERVER_IP[@]}    
elif [[ $1 == "update" ]]; then
    update_code ${#SERVER_IP[@]}
elif [[ $1 == "set-param" ]]; then
    set_param $2 $3 $4 $5
elif [[ $1 == "mitigate" ]]; then
    mitigate_server_state ${#SERVER_IP[@]}
elif [[ $1 == "start-leader" ]]; then
    start_leader $2 $3 $4
elif [[ $1 == "start-follower" ]]; then
    start_follower $2 $3 $4 $5
elif [[ $1 == "cal-time" ]]; then
    cal_time $2 $3 $4 $5
elif [[ $1 == "cal-leader" ]]; then
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
