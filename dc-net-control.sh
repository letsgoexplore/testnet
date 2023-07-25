SERVER_IP=("3.15.148.53")
SERVER_AWS_COMMANDS=("ubuntu@ec2-3-15-148-53.us-east-2.compute.amazonaws.com")
SSH_PREFIX="ssh -t -i"
KEY_ADDRESS="./dc-net-test.pem"
TIME_LOG_ALL="server/time_recorder_all.txt"
GIT_REPO="https://github.com/letsgoexplore/testnet"
eval(){
    rm -f $TIME_LOG_ALL || true
    # num_users=("30" "60" "90" "120" "150" "180" "210")
    num_users=("150" "180" "210")
    num_leader=1
    # num_follower=("0" "3" "5" "7")
    num_follower=0
    num_server=$((num_leader + num_follower))
    num_aggregator=1
    dc_net_message_length=160
    # dc_net_n_slots=("10" "20" "30")
    # dc_net_n_slots=("20" "30" "40" "50")
    # dc_net_n_slots=("5" "10")
    # dc_net_message_lengths=("20" "40" "60" "80" "100" "120" "140" "160")
    echo "[settings]: aggregator: $num_aggregator, servers: $num_server" >> $TIME_LOG_ALL
    echo "[num_user]" >> $TIME_LOG_ALL
    echo "[entire time]" >> $TIME_LOG_ALL
    
    for num_user in "${num_users[@]}"; do
        echo "$num_user" >> $TIME_LOG_ALL
        dc_net_n_slot=$num_user
        update_clean_and_set_param_for_all $num_server $dc_net_message_length $dc_net_n_slot
        ./server_ctrl.sh setup_env $dc_net_message_length $dc_net_n_slot $num_server $num_user
        mitigate_server_state
        start_leader
        if [[ $num_follower -gt 0 ]]; then
            start_followers $num_follower
        fi
        ./server_ctrl.sh start_root_agg $num_server
        ./server_ctrl.sh test_multi_clients $num_user $dc_net_message_length
        cal_time
        stop-all
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
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND '
            cd dc-net/testnet
            git add origin $GIT_REPO
            git pull origin master
            chmod +x ./server_ctrl.sh
            cd  
            ./dc-net/testnet/server_ctrl.sh clean
            ./dc-net/testnet/server_ctrl.sh setup-param $dc_net_message_length $dc_net_n_slot
            exit
        '
    done
}

mitigate_server_state(){
    NUM_SERVERS=$1

    for i in $(seq 1 $NUM_SERVERS); do 
        LOCAL_ADDR="./server/server-state$2.txt"
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        TARGET_ADDR="$SERVER_AWS_COMMAND:./dc-net/testnet/server/server-state$2.txt"
        scp -i KEY_ADDRESS "$LOCAL_ADDR" "$TARGET_ADDR"
    done
}

start_leader(){
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND '
        cd dc-net/testnet/
        ./server_ctrl.sh start-leader
        cd
        exit
    '
}

start_follower(){
    num_follower=$1
    for i in $(seq 1 $num_follower); do
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$i]}
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND '
            cd dc-net/testnet/
            ./server_ctrl.sh start-follower $((i+1))
            cd
            exit
        '
    done
}

cal_time(){
    SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[0]}
    $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND '
        cd dc-net/testnet/
        python3 -c "from time_cal import time_cal; time_cal()"
        cd
        exit
    '
}

stop-all(){
    NUM_SERVERS=$1
    # clean server
    for i in $(seq 1 $NUM_SERVERS); do 
        SERVER_AWS_COMMAND=${SERVER_AWS_COMMANDS[$((i-1))]}
        $SSH_PREFIX $KEY_ADDRESS $SERVER_AWS_COMMAND '
            ./dc-net/testnet/server_ctrl.sh stop-all
            exit
        '
    done
}

if [[ $1 == "eval" ]]; then
    eval
fi