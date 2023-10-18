#!/bin/bash

USER_STATE="../client/user-state.txt"
AGG_FINALAGG="../aggregator/final-agg.txt"
AGG_ROOTSTATE="../aggregator/agg-root-state.txt"
AGG_STATE_PREFIX="../aggregator/agg_state_"
SERVER_STATE="../server/server-state.txt"
SERVER_SHARES="../server/shares.txt"
SERVER_SHARES_PARTIAL="../server/partial_shares.txt"

USER_SERVERKEYS="../client/server-keys.txt"
AGG_SERVERKEYS="../aggregator/server-keys.txt"

CLIENT_MESSAGE="../client/message/clientmessage.txt"
AGG_DATA="../aggregator/data_collection.txt"
ERROR_LOG="../aggregator/error.txt"
SUCCESS_LOG="../aggregator/success.txt"
SERVER_ROUNDOUTPUT="../server/round_output.txt"

CLINET_TIME_LOG="../client/time_recorder.txt"
AGG_TIME_LOG="../aggregator/time_recorder.txt"
AGG_DETAILED_LOG="../aggregator/time_recorder_detailed_timestamp.txt"
SERVER_TIME_LOG="../server/time_recorder.txt"
RESULT_TIME="../server/result_time.txt"

CLIENT_SERVICE_PORT="9330"
AGGREGATOR_PORT="18300"
SERVER_PORT="28942"
SERVER_IP=("3.137.191.31" "13.38.37.45" "54.176.5.119" "43.207.114.246" "34.221.6.203")

# CMD_PREFIX="cargo run --release -- "
# [onlytest]
CMD_PREFIX="cargo run -- "

SERVER_CMD_PREFIX="/home/ubuntu/.cargo/bin/cargo cargo run -- "
# Assume wlog that the leading anytrust node is the first one
ROUND=0
ROUND_DURATION=100000
THREAD_NUM=16
LOG_TYPE=debug

log_time() {
    timestamp=$(date +%s%N)
    echo "$timestamp" >> $SERVER_TIME_LOG
}

clean() {
    # The below pattern removes all files of the form "client/user-stateX.txt" for any X
    rm -f ${USER_STATE%.txt}*.txt || true
    rm -f $USER_SERVERKEYS || true
    # rm -f ${AGG_STATE%.txt}*.txt || true
    rm -f $AGG_ROOTSTATE || true
    rm -f $AGG_SERVERKEYS || true
    rm -f $AGG_FINALAGG || true
    rm -f ${SERVER_STATE%.txt}*.txt || true
    rm -f $SERVER_SHARES || true
    rm -f $SERVER_SHARES_PARTIAL || true
    rm -f ${SERVER_ROUNDOUTPUT%.txt}*.txt || true
    rm -f ${CLIENT_MESSAGE%.txt}*.txt || true
    rm -f $SERVER_TIME_LOG || true
    rm -f $ERROR_LOG || true
    rm -f $SUCCESS_LOG || true
    rm -f $AGG_STATE_PREFIX*.txt || true
    rm -f ${AGG_DATA%.txt}*.txt || true
    rm -f $AGG_TIME_LOG || true
    rm -f $RESULT_TIME || true
    rm -f $AGG_DETAILED_LOG || true
    echo "Cleaned"
}

# build() {
#     make -C enclave
#     for d in "client" "server" "aggregator"; do
#         pushd $d && cargo build && popd
#     done
# }

# Creates new servers and records their KEM pubkeys
setup_server() {
    touch $USER_SERVERKEYS
    cd ../server

    # Accumulate the server registration data in this variable. The separator we use is ';'
    SERVER_REGS=""
    NUM_SERVERS=$1

    # Make a bunch of servers and save their pubkeys in client/ and aggregator/
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"

        # Make a new server and save the registration data
        SERVER_REG=$(
            $CMD_PREFIX new --server-state "$STATE"
        )
        # Append
        if [[ i -eq 1 ]]; then
            SERVER_REGS="$SERVER_REG"
        else
            SERVER_REGS="$SERVER_REGS;$SERVER_REG"
        fi

        # Save the server pubkeys
        $CMD_PREFIX get-pubkeys --server-state "$STATE" >> "$USER_SERVERKEYS"
    done

    # Copy the pubkeys file to the aggregators
    cp "$USER_SERVERKEYS" "$AGG_SERVERKEYS"

    # Read the regs into a variable
    IFS=';' read -ra SERVER_REGS <<< "$SERVER_REGS"

    # Register the srvers with each other
    i=1
    for SERVER_REG in "${SERVER_REGS[@]}"; do
        for j in $(seq 1 $NUM_SERVERS); do
            # Don't register any serve with itself
            if [[ $i -eq $j ]]; then
                continue
            fi

            # Register server i with server j
            STATE="${SERVER_STATE%.txt}$j.txt"
            echo $SERVER_REG | $CMD_PREFIX register-server --server-state "$STATE"
        done

        i=$(($i + 1))
    done

    echo "Set up server"
    cd ../script
}

# Creates new aggregators wrt the server KEM pubkeys
setup_aggregator() {
    # step 1: setup root-aggregator
    cd ../aggregator
    NUM_SERVERS=$1
    NUM_LEAF_AGGREGATORS=$THREAD_NUM
    # Make a new root aggregator and capture the registration data
    AGG_REG=$(
        $CMD_PREFIX new --level 0 --agg-number 0 --agg-state "$AGG_ROOTSTATE" --server-keys "$AGG_SERVERKEYS"
    )
     # Now do the registration
    cd ../server
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        echo $AGG_REG | $CMD_PREFIX register-aggregator --server-state "$STATE"
    done
    echo "Set up root aggregator"
    cd ../script

    # step 2: setup aggregator
    if [[ $NUM_LEAF_AGGREGATORS -gt 0 ]]; then
        for i in $(seq 1 $NUM_LEAF_AGGREGATORS); do
            cd ../aggregator
            file_name="$AGG_STATE_PREFIX$i.txt"
            AGG_REG=$(
                $CMD_PREFIX new --level 1 --agg-number $i --agg-state "$file_name" --server-keys "$AGG_SERVERKEYS")
            cd ../server
            for i in $(seq 1 $NUM_SERVERS); do
                STATE="${SERVER_STATE%.txt}$i.txt"
                echo $AGG_REG | $CMD_PREFIX register-aggregator --server-state "$STATE"
            done
            echo "Set up aggregator $i"
            cd ../script
        done
    fi
    
}


setup_client() {
    cd ../client
    NUM_SERVERS=$1
    NUM_USERS=$2
    # Make new clients and capture the registration data
    USER_REG=$(
        $CMD_PREFIX new \
            --num-regs $NUM_USERS \
            --user-state "$USER_STATE" \
            --server-keys "$USER_SERVERKEYS"
    )

    # Now do other registrations
    cd ../server
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        echo "$USER_REG" | $CMD_PREFIX register-user --server-state "$STATE"
    done
    sleep 5
    echo "Set up clients"
    cd ../script
}

setup_parameter() {
    footprint_n_slots=$(expr 4 \* $2)
    echo "DC_NET_MESSAGE_LENGTH=$1"
    echo "DC_NET_N_SLOTS=$2"
    echo "FOOTPRINT_N_SLOTS=$footprint_n_slots"
    echo "DC_NUM_USER=$3"

    export DC_NET_MESSAGE_LENGTH=$1
    export DC_NET_N_SLOTS=$2
    export FOOTPRINT_N_SLOTS=$footprint_n_slots
    export DC_NUM_USER=$3
}

client_eval(){
    DC_NET_MESSAGE_LENGTH=$1
    DC_NET_N_SLOTS=$2
    NUM_SERVERS=$3
    NUM_USERS=$4

    clean
    setup_parameter $DC_NET_MESSAGE_LENGTH $DC_NET_N_SLOTS $NUM_USERS
    
    #setup server
    touch $USER_SERVERKEYS
    cd ../server

    # Accumulate the server registration data in this variable. The separator we use is ';'
    SERVER_REGS=""

    # Make a bunch of servers and save their pubkeys in client/ and aggregator/
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"

        # Make a new server and save the registration data
        SERVER_REG=$(
            $CMD_PREFIX new --server-state "$STATE"
        )
        # Append
        if [[ i -eq 1 ]]; then
            SERVER_REGS="$SERVER_REG"
        else
            SERVER_REGS="$SERVER_REGS;$SERVER_REG"
        fi

        # Save the server pubkeys
        $CMD_PREFIX get-pubkeys --server-state "$STATE" >> "$USER_SERVERKEYS"
    done

    # Copy the pubkeys file to the aggregators
    cp "$USER_SERVERKEYS" "$AGG_SERVERKEYS"

    # Read the regs into a variable
    IFS=';' read -ra SERVER_REGS <<< "$SERVER_REGS"
    
    cd ../client
    # Make new clients and capture the registration data
    USER_REG=$(
        $CMD_PREFIX new \
            --num-regs 10 \
            --user-state "$USER_STATE" \
            --server-keys "$USER_SERVERKEYS"
    )
    cd ../script

    python -c "from generate_message import generate_round_multiple_message; generate_round_multiple_message(10,$DC_NET_MESSAGE_LENGTH)"
    for i in {1..10}
    do
        single_client_send $i
    done

}

setup_env() {
    clean
    setup_parameter $1 $2 $4
    setup_server $3
    setup_aggregator $3
    setup_client $3 $4
}

# Starts the first client
start_client() {
    cd ../client
    NUM_USERS=$1
    for i in $(seq 1 $NUM_USERS); do
        STATE="${USER_STATE%.txt}$i.txt"
        USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"
        RUST_LOG=$LOG_TYPE $CMD_PREFIX start-service \
            --user-state $STATE \
            --round $ROUND \
            --bind localhost:$USER_PORT \
            --agg-url http://localhost:$AGGREGATOR_PORT &
            # --no-persist \
    done
    sleep 10
    cd ../script
}

# all groups of clients sending message to aggregator one by one
# "group" here is for multi-threading. Different gruop is executing in parallel.
test_multi_clients() {
    NUM_USERS=$1
    MESSAGE_LENGTH=$2
    NUM_SLOT=$3
    NUM_GROUP=2
    python -c "from generate_message import generate_round_multiple_message; generate_round_multiple_message($NUM_SLOT,$MESSAGE_LENGTH)"
    for i in $(seq 1 $NUM_GROUP); do
        test_multi_client $(( NUM_SLOT/NUM_GROUP )) $i &
    done
    wait
    COVER_NUM=$NUM_USERS-$NUM_SLOT
    COVER_NUM_GROUP=2
    for i in $(seq 1 $NUM_GROUP); do
        multi_client_send_cover $(( COVER_NUM/COVER_NUM_GROUP )) $i $NUM_SLOT &
    done
    wait
    echo "start sending error msg"
    sleep 10
    retry_failed_clients $NUM_SLOT
    sleep 3
}

# one-group of clients sending message to aggregator one by one
test_multi_client() {
    GROUP_NUM_USERS=$1
    GROUP_SEQ=$2
    for i in $(seq 1 $GROUP_NUM_USERS); do
        USER_SEQ=$(( (GROUP_SEQ-1) * GROUP_NUM_USERS + i))
        single_client_send $USER_SEQ
    done
}

# one client sending message to aggregator
single_client_send() {
    USER_SEQ=$1
    echo "client $USER_SEQ begins to send msg"
    # start one client at a time
    cd ../client
    FILENAME="message/clientmessage_$(($USER_SEQ-1)).txt"
    STATE="${USER_STATE%.txt}$USER_SEQ.txt"
    PAYLOAD=$(cat $FILENAME)
    USER_PORT="$(($CLIENT_SERVICE_PORT + $(($USER_SEQ-1))))"
    aggre_port=$((AGGREGATOR_PORT + USER_SEQ % THREAD_NUM + 1))
    RUST_LOG=$LOG_TYPE $CMD_PREFIX start-service \
        --user-state "$STATE" \
        --round $ROUND \
        --bind "localhost:$USER_PORT" \
        --agg-url "http://localhost:$aggre_port" &

    cd ../script
    
    if [[ $ROUND -gt 0 ]]; then
        PREV_ROUND_OUTPUT=$(<"${SERVER_ROUNDOUTPUT%.txt}$(($ROUND-1)).txt")
        PAYLOAD="$PAYLOAD,$PREV_ROUND_OUTPUT"
    fi

    # Do the operation
    cd ../client
    echo "$PAYLOAD" > $FILENAME

    # if working in HW mode, then sleep is necessary. Because the client_sgx need time to setup
    # but if in SW mode, then this part can be neglect, to save time.
    # sleep 10

    sleep 2 && (curl "http://localhost:$USER_PORT/encrypt-msg" \
    -X POST \
    -H "Content-Type: text/plain" \
    --data-binary "@$FILENAME"
    if [[ $? -ne 0 ]]; then
        # log error
        echo $USER_SEQ >> "$ERROR_LOG"
    else
        echo $USER_SEQ >> "$SUCCESS_LOG"
    fi)
    cd ../script
    sleep 2.4 && kill_clients
}

# the same with above, but sending cover
multi_client_send_cover() {
    GROUP_NUM_USERS=$1
    GROUP_SEQ=$2
    NUM_SLOT=$3
    for i in $(seq 1 $GROUP_NUM_USERS); do
        USER_SEQ=$(( (GROUP_SEQ-1) * GROUP_NUM_USERS + NUM_SLOT + i))
        single_client_send_cover $USER_SEQ
    done
}

# single client sending cover
single_client_send_cover() {
    USER_SEQ=$1
    echo "client $USER_SEQ begins to send cover"
        # start one client at a time
        cd ../client
        USER_PORT="$(($CLIENT_SERVICE_PORT + $(($USER_SEQ-1))))"
        STATE="${USER_STATE%.txt}$USER_SEQ.txt"
        aggre_port=$((AGGREGATOR_PORT + USER_SEQ % THREAD_NUM + 1))
        RUST_LOG=$LOG_TYPE $CMD_PREFIX start-service \
            --user-state "$STATE" \
            --round $ROUND \
            --bind "localhost:$USER_PORT" \
            --agg-url "http://localhost:$aggre_port" &

        cd ../script

        # Do the operation
        cd ../client
        sleep 2 && (curl -X POST "http://localhost:$USER_PORT/send-cover"
        if [[ $? -ne 0 ]]; then
            # log error
            echo $USER_SEQ >> "$ERROR_LOG"
        else
            echo $USER_SEQ >> "$SUCCESS_LOG"
        fi)
        cd ../script
        sleep 2.4 && kill_clients
}

# resending the failed message.
retry_failed_clients() {
    NUM_SLOT=$1
    while IFS= read -r line
    do
        USER_SEQ=$line
        echo "we 're resending msg-$USER_SEQ"
        sleep 1
        if [[ $USER_SEQ -gt $NUM_SLOT ]]; then
            echo "$USER_SEQ is sending msg from retry"
            single_client_send_cover $USER_SEQ
        else
            echo "$USER_SEQ is sending covering from retry"
            single_client_send $USER_SEQ
        fi
    done < "$ERROR_LOG"
}

# aggregate-evaluation
aggregate_evaluation(){
    NUM_LEAF_AGGREGATORS=$THREAD_NUM
    if [[ $NUM_LEAF_AGGREGATORS -gt 0 ]]; then
        echo "start"
        for i in $(seq 1 $NUM_LEAF_AGGREGATORS); do
            port=$(($AGGREGATOR_PORT+$i))
            curl -s POST "http://localhost:$port/aggregate-eval" &
        done
        echo "done"
    fi
}

# Starts the root aggregator
start_agg() {
    NUM_SERVERS=$1
    NUM_LEAF_AGGREGATORS=$THREAD_NUM
    SERVER_IP=("$@")
    cd ../aggregator
    echo "starting aggregator..."
    # Build first so that build time doesn't get included in the start time
    # cargo build --release

    # step 1: start root aggregator
    # Start the aggregator in 5 sec from now
    NOW=$(date +%s)
    START_TIME=$(($NOW + 20))
    for i in $(seq 1 $NUM_SERVERS); do
        ip=${SERVER_IP[$i]}
        if [[ $i -eq 1 ]]; then
            FORWARD_TO="http://$ip:$SERVER_PORT"
        else
            FORWARD_TO="$FORWARD_TO,http://$ip:$SERVER_PORT"
        fi
    done
    echo "Aggregator Forward-to:$FORWARD_TO"
    RUST_LOG=$LOG_TYPE $CMD_PREFIX start-service \
        --agg-state "$AGG_ROOTSTATE" \
        --round $ROUND \
        --bind "localhost:$AGGREGATOR_PORT" \
        --start-time $START_TIME \
        --round-duration $ROUND_DURATION \
        --forward-to $FORWARD_TO &
        # --no-persist \
    sleep 1

    # step 2: start leaf aggregators
    if [[ $NUM_LEAF_AGGREGATORS -gt 0 ]]; then
        for i in $(seq 1 $NUM_LEAF_AGGREGATORS); do
            NOW=$(date +%s)
            START_TIME=$(($NOW + 20))
            file_name="$AGG_STATE_PREFIX$i.txt"
            port=$(($AGGREGATOR_PORT+$i))
            forward_url="http://localhost:$AGGREGATOR_PORT"
            
            RUST_LOG=$LOG_TYPE $CMD_PREFIX start-service \
                --agg-state "$file_name" \
                --round $ROUND \
                --bind "localhost:$port" \
                --start-time $START_TIME \
                --round-duration $ROUND_DURATION \
                --forward-to $forward_url &
                # --no-persist \
            echo "start aggregator $i" 
        done
    fi
    sleep 5
    cd ../script
}

# Starts the anytrust leader
start_leader() {
    MESSAGE_LENGTH=$1
    NUM_SLOT=$2
    NUM_USERS=$3
    setup_parameter $MESSAGE_LENGTH $NUM_SLOT $NUM_USERS
    cd ../server
    echo "starting leader..."
    STATE="${SERVER_STATE%.txt}1.txt"
    leader_ip=${SERVER_IP[0]}
    leader_addr="0.0.0.0:$SERVER_PORT"
    echo "leader addr: $leader_addr"
    RUST_LOG=$LOG_TYPE $CMD_PREFIX start-service \
        --server-state "$STATE" \
        --bind $leader_addr &
        # --no-persist \
    sleep 1
    cd ../script
}

# Starts the anytrust followers
start_follower() {
    MESSAGE_LENGTH=$2
    NUM_SLOT=$3
    NUM_USERS=$4
    setup_parameter $MESSAGE_LENGTH $NUM_SLOT $NUM_USERS
    cd ../server
    STATE="${SERVER_STATE%.txt}$1.txt"
    leader_ip=${SERVER_IP[0]}
    leader_addr="http://$leader_ip:$SERVER_PORT"
    index=$(($1-1))
    follower_ip=${SERVER_IP[$index]}
    follower_addr="0.0.0.0:$SERVER_PORT"
    RUST_LOG=$LOG_TYPE $CMD_PREFIX start-service \
        --server-state "$STATE" \
        --bind $follower_addr \
        --leader-url $leader_addr &

    cd ../script
}

encrypt_msg() {
    dc_net_n_slot=$1
    NUM_USERS=$2
    MESSAGE_LENGTH=$3
    python -c "from generate_message import generate_round_multiple_message; generate_round_multiple_message($NUM_USERS,$MESSAGE_LENGTH)"
    for i in $(seq 1 $dc_net_n_slot); do
        # Base64-encode the given message
        cd ../client
        FILENAME="message/clientmessage_$(($i-1)).txt"
        PAYLOAD=$(cat $FILENAME)
        USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"
        cd ../script
        # If this isn't the first round, append the previous round output to the payload. Separate with
        # a comma.
        if [[ $ROUND -gt 0 ]]; then
            PREV_ROUND_OUTPUT=$(<"${SERVER_ROUNDOUTPUT%.txt}$(($ROUND-1)).txt")
            PAYLOAD="$PAYLOAD,$PREV_ROUND_OUTPUT"
            echo "$PAYLOAD" > $FILENAME
        fi

        # Do the operation
        # curl "http://localhost:$CLIENT_SERVICE_PORT/encrypt-msg" \
        #     -X POST \
        #     -H "Content-Type: text/plain" \
        #     --data-binary "$PAYLOAD"
        
        

        # USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"
        # curl "http://localhost:$USER_PORT/encrypt-msg" \
        # -X POST \
        # -H "Content-Type: text/plain" \
        # --data-binary "@payload.txt"
    # done
        cd ../client
        (curl "http://localhost:$USER_PORT/encrypt-msg" \
            -X POST \
            -H "Content-Type: text/plain" \
            --data-binary "@$FILENAME" \
            2>/dev/null) &
        cd ../script
    done
    sleep 2
}

send_cover() {
    # Do a POST. No payload necessary
    curl -X POST "http://localhost:$CLIENT_SERVICE_PORT/send-cover"
}

reserve_slot() {
    # Do a POST. No payload necessary
    curl -X POST "http://localhost:$CLIENT_SERVICE_PORT/reserve-slot"
}

force_root_round_end() {
    # Force the round to end
    curl "http://localhost:$AGGREGATOR_PORT/force-round-end"
}

# Returns the round result
get_round_result() {
    curl -s "http://localhost:$SERVER_LEADER_PORT/round-result/$1"
}

# Returns the just the msg of the round result
get_round_msg() {
    curl -s "http://localhost:$SERVER_LEADER_PORT/round-msg/$1"
}

kill_servers() {
    ps aux | grep sgxdcnet-server | grep -v grep | awk '{print $2}' | xargs kill
}

kill_aggregators() {
    ps aux | grep sgxdcnet-aggregator | grep -v grep | awk '{print $2}' | xargs kill
}

kill_clients() {
    ps aux | grep sgxdcnet-client | grep -v grep | awk '{print $2}' | xargs kill
}

stop_all() {
    kill_clients 2> /dev/null || true
    kill_aggregators 2> /dev/null || true
    kill_servers 2> /dev/null || true
}

cal_time() {
    python3 -c "from time_cal import time_cal; time_cal($THREAD_NUM)"
}

cal_agg() {
    python3 -c "from time_cal import time_cal_agg; time_cal_agg($THREAD_NUM)"
}

save_data() {
    echo "start saving"
    curl "http://localhost:$AGGREGATOR_PORT/save-data"

}

# [single2multi] this is for re-setup, to ultilize the dataset of singlethread, changing it to multi-thread
# in single-thread, there is only one root aggregator; and now, we want several more aggregators.
re_setup_aggregator(){
    NUM_SERVERS=$1
    NUM_LEAF_AGGREGATORS=$THREAD_NUM

    # step 1: regenerate server-keys.txt
    touch $USER_SERVERKEYS
    cd ../server
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        # Save the server pubkeys
        $CMD_PREFIX get-pubkeys --server-state "$STATE" >> "$USER_SERVERKEYS"
    done
    # Copy the pubkeys file to the aggregators
    cp "$USER_SERVERKEYS" "$AGG_SERVERKEYS"
    cd ../script

    # step 2: generate the aggregator
    if [[ $NUM_LEAF_AGGREGATORS -gt 0 ]]; then
        for i in $(seq 1 $NUM_LEAF_AGGREGATORS); do
            cd ../aggregator
            file_name="$AGG_STATE_PREFIX$i.txt"
            AGG_REG=$(
                $CMD_PREFIX new --level 1 --agg-number $i --agg-state "$file_name" --server-keys "$AGG_SERVERKEYS")
            cd ../server
            # for i in $(seq 1 $NUM_SERVERS); do
            #     STATE="${SERVER_STATE%.txt}$i.txt"
            #     echo $AGG_REG | $CMD_PREFIX register-aggregator --server-state "$STATE"
            # done
            echo "Set up aggregator $i"
            cd ../script
        done
    fi
}

# [single2multi] this is to seperate the single dataset to multiple small datasets, for multi-thread purpose
seperate_dataset(){
    user_num=$1
    thread_num=$THREAD_NUM
    cd ../aggregator
    $CMD_PREFIX split-dataset --user-number $user_num --thread-number $thread_num
    cd ../script
}

# Commands with parameters:
#     encrypt-msg <MSG> takes a plain string. E.g., `./server_ctrl.sh encrypt-msg hello`
#     get-round-result <ROUND> takes an integer. E.g., `./server_ctrl.sh get-round-result 4`
#     test-multi-clients <MSG> takes a plain string. E.g., `./server_ctrl.sh test-multi-clients hello`

if [[ $1 == "clean" ]]; then
    clean
elif [[ $1 == "setup-env" ]]; then
    setup_env $2 $3 $4 $5
elif [[ $1 == "client-eval" ]]; then
    client_eval $2 $3 $4 $5
elif [[ $1 == "setup-param" ]]; then
    setup_parameter $2 $3 $4
elif [[ $1 == "resetup-agg" ]]; then
    re_setup_aggregator $2
elif [[ $1 == "start-leader" ]]; then
    start_leader $2 $3 $4
elif [[ $1 == "start-follower" ]]; then
    start_follower $2 $3 $4 $5"${SERVER_IP[@]}"
elif [[ $1 == "start-agg" ]]; then
    start_agg ${#SERVER_IP[@]} "${SERVER_IP[@]}"
elif [[ $1 == "start-client" ]]; then
    start_client
# elif [[ $1 == "start-agg" ]]; then
#     start_client
elif [[ $1 == "encrypt-msg" ]]; then
    encrypt_msg $2
elif [[ $1 == "send-cover" ]]; then
    send_cover
elif [[ $1 == "reserve-slot" ]]; then
    reserve_slot
elif [[ $1 == "force-root-round-end" ]]; then
    force_root_round_end
elif [[ $1 == "round-result" ]]; then
    get_round_result $2
elif [[ $1 == "round-msg" ]]; then
    get_round_msg $2
elif [[ $1 == "stop-servers" ]]; then
    kill_servers
elif [[ $1 == "stop-aggs" ]]; then
    kill_aggregators
elif [[ $1 == "stop-clients" ]]; then
    kill_clients
elif [[ $1 == "stop-all" ]]; then
    kill_clients 2> /dev/null || true
    kill_aggregators 2> /dev/null || true
    kill_servers 2> /dev/null || true
elif [[ $1 == "multi" ]]; then
    test_multi_clients $2 $3 $4
elif [[ $1 == "resend" ]]; then
    retry_failed_clients
elif [[ $1 == "agg-eval" ]]; then
    aggregate_evaluation
elif [[ $1 == "cal-time" ]]; then
    cal_time
elif [[ $1 == "cal-agg" ]]; then
    cal_agg
elif [[ $1 == "save-data" ]]; then
    save_data
elif [[ $1 == "log-time" ]]; then
    log_time
elif [[ $1 == "seperate" ]]; then
    # $2: user number
    seperate_dataset $2
else
    echo "Did not recognize command"
fi
