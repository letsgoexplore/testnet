#!/bin/bash

USER_STATE="client/user-state.txt"
AGG_FINALAGG="aggregator/final-agg.txt"
AGG_ROOTSTATE="aggregator/agg-root-state.txt"
SERVER_STATE="server/server-state.txt"
SERVER_SHARES="server/shares.txt"
SERVER_SHARES_PARTIAL="server/partial_shares.txt"

USER_SERVERKEYS="client/server-keys.txt"
AGG_SERVERKEYS="aggregator/server-keys.txt"

SERVER_ROUNDOUTPUT="server/round_output.txt"
TIME_LOG="server/time_recorder.txt"
TIME_LOG_ALL="server/time_recorder_all.txt"
CLIENT_MESSAGE="client/src/message/clientmessage.txt"
CLINET_TIME_LOG="client/client_time_recorder.txt"
CLINET_ENCRYPT_TIME_LOG="client/client_encrypt_time_recorder.txt"
AGG_ENCRYPT_TIME_LOG="aggregator/agg_encrypt_time_recorder.txt"
CLIENT_SERVICE_PORT="9323"
AGGREGATOR_PORT="18300"
SERVER_PORT="28942"
SERVER_IP=("18.117.139.165" "18.117.196.197" "18.217.9.71" "18.221.129.24" "18.217.189.71")

# -q to reduce clutter
CMD_PREFIX="cargo build run -- "
SERVER_CMD_PREFIX="/home/ubuntu/.cargo/bin/cargo cargo run -- "
# Assume wlog that the leading anytrust node is the first one
LEADER=1
NUM_FOLLOWERS=0

NUM_SERVERS=$((LEADER + NUM_FOLLOWERS))
NUM_USERS=5
NUM_AGGREGATORS=1
MESSAGE_LENGTH=40
ROUND=0

evaluate_bit() {
    rm -f $TIME_LOG_ALL || true
    # num_users=("30" "60" "90" "120" "150" "180" "210")
    num_users=("150" "180" "210")
    num_leader=1
    # num_follower=("0" "3" "5" "7")
    num_follower=3
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
        setup_env $dc_net_message_length $dc_net_n_slot $num_server $num_user
        start_leader
        if [[ $num_follower -gt 0 ]]; then
            start_followers $num_follower
        fi
        start_root_agg $num_server
        test_multi_clients $num_user $dc_net_message_length
        python -c "from time_cal import time_cal; time_cal()"
    done
}

evaluate_bit_server() {
    rm -f $TIME_LOG_ALL || true
    num_user=120
    num_leader=1
    # num_follower=("0" "3" "5" "7")
    num_followers=( "2" "3" "4" "5" "6" "7" )
    
    num_aggregator=1
    dc_net_message_length=160
    # dc_net_n_slots=("10" "20" "30")
    # dc_net_n_slots=("20" "30" "40" "50")
    # dc_net_n_slots=("5" "10")
    # dc_net_message_lengths=("20" "40" "60" "80" "100" "120" "140" "160")
    echo "[settings]: aggregator: $num_aggregator, clients: $num_user" >> $TIME_LOG_ALL
    echo "[num_server]" >> $TIME_LOG_ALL
    echo "[entire time]" >> $TIME_LOG_ALL
    
    for num_follower in "${num_followers[@]}"; do
        num_server=$((num_leader + num_follower))
        dc_net_n_slot=$num_user
        echo "$num_server" >> $TIME_LOG_ALL
        setup_env $dc_net_message_length $dc_net_n_slot $num_server $num_user
        start_leader
        if [[ $num_follower -gt 0 ]]; then
            start_followers $num_follower
        fi
        start_root_agg $num_server
        test_multi_clients $num_user $dc_net_message_length
        python -c "from time_cal import time_cal; time_cal()"
    done
}


test() {
    rm -f $TIME_LOG_ALL || true
    num_users=("50" "100" "200" "300" "500" "700" "1000")
    num_leader=1
    num_follower=3
    num_server=$((num_leader + num_follower))
    num_aggregator=1
    dc_net_n_slot=10
    dc_net_message_length=20
    setup_env $dc_net_message_length $dc_net_n_slot $num_server $num_user
    start_leader
    if [[ $num_follower -gt 0 ]]; then
        start_followers $num_follower
    fi
    start_root_agg $num_server
    test_multi_clients $num_user $dc_net_message_length
}

log_time() {
    timestamp=$(date +%s%N)
    echo "$timestamp" >> $TIME_LOG
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
    rm -f $TIME_LOG || true
    rm -f $CLINET_TIME_LOG || true
    rm -f $CLINET_ENCRYPT_TIME_LOG || true
    rm -f $AGG_ENCRYPT_TIME_LOG || true
    
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
    cd server

    # Accumulate the server registration data in this variable. The separator we use is ';'
    SERVER_REGS=""
    NUM_SERVERS=$1

    # Make a bunch of servers and save their pubkeys in client/ and aggregator/
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"

        # Make a new server and save the registration data
        SERVER_REG=$(
            $CMD_PREFIX new --server-state "../$STATE"
        )
        # Append
        if [[ i -eq 1 ]]; then
            SERVER_REGS="$SERVER_REG"
        else
            SERVER_REGS="$SERVER_REGS;$SERVER_REG"
        fi

        # Save the server pubkeys
        $CMD_PREFIX get-pubkeys --server-state "../$STATE" >> "../$USER_SERVERKEYS"
    done

    # Copy the pubkeys file to the aggregators
    cp "../$USER_SERVERKEYS" "../$AGG_SERVERKEYS"

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
            echo $SERVER_REG | $CMD_PREFIX register-server --server-state "../$STATE"
        done

        i=$(($i + 1))
    done

    echo "Set up server"
    cd ..
}

# Creates new aggregators wrt the server KEM pubkeys
setup_aggregator() {
    # We only have one aggregator right now
    cd aggregator
    NUM_SERVERS=$1
    # Make a new root aggregator and capture the registration data
    AGG_REG=$(
        $CMD_PREFIX new --level 0 --agg-state "../$AGG_ROOTSTATE" --server-keys "../$AGG_SERVERKEYS"
    )

    # Now do the registration
    cd ../server
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        echo $AGG_REG | $CMD_PREFIX register-aggregator --server-state "../$STATE"
    done

    echo "Set up aggregator"
    cd ..
}

setup_client() {
    cd client
    NUM_SERVERS=$1
    NUM_USERS=$2
    # Make new clients and capture the registration data
    USER_REG=$(
        $CMD_PREFIX new \
            --num-regs $NUM_USERS \
            --user-state "../$USER_STATE" \
            --server-keys "../$USER_SERVERKEYS"
    )

    # Now do oteh registrations
    cd ../server
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        echo "$USER_REG" | $CMD_PREFIX register-user --server-state "../$STATE"
    done

    echo "Set up clients"
    cd ..
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

    source ./server_ctrl.sh
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
    cd client
    NUM_USERS=$1
    for i in $(seq 1 $NUM_USERS); do
        STATE="${USER_STATE%.txt}$i.txt"
        USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"
        RUST_LOG=debug $CMD_PREFIX start-service \
            --user-state ../$STATE \
            --round $ROUND \
            --bind localhost:$USER_PORT \
            --agg-url http://localhost:$AGGREGATOR_PORT &
            # --no-persist \
    done
    sleep 10
    cd ..
}

test_multi_clients() {
    NUM_USERS=$1
    MESSAGE_LENGTH=$2
    NUM_GROUP=2
    python -c "from generate_message import generate_round_multiple_message; generate_round_multiple_message($NUM_USERS,$MESSAGE_LENGTH)"
    for i in $(seq 1 $NUM_GROUP); do
        test_multi_client $(( NUM_USERS/NUM_GROUP )) $i &
    done
    sleep 3
}

test_multi_client() {
    GROUP_NUM_USERS=$1
    GROUP_SEQ=$2
    for i in $(seq 1 $GROUP_NUM_USERS); do
        USER_SEQ=$(( (GROUP_SEQ-1) * GROUP_NUM_USERS + i))
        echo "client $USER_SEQ begins to send msg"
        # start one client at a time
        cd client
        FILENAME="message/clientmessage_$(($USER_SEQ-1)).txt"
        STATE="${USER_STATE%.txt}$USER_SEQ.txt"
        PAYLOAD=$(cat $FILENAME)
        USER_PORT="$(($CLIENT_SERVICE_PORT + $(($USER_SEQ-1))))"

        RUST_LOG=debug $CMD_PREFIX start-service \
            --user-state "../$STATE" \
            --round $ROUND \
            --bind "localhost:$USER_PORT" \
            --agg-url "http://localhost:$AGGREGATOR_PORT" &

        cd ..
        # encrypt-msg
        # Base64-encode the given message
        # PAYLOAD1=$(base64 <<< "$1")

        # If this isn't the first round, append the previous round output to the payload. Separate with
        # a comma.
        if [[ $ROUND -gt 0 ]]; then
            PREV_ROUND_OUTPUT=$(<"${SERVER_ROUNDOUTPUT%.txt}$(($ROUND-1)).txt")
            PAYLOAD="$PAYLOAD,$PREV_ROUND_OUTPUT"
        fi

        # Do the operation
        cd client
        echo "$PAYLOAD" > $FILENAME
                
        sleep 1.4 && (curl "http://localhost:$USER_PORT/encrypt-msg" \
        -X POST \
        -H "Content-Type: text/plain" \
        --data-binary "@$FILENAME")
        cd ..
        sleep 0.2 && kill_clients
    done

    # aggregate_evaluation
    # all ciphertexts have been submitted to the aggregator
    # start server
    # log_time
    # force_root_round_end
    # sleep 5
    # kill_clients 2> /dev/null || true
    # kill_aggregators 2> /dev/null || true
    # kill_servers 2> /dev/null || true
}

# aggregate-evaluation
aggregate_evaluation(){
    curl -s POST "http://localhost:$AGGREGATOR_PORT/aggregate-eval"
}


# Starts the root aggregator
start_root_agg() {
    NUM_SERVERS=$1
    SERVER_IP=("$@")
    cd aggregator
    echo "starting aggregator..."
    # Build first so that build time doesn't get included in the start time
    cargo build

    # Start the aggregator in 5 sec from now
    NOW=$(date +%s)
    START_TIME=$(($NOW + 5))
    for i in $(seq 1 $NUM_SERVERS); do
        ip=${SERVER_IP[$i]}
        if [[ $i -eq 1 ]]; then
            FORWARD_TO="http://$ip:$SERVER_PORT"
        else
            FORWARD_TO="$FORWARD_TO,http://$ip:$SERVER_PORT"
        fi
    done
    echo "Aggregator Forward-to:$FORWARD_TO"
    RUST_LOG=debug $CMD_PREFIX start-service \
        --agg-state "../$AGG_ROOTSTATE" \
        --round $ROUND \
        --bind "localhost:$AGGREGATOR_PORT" \
        --start-time $START_TIME \
        --round-duration 10000 \
        --forward-to $FORWARD_TO &
        # --no-persist \
    sleep 1
    cd ..
}

# Starts the anytrust leader
start_leader() {
    cd server
    echo "starting leader..."
    STATE="${SERVER_STATE%.txt}$LEADER.txt"
    leader_ip=${SERVER_IP[0]}
    leader_addr="0.0.0.0:$SERVER_PORT"
    echo "leader addr: $leader_addr"
    RUST_LOG=debug $CMD_PREFIX start-service \
        --server-state "../$STATE" \
        --bind $leader_addr &
        # --no-persist \
    sleep 1
    cd ..
}

# Starts the anytrust followers
start_follower() {
    cd server
    STATE="${SERVER_STATE%.txt}$1.txt"
    leader_ip=${SERVER_IP[0]}
    leader_addr="http://$leader_ip:$SERVER_PORT"
    index=$(($1-1))
    follower_ip=${SERVER_IP[$index]}
    follower_addr="0.0.0.0:$SERVER_PORT"
    RUST_LOG=debug $CMD_PREFIX start-service \
        --server-state "../$STATE" \
        --bind $follower_addr \
        --leader-url $leader_addr &

    cd ..
}

encrypt_msg() {
    dc_net_n_slot=$1
    NUM_USERS=$2
    MESSAGE_LENGTH=$3
    python -c "from generate_message import generate_round_multiple_message; generate_round_multiple_message($NUM_USERS,$MESSAGE_LENGTH)"
    for i in $(seq 1 $dc_net_n_slot); do
        # Base64-encode the given message
        cd client
        FILENAME="message/clientmessage_$(($i-1)).txt"
        PAYLOAD=$(cat $FILENAME)
        USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"
        cd ..
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
        cd client
        (curl "http://localhost:$USER_PORT/encrypt-msg" \
            -X POST \
            -H "Content-Type: text/plain" \
            --data-binary "@$FILENAME" \
            2>/dev/null) &
        cd ..
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
    python3 -c "from time_cal import time_cal; time_cal()"
}
# Commands with parameters:
#     encrypt-msg <MSG> takes a plain string. E.g., `./server_ctrl.sh encrypt-msg hello`
#     get-round-result <ROUND> takes an integer. E.g., `./server_ctrl.sh get-round-result 4`
#     test-multi-clients <MSG> takes a plain string. E.g., `./server_ctrl.sh test-multi-clients hello`

if [[ $1 == "clean" ]]; then
    clean
elif [[ $1 == "run" ]]; then
    setup_env
    start_leader
    start_root_agg
    test_multi_clients $2
elif [[ $1 == "test" ]]; then
    test
elif [[ $1 == "eval" ]]; then
    evaluate_bit
elif [[ $1 == "eval-ser" ]]; then
    evaluate_bit_server
elif [[ $1 == "setup-env" ]]; then
    setup_env $2 $3 $4 $5
elif [[ $1 == "setup-param" ]]; then
    setup_parameter $2 $3 $4
elif [[ $1 == "start-leader" ]]; then
    start_leader
elif [[ $1 == "start-follower" ]]; then
    start_follower $2 "${SERVER_IP[@]}"
elif [[ $1 == "start-agg" ]]; then
    start_root_agg $2 "${SERVER_IP[@]}"
elif [[ $1 == "start-client" ]]; then
    start_client
# elif [[ $1 == "start-agg" ]]; then
#     start_client
elif [[ $1 == "encrypt-msg" ]]; then
    encrypt_msg $2
elif [[ $1 == "multi-encrypt" ]]; then
    test_multi_clients $2 $3
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
    test_multi_clients $2 $3
elif [[ $1 == "agg-eval" ]]; then
    aggregate_evaluation
elif [[ $1 == "cal-time" ]]; then
    cal_time
else
    echo "Did not recognize command"
fi
