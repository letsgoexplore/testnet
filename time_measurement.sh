#!/bin/bash

# -e => Exits immediately on error
# -u => Error when using undefined vars
set -eu

USER_STATE="client/user-state.txt"
AGG_FINALAGG="aggregator/final-agg.txt"
AGG_ROOTSTATE="aggregator/agg-root-state.txt"
SERVER_STATE="server/server-state.txt"
SERVER_SHARES="server/shares.txt"
SERVER_SHARES_PARTIAL="server/partial_shares.txt"

USER_SERVERKEYS="client/server-keys.txt"
AGG_SERVERKEYS="aggregator/server-keys.txt"

SERVER_ROUNDOUTPUT="server/round_output.txt"
CLIENT_MESSAGE="client/src/message/clientmessage.txt"
TIME_LOG="server/time_recorder.txt"
TIME_LOG_ALL="server/time_recorder_all.txt"

CLIENT_SERVICE_PORT="28333"
AGGREGATOR_PORT="38424"
SERVER_LEADER_PORT="38524"

CONTAINER_NAME_PREFIX="dcnet-user-"

# -q to reduce clutter
CMD_PREFIX="cargo run -- "
DOCKER_CREATE_PREFIX="docker run "
DOCKER_SWITCH_PREFIX="docker exec -it"


# Assume wlog that the leading anytrust node is the first one
# LEADER=1
# NUM_FOLLOWERS=3

# NUM_SERVERS=$((LEADER + NUM_FOLLOWERS))
# NUM_USERS=1
# NUM_AGGREGATORS=1

# MESSAGE_LENGTH=20
ROUND=0
AGG_TIMEOUT=100.3

evaluate_bit() {
    rm -f $TIME_LOG_ALL || true
    num_user=10
    num_leader=1
    num_follower=0
    num_server=$((num_leader + num_follower))
    num_aggregator=1
    # dc_net_n_slots=("10" "20" "30" "40" "50")
    dc_net_n_slots=("5" "10")
    dc_net_message_lengths=("20" "40" "60" "80" "100" "120" "140" "160")
    for dc_net_n_slot in "${dc_net_n_slots[@]}"; do
        for dc_net_message_length in "${dc_net_message_lengths[@]}"; do
            setup_env $dc_net_message_length $dc_net_n_slot $num_server $num_user
            echo "$dc_net_n_slot $dc_net_message_length" >> $TIME_LOG_ALL 
            start_leader
            if [[ $num_follower -gt 0 ]]; then
                start_followers $num_follower
            fi
            start_root_agg 
            start_client $num_user
            log_time
            send_round_msg $dc_net_n_slot $num_user $dc_net_message_length
            force_root_round_end
            stop_all
            python -c "from time_cal import time_cal; time_cal()"
        done
    done
}

test() {
    num_user=5
    num_leader=1
    num_follower=0
    num_server=$((num_leader + num_follower))
    num_aggregator=1
    # dc_net_n_slots=("10" "20" "30" "40" "50")
    dc_net_n_slot=5
    dc_net_message_length=20
    setup_env $dc_net_message_length $dc_net_n_slot $num_server $num_user
    start_leader
    start_root_agg 
    start_client $num_user
    log_time
    send_round_msg $dc_net_n_slot $num_user $dc_net_message_length
    force_root_round_end
    stop_all
    sleep 5
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

    # Make a new root aggregator and capture the registration data
    AGG_REG=$(
        $CMD_PREFIX new --level 0 --agg-state "../$AGG_ROOTSTATE" --server-keys "../$AGG_SERVERKEYS"
    )

    # Now do the registration
    cd ../server
    NUM_SERVERS=$1
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        echo $AGG_REG | $CMD_PREFIX register-aggregator --server-state "../$STATE"
    done

    echo "Set up aggregator"
    cd ..
}

setup_client() {
    # for i in $(seq 1 $NUM_USERS); do
    #     echo "client $i begins to setup msg"

    #     CONTAINER_NAME="$CONTAINER_NAME_PREFIX$i"
    #     if docker container inspect $CONTAINER_NAME > /dev/null 2>&1; then
    #         docker start -ai $CONTAINER_NAME
    #     else
    #         docker run \
    #             -v $PWD:/root/sgx \
    #             -ti \
    #             --hostname $CONTAINER_NAME \
    #             --name $CONTAINER_NAME \
    #             -e SGX_MODE=SW \
    #             $DOCKER_IMAGE
    #     fi

    # Make new clients and capture the registration data
    cd client
    NUM_SERVERS=$1
    NUM_USERS=$2
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
    echo "DC_NET_MESSAGE_LENGTH=$1\n"
    echo "DC_NET_N_SLOTS=$2\n"
    echo "FOOTPRINT_N_SLOTS=$footprint_n_slots\n"

    export DC_NET_MESSAGE_LENGTH=$1
    export DC_NET_N_SLOTS=$2
    export FOOTPRINT_N_SLOTS=$footprint_n_slots
}

setup_env() {
    clean
    setup_parameter $1 $2
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
        echo "$STATE"
        USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"

        echo $USER_PORT

        RUST_LOG=debug $CMD_PREFIX start-service \
            --user-state "../$STATE" \
            --round $ROUND \
            --bind "localhost:$USER_PORT" \
            --agg-url "http://localhost:$AGGREGATOR_PORT" &
    done
    sleep 10
    echo "hihi"
    cd ..

}

test_multi_clients() {
    # start the aggregator
    start_root_agg

    # start clients and send the ciphertexts
    # CMD_PREFIX=/tmp/sgxdcnet/target/debug/sgxdcnet-client
    for i in $(seq 1 $NUM_USERS); do
        echo "client $i begins to send msg"
        # start one client at a time
        cd client
        STATE="${USER_STATE%.txt}$i.txt"
        USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"

        RUST_LOG=debug $CMD_PREFIX start-service \
            --user-state "../$STATE" \
            --round $ROUND \
            --bind "localhost:$USER_PORT" \
            --agg-url "http://localhost:$AGGREGATOR_PORT" &

        cd ..
        # encrypt-msg
        # Base64-encode the given message
        PAYLOAD=$(base64 <<< "$1")

        # If this isn't the first round, append the previous round output to the payload. Separate with
        # a comma.
        if [[ $ROUND -gt 0 ]]; then
            PREV_ROUND_OUTPUT=$(<"${SERVER_ROUNDOUTPUT%.txt}$(($ROUND-1)).txt")
            PAYLOAD="$PAYLOAD,$PREV_ROUND_OUTPUT"
        fi

        # Do the operation
        echo "$PAYLOAD" > payload.txt
                
        sleep 3 && (curl "http://localhost:$USER_PORT/encrypt-msg" \
        -X POST \
        -H "Content-Type: text/plain" \
        --data-binary "@payload.txt")

        sleep 1 && kill_clients
    done

    rm payload.txt

    # all ciphertexts have been submitted to the aggregator
    # start server
    start_leader
    sleep 3 && force_root_round_end
    sleep 2
    kill_clients 2> /dev/null || true
    kill_aggregators 2> /dev/null || true
    kill_servers 2> /dev/null || true
}

# Starts the root aggregator
start_root_agg() {
    cd aggregator

    # Build first so that build time doesn't get included in the start time
    cargo build

    # Start the aggregator in 5 sec from now
    NOW=$(date +%s)
    START_TIME=$(($NOW + 5))

    STATE="${USER_STATE%.txt}1.txt"

    RUST_LOG=debug $CMD_PREFIX start-service \
        --agg-state "../$AGG_ROOTSTATE" \
        --round $ROUND \
        --bind "localhost:$AGGREGATOR_PORT" \
        --start-time $START_TIME \
        --round-duration 10000 \
        --forward-to "http://localhost:$SERVER_LEADER_PORT" &
        # --no-persist \

    cd ..
}

# Starts the anytrust leader
start_leader() {
    cd server

    STATE="${SERVER_STATE%.txt}1.txt"

    RUST_LOG=debug $CMD_PREFIX start-service \
        --server-state "../$STATE" \
        --bind "localhost:$SERVER_LEADER_PORT" &
        # --no-persist \

    cd ..
}

# Starts the anytrust followers
start_followers() {
    cd server
    NUM_FOLLOWERS=$1
    for i in $(seq 1 $NUM_FOLLOWERS); do
        FOLLOWER_PORT=$(($SERVER_LEADER_PORT + $i))
        STATE="${SERVER_STATE%.txt}$(($i+1)).txt"

        $CMD_PREFIX start-service \
            --server-state "../$STATE" \
            --bind "localhost:$FOLLOWER_PORT" \
            --leader-url "http://localhost:$SERVER_LEADER_PORT" &
    done

    cd ..
}

send_round_msg_single_client() {
    FILENAME="src/message/clientmessage_$(($1-1)).txt"
    PAYLOAD=$(cat $FILENAME)
    CURRENT_ROUND=$(curl -s -X GET "http://localhost:$AGGREGATOR_PORT/round-num")
    USER_PORT="$(($CLIENT_SERVICE_PORT + $(($1-1))))"
    echo "haha$1"

    if [[ $1 -le $2 ]]; then # $1 refers to the sequence num of this user; $2 refers to the dc_net_slot_num
        # If this isn't the first round, append the previous round output to the payload. Separate with
        # a comma.
        if [[ $CURRENT_ROUND -gt 0 ]]; then
            PREV_ROUND_OUTPUT=$(<"${SERVER_ROUNDOUTPUT%.txt}$(($CURRENT_ROUND-1)).txt")
            PAYLOAD="$PAYLOAD,$PREV_ROUND_OUTPUT"
        fi
        echo "$PAYLOAD" > "$FILENAME"
        result=$(curl "http://localhost:$USER_PORT/encrypt-msg" \
        -X POST \
        -H "Content-Type: text/plain" \
        --data-binary "@$FILENAME" \
        2>/dev/null)
    else
        result=$(curl -X POST "http://localhost:$USER_PORT/send-cover" 2>/dev/null)
    fi
}

send_round_msg() {
    dc_net_n_slot=$1
    NUM_USERS=$2
    MESSAGE_LENGTH=$3
    # randomly generate the new message of term
    python -c "from generate_message import generate_round_multiple_message; generate_round_multiple_message($NUM_USERS,$MESSAGE_LENGTH)"
    cd client
    for i in $(seq 1 $NUM_USERS); do
        if [[ $i -eq $NUM_USERS ]]; then
            send_round_msg_single_client $i $dc_net_n_slot
        else
            send_round_msg_single_client $i $dc_net_n_slot &
        fi
    done
    echo "hihi"
    cd ..
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
    result=$(curl "http://localhost:$AGGREGATOR_PORT/force-round-end" 2>/dev/null)
}

# get round_num from aggregator
get_agg_round_num(){
    result=$(curl -s -X GET "http://localhost:$AGGREGATOR_PORT/round-num")
    echo "result:$result"
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

# Commands with parameters:
#     encrypt-msg <MSG> takes a plain string. E.g., `./server_ctrl.sh encrypt-msg hello`
#     get-round-result <ROUND> takes an integer. E.g., `./server_ctrl.sh get-round-result 4`
#     test-multi-clients <MSG> takes a plain string. E.g., `./server_ctrl.sh test-multi-clients hello`
if [[ $1 == "eval" ]]; then
    evaluate_bit
elif [[ $1 == "test" ]]; then
    test
elif [[ $1 == "send" ]]; then
    send_round_msg 5 5 20
elif [[ $1 == "clean" ]]; then
    clean_port
    clean_file
elif [[ $1 == "setup-env" ]]; then
    setup_env
elif [[ $1 == "start-leader" ]]; then
    start_leader
elif [[ $1 == "start-followers" ]]; then
    start_followers
elif [[ $1 == "start-agg" ]]; then
    start_root_agg
elif [[ $1 == "start-client" ]]; then
    start_client
# elif [[ $1 == "start-agg" ]]; then
#     start_client
elif [[ $1 == "getnum" ]]; then
    get_agg_round_num
elif [[ $1 == "encrypt-msg" ]]; then
    encrypt_msg
elif [[ $1 == "send-cover" ]]; then
    send_cover
elif [[ $1 == "reserve-slot" ]]; then
    reserve_slot
elif [[ $1 == "force-root-round-end" ]]; then
    force_root_round_end
elif [[ $1 == "roundresult" ]]; then
    get_round_result $2
elif [[ $1 == "roundmsg" ]]; then
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
elif [[ $1 == "test-multi-clients" ]]; then
    test_multi_clients $2
else
    echo "Did not recognize command"
fi
