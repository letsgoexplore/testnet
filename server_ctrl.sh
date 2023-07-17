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

CLIENT_SERVICE_PORT="28325"
AGGREGATOR_PORT="38423"
SERVER_LEADER_PORT="38525"

# -q to reduce clutter
CMD_PREFIX="cargo run -- "

# Assume wlog that the leading anytrust node is the first one
LEADER=1
NUM_FOLLOWERS=0

NUM_SERVERS=$((LEADER + NUM_FOLLOWERS))
NUM_USERS=1
NUM_AGGREGATORS=1

ROUND=0

# clean_port() {
#     # clean port
#     echo "start hahah"
#     for i in $(seq 1 $NUM_USERS); do
#         PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"
#         PID=$(lsof -t -i:${PORT} 2>/dev/null)
#         echo "1"
#         if [ -z "$PID" ]; then
#             PID=0
#         fi

#         if [ "$PID" -gt 0 ]; then
#             echo "Terminating process $PID"
#             kill $PID
#         else
#             echo "No process found listening on port $PORT"
#         fi
#     done
#     echo "clean user port"

#     for i in $(seq 1 $NUM_AGGREGATORS); do
#         PORT="$(($AGGREGATOR_PORT + $(($i-1))))"
#         PID=$(lsof -t -i:${PORT})
#         if [ -n "$PID" ]; then
#             echo "Terminating process $PID"
#             kill $PID
#         else
#             echo "No process found listening on port $PORT"
#         fi
#     done
#     echo "clean aggregator port"


#     for i in $(seq 1 $NUM_SERVERS); do
#         PORT="$(($SERVER_LEADER_PORT + $(($i-1))))"
#         PID=$(lsof -t -i:${PORT})
#         if [ -n "$PID" ]; then
#             echo "Terminating process $PID"
#             kill $PID
#         else
#             echo "No process found listening on port $PORT"
#         fi
#     done
#     echo "clean server port"
# }

clean_file(){
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
    echo "Cleaned"
}

clean(){
    clean_port
    clean_file
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
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        echo $AGG_REG | $CMD_PREFIX register-aggregator --server-state "../$STATE"
    done

    echo "Set up aggregator"
    cd ..
}

setup_client() {
    cd client

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

setup_env() {
    clean_file
    setup_server
    setup_aggregator
    setup_client
}

# Starts the first client
start_client() {
    cd client

    # CMD_PREFIX=/tmp/sgxdcnet/target/debug/sgxdcnet-client
    # for i in $(seq 1 $NUM_USERS); do
    #     STATE="${USER_STATE%.txt}$i.txt"
    #     USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"

    #     echo $USER_PORT

    #     RUST_LOG=debug $CMD_PREFIX start-service \
    #         --user-state "../$STATE" \
    #         --round $ROUND \
    #         --bind "localhost:$USER_PORT" \
    #         --agg-url "http://localhost:$AGGREGATOR_PORT" &
    # done

    STATE="${USER_STATE%.txt}1.txt"

    RUST_LOG=debug $CMD_PREFIX start-service \
        --user-state "../$STATE" \
        --round $ROUND \
        --bind "localhost:$CLIENT_SERVICE_PORT" \
        --agg-url "http://localhost:$AGGREGATOR_PORT" &
        # --no-persist \

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

    STATE="${SERVER_STATE%.txt}$LEADER.txt"

    RUST_LOG=debug $CMD_PREFIX start-service \
        --server-state "../$STATE" \
        --bind "localhost:$SERVER_LEADER_PORT" &
        # --no-persist \

    cd ..
}

# Starts the anytrust followers
start_followers() {
    cd server

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

encrypt_msg() {
    # for i in $(seq 1 $NUM_USERS); do
        # Base64-encode the given message
        PAYLOAD=$(base64 <<< "$1")

        # If this isn't the first round, append the previous round output to the payload. Separate with
        # a comma.
        if [[ $ROUND -gt 0 ]]; then
            PREV_ROUND_OUTPUT=$(<"${SERVER_ROUNDOUTPUT%.txt}$(($ROUND-1)).txt")
            PAYLOAD="$PAYLOAD,$PREV_ROUND_OUTPUT"
        fi

        # Do the operation
        # curl "http://localhost:$CLIENT_SERVICE_PORT/encrypt-msg" \
        #     -X POST \
        #     -H "Content-Type: text/plain" \
        #     --data-binary "$PAYLOAD"
        
        echo "$PAYLOAD" > payload.txt

        # USER_PORT="$(($CLIENT_SERVICE_PORT + $(($i-1))))"
        # curl "http://localhost:$USER_PORT/encrypt-msg" \
        # -X POST \
        # -H "Content-Type: text/plain" \
        # --data-binary "@payload.txt"
    # done
    
    curl "http://localhost:$CLIENT_SERVICE_PORT/encrypt-msg" \
    -X POST \
    -H "Content-Type: text/plain" \
    --data-binary "@payload.txt"
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

# Commands with parameters:
#     encrypt-msg <MSG> takes a plain string. E.g., `./server_ctrl.sh encrypt-msg hello`
#     get-round-result <ROUND> takes an integer. E.g., `./server_ctrl.sh get-round-result 4`
#     test-multi-clients <MSG> takes a plain string. E.g., `./server_ctrl.sh test-multi-clients hello`
if [[ $1 == "run" ]]; then
    setup_env
    start_leader
    start_followers
    start_root_agg
    start_client
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
elif [[ $1 == "get-agg-round-num" ]]; then
    get_agg_round_num
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
elif [[ $1 == "test-multi-clients" ]]; then
    test_multi_clients $2
else
    echo "Did not recognize command"
fi
