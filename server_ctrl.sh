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

SERVER_ROUNDOUTPUT="server/round_output.txt"

CLIENT_SERVICE_PORT="8323"
AGGREGATOR_PORT="8423"
SERVER_LEADER_PORT="8523"

# -q to reduce clutter
CMD_PREFIX="cargo run -- "

# Assume wlog that the leading anytrust node is the first one
LEADER=1
NUM_FOLLOWERS=1

ROUND=3

# Starts the first client
start_client() {
    cd client

    STATE="${USER_STATE%.txt}1.txt"
    $CMD_PREFIX start-service \
        --user-state "../$STATE" \
        --round $ROUND \
        --bind "localhost:$CLIENT_SERVICE_PORT" \
        --no-persist \
        --agg-url "http://localhost:$AGGREGATOR_PORT" &

    cd ..
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
    $CMD_PREFIX start-service \
        --agg-state "../$AGG_ROOTSTATE" \
        --round $ROUND \
        --bind "localhost:$AGGREGATOR_PORT" \
        --start-time $START_TIME \
        --round-duration 10000 \
        --no-persist \
        --forward-to "http://localhost:$SERVER_LEADER_PORT" &

    cd ..
}

# Starts the anytrust leader
start_leader() {
    cd server

    STATE="${SERVER_STATE%.txt}$LEADER.txt"
    $CMD_PREFIX start-service \
        --no-persist \
        --server-state "../$STATE" \
        --bind "localhost:$SERVER_LEADER_PORT" &

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
    # Base64-encode the given message
    PAYLOAD=$(base64 <<< "$1")

    # If this isn't the first round, append the previous round output to the payload. Separate with
    # a comma.
    if [[ $ROUND -gt 0 ]]; then
        PREV_ROUND_OUTPUT=$(<"${SERVER_ROUNDOUTPUT%.txt}$(($ROUND-1)).txt")
        PAYLOAD="$PAYLOAD,$PREV_ROUND_OUTPUT"
    fi

    # Do the operation
    curl "http://localhost:$CLIENT_SERVICE_PORT/encrypt-msg" \
        -X POST \
        -H "Content-Type: text/plain" \
        --data-binary "$PAYLOAD"
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

# Commands with parameters:
#     encrypt-msg <MSG> takes a plain string. E.g., `./server_ctrl.sh encrypt-msg hello`
#     get-round-result <ROUND> takes an integer. E.g., `./server_ctrl.sh get-round-result 4`

if [[ $1 == "start-leader" ]]; then
    start_leader
elif [[ $1 == "start-followers" ]]; then
    start_followers
elif [[ $1 == "start-agg" ]]; then
    start_root_agg
elif [[ $1 == "start-client" ]]; then
    start_client
elif [[ $1 == "start-agg" ]]; then
    start_client
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
else
    echo "Did not recognize command"
fi
