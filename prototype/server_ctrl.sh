#!/bin/bash

# -e => Exits immediately on error
# -u => Error when using undefined vars
set -eu

USER_STATE="client/user-state.txt"
USER_SERVERKEYS="client/server-keys.txt"
AGG_STATE="aggregator/agg-state.txt"
AGG_ROOTSTATE="aggregator/agg-root-state.txt"
AGG_SERVERKEYS="aggregator/server-keys.txt"
AGG_FINALAGG="aggregator/final-agg.txt"
SERVER_STATE="server/server-state.txt"
SERVER_SHARES="server/shares.txt"
SERVER_SHARES_PARTIAL="server/partial_shares.txt"

AGG_SERVICE_ADDR="localhost:8785"
SERVER_SERVICE_ADDR="0.0.0.0:8122"

# -q to reduce clutter
CMD_PREFIX="cargo run -- "

NUM_SERVERS=2
NUM_USERS=2
NUM_AGGREGATORS=1
NUM_USERS_PER_AGGREGATOR=2
ROUND=0

# Starts the anytrust leader
start_server_service() {
    cd server

    # Assume wlog that the leading anytrust node is the first one
    LEADER=1
    STATE="${SERVER_STATE%.txt}$LEADER.txt"
    $CMD_PREFIX start-service \
        --server-state "../$STATE" \
        --bind "$SERVER_SERVICE_ADDR" \
        --round $ROUND

    cd ..
}

# Submits the toplevel aggregate to the leader
submit_agg() {
    cd server

    curl "http://$SERVER_SERVICE_ADDR/submit-agg" \
        -X POST \
        -H "Content-Type: text/plain" \
        --data-binary "@../$AGG_FINALAGG"

    cd ..
}

# Submits the followers' shares to the leader
submit_shares() {
    cd server

    # Read the non-leaders' shares line by line
    while IFS="" read -r SHARE || [ -n "$SHARE" ]
    do
        # Send the share to the leader
        curl "http://$SERVER_SERVICE_ADDR/submit-share" \
            -X POST \
            -H "Content-Type: text/plain" \
            --data-binary "$SHARE"
    done < "../$SERVER_SHARES_PARTIAL"

    cd ..
}

# Returns the round result
get_round_result() {
    # Now get the round result
    curl -s "http://$SERVER_SERVICE_ADDR/round-result/$ROUND" | base64 -d
}

if [[ $1 == "start" ]]; then
    start_server_service
elif [[ $1 == "submit-agg" ]]; then
    submit_agg
elif [[ $1 == "submit-shares" ]]; then
    submit_shares
elif [[ $1 == "round-result" ]]; then
    get_round_result
fi
