#!/bin/bash

# -e => Exits immediately on error
# -u => Error when using undefined vars
set -eu

USER_STATE="client/user-state.txt"
USER_SERVERKEYS="client/server-keys.txt"
AGG_STATE="aggregator/agg-state.txt"
AGG_ROOTSTATE="aggregator/agg-root-state.txt"
AGG_SERVERKEYS="aggregator/server-keys.txt"
SERVER_STATE="server/server-state.txt"
SERVER_SHARES="server/shares.txt"

CMD_PREFIX="cargo run -- "

NUM_SERVERS=1
NUM_USERS=2
NUM_AGGREGATORS=2
NUM_USERS_PER_AGGREGATOR=2
ROUND=1

# We define four messages. "testing", "\0\0\0\0\0\0\0hello", and "\0\0\0\0\0\0\0\0\0\0\0\0world",
# and "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0yo". These XOR to "testinghelloworld". The leading ';' is
# just because other things are indexed by 1.
MSGS=";testing;\0\0\0\0\0\0\0hello;\0\0\0\0\0\0\0\0\0\0\0\0world;\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0yo"

# Magic command to trim the leading and trailing whitespace of its input
TRIM="sed 's/\n$//' | sed '/^$/d'"

# Checks that the given constants make sense
check() {
    if [[ $NUM_USERS -lt 1 ]]; then
        echo "Error: NUM_USERS must be at least 1"
        exit -1
    fi

    if [[ $NUM_AGGREGATORS -lt 1 ]]; then
        echo "Error: NUM_AGGREGATORS must be at least 1"
        exit -1
    fi

    if [[ $NUM_SERVERS -lt 1 ]]; then
        echo "Error: NUM_SERVERS must be at least 1"
        exit -1
    fi

    # If ceil(NUM_USERS / NUM_USERS_PER_AGGREGATOR) > NUM_AGGREGATORS, then this will fail
    if [[ \
        $(( ($NUM_USERS+$NUM_USERS_PER_AGGREGATOR-1) / $NUM_USERS_PER_AGGREGATOR)) \
        -gt $NUM_AGGREGATORS \
    ]]
    then
        echo "Error: NUM_USERS too high for the given NUM_AGGREGATORS"
        exit -1
    fi
}

# Removes all the intermediate files
clean() {
    # The below pattern removes all files of the form "client/user-stateX.txt" for any X
    rm -f ${USER_STATE%.txt}*.txt || true
    rm -f ${USER_SERVERKEYS%.txt}*.txt || true
    rm -f ${AGG_STATE%.txt}*.txt || true
    rm -f $AGG_ROOTSTATE || true
    rm -f ${AGG_SERVERKEYS%.txt}*.txt || true
    rm -f ${SERVER_STATE%.txt}*.txt || true
    rm -f $SERVER_SHARES || true
    echo "Cleaned"
}

# Creates new servers and records their KEM pubkeys
setup_servers() {
    touch $USER_SERVERKEYS
    cd server

    # Make a bunch of servers and save their pubkeys in client/ and aggregator/
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        # TODO: Do server registration
        $CMD_PREFIX new --server-state "../$STATE" > /dev/null
        $CMD_PREFIX get-kem-pubkey --server-state "../$STATE" >> "../$USER_SERVERKEYS"
    done

    # Copy the pubkey file to the aggregator
    cp "../$USER_SERVERKEYS" "../$AGG_SERVERKEYS"

    cd ..
}

# Creates new aggregators wrt the server KEM pubkeys
setup_aggregators() {
    cd aggregator

    # Accumulate the client registration data in this variable. The separator we use is ';'
    AGG_REGS=""

    # Make new base-level aggregators and capture the registration data
    for i in $(seq 1 $NUM_AGGREGATORS); do
        STATE="${AGG_STATE%.txt}$i.txt"
        AGG_REG=$(
            $CMD_PREFIX new --agg-state "../$STATE" --server-keys "../$AGG_SERVERKEYS"
        )

        # Append
        if [[ i -eq 1 ]]; then
            AGG_REGS="$AGG_REG"
        else
            AGG_REGS="$AGG_REGS;$AGG_REG"
        fi
    done

    # Make a new root aggregator and capture the registration data
    AGG_REG=$(
        $CMD_PREFIX new --agg-state "../$AGG_ROOTSTATE" --server-keys "../$AGG_SERVERKEYS"
    )
    AGG_REGS="$AGG_REGS;$AGG_REG"

    # Now do the registrations
    cd ../server

    # Read the regs into a variable
    IFS=';' read -ra AGG_REGS <<< "$AGG_REGS"

    # Register all the aggregators
    for AGG_REG in "${AGG_REGS[@]}"; do
        echo $(seq 1 $NUM_SERVERS)
        for i in $(seq 1 $NUM_SERVERS); do
            STATE="${SERVER_STATE%.txt}$i.txt"
            echo $AGG_REG | $CMD_PREFIX register-aggregator --server-state "../$STATE"
        done
    done

    cd ..
}

# Creates new clients wrt the server KEM pubkeys
setup_clients() {
    cd client

    # Accumulate the client registration data in this variable. The separator we use is ';'
    USER_REGS=""

    # Make new clients and capture the registration data
    for i in $(seq 1 $NUM_USERS); do
        STATE="${USER_STATE%.txt}$i.txt"
        USER_REG=$(
            $CMD_PREFIX new --user-state "../$STATE" --server-keys "../$USER_SERVERKEYS"
        )

        # Append
        if [[ i -eq 1 ]]; then
            USER_REGS="$USER_REG"
        else
            USER_REGS="$USER_REGS;$USER_REG"
        fi
    done

    # Now do the registrations
    cd ../server

    # Read the regs into an array
    IFS=';' read -ra USER_REGS <<< "$USER_REGS"

    for USER_REG in "${USER_REGS[@]}"; do
        for i in $(seq 1 $NUM_SERVERS); do
            STATE="${SERVER_STATE%.txt}$i.txt"
            echo $USER_REG | $CMD_PREFIX register-user --server-state "../$STATE"
        done
    done

    cd ..
}

# Starts round $ROUND with all the aggregators
start_round() {
    cd aggregator

    # Start the base aggregators
    for i in $(seq 1 $NUM_AGGREGATORS); do
        STATE="${AGG_STATE%.txt}$i.txt"
        $CMD_PREFIX start-round --agg-state "../$STATE" --round $ROUND
    done
    # Start the root aggregator
    $CMD_PREFIX start-round --agg-state "../$AGG_ROOTSTATE" --round $ROUND

    cd ..
}

# Encrypts the messages and sends them to the aggregators
encrypt_msgs() {
    cd client

    # Read the messages into a variable
    IFS=';' read -ra MSGS <<< "$MSGS"

    if [[ ${#MSGS[@]} -lt $NUM_USERS ]]; then
        echo "Error: we don't have enough sample messages for $NUM_USERS users"
        exit -1
    fi

    # Accumulate the ciphertexts. The separator we use is ';'
    CIPHERTEXTS=""

    # Encrypt all the messages in sequence
    for i in $(seq 1 $NUM_USERS); do
        STATE="${USER_STATE%.txt}$i.txt"
        MSG="${MSGS[$i]}"

        echo -n $MSG;

        CIPHERTEXT=$(
            echo -ne "$MSG" \
            | base64 \
            | $CMD_PREFIX encrypt-msg --user-state "../$STATE" --round $ROUND
        )

        # Append
        if [[ i -eq 1 ]]; then
            CIPHERTEXTS="$CIPHERTEXT"
        else
            CIPHERTEXTS="$CIPHERTEXTS;$CIPHERTEXT"
        fi
    done

    # Read the ciphertexts into an array
    IFS=';' read -ra CIPHERTEXTS <<< "$CIPHERTEXTS"

    cd ..

    # Then send user messages to the base-level aggregators
    cd aggregator

    # Now send them to the base-level aggregators, parititoning the users
    i=0
    CURRENT_AGG=1
    for CIPHERTEXT in "${CIPHERTEXTS[@]}"; do
        # If we've already sent N ciphertext to this aggregator, switch to the next
        if [[ $i -eq $NUM_USERS_PER_AGGREGATOR ]]; then
            CURRENT_AGG=$(($CURRENT_AGG + 1))
            i=0
        fi
        STATE="${AGG_STATE%.txt}$CURRENT_AGG.txt"

        echo "$CIPHERTEXT" | $CMD_PREFIX input --agg-state "../$STATE"

        i=$(($i + 1))
    done

    cd ..
}

# Propagates the base-level aggregates to the root aggregator
propagate_aggregates() {
    cd aggregator

    # Collect the second-to-top aggregates. Currently we only support two layers
    AGGS=""
    for i in $(seq 1 $NUM_AGGREGATORS); do
        STATE="${AGG_STATE%.txt}$i.txt"
        AGG=$($CMD_PREFIX finalize --agg-state "../$STATE")

        # Append
        if [[ i -eq 1 ]]; then
            AGGS="$AGG"
        else
            AGGS="$AGGS;$AGG"
        fi
    done

    # Read the aggregates into an array
    IFS=';' read -ra AGGS <<< "$AGGS"

    # Now input all the aggregates into the root aggregator
    for AGG in "${AGGS[@]}"; do
        echo "$AGG" | $CMD_PREFIX input --agg-state "../$AGG_ROOTSTATE"
    done

     cd ..
}

# Decrypts the aggregated messages using the server's secrets
decrypt_msgs() {
    # Finalize the root aggregator
    cd aggregator
    AGG=$($CMD_PREFIX finalize --agg-state "../$AGG_ROOTSTATE")
    cd ..

    cd server

    # Create the unblinded shares file
    touch "../$SERVER_SHARES"

    # For each server, unblind the top-level aggregate and put them all in the server share file
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        echo $AGG \
            | $CMD_PREFIX unblind-aggregate --server-state "../$STATE" \
            >> "../$SERVER_SHARES"
    done

    # Now have every combine the shares. The output should be the same for all of them.
    for i in $(seq 1 $NUM_SERVERS); do
        STATE="${SERVER_STATE%.txt}$i.txt"
        ROUND_OUTPUT=$(
            $CMD_PREFIX combine-shares --server-state "../$STATE" --shares "../$SERVER_SHARES"
        )

        echo -n "ROUND OUTPUT: "
        echo -n $ROUND_OUTPUT | base64 -d
        echo ""
    done

    cd ..
}

clean
check
setup_servers
setup_aggregators
setup_clients
start_round
encrypt_msgs
propagate_aggregates
decrypt_msgs
