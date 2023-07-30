FOLDER_PREFIX="./data_saving"
WORKING_ADDR="./testnet"
KEY_ADDRESS="./dc-net-test.pem"


mitigate_to_database(){
    SERVER_AWS_COMMAND=$1
    FOLDER="$FOLDER_PREFIX/$2"

    # mitigate server-state
    for i in $(seq 1 $NUM_SERVERS); do 
        LOCAL_ADDR="$FOLDER/server-state$i.txt" 
        REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
        scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
        echo "success! server-state $i moved"
    done

    # mitigate root-agg-state
    LOCAL_ADDR="$FOLDER/agg-root-state.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/agg-root-state.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! agg-state moved"

    # mitigate client-error
    LOCAL_ADDR="$FOLDER/error.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/error.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! error moved"

    # mitigate data_collection
    LOCAL_ADDR="$FOLDER/data_collection.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! data_collection moved"
}

mitigate_to_test(){
    SERVER_AWS_COMMAND=$1
    WORKING_AWS_COMMAND=$2
    # mitigate server-state
    for i in $(seq 1 $NUM_SERVERS); do 
        LOCAL_ADDR="$WORKING_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
        REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
        scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
        echo "success! server-state $i moved"
    done

    # mitigate root-agg-state
    LOCAL_ADDR="$WORKING_AWS_COMMAND:$WORKING_ADDR/aggregator/agg-root-state.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/agg-root-state.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! agg-state moved"

    # mitigate client-error
    LOCAL_ADDR="$WORKING_AWS_COMMAND:$WORKING_ADDR/aggregator/error.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/error.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! error moved"

    # mitigate data_collection
    LOCAL_ADDR="$WORKING_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! data_collection moved"
}

if [[ $1 == "database" ]]; then
    # source AWS Command, Foler-name
    mitigate_to_database $2 $3
elif [[ $1 == "test" ]]; then
    # source AWS Command, target AWS Command
    mitigate_to_test $2 $3
else
    echo "command incorrect"
fi