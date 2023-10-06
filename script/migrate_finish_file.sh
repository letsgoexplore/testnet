FOLDER_PREFIX="../data_saving"
WORKING_ADDR="./testnet1"
KEY_ADDRESS="../.ssh/dc-net-test.pem"


migrate_to_database(){
    SERVER_AWS_COMMAND=$1
    FOLDER="$FOLDER_PREFIX/$2"
    NUM_SERVERS=$3
    NUM_THREAD=$4
    # migrate server-state
    for i in $(seq 1 $NUM_SERVERS); do 
        LOCAL_ADDR="$FOLDER/server-state$i.txt" 
        REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
        scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
        echo "success! server-state $i moved"
    done

    # migrate root-agg-state
    LOCAL_ADDR="$FOLDER/agg-root-state.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/agg-root-state.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! agg-state moved"

    # migrate client-error
    LOCAL_ADDR="$FOLDER/error.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/error.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! error moved"

    # migrate data_collection
    LOCAL_ADDR="$FOLDER/data_collection.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! data_collection moved"
    
    for i in $(seq 1 $NUM_THREAD); do 
        LOCAL_ADDR="$FOLDER/data_collection_$i.txt" 
        REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection_$i.txt"
        scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
        echo "success! data_collection_$i moved"
    done

    for i in $(seq 1 $NUM_THREAD); do 
        LOCAL_ADDR="$FOLDER/agg_state_$i.txt" 
        REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/agg_state_$i.txt"
        scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
        echo "success! agg_state_$i moved"
    done

    # migrate server-keys
    LOCAL_ADDR="$FOLDER/server-keys.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/server-keys.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! server-keys moved"

    # migrate aggregate time-record
    LOCAL_ADDR="$FOLDER/aggregator_time_recorder.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/time_recorder.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! agg-recorder moved"

    # migrate aggregate time-record
    LOCAL_ADDR="$FOLDER/server_time_recorder.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/time_recorder.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! server-record moved"

    LOCAL_ADDR="$FOLDER/time_recorder_detailed_timestamp.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/time_recorder_detailed_timestamp.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! server-record moved"

    # migrate all time result
    LOCAL_ADDR="$FOLDER/result_time.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/result_time.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! result_time-record moved"

    # migrate server_ctrl.sh
    # LOCAL_ADDR="$FOLDER/server_ctrl.sh"
    # REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server_ctrl.sh"
    # scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    # echo "success! server_ctrl.sh moved"

    # migrate dc-net-control.sh
    # LOCAL_ADDR="$FOLDER/dc-net-control.sh"
    # REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/dc-net-control.sh"
    # scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    # echo "success! data_collection moved"
}

send_time_recorder_to_databse(){
    SERVER_AWS_COMMAND=$1
    FOLDER="$FOLDER_PREFIX/$2"
    NUM_SERVERS=$3
    NUM_THREAD=$4
    
    # migrate aggregate time-record
    LOCAL_ADDR="$FOLDER/aggregator_time_recorder.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/time_recorder.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! agg-recorder moved"

    # migrate server time-record
    LOCAL_ADDR="$FOLDER/server_time_recorder.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/time_recorder.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! server-record moved"

    LOCAL_ADDR="$FOLDER/time_recorder_detailed_timestamp.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/time_recorder_detailed_timestamp.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! server-record moved"

    # migrate all time result
    LOCAL_ADDR="$FOLDER/result_time.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/result_time.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! result_time-record moved"
}

database_to_test(){
    SERVER_AWS_COMMAND=$1
    FOLDER="$FOLDER_PREFIX/$2"
    NUM_SERVERS=$3
    NUM_THREAD=$4
    # migrate server-state
    for i in $(seq 1 $NUM_SERVERS); do 
        LOCAL_ADDR="$FOLDER/server-state$i.txt" 
        REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
        scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
        echo "success! server-state $i moved"
    done

    # migrate root-agg-state
    LOCAL_ADDR="$FOLDER/agg-root-state.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/agg-root-state.txt"
    scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
    echo "success! agg-state moved"

    # migrate client-error
    LOCAL_ADDR="$FOLDER/error.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/error.txt"
    scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
    echo "success! error moved"

    # migrate data_collection
    LOCAL_ADDR="$FOLDER/data_collection.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection.txt"
    scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
    echo "success! data_collection moved"

    for i in $(seq 1 $NUM_THREAD); do 
        LOCAL_ADDR="$FOLDER/data_collection_$i.txt" 
        REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection_$i.txt"
        scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
        echo "success! data_collection_$i moved"
    done

    for i in $(seq 1 $NUM_THREAD); do 
        LOCAL_ADDR="$FOLDER/agg_state_$i.txt" 
        REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/agg_state_$i.txt"
        scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
        echo "success! agg_state_$i moved"
    done

    # migrate server-keys
    LOCAL_ADDR="$FOLDER/server-keys.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/server-keys.txt"
    scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
    echo "success! server-keys moved"
}

send_back_client_test(){
    SERVER_AWS_COMMAND=$1
    FOLDER="$FOLDER_PREFIX/$2"

    LOCAL_ADDR="$FOLDER/result_time.txt"
    REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/client/time_recorder.txt"
    scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
    echo "success! result_time-record moved"
}

    # # migrate server_ctrl.sh
    # LOCAL_ADDR="$FOLDER/server_ctrl.sh"
    # REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server_ctrl.sh"
    # scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
    # echo "success! server_ctrl.sh moved"

    # # migrate dc-net-control.sh
    # LOCAL_ADDR="$FOLDER/dc-net-control.sh"
    # REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/dc-net-control.sh"
    # scp -i $KEY_ADDRESS "$LOCAL_ADDR" "$REMOTE_ADDR" 
    # echo "success! data_collection moved"


# migrate_to_test(){
#     SERVER_AWS_COMMAND=$1
#     WORKING_AWS_COMMAND=$2
#     NUM_SERVERS=$3
#     # migrate server-state
#     for i in $(seq 1 $NUM_SERVERS); do 
#         LOCAL_ADDR="$WORKING_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
#         REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/server/server-state$i.txt"
#         scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
#         echo "success! server-state $i moved"
#     done

#     # migrate root-agg-state
#     LOCAL_ADDR="$WORKING_AWS_COMMAND:$WORKING_ADDR/aggregator/agg-root-state.txt"
#     REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/agg-root-state.txt"
#     scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
#     echo "success! agg-state moved"

#     # migrate client-error
#     LOCAL_ADDR="$WORKING_AWS_COMMAND:$WORKING_ADDR/aggregator/error.txt"
#     REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/error.txt"
#     scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
#     echo "success! error moved"

#     # migrate data_collection
#     LOCAL_ADDR="$WORKING_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection.txt"
#     REMOTE_ADDR="$SERVER_AWS_COMMAND:$WORKING_ADDR/aggregator/data_collection.txt"
#     scp -i $KEY_ADDRESS "$REMOTE_ADDR" "$LOCAL_ADDR" 
#     echo "success! data_collection moved"
# }

if [[ $1 == "database" ]]; then
    # source AWS Command, Folder-name num_server num_thread/num_leaf_aggregator
    migrate_to_database $2 $3 $4 $5
elif [[ $1 == "send-back-recorder" ]]; then
    send_time_recorder_to_databse $2 $3 $4 $5
elif [[ $1 == "fromdatabase" ]]; then
    # source AWS Command, Folder-name num_server num_thread/num_leaf_aggregator
    database_to_test $2 $3 $4 $5
elif [[ $1 == "client" ]]; then
    send_back_client_test $2 $3
else
    echo "command incorrect"
fi
