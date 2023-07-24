def time_cal():
    with open("server/time_recorder.txt", "r") as file:
        lines = file.readlines()
        timestamps = [int(line.strip()) for line in lines]

    with open("client/client_time_recorder.txt", "r") as file:
        client_lines = file.readlines()
        client_timestamps = [int(line.strip()) for line in lines]
    
    max_client_timestamp = max(client_timestamps)
    min_client_timestamp = min(client_timestamps)
    # for client_timestamp in client_timestamps:
    #     max_client_timestamp
    dt1 = timestamps[0]
    dt2 = min_client_timestamp
    dt3 = timestamps[1]
    dt4 = timestamps[2]

    time_difference = dt4 - dt3 + dt2 - dt1

    with open("server/time_recorder_all.txt", "a") as file:
        file.write(str(time_difference) + "\n")

    print(time_difference)