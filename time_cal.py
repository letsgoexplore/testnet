# -*- coding: utf-8 -*-

def read_timestamps_from_file(filepath):
    timestamps = []
    with open(filepath, "r") as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip()
            # If the line is empty or too long, set the value to 0
            if not line or len(line) > 20:
                timestamps.append(0)
                continue
            try:
                timestamps.append(int(line))
            except ValueError:
                # If the line cannot be converted to an integer, set the value to 0
                timestamps.append(0)
    return timestamps

def time_cal():
    # Read timestamps from aggregator and server files
    agg_timestamps = read_timestamps_from_file("aggregator/time_recorder.txt")
    server_timestamps = read_timestamps_from_file("server/time_recorder.txt")
    
    group_num = len(server_timestamps) // 2
    agg_runtimes=[]
    server_runtimes=[]
    end2end_times=[]
    with open("server/result_time.txt", "a") as file:
        for i in range(group_num):
            ts1 = agg_timestamps[33*i]
            ts2 = agg_timestamps[33*i+32]
            ts3 = server_timestamps[2*i]
            ts4 = server_timestamps[2*i+1]

            agg_runtime = ts2 - ts1
            server_runtime = ts4 - ts3
            end2end_time = ts4 - ts1
            
            agg_runtimes.append(agg_runtime)
            server_runtimes.append(server_runtime)
            end2end_times.append(end2end_time)

            file.write("group" + str(i) + ":\n")
            file.write("agg_runtime:" + str(agg_runtime) + "ns\n")
            file.write("server_runtime:" + str(server_runtime) + "ns\n")
            file.write("end2end_time:" + str(end2end_time) + "ns\n")
        agg_runtime_avg = sum(agg_runtimes)/ len(agg_runtimes)
        server_runtime_avg = sum(server_runtimes) / len(server_runtimes)
        end2end_time_avg = sum(end2end_times) / len(end2end_times)
        file.write("average:\n")
        file.write("agg_runtime:" + str(agg_runtime_avg) + "ns\n")
        file.write("server_runtime:" + str(server_runtime_avg) + "ns\n")
        file.write("end2end_time:" + str(end2end_time_avg) + "ns\n")
