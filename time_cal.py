# -*- coding: utf-8 -*-

def time_cal():
    # part1: calculate the entire time
    with open("server/time_recorder.txt", "r") as file:
        lines = file.readlines()
        timestamps = [int(line.strip()) for line in lines]

    dt1 = timestamps[0]
    dt2 = timestamps[1]


    time_difference = dt2 - dt1
    with open("server/time_recorder_all.txt", "a") as file:
        # file.write(str(time_difference) + "\n")
        file.write("duration after sending to end:" + str(time_difference) + "ns\n")
    print(time_difference)
