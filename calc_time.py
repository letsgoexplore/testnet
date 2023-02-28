filename = "output.txt"

client_submit_round_msg = []
client_send_ciphertext = []
client_encrypt_msg = []

agg_submit_agg = []
agg_get_agg_payload = []
agg_start_next_round = []
agg_force_round_end = []
agg_send_aggregate = []

server_unblind_aggregate = []
server_leader_finish_round = []
server_submit_agg = []

def extract_time(line: str) -> float:
    start_index = line.rfind(' ')

    if 'ms' in line:
        end_index = line.rfind('ms')
        t = float(line[start_index:end_index].strip())
    elif 's' in line:
        end_index = line.rfind('s')
        t = float(line[start_index:end_index].strip()) * 1000
    else:
        print("[ERROR] no time found")
        exit(-1)
    return t


def count_talking_clients(line: str) -> int:
    start_index = line.find('scheduling_msg: [') + len('scheduling_msg: [')
    end_index = line.find('], aggregated_msg: [')
    scheduling_msgs = line[start_index : end_index].split(', ')
    print(f"Number of reserved talknig clients for next round: {len(scheduling_msgs) - scheduling_msgs.count('0')}")

    start_index = line.rfind('aggregated_msg: [') + len('aggregated_msg: [')
    end_index = line.rfind('] }, server_sigs')
    agg_msgs = line[start_index : end_index].split(', ')
    print(f"Number of real talking clients: {len(agg_msgs) - agg_msgs.count('EMPTY')}")


with open(filename, encoding="utf-8") as file:
    for line in file:
        if "[client] submit_round_msg:" in line:
            client_submit_round_msg.append(extract_time(line))
        elif "[client] send_ciphertext:" in line:
            client_send_ciphertext.append(extract_time(line))
        elif "[client] encrypt-msg:" in line:
            client_encrypt_msg.append(extract_time(line))
        elif "[agg] submit_agg:" in line:
            agg_submit_agg.append(extract_time(line))
        elif "[agg] get_agg_payload:" in line:
            agg_get_agg_payload.append(extract_time(line)) 
        elif "[agg] start_next_round:" in line:
            agg_start_next_round.append(extract_time(line))
        elif "[agg] force_round_end:" in line:
            agg_force_round_end.append(extract_time(line))
        elif "[agg] send_aggregate:" in line:
            agg_send_aggregate.append(extract_time(line))
        elif "[server] unblind_aggregate:" in line:
            server_unblind_aggregate.append(extract_time(line))
        elif "[server] leader_finish_round:" in line:
            server_leader_finish_round.append(extract_time(line))
        elif "[server] submit_agg:" in line:
            server_submit_agg.append(extract_time(line))
        elif "DEBUG sgxdcnet_server::service] output: RoundOutput { round:" in line:
            count_talking_clients(line)



print(f"client_submit_round_msg size: {len(client_submit_round_msg)}")
print(f"client_send_ciphertext size: {len(client_send_ciphertext)}")
print(f"client_encrypt_msg size: {len(client_encrypt_msg)}")
print(f"agg_submit_agg size: {len(agg_submit_agg)}")
print(f"agg_get_agg_payload size: {len(agg_get_agg_payload)}")
print(f"agg_send_aggregate size: {len(agg_send_aggregate)}")
print(f"agg_start_next_round size: {len(agg_start_next_round)}")
print(f"agg_force_round_end size: {len(agg_force_round_end)}")
print(f"server_unblind_aggregate size: {len(server_unblind_aggregate)}")
print(f"server_leader_finish_round size: {len(server_leader_finish_round)}")
print(f"server_submit_agg size: {len(server_submit_agg)}")

print(f"[client] submit_round_msg: {sum(client_submit_round_msg) / len(client_submit_round_msg)}")
print(f"[client] send_ciphertext: {sum(client_send_ciphertext) / len(client_send_ciphertext)}")
print(f"[client] client_encrypt_msg: {sum(client_encrypt_msg) / len(client_encrypt_msg)}")
print(f"[agg] submit_agg: {sum(agg_submit_agg) / len(agg_submit_agg)}")
print(f"[agg] get_agg_payload: {sum(agg_get_agg_payload) / len(agg_get_agg_payload)}")
print(f"[agg] send_aggregate: {sum(agg_send_aggregate) / len(agg_send_aggregate)}")
print(f"[agg] start_next_round: {sum(agg_start_next_round) / len(agg_start_next_round)}")
print(f"[agg] force_round_end: {sum(agg_force_round_end) / len(agg_force_round_end)}")
print(f"[server] unblind_aggregate: {sum(server_unblind_aggregate) / len(server_unblind_aggregate)}")
print(f"[server] leader_finish_round: {sum(server_leader_finish_round) / len(server_leader_finish_round)}")
print(f"[server] submit_agg: {sum(server_submit_agg) / len(server_submit_agg)}")
