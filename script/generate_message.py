import random
import binascii
import os

def generate_random_hex(length):
    num_bytes = (length + 1) // 2
    random_bytes = bytearray(random.getrandbits(8) for _ in range(num_bytes))
    random_hex = binascii.hexlify(random_bytes)[:length]
    return random_hex

def generate_round_multiple_message(user, length):
    folder_name = '../client/message'
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        
    for i in range(user):  
        random_message_hex = generate_random_hex(length)
        filename = "../client/message/clientmessage_" + str(i) + ".txt"
        with open(filename, "w") as file:
            file.write(random_message_hex)
        print("already saved in {}".format(filename))
# generate_round_multiple_message(2,10)