import secrets

def generate_random_hex(length):
    num_bytes = (length + 1) // 2
    random_bytes = secrets.token_bytes(num_bytes)
    random_hex = random_bytes.hex()[:length]
    return random_hex

def generate_round_multiple_message(user, length):
    for i in range(user):  
        random_message_hex = generate_random_hex(length)
        filename = "./client/src/message/clientmessage_" + str(i) + ".txt"
        with open(filename, "w") as file:
            file.write(random_message_hex)
        print(f"already saved in {filename}")

# generate_round_multiple_message(2,10)