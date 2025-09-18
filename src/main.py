import Cryptodome
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import *
from Cryptodome.Util import *
from Cryptodome.IO import *
from Cryptodome.Protocol import *
from Cryptodome.Hash import *

import os
from pathlib import Path
import time
import socket
import json

def sender():

    createKeys()

    print()
    print("Choose a test option:")
    print("1) (AES 128-bit) Send a message to Bob using AES 128-bit key")
    print("2) (RSA 2048-bit) Send a message to Bob using RSA 2048-bit key")
    print("3) (Performance) Mesure the performance of AES and RSA")

    option = input("=>")

    if (option == "1"):
        test_aes()
    elif (option == "2"):
        test_rsa()
    elif (option == "3"):
        print("TODO")
    else:
        print("TODO")



def receiver():
    SOCKET.bind((ADDRESS, PORT))

    print()
    print("Listening to " + ADDRESS + ":" + str(PORT))

    while True:
        buffer_size = 4096
        data, address = SOCKET.recvfrom(buffer_size)

        json_data = json.loads(data.decode())

        ciphertext = bytes.fromhex(json_data["ciphertext"])
        encryption_method = str(json_data["encryption-method"])

        if (encryption_method == "aes"):
            iv = bytes.fromhex(json_data["iv"])
            block_size = int(json_data["block-size"])

            aes_file_path = Path("keys/aes-" + str(block_size * 8))

            if (not aes_file_path.exists()):
                print()
                print("Error: AES-" + str(block_size * 8) + " bit key does not exist.")
                continue

            aes_key = ""

            with open(aes_file_path, "rb") as file:
                aes_key = file.read()

            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext = Padding.unpad(cipher.decrypt(ciphertext), block_size).decode()

            print()
            print("Message received from Alice: " + plaintext)
        elif (encryption_method == "rsa"):
            key_size = int(json_data["key-size"])

            rsa_private_file_path = Path("keys/rsa-" + str(key_size) + "-private")

            if (not rsa_private_file_path.exists()):
                print()
                print("Error: RSA-" + str(key_size) + " bit key pair does not exist.")
                continue

            rsa_private = b""

            with open(rsa_private_file_path, "rb") as file:
                rsa_private = file.read()

            cipher = PKCS1_OAEP.new(RSA.import_key(rsa_private))
            plaintext = cipher.decrypt(ciphertext).decode()

            print()
            print("Message received from Alice: " + plaintext)

        else:
            print()
            print(data)






###################
# Sender functions

def test_aes():
    aes_128_file_path = Path("keys/aes-128")

    if (not aes_128_file_path.exists()):
        print()
        print("Error: AES-128 bit key does not exist.")
        print("Attempting to create a new key...")

        createKeys()
        aes_128_file_path = Path("keys/aes-128")

    aes_128_key = ""

    with open(aes_128_file_path, "rb") as file:
        aes_128_key = file.read()
    
    print()
    print("AES-128 key: " + str(aes_128_key))

    print()
    print("Enter a message to send to Bob.")

    message = input("=>")

    print()
    print("Encrypting message...")

    cipher = AES.new(aes_128_key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(Padding.pad(message.encode(), 16))

    print("Sending encrypted message...")

    data = json.dumps({
        "ciphertext": ciphertext.hex(),
        "iv": iv.hex(),
        "encryption-method": "aes",
        "block-size": 16
    }).encode()

    SOCKET.sendto(data, (ADDRESS, PORT))

    print("The message has been sent to Bob.")

    ctext_file_path = Path("keys/ctext")
    with open(ctext_file_path, "wb") as file:
        file.write(ciphertext)
    
    print()
    print("The message was written to 'ctext'.")


def test_rsa():
    rsa_2048_private_file_path = Path("keys/rsa-2048-private")
    rsa_2048_public_file_path = Path("keys/rsa-2048-public")

    if (not rsa_2048_private_file_path.exists() or not rsa_2048_public_file_path.exists()):
        print()
        print("Error: RSA-2048 bit key pair does not exist.")
        print("Attempting to create a new key pair...")

        createKeys()
        rsa_2048_private_file_path = Path("keys/rsa-2048-private")
        rsa_2048_public_file_path = Path("keys/rsa-2048-public")

    rsa_2048_public = b""

    with open(rsa_2048_public_file_path, "rb") as file:
        rsa_2048_public = file.read()
    
    print()
    print("RSA-2048 public key: " + str(rsa_2048_public))

    print()
    print("Enter a message to send to Bob.")

    message = input("=>")

    print()
    print("Encrypting message...")

    cipher = PKCS1_OAEP.new(RSA.import_key(rsa_2048_public))
    ciphertext = cipher.encrypt(message.encode())

    print("Sending encrypted message...")

    data = json.dumps({
        "ciphertext": ciphertext.hex(),
        "encryption-method": "rsa",
        "key-size": 2048
    }).encode()

    SOCKET.sendto(data, (ADDRESS, PORT))

    print("The message has been sent to Bob.")

    ctext_file_path = Path("keys/ctext")
    with open(ctext_file_path, "wb") as file:
        file.write(ciphertext)
    
    print()
    print("The message was written to 'ctext'.")

    

def createKeys():
    aes_128_file_path = Path("keys/aes-128")

    if (not aes_128_file_path.exists()):
        print()
        print("AES-128 key not found.")
        print("Creating random AES-128 key...")

        aes_128_key = get_random_bytes(128 // 8)

        if (not aes_128_file_path.parent.exists()):
            aes_128_file_path.parent.mkdir(parents = True, exist_ok = True)

        with open(aes_128_file_path, "wb") as file:
            file.write(aes_128_key)

        print("Done.")

    #################

    rsa_2048_private_file_path = Path("keys/rsa-2048-private")
    rsa_2048_public_file_path = Path("keys/rsa-2048-public")

    if (not rsa_2048_private_file_path.exists() or not rsa_2048_public_file_path.exists()):
        print()
        print("RSA-2048 key pair not found.")
        print("Creating random RSA-2048 key pair...")

        rsa_2048_key = RSA.generate(2048)
        rsa_2048_private = rsa_2048_key.export_key("DER")
        rsa_2048_public = rsa_2048_key.public_key().export_key("DER")

        with open(rsa_2048_private_file_path, "wb") as file:
            file.write(rsa_2048_private)

        with open(rsa_2048_public_file_path, "wb") as file:
            file.write(rsa_2048_public)
        
        print("Done.")

    






###################
###################
# Receiver functions





###################


ADDRESS = "127.0.0.1"
PORT = 5200
SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("=" * 30)
print(f"{'Encrypted Communication':^30}")
print(f"{'Brandon Key':^30}")
print("=" * 30)

print()
print("Do you want to be the sender (Alice) or the reciever (Bob)?")
print("1) Sender (Alice)")
print("2) Receiver (Bob)")

role = input("=>")

if (role == "1"):
    print("You chose Sender (Alice).")
    sender()
else:
    print("You chose Receiver (Bob).")
    receiver()

SOCKET.close()
