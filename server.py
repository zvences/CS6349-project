#!/usr/bin/env python3

import socket
import struct
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = '127.0.0.1'  
PORT = 65432        

#def connect():
    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #     s.bind((HOST, PORT))
    #     s.listen()
    #     conn, addr = s.accept()
    #     with conn:
    #         print('Connected by', addr)
    #         while True:
    #             data = conn.recv(1024)
    #             if not data:
    #                 break
    #             conn.sendall(data)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST,PORT))
s.listen(1)
(conn, address) = s.accept()

def send(connection, message):
    try:
        connection.send(struct.pack("i", len(message)) + message)
        return True
    except OSError as er:
        print (er)
        return False
def receive( channel ):
    try:
        msg = b''
        size = struct.unpack("i", channel.recv(struct.calcsize("i")))[0]
        data = ""
        while len(data) < size:
            msg = channel.recv(size - len(data))
            if not msg:
                return None
            data += msg.decode('utf-8')
        return msg
    except OSError as e:
        print (e)
        return False

def decrypt(encr_msg):
    
    with open("server-keyout.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    original_message = private_key.decrypt(
        encr_msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("\tDecrypted:", original_message)

encrypted = b''
while True:
    data = receive(conn)
    if not data:
        break
    file_name = 'server-cert.pem'
    try:
        msg = data.decode('utf-8')
    except UnicodeDecodeError as e:
        #print(e)
        print(data)
        msg = 'Misc bytes'

    print("Received: ", msg)
    if(msg == "Certificate request"):
        print("\n\tretreiving cetificate...")
        with open(file_name, 'rb') as fs: 
            while True:
                data = fs.read(1024)
                send(conn, data)
                if not data:
                    #conn.send(b"done")
                    break
            fs.close()
            print("Sent: Certificate")
    elif (msg == "DH Start"):
        encrypted = b''
        while sys.getsizeof(encrypted) < 289:
            
            encrypted = conn.recv(289-sys.getsizeof(encrypted))
            if not encrypted:
                break
            
            
        decrypt(encrypted)
    elif(msg == "close"):
        print("-Closing Connection-")
        break
    else:
        conn.send(b"received :)")
    
    





