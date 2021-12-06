#!/usr/bin/env python3

import socket
import os
import struct

from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import strxor
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from dotenv import load_dotenv

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from params import diffie_hellman


load_dotenv()
host = os.getenv('HOST')    
port = os.getenv('PORT')  

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(1)
(conn, address) = s.accept()

session_key = b''
session_hash = b''

client_seq = 0
server_seq = 0

def send(connection, message):
    # send data 
    #  send size to ensure full packet received
    try:
        connection.send(struct.pack("i", len(message)) + message)
        return True
    except OSError as er:
        print (er)
        return False
def receive(channel):
    # receive data
    # checks size to ensure full packet received
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



def encrypt_and_hash(data, key, hash_key):
    # encrypt data to maintain confidentiality
    #  and hash to maintain integrity
    if(len(data) != 32):
        data = pad(data, 32)
    encr = strxor(SHA256.new(key).digest(),data)
    hashed = SHA256.new(data+hash_key).digest()

    return encr+hashed

def decrypt_and_verify(data, key, hash_key):
    # decrypts value and checks hash value to verify integrity
    #  returns decrypted data
    
    hashed = data[32:]
    data = data[:32]
    decrypted_data = strxor(SHA256.new(key).digest(),data)
    hash_integrity = SHA256.new(decrypted_data+hash_key).digest()

    if not (hash_integrity == hashed):
        print("Message integrity compromised")
        raise ValueError("Message integrity compromised")
    return decrypted_data
def session_sequence():
    # generate convo sequence numbers 
    # to prevent replay/reflection attacks
    recSeq = conn.recv(64)
    
    key_send = "Client".encode()+session_key

    client_seq_bytes = decrypt_and_verify(recSeq, key_send, session_hash)
    client_seq = int.from_bytes(client_seq_bytes, 'big')
    print("Client sequence: ", client_seq)

    server_seq_bytes = get_random_bytes(32)
    server_seq = int.from_bytes(server_seq_bytes, 'big')
    print("Server sequence: ", server_seq)
    sendSeq = encrypt_and_hash(server_seq_bytes, session_key, session_hash)
    conn.send(sendSeq)
    return client_seq, server_seq

def upload_data(client_seq, server_seq):
    # receives data in blocks
    print("\t...Receiving...")
    data = b''
    
    # seq config
    client_seq += 1
    server_seq += 1

    while True:
        rec = conn.recv(64)
        key_send = "Client".encode() + session_key + client_seq.to_bytes(32,"big")
        key_rec = "Server".encode() + session_key + server_seq.to_bytes(32,"big")
        recDec = decrypt_and_verify(rec, key_send, session_hash + client_seq.to_bytes(32, "big"))
        block_len = int.from_bytes(recDec[0:2], 'big')
        block = recDec[2:2+block_len]
        try:
            if block_len == 0:
                ack = b"1"
                sendAck = encrypt_and_hash(ack, key_rec, session_hash+server_seq.to_bytes(32,"big"))
                conn.send(sendAck)
                            
                client_seq += 1
                server_seq += 1
                break
        except UnicodeDecodeError:
            pass
        ack = b"1"
        sendAck = encrypt_and_hash(ack, key_rec, session_hash+server_seq.to_bytes(32,"big"))
        conn.send(sendAck)

        data += block

        client_seq += 1
        server_seq += 1

    return data, client_seq, server_seq


def upload(f_name, client_seq, server_seq):
    print("\t File upload")

    ack = b"1"
    s_seq_bytes = server_seq.to_bytes(32, "big")
    key_send = "Server".encode() + session_key + s_seq_bytes
    hash_send = session_hash + s_seq_bytes

    sendAck = encrypt_and_hash(ack, key_send, hash_send)
    conn.send(sendAck)

    data, client_seq, server_seq = upload_data(client_seq, server_seq)
    server_f_name = "serv_"+f_name
    file = open(server_f_name,"wb")
    file.write(data)
    file.close()
    return client_seq, server_seq


def download_data(data, client_seq, server_seq):
    # uploads data to server in blocks
    print("\t...Sending...")
    block_size = 30
    offset = 0
    end = False

    # key, seq config
    client_seq += 1
    server_seq += 1

    key_client = "Client".encode() + session_key 
    key_server = "Server".encode() + session_key

    while not end:
        block = data[offset:offset + block_size]
        
        if len(block) % block_size != 0 or len(block) == 0:
            end = True

        block = (len(block)).to_bytes(2, "big") + block

        dataSend = encrypt_and_hash(block, key_server + server_seq.to_bytes(32, "big"), session_hash + server_seq.to_bytes(32, "big"))
        
        conn.send(dataSend)

        recv_ack = conn.recv(64)
        ack = decrypt_and_verify(recv_ack, key_client + client_seq.to_bytes(32,"big"), session_hash + client_seq.to_bytes(32,"big"))
        ackUnpad = unpad(ack,32)
        ackReady = ackUnpad.decode()

        if(ackReady != "1"):
            print(ackReady)
            raise Exception("No Ack, block may be lost")

        client_seq += 1
        server_seq += 1
        offset +=block_size
    dint = 0
    done = dint.to_bytes(2, "big")
    dataSend = encrypt_and_hash(done, key_server + server_seq.to_bytes(32, "big"), session_hash+ server_seq.to_bytes(32, "big"))

    conn.send(dataSend)
    recv_ack = conn.recv(64)
    ack = decrypt_and_verify(recv_ack, key_client+client_seq.to_bytes(32,"big"), session_hash + client_seq.to_bytes(32,"big"))
    ackUnpad = unpad(ack,32)
    ackReady = ackUnpad.decode()

    if(ackReady != "1"):
        print(ackReady)
        raise Exception("No Ack, Done may be lost")
    
    client_seq += 1
    server_seq += 1

    return client_seq, server_seq


def download(f_name, client_seq, server_seq):
    print("\t File download")

    ack = b"1"
    s_seq_bytes = server_seq.to_bytes(32, "big")
    key_send = "Server".encode() + session_key + s_seq_bytes
    hash_send = session_hash + s_seq_bytes

    sendAck = encrypt_and_hash(ack, key_send, hash_send)
    conn.send(sendAck)
    
    up_file = open(f_name, 'rb')
    uploadf = up_file.read()
    
    client_seq, server_seq = download_data(uploadf, client_seq, server_seq)

    return client_seq, server_seq


if __name__ == "__main__":
    encrypted = b''
    
    session_key = diffie_hellman()
    session = int.from_bytes(session_key,"big")
    session_hash = (session+3).to_bytes(16,"big")
    client_seq = 0
    server_seq = 0

    while True:
        data = receive(conn)
        if not data:
            break
        file_name = 'server-cert.pem'
        try:
            msg = data.decode('utf-8')
        except UnicodeDecodeError as e:
            print(data)
            msg = 'Misc bytes'

        print("Received: ", msg)
        if(msg == "Certificate request"):
            print("\tRetrieving certificate...")
            with open(file_name, 'rb') as fs: 
                while True:
                    data = fs.read(1024)
                    send(conn, data)
                    if not data:
                        break
                fs.close()
                print("Sent: Certificate")
        elif(msg == "Sequence"):
            client_seq, server_seq = session_sequence()
            print("Sequence established")
            break
    
    print("_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-")
    while True:
        data = conn.recv(64)
        if not data:
            break

        client_seq +=1
        server_seq +=1

        c_seq_bytes = client_seq.to_bytes(32, "big")
        key_send = "Client".encode() + session_key + c_seq_bytes
        hash_send = session_hash + c_seq_bytes
        decrData = decrypt_and_verify(data, key_send, hash_send)
        
        dataUnpad = unpad(decrData, 32)
        data = dataUnpad.decode() 

        if(data[0] == "1"):
            client_seq, server_seq = upload(data[1:], client_seq, server_seq)
            print("\tFile Uploaded")
        elif(data[0] == "2"):
            client_seq, server_seq = download(data[1:], client_seq, server_seq)
            print("\tFile Downloaded")
        elif(data[0] == "3"):
            print("- Closing Connection -")
            break
        else:
            conn.send(b"received :)")
        
        
        





