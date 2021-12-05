#!/usr/bin/env python3

import os
import socket
import struct

from dotenv import load_dotenv
from OpenSSL import crypto
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from params import parameters

load_dotenv()
host = os.getenv('HOST')
port = os.getenv('PORT')
file_name = os.getenv('CLIENT_REC_FILE_NAME')
pub_key = os.getenv('CLIENT_PUB_KEY')
server_pub_key = os.get_env('SERVER_PUB_KEY')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

session_key = b''
session_hash = b''

client_seq = 0
server_seq = 0

def secret_key(file):
    with open('./'+file, 'r') as public_key_file:
        pub_key=public_key_file.read()
        clprivkey = crypto.load_publickey(crypto.FILETYPE_PEM, pub_key)
    return clprivkey


def verify(file):
    # verify received certificate
    with open('./'+file, 'r') as server_cert_file:
        server_cert = server_cert_file.read()

    with open('./ca-cert.pem', 'r') as ca_cert_file:
        ca_cert = ca_cert_file.read()

    verified = verify_chain_of_trust(server_cert, ca_cert)

    if verified:
        print('\t*Certificate verified.*')
    else:
        print('\t*Certificate could not be verified.*')


def verify_chain_of_trust(server_pem, ca_cert_pem):
    # verify certificate chain of trust
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, server_pem)

    # Create and fill a X509Store with trusted certs
    store = crypto.X509Store()

    trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
    
    store.add_cert(trusted_cert)

    # Create a X590StoreContext with the cert and trusted certs
    # and verify the the chain of trust
    store_ctx = crypto.X509StoreContext(store, certificate)
    # Returns None if certificate can be validated
    try:
        result = store_ctx.verify_certificate()
    except crypto.X509StoreContextError as e:
        result = "0"

    if result is None:
        return True
    else:
        return False


def receive(channel):
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


def send( connection, message ):
    try:
        connection.send(struct.pack("i", len(message)) + message)
        return True
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
    client_seq_bytes = get_random_bytes(32)
    client_seq = int.from_bytes(client_seq_bytes,"big")
    print("Client sequence: ", client_seq)
    key_send = "Client".encode()+session_key
    sendSeq = encrypt_and_hash(client_seq_bytes, key_send, session_hash)
    s.send(sendSeq)

    # receive server sequence
    recSeq = s.recv(64)  
    server_seq_bytes = decrypt_and_verify(recSeq, session_key, session_hash)
    server_seq = int.from_bytes(server_seq_bytes, "big")

    print("Server sequence: ", server_seq)
    return client_seq, server_seq


def upload_data(data, client_seq, server_seq):
    # uploads data to server in blocks
    print("\t...Uploading...")
    block_size = 30
    offset = 0
    end = False

    # key, seq config
    client_seq += 1
    server_seq += 1

    key_send = "Client".encode() + session_key 
    key_rec = "Server".encode() + session_key

    while not end:
        block = data[offset:offset + block_size]
        count = 2
        if len(block) % block_size != 0 or len(block) == 0:
            end = True

        block = (len(block)).to_bytes(2, "big") + block

        dataSend = encrypt_and_hash(block, key_send + client_seq.to_bytes(32, "big"), session_hash+ client_seq.to_bytes(32, "big"))
        s.send(dataSend)

        recv_ack = s.recv(64)
        ack = decrypt_and_verify(recv_ack, key_rec+server_seq.to_bytes(32,"big"), session_hash + server_seq.to_bytes(32,"big"))
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
    dataSend = encrypt_and_hash(done, key_send + client_seq.to_bytes(32, "big"), session_hash+ client_seq.to_bytes(32, "big"))

    s.send(dataSend)
    recv_ack = s.recv(64)
    ack = decrypt_and_verify(recv_ack, key_rec+server_seq.to_bytes(32,"big"), session_hash + server_seq.to_bytes(32,"big"))
    ackUnpad = unpad(ack,32)
    ackReady = ackUnpad.decode()

    if(ackReady != "1"):
        print(ackReady)
        raise Exception("No Ack, Done may be lost")
    
    client_seq += 1
    server_seq += 1

    return client_seq, server_seq


def upload(client_seq, server_seq):
    # uploads data to server
    file_n = input("\tType file to be uploaded : ")
    if not os.path.isfile(file_n):
        print("\t**File does not exist")
    else:
        up_file = open(file_n, 'rb')
        uploadf = up_file.read()
        opt_file = "1" + file_n
        c_seq_bytes = client_seq.to_bytes(32, "big")
        
        key_send = "Client".encode() + session_key + c_seq_bytes
        hash_send = session_hash + c_seq_bytes
        send_opt = encrypt_and_hash(opt_file.encode(), key_send, hash_send)
        s.send(send_opt)
        
        recv_ack = s.recv(64)
        s_seq_bytes = server_seq.to_bytes(32, "big")
        key_rec = "Server".encode() + session_key + s_seq_bytes
        hash_rec = session_hash + s_seq_bytes
        decrData = decrypt_and_verify(recv_ack, key_rec, hash_rec)
        ackUnpad = unpad(decrData,32)
        ack = ackUnpad.decode()

        if(ack != "1"):
            print(ack)
            raise Exception("No Ack")

        client_seq, server_seq = upload_data(uploadf, client_seq, server_seq)

    return client_seq, server_seq


def download_data(client_seq, server_seq):
    # receives data in blocks
    print("\t...Receiving...")
    data = b''
    
    # key, seq config
    client_seq += 1
    server_seq += 1


    while True:
        rec = s.recv(64)
        key_client = "Client".encode() + session_key + client_seq.to_bytes(32,"big")
        key_server = "Server".encode() + session_key + server_seq.to_bytes(32,"big")
        recDec = decrypt_and_verify(rec, key_server, session_hash + server_seq.to_bytes(32, "big"))
        block_len = int.from_bytes(recDec[0:2], 'big')
        block = recDec[2:2+block_len]
        try:
            if block_len == 0:
                ack = b"1"
                sendAck = encrypt_and_hash(ack, key_client, session_hash+client_seq.to_bytes(32,"big"))
                s.send(sendAck)
                            
                client_seq += 1
                server_seq += 1
                break
        except UnicodeDecodeError:
            pass
        ack = b"1"
        sendAck = encrypt_and_hash(ack, key_client, session_hash+client_seq.to_bytes(32,"big"))
        s.send(sendAck)

        data += block

        client_seq += 1
        server_seq += 1

    return data, client_seq, server_seq


def download(client_seq, server_seq):
    # downloads data from server
    file_n = input("\tType file to be downloaded : ")
    if not os.path.isfile(file_n):
        print("\t**File does not exist")
    else:
        opt_file = "2" + file_n
        c_seq_bytes = client_seq.to_bytes(32, "big")

        key_send = "Client".encode() + session_key + c_seq_bytes
        hash_send = session_hash + c_seq_bytes
        send_opt = encrypt_and_hash(opt_file.encode(), key_send, hash_send)
        s.send(send_opt)

        recv_ack = s.recv(64)
        s_seq_bytes = server_seq.to_bytes(32, "big")
        key_rec = "Server".encode() + session_key + s_seq_bytes
        hash_rec = session_hash + s_seq_bytes
        decrData = decrypt_and_verify(recv_ack, key_rec, hash_rec)
        ackUnpad = unpad(decrData,32)
        ack = ackUnpad.decode()
        
        data, client_seq, server_seq = download_data(client_seq, server_seq)

        client_f_name = "cli_"+file_n
        file = open(client_f_name,"wb")
        file.write(data)
        file.close()
    return client_seq, server_seq


def close(client_seq, server_seq):
    print("\tSending close")
    opt_file = "3"
    c_seq_bytes = client_seq.to_bytes(32, "big")

    key_send = "Client".encode() + session_key + c_seq_bytes
    hash_send = session_hash + c_seq_bytes
    send_opt = encrypt_and_hash(opt_file.encode(), key_send, hash_send)
    s.send(send_opt)


#In our implementation of Diffie Hellman, the parameters are reused but a new private key is generated every time 
#a message needs to be exchanged to ensure forward secrecy.
def diffie_hellman(params, server_pub):
    client_private_key = params.generate_private_key()
    shared_secret = client_private_key.exchange(server_pub) 
    session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'session key',
    ).derive(shared_secret)
    return session_key


if __name__ == "__main__":
    
    # Authentication
    send(s, b'Certificate request')
    print("Sent: Certificate request")

    print("...")
    with open(file_name, 'wb') as fw:
        while True:
            data = receive(s)
            if not data:
                break
            fw.write(data)
        fw.close()
    print("Received: Certificate")

    verify(file_name)

    session_key = diffie_hellman(parameters, server_pub_key)
    session = int.from_bytes(session_key,"big")
    session_hash = (session+3).to_bytes(16,"big")
    

    print("Starting sequence establishment")
    send(s, b"Sequence")
    client_seq, server_seq = session_sequence()
    print("Sequence established")
    print("_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-")
    while True:
        print("Options:")
        print("1) Upload to server")
        print("2) Download from server")
        print("3) Close connection")
        
        client_seq +=1
        server_seq +=1

        opt = int(input('Select an option : '))

        if (opt == 1):
            print("\tUpload to server")
            client_seq, server_seq = upload(client_seq, server_seq)
            print("\tUpload Complete")

        elif(opt == 2):
            print("\tDownload from server")
            client_seq, server_seq = download(client_seq, server_seq)
            print("\Download Complete")

        elif(opt == 3):
            print("\tClose connection")
            close(client_seq, server_seq)
            print('- Connection Closed -')
            break

        else:
            print("\t**That is not a valid choice")
        
        print("Client sequence: ", client_seq)
        print("Server sequence: ", server_seq)
