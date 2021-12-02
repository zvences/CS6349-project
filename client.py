#!/usr/bin/env python3

import socket
import sys
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import struct
from Crypto.PublicKey import RSA
import uuid

HOST = '127.0.0.1'  # server IP address
PORT = 65432        # server port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

def verify(file):
    # verify received certificate
    with open('./'+file, 'r') as server_cert_file:
        server_cert = server_cert_file.read()

    with open('./ca-cert.pem', 'r') as ca_cert_file:
        ca_cert = ca_cert_file.read()

    verified = verify_chain_of_trust(server_cert, ca_cert)

    if verified:
        print('\t*Certificate verified*')
    else:
        print('\t*Certificate not verified*')


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



with open("server-pubkey.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

with open("server-keyout.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

message = b'encrypt me!'

encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
print("#######:",original_message)

def DH_handshake(key):
    # acquire session key
    session_key = b''
    pub_key = RSA.importkey(key)
    rsa_key = crypto.PKCS12

    return session_key

if __name__ == "__main__":
    
    file_name = 'ser-cert.pem'
    
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


    print("Starting DH Handshake")

    send(s, b"DH Start")

    s.send(encrypted)

    endMsg = b'close'
    send(s, b'close')
    print('-Closing Connection-')