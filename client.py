#!/usr/bin/env python3

import socket
from OpenSSL import crypto

def verify(file):
    with open('./'+file, 'r') as server_cert_file:
        server_cert = server_cert_file.read()

    with open('./ca-cert.pem', 'r') as ca_cert_file:
        ca_cert = ca_cert_file.read()

    verified = verify_chain_of_trust(server_cert, ca_cert)

    if verified:
        print('*Certificate verified*')
    else:
        print('*Certificate not verified*')


def verify_chain_of_trust(server_pem, ca_cert_pem):

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


HOST = '127.0.0.1'  # server IP address
PORT = 65432        # server port
# def connect():
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.connect((HOST, PORT))
#         s.sendall(b'Send server-req.pem')
#         s.sendall(b' one two')
#         data = s.recv(1024)

#     print('Received .', repr(data),'.')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
file_name = 'ser-cert.pem'

s.send(b'Certificate request')
print("Sent: Certificate request")

print("...")
with open(file_name, 'wb') as fw:
    while True:
        data = s.recv(1024)
        if not data:
            break
        fw.write(data)
    fw.close()
print("Received: Certificate")

# with open("./client-pubkey.pem") as f:
#     contents = f.read()
# print("********",contents)
#clprivkey = crypto.load_publickey(crypto.FILETYPE_PEM, contents)
#print(clprivkey)

def main():
    verify(file_name)
    #connect()


if __name__ == "__main__":
    main()