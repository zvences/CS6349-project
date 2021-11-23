#!/usr/bin/env python3

import socket

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
while True:
    (conn, address) = s.accept()
    data = conn.recv(32)
    print("Received: ", data.decode('utf-8'))
    file_name = 'server-cert.pem'

    with open(file_name, 'rb') as fs: 
        while True:
            data = fs.read(1024)
            conn.send(data)
            if not data:
                break
        fs.close()
        
        print("Sent: Certificate")
    break

