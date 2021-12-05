from cryptography.hazmat.primitives.asymmetric import dh

def client():
    return client_private_key

def server():
    return server_private_key

parameters = dh.generate_parameters(generator=2, key_size=2048)
client_private_key = parameters.generate_private_key()
server_private_key = parameters.generate_private_key()