from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

parameters = dh.generate_parameters(generator=2, key_size=2048)
client_private_key = parameters.generate_private_key()
server_private_key = parameters.generate_private_key()

shared_secret = client_private_key.exchange(server_private_key.public_key()) 
session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'session key',
    ).derive(shared_secret)
session_key_int = int.from_bytes(session_key, byteorder='big')

#In our implementation of Diffie Hellman, the parameters are reused but a new private key is generated every time 
#a message needs to be exchanged to ensure forward secrecy.
def diffie_hellman():
    return session_key_int
