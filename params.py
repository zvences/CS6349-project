from cryptography.hazmat.primitives.asymmetric import dh

def parameters():
    return parameters

parameters = dh.generate_parameters(generator=2, key_size=2048)
