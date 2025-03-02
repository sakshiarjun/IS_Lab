'''
As part of a project to enhance the security of communication in a peer-to-peer
file sharing system, you are tasked with implementing a secure key exchange
mechanism using the Diffie-Hellman algorithm. Each peer must establish a
shared secret key with another peer over an insecure channel. Implement the
Diffie-Hellman key exchange protocol, enabling peers to generate their public
and private keys and securely compute the shared secret key. Measure the time
taken for key generation and key exchange processes.
'''

from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
import time

# Generate Diffie-Hellman parameters (p, g)
key = DSA.generate(2048)
p = key.p
g = key.g

#Alice generates private and public keys
start_time = time.perf_counter()
private_key_1 = int.from_bytes(get_random_bytes(32), byteorder='big') % p
public_key_1 = pow(g, private_key_1, p)
key_gen_time_1 = time.perf_counter() - start_time

#Bob generates private and public keys
start_time = time.perf_counter()
private_key_2 = int.from_bytes(get_random_bytes(32), byteorder='big') % p
public_key_2 = pow(g, private_key_2, p)
key_gen_time_2 = time.perf_counter() - start_time

#Alice computes shared secret with Alice's pvt key and Bob's public key
start_time = time.perf_counter()
shared_secret_1 = pow(public_key_2, private_key_1, p)
key_exchange_time_1 = time.perf_counter() - start_time

# Peer 2 computes shared secret
start_time = time.perf_counter()
shared_secret_2 = pow(public_key_1, private_key_2, p)
key_exchange_time_2 = time.perf_counter() - start_time

# # Results
# print(f"Peer 1 Private Key: {private_key_1}")
# print(f"Peer 1 Public Key: {public_key_1}")
# print(f"Peer 2 Private Key: {private_key_2}")
# print(f"Peer 2 Public Key: {public_key_2}")
# print(f"Shared Secret (Peer 1): {shared_secret_1}")
# print(f"Shared Secret (Peer 2): {shared_secret_2}")

print(f"Key Generation Time (Peer 1): {key_gen_time_1:.10f} seconds")
print(f"Key Generation Time (Peer 2): {key_gen_time_2:.10f} seconds")
print(f"Key Exchange Time (Peer 1): {key_exchange_time_1:.10f} seconds")
print(f"Key Exchange Time (Peer 2): {key_exchange_time_2:.10f} seconds")

# Verify that both shared secrets are the same
print(shared_secret_1 == shared_secret_2)