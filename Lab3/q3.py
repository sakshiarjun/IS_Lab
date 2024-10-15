'''
Given an ElGamal encryption scheme with a public key (p, g, h) and a
private key x, encrypt the message "Confidential Data". Then decrypt the
ciphertext to retrieve the original message.
'''

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random

message = b"Confidential Data"

def generate_keys():
    p = getPrime(256)
    g = random.randint(2, p-1)
    x = random.randint(1, p-2) #private key
    h = pow(g, x, p) #public key
    return (p,g,h,x)

def elgamal_encrypt(message,p,g,h):
    m = bytes_to_long(message)
    k = random.randint(1, p-2)  #Ephemeral key
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return (c1,c2)

def elgamal_decrypt(c1,c2,p,x):
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m_decrypted = (c2 * s_inv) % p
    decrypted_message = long_to_bytes(m_decrypted)
    return decrypted_message.decode()

p, g, h, x = generate_keys()
print("p (prime):", p)
print("g (generator):", g)
print("h (public key):", h)
print("x (private key):", x)

c1, c2 = elgamal_encrypt(message, p, g, h)
print("c1:", c1)
print("c2:", c2)

decrypted_message = elgamal_decrypt(c1, c2, p, x)
print("Decrypted message:", decrypted_message)