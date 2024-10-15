from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import GCD
from Crypto.Hash import SHA256

# Key Generation
key = ElGamal.generate(256, get_random_bytes)
public_key = (int(key.p), int(key.g), int(key.y))  # Ensure all are integers
private_key = int(key.x)  # Ensure the private key is an integer

def elgamal_encrypt(message, key):
    p, g, y = int(key.p), int(key.g), int(key.y)  # Convert to native Python integers
    k = randint(1, p - 2)
    while GCD(k, p - 1) != 1:
        k = randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(cipher_text, key):
    c1, c2 = cipher_text
    p = int(key.p)  # Convert to native Python integer
    s = pow(c1, int(key.x), p)  # Convert to native Python integers
    # Use pow to compute the modular inverse
    s_inv = pow(s, p - 2, p)  # Fermat's Little Theorem
    return (c2 * s_inv) % p

def elgamal_sign(message, key):
    p, g, x = int(key.p), int(key.g), int(key.x)  # Convert to integers
    k = randint(1, p - 2)  # Random value k, which must be coprime with p-1
    while GCD(k, p - 1) != 1:
        k = randint(1, p - 2)
    
    r = pow(g, k, p)
    
    # Hash the message using SHA256
    hash_value = int(SHA256.new(message.encode('utf-8')).hexdigest(), 16)
    
    # Compute s using the formula
    k_inv = pow(k, p - 2, p - 1)  # Modular inverse of k mod p-1
    s = (k_inv * (hash_value - x * r)) % (p - 1)
    
    return (r, s)

def elgamal_verify(message, signature, public_key):
    r, s = signature
    p, g, y = public_key
    
    if not (1 < r < p):  # Ensure r is within valid range
        return False

    # Hash the message
    hash_value = int(SHA256.new(message.encode('utf-8')).hexdigest(), 16)
    
    # Verify the signature using the public key
    v1 = pow(g, hash_value, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    
    return v1 == v2

message = 4441
cipher_text = elgamal_encrypt(message, key)
decrypted_message = elgamal_decrypt(cipher_text, key)

print("Original message:", message)
print("Encrypted message:", cipher_text)
print("Decrypted message:", decrypted_message)

# Example string message for signing and verifying
message_to_sign = "ElGamal Digital Signature Test"
signature = elgamal_sign(message_to_sign, key)
print(f"Digital Signature (r, s): {signature}")
is_valid = elgamal_verify(message_to_sign, signature, public_key)
print("Is the signature valid?", is_valid)