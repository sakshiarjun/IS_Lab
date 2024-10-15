'''
Encrypt the message "I am learning information security" using each of the
following ciphers. Ignore the space between words. Decrypt the message to
get the original plaintext:
a) Additive cipher with key = 20
b) Multiplicative cipher with key = 15
c) Affine cipher with key = (15, 20)
'''

plaintext = "I am learning information security"

def additive_encrypt(plaintext: str, key: int):
    encrypted_text = ""
    for c in plaintext:
        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr(((ord(c) - ord('A') + key) % 26) + ord('A')) 
        else:
            shifted_c = chr(((ord(c) - ord('a') + key) % 26) + ord('a'))
        encrypted_text += shifted_c
    return encrypted_text

def additive_decrypt(cipher: str, key: int):
    decrypted_text = ""
    for c in cipher:
        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr(((ord(c) - ord('A') - key) % 26) + ord('A')) 
        else:
            shifted_c = chr(((ord(c) - ord('a') - key) % 26) + ord('a'))
        decrypted_text += shifted_c
    return decrypted_text

print("Additive Cipher")
enc = additive_encrypt(plaintext=plaintext, key=20)
dec = additive_decrypt(cipher=enc, key=20)
print(enc)
print(dec+"\n")

def multiplicative_encrypt(plaintext: str, key: int):
    encrypted_text = ""
    if key == 0:
        return plaintext
    for c in plaintext:
        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr((((ord(c) - ord('A')) * key) % 26) + ord('A'))
        else:
            shifted_c = chr((((ord(c) - ord('a')) * key) % 26) + ord('a'))
        encrypted_text += shifted_c
    return encrypted_text

def multiplicative_decrypt(cipher: str, key: int):
    decrypted_text = ""
    if key == 0:
        return cipher
    key = pow(key, -1, 26)
    for c in cipher:
        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr((((ord(c) - ord('A')) * key) % 26) + ord('A'))
        else:
            shifted_c = chr((((ord(c) - ord('a')) * key) % 26) + ord('a'))   
        decrypted_text += shifted_c
    return decrypted_text

print("Multiplicative Cipher")
enc = multiplicative_encrypt(plaintext=plaintext, key=15)
dec = multiplicative_decrypt(cipher=enc, key=15)
print(enc)
print(dec+"\n")

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    else:
        return x % m


def affine_encrpyt(plaintext: str, key: tuple):
    a = key[0]
    b = key[1]
    encrypted_text = ""
    for c in plaintext:
        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr((((ord(c) - ord('A')) * a + b) % 26) + ord('A')) 
        else:
            shifted_c = chr((((ord(c) - ord('a')) * a + b) % 26) + ord('a'))
        encrypted_text += shifted_c
    return encrypted_text

def affine_decrypt(ciphertext: str, key: tuple):
    a = key[0]
    b = key[1]
    decrypted_txt = ""
    a_mod_inv = mod_inverse(a, 26)
    for c in ciphertext:
        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr((((ord(c) - ord('A') - b) * a_mod_inv) % 26) + ord('A')) 
        else:
            shifted_c = chr((((ord(c) - ord('a') - b) * a_mod_inv) % 26) + ord('a'))        
        decrypted_txt += shifted_c
    return decrypted_txt

enc = affine_encrpyt(plaintext=plaintext, key=(15,20))
dec = affine_decrypt(ciphertext=enc, key=(15,20))
print("AFFINE CIPHER")
print(enc)
print(dec)