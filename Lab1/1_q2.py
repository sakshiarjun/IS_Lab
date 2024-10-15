plaintext = "the house is being sold tonight"

def character_ord(character):
    if character.isupper():
        return ord(character) - ord('A')
    else:
        return ord(character) - ord('a')

def vignere_encrypt(plaintext, key):
    cipher = ""
    key_index = 0
    key_length = len(key)
    for c in plaintext:
        if c == " ":
            shifted_c = " "
            cipher += shifted_c
            continue
        elif c.isupper():
            shifted_c = chr(((character_ord(c) + character_ord(key[key_index % key_length])) % 26) + ord('A')) 
        else:
            shifted_c = chr(((character_ord(c) + character_ord(key[key_index % key_length])) % 26) + ord('a'))
        cipher += shifted_c
        key_index+=1
    return cipher

def vignere_decrypt(cipher,key):
    plaintext = ""
    key_index = 0
    key_length = len(key)
    for c in cipher:
        if c == " ":
            shifted_c = " "
            plaintext += shifted_c
            continue
        elif c.isupper():
            shifted_c = chr(((character_ord(c) - character_ord(key[key_index % key_length])) % 26) + ord('A')) 
        else:
            shifted_c = chr(((character_ord(c) - character_ord(key[key_index % key_length])) % 26) + ord('a'))        
        plaintext += shifted_c
        key_index+=1
    return plaintext

def autokey_encrypt(plaintext, key):
    cipher = ""
    key_arr = [key]
    key_index = 0
    for c in plaintext:
        if c == " ":
            shifted_c = " "
            cipher+= shifted_c
            continue
        elif c.isupper():
            shifted_c = chr(((character_ord(c) + key_arr[key_index]) % 26) + ord('A'))
            key_arr.append(character_ord(shifted_c))
        else:
            shifted_c = chr(((character_ord(c) + key_arr[key_index]) % 26) + ord('a'))
            key_arr.append(character_ord(shifted_c))
        cipher+= shifted_c
        key_index+=1
    return cipher

def autokey_decrypt(cipher, key):
    plaintext = ""
    key_arr = [key]
    for i in cipher:
        if i == " ":
            continue
        key_arr.append(character_ord(i))
    key_index = 0
    for c in cipher:
        if c == " ":
            shifted_c = " "
            plaintext+= shifted_c
            continue
        elif c.isupper():
            shifted_c = chr(((character_ord(c) - key_arr[key_index]) % 26) + ord('A')) 
        else:
            shifted_c = chr(((character_ord(c) - key_arr[key_index]) % 26) + ord('a'))
        
        plaintext += shifted_c
        key_index+=1
    return plaintext

v_encrypt = vignere_encrypt(plaintext=plaintext,key="dollars")
v_decrypt = vignere_decrypt(v_encrypt,"dollars")
a_encrypt = autokey_encrypt(plaintext="attack is today",key=12)
a_decrypt = autokey_decrypt(a_encrypt,12) 
print(v_encrypt)
print(v_decrypt)
print(a_encrypt)
print(a_decrypt)