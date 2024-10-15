'''
Implement the hash function in Python. Your function should start with an
initial hash value of 5381 and for each character in the input string,
multiply the current hash value by 33, add the ASCII value of the character,
and use bitwise operations to ensure thorough mixing of the bits.
Finally, ensure the hash value is kept within a 32-bit range by applying an appropriate mask.
'''

def hashing(s):
    hashval = 5381
    for char in s:
        hashval = (hashval * 33) + ord(char)

    hashval = hashval & 0xFFFFFFFF
    return hashval


msg = "testinputstringforhashing"
print(hashing(msg))