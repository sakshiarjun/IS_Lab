from itertools import product
from string import ascii_uppercase

def playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    matrix = []
    used = set()
    for char in key:
        if char not in used and char.isalpha():
            used.add(char)
            matrix.append(char)
    for char in ascii_uppercase:
        if char not in used and char.isalpha():
            used.add(char)
            matrix.append(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def preprocess_text(text):
    text = text.upper().replace('J', 'I').replace(' ', '')
    if len(text) % 2 != 0:
        text += 'X'
    return [text[i:i+2] for i in range(0, len(text), 2)]

def find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return None

def playfair_encrypt(text_pairs, matrix):
    cipher = []
    for pair in text_pairs:
        r1, c1 = find_position(matrix, pair[0])
        r2, c2 = find_position(matrix, pair[1])
        if r1 == r2:
            cipher.append(matrix[r1][(c1 + 1) % 5])
            cipher.append(matrix[r2][(c2 + 1) % 5])
        elif c1 == c2:
            cipher.append(matrix[(r1 + 1) % 5][c1])
            cipher.append(matrix[(r2 + 1) % 5][c2])
        else:
            cipher.append(matrix[r1][c2])
            cipher.append(matrix[r2][c1])
    return ''.join(cipher)

def main():
    key = "guidance"
    plaintext = "the key is hidden under the door pad"
    matrix = playfair_matrix(key)
    pairs = preprocess_text(plaintext)
    ciphertext = playfair_encrypt(pairs, matrix)
    print("Playfair Cipher Matrix:")
    for row in matrix:
        print(' '.join(row))
    print(f"\nEncrypted Message: {ciphertext}")

if __name__ == "__main__":
    main()