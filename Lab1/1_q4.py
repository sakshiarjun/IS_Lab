keyMatrix = [[0] * 3 for i in range(3)]
messageVector = [[0] for i in range(3)]
cipherMatrix = [[0] for i in range(3)]

def getKeyMatrix(key):
    k = 0
    for i in range(3):
        for j in range(3):
            keyMatrix[i][j] = ord(key[k]) % 65
            k += 1

def encrypt(messageVector):
    for i in range(3):
        for j in range(1):
            cipherMatrix[i][j] = 0
            for x in range(3):
                cipherMatrix[i][j] += (keyMatrix[i][x] * messageVector[x][j])
            cipherMatrix[i][j] = cipherMatrix[i][j] % 26

def HillCipher(message,key):
    getKeyMatrix(key)
    message = message.replace(" ", "")
    if len(message) % 3 != 0:
        message += 'X' * (3 - len(message) % 3)  # Padding with 'X'

    CipherText = []
    for i in range(0, len(message), 3):
        for j in range(3):
            messageVector[j][0] = ord(message[i + j]) % 65
        encrypt(messageVector)
        for j in range(3):
            CipherText.append(chr(cipherMatrix[j][0] + 65))
    
    print("Ciphertext: ", "".join(CipherText))

message = "We live in an insecure world"
key = "GYBNQKURP"

HillCipher(message,key)