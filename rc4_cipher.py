class RC4:
    def __init__(self, key):
        self.key = key
        self.S = list(range(256))
        self.KSA()

    def KSA(self):
        j = 0
        key_length = len(self.key)
        for i in range(256):
            j = (j + self.S[i] + ord(self.key[i % key_length])) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def PRGA(self, plaintext):
        i = j = 0
        result = []
        for char in plaintext:
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
            k = self.S[(self.S[i] + self.S[j]) % 256]
            result.append(chr(ord(char) ^ k))
        return ''.join(result)

    def encrypt(self, plaintext):
        return self.PRGA(plaintext)

    def decrypt(self, ciphertext):
        return self.PRGA(ciphertext)  # Symmetric encryption/decryption
