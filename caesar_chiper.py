class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift

    def encrypt(self, plaintext):
        result = ""
        for i in range(len(plaintext)):
            char = plaintext[i]
            if char.isupper():
                result += chr((ord(char) + self.shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) + self.shift - 97) % 26 + 97)
        return result

    def decrypt(self, ciphertext):
        result = ""
        for i in range(len(ciphertext)):
            char = ciphertext[i]
            if char.isupper():
                result += chr((ord(char) - self.shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) - self.shift - 97) % 26 + 97)
        return result
