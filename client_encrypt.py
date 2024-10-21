import socket
import threading
import argparse

# Caesar Cipher Encryption
def caesar_encrypt(text, shift):
    encrypted = []
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def caesar_decrypt(cipher, shift):
    return caesar_encrypt(cipher, -shift)

# RC4 Encryption Implementation
def rc4_encrypt(key, plaintext):
    S = list(range(256))
    j = 0
    out = []
    
    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    # Pseudo-random generation algorithm (PRGA)
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
    
    return ''.join(out)

def rc4_decrypt(key, ciphertext):
    return rc4_encrypt(key, ciphertext)  # Symmetric operation

# Simple Checksum for Message Integrity
def checksum(message):
    return sum(bytearray(message.encode())) % 256

class ChatClient:
    def __init__(self, ip: str, port: int, username: str, password: str):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (ip, port)
        self.username = username
        self.password = password

    def send_message(self, message: str, shift: int, key: str):
        encrypted_msg = caesar_encrypt(message, shift)  # Encrypt with Caesar Cipher
        rc4_msg = rc4_encrypt(key, encrypted_msg)  # Apply RC4 Encryption

        # Add checksum to the message
        checksum_value = checksum(rc4_msg)
        message_with_checksum = f"{rc4_msg}:{checksum_value}"
        
        self.client_socket.sendto(message_with_checksum.encode(), self.server_address)

    def listen_for_messages(self, shift: int, key: str):
        while True:
            try:
                data, _ = self.client_socket.recvfrom(1024)
                message = data.decode()

                rc4_msg, msg_checksum = message.rsplit(":", 1)
                msg_checksum = int(msg_checksum)

                # Check integrity
                if checksum(rc4_msg) != msg_checksum:
                    print("[ERROR] Message integrity check failed.")
                    continue

                decrypted_rc4 = rc4_decrypt(key, rc4_msg)
                decrypted_message = caesar_decrypt(decrypted_rc4, shift)
                print(decrypted_message)
            except:
                print("[ERROR] Unable to receive message.")
                break

    def start(self):
        shift = 4  # Caesar Cipher shift value
        key = "secretkey"  # RC4 key
        
        # Join the chat
        self.send_message(f"/join {self.username} {self.password}", shift, key)
        threading.Thread(target=self.listen_for_messages, args=(shift, key), daemon=True).start()

        while True:
            message = input()
            if message.lower() == "/exit":
                self.send_message("/exit", shift, key)
                break
            self.send_message(message, shift, key)

        self.client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat Client")
    parser.add_argument("ip", help="Server IP address")
    parser.add_argument("port", type=int, help="Server port")
    parser.add_argument("username", help="Your username")
    parser.add_argument("password", help="Password to join the chat")

    args = parser.parse_args()

    client = ChatClient(ip=args.ip, port=args.port, username=args.username, password=args.password)
    client.start()
