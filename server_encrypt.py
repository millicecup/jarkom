import socket
import threading
import random
from dataclasses import dataclass

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

@dataclass
class Client:
    username: str
    address: tuple

class ChatServer:
    def __init__(self, ip: str, port: int, password: str):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((ip, port))
        self.clients = {}
        self.password = password
        print(f"[SERVER STARTED] Listening on {ip}:{port}")

    def broadcast(self, message: str, sender_addr, shift: int, key: str):
        encrypted_msg = caesar_encrypt(message, shift)  # Encrypt with Caesar Cipher
        rc4_msg = rc4_encrypt(key, encrypted_msg)  # Apply RC4 Encryption

        # Add checksum to the message
        checksum_value = checksum(rc4_msg)
        message_with_checksum = f"{rc4_msg}:{checksum_value}"
        
        for client in self.clients.values():
            if client.address != sender_addr:
                self.server_socket.sendto(message_with_checksum.encode(), client.address)

    def handle_client(self, addr, data, shift: int, key: str):
        try:
            message = data.decode()
            rc4_msg, msg_checksum = message.rsplit(":", 1)
            msg_checksum = int(msg_checksum)

            # Check integrity
            if checksum(rc4_msg) != msg_checksum:
                print("[ERROR] Message integrity check failed.")
                return

            # Decrypt the message
            decrypted_rc4 = rc4_decrypt(key, rc4_msg)
            decrypted_message = caesar_decrypt(decrypted_rc4, shift)

            if addr not in self.clients:
                if decrypted_message.startswith("/join "):
                    _, username, user_password = decrypted_message.split()
                    if user_password == self.password:
                        self.clients[addr] = Client(username, addr)
                        self.server_socket.sendto("[SERVER] You have joined the chat!".encode(), addr)
                        print(f"[NEW CONNECTION] {username} joined from {addr}")
                        self.broadcast(f"[SERVER] {username} has joined the chat!", addr, shift, key)
                    else:
                        self.server_socket.sendto("[ERROR] Wrong password!".encode(), addr)
                else:
                    self.server_socket.sendto("[ERROR] You need to join the chat first using /join <username> <password>".encode(), addr)
            else:
                if decrypted_message == "/exit":
                    username = self.clients[addr].username
                    self.broadcast(f"[SERVER] {username} has left the chat.", addr, shift, key)
                    del self.clients[addr]
                    print(f"[DISCONNECTED] {username} from {addr}")
                else:
                    sender = self.clients[addr].username
                    print(f"[MESSAGE] {sender}: {decrypted_message}")
                    self.broadcast(f"{sender}: {decrypted_message}", addr, shift, key)
        except Exception as e:
            print(f"[ERROR] {e}")

    def start(self):
        shift = 4  # Caesar Cipher shift value
        key = "secretkey"  # RC4 key
        
        while True:
            data, addr = self.server_socket.recvfrom(1024)
            threading.Thread(target=self.handle_client, args=(addr, data, shift, key)).start()

if __name__ == "__main__":
    server = ChatServer(ip="127.0.0.1", port=12345, password="secret")
    server.start()
