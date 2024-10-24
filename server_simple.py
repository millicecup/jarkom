import socket
import threading
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
    return rc4_encrypt(key, ciphertext)

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

    def send_encrypted_message(self, message: str, addr, shift: int, key: str):
        print(f"\n[Original Message] {message}")
        
        # Encrypt message
        encrypted_msg = caesar_encrypt(message, shift)
        rc4_msg = rc4_encrypt(key, encrypted_msg)
        
        # Add checksum
        checksum_value = checksum(rc4_msg)
        message_with_checksum = f"{rc4_msg}:{checksum_value}"
        
        print(f"[Encrypted] {message_with_checksum}")
        
        self.server_socket.sendto(message_with_checksum.encode(), addr)

    def broadcast(self, message: str, sender_addr, shift: int, key: str):
        for client in self.clients.values():
            if client.address != sender_addr:
                self.send_encrypted_message(message, client.address, shift, key)
    
    def handle_client(self, addr, data, shift: int, key: str):
        try:
            message = data.decode()
            print(f"\n[Received Encrypted] {message}")
            
            if ":" not in message:
                print(f"[ERROR] Malformed message from {addr}")
                self.send_encrypted_message("[ERROR] Malformed message", addr, shift, key)
                return
                
            rc4_msg, msg_checksum = message.rsplit(":", 1)
            msg_checksum = int(msg_checksum)

            # Verify checksum
            if checksum(rc4_msg) != msg_checksum:
                print("[ERROR] Message integrity check failed")
                self.send_encrypted_message("[ERROR] Message integrity check failed", addr, shift, key)
                return

            # Decrypt message
            decrypted_rc4 = rc4_decrypt(key, rc4_msg)
            decrypted_message = caesar_decrypt(decrypted_rc4, shift)
            
            print(f"[Decrypted] {decrypted_message}")

            if addr not in self.clients:
                if decrypted_message.startswith("/join "):
                    try:
                        _, username, user_password = decrypted_message.split()
                        if user_password == self.password:
                            self.clients[addr] = Client(username, addr)
                            self.send_encrypted_message("[SERVER] You have joined the chat!", addr, shift, key)
                            print(f"[NEW CONNECTION] {username} joined from {addr}")
                            self.broadcast(f"[SERVER] {username} has joined the chat!", addr, shift, key)
                        else:
                            self.send_encrypted_message("[ERROR] Wrong password!", addr, shift, key)
                    except ValueError:
                        self.send_encrypted_message("[ERROR] Invalid join command format. Use: /join username password", addr, shift, key)
                else:
                    self.send_encrypted_message("[ERROR] You need to join first using /join username password", addr, shift, key)
            else:
                if decrypted_message == "/exit":
                    username = self.clients[addr].username
                    self.broadcast(f"[SERVER] {username} has left the chat.", addr, shift, key)
                    del self.clients[addr]
                    print(f"[DISCONNECTED] {username} from {addr}")
                else:
                    sender = self.clients[addr].username
                    self.broadcast(f"{sender}: {decrypted_message}", addr, shift, key)
                    
        except Exception as e:
            print(f"[ERROR] Error handling message from {addr}: {str(e)}")
            self.send_encrypted_message("[ERROR] Server error occurred", addr, shift, key)

    def start(self):
        shift = 4  # Caesar Cipher shift value
        key = "secretkey"  # RC4 key
        
        print("[SERVER] Ready to receive messages...")
        while True:
            try:
                data, addr = self.server_socket.recvfrom(1024)
                threading.Thread(target=self.handle_client, args=(addr, data, shift, key)).start()
            except Exception as e:
                print(f"[ERROR] Server error: {str(e)}")

if __name__ == "__main__":
    server = ChatServer(ip="127.0.0.1", port=12345, password="secret")
    server.start()