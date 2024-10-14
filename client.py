import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from caesar_cipher import CaesarCipher
from rc4_cipher import RC4
import hashlib

class Client:
    def __init__(self, username, password, server_ip, server_port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_ip = server_ip
        self.server_port = server_port
        self.username = username
        self.password = password
        self.sequence_number = 0
        self.cipher_rc4 = RC4("secretkey")
    
    def calculate_checksum(self, message):
        return hashlib.md5(message.encode()).hexdigest()

    def start(self):
        # Send login to server
        login_message = f"LOGIN:{self.username}:{self.password}"
        self.client_socket.sendto(login_message.encode('utf-8'), (self.server_ip, self.server_port))

        # Receive public key from server (for RSA)
        public_key, _ = self.client_socket.recvfrom(1024)
        public_key = RSA.import_key(public_key)

        # Generate RSA cipher
        cipher_rsa = PKCS1_OAEP.new(public_key)

        # Listen for incoming messages
        threading.Thread(target=self.receive_messages).start()

        while True:
            message = input("You: ")
            if message == "exit":
                break

            # Encrypt message using RC4
            encrypted_message = self.cipher_rc4.encrypt(message)
            checksum = self.calculate_checksum(message)

            packet = {
                'message': encrypted_message,
                'checksum': checksum,
                'ack': 0,  # Will be updated when ACK is received
                'seq': self.sequence_number + 1
            }
            self.client_socket.sendto(json.dumps(packet).encode('utf-8'), (self.server_ip, self.server_port))
            self.sequence_number += 1

    def receive_messages(self):
        while True:
            data, _ = self.client_socket.recvfrom(1024)
            packet = json.loads(data.decode('utf-8'))
            encrypted_message = packet['message']
            seq_number = packet['seq']
            
            # Decrypt message
            message = self.cipher_rc4.decrypt(encrypted_message)

            print(f"Received [{seq_number}]: {message}")

if __name__ == "__main__":
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    client = Client(username, password, "127.0.0.1", 12345)
    client.start()
