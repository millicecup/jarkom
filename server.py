import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from caesar_cipher import CaesarCipher
from rc4_cipher import RC4
import hashlib

class Server:
    def __init__(self, ip, port):
        self.server_ip = ip
        self.server_port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.clients = {}  # To store clients
        self.messages_log = "server_messages.log"
        self.sequence_number = 0
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey().export_key()

    def calculate_checksum(self, message):
        return hashlib.md5(message.encode()).hexdigest()

    def start(self):
        print(f"Server running at {self.server_ip}:{self.server_port}")
        threading.Thread(target=self.listen_for_clients).start()

    def listen_for_clients(self):
        while True:
            data, addr = self.server_socket.recvfrom(1024)
            packet = json.loads(data.decode('utf-8'))
            encrypted_message, checksum, ack, seq_number = packet['message'], packet['checksum'], packet['ack'], packet['seq']

            if seq_number == self.sequence_number + 1:
                # Handle Encrypted Messages
                cipher_rc4 = RC4("secretkey")
                message = cipher_rc4.decrypt(encrypted_message)

                # Verify checksum
                if self.calculate_checksum(message) != checksum:
                    print(f"[ERROR] Message integrity compromised from {addr}")
                    continue

                # Send ACK back
                self.server_socket.sendto(json.dumps({'ack': seq_number}).encode('utf-8'), addr)

                print(f"[{addr}] {message}")
                self.sequence_number += 1
                self.save_message(addr, message)

                # Broadcast message to other clients
                for client_addr in self.clients.values():
                    if client_addr != addr:
                        self.server_socket.sendto(data, client_addr)
            else:
                print(f"Invalid sequence number from {addr}")

    def save_message(self, addr, message):
        with open(self.messages_log, "a") as f:
            f.write(f"{addr}: {message}\n")

    def authenticate(self, username, password):
        # Simulated authentication, replace with real implementation
        return True if password == "password123" else False

    def send_public_key(self, addr):
        self.server_socket.sendto(self.public_key, addr)

if __name__ == "__main__":
    server = Server("127.0.0.1", 12345)
    server.start()
