import socket
import threading
from dataclasses import dataclass
import time

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
        self.chat_log = "chat_log.txt"  # Tempat penyimpanan pesan
        print(f"[SERVER STARTED] Listening on {ip}:{port}")
        self.load_chat_history()

    def load_chat_history(self):
        # Jika file log ada, simpan isi file ke memori
        try:
            with open(self.chat_log, 'r') as f:
                self.chat_history = f.readlines()
        except FileNotFoundError:
            self.chat_history = []

    def send_chat_history(self, addr):
        # Kirim pesan-pesan lampau ke client baru
        for line in self.chat_history:
            self.server_socket.sendto(line.encode(), addr)

    def broadcast(self, message: str, sender_addr):
        for client in self.clients.values():
            if client.address != sender_addr:
                self.server_socket.sendto(message.encode(), client.address)
        self.log_message(message)

    def log_message(self, message: str):
        # Simpan pesan ke dalam file log
        with open(self.chat_log, 'a') as f:
            f.write(message + '\n')
        self.chat_history.append(message + '\n')

    def handle_client(self, addr, data):
        message = data.decode()

        if addr not in self.clients:
            if message.startswith("/join "):
                _, username, user_password = message.split()
                if user_password == self.password:
                    self.clients[addr] = Client(username, addr)
                    self.server_socket.sendto("[SERVER] You have joined the chat!".encode(), addr)
                    self.send_chat_history(addr)
                    print(f"[NEW CONNECTION] {username} joined from {addr}")
                    self.broadcast(f"[SERVER] {username} has joined the chat!", addr)
                else:
                    self.server_socket.sendto("[ERROR] Wrong password!".encode(), addr)
            else:
                self.server_socket.sendto("[ERROR] You need to join the chat first using /join <username> <password>".encode(), addr)
        else:
            if message == "/exit":
                username = self.clients[addr].username
                self.broadcast(f"[SERVER] {username} has left the chat.", addr)
                del self.clients[addr]
                print(f"[DISCONNECTED] {username} from {addr}")
            else:
                sender = self.clients[addr].username
                print(f"[MESSAGE] {sender}: {message}")
                self.broadcast(f"{sender}: {message}", addr)

    def start(self):
        while True:
            data, addr = self.server_socket.recvfrom(1024)
            threading.Thread(target=self.handle_client, args=(addr, data)).start()

if __name__ == "__main__":
    server = ChatServer(ip="10.97.57.124", port=12345, password="secret")
    server.start()
