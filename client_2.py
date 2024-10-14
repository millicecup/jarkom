import socket
import threading
import argparse

class ChatClient:
    def __init__(self, ip: str, port: int, username: str, password: str):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (ip, port)
        self.username = username
        self.password = password

    def send_message(self, message: str):
        self.client_socket.sendto(message.encode(), self.server_address)

    def listen_for_messages(self):
        while True:
            try:
                data, _ = self.client_socket.recvfrom(1024)
                print(data.decode())
            except:
                print("[ERROR] Unable to receive message.")
                break

    def start(self):
        # Join the chat
        self.send_message(f"/join {self.username} {self.password}")
        threading.Thread(target=self.listen_for_messages, daemon=True).start()

        while True:
            message = input()
            if message.lower() == "/exit":
                self.send_message("/exit")
                break
            self.send_message(message)

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
