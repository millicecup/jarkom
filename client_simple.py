import socket
import threading
import time

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

class ChatClient:
    def __init__(self, ip: str, port: int, username: str, password: str):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (ip, port)
        self.username = username
        self.password = password
        self.running = True

    def send_message(self, message: str, shift: int, key: str):
        try:
            print(f"\n[Original Message] {message}")
            
            # Encrypt message using Caesar cipher then RC4
            encrypted_msg = caesar_encrypt(message, shift)
            rc4_msg = rc4_encrypt(key, encrypted_msg)
            
            # Add checksum
            checksum_value = checksum(rc4_msg)
            message_with_checksum = f"{rc4_msg}:{checksum_value}"
            
            print(f"[Encrypted] {message_with_checksum}")
            
            self.client_socket.sendto(message_with_checksum.encode(), self.server_address)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send message: {str(e)}")
            return False

    def listen_for_messages(self, shift: int, key: str):
        self.client_socket.settimeout(1)  # Set socket timeout to 1 second
        
        while self.running:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    continue
                    
                message = data.decode()
                print(f"\n[Received Encrypted] {message}")
                
                # Split message and checksum
                if ":" not in message:
                    print("[ERROR] Received malformed message")
                    continue
                    
                rc4_msg, msg_checksum = message.rsplit(":", 1)
                msg_checksum = int(msg_checksum)

                # Verify checksum
                if checksum(rc4_msg) != msg_checksum:
                    print("[ERROR] Message integrity check failed")
                    continue

                # Decrypt message
                decrypted_rc4 = rc4_decrypt(key, rc4_msg)
                final_message = caesar_decrypt(decrypted_rc4, shift)
                
                print(f"[Decrypted] {final_message}\n")
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[ERROR] {str(e)}")
                continue

    def start(self):
        shift = 4  # Caesar Cipher shift value
        key = "secretkey"  # RC4 key
        
        # Start listener thread
        listener_thread = threading.Thread(target=self.listen_for_messages, args=(shift, key))
        listener_thread.daemon = True
        listener_thread.start()
        
        # Join the chat
        print("[CLIENT] Connecting to server...")
        if not self.send_message(f"/join {self.username} {self.password}", shift, key):
            print("[ERROR] Failed to connect to server")
            return

        # Small delay to allow server response
        time.sleep(0.5)
        
        print("\n[CLIENT] Enter your messages (type /exit to quit):")
        
        while True:
            try:
                message = input()
                if message.lower() == '/exit':
                    self.send_message("/exit", shift, key)
                    self.running = False
                    break
                elif message:
                    self.send_message(message, shift, key)
            except KeyboardInterrupt:
                print("\n[CLIENT] Closing connection...")
                self.running = False
                break
            except Exception as e:
                print(f"[ERROR] {str(e)}")
                break
        
        # Clean up
        self.client_socket.close()
        print("[CLIENT] Connection closed")

if __name__ == "__main__":
    # Request user input for server details
    ip = input("Enter server IP address: ")
    port = int(input("Enter server port: "))
    username = input("Enter your username: ")
    password = input("Enter chat room password: ")
    
    try:
        client = ChatClient(ip, port, username, password)
        client.start()
    except Exception as e:
        print(f"[ERROR] Failed to start client: {str(e)}")
