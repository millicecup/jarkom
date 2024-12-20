import socket
import threading
import argparse
#import sys
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
    result = ''.join(encrypted)
    print(f"[Caesar Cipher] {text} -> {result}")
    return result

def caesar_decrypt(cipher, shift):
    decrypted = caesar_encrypt(cipher, -shift)
    print(f"[Caesar Decrypt] {cipher} -> {decrypted}")
    return decrypted

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
    
    result = ''.join(out)
    print(f"[RC4 Encrypt] {plaintext} -> {result}")
    return result

def rc4_decrypt(key, ciphertext):
    decrypted = rc4_encrypt(key, ciphertext)
    print(f"[RC4 Decrypt] {ciphertext} -> {decrypted}")
    return decrypted

# Simple Checksum for Message Integrity
def checksum(message):
    result = sum(bytearray(message.encode())) % 256
    print(f"[Checksum] Message checksum: {result}")
    return result

class ChatClient:
    def __init__(self, ip: str, port: int, username: str, password: str):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = (ip, port)
        self.username = username
        self.password = password
        self.running = True

    def send_message(self, message: str, shift: int, key: str):
        try:
            print("\n=== ENCRYPTION PROCESS ===")
            print(f"[Original Message] {message}")
            
            # Step 1: Caesar Cipher
            encrypted_msg = caesar_encrypt(message, shift)
            
            # Step 2: RC4 Encryption
            rc4_msg = rc4_encrypt(key, encrypted_msg)
            
            # Step 3: Add checksum
            checksum_value = checksum(rc4_msg)
            message_with_checksum = f"{rc4_msg}:{checksum_value}"
            
            print(f"[Final Encrypted Message] {message_with_checksum}")
            print("========================")
            
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
                print("\n=== DECRYPTION PROCESS ===")
                print(f"[Received Encrypted Message] {message}")
                
                # Split message and checksum
                if ":" not in message:
                    print("[ERROR] Received malformed message")
                    continue
                    
                rc4_msg, msg_checksum = message.rsplit(":", 1)
                msg_checksum = int(msg_checksum)

                # Verify checksum
                calculated_checksum = checksum(rc4_msg)
                if calculated_checksum != msg_checksum:
                    print(f"[ERROR] Checksum verification failed: {calculated_checksum} != {msg_checksum}")
                    continue

                # Decrypt message
                decrypted_rc4 = rc4_decrypt(key, rc4_msg)
                final_message = caesar_decrypt(decrypted_rc4, shift)
                
                print(f"[Final Decrypted Message] {final_message}")
                print("========================\n")
                
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
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("ip", help="Server IP address")
    parser.add_argument("port", type=int, help="Server port")
    parser.add_argument("username", help="Your username")
    parser.add_argument("password", help="Chat room password")
    
    args = parser.parse_args()
    
    try:
        client = ChatClient(args.ip, args.port, args.username, args.password)
        client.start()
    except Exception as e:
        print(f"[ERROR] Failed to start client: {str(e)}")
        #sys.exit(1)