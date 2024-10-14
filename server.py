import socket
import threading

# Dictionary untuk menyimpan (username, address) client
clients = {}
PASSWORD = "itb1920"  # Password untuk akses ke chatroom

# Fungsi Enkripsi Caesar Cipher
def encrypt_caesar(plaintext, shift=3):
    result = ""
    for char in plaintext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

# Fungsi Dekripsi Caesar Cipher
def decrypt_caesar(ciphertext, shift=3):
    return encrypt_caesar(ciphertext, -shift)

def handle_client(sock, addr):
    while True:
        try:
            # Menerima pesan dari client
            data, address = sock.recvfrom(1024)
            decrypted_message = decrypt_caesar(data.decode('utf-8'))  # Dekripsi pesan yang diterima
            print(f"[{addr}] {decrypted_message}")  # Tampilkan pesan ke layar server
            
            # Meneruskan pesan ke semua client lain setelah dienkripsi
            for client, client_addr in clients.items():
                if client_addr != addr:  # Jangan kirim ke client asal
                    encrypted_message = encrypt_caesar(decrypted_message)  # Enkripsi pesan sebelum dikirim
                    sock.sendto(encrypted_message.encode('utf-8'), client_addr)
        except:
            break

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("0.0.0.0", 12345))  # Menggunakan port 12345
    
    print("[SERVER] Server is running and listening...")

    while True:
        # Menerima pesan dari client untuk bergabung
        data, addr = server_socket.recvfrom(1024)
        message = data.decode('utf-8')
        
        if message.startswith("JOIN"):
            username, password = message.split(":")[1:]
            
            # Validasi password
            if password != PASSWORD:
                server_socket.sendto("Invalid password".encode('utf-8'), addr)
                continue
            
            # Cek apakah username sudah digunakan
            if username in clients:
                server_socket.sendto("Username already in use".encode('utf-8'), addr)
                continue
            
            # Simpan username dan alamat client
            clients[username] = addr
            print(f"[JOIN] {username} has joined the chat.")
            server_socket.sendto("Welcome to the chatroom!".encode('utf-8'), addr)
            
            # Mulai thread untuk menangani client
            threading.Thread(target=handle_client, args=(server_socket, addr)).start()

if __name__ == "__main__":
    start_server()
