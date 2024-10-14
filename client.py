import socket
import threading

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

def receive_messages(sock):
    while True:
        try:
            # Menerima pesan dari server
            data, addr = sock.recvfrom(1024)
            decrypted_message = decrypt_caesar(data.decode('utf-8'))  # Dekripsi pesan
            print(decrypted_message)  # Cetak pesan yang sudah didekripsi ke layar
        except:
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    server_ip = input("Enter server IP: ")
    server_port = int(input("Enter server port: "))
    
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    # Mengirim permintaan untuk join ke server
    join_message = f"JOIN:{username}:{password}"
    client_socket.sendto(join_message.encode('utf-8'), (server_ip, server_port))
    
    # Menerima respons dari server
    data, addr = client_socket.recvfrom(1024)
    response = data.decode('utf-8')
    
    if "Welcome" in response:
        print(response)
        
        # Mulai thread untuk menerima pesan
        threading.Thread(target=receive_messages, args=(client_socket,)).start()
        
        # Mengirim pesan ke server dengan enkripsi
        while True:
            message = input()
            if message == "exit":
                break
            encrypted_message = encrypt_caesar(message)  # Enkripsi pesan sebelum dikirim
            client_socket.sendto(encrypted_message.encode('utf-8'), (server_ip, server_port))
    else:
        print(response)

if __name__ == "__main__":
    start_client()
