import socket
import threading

# Konfigurasi client
server_ip = "10.97.54.126"  # IP server yang diberikan
server_port = 12000          # Port server
buffer_size = 1024           # Ukuran buffer

# Membuat socket UDP
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Mengatur timeout (opsional, bisa diubah sesuai kebutuhan)
client_socket.settimeout(5)  # Timeout 5 detik

# Fungsi untuk mengirim pesan ke server
def send_message():
    while True:
        try:
            message = input()  # Input pesan dari pengguna
            if message.lower() == "exit":
                print("Exiting chat...")
                client_socket.close()
                break
            client_socket.sendto(message.encode('utf-8'), (server_ip, server_port))
        except Exception as e:
            print(f"Error in sending message: {e}")
            break

# Fungsi untuk menerima pesan dari server
def receive_message():
    while True:
        try:
            message, server = client_socket.recvfrom(buffer_size)
            print(f"\nMessage from {server}: {message.decode('utf-8')}")
        except socket.timeout:
            # Mengabaikan timeout, tidak ada pesan yang ditampilkan
            continue
        except ConnectionResetError as e:
            # Menangani jika koneksi terputus secara tiba-tiba
            print(f"ConnectionResetError: {e}. The connection was forcibly closed.")
            break
        except Exception as e:
            # Penanganan error lainnya
            print(f"An error occurred: {e}")
            break

# Membuat thread untuk mengirim dan menerima pesan secara bersamaan
send_thread = threading.Thread(target=send_message)
receive_thread = threading.Thread(target=receive_message)

send_thread.start()
receive_thread.start()

# Menunggu thread selesai
send_thread.join()
receive_thread.join()

# Menutup socket
client_socket.close()
