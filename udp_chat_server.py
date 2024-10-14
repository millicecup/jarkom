import socket

# Konfigurasi server
server_ip = "10.97.57.124"  # Gunakan IP yang diberikan
server_port = 12000          # Port server
buffer_size = 1024           # Ukuran buffer untuk menerima pesan

# Membuat socket UDP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind server dengan IP dan Port
server_socket.bind((server_ip, server_port))

print(f"Server running on {server_ip}:{server_port}")

# Menyimpan daftar alamat klien yang terhubung
clients = set()

while True:
    try:
        # Menerima pesan dari klien
        message, client_address = server_socket.recvfrom(buffer_size)

        # Menambahkan klien ke dalam set (agar tidak ada duplikat)
        if client_address not in clients:
            clients.add(client_address)

        # Menampilkan pesan yang diterima di server
        print(f"Received message from {client_address}: {message.decode('utf-8')}")

        # Menyiarkan pesan ke semua klien yang terhubung
        for client in clients:
            if client != client_address:  # Jangan kirim kembali ke pengirim
                server_socket.sendto(message, client)

    except ConnectionResetError as e:
        # Menangani error jika koneksi klien terputus secara tiba-tiba
        print(f"ConnectionResetError: {e}. The connection was reset by the client.")
    except Exception as e:
        # Penanganan error lainnya
        print(f"An error occurred: {e}")
