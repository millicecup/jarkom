# jarkom
## Tugas socket jaringan komputer
Merupakan sebuah aplikasi chat room dimana pengguna dapat berbicara dengan 1 server yang sama.
Berbasis UDP dan sudah menggunakan cipher rc4 encryption

## cara menjalankan
1. download dan simpan di folder yang sama
2. buka powershell
3. arahkan ke folder tempat repository ini berada
   
### untuk menjalankan server
python server.py
#### memberhentikan server
tutup terminal 🙏
##
### untuk menjalankan client(s)
#### python client.py /ip/ /port/ /username/ /password/
contoh : python client.py 127.0.0.1 12345 hil secret
#### memberhentikan client(s)
ketik ini di terminal/powershell client
##### /exit
## 

### port dapat dilihat ketika menjalankan server
[SERVER STARTED] Listening on 127.0.0.1:12345
[SERVER] Ready to receive messages...
*127.0.0.1 = IP*
*12345 = port*

### ganti password server
pada line 147 (simple)
pada line 164 (full encryption progress)

