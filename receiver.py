"""RECEIVER (server TCP). Jalankan di WSL2."""
import socket
from chat import run_chat

HOST, PORT = "0.0.0.0", 5050   # 0.0.0.0 = terima koneksi dari mana saja

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    # Tampilkan IP WSL2 yang sebenarnya (baca dari socket yang sudah bind)
    wsl_ip = server.getsockname()[0]
    # Kalau masih 0.0.0.0, cari IP eth0 WSL2
    if wsl_ip == "0.0.0.0":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("172.20.80.1", 1))   # gateway Windows ke WSL2
            wsl_ip = s.getsockname()[0]
            s.close()
        except OSError:
            wsl_ip = "tidak terdeteksi"
    print(f"[Receiver] IP WSL2 : {wsl_ip}")
    print(f"[Receiver] Port    : {PORT}")
    print(f"[Receiver] Menunggu sender di port {PORT} ...")
    conn, addr = server.accept()
    sender_ip, sender_port = addr
    print(f"[Receiver] Sender terhubung dari {sender_ip}:{sender_port}")
    run_chat(conn, "Receiver", "Sender")
