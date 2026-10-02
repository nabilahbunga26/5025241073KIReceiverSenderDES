"""SENDER (client TCP). Jalankan di Windows."""
import socket
import sys
from chat import run_chat

PORT = 5050

RECEIVER_IP = "172.20.93.6"   # IP WSL2 Receiver

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect((RECEIVER_IP, PORT))
except OSError as e:
    print(f"[Sender] Gagal konek ke {RECEIVER_IP}:{PORT} -> {e}")
    print("Cek: receiver sudah jalan di WSL2? IP benar?")
    sys.exit(1)

sender_ip, sender_port = sock.getsockname()
print(f"[Sender] IP Windows : {sender_ip}")
print(f"[Sender] Port       : {sender_port}")
print(f"[Sender] Terhubung ke receiver {RECEIVER_IP}:{PORT}")
run_chat(sock, "Sender", "Receiver")
