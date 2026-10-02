"""Loop komunikasi dua arah (dipakai Sender & Receiver)."""
import threading
from des_cipher import encrypt, decrypt
from net_utils import send_frame, recv_frame


def _receive_loop(sock, me, peer):
    while True:
        try:
            data = recv_frame(sock)
        except OSError:
            break
        if data is None:
            print(f"\n[{me}] Koneksi ditutup oleh {peer}. Ketik 'exit'.")
            break
        print(f"\n[{me}] Ciphertext diterima (hex): {data.hex()}")
        try:
            print(f"[{me}] Hasil dekripsi DES dari {peer}: {decrypt(data)}")
        except (ValueError, UnicodeDecodeError):
            print(f"[{me}] Dekripsi gagal (key salah / data rusak).")
        print(f"[{me}] > ", end="", flush=True)


def run_chat(sock, me, peer):
    threading.Thread(target=_receive_loop, args=(sock, me, peer), daemon=True).start()
    print(f"[{me}] Terhubung. Ketik pesan, 'exit' untuk keluar.")
    while True:
        try:
            msg = input(f"[{me}] > ")
        except (EOFError, KeyboardInterrupt):
            break
        if msg.strip().lower() == "exit":
            break
        if not msg:
            continue
        ct = encrypt(msg)
        print(f"[{me}] Plaintext        : {msg}")
        print(f"[{me}] Ciphertext (hex) : {ct.hex()}  (8 byte pertama = IV)  -> dikirim")
        try:
            send_frame(sock, ct)
        except OSError:
            print(f"[{me}] Gagal kirim, koneksi sudah putus.")
            break
    sock.close()
