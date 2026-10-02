TUGAS KI - Komunikasi 2 Arah dengan DES (manual, tanpa library kripto)

File:
  des_cipher.py : implementasi DES manual (IP, 16 ronde Feistel, S-box, key schedule)
                  + mode CBC + padding PKCS#7. KEY ada di sini (sama di kedua sisi).
  net_utils.py  : framing TCP
  chat.py       : loop kirim & terima dua arah
  receiver.py   : server (jalankan DULU)
  sender.py     : client
  des_trace.py  : cetak subkey & 16 ronde 1 blok (untuk belajar/jelasin mekanisme)

CARA JALAN (beda host, wajib):
  Host A (Receiver): python receiver.py     -> catat IP yang tampil
  Host B (Sender)  : python sender.py <IP_Host_A>
  Ketik pesan di salah satu sisi, sisi lain otomatis menerima & mendekripsi. 'exit' untuk keluar.
  Kedua host harus satu jaringan (WiFi/hotspot sama). Izinkan port TCP 5000 di firewall Host A.

WIRESHARK (opsional, nilai tambah):
  Capture di interface WiFi, filter:  tcp.port == 5000
  Klik kanan paket -> Follow -> TCP Stream: isi paket berupa byte acak (ciphertext).
