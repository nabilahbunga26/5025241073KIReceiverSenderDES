"""Untuk belajar/demo mekanisme DES: tampilkan subkey & 16 ronde untuk 1 blok.
Jalankan: python des_trace.py"""
from des_cipher import generate_subkeys, des_encrypt_block, des_decrypt_block, KEY

block = b"HALO DES"   # tepat 8 byte
print("Key (hex)      :", KEY.hex())
print("Plaintext blok :", block, block.hex())
print("\n== 16 subkey (48 bit) ==")
for i, k in enumerate(generate_subkeys(KEY), 1):
    bitstr = "".join(map(str, k))
    print("K%-2d = %s  (%s)" % (i, hex(int(bitstr, 2))[2:].zfill(12), bitstr))
print("\n== ENKRIPSI ==")
ct = des_encrypt_block(block, trace=True)
print("Ciphertext     :", ct.hex())
print("\n== DEKRIPSI (subkey dibalik) ==")
pt = des_decrypt_block(ct, trace=True)
print("Plaintext      :", pt)
