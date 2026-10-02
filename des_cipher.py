"""
DES manual (tanpa library kriptografi) + mode CBC + padding PKCS#7.
Dipakai oleh Sender dan Receiver. Key sudah diketahui kedua pihak (TIDAK dikirim).

Ringkasan DES:
  - Blok 64 bit, key 64 bit (efektif 56 bit; 8 bit sisanya parity).
  - 1 blok: IP -> 16 ronde Feistel -> swap L/R -> FP (IP^-1)
  - Tiap ronde: L_i = R_(i-1) ;  R_i = L_(i-1) XOR f(R_(i-1), K_i)
  - f = Expansion(32->48) -> XOR subkey 48 bit -> 8 S-box (6->4 bit) -> Permutasi P (32 bit)
  - Dekripsi = algoritma yang sama dengan urutan subkey dibalik (K16 ... K1)
"""
import os

# ----------------------------- TABEL STANDAR DES -----------------------------
IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
      38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
      34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]

E = [32,1,2,3,4,5,4,5,6,7,8,9,
     8,9,10,11,12,13,12,13,14,15,16,17,
     16,17,18,19,20,21,20,21,22,23,24,25,
     24,25,26,27,28,29,28,29,30,31,32,1]

P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]

PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,21,13,5,28,20,12,4]

PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
       26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
       51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

SBOX = [
 [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]

# Key bersama (8 byte). Sama di Sender & Receiver, tidak pernah dikirim lewat jaringan.
KEY = b"ITS2026K"


# ----------------------------- UTIL BIT -----------------------------
def bytes_to_bits(data):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def permute(bits, table):
    return [bits[i - 1] for i in table]


def xor_bits(a, b):
    return [x ^ y for x, y in zip(a, b)]


def left_rotate(bits, n):
    return bits[n:] + bits[:n]


# ----------------------------- KEY SCHEDULE -----------------------------
def generate_subkeys(key8):
    key_bits = bytes_to_bits(key8)
    k56 = permute(key_bits, PC1)
    c, d = k56[:28], k56[28:]
    subkeys = []
    for shift in SHIFTS:
        c, d = left_rotate(c, shift), left_rotate(d, shift)
        subkeys.append(permute(c + d, PC2))   # 48 bit
    return subkeys


# ----------------------------- FUNGSI f -----------------------------
def feistel(r32, subkey48):
    expanded = permute(r32, E)                 # 32 -> 48
    x = xor_bits(expanded, subkey48)
    out = []
    for i in range(8):
        chunk = x[i * 6:(i + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = SBOX[i][row * 16 + col]
        out.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
    return permute(out, P)                     # permutasi P


# ----------------------------- 1 BLOK (8 byte) -----------------------------
def crypt_block(block8, subkeys, trace=False):
    bits = permute(bytes_to_bits(block8), IP)
    l, r = bits[:32], bits[32:]
    if trace:
        print(f"  Setelah IP : L0={bits_to_bytes(l).hex()} R0={bits_to_bytes(r).hex()}")
    for i in range(16):
        new_r = xor_bits(l, feistel(r, subkeys[i]))
        l, r = r, new_r
        if trace:
            print(f"  Ronde {i+1:2d}  : L={bits_to_bytes(l).hex()} R={bits_to_bytes(r).hex()}")
    return bits_to_bytes(permute(r + l, FP))   # swap terakhir lalu FP


def des_encrypt_block(block8, key8=KEY, trace=False):
    return crypt_block(block8, generate_subkeys(key8), trace)


def des_decrypt_block(block8, key8=KEY, trace=False):
    return crypt_block(block8, generate_subkeys(key8)[::-1], trace)   # subkey dibalik


# ----------------------------- PADDING & MODE CBC -----------------------------
def pad(data):
    n = 8 - (len(data) % 8)
    return data + bytes([n]) * n


def unpad(data):
    n = data[-1]
    if n < 1 or n > 8 or data[-n:] != bytes([n]) * n:
        raise ValueError("padding tidak valid (key salah / data rusak)")
    return data[:-n]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(plaintext: str, key8=KEY) -> bytes:
    """Hasil: IV (8 byte, acak, boleh publik) + ciphertext CBC."""
    subkeys = generate_subkeys(key8)
    iv = os.urandom(8)
    data = pad(plaintext.encode("utf-8"))
    prev, out = iv, b""
    for i in range(0, len(data), 8):
        block = crypt_block(xor_bytes(data[i:i + 8], prev), subkeys)
        out += block
        prev = block
    return iv + out


def decrypt(packet: bytes, key8=KEY) -> str:
    subkeys = generate_subkeys(key8)[::-1]
    iv, ct = packet[:8], packet[8:]
    if len(ct) == 0 or len(ct) % 8 != 0:
        raise ValueError("panjang ciphertext tidak valid")
    prev, out = iv, b""
    for i in range(0, len(ct), 8):
        block = ct[i:i + 8]
        out += xor_bytes(crypt_block(block, subkeys), prev)
        prev = block
    return unpad(out).decode("utf-8")
