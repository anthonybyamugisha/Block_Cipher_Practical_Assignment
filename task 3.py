from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



# CBC MODE — ENCRYPTION

def aes_cbc_encrypt(key: bytes, plaintext: bytes):
    """Return (iv, ciphertext)."""
    iv = get_random_bytes(AES.block_size)           #generating a random 16 byte IV
    cipher = AES.new(key, AES.MODE_CBC, iv)         #CBC cipher
    padded = pad(plaintext, AES.block_size)         #padding
    ciphertext = cipher.encrypt(padded)         #encrypting
    return iv, ciphertext



# CBC MODE — DECRYPTION

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
    """Return original plaintext."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)         #decrypt to padded plain text
    plaintext = unpad(padded, AES.block_size)   # remove padding
    return plaintext



# CTR MODE — ROUND TRIP

def aes_ctr_roundtrip(key: bytes, plaintext: bytes):
    
    nonce = get_random_bytes(8)                         # 8 byte nonce

    
    initial_counter = nonce + b'\x00' * 8                   # Full 16-byte initial counter block

   
    enc_cipher = AES.new(key, AES.MODE_CTR,
                         nonce=b'',                    # we pass a 0-byte nonce
                         initial_value=initial_counter)
    ciphertext = enc_cipher.encrypt(plaintext)

    
    dec_cipher = AES.new(key, AES.MODE_CTR,
                         nonce=b'',                                     #Decrypt with the SAME 16-byte initial counter block
                         initial_value=initial_counter)
    recovered_plaintext = dec_cipher.decrypt(ciphertext)

    return nonce, initial_counter, ciphertext, recovered_plaintext


# ============================================================
# DEMO
# ============================================================
if __name__ == "__main__":
    key = get_random_bytes(16)                                    # AES-128 key
    plaintext = b"Cryptology and coding theory protect digital communication."

    print("Original message :", plaintext.decode())
    print("Plaintext length :", len(plaintext), "bytes")
    print("Key length       :", len(key), "bytes")
    print("=" * 60)

   #CBC
    iv, ct_cbc = aes_cbc_encrypt(key, plaintext)
    pt_cbc = aes_cbc_decrypt(key, iv, ct_cbc)

    print("[AES-CBC]")
    print("  IV (hex)          :", iv.hex())
    print("  Ciphertext (hex)  :", ct_cbc.hex())
    print("  Ciphertext length :", len(ct_cbc), "bytes")
    print("  Recovered text    :", pt_cbc.decode())
    print("  Match original    :", pt_cbc == plaintext)
    print("-" * 60)


       #CTR
    nonce, init_ctr, ct_ctr, pt_ctr = aes_ctr_roundtrip(key, plaintext)

    print("[AES-CTR]")
    print("  Nonce (hex)       :", nonce.hex())
    print("  Init counter (hex):", init_ctr.hex())        
    print("  Ciphertext (hex)  :", ct_ctr.hex())
    print("  Ciphertext length :", len(ct_ctr), "bytes")
    print("  Recovered text    :", pt_ctr.decode())       
    print("  Match original    :", pt_ctr == plaintext) 


    # ---------------- Observations ----------------
    print("Observations:")
    print(f"1. CBC ciphertext is {len(ct_cbc)} bytes (padded to a multiple")
    print(f"   of 16); CTR ciphertext is {len(ct_ctr)} bytes (same as plaintext).")
    print("2. CBC uses an IV + padding and chains blocks sequentially; CTR uses")
    print("   a unique nonce/counter, needs no padding, and is parallelizable.")