"""
Task 2: Python Avalanche Experiment (AES-128)

Instructions from the brief, and where each one is handled:
  1. Use AES-128 to encrypt one 16-byte plaintext block   -> KEY / PLAINTEXT / encrypt_block (+ known-answer test)
  2. Flip exactly one bit in the plaintext                 -> flip_bit (verified with count_changed_bits == 1)
  3. Encrypt again with the same key                       -> avalanche_trial uses the same encrypt_block / KEY
  4. Count how many ciphertext bits change                 -> count_changed_bits
  5. Repeat for at least 10 different single-bit flips     -> 16 distinct flip positions (asserted)
  6. Present the results in a small table                  -> printed table (+ saved to results_table.md)
  7. Compute the average percentage of changed bits        -> computed and printed
  8. Briefly interpret the results                         -> printed from the measured values
"""

import statistics
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# ------------------------------------------------------------------ setup
KEY = bytes.fromhex("9f3c7a1e5b8d2406c1e4a7b30d6f8952")   # 16 bytes = AES-128
PLAINTEXT = b"Zebra#Quartz@904"                            # exactly 16 bytes = one block
BLOCK_BITS = 128

assert len(KEY) == 16, "AES-128 needs a 16-byte key"
assert len(PLAINTEXT) == 16, "Plaintext must be exactly one 16-byte block"


def encrypt_block(block: bytes) -> bytes:
    """AES-128 encryption of exactly one 16-byte block with the fixed KEY.
    ECB is used only as the raw single-block primitive (no chaining with one block)."""
    assert len(block) == 16
    encryptor = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def flip_bit(data: bytes, bit_index: int) -> bytes:
    b = bytearray(data)
    byte_i, offset = divmod(bit_index, 8)
    b[byte_i] ^= (1 << offset)
    return bytes(b)


def count_changed_bits(x: bytes, y: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(x, y))


def avalanche_trial(encrypt_block, plaintext: bytes, bit_index: int):
    c1 = encrypt_block(plaintext)
    c2 = encrypt_block(flip_bit(plaintext, bit_index))
    return count_changed_bits(c1, c2)


kat_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
kat_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
kat_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
_kat = Cipher(algorithms.AES(kat_key), modes.ECB()).encryptor()
assert _kat.update(kat_pt) + _kat.finalize() == kat_ct, "AES-128 known-answer test failed"

# 16 different single-bit flips, spread over the whole block
flip_positions = [0, 3, 14, 21, 38, 47, 59, 66, 79, 85, 92, 103, 111, 120, 125, 127]
assert len(set(flip_positions)) == len(flip_positions) >= 10, "Need >= 10 DIFFERENT flips"

print("AES-128 avalanche experiment")
print(f"Key (hex)         : {KEY.hex()}")
print(f"Plaintext (hex)   : {PLAINTEXT.hex()}   {PLAINTEXT!r}")
print(f"Ciphertext (hex)  : {encrypt_block(PLAINTEXT).hex()}")
print("AES-128 known-answer test (FIPS-197): PASSED\n")

rows = []
for n, pos in enumerate(flip_positions, start=1):
    # Verify the flip really changes exactly ONE plaintext bit
    flipped = flip_bit(PLAINTEXT, pos)
    assert count_changed_bits(PLAINTEXT, flipped) == 1, "flip must change exactly one bit"

    changed = avalanche_trial(encrypt_block, PLAINTEXT, pos)
    pct = changed / BLOCK_BITS * 100
    rows.append((n, pos, changed, pct))

#  table
header = f"{'Trial':<6}{'Flipped bit':<13}{'Changed bits':<14}{'% changed':<10}"
print(header)
print("-" * len(header))
for n, pos, changed, pct in rows:
    print(f"{n:<6}{pos:<13}{changed:<14}{pct:<10.2f}")
print("-" * len(header))

pcts = [r[3] for r in rows]
avg = sum(pcts) / len(pcts)
print(f"Average % of ciphertext bits changed: {avg:.2f}%  (over {len(rows)} flips)")
print(f"Min: {min(pcts):.2f}%   Max: {max(pcts):.2f}%   Std dev: {statistics.pstdev(pcts):.2f}%")

# extra evidence: every possible single-bit flip
all_pct = [avalanche_trial(encrypt_block, PLAINTEXT, i) / BLOCK_BITS * 100 for i in range(BLOCK_BITS)]
print(f"Extra check: average over all 128 single-bit flips = {sum(all_pct)/128:.2f}%")

# save the table in a form that can be pasted into the report
with open("results_table.md", "w", encoding="utf-8") as f:
    f.write("| Trial | Flipped bit | Changed bits | % changed |\n|---|---|---|---|\n")
    for n, pos, changed, pct in rows:
        f.write(f"| {n} | {pos} | {changed} | {pct:.2f} |\n")
    f.write(f"| **Average** | | | **{avg:.2f}** |\n")