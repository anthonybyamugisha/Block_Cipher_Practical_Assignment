import hashlib
import hmac

# Original message
message = b"Cryptology and coding theory protect digital communication."

# Modified message - one character changed
modified_message = b"Cryptology and coding theory protect Digital communication."

# Secret key
key = b"CSC3114-Group-Secret-Key-2026"

def sha256_digest(message: bytes) -> str:
    return hashlib.sha256(message).hexdigest()

def make_hmac(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_hmac(key: bytes, message: bytes, tag: bytes) -> bool:
    expected = make_hmac(key, message)
    return hmac.compare_digest(expected, tag)

# Compute SHA-256 hashes
original_hash = sha256_digest(message)
modified_hash = sha256_digest(modified_message)

# Compute HMAC-SHA256 tags
original_hmac = make_hmac(key, message)
modified_hmac = make_hmac(key, modified_message)

# HMAC verification
original_verification = verify_hmac(key, message, original_hmac)

# Modified message checked using the ORIGINAL tag
modified_verification = verify_hmac(key, modified_message, original_hmac)

print("Original message:")
print(message.decode())

print("\nOriginal SHA-256 hash:")
print(original_hash)

print("\nOriginal HMAC-SHA256 tag:")
print(original_hmac.hex())

print("\nModified message:")
print(modified_message.decode())

print("\nModified SHA-256 hash:")
print(modified_hash)

print("\nModified HMAC-SHA256 tag:")
print(modified_hmac.hex())

print("\nOriginal message HMAC verification:")
print(original_verification)

print("\nModified message HMAC verification using original tag:")
print(modified_verification)