import os
import base64

# Generate 32 bytes (256 bits) of random data
hmac_key_bytes = os.urandom(32)

# Encode in base64 for safe storage in .env
hmac_key_b64 = base64.urlsafe_b64encode(hmac_key_bytes).decode()

print("HMAC_KEY=", hmac_key_b64)
