import os
from cryptography.fernet import Fernet, InvalidToken

AES_KEY = os.getenv("AES_KEY")

if AES_KEY is None:
    raise ValueError("AES_KEY is missing from .env file")

fernet = Fernet(AES_KEY)

def encrypt_data(plaintext: str | None) -> str | None:
    if plaintext is None:
        return None
    token = fernet.encrypt(plaintext.encode())
    return token.decode()


def decrypt_data(ciphertext: str | None) -> str | None:
    if ciphertext is None:
        return None
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return ciphertext
