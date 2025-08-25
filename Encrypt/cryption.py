import base64
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def get_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=1000000)


def encrypt_aes(text, password, email_recovery=False):
    try:
        # 1. Generate a random Data Encryption Key (DEK) for AES-GCM
        dek = AESGCM.generate_key(bit_length=256)

        # 2. Encrypt the plaintext with the DEK
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, text.encode('utf-8'), None)

        # 3. Wrap the DEK with a key derived from the user's password
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        password_key = kdf.derive(password.encode('utf-8'))
        password_wrapped_key = AESGCM(password_key).encrypt(os.urandom(12), dek, None)

        # 4. Prepare the base result object
        result = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'password_wrapped_key': base64.b64encode(password_wrapped_key).decode('utf-8')
        }

        # 5. If email recovery is enabled, also wrap the DEK with an RSA public key
        if email_recovery:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            recovery_wrapped_key = public_key.encrypt(
                dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result['recovery_wrapped_key'] = base64.b64encode(recovery_wrapped_key).decode('utf-8')

            # Serialize and return the private key for the user to handle
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            result['recovery_key'] = base64.b64encode(private_pem).decode('utf-8')

        return result
    except Exception as e:
        return {'error': str(e)}


def decrypt_aes(encrypted_data, password):
    try:
        # 1. Decode all components from Base64
        salt = base64.b64decode(encrypted_data['salt'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        password_wrapped_key = base64.b64decode(encrypted_data['password_wrapped_key'])

        # 2. Derive the same key from the password and salt
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        password_key = kdf.derive(password.encode('utf-8'))

        # 3. Unwrap (decrypt) the DEK
        dek = AESGCM(password_key).decrypt(password_wrapped_key[:12], password_wrapped_key[12:], None)

        # 4. Decrypt the actual ciphertext with the DEK
        aesgcm = AESGCM(dek)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

        return {'text': plaintext_bytes.decode('utf-8')}
    except Exception:
        return {'error': 'Failed to decrypt. Check password or data integrity.'}


def decrypt_aes_with_recovery(encrypted_data, recovery_key_b64):
    try:
        # 1. Decode components
        recovery_wrapped_key = base64.b64decode(encrypted_data['recovery_wrapped_key'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])

        # 2. Load the private key from the recovery key
        private_key_pem = base64.b64decode(recovery_key_b64)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        # 3. Unwrap (decrypt) the DEK using the private key
        dek = private_key.decrypt(
            recovery_wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 4. Decrypt the ciphertext with the DEK
        aesgcm = AESGCM(dek)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        return {'text': plaintext_bytes.decode('utf-8')}
    except Exception:
        return {'error': 'Invalid recovery key or corrupt data.'}


def encrypt_base64(text):
    try:
        encoded_text = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        return {'text': encoded_text}
    except Exception as e:
        return {'error': 'Invalid Base64 string'}


def decrypt_base64(text):
    try:
        return {'text': base64.b64decode(text).decode('utf-8')}
    except Exception:
        return {'error': 'Invalid Base64 string.'}


def encrypt_fernet(text, key_str=None):
    if key_str:
        key = key_str.encode('utf-8')
    else:
        key = Fernet.generate_key()
    f = Fernet(key)
    encrypted_text = f.encrypt(text.encode('utf-8'))
    return {
        'text': encrypted_text.decode('utf-8'),
        'key': key.decode('utf-8')
    }


def decrypt_fernet(text, key):
    try:
        f = Fernet(key.encode('utf-8'))
        decrypted_text = f.decrypt(text.encode('utf-8'))
        return {'text': decrypted_text.decode('utf-8')}
    except Exception:
        return {'error': 'Invalid key or corrupted data.'}


def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        elif '0' <= char <= '9':
            result += chr((ord(char) - ord('0') + shift) % 10 + ord('0'))
        else:
            result += char
    return result


def encrypt_caesar(text, shift, rounds):
    total_shift = shift * rounds
    return {'text': caesar_cipher(text, total_shift)}


def decrypt_caesar(text, shift, rounds):
    total_shift = shift * rounds
    return {'text': caesar_cipher(text, -total_shift)}

# --- Cifrado Vigenère (César Avanzado) ---
VIGENERE_CHARSET = (
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    '!@#$%^&*()_+-=[]{}|;:,.<>/?`~'
)


def vigenere_cipher(text, key, mode='encrypt'):
    result = []
    key_len = len(key)
    charset_len = len(VIGENERE_CHARSET)
    char_to_index = {char: i for i, char in enumerate(VIGENERE_CHARSET)}

    for i, char in enumerate(text):
        if char in char_to_index:
            text_index = char_to_index[char]
            key_char = key[i % key_len]

            if key_char not in char_to_index:
                # If a character in the key is not in the charset, treat its index as 0 (no shift)
                key_index = 0
            else:
                key_index = char_to_index[key_char]

            if mode == 'encrypt':
                new_index = (text_index + key_index) % charset_len
            else:  # decrypt
                new_index = (text_index - key_index + charset_len) % charset_len

            result.append(VIGENERE_CHARSET[new_index])
        else:
            result.append(char)

    return "".join(result)


def encrypt_vigenere(text, password):
    if not password:
        return {'error': 'Password is required for Vigenere cipher.'}
    return {'text': vigenere_cipher(text, password, 'encrypt')}


def decrypt_vigenere(text, password):
    if not password:
        return {'error': 'Password is required for Vigenere cipher.'}
    return {'text': vigenere_cipher(text, password, 'decrypt')}
