import base64
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Se carga la misma lista de palabras clave que usa el cracker de Vigenère
try:
    with open('cribs.json', 'r', encoding='utf-8') as f:
        CRIBS = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    CRIBS = [
        "porque", "cuando", "entonces", "siempre", "cifrado",
        "mensaje", "secreto", "informacion", "confidencial"
    ]

# Filtrar cribs para que sean útiles (evitar falsos positivos con palabras muy cortas)
CRIBS = [crib.encode('utf-8') for crib in CRIBS if len(crib) >= 4]

# --- Constantes para el descifrado AES ---
# Estas constantes deben coincidir con las usadas en el script de cifrado.
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # AES-256
# ATENCIÓN: Se ha reducido drásticamente el número de iteraciones para aumentar
# la velocidad del cracking en la CPU. El valor original (100000) es más seguro
# pero hace que la fuerza bruta sea extremadamente lenta.
ITERATIONS = 100

def decrypt_aes(encrypted_data, password):
    """
    Intenta descifrar un bloque de datos AES-CBC usando una contraseña.
    Se asume que los datos están formateados como: SALT | IV | CIPHERTEXT
    """
    try:
        password_bytes = str(password).encode('utf-8')

        # Extraer salt, IV y texto cifrado
        salt = encrypted_data[:SALT_SIZE]
        iv = encrypted_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
        ciphertext = encrypted_data[SALT_SIZE + IV_SIZE:]

        # Derivar la clave desde la contraseña y el salt (EL PASO CRUCIAL)
        key = PBKDF2(password_bytes, salt, dkLen=KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA256)

        # Crear el objeto cipher y descifrar
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)

        # Quitar el padding PKCS7
        padding_len = decrypted_padded[-1]
        if padding_len > AES.block_size or padding_len == 0:
            return None # Padding incorrecto
        
        # Verificar que el padding sea consistente
        for i in range(1, padding_len + 1):
            if decrypted_padded[-i] != padding_len:
                return None # Padding incorrecto

        return decrypted_padded[:-padding_len]

    except (ValueError, IndexError):
        # Un error aquí normalmente significa que la contraseña es incorrecta
        return None

def run_aes_cracker(encrypted_b64, max_key=1000000):
    """
    Función principal para crackear AES por fuerza bruta numérica en la CPU.
    Recibe un objeto JSON (que contiene salt, iv y ciphertext) codificado en Base64.
    """
    if not CRIBS:
        return "Error: No se encontraron 'cribs' para verificar la contraseña."

    try:
        # Paso 1: Decodificar el Base64 de entrada para obtener el string JSON.
        json_string = base64.b64decode(encrypted_b64).decode('utf-8')
        
        # Paso 2: Parsear el string JSON para obtener el objeto.
        encrypted_json = json.loads(json_string)
        salt_b64 = encrypted_json['salt']
        iv_b64 = encrypted_json['iv']
        ciphertext_b64 = encrypted_json['ciphertext']

        # Paso 3: Decodificar cada componente de Base64
        salt = base64.b64decode(salt_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # Paso 4: Reconstruir el bloque de datos que espera decrypt_aes
        encrypted_data = salt + iv + ciphertext

    except (json.JSONDecodeError, KeyError, TypeError):
        return "Error: El texto de entrada no es un JSON válido con los campos 'salt', 'iv' y 'ciphertext'."
    except base64.binascii.Error:
        return "Error: El texto de entrada no es un Base64 válido o su contenido JSON es incorrecto."

    if len(encrypted_data) < SALT_SIZE + IV_SIZE + AES.block_size:
        return "Error: Los datos cifrados reconstruidos son demasiado cortos."

    print(f"Iniciando ataque de fuerza bruta en CPU para AES (1 a {max_key})...")

    for password_candidate in range(1, max_key + 1):
        decrypted_data = decrypt_aes(encrypted_data, password_candidate)

        if decrypted_data:
            # Comprobar si alguno de los cribs está en el texto descifrado
            for crib in CRIBS:
                if crib in decrypted_data:
                    try:
                        # Intentar decodificar como texto para mostrar un resultado legible
                        plaintext_preview = decrypted_data.decode('utf-8', errors='ignore').strip()
                        return (f"¡Contraseña encontrada!: {password_candidate}\n"
                                f"Texto descifrado (parcial): '{plaintext_preview[:100]}...'")
                    except Exception:
                         return (f"¡Contraseña encontrada!: {password_candidate}\n"
                                f"El contenido descifrado no es texto UTF-8 válido, pero se encontró un crib.")

    return f"No se encontró la contraseña después de probar {max_key} combinaciones."
