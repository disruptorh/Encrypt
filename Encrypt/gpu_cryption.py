import numpy as np
from numba import cuda
import math
import base64
from time import time
from threading import Thread
import os
import hashlib
import logging
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- Constantes y Configuración ---

# El cracker de GPU se enfocará en AES-128, que es lo que implementa
# el código proporcionado (10 rondas).
AES_BLOCK_SIZE_BYTES = 16
RESULTS_FILENAME = "gpu_aes_results.txt"
KDF_ROUNDS = 100_000 # Factor de trabajo para la derivación de la clave (ajustar según la potencia de la GPU)
SALT_BYTES = 16
IV_BYTES = 16

# --- Implementación de AES para Numba/CUDA ---

Sbox = np.array([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
], dtype=np.uint8)

InvSbox = np.array([
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
], dtype=np.uint8)

Rcon = np.array([
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
], dtype=np.uint8)

@cuda.jit(device=True)
def gmul(a, b):
    p = np.uint8(0)
    for _ in range(8):
        if (b & 1) != 0:
            p ^= a
        
        is_high_bit_set = (a & 0x80) != 0
        a = np.uint8(a << 1)
        if is_high_bit_set:
            a ^= np.uint8(0x1B)
        b = np.uint8(b >> 1)
    return p

# --- Derivación de Clave en GPU (KDF) ---

@cuda.jit(device=True)
def kdf_transform(state):
    """ Una transformación simple y no lineal para el KDF. """
    for i in range(16):
        # La transformación usa la S-box de AES para añadir no linealidad
        # y un XOR con otro byte del estado para difusión.
        state[i] = Sbox[state[i]] ^ state[(i + 5) % 16]
    return state

@cuda.jit
def kdf_kernel(initial_state, rounds, derived_key):
    """
    Kernel para realizar un trabajo intensivo en la GPU y derivar una clave
    a partir de un estado inicial (hash de la contraseña + salt).
    """
    # Copiar el estado inicial a la memoria local del hilo
    state = cuda.local.array(16, dtype=np.uint8)
    for i in range(16):
        state[i] = initial_state[i]

    # Transformar iterativamente el estado 'rounds' veces
    for _ in range(rounds):
        state = kdf_transform(state)

    # Escribir el estado final en el array de salida
    for i in range(16):
        derived_key[i] = state[i]

def derive_key_gpu(password: str, salt: bytes):
    """
    Función Host que orquesta la derivación de la clave en la GPU.
    """
    # 1. Generar estado inicial a partir de la contraseña y el salt
    initial_state_hash = hashlib.sha256(password.encode('utf-8') + salt).digest()
    h_initial_state = np.frombuffer(initial_state_hash[:16], dtype=np.uint8)
    
    # 2. Preparar buffers en la GPU
    d_initial_state = cuda.to_device(h_initial_state)
    d_derived_key = cuda.device_array(16, dtype=np.uint8)

    # 3. Lanzar el kernel de KDF (1 bloque, 1 hilo es suficiente ya que es un trabajo secuencial)
    kdf_kernel[1, 1](d_initial_state, KDF_ROUNDS, d_derived_key)
    
    # 4. Obtener el resultado de vuelta a la CPU
    h_derived_key = d_derived_key.copy_to_host()
    return bytes(h_derived_key)

# --- Primitivas de Cifrado AES en GPU ---

@cuda.jit(device=True)
def _key_expansion_logic(master_key, round_keys):
    """ Expansión de clave para AES-128. """
    for i in range(16):
        round_keys[i // 4, i % 4] = master_key[i]
   
    for i in range(4, 44):
        temp = cuda.local.array(4, dtype=np.uint8)
        for k in range(4):
            temp[k] = round_keys[i - 1, k]

        if i % 4 == 0:
            # RotWord
            t = temp[0]
            temp[0], temp[1], temp[2], temp[3] = temp[1], temp[2], temp[3], t
            # SubWord
            for k in range(4):
                temp[k] = Sbox[temp[k]]
            # Rcon
            temp[0] ^= Rcon[i // 4]

        for k in range(4):
            round_keys[i, k] = round_keys[i - 4, k] ^ temp[k]

@cuda.jit
def key_expansion_kernel(master_key, round_keys):
    """Kernel que envuelve la lógica de expansión de clave para ser llamada desde el host."""
    _key_expansion_logic(master_key, round_keys)

@cuda.jit(device=True)
def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i, j] ^= k[i, j]

@cuda.jit(device=True)
def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i, j] = Sbox[s[i, j]]

@cuda.jit(device=True)
def shift_rows(s):
    # Fila 1: shift left by 1
    s[1,0], s[1,1], s[1,2], s[1,3] = s[1,1], s[1,2], s[1,3], s[1,0]
    # Fila 2: shift left by 2
    s[2,0], s[2,1], s[2,2], s[2,3] = s[2,2], s[2,3], s[2,0], s[2,1]
    # Fila 3: shift left by 3
    s[3,0], s[3,1], s[3,2], s[3,3] = s[3,3], s[3,0], s[3,1], s[3,2]

@cuda.jit(device=True)
def mix_columns(s):
    temp = cuda.local.array(4, dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            temp[j] = s[j, i]
        
        s[0, i] = np.uint8(gmul(temp[0], 2)) ^ np.uint8(gmul(temp[1], 3)) ^ temp[2] ^ temp[3]
        s[1, i] = temp[0] ^ np.uint8(gmul(temp[1], 2)) ^ np.uint8(gmul(temp[2], 3)) ^ temp[3]
        s[2, i] = temp[0] ^ temp[1] ^ np.uint8(gmul(temp[2], 2)) ^ np.uint8(gmul(temp[3], 3))
        s[3, i] = np.uint8(gmul(temp[0], 3)) ^ temp[1] ^ temp[2] ^ np.uint8(gmul(temp[3], 2))

@cuda.jit(device=True)
def encrypt_block_gpu(state, round_keys):
    """ Realiza el cifrado AES completo en un solo bloque (estado). """
    # Ronda inicial
    add_round_key(state, round_keys[0:4])

    # 9 rondas principales
    for i in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[i*4 : (i+1)*4])

    # Ronda final (sin MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[40:44])

# --- Kernel de Cifrado/Descifrado (Modo CTR) ---

@cuda.jit
def aes_ctr_kernel(data, data_len, iv, round_keys, output):
    """
    Kernel para cifrar/descifrar datos usando AES en modo CTR.
    Cada hilo procesa un byte de los datos de entrada/salida.
    """
    thread_id = cuda.grid(1)

    if thread_id >= data_len:
        return

    # Calcular el bloque de datos al que pertenece este hilo/byte
    block_idx = thread_id // 16
    byte_in_block_idx = thread_id % 16
    
    # 1. Preparar el bloque contador (nonce + counter) para el bloque de datos actual
    # El IV se divide en un nonce (primeros 8 bytes) y un contador inicial (últimos 8 bytes)
    counter_block_state = cuda.local.array((4, 4), dtype=np.uint8)
    
    # Copiar el nonce
    for i in range(8):
        counter_block_state[i % 4, i // 4] = iv[i]

    # Calcular el valor del contador para este bloque específico
    counter_part = 0
    for i in range(8):
        counter_part = (counter_part << 8) | iv[8 + i]
    counter_part += block_idx

    # Escribir el nuevo valor del contador en el estado
    for i in range(8):
        byte = (counter_part >> (8 * (7 - i))) & 0xFF
        counter_block_state[(i + 8) % 4, (i + 8) // 4] = byte

    # 2. Cifrar el bloque contador para generar el keystream
    encrypt_block_gpu(counter_block_state, round_keys)
    
    # 3. Aplicar XOR entre el keystream y el byte de datos
    # Extraer el byte correspondiente del keystream
    keystream_byte = counter_block_state[byte_in_block_idx % 4, byte_in_block_idx // 4]
    
    output[thread_id] = data[thread_id] ^ keystream_byte

# --- Funciones Host de Orquestación ---

def _execute_aes_ctr(data: bytes, password: str, salt: bytes):
    """Función interna para ejecutar el proceso de cifrado/descifrado."""
    if not cuda.is_available():
        raise RuntimeError("No se detecta un entorno CUDA funcional.")

    # 1. Derivar la clave de 16 bytes a partir de la contraseña
    logging.info(f"Derivando clave con {KDF_ROUNDS} rondas en GPU...")
    start_time = time()
    key = derive_key_gpu(password, salt)
    logging.info(f"Clave derivada en {time() - start_time:.2f} segundos.")
    
    # 2. Expandir la clave en la GPU
    logging.info("Preparando para expandir la clave en la GPU...")
    h_key = np.frombuffer(key, dtype=np.uint8)
    d_key = cuda.to_device(h_key) # Copiar la clave a la memoria del dispositivo
    d_round_keys = cuda.device_array((44, 4), dtype=np.uint8)
    
    logging.info("Lanzando kernel de expansión de clave...")
    start_expansion_time = time()
    key_expansion_kernel[1, 1](d_key, d_round_keys)
    cuda.synchronize()
    logging.info(f"Expansión de clave completada en {time() - start_expansion_time:.4f} segundos.")

    # 3. Preparar datos para el kernel principal
    h_data = np.frombuffer(data, dtype=np.uint8)
    h_iv = np.frombuffer(salt, dtype=np.uint8) # Usar salt como IV para CTR
    d_data = cuda.to_device(h_data)
    d_iv = cuda.to_device(h_iv)
    d_output = cuda.device_array_like(d_data)
    
    data_len = len(data)

    # 4. Configurar y lanzar el kernel CTR
    threads_per_block = 256
    blocks_per_grid = math.ceil(data_len / threads_per_block)
    
    logging.info(f"Ejecutando AES-CTR en GPU para {data_len} bytes...")
    start_time = time()
    aes_ctr_kernel[blocks_per_grid, threads_per_block](
        d_data, data_len, d_iv, d_round_keys, d_output
    )
    cuda.synchronize()
    logging.info(f"Procesamiento en GPU completado en {time() - start_time:.4f} segundos.")

    # 5. Devolver el resultado
    return d_output.copy_to_host().tobytes()

def encrypt_aes(plaintext, password, google_user_id=None, recipient_id=None):
    """
    Cifra el texto plano usando un enfoque híbrido:
    1. Genera una Clave de Cifrado de Datos (DEK) aleatoria.
    2. Cifra el texto plano con la DEK usando AES-256-GCM.
    3. "Envuelve" (cifra) la DEK con una clave derivada de la contraseña (KEK).
    4. Si se proporciona un google_user_id, envuelve también la DEK con una clave
       de recuperación derivada de la ID de usuario.
    5. Si se proporciona un recipient_id, envuelve también la DEK con una clave
       de recuperación derivada del ID del destinatario.
    """
    backend = default_backend()
    
    # 1. Generar DEK
    dek = os.urandom(32) # AES-256
    
    # 2. Cifrar datos con DEK
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12) # GCM recomienda 12 bytes
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    # 3. Envolver DEK con la contraseña
    password_salt = os.urandom(16)
    kdf = Scrypt(salt=password_salt, length=32, n=2**14, r=8, p=1, backend=backend)
    password_kek = kdf.derive(password.encode('utf-8'))
    
    kek_aesgcm = AESGCM(password_kek)
    kek_nonce = os.urandom(12)
    wrapped_dek = kek_aesgcm.encrypt(kek_nonce, dek, None)

    # 4. Envolver DEK con la ID de Google del autor para recuperación
    author_recovery_data = {}
    if google_user_id:
        # Usamos un "pepper" del lado del servidor para fortalecer la derivación de la clave
        # En una aplicación real, esto debería estar en una variable de entorno segura.
        recovery_pepper = b'some-very-secret-server-side-pepper'
        author_salt = os.urandom(16)
        
        # Usamos PBKDF2 ya que la entrada (user_id + pepper) no es una contraseña de baja entropía
        kdf_recovery = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=author_salt,
            iterations=100000,
            backend=backend
        )
        author_recovery_kek = kdf_recovery.derive(google_user_id.encode('utf-8') + recovery_pepper)
        
        author_recovery_aesgcm = AESGCM(author_recovery_kek)
        author_recovery_nonce = os.urandom(12)
        author_recovery_wrapped_dek = author_recovery_aesgcm.encrypt(author_recovery_nonce, dek, None)
        
        author_recovery_data = {
            "recovery_salt": base64.b64encode(author_salt).decode('utf-8'),
            "recovery_nonce": base64.b64encode(author_recovery_nonce).decode('utf-8'),
            "recovery_wrapped_dek": base64.b64encode(author_recovery_wrapped_dek).decode('utf-8')
        }

    # 5. Envolver DEK con la ID de Google del destinatario (si se proporciona)
    recipient_recovery_data = {}
    if recipient_id:
        # Usamos un "pepper" del lado del servidor para fortalecer la derivación de la clave
        # En una aplicación real, esto debería estar en una variable de entorno segura.
        recovery_pepper = b'some-very-secret-server-side-pepper'
        recipient_salt = os.urandom(16)
        
        # Usamos PBKDF2 ya que la entrada (user_id + pepper) no es una contraseña de baja entropía
        kdf_recovery = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=recipient_salt,
            iterations=100000,
            backend=backend
        )
        recipient_recovery_kek = kdf_recovery.derive(recipient_id.encode('utf-8') + recovery_pepper)
        
        recipient_recovery_aesgcm = AESGCM(recipient_recovery_kek)
        recipient_recovery_nonce = os.urandom(12)
        recipient_recovery_wrapped_dek = recipient_recovery_aesgcm.encrypt(recipient_recovery_nonce, dek, None)
        
        recipient_recovery_data = {
            "recovery_salt": base64.b64encode(recipient_salt).decode('utf-8'),
            "recovery_nonce": base64.b64encode(recipient_recovery_nonce).decode('utf-8'),
            "recovery_wrapped_dek": base64.b64encode(recipient_recovery_wrapped_dek).decode('utf-8')
        }

    # 6. Empaquetar todo en un JSON
    encrypted_payload = {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "password_salt": base64.b64encode(password_salt).decode('utf-8'),
        "kek_nonce": base64.b64encode(kek_nonce).decode('utf-8'),
        "wrapped_dek": base64.b64encode(wrapped_dek).decode('utf-8'),
        "author_recovery_data": author_recovery_data,
        "recipient_recovery_data": recipient_recovery_data
    }
    
    return json.dumps(encrypted_payload)


def decrypt_aes(encrypted_json, password):
    """
    Descifra un payload JSON usando la contraseña proporcionada.
    """
    backend = default_backend()
    payload = json.loads(encrypted_json)

    # Decodificar todos los componentes
    nonce = base64.b64decode(payload['nonce'])
    ciphertext = base64.b64decode(payload['ciphertext'])
    password_salt = base64.b64decode(payload['password_salt'])
    kek_nonce = base64.b64decode(payload['kek_nonce'])
    wrapped_dek = base64.b64decode(payload['wrapped_dek'])

    # 1. Derivar la KEK de la contraseña
    kdf = Scrypt(salt=password_salt, length=32, n=2**14, r=8, p=1, backend=backend)
    password_kek = kdf.derive(password.encode('utf-8'))

    # 2. Descifrar la DEK
    try:
        kek_aesgcm = AESGCM(password_kek)
        dek = kek_aesgcm.decrypt(kek_nonce, wrapped_dek, None)
    except Exception as e:
        print(f"Error al descifrar la DEK con la contraseña: {e}")
        raise ValueError("Contraseña incorrecta o datos corruptos.")

    # 3. Descifrar el texto original
    aesgcm = AESGCM(dek)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext_bytes.decode('utf-8')


def decrypt_aes_with_recovery(encrypted_json, google_user_id):
    """
    Descifra un payload JSON usando la ID de usuario de Google.
    Intenta descifrar usando los datos de recuperación del autor o del destinatario.
    """
    payload = json.loads(encrypted_json)
    
    author_data = payload.get("author_recovery_data")
    recipient_data = payload.get("recipient_recovery_data")

    # Primero, verificar si el archivo se guardó con alguna opción de recuperación
    if not author_data and not recipient_data:
        raise ValueError("Este archivo no fue cifrado con la opción de recuperación por identidad habilitada.")

    # Intentar con los datos del autor si existen
    if author_data:
        try:
            return _try_recovery_decryption(payload, google_user_id, "author_recovery_data")
        except ValueError:
            pass # Falla silenciosamente y prueba con el siguiente

    # Intentar con los datos del destinatario si existen
    if recipient_data:
        try:
            return _try_recovery_decryption(payload, google_user_id, "recipient_recovery_data")
        except ValueError:
            pass # Falla silenciosamente

    # Si hemos llegado hasta aquí, significa que había datos de recuperación pero ninguno coincidió
    raise ValueError("Tu identidad de Google no coincide con la del autor o destinatario del archivo.")

def _try_recovery_decryption(payload, google_user_id, recovery_key):
    """Función auxiliar para no repetir código de descifrado."""
    backend = default_backend()
    
    # Decodificar componentes principales
    nonce = base64.b64decode(payload['nonce'])
    ciphertext = base64.b64decode(payload['ciphertext'])
    
    # Decodificar componentes de recuperación específicos
    recovery_data = payload[recovery_key]
    if not recovery_data:
        raise ValueError("No hay datos en este bloque de recuperación.")
        
    recovery_salt = base64.b64decode(recovery_data['recovery_salt'])
    recovery_nonce = base64.b64decode(recovery_data['recovery_nonce'])
    recovery_wrapped_dek = base64.b64decode(recovery_data['recovery_wrapped_dek'])
    
    # 1. Derivar la KEK de recuperación
    recovery_pepper = b'some-very-secret-server-side-pepper' # Debe ser el mismo que en el cifrado
    kdf_recovery = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=recovery_salt,
        iterations=100000,
        backend=backend
    )
    recovery_kek = kdf_recovery.derive(google_user_id.encode('utf-8') + recovery_pepper)

    # 2. Descifrar la DEK
    try:
        recovery_aesgcm = AESGCM(recovery_kek)
        dek = recovery_aesgcm.decrypt(recovery_nonce, recovery_wrapped_dek, None)
    except Exception as e:
        print(f"Error al descifrar la DEK con la clave de recuperación: {e}")
        raise ValueError("Identidad de Google incorrecta o datos corruptos.")
        
    # 3. Descifrar el texto original
    aesgcm = AESGCM(dek)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext_bytes.decode('utf-8')

# --- Ejemplo de uso ---
if __name__ == '__main__':
    try:
        # Este bloque solo se ejecutará si se corre el script directamente
        print("--- DEMO DEL MÓDULO DE CIFRADO GPU ---")
        
        user_password = "mi_contraseña_super_secreta_123"
        original_text = "Este es un mensaje de prueba para el nuevo sistema de cifrado con GPU. La idea es que sea muy seguro."

        print(f"\nContraseña: '{user_password}'")
        print(f"Texto Original: '{original_text}'")

        # Cifrado
        print("\n--- CIFRANDO ---")
        encrypted_message = encrypt_aes(original_text, user_password)
        print(f"\nMensaje Cifrado (JSON): {encrypted_message}")

        # Descifrado
        print("\n--- DESCIFRANDO ---")
        decrypted_text = decrypt_aes(encrypted_message, user_password)
        print(f"\nMensaje Descifrado: '{decrypted_text}'")
        
        # Verificación
        assert original_text == decrypted_text
        print("\nÉXITO: El texto original y el descifrado coinciden.")

    except Exception as e:
        print(f"\nERROR: Ha ocurrido un problema. Asegúrate de tener los drivers de NVIDIA y CUDA instalados.")
        print(f"Detalle: {e}")
