import numpy as np
from numba import cuda
import math
import json
import base64
from time import time
from threading import Thread

# --- Constantes y Configuración ---

# El cracker de GPU se enfocará en AES-128, que es lo que implementa
# el código proporcionado (10 rondas).
AES_BLOCK_SIZE_BYTES = 16

# Límite de resultados a almacenar desde la GPU para no agotar la memoria
MAX_RESULTS = 100
# Nombre del archivo donde se guardarán los resultados.
RESULTS_FILENAME = "gpu_aes_results.txt"

# Se carga la misma lista de palabras clave que usan los otros crackers
try:
    with open('cribs.json', 'r', encoding='utf-8') as f:
        CRIBS = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    CRIBS = ["porque", "cuando", "entonces", "cifrado", "mensaje", "secreto"]

# Filtrar cribs y convertirlos a bytes para la GPU
CRIBS_BYTES = [c.encode('utf-8') for c in CRIBS if len(c) >= 4]

# --- Implementación de AES para Numba/CUDA ---
# Estas son las funciones y constantes del código que proporcionaste,
# adaptadas para ser compiladas por Numba y ejecutadas en la GPU.
# Todas las funciones que se ejecutan en la GPU deben ser "device functions".

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
    """
    Multiplicación explícita en el campo de Galois GF(2^8).
    Se fuerza el tipado a uint8 para evitar errores de inferencia en Numba.
    """
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


@cuda.jit(device=True)
def key_expansion(master_key, round_keys):
    # Convertimos el master key (un entero de 128-bit) a una matriz 4x4 de bytes
    for i in range(16):
        byte = (master_key >> (8 * (15 - i))) & 0xFF
        round_keys[i // 4, i % 4] = byte

    # Generamos el resto de las round keys
    for i in range(4, 4 * 11):
        if i % 4 == 0:
            # RotWord and SubWord
            temp = Sbox[round_keys[(i - 1) // 4, 1]]
            byte = round_keys[(i - 4) // 4, 0] ^ temp ^ Rcon[i // 4]
            round_keys[i // 4, 0] = byte
            
            for j in range(1, 4):
                temp = Sbox[round_keys[(i - 1) // 4, (j + 1) % 4]] if j != 3 else Sbox[round_keys[(i - 1) // 4, 0]]
                byte = round_keys[(i - 4) // 4, j] ^ temp
                round_keys[i // 4, j] = byte
        else:
            for j in range(4):
                byte = round_keys[(i - 4) // 4, j] ^ round_keys[(i - 1) // 4, j]
                round_keys[i // 4, j] = byte

@cuda.jit(device=True)
def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i, j] ^= k[i, j]

@cuda.jit(device=True)
def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i, j] = InvSbox[s[i, j]]

@cuda.jit(device=True)
def inv_shift_rows(s):
    # Fila 1: shift right by 1
    s[1,0], s[1,1], s[1,2], s[1,3] = s[1,3], s[1,0], s[1,1], s[1,2]
    # Fila 2: shift right by 2
    s[2,0], s[2,1], s[2,2], s[2,3] = s[2,2], s[2,3], s[2,0], s[2,1]
    # Fila 3: shift right by 3
    s[3,0], s[3,1], s[3,2], s[3,3] = s[3,1], s[3,2], s[3,3], s[3,0]


@cuda.jit(device=True)
def inv_mix_columns(s):
    """
    Implementación explícita de InvMixColumns usando gmul.
    Se fuerza el tipado a uint8 para evitar errores de inferencia.
    """
    temp = cuda.local.array(4, dtype=np.uint8)
    for i in range(4):
        # Copiamos la columna actual a un array temporal
        for j in range(4):
            temp[j] = s[j, i]

        # Aplicamos la matriz de transformación inversa con casting explícito
        s[0, i] = np.uint8(gmul(temp[0], np.uint8(0x0e))) ^ np.uint8(gmul(temp[1], np.uint8(0x0b))) ^ np.uint8(gmul(temp[2], np.uint8(0x0d))) ^ np.uint8(gmul(temp[3], np.uint8(0x09)))
        s[1, i] = np.uint8(gmul(temp[0], np.uint8(0x09))) ^ np.uint8(gmul(temp[1], np.uint8(0x0e))) ^ np.uint8(gmul(temp[2], np.uint8(0x0b))) ^ np.uint8(gmul(temp[3], np.uint8(0x0d)))
        s[2, i] = np.uint8(gmul(temp[0], np.uint8(0x0d))) ^ np.uint8(gmul(temp[1], np.uint8(0x09))) ^ np.uint8(gmul(temp[2], np.uint8(0x0e))) ^ np.uint8(gmul(temp[3], np.uint8(0x0b)))
        s[3, i] = np.uint8(gmul(temp[0], np.uint8(0x0b))) ^ np.uint8(gmul(temp[1], np.uint8(0x0d))) ^ np.uint8(gmul(temp[2], np.uint8(0x09))) ^ np.uint8(gmul(temp[3], np.uint8(0x0e)))


@cuda.jit(device=True)
def decrypt_block(cipher_state, round_keys):
    # Ronda final
    add_round_key(cipher_state, round_keys[40:44])
    inv_shift_rows(cipher_state)
    inv_sub_bytes(cipher_state)

    # 9 rondas principales
    for i in range(9, 0, -1):
        add_round_key(cipher_state, round_keys[i*4 : (i+1)*4])
        inv_mix_columns(cipher_state)
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

    # Ronda inicial
    add_round_key(cipher_state, round_keys[0:4])

@cuda.jit(device=True)
def check_crib_match(decrypted_block, block_len, crib, crib_len):
    if crib_len > block_len:
        return False
    for i in range(block_len - crib_len + 1):
        match = True
        for j in range(crib_len):
            if decrypted_block[i + j] != crib[j]:
                match = False
                break
        if match:
            return True
    return False

# --- Kernel Principal de CUDA ---
@cuda.jit
def aes_brute_force_kernel(
    encrypted_block, start_key, chunk_size,
    results_passwords, results_count,
    cribs_array, crib_lengths, num_cribs
):
    thread_id = cuda.grid(1)
    if thread_id >= chunk_size:
        return

    password_candidate = start_key + thread_id

    # --- Expansión de Clave (Lógica corregida y robusta) ---
    round_keys = cuda.local.array((44, 4), dtype=np.uint8)
    
    # Copiar la clave maestra (16 bytes) a las primeras 4 "palabras" de round_keys
    for i in range(16):
        byte = (password_candidate >> (8 * (15 - i))) & 0xFF
        word_index = i // 4
        byte_index = i % 4
        round_keys[word_index, byte_index] = byte

    # Generar las 10 claves de ronda restantes (palabras 4 a 43)
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


    # --- Descifrado ---
    # Copiar el bloque cifrado a la memoria local del hilo
    cipher_state = cuda.local.array((4, 4), dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            cipher_state[j, i] = encrypted_block[j, i]
    
    decrypt_block(cipher_state, round_keys)

    # --- Verificación con Cribs ---
    decrypted_bytes = cuda.local.array(AES_BLOCK_SIZE_BYTES, dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            decrypted_bytes[i * 4 + j] = cipher_state[j, i] # Convertir de column-major a flat array
    
    found_match = False
    for i in range(num_cribs):
        crib = cribs_array[i]
        crib_len = crib_lengths[i]
        if check_crib_match(decrypted_bytes, AES_BLOCK_SIZE_BYTES, crib, crib_len):
            found_match = True
            break
            
    if found_match:
        result_idx = cuda.atomic.add(results_count, 0, 1)
        if result_idx < MAX_RESULTS:
            results_passwords[result_idx] = password_candidate

# --- Lógica de CPU para Verificación ---
# Esta es una versión en CPU del algoritmo para descifrar el texto completo
# y así filtrar los falsos positivos.
def aes_decrypt_cpu(ciphertext, key_int):
    key = key_int.to_bytes(16, byteorder='big')
    
    # Key expansion
    round_keys = np.zeros((44, 4), dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            round_keys[i, j] = key[i * 4 + j]
            
    for i in range(4, 44):
        temp = round_keys[i - 1].copy()
        if i % 4 == 0:
            temp = np.roll(temp, -1)
            temp = np.array([Sbox[b] for b in temp], dtype=np.uint8)
            temp[0] ^= Rcon[i // 4]
        round_keys[i] = round_keys[i-4] ^ temp
    
    # Decryption
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        state = np.array(list(block), dtype=np.uint8).reshape(4, 4).T
        
        # AddRoundKey (last round)
        state ^= round_keys[40:44].T
        # InvShiftRows
        state[1,:] = np.roll(state[1,:], 1)
        state[2,:] = np.roll(state[2,:], 2)
        state[3,:] = np.roll(state[3,:], 3)
        # InvSubBytes
        state = np.vectorize(lambda x: InvSbox[x])(state)

        for r in range(9, 0, -1):
            state ^= round_keys[r*4:(r+1)*4].T
            # InvMixColumns - CPU version
            temp_state = state.copy()
            for c in range(4):
                temp_state[0, c] = gmul_cpu(state[0, c], 0x0e) ^ gmul_cpu(state[1, c], 0x0b) ^ gmul_cpu(state[2, c], 0x0d) ^ gmul_cpu(state[3, c], 0x09)
                temp_state[1, c] = gmul_cpu(state[0, c], 0x09) ^ gmul_cpu(state[1, c], 0x0e) ^ gmul_cpu(state[2, c], 0x0b) ^ gmul_cpu(state[3, c], 0x0d)
                temp_state[2, c] = gmul_cpu(state[0, c], 0x0d) ^ gmul_cpu(state[1, c], 0x09) ^ gmul_cpu(state[2, c], 0x0e) ^ gmul_cpu(state[3, c], 0x0b)
                temp_state[3, c] = gmul_cpu(state[0, c], 0x0b) ^ gmul_cpu(state[1, c], 0x0d) ^ gmul_cpu(state[2, c], 0x09) ^ gmul_cpu(state[3, c], 0x0e)
            state = temp_state
            # InvShiftRows
            state[1,:] = np.roll(state[1,:], 1)
            state[2,:] = np.roll(state[2,:], 2)
            state[3,:] = np.roll(state[3,:], 3)
            # InvSubBytes
            state = np.vectorize(lambda x: InvSbox[x])(state)

        state ^= round_keys[0:4].T
        plaintext.extend(state.T.flatten())
        
    # Eliminar el padding PKCS7 al final
    if len(plaintext) > 0:
        padding_len = plaintext[-1]
        if padding_len > 0 and padding_len <= 16:
            # Verificar que el padding es válido
            is_padding_valid = all(p == padding_len for p in plaintext[-padding_len:])
            if is_padding_valid:
                return bytes(plaintext[:-padding_len])

    return bytes(plaintext)

def gmul_cpu(a, b):
    p = 0
    for _ in range(8):
        if (b & 1) != 0:
            p ^= a
        is_high_bit_set = (a & 0x80) != 0
        a <<= 1
        if is_high_bit_set:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


# --- Proceso de Cracking en Segundo Plano ---
def background_cracker_task(encrypted_data, start_key=1, chunk_size=10000000):
    
    # Manejo de error para padding incorrecto
    if len(encrypted_data) % AES_BLOCK_SIZE_BYTES != 0:
        print(f"Error: El tamaño del texto cifrado ({len(encrypted_data)} bytes) no es un múltiplo de {AES_BLOCK_SIZE_BYTES}. No se puede procesar.")
        with open(RESULTS_FILENAME, "a", encoding="utf-8") as f:
            f.write(f"Error: Datos cifrados inválidos (longitud incorrecta).\n")
        return

    # Preparar datos comunes para la GPU una sola vez
    max_crib_len = max(len(c) for c in CRIBS_BYTES) if CRIBS_BYTES else 0
    num_cribs = len(CRIBS_BYTES)
    h_cribs_array = np.full((num_cribs, max_crib_len), 0, dtype=np.uint8)
    h_crib_lengths = np.zeros(num_cribs, dtype=np.int32)
    for i, c in enumerate(CRIBS_BYTES):
        h_crib_lengths[i] = len(c)
        h_cribs_array[i, :len(c)] = list(c)
    d_cribs_array = cuda.to_device(h_cribs_array)
    d_crib_lengths = cuda.to_device(h_crib_lengths)

    current_key = start_key
    while True: # Bucle infinito para búsqueda continua
        max_key_chunk = current_key + chunk_size
        print(f"GPU: Iniciando búsqueda en el rango de claves: {current_key} a {max_key_chunk - 1}...")

        first_block_bytes = encrypted_data[:AES_BLOCK_SIZE_BYTES]
        h_encrypted_block = np.array(list(first_block_bytes), dtype=np.uint8).reshape(4, 4).T

        h_results_passwords = np.zeros(MAX_RESULTS, dtype=np.uint64)
        h_results_count = np.zeros(1, dtype=np.int32)
        
        d_encrypted_block = cuda.to_device(h_encrypted_block)
        d_results_passwords = cuda.to_device(h_results_passwords)
        d_results_count = cuda.to_device(h_results_count)

        threads_per_block = 256
        blocks_per_grid = math.ceil(chunk_size / threads_per_block)

        aes_brute_force_kernel[blocks_per_grid, threads_per_block](
            d_encrypted_block, current_key, chunk_size,
            d_results_passwords, d_results_count,
            d_cribs_array, d_crib_lengths, num_cribs
        )
        cuda.synchronize()

        count = d_results_count.copy_to_host()[0]
        if count > 0:
            h_results_passwords = d_results_passwords.copy_to_host()
            found_passwords = h_results_passwords[:min(int(count), MAX_RESULTS)]
            
            print(f"GPU: Se encontraron {count} claves potenciales. Verificando en CPU...")

            final_results = []
            for password in found_passwords:
                if password == 0: continue
                try:
                    decrypted_full = aes_decrypt_cpu(encrypted_data, int(password))
                    is_match = any(crib in decrypted_full for crib in CRIBS_BYTES)
                    
                    if is_match:
                        plaintext_preview = decrypted_full.decode('utf-8', errors='ignore').strip()
                        result_str = f"Contraseña: {password} => Texto: '{plaintext_preview[:150]}...'\n"
                        final_results.append(result_str)
                except Exception:
                    continue
            
            if final_results:
                print(f"¡RESULTADO POSITIVO! Guardando {len(final_results)} resultado(s) verificado(s) en '{RESULTS_FILENAME}'")
                with open(RESULTS_FILENAME, "a", encoding="utf-8") as f:
                    f.write(f"--- Resultados de la sesión del {time()} ---\n")
                    for res in final_results:
                        f.write(res)
                    f.write("\n")
                # Opcional: ¿detener la búsqueda después de encontrar un resultado?
                # Por ahora, continúa buscando más posibles claves.
        
        current_key = max_key_chunk


# --- Función de Orquestación (Host) ---
def run_aes_gpu_cracker(encrypted_b64):
    if not cuda.is_available():
        return "Error: No se detecta un entorno CUDA funcional."
    
    try:
        encrypted_data = base64.b64decode(encrypted_b64)
    except Exception:
        return "Error: El texto cifrado no es un Base64 válido."

    if len(encrypted_data) < AES_BLOCK_SIZE_BYTES:
        return f"Error: El texto cifrado debe tener al menos {AES_BLOCK_SIZE_BYTES} bytes."

    # Lanzar el proceso de cracking en un hilo separado
    cracker_thread = Thread(target=background_cracker_task, args=(encrypted_data,))
    cracker_thread.start()

    return f"Ataque AES con GPU iniciado en un bucle continuo. Los resultados se guardarán en '{RESULTS_FILENAME}'."
