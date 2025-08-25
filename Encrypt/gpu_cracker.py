import numpy as np
from numba import cuda
import math
import json

# El mismo charset que se usa para cifrar
VIGENERE_CHARSET = (
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    '!@#$%^&*()_+-=[]{}|;:,.<>/?`~'
)
CHARSET_SIZE = len(VIGENERE_CHARSET)

# Constantes para el tamaño de la memoria local en la GPU.
# Deben ser valores fijos conocidos en tiempo de compilación.
MAX_PW_LEN_CONST = 6 
DECRYPT_CHUNK_SIZE = 32
# Limitar el número de cribs para no sobrecargar la memoria de la GPU
MAX_CRIBS_FOR_GPU = 1000
# Límite de resultados a almacenar desde la GPU
MAX_RESULTS = 100
# Tamaño de los lotes para el ataque de diccionario para evitar TDR
WORDLIST_CHUNK_SIZE = 50000


# Un "crib" es un texto que sospechamos que está en el mensaje original.
# Ayuda a identificar una desencriptación correcta.
# Se carga desde JSON, con una lista de respaldo si el archivo no existe.
try:
    with open('cribs.json', 'r', encoding='utf-8') as f:
        # Tomamos solo los primeros MAX_CRIBS_FOR_GPU para la GPU
        CRIBS = json.load(f)[:MAX_CRIBS_FOR_GPU]
except (FileNotFoundError, json.JSONDecodeError):
    CRIBS = [
        "porque", "cuando", "entonces", "siempre", "cifrado",
        "mensaje", "secreto", "informacion", "confidencial"
    ]

# --- Filtro de Calidad de Cribs en Tiempo de Ejecución ---
# Se eliminan las palabras cortas para reducir drásticamente los falsos positivos.

# Esta es una función auxiliar que se ejecuta EN la GPU
@cuda.jit(device=True)
def check_crib_match(decrypted_chunk, chunk_len, crib, crib_len):
    """
    Comprueba si un 'crib' (array de índices) existe en el fragmento
    descifrado.
    """
    for i in range(chunk_len - crib_len + 1):
        match = True
        for j in range(crib_len):
            if decrypted_chunk[i + j] != crib[j]:
                match = False
                break
        if match:
            return True
    return False


@cuda.jit
def vigenere_brute_force_kernel(
    encrypted_indices, max_len,
    results_passwords, results_password_lengths, results_crib_indices,
    results_count,
    cribs_array, crib_lengths,
    password_list_mode,
    password_list,
    password_lengths,
    num_passwords_in_list
):
    """
    Kernel de CUDA que prueba una contraseña única por cada hilo.
    """
    thread_id = cuda.grid(1)

    # Declarar arrays locales y variables al principio para ambos modos
    password_indices = cuda.local.array(MAX_PW_LEN_CONST, dtype=np.int32)
    current_len = 0

    # Si el ataque es de fuerza bruta, generar contraseña desde el ID del hilo
    if password_list_mode == 0:
        # --- Generar la contraseña para este hilo ---
        start_index_for_len = 0
        for length in range(1, max_len + 1):
            num_passwords_for_len = CHARSET_SIZE ** length
            if thread_id < start_index_for_len + num_passwords_for_len:
                current_len = length
                break
            start_index_for_len += num_passwords_for_len
        
        if current_len == 0:
            return  # Este hilo está fuera del rango de contraseñas a probar

        temp_id = thread_id - start_index_for_len
        for i in range(current_len - 1, -1, -1):
            password_indices[i] = temp_id % CHARSET_SIZE
            temp_id //= CHARSET_SIZE

    # Si el ataque es de lista de palabras, tomar la contraseña de la lista
    else:
        if thread_id >= num_passwords_in_list:
            return

        current_len = password_lengths[thread_id]
        # Copiar la contraseña del array global al array local
        for i in range(current_len):
            password_indices[i] = password_list[thread_id, i]


    # --- Probar la contraseña generada ---
    # Solo probamos un fragmento
    decrypted_chunk = cuda.local.array(DECRYPT_CHUNK_SIZE, dtype=np.int32)
    chunk_len = min(len(encrypted_indices), DECRYPT_CHUNK_SIZE)

    for i in range(chunk_len):
        key_char_index = password_indices[i % current_len]
        decrypted_val = (
            encrypted_indices[i] - key_char_index + CHARSET_SIZE
        ) % CHARSET_SIZE
        decrypted_chunk[i] = decrypted_val

    # --- Comprobar si el texto descifrado contiene un "crib" ---
    # Se comprueba cada "crib" manualmente porque Numba no puede iterar
    # sobre una tupla de tuplas en modo CUDA con un índice dinámico.
    found_match = False
    match_crib_idx = -1
    for i in range(len(crib_lengths)):
        crib = cribs_array[i]
        crib_len = crib_lengths[i]
        if check_crib_match(decrypted_chunk, chunk_len, crib, crib_len):
            found_match = True
            match_crib_idx = i
            break  # Solo necesitamos el primer crib que coincida
    
    if found_match:
        # Obtener un espacio en el array de resultados de forma atómica
        result_idx = cuda.atomic.add(results_count, 0, 1)

        # Asegurarse de no escribir fuera de los límites del array
        if result_idx < MAX_RESULTS:
            # Guardar la contraseña, su longitud y el índice del crib
            for k in range(current_len):
                results_passwords[result_idx, k] = password_indices[k]
            results_password_lengths[result_idx] = current_len
            results_crib_indices[result_idx] = match_crib_idx


def run_gpu_cracker(encrypted_text, max_len=4, attack_mode='bruteforce', wordlist_file='wordlist.json'):
    """
    Función principal para configurar y lanzar el cracker de GPU.
    Soporta dos modos: 'bruteforce' y 'wordlist'.
    """
    # --- Comprobar disponibilidad de la GPU ---
    if not cuda.is_available():
        return ("Error: Numba no detecta un entorno CUDA funcional. "
                "Asegúrate de que los drivers de NVIDIA y el CUDA Toolkit "
                "están instalados y configurados correctamente.")

    if not cuda.list_devices():
        return "Error: No se ha encontrado ninguna GPU compatible con CUDA."

    # --- Preparar y Filtrar Cribs para la GPU ---
    if not CRIBS:
        return "Error: No se encontraron 'cribs' para verificar la contraseña."

    max_crib_len = 0
    # --- Filtro de Calidad Dinámico ---
    # Para textos cortos, reducimos la exigencia para encontrar coincidencias.
    # Para textos largos, la mantenemos alta para evitar falsos positivos.
    if len(encrypted_text) < 15:
        min_crib_len_for_gpu = 4
    else:
        min_crib_len_for_gpu = 5

    cribs_for_gpu_indices = []
    # Es necesario mantener una lista separada de las palabras originales que pasan el filtro.
    cribs_for_gpu_original_words = []

    for crib_text in CRIBS:
        # Convertir a índices, eliminando caracteres que no están en el charset.
        indices = [VIGENERE_CHARSET.find(c) for c in crib_text.strip() if c in VIGENERE_CHARSET]
        
        # Aplicar el filtro de longitud sobre los índices reales que irán a la GPU.
        if len(indices) >= min_crib_len_for_gpu:
            cribs_for_gpu_indices.append(indices)
            cribs_for_gpu_original_words.append(crib_text)
            if len(indices) > max_crib_len:
                max_crib_len = len(indices)
    
    if not cribs_for_gpu_indices:
        return (f"Error: Ninguna palabra del diccionario cumple el requisito de "
                f"calidad (>={min_crib_len_for_gpu} caracteres válidos).")

    # Crear arrays 2D para Numba. Rellenar con -1 (valor inválido).
    num_cribs = len(cribs_for_gpu_indices)
    cribs_array = np.full((num_cribs, max_crib_len), -1, dtype=np.int32)
    crib_lengths = np.zeros(num_cribs, dtype=np.int32)

    for i, indices in enumerate(cribs_for_gpu_indices):
        crib_lengths[i] = len(indices)
        cribs_array[i, :len(indices)] = indices
    
    # Convertir texto a índices numéricos (movido a un scope común)
    encrypted_indices = np.array(
        [VIGENERE_CHARSET.find(c) for c in encrypted_text
         if c in VIGENERE_CHARSET],
        dtype=np.int32
    )
    
    if len(encrypted_indices) == 0:
        return "Error: El texto cifrado no contiene caracteres válidos."

    # Mover datos a la GPU (movido a un scope común)
    d_encrypted_indices = cuda.to_device(encrypted_indices)
    d_cribs_array = cuda.to_device(cribs_array)
    d_crib_lengths = cuda.to_device(crib_lengths)

    # --- Configuración del modo de ataque y ejecución ---
    threads_per_block = 256

    # Preparar buffers de resultados en la GPU (una sola vez)
    h_results_passwords = np.full((MAX_RESULTS, MAX_PW_LEN_CONST), -1, dtype=np.int32)
    h_results_password_lengths = np.zeros(MAX_RESULTS, dtype=np.int32)
    h_results_crib_indices = np.full(MAX_RESULTS, -1, dtype=np.int32)
    h_results_count = np.zeros(1, dtype=np.int32)

    d_results_passwords = cuda.to_device(h_results_passwords)
    d_results_password_lengths = cuda.to_device(h_results_password_lengths)
    d_results_crib_indices = cuda.to_device(h_results_crib_indices)
    d_results_count = cuda.to_device(h_results_count)

    if attack_mode == 'wordlist':
        password_list_mode = 1
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                wordlist = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return f"Error: No se pudo cargar el archivo '{wordlist_file}'."

        if not wordlist:
            return "Error: La lista de palabras está vacía."

        num_total_passwords = len(wordlist)
        max_pw_len_in_list = len(max(wordlist, key=len, default=""))

        # Convertir toda la wordlist a un array de NumPy en el host
        passwords_array = np.full((num_total_passwords, max_pw_len_in_list), -1, dtype=np.int32)
        password_lengths_array = np.zeros(num_total_passwords, dtype=np.int32)

        for i, password in enumerate(wordlist):
            password_lengths_array[i] = len(password)
            indices = [VIGENERE_CHARSET.find(c) for c in password if c in VIGENERE_CHARSET]
            passwords_array[i, :len(indices)] = indices
        
        # Procesar la wordlist en lotes
        print(f"Iniciando ataque de diccionario con {num_total_passwords} contraseñas...")
        for i in range(0, num_total_passwords, WORDLIST_CHUNK_SIZE):
            chunk_end = min(i + WORDLIST_CHUNK_SIZE, num_total_passwords)
            
            passwords_chunk = passwords_array[i:chunk_end]
            password_lengths_chunk = password_lengths_array[i:chunk_end]
            
            d_password_list_chunk = cuda.to_device(passwords_chunk)
            d_password_lengths_chunk = cuda.to_device(password_lengths_chunk)
            
            current_chunk_size = len(passwords_chunk)
            blocks_per_grid = math.ceil(current_chunk_size / threads_per_block)
            
            print(f"Procesando lote {i//WORDLIST_CHUNK_SIZE + 1} ({current_chunk_size} contraseñas)...")

            vigenere_brute_force_kernel[blocks_per_grid, threads_per_block](
                d_encrypted_indices, max_len,
                d_results_passwords, d_results_password_lengths, d_results_crib_indices, d_results_count,
                d_cribs_array, d_crib_lengths,
                password_list_mode, d_password_list_chunk, d_password_lengths_chunk, current_chunk_size
            )
            cuda.synchronize()

            count = d_results_count.copy_to_host()[0]
            if count >= MAX_RESULTS:
                print("Límite de resultados alcanzado. Deteniendo la búsqueda.")
                break

    else:  # Modo 'bruteforce'
        password_list_mode = 0
        total_passwords_to_check = sum([CHARSET_SIZE ** i for i in range(1, max_len + 1)])
        blocks_per_grid = math.ceil(total_passwords_to_check / threads_per_block)

        # Para fuerza bruta, los arrays de lista de palabras están vacíos pero deben existir
        d_password_list_empty = cuda.to_device(np.array([[]], dtype=np.int32))
        d_password_lengths_empty = cuda.to_device(np.array([], dtype=np.int32))

        print(f"Iniciando ataque de fuerza bruta (longitud máx: {max_len})...")
        vigenere_brute_force_kernel[blocks_per_grid, threads_per_block](
                d_encrypted_indices, max_len,
                d_results_passwords, d_results_password_lengths, d_results_crib_indices, d_results_count,
                d_cribs_array, d_crib_lengths,
                password_list_mode, d_password_list_empty, d_password_lengths_empty, 0
            )

    cuda.synchronize()

    # --- Procesar y mostrar los resultados ---
    h_results_count = d_results_count.copy_to_host()
    count = h_results_count[0]

    if count == 0:
        return (f"No se encontró ninguna contraseña (límite de longitud: "
                f"{max_len} caracteres).")

    h_results_passwords = d_results_passwords.copy_to_host()
    h_results_password_lengths = d_results_password_lengths.copy_to_host()
    h_results_crib_indices = d_results_crib_indices.copy_to_host()

    found_results = []
    num_to_report = min(int(count), MAX_RESULTS)

    for i in range(num_to_report):
        pw_len = h_results_password_lengths[i]
        pw_indices = h_results_passwords[i, :pw_len]
        password = "".join([VIGENERE_CHARSET[idx] for idx in pw_indices])
        
        crib_idx = h_results_crib_indices[i]
        # Usar la lista filtrada de palabras para obtener el crib correcto.
        crib_word = cribs_for_gpu_original_words[crib_idx]

        found_results.append(
            f"¡Contraseña encontrada!: {password} => (contiene: '{crib_word}')"
        )

    if count > MAX_RESULTS:
        found_results.append(
            f"\n... y al menos {count - MAX_RESULTS} resultado(s) más "
            f"(límite de visualización: {MAX_RESULTS})."
        )

    return "\n".join(found_results)
