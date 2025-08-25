import json
import itertools

# --- Reglas de Mutación ---

# Prefijos y Sufijos comunes
COMMON_PREFIXES = ['123']
COMMON_SUFFIXES = ['123', '1', '2', '3', '2023', '2024', '2025', '!', '@', '#', '$']

# Mapeo de sustituciones "Leet Speak" comunes
LEET_MAP = {
    'a': ['4', '@'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7']
}


def apply_capitalization(word):
    """Genera variaciones de mayúsculas para una palabra."""
    if not word:
        return set()
    return {word.lower(), word.capitalize(), word.upper()}


def apply_prefixes(word):
    """Añade prefijos comunes a una palabra."""
    return {prefix + word for prefix in COMMON_PREFIXES}


def apply_suffixes(word):
    """Añade sufijos comunes a una palabra."""
    return {word + suffix for suffix in COMMON_SUFFIXES}


def apply_leetspeak(word):
    """
    Genera todas las combinaciones posibles de Leet Speak para una palabra.
    Esto puede ser computacionalmente caro para palabras largas.
    """
    word = word.lower()
    # Generar una lista de posibles caracteres para cada posición
    char_possibilities = []
    for char in word:
        # Añadir el caracter original más sus posibles sustituciones
        char_possibilities.append([char] + LEET_MAP.get(char, []))

    # Crear todas las combinaciones posibles
    leet_combinations = set()
    for combo in itertools.product(*char_possibilities):
        leet_combinations.add("".join(combo))

    return leet_combinations


def generate_candidates(base_words, max_per_word=100):
    """
    Genera una lista de contraseñas candidatas a partir de una lista de palabras base.
    """
    final_candidates = set()

    # Añadir contraseñas puramente numéricas y comunes
    common_numeric = {'123', '1234', '12345', '123456', '111', '222', '0000'}
    final_candidates.update(common_numeric)

    for word in base_words:
        if len(word) > 12:  # Evitar explosión combinatoria en palabras largas
            continue

        word_candidates = set()

        # 1. Variaciones de capitalización (incluye la palabra original)
        capitalized_variations = apply_capitalization(word)
        word_candidates.update(capitalized_variations)

        # 2. Añadir prefijos y sufijos a cada variación de capitalización
        for cap_var in capitalized_variations:
            word_candidates.update(apply_prefixes(cap_var))
            word_candidates.update(apply_suffixes(cap_var))

        # 3. Aplicar Leetspeak (solo a la versión en minúsculas para simplicidad)
        leet_variations = apply_leetspeak(word)
        word_candidates.update(leet_variations)

        # 4. Añadir sufijos a las variaciones de leetspeak más comunes
        # (para no generar una lista excesivamente grande)
        if '4' in word or '3' in word or '0' in word: # Heurística simple
             for leet_var in leet_variations:
                 if len(word_candidates) < max_per_word * 5:
                    word_candidates.update(apply_suffixes(leet_var))

        final_candidates.update(word_candidates)

    return sorted(list(final_candidates))


def generate_from_cribs(cribs_file='cribs.json', output_file='wordlist.json'):
    """
    Función principal para leer un archivo de cribs y generar una wordlist.
    """
    try:
        with open(cribs_file, 'r', encoding='utf-8') as f:
            base_words = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Error: No se pudo leer el archivo '{cribs_file}'.")
        return False, 0

    # Filtrar palabras para que sean aptas como base de contraseñas
    # (por ejemplo, longitud razonable)
    base_words = [
        word for word in base_words if 4 <= len(word) <= 10
    ]

    print(f"Generando contraseñas candidatas desde {len(base_words)} palabras base...")
    candidates = generate_candidates(base_words)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(candidates, f, ensure_ascii=False, indent=4)
        print(f"Éxito: Se generaron {len(candidates)} candidatas y se guardaron en '{output_file}'.")
        return True, len(candidates)
    except IOError:
        print(f"Error: No se pudo escribir en el archivo '{output_file}'.")
        return False, 0


if __name__ == '__main__':
    # Esto permite ejecutar el script directamente para probarlo
    generate_from_cribs()
