from flask import Flask, render_template, request, jsonify
import webbrowser
from threading import Timer
import os
import signal
import json
import re
import importlib.util
import sys
import logging
import traceback
import io
from flask import send_file
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryption import (
    encrypt_aes, decrypt_aes, decrypt_aes_with_recovery,
    encrypt_base64, decrypt_base64,
    encrypt_fernet, decrypt_fernet,
    encrypt_caesar, decrypt_caesar,
    encrypt_vigenere, decrypt_vigenere
)
from password_generator import generate_from_cribs
import base64
from werkzeug.utils import secure_filename
import logging
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

try:
    # Cambiado para importar los nombres de función correctos
    from gpu_cryption import encrypt_aes as encrypt_aes_gpu, decrypt_aes as decrypt_aes_gpu, decrypt_aes_with_recovery
    GPU_ENABLED = True
except ImportError as e:
    print(f"ADVERTENCIA: No se pudo importar 'gpu_cryption'. Las funciones de GPU estarán desactivadas. Error: {e}")
    GPU_ENABLED = False

logging.basicConfig(level=logging.INFO)

# Configuración
UPLOAD_FOLDER = 'uploads'
VAULT_FILE = 'keychain.vault' # Bóveda segura para el llavero
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'xlsx', 'pptx', 'mp4', 'mp3', 'zip', 'rar'}
GOOGLE_CLIENT_ID = "879785792270-u3fneofgm8351ods5e17ed0fi57tknpk.apps.googleusercontent.com"

app = Flask(__name__)
# Configurar una carpeta para subidas temporales y scripts personalizados
UPLOAD_FOLDER = 'uploads'
CUSTOM_CRACKERS_FOLDER = 'custom_crackers'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CUSTOM_CRACKERS_FOLDER, exist_ok=True)


# --- Lógica de la Bóveda Segura ---

def load_vault(master_password):
    """
    Carga y descifra el archivo de la bóveda.
    Devuelve un diccionario con los datos del llavero.
    Lanza ValueError si la contraseña es incorrecta o el archivo está corrupto.
    """
    if not os.path.exists(VAULT_FILE):
        return {}  # Si no hay bóveda, devuelve un llavero vacío

    with open(VAULT_FILE, 'rb') as f:
        vault_data = f.read()

    if not vault_data:
        return {} # Devuelve un llavero vacío si el archivo está vacío

    try:
        salt = vault_data[:16]
        nonce = vault_data[16:28]
        ciphertext = vault_data[28:]

        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(master_password.encode('utf-8'))

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # El llavero es un diccionario donde las claves son los nombres de los elementos
        keychain = json.loads(plaintext.decode('utf-8'))
        return keychain
    except Exception as e:
        logging.error(f"Fallo al cargar la bóveda: {e}")
        raise ValueError("Contraseña maestra incorrecta o archivo de bóveda corrupto.")

def save_vault(keychain_data, master_password):
    """Cifra y guarda los datos del llavero en el archivo de la bóveda."""
    plaintext = json.dumps(keychain_data).encode('utf-8')
    
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(master_password.encode('utf-8'))
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    with open(VAULT_FILE, 'wb') as f:
        f.write(salt + nonce + ciphertext)

# --- Endpoints de la API Refactorizados para la Bóveda ---

@app.route('/api/keychain/open', methods=['POST'])
def open_keychain():
    """Abre la bóveda y devuelve la lista de nombres de claves."""
    try:
        data = request.json
        master_password = data.get('master_password')
        if not master_password:
            return jsonify({'error': 'Se requiere la contraseña maestra'}), 400

        keychain = load_vault(master_password)
        
        # Devuelve solo nombres y tipos, no el contenido, por seguridad y rendimiento
        key_list = [{'name': name, 'type': details.get('type', 'text')} for name, details in keychain.items()]
        
        return jsonify(sorted(key_list, key=lambda x: x['name']))
    except ValueError as e:
        return jsonify({'error': str(e)}), 401  # No autorizado
    except Exception as e:
        logging.error(f"Error al abrir el llavero: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Fallo al abrir la bóveda del llavero'}), 500

@app.route('/api/keychain/add', methods=['POST'])
def save_key_to_vault():
    """Guarda una nueva clave de texto o actualiza una existente en la bóveda."""
    try:
        data = request.json
        master_password = data.get('master_password')
        name = data.get('name')
        content = data.get('content')

        if not all([master_password, name, content is not None]):
            return jsonify({'error': 'Se requieren contraseña maestra, nombre y contenido'}), 400
        if '..' in name or '/' in name or '\\' in name:
            return jsonify({'error': 'Nombre de archivo inválido'}), 400

        keychain = load_vault(master_password)
        
        keychain[name] = {'type': 'text', 'content': content}
        
        save_vault(keychain, master_password)
        
        return jsonify({'message': f'Clave "{name}" guardada correctamente.', 'name': name}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logging.error(f"Error al guardar la clave en la bóveda: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Fallo al guardar la clave en la bóveda'}), 500

@app.route('/api/keychain/upload_key', methods=['POST'])
def upload_key_to_vault():
    """Sube un archivo como clave y lo guarda en la bóveda."""
    try:
        master_password = request.form.get('master_password')
        if not master_password:
            return jsonify({'error': 'Se requiere la contraseña maestra'}), 400
        if 'file' not in request.files:
            return jsonify({'error': 'No se encontró el archivo en la petición'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
        
        filename = secure_filename(file.filename)
        file_content_bytes = file.read()
        content_b64 = base64.b64encode(file_content_bytes).decode('utf-8')

        keychain = load_vault(master_password)
        
        if filename in keychain:
            # Permitir sobreescritura si el usuario lo confirma (lógica del frontend)
            # Por ahora, simplemente sobreescribimos.
            pass

        keychain[filename] = {'type': 'file', 'content_b64': content_b64}
        
        save_vault(keychain, master_password)
        
        return jsonify({'message': f'Archivo clave "{filename}" subido correctamente.', 'name': filename}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logging.error(f"Error al subir archivo clave a la bóveda: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Fallo al subir el archivo clave a la bóveda'}), 500

@app.route('/api/keychain/delete', methods=['POST'])
def delete_key_from_vault():
    """Elimina una clave de la bóveda."""
    try:
        data = request.json
        master_password = data.get('master_password')
        name = data.get('name')

        if not all([master_password, name]):
            return jsonify({'error': 'Se requieren contraseña maestra y nombre de la clave'}), 400

        keychain = load_vault(master_password)
        
        if name in keychain:
            del keychain[name]
            save_vault(keychain, master_password)
            return jsonify({'message': f'Clave "{name}" eliminada correctamente.'})
        else:
            return jsonify({'error': 'Clave no encontrada en la bóveda'}), 404
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logging.error(f"Error al eliminar clave de la bóveda: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Fallo al eliminar la clave de la bóveda'}), 500

@app.route('/api/vault/download', methods=['POST'])
def download_vault():
    """Permite al usuario descargar el archivo de la bóveda cifrada."""
    try:
        master_password = request.json.get('master_password')
        if not master_password:
            return jsonify({'error': 'Se requiere la contraseña maestra para verificar antes de descargar.'}), 400
            
        load_vault(master_password)  # Verifica la contraseña
        
        if not os.path.exists(VAULT_FILE):
             return jsonify({'error': 'El archivo de la bóveda no se ha creado aún.'}), 404
        
        return send_file(
            VAULT_FILE,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='keychain.vault'
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logging.error(f"Error en la descarga de la bóveda: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Fallo al descargar la bóveda'}), 500

@app.route('/api/vault/upload', methods=['POST'])
def upload_vault():
    """Permite al usuario restaurar una bóveda desde un archivo."""
    temp_vault_path = "temp_vault_upload.vault"
    try:
        master_password = request.form.get('master_password')
        if not master_password:
            return jsonify({'error': 'Se requiere la contraseña maestra para verificar la bóveda subida.'}), 400
        if 'vault_file' not in request.files:
            return jsonify({'error': 'No se proporcionó el archivo de la bóveda'}), 400
        
        file = request.files['vault_file']
        file.save(temp_vault_path)

        # Usar una función auxiliar para probar la bóveda temporalmente
        _test_load_vault(temp_vault_path, master_password)
        
        # Si la verificación es exitosa, sobreescribir la bóveda original
        os.replace(temp_vault_path, VAULT_FILE)

        return jsonify({'message': 'Bóveda restaurada correctamente.'})
    except ValueError as e:
        return jsonify({'error': f'Contraseña maestra incorrecta para la bóveda subida o archivo corrupto. La restauración ha sido cancelada.'}), 401
    except Exception as e:
        logging.error(f"Error en la restauración de la bóveda: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Fallo al restaurar la bóveda'}), 500
    finally:
        if os.path.exists(temp_vault_path):
            os.remove(temp_vault_path)

def _test_load_vault(path, master_password):
    """Función auxiliar para cargar una bóveda desde una ruta específica para verificación."""
    with open(path, 'rb') as f:
        vault_data = f.read()
    salt = vault_data[:16]
    nonce = vault_data[16:28]
    ciphertext = vault_data[28:]
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(master_password.encode('utf-8'))
    aesgcm = AESGCM(key)
    aesgcm.decrypt(nonce, ciphertext, None) # Solo para verificar, no necesitamos el resultado

@app.route('/api/keychain/get_content', methods=['POST'])
def get_key_content():
    """Obtiene el contenido de una clave específica de la bóveda."""
    try:
        data = request.json
        master_password = data.get('master_password')
        name = data.get('name')

        if not all([master_password, name]):
            return jsonify({'error': 'Se requieren contraseña maestra y nombre de la clave'}), 400

        keychain = load_vault(master_password)
        
        if name in keychain:
            return jsonify(keychain[name])
        else:
            return jsonify({'error': 'Clave no encontrada en la bóveda'}), 404
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        logging.error(f"Error al obtener contenido de la clave: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Fallo al obtener el contenido de la clave'}), 500


VIGENERE_CHARSET = (
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    '!@#$%^&*()_+-=[]{}|;:,.<>/?`~'
)

EXTENDED_CHARSET = "".join([chr(i) for i in range(256)])

def vigenere_cipher_extended(text, key, mode='encrypt'):
    result = []
    key_len = len(key)
    charset_len = len(EXTENDED_CHARSET)
    char_to_index = {char: i for i, char in enumerate(EXTENDED_CHARSET)}

    for i, char in enumerate(text):
        if char in char_to_index:
            text_index = char_to_index[char]
            key_char = key[i % key_len]

            if key_char not in char_to_index:
                key_index = 0 # Default to no shift if key char is not in charset
            else:
                key_index = char_to_index[key_char]

            if mode == 'encrypt':
                new_index = (text_index + key_index) % charset_len
            else:  # decrypt
                new_index = (text_index - key_index + charset_len) % charset_len
            
            result.append(EXTENDED_CHARSET[new_index])
        else:
            # Si un caracter no está en el set, se añade sin cambios (podría ajustarse)
            result.append(char)

    return "".join(result)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/add_cribs', methods=['POST'])
def add_cribs():
    data = request.json
    text = data.get('text', '')
    cribs_file = 'cribs.json'
    min_word_length = 4  # Establecer una longitud mínima para los cribs

    # Extraer palabras del texto.
    words = set(re.findall(r'\b[a-zA-ZáéíóúÁÉÍÓÚñÑ]+\b', text.lower()))

    # Filtrar palabras demasiado cortas para evitar falsos positivos
    filtered_words = {
        word for word in words if len(word) >= min_word_length
    }

    # Cargar cribs existentes
    try:
        with open(cribs_file, 'r', encoding='utf-8') as f:
            existing_cribs = set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        existing_cribs = set()

    # Añadir solo palabras nuevas que cumplan el filtro
    new_words_added = filtered_words - existing_cribs
    if not new_words_added:
        return jsonify({
            'message': 'No se añadieron palabras (ya existían o eran muy cortas).'
        })

    updated_cribs = existing_cribs.union(new_words_added)

    # Guardar la lista actualizada
    try:
        with open(cribs_file, 'w', encoding='utf-8') as f:
            # Guardar como lista ordenada
            json.dump(sorted(list(updated_cribs)), f, ensure_ascii=False, indent=4)
    except IOError:
        return jsonify({'error': 'No se pudo escribir en el archivo de cribs.'}), 500

    message = f'Éxito: Se añadieron {len(new_words_added)} palabra(s) nueva(s) al diccionario.'
    return jsonify({'message': message})


def _get_passwords_from_vault(data, keychain):
    """
    Extrae las contraseñas seleccionadas desde los datos de la petición y el llavero ya descifrado.
    """
    selected_key_names = data.get('selected_keys', [])
    passwords_from_input = data.get('passwords', [])

    # Filtrar valores nulos que puedan venir del frontend
    passwords = [p for p in passwords_from_input if p is not None]

    for name in selected_key_names:
        if name in keychain:
            item = keychain[name]
            if item.get('type') == 'file':
                # Para archivos, usamos el contenido b64 directamente, el backend de cifrado lo espera así.
                passwords.append(item.get('content_b64', ''))
            else: # 'text'
                passwords.append(item.get('content', ''))
    
    return passwords


def _get_passwords(data):
    """
    Obtiene las contraseñas de la petición, ya sea desde la entrada directa o desde la bóveda.
    Lanza ValueError si la contraseña maestra es incorrecta.
    """
    master_password = data.get('master_password')
    
    if master_password:
        keychain = load_vault(master_password)  # Puede lanzar ValueError
        return _get_passwords_from_vault(data, keychain)
    
    # Si no, solo se usan las contraseñas del input
    passwords_data = data.get('passwords', '[]')
    
    # Para subidas de archivos, las contraseñas pueden ser un string JSON en un campo de formulario
    if isinstance(passwords_data, str):
        try:
            passwords = json.loads(passwords_data)
        except json.JSONDecodeError:
            passwords = []  # Por defecto, lista vacía si hay error de parsing
    else:
        passwords = passwords_data if passwords_data is not None else []
            
    return [p for p in passwords if p is not None]


@app.route('/encrypt', methods=['POST'])
def encrypt():
    google_user_id = None
    try:
        # 1. Obtener datos de la petición y contenido a cifrar
        is_file_upload = 'file' in request.files
        
        if is_file_upload:
            file = request.files['file']
            filename = secure_filename(file.filename)
            if not filename:
                return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
            if filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
                return jsonify({'error': 'Tipo de archivo no permitido'}), 400
            content = file.read().decode('utf-8')
            data = request.form
        else:  # Carga JSON
            data = request.get_json()
            content = data.get('text')
            filename = None

        method = data.get('method')
        if not content or not method:
            return jsonify({'error': 'Se requiere texto/archivo y método'}), 400

        # 2. Autenticar usuario
        token = data.get('id_token')
        if token:
            try:
                idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
                google_user_id = idinfo['sub']
                logging.info(f"Token de Google verificado. ID de usuario: {google_user_id}")
            except ValueError as e:
                logging.error(f"Error al verificar el token de Google: {e}")
                return jsonify({"error": "Token de Google inválido"}), 401

        # 3. Obtener contraseñas
        try:
            passwords = _get_passwords(data)
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        
        # 4. Despachar al manejador de cifrado
        recipient_id = data.get('recipient_id')
        email_recovery = data.get('email_recovery') == 'true'
        
        encrypted_result = None

        if method == 'aes_gpu':
            if not GPU_ENABLED:
                return jsonify({'error': 'La encriptación por GPU no está disponible en el servidor.'}), 500
            master_password = "".join(passwords)
            if not master_password:
                return jsonify({"error": "Se requiere al menos una contraseña o archivo clave para AES-GPU"}), 400
            encrypted_json = encrypt_aes_gpu(content, master_password, google_user_id, recipient_id)
            encrypted_result = base64.b64encode(encrypted_json.encode('utf-8')).decode('utf-8')
        
        elif method == 'aes':
            master_password = "".join(passwords)
            encrypted_result = encrypt_aes(content, master_password, email_recovery)
            
        elif method == 'base64':
            encrypted_result = encrypt_base64(content)
            
        elif method == 'fernet':
            key = passwords[0] if passwords else None
            if not key:
                return jsonify({"error": "La clave es requerida para Fernet"}), 400
            encrypted_result = encrypt_fernet(content, key)
            
        elif method in ['vigenere', 'vigenere_extended']:
            processed_text = content
            cipher_func = encrypt_vigenere if method == 'vigenere' else lambda txt, pwd: {'text': vigenere_cipher_extended(txt, pwd, mode='encrypt')}
            for pwd in passwords:
                res = cipher_func(processed_text, pwd)
                if 'error' in res: return jsonify(res), 400
                processed_text = res.get('text', '')
            encrypted_result = {'text': processed_text}

        elif method == 'caesar':
            shift = int(passwords[0]) if passwords else 13
            rounds = int(passwords[1]) if len(passwords) > 1 else 1
            encrypted_result = encrypt_caesar(content, shift, rounds)
            
        else:
            return jsonify({'error': 'Método de cifrado inválido.'}), 400

        # 5. Devolver la respuesta
        if is_file_upload:
            output_filename = f"{filename}.enc"
            # Para AES-GPU, el resultado ya es un JSON en un string b64, no necesitamos `json.dumps`
            # Para otros métodos, el resultado es un dict que necesita ser dumpeado a JSON.
            # Estandarizamos para que todos devuelvan un objeto serializable.
            payload = json.dumps(encrypted_result).encode('utf-8')
            
            return send_file(
                io.BytesIO(payload),
                as_attachment=True,
                download_name=output_filename,
                mimetype='application/json'
            )
        else:
            return jsonify({"encrypted": encrypted_result})

    except Exception as e:
        logging.error(f"Error en /encrypt: {e}", exc_info=True)
        return jsonify({"error": "Ocurrió un error interno en el servidor."}), 500


@app.route('/decrypt_with_recovery', methods=['POST'])
def decrypt_with_recovery():
    google_user_id = None
    try:
        # 1. Validar el token de Google
        token = request.form.get('id_token') or request.json.get('id_token')
        if not token:
            return jsonify({"error": "Falta el token de Google"}), 400
            
        try:
            idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
            google_user_id = idinfo['sub']
        except ValueError as e:
            logging.error(f"Error al verificar el token de Google en recuperación: {e}")
            return jsonify({"error": "Token de Google inválido"}), 401

        # 2. Obtener los datos cifrados
        if 'file' in request.files:
            file = request.files['file']
            encrypted_b64 = file.read().decode('utf-8')
            try:
                encrypted_data_json = base64.b64decode(encrypted_b64).decode('utf-8')
            except (ValueError, TypeError):
                return jsonify({"error": "El archivo de recuperación no contiene un Base64 válido."}), 400

            decrypted_content = decrypt_aes_with_recovery(encrypted_data_json, google_user_id)
            
            output_filename = file.filename.rsplit('.enc', 1)[0] if file.filename.endswith('.enc') else f"{file.filename}.dec"
            return send_file(
                io.BytesIO(decrypted_content.encode('utf-8')),
                as_attachment=True,
                download_name=output_filename,
                mimetype='application/octet-stream'
            )
        else:
            data = request.json
            encrypted_b64 = data.get('text')
            try:
                encrypted_json = base64.b64decode(encrypted_b64).decode('utf-8')
            except (ValueError, TypeError):
                return jsonify({"error": "El texto cifrado para recuperación no es un Base64 válido."}), 400
            
            decrypted_text = decrypt_aes_with_recovery(encrypted_json, google_user_id)
            return jsonify({"decrypted": decrypted_text})

    except Exception as e:
        logging.error(f"Error en /decrypt_with_recovery: {e}", exc_info=True)
        return jsonify({"error": "Ocurrió un error durante la recuperación."}), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # 1. Obtener datos de la petición y contenido cifrado
        if 'file' in request.files:
            file = request.files['file']
            encrypted_content_str = file.read().decode('utf-8')
            params = request.form
        else:  # Carga JSON
            params = request.json
            encrypted_content_str = params.get('text', '')

        method = params.get('method')
        if not method:
            return jsonify({'error': 'Se requiere el método de descifrado.'}), 400

        # 2. Obtener contraseñas
        try:
            passwords = _get_passwords(params)
        except ValueError as e:  # Contraseña maestra incorrecta
            return jsonify({'error': str(e)}), 401
        
        # 3. Descifrar basándose en el método
        result = {}

        try:
            if method == 'aes':
                master_password = "".join(passwords)
                if not master_password: return jsonify({'error': 'Se requiere contraseña.'}), 400
                encrypted_data = json.loads(encrypted_content_str)
                result = decrypt_aes(encrypted_data, master_password)

            elif method == 'aes_gpu':
                if not GPU_ENABLED: return jsonify({'error': 'El descifrado por GPU no está disponible.'}), 500
                master_password = "".join(passwords)
                if not master_password: return jsonify({'error': 'Se requiere contraseña.'}), 400
                
                try:
                    encrypted_json = base64.b64decode(encrypted_content_str).decode('utf-8')
                except (ValueError, TypeError):
                    return jsonify({"error": "Contenido Base64 inválido para AES-GPU."}), 400
                
                result = {'decrypted': decrypt_aes_gpu(encrypted_json, master_password)}

            elif method == 'base64':
                result = decrypt_base64(encrypted_content_str)

            elif method == 'fernet':
                if not passwords: return jsonify({'error': 'Se requiere clave para Fernet.'}), 400
                key = passwords[0]
                encrypted_data = json.loads(encrypted_content_str)
                result = decrypt_fernet(encrypted_data.get('text'), key)

            elif method in ['vigenere', 'vigenere_extended']:
                if not passwords: return jsonify({'error': 'Se requiere contraseña.'}), 400
                encrypted_data = json.loads(encrypted_content_str)
                processed_text = encrypted_data.get('text', '')
                
                cipher_func = decrypt_vigenere if method == 'vigenere' else lambda txt, pwd: {'text': vigenere_cipher_extended(txt, pwd, mode='decrypt')}

                for pwd in reversed(passwords):
                    res = cipher_func(processed_text, pwd)
                    if 'error' in res: return jsonify(res), 400
                    processed_text = res.get('text', '')
                result = {'decrypted': processed_text}

            elif method == 'caesar':
                encrypted_data = json.loads(encrypted_content_str)
                shift = int(encrypted_data.get('shift', 13))
                rounds = int(encrypted_data.get('rounds', 1))
                result = decrypt_caesar(encrypted_data.get('text'), shift, rounds)
            
            else:
                return jsonify({'error': 'Método de descifrado inválido.'}), 400

        except json.JSONDecodeError:
            return jsonify({'error': 'El contenido cifrado no es un objeto JSON válido para este método.'}), 400
        except Exception as e:
            logging.error(f"Fallo en la lógica de descifrado para el método {method}: {e}", exc_info=True)
            return jsonify({'error': f'Fallo al descifrar: {e}'}), 500

        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)

    except Exception as e:
        logging.error(f"Error en /decrypt: {e}", exc_info=True)
        return jsonify({"error": "Ocurrió un error interno en el servidor."}), 500


def open_browser():
    webbrowser.open_new('http://127.0.0.1:5000/')


@app.route('/shutdown', methods=['POST'])
def shutdown():
    # Esta función se usa para detener el servidor Flask.
    # Es especialmente útil en un entorno compilado donde no hay una terminal visible.
    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        # Si no se encuentra la función de apagado de Werkzeug (por ejemplo, en producción),
        # se recurre a una salida forzada.
        logging.info("Forzando la salida del servidor...")
        os._exit(0)
    else:
        shutdown_func()
    return "Servidor apagándose..."


if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        Timer(1, open_browser).start()
    app.run(debug=True, port=5000)
