// =================================================================================
// VARIABLES GLOBALES E INICIALIZACIÓN
// =================================================================================
let currentFile = null;
let keychain = [];
let googleIdToken = null;
let currentlyEditingName = null;
let masterPassword = null; // Almacenará la contraseña maestra para la sesión
let vaultRestoreFile = null; // Para el archivo de bóveda a restaurar
let onMasterPasswordSuccess = null; // Callback a ejecutar tras introducir la contraseña

const decryptionInstructions = {
    aes_gpu: "Utiliza una derivación de clave en GPU (KDF) para hacer los ataques de fuerza bruta extremadamente lentos. El descifrado manual es inviable y requiere la contraseña original.",
    aes: "El descifrado manual de AES-256 es computacionalmente inviable. Requiere la contraseña original y software especializado para revertir el proceso.",
    fernet: "El descifrado manual de Fernet es inviable. Al ser un cifrado simétrico de alto nivel, requiere la clave original y software para ser descifrado.",
    vigenere: `Para descifrar manualmente:\n1. Alinea la contraseña con el texto cifrado, repitiéndola si es necesario.\n2. Usa el conjunto de caracteres de referencia para encontrar el índice de cada carácter.\n3. Aplica la fórmula: (Índice Cifrado - Índice Clave + 93) % 93 para cada carácter.`,
    vigenere_extended: `Similar al César Avanzado, pero utiliza un conjunto de 256 caracteres, incluyendo símbolos extendidos y caracteres no imprimibles, lo que lo hace más resistente al análisis de frecuencia. El descifrado manual es extremadamente tedioso.`,
    base64: "Base64 no es cifrado. Para decodificar, agrupa los caracteres en bloques de 4, conviértelos a su valor de 6 bits usando la tabla Base64, concatena los bits y reagrupa en bloques de 8 bits para obtener los caracteres originales.",
    caesar: "Para descifrar, simplemente desplaza cada letra del texto cifrado hacia atrás en el alfabeto el número de posiciones indicado en la 'rotación'."
};

// =================================================================================
// LÓGICA DE AUTENTICACIÓN DE GOOGLE (FUNCIONES GLOBALES)
// =================================================================================

// Estas funciones deben ser globales para que el script de Google pueda llamarlas.
function jwtDecode(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (e) {
        console.error("Fallo al decodificar JWT:", e);
        return null;
    }
}

function onSignIn(googleUser) {
    googleIdToken = googleUser.credential;
    const profile = jwtDecode(googleIdToken);
    
    if (profile) {
        document.querySelector('.g_id_signin').style.display = 'none';
        const userInfo = document.getElementById('google-user-info');
        userInfo.style.display = 'flex';
        document.getElementById('google-user-name').textContent = profile.name;
        document.getElementById('google-user-id').textContent = profile.sub; // 'sub' es el ID de usuario único
        document.getElementById('google-user-id-container').style.display = 'block';
        showToast(`Conectado como ${profile.name}`);
    } else {
        showToast(`Error al verificar la identidad.`);
    }
}

function signOut() {
    google.accounts.id.disableAutoSelect();
    googleIdToken = null;
    document.querySelector('.g_id_signin').style.display = 'block';
    const userInfo = document.getElementById('google-user-info');
    userInfo.style.display = 'none';
    document.getElementById('google-user-id-container').style.display = 'none';
    showToast("Sesión cerrada.");
}

// Exponer funciones al objeto window para asegurar accesibilidad global
window.onSignIn = onSignIn;


// =================================================================================
// FUNCIONES GLOBALES
// =================================================================================

function showToast(message) {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.textContent = message;
        toast.className = 'toast show';
        setTimeout(function(){ toast.className = toast.className.replace('show', ''); }, 3000);
    }
}

// =================================================================================
// LÓGICA PRINCIPAL DE LA APLICACIÓN (DENTRO DE DOMCONTENTLOADED)
// =================================================================================
document.addEventListener('DOMContentLoaded', function() {
    
    // --- CACHE DE ELEMENTOS DOM ---
    // (Mueve aquí todos los `document.getElementById` para eficiencia)
    const elements = {
        methodSelect: document.getElementById('method'),
        savePasswordBtn: document.getElementById('save-password-btn'),
        backupKeychainBtn: document.getElementById('backup-keychain-btn'), // Ahora es "Download Vault"
        restoreKeychainBtn: document.getElementById('restore-keychain-btn'), // Ahora es "Upload Vault"
        backupFileInput: document.getElementById('backup-file-input'), // Aceptará .vault
        importKeyBtn: document.getElementById('import-key-btn'),
        importKeyInput: document.getElementById('import-key-input'),
        passwordWrapper: document.querySelector('.password-wrapper'),
        keychainSidebar: document.querySelector('.password-sidebar'),
        counter: document.querySelector('.password-selection-counter'),
        shiftContainer: document.getElementById('shift-container'),
        fernetKeyContainer: document.getElementById('fernet-key-container'),
        warningContainer: document.getElementById('algorithm-warning'),
        instructionsContainer: document.getElementById('decryption-instructions'),
        indicesLink: document.getElementById('indices-link'),
        startHackBtn: document.getElementById('start-hack-btn'),
        emailRecoveryCheckbox: document.getElementById('email-recovery-checkbox'),
        emailInputContainer: document.getElementById('email-input-container'),
        recoverBtn: document.getElementById('recoverBtn'),
        googleSignoutBtn: document.getElementById('google-signout-btn'),
        copyUserIdBtn: document.getElementById('copy-user-id-btn'),
        identityToggle: document.getElementById('identity-toggle-btn'), // Nuevo botón
        identitySection: document.getElementById('identity-section'), // Nuevo contenedor
        sidebar: document.querySelector('.sidebar'),
        sidebarToggle: document.querySelector('.sidebar-toggle'),
        settingsToggleBtn: document.getElementById('settings-toggle-btn'),
        settingsSection: document.getElementById('settings-section'),
        encryptBtn: document.getElementById('encryptBtn'),
        fileInput: document.getElementById('fileInput'),
        importBtn: document.getElementById('importBtn'),
        exportBtn: document.getElementById('exportBtn'),
        decryptBtn: document.getElementById('decryptBtn'),
        copyBtn: document.getElementById('copyBtn'),
        clearBtn: document.getElementById('clearBtn'),
        togglePassword: document.getElementById('togglePassword'),
        generatePasswordBtn: document.getElementById('generate-password-btn'),
        shutdownBtn: document.getElementById('shutdown-btn'),
        masterPasswordModal: document.getElementById('master-password-modal'),
        masterPasswordInput: document.getElementById('master-password-input'),
        confirmMasterPasswordBtn: document.getElementById('confirm-master-password-btn'),
        generateMasterPasswordBtn: document.getElementById('generate-master-password-btn'),
        closeMasterPasswordModalBtn: document.getElementById('close-master-password-modal-btn')
    };
    
    // --- FUNCIONES Y LÓGICA ---
    // (Mueve aquí todas las demás funciones: showToast, fetchKeychain, renderKeychain, etc.)
    
    // --- DOM Element Cache ---
    const passwordInput = document.getElementById('password');
    const strengthBar = document.getElementById('password-strength-bar');

    function checkPasswordStrength(password) {
        let strength = 0;
        if (password.length >= 8) strength++;
        if (password.length >= 12) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;
        return Math.floor((strength / 6) * 100);
    }

    function updateStrengthBar(strength) {
        strengthBar.style.width = strength + '%';
        if (strength < 33) {
            strengthBar.style.backgroundColor = 'red';
        } else if (strength < 66) {
            strengthBar.style.backgroundColor = 'orange';
        } else {
            strengthBar.style.backgroundColor = 'green';
        }
    }

    // --- Keychain & Vault Logic ---

    async function fetchKeychain() {
        if (!masterPassword) {
            // Si no tenemos la contraseña, pedírsela al usuario.
            // El callback se encargará de volver a llamar a fetchKeychain
            return requestMasterPassword(fetchKeychain);
        }

        try {
            const response = await fetch('/api/keychain/open', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ master_password: masterPassword })
            });

            if (response.status === 401) {
                const err = await response.json();
                showToast(`Error: ${err.error}. Inténtalo de nuevo.`);
                masterPassword = null; // Contraseña incorrecta, la borramos
                return requestMasterPassword(fetchKeychain); // Pedir de nuevo
            }
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'No se pudo abrir el llavero');
            }

            const keyList = await response.json();
            
            const currentSelection = keychain.reduce((acc, item) => {
                if (item.selected) acc[item.name] = true;
                return acc;
            }, {});

            // El contenido ya no se carga aquí, solo la lista de nombres.
            keychain = keyList.map(key => ({
                name: key.name,
                type: key.type, // 'file' o 'text'
                content: null, // El contenido se pedirá bajo demanda
                selected: currentSelection[key.name] || false
            }));
            
            renderKeychain();
        } catch (error) {
            console.error("Error fetching keychain:", error);
            showToast(`Error al cargar el llavero: ${error.message}`);
        }
    }

    function updatePasswordCounter() {
        const selectedKeyCount = keychain.filter(item => item.selected).length;
        document.getElementById('password-counter').textContent = selectedKeyCount;
    }

    function renderKeychain() {
        const passwordList = document.getElementById('password-list');
        passwordList.innerHTML = '';

        keychain.forEach(item => {
            const li = document.createElement('li');
            li.className = 'password-list-item';
            li.dataset.name = item.name;
            if (item.selected) {
                li.classList.add('selected');
            }

            // Añadir un icono para diferenciar archivos de texto
            const iconClass = item.type === 'file' ? 'fa-file-alt' : 'fa-font';

            li.innerHTML = `
                <input type="checkbox" class="keychain-checkbox" ${item.selected ? 'checked' : ''}>
                <i class="fas ${iconClass} key-type-icon"></i>
                <span class="password-name">${item.name}</span>
                <div class="password-actions">
                    <button class="edit-btn" title="Editar" ${item.type === 'file' ? 'disabled' : ''}><i class="fas fa-pencil-alt"></i></button>
                    <button class="delete-btn" title="Eliminar"><i class="fas fa-trash"></i></button>
                </div>
            `;
            passwordList.appendChild(li);
        });
        
        attachKeychainListeners();
        updatePasswordCounter();
    }

    function attachKeychainListeners() {
        // Se elimina el listener de click en el nombre para unificar la selección solo a checkboxes.
        document.querySelectorAll('.keychain-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', function() {
                const name = this.closest('.password-list-item').dataset.name;
                const item = keychain.find(p => p.name === name);
                if (item) {
                    item.selected = this.checked;
                }
                updatePasswordCounter();
            });
        });

        document.querySelectorAll('.edit-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                if(this.disabled) return;
                const name = this.closest('.password-list-item').dataset.name;
                openEditModal(name);
            });
        });

        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', async function() {
                const name = this.closest('.password-list-item').dataset.name;
                if (confirm(`¿Estás seguro de que quieres eliminar la clave "${name}"?`)) {
                    if (!masterPassword) return requestMasterPassword(() => this.click());

                    try {
                        const response = await fetch(`/api/keychain/delete`, {
                             method: 'POST',
                             headers: { 'Content-Type': 'application/json' },
                             body: JSON.stringify({ master_password: masterPassword, name: name })
                        });
                        if (!response.ok) {
                            const err = await response.json();
                            throw new Error(err.error || 'Failed to delete key');
                        }
                        fetchKeychain();
                    } catch (error) {
                        console.error("Error deleting key:", error);
                        showToast(`Error al eliminar la clave: ${error.message}`);
                    }
                }
            });
        });
    }

    async function getPasswordsForOperation() {
        let passwords = [];
        // 1. Contraseña del campo de texto principal
        if (passwordInput.value) {
            passwords.push(passwordInput.value);
        }

        // 2. Nombres de las claves seleccionadas en el llavero
        const selectedKeyNames = keychain
            .filter(item => item.selected)
            .map(item => item.name);
        
        // No necesitamos cargar el contenido aquí. El backend lo hará
        // a partir de la lista de nombres que le enviemos.
        return {
            passwords: passwords,
            selected_keys: selectedKeyNames
        };
    }

    // Modal Logic
    const editModal = document.getElementById('edit-password-modal');
    const editModalTitle = document.getElementById('edit-modal-title');
    const editPasswordTextarea = document.getElementById('edit-password-textarea');

    async function openEditModal(name) {
        if (!masterPassword) return requestMasterPassword(() => openEditModal(name));
        
        try {
            const response = await fetch('/api/keychain/get_content', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ master_password: masterPassword, name: name })
            });
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error);
            }
            const item = await response.json();
            
            currentlyEditingName = name;
            editModalTitle.textContent = `Editar: ${name}`;
            editPasswordTextarea.value = item.content; // Asumimos que es de tipo 'text'
            editModal.style.display = 'block';

        } catch (error) {
            showToast(`Error al cargar la clave: ${error.message}`);
        }
    }

    function closeEditModal() {
        editModal.style.display = 'none';
        currentlyEditingName = null;
    }

    async function saveEditedPassword() {
        if (currentlyEditingName) {
            if (!masterPassword) return requestMasterPassword(saveEditedPassword);

            try {
                const response = await fetch('/api/keychain/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        master_password: masterPassword,
                        name: currentlyEditingName,
                        content: editPasswordTextarea.value
                    })
                });
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Failed to save changes');
                }
                
                closeEditModal();
                showToast(`Contraseña "${currentlyEditingName}" actualizada.`);
                fetchKeychain(); // Refresh list
            } catch (error) {
                console.error("Error saving edited password:", error);
                showToast(`Error al guardar los cambios: ${error.message}`);
            }
        }
    }

    document.getElementById('save-edited-password-btn').addEventListener('click', saveEditedPassword);
    document.getElementById('close-edit-modal-btn').addEventListener('click', closeEditModal);
    window.addEventListener('click', function(event) {
        if (event.target == editModal) {
            closeEditModal();
        }
    });

    // --- Master Password Modal Logic ---
    const masterPasswordModal = document.getElementById('master-password-modal');
    const masterPasswordInput = document.getElementById('master-password-input');
    const confirmMasterPasswordBtn = document.getElementById('confirm-master-password-btn');

    function requestMasterPassword(callback) {
        onMasterPasswordSuccess = callback;
        masterPasswordModal.style.display = 'block';
        masterPasswordInput.focus();
    }

    function closeMasterPasswordModal() {
        masterPasswordModal.style.display = 'none';
        masterPasswordInput.value = '';
        onMasterPasswordSuccess = null;
    }

    confirmMasterPasswordBtn.addEventListener('click', async () => {
        const pass = masterPasswordInput.value;
        if (!pass) {
            showToast("Por favor, ingresa una contraseña maestra.");
            return;
        }

        const originalBtnText = confirmMasterPasswordBtn.innerHTML;
        confirmMasterPasswordBtn.disabled = true;
        confirmMasterPasswordBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Desbloqueando...`;
        
        masterPassword = pass;
        
        if (onMasterPasswordSuccess) {
            await onMasterPasswordSuccess();
        }

        // Si la contraseña era incorrecta, fetchKeychain habrá reseteado masterPassword a null.
        if (masterPassword) { 
            closeMasterPasswordModal();
        }

        // Restaurar el botón para el siguiente intento si falla.
        confirmMasterPasswordBtn.disabled = false;
        confirmMasterPasswordBtn.innerHTML = originalBtnText;
    });
    
    document.getElementById('generate-master-password-btn').addEventListener('click', () => {
        masterPasswordInput.value = generateSecurePassword();
    });

    document.getElementById('close-master-password-modal-btn').addEventListener('click', closeMasterPasswordModal);

    // --- Backup/Restore Modal Logic ---
    const backupModal = document.getElementById('backup-password-modal');
    const backupModalTitle = document.getElementById('backup-modal-title');
    const backupModalInstructions = document.getElementById('backup-modal-instructions');
    const backupPasswordInput = document.getElementById('backup-password-input');
    const confirmBackupActionBtn = document.getElementById('confirm-backup-action-btn');

    function openBackupModal(mode, data) {
        backupAction = mode;
        if (mode === 'backup') {
            backupModalTitle.textContent = 'Crear Backup Cifrado';
            backupModalInstructions.textContent = 'Ingresa una contraseña maestra para cifrar las contraseñas seleccionadas. Necesitarás esta misma contraseña para restaurarlas.';
            confirmBackupActionBtn.textContent = 'Cifrar y Descargar';
        } else if (mode === 'restore') {
            backupModalTitle.textContent = 'Restaurar desde Backup';
            backupModalInstructions.textContent = `Ingresa la contraseña maestra para el archivo "${data.name}". Las contraseñas se añadirán a tu llavero.`;
            confirmBackupActionBtn.textContent = 'Descifrar y Restaurar';
            restoreFile = data;
        }
        backupModal.style.display = 'block';
    }

    function closeBackupModal() {
        backupModal.style.display = 'none';
        backupPasswordInput.value = '';
        backupAction = null;
        restoreFile = null;
    }

    document.getElementById('close-backup-modal-btn').addEventListener('click', closeBackupModal);
    window.addEventListener('click', function(event) {
        if (event.target == backupModal) {
            closeBackupModal();
        }
    });

    confirmBackupActionBtn.addEventListener('click', async function() {
        const masterPassword = backupPasswordInput.value;
        if (!masterPassword) {
            alert("Por favor, ingresa una contraseña maestra.");
            return;
        }

        if (backupAction === 'backup') {
            const selectedKeyNames = keychain
                .filter(item => item.selected)
                .map(item => item.name);

            try {
                const response = await fetch('/api/keychain/backup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        key_names: selectedKeyNames,
                        master_password: masterPassword
                    })
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Error en el servidor');
                }
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = 'keychain_backup.bin';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
                
                showToast('Backup creado y descargado.');

            } catch (error) {
                console.error("Backup error:", error);
                showToast(`Error al crear el backup: ${error.message}`);
            }
        } else if (backupAction === 'restore') {
            const formData = new FormData();
            formData.append('backup_file', restoreFile);
            formData.append('master_password', masterPassword);
            
            try {
                const response = await fetch('/api/keychain/restore', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();
                if (!response.ok) {
                    throw new Error(result.error || 'Error desconocido');
                }
                
                showToast(result.message);
                await fetchKeychain();

            } catch (error) {
                console.error("Restore error:", error);
                showToast(`Error al restaurar: ${error.message}`);
            }
        }
        closeBackupModal();
    });


    // --- EVENT LISTENERS ---
    
    elements.methodSelect.addEventListener('change', function() {
        // Hide all optional controls by default
        elements.passwordWrapper.style.display = 'none';
        elements.keychainSidebar.style.display = 'none';
        elements.counter.style.display = 'none';
        elements.shiftContainer.style.display = 'none';
        elements.fernetKeyContainer.style.display = 'none';
        elements.indicesLink.style.display = 'none';
        elements.warningContainer.style.display = 'none';
        elements.warningContainer.textContent = '';
        elements.instructionsContainer.textContent = decryptionInstructions[this.value] || 'Selecciona un algoritmo para ver las instrucciones.';

        // Show controls based on selected method
    switch (this.value) {
            case 'aes_gpu':
        case 'aes':
        case 'vigenere':
            case 'vigenere_extended':
                elements.passwordWrapper.style.display = 'flex';
                elements.keychainSidebar.style.display = 'flex';
                elements.counter.style.display = 'block';
                if (this.value.includes('vigenere')) {
                    elements.indicesLink.style.display = 'block';
                    elements.warningContainer.textContent = 'Advertencia: Vigenère es un cifrado clásico y no es seguro para datos sensibles.';
                    elements.warningContainer.style.display = 'block';
                }
            break;
        case 'caesar':
                elements.shiftContainer.style.display = 'flex';
                elements.warningContainer.textContent = 'Advertencia: El Cifrado César es inseguro y no debe usarse para datos sensibles.';
                elements.warningContainer.style.display = 'block';
            break;
        case 'fernet':
                elements.fernetKeyContainer.style.display = 'flex';
            break;
        case 'base64':
                elements.warningContainer.textContent = 'Nota: Base64 es un método de codificación, no de cifrado. No proporciona seguridad.';
                elements.warningContainer.style.display = 'block';
            break;
    }
});

    passwordInput.addEventListener('input', function() {
        // Se elimina la lógica de activeKeychainItem para no deseleccionar un archivo clave al escribir una contraseña.
        const strength = checkPasswordStrength(passwordInput.value);
        updateStrengthBar(strength);
        // Quitado updatePasswordCounter() de aquí para evitar contar doble.
    });

    elements.savePasswordBtn.addEventListener('click', async function() {
        const passwordValue = passwordInput.value;
        if (!passwordValue) {
            alert("El campo de contraseña está vacío.");
            return;
        }

        let defaultName = "clave-" + (keychain.length + 1) + ".txt";
        let name = prompt("Ingresa un nombre para guardar la contraseña:", defaultName);
        
        if (name) {
            if (!masterPassword) return requestMasterPassword(() => this.click());
            
            if (!/\./.test(name)) {
                name += '.txt';
            }

            try {
                const response = await fetch('/api/keychain/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        master_password: masterPassword,
                        name: name, 
                        content: passwordValue 
                    })
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Failed to save password');
                }
                
                const result = await response.json();
                
                showToast(`Contraseña "${result.name}" guardada.`);
                await fetchKeychain();
                
            } catch (error) {
                console.error("Error saving password:", error);
                showToast(`Error al guardar la contraseña: ${error.message}`);
            }
        }
    });

    elements.backupKeychainBtn.addEventListener('click', function() {
        if (!masterPassword) return requestMasterPassword(() => this.click());
        
        fetch('/api/vault/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ master_password: masterPassword })
        })
        .then(async response => {
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error);
            }
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'keychain.vault';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
            showToast('Bóveda descargada correctamente.');
        })
        .catch(error => {
            showToast(`Error al descargar la bóveda: ${error.message}`);
        });
    });

    elements.restoreKeychainBtn.addEventListener('click', function() {
        elements.backupFileInput.click();
    });
    
    elements.backupFileInput.addEventListener('change', async function(event) {
        const file = event.target.files[0];
        if (!file) return;

        vaultRestoreFile = file;
        
        // Pedir la contraseña de la bóveda que se está subiendo
        requestMasterPassword(async () => {
            const formData = new FormData();
            formData.append('vault_file', vaultRestoreFile);
            formData.append('master_password', masterPassword);

            try {
                const response = await fetch('/api/vault/upload', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error);

                showToast(result.message);
                // La contraseña es correcta, así que podemos recargar el llavero con ella.
                await fetchKeychain(); 
            } catch (error) {
                showToast(`Error al restaurar bóveda: ${error.message}`);
                // La contraseña era incorrecta para el archivo subido, la reseteamos.
                masterPassword = null; 
            } finally {
                vaultRestoreFile = null;
            }
        });
        event.target.value = '';
    });

    elements.importKeyBtn.addEventListener('click', () => {
        elements.importKeyInput.click();
    });

    elements.importKeyInput.addEventListener('change', async function(event) {
        const files = event.target.files;
        if (files.length === 0) return;

        if (!masterPassword) return requestMasterPassword(() => this.dispatchEvent(new Event('change')));

        const uploadPromises = [];
        for (const file of files) {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('master_password', masterPassword);
            
            const promise = fetch('/api/keychain/upload_key', {
                method: 'POST',
                body: formData
            })
            .then(async response => {
                const result = await response.json();
                if (!response.ok) {
                    // Mostrar error específico si el archivo ya existe
                    if (response.status === 409) {
                        return { success: false, message: `El archivo "${file.name}" ya existe.` };
                    }
                    throw new Error(result.error || `Error al subir ${file.name}`);
                }
                return { success: true, message: `"${file.name}" subido.` };
            })
            .catch(error => ({ success: false, message: error.message }));
            
            uploadPromises.push(promise);
        }

        const results = await Promise.all(uploadPromises);
        
        const successCount = results.filter(r => r.success).length;
        const errorMessages = results.filter(r => !r.success).map(r => r.message);

        if (successCount > 0) {
            showToast(`${successCount} archivo(s) de clave importado(s) correctamente.`);
            await fetchKeychain(); // Recargar el llavero
        }
        if (errorMessages.length > 0) {
            alert("Ocurrieron errores:\n- " + errorMessages.join('\n- '));
        }

        // Limpiar el input para permitir la re-selección del mismo archivo
        event.target.value = '';
    });

    if (elements.emailRecoveryCheckbox) {
        elements.emailRecoveryCheckbox.addEventListener('change', function() {
            elements.emailInputContainer.style.display = this.checked ? 'block' : 'none';
        });
    }

    elements.recoverBtn.addEventListener('click', function() {
        if (!googleIdToken) {
            showToast("Debes iniciar sesión con Google para usar la recuperación.");
            return;
        }

        let headers = {};
        let body;
        const text = document.getElementById('inputText').value;

        if (!text) {
            alert("Por favor, ingresa el texto cifrado que deseas recuperar.");
            return;
        }

        let payload = { id_token: googleIdToken, text: text };
        if (googleIdToken) {
            payload.id_token = googleIdToken;
        }
        const recipientId = document.getElementById('recipient-id-input').value;
        if (recipientId) {
            payload.recipient_id = recipientId;
        }
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(payload);

        fetch('/decrypt_with_recovery', {
            method: 'POST',
            headers: headers,
            body: body
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { throw new Error(err.error || 'Error en la recuperación'); });
            }
            return response.json();
        })
        .then(data => {
            if (data.decrypted) {
                document.getElementById('outputText').value = data.decrypted;
                showToast('Texto recuperado con éxito.');
            } else {
                throw new Error('La respuesta del servidor no contiene datos descifrados.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('outputText').value = `Error en la recuperación: ${error.message}`;
        });
    });

    if (elements.encryptBtn) {
        elements.encryptBtn.addEventListener('click', async function() {
    const method = document.getElementById('method').value;
    let headers = {};
    let body;
            const recipientId = document.getElementById('recipient-id-input').value;
            const operationPasswords = await getPasswordsForOperation();

    if (currentFile) {
        const formData = new FormData();
        formData.append('method', method);
        formData.append('file', currentFile);
                if (method === 'aes' || method === 'vigenere' || method === 'aes_gpu' || method === 'vigenere_extended') {
                    if (operationPasswords.selected_keys.length > 0 && !masterPassword) {
                        return requestMasterPassword(() => this.click());
                    }
                    formData.append('passwords', JSON.stringify(operationPasswords.passwords));
                    formData.append('selected_keys', JSON.stringify(operationPasswords.selected_keys));
                    if (masterPassword) formData.append('master_password', masterPassword);
                }
                if (googleIdToken) {
                    formData.append('id_token', googleIdToken);
        }
        body = formData;
    } else {
        const text = document.getElementById('inputText').value;
        if (!text) { alert("Por favor, ingresa texto."); return; }

        let payload = { method: method, text: text };
        
                if (method === 'aes' || method === 'vigenere' || method === 'aes_gpu' || method === 'vigenere_extended') {
                    if (operationPasswords.selected_keys.length > 0 && !masterPassword) {
                        return requestMasterPassword(() => this.click());
                    }
                    payload.passwords = operationPasswords.passwords;
                    payload.selected_keys = operationPasswords.selected_keys;
                    if (masterPassword) payload.master_password = masterPassword;
        } else if (method === 'fernet') {
            payload.key = document.getElementById('fernet-key').value || '';
        } else if (method === 'caesar') {
            payload.shift = document.getElementById('shift').value;
            payload.rounds = document.getElementById('rounds').value;
        }

                if (googleIdToken) {
                    payload.id_token = googleIdToken;
                }
                if (recipientId) {
                    payload.recipient_id = recipientId;
                }
        
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(payload);
    }

    fetch('/encrypt', {
        method: 'POST',
        headers: headers,
        body: body
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error || 'Error en el servidor') });
        }
                const disposition = response.headers.get('content-disposition');
                if (disposition && disposition.indexOf('attachment') !== -1) {
                    let filename = "download";
                    const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                    let matches = filenameRegex.exec(disposition);
                    if (matches != null && matches[1]) { 
                      filename = matches[1].replace(/['"]/g, '');
                    }
                    return response.blob().then(blob => ({blob, filename}));
        }
        return response.json();
    })
    .then(data => {
        if (data.blob) {
            const url = window.URL.createObjectURL(data.blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
                    a.download = data.filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            showToast('Archivo cifrado y descargado.');
        } else {
                    document.getElementById('outputText').value = data.encrypted;
        }
    })
    .catch(error => {
                document.getElementById('outputText').value = `Error: ${error.message}`;
            });
        });
    }

    // --- Generate Password Modal Logic ---
    const generatePasswordBtn = document.getElementById('generate-password-btn');
    const passwordModal = document.getElementById('password-modal');
    const closeModalBtns = document.querySelectorAll('.close-btn'); // Handles multiple modals
    const generatedPasswordField = document.getElementById('generated-password');
    const copyGeneratedPasswordBtn = document.getElementById('copy-generated-password-btn');
    const regeneratePasswordBtn = document.getElementById('regenerate-password-btn');

    function generateSecurePassword(length = 24) {
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        let password = "";
        for (let i = 0, n = charset.length; i < length; ++i) {
            password += charset.charAt(Math.floor(Math.random() * n));
        }
        return password;
    }

    function showPasswordModal() {
        if (generatedPasswordField && passwordModal) {
        generatedPasswordField.value = generateSecurePassword();
        passwordModal.style.display = "block";
        }
    }

    function hidePasswordModal() {
        if (passwordModal) {
        passwordModal.style.display = "none";
        }
    }

    if (generatePasswordBtn) {
    generatePasswordBtn.addEventListener('click', showPasswordModal);
    }
    
    closeModalBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            this.closest('.modal').style.display = 'none';
        });
    });

    if (regeneratePasswordBtn) {
    regeneratePasswordBtn.addEventListener('click', function() {
        generatedPasswordField.value = generateSecurePassword();
    });
    }

    if (copyGeneratedPasswordBtn) {
    copyGeneratedPasswordBtn.addEventListener('click', function() {
        generatedPasswordField.select();
        document.execCommand('copy');
        showToast('Contraseña copiada');
    });
    }

    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    });

    // --- Generate Password Logic for Backup Modal ---
    const generateBackupPasswordBtn = document.getElementById('generate-backup-password-btn');
    if (generateBackupPasswordBtn) {
        generateBackupPasswordBtn.addEventListener('click', function() {
            const newPassword = generateSecurePassword();
            const backupPasswordInput = document.getElementById('backup-password-input');
            if (backupPasswordInput) {
                backupPasswordInput.value = newPassword;
                showToast('Nueva contraseña generada en el campo.');
            }
        });
    }

    // --- Shutdown Logic ---
    if (elements.shutdownBtn) {
        elements.shutdownBtn.addEventListener('click', function() {
            if (confirm("¿Estás seguro de que quieres cerrar la aplicación?")) {
                // Enviamos la petición de apagado, pero no esperamos una respuesta,
                // ya que el servidor se cerrará antes de poder enviarla.
                fetch('/shutdown', { method: 'POST' }).catch(error => {
                    // Es normal que fetch falle aquí. Simplemente lo ignoramos.
                    console.log("Petición de apagado enviada. Se espera un error de red al cerrarse el servidor.");
                });

                // Mostramos inmediatamente el mensaje de cierre y cerramos la ventana.
                document.body.innerHTML = "<h1>Cerrando la aplicación... Puedes cerrar esta pestaña.</h1>";
                setTimeout(() => window.close(), 2000);
            }
        });
    }

    // --- Google Sign-In Logic ---
    // SE ELIMINA LA INICIALIZACIÓN MANUAL DE GOOGLE DESDE AQUÍ
    // El HTML se encargará de ello con los atributos data-
    
    // --- Recovery Key Modal Logic ---
    const recoveryModal = document.getElementById('recovery-key-modal');
    const recoveryKeyOutput = document.getElementById('recovery-key-output');
    const sendEmailBtn = document.getElementById('send-recovery-email-btn');

    function openRecoveryKeyModal(recoveryKey) {
        recoveryKeyOutput.value = recoveryKey;
        recoveryModal.style.display = 'block';
    }

    document.getElementById('copy-recovery-key-btn').addEventListener('click', function() {
        recoveryKeyOutput.select();
        document.execCommand('copy');
        showToast('Clave de recuperación copiada');
    });

    sendEmailBtn.addEventListener('click', function(e) {
        e.preventDefault();
        const email = document.getElementById('recovery-email-input').value;
        const recoveryKey = recoveryKeyOutput.value;
        if (!email) {
            alert("Por favor, ingresa una dirección de correo para enviar la clave.");
            return;
        }
        const subject = "Clave de Recuperación para Archivo Cifrado";
        const body = `Guarda esta clave en un lugar seguro. La necesitarás para descifrar tu archivo si olvidas la contraseña original.\n\nClave:\n${recoveryKey}`;
        window.location.href = `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    });

    if (elements.googleSignoutBtn) {
        elements.googleSignoutBtn.addEventListener('click', signOut);
    }

    if (elements.copyUserIdBtn) {
        elements.copyUserIdBtn.addEventListener('click', function() {
            const userId = document.getElementById('google-user-id').textContent;
            navigator.clipboard.writeText(userId).then(() => {
                showToast('ID de Usuario copiado al portapapeles.');
            });
        });
    }

    // --- Sidebar Panel Logic ---
    const settingsToggleBtn = document.getElementById('settings-toggle-btn');
    const identityToggleBtn = document.getElementById('identity-toggle-btn');
    const settingsSection = document.getElementById('settings-section');
    const identitySection = document.getElementById('identity-section');

    const sidebarPanels = [settingsSection, identitySection];
    const sidebarToggles = [settingsToggleBtn, identityToggleBtn];

    function closeAllPanels() {
        sidebarPanels.forEach(panel => {
            if(panel) panel.classList.remove('visible');
        });
        sidebarToggles.forEach(toggle => {
            if(toggle) toggle.classList.remove('active');
        });
    }

    function setupSidebarToggle(toggleBtn, panel) {
        if (toggleBtn && panel) {
            toggleBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                const isVisible = panel.classList.contains('visible');
                closeAllPanels();
                if (!isVisible) {
                    panel.classList.add('visible');
                    toggleBtn.classList.add('active');
                    
                    // Si estamos mostrando el panel de identidad y el botón de Google aún no se ha renderizado,
                    // lo renderizamos explícitamente ahora.
                    if (panel.id === 'identity-section' && document.querySelector('.g_id_signin div') === null) {
                        try {
                            google.accounts.id.renderButton(
                                document.querySelector(".g_id_signin"),
                                { theme: "outline", size: "large", text: "sign_in_with", shape: "rectangular", logo_alignment: "left" }
                            );
                        } catch (error) {
                            console.error("Error rendering Google Sign-In button:", error);
                        }
                    }
                }
            });
        }
    }

    setupSidebarToggle(settingsToggleBtn, settingsSection);
    setupSidebarToggle(identityToggleBtn, identitySection);

    // Close panels if clicking outside of them or their toggles
    document.addEventListener('click', (e) => {
        // Check if the click is outside the entire sidebar area
        if (!e.target.closest('.sidebar-panel') && !e.target.closest('.sidebar-toggle')) {
            closeAllPanels();
        }
    });

    // Initially hide all panels
    closeAllPanels();

    // --- File Input Logic ---
    if (elements.fileInput) {
        elements.fileInput.addEventListener('change', function(event) {
            const file = event.target.files[0];
            if (file) {
                currentFile = file;
                showToast(`Archivo "${file.name}" cargado.`);
            }
        });
    }

    // --- Import/Export Logic ---
    if (elements.importBtn) {
        elements.importBtn.addEventListener('click', () => elements.fileInput.click());
    }

    if (elements.exportBtn) {
        elements.exportBtn.addEventListener('click', function() {
            const textToExport = document.getElementById('outputText').value;
            const blob = new Blob([textToExport], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'keychain_backup.txt'; // Or a more descriptive name
            document.body.appendChild(a);
            a.click();
            URL.revokeObjectURL(url);
            a.remove();
            showToast('Contraseñas exportadas.');
        });
    }

    // --- Decrypt Logic ---
    if (elements.decryptBtn) {
        elements.decryptBtn.addEventListener('click', async function() {
            const method = document.getElementById('method').value;
            let headers = {};
            let body;
            const recipientId = document.getElementById('recipient-id-input').value;
            const operationPasswords = await getPasswordsForOperation();

            if (currentFile) {
                const formData = new FormData();
                formData.append('method', method);
                formData.append('file', currentFile);
                if (method === 'aes' || method === 'vigenere' || method === 'aes_gpu' || method === 'vigenere_extended') {
                    if (operationPasswords.selected_keys.length > 0 && !masterPassword) {
                        return requestMasterPassword(() => this.click());
                    }
                    formData.append('passwords', JSON.stringify(operationPasswords.passwords));
                    formData.append('selected_keys', JSON.stringify(operationPasswords.selected_keys));
                    if (masterPassword) formData.append('master_password', masterPassword);
                }
                if (googleIdToken) {
                    formData.append('id_token', googleIdToken);
        }
        body = formData;
    } else {
        const text = document.getElementById('inputText').value;
        if (!text) { alert("Por favor, ingresa texto."); return; }

        let payload = { method: method, text: text };
        
                if (method === 'aes' || method === 'vigenere' || method === 'aes_gpu' || method === 'vigenere_extended') {
                    if (operationPasswords.selected_keys.length > 0 && !masterPassword) {
                        return requestMasterPassword(() => this.click());
                    }
                    payload.passwords = operationPasswords.passwords;
                    payload.selected_keys = operationPasswords.selected_keys;
                    if (masterPassword) payload.master_password = masterPassword;
                } else if (method === 'fernet') {
                    payload.key = document.getElementById('fernet-key').value || '';
                } else if (method === 'caesar') {
                    payload.shift = document.getElementById('shift').value;
                    payload.rounds = document.getElementById('rounds').value;
                }

                if (googleIdToken) {
                    payload.id_token = googleIdToken;
                }
                if (recipientId) {
                    payload.recipient_id = recipientId;
                }
                
                headers['Content-Type'] = 'application/json';
                body = JSON.stringify(payload);
            }

            try {
                const response = await fetch('/decrypt', {
                    method: 'POST',
                    headers: headers,
                    body: body
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Error desconocido');
                }
                const data = await response.json();
                if (data.decrypted) {
                    document.getElementById('outputText').value = data.decrypted;
                    showToast('Texto descifrado con éxito.');
                } else {
                    throw new Error('La respuesta del servidor no contiene datos descifrados.');
                }
            } catch (error) {
                console.error('Error al descifrar:', error);
                document.getElementById('outputText').value = `Error al descifrar: ${error.message}`;
            }
        });
    }

    // --- Copy/Clear Logic ---
    if (elements.copyBtn) {
        elements.copyBtn.addEventListener('click', function() {
            const textToCopy = document.getElementById('outputText').value;
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    showToast('Texto copiado al portapapeles.');
                }).catch(err => {
                    console.error('Error al copiar texto:', err);
                    showToast('Error al copiar texto.');
                });
            } else {
                showToast('No hay texto para copiar.');
            }
        });
    }

    if (elements.clearBtn) {
        elements.clearBtn.addEventListener('click', function() {
            document.getElementById('inputText').value = '';
            document.getElementById('outputText').value = '';
            document.getElementById('password').value = '';
            document.getElementById('password-strength-bar').style.width = '0%';
            document.getElementById('password-counter').textContent = '0';
            keychain.forEach(item => item.selected = false);
            renderKeychain();
            showToast('Contenido limpiado.');
        });
    }

    // --- Toggle Password Visibility ---
    function setupPasswordToggle(toggleElementId, inputElementId) {
        const toggle = document.getElementById(toggleElementId);
        const input = document.getElementById(inputElementId);

        if (toggle && input) {
            const eyeOpen = toggle.querySelector('.fa-eye');
            const eyeClosed = toggle.querySelector('.fa-eye-slash');

            toggle.addEventListener('click', function() {
                if (input.type === 'password') {
                    input.type = 'text';
                    if (eyeOpen) eyeOpen.style.display = 'none';
                    if (eyeClosed) eyeClosed.style.display = 'block';
                } else {
                    input.type = 'password';
                    if (eyeOpen) eyeOpen.style.display = 'block';
                    if (eyeClosed) eyeClosed.style.display = 'none';
                }
            });
        }
    }
    setupPasswordToggle('togglePassword', 'password');
    setupPasswordToggle('toggleBackupPassword', 'backup-password-input');
    setupPasswordToggle('toggle-master-password', 'master-password-input');


    // --- Initial Load ---
    fetchKeychain();
    if(elements.methodSelect) {
        elements.methodSelect.dispatchEvent(new Event('change'));
    }
});
