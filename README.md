# Cifrador Web

## ¿Por qué Cifrador Web?

A diferencia de otras herramientas de cifrado, Cifrador Web destaca por:

*   **Seguridad y Privacidad Total:** Al ser una aplicación que se ejecuta 100% en tu máquina, tus datos y contraseñas nunca salen de tu control. No dependes de servicios en la nube que pueden ser vulnerables.
*   **Potencia y Flexibilidad:** Más allá del cifrado estándar, este proyecto integra módulos avanzados para la generación de contraseñas seguras y herramientas de análisis de seguridad.
*   **Alto Rendimiento:** Incorpora la capacidad de utilizar la potencia de tu tarjeta gráfica (GPU) para acelerar operaciones criptográficas, ofreciendo una velocidad muy superior a las alternativas que solo usan la CPU.
*   **Recuperación Segura (Gestionada por el Usuario):** La aplicación puede generar claves de recuperación y facilita que te las envíes a tu propio correo con un solo clic, sin que el servidor gestione nunca tus emails ni tus claves. Tú tienes el control.

Una sencilla aplicación web para cifrar y descifrar texto utilizando varios algoritmos. La interfaz es fácil de usar y se ejecuta localmente en tu navegador.

## Funcionalidades

*   **Cifrado AES-256:** Cifra y descifra texto utilizando el robusto algoritmo AES en modo CBC. La clave se deriva de una contraseña proporcionada por el usuario usando PBKDF2 con un alto número de iteraciones para mayor seguridad.
*   **Recuperación mediante Google ID y Claves Locales:** Permite cifrar archivos vinculados a tu identidad de Google, permitiendo una recuperación segura desde cualquier dispositivo donde inicies sesión. Además, genera claves de recuperación que puedes guardar o enviarte por correo para descifrar información si olvidas la contraseña original.
*   **Codificación Base64:** Codifica y decodifica texto en formato Base64.
*   **Cifrado César:** Implementa el clásico cifrado César con desplazamiento y número de rondas configurables.
*   **Interfaz Web Local:** La aplicación se ejecuta como un servidor web local y abre automáticamente una pestaña en tu navegador para un uso inmediato.
*   **Compilable:** Incluye un script para compilar la aplicación en un ejecutable para Windows.

## Instalación y Uso

Para utilizar la aplicación desde el código fuente, sigue estos pasos:

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/disruptorh/Encrypt.git
    cd Encrypt
    ```

2.  **Instala las dependencias:**
    Asegúrate de tener Python 3 instalado. Luego, instala las dependencias necesarias:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Ejecuta la aplicación:**
    ```bash
    python app.py
    ```
    Se abrirá automáticamente una pestaña en tu navegador web en `http://127.0.0.1:5000/`.

4.  **Uso de la interfaz:**
    *   Selecciona el método de cifrado que deseas utilizar.
    *   Introduce el texto y los parámetros necesarios (contraseña, desplazamiento, etc.).
    *   Haz clic en "Cifrar" o "Descifrar" para obtener el resultado.
    *   Para cerrar la aplicación, puedes cerrar la ventana de la terminal o usar el botón "Apagar Servidor" en la interfaz.

## Compilación desde el código fuente (Opcional)

Si deseas compilar la aplicación en un ejecutable para Windows, sigue estos pasos:

1.  Asegúrate de haber instalado las dependencias como se describe en la sección anterior.
2.  Ejecuta el script de compilación:
    ```bash
    build.bat
    ```
3.  Los archivos compilados se encontrarán en la carpeta `dist`.

## Tecnologías Utilizadas

*   **Python**: Lenguaje principal de la aplicación.
*   **Flask**: Framework web para la interfaz de usuario.
*   **PyCryptodome**: Librería para las operaciones de cifrado AES.
*   **Nuitka**: Herramienta para compilar el script de Python a un ejecutable.
