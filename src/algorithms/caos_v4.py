#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CAOS v4.0 - Versión mejorada con AES-GCM y derivación de clave mediante PBKDF2.

Características principales:
- Cifrado autenticado con AES en modo GCM (128 bits, 256 bits, etc. según la clave).
- Derivación de clave con PBKDF2-HMAC-SHA256 para mayor resistencia a ataques de fuerza bruta.
- Uso de sal aleatoria para cada mensaje, evitando la reutilización de claves derivadas.
- Integridad garantizada (al descifrar, la etiqueta GCM verifica no alteración del ciphertext).
- Padding automático gestionado por el propio modo AEAD (no se requiere manualmente).
- Métodos auxiliares para encriptar y desencriptar archivos.
- Código simplificado y mantenible, con mejor balance entre seguridad y rendimiento.

Requisitos:
    pip install cryptography
"""

import os
import time
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class CaosEncryption:
    """
    CAOS v4.0 - Cifrado con AES-GCM y PBKDF2 para una seguridad mejorada.
    """

    def __init__(
        self,
        password: str,
        iterations: int = 100_000,
        key_size: int = 32
    ):
        """
        Inicializa la clase con la contraseña y parámetros de derivación de clave.

        Args:
            password (str): Contraseña o passphrase para derivar la clave.
            iterations (int): Número de iteraciones PBKDF2 (ajustar según requisitos de seguridad).
            key_size (int): Tamaño de la clave en bytes (32 = 256 bits, 16 = 128 bits, etc.).
        """
        self.password = password.encode("utf-8") if isinstance(password, str) else password
        self.iterations = iterations
        self.key_size = key_size
        self.backend = default_backend()

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Genera la clave a partir de la contraseña y una sal usando PBKDF2-HMAC-SHA256.

        Args:
            salt (bytes): Sal aleatoria de al menos 16 bytes.

        Returns:
            bytes: Clave derivada de longitud `self.key_size`.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encripta los datos usando AES-GCM con clave derivada por PBKDF2.

        Formato de salida:
        - 16 bytes de sal
        - 12 bytes de nonce (IV)
        - ciphertext + 16 bytes del tag GCM

        Args:
            data (bytes): Datos a encriptar.

        Returns:
            bytes: Mensaje cifrado con la estructura: salt || nonce || ciphertext+tag
        """
        # Generar sal aleatoria (recomendada de 16 bytes o más).
        salt = os.urandom(16)

        # Derivar la clave usando la sal.
        key = self._derive_key(salt)

        # Crear instancia de AES-GCM. Nonce (IV) de 12 bytes recomendado.
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)

        # Cifrar con AES-GCM. El tag se adjunta al final del ciphertext.
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Retornar salt + nonce + ciphertext (incluye el tag GCM)
        return salt + nonce + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Desencripta el contenido generado por el método `encrypt`.

        Args:
            encrypted_data (bytes): Estructura con salt || nonce || ciphertext+tag

        Returns:
            bytes: Datos en texto plano (descifrados y autenticados).
        """
        # Proporcionar un mensaje de error más detallado si los datos son demasiado cortos
        min_length = 16 + 12 + 16  # salt + nonce + tag mínimo
        if len(encrypted_data) < min_length:
            error_msg = f"Datos encriptados demasiado cortos: {len(encrypted_data)} bytes. Se requieren al menos {min_length} bytes."
            print(f"Error de descifrado: {error_msg}")
            print(f"Primeros bytes (hex): {encrypted_data[:20].hex() if len(encrypted_data) >= 20 else encrypted_data.hex()}")
            raise ValueError(error_msg)

        try:
            # Extraer sal y nonce
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]  # Resto incluye ciphertext + tag

            # Derivar la misma clave
            key = self._derive_key(salt)

            # Instanciar AES-GCM con la clave derivada
            aesgcm = AESGCM(key)

            # Desencriptar y verificar la integridad automáticamente
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                # Verificar que el texto plano sea procesable
                if len(plaintext) == 0:
                    print("Advertencia: El mensaje descifrado está vacío")
                else:
                    print(f"Descifrado exitoso. Longitud: {len(plaintext)} bytes")
                    if len(plaintext) < 100:
                        print(f"Contenido descifrado: {plaintext}")
                return plaintext
            except Exception as e:
                print(f"Error en la desencriptación AES-GCM: {str(e)}")
                print(f"Longitud del ciphertext: {len(ciphertext)} bytes")
                if "verification" in str(e).lower() or "mac" in str(e).lower():
                    raise ValueError(f"Falló la verificación de integridad. La contraseña es incorrecta o el mensaje ha sido alterado.") from e
                else:
                    raise ValueError(f"Error al descifrar: {str(e)}") from e
        except Exception as e:
            if not isinstance(e, ValueError) or "Falló la verificación" not in str(e):
                print(f"Error general al descifrar: {str(e)}")
                raise ValueError(f"Error al procesar los datos cifrados: {str(e)}") from e
            raise

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Lee un archivo y guarda su versión encriptada.

        Args:
            input_path (str): Ruta del archivo original.
            output_path (str): Ruta donde se escribirá el archivo cifrado.
        """
        with open(input_path, "rb") as infile:
            data = infile.read()

        encrypted_data = self.encrypt(data)

        with open(output_path, "wb") as outfile:
            outfile.write(encrypted_data)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Desencripta un archivo previamente encriptado con este mismo método.

        Args:
            input_path (str): Ruta del archivo cifrado.
            output_path (str): Ruta donde se escribirá el archivo desencriptado.
        """
        with open(input_path, "rb") as infile:
            encrypted_data = infile.read()

        decrypted_data = self.decrypt(encrypted_data)

        with open(output_path, "wb") as outfile:
            outfile.write(decrypted_data)


def demo():
    """
    Demostración del uso de CAOS v4.0 con AES-GCM y derivación PBKDF2.
    """
    print("=" * 80)
    print(" DEMOSTRACIÓN DE CAOS v4.0 - ALGORITMO DE CIFRADO AUTENTICADO (AES-GCM + PBKDF2)")
    print(" (Cryptographic Algorithm using AES-GCM Optimized for Security and Speed)")
    print("=" * 80)
    
    # Mensaje de prueba
    mensaje = "Este es un mensaje de prueba para CAOS v4.0 con AES-GCM y PBKDF2."
    password = "clave_secreta_2025"

    print(f"Mensaje original ({len(mensaje)} bytes):")
    print(f"'{mensaje}'")
    print(f"Contraseña: '{password}'")

    # Crear instancia (con 100.000 iteraciones, ajustable según requisitos)
    cipher = CaosEncryption(password=password, iterations=100_000, key_size=32)

    # Encriptar
    start_time = time.time()
    mensaje_encriptado = cipher.encrypt(mensaje.encode('utf-8'))
    enc_time = time.time() - start_time

    print(f"\nTiempo de encriptación: {enc_time:.6f} s")
    print(f"Salida cifrada (primeros 64 bytes en hex): {mensaje_encriptado[:64].hex()}...")
    
    # Desencriptar
    start_time = time.time()
    mensaje_desencriptado = cipher.decrypt(mensaje_encriptado).decode('utf-8')
    dec_time = time.time() - start_time
    
    print(f"Tiempo de desencriptación: {dec_time:.6f} s")
    print(f"Mensaje desencriptado: '{mensaje_desencriptado}'")

    # Verificación
    if mensaje == mensaje_desencriptado:
        print("\n✓ Verificación correcta: los datos coinciden.")
    else:
        print("\n❌ Error: los datos no coinciden.")

    # Ejemplo de cifrado de archivos
    print("\nEjemplo de cifrado/descifrado de archivos:")
    test_filename = "mensaje_demo.txt"
    enc_filename = "mensaje_demo.enc"
    dec_filename = "mensaje_demo_dec.txt"

    # Crear archivo de prueba
    with open(test_filename, "w", encoding="utf-8") as f:
        f.write(mensaje)

    # Cifrar archivo
    cipher.encrypt_file(test_filename, enc_filename)

    # Descifrar archivo
    cipher.decrypt_file(enc_filename, dec_filename)

    # Verificar contenido
    with open(dec_filename, "r", encoding="utf-8") as f:
        contenido_descifrado = f.read()

    print(f"\nContenido descifrado desde archivo: '{contenido_descifrado}'")
    if contenido_descifrado == mensaje:
        print("✓ Archivo desencriptado correctamente.")
    else:
        print("❌ Error en la desencriptación del archivo.")

    # Limpieza (opcional)
    # os.remove(test_filename)
    # os.remove(enc_filename)
    # os.remove(dec_filename)

    print("\n" + "=" * 80)
    print("CAOS v4.0 finalizado.")


if __name__ == "__main__":
    demo() 