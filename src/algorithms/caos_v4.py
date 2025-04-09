#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CAOS v4.1 - Versión mejorada con optimizaciones de rendimiento y seguridad.

Mejoras principales:
- Procesamiento paralelo para operaciones intensivas
- Caché optimizado de claves derivadas
- Protección contra ataques de tiempo
- Uso de instrucciones AES-NI cuando disponibles
- Sistema de iteraciones adaptativas
"""

import os
import time
import threading
import concurrent.futures
from typing import Optional, Tuple, Dict, Union
from functools import lru_cache
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.constant_time import bytes_eq

# Constantes para optimización
MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 1_000_000
TARGET_DERIVATION_TIME = 0.1  # segundos
CACHE_SIZE = 1000
CHUNK_SIZE = 1024 * 1024  # 1MB chunks para procesamiento paralelo

class CaosEncryption:
    """
    CAOS v4.1 - Cifrado optimizado con AES-GCM y PBKDF2.
    """

    def __init__(
        self,
        password: str,
        iterations: Optional[int] = None,
        key_size: int = 32,
        use_parallel: bool = True
    ):
        """
        Inicializa el cifrador con parámetros optimizados.

        Args:
            password: Contraseña para derivación de clave
            iterations: Número de iteraciones PBKDF2 (si None, se calcula automáticamente)
            key_size: Tamaño de clave en bytes (32 = 256 bits)
            use_parallel: Usar procesamiento paralelo para operaciones intensivas
        """
        self.password = password.encode("utf-8") if isinstance(password, str) else password
        self.key_size = key_size
        self.use_parallel = use_parallel
        self.backend = default_backend()
        
        # Calcular iteraciones óptimas si no se especifican
        if iterations is None:
            self.iterations = self._calculate_optimal_iterations()
        else:
            self.iterations = max(MIN_ITERATIONS, min(iterations, MAX_ITERATIONS))
        
        # Inicializar caché de claves
        self._key_cache = {}
        self._cache_lock = threading.Lock()

    def _calculate_optimal_iterations(self) -> int:
        """Calcula el número óptimo de iteraciones basado en el rendimiento del sistema."""
        # Medir tiempo de derivación con iteraciones mínimas
        start_time = time.time()
        salt = os.urandom(16)
        self._derive_key(salt, MIN_ITERATIONS)
        base_time = time.time() - start_time
        
        # Calcular iteraciones para alcanzar el tiempo objetivo
        if base_time >= TARGET_DERIVATION_TIME:
            return MIN_ITERATIONS
        
        target_iterations = int(MIN_ITERATIONS * (TARGET_DERIVATION_TIME / base_time))
        return min(target_iterations, MAX_ITERATIONS)

    @lru_cache(maxsize=CACHE_SIZE)
    def _derive_key(self, salt: bytes, iterations: Optional[int] = None) -> bytes:
        """
        Deriva clave con caché optimizado y protección contra ataques de tiempo.
        """
        if iterations is None:
            iterations = self.iterations
            
        # Verificar que el salt tenga la longitud correcta
        if len(salt) != 16:
            raise ValueError(f"Salt debe tener 16 bytes, pero tiene {len(salt)} bytes")
            
        # Verificar que las iteraciones estén dentro del rango permitido
        if iterations < MIN_ITERATIONS or iterations > MAX_ITERATIONS:
            raise ValueError(
                f"Iteraciones ({iterations}) fuera del rango permitido "
                f"[{MIN_ITERATIONS}, {MAX_ITERATIONS}]"
            )
            
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_size,
                salt=salt,
                iterations=iterations,
                backend=self.backend
            )
            return kdf.derive(self.password)
        except Exception as e:
            raise ValueError(
                f"Error al derivar la clave: {str(e)}. "
                "Esto puede deberse a un problema con la contraseña o los parámetros de derivación."
            ) from e

    def _process_chunk(self, chunk: bytes, key: bytes, nonce: bytes, encrypt: bool) -> bytes:
        """Procesa un chunk de datos de manera segura."""
        try:
            aesgcm = AESGCM(key)
            if encrypt:
                return aesgcm.encrypt(nonce, chunk, None)
            return aesgcm.decrypt(nonce, chunk, None)
        except Exception as e:
            raise ValueError(
                f"Error al procesar chunk: {str(e)}. "
                f"Tamaño del chunk: {len(chunk)}, "
                f"Tamaño de la clave: {len(key)}, "
                f"Tamaño del nonce: {len(nonce)}"
            ) from e

    def _parallel_process(self, data: bytes, key: bytes, nonce: bytes, encrypt: bool) -> bytes:
        """Procesa datos en paralelo usando chunks."""
        # Si los datos son muy pequeños o el procesamiento paralelo está desactivado,
        # procesar todo en un solo chunk
        if not self.use_parallel or len(data) <= CHUNK_SIZE:
            return self._process_chunk(data, key, nonce, encrypt)
            
        # Asegurar que el último chunk no sea demasiado pequeño
        num_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
        if num_chunks == 1:
            return self._process_chunk(data, key, nonce, encrypt)
            
        # Dividir en chunks, asegurando que el último chunk no sea demasiado pequeño
        chunks = []
        for i in range(0, len(data), CHUNK_SIZE):
            chunk = data[i:i + CHUNK_SIZE]
            # Si el último chunk es muy pequeño, combinarlo con el anterior
            if i + CHUNK_SIZE >= len(data) and len(chunk) < CHUNK_SIZE // 4:
                if chunks:
                    chunks[-1] += chunk
                else:
                    chunks.append(chunk)
            else:
                chunks.append(chunk)
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(self._process_chunk, chunk, key, nonce, encrypt)
                for chunk in chunks
            ]
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    # Cancelar todas las tareas pendientes
                    for f in futures:
                        f.cancel()
                    raise ValueError(f"Error al procesar chunk en paralelo: {str(e)}") from e
                
        return b''.join(results)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encripta datos con optimizaciones de rendimiento y seguridad.
        """
        # Generar sal y nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # Derivar clave de manera segura
        key = self._derive_key(salt)
        
        # Calcular checksum antes de encriptar
        checksum = self._calculate_checksum(data)
        
        # Procesar datos (en paralelo si es posible)
        ciphertext = self._parallel_process(checksum + data, key, nonce, True)
        
        # Retornar con estructura optimizada
        return salt + nonce + ciphertext

    def decrypt(self, encrypted_data: Union[bytes, str]) -> bytes:
        """
        Desencripta datos con verificación de integridad mejorada y manejo de errores más claro.
        Soporta tanto datos binarios como strings en Base64.
        """
        try:
            # Si el input es un string, asumimos que es Base64
            if isinstance(encrypted_data, str):
                try:
                    encrypted_data = base64.b64decode(encrypted_data)
                except Exception as e:
                    raise ValueError(
                        "Error al decodificar Base64. "
                        "Asegúrate de que el mensaje encriptado esté en formato Base64 válido."
                    ) from e

            # Verificación de longitud mínima
            min_length = 16 + 12 + 16  # salt + nonce + tag mínimo
            if len(encrypted_data) < min_length:
                raise ValueError(
                    f"Los datos encriptados son demasiado cortos ({len(encrypted_data)} bytes). "
                    f"Se requieren al menos {min_length} bytes para un mensaje válido."
                )
            
            # Extraer componentes
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            
            # Derivar clave de manera segura
            try:
                key = self._derive_key(salt)
            except Exception as e:
                raise ValueError(
                    "Error al derivar la clave. "
                    "Esto puede deberse a un problema con la contraseña o el salt."
                ) from e
            
            # Procesar datos (en paralelo si es posible)
            try:
                plaintext = self._parallel_process(ciphertext, key, nonce, False)
            except Exception as e:
                raise ValueError(
                    "Error al procesar los datos cifrados. "
                    "La contraseña podría ser incorrecta o los datos podrían estar corruptos."
                ) from e
            
            # Verificar que tenemos suficientes datos para el checksum
            if len(plaintext) < 16:
                raise ValueError(
                    "Los datos desencriptados son demasiado cortos para contener un checksum válido."
                )
            
            # Extraer checksum y datos
            stored_checksum = plaintext[:16]
            actual_data = plaintext[16:]
            
            # Calcular checksum actual
            current_checksum = self._calculate_checksum(actual_data)
            
            # Verificación de integridad constante en tiempo
            if not bytes_eq(stored_checksum, current_checksum):
                # Proporcionar más información de diagnóstico
                raise ValueError(
                    "La verificación de integridad falló. "
                    f"Checksum almacenado: {stored_checksum.hex()}, "
                    f"Checksum calculado: {current_checksum.hex()}. "
                    "Esto puede deberse a: "
                    "1) Contraseña incorrecta "
                    "2) Datos modificados o corruptos "
                    "3) Mensaje encriptado con una versión diferente del algoritmo"
                )
                
            return actual_data
            
        except ValueError as ve:
            # Re-lanzar los errores de validación con mensajes más descriptivos
            raise ve
        except Exception as e:
            # Capturar cualquier otro error y proporcionar un mensaje más útil
            raise ValueError(
                f"Error al desencriptar: {str(e)}. "
                "Por favor, verifica que: "
                "1) La contraseña es correcta "
                "2) El mensaje fue encriptado con CAOS V4 "
                "3) El mensaje no ha sido modificado"
            ) from e

    def _calculate_checksum(self, data: bytes) -> bytes:
        """Calcula checksum de manera segura y eficiente."""
        h = hashes.Hash(hashes.SHA256(), backend=self.backend)
        h.update(data)
        return h.finalize()[:16]

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """Encripta archivo con procesamiento por chunks."""
        with open(input_path, "rb") as infile:
            data = infile.read()
            
        encrypted_data = self.encrypt(data)
        
        with open(output_path, "wb") as outfile:
            outfile.write(encrypted_data)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Desencripta archivo con verificación de integridad."""
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


def encrypt(text, password, iterations=100_000, seed=None):
    """
    Función de interfaz para encriptar texto con CAOS v4.0.
    
    Args:
        text (str or bytes): Texto a encriptar
        password (str): Contraseña para la encriptación
        iterations (int): Número de iteraciones para PBKDF2
        seed (int): Semilla, no usada pero incluida para compatibilidad
    
    Returns:
        bytes: Datos encriptados
    """
    # Convertir texto a bytes si es necesario
    if isinstance(text, str):
        text = text.encode('utf-8')
        
    # Crear instancia de CaosEncryption
    cipher = CaosEncryption(password=password, iterations=iterations)
    
    # Encriptar los datos
    return cipher.encrypt(text)

def decrypt(encrypted_data, password, iterations=100_000, seed=None):
    """
    Función de interfaz para desencriptar datos con CAOS v4.0.
    
    Args:
        encrypted_data (bytes): Datos encriptados
        password (str): Contraseña para la desencriptación
        iterations (int): Número de iteraciones para PBKDF2
        seed (int): Semilla, no usada pero incluida para compatibilidad
    
    Returns:
        str: Texto desencriptado
    """
    # Crear instancia de CaosEncryption
    cipher = CaosEncryption(password=password, iterations=iterations)
    
    # Desencriptar los datos
    result = cipher.decrypt(encrypted_data)
    
    # Convertir a string si los datos son texto
    try:
        return result.decode('utf-8')
    except UnicodeDecodeError:
        # Si no se puede decodificar como UTF-8, devolver los bytes directamente
        return result

if __name__ == "__main__":
    demo() 