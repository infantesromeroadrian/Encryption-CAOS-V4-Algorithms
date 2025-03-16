#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de encriptación simétrica en Python.
Este script demuestra el uso de algoritmos de encriptación simétrica como AES.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_example_with_cryptography():
    """Ejemplo de encriptación AES usando la biblioteca cryptography."""
    print("=" * 50)
    print("ENCRIPTACIÓN AES CON CRYPTOGRAPHY")
    print("=" * 50)
    
    # Mensaje a encriptar
    mensaje = "Este es un mensaje secreto que será encriptado con AES."
    print(f"Mensaje original: {mensaje}")
    
    # Generar una clave aleatoria de 256 bits (32 bytes)
    key = os.urandom(32)
    print(f"Clave (en base64): {base64.b64encode(key).decode()}")
    
    # Generar un vector de inicialización (IV) aleatorio
    iv = os.urandom(16)  # AES block size = 16 bytes
    print(f"IV (en base64): {base64.b64encode(iv).decode()}")
    
    # Convertir el mensaje a bytes y aplicar padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    mensaje_bytes = mensaje.encode('utf-8')
    padded_data = padder.update(mensaje_bytes) + padder.finalize()
    
    # Crear un cifrador AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encriptar el mensaje
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print(f"Mensaje encriptado (en base64): {base64.b64encode(ciphertext).decode()}")
    
    # Desencriptar el mensaje
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Quitar el padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
    print("\n")

def aes_example_with_pycryptodome():
    """Ejemplo de encriptación AES usando la biblioteca PyCryptodome."""
    print("=" * 50)
    print("ENCRIPTACIÓN AES CON PYCRYPTODOME")
    print("=" * 50)
    
    # Mensaje a encriptar
    mensaje = "Este es otro mensaje secreto para encriptar con AES usando PyCryptodome."
    print(f"Mensaje original: {mensaje}")
    
    # Generar una clave aleatoria de 256 bits (32 bytes)
    key = get_random_bytes(32)
    print(f"Clave (en base64): {base64.b64encode(key).decode()}")
    
    # Generar un vector de inicialización (IV) aleatorio
    iv = get_random_bytes(16)  # AES block size = 16 bytes
    print(f"IV (en base64): {base64.b64encode(iv).decode()}")
    
    # Crear un cifrador AES en modo CBC
    cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
    
    # Encriptar el mensaje (con padding)
    mensaje_bytes = mensaje.encode('utf-8')
    padded_data = pad(mensaje_bytes, CryptoAES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    print(f"Mensaje encriptado (en base64): {base64.b64encode(ciphertext).decode()}")
    
    # Desencriptar el mensaje
    decipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
    padded_plaintext = decipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, CryptoAES.block_size)
    
    print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
    print("\n")

def aes_gcm_example():
    """Ejemplo de encriptación AES en modo GCM (Galois/Counter Mode) que proporciona autenticación."""
    print("=" * 50)
    print("ENCRIPTACIÓN AES-GCM (CON AUTENTICACIÓN)")
    print("=" * 50)
    
    # Mensaje a encriptar
    mensaje = "Mensaje secreto con autenticación usando AES-GCM."
    print(f"Mensaje original: {mensaje}")
    
    # Datos adicionales autenticados (no encriptados pero autenticados)
    aad = b"Datos adicionales autenticados"
    print(f"Datos adicionales: {aad.decode()}")
    
    # Generar una clave aleatoria de 256 bits (32 bytes)
    key = get_random_bytes(32)
    print(f"Clave (en base64): {base64.b64encode(key).decode()}")
    
    # Generar un nonce aleatorio (similar a un IV pero para GCM)
    nonce = get_random_bytes(12)  # 12 bytes es el tamaño recomendado para GCM
    print(f"Nonce (en base64): {base64.b64encode(nonce).decode()}")
    
    # Crear un cifrador AES en modo GCM
    cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
    
    # Añadir los datos adicionales autenticados
    cipher.update(aad)
    
    # Encriptar el mensaje (GCM no requiere padding)
    mensaje_bytes = mensaje.encode('utf-8')
    ciphertext, tag = cipher.encrypt_and_digest(mensaje_bytes)
    
    print(f"Mensaje encriptado (en base64): {base64.b64encode(ciphertext).decode()}")
    print(f"Tag de autenticación (en base64): {base64.b64encode(tag).decode()}")
    
    # Desencriptar y verificar el mensaje
    decipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
    decipher.update(aad)
    
    try:
        plaintext = decipher.decrypt_and_verify(ciphertext, tag)
        print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
        print("✓ Autenticación exitosa: El mensaje no ha sido alterado.")
    except ValueError:
        print("✗ Error de autenticación: El mensaje o el tag han sido alterados.")
    
    # Demostrar qué sucede si el mensaje es alterado
    print("\nSimulación de alteración del mensaje:")
    
    # Alterar un byte del mensaje encriptado
    altered_ciphertext = bytearray(ciphertext)
    altered_ciphertext[0] = (altered_ciphertext[0] + 1) % 256
    altered_ciphertext = bytes(altered_ciphertext)
    
    # Intentar desencriptar el mensaje alterado
    decipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
    decipher.update(aad)
    
    try:
        plaintext = decipher.decrypt_and_verify(altered_ciphertext, tag)
        print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
        print("✓ Autenticación exitosa: El mensaje no ha sido alterado.")
    except ValueError:
        print("✗ Error de autenticación: El mensaje o el tag han sido alterados.")
    
    print("\n")

def file_encryption_example():
    """Ejemplo de encriptación de archivos usando AES."""
    print("=" * 50)
    print("ENCRIPTACIÓN DE ARCHIVOS CON AES")
    print("=" * 50)
    
    # Crear un archivo de ejemplo
    filename = "archivo_secreto.txt"
    encrypted_filename = "archivo_secreto.enc"
    
    with open(filename, "w") as f:
        f.write("Este es un archivo con información confidencial que necesita ser encriptado.")
    
    print(f"Archivo creado: {filename}")
    
    # Generar una clave aleatoria de 256 bits (32 bytes)
    key = get_random_bytes(32)
    print(f"Clave (en base64): {base64.b64encode(key).decode()}")
    
    # Generar un vector de inicialización (IV) aleatorio
    iv = get_random_bytes(16)
    
    # Encriptar el archivo
    cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
    
    with open(filename, "rb") as file_in:
        file_data = file_in.read()
        
        # Aplicar padding a los datos
        padded_data = pad(file_data, CryptoAES.block_size)
        
        # Encriptar los datos
        encrypted_data = cipher.encrypt(padded_data)
        
        # Guardar IV + datos encriptados
        with open(encrypted_filename, "wb") as file_out:
            file_out.write(iv + encrypted_data)
    
    print(f"Archivo encriptado guardado como: {encrypted_filename}")
    
    # Desencriptar el archivo
    decrypted_filename = "archivo_secreto_decrypted.txt"
    
    with open(encrypted_filename, "rb") as file_in:
        # Leer el IV (primeros 16 bytes)
        iv = file_in.read(16)
        
        # Leer los datos encriptados
        encrypted_data = file_in.read()
        
        # Crear un nuevo cifrador con el mismo IV
        decipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
        
        # Desencriptar los datos
        padded_data = decipher.decrypt(encrypted_data)
        
        # Quitar el padding
        data = unpad(padded_data, CryptoAES.block_size)
        
        # Guardar los datos desencriptados
        with open(decrypted_filename, "wb") as file_out:
            file_out.write(data)
    
    print(f"Archivo desencriptado guardado como: {decrypted_filename}")
    
    # Mostrar el contenido del archivo desencriptado
    with open(decrypted_filename, "r") as f:
        content = f.read()
    
    print(f"Contenido del archivo desencriptado: {content}")
    
    # Limpiar: eliminar los archivos de ejemplo
    os.remove(filename)
    os.remove(encrypted_filename)
    os.remove(decrypted_filename)
    print(f"Archivos de ejemplo eliminados.")
    print("\n")

def main():
    """Función principal que ejecuta todos los ejemplos."""
    print("\n🔒 EJEMPLOS DE ENCRIPTACIÓN SIMÉTRICA EN PYTHON 🔒\n")
    
    aes_example_with_cryptography()
    aes_example_with_pycryptodome()
    aes_gcm_example()
    file_encryption_example()
    
    print("=" * 50)
    print("CONCLUSIÓN")
    print("=" * 50)
    print("La encriptación simétrica es fundamental para proteger la confidencialidad de los datos.")
    print("Recuerda:")
    print("- AES es actualmente el estándar más utilizado y seguro para encriptación simétrica.")
    print("- El modo GCM proporciona autenticación además de confidencialidad.")
    print("- La gestión segura de claves es crucial - nunca almacenes claves en texto plano.")
    print("- El vector de inicialización (IV) debe ser único para cada mensaje con la misma clave.")
    print("=" * 50)

if __name__ == "__main__":
    main() 