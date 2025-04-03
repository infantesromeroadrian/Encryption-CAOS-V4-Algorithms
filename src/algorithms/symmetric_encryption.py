#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de encriptación simétrica en Python.
Este script demuestra el uso de algoritmos de encriptación simétrica como AES.
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES as CryptoAES
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Funciones utilizadas por el servicio de benchmark

def derive_key_and_iv(password, salt=None, key_length=32, iv_length=16):
    """
    Deriva una clave y un IV a partir de una contraseña.
    
    Args:
        password: Contraseña de la que derivar la clave
        salt: Sal para la derivación (opcional)
        key_length: Longitud de la clave en bytes
        iv_length: Longitud del IV en bytes
        
    Returns:
        Tuple (clave, iv, salt)
    """
    if salt is None:
        salt = get_random_bytes(16)
    
    d = d_i = b''
    
    # Usar PBKDF2 sería mejor, pero esto es más simple para el ejemplo
    while len(d) < key_length + iv_length:
        d_i = hashlib.md5(d_i + password.encode('utf-8') + salt).digest()
        d += d_i
    
    key = d[:key_length]
    iv = d[key_length:key_length + iv_length]
    
    return key, iv, salt

def aes_encrypt_cbc(text, password):
    """
    Cifra un texto usando AES en modo CBC.
    
    Args:
        text: Texto a cifrar
        password: Contraseña para derivar la clave
        
    Returns:
        Texto cifrado en base64
    """
    # Derivar clave e IV
    key, iv, salt = derive_key_and_iv(password)
    
    # Crear cifrador AES en modo CBC
    cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
    
    # Cifrar el texto
    text_bytes = text.encode('utf-8')
    padded_data = pad(text_bytes, CryptoAES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # Combinar salt + iv + ciphertext y convertir a base64
    result = salt + iv + ciphertext
    return base64.b64encode(result).decode('utf-8')

def aes_decrypt_cbc(ciphertext_b64, password):
    """
    Descifra un texto cifrado con AES en modo CBC.
    
    Args:
        ciphertext_b64: Texto cifrado en base64
        password: Contraseña para derivar la clave
        
    Returns:
        Texto descifrado
    """
    # Decodificar de base64
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # Extraer salt, iv y texto cifrado
    salt = ciphertext[:16]
    iv = ciphertext[16:32]
    actual_ciphertext = ciphertext[32:]
    
    # Derivar clave
    key, _, _ = derive_key_and_iv(password, salt)
    
    # Descifrar
    cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
    padded_text = cipher.decrypt(actual_ciphertext)
    text = unpad(padded_text, CryptoAES.block_size)
    
    return text.decode('utf-8')

def aes_encrypt_gcm(text, password):
    """
    Cifra un texto usando AES en modo GCM.
    
    Args:
        text: Texto a cifrar
        password: Contraseña para derivar la clave
        
    Returns:
        Texto cifrado en base64
    """
    # Derivar clave y nonce
    key, nonce, salt = derive_key_and_iv(password, key_length=32, iv_length=12)
    
    # Crear cifrador AES en modo GCM
    cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
    
    # Cifrar el texto
    text_bytes = text.encode('utf-8')
    ciphertext, tag = cipher.encrypt_and_digest(text_bytes)
    
    # Combinar salt + nonce + tag + ciphertext y convertir a base64
    result = salt + nonce + tag + ciphertext
    return base64.b64encode(result).decode('utf-8')

def aes_decrypt_gcm(ciphertext_b64, password):
    """
    Descifra un texto cifrado con AES en modo GCM.
    
    Args:
        ciphertext_b64: Texto cifrado en base64
        password: Contraseña para derivar la clave
        
    Returns:
        Texto descifrado
    """
    # Decodificar de base64
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # Extraer salt, nonce, tag y texto cifrado
    salt = ciphertext[:16]
    nonce = ciphertext[16:28]
    tag = ciphertext[28:44]
    actual_ciphertext = ciphertext[44:]
    
    # Derivar clave
    key, _, _ = derive_key_and_iv(password, salt, key_length=32, iv_length=12)
    
    # Descifrar
    cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
    text = cipher.decrypt_and_verify(actual_ciphertext, tag)
    
    return text.decode('utf-8')

def triple_des_encrypt(text, password):
    """
    Cifra un texto usando 3DES.
    
    Args:
        text: Texto a cifrar
        password: Contraseña para derivar la clave
        
    Returns:
        Texto cifrado en base64
    """
    # Derivar clave e IV (3DES necesita 24 bytes para clave y 8 bytes para IV)
    key, iv, salt = derive_key_and_iv(password, key_length=24, iv_length=8)
    
    # Crear cifrador 3DES en modo CBC
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    
    # Cifrar el texto
    text_bytes = text.encode('utf-8')
    padded_data = pad(text_bytes, DES3.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # Combinar salt + iv + ciphertext y convertir a base64
    result = salt + iv + ciphertext
    return base64.b64encode(result).decode('utf-8')

def triple_des_decrypt(ciphertext_b64, password):
    """
    Descifra un texto cifrado con 3DES.
    
    Args:
        ciphertext_b64: Texto cifrado en base64
        password: Contraseña para derivar la clave
        
    Returns:
        Texto descifrado
    """
    # Decodificar de base64
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # Extraer salt, iv y texto cifrado
    salt = ciphertext[:16]
    iv = ciphertext[16:24]
    actual_ciphertext = ciphertext[24:]
    
    # Derivar clave
    key, _, _ = derive_key_and_iv(password, salt, key_length=24, iv_length=8)
    
    # Descifrar
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_text = cipher.decrypt(actual_ciphertext)
    text = unpad(padded_text, DES3.block_size)
    
    return text.decode('utf-8')

# Ejemplos originales
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