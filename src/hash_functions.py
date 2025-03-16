#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de funciones hash en Python.
Este script demuestra el uso de diferentes algoritmos hash disponibles en Python.
"""

import hashlib
import binascii
import os
from Crypto.Hash import SHA256, BLAKE2b

def basic_hash_example():
    """Ejemplo básico de hashing con diferentes algoritmos."""
    print("=" * 50)
    print("EJEMPLOS BÁSICOS DE FUNCIONES HASH")
    print("=" * 50)
    
    # Texto de ejemplo
    texto = "Hola, este es un ejemplo de texto para hashear."
    print(f"Texto original: {texto}")
    print("-" * 50)
    
    # MD5 (No recomendado para uso criptográfico)
    md5_hash = hashlib.md5(texto.encode()).hexdigest()
    print(f"MD5: {md5_hash}")
    
    # SHA-1 (No recomendado para uso criptográfico)
    sha1_hash = hashlib.sha1(texto.encode()).hexdigest()
    print(f"SHA-1: {sha1_hash}")
    
    # SHA-256
    sha256_hash = hashlib.sha256(texto.encode()).hexdigest()
    print(f"SHA-256: {sha256_hash}")
    
    # SHA-512
    sha512_hash = hashlib.sha512(texto.encode()).hexdigest()
    print(f"SHA-512: {sha512_hash}")
    
    # BLAKE2
    blake2_hash = hashlib.blake2b(texto.encode()).hexdigest()
    print(f"BLAKE2b: {blake2_hash}")
    
    print("\n")

def hash_file_example():
    """Ejemplo de cómo calcular el hash de un archivo."""
    print("=" * 50)
    print("HASH DE ARCHIVOS")
    print("=" * 50)
    
    # Crear un archivo de ejemplo
    filename = "archivo_ejemplo.txt"
    with open(filename, "w") as f:
        f.write("Este es un archivo de ejemplo para demostrar el hash de archivos.")
    
    print(f"Archivo creado: {filename}")
    
    # Calcular hash SHA-256 del archivo
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Leer el archivo en bloques de 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    print(f"SHA-256 del archivo: {sha256_hash.hexdigest()}")
    
    # Limpiar: eliminar el archivo de ejemplo
    os.remove(filename)
    print(f"Archivo {filename} eliminado.")
    print("\n")

def hash_with_salt_example():
    """Ejemplo de hash con salt para mayor seguridad."""
    print("=" * 50)
    print("HASH CON SALT")
    print("=" * 50)
    
    password = "mi_contraseña_secreta"
    print(f"Contraseña original: {password}")
    
    # Generar un salt aleatorio
    salt = os.urandom(16)  # 16 bytes = 128 bits
    print(f"Salt (en hexadecimal): {binascii.hexlify(salt).decode()}")
    
    # Combinar password y salt, luego hashear
    salted_password = password.encode() + salt
    hash_obj = hashlib.sha256(salted_password)
    password_hash = hash_obj.hexdigest()
    
    print(f"Hash con salt: {password_hash}")
    
    # Simulación de verificación
    print("\nVerificación de contraseña:")
    
    # Contraseña correcta
    test_password = "mi_contraseña_secreta"
    test_salted = test_password.encode() + salt
    test_hash = hashlib.sha256(test_salted).hexdigest()
    
    if test_hash == password_hash:
        print(f"Contraseña '{test_password}' es correcta ✓")
    else:
        print(f"Contraseña '{test_password}' es incorrecta ✗")
    
    # Contraseña incorrecta
    wrong_password = "contraseña_incorrecta"
    wrong_salted = wrong_password.encode() + salt
    wrong_hash = hashlib.sha256(wrong_salted).hexdigest()
    
    if wrong_hash == password_hash:
        print(f"Contraseña '{wrong_password}' es correcta ✓")
    else:
        print(f"Contraseña '{wrong_password}' es incorrecta ✗")
    
    print("\n")

def hash_collision_demo():
    """Demostración del efecto avalancha (pequeños cambios causan grandes diferencias en el hash)."""
    print("=" * 50)
    print("DEMOSTRACIÓN DEL EFECTO AVALANCHA")
    print("=" * 50)
    
    texto1 = "Este es un texto de ejemplo."
    texto2 = "Este es un texto de ejempla."  # Solo cambia la última letra
    
    print(f"Texto 1: {texto1}")
    print(f"Texto 2: {texto2}")
    print("-" * 50)
    
    # Calcular hashes SHA-256
    hash1 = hashlib.sha256(texto1.encode()).hexdigest()
    hash2 = hashlib.sha256(texto2.encode()).hexdigest()
    
    print(f"Hash SHA-256 del Texto 1: {hash1}")
    print(f"Hash SHA-256 del Texto 2: {hash2}")
    
    # Contar cuántos caracteres son diferentes
    diff_count = sum(1 for a, b in zip(hash1, hash2) if a != b)
    diff_percentage = (diff_count / len(hash1)) * 100
    
    print(f"\nDiferencia: {diff_count} de {len(hash1)} caracteres ({diff_percentage:.2f}%)")
    print("Esto demuestra cómo un pequeño cambio en la entrada produce un hash completamente diferente.")
    print("\n")

def pycrypto_hash_example():
    """Ejemplo usando la biblioteca PyCryptodome."""
    print("=" * 50)
    print("HASH CON PYCRYPTODOME")
    print("=" * 50)
    
    mensaje = "Ejemplo de mensaje para hashear con PyCryptodome."
    print(f"Mensaje original: {mensaje}")
    print("-" * 50)
    
    # SHA-256 con PyCryptodome
    h = SHA256.new()
    h.update(mensaje.encode())
    print(f"SHA-256 (PyCryptodome): {h.hexdigest()}")
    
    # BLAKE2b con PyCryptodome
    h = BLAKE2b.new(digest_bits=256)
    h.update(mensaje.encode())
    print(f"BLAKE2b-256 (PyCryptodome): {h.hexdigest()}")
    
    print("\n")

def main():
    """Función principal que ejecuta todos los ejemplos."""
    print("\n🔐 EJEMPLOS DE FUNCIONES HASH EN PYTHON 🔐\n")
    
    basic_hash_example()
    hash_file_example()
    hash_with_salt_example()
    hash_collision_demo()
    pycrypto_hash_example()
    
    print("=" * 50)
    print("CONCLUSIÓN")
    print("=" * 50)
    print("Las funciones hash son fundamentales en la seguridad informática.")
    print("Recuerda:")
    print("- MD5 y SHA-1 ya no se consideran seguros para aplicaciones criptográficas.")
    print("- Siempre usa salt al hashear contraseñas.")
    print("- Para contraseñas, considera usar funciones especializadas como bcrypt, Argon2 o PBKDF2.")
    print("- El efecto avalancha es una propiedad deseable en las funciones hash.")
    print("=" * 50)

if __name__ == "__main__":
    main() 