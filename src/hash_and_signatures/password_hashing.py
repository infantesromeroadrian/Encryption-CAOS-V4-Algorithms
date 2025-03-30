#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de técnicas seguras para el almacenamiento de contraseñas en Python.
Este script demuestra el uso de algoritmos especializados para el hash de contraseñas.
"""

import os
import hashlib
import binascii
import time
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def insecure_password_storage():
    """Ejemplo de almacenamiento inseguro de contraseñas (NO USAR EN PRODUCCIÓN)."""
    print("=" * 50)
    print("❌ ALMACENAMIENTO INSEGURO DE CONTRASEÑAS (NO USAR) ❌")
    print("=" * 50)
    
    # Contraseña de ejemplo
    password = "mi_contraseña_123"
    print(f"Contraseña original: {password}")
    
    # Método 1: Almacenamiento en texto plano (extremadamente inseguro)
    print("\n1. Almacenamiento en texto plano:")
    print(f"Contraseña almacenada: {password}")
    print("⚠️ NUNCA almacenes contraseñas en texto plano.")
    
    # Método 2: Hash simple sin salt (inseguro)
    print("\n2. Hash simple sin salt (MD5):")
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    print(f"Hash MD5: {md5_hash}")
    print("⚠️ MD5 es vulnerable a ataques de fuerza bruta y tablas rainbow.")
    
    # Método 3: Hash SHA-256 sin salt (inseguro)
    print("\n3. Hash SHA-256 sin salt:")
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    print(f"Hash SHA-256: {sha256_hash}")
    print("⚠️ Aunque SHA-256 es criptográficamente más fuerte que MD5,")
    print("   sin salt sigue siendo vulnerable a ataques de diccionario y tablas rainbow.")
    
    print("\nProblemas con estos métodos:")
    print("- Sin salt, contraseñas idénticas producen hashes idénticos")
    print("- Vulnerables a ataques de diccionario y tablas rainbow")
    print("- Los hashes simples son demasiado rápidos de calcular para los atacantes")
    print("\n")

def basic_salted_hash():
    """Ejemplo básico de hash con salt usando hashlib."""
    print("=" * 50)
    print("HASH CON SALT BÁSICO (HASHLIB)")
    print("=" * 50)
    
    # Contraseña de ejemplo
    password = "mi_contraseña_123"
    print(f"Contraseña original: {password}")
    
    # Generar un salt aleatorio
    salt = os.urandom(32)  # 32 bytes = 256 bits
    print(f"Salt (en hexadecimal): {binascii.hexlify(salt).decode()}")
    
    # Método 1: Concatenación simple + SHA-256:
    print("\n1. Concatenación simple + SHA-256:")
    salted_password = password.encode() + salt
    hash_obj = hashlib.sha256(salted_password)
    password_hash = hash_obj.hexdigest()
    
    print(f"Hash con salt: {password_hash}")
    
    # Método 2: Usar PBKDF2 (Password-Based Key Derivation Function 2)
    print("\n2. PBKDF2 con HMAC-SHA256:")
    # 100,000 iteraciones es un buen punto de partida en 2023
    iterations = 100000
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    password_hash = binascii.hexlify(dk).decode()
    
    print(f"PBKDF2 hash: {password_hash}")
    print(f"Iteraciones: {iterations}")
    
    # Simulación de verificación
    print("\nVerificación de contraseña:")
    
    # Contraseña correcta
    test_password = "mi_contraseña_123"
    dk_verify = hashlib.pbkdf2_hmac('sha256', test_password.encode(), salt, iterations)
    test_hash = binascii.hexlify(dk_verify).decode()
    
    if test_hash == password_hash:
        print(f"Contraseña '{test_password}' es correcta ✓")
    else:
        print(f"Contraseña '{test_password}' es incorrecta ✗")
    
    # Contraseña incorrecta
    wrong_password = "contraseña_incorrecta"
    dk_verify = hashlib.pbkdf2_hmac('sha256', wrong_password.encode(), salt, iterations)
    wrong_hash = binascii.hexlify(dk_verify).decode()
    
    if wrong_hash == password_hash:
        print(f"Contraseña '{wrong_password}' es correcta ✓")
    else:
        print(f"Contraseña '{wrong_password}' es incorrecta ✗")
    
    print("\n")

def bcrypt_example():
    """Ejemplo de hash de contraseñas usando bcrypt."""
    print("=" * 50)
    print("HASH DE CONTRASEÑAS CON BCRYPT")
    print("=" * 50)
    
    # Contraseña de ejemplo
    password = "mi_contraseña_123"
    print(f"Contraseña original: {password}")
    
    # Generar un hash bcrypt
    # El parámetro rounds determina la complejidad (12 es un buen valor por defecto)
    rounds = 12
    start_time = time.time()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds))
    end_time = time.time()
    
    print(f"\nHash bcrypt: {hashed.decode()}")
    print(f"Tiempo de cálculo: {(end_time - start_time):.4f} segundos")
    print(f"Factor de trabajo (rounds): {rounds}")
    
    # Explicar la estructura del hash bcrypt
    print("\nEstructura del hash bcrypt:")
    print("- $2b$: Identificador de versión de bcrypt")
    print(f"- $12$: Factor de trabajo (2^{rounds} iteraciones)")
    print("- 22 caracteres siguientes: Salt codificado en base64")
    print("- 31 caracteres restantes: Hash codificado en base64")
    
    # Simulación de verificación
    print("\nVerificación de contraseña:")
    
    # Contraseña correcta
    test_password = "mi_contraseña_123"
    if bcrypt.checkpw(test_password.encode(), hashed):
        print(f"Contraseña '{test_password}' es correcta ✓")
    else:
        print(f"Contraseña '{test_password}' es incorrecta ✗")
    
    # Contraseña incorrecta
    wrong_password = "contraseña_incorrecta"
    if bcrypt.checkpw(wrong_password.encode(), hashed):
        print(f"Contraseña '{wrong_password}' es correcta ✓")
    else:
        print(f"Contraseña '{wrong_password}' es incorrecta ✗")
    
    # Demostrar cómo bcrypt ajusta automáticamente la dificultad
    print("\nAjuste de dificultad en bcrypt:")
    
    for r in [10, 12, 14]:
        start_time = time.time()
        bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=r))
        end_time = time.time()
        print(f"rounds={r}: {(end_time - start_time):.4f} segundos")
    
    print("\n")

def pbkdf2_example():
    """Ejemplo de hash de contraseñas usando PBKDF2 con la biblioteca cryptography."""
    print("=" * 50)
    print("HASH DE CONTRASEÑAS CON PBKDF2")
    print("=" * 50)
    
    # Contraseña de ejemplo
    password = "mi_contraseña_123"
    print(f"Contraseña original: {password}")
    
    # Generar un salt aleatorio
    salt = os.urandom(16)
    print(f"Salt (en hexadecimal): {binascii.hexlify(salt).decode()}")
    
    # Configurar PBKDF2
    iterations = 100000  # 100,000 iteraciones es un buen punto de partida en 2023
    
    start_time = time.time()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    end_time = time.time()
    
    print(f"\nPBKDF2 hash (en hexadecimal): {binascii.hexlify(key).decode()}")
    print(f"Iteraciones: {iterations}")
    print(f"Tiempo de cálculo: {(end_time - start_time):.4f} segundos")
    
    # Verificación de contraseña
    print("\nVerificación de contraseña:")
    
    # Crear un nuevo objeto PBKDF2HMAC para verificación
    kdf_verify = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    # Contraseña correcta
    test_password = "mi_contraseña_123"
    try:
        kdf_verify.verify(test_password.encode(), key)
        print(f"Contraseña '{test_password}' es correcta ✓")
    except Exception:
        print(f"Contraseña '{test_password}' es incorrecta ✗")
    
    # Contraseña incorrecta
    wrong_password = "contraseña_incorrecta"
    try:
        kdf_verify.verify(wrong_password.encode(), key)
        print(f"Contraseña '{wrong_password}' es correcta ✓")
    except Exception:
        print(f"Contraseña '{wrong_password}' es incorrecta ✗")
    
    print("\n")

def password_storage_format():
    """Ejemplo de formato para almacenar hashes de contraseñas."""
    print("=" * 50)
    print("FORMATO PARA ALMACENAR HASHES DE CONTRASEÑAS")
    print("=" * 50)
    
    # Contraseña de ejemplo
    password = "mi_contraseña_123"
    print(f"Contraseña original: {password}")
    
    # Método 1: Formato para PBKDF2
    print("\n1. Formato para PBKDF2:")
    
    # Parámetros
    salt = os.urandom(16)
    iterations = 100000
    
    # Generar el hash
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    
    # Formato: algoritmo$iteraciones$salt_en_base64$hash_en_base64
    salt_b64 = binascii.b2a_base64(salt, newline=False).decode()
    dk_b64 = binascii.b2a_base64(dk, newline=False).decode()
    
    stored_password = f"pbkdf2_sha256${iterations}${salt_b64}${dk_b64}"
    print(f"Hash almacenado: {stored_password}")
    
    # Simulación de verificación
    print("\nVerificación usando el formato almacenado:")
    
    # Extraer los componentes
    algorithm, iter_count, salt_b64, hash_b64 = stored_password.split('$')
    iter_count = int(iter_count)
    salt = binascii.a2b_base64(salt_b64)
    stored_hash = binascii.a2b_base64(hash_b64)
    
    # Verificar la contraseña
    test_password = "mi_contraseña_123"
    computed_hash = hashlib.pbkdf2_hmac('sha256', test_password.encode(), salt, iter_count)
    
    if computed_hash == stored_hash:
        print(f"Contraseña '{test_password}' es correcta ✓")
    else:
        print(f"Contraseña '{test_password}' es incorrecta ✗")
    
    # Método 2: bcrypt ya incluye un formato estándar
    print("\n2. Formato para bcrypt (incorporado):")
    
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    print(f"Hash almacenado: {hashed.decode()}")
    
    # Verificación
    if bcrypt.checkpw(password.encode(), hashed):
        print(f"Contraseña '{password}' es correcta ✓")
    
    print("\nVentajas de estos formatos:")
    print("- Incluyen toda la información necesaria para la verificación")
    print("- Permiten actualizar los parámetros (iteraciones, algoritmo) en el futuro")
    print("- Son autocontenidos (no requieren almacenar el salt por separado)")
    print("\n")

def password_upgrade_example():
    """Ejemplo de cómo actualizar el hash de una contraseña cuando el usuario inicia sesión."""
    print("=" * 50)
    print("ACTUALIZACIÓN DE HASHES DE CONTRASEÑAS")
    print("=" * 50)
    
    print("Escenario: Actualizar de PBKDF2 con 10,000 iteraciones a bcrypt")
    
    # Contraseña de ejemplo
    password = "mi_contraseña_123"
    print(f"Contraseña original: {password}")
    
    # Hash antiguo (PBKDF2 con 10,000 iteraciones)
    salt_old = os.urandom(16)
    iterations_old = 10000
    dk_old = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_old, iterations_old)
    
    # Formato antiguo
    salt_b64_old = binascii.b2a_base64(salt_old, newline=False).decode()
    dk_b64_old = binascii.b2a_base64(dk_old, newline=False).decode()
    old_stored_password = f"pbkdf2_sha256${iterations_old}${salt_b64_old}${dk_b64_old}"
    
    print(f"\nHash antiguo (PBKDF2): {old_stored_password}")
    
    # Simulación de inicio de sesión
    print("\nUsuario inicia sesión con la contraseña correcta...")
    
    # Verificar con el hash antiguo
    algorithm, iter_count, salt_b64, hash_b64 = old_stored_password.split('$')
    iter_count = int(iter_count)
    salt = binascii.a2b_base64(salt_b64)
    stored_hash = binascii.a2b_base64(hash_b64)
    
    login_password = "mi_contraseña_123"
    computed_hash = hashlib.pbkdf2_hmac('sha256', login_password.encode(), salt, iter_count)
    
    if computed_hash == stored_hash:
        print("✓ Autenticación exitosa con el hash antiguo")
        
        # Generar un nuevo hash con bcrypt
        new_hash = bcrypt.hashpw(login_password.encode(), bcrypt.gensalt(rounds=12))
        new_stored_password = new_hash.decode()
        
        print(f"✓ Hash actualizado a bcrypt: {new_stored_password}")
    else:
        print("✗ Autenticación fallida")
    
    print("\nVentajas de la actualización gradual:")
    print("- No requiere que todos los usuarios cambien sus contraseñas")
    print("- Actualiza los hashes a medida que los usuarios inician sesión")
    print("- Permite una transición suave a algoritmos más seguros")
    print("\n")

def main():
    """Función principal que ejecuta todos los ejemplos."""
    print("\n🔐 TÉCNICAS SEGURAS PARA EL ALMACENAMIENTO DE CONTRASEÑAS 🔐\n")
    
    insecure_password_storage()
    basic_salted_hash()
    bcrypt_example()
    pbkdf2_example()
    password_storage_format()
    password_upgrade_example()
    
    print("=" * 50)
    print("CONCLUSIÓN")
    print("=" * 50)
    print("El almacenamiento seguro de contraseñas es crucial para proteger a los usuarios.")
    print("Recuerda:")
    print("- NUNCA almacenes contraseñas en texto plano o con hashes simples")
    print("- Usa algoritmos especializados como bcrypt, Argon2 o PBKDF2")
    print("- Asegúrate de usar un salt único para cada contraseña")
    print("- Ajusta los parámetros de costo para que el hash tome tiempo (100ms-500ms)")
    print("- Actualiza tus algoritmos de hash cuando surjan nuevas recomendaciones")
    print("=" * 50)

if __name__ == "__main__":
    main() 