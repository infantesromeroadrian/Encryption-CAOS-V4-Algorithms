#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Funciones de utilidad para la interfaz de encriptación.
Este archivo contiene funciones auxiliares para los diferentes módulos de encriptación.
"""

import os
import base64
import hashlib
import matplotlib.pyplot as plt
from typing import Dict, Tuple, Any, List, Union

# Funciones de encriptación simétrica
def aes_encrypt_decrypt(text: str, password: str, encrypt: bool = True, iv: str = None, mode: str = 'CBC') -> Union[Tuple[str, str], str]:
    """
    Encripta o desencripta un texto usando AES.
    
    Args:
        text: Texto a encriptar o texto encriptado base64 para desencriptar
        password: Contraseña para la encriptación
        encrypt: True para encriptar, False para desencriptar
        iv: Vector de inicialización en base64 (solo para descifrar)
        mode: Modo de operación (CBC, GCM)
        
    Returns:
        Si encrypt=True: (texto_encriptado_base64, iv_base64)
        Si encrypt=False: texto_desencriptado
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
    
    # Derivar clave a partir de contraseña
    salt = b'cryptolab_salt'  # Salt fijo para demo (en sistemas reales debería ser aleatorio)
    key = PBKDF2(password.encode(), salt, dkLen=32, count=1000)
    
    if encrypt:
        # Generar IV aleatorio
        iv_bytes = get_random_bytes(16)
        
        # Encriptar
        if mode == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
            padded_data = pad(text.encode('utf-8'), AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
        elif mode == 'GCM':
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv_bytes)
            ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
            # Para GCM, incluimos el tag en el ciphertext
            ciphertext = ciphertext + tag
        else:
            raise ValueError(f"Modo no soportado: {mode}")
        
        # Codificar en base64
        encrypted_text = base64.b64encode(ciphertext).decode('utf-8')
        iv_text = base64.b64encode(iv_bytes).decode('utf-8')
        
        return encrypted_text, iv_text
    else:
        # Decodificar de base64
        ciphertext = base64.b64decode(text)
        iv_bytes = base64.b64decode(iv)
        
        # Desencriptar
        if mode == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
        elif mode == 'GCM':
            # Para GCM, extraer el tag (últimos 16 bytes)
            tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv_bytes)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            raise ValueError(f"Modo no soportado: {mode}")
        
        return plaintext.decode('utf-8')

# Funciones de encriptación asimétrica
def rsa_encrypt_decrypt(text: Union[str, None], key: Union[str, None], action: str = 'encrypt') -> Union[Tuple[str, str], str]:
    """
    Encripta, desencripta o genera claves RSA.
    
    Args:
        text: Texto a encriptar/desencriptar o None para generación de claves
        key: Clave pública/privada (según acción) o None para generación de claves
        action: 'encrypt', 'decrypt' o 'generate_keys'
        
    Returns:
        Según action:
        - 'generate_keys': (public_key_pem, private_key_pem)
        - 'encrypt': encrypted_base64
        - 'decrypt': decrypted_text
    """
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    
    if action == 'generate_keys':
        # Generar par de claves RSA
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return public_key, private_key
    
    elif action == 'encrypt':
        # Convertir clave pública de PEM a objeto RSA
        public_key = RSA.import_key(key)
        
        # Crear cifrador OAEP con SHA-256
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        # Encriptar (considerando límite de tamaño para RSA)
        max_size = 190  # Límite para RSA-2048 con OAEP y SHA-256
        if len(text.encode('utf-8')) > max_size:
            # Para la demo, truncamos (en producción usaríamos encriptación híbrida)
            text = text[:max_size // 2]  # Truncamos para asegurar compatibilidad con UTF-8
        
        ciphertext = cipher.encrypt(text.encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')
    
    elif action == 'decrypt':
        # Convertir clave privada de PEM a objeto RSA
        private_key = RSA.import_key(key)
        
        # Crear descifrador OAEP con SHA-256
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        # Desencriptar
        ciphertext = base64.b64decode(text)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8')

# Funciones de encriptación híbrida
def hybrid_encrypt_decrypt(text: Union[str, None], key: Union[str, None], action: str = 'encrypt', metadata: str = None) -> Union[Tuple[str, str], Tuple[str, str, str], str]:
    """
    Encripta, desencripta o genera claves para encriptación híbrida.
    
    Args:
        text: Texto a encriptar/desencriptar o None para generación de claves
        key: Clave pública/privada (según acción) o None para generación de claves
        action: 'encrypt', 'decrypt' o 'generate_keys'
        metadata: Metadatos necesarios para desencriptar (iv, datos de clave AES)
        
    Returns:
        Según action:
        - 'generate_keys': (public_key_pem, private_key_pem)
        - 'encrypt': (encrypted_base64, metadata_json)
        - 'decrypt': decrypted_text
    """
    import json
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Hash import SHA256
    
    if action == 'generate_keys':
        # Generar par de claves RSA
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return public_key, private_key
    
    elif action == 'encrypt':
        # Convertir clave pública de PEM a objeto RSA
        public_key = RSA.import_key(key)
        
        # Crear cifrador RSA-OAEP
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        # Generar clave AES aleatoria
        aes_key = get_random_bytes(32)  # AES-256
        
        # Generar IV aleatorio
        iv = get_random_bytes(16)
        
        # Encriptar datos con AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(text.encode('utf-8'), AES.block_size)
        ciphertext = cipher_aes.encrypt(padded_data)
        
        # Encriptar clave AES con RSA
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Codificar en base64
        encrypted_text = base64.b64encode(ciphertext).decode('utf-8')
        
        # Crear metadatos
        metadata = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8')
        }
        
        return encrypted_text, json.dumps(metadata)
    
    elif action == 'decrypt':
        # Convertir clave privada de PEM a objeto RSA
        private_key = RSA.import_key(key)
        
        # Crear descifrador RSA-OAEP
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        # Parsear metadatos
        metadata_dict = json.loads(metadata)
        iv = base64.b64decode(metadata_dict['iv'])
        encrypted_aes_key = base64.b64decode(metadata_dict['encrypted_aes_key'])
        
        # Desencriptar clave AES con RSA
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        # Desencriptar datos con AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = base64.b64decode(text)
        padded_plaintext = cipher_aes.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        return plaintext.decode('utf-8')

# Funciones de hash
def calculate_hash(text: str, algorithm: str = 'sha256') -> str:
    """
    Calcula el hash de un texto con el algoritmo especificado.
    
    Args:
        text: Texto a hashear
        algorithm: Algoritmo de hash (md5, sha1, sha256, sha512)
        
    Returns:
        Valor hash en hexadecimal
    """
    data = text.encode('utf-8')
    
    if algorithm == 'md5':
        return hashlib.md5(data).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(data).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Algoritmo de hash no soportado: {algorithm}")

# Funciones de firma digital
def sign_verify_message(message: Union[str, None], key: Union[str, None], action: str = 'sign', signature: str = None) -> Union[Tuple[str, str], str, bool]:
    """
    Firma o verifica un mensaje, o genera claves para firma digital.
    
    Args:
        message: Mensaje a firmar/verificar o None para generación de claves
        key: Clave privada (para firmar), pública (para verificar) o None para generación
        action: 'sign', 'verify' o 'generate_keys'
        signature: Firma en base64 (solo para verificar)
        
    Returns:
        Según action:
        - 'generate_keys': (public_key_pem, private_key_pem)
        - 'sign': signature_base64
        - 'verify': True/False
    """
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    
    if action == 'generate_keys':
        # Generar par de claves RSA
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return public_key, private_key
    
    elif action == 'sign':
        # Convertir clave privada de PEM a objeto RSA
        private_key = RSA.import_key(key)
        
        # Calcular hash del mensaje
        h = SHA256.new(message.encode('utf-8'))
        
        # Firmar el hash
        signer = pkcs1_15.new(private_key)
        signature = signer.sign(h)
        
        # Codificar en base64
        return base64.b64encode(signature).decode('utf-8')
    
    elif action == 'verify':
        # Convertir clave pública de PEM a objeto RSA
        public_key = RSA.import_key(key)
        
        # Calcular hash del mensaje
        h = SHA256.new(message.encode('utf-8'))
        
        # Verificar firma
        verifier = pkcs1_15.new(public_key)
        try:
            signature_bytes = base64.b64decode(signature)
            verifier.verify(h, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False

# Función para benchmark
def run_benchmark_for_ui(data_size: int = 1000, password: str = 'benchmark') -> Dict[str, Any]:
    """
    Ejecuta un benchmark rápido para la interfaz de usuario.
    
    Args:
        data_size: Tamaño de los datos de prueba en bytes
        password: Contraseña para algoritmos que la requieran
        
    Returns:
        Diccionario con resultados y gráfica
    """
    import time
    from algorithms.custom_encryption import CaosEncryption
    from algorithms.caos_v4 import CaosEncryption as CaosV4Encryption
    
    # Generar datos aleatorios
    data = os.urandom(data_size)
    
    # Preparar resultados
    results = {
        'data': [],
        'chart': None
    }
    
    # Benchmark AES
    start_time = time.time()
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    aes_encrypt_time = time.time() - start_time
    
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    aes_decrypt_time = time.time() - start_time
    
    results['data'].append({
        'algorithm': 'AES (Simétrico)',
        'encrypt_time': aes_encrypt_time,
        'decrypt_time': aes_decrypt_time
    })
    
    # Benchmark RSA (solo para tamaños pequeños)
    if data_size <= 190:  # Límite para RSA-2048 con OAEP
        start_time = time.time()
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        
        key = RSA.generate(2048)
        public_key = key.publickey()
        cipher = PKCS1_OAEP.new(public_key)
        rsa_ciphertext = cipher.encrypt(data)
        
        rsa_encrypt_time = time.time() - start_time
        
        start_time = time.time()
        decipher = PKCS1_OAEP.new(key)
        rsa_plaintext = decipher.decrypt(rsa_ciphertext)
        
        rsa_decrypt_time = time.time() - start_time
        
        results['data'].append({
            'algorithm': 'RSA (Asimétrico)',
            'encrypt_time': rsa_encrypt_time,
            'decrypt_time': rsa_decrypt_time
        })
    
    # Benchmark Híbrido
    start_time = time.time()
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    
    key_rsa = RSA.generate(2048)
    public_key = key_rsa.publickey()
    aes_key = get_random_bytes(32)
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    padded_data = pad(data, AES.block_size)
    hybrid_ciphertext = cipher_aes.encrypt(padded_data)
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    hybrid_encrypt_time = time.time() - start_time
    
    start_time = time.time()
    cipher_rsa = PKCS1_OAEP.new(key_rsa)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher_aes.decrypt(hybrid_ciphertext)
    hybrid_plaintext = unpad(padded_plaintext, AES.block_size)
    
    hybrid_decrypt_time = time.time() - start_time
    
    results['data'].append({
        'algorithm': 'Híbrido (RSA+AES)',
        'encrypt_time': hybrid_encrypt_time,
        'decrypt_time': hybrid_decrypt_time
    })
    
    # Benchmark CAOS v3
    try:
        caos = CaosEncryption(password)
        
        start_time = time.time()
        caos_ciphertext = caos.encrypt(data)
        caos_encrypt_time = time.time() - start_time
        
        start_time = time.time()
        caos_plaintext = caos.decrypt(caos_ciphertext)
        caos_decrypt_time = time.time() - start_time
        
        results['data'].append({
            'algorithm': 'CAOS v3 (Personalizado)',
            'encrypt_time': caos_encrypt_time,
            'decrypt_time': caos_decrypt_time
        })
    except Exception as e:
        print(f"Error en CAOS v3: {e}")
    
    # Benchmark CAOS v4
    try:
        from algorithms.caos_v4 import encrypt as caos_v4_encrypt, decrypt as caos_v4_decrypt
        
        start_time = time.time()
        caosv4_ciphertext = caos_v4_encrypt(data, password, iterations=1000)
        caosv4_encrypt_time = time.time() - start_time
        
        start_time = time.time()
        caosv4_plaintext = caos_v4_decrypt(caosv4_ciphertext, password, iterations=1000)
        caosv4_decrypt_time = time.time() - start_time
        
        results['data'].append({
            'algorithm': 'CAOS v4 (AES-GCM)',
            'encrypt_time': caosv4_encrypt_time,
            'decrypt_time': caosv4_decrypt_time
        })
    except Exception as e:
        print(f"Error en CAOS v4: {e}")
    
    # Crear gráfica
    plt.figure(figsize=(10, 6))
    
    # Datos para el gráfico
    algorithms = [result['algorithm'] for result in results['data']]
    encrypt_times = [result['encrypt_time'] for result in results['data']]
    decrypt_times = [result['decrypt_time'] for result in results['data']]
    
    # Graficar
    bar_width = 0.35
    x = range(len(algorithms))
    plt.bar([i - bar_width/2 for i in x], encrypt_times, bar_width, label='Encriptación')
    plt.bar([i + bar_width/2 for i in x], decrypt_times, bar_width, label='Desencriptación')
    
    plt.xlabel('Algoritmo')
    plt.ylabel('Tiempo (segundos)')
    plt.title(f'Comparativa de Rendimiento (Tamaño: {data_size} bytes)')
    plt.xticks(x, algorithms, rotation=30, ha='right')
    plt.legend()
    plt.tight_layout()
    
    results['chart'] = plt
    
    return results 