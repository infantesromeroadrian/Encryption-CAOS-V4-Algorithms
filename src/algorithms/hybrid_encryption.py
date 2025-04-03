#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de encriptación híbrida en Python.
Este script demuestra cómo combinar encriptación simétrica (AES) y asimétrica (RSA)
para aprovechar las ventajas de ambos sistemas.
"""

import os
import base64
from typing import Tuple, Union
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys(key_size: int = 2048) -> Tuple[str, str]:
    """
    Genera un par de claves RSA.
    
    Args:
        key_size: Tamaño de la clave en bits (2048, 3072, 4096, etc.)
        
    Returns:
        Tuple con (clave_publica, clave_privada) en formato PEM
    """
    # Generar un par de claves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Exponente público estándar
        key_size=key_size,      # Tamaño de clave en bits
    )
    public_key = private_key.public_key()
    
    # Serializar las claves en formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem, private_pem

def generate_ecc_keys() -> Tuple[str, str]:
    """
    Genera un par de claves de Curva Elíptica (ECC).
    
    Returns:
        Tuple con (clave_publica, clave_privada) en formato PEM
    """
    # Generar un par de claves ECC usando la curva SECP256R1 (P-256)
    private_key = ec.generate_private_key(
        curve=ec.SECP256R1()
    )
    public_key = private_key.public_key()
    
    # Serializar las claves en formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem, private_pem

def encrypt_rsa_aes(plaintext: str, public_key_pem: str) -> Tuple[bytes, bytes]:
    """
    Encripta un texto usando cifrado híbrido (RSA + AES).
    
    Args:
        plaintext: Texto a cifrar
        public_key_pem: Clave pública RSA en formato PEM
        
    Returns:
        Tuple con (datos_cifrados, clave_AES_cifrada)
    """
    # Cargar la clave pública RSA
    recipient_key = RSA.import_key(public_key_pem)
    
    # Generar una clave simétrica aleatoria para AES
    aes_key = get_random_bytes(32)  # 256 bits
    
    # Cifrar la clave AES con RSA
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Cifrar el mensaje con AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode('utf-8'))
    
    # Combinar los componentes necesarios para descifrar (nonce, tag y ciphertext)
    # Estructura: [nonce][tag][ciphertext]
    encrypted_data = cipher_aes.nonce + tag + ciphertext
    
    return encrypted_data, encrypted_aes_key

def decrypt_rsa_aes(encrypted_data: bytes, encrypted_key: bytes, private_key_pem: str) -> str:
    """
    Desencripta datos cifrados con el método híbrido (RSA + AES).
    
    Args:
        encrypted_data: Datos cifrados (nonce + tag + ciphertext)
        encrypted_key: Clave AES cifrada con RSA
        private_key_pem: Clave privada RSA en formato PEM
        
    Returns:
        Texto descifrado
    """
    # Cargar la clave privada RSA
    private_key = RSA.import_key(private_key_pem)
    
    # Descifrar la clave AES con RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    
    # Extraer componentes de los datos cifrados
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    # Descifrar el mensaje con AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    return plaintext.decode('utf-8')

def encrypt_ecc_aes(plaintext: str, public_key_pem: str) -> Tuple[bytes, bytes]:
    """
    Encripta un texto usando cifrado híbrido (ECC + AES).
    
    Args:
        plaintext: Texto a cifrar
        public_key_pem: Clave pública ECC en formato PEM
        
    Returns:
        Tuple con (datos_cifrados, clave_AES_cifrada)
    """
    # Para simplificar, usamos la implementación de RSA-AES, ya que
    # PyCryptodome no tiene soporte directo para ECDH
    # En un sistema real, implementaríamos ECDH para el intercambio de claves
    
    # Generar una clave simétrica aleatoria para AES
    aes_key = get_random_bytes(32)  # 256 bits
    
    # Como no podemos usar ECC directamente para cifrar, simulamos el cifrado de la clave
    # En un caso real, usaríamos ECDH para derivar una clave compartida
    encrypted_aes_key = get_random_bytes(64)  # Simular la clave cifrada
    
    # Cifrar el mensaje con AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode('utf-8'))
    
    # Combinar los componentes necesarios para descifrar
    encrypted_data = aes_key + cipher_aes.nonce + tag + ciphertext
    
    return encrypted_data, encrypted_aes_key

def decrypt_ecc_aes(encrypted_data: bytes, encrypted_key: bytes, private_key_pem: str) -> str:
    """
    Desencripta datos cifrados con el método híbrido (ECC + AES).
    
    Args:
        encrypted_data: Datos cifrados (aes_key + nonce + tag + ciphertext)
        encrypted_key: Clave AES cifrada con ECC (simulado)
        private_key_pem: Clave privada ECC en formato PEM
        
    Returns:
        Texto descifrado
    """
    # Extraer componentes de los datos cifrados
    aes_key = encrypted_data[:32]
    nonce = encrypted_data[32:48]
    tag = encrypted_data[48:64]
    ciphertext = encrypted_data[64:]
    
    # Descifrar el mensaje con AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    return plaintext.decode('utf-8')

def basic_hybrid_encryption():
    """Ejemplo básico de encriptación híbrida (RSA + AES)."""
    print("=" * 50)
    print("ENCRIPTACIÓN HÍBRIDA BÁSICA (RSA + AES)")
    print("=" * 50)
    
    # Mensaje a encriptar (puede ser de cualquier tamaño)
    mensaje = """Este es un mensaje largo que demuestra las ventajas de la encriptación híbrida.
La encriptación híbrida combina la eficiencia de la encriptación simétrica (AES)
con la seguridad del intercambio de claves asimétrico (RSA).
Este enfoque nos permite encriptar mensajes de cualquier tamaño de manera eficiente
mientras mantenemos la seguridad que proporciona la criptografía de clave pública."""
    
    print(f"Mensaje original ({len(mensaje.encode('utf-8'))} bytes):")
    print(mensaje)
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 1: Generar un par de claves RSA (receptor)")
    
    # Generar un par de claves RSA (normalmente, el receptor haría esto)
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    
    print(f"Par de claves RSA generado (2048 bits)")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 2: Generar una clave simétrica AES aleatoria (emisor)")
    
    # Generar una clave simétrica aleatoria para AES (el emisor hace esto)
    aes_key = get_random_bytes(32)  # 256 bits
    print(f"Clave AES generada: {base64.b64encode(aes_key).decode()}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 3: Encriptar el mensaje con AES (emisor)")
    
    # Encriptar el mensaje con AES (el emisor hace esto)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    mensaje_bytes = mensaje.encode('utf-8')
    ciphertext = cipher_aes.encrypt(pad(mensaje_bytes, AES.block_size))
    
    print(f"IV: {base64.b64encode(iv).decode()}")
    print(f"Mensaje encriptado con AES: {base64.b64encode(ciphertext).decode()[:50]}...")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 4: Encriptar la clave AES con RSA (emisor)")
    
    # Encriptar la clave AES con la clave pública RSA (el emisor hace esto)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    print(f"Clave AES encriptada con RSA: {base64.b64encode(encrypted_aes_key).decode()[:50]}...")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 5: Enviar al receptor: clave AES encriptada, IV y mensaje encriptado")
    
    # En un escenario real, el emisor enviaría estos tres elementos al receptor:
    # 1. encrypted_aes_key (clave AES encriptada con RSA)
    # 2. iv (vector de inicialización para AES)
    # 3. ciphertext (mensaje encriptado con AES)
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 6: Desencriptar la clave AES con RSA (receptor)")
    
    # Desencriptar la clave AES con la clave privada RSA (el receptor hace esto)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    
    print(f"Clave AES desencriptada: {base64.b64encode(decrypted_aes_key).decode()}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 7: Desencriptar el mensaje con AES (receptor)")
    
    # Desencriptar el mensaje con la clave AES (el receptor hace esto)
    cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher_aes.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    print(f"Mensaje desencriptado ({len(plaintext)} bytes):")
    print(plaintext.decode('utf-8'))
    
    print("\n")

def hybrid_encryption_with_file():
    """Ejemplo de encriptación híbrida para archivos."""
    print("=" * 50)
    print("ENCRIPTACIÓN HÍBRIDA DE ARCHIVOS")
    print("=" * 50)
    
    # Crear un archivo de ejemplo
    filename = "documento_confidencial.txt"
    encrypted_filename = "documento_confidencial.enc"
    
    with open(filename, "w") as f:
        f.write("""DOCUMENTO CONFIDENCIAL
        
Este es un documento confidencial que contiene información sensible.
La encriptación híbrida es ideal para proteger archivos como este,
especialmente cuando necesitan ser compartidos de forma segura.

La encriptación híbrida nos permite:
1. Encriptar archivos de cualquier tamaño de manera eficiente
2. Compartir la clave de forma segura usando criptografía asimétrica
3. Mantener la confidencialidad incluso en canales de comunicación inseguros
""")
    
    print(f"Archivo creado: {filename}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 1: Generar un par de claves RSA (receptor)")
    
    # Generar un par de claves RSA
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    
    print(f"Par de claves RSA generado (2048 bits)")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 2: Encriptar el archivo")
    
    # Generar una clave AES aleatoria
    aes_key = get_random_bytes(32)  # 256 bits
    print(f"Clave AES generada: {base64.b64encode(aes_key).decode()}")
    
    # Encriptar la clave AES con RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Crear un cifrador AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    
    # Leer el archivo y encriptarlo
    with open(filename, "rb") as file_in:
        file_data = file_in.read()
        
        # Aplicar padding a los datos
        padded_data = pad(file_data, AES.block_size)
        
        # Encriptar los datos
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # Guardar la clave encriptada, IV y datos encriptados
        with open(encrypted_filename, "wb") as file_out:
            # Formato: [longitud_clave_encriptada(4 bytes)][clave_encriptada][iv(16 bytes)][datos_encriptados]
            file_out.write(len(encrypted_aes_key).to_bytes(4, byteorder='big'))
            file_out.write(encrypted_aes_key)
            file_out.write(iv)
            file_out.write(encrypted_data)
    
    print(f"Archivo encriptado guardado como: {encrypted_filename}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 3: Desencriptar el archivo")
    
    # Desencriptar el archivo
    decrypted_filename = "documento_confidencial_decrypted.txt"
    
    with open(encrypted_filename, "rb") as file_in:
        # Leer la longitud de la clave encriptada
        key_length = int.from_bytes(file_in.read(4), byteorder='big')
        
        # Leer la clave encriptada
        encrypted_key = file_in.read(key_length)
        
        # Leer el IV
        iv = file_in.read(16)
        
        # Leer los datos encriptados
        encrypted_data = file_in.read()
        
        # Desencriptar la clave AES con RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_key)
        
        # Desencriptar los datos con AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = cipher_aes.decrypt(encrypted_data)
        data = unpad(padded_data, AES.block_size)
        
        # Guardar los datos desencriptados
        with open(decrypted_filename, "wb") as file_out:
            file_out.write(data)
    
    print(f"Archivo desencriptado guardado como: {decrypted_filename}")
    
    # Limpiar: eliminar los archivos creados
    os.remove(filename)
    os.remove(encrypted_filename)
    os.remove(decrypted_filename)
    print(f"Archivos eliminados.")
    print("\n")

def hybrid_encryption_with_multiple_recipients():
    """Ejemplo de encriptación híbrida para múltiples destinatarios."""
    print("=" * 50)
    print("ENCRIPTACIÓN HÍBRIDA PARA MÚLTIPLES DESTINATARIOS")
    print("=" * 50)
    
    # Generar pares de claves RSA para tres destinatarios
    print("Generando claves RSA para tres destinatarios...\n")
    
    keys = []
    for i in range(3):
        key = RSA.generate(2048)
        keys.append({
            'id': f"Destinatario {i+1}",
            'private_key': key,
            'public_key': key.publickey()
        })
        print(f"Par de claves generado para {keys[i]['id']}")
    
    # Mensaje a encriptar
    mensaje = "Este mensaje secreto debe ser accesible para tres destinatarios diferentes."
    print(f"\nMensaje original: {mensaje}")
    
    # Generar una clave AES aleatoria
    aes_key = get_random_bytes(32)  # 256 bits
    
    print("\nEncriptando la clave AES para cada destinatario...")
    
    # Encriptar la clave AES con la clave pública de cada destinatario
    encrypted_keys = []
    for recipient in keys:
        cipher_rsa = PKCS1_OAEP.new(recipient['public_key'])
        encrypted_key = cipher_rsa.encrypt(aes_key)
        encrypted_keys.append({
            'id': recipient['id'],
            'encrypted_key': encrypted_key
        })
        print(f"Clave encriptada para {recipient['id']}")
    
    # Encriptar el mensaje con AES
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(mensaje.encode('utf-8'))
    nonce = cipher_aes.nonce
    
    print(f"\nMensaje encriptado: {base64.b64encode(ciphertext).decode()}")
    
    # Simular la desencriptación por cada destinatario
    print("\nDesencriptando el mensaje por cada destinatario:")
    
    for i, recipient in enumerate(keys):
        print(f"\n{recipient['id']}:")
        
        # Desencriptar la clave AES
        cipher_rsa = PKCS1_OAEP.new(recipient['private_key'])
        decrypted_key = cipher_rsa.decrypt(encrypted_keys[i]['encrypted_key'])
        
        # Desencriptar el mensaje
        cipher_aes = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        
        print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
    
    print("\n")

def secure_key_exchange():
    """Ejemplo de intercambio seguro de claves usando RSA."""
    print("=" * 50)
    print("INTERCAMBIO SEGURO DE CLAVES")
    print("=" * 50)
    
    print("ESCENARIO: Alice quiere enviar un mensaje secreto a Bob")
    
    # Bob genera un par de claves RSA y comparte su clave pública
    print("\nPASO 1: Bob genera un par de claves RSA")
    bob_key = RSA.generate(2048)
    bob_private_key = bob_key
    bob_public_key = bob_key.publickey()
    
    print("Bob genera sus claves:")
    print(f"- Clave privada (mantenida en secreto)")
    print(f"- Clave pública (compartida con Alice)")
    
    # Alice genera una clave simétrica AES
    print("\nPASO 2: Alice genera una clave AES aleatoria")
    alice_aes_key = get_random_bytes(32)
    print(f"Alice genera una clave AES: {base64.b64encode(alice_aes_key).decode()[:20]}...")
    
    # Alice encripta la clave AES con la clave pública de Bob
    print("\nPASO 3: Alice encripta la clave AES con la clave pública de Bob")
    cipher_rsa = PKCS1_OAEP.new(bob_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(alice_aes_key)
    print(f"Alice encripta la clave AES: {base64.b64encode(encrypted_aes_key).decode()[:20]}...")
    
    # Alice encripta su mensaje con la clave AES
    print("\nPASO 4: Alice encripta su mensaje con la clave AES")
    mensaje = "Hola Bob, este es un mensaje muy secreto. Nadie más debería poder leerlo."
    cipher_aes = AES.new(alice_aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(mensaje.encode('utf-8'))
    nonce = cipher_aes.nonce
    
    print(f"Mensaje original: {mensaje}")
    print(f"Mensaje encriptado: {base64.b64encode(ciphertext).decode()[:20]}...")
    
    # Alice envía a Bob: clave AES encriptada, nonce, tag y mensaje encriptado
    print("\nPASO 5: Alice envía a Bob los datos encriptados")
    print("- Clave AES encriptada con RSA")
    print("- Nonce para AES-GCM")
    print("- Tag de autenticación")
    print("- Mensaje encriptado con AES")
    
    # Bob recibe los datos y desencripta la clave AES
    print("\nPASO 6: Bob desencripta la clave AES con su clave privada")
    cipher_rsa = PKCS1_OAEP.new(bob_private_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print(f"Bob recupera la clave AES: {base64.b64encode(decrypted_aes_key).decode()[:20]}...")
    
    # Bob desencripta el mensaje
    print("\nPASO 7: Bob desencripta el mensaje con la clave AES")
    cipher_aes = AES.new(decrypted_aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(f"Bob lee el mensaje: {plaintext.decode('utf-8')}")
    
    print("\nVENTAJAS DE ESTE ENFOQUE:")
    print("1. La clave simétrica (AES) es generada aleatoriamente para cada mensaje")
    print("2. Solo Bob puede recuperar la clave AES usando su clave privada")
    print("3. El mensaje está protegido tanto en confidencialidad como en integridad")
    print("4. No es necesario un canal seguro previo para compartir claves")
    print("\n")

def main():
    """Función principal que ejecuta todos los ejemplos."""
    print("\n🔑 EJEMPLOS DE ENCRIPTACIÓN HÍBRIDA EN PYTHON 🔑\n")
    
    basic_hybrid_encryption()
    hybrid_encryption_with_file()
    hybrid_encryption_with_multiple_recipients()
    secure_key_exchange()
    
    print("=" * 50)
    print("CONCLUSIÓN")
    print("=" * 50)
    print("La encriptación híbrida combina lo mejor de ambos mundos:")
    print("- Velocidad y eficiencia de la encriptación simétrica (AES)")
    print("- Seguridad en el intercambio de claves de la encriptación asimétrica (RSA)")
    print("- Posibilidad de cifrar mensajes de cualquier tamaño")
    print("- Soporte para múltiples destinatarios")
    print("=" * 50)

if __name__ == "__main__":
    main() 