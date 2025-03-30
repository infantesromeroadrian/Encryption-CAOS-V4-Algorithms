#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de encriptación asimétrica en Python.
Este script demuestra el uso de algoritmos de encriptación asimétrica como RSA.
"""

import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def rsa_example_with_cryptography():
    """Ejemplo de encriptación RSA usando la biblioteca cryptography."""
    print("=" * 50)
    print("ENCRIPTACIÓN RSA CON CRYPTOGRAPHY")
    print("=" * 50)
    
    # Generar un par de claves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Exponente público estándar
        key_size=2048,          # Tamaño de clave en bits
    )
    public_key = private_key.public_key()
    
    print("Par de claves RSA generado:")
    print(f"- Tamaño de clave: 2048 bits")
    print(f"- Exponente público: 65537")
    
    # Serializar las claves para mostrarlas
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print("\nClave privada (PEM):")
    print(private_pem.decode('utf-8')[:100] + "...")
    
    print("\nClave pública (PEM):")
    print(public_pem.decode('utf-8'))
    
    # Mensaje a encriptar
    mensaje = "Este es un mensaje secreto que será encriptado con RSA."
    print(f"\nMensaje original: {mensaje}")
    
    # Encriptar el mensaje con la clave pública
    ciphertext = public_key.encrypt(
        mensaje.encode('utf-8'),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Mensaje encriptado (en base64): {base64.b64encode(ciphertext).decode()}")
    
    # Desencriptar el mensaje con la clave privada
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
    print("\n")

def rsa_example_with_pycryptodome():
    """Ejemplo de encriptación RSA usando la biblioteca PyCryptodome."""
    print("=" * 50)
    print("ENCRIPTACIÓN RSA CON PYCRYPTODOME")
    print("=" * 50)
    
    # Generar un par de claves RSA
    key = RSA.generate(2048)
    
    print("Par de claves RSA generado:")
    print(f"- Tamaño de clave: {key.size_in_bits()} bits")
    print(f"- Exponente público: {key.e}")
    print(f"- Módulo (n): {str(key.n)[:20]}...")
    
    # Extraer la clave pública
    public_key = key.publickey()
    
    # Mensaje a encriptar
    mensaje = "Este es otro mensaje secreto para encriptar con RSA usando PyCryptodome."
    print(f"\nMensaje original: {mensaje}")
    
    # Crear un cifrador PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(public_key)
    
    # Encriptar el mensaje
    ciphertext = cipher.encrypt(mensaje.encode('utf-8'))
    
    print(f"Mensaje encriptado (en base64): {base64.b64encode(ciphertext).decode()}")
    
    # Desencriptar el mensaje
    decipher = PKCS1_OAEP.new(key)
    plaintext = decipher.decrypt(ciphertext)
    
    print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
    print("\n")

def rsa_key_storage_example():
    """Ejemplo de almacenamiento y carga de claves RSA."""
    print("=" * 50)
    print("ALMACENAMIENTO Y CARGA DE CLAVES RSA")
    print("=" * 50)
    
    # Nombres de archivo para las claves
    private_key_file = "private_key.pem"
    public_key_file = "public_key.pem"
    
    # Generar un par de claves RSA
    key = RSA.generate(2048)
    
    # Guardar la clave privada
    with open(private_key_file, "wb") as f:
        f.write(key.export_key('PEM'))
    
    print(f"Clave privada guardada en: {private_key_file}")
    
    # Guardar la clave pública
    with open(public_key_file, "wb") as f:
        f.write(key.publickey().export_key('PEM'))
    
    print(f"Clave pública guardada en: {public_key_file}")
    
    # Cargar las claves desde los archivos
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())
    
    print("\nClaves cargadas correctamente desde los archivos.")
    
    # Verificar que las claves funcionan
    mensaje = "Mensaje de prueba para verificar las claves cargadas."
    print(f"Mensaje original: {mensaje}")
    
    # Encriptar con la clave pública cargada
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(mensaje.encode('utf-8'))
    
    # Desencriptar con la clave privada cargada
    decipher = PKCS1_OAEP.new(private_key)
    plaintext = decipher.decrypt(ciphertext)
    
    print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
    
    # Limpiar: eliminar los archivos de claves
    os.remove(private_key_file)
    os.remove(public_key_file)
    print(f"Archivos de claves eliminados.")
    print("\n")

def digital_signature_example():
    """Ejemplo de firma digital usando RSA."""
    print("=" * 50)
    print("FIRMA DIGITAL CON RSA")
    print("=" * 50)
    
    # Generar un par de claves RSA
    key = RSA.generate(2048)
    
    # Mensaje a firmar
    mensaje = "Este mensaje será firmado digitalmente para verificar su autenticidad."
    print(f"Mensaje original: {mensaje}")
    
    # Calcular el hash del mensaje
    h = SHA256.new(mensaje.encode('utf-8'))
    
    # Firmar el hash con la clave privada
    signature = pkcs1_15.new(key).sign(h)
    
    print(f"Firma digital (en base64): {base64.b64encode(signature).decode()}")
    
    # Verificar la firma con la clave pública
    public_key = key.publickey()
    
    print("\nVerificación de la firma:")
    
    try:
        # Calcular el hash del mensaje recibido
        h = SHA256.new(mensaje.encode('utf-8'))
        
        # Verificar la firma
        pkcs1_15.new(public_key).verify(h, signature)
        print("✓ Firma válida: El mensaje es auténtico y no ha sido alterado.")
    except (ValueError, TypeError):
        print("✗ Firma inválida: El mensaje puede haber sido alterado.")
    
    # Demostrar qué sucede si el mensaje es alterado
    print("\nSimulación de alteración del mensaje:")
    
    # Mensaje alterado
    mensaje_alterado = mensaje + " (alterado)"
    print(f"Mensaje alterado: {mensaje_alterado}")
    
    try:
        # Calcular el hash del mensaje alterado
        h = SHA256.new(mensaje_alterado.encode('utf-8'))
        
        # Verificar la firma con el mensaje alterado
        pkcs1_15.new(public_key).verify(h, signature)
        print("✓ Firma válida: El mensaje es auténtico y no ha sido alterado.")
    except (ValueError, TypeError):
        print("✗ Firma inválida: El mensaje ha sido alterado.")
    
    print("\n")

def rsa_limitations_example():
    """Ejemplo que muestra las limitaciones de RSA para mensajes largos."""
    print("=" * 50)
    print("LIMITACIONES DE RSA PARA MENSAJES LARGOS")
    print("=" * 50)
    
    # Generar un par de claves RSA
    key = RSA.generate(2048)
    public_key = key.publickey()
    
    # Crear un cifrador PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(public_key)
    
    # Calcular el tamaño máximo de mensaje que se puede encriptar
    # Para RSA-2048 con OAEP y SHA-256, el tamaño máximo es aproximadamente:
    # 2048/8 - 2*hash_size - 2 = 256 - 2*32 - 2 = 190 bytes
    max_message_size = 190
    
    print(f"Tamaño máximo de mensaje para RSA-2048 con OAEP: {max_message_size} bytes")
    
    # Mensaje corto (dentro del límite)
    mensaje_corto = "Este es un mensaje corto que cabe en un solo bloque RSA."
    print(f"\nMensaje corto ({len(mensaje_corto.encode('utf-8'))} bytes): {mensaje_corto}")
    
    # Encriptar el mensaje corto
    try:
        ciphertext = cipher.encrypt(mensaje_corto.encode('utf-8'))
        print("✓ Encriptación exitosa del mensaje corto.")
        
        # Desencriptar para verificar
        decipher = PKCS1_OAEP.new(key)
        plaintext = decipher.decrypt(ciphertext)
        print(f"  Mensaje desencriptado: {plaintext.decode('utf-8')}")
    except ValueError as e:
        print(f"✗ Error al encriptar el mensaje corto: {e}")
    
    # Mensaje largo (excede el límite)
    mensaje_largo = "Este es un mensaje largo que excede el tamaño máximo que puede ser encriptado directamente con RSA. " * 3
    print(f"\nMensaje largo ({len(mensaje_largo.encode('utf-8'))} bytes): {mensaje_largo[:50]}...")
    
    # Intentar encriptar el mensaje largo
    try:
        ciphertext = cipher.encrypt(mensaje_largo.encode('utf-8'))
        print("✓ Encriptación exitosa del mensaje largo.")
    except ValueError as e:
        print(f"✗ Error al encriptar el mensaje largo: {e}")
    
    print("\nSolución: Para mensajes largos, se recomienda usar encriptación híbrida:")
    print("1. Generar una clave simétrica aleatoria (AES)")
    print("2. Encriptar el mensaje con la clave simétrica")
    print("3. Encriptar la clave simétrica con RSA")
    print("4. Transmitir tanto el mensaje encriptado como la clave encriptada")
    print("\n")

def main():
    """Función principal que ejecuta todos los ejemplos."""
    print("\n🔑 EJEMPLOS DE ENCRIPTACIÓN ASIMÉTRICA EN PYTHON 🔑\n")
    
    rsa_example_with_cryptography()
    rsa_example_with_pycryptodome()
    rsa_key_storage_example()
    digital_signature_example()
    rsa_limitations_example()
    
    print("=" * 50)
    print("CONCLUSIÓN")
    print("=" * 50)
    print("La encriptación asimétrica es fundamental para el intercambio seguro de claves y firmas digitales.")
    print("Recuerda:")
    print("- RSA es uno de los algoritmos asimétricos más utilizados.")
    print("- La clave pública se usa para encriptar, la privada para desencriptar.")
    print("- RSA tiene limitaciones en el tamaño de los datos que puede encriptar directamente.")
    print("- Para mensajes largos, se recomienda usar encriptación híbrida (combinación de simétrica y asimétrica).")
    print("- Las firmas digitales proporcionan autenticidad e integridad a los mensajes.")
    print("=" * 50)

if __name__ == "__main__":
    main() 