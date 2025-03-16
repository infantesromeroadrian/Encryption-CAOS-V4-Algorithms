#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de firmas digitales en Python.
Este script demuestra el uso de diferentes algoritmos para crear y verificar firmas digitales.
"""

import os
import base64
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256, SHA384, SHA512

def rsa_signature_with_cryptography():
    """Ejemplo de firma digital RSA usando la biblioteca cryptography."""
    print("=" * 50)
    print("FIRMA DIGITAL RSA CON CRYPTOGRAPHY")
    print("=" * 50)
    
    # Generar un par de claves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    print("Par de claves RSA generado:")
    print(f"- Tamaño de clave: 2048 bits")
    print(f"- Exponente público: 65537")
    
    # Mensaje a firmar
    mensaje = "Este mensaje será firmado digitalmente para verificar su autenticidad e integridad."
    print(f"\nMensaje original: {mensaje}")
    
    # Firmar el mensaje
    signature = private_key.sign(
        mensaje.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print(f"Firma digital (en base64): {base64.b64encode(signature).decode()[:50]}...")
    
    # Verificar la firma
    print("\nVerificación de la firma:")
    
    try:
        public_key.verify(
            signature,
            mensaje.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✓ Firma válida: El mensaje es auténtico y no ha sido alterado.")
    except InvalidSignature:
        print("✗ Firma inválida: El mensaje puede haber sido alterado.")
    
    # Demostrar qué sucede si el mensaje es alterado
    print("\nSimulación de alteración del mensaje:")
    
    # Mensaje alterado
    mensaje_alterado = mensaje + " (alterado)"
    print(f"Mensaje alterado: {mensaje_alterado}")
    
    try:
        public_key.verify(
            signature,
            mensaje_alterado.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✓ Firma válida: El mensaje es auténtico y no ha sido alterado.")
    except InvalidSignature:
        print("✗ Firma inválida: El mensaje ha sido alterado.")
    
    print("\n")

def rsa_signature_with_pycryptodome():
    """Ejemplo de firma digital RSA usando la biblioteca PyCryptodome."""
    print("=" * 50)
    print("FIRMA DIGITAL RSA CON PYCRYPTODOME")
    print("=" * 50)
    
    # Generar un par de claves RSA
    key = RSA.generate(2048)
    
    print("Par de claves RSA generado:")
    print(f"- Tamaño de clave: {key.size_in_bits()} bits")
    print(f"- Exponente público: {key.e}")
    
    # Mensaje a firmar
    mensaje = "Este es otro mensaje para firmar con RSA usando PyCryptodome."
    print(f"\nMensaje original: {mensaje}")
    
    # Calcular el hash del mensaje
    h = SHA256.new(mensaje.encode('utf-8'))
    
    # Firmar el hash con la clave privada
    signature = pkcs1_15.new(key).sign(h)
    
    print(f"Firma digital (en base64): {base64.b64encode(signature).decode()[:50]}...")
    
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

def ecdsa_signature():
    """Ejemplo de firma digital ECDSA (Elliptic Curve Digital Signature Algorithm)."""
    print("=" * 50)
    print("FIRMA DIGITAL ECDSA")
    print("=" * 50)
    
    # Generar un par de claves ECC (Elliptic Curve Cryptography)
    key = ECC.generate(curve='P-256')
    
    print("Par de claves ECC generado:")
    print(f"- Curva: NIST P-256")
    print(f"- Tamaño de clave: 256 bits")
    
    # Mensaje a firmar
    mensaje = "Este mensaje será firmado con ECDSA, que es más eficiente que RSA."
    print(f"\nMensaje original: {mensaje}")
    
    # Calcular el hash del mensaje
    h = SHA256.new(mensaje.encode('utf-8'))
    
    # Crear un objeto de firma
    signer = DSS.new(key, 'fips-186-3')
    
    # Medir el tiempo de firma
    start_time = time.time()
    signature = signer.sign(h)
    end_time = time.time()
    
    print(f"Firma digital (en base64): {base64.b64encode(signature).decode()[:50]}...")
    print(f"Tiempo de firma: {(end_time - start_time):.6f} segundos")
    
    # Verificar la firma con la clave pública
    public_key = key.public_key()
    
    print("\nVerificación de la firma:")
    
    # Medir el tiempo de verificación
    start_time = time.time()
    try:
        # Calcular el hash del mensaje recibido
        h = SHA256.new(mensaje.encode('utf-8'))
        
        # Crear un objeto de verificación
        verifier = DSS.new(public_key, 'fips-186-3')
        
        # Verificar la firma
        verifier.verify(h, signature)
        end_time = time.time()
        print("✓ Firma válida: El mensaje es auténtico y no ha sido alterado.")
        print(f"Tiempo de verificación: {(end_time - start_time):.6f} segundos")
    except (ValueError, TypeError):
        end_time = time.time()
        print("✗ Firma inválida: El mensaje puede haber sido alterado.")
        print(f"Tiempo de verificación: {(end_time - start_time):.6f} segundos")
    
    print("\n")

def compare_signature_algorithms():
    """Comparación de diferentes algoritmos de firma digital."""
    print("=" * 50)
    print("COMPARACIÓN DE ALGORITMOS DE FIRMA DIGITAL")
    print("=" * 50)
    
    # Mensaje a firmar
    mensaje = "Este mensaje será firmado con diferentes algoritmos para comparar su rendimiento y tamaño de firma."
    print(f"Mensaje original ({len(mensaje.encode('utf-8'))} bytes): {mensaje}")
    
    print("\n" + "-" * 40 + "\n")
    
    # Generar claves para cada algoritmo
    rsa_key_2048 = RSA.generate(2048)
    rsa_key_4096 = RSA.generate(4096)
    ec_key_p256 = ECC.generate(curve='P-256')
    ec_key_p384 = ECC.generate(curve='P-384')
    ec_key_p521 = ECC.generate(curve='P-521')
    
    # Calcular hashes con diferentes algoritmos
    hash_sha256 = SHA256.new(mensaje.encode('utf-8'))
    hash_sha384 = SHA384.new(mensaje.encode('utf-8'))
    hash_sha512 = SHA512.new(mensaje.encode('utf-8'))
    
    # Tabla de resultados
    print("| Algoritmo          | Tamaño de clave | Tamaño de firma | Tiempo de firma | Tiempo de verificación |")
    print("|--------------------|-----------------|-----------------|-----------------|-----------------------|")
    
    # RSA-2048 con SHA-256
    start_time = time.time()
    signature = pkcs1_15.new(rsa_key_2048).sign(hash_sha256)
    sign_time = time.time() - start_time
    
    start_time = time.time()
    try:
        pkcs1_15.new(rsa_key_2048.publickey()).verify(hash_sha256, signature)
        verify_result = "✓"
    except:
        verify_result = "✗"
    verify_time = time.time() - start_time
    
    print(f"| RSA-2048 + SHA-256 | 2048 bits       | {len(signature)} bytes      | {sign_time:.6f} s     | {verify_time:.6f} s {verify_result}         |")
    
    # RSA-4096 con SHA-256
    start_time = time.time()
    signature = pkcs1_15.new(rsa_key_4096).sign(hash_sha256)
    sign_time = time.time() - start_time
    
    start_time = time.time()
    try:
        pkcs1_15.new(rsa_key_4096.publickey()).verify(hash_sha256, signature)
        verify_result = "✓"
    except:
        verify_result = "✗"
    verify_time = time.time() - start_time
    
    print(f"| RSA-4096 + SHA-256 | 4096 bits       | {len(signature)} bytes      | {sign_time:.6f} s     | {verify_time:.6f} s {verify_result}         |")
    
    # ECDSA P-256 con SHA-256
    signer = DSS.new(ec_key_p256, 'fips-186-3')
    start_time = time.time()
    signature = signer.sign(hash_sha256)
    sign_time = time.time() - start_time
    
    verifier = DSS.new(ec_key_p256.public_key(), 'fips-186-3')
    start_time = time.time()
    try:
        verifier.verify(hash_sha256, signature)
        verify_result = "✓"
    except:
        verify_result = "✗"
    verify_time = time.time() - start_time
    
    print(f"| ECDSA P-256 + SHA-256 | 256 bits      | {len(signature)} bytes       | {sign_time:.6f} s     | {verify_time:.6f} s {verify_result}         |")
    
    # ECDSA P-384 con SHA-384
    signer = DSS.new(ec_key_p384, 'fips-186-3')
    start_time = time.time()
    signature = signer.sign(hash_sha384)
    sign_time = time.time() - start_time
    
    verifier = DSS.new(ec_key_p384.public_key(), 'fips-186-3')
    start_time = time.time()
    try:
        verifier.verify(hash_sha384, signature)
        verify_result = "✓"
    except:
        verify_result = "✗"
    verify_time = time.time() - start_time
    
    print(f"| ECDSA P-384 + SHA-384 | 384 bits      | {len(signature)} bytes       | {sign_time:.6f} s     | {verify_time:.6f} s {verify_result}         |")
    
    # ECDSA P-521 con SHA-512
    signer = DSS.new(ec_key_p521, 'fips-186-3')
    start_time = time.time()
    signature = signer.sign(hash_sha512)
    sign_time = time.time() - start_time
    
    verifier = DSS.new(ec_key_p521.public_key(), 'fips-186-3')
    start_time = time.time()
    try:
        verifier.verify(hash_sha512, signature)
        verify_result = "✓"
    except:
        verify_result = "✗"
    verify_time = time.time() - start_time
    
    print(f"| ECDSA P-521 + SHA-512 | 521 bits      | {len(signature)} bytes       | {sign_time:.6f} s     | {verify_time:.6f} s {verify_result}         |")
    
    print("\nObservaciones:")
    print("- RSA produce firmas más grandes que ECDSA")
    print("- ECDSA es generalmente más rápido que RSA para el mismo nivel de seguridad")
    print("- El tamaño de la firma ECDSA es aproximadamente el doble del tamaño de la clave")
    print("- RSA-2048 es aproximadamente equivalente en seguridad a ECDSA P-256")
    print("- RSA-4096 es aproximadamente equivalente en seguridad a ECDSA P-384/P-521")
    
    print("\n")

def file_signature_example():
    """Ejemplo de firma digital para archivos."""
    print("=" * 50)
    print("FIRMA DIGITAL DE ARCHIVOS")
    print("=" * 50)
    
    # Crear un archivo de ejemplo
    filename = "documento_importante.txt"
    signature_filename = "documento_importante.sig"
    
    with open(filename, "w") as f:
        f.write("""DOCUMENTO IMPORTANTE
        
Este es un documento importante cuya autenticidad e integridad
necesita ser verificada. La firma digital nos permite asegurar
que el documento no ha sido alterado y que fue firmado por el
emisor legítimo.

Las firmas digitales son ampliamente utilizadas en documentos
legales, actualizaciones de software, certificados digitales,
y muchas otras aplicaciones donde la autenticidad es crucial.
""")
    
    print(f"Archivo creado: {filename}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 1: Generar un par de claves RSA")
    
    # Generar un par de claves RSA
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    
    print(f"Par de claves RSA generado (2048 bits)")
    
    # Guardar la clave pública para verificación posterior
    public_key_filename = "public_key.pem"
    with open(public_key_filename, "wb") as f:
        f.write(public_key.export_key('PEM'))
    
    print(f"Clave pública guardada en: {public_key_filename}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 2: Calcular el hash del archivo")
    
    # Calcular el hash SHA-256 del archivo
    with open(filename, "rb") as f:
        file_data = f.read()
        file_hash = SHA256.new(file_data)
    
    print(f"Hash SHA-256 del archivo: {file_hash.hexdigest()}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 3: Firmar el hash con la clave privada")
    
    # Firmar el hash con la clave privada
    signature = pkcs1_15.new(private_key).sign(file_hash)
    
    # Guardar la firma en un archivo
    with open(signature_filename, "wb") as f:
        f.write(signature)
    
    print(f"Firma digital guardada en: {signature_filename}")
    print(f"Tamaño de la firma: {len(signature)} bytes")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 4: Verificar la firma")
    
    # Cargar la clave pública
    with open(public_key_filename, "rb") as f:
        public_key_data = f.read()
        loaded_public_key = RSA.import_key(public_key_data)
    
    # Cargar la firma
    with open(signature_filename, "rb") as f:
        loaded_signature = f.read()
    
    # Calcular el hash del archivo a verificar
    with open(filename, "rb") as f:
        file_data = f.read()
        file_hash = SHA256.new(file_data)
    
    # Verificar la firma
    try:
        pkcs1_15.new(loaded_public_key).verify(file_hash, loaded_signature)
        print("✓ Firma válida: El archivo es auténtico y no ha sido alterado.")
    except (ValueError, TypeError):
        print("✗ Firma inválida: El archivo puede haber sido alterado.")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 5: Simular alteración del archivo")
    
    # Crear una versión alterada del archivo
    altered_filename = "documento_importante_alterado.txt"
    
    with open(filename, "r") as f:
        content = f.read()
    
    # Modificar el contenido
    altered_content = content.replace("importante", "modificado")
    
    with open(altered_filename, "w") as f:
        f.write(altered_content)
    
    print(f"Archivo alterado creado: {altered_filename}")
    
    # Calcular el hash del archivo alterado
    with open(altered_filename, "rb") as f:
        altered_file_data = f.read()
        altered_file_hash = SHA256.new(altered_file_data)
    
    print(f"Hash SHA-256 del archivo alterado: {altered_file_hash.hexdigest()}")
    
    # Verificar la firma con el archivo alterado
    try:
        pkcs1_15.new(loaded_public_key).verify(altered_file_hash, loaded_signature)
        print("✓ Firma válida: El archivo es auténtico y no ha sido alterado.")
    except (ValueError, TypeError):
        print("✗ Firma inválida: El archivo ha sido alterado.")
    
    # Limpiar: eliminar los archivos de ejemplo
    os.remove(filename)
    os.remove(signature_filename)
    os.remove(public_key_filename)
    os.remove(altered_filename)
    print(f"Archivos de ejemplo eliminados.")
    
    print("\n")

def main():
    """Función principal que ejecuta todos los ejemplos."""
    print("\n🔏 EJEMPLOS DE FIRMAS DIGITALES EN PYTHON 🔏\n")
    
    rsa_signature_with_cryptography()
    rsa_signature_with_pycryptodome()
    ecdsa_signature()
    compare_signature_algorithms()
    file_signature_example()
    
    print("=" * 50)
    print("CONCLUSIÓN")
    print("=" * 50)
    print("Las firmas digitales son fundamentales para garantizar la autenticidad e integridad de los datos.")
    print("Recuerda:")
    print("- La firma digital se crea con la clave privada del emisor")
    print("- La verificación se realiza con la clave pública del emisor")
    print("- RSA y ECDSA son los algoritmos de firma más utilizados")
    print("- ECDSA ofrece firmas más pequeñas y mayor eficiencia que RSA")
    print("- Las firmas digitales son la base de los certificados digitales, blockchain y más")
    print("=" * 50)

if __name__ == "__main__":
    main() 