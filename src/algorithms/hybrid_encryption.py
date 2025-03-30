#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de encriptación híbrida en Python.
Este script demuestra cómo combinar encriptación simétrica (AES) y asimétrica (RSA)
para aprovechar las ventajas de ambos sistemas.
"""

import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

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
    
    # Mostrar el contenido del archivo desencriptado
    with open(decrypted_filename, "r") as f:
        content = f.read()
    
    print("\nContenido del archivo desencriptado:")
    print("-" * 40)
    print(content)
    print("-" * 40)
    
    # Limpiar: eliminar los archivos de ejemplo
    os.remove(filename)
    os.remove(encrypted_filename)
    os.remove(decrypted_filename)
    print(f"Archivos de ejemplo eliminados.")
    print("\n")

def hybrid_encryption_with_multiple_recipients():
    """Ejemplo de encriptación híbrida para múltiples destinatarios."""
    print("=" * 50)
    print("ENCRIPTACIÓN HÍBRIDA PARA MÚLTIPLES DESTINATARIOS")
    print("=" * 50)
    
    # Mensaje a encriptar
    mensaje = "Este mensaje confidencial está destinado a múltiples receptores."
    print(f"Mensaje original: {mensaje}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 1: Generar pares de claves RSA para cada receptor")
    
    # Generar pares de claves para tres receptores
    keys = [RSA.generate(2048) for _ in range(3)]
    private_keys = keys
    public_keys = [key.publickey() for key in keys]
    
    print(f"Pares de claves RSA generados para 3 receptores")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 2: Generar una única clave simétrica AES")
    
    # Generar una clave simétrica aleatoria para AES
    aes_key = get_random_bytes(32)  # 256 bits
    print(f"Clave AES generada: {base64.b64encode(aes_key).decode()}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 3: Encriptar el mensaje con AES")
    
    # Encriptar el mensaje con AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    mensaje_bytes = mensaje.encode('utf-8')
    ciphertext = cipher_aes.encrypt(pad(mensaje_bytes, AES.block_size))
    
    print(f"Mensaje encriptado con AES: {base64.b64encode(ciphertext).decode()}")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 4: Encriptar la clave AES con la clave pública de cada receptor")
    
    # Encriptar la clave AES con la clave pública de cada receptor
    encrypted_aes_keys = []
    for i, public_key in enumerate(public_keys):
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)
        encrypted_aes_keys.append(encrypted_key)
        print(f"Clave AES encriptada para receptor {i+1}: {base64.b64encode(encrypted_key).decode()[:30]}...")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 5: Enviar a cada receptor: su clave AES encriptada, IV y mensaje encriptado")
    
    # En un escenario real, enviaríamos a cada receptor:
    # 1. Su versión de la clave AES encriptada con su clave pública
    # 2. El IV
    # 3. El mensaje encriptado con AES
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 6: Desencriptar (simulación para el receptor 2)")
    
    # Simular la desencriptación para el receptor 2
    receptor_id = 1  # 0-indexed
    
    # Desencriptar la clave AES con la clave privada del receptor
    cipher_rsa = PKCS1_OAEP.new(private_keys[receptor_id])
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_keys[receptor_id])
    
    print(f"Receptor {receptor_id+1} desencripta la clave AES: {base64.b64encode(decrypted_aes_key).decode()}")
    
    # Desencriptar el mensaje con la clave AES
    cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher_aes.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    print(f"Receptor {receptor_id+1} desencripta el mensaje: {plaintext.decode('utf-8')}")
    
    print("\n")

def secure_key_exchange():
    """Ejemplo de intercambio seguro de claves usando encriptación híbrida."""
    print("=" * 50)
    print("INTERCAMBIO SEGURO DE CLAVES")
    print("=" * 50)
    
    print("Escenario: Alice quiere establecer una comunicación segura con Bob")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 1: Bob genera un par de claves RSA y comparte su clave pública")
    
    # Bob genera un par de claves RSA
    bob_key = RSA.generate(2048)
    bob_private_key = bob_key
    bob_public_key = bob_key.publickey()
    
    print("Bob genera un par de claves RSA")
    print("Bob comparte su clave pública con Alice")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 2: Alice genera una clave de sesión AES y la encripta con la clave pública de Bob")
    
    # Alice genera una clave de sesión AES
    session_key = get_random_bytes(32)  # 256 bits
    print(f"Alice genera una clave de sesión AES: {base64.b64encode(session_key).decode()[:30]}...")
    
    # Alice encripta la clave de sesión con la clave pública de Bob
    cipher_rsa = PKCS1_OAEP.new(bob_public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    
    print("Alice encripta la clave de sesión con la clave pública de Bob")
    print("Alice envía la clave de sesión encriptada a Bob")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 3: Bob desencripta la clave de sesión con su clave privada")
    
    # Bob desencripta la clave de sesión
    cipher_rsa = PKCS1_OAEP.new(bob_private_key)
    decrypted_session_key = cipher_rsa.decrypt(encrypted_session_key)
    
    print("Bob desencripta la clave de sesión con su clave privada")
    print(f"Bob obtiene la clave de sesión: {base64.b64encode(decrypted_session_key).decode()[:30]}...")
    
    print("\n" + "-" * 50 + "\n")
    print("PASO 4: Alice y Bob ahora pueden comunicarse usando encriptación AES")
    
    # Alice envía un mensaje a Bob
    mensaje_alice = "Hola Bob, este mensaje está encriptado con nuestra clave de sesión compartida."
    
    # Alice encripta el mensaje con la clave de sesión
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    iv_alice = cipher_aes.iv
    mensaje_alice_bytes = mensaje_alice.encode('utf-8')
    ciphertext_alice = cipher_aes.encrypt(pad(mensaje_alice_bytes, AES.block_size))
    
    print("Alice encripta un mensaje con la clave de sesión")
    print(f"Alice envía a Bob: IV y mensaje encriptado")
    
    # Bob desencripta el mensaje
    cipher_aes = AES.new(decrypted_session_key, AES.MODE_CBC, iv_alice)
    padded_plaintext = cipher_aes.decrypt(ciphertext_alice)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    print("\nBob desencripta el mensaje de Alice:")
    print(f"Mensaje: {plaintext.decode('utf-8')}")
    
    # Bob responde a Alice
    mensaje_bob = "Hola Alice, he recibido tu mensaje. Esta comunicación es segura."
    
    # Bob encripta el mensaje con la clave de sesión
    cipher_aes = AES.new(decrypted_session_key, AES.MODE_CBC)
    iv_bob = cipher_aes.iv
    mensaje_bob_bytes = mensaje_bob.encode('utf-8')
    ciphertext_bob = cipher_aes.encrypt(pad(mensaje_bob_bytes, AES.block_size))
    
    print("\nBob encripta una respuesta con la clave de sesión")
    print(f"Bob envía a Alice: IV y mensaje encriptado")
    
    # Alice desencripta el mensaje
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv_bob)
    padded_plaintext = cipher_aes.decrypt(ciphertext_bob)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    print("\nAlice desencripta el mensaje de Bob:")
    print(f"Mensaje: {plaintext.decode('utf-8')}")
    
    print("\n" + "-" * 50 + "\n")
    print("Ventajas de este enfoque:")
    print("1. La clave de sesión se transmite de forma segura")
    print("2. Solo se usa RSA una vez para intercambiar la clave de sesión")
    print("3. La comunicación posterior usa AES, que es más eficiente")
    print("4. Se puede generar una nueva clave de sesión periódicamente para mayor seguridad")
    
    print("\n")

def main():
    """Función principal que ejecuta todos los ejemplos."""
    print("\n🔐 EJEMPLOS DE ENCRIPTACIÓN HÍBRIDA EN PYTHON 🔐\n")
    
    basic_hybrid_encryption()
    hybrid_encryption_with_file()
    hybrid_encryption_with_multiple_recipients()
    secure_key_exchange()
    
    print("=" * 50)
    print("CONCLUSIÓN")
    print("=" * 50)
    print("La encriptación híbrida combina lo mejor de la encriptación simétrica y asimétrica.")
    print("Recuerda:")
    print("- Usa encriptación asimétrica (RSA) para intercambiar claves simétricas")
    print("- Usa encriptación simétrica (AES) para encriptar los datos reales")
    print("- Este enfoque es eficiente para mensajes de cualquier tamaño")
    print("- Es el método utilizado en protocolos como TLS/SSL (HTTPS)")
    print("- Permite comunicación segura incluso en canales inseguros")
    print("=" * 50)

if __name__ == "__main__":
    main() 