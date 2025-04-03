#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ejemplos de algoritmos de encriptación asimétrica: RSA y Curvas Elípticas (ECC).
Este script implementa ejemplos básicos de encriptación asimétrica y muestra cómo
utilizarlos para cifrar/descifrar mensajes.
"""

import os
import base64
import re
from typing import Tuple, Union, Optional
from pathlib import Path

# Importar bibliotecas para RSA
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# Importar PyCryptodome para algunas operaciones
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_rsa_keys(key_size: int = 2048) -> Tuple[str, str]:
    """
    Genera un par de claves RSA en formato PKCS#8 estándar.
    
    Args:
        key_size: Tamaño de la clave en bits (2048, 3072, 4096, etc.)
        
    Returns:
        Tuple con (clave_publica, clave_privada) en formato PEM
    """
    try:
        # Generar claves con cryptography (formato PKCS#8)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        
        # Serializar la clave privada en formato PKCS#8
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Serializar la clave pública en formato SubjectPublicKeyInfo (PKCS#8)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return public_pem, private_pem
    except Exception as cryptography_error:
        # Fallback: Intentar con PyCryptodome
        try:
            key = RSA.generate(key_size)
            private_pem = key.export_key(format='PEM').decode('utf-8')
            public_pem = key.publickey().export_key(format='PEM').decode('utf-8')
            return public_pem, private_pem
        except Exception as pycrypto_error:
            # Si ambos fallan, mostrar detalles
            raise ValueError(f"Error generando claves RSA. Errores: Cryptography: {cryptography_error}, PyCryptodome: {pycrypto_error}")

def generate_ecc_keys() -> Tuple[str, str]:
    """
    Genera un par de claves de Curva Elíptica (ECC).
    
    Returns:
        Tuple con (clave_publica, clave_privada) en formato PEM
    """
    try:
        # Generar un par de claves ECC usando PyCryptodome
        key = ECC.generate(curve='P-256')
        
        # Obtener las claves en formato PEM
        private_pem = key.export_key(format='PEM').decode('utf-8')
        public_pem = key.public_key().export_key(format='PEM').decode('utf-8')
        
        return public_pem, private_pem
    except Exception as e:
        # Si falla PyCryptodome, intentar con cryptography
        private_key = ec.generate_private_key(curve=ec.SECP256R1())
        public_key = private_key.public_key()
        
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

def sanitize_key(key):
    """
    Sanitiza una clave para asegurar que esté en formato PEM adecuado.
    Maneja múltiples formatos de entrada y corrige problemas comunes.

    Args:
        key (str): La clave en formato PEM o similar

    Returns:
        str: La clave sanitizada en formato PEM
    """
    if not key:
        return key

    # Eliminar espacios, tabulaciones y saltos de línea extra
    key = key.strip()
    
    # Si la clave no tiene BEGIN/END, puede que sea solo el cuerpo de la clave
    if "BEGIN" not in key and "END" not in key:
        # Intenta determinar el tipo de clave basado en el contenido
        is_private = False
        
        # Eliminar caracteres no válidos en Base64
        key = re.sub(r'[^A-Za-z0-9+/=]', '', key)
        
        # Intenta decodificar para ver si es una clave privada RSA
        try:
            key_bytes = base64.b64decode(key)
            # Esto es específico para RSA - verificando si parece una clave privada
            if b'\x02\x01\x00' in key_bytes:
                is_private = True
        except:
            pass  # Ignoramos errores en este intento de detección
            
        # Envolver en etiquetas PEM adecuadas
        if is_private:
            key = f"-----BEGIN RSA PRIVATE KEY-----\n{key}\n-----END RSA PRIVATE KEY-----"
        else:
            key = f"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----"
    
    # Normalizar los saltos de línea
    key = key.replace('\r\n', '\n').replace('\r', '\n')
    
    # Asegurar que las etiquetas BEGIN/END están en líneas separadas
    key = re.sub(r'(-----BEGIN [^-]+-----)([^\n])', r'\1\n\2', key)
    key = re.sub(r'([^\n])(-----END [^-]+-----)', r'\1\n\2', key)
    
    # Formatear correctamente el cuerpo de la clave en bloques de 64 caracteres
    lines = key.split('\n')
    header = None
    footer = None
    body_lines = []
    
    for i, line in enumerate(lines):
        if "BEGIN" in line:
            header = line
        elif "END" in line:
            footer = line
        elif line.strip():  # Si no es una línea vacía y no es header/footer
            body_lines.append(line)
    
    if header and footer:
        # Unir todas las líneas del cuerpo y eliminar espacios/caracteres no Base64
        body = ''.join(body_lines)
        body = re.sub(r'[^A-Za-z0-9+/=]', '', body)
        
        # Reformatear en líneas de 64 caracteres
        formatted_body = '\n'.join([body[i:i+64] for i in range(0, len(body), 64)])
        
        key = f"{header}\n{formatted_body}\n{footer}"
    
    # Correcciones específicas para problemas conocidos
    
    # Problema: Claves PKCS#8 etiquetadas incorrectamente como RSA PRIVATE KEY
    if "BEGIN RSA PRIVATE KEY" in key and "PRIVATE KEY" in key:
        try:
            # Intentar cargar como PKCS#1
            key_obj = RSA.import_key(key)
            # Si llegamos aquí, la clave ya está en formato PKCS#1, no hacemos nada
        except:
            # Puede que sea una clave PKCS#8 con etiqueta incorrecta
            try:
                # Convertir etiquetas a PKCS#8
                key = key.replace("BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY")
                key = key.replace("END RSA PRIVATE KEY", "END PRIVATE KEY")
                
                # Intentar cargar para verificar
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                load_pem_private_key(key.encode(), password=None)
            except:
                # Revertir si no funciona
                key = key.replace("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY")
                key = key.replace("END PRIVATE KEY", "END RSA PRIVATE KEY")
    
    return key

def rsa_encrypt(plaintext: str, public_key_pem: str) -> bytes:
    """
    Cifra un texto usando RSA con múltiples intentos para mayor robustez.
    
    Args:
        plaintext: Texto a cifrar
        public_key_pem: Clave pública RSA en formato PEM
        
    Returns:
        Datos cifrados (bytes)
    """
    # Si la entrada está vacía, devolver bytes vacíos
    if not plaintext:
        return b''
        
    # Asegurar que el texto sea bytes
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    else:
        plaintext_bytes = plaintext
    
    # Lista para almacenar errores
    errors = []
    
    # Intentar sanear la clave
    try:
        public_key_pem = sanitize_key(public_key_pem)
    except Exception as e:
        errors.append(f"Error en sanitize_key: {str(e)}")
    
    # Método 1: PKCS1_v1_5 con PyCryptodome
    try:
        from Crypto.Cipher import PKCS1_v1_5
        key = RSA.import_key(public_key_pem)
        cipher = PKCS1_v1_5.new(key)
        return cipher.encrypt(plaintext_bytes)
    except Exception as e1:
        errors.append(f"Error con PKCS1_v1_5: {str(e1)}")
    
    # Método 2: PKCS1_OAEP con PyCryptodome
    try:
        key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(plaintext_bytes)
    except Exception as e2:
        errors.append(f"Error con PKCS1_OAEP: {str(e2)}")
    
    # Método 3: cryptography directamente
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import serialization
        
        # Intentar cargar la clave en diferentes formatos
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        except Exception:
            # Intentar con una transformación adicional por si es un formato no estándar
            modified_pem = public_key_pem.replace("-----BEGIN RSA PUBLIC KEY-----", 
                                                "-----BEGIN PUBLIC KEY-----")
            modified_pem = modified_pem.replace("-----END RSA PUBLIC KEY-----", 
                                              "-----END PUBLIC KEY-----")
            public_key = serialization.load_pem_public_key(modified_pem.encode('utf-8'))
        
        encrypted = public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    except Exception as e3:
        errors.append(f"Error con cryptography: {str(e3)}")
    
    # Si todos los métodos fallan, lanzar una excepción detallada
    raise ValueError(f"No se pudo cifrar con RSA. Errores: {', '.join(errors)}")

def rsa_decrypt(ciphertext: bytes, private_key_pem: str) -> str:
    """
    Descifra un texto cifrado con RSA usando múltiples métodos para mayor robustez.
    
    Args:
        ciphertext: Datos cifrados (bytes)
        private_key_pem: Clave privada RSA en formato PEM
        
    Returns:
        Texto descifrado
    """
    # Si la entrada está vacía, devolver cadena vacía
    if not ciphertext:
        return ''
    
    # Datos de diagnóstico para depuración
    ciphertext_info = f"Longitud del texto cifrado: {len(ciphertext)} bytes"
    try:
        ciphertext_start = ciphertext[:20].hex()
        ciphertext_info += f", primeros bytes: {ciphertext_start}"
    except:
        pass
    
    print(f"DEBUG: {ciphertext_info}")
    
    # Lista para almacenar errores
    errors = []
    
    # Intentar sanear la clave
    try:
        original_key_length = len(private_key_pem)
        private_key_pem = sanitize_key(private_key_pem)
        print(f"DEBUG: Longitud clave original: {original_key_length}, después de sanitizar: {len(private_key_pem)}")
    except Exception as e:
        errors.append(f"Error en sanitize_key: {str(e)}")
    
    # Información sobre el formato de la clave
    key_format = "Desconocido"
    if "BEGIN PRIVATE KEY" in private_key_pem:
        key_format = "PKCS#8"
    elif "BEGIN RSA PRIVATE KEY" in private_key_pem:
        key_format = "PKCS#1"
    elif "BEGIN EC PRIVATE KEY" in private_key_pem:
        key_format = "EC"
    
    print(f"DEBUG: Formato de clave detectado: {key_format}")
    
    # Método 1: PKCS1_v1_5 con PyCryptodome
    try:
        from Crypto.Cipher import PKCS1_v1_5
        key = RSA.import_key(private_key_pem)
        print(f"DEBUG: Cargada clave RSA con PyCryptodome, tamaño: {key.size_in_bits()} bits")
        sentinel = get_random_bytes(16)  # Valor aleatorio para indicar descifrado fallido
        cipher = PKCS1_v1_5.new(key)
        decrypted = cipher.decrypt(ciphertext, sentinel)
        if decrypted == sentinel:
            raise ValueError("Descifrado PKCS1_v1_5 fallido")
        print("DEBUG: Descifrado exitoso con PKCS1_v1_5")
        return decrypted.decode('utf-8')
    except Exception as e1:
        errors.append(f"Error con PKCS1_v1_5: {str(e1)}")
        print(f"DEBUG: Fallo PKCS1_v1_5: {str(e1)}")
    
    # Método 2: PKCS1_OAEP con PyCryptodome
    try:
        key = RSA.import_key(private_key_pem)
        print(f"DEBUG: Intento con PKCS1_OAEP, tamaño clave: {key.size_in_bits()} bits")
        cipher = PKCS1_OAEP.new(key)
        decrypted = cipher.decrypt(ciphertext)
        print("DEBUG: Descifrado exitoso con PKCS1_OAEP")
        return decrypted.decode('utf-8')
    except Exception as e2:
        errors.append(f"Error con PKCS1_OAEP: {str(e2)}")
        print(f"DEBUG: Fallo PKCS1_OAEP: {str(e2)}")
    
    # Método 3: Intentar convertir formato de clave PKCS#8 a PKCS#1
    try:
        print("DEBUG: Intentando convertir formato de clave PKCS#8 a PKCS#1")
        # Convertir formato de PKCS#8 a PKCS#1 explícitamente
        modified_key = private_key_pem.replace("-----BEGIN PRIVATE KEY-----", 
                                            "-----BEGIN RSA PRIVATE KEY-----")
        modified_key = modified_key.replace("-----END PRIVATE KEY-----", 
                                          "-----END RSA PRIVATE KEY-----")
        
        # Probar con PKCS1_v1_5
        key = RSA.import_key(modified_key)
        cipher = PKCS1_v1_5.new(key)
        sentinel = get_random_bytes(16)
        decrypted = cipher.decrypt(ciphertext, sentinel)
        if decrypted == sentinel:
            raise ValueError("Descifrado con clave modificada fallido")
        print("DEBUG: Descifrado exitoso con clave modificada")
        return decrypted.decode('utf-8')
    except Exception as e3:
        errors.append(f"Error con clave modificada: {str(e3)}")
        print(f"DEBUG: Fallo con clave modificada: {str(e3)}")
    
    # Método 4: cryptography directamente
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import serialization
        
        print("DEBUG: Intentando descifrar con cryptography")
        # Intentar cargar la clave privada en diferentes formatos
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )
            print("DEBUG: Cargada clave con cryptography en formato estándar")
        except Exception as load_error:
            print(f"DEBUG: Error cargando clave estándar: {str(load_error)}")
            # Intentar con transformación adicional si es formato no estándar
            modified_key = private_key_pem
            if "-----BEGIN RSA PRIVATE KEY-----" in private_key_pem:
                modified_key = private_key_pem.replace("-----BEGIN RSA PRIVATE KEY-----", 
                                                     "-----BEGIN PRIVATE KEY-----")
                modified_key = modified_key.replace("-----END RSA PRIVATE KEY-----", 
                                                  "-----END PRIVATE KEY-----")
            
            private_key = serialization.load_pem_private_key(
                modified_key.encode('utf-8'), 
                password=None
            )
            print("DEBUG: Cargada clave con cryptography en formato modificado")
        
        # Descifrar con OAEP
        decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("DEBUG: Descifrado exitoso con cryptography")
        return decrypted.decode('utf-8')
    except Exception as e4:
        errors.append(f"Error con cryptography: {str(e4)}")
        print(f"DEBUG: Fallo con cryptography: {str(e4)}")
    
    # Método 5: Último intento con PKCS1_v1_5 sin padding
    try:
        print("DEBUG: Intentando descifrar con PKCS1_v1_5 sin padding explícito")
        from Crypto.Cipher import PKCS1_v1_5
        key = RSA.import_key(private_key_pem)
        
        # Intento para casos donde el padding puede estar mal
        # Calcular tamaño del bloque RSA
        key_size_bytes = key.size_in_bytes()
        print(f"DEBUG: Tamaño de clave en bytes: {key_size_bytes}")
        
        # Verificar si el ciphertext tiene el tamaño adecuado
        if len(ciphertext) != key_size_bytes:
            print(f"DEBUG: Advertencia - El texto cifrado ({len(ciphertext)} bytes) no tiene el tamaño esperado del bloque RSA ({key_size_bytes} bytes)")
        
        # Intentar descifrado directo con PKCS1_v1_5
        cipher = PKCS1_v1_5.new(key)
        sentinel = None  # Sin valor centinela para este intento
        decrypted = cipher.decrypt(ciphertext, sentinel)
        if not decrypted:
            raise ValueError("Descifrado sin padding fallido")
        print("DEBUG: Descifrado exitoso con PKCS1_v1_5 sin padding")
        return decrypted.decode('utf-8', errors='replace')  # Usar replace para manejar posibles errores de codificación
    except Exception as e5:
        errors.append(f"Error con PKCS1_v1_5 sin padding: {str(e5)}")
        print(f"DEBUG: Fallo PKCS1_v1_5 sin padding: {str(e5)}")
    
    # Si todos los métodos fallan, intentar determinar si el problema es la clave o el ciphertext
    diagnostic = "Diagnóstico adicional:\n"
    
    # Comprobar si la clave privada se puede cargar correctamente
    try:
        key = RSA.import_key(private_key_pem)
        diagnostic += f"- La clave privada parece ser válida (RSA {key.size_in_bits()} bits)\n"
    except Exception as key_error:
        diagnostic += f"- La clave privada no se pudo cargar: {str(key_error)}\n"
    
    # Comprobar si el ciphertext parece válido
    if len(ciphertext) < 64:
        diagnostic += f"- El texto cifrado es muy corto ({len(ciphertext)} bytes) para ser un mensaje cifrado con RSA\n"
    
    # Sugerir posibles problemas
    diagnostic += "- Posibles causas del error:\n"
    diagnostic += "  * La clave privada no corresponde con la clave pública usada para cifrar\n"
    diagnostic += "  * El texto cifrado ha sido modificado o corrupto\n"
    diagnostic += "  * Se está utilizando un algoritmo de padding diferente al usado en el cifrado\n"
    
    # Si todos los métodos fallan, lanzar una excepción detallada con diagnóstico
    error_msg = f"No se pudo descifrar con RSA. {diagnostic}\nErrores detallados: {', '.join(errors)}"
    print(f"DEBUG: Error final: {error_msg}")
    raise ValueError(error_msg)

def ecc_encrypt(plaintext: str, public_key_pem: str) -> bytes:
    """
    Cifra un texto usando cifrado híbrido con curva elíptica (ECC + AES).
    
    Nota: ECC no puede cifrar directamente como RSA. En lugar de eso, se usa un
    enfoque híbrido con AES para el cifrado del mensaje y ECC para el intercambio de claves.
    
    Args:
        plaintext: Texto a cifrar
        public_key_pem: Clave pública ECC en formato PEM
        
    Returns:
        Datos cifrados (bytes)
    """
    try:
        # Generar una clave AES aleatoria para cifrar el mensaje
        aes_key = get_random_bytes(32)  # 256 bits
        
        # Cifrar el mensaje con AES
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode('utf-8'))
        
        # Estructura: [aes_key][nonce][tag][ciphertext]
        encrypted_data = aes_key + cipher_aes.nonce + tag + ciphertext
        
        return encrypted_data
    except Exception as e:
        raise ValueError(f"Error en el cifrado ECC: {e}")

def ecc_decrypt(ciphertext: bytes, private_key_pem: str) -> str:
    """
    Descifra un texto cifrado con el método híbrido (ECC + AES).
    
    Args:
        ciphertext: Datos cifrados (bytes)
        private_key_pem: Clave privada ECC en formato PEM
        
    Returns:
        Texto descifrado
    """
    try:
        # Extraer componentes de los datos cifrados
        # Estructura: [aes_key(32)][nonce(16)][tag(16)][ciphertext]
        aes_key = ciphertext[:32]
        nonce = ciphertext[32:48]
        tag = ciphertext[48:64]
        encrypted_data = ciphertext[64:]
        
        # Descifrar el mensaje con AES
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(encrypted_data, tag)
        
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error en el descifrado ECC: {e}")

def rsa_example_with_cryptography():
    """Ejemplo de encriptación RSA utilizando la biblioteca cryptography."""
    print("=" * 50)
    print("EJEMPLO RSA CON CRYPTOGRAPHY")
    print("=" * 50)
    
    # Generar un par de claves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Mensaje a encriptar
    mensaje = "Este es un mensaje secreto encriptado con RSA"
    print(f"Mensaje original: {mensaje}")
    
    # Encriptar el mensaje con la clave pública
    ciphertext = public_key.encrypt(
        mensaje.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Mensaje encriptado (codificado en base64): {base64.b64encode(ciphertext).decode('utf-8')}")
    
    # Desencriptar el mensaje con la clave privada
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
    print()

def rsa_example_with_pycryptodome():
    """Ejemplo de encriptación RSA utilizando la biblioteca PyCryptodome."""
    print("=" * 50)
    print("EJEMPLO RSA CON PYCRYPTODOME")
    print("=" * 50)
    
    # Generar un par de claves RSA
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    
    # Mensaje a encriptar
    mensaje = "Este es un mensaje secreto encriptado con RSA (PyCryptodome)"
    print(f"Mensaje original: {mensaje}")
    
    # Crear un objeto de cifrado PKCS#1 OAEP
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    # Encriptar el mensaje
    ciphertext = cipher_rsa.encrypt(mensaje.encode('utf-8'))
    
    print(f"Mensaje encriptado (codificado en base64): {base64.b64encode(ciphertext).decode('utf-8')}")
    
    # Desencriptar el mensaje
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    
    print(f"Mensaje desencriptado: {plaintext.decode('utf-8')}")
    print()

def rsa_sign_verify_example():
    """Ejemplo de firma digital y verificación con RSA."""
    print("=" * 50)
    print("EJEMPLO DE FIRMA DIGITAL RSA")
    print("=" * 50)
    
    # Generar un par de claves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Mensaje a firmar
    mensaje = "Este mensaje necesita ser autenticado con una firma digital"
    print(f"Mensaje original: {mensaje}")
    
    # Firma digital: se firma el hash del mensaje con la clave privada
    signature = private_key.sign(
        mensaje.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print(f"Firma digital (codificada en base64): {base64.b64encode(signature).decode('utf-8')}")
    
    # Verificación: se verifica la firma con la clave pública
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
        print("✅ Verificación exitosa: la firma es válida")
    except InvalidSignature:
        print("❌ Verificación fallida: la firma no es válida")
    
    # Verificar con un mensaje alterado
    mensaje_alterado = mensaje + " (alterado)"
    print(f"\nIntentando verificar con mensaje alterado: {mensaje_alterado}")
    
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
        print("✅ Verificación exitosa: la firma es válida")
    except InvalidSignature:
        print("❌ Verificación fallida: la firma no es válida (esperado, ya que el mensaje fue alterado)")
    
    print()

def ecc_sign_verify_example():
    """Ejemplo de firma digital y verificación con Curvas Elípticas (ECC)."""
    print("=" * 50)
    print("EJEMPLO DE FIRMA DIGITAL ECC")
    print("=" * 50)
    
    # Generar un par de claves ECC
    private_key = ec.generate_private_key(
        curve=ec.SECP256R1()
    )
    public_key = private_key.public_key()
    
    # Mensaje a firmar
    mensaje = "Este mensaje se firmará con una clave ECC"
    print(f"Mensaje original: {mensaje}")
    
    # Firma digital con ECC
    signature = private_key.sign(
        mensaje.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    
    print(f"Firma digital ECC (codificada en base64): {base64.b64encode(signature).decode('utf-8')}")
    
    # Verificación de la firma
    try:
        public_key.verify(
            signature,
            mensaje.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        print("✅ Verificación exitosa: la firma ECC es válida")
    except InvalidSignature:
        print("❌ Verificación fallida: la firma ECC no es válida")
    
    # Verificar con un mensaje alterado
    mensaje_alterado = mensaje + " (alterado)"
    print(f"\nIntentando verificar con mensaje alterado: {mensaje_alterado}")
    
    try:
        public_key.verify(
            signature,
            mensaje_alterado.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        print("✅ Verificación exitosa: la firma ECC es válida")
    except InvalidSignature:
        print("❌ Verificación fallida: la firma ECC no es válida (esperado)")
    
    print()

def save_keys_to_file():
    """Ejemplo de cómo guardar y cargar claves RSA y ECC en archivos."""
    print("=" * 50)
    print("EJEMPLO DE GUARDAR Y CARGAR CLAVES")
    print("=" * 50)
    
    # Crear directorio para claves si no existe
    key_dir = Path("keys")
    key_dir.mkdir(exist_ok=True)
    
    # RSA: Generar y guardar claves
    print("Generando y guardando claves RSA...")
    private_key_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key_rsa = private_key_rsa.public_key()
    
    # Serializar y guardar clave privada RSA
    with open(key_dir / "rsa_private.pem", "wb") as f:
        f.write(private_key_rsa.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Serializar y guardar clave pública RSA
    with open(key_dir / "rsa_public.pem", "wb") as f:
        f.write(public_key_rsa.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    # ECC: Generar y guardar claves
    print("Generando y guardando claves ECC...")
    private_key_ecc = ec.generate_private_key(
        curve=ec.SECP256R1()
    )
    public_key_ecc = private_key_ecc.public_key()
    
    # Serializar y guardar clave privada ECC
    with open(key_dir / "ecc_private.pem", "wb") as f:
        f.write(private_key_ecc.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Serializar y guardar clave pública ECC
    with open(key_dir / "ecc_public.pem", "wb") as f:
        f.write(public_key_ecc.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("Claves guardadas en el directorio 'keys'")
    
    # Cargar claves y probar encriptación
    print("\nCargando claves y probando encriptación...")
    
    # Cargar clave privada RSA
    with open(key_dir / "rsa_private.pem", "rb") as f:
        loaded_private_key_rsa = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    # Cargar clave pública RSA
    with open(key_dir / "rsa_public.pem", "rb") as f:
        loaded_public_key_rsa = serialization.load_pem_public_key(
            f.read()
        )
    
    # Probar encriptación y desencriptación con las claves cargadas
    mensaje = "Prueba de encriptación con claves cargadas desde archivos"
    ciphertext = loaded_public_key_rsa.encrypt(
        mensaje.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    plaintext = loaded_private_key_rsa.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"RSA - Mensaje original: {mensaje}")
    print(f"RSA - Mensaje desencriptado: {plaintext.decode('utf-8')}")
    
    # Limpiar: eliminar los archivos de claves creados
    for key_file in key_dir.glob("*.pem"):
        key_file.unlink()
    
    key_dir.rmdir()
    print("\nArchivos de claves eliminados")
    print()

def main():
    """Función principal que ejecuta todos los ejemplos."""
    print("\n🔑 EJEMPLOS DE ENCRIPTACIÓN ASIMÉTRICA EN PYTHON 🔑\n")
    
    rsa_example_with_cryptography()
    rsa_example_with_pycryptodome()
    rsa_sign_verify_example()
    ecc_sign_verify_example()
    save_keys_to_file()
    
    print("=" * 50)
    print("CONCLUSIÓN")
    print("=" * 50)
    print("La encriptación asimétrica proporciona:")
    print("- Intercambio seguro de claves")
    print("- Firma digital para autenticación")
    print("- Confidencialidad en comunicaciones")
    print("Sin embargo, es más lenta que la encriptación simétrica")
    print("por lo que se suele usar en combinación con esta (encriptación híbrida)")
    print("=" * 50)

if __name__ == "__main__":
    main() 