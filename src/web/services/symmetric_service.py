"""
Servicio para operaciones de cifrado simétrico.
Este módulo proporciona funciones para cifrar y descifrar utilizando algoritmos simétricos.
"""

import base64
import logging
from typing import Dict, Any, Tuple, Optional, Union

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

def aes_encrypt_decrypt(
    data: str, 
    password: str, 
    encrypt: bool = True, 
    iv: Optional[str] = None, 
    mode: str = "CBC"
) -> Union[Tuple[str, str], str]:
    """
    Adapta las funciones de symmetric_encryption.py para la interfaz web.
    
    Args:
        data: Texto a encriptar o desencriptar
        password: Contraseña para derivar la clave
        encrypt: True para encriptar, False para desencriptar
        iv: Vector de inicialización (solo para desencriptar)
        mode: Modo de operación (CBC o GCM)
        
    Returns:
        Si encrypt=True: (texto_encriptado, iv)
        Si encrypt=False: texto_desencriptado
    """
    # Validar parámetros
    if not data:
        raise ValueError("No hay datos para procesar")
    
    if not password:
        raise ValueError("Se requiere una contraseña")
    
    if not encrypt and not iv:
        raise ValueError("Se requiere un vector de inicialización (IV) para descifrar")
    
    # Derivar clave de 32 bytes a partir de la contraseña
    from hashlib import sha256
    key = sha256(password.encode()).digest()
    
    try:
        if encrypt:
            # Generar IV aleatorio
            iv = get_random_bytes(16)
            
            # Crear el cifrador
            if mode == "GCM":
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv[:12])
                ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
                # Combinar tag con ciphertext
                ciphertext = tag + ciphertext
            else:  # CBC
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_data = pad(data.encode('utf-8'), AES.block_size)
                ciphertext = cipher.encrypt(padded_data)
            
            # Convertir a Base64 para la web
            encrypted = base64.b64encode(ciphertext).decode('utf-8')
            iv_str = base64.b64encode(iv).decode('utf-8')
            
            logger.debug(f"Datos cifrados correctamente: {len(encrypted)} caracteres")
            return encrypted, iv_str
        else:
            # Desencriptar
            try:
                ciphertext = base64.b64decode(data)
                iv_bytes = base64.b64decode(iv)
                
                if mode == "GCM":
                    # Extraer tag (16 bytes) del inicio
                    tag, ciphertext = ciphertext[:16], ciphertext[16:]
                    decipher = AES.new(key, AES.MODE_GCM, nonce=iv_bytes[:12])
                    plaintext = decipher.decrypt_and_verify(ciphertext, tag)
                else:  # CBC
                    decipher = AES.new(key, AES.MODE_CBC, iv_bytes)
                    padded_plaintext = decipher.decrypt(ciphertext)
                    plaintext = unpad(padded_plaintext, AES.block_size)
                
                logger.debug(f"Datos descifrados correctamente: {len(plaintext)} bytes")
                return plaintext.decode('utf-8')
            except Exception as e:
                logger.error(f"Error al desencriptar: {str(e)}")
                raise ValueError(f"Error al desencriptar: {str(e)}")
    except Exception as e:
        logger.error(f"Error en operación de cifrado: {str(e)}")
        raise

def process_symmetric_request(
    action: str, 
    text: str, 
    password: str, 
    algorithm: str, 
    mode: str, 
    encrypted: Optional[str] = None, 
    iv: Optional[str] = None
) -> Dict[str, Any]:
    """
    Procesa una solicitud de cifrado o descifrado simétrico.
    
    Args:
        action: Acción a realizar ('encrypt' o 'decrypt')
        text: Texto a cifrar o descifrar
        password: Contraseña para la operación
        algorithm: Algoritmo a utilizar
        mode: Modo de operación
        encrypted: Texto cifrado (solo para descifrar)
        iv: Vector de inicialización (solo para descifrar)
        
    Returns:
        Resultado de la operación en formato diccionario
    """
    logger.info(f"Procesando solicitud de cifrado simétrico: {action}")
    
    try:
        # Validar datos de entrada
        if action not in ['encrypt', 'decrypt']:
            raise ValueError(f"Acción no válida: {action}")
        
        if algorithm != 'AES':
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
        if mode not in ['CBC', 'GCM']:
            raise ValueError(f"Modo no soportado: {mode}")
        
        # Procesar según la acción
        if action == 'encrypt':
            if not text:
                raise ValueError("No hay texto para cifrar")
                
            logger.info(f"Cifrando mensaje con {algorithm}-{mode}")
            
            if mode == 'GCM':
                # Usar la función GCM especial para autenticación
                key = get_random_bytes(32)  # Generar clave aleatoria
                nonce = get_random_bytes(12)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
                
                # Combinar todo en un solo string base64
                combined = key + nonce + tag + ciphertext
                encrypted = base64.b64encode(combined).decode('utf-8')
                return {
                    'success': True,
                    'encrypted': encrypted,
                    'original': text
                }
            else:  # CBC
                encrypted, iv = aes_encrypt_decrypt(text, password, encrypt=True, mode=mode)
                return {
                    'success': True,
                    'encrypted': encrypted,
                    'iv': iv,
                    'original': text,
                    'mode': mode
                }
        else:  # decrypt
            logger.info("Descifrando mensaje...")
            
            # Verificar que exista el texto cifrado
            if not encrypted:
                raise ValueError("No hay texto cifrado para descifrar")
                
            if mode == 'GCM':
                # Desencriptar GCM
                try:
                    combined = base64.b64decode(encrypted)
                    key = combined[:32]
                    nonce = combined[32:44]
                    tag = combined[44:60]
                    ciphertext = combined[60:]
                    
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    return {
                        'success': True,
                        'decrypted': plaintext.decode('utf-8'),
                        'encrypted': encrypted
                    }
                except Exception as e:
                    raise ValueError(f"Error al desencriptar GCM: {str(e)}")
            else:  # CBC
                if not iv:
                    raise ValueError("Falta el Vector de Inicialización (IV). Este valor es necesario para descifrar.")
                
                decrypted = aes_encrypt_decrypt(encrypted, password, encrypt=False, iv=iv, mode=mode)
                return {
                    'success': True,
                    'decrypted': decrypted,
                    'encrypted': encrypted
                }
    except ValueError as ve:
        logger.error(f"Error de validación: {str(ve)}")
        return {
            'success': False,
            'error': str(ve)
        }
    except Exception as e:
        logger.error(f"Error inesperado: {str(e)}", exc_info=True)
        return {
            'success': False,
            'error': f"Error inesperado: {str(e)}"
        } 