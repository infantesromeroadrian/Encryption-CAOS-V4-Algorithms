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
        
        # Importar CAOS V4
        from algorithms.caos_v4 import CaosEncryption
        
        # Crear instancia de CAOS V4 con iteraciones fijas
        iterations = 100_000  # Usar el mismo número de iteraciones que en custom_service
        cipher = CaosEncryption(password=password, iterations=iterations)
        
        # Procesar según la acción
        if action == 'encrypt':
            if not text:
                raise ValueError("No hay texto para cifrar")
                
            logger.info(f"Cifrando mensaje con CAOS V4")
            
            try:
                # Asegurar que el texto esté en bytes
                if isinstance(text, str):
                    text_bytes = text.encode('utf-8')
                else:
                    text_bytes = text
                    
                # Encriptar con CAOS V4
                encrypted_data = cipher.encrypt(text_bytes)
                
                # Extraer el IV (nonce) del mensaje encriptado
                # En CAOS V4, el IV está en los bytes 16:28 del mensaje encriptado
                iv = encrypted_data[16:28]
                
                # Convertir a Base64 para la web
                encrypted = base64.b64encode(encrypted_data).decode('utf-8')
                iv_str = base64.b64encode(iv).decode('utf-8')
                
                return {
                    'success': True,
                    'encrypted': encrypted,
                    'original': text,
                    'iv': iv_str,
                    'parameters': {
                        'iterations': iterations
                    }
                }
            except Exception as e:
                logger.error(f"Error durante la encriptación: {str(e)}")
                raise ValueError(f"Error al encriptar: {str(e)}") from e
        else:  # decrypt
            logger.info("Descifrando mensaje con CAOS V4...")
            
            # Verificar que exista el texto cifrado
            if not encrypted:
                raise ValueError("No hay texto cifrado para descifrar")
                
            try:
                # Decodificar de Base64
                encrypted_data = base64.b64decode(encrypted)
                
                # Verificar que el mensaje tenga la longitud mínima requerida
                if len(encrypted_data) < 28:  # 16 bytes salt + 12 bytes nonce
                    raise ValueError("Mensaje cifrado demasiado corto")
                
                # Desencriptar con CAOS V4
                decrypted_data = cipher.decrypt(encrypted_data)
                
                # Intentar decodificar como UTF-8, si falla devolver los bytes
                try:
                    decrypted_text = decrypted_data.decode('utf-8')
                except UnicodeDecodeError:
                    logger.warning("No se pudo decodificar como UTF-8, devolviendo bytes")
                    decrypted_text = decrypted_data
                
                return {
                    'success': True,
                    'decrypted': decrypted_text,
                    'encrypted': encrypted,
                    'parameters': {
                        'iterations': iterations
                    }
                }
            except Exception as e:
                logger.error(f"Error durante la desencriptación: {str(e)}")
                raise ValueError(f"Error al desencriptar: {str(e)}") from e
                
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