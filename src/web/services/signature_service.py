"""
Servicio para operaciones con firmas digitales.
Este módulo proporciona funciones para firmar y verificar firmas digitales.
"""

import base64
import logging
import os
import sys
from typing import Dict, Any, Optional, Tuple, Union

# Asegurar que src está en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(os.path.dirname(current_dir))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Intentar importar desde la carpeta de hash y firmas si existe
try:
    from hash_and_signatures import digital_signature
    has_module = True
except ImportError:
    # Fallback a una implementación básica si no existe el módulo
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    has_module = False

logger = logging.getLogger(__name__)

# Implementación básica si no existe el módulo de firmas digitales
def generate_keys(key_size: int = 2048) -> Tuple[str, str]:
    """
    Genera un par de claves RSA para firmas digitales.
    
    Args:
        key_size: Tamaño de la clave en bits
        
    Returns:
        Tuple con (clave_publica, clave_privada) en formato PEM
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    
    # Serializar las claves en formato PEM
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem, private_pem

def sign_message(message: str, private_key_pem: str) -> bytes:
    """
    Firma un mensaje con una clave privada RSA.
    
    Args:
        message: Mensaje a firmar
        private_key_pem: Clave privada en formato PEM
        
    Returns:
        Firma digital en bytes
    """
    private_key = load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    message_bytes = message.encode('utf-8')
    
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature

def verify_signature(message: str, signature: bytes, public_key_pem: str) -> bool:
    """
    Verifica una firma digital con una clave pública.
    
    Args:
        message: Mensaje original
        signature: Firma digital a verificar
        public_key_pem: Clave pública en formato PEM
        
    Returns:
        True si la firma es válida, False en caso contrario
    """
    public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
    message_bytes = message.encode('utf-8')
    
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def process_signature_request(
    action: str, 
    text: str, 
    algorithm: str = 'RSA-PSS',
    key_size: int = 2048,
    public_key: Optional[str] = None,
    private_key: Optional[str] = None,
    signature: Optional[str] = None
) -> Dict[str, Any]:
    """
    Procesa una solicitud relacionada con firmas digitales.
    
    Args:
        action: Acción a realizar ('generate_keys', 'sign', 'verify')
        text: Texto para firmar o verificar
        algorithm: Algoritmo de firma a utilizar
        key_size: Tamaño de clave para generación
        public_key: Clave pública en formato PEM
        private_key: Clave privada en formato PEM
        signature: Firma en formato Base64 (para verificar)
        
    Returns:
        Resultado de la operación en formato diccionario
    """
    logger.info(f"Procesando solicitud de firma digital: {action}")
    
    try:
        # Validar datos de entrada
        if action not in ['generate_keys', 'sign', 'verify']:
            raise ValueError(f"Acción no válida: {action}")
        
        if algorithm != 'RSA-PSS':
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
        # Procesar según la acción
        if action == 'generate_keys':
            logger.info(f"Generando par de claves RSA de {key_size} bits")
            
            if has_module:
                public_key, private_key = digital_signature.generate_keys(key_size)
            else:
                public_key, private_key = generate_keys(key_size)
                
            return {
                'success': True,
                'public_key': public_key,
                'private_key': private_key
            }
        
        elif action == 'sign':
            if not text:
                raise ValueError("No hay texto para firmar")
                
            if not private_key:
                raise ValueError("Se requiere una clave privada para firmar")
                
            logger.info(f"Firmando mensaje con {algorithm}")
            
            if has_module:
                signature = digital_signature.sign_message(text, private_key)
            else:
                signature = sign_message(text, private_key)
                
            # Convertir a Base64 para transferencia web
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            return {
                'success': True,
                'signature': signature_b64,
                'original': text,
                'algorithm': algorithm
            }
        
        else:  # verify
            if not text or not signature:
                raise ValueError("Se requiere texto y una firma para la verificación")
                
            if not public_key:
                raise ValueError("Se requiere una clave pública para verificar")
                
            logger.info(f"Verificando firma con {algorithm}")
            
            try:
                # Decodificar firma de Base64
                signature_bytes = base64.b64decode(signature)
                
                if has_module:
                    is_valid = digital_signature.verify_signature(text, signature_bytes, public_key)
                else:
                    is_valid = verify_signature(text, signature_bytes, public_key)
                
                return {
                    'success': True,
                    'valid': is_valid,
                    'original': text,
                    'algorithm': algorithm
                }
            except Exception as e:
                raise ValueError(f"Error al verificar la firma: {str(e)}")
    
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