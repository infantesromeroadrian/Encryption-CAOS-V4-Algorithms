"""
Servicio para operaciones con funciones hash.
Este módulo proporciona funciones para calcular y verificar hashes.
"""

import hashlib
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def calculate_hash(text: str, algorithm: str) -> str:
    """
    Calcula el hash de un texto utilizando el algoritmo especificado.
    
    Args:
        text: Texto para calcular el hash
        algorithm: Algoritmo hash a utilizar
        
    Returns:
        Hash calculado en formato hexadecimal
    """
    if not text:
        raise ValueError("No hay texto para calcular el hash")
    
    text_bytes = text.encode('utf-8')
    
    if algorithm == 'md5':
        hash_obj = hashlib.md5(text_bytes)
    elif algorithm == 'sha1':
        hash_obj = hashlib.sha1(text_bytes)
    elif algorithm == 'sha256':
        hash_obj = hashlib.sha256(text_bytes)
    elif algorithm == 'sha512':
        hash_obj = hashlib.sha512(text_bytes)
    else:
        raise ValueError(f"Algoritmo hash no soportado: {algorithm}")
        
    return hash_obj.hexdigest()

def verify_hash(text: str, hash_value: str, algorithm: str) -> bool:
    """
    Verifica si un hash corresponde al texto proporcionado.
    
    Args:
        text: Texto original
        hash_value: Hash a verificar
        algorithm: Algoritmo hash utilizado
        
    Returns:
        True si el hash es válido, False en caso contrario
    """
    calculated_hash = calculate_hash(text, algorithm)
    return calculated_hash.lower() == hash_value.lower()

def process_hash_request(
    action: str, 
    text: str, 
    algorithm: str = 'sha256',
    hash_value: Optional[str] = None
) -> Dict[str, Any]:
    """
    Procesa una solicitud relacionada con funciones hash.
    
    Args:
        action: Acción a realizar ('calculate' o 'verify')
        text: Texto para calcular o verificar el hash
        algorithm: Algoritmo hash a utilizar
        hash_value: Hash a verificar (solo para acción 'verify')
        
    Returns:
        Resultado de la operación en formato diccionario
    """
    logger.info(f"Procesando solicitud de hash: {action}")
    
    try:
        # Validar datos de entrada
        if action not in ['calculate', 'verify']:
            raise ValueError(f"Acción no válida: {action}")
        
        if algorithm not in ['md5', 'sha1', 'sha256', 'sha512']:
            raise ValueError(f"Algoritmo hash no soportado: {algorithm}")
            
        # Procesar según la acción
        if action == 'calculate':
            if not text:
                raise ValueError("No hay texto para calcular el hash")
                
            logger.info(f"Calculando hash {algorithm}")
            
            calculated_hash = calculate_hash(text, algorithm)
            
            return {
                'success': True,
                'hash': calculated_hash,
                'original': text,
                'algorithm': algorithm
            }
        
        else:  # verify
            if not text or not hash_value:
                raise ValueError("Se requiere texto y un hash para la verificación")
                
            logger.info(f"Verificando hash {algorithm}")
            
            is_valid = verify_hash(text, hash_value, algorithm)
            
            return {
                'success': True,
                'valid': is_valid,
                'original': text,
                'hash': hash_value,
                'algorithm': algorithm
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