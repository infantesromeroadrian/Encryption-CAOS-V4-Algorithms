"""
Servicio para operaciones de cifrado personalizado CAOS V4.0.
Este módulo proporciona funciones para cifrar y descifrar utilizando algoritmos personalizados.
"""

import base64
import logging
import os
import sys
from typing import Dict, Any, Tuple, Optional, Union

# Asegurar que src está en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(os.path.dirname(current_dir))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Importar funciones del módulo de cifrado personalizado
from algorithms.custom_encryption import caos_v3_encrypt, caos_v3_decrypt
from algorithms.caos_v4 import encrypt as caos_v4_encrypt, decrypt as caos_v4_decrypt

logger = logging.getLogger(__name__)

def process_custom_request(
    action: str, 
    text: str, 
    password: str, 
    algorithm: str = 'CAOS_V4',
    encrypted: Optional[str] = None,
    parameters: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Procesa una solicitud de cifrado o descifrado personalizado.
    
    Args:
        action: Acción a realizar ('encrypt' o 'decrypt')
        text: Texto a cifrar o descifrar
        password: Contraseña para la operación
        algorithm: Algoritmo a utilizar ('CAOS_V3', 'CAOS_V4')
        encrypted: Texto cifrado (solo para descifrar)
        parameters: Parámetros adicionales para el algoritmo
        
    Returns:
        Resultado de la operación en formato diccionario
    """
    logger.info(f"Procesando solicitud de cifrado personalizado: {action}")
    
    try:
        # Validar datos de entrada
        if action not in ['encrypt', 'decrypt']:
            raise ValueError(f"Acción no válida: {action}")
        
        if algorithm not in ['CAOS_V3', 'CAOS_V4']:
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
        
        # Establecer parámetros por defecto si no se proporcionan
        if parameters is None:
            parameters = {}
        
        # Procesar según la acción
        if action == 'encrypt':
            if not text:
                raise ValueError("No hay texto para cifrar")
                
            if not password:
                raise ValueError("Se requiere una contraseña para cifrar")
                
            logger.info(f"Cifrando mensaje con {algorithm}")
            
            if algorithm == 'CAOS_V4':
                iterations = parameters.get('iterations', 3)
                seed = parameters.get('seed', 42)
                
                encrypted_data = caos_v4_encrypt(
                    text, 
                    password,
                    iterations=iterations,
                    seed=seed
                )
                
                # Convertir a Base64 para transferencia web
                encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
                
                return {
                    'success': True,
                    'encrypted': encrypted_b64,
                    'original': text,
                    'algorithm': algorithm,
                    'parameters': {
                        'iterations': iterations,
                        'seed': seed
                    }
                }
            else:  # CAOS_V3
                rounds = parameters.get('rounds', 10)
                
                encrypted_data = caos_v3_encrypt(
                    text, 
                    password,
                    rounds=rounds
                )
                
                # Para CAOS_V3, la salida ya es una cadena, no necesita codificación adicional
                return {
                    'success': True,
                    'encrypted': encrypted_data,
                    'original': text,
                    'algorithm': algorithm,
                    'parameters': {
                        'rounds': rounds
                    }
                }
        
        else:  # decrypt
            logger.info(f"Descifrando mensaje con {algorithm}")
            
            if not encrypted:
                raise ValueError("No hay texto cifrado para descifrar")
                
            if not password:
                raise ValueError("Se requiere una contraseña para descifrar")
                
            try:
                if algorithm == 'CAOS_V4':
                    iterations = parameters.get('iterations', 3)
                    seed = parameters.get('seed', 42)
                    
                    # Decodificar de Base64
                    encrypted_bytes = base64.b64decode(encrypted)
                    
                    decrypted = caos_v4_decrypt(
                        encrypted_bytes, 
                        password,
                        iterations=iterations,
                        seed=seed
                    )
                else:  # CAOS_V3
                    rounds = parameters.get('rounds', 10)
                    
                    decrypted = caos_v3_decrypt(
                        encrypted, 
                        password,
                        rounds=rounds
                    )
                
                return {
                    'success': True,
                    'decrypted': decrypted,
                    'encrypted': encrypted,
                    'algorithm': algorithm
                }
            except Exception as e:
                raise ValueError(f"Error al desencriptar: {str(e)}")
    
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