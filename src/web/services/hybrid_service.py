#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Servicio para cifrado híbrido que combina algoritmos simétricos y asimétricos.
Este servicio actúa como intermediario entre la interfaz web y los algoritmos
de cifrado híbrido.
"""

import base64
import logging
import os
import sys
from typing import Dict, Any, Tuple, Optional, Union
from algorithms.hybrid_encryption import (
    generate_rsa_keys, 
    generate_ecc_keys, 
    encrypt_rsa_aes, 
    decrypt_rsa_aes,
    encrypt_ecc_aes,
    decrypt_ecc_aes
)

# Asegurar que src está en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(os.path.dirname(current_dir))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

logger = logging.getLogger(__name__)

class HybridService:
    """
    Servicio para operaciones de cifrado híbrido.
    Este servicio gestiona operaciones de generación de claves y cifrado/descifrado
    híbrido usando RSA+AES o ECC+AES.
    """
    
    @staticmethod
    def generate_key_pair(algorithm="rsa", key_size=2048):
        """
        Genera un par de claves (pública y privada) para el algoritmo especificado.
        
        Args:
            algorithm: Algoritmo asimétrico a utilizar ("rsa" o "ecc")
            key_size: Tamaño de clave para RSA (2048, 3072, 4096)
            
        Returns:
            dict: Diccionario con las claves pública y privada generadas
        """
        try:
            if algorithm.lower() == "rsa":
                public_key, private_key = generate_rsa_keys(key_size)
            elif algorithm.lower() == "ecc":
                public_key, private_key = generate_ecc_keys()
            else:
                raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
            return {
                "public_key": public_key,
                "private_key": private_key
            }
        except Exception as e:
            raise Exception(f"Error generando par de claves: {str(e)}")
    
    @staticmethod
    def encrypt(plaintext, public_key, algorithm="rsa"):
        """
        Cifra un mensaje usando cifrado híbrido.
        
        Args:
            plaintext: Texto a cifrar
            public_key: Clave pública en formato PEM
            algorithm: Algoritmo a utilizar ("rsa" o "ecc")
            
        Returns:
            dict: Diccionario con los componentes del mensaje cifrado y la clave cifrada
        """
        try:
            if algorithm.lower() == "rsa":
                encrypted_data, encrypted_key = encrypt_rsa_aes(plaintext, public_key)
            elif algorithm.lower() == "ecc":
                encrypted_data, encrypted_key = encrypt_ecc_aes(plaintext, public_key)
            else:
                raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
                "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8')
            }
        except Exception as e:
            raise Exception(f"Error cifrando mensaje: {str(e)}")
    
    @staticmethod
    def decrypt(encrypted_data, encrypted_key, private_key, algorithm="rsa"):
        """
        Descifra un mensaje usando cifrado híbrido.
        
        Args:
            encrypted_data: Datos cifrados en base64
            encrypted_key: Clave AES cifrada en base64
            private_key: Clave privada en formato PEM
            algorithm: Algoritmo a utilizar ("rsa" o "ecc")
            
        Returns:
            str: Texto descifrado
        """
        try:
            # Decodificar de base64
            encrypted_data_bytes = base64.b64decode(encrypted_data)
            encrypted_key_bytes = base64.b64decode(encrypted_key)
            
            if algorithm.lower() == "rsa":
                plaintext = decrypt_rsa_aes(encrypted_data_bytes, encrypted_key_bytes, private_key)
            elif algorithm.lower() == "ecc":
                plaintext = decrypt_ecc_aes(encrypted_data_bytes, encrypted_key_bytes, private_key)
            else:
                raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
            return plaintext
        except Exception as e:
            raise Exception(f"Error descifrando mensaje: {str(e)}")

def process_hybrid_request(
    action: str, 
    text: str, 
    algorithm: str = 'RSA-AES',
    key_size: int = 2048, 
    public_key: Optional[str] = None, 
    private_key: Optional[str] = None,
    encrypted_data: Optional[str] = None,
    encrypted_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Procesa una solicitud de cifrado o descifrado híbrido.
    
    Args:
        action: Acción a realizar ('encrypt', 'decrypt', 'generate_keys')
        text: Texto a cifrar o descifrar
        algorithm: Algoritmo híbrido a utilizar ('RSA-AES', 'ECC-AES')
        key_size: Tamaño de clave RSA para generación
        public_key: Clave pública en formato PEM (para cifrar)
        private_key: Clave privada en formato PEM (para descifrar)
        encrypted_data: Datos cifrados (para descifrar)
        encrypted_key: Clave simétrica cifrada (para descifrar)
        
    Returns:
        Resultado de la operación en formato diccionario
    """
    logger.info(f"Procesando solicitud de cifrado híbrido: {action}")
    
    try:
        # Validar datos de entrada
        if action not in ['encrypt', 'decrypt', 'generate_keys']:
            raise ValueError(f"Acción no válida: {action}")
        
        if algorithm not in ['RSA-AES', 'ECC-AES']:
            raise ValueError(f"Algoritmo no soportado: {algorithm}")

        # Procesar según la acción
        if action == 'generate_keys':
            logger.info(f"Generando par de claves para {algorithm}")
            
            if algorithm == 'RSA-AES':
                public_key, private_key = generate_rsa_keys(key_size)
            else:  # ECC-AES
                public_key, private_key = generate_ecc_keys()
                
            return {
                'success': True,
                'public_key': public_key,
                'private_key': private_key,
                'algorithm': algorithm
            }
        
        # Si el usuario envía 'generate', asegurarse de procesarlo como 'generate_keys'
        if action == 'generate':
            logger.info(f"Redirigiendo acción 'generate' a 'generate_keys' para {algorithm}")
            
            if algorithm == 'RSA-AES':
                public_key, private_key = generate_rsa_keys(key_size)
            else:  # ECC-AES
                public_key, private_key = generate_ecc_keys()
                
            return {
                'success': True,
                'public_key': public_key,
                'private_key': private_key,
                'algorithm': algorithm
            }
        
        elif action == 'encrypt':
            if not text:
                raise ValueError("No hay texto para cifrar")
                
            if not public_key:
                raise ValueError("Se requiere una clave pública para cifrar")
                
            logger.info(f"Cifrando mensaje con {algorithm}")
            
            if algorithm == 'RSA-AES':
                encrypted_data, encrypted_key = encrypt_rsa_aes(text, public_key)
            else:  # ECC-AES
                encrypted_data, encrypted_key = encrypt_ecc_aes(text, public_key)
            
            # Convertir a Base64 para transferencia web
            encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')
            
            # Añadir un resumen para mostrar en la interfaz
            plaintext_info = f"{len(text)} caracteres"
            if len(text) > 50:
                preview = text[:47] + "..."
            else:
                preview = text
            
            # Crear mensaje para el usuario
            message = f"El mensaje ha sido cifrado correctamente con cifrado híbrido ({algorithm})."
            message += f" Longitud original: {plaintext_info}."
            
            return {
                'success': True,
                'message': message,
                'encrypted_data': encrypted_data_b64,
                'encrypted_key': encrypted_key_b64,
                'encrypted_content': encrypted_data_b64,  # Añadir con el nombre exacto del campo
                'metadata': encrypted_key_b64,            # Añadir con el nombre exacto del campo
                'original': plaintext_info,
                'preview': preview,
                'algorithm': algorithm,
                'note': 'El cifrado híbrido combina la velocidad de AES con la seguridad de RSA/ECC'
            }
        
        else:  # decrypt
            logger.info(f"Descifrando mensaje con {algorithm}")
            
            if not encrypted_data or not encrypted_key:
                raise ValueError("Se requieren los datos cifrados y la clave cifrada para descifrar")
                
            if not private_key:
                raise ValueError("Se requiere una clave privada para descifrar")
                
            try:
                # Decodificar de Base64
                encrypted_data_bytes = base64.b64decode(encrypted_data)
                encrypted_key_bytes = base64.b64decode(encrypted_key)
                
                if algorithm == 'RSA-AES':
                    decrypted = decrypt_rsa_aes(
                        encrypted_data_bytes, 
                        encrypted_key_bytes, 
                        private_key
                    )
                else:  # ECC-AES
                    decrypted = decrypt_ecc_aes(
                        encrypted_data_bytes,
                        encrypted_key_bytes,
                        private_key
                    )
                
                return {
                    'success': True,
                    'decrypted': decrypted,
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