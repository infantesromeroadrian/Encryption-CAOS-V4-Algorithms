#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Servicio para cifrado asimétrico como RSA y ECC.
Este servicio actúa como intermediario entre la interfaz web y los algoritmos
de cifrado asimétrico.
"""

import logging
import os
import sys
import base64
from typing import Dict, Any, Optional, Union

# Asegurar que src está en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, '..', '..'))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from algorithms.asymmetric_encryption import (
    generate_rsa_keys,
    generate_ecc_keys,
    rsa_encrypt,
    rsa_decrypt,
    ecc_encrypt,
    ecc_decrypt
)

logger = logging.getLogger(__name__)

class AsymmetricService:
    """
    Servicio para operaciones de cifrado asimétrico.
    Este servicio gestiona operaciones de generación de claves y cifrado/descifrado
    usando algoritmos asimétricos como RSA y ECC.
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
            logger.info(f"Generando par de claves {algorithm.upper()}")
            
            if algorithm.lower() == "rsa":
                public_key, private_key = generate_rsa_keys(key_size)
            elif algorithm.lower() == "ecc":
                public_key, private_key = generate_ecc_keys()
            else:
                raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
            # Verificar que las claves se generaron correctamente
            if not public_key or not private_key:
                raise ValueError("Error al generar las claves")
            
            logger.info(f"Par de claves {algorithm.upper()} generado exitosamente")
            return {
                "public_key": public_key,
                "private_key": private_key
            }
        except Exception as e:
            logger.error(f"Error generando par de claves {algorithm}: {str(e)}")
            raise Exception(f"Error generando par de claves: {str(e)}")
    
    @staticmethod
    def encrypt(plaintext, public_key, algorithm="rsa"):
        """
        Cifra un mensaje usando el algoritmo asimétrico especificado.
        
        Args:
            plaintext: Texto a cifrar
            public_key: Clave pública en formato PEM
            algorithm: Algoritmo a utilizar ("rsa" o "ecc")
            
        Returns:
            str: Texto cifrado en formato base64
        """
        try:
            logger.info(f"Iniciando cifrado con {algorithm.upper()}")
            
            # En caso de clave vacía o formato incorrecto
            if not public_key or "-----BEGIN" not in public_key:
                raise ValueError("Formato de clave pública inválido")
            
            # Verificar que el texto no esté vacío
            if not plaintext:
                raise ValueError("El texto a cifrar no puede estar vacío")
            
            if algorithm.lower() == "rsa":
                # Cifrar directamente con la función específica
                encrypted_bytes = rsa_encrypt(plaintext, public_key)
            elif algorithm.lower() == "ecc":
                encrypted_bytes = ecc_encrypt(plaintext, public_key)
            else:
                raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
            # Convertir a Base64 para transferencia web
            result = base64.b64encode(encrypted_bytes).decode('utf-8')
            logger.info(f"Cifrado con {algorithm.upper()} completado correctamente")
            return result
        except Exception as e:
            logger.error(f"Error cifrando mensaje con {algorithm}: {str(e)}")
            raise Exception(f"Error cifrando mensaje: {str(e)}")
    
    @staticmethod
    def decrypt(ciphertext, private_key, algorithm="rsa"):
        """
        Descifra un mensaje usando el algoritmo asimétrico especificado.
        
        Args:
            ciphertext: Texto cifrado en formato base64
            private_key: Clave privada en formato PEM
            algorithm: Algoritmo a utilizar ("rsa" o "ecc")
            
        Returns:
            str: Texto descifrado
        """
        try:
            logger.info(f"Iniciando descifrado con {algorithm.upper()}")
            
            # En caso de clave vacía o formato incorrecto
            if not private_key or "-----BEGIN" not in private_key:
                raise ValueError("Formato de clave privada inválido")
            
            # Verificar que el texto cifrado no esté vacío
            if not ciphertext:
                raise ValueError("El texto cifrado no puede estar vacío")
            
            # Decodificar de base64
            try:
                ciphertext_bytes = base64.b64decode(ciphertext)
            except Exception as decode_error:
                raise ValueError(f"Error decodificando el texto cifrado: {str(decode_error)}")
            
            if algorithm.lower() == "rsa":
                # Descifrar directamente con la función específica
                plaintext = rsa_decrypt(ciphertext_bytes, private_key)
            elif algorithm.lower() == "ecc":
                plaintext = ecc_decrypt(ciphertext_bytes, private_key)
            else:
                raise ValueError(f"Algoritmo no soportado: {algorithm}")
            
            logger.info(f"Descifrado con {algorithm.upper()} completado correctamente")
            return plaintext
        except Exception as e:
            logger.error(f"Error descifrando mensaje con {algorithm}: {str(e)}")
            raise Exception(f"Error descifrando mensaje: {str(e)}")


def process_asymmetric_request(
    action: str, 
    algorithm: str = "RSA", 
    key_size: int = 2048,
    public_key: Optional[str] = None,
    private_key: Optional[str] = None,
    plaintext: Optional[str] = None,
    ciphertext: Optional[str] = None
) -> Dict[str, Any]:
    """
    Procesa una solicitud de cifrado asimétrico basada en la acción especificada.
    
    Args:
        action: Acción a realizar ('generate_keys', 'encrypt', 'decrypt')
        algorithm: Algoritmo a utilizar ('RSA' o 'ECC')
        key_size: Tamaño de la clave (para RSA)
        public_key: Clave pública en formato PEM (para cifrado)
        private_key: Clave privada en formato PEM (para descifrado)
        plaintext: Texto a cifrar
        ciphertext: Texto cifrado a descifrar
        
    Returns:
        Dictionary con los resultados de la acción
    """
    try:
        algorithm = algorithm.upper()
        service = AsymmetricService()
        
        # Acción: Generar par de claves
        if action == 'generate_keys':
            keys = service.generate_key_pair(algorithm.lower(), key_size)
            return keys
            
        # Acción: Cifrar texto
        elif action == 'encrypt':
            if not public_key:
                raise ValueError("Se requiere la clave pública para cifrar")
                
            if not plaintext:
                raise ValueError("Se requiere el texto a cifrar")
                
            encrypted = service.encrypt(plaintext, public_key, algorithm.lower())
            return {"ciphertext": encrypted}
            
        # Acción: Descifrar texto
        elif action == 'decrypt':
            if not private_key:
                raise ValueError("Se requiere la clave privada para descifrar")
                
            if not ciphertext:
                raise ValueError("Se requiere el texto cifrado")
                
            decrypted = service.decrypt(ciphertext, private_key, algorithm.lower())
            return {"plaintext": decrypted}
            
        else:
            raise ValueError(f"Acción no válida: {action}")
            
    except Exception as e:
        logger.error(f"Error en asymmetric_service: {str(e)}")
        raise Exception(f"Error procesando la solicitud: {str(e)}") 