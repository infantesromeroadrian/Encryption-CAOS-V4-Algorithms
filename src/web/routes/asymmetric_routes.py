#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para manejar las rutas relacionadas con el cifrado asimétrico.
Este módulo se encarga de procesar las solicitudes relacionadas con RSA, ECC y otras
operaciones de criptografía asimétrica.
"""

import logging
from flask import Blueprint, render_template, request, jsonify
from web.services.asymmetric_service import process_asymmetric_request
from web.services.asymmetric_service import AsymmetricService

# Crear el Blueprint para las rutas de cifrado asimétrico
asymmetric_bp = Blueprint('asymmetric', __name__, url_prefix='/asymmetric')

logger = logging.getLogger(__name__)

@asymmetric_bp.route('/')
def asymmetric_index():
    """Ruta principal para la página de cifrado asimétrico."""
    return render_template('asymmetric.html')

@asymmetric_bp.route('/', methods=['POST'])
def asymmetric_process():
    """Procesa las solicitudes del formulario de cifrado asimétrico."""
    try:
        action = request.form.get('action', '')
        
        # Para generar claves
        if action == 'generate_keys' or action == 'generate':
            algorithm = 'RSA'  # Por defecto usar RSA
            key_size = 2048    # Tamaño de clave por defecto
            
            # Usar el servicio para generar las claves
            key_result = AsymmetricService.generate_key_pair(algorithm, key_size)
            public_key = key_result.get('public_key', '')
            private_key = key_result.get('private_key', '')
            
            # Si es una solicitud AJAX, devolver JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'public_key': public_key,
                    'private_key': private_key
                })
            
            # Si es una solicitud normal, renderizar la plantilla con los datos
            return render_template('asymmetric.html', 
                                  public_key=public_key, 
                                  private_key=private_key)
        
        # Para cifrar un mensaje
        elif action == 'encrypt':
            text = request.form.get('text', '')
            public_key = request.form.get('public_key', '')
            
            if not text or not public_key:
                error = "Se requiere texto y clave pública para cifrar"
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'error': error})
                return render_template('asymmetric.html', error=error)
            
            # Cifrar el texto
            encrypted = AsymmetricService.encrypt(text, public_key)
            
            # Si es una solicitud AJAX, devolver JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'encrypted': encrypted
                })
            
            # Si es una solicitud normal, renderizar la plantilla con los datos
            return render_template('asymmetric.html', 
                                  encrypted=encrypted,
                                  public_key=public_key,
                                  original=text)
        
        # Para descifrar un mensaje
        elif action == 'decrypt':
            encrypted = request.form.get('encrypted', '')
            private_key = request.form.get('private_key', '')
            
            if not encrypted or not private_key:
                error = "Se requiere texto cifrado y clave privada para descifrar"
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'error': error})
                return render_template('asymmetric.html', error=error)
            
            # Descifrar el texto
            decrypted = AsymmetricService.decrypt(encrypted, private_key)
            
            # Si es una solicitud AJAX, devolver JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'decrypted': decrypted
                })
            
            # Si es una solicitud normal, renderizar la plantilla con los datos
            return render_template('asymmetric.html', 
                                  encrypted=encrypted,
                                  private_key=private_key,
                                  original=decrypted)
        
        else:
            error = f"Acción no válida: {action}"
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': error})
            return render_template('asymmetric.html', error=error)
    
    except Exception as e:
        logger.error(f"Error en el procesamiento de cifrado asimétrico: {str(e)}")
        error = f"Error: {str(e)}"
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error})
        return render_template('asymmetric.html', error=error)

@asymmetric_bp.route('/rsa')
def rsa_page():
    """Ruta para la página de cifrado RSA."""
    return render_template('asymmetric/rsa.html')

@asymmetric_bp.route('/ecc')
def ecc_page():
    """Ruta para la página de cifrado ECC."""
    return render_template('asymmetric/ecc.html')

@asymmetric_bp.route('/api/process', methods=['POST'])
def process_asymmetric():
    """
    Procesa las solicitudes de cifrado asimétrico.
    Acepta solicitudes POST con los siguientes parámetros:
    - action: La acción a realizar (generate_keys, encrypt, decrypt)
    - algorithm: El algoritmo a utilizar (RSA o ECC)
    - key_size: El tamaño de la clave (para RSA)
    - public_key: La clave pública (para cifrado)
    - private_key: La clave privada (para descifrado)
    - plaintext: El texto a cifrar
    - ciphertext: El texto cifrado a descifrar
    """
    try:
        data = request.json
        action = data.get('action')
        algorithm = data.get('algorithm', 'RSA')
        
        # Procesar la solicitud según la acción
        result = process_asymmetric_request(
            action=action,
            algorithm=algorithm,
            key_size=data.get('key_size', 2048),
            public_key=data.get('public_key'),
            private_key=data.get('private_key'),
            plaintext=data.get('plaintext'),
            ciphertext=data.get('ciphertext')
        )
        
        return jsonify({"success": True, "result": result})
    
    except Exception as e:
        logger.error(f"Error en process_asymmetric: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@asymmetric_bp.route('/api/generate_keys', methods=['POST'])
def generate_keys():
    """
    Genera un par de claves (pública y privada) para el algoritmo especificado.
    
    Args (POST JSON):
        algorithm: Algoritmo asimétrico a utilizar ("RSA" o "ECC")
        key_size: Tamaño de clave para RSA (2048, 3072, 4096)
    
    Returns:
        JSON con las claves pública y privada generadas
    """
    try:
        data = request.json
        algorithm = data.get('algorithm', 'RSA')
        key_size = int(data.get('key_size', 2048))
        
        # Validar el algoritmo
        if algorithm.upper() not in ['RSA', 'ECC']:
            logger.error(f"Algoritmo no soportado: {algorithm}")
            return jsonify({"success": False, "error": "Algoritmo no soportado"}), 400
        
        # Validar tamaño de clave para RSA
        if algorithm.upper() == 'RSA' and key_size not in [2048, 3072, 4096]:
            logger.warning(f"Tamaño de clave RSA no estándar: {key_size}. Ajustando a 2048.")
            key_size = 2048
        
        logger.info(f"Generando claves {algorithm} (tamaño: {key_size})")
        
        # Usar directamente las funciones de generación de claves
        try:
            from algorithms.asymmetric_encryption import generate_rsa_keys, generate_ecc_keys
            
            if algorithm.upper() == 'RSA':
                public_key, private_key = generate_rsa_keys(key_size)
            else:  # ECC
                public_key, private_key = generate_ecc_keys()
            
            # Verificar que las claves están en formato correcto
            if "BEGIN" not in public_key or "BEGIN" not in private_key:
                logger.error("Error en formato de claves generadas")
                return jsonify({"success": False, "error": "Error en formato de claves generadas"}), 500
            
            logger.info(f"Claves {algorithm} generadas exitosamente")
            return jsonify({
                "success": True, 
                "public_key": public_key,
                "private_key": private_key
            })
        except Exception as crypto_error:
            logger.error(f"Error en generación de claves: {str(crypto_error)}")
            return jsonify({"success": False, "error": f"Error generando claves: {str(crypto_error)}"}), 500
    
    except Exception as e:
        logger.error(f"Error general en generate_keys: {str(e)}")
        return jsonify({"success": False, "error": f"Error generando claves: {str(e)}"}), 400

@asymmetric_bp.route('/api/encrypt', methods=['POST'])
def encrypt():
    """
    Cifra un texto usando el algoritmo asimétrico especificado.
    
    Args (POST JSON):
        algorithm: Algoritmo a utilizar ("RSA" o "ECC")
        public_key: Clave pública en formato PEM
        plaintext: Texto a cifrar
    
    Returns:
        JSON con el texto cifrado en base64
    """
    try:
        # Reutilizar la implementación más robusta
        return direct_encrypt()
    except Exception as e:
        logger.error(f"Error general en encrypt API: {str(e)}")
        return jsonify({"success": False, "error": f"Error cifrando mensaje: {str(e)}"}), 400

@asymmetric_bp.route('/api/decrypt', methods=['POST'])
def decrypt():
    """
    Descifra un texto usando el algoritmo asimétrico especificado.
    
    Args (POST JSON):
        algorithm: Algoritmo a utilizar ("RSA" o "ECC")
        private_key: Clave privada en formato PEM
        ciphertext: Texto cifrado en base64
    
    Returns:
        JSON con el texto descifrado
    """
    try:
        # Reenviar a la implementación directa para mayor robustez
        return direct_decrypt()
    except Exception as e:
        logger.error(f"Error general en decrypt API: {str(e)}")
        return jsonify({"success": False, "error": f"Error descifrando mensaje: {str(e)}"}), 400

# Rutas de API directas para clientes
@asymmetric_bp.route('/api/direct/generate_keys', methods=['POST'])
def direct_generate_keys():
    """
    API directa para generar claves sin pasar por formulario.
    Útil para aplicaciones cliente.
    """
    try:
        data = request.json
        algorithm = data.get('algorithm', 'RSA')
        key_size = int(data.get('key_size', 2048))
        
        from algorithms.asymmetric_encryption import generate_rsa_keys, generate_ecc_keys
        
        if algorithm.upper() == 'RSA':
            public_key, private_key = generate_rsa_keys(key_size)
        elif algorithm.upper() == 'ECC':
            public_key, private_key = generate_ecc_keys()
        else:
            return jsonify({"success": False, "error": "Algoritmo no soportado"}), 400
        
        return jsonify({
            "success": True,
            "public_key": public_key,
            "private_key": private_key
        })
    except Exception as e:
        logger.error(f"Error en direct_generate_keys: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@asymmetric_bp.route('/api/direct/encrypt', methods=['POST'])
def direct_encrypt():
    """
    API directa para cifrar sin pasar por formulario.
    Útil para aplicaciones cliente.
    """
    try:
        data = request.json
        algorithm = data.get('algorithm', 'RSA')
        public_key = data.get('public_key', '')
        plaintext = data.get('plaintext', '')
        
        # Validaciones básicas con logging detallado
        if not public_key:
            logger.error("Error en direct_encrypt: Clave pública vacía")
            return jsonify({"success": False, "error": "Se requiere una clave pública"}), 400
        
        logger.debug(f"Longitud de la clave pública recibida: {len(public_key)}")
        
        if not plaintext:
            logger.error("Error en direct_encrypt: Texto a cifrar vacío")
            return jsonify({"success": False, "error": "Se requiere texto a cifrar"}), 400
        
        # Registrar información de depuración
        logger.info(f"Direct encrypt: algoritmo={algorithm}, longitud del texto={len(plaintext)}")
        
        # Importaciones con manejo de errores explícito
        try:
            from algorithms.asymmetric_encryption import rsa_encrypt, ecc_encrypt, sanitize_key
        except ImportError as import_error:
            logger.error(f"Error importando módulos de cifrado: {str(import_error)}")
            return jsonify({"success": False, "error": "Error interno del servidor"}), 500
        
        # Intentar sanitizar la clave pública
        logger.debug(f"Sanitizando clave pública de longitud: {len(public_key)}")
        try:
            cleaned_public_key = sanitize_key(public_key)
            logger.debug(f"Clave sanitizada longitud: {len(cleaned_public_key)}")
        except Exception as e:
            logger.error(f"Error al sanitizar la clave pública: {str(e)}")
            return jsonify({"success": False, "error": f"Error al procesar la clave pública: {str(e)}"}), 400
        
        # Cifrar según algoritmo con más información de depuración
        try:
            if algorithm.upper() == 'RSA':
                logger.debug("Intentando cifrar con RSA")
                try:
                    encrypted_bytes = rsa_encrypt(plaintext, cleaned_public_key)
                    logger.info("Cifrado RSA exitoso")
                except ValueError as rsa_error:
                    error_msg = str(rsa_error)
                    logger.error(f"Error específico en cifrado RSA: {error_msg}")
                    # Extraer un mensaje más amigable
                    user_friendly_msg = "Error en el cifrado RSA."
                    if "muy largo" in error_msg.lower() or "too large" in error_msg.lower():
                        user_friendly_msg = "El texto es demasiado largo para cifrarse directamente con RSA. Usa cifrado híbrido para textos largos."
                    elif "formato" in error_msg.lower() or "format" in error_msg.lower():
                        user_friendly_msg = "La clave pública tiene un formato incorrecto."
                    return jsonify({
                        "success": False, 
                        "error": user_friendly_msg,
                        "details": error_msg
                    }), 400
            elif algorithm.upper() == 'ECC':
                logger.debug("Intentando cifrar con ECC")
                encrypted_bytes = ecc_encrypt(plaintext, cleaned_public_key)
            else:
                return jsonify({"success": False, "error": "Algoritmo no soportado"}), 400
        except Exception as encrypt_error:
            error_msg = str(encrypt_error)
            logger.error(f"Error en cifrado: {error_msg}")
            return jsonify({
                "success": False, 
                "error": f"Error en cifrado: {error_msg}",
                "details": error_msg
            }), 400
        
        # Codificar en base64
        try:
            import base64
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception as encode_error:
            logger.error(f"Error codificando resultado: {str(encode_error)}")
            return jsonify({"success": False, "error": "Error codificando resultado"}), 500
        
        logger.info("Cifrado completado exitosamente")
        return jsonify({
            "success": True,
            "ciphertext": encrypted_b64
        })
    except Exception as e:
        logger.error(f"Error general en direct_encrypt: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 400

@asymmetric_bp.route('/api/direct/decrypt', methods=['POST'])
def direct_decrypt():
    """
    API directa para descifrar sin pasar por formulario.
    Útil para aplicaciones cliente.
    """
    try:
        data = request.json
        algorithm = data.get('algorithm', 'RSA')
        private_key = data.get('private_key', '')
        ciphertext = data.get('ciphertext', '')
        
        # Validaciones básicas con logging detallado
        if not private_key:
            logger.error("Error en direct_decrypt: Clave privada vacía")
            return jsonify({"success": False, "error": "Se requiere una clave privada"}), 400
        
        logger.debug(f"Longitud de la clave privada recibida: {len(private_key)}")
        
        if not ciphertext:
            logger.error("Error en direct_decrypt: Texto cifrado vacío")
            return jsonify({"success": False, "error": "Se requiere texto cifrado"}), 400
        
        # Registrar información de depuración
        logger.info(f"Direct decrypt: algoritmo={algorithm}, longitud del texto cifrado={len(ciphertext)}")
        
        # Importaciones con manejo de errores explícito
        try:
            from algorithms.asymmetric_encryption import rsa_decrypt, ecc_decrypt, sanitize_key
            import base64
        except ImportError as import_error:
            logger.error(f"Error importando módulos de descifrado: {str(import_error)}")
            return jsonify({"success": False, "error": "Error interno del servidor"}), 500
        
        # Intentar sanitizar la clave privada
        logger.debug(f"Sanitizando clave privada de longitud: {len(private_key)}")
        try:
            cleaned_private_key = sanitize_key(private_key)
            logger.debug(f"Clave sanitizada longitud: {len(cleaned_private_key)}")
        except Exception as e:
            logger.error(f"Error al sanitizar la clave privada: {str(e)}")
            return jsonify({"success": False, "error": f"Error al procesar la clave privada: {str(e)}"}), 400
        
        # Decodificar de base64 con manejo de errores
        try:
            ciphertext_bytes = base64.b64decode(ciphertext)
            logger.debug(f"Texto cifrado decodificado: {len(ciphertext_bytes)} bytes")
        except Exception as decode_error:
            logger.error(f"Error decodificando el texto cifrado: {str(decode_error)}")
            return jsonify({"success": False, "error": f"Error decodificando el texto cifrado: {str(decode_error)}"}), 400
        
        # Descifrar según algoritmo con más información de depuración
        try:
            if algorithm.upper() == 'RSA':
                logger.debug("Intentando descifrar con RSA")
                # Intentar descifrar directamente
                try:
                    plaintext = rsa_decrypt(ciphertext_bytes, cleaned_private_key)
                    logger.info("Descifrado RSA exitoso")
                except ValueError as rsa_error:
                    # Capturar el mensaje extendido de diagnóstico
                    error_msg = str(rsa_error)
                    logger.error(f"Error específico en descifrado RSA: {error_msg}")
                    
                    # Extraer información de diagnóstico para el cliente
                    diagnostic_info = ""
                    if "Diagnóstico adicional:" in error_msg:
                        diagnostic_parts = error_msg.split("Diagnóstico adicional:")
                        if len(diagnostic_parts) > 1:
                            diagnostic_info = diagnostic_parts[1].split("Errores detallados:")[0].strip()
                    
                    # Devolver un mensaje más claro al cliente
                    user_friendly_message = "Error al descifrar. "
                    if diagnostic_info:
                        user_friendly_message += f"Diagnóstico: {diagnostic_info}"
                    else:
                        user_friendly_message += "La clave privada probablemente no corresponde con la clave pública usada para cifrar."
                    
                    return jsonify({
                        "success": False, 
                        "error": user_friendly_message,
                        "details": error_msg  # Incluir detalles completos para depuración
                    }), 400
            elif algorithm.upper() == 'ECC':
                logger.debug("Intentando descifrar con ECC")
                plaintext = ecc_decrypt(ciphertext_bytes, cleaned_private_key)
            else:
                return jsonify({"success": False, "error": "Algoritmo no soportado"}), 400
        except Exception as decrypt_error:
            error_msg = str(decrypt_error)
            logger.error(f"Error en descifrado: {error_msg}")
            
            # Mensaje más amigable para el usuario
            user_message = "Error en descifrado. "
            if "clave privada no corresponde" in error_msg.lower():
                user_message += "La clave privada no corresponde con la clave pública usada para cifrar."
            elif "corrupto" in error_msg.lower():
                user_message += "El texto cifrado parece estar dañado o no es un texto válido cifrado con RSA."
            elif "padding" in error_msg.lower():
                user_message += "Hay un problema con el formato de los datos cifrados."
            else:
                user_message += error_msg
                
            return jsonify({
                "success": False, 
                "error": user_message,
                "details": error_msg  # Incluir detalles completos para depuración
            }), 400
        
        logger.info("Descifrado completado exitosamente")
        return jsonify({
            "success": True,
            "plaintext": plaintext
        })
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error general en direct_decrypt: {error_msg}")
        return jsonify({
            "success": False, 
            "error": f"Error en el proceso de descifrado: {error_msg}"
        }), 400

@asymmetric_bp.route('/api/direct/verify_key_pair', methods=['POST'])
def verify_key_pair():
    """
    Verifica si un par de claves (pública y privada) corresponden entre sí.
    Esta API es útil para diagnóstico cuando el cifrado/descifrado falla.
    """
    try:
        data = request.json
        public_key = data.get('public_key', '')
        private_key = data.get('private_key', '')
        
        # Validaciones básicas
        if not public_key or not private_key:
            return jsonify({
                "success": False, 
                "error": "Se requieren ambas claves (pública y privada)", 
                "verified": False
            }), 400
        
        logger.info("Verificando correspondencia de par de claves")
        
        # Importar los módulos necesarios con manejo de errores
        try:
            from algorithms.asymmetric_encryption import sanitize_key
            from Crypto.PublicKey import RSA
        except ImportError as import_error:
            logger.error(f"Error importando módulos: {str(import_error)}")
            return jsonify({"success": False, "error": "Error interno del servidor", "verified": False}), 500
        
        # Sanear las claves
        try:
            clean_public_key = sanitize_key(public_key)
            clean_private_key = sanitize_key(private_key)
        except Exception as e:
            logger.error(f"Error sanitizando claves: {str(e)}")
            return jsonify({
                "success": False, 
                "error": f"Error procesando formato de claves: {str(e)}", 
                "verified": False
            }), 400
        
        # Verificar si las claves corresponden entre sí
        try:
            # Cargar clave privada
            private_key_obj = RSA.import_key(clean_private_key)
            # Obtener clave pública derivada de la privada
            derived_public_key = private_key_obj.publickey().export_key().decode('utf-8')
            
            # Cargar la clave pública proporcionada
            public_key_obj = RSA.import_key(clean_public_key)
            provided_public_key = public_key_obj.export_key().decode('utf-8')
            
            # Hay varios formatos posibles de clave pública, necesitamos normalizarlos
            # para la comparación. Extraemos los componentes n y e (módulo y exponente)
            match = (private_key_obj.n == public_key_obj.n and 
                     private_key_obj.e == public_key_obj.e)
            
            if match:
                logger.info("Verificación exitosa: Las claves corresponden entre sí")
                return jsonify({
                    "success": True, 
                    "verified": True, 
                    "message": "Las claves pública y privada corresponden correctamente entre sí."
                })
            else:
                logger.warning("Verificación fallida: Las claves no corresponden entre sí")
                return jsonify({
                    "success": True, 
                    "verified": False, 
                    "message": "Las claves NO corresponden entre sí. Esto explica los problemas de cifrado/descifrado."
                })
        except Exception as e:
            logger.error(f"Error verificando par de claves: {str(e)}")
            return jsonify({
                "success": False, 
                "error": f"Error verificando las claves: {str(e)}", 
                "verified": False
            }), 400
    except Exception as e:
        logger.error(f"Error general en verify_key_pair: {str(e)}")
        return jsonify({
            "success": False, 
            "error": f"Error: {str(e)}", 
            "verified": False
        }), 400

def register_routes(app):
    """
    Registra las rutas del Blueprint en la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(asymmetric_bp) 