#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interfaz web para probar diferentes algoritmos de encriptación.
Esta aplicación permite interactuar con algoritmos simétricos, asimétricos, 
híbridos y personalizados de encriptación.
"""

from flask import Flask, render_template, request, jsonify, session
import os
import base64
import json
import traceback
import sys

# Asegurar que src está en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Importaciones para encriptación simétrica
from algorithms.symmetric_encryption import aes_example_with_pycryptodome, aes_gcm_example
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Importaciones para encriptación asimétrica
from algorithms.asymmetric_encryption import rsa_example_with_pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Importaciones para encriptación híbrida
from algorithms.hybrid_encryption import basic_hybrid_encryption
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Importaciones para encriptación personalizada
from algorithms.custom_encryption import CaosEncryption
from algorithms.caos_v4 import CaosEncryption as CaosV4Encryption

# Importaciones para hash
from hash_and_signatures.hash_functions import calculate_hash

# Importaciones para firma digital
from hash_and_signatures.digital_signatures import sign_verify_message

# Importación para benchmarking
from benchmarking.encryption_benchmark import run_benchmark_for_ui

# Configurar la aplicación Flask para usar el directorio src/templates
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates'),
            static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static'))
app.secret_key = os.urandom(24)

# Asegurarse de que el directorio 'static' exista
if not os.path.exists('static'):
    os.makedirs('static')

# Asegurarse de que el directorio 'templates' exista
if not os.path.exists('templates'):
    os.makedirs('templates')

# Función adaptadora para usar con la interfaz
def aes_encrypt_decrypt(data, password, encrypt=True, iv=None, mode="CBC"):
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
    # Derivar clave de 32 bytes a partir de la contraseña
    from hashlib import sha256
    key = sha256(password.encode()).digest()
    
    if encrypt:
        # Generar IV aleatorio
        iv = get_random_bytes(16)
        
        # Crear el cifrador
        if mode == "GCM":
            cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=iv[:12])
            ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
            # Combinar tag con ciphertext
            ciphertext = tag + ciphertext
        else:  # CBC
            cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
            padded_data = pad(data.encode('utf-8'), CryptoAES.block_size)
            ciphertext = cipher.encrypt(padded_data)
        
        # Convertir a Base64 para la web
        encrypted = base64.b64encode(ciphertext).decode('utf-8')
        iv_str = base64.b64encode(iv).decode('utf-8')
        
        return encrypted, iv_str
    else:
        # Desencriptar
        try:
            ciphertext = base64.b64decode(data)
            iv_bytes = base64.b64decode(iv)
            
            if mode == "GCM":
                # Extraer tag (16 bytes) del inicio
                tag, ciphertext = ciphertext[:16], ciphertext[16:]
                decipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=iv_bytes[:12])
                plaintext = decipher.decrypt_and_verify(ciphertext, tag)
            else:  # CBC
                decipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv_bytes)
                padded_plaintext = decipher.decrypt(ciphertext)
                plaintext = unpad(padded_plaintext, CryptoAES.block_size)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Error al desencriptar: {str(e)}")

# Función adaptadora para encriptación RSA
def rsa_encrypt_decrypt(data, key, action='encrypt'):
    """
    Adapta las funciones de RSA para su uso en la interfaz web.
    
    Args:
        data: Datos a procesar o None si se generan claves
        key: Clave pública/privada según la acción
        action: 'encrypt', 'decrypt' o 'generate_keys'
        
    Returns:
        Depende de la acción:
        - 'generate_keys': (public_key, private_key)
        - 'encrypt': texto encriptado en base64
        - 'decrypt': texto desencriptado
    """
    if action == 'generate_keys':
        # Generar par de claves
        key_obj = RSA.generate(2048)
        private_key = key_obj.export_key().decode('utf-8')
        public_key = key_obj.publickey().export_key().decode('utf-8')
        return public_key, private_key
    
    elif action == 'encrypt':
        # Encriptar con clave pública
        if isinstance(key, str):
            key_obj = RSA.import_key(key)
        else:
            key_obj = key
            
        cipher = PKCS1_OAEP.new(key_obj)
        ciphertext = cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(ciphertext).decode('utf-8')
    
    elif action == 'decrypt':
        # Desencriptar con clave privada
        if isinstance(key, str):
            key_obj = RSA.import_key(key)
        else:
            key_obj = key
            
        cipher = PKCS1_OAEP.new(key_obj)
        ciphertext = base64.b64decode(data)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    
    else:
        raise ValueError(f"Acción no reconocida: {action}")

# Función adaptadora para encriptación híbrida
def hybrid_encrypt_decrypt(data, key, action='encrypt', metadata=None):
    """
    Adapta las funciones de encriptación híbrida para la interfaz web.
    
    Args:
        data: Datos a procesar o None si se generan claves
        key: Clave pública/privada según la acción
        action: 'encrypt', 'decrypt' o 'generate_keys'
        metadata: Metadatos adicionales para desencriptar (IV, etc.)
        
    Returns:
        Depende de la acción:
        - 'generate_keys': (public_key, private_key)
        - 'encrypt': (texto_encriptado, metadata)
        - 'decrypt': texto desencriptado
    """
    if action == 'generate_keys':
        # Generar par de claves RSA
        key_obj = RSA.generate(2048)
        private_key = key_obj.export_key().decode('utf-8')
        public_key = key_obj.publickey().export_key().decode('utf-8')
        return public_key, private_key
    
    elif action == 'encrypt':
        # Importar clave pública
        if isinstance(key, str):
            key_obj = RSA.import_key(key)
        else:
            key_obj = key
        
        # Generar clave AES aleatoria
        aes_key = get_random_bytes(32)  # 256 bits
        
        # Crear cifrador AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher_aes.iv
        
        # Encriptar datos con AES
        mensaje_bytes = data.encode('utf-8')
        ciphertext = cipher_aes.encrypt(pad(mensaje_bytes, AES.block_size))
        
        # Encriptar la clave AES con RSA
        cipher_rsa = PKCS1_OAEP.new(key_obj)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Convertir a base64 para transmisión web
        encrypted_data = base64.b64encode(ciphertext).decode('utf-8')
        metadata_json = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8')
        }
        
        return encrypted_data, json.dumps(metadata_json)
    
    elif action == 'decrypt':
        # Importar clave privada
        if isinstance(key, str):
            key_obj = RSA.import_key(key)
        else:
            key_obj = key
        
        # Decodificar metadata
        try:
            metadata_json = json.loads(metadata)
            iv = base64.b64decode(metadata_json['iv'])
            encrypted_aes_key = base64.b64decode(metadata_json['aes_key'])
        except:
            raise ValueError("Metadata inválida o corrupta")
        
        # Desencriptar la clave AES con RSA
        cipher_rsa = PKCS1_OAEP.new(key_obj)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        # Desencriptar el mensaje con AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_data = base64.b64decode(data)
        padded_data = cipher_aes.decrypt(encrypted_data)
        plaintext = unpad(padded_data, AES.block_size)
        
        return plaintext.decode('utf-8')
    
    else:
        raise ValueError(f"Acción no reconocida: {action}")

@app.route('/')
def index():
    """Renderiza la página principal."""
    return render_template('index.html')

@app.route('/symmetric', methods=['GET', 'POST'])
def symmetric():
    """Maneja la encriptación simétrica."""
    result = None
    if request.method == 'POST':
        try:
            # Obtener datos del formulario
            text = request.form.get('text', '')
            password = request.form.get('password', '')
            algorithm = request.form.get('algorithm', 'AES')
            mode = request.form.get('mode', 'CBC')
            action = request.form.get('action', 'encrypt')
            
            # Procesar con el algoritmo seleccionado
            if algorithm == 'AES':
                if action == 'encrypt':
                    if mode == 'GCM':
                        # Usar la función GCM
                        key = get_random_bytes(32)  # Generar clave aleatoria
                        nonce = get_random_bytes(12)
                        cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
                        ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
                        
                        # Combinar todo en un solo string base64
                        combined = key + nonce + tag + ciphertext
                        encrypted = base64.b64encode(combined).decode('utf-8')
                        result = {
                            'success': True,
                            'encrypted': encrypted,
                            'original': text
                        }
                    else:  # CBC
                        encrypted, iv = aes_encrypt_decrypt(text, password, encrypt=True, mode=mode)
                        result = {
                            'success': True,
                            'encrypted': encrypted,
                            'iv': iv,
                            'original': text
                        }
                else:  # decrypt
                    if mode == 'GCM':
                        # Desencriptar GCM
                        try:
                            combined = base64.b64decode(request.form.get('encrypted', ''))
                            key = combined[:32]
                            nonce = combined[32:44]
                            tag = combined[44:60]
                            ciphertext = combined[60:]
                            
                            cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
                            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                            result = {
                                'success': True,
                                'decrypted': plaintext.decode('utf-8'),
                                'encrypted': request.form.get('encrypted', '')
                            }
                        except Exception as e:
                            raise ValueError(f"Error al desencriptar GCM: {str(e)}")
                    else:  # CBC
                        encrypted = request.form.get('encrypted', '')
                        iv = request.form.get('iv', '')
                        decrypted = aes_encrypt_decrypt(encrypted, password, encrypt=False, iv=iv, mode=mode)
                        result = {
                            'success': True,
                            'decrypted': decrypted,
                            'encrypted': encrypted
                        }
        except Exception as e:
            result = {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    return render_template('symmetric.html', result=result)

@app.route('/asymmetric', methods=['GET', 'POST'])
def asymmetric():
    """Maneja la encriptación asimétrica."""
    result = None
    if request.method == 'POST':
        try:
            # Obtener datos del formulario
            text = request.form.get('text', '')
            action = request.form.get('action', 'generate')
            
            if action == 'generate':
                # Generar par de claves
                public_key, private_key = rsa_encrypt_decrypt(None, None, action='generate_keys')
                session['public_key'] = public_key
                session['private_key'] = private_key
                result = {
                    'success': True,
                    'public_key': public_key,
                    'private_key': private_key
                }
            elif action == 'encrypt':
                # Encriptar texto
                public_key = request.form.get('public_key', session.get('public_key', ''))
                encrypted = rsa_encrypt_decrypt(text, public_key, action='encrypt')
                result = {
                    'success': True,
                    'encrypted': encrypted,
                    'original': text
                }
            elif action == 'decrypt':
                # Desencriptar texto
                encrypted = request.form.get('encrypted', '')
                private_key = request.form.get('private_key', session.get('private_key', ''))
                decrypted = rsa_encrypt_decrypt(encrypted, private_key, action='decrypt')
                result = {
                    'success': True,
                    'decrypted': decrypted,
                    'encrypted': encrypted
                }
        except Exception as e:
            result = {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    return render_template('asymmetric.html', result=result)

@app.route('/hybrid', methods=['GET', 'POST'])
def hybrid():
    """Maneja la encriptación híbrida."""
    result = None
    if request.method == 'POST':
        try:
            # Obtener datos del formulario
            text = request.form.get('text', '')
            action = request.form.get('action', 'generate')
            
            if action == 'generate':
                # Generar par de claves
                public_key, private_key = hybrid_encrypt_decrypt(None, None, action='generate_keys')
                session['hybrid_public_key'] = public_key
                session['hybrid_private_key'] = private_key
                result = {
                    'success': True,
                    'public_key': public_key,
                    'private_key': private_key
                }
            elif action == 'encrypt':
                # Encriptar texto
                public_key = request.form.get('public_key', session.get('hybrid_public_key', ''))
                encrypted, metadata = hybrid_encrypt_decrypt(text, public_key, action='encrypt')
                result = {
                    'success': True,
                    'encrypted': encrypted,
                    'metadata': metadata,
                    'original': text
                }
            elif action == 'decrypt':
                # Desencriptar texto
                encrypted = request.form.get('encrypted', '')
                metadata = request.form.get('metadata', '')
                private_key = request.form.get('private_key', session.get('hybrid_private_key', ''))
                decrypted = hybrid_encrypt_decrypt(encrypted, private_key, action='decrypt', metadata=metadata)
                result = {
                    'success': True,
                    'decrypted': decrypted,
                    'encrypted': encrypted
                }
        except Exception as e:
            result = {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    return render_template('hybrid.html', result=result)

@app.route('/custom', methods=['GET', 'POST'])
def custom():
    """Maneja la encriptación personalizada."""
    result = None
    if request.method == 'POST':
        try:
            # Obtener datos del formulario
            text = request.form.get('text', '')
            password = request.form.get('password', '')
            version = request.form.get('version', 'caos_v3')
            action = request.form.get('action', 'encrypt')
            
            if version == 'caos_v3':
                encryptor = CaosEncryption(password)
            else:  # caos_v4
                encryptor = CaosV4Encryption(password)
            
            if action == 'encrypt':
                # Encriptar texto
                encrypted = encryptor.encrypt(text.encode('utf-8'))
                if isinstance(encrypted, bytes):
                    encrypted = base64.b64encode(encrypted).decode('utf-8')
                result = {
                    'success': True,
                    'encrypted': encrypted,
                    'original': text
                }
            else:  # decrypt
                # Desencriptar texto
                encrypted = request.form.get('encrypted', '')
                try:
                    # Intentar decodificar base64
                    encrypted_bytes = base64.b64decode(encrypted)
                except:
                    # Si falla, usar directamente
                    encrypted_bytes = encrypted.encode('utf-8')
                
                decrypted = encryptor.decrypt(encrypted_bytes)
                if isinstance(decrypted, bytes):
                    decrypted = decrypted.decode('utf-8')
                
                result = {
                    'success': True,
                    'decrypted': decrypted,
                    'encrypted': encrypted
                }
        except Exception as e:
            result = {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    return render_template('custom.html', result=result)

@app.route('/hash', methods=['GET', 'POST'])
def hash_function():
    """Maneja las funciones hash."""
    # Variables por defecto
    result = None
    message = None
    algorithm = 'sha256'
    
    # Variables para verificación de integridad
    verification_result = None
    message1 = None
    message2 = None
    verify_algorithm = 'sha256'
    hash1 = None
    hash2 = None
    
    try:
        if request.method == 'POST':
            # DEBUG: Imprimir todos los campos del formulario
            app.logger.info(f"Formulario recibido: {request.form}")
            for key, value in request.form.items():
                app.logger.info(f"Campo: {key}, Valor: {value}")
            
            # Verificar si es una solicitud de verificación
            if request.args.get('verify') == 'true':
                # Verificación de integridad
                message1 = request.form.get('message1', '')
                message2 = request.form.get('message2', '')
                verify_algorithm = request.form.get('verify_algorithm', 'sha256')
                
                # Calcular los hashes de ambos mensajes
                hash1 = calculate_hash(message1, verify_algorithm)
                hash2 = calculate_hash(message2, verify_algorithm)
                
                # Verificar si los hashes son iguales
                verification_result = (hash1 == hash2)
            else:
                # Cálculo normal de hash
                message = request.form.get('text', '')
                if not message:
                    # Si el campo text está vacío, intenta todos los nombres posibles
                    possible_fields = ['text', 'message', 'input', 'content']
                    for field in possible_fields:
                        if field in request.form:
                            message = request.form.get(field, '')
                            app.logger.info(f"Usando campo alternativo: {field}")
                            break
                
                algorithm = request.form.get('algorithm', 'sha256')
                
                # Calcular hash
                hash_value = calculate_hash(message, algorithm)
                
                # Crear resultado
                result = {
                    'success': True,
                    'hash': hash_value,
                    'original': message,
                    'algorithm': algorithm
                }
                
                # Para debug
                app.logger.info(f"Calculado hash: {hash_value} para mensaje: '{message}' usando algoritmo: {algorithm}")
    except Exception as e:
        app.logger.error(f"Error en función hash: {str(e)}")
        result = {
            'success': False,
            'error': str(e)
        }
    
    return render_template('hash.html',
                         result=result,
                         message=message,
                         algorithm=algorithm,
                         verification_result=verification_result,
                         message1=message1,
                         message2=message2,
                         verify_algorithm=verify_algorithm,
                         hash1=hash1,
                         hash2=hash2)

@app.route('/digital_signature', methods=['GET', 'POST'])
def digital_signature():
    """Maneja las firmas digitales."""
    result = None
    if request.method == 'POST':
        try:
            # Obtener datos del formulario
            message = request.form.get('message', '')
            action = request.form.get('action', 'sign')
            
            if action == 'generate':
                # Generar par de claves
                public_key, private_key = sign_verify_message(None, None, action='generate_keys')
                session['signature_public_key'] = public_key
                session['signature_private_key'] = private_key
                result = {
                    'success': True,
                    'message': 'Claves generadas correctamente',
                    'public_key': public_key,
                    'private_key': private_key
                }
            elif action == 'sign':
                # Firmar mensaje
                private_key = request.form.get('private_key', session.get('signature_private_key', ''))
                signature = sign_verify_message(message, private_key, action='sign')
                result = {
                    'success': True,
                    'message': 'Mensaje firmado correctamente',
                    'signature': signature,
                    'original': message
                }
            elif action == 'verify':
                # Verificar firma
                signature = request.form.get('signature', '')
                public_key = request.form.get('public_key', session.get('signature_public_key', ''))
                is_valid = sign_verify_message(message, public_key, action='verify', signature=signature)
                result = {
                    'success': is_valid,
                    'message': 'La firma es válida.' if is_valid else 'La firma NO es válida.',
                    'details': 'El mensaje es auténtico y no ha sido alterado.' if is_valid else 'La firma no corresponde al mensaje o la clave pública no es correcta.'
                }
        except Exception as e:
            result = {
                'success': False,
                'message': f'Error: {str(e)}',
                'traceback': traceback.format_exc()
            }
    
    # Recuperar claves si existen en la sesión
    public_key = session.get('signature_public_key', '')
    private_key = session.get('signature_private_key', '')

    return render_template('digital_signature.html', result=result, public_key=public_key, private_key=private_key)

@app.route('/benchmark', methods=['GET', 'POST'])
def benchmark():
    """Maneja el benchmarking de algoritmos."""
    result = None
    if request.method == 'POST':
        try:
            # Obtener datos del formulario
            data_size = int(request.form.get('data_size', 1000))
            password = request.form.get('password', 'benchmark_password')
            
            # Ejecutar benchmark
            benchmark_results = run_benchmark_for_ui(data_size, password)
            
            # Guardar resultados
            chart_path = 'static/benchmark_chart.png'
            if os.path.exists(chart_path):
                os.remove(chart_path)
            
            # Guardar gráfica
            benchmark_results['chart'].savefig(chart_path)
            
            result = {
                'success': True,
                'chart_path': 'benchmark_chart.png',
                'results': benchmark_results['data']
            }
        except Exception as e:
            result = {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    return render_template('benchmark.html', result=result)

if __name__ == '__main__':
    # Crear directorios necesarios
    for d in ['templates', 'static']:
        if not os.path.exists(d):
            os.makedirs(d)
    
    app.run(debug=True, host='0.0.0.0') 