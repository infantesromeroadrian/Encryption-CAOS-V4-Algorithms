"""
Servicio para operaciones de benchmark de algoritmos de encriptación.
Este módulo proporciona funciones para medir el rendimiento de diferentes algoritmos.
"""

import logging
import os
import sys
import time
from typing import Dict, Any, List, Tuple, Optional
import matplotlib.pyplot as plt
import uuid
import io
import base64

# Asegurar que src está en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(os.path.dirname(current_dir))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Importar algoritmos
from algorithms import symmetric_encryption, asymmetric_encryption, hybrid_encryption
from algorithms.custom_encryption import caos_v3_encrypt, caos_v3_decrypt
from algorithms.caos_v4 import encrypt as caos_v4_encrypt, decrypt as caos_v4_decrypt

logger = logging.getLogger(__name__)

def benchmark_symmetric(
    text: str,
    password: str,
    iterations: int = 10
) -> Dict[str, Any]:
    """
    Realiza benchmark de algoritmos simétricos.
    
    Args:
        text: Texto para cifrar
        password: Contraseña para cifrado
        iterations: Número de iteraciones
        
    Returns:
        Resultados del benchmark
    """
    logger.info(f"Iniciando benchmark simétrico con {iterations} iteraciones")
    
    algorithms = [
        ("AES (CBC)", lambda: symmetric_encryption.aes_encrypt_cbc(text, password)),
        ("AES (GCM)", lambda: symmetric_encryption.aes_encrypt_gcm(text, password)),
        ("3DES", lambda: symmetric_encryption.triple_des_encrypt(text, password))
    ]
    
    results = []
    
    for name, func in algorithms:
        # Medir tiempo de cifrado
        start_time = time.time()
        for _ in range(iterations):
            encrypted = func()
        end_time = time.time()
        encrypt_time = (end_time - start_time) / iterations
        
        results.append({
            "name": name,
            "encrypt_time": encrypt_time,
            "encrypt_speed": len(text) / encrypt_time if encrypt_time > 0 else 0
        })
    
    return {
        "success": True,
        "results": results,
        "text_size": len(text),
        "iterations": iterations
    }

def benchmark_asymmetric(
    text: str,
    iterations: int = 5
) -> Dict[str, Any]:
    """
    Realiza benchmark de algoritmos asimétricos.
    
    Args:
        text: Texto para cifrar
        iterations: Número de iteraciones
        
    Returns:
        Resultados del benchmark
    """
    logger.info(f"Iniciando benchmark asimétrico con {iterations} iteraciones")
    
    # Generar claves para las pruebas
    rsa_pub, rsa_priv = asymmetric_encryption.generate_rsa_keys(2048)
    ecc_pub, ecc_priv = asymmetric_encryption.generate_ecc_keys()
    
    algorithms = [
        ("RSA-2048", 
            lambda: asymmetric_encryption.rsa_encrypt(text, rsa_pub),
            lambda c: asymmetric_encryption.rsa_decrypt(c, rsa_priv)),
        ("ECC", 
            lambda: asymmetric_encryption.ecc_encrypt(text, ecc_pub),
            lambda c: asymmetric_encryption.ecc_decrypt(c, ecc_priv))
    ]
    
    results = []
    
    for name, encrypt_func, decrypt_func in algorithms:
        try:
            # Intentar precalcular para la primera ronda
            # Si falla aquí debido a que el texto es demasiado largo, capturaremos la excepción
            ciphertext = encrypt_func()
            decrypt_func(ciphertext)
            
            # Medir tiempo de cifrado
            start_time = time.time()
            for _ in range(iterations):
                ciphertext = encrypt_func()
            end_time = time.time()
            encrypt_time = (end_time - start_time) / iterations
            
            # Medir tiempo de descifrado
            start_time = time.time()
            for _ in range(iterations):
                decrypt_func(ciphertext)
            end_time = time.time()
            decrypt_time = (end_time - start_time) / iterations
            
            results.append({
                "name": name,
                "encrypt_time": encrypt_time,
                "decrypt_time": decrypt_time,
                "encrypt_speed": len(text) / encrypt_time if encrypt_time > 0 else 0,
                "decrypt_speed": len(text) / decrypt_time if decrypt_time > 0 else 0
            })
        except Exception as e:
            logger.warning(f"Error en benchmark de {name}: {str(e)}")
            # Añadir un resultado con error
            results.append({
                "name": name,
                "error": f"Error: {str(e)}",
                "encrypt_time": 0,
                "decrypt_time": 0,
                "encrypt_speed": 0,
                "decrypt_speed": 0
            })
    
    return {
        "success": True,
        "results": results,
        "text_size": len(text),
        "iterations": iterations
    }

def benchmark_hybrid(
    text: str,
    iterations: int = 5
) -> Dict[str, Any]:
    """
    Realiza benchmark de algoritmos híbridos.
    
    Args:
        text: Texto para cifrar
        iterations: Número de iteraciones
        
    Returns:
        Resultados del benchmark
    """
    logger.info(f"Iniciando benchmark híbrido con {iterations} iteraciones")
    
    # Generar claves para las pruebas
    rsa_pub, rsa_priv = hybrid_encryption.generate_rsa_keys(2048)
    ecc_pub, ecc_priv = hybrid_encryption.generate_ecc_keys()
    
    algorithms = [
        ("RSA-AES", 
            lambda: hybrid_encryption.encrypt_rsa_aes(text, rsa_pub),
            lambda c, k: hybrid_encryption.decrypt_rsa_aes(c, k, rsa_priv)),
        ("ECC-AES", 
            lambda: hybrid_encryption.encrypt_ecc_aes(text, ecc_pub),
            lambda c, k: hybrid_encryption.decrypt_ecc_aes(c, k, ecc_priv))
    ]
    
    results = []
    
    for name, encrypt_func, decrypt_func in algorithms:
        # Precalcular para la primera ronda
        encrypted_data, encrypted_key = encrypt_func()
        decrypt_func(encrypted_data, encrypted_key)
        
        # Medir tiempo de cifrado
        start_time = time.time()
        for _ in range(iterations):
            encrypted_data, encrypted_key = encrypt_func()
        end_time = time.time()
        encrypt_time = (end_time - start_time) / iterations
        
        # Medir tiempo de descifrado
        start_time = time.time()
        for _ in range(iterations):
            decrypt_func(encrypted_data, encrypted_key)
        end_time = time.time()
        decrypt_time = (end_time - start_time) / iterations
        
        results.append({
            "name": name,
            "encrypt_time": encrypt_time,
            "decrypt_time": decrypt_time,
            "encrypt_speed": len(text) / encrypt_time if encrypt_time > 0 else 0,
            "decrypt_speed": len(text) / decrypt_time if decrypt_time > 0 else 0
        })
    
    return {
        "success": True,
        "results": results,
        "text_size": len(text),
        "iterations": iterations
    }

def benchmark_custom(
    text: str,
    password: str,
    iterations: int = 3
) -> Dict[str, Any]:
    """
    Realiza benchmark de algoritmos personalizados.
    
    Args:
        text: Texto para cifrar
        password: Contraseña para cifrado
        iterations: Número de iteraciones
        
    Returns:
        Resultados del benchmark
    """
    logger.info(f"Iniciando benchmark personalizado con {iterations} iteraciones")
    
    algorithms = [
        ("CAOS v3", 
            lambda: caos_v3_encrypt(text, password),
            lambda c: caos_v3_decrypt(c, password)),
        ("CAOS v4", 
            lambda: caos_v4_encrypt(text, password),
            lambda c: caos_v4_decrypt(c, password))
    ]
    
    results = []
    
    for name, encrypt_func, decrypt_func in algorithms:
        # Medir tiempo de cifrado
        start_time = time.time()
        for _ in range(iterations):
            ciphertext = encrypt_func()
        end_time = time.time()
        encrypt_time = (end_time - start_time) / iterations
        
        # Medir tiempo de descifrado
        start_time = time.time()
        for _ in range(iterations):
            decrypt_func(ciphertext)
        end_time = time.time()
        decrypt_time = (end_time - start_time) / iterations
        
        results.append({
            "name": name,
            "encrypt_time": encrypt_time,
            "decrypt_time": decrypt_time,
            "encrypt_speed": len(text) / encrypt_time if encrypt_time > 0 else 0,
            "decrypt_speed": len(text) / decrypt_time if decrypt_time > 0 else 0
        })
    
    return {
        "success": True,
        "results": results,
        "text_size": len(text),
        "iterations": iterations
    }

def generate_chart(results: List[Dict[str, Any]]) -> str:
    """
    Genera un gráfico de barras para los resultados del benchmark.
    
    Args:
        results: Lista de resultados con algorithm, encrypt_time y decrypt_time
        
    Returns:
        Ruta relativa a la imagen del gráfico
    """
    # Crear figura y ejes
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Extraer datos
    algorithms = [r['algorithm'] for r in results]
    encrypt_times = [r['encrypt_time'] for r in results]
    decrypt_times = [r.get('decrypt_time', 0) for r in results]
    
    # Configurar posiciones de barras
    x = range(len(algorithms))
    width = 0.35
    
    # Crear barras
    ax.bar([i - width/2 for i in x], encrypt_times, width, label='Cifrado')
    ax.bar([i + width/2 for i in x], decrypt_times, width, label='Descifrado')
    
    # Configurar etiquetas y leyenda
    ax.set_xlabel('Algoritmo')
    ax.set_ylabel('Tiempo (segundos)')
    ax.set_title('Comparativa de Rendimiento')
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms, rotation=30, ha='right')
    ax.legend()
    
    # Ajustar diseño
    plt.tight_layout()
    
    # Generar nombre único para el archivo
    unique_id = uuid.uuid4().hex[:8]
    filename = f"benchmark_{unique_id}.png"
    filepath = os.path.join("src", "static", "images", filename)
    
    # Asegurarse de que el directorio existe
    os.makedirs(os.path.join("src", "static", "images"), exist_ok=True)
    
    # Guardar gráfico
    plt.savefig(filepath)
    plt.close(fig)
    
    # Devolver ruta relativa desde static
    return f"images/{filename}"

def process_benchmark_request(
    category: str,
    text: str,
    password: Optional[str] = None,
    iterations: int = 5
) -> Dict[str, Any]:
    """
    Procesa una solicitud de benchmark.
    
    Args:
        category: Categoría de algoritmos ('symmetric', 'asymmetric', 'hybrid', 'custom', 'all')
        text: Texto para cifrar
        password: Contraseña para algoritmos que lo requieren
        iterations: Número de iteraciones
        
    Returns:
        Resultado del benchmark en formato diccionario
    """
    logger.info(f"Procesando solicitud de benchmark para: {category}")
    
    try:
        # Validar datos de entrada
        if category not in ['symmetric', 'asymmetric', 'hybrid', 'custom', 'all']:
            raise ValueError(f"Categoría no válida: {category}")
        
        if not text:
            raise ValueError("Se requiere texto para realizar el benchmark")
            
        if category in ['symmetric', 'custom', 'all'] and not password:
            raise ValueError("Se requiere contraseña para algoritmos simétricos y personalizados")
            
        # Limitar las iteraciones para evitar bloqueos
        iterations = min(max(1, iterations), 20)
        
        # Procesar según la categoría
        results = {}
        
        if category in ['symmetric', 'all']:
            results['symmetric'] = benchmark_symmetric(text, password, iterations)
            
        if category in ['asymmetric', 'all']:
            results['asymmetric'] = benchmark_asymmetric(text, iterations)
            
        if category in ['hybrid', 'all']:
            results['hybrid'] = benchmark_hybrid(text, iterations)
            
        if category in ['custom', 'all']:
            results['custom'] = benchmark_custom(text, password, iterations)
        
        # Preparar los resultados para la plantilla
        # La plantilla espera una lista de objetos con algorithm, encrypt_time y decrypt_time
        formatted_results = []
        
        if category == 'all':
            # Si son todas las categorías, procesar cada resultado individual
            for cat, cat_result in results.items():
                if 'results' in cat_result and isinstance(cat_result['results'], list):
                    for algo_result in cat_result['results']:
                        formatted_results.append({
                            'algorithm': algo_result['name'],
                            'encrypt_time': algo_result['encrypt_time'],
                            'decrypt_time': algo_result.get('decrypt_time', 0)
                        })
        else:
            # Si es una sola categoría
            if 'results' in results[category] and isinstance(results[category]['results'], list):
                for algo_result in results[category]['results']:
                    formatted_results.append({
                        'algorithm': algo_result['name'],
                        'encrypt_time': algo_result['encrypt_time'],
                        'decrypt_time': algo_result.get('decrypt_time', 0)
                    })
        
        # Generar gráfico para los resultados
        chart_path = generate_chart(formatted_results)
            
        return {
            'success': True,
            'category': category,
            'results': formatted_results,
            'text_size': len(text),
            'iterations': iterations,
            'chart_path': chart_path
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