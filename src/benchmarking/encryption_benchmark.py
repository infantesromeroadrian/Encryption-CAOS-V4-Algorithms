#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comparativa de rendimiento entre diferentes algoritmos de encriptación.
Este script compara el rendimiento de algoritmos simétricos, asimétricos, híbridos y personalizados.
"""

import os
import time
import base64
import statistics
import matplotlib.pyplot as plt
from tabulate import tabulate
from typing import Dict, List, Tuple
import sys

# Importaciones para encriptación simétrica
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Importaciones para encriptación asimétrica
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Importar nuestra implementación personalizada
from algorithms.custom_encryption import CaosEncryption
from algorithms.caos_v4 import CaosEncryption as CaosV4Encryption

# Definir tamaños de datos para las pruebas
DATA_SIZES = [100, 1000, 10000, 50000]  # Tamaños en bytes (reducidos para pruebas más rápidas)
REPEAT_COUNT = 3  # Número de veces que se repite cada prueba

class BenchmarkResult:
    """Clase para almacenar los resultados del benchmark."""
    def __init__(self, algorithm_name: str):
        self.algorithm_name = algorithm_name
        self.encrypt_times: Dict[int, List[float]] = {}
        self.decrypt_times: Dict[int, List[float]] = {}
        self.sizes: List[int] = []
    
    def add_result(self, data_size: int, encrypt_time: float, decrypt_time: float):
        """Añade un resultado de tiempo para un tamaño específico."""
        if data_size not in self.encrypt_times:
            self.encrypt_times[data_size] = []
            self.decrypt_times[data_size] = []
            self.sizes.append(data_size)
        
        self.encrypt_times[data_size].append(encrypt_time)
        self.decrypt_times[data_size].append(decrypt_time)
    
    def get_avg_encrypt_times(self) -> List[float]:
        """Obtiene los tiempos promedio de encriptación para todos los tamaños."""
        return [statistics.mean(self.encrypt_times[size]) for size in sorted(self.sizes)]
    
    def get_avg_decrypt_times(self) -> List[float]:
        """Obtiene los tiempos promedio de desencriptación para todos los tamaños."""
        return [statistics.mean(self.decrypt_times[size]) for size in sorted(self.sizes)]


def generate_test_data(size: int) -> bytes:
    """Genera datos aleatorios del tamaño especificado."""
    return os.urandom(size)


def benchmark_aes_encryption(data: bytes) -> Tuple[float, float, bytes]:
    """Benchmarking de encriptación AES."""
    # Generar clave e IV
    key = get_random_bytes(32)  # 256 bits
    iv = get_random_bytes(16)   # 128 bits
    
    # Medir tiempo de encriptación
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    encrypt_time = time.time() - start_time
    
    # Medir tiempo de desencriptación
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    decrypt_time = time.time() - start_time
    
    return encrypt_time, decrypt_time, iv + ciphertext


def benchmark_rsa_encryption(data: bytes) -> Tuple[float, float, bytes]:
    """Benchmarking de encriptación RSA."""
    # Generar par de claves
    key = RSA.generate(2048)
    public_key = key.publickey()
    
    # Para RSA solo podemos encriptar mensajes pequeños
    # Si el mensaje es demasiado grande, lo truncamos
    max_size = 190  # Tamaño máximo para RSA-2048 con OAEP y SHA-256
    if len(data) > max_size:
        data = data[:max_size]
    
    # Medir tiempo de encriptación
    start_time = time.time()
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(data)
    encrypt_time = time.time() - start_time
    
    # Medir tiempo de desencriptación
    start_time = time.time()
    decipher = PKCS1_OAEP.new(key)
    plaintext = decipher.decrypt(ciphertext)
    decrypt_time = time.time() - start_time
    
    return encrypt_time, decrypt_time, ciphertext


def benchmark_hybrid_encryption(data: bytes) -> Tuple[float, float, bytes]:
    """Benchmarking de encriptación híbrida (RSA + AES)."""
    # Generar par de claves RSA
    key_rsa = RSA.generate(2048)
    public_key = key_rsa.publickey()
    
    # Generar clave AES
    aes_key = get_random_bytes(32)  # 256 bits
    
    # Medir tiempo de encriptación
    start_time = time.time()
    
    # 1. Encriptar datos con AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher_aes.encrypt(padded_data)
    
    # 2. Encriptar clave AES con RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    encrypt_time = time.time() - start_time
    
    # Formato del resultado: [encrypted_aes_key_length(4 bytes)][encrypted_aes_key][iv][ciphertext]
    result = len(encrypted_aes_key).to_bytes(4, byteorder='big') + encrypted_aes_key + iv + ciphertext
    
    # Medir tiempo de desencriptación
    start_time = time.time()
    
    # 1. Extraer y desencriptar la clave AES
    key_length = int.from_bytes(result[:4], byteorder='big')
    encrypted_key = result[4:4+key_length]
    iv = result[4+key_length:4+key_length+16]
    ciphertext = result[4+key_length+16:]
    
    cipher_rsa = PKCS1_OAEP.new(key_rsa)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    
    # 2. Desencriptar datos con AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher_aes.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    decrypt_time = time.time() - start_time
    
    return encrypt_time, decrypt_time, result


def benchmark_custom_encryption(data: bytes) -> Tuple[float, float, str]:
    """Benchmarking de nuestra encriptación personalizada CAOS v3."""
    # Crear instancia de nuestro encriptador
    try:
        encriptador = CaosEncryption("clave_benchmark")
        
        # Medir tiempo de encriptación
        start_time = time.time()
        encrypted_data = encriptador.encrypt(data)
        encrypt_time = time.time() - start_time
        
        # Medir tiempo de desencriptación
        start_time = time.time()
        decrypted_data = encriptador.decrypt(encrypted_data)
        decrypt_time = time.time() - start_time
        
        return encrypt_time, decrypt_time, encrypted_data
    except Exception as e:
        print(f"Error en el algoritmo personalizado v3: {e}")
        return 0.0, 0.0, ""


def benchmark_caos_v4_encryption(data: bytes) -> Tuple[float, float, str]:
    """Benchmarking de nuestra encriptación CAOS v4 con AES-GCM."""
    # Crear instancia con iteraciones reducidas para benchmark
    try:
        # Usamos menos iteraciones para el benchmark (1000 en lugar de 100000)
        encriptador = CaosV4Encryption(password="clave_benchmark", iterations=1000)
        
        # Medir tiempo de encriptación
        start_time = time.time()
        encrypted_data = encriptador.encrypt(data)
        encrypt_time = time.time() - start_time
        
        # Medir tiempo de desencriptación
        start_time = time.time()
        decrypted_data = encriptador.decrypt(encrypted_data)
        decrypt_time = time.time() - start_time
        
        return encrypt_time, decrypt_time, encrypted_data
    except Exception as e:
        print(f"Error en el algoritmo CAOS v4: {e}")
        return 0.0, 0.0, ""


def run_benchmarks() -> Dict[str, BenchmarkResult]:
    """Ejecuta todas las pruebas de rendimiento."""
    results = {
        "AES (Simétrico)": BenchmarkResult("AES (Simétrico)"),
        "RSA (Asimétrico)": BenchmarkResult("RSA (Asimétrico)"),
        "Híbrido (RSA+AES)": BenchmarkResult("Híbrido (RSA+AES)"),
        "Caos v3 (Personalizado)": BenchmarkResult("Caos v3 (Personalizado)"),
        "Caos v4 (AES-GCM)": BenchmarkResult("Caos v4 (AES-GCM)")
    }
    
    # Para RSA, solo usamos tamaños pequeños debido a sus limitaciones
    rsa_sizes = [100, 190]
    
    for size in DATA_SIZES:
        print(f"\nEjecutando pruebas para tamaño de datos: {size} bytes")
        
        # Generar datos de prueba
        test_data = generate_test_data(size)
        
        # AES
        print("  Probando AES (Simétrico)...")
        for i in range(REPEAT_COUNT):
            try:
                encrypt_time, decrypt_time, _ = benchmark_aes_encryption(test_data)
                results["AES (Simétrico)"].add_result(size, encrypt_time, decrypt_time)
            except Exception as e:
                print(f"    Error en AES: {e}")
        
        # RSA (solo para tamaños pequeños)
        if size in rsa_sizes:
            print("  Probando RSA (Asimétrico)...")
            for i in range(REPEAT_COUNT):
                try:
                    encrypt_time, decrypt_time, _ = benchmark_rsa_encryption(test_data)
                    results["RSA (Asimétrico)"].add_result(size, encrypt_time, decrypt_time)
                except Exception as e:
                    print(f"    Error en RSA: {e}")
        
        # Híbrido
        print("  Probando Híbrido (RSA+AES)...")
        for i in range(REPEAT_COUNT):
            try:
                encrypt_time, decrypt_time, _ = benchmark_hybrid_encryption(test_data)
                results["Híbrido (RSA+AES)"].add_result(size, encrypt_time, decrypt_time)
            except Exception as e:
                print(f"    Error en Híbrido: {e}")
        
        # Personalizado CAOS v3
        print("  Probando Caos v3 (Personalizado)...")
        for i in range(REPEAT_COUNT):
            encrypt_time, decrypt_time, _ = benchmark_custom_encryption(test_data)
            # Solo añadir resultados si la prueba tuvo éxito
            if encrypt_time > 0 and decrypt_time > 0:
                results["Caos v3 (Personalizado)"].add_result(size, encrypt_time, decrypt_time)
        
        # CAOS v4 con AES-GCM
        print("  Probando Caos v4 (AES-GCM)...")
        for i in range(REPEAT_COUNT):
            encrypt_time, decrypt_time, _ = benchmark_caos_v4_encryption(test_data)
            # Solo añadir resultados si la prueba tuvo éxito
            if encrypt_time > 0 and decrypt_time > 0:
                results["Caos v4 (AES-GCM)"].add_result(size, encrypt_time, decrypt_time)
    
    return results


def print_results(results: Dict[str, BenchmarkResult]):
    """Imprime los resultados de las pruebas en formato tabular."""
    print("\n" + "=" * 80)
    print("RESULTADOS DEL BENCHMARK DE ENCRIPTACIÓN")
    print("=" * 80)
    
    # Preparar datos para encriptación
    headers = ["Algoritmo"] + [f"{size} bytes" for size in sorted(DATA_SIZES)]
    table_encrypt = []
    table_decrypt = []
    
    for name, result in results.items():
        # Solo incluimos los tamaños disponibles para cada algoritmo
        encrypt_times = []
        decrypt_times = []
        
        for size in sorted(DATA_SIZES):
            if size in result.sizes:
                avg_encrypt = statistics.mean(result.encrypt_times[size])
                avg_decrypt = statistics.mean(result.decrypt_times[size])
                encrypt_times.append(f"{avg_encrypt:.6f} s")
                decrypt_times.append(f"{avg_decrypt:.6f} s")
            else:
                encrypt_times.append("N/A")
                decrypt_times.append("N/A")
        
        table_encrypt.append([name] + encrypt_times)
        table_decrypt.append([name] + decrypt_times)
    
    print("\nTiempos de Encriptación (segundos):")
    print(tabulate(table_encrypt, headers=headers, tablefmt="grid"))
    
    print("\nTiempos de Desencriptación (segundos):")
    print(tabulate(table_decrypt, headers=headers, tablefmt="grid"))


def plot_results(results: Dict[str, BenchmarkResult]):
    """Genera gráficos para visualizar los resultados."""
    # Configurar el estilo del gráfico
    plt.style.use('ggplot')
    
    # Crear una figura con dos subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Colores para cada algoritmo
    colors = {
        "AES (Simétrico)": 'blue',
        "RSA (Asimétrico)": 'red',
        "Híbrido (RSA+AES)": 'green',
        "Caos v3 (Personalizado)": 'purple',
        "Caos v4 (AES-GCM)": 'orange'
    }
    
    # Preparar datos para el gráfico
    for name, result in results.items():
        sizes = sorted(result.sizes)
        
        if len(sizes) > 0:  # Solo graficamos si hay datos
            # Tiempos de encriptación
            ax1.plot(
                [str(size) for size in sizes], 
                result.get_avg_encrypt_times(),
                marker='o',
                linestyle='-',
                color=colors[name],
                label=name
            )
            
            # Tiempos de desencriptación
            ax2.plot(
                [str(size) for size in sizes], 
                result.get_avg_decrypt_times(),
                marker='s',
                linestyle='-',
                color=colors[name],
                label=name
            )
    
    # Configurar el gráfico de encriptación
    ax1.set_title('Tiempos de Encriptación', fontsize=14)
    ax1.set_xlabel('Tamaño de datos (bytes)', fontsize=12)
    ax1.set_ylabel('Tiempo (segundos)', fontsize=12)
    ax1.legend()
    ax1.grid(True)
    
    # Configurar el gráfico de desencriptación
    ax2.set_title('Tiempos de Desencriptación', fontsize=14)
    ax2.set_xlabel('Tamaño de datos (bytes)', fontsize=12)
    ax2.set_ylabel('Tiempo (segundos)', fontsize=12)
    ax2.legend()
    ax2.grid(True)
    
    # Ajustar el diseño
    plt.tight_layout()
    
    # Guardar la figura
    plt.savefig('encryption_benchmark_results.png', dpi=300)
    print("\nGráfico guardado como 'encryption_benchmark_results.png'")


def run_benchmark_for_ui(data_size: int = 1000, password: str = 'benchmark_password') -> dict:
    """
    Ejecuta un benchmark para la interfaz web.
    
    Args:
        data_size: Tamaño de los datos de prueba en bytes
        password: Contraseña para algoritmos que la requieran
        
    Returns:
        Diccionario con resultados y gráfica
    """
    import matplotlib.pyplot as plt
    
    # Generar datos aleatorios
    test_data = generate_test_data(data_size)
    
    # Preparar resultados
    results = {
        'data': [],
        'chart': None
    }
    
    # Benchmark AES
    print("  Probando AES (Simétrico)...")
    encrypt_times = []
    decrypt_times = []
    for i in range(3):  # 3 repeticiones
        try:
            encrypt_time, decrypt_time, _ = benchmark_aes_encryption(test_data)
            encrypt_times.append(encrypt_time)
            decrypt_times.append(decrypt_time)
        except Exception as e:
            print(f"    Error en AES: {e}")
    
    if encrypt_times and decrypt_times:
        results['data'].append({
            'algorithm': 'AES (Simétrico)',
            'encrypt_time': sum(encrypt_times) / len(encrypt_times),
            'decrypt_time': sum(decrypt_times) / len(decrypt_times)
        })
    
    # Benchmark RSA (solo para tamaños pequeños)
    if data_size <= 190:  # Límite para RSA-2048 con OAEP
        print("  Probando RSA (Asimétrico)...")
        encrypt_times = []
        decrypt_times = []
        for i in range(3):  # 3 repeticiones
            try:
                encrypt_time, decrypt_time, _ = benchmark_rsa_encryption(test_data)
                encrypt_times.append(encrypt_time)
                decrypt_times.append(decrypt_time)
            except Exception as e:
                print(f"    Error en RSA: {e}")
        
        if encrypt_times and decrypt_times:
            results['data'].append({
                'algorithm': 'RSA (Asimétrico)',
                'encrypt_time': sum(encrypt_times) / len(encrypt_times),
                'decrypt_time': sum(decrypt_times) / len(decrypt_times)
            })
    
    # Benchmark Híbrido
    print("  Probando Híbrido (RSA+AES)...")
    encrypt_times = []
    decrypt_times = []
    for i in range(3):  # 3 repeticiones
        try:
            encrypt_time, decrypt_time, _ = benchmark_hybrid_encryption(test_data)
            encrypt_times.append(encrypt_time)
            decrypt_times.append(decrypt_time)
        except Exception as e:
            print(f"    Error en Híbrido: {e}")
    
    if encrypt_times and decrypt_times:
        results['data'].append({
            'algorithm': 'Híbrido (RSA+AES)',
            'encrypt_time': sum(encrypt_times) / len(encrypt_times),
            'decrypt_time': sum(decrypt_times) / len(decrypt_times)
        })
    
    # Benchmark CAOS v3
    print("  Probando Caos v3 (Personalizado)...")
    encrypt_times = []
    decrypt_times = []
    for i in range(3):  # 3 repeticiones
        try:
            encrypt_time, decrypt_time, _ = benchmark_custom_encryption(test_data)
            if encrypt_time > 0 and decrypt_time > 0:
                encrypt_times.append(encrypt_time)
                decrypt_times.append(decrypt_time)
        except Exception as e:
            print(f"    Error en CAOS v3: {e}")
    
    if encrypt_times and decrypt_times:
        results['data'].append({
            'algorithm': 'Caos v3 (Personalizado)',
            'encrypt_time': sum(encrypt_times) / len(encrypt_times),
            'decrypt_time': sum(decrypt_times) / len(decrypt_times)
        })
    
    # Benchmark CAOS v4
    print("  Probando Caos v4 (AES-GCM)...")
    encrypt_times = []
    decrypt_times = []
    for i in range(3):  # 3 repeticiones
        try:
            encrypt_time, decrypt_time, _ = benchmark_caos_v4_encryption(test_data)
            if encrypt_time > 0 and decrypt_time > 0:
                encrypt_times.append(encrypt_time)
                decrypt_times.append(decrypt_time)
        except Exception as e:
            print(f"    Error en CAOS v4: {e}")
    
    if encrypt_times and decrypt_times:
        results['data'].append({
            'algorithm': 'Caos v4 (AES-GCM)',
            'encrypt_time': sum(encrypt_times) / len(encrypt_times),
            'decrypt_time': sum(decrypt_times) / len(decrypt_times)
        })
    
    # Crear gráfica
    plt.figure(figsize=(10, 6))
    
    # Datos para el gráfico
    algorithms = [result['algorithm'] for result in results['data']]
    encrypt_times = [result['encrypt_time'] for result in results['data']]
    decrypt_times = [result['decrypt_time'] for result in results['data']]
    
    # Graficar
    bar_width = 0.35
    x = range(len(algorithms))
    plt.bar([i - bar_width/2 for i in x], encrypt_times, bar_width, label='Encriptación')
    plt.bar([i + bar_width/2 for i in x], decrypt_times, bar_width, label='Desencriptación')
    
    plt.xlabel('Algoritmo')
    plt.ylabel('Tiempo (segundos)')
    plt.title(f'Comparativa de Rendimiento (Tamaño: {data_size} bytes)')
    plt.xticks(x, algorithms, rotation=30, ha='right')
    plt.legend()
    plt.tight_layout()
    
    results['chart'] = plt
    
    return results


def main():
    """Función principal."""
    print("=" * 80)
    print("BENCHMARK DE ALGORITMOS DE ENCRIPTACIÓN")
    print("=" * 80)
    print("Comparando rendimiento de algoritmos:")
    print("- AES (Simétrico)")
    print("- RSA (Asimétrico)")
    print("- Híbrido (RSA+AES)")
    print("- Caos v3 (Personalizado)")
    print("- Caos v4 (AES-GCM)")
    print("\nTamaños de datos a probar:", DATA_SIZES, "bytes")
    print("Número de repeticiones por prueba:", REPEAT_COUNT)
    
    try:
        # Asegurarse de que tenemos tabulate para la presentación
        import tabulate
    except ImportError:
        print("\nInstalando dependencias necesarias...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate", "matplotlib"])
        print("Dependencias instaladas correctamente.")
    
    print("\nIniciando pruebas de rendimiento...")
    results = run_benchmarks()
    
    # Mostrar resultados
    print_results(results)
    
    # Generar gráficos
    try:
        plot_results(results)
    except Exception as e:
        print(f"\nError al generar gráficos: {e}")
        print("Asegúrate de tener matplotlib instalado.")
    
    print("\n" + "=" * 80)
    print("CONCLUSIONES DEL BENCHMARK")
    print("=" * 80)
    print("1. Algoritmos Simétricos (AES):")
    print("   - Alto rendimiento tanto para encriptación como desencriptación")
    print("   - Escala bien con tamaños de datos grandes")
    print("   - Ideal para encriptar grandes volúmenes de datos")
    
    print("\n2. Algoritmos Asimétricos (RSA):")
    print("   - Más lentos que los simétricos")
    print("   - Limitados en el tamaño de datos que pueden manejar directamente")
    print("   - Mejor para intercambio seguro de claves que para encriptación de datos")
    
    print("\n3. Encriptación Híbrida (RSA+AES):")
    print("   - Combina la seguridad de RSA con la eficiencia de AES")
    print("   - Tiene una pequeña sobrecarga por usar dos algoritmos")
    print("   - Puede manejar datos de cualquier tamaño manteniendo alta seguridad")
    
    print("\n4. Algoritmo Personalizado (Caos v3):")
    print("   - Implementación educativa con rendimiento variable")
    print("   - Sirve como base para entender los principios de encriptación")
    print("   - NO recomendado para uso en producción o datos sensibles reales")
    
    print("\n5. Algoritmo Seguro (Caos v4):")
    print("   - Implementación basada en AES-GCM y PBKDF2")
    print("   - Provee cifrado autenticado y protección de integridad")
    print("   - Balance entre seguridad y rendimiento para uso real")
    
    print("\nEstas pruebas ilustran por qué en el mundo real:")
    print("- Los sistemas seguros utilizan encriptación híbrida")
    print("- TLS/SSL (HTTPS) usa RSA o ECC para intercambiar claves, y AES para los datos")
    print("- Los algoritmos estándar probados son siempre preferibles a implementaciones personalizadas")


if __name__ == "__main__":
    main() 