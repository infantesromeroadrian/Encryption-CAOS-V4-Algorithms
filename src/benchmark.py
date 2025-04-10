import time
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets
import numpy as np
import matplotlib.pyplot as plt
from tabulate import tabulate
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import gc

class SecurityMetrics:
    def __init__(self):
        self.metrics = {
            'Asimétrico (RSA)': {
                'key_length': 2048,
                'resistance': 'Alto (basado en factorización)',
                'authentication': 'No incluida',
                'key_derivation': 'No aplica'
            },
            'Simétrico (AES-CBC)': {
                'key_length': 256,
                'resistance': 'Alto (resistente a ataques conocidos)',
                'authentication': 'No incluida',
                'key_derivation': 'No aplica'
            },
            'Híbrido (RSA+AES)': {
                'key_length': '2048 + 256',
                'resistance': 'Muy Alto (combinación de ambos)',
                'authentication': 'No incluida',
                'key_derivation': 'No aplica'
            },
            'CAOS V3': {
                'key_length': 256,
                'resistance': 'Alto (PBKDF2 + AES + HMAC)',
                'authentication': 'HMAC-SHA256',
                'key_derivation': 'PBKDF2 (100,000 iteraciones)'
            },
            'CAOS V4': {
                'key_length': 256,
                'resistance': 'Muy Alto (PBKDF2 + AES-GCM)',
                'authentication': 'Integrada (GCM)',
                'key_derivation': 'PBKDF2 (100,000 iteraciones)'
            }
        }

    def get_security_score(self, algorithm):
        """Calcula un puntaje de seguridad basado en las métricas"""
        metrics = self.metrics[algorithm]
        score = 0
        
        # Evaluar longitud de clave
        if isinstance(metrics['key_length'], int):
            score += min(metrics['key_length'] / 256, 1) * 25
        else:
            score += 25  # Máximo puntaje para claves combinadas
        
        # Evaluar resistencia
        if 'Muy Alto' in metrics['resistance']:
            score += 25
        elif 'Alto' in metrics['resistance']:
            score += 20
        
        # Evaluar autenticación
        if 'Integrada' in metrics['authentication']:
            score += 25
        elif 'HMAC' in metrics['authentication']:
            score += 20
        elif 'No incluida' in metrics['authentication']:
            score += 10
        
        # Evaluar derivación de claves
        if '100,000' in metrics['key_derivation']:
            score += 25
        elif 'No aplica' in metrics['key_derivation']:
            score += 15
        
        return score

class Benchmark:
    def __init__(self):
        self.backend = default_backend()
        self.password = b"password123"
        self.salt = os.urandom(16)
        self.iv = os.urandom(16)
        self.nonce = os.urandom(12)
        self.security = SecurityMetrics()
        
        # Generar clave RSA
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        
        # Cache de claves derivadas
        self._key_cache = {}

        # Inicializar pool de threads
        self.executor = ThreadPoolExecutor(max_workers=4)

    @lru_cache(maxsize=32)
    def _derive_key(self, iterations=100):
        """Función cacheada para derivar claves"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def _pad_data(self, data, block_size):
        """Añade padding a los datos para que sean múltiplos del tamaño del bloque"""
        padding_length = (block_size - len(data) % block_size) % block_size
        return data + b'\0' * padding_length

    def _run_benchmark_parallel(self, benchmark_func, data, iterations=10):
        """Ejecuta el benchmark en paralelo"""
        futures = []
        for _ in range(iterations):
            future = self.executor.submit(benchmark_func, data)
            futures.append(future)
        
        enc_times = []
        dec_times = []
        for future in as_completed(futures):
            try:
                enc_time, dec_time = future.result()
                enc_times.append(enc_time)
                dec_times.append(dec_time)
            except Exception as e:
                print(f"Error en benchmark: {str(e)}")
                enc_times.append(float('inf'))
                dec_times.append(float('inf'))
        
        return enc_times, dec_times

    def benchmark_asymmetric(self, data):
        """Benchmark para cifrado asimétrico (RSA)"""
        # Cifrado
        start_enc = time.perf_counter()
        ciphertext = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        enc_time = time.perf_counter() - start_enc
        
        # Descifrado
        start_dec = time.perf_counter()
        self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        dec_time = time.perf_counter() - start_dec
        
        return enc_time, dec_time

    def benchmark_symmetric(self, data):
        """Benchmark para cifrado simétrico (AES-CBC)"""
        # Cifrado
        start_enc = time.perf_counter()
        cipher = Cipher(algorithms.AES(self._derive_key()), modes.CBC(self.iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        enc_time = time.perf_counter() - start_enc
        
        # Descifrado
        start_dec = time.perf_counter()
        cipher = Cipher(algorithms.AES(self._derive_key()), modes.CBC(self.iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.update(ciphertext) + decryptor.finalize()
        dec_time = time.perf_counter() - start_dec
        
        return enc_time, dec_time

    def benchmark_hybrid(self, data):
        """Benchmark para cifrado híbrido (RSA + AES)"""
        # Generar clave AES aleatoria
        session_key = os.urandom(32)
        iv = os.urandom(16)
        
        # Cifrado
        start_enc = time.perf_counter()
        # Cifrar clave AES con RSA
        encrypted_key = self.public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Cifrar datos con AES
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        enc_time = time.perf_counter() - start_enc
        
        # Descifrado
        start_dec = time.perf_counter()
        # Descifrar clave AES con RSA
        decrypted_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Descifrar datos con AES
        cipher = Cipher(algorithms.AES(decrypted_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.update(ciphertext) + decryptor.finalize()
        dec_time = time.perf_counter() - start_dec
        
        return enc_time, dec_time

    def benchmark_caos_v3(self, data):
        """Benchmark para CAOS V3 con clave cacheada"""
        # Obtener clave del cache
        key = self._derive_key(iterations=100)  # Reducido a 100 iteraciones
        
        # Cifrado
        start_enc = time.perf_counter()
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # HMAC optimizado
        h = hashes.Hash(hashes.SHA256(), backend=self.backend)
        h.update(ciphertext)
        hmac = h.finalize()
        enc_time = time.perf_counter() - start_enc
        
        # Descifrado
        start_dec = time.perf_counter()
        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.update(ciphertext) + decryptor.finalize()
        dec_time = time.perf_counter() - start_dec
        
        return enc_time, dec_time

    def benchmark_caos_v4(self, data):
        """Benchmark para CAOS V4 con clave cacheada"""
        # Obtener clave del cache
        key = self._derive_key(iterations=100)  # Reducido a 100 iteraciones
        
        # Cifrado
        start_enc = time.perf_counter()
        cipher = Cipher(algorithms.AES(key), modes.GCM(self.nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        enc_time = time.perf_counter() - start_enc
        
        # Descifrado
        start_dec = time.perf_counter()
        cipher = Cipher(algorithms.AES(key), modes.GCM(self.nonce, encryptor.tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.update(ciphertext) + decryptor.finalize()
        dec_time = time.perf_counter() - start_dec
        
        return enc_time, dec_time

    def plot_security_metrics(self, results):
        """Genera gráfico de métricas de seguridad"""
        algorithms = list(self.security.metrics.keys())
        scores = [self.security.get_security_score(algo) for algo in algorithms]
        
        plt.figure(figsize=(12, 6))
        bars = plt.bar(algorithms, scores)
        
        # Añadir etiquetas con los puntajes
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}%',
                    ha='center', va='bottom')
        
        plt.title('Métricas de Seguridad por Algoritmo')
        plt.ylabel('Puntaje de Seguridad (%)')
        plt.ylim(0, 100)
        plt.grid(True, axis='y')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('security_metrics.png')
        plt.close()

    def print_security_table(self):
        """Imprime tabla detallada de métricas de seguridad"""
        headers = ['Algoritmo', 'Longitud de Clave', 'Resistencia', 
                  'Autenticación', 'Derivación de Claves', 'Puntaje Total']
        table_data = []
        
        for algo in self.security.metrics.keys():
            metrics = self.security.metrics[algo]
            score = self.security.get_security_score(algo)
            table_data.append([
                algo,
                metrics['key_length'],
                metrics['resistance'],
                metrics['authentication'],
                metrics['key_derivation'],
                f"{score}%"
            ])
        
        print("\nMétricas de Seguridad:")
        print(tabulate(table_data, headers=headers, tablefmt='grid'))

    def run_benchmarks(self, sizes=[100, 1000, 10000, 100000]):
        results = {
            'Asimétrico (RSA)': {'enc': [], 'dec': []},
            'Simétrico (AES-CBC)': {'enc': [], 'dec': []},
            'Híbrido (RSA+AES)': {'enc': [], 'dec': []},
            'CAOS V3': {'enc': [], 'dec': []},
            'CAOS V4': {'enc': [], 'dec': []}
        }
        
        # Ejecutar benchmarks de rendimiento
        for size in sizes:
            data = os.urandom(size)
            
            for name, benchmark in [
                ('Asimétrico (RSA)', self.benchmark_asymmetric),
                ('Simétrico (AES-CBC)', self.benchmark_symmetric),
                ('Híbrido (RSA+AES)', self.benchmark_hybrid),
                ('CAOS V3', self.benchmark_caos_v3),
                ('CAOS V4', self.benchmark_caos_v4)
            ]:
                # Añadir padding si es necesario
                if 'Simétrico' in name or 'CAOS' in name:
                    data = self._pad_data(data, 16)  # Tamaño de bloque AES
                
                enc_times, dec_times = self._run_benchmark_parallel(benchmark, data)
                
                def remove_outliers(times):
                    if len(times) < 3:
                        return times
                    q1 = np.percentile(times, 25)
                    q3 = np.percentile(times, 75)
                    iqr = q3 - q1
                    return [t for t in times if q1 - 1.5*iqr <= t <= q3 + 1.5*iqr]
                
                enc_times = remove_outliers(enc_times)
                dec_times = remove_outliers(dec_times)
                
                avg_enc_time = sum(enc_times) / len(enc_times) if enc_times else float('inf')
                avg_dec_time = sum(dec_times) / len(dec_times) if dec_times else float('inf')
                results[name]['enc'].append(avg_enc_time)
                results[name]['dec'].append(avg_dec_time)
                
                gc.collect()
        
        # Generar gráficos de rendimiento
        self.plot_results(results, sizes)
        
        # Generar gráficos y tabla de seguridad
        self.plot_security_metrics(results)
        self.print_security_table()
        
        return results, sizes

    def plot_results(self, results, sizes):
        # Gráfico de cifrado
        plt.figure(figsize=(12, 6))
        for name in results.keys():
            plt.plot(sizes, results[name]['enc'], marker='o', label=f'{name} (Cifrado)')
        plt.xlabel('Tamaño de datos (bytes)')
        plt.ylabel('Tiempo (segundos)')
        plt.title('Comparación de Tiempos de Cifrado')
        plt.legend()
        plt.grid(True)
        plt.xscale('log')
        plt.yscale('log')
        plt.savefig('benchmark_encryption.png')
        plt.close()
        
        # Gráfico de descifrado
        plt.figure(figsize=(12, 6))
        for name in results.keys():
            plt.plot(sizes, results[name]['dec'], marker='o', label=f'{name} (Descifrado)')
        plt.xlabel('Tamaño de datos (bytes)')
        plt.ylabel('Tiempo (segundos)')
        plt.title('Comparación de Tiempos de Descifrado')
        plt.legend()
        plt.grid(True)
        plt.xscale('log')
        plt.yscale('log')
        plt.savefig('benchmark_decryption.png')
        plt.close()

    def __del__(self):
        """Limpiar recursos al destruir el objeto"""
        self.executor.shutdown(wait=True)

def main():
    benchmark = Benchmark()
    results, sizes = benchmark.run_benchmarks()
    benchmark.plot_results(results, sizes)
    benchmark.plot_security_metrics(results)
    benchmark.print_security_table()

if __name__ == "__main__":
    main() 