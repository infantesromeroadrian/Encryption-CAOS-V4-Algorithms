from flask import Blueprint, send_from_directory
import os

# Crear un Blueprint para las rutas de métricas
metrics_bp = Blueprint('metrics', __name__)

# Ruta para servir el gráfico de métricas de seguridad
@metrics_bp.route('/metrics/security')
def serve_security_metrics():
    return send_from_directory(
        directory=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'benchmark_results'),
        filename='security_metrics.png'
    )

# Ruta para servir el gráfico de cifrado
@metrics_bp.route('/metrics/encryption')
def serve_encryption_metrics():
    return send_from_directory(
        directory=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'benchmark_results'),
        filename='benchmark_encryption.png'
    )

# Ruta para servir el gráfico de descifrado
@metrics_bp.route('/metrics/decryption')
def serve_decryption_metrics():
    return send_from_directory(
        directory=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'benchmark_results'),
        filename='benchmark_decryption.png'
    ) 