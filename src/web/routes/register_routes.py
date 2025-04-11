"""
Registro centralizado de rutas para la aplicación.
"""

from flask import Blueprint, send_from_directory, jsonify
import os
import logging
import sys

# Configurar logger
logger = logging.getLogger(__name__)

# Crear blueprint para métricas y monitoreo
metrics_bp = Blueprint('metrics', __name__, url_prefix='/metrics')

# Blueprint para informar sobre el estado de RAG
rag_status_bp = Blueprint('rag_status', __name__, url_prefix='/api/rag')

# Importar los blueprints existentes
from .main_routes import main_bp
from .symmetric_routes import symmetric_bp
from .asymmetric_routes import asymmetric_bp
from .hybrid_routes import hybrid_bp
from .custom_routes import custom_bp
from .hash_routes import hash_bp
from .signature_routes import signature_bp
from .benchmark_routes import benchmark_bp

# Verificar disponibilidad de RAG
RAG_AVAILABLE = False
RAG_MISSING_PACKAGES = []

try:
    # Verificar requests
    try:
        import requests
    except ImportError:
        RAG_MISSING_PACKAGES.append('requests')
        raise ImportError("El paquete 'requests' no está instalado")
        
    # Verificar langchain
    try:
        import langchain
    except ImportError:
        RAG_MISSING_PACKAGES.append('langchain')
        raise ImportError("El paquete 'langchain' no está instalado")
    
    # Verificar chromadb
    try:
        import chromadb
    except ImportError:
        RAG_MISSING_PACKAGES.append('chromadb')
        raise ImportError("El paquete 'chromadb' no está instalado")
    
    # Si llegamos aquí, podemos importar las rutas de RAG
    from . import rag_routes
    RAG_AVAILABLE = True
    
except ImportError as e:
    install_command = f"pip install {' '.join(RAG_MISSING_PACKAGES)}"
    logger.warning(f"No se pudieron importar las rutas de RAG: {str(e)}")
    logger.info(f"Para habilitar la funcionalidad RAG, instale los paquetes faltantes: {install_command}")
    RAG_AVAILABLE = False

def register_routes(app):
    """
    Registra todas las rutas en la aplicación Flask.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(main_bp)
    app.register_blueprint(symmetric_bp)
    app.register_blueprint(asymmetric_bp)
    app.register_blueprint(hybrid_bp)
    app.register_blueprint(custom_bp)
    app.register_blueprint(hash_bp)
    app.register_blueprint(signature_bp)
    app.register_blueprint(benchmark_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(rag_status_bp)
    
    # Registrar las rutas de RAG si están disponibles
    if RAG_AVAILABLE:
        try:
            logger.info("Registrando rutas de RAG")
            rag_routes.register_routes(app)
        except Exception as e:
            logger.error(f"Error al registrar rutas de RAG: {str(e)}")
            RAG_AVAILABLE = False
            RAG_MISSING_PACKAGES.append("Configuración incorrecta")

# Endpoint para verificar el estado de RAG
@rag_status_bp.route('/status')
def rag_status():
    """Retorna el estado de la funcionalidad RAG y los paquetes faltantes si corresponde."""
    if RAG_AVAILABLE:
        return jsonify({
            "status": "available",
            "message": "La funcionalidad RAG está disponible y configurada correctamente."
        })
    else:
        python_executable = sys.executable
        install_command = f"{python_executable} -m pip install {' '.join(RAG_MISSING_PACKAGES)}"
        return jsonify({
            "status": "unavailable",
            "message": "La funcionalidad RAG no está disponible.",
            "missing_packages": RAG_MISSING_PACKAGES,
            "install_command": install_command,
            "note": "Asegúrese de que las dependencias estén correctamente instaladas en el entorno de la aplicación (contenedor Docker o entorno virtual)."
        })

# Ruta para servir el gráfico de métricas de seguridad
@metrics_bp.route('/security')
def serve_security_metrics():
    return send_from_directory(
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'static', 'benchmark'),
        'security_metrics.html'
    )

# Ruta para servir el gráfico de cifrado
@metrics_bp.route('/encryption')
def serve_encryption_metrics():
    return send_from_directory(
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'static', 'benchmark'),
        'encryption_metrics.html'
    )

# Ruta para servir el gráfico de descifrado
@metrics_bp.route('/decryption')
def serve_decryption_metrics():
    return send_from_directory(
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'static', 'benchmark'),
        'decryption_metrics.html'
    )

# API para métricas simplificadas
@metrics_bp.route('/api')
def metrics_api():
    """Retorna métricas simplificadas para seguridad y cifrado."""
    return jsonify({
        "security": {
            "hash_algorithms": ["SHA-256", "SHA-512", "BLAKE2"],
            "signature_algorithms": ["RSA", "DSA", "ECDSA"],
            "recommendation": "Para máxima seguridad, utilice SHA-512 o BLAKE2 para hashing y ECDSA para firmas digitales."
        },
        "encryption": {
            "symmetric": ["AES", "ChaCha20"],
            "asymmetric": ["RSA", "ECC"],
            "hybrid": ["RSA+AES", "ECC+ChaCha20"],
            "recommendation": "Para mejor rendimiento con alta seguridad, utilice cifrado híbrido con ECC+ChaCha20."
        }
    }) 