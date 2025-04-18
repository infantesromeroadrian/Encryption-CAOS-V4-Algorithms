"""
Módulo que contiene las rutas de la aplicación web.
Este paquete agrupa todas las rutas por funcionalidad.
"""

import logging

# Configurar logger
logger = logging.getLogger(__name__)

# Importar rutas principales
from . import main_routes, symmetric_routes, asymmetric_routes, hybrid_routes
from . import custom_routes, hash_routes, signature_routes, benchmark_routes
from .register_routes import metrics_bp

# Intentar importar las rutas de RAG
try:
    from . import rag_routes
    RAG_AVAILABLE = True
except ImportError as e:
    logger.warning(f"No se pudieron importar las rutas de RAG: {str(e)}")
    RAG_AVAILABLE = False

def register_routes(app):
    """
    Registra todas las rutas en la aplicación Flask.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    main_routes.register_routes(app)
    symmetric_routes.register_routes(app)
    asymmetric_routes.register_routes(app)
    hybrid_routes.register_routes(app)
    custom_routes.register_routes(app)
    hash_routes.register_routes(app)
    signature_routes.register_routes(app)
    benchmark_routes.register_routes(app)

    # Registrar el Blueprint de métricas
    app.register_blueprint(metrics_bp)
    
    # Registrar las rutas de RAG si están disponibles
    if RAG_AVAILABLE:
        try:
            logger.info("Registrando rutas de RAG")
            rag_routes.register_routes(app)
        except Exception as e:
            logger.error(f"Error al registrar rutas de RAG: {str(e)}") 