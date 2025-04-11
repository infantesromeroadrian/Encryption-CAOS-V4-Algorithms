"""
Módulo para la implementación de un sistema RAG (Retrieval-Augmented Generation).
Este módulo permite indexar y consultar información sobre criptografía para mejorar
las respuestas del LLM con el contenido específico de la aplicación.
"""

# Asegurar que las variables de entorno se cargan
import os
import logging
from dotenv import load_dotenv

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Cargar variables de entorno
load_dotenv()

# Verificar la clave API
api_key = os.getenv("OPENAI_APIKEY")
if not api_key:
    logger.warning("No se encontró la clave API de OpenAI. El sistema RAG no funcionará correctamente.")
else:
    logger.info(f"Clave API de OpenAI cargada correctamente (comienza con {api_key[:4]}...).")

# Importar componentes principales
try:
    from .rag_system import answer_crypto_question, rebuild_knowledge_base
except ImportError:
    # Manejar caso donde las dependencias no están disponibles
    logger.warning("No se pudieron importar los componentes del RAG. Algunas funciones no estarán disponibles.")
    
    def answer_crypto_question(question):
        return {
            "error": "Sistema RAG no disponible",
            "message": "No se pudieron cargar las dependencias necesarias para el RAG."
        }
    
    def rebuild_knowledge_base():
        return {
            "error": "Sistema RAG no disponible",
            "message": "No se pudieron cargar las dependencias necesarias para el RAG."
        } 