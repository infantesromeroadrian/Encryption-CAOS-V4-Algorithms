"""
Módulo para la implementación de un sistema RAG (Retrieval-Augmented Generation).
Este módulo permite indexar y consultar información sobre criptografía para mejorar
las respuestas del LLM con el contenido específico de la aplicación.
"""

# Importar componentes principales
try:
    from .rag_system import answer_crypto_question, rebuild_knowledge_base
except ImportError:
    # Manejar caso donde las dependencias no están disponibles
    import logging
    logging.warning("No se pudieron importar los componentes del RAG. Algunas funciones no estarán disponibles.")
    
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