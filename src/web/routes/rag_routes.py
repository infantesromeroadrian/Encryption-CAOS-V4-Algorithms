#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rutas para la interfaz de consulta de RAG sobre criptografía.
Permite a los usuarios hacer preguntas y obtener respuestas basadas en el conocimiento
del sistema.
"""

from flask import Blueprint, render_template, request, jsonify, current_app
import json
import logging
import importlib.util

# Configurar logger
logger = logging.getLogger(__name__)

# Crear el blueprint
rag_bp = Blueprint('rag', __name__, url_prefix='/rag')

# Verificar si las dependencias necesarias están disponibles
DEPENDENCIES_AVAILABLE = True
try:
    # Importar el sistema RAG
    from rag.rag_system import answer_crypto_question, rebuild_knowledge_base
    import requests
    from dotenv import load_dotenv
except ImportError as e:
    logger.error(f"Error al importar dependencias para RAG: {str(e)}")
    DEPENDENCIES_AVAILABLE = False

@rag_bp.route('/')
def rag_home():
    """Página principal del sistema RAG."""
    return render_template('rag.html')

@rag_bp.route('/status')
def rag_status():
    """Devuelve el estado del sistema RAG."""
    status = {
        "available": DEPENDENCIES_AVAILABLE,
        "message": "Sistema RAG disponible y funcionando correctamente." if DEPENDENCIES_AVAILABLE else "Sistema RAG no disponible. Faltan dependencias."
    }
    return jsonify(status)

@rag_bp.route('/query', methods=['POST'])
def query_rag():
    """
    Endpoint para realizar consultas al sistema RAG.
    
    Recibe una pregunta del usuario y devuelve la respuesta con contexto.
    """
    if not DEPENDENCIES_AVAILABLE:
        return jsonify({
            "error": "Sistema RAG no disponible",
            "message": "No se pudieron cargar las dependencias necesarias para el RAG.",
            "fix": "Instale las dependencias con 'pip install requests python-dotenv'"
        }), 503
    
    try:
        # Obtener la pregunta del usuario
        data = request.get_json()
        question = data.get('question', '')
        
        if not question:
            return jsonify({'error': 'No se ha proporcionado una pregunta'}), 400
            
        # Registrar la pregunta para análisis
        logger.info(f"RAG Query: {question}")
        
        # Obtener respuesta del sistema RAG
        response = answer_crypto_question(question)
        
        # Devolver respuesta
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error al procesar consulta RAG: {str(e)}")
        return jsonify({
            'error': 'Error al procesar la consulta',
            'message': str(e)
        }), 500

@rag_bp.route('/rebuild', methods=['POST'])
def rebuild_kb():
    """
    Endpoint para reconstruir la base de conocimiento.
    
    Solo debe usarse cuando se actualice el código fuente con nueva información.
    """
    if not DEPENDENCIES_AVAILABLE:
        return jsonify({
            "error": "Sistema RAG no disponible",
            "message": "No se pudieron cargar las dependencias necesarias para el RAG.",
            "fix": "Instale las dependencias con 'pip install requests python-dotenv'"
        }), 503
    
    try:
        # Comprobar credenciales (en un sistema real, implementaríamos autenticación)
        data = request.get_json()
        admin_key = data.get('admin_key', '')
        
        # Clave simple para este ejemplo (en un sistema real, usaríamos autenticación adecuada)
        if admin_key != 'crypto_admin':
            return jsonify({'error': 'No autorizado'}), 403
            
        # Reconstruir la base de conocimiento
        result = rebuild_knowledge_base()
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error al reconstruir base de conocimiento: {str(e)}")
        return jsonify({
            'error': 'Error al reconstruir la base de conocimiento',
            'message': str(e)
        }), 500

def register_routes(app):
    """
    Registra las rutas del sistema RAG en la aplicación Flask.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(rag_bp) 