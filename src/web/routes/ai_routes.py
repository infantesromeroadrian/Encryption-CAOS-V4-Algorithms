from flask import Blueprint, request, jsonify
import os
import sys
import logging
from ..utils.rag_utils import get_rag_response

# Configurar logger
logger = logging.getLogger(__name__)

# Crear Blueprint
ai_bp = Blueprint('ai', __name__)

@ai_bp.route('/api/ai/chat', methods=['POST'])
def chat():
    """
    Endpoint para el chat con el asistente de AI.
    Utiliza RAG para proporcionar respuestas contextuales sobre criptografía.
    """
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        if not user_message:
            return jsonify({
                'error': 'El mensaje no puede estar vacío'
            }), 400

        # Obtener respuesta usando RAG
        response = get_rag_response(user_message)
        
        return jsonify({
            'response': response
        })

    except Exception as e:
        logger.error(f"Error en el chat de AI: {str(e)}")
        return jsonify({
            'error': 'Hubo un error al procesar tu pregunta'
        }), 500 