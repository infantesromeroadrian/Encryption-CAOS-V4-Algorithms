"""
Rutas para las operaciones de funciones hash.
Este módulo maneja las solicitudes HTTP relacionadas con las funciones hash.
"""

from flask import Blueprint, request, session
from ..services import hash_service
from ..utils import response_utils

# Crear un Blueprint para las rutas de funciones hash
hash_bp = Blueprint('hash', __name__)

@hash_bp.route('/hash', methods=['GET', 'POST'])
def hash_functions():
    """Maneja las funciones hash."""
    result = None
    
    if request.method == 'POST':
        # Obtener datos del formulario
        text = request.form.get('text', '').strip()
        hash_value = request.form.get('hash_value', '').strip()
        algorithm = request.form.get('algorithm', 'sha256')
        action = request.form.get('action', 'calculate')
        
        # Procesar la solicitud utilizando el servicio
        result = hash_service.process_hash_request(
            action=action,
            text=text,
            algorithm=algorithm,
            hash_value=hash_value
        )
    
    # Manejar la respuesta según el tipo de solicitud (AJAX o normal)
    return response_utils.handle_response(
        result=result,
        template_name='hash.html',
        session=session
    )

def register_routes(app):
    """
    Registra las rutas del Blueprint en la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(hash_bp) 