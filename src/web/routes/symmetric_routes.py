"""
Rutas para las operaciones de cifrado simétrico.
Este módulo maneja las solicitudes HTTP relacionadas con el cifrado simétrico.
"""

from flask import Blueprint, request, session
from ..services import symmetric_service
from ..utils import response_utils

# Crear un Blueprint para las rutas de cifrado simétrico
symmetric_bp = Blueprint('symmetric', __name__)

@symmetric_bp.route('/symmetric', methods=['GET', 'POST'])
def symmetric():
    """Maneja la encriptación simétrica."""
    result = None
    
    if request.method == 'POST':
        # Obtener datos del formulario
        text = request.form.get('text', '').strip()
        password = request.form.get('password', '').strip()
        algorithm = request.form.get('algorithm', 'AES')
        mode = request.form.get('mode', 'CBC')
        action = request.form.get('action', 'encrypt')
        encrypted = request.form.get('encrypted', '').strip()
        iv = request.form.get('iv', '').strip()
        
        # Procesar la solicitud utilizando el servicio
        result = symmetric_service.process_symmetric_request(
            action=action,
            text=text,
            password=password,
            algorithm=algorithm,
            mode=mode,
            encrypted=encrypted,
            iv=iv
        )
        
        # Si la operación fue exitosa y se usó el modo CBC para cifrar,
        # guardar la contraseña en la sesión para facilitar el descifrado
        if result.get('success') and action == 'encrypt' and mode == 'CBC':
            session['last_encryption_password'] = password
    
    # Manejar la respuesta según el tipo de solicitud (AJAX o normal)
    return response_utils.handle_response(
        result=result,
        template_name='symmetric.html',
        session=session
    )

def register_routes(app):
    """
    Registra las rutas del Blueprint en la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(symmetric_bp) 