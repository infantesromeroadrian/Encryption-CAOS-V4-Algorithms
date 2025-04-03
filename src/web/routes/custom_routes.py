"""
Rutas para las operaciones de cifrado personalizado CAOS V4.0.
Este módulo maneja las solicitudes HTTP relacionadas con el cifrado personalizado.
"""

from flask import Blueprint, request, session
from ..services import custom_service
from ..utils import response_utils

# Crear un Blueprint para las rutas de cifrado personalizado
custom_bp = Blueprint('custom', __name__)

@custom_bp.route('/custom', methods=['GET', 'POST'])
def custom():
    """Maneja la encriptación personalizada CAOS V4.0."""
    result = None
    
    if request.method == 'POST':
        # Obtener datos del formulario
        text = request.form.get('text', '').strip()
        password = request.form.get('password', '').strip()
        algorithm = request.form.get('algorithm', 'CAOS_V4')
        action = request.form.get('action', 'encrypt')
        encrypted = request.form.get('encrypted', '').strip()
        
        # Procesar parámetros específicos del algoritmo
        parameters = {}
        if algorithm == 'CAOS_V4':
            iterations = request.form.get('iterations', '')
            seed = request.form.get('seed', '')
            
            if iterations:
                parameters['iterations'] = int(iterations)
            if seed:
                parameters['seed'] = int(seed)
        else:  # CAOS_V3
            rounds = request.form.get('rounds', '')
            if rounds:
                parameters['rounds'] = int(rounds)
        
        # Procesar la solicitud utilizando el servicio
        result = custom_service.process_custom_request(
            action=action,
            text=text,
            password=password,
            algorithm=algorithm,
            encrypted=encrypted,
            parameters=parameters
        )
        
        # Si la operación fue exitosa, guardar la contraseña en la sesión para facilitar el descifrado
        if result.get('success') and action == 'encrypt':
            session['custom_password'] = password
    
    # Manejar la respuesta según el tipo de solicitud (AJAX o normal)
    return response_utils.handle_response(
        result=result,
        template_name='custom.html',
        session=session
    )

def register_routes(app):
    """
    Registra las rutas del Blueprint en la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(custom_bp) 