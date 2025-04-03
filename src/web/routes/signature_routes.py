"""
Rutas para las operaciones de firmas digitales.
Este módulo maneja las solicitudes HTTP relacionadas con las firmas digitales.
"""

from flask import Blueprint, request, session
from ..services import signature_service
from ..utils import response_utils

# Crear un Blueprint para las rutas de firmas digitales
signature_bp = Blueprint('signature', __name__)

@signature_bp.route('/digital_signature', methods=['GET', 'POST'])
def digital_signature():
    """Maneja las firmas digitales."""
    result = None
    
    if request.method == 'POST':
        # Obtener datos del formulario
        text = request.form.get('text', '').strip()
        public_key = request.form.get('public_key', '').strip()
        private_key = request.form.get('private_key', '').strip()
        signature = request.form.get('signature', '').strip()
        algorithm = request.form.get('algorithm', 'RSA-PSS')
        action = request.form.get('action', 'sign')
        key_size = int(request.form.get('key_size', 2048))
        
        # Procesar la solicitud utilizando el servicio
        result = signature_service.process_signature_request(
            action=action,
            text=text,
            algorithm=algorithm,
            key_size=key_size,
            public_key=public_key,
            private_key=private_key,
            signature=signature
        )
        
        # Si se generaron claves y fue exitoso, guardar en sesión para uso posterior
        if result.get('success') and action == 'generate_keys':
            session['signature_public_key'] = result.get('public_key', '')
            session['signature_private_key'] = result.get('private_key', '')
    
    # Manejar la respuesta según el tipo de solicitud (AJAX o normal)
    return response_utils.handle_response(
        result=result,
        template_name='digital_signature.html',
        session=session
    )

def register_routes(app):
    """
    Registra las rutas del Blueprint en la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(signature_bp) 