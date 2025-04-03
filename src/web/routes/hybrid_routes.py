"""
Rutas para las operaciones de cifrado híbrido.
Este módulo maneja las solicitudes HTTP relacionadas con el cifrado híbrido.
"""

import logging
from flask import Blueprint, request, session
from ..services import hybrid_service
from ..utils import response_utils

# Obtener logger
logger = logging.getLogger(__name__)

# Crear un Blueprint para las rutas de cifrado híbrido
hybrid_bp = Blueprint('hybrid', __name__)

@hybrid_bp.route('/hybrid', methods=['GET', 'POST'])
def hybrid():
    """Maneja la encriptación híbrida."""
    result = None
    
    # Inicializar variables para evitar errores de referencia
    public_key = ''
    private_key = ''
    text = ''
    encrypted_data = ''
    encrypted_key = ''
    
    if request.method == 'POST':
        # Obtener datos del formulario
        action = request.form.get('action', 'encrypt')
        algorithm = request.form.get('algorithm', 'RSA-AES')
        key_size = int(request.form.get('key_size', 2048))
        
        # Obtener mensaje (puede venir como 'message' o 'text')
        text = request.form.get('message', '').strip()
        
        # Obtener claves
        public_key = request.form.get('public_key', '').strip()
        private_key = request.form.get('private_key', '').strip()
        
        # Datos para descifrado
        encrypted_data = request.form.get('encrypted_content', '').strip()
        encrypted_key = request.form.get('metadata', '').strip()
        
        # Logging para depuración
        logger.info(f"Hybrid request: action={action}, message length={len(text)}, "
                     f"encrypted data length={len(encrypted_data)}")
        
        # Procesar la solicitud utilizando el servicio
        result = hybrid_service.process_hybrid_request(
            action=action,
            text=text,
            algorithm=algorithm,
            key_size=key_size,
            public_key=public_key,
            private_key=private_key,
            encrypted_data=encrypted_data,
            encrypted_key=encrypted_key
        )
        
        # Si se generaron claves y fue exitoso, guardar en sesión para uso posterior
        if result.get('success') and action == 'generate_keys':
            session['hybrid_public_key'] = result.get('public_key', '')
            session['hybrid_private_key'] = result.get('private_key', '')
    
    # Manejar la respuesta según el tipo de solicitud (AJAX o normal)
    return response_utils.handle_response(
        result=result,
        template_name='hybrid.html',
        session=session,
        public_key=(result.get('public_key') if result and result.get('success') and 'public_key' in result else public_key),
        private_key=(result.get('private_key') if result and result.get('success') and 'private_key' in result else private_key),
        message=text,
        encrypted_content=(result.get('encrypted_data') if result and result.get('success') and 'encrypted_data' in result else encrypted_data),
        metadata=(result.get('encrypted_key') if result and result.get('success') and 'encrypted_key' in result else encrypted_key)
    )

def register_routes(app):
    """
    Registra las rutas del Blueprint en la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(hybrid_bp)