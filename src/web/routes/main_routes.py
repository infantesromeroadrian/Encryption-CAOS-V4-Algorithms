"""
Rutas principales de la aplicación.
Este módulo maneja las solicitudes HTTP para las páginas principales.
"""

from flask import Blueprint, render_template

# Crear un Blueprint para las rutas principales
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Renderiza la página principal."""
    return render_template('index.html')

def register_routes(app):
    """
    Registra las rutas del Blueprint en la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(main_bp) 