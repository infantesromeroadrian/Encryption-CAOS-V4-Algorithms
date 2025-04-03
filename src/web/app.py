#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interfaz web para probar diferentes algoritmos de encriptación.
Esta aplicación permite interactuar con algoritmos simétricos, asimétricos, 
híbridos y personalizados de encriptación.
"""

import os
import sys
from flask import Flask, session

# Asegurar que src está en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Importaciones para los manejadores de errores y utilidades
from .utils import error_handlers
from .routes import register_routes

# Función para crear la aplicación Flask
def create_app(testing=False):
    """
    Crea y configura la aplicación Flask.
    
    Args:
        testing: Si se está en modo de prueba
        
    Returns:
        Instancia configurada de la aplicación Flask
    """
    # Configurar la aplicación Flask
    app = Flask(__name__, 
                template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates'),
                static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static'))
    
    # Configurar clave secreta para la sesión
    app.secret_key = os.urandom(24)
    
    # Configurar el modo de desarrollo
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.config['TESTING'] = testing
    
    # Configurar logging
    error_handlers.configure_logging(app)
    
    # Registrar los manejadores de errores
    error_handlers.register_error_handlers(app)
    
    # Registrar todas las rutas
    register_routes(app)
    
    # Asegurarse de que los directorios estáticos y de plantillas existan
    for d in ['static', 'templates']:
        full_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), d)
        if not os.path.exists(full_path):
            os.makedirs(full_path)
    
    return app

# Crear una instancia de la aplicación
app = create_app()

# Punto de entrada para ejecución directa
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0') 