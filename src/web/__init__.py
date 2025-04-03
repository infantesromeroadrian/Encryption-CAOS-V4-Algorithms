"""
Módulo que contiene la aplicación web Flask para la interfaz de usuario.
"""

# Crear la instancia de la aplicación
from .app import create_app

# Para mantener compatibilidad con el código existente, exportamos la instancia app
from .app import app 