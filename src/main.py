#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CryptoLab - Herramienta educativa para aprender sobre algoritmos de encriptación
Este script es el punto de entrada principal de la aplicación.
"""

import os
import sys

# Asegurar que src está en el path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Importar la aplicación Flask desde el paquete web
from web import app

if __name__ == "__main__":
    # Crear directorios necesarios
    for d in ['templates', 'static']:
        full_path = os.path.join(os.path.dirname(__file__), d)
        if not os.path.exists(full_path):
            os.makedirs(full_path)
    
    # Ejecutar la aplicación
    app.run(debug=True, host='0.0.0.0') 