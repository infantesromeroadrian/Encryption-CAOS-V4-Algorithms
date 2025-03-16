#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Servidor simple para servir el frontend.
"""

import http.server
import socketserver
import os

# Puerto en el que se ejecutará el servidor
PORT = 8080

# Directorio actual
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

if __name__ == "__main__":
    # Usar "0.0.0.0" para escuchar en todas las interfaces
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"Servidor ejecutándose en http://0.0.0.0:{PORT}")
        print(f"Accede desde tu navegador a http://localhost:{PORT}")
        httpd.serve_forever() 