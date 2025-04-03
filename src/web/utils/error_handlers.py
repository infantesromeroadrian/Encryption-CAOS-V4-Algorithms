"""
Manejadores de errores para la aplicación web.
Este módulo proporciona funciones para manejar diferentes tipos de errores.
"""

import logging
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from . import response_utils

def register_error_handlers(app: Flask) -> None:
    """
    Registra los manejadores de errores para la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    @app.errorhandler(400)
    def bad_request_error(error):
        """Manejador para errores 400 Bad Request."""
        app.logger.warning(f"Error 400: {error}")
        if response_utils.is_ajax_request():
            return jsonify(response_utils.create_error_response("Solicitud inválida")), 400
        return render_template('error.html', error=error), 400
    
    @app.errorhandler(404)
    def not_found_error(error):
        """Manejador para errores 404 Not Found."""
        app.logger.warning(f"Error 404: {error}")
        if response_utils.is_ajax_request():
            return jsonify(response_utils.create_error_response("Recurso no encontrado")), 404
        return render_template('error.html', error=error), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Manejador para errores 500 Internal Server Error."""
        app.logger.error(f"Error 500: {error}")
        if response_utils.is_ajax_request():
            return jsonify(response_utils.create_error_response("Error interno del servidor")), 500
        return render_template('error.html', error=error), 500
    
    @app.errorhandler(Exception)
    def unhandled_exception(error):
        """Manejador para excepciones no manejadas."""
        app.logger.error(f"Excepción no manejada: {error}", exc_info=True)
        if response_utils.is_ajax_request():
            return jsonify(response_utils.create_error_response(error, include_traceback=app.debug)), 500
        return render_template('error.html', error=error), 500
    
    @app.errorhandler(HTTPException)
    def http_exception(error):
        """Manejador para excepciones HTTP."""
        app.logger.warning(f"Excepción HTTP {error.code}: {error}")
        if response_utils.is_ajax_request():
            return jsonify(response_utils.create_error_response(error.description)), error.code
        return render_template('error.html', error=error), error.code

def configure_logging(app: Flask) -> None:
    """
    Configura el logging para la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO if not app.debug else logging.DEBUG) 