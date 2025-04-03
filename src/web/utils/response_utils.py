"""
Utilidades para el manejo de respuestas y errores.
Este módulo proporciona funciones para crear respuestas consistentes.
"""

import traceback
from flask import jsonify, render_template, request
from typing import Dict, Any, Union, Optional, Tuple

def create_success_response(
    data: Dict[str, Any], 
    message: Optional[str] = None
) -> Dict[str, Any]:
    """
    Crea una respuesta exitosa estándar.
    
    Args:
        data: Datos a incluir en la respuesta
        message: Mensaje opcional de éxito
        
    Returns:
        Diccionario con la respuesta exitosa
    """
    response = {
        'success': True,
        **data
    }
    
    if message:
        response['message'] = message
    
    return response

def create_error_response(
    error: Union[str, Exception], 
    include_traceback: bool = False
) -> Dict[str, Any]:
    """
    Crea una respuesta de error estándar.
    
    Args:
        error: Error o mensaje de error
        include_traceback: Si se debe incluir el traceback o no
        
    Returns:
        Diccionario con la respuesta de error
    """
    error_message = str(error)
    
    response = {
        'success': False,
        'error': error_message
    }
    
    if include_traceback and isinstance(error, Exception):
        response['traceback'] = traceback.format_exc()
    
    return response

def handle_request_and_render(
    template_name: str, 
    result: Optional[Dict[str, Any]] = None, 
    **kwargs
) -> str:
    """
    Maneja la renderización de plantillas con resultados.
    
    Args:
        template_name: Nombre de la plantilla a renderizar
        result: Resultado a pasar a la plantilla
        **kwargs: Argumentos adicionales para la plantilla
        
    Returns:
        HTML renderizado
    """
    context = kwargs
    if result:
        context['result'] = result
    
    return render_template(template_name, **context)

def is_ajax_request() -> bool:
    """
    Determina si la solicitud actual es una solicitud AJAX.
    
    Returns:
        True si es una solicitud AJAX, False en caso contrario
    """
    return (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
        request.headers.get('Accept') == 'application/json' or
        'application/json' in request.headers.get('Accept', '') or
        request.headers.get('Content-Type') == 'application/json'
    )

def handle_response(
    result: Dict[str, Any], 
    template_name: str, 
    **kwargs
) -> Union[Dict[str, Any], str]:
    """
    Maneja la respuesta dependiendo de si es una solicitud AJAX o no.
    
    Args:
        result: Resultado a devolver
        template_name: Nombre de la plantilla a renderizar si no es AJAX
        **kwargs: Argumentos adicionales para la plantilla
        
    Returns:
        Respuesta JSON o HTML renderizado
    """
    if is_ajax_request():
        return jsonify(result) if result else jsonify({'success': False, 'error': 'Ninguna acción realizada'})
    
    return handle_request_and_render(template_name, result, **kwargs) 