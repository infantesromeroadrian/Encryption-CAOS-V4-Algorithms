"""
Rutas para las operaciones de benchmark.
Este módulo maneja las solicitudes HTTP relacionadas con el benchmark de algoritmos.
"""

from flask import Blueprint, request, session
from ..services import benchmark_service
from ..utils import response_utils
import random
import string

# Crear un Blueprint para las rutas de benchmark
benchmark_bp = Blueprint('benchmark', __name__)

@benchmark_bp.route('/benchmark', methods=['GET', 'POST'])
def benchmark():
    """Maneja el benchmark de algoritmos."""
    result = None
    
    if request.method == 'POST':
        # Obtener datos del formulario
        data_size = int(request.form.get('data_size', 1000))
        password = request.form.get('password', 'benchmark_password').strip()
        category = request.form.get('category', 'all')
        iterations = int(request.form.get('iterations', 5))
        
        # Generar texto de prueba del tamaño especificado
        # Crear una cadena aleatoria para el benchmark
        text = ''.join(random.choices(string.ascii_letters + string.digits, k=data_size))
        
        # Para algoritmos asimétricos necesitamos un texto más pequeño (máximo 245 bytes para RSA-2048)
        # Crear una versión recortada para el benchmark de algoritmos asimétricos
        small_text = text[:200] if len(text) > 200 else text
        
        # Procesar diferentes categorías con textos apropiados para cada una
        if category == 'all':
            # Ejecutar cada categoría con el tamaño de texto apropiado
            symmetric_result = benchmark_service.process_benchmark_request(
                category='symmetric',
                text=text,
                password=password,
                iterations=iterations
            )
            
            asymmetric_result = benchmark_service.process_benchmark_request(
                category='asymmetric',
                text=small_text,  # Usar texto pequeño para RSA
                password=password,
                iterations=iterations
            )
            
            hybrid_result = benchmark_service.process_benchmark_request(
                category='hybrid',
                text=text,
                password=password,
                iterations=iterations
            )
            
            custom_result = benchmark_service.process_benchmark_request(
                category='custom',
                text=text,
                password=password,
                iterations=iterations
            )
            
            # Combinar resultados
            # Cada resultado ya debe tener los elementos formateados correctamente de process_benchmark_request
            combined_results = []
            if symmetric_result['success'] and 'results' in symmetric_result:
                combined_results.extend(symmetric_result['results'])
            if asymmetric_result['success'] and 'results' in asymmetric_result:
                combined_results.extend(asymmetric_result['results'])
            if hybrid_result['success'] and 'results' in hybrid_result:
                combined_results.extend(hybrid_result['results'])
            if custom_result['success'] and 'results' in custom_result:
                combined_results.extend(custom_result['results'])
            
            # Generar un nuevo gráfico para los resultados combinados
            from ..services.benchmark_service import generate_chart
            chart_path = generate_chart(combined_results)
                
            result = {
                'success': True,
                'category': 'all',
                'results': combined_results,
                'chart_path': chart_path  # Añadir ruta del gráfico
            }
        elif category == 'asymmetric':
            # Para algoritmos asimétricos, usar texto pequeño
            result = benchmark_service.process_benchmark_request(
                category=category,
                text=small_text,
                password=password,
                iterations=iterations
            )
        else:
            # Para otros algoritmos, usar el texto completo
            result = benchmark_service.process_benchmark_request(
                category=category,
                text=text,
                password=password,
                iterations=iterations
            )
    
    # Manejar la respuesta según el tipo de solicitud (AJAX o normal)
    return response_utils.handle_response(
        result=result,
        template_name='benchmark.html',
        session=session
    )

def register_routes(app):
    """
    Registra las rutas del Blueprint en la aplicación.
    
    Args:
        app: Instancia de la aplicación Flask
    """
    app.register_blueprint(benchmark_bp) 