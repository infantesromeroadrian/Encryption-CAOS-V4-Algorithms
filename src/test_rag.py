#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para probar el sistema RAG desde la línea de comandos.
Útil para verificar que la clave API de OpenAI funciona correctamente.
"""

import os
import sys
import json
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Asegurar que src está en el path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Cargar variables de entorno
from dotenv import load_dotenv
load_dotenv()

def print_separator():
    """Imprime una línea separadora para mejor legibilidad."""
    print("\n" + "="*80 + "\n")

def main():
    """Función principal del script."""
    print_separator()
    print("PRUEBA DEL SISTEMA RAG")
    print_separator()
    
    # Verificar la clave API
    api_key = os.getenv("OPENAI_APIKEY")
    if not api_key:
        print("ERROR: No se encontró la clave API de OpenAI en las variables de entorno.")
        print("Asegúrate de tener un archivo .env con una clave válida en la variable OPENAI_APIKEY.")
        return
    
    print(f"Clave API detectada (comienza con {api_key[:4]}...)")
    
    # Intentar importar el sistema RAG
    try:
        from rag.rag_system import answer_crypto_question, reload_api_key
        
        # Recargar la clave API por si acaso
        print("Recargando la clave API...")
        result = reload_api_key()
        print(f"Resultado: {result['message']}")
        
        print_separator()
        print("Ingresa 'salir' para terminar.")
        print_separator()
        
        # Ciclo de preguntas
        while True:
            question = input("\nIngresa tu pregunta sobre criptografía: ")
            if question.lower() in ['salir', 'exit', 'quit', 'q']:
                break
                
            print("\nConsultando al sistema RAG...")
            response = answer_crypto_question(question)
            
            # Si hay una respuesta generada, mostrarla
            if 'answer' in response:
                print_separator()
                print("RESPUESTA:")
                print(response['answer'])
                print_separator()
            else:
                print("No se pudo generar una respuesta.")
            
            # Mostrar fuentes utilizadas
            print("FUENTES UTILIZADAS:")
            for source in response.get('sources', []):
                print(f"- {source['source']} ({source['type']}) - {source['category']}")
            
    except ImportError as e:
        print(f"ERROR: No se pudo importar el sistema RAG: {str(e)}")
        print("Asegúrate de tener instaladas todas las dependencias.")
    except Exception as e:
        print(f"ERROR: {str(e)}")

if __name__ == "__main__":
    main() 