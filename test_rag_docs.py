#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para probar el sistema RAG con preguntas específicas sobre la documentación.
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

def test_questions():
    """Prueba el sistema RAG con preguntas específicas sobre la documentación."""
    try:
        # Intentar importar el sistema RAG
        from src.rag.rag_system import answer_crypto_question, rebuild_knowledge_base
        
        # Reconstruir la base de conocimiento para asegurar que tiene la documentación
        print("Reconstruyendo la base de conocimiento...")
        result = rebuild_knowledge_base()
        print(f"Resultado: {result['message']}")
        
        # Lista de preguntas para probar
        questions = [
            "¿Qué es CAOS v4?",
            "¿Cuáles son las principales diferencias entre CAOS v3 y CAOS v4?",
            "¿Qué mejoras de seguridad ofrece CAOS v4?",
            "Explica cómo funciona el algoritmo de cifrado CAOS"
        ]
        
        # Probar cada pregunta
        for i, question in enumerate(questions, 1):
            print_separator()
            print(f"PREGUNTA {i}: {question}")
            print_separator()
            
            # Obtener respuesta
            response = answer_crypto_question(question)
            
            # Mostrar respuesta
            if 'answer' in response:
                print("RESPUESTA:")
                print(response['answer'])
                print_separator()
            else:
                print("No se pudo generar una respuesta.")
            
            # Mostrar fuentes utilizadas (para verificar si se usó la documentación)
            print("FUENTES UTILIZADAS:")
            doc_sources = []
            for source in response.get('sources', []):
                source_info = f"- {source['source']} ({source['type']}) - {source['category']}"
                print(source_info)
                if source['type'] == 'documentation':
                    doc_sources.append(source['source'])
            
            # Verificar si se utilizaron fuentes de documentación
            if doc_sources:
                print("\n✓ Se utilizaron fuentes de documentación:")
                for doc in doc_sources:
                    print(f"  - {doc}")
            else:
                print("\n✗ No se utilizaron fuentes de documentación para esta respuesta.")
            
            print_separator()
            
    except ImportError as e:
        print(f"ERROR: No se pudo importar el sistema RAG: {str(e)}")
        print("Asegúrate de tener instaladas todas las dependencias.")
    except Exception as e:
        print(f"ERROR: {str(e)}")

if __name__ == "__main__":
    test_questions() 