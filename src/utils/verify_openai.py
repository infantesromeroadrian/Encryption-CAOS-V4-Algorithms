#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilidad para verificar y actualizar la clave API de OpenAI.
Este script ayuda a los usuarios a verificar si su clave API de OpenAI es válida
y a actualizarla en el archivo .env si es necesario.
"""

import os
import requests
import sys
from pathlib import Path
from dotenv import load_dotenv, set_key

def is_valid_api_key(api_key):
    """
    Verifica si una clave API de OpenAI es válida realizando una solicitud de prueba.
    
    Args:
        api_key: La clave API a verificar
    
    Returns:
        bool: True si la clave es válida, False en caso contrario
    """
    if not api_key or not api_key.startswith('sk-') or len(api_key) < 20:
        return False
        
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    data = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": "This is a test request to verify the API key."},
            {"role": "user", "content": "Say 'API key is valid'"}
        ],
        "max_tokens": 10
    }
    
    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=10
        )
        
        # Si la respuesta es 200, la clave es válida
        return response.status_code == 200
    except Exception:
        return False

def update_api_key(env_path, new_api_key):
    """
    Actualiza la clave API de OpenAI en el archivo .env
    
    Args:
        env_path: Ruta al archivo .env
        new_api_key: Nueva clave API
    
    Returns:
        bool: True si la actualización fue exitosa, False en caso contrario
    """
    try:
        # Asegurarse de que la clave tenga el formato correcto
        if not new_api_key.startswith('sk-'):
            print("❌ Error: La clave API debe comenzar con 'sk-'")
            return False
            
        if len(new_api_key) < 20:
            print("❌ Error: La clave API parece demasiado corta")
            return False
        
        # Actualizar el archivo .env
        set_key(env_path, "OPENAI_API_KEY", new_api_key)
        return True
    except Exception as e:
        print(f"❌ Error al actualizar el archivo .env: {str(e)}")
        return False

def main():
    """Función principal"""
    # Encontrar la ruta al archivo .env
    root_dir = Path(__file__).parent.parent.parent
    env_path = root_dir / ".env"
    env_example_path = root_dir / ".env.example"
    
    print("\n📋 Verificador de clave API de OpenAI 📋")
    print("===========================================")
    
    # Cargar variables de entorno
    load_dotenv(env_path)
    
    # Verificar si el archivo .env existe
    if not env_path.exists():
        print("❓ No se encontró el archivo .env")
        create_env = input("¿Desea crear un archivo .env a partir de .env.example? (s/n): ")
        if create_env.lower() == 's':
            try:
                # Copiar .env.example a .env si existe
                if env_example_path.exists():
                    with open(env_example_path, 'r') as f_example:
                        with open(env_path, 'w') as f_env:
                            f_env.write(f_example.read())
                    print("✅ Archivo .env creado correctamente")
                else:
                    # Crear un archivo .env vacío con la estructura básica
                    with open(env_path, 'w') as f:
                        f.write("# Configuración de OpenAI\nOPENAI_API_KEY=\n")
                    print("✅ Archivo .env creado correctamente (vacío)")
            except Exception as e:
                print(f"❌ Error al crear el archivo .env: {str(e)}")
                return
        else:
            print("❌ Se requiere un archivo .env para continuar")
            return
    
    # Obtener la clave API actual
    current_api_key = os.getenv("OPENAI_API_KEY", "")
    
    # Verificar si la clave API actual es válida
    print("\n🔍 Verificando la clave API actual...")
    if is_valid_api_key(current_api_key):
        print("✅ La clave API de OpenAI es válida")
        print("\n🎉 El sistema RAG debería funcionar correctamente con esta clave.")
        print("    Si tienes problemas, asegúrate de que todas las dependencias estén instaladas:")
        print("    pip install openai requests python-dotenv langchain chromadb")
        return
    else:
        if not current_api_key or current_api_key == "your_openai_api_key_here":
            print("❌ No se ha configurado una clave API válida")
        elif not current_api_key.startswith("sk-"):
            print("❌ La clave API no tiene el formato correcto (debe comenzar con 'sk-')")
        else:
            print("❌ La clave API no es válida o ha expirado")
    
    # Solicitar una nueva clave API
    print("\n🔑 Por favor, proporciona una nueva clave API de OpenAI")
    print("   Puedes obtenerla en: https://platform.openai.com/api-keys")
    new_api_key = input("Nueva clave API: ").strip()
    
    # Verificar si la nueva clave API es válida
    print("\n🔍 Verificando la nueva clave API...")
    if is_valid_api_key(new_api_key):
        # Actualizar el archivo .env
        if update_api_key(env_path, new_api_key):
            print("✅ Clave API actualizada correctamente en el archivo .env")
            print("\n🎉 El sistema RAG debería funcionar correctamente ahora.")
            print("    Reinicia la aplicación para aplicar los cambios.")
        else:
            print("❌ No se pudo actualizar el archivo .env")
    else:
        print("❌ La nueva clave API no es válida")
        print("   Asegúrate de copiar la clave completa y que comience con 'sk-'")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Operación cancelada por el usuario")
    except Exception as e:
        print(f"\n❌ Error inesperado: {str(e)}")
    finally:
        print("\n�� Fin del programa") 