#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema RAG (Retrieval-Augmented Generation) para consultas sobre criptografía.
Este módulo implementa un sistema que indexa información de criptografía
y proporciona respuestas contextuales basadas en el contenido de la aplicación.
"""

import os
import re
import json
import logging
from pathlib import Path
import inspect
import requests
import markdown
from typing import Dict, List, Optional, Tuple, Union
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Establecer logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importar módulos del proyecto para extraer información
import algorithms
import hash_and_signatures

class CryptoKnowledgeBase:
    """
    Base de conocimiento sobre criptografía que indexa y consulta información
    de los módulos de la aplicación.
    """
    def __init__(self):
        """
        Inicializa la base de conocimiento.
        """
        self.documents = []
        self.openai_api_key = os.getenv("OPENAI_APIKEY")
        self.content_path = Path(os.path.dirname(os.path.abspath(__file__))) / "crypto_content.json"
        
        # Cargar contenido si existe
        if self.content_path.exists():
            self.load_content()
        else:
            # Construir índice
            self.build_index()
            
    def extract_docstring(self, obj) -> Optional[str]:
        """
        Extrae el docstring de un objeto.
        
        Args:
            obj: Objeto del que extraer el docstring
            
        Returns:
            Docstring o None si no existe
        """
        doc = inspect.getdoc(obj)
        if doc:
            return doc
        return None
    
    def extract_function_content(self, func) -> str:
        """
        Extrae el contenido de una función.
        
        Args:
            func: Función de la que extraer el contenido
            
        Returns:
            Contenido de la función como texto
        """
        source = inspect.getsource(func)
        # Remover la definición de la función y quedarse solo con el cuerpo
        lines = source.split('\n')
        indent = len(lines[0]) - len(lines[0].lstrip())
        body_lines = []
        
        for i, line in enumerate(lines):
            if i == 0:
                # Conservar la definición para contexto
                body_lines.append(line)
            elif line.strip() and len(line) - len(line.lstrip()) >= indent:
                # Solo líneas con indentación igual o mayor a la de la función
                body_lines.append(line)
        
        return '\n'.join(body_lines)
    
    def build_index(self):
        """
        Construye el índice de conocimiento analizando los módulos de la aplicación.
        """
        logger.info("Construyendo índice de conocimiento de criptografía...")
        self.documents = []
        
        # Indexar documentación de algoritmos
        self._index_module(algorithms, "Algoritmos de Criptografía")
        
        # Indexar documentación de funciones hash y firmas
        self._index_module(hash_and_signatures, "Hash y Firmas Digitales")
        
        # Añadir conocimiento general sobre criptografía
        self._add_general_knowledge()
        
        # Indexar documentos en la carpeta docs
        self._index_documentation_files()
        
        # Guardar índice
        self.save_content()
        logger.info("Índice construido y guardado correctamente.")
    
    def _index_module(self, module, category: str):
        """
        Indexa un módulo completo.
        
        Args:
            module: Módulo a indexar
            category: Categoría del módulo
        """
        logger.info(f"Indexando módulo: {module.__name__}")
        
        # Añadir docstring del módulo
        module_doc = self.extract_docstring(module)
        if module_doc:
            self.documents.append({
                'content': f"Módulo {module.__name__}: {module_doc}",
                'source': f"{module.__name__}",
                'type': 'module',
                'category': category
            })
        
        # Recorrer todos los elementos del módulo
        for name, obj in inspect.getmembers(module):
            # Ignorar elementos privados
            if name.startswith('_'):
                continue
                
            # Indexar funciones
            if inspect.isfunction(obj):
                self._index_function(obj, category)
            
            # Indexar clases
            elif inspect.isclass(obj):
                self._index_class(obj, category)
                
            # Indexar submódulos
            elif inspect.ismodule(obj) and obj.__name__.startswith(module.__name__):
                self._index_module(obj, category)
    
    def _index_function(self, func, category: str):
        """
        Indexa una función y su docstring.
        
        Args:
            func: Función a indexar
            category: Categoría de la función
        """
        # Obtener docstring
        doc = self.extract_docstring(func)
        if not doc:
            return
            
        # Añadir función con su documentación
        func_content = self.extract_function_content(func)
        self.documents.append({
            'content': f"Función {func.__name__}: {doc}\n\nCódigo:\n{func_content}",
            'source': f"{func.__module__}.{func.__name__}",
            'type': 'function',
            'category': category
        })
    
    def _index_class(self, cls, category: str):
        """
        Indexa una clase, sus métodos y su docstring.
        
        Args:
            cls: Clase a indexar
            category: Categoría de la clase
        """
        # Obtener docstring de la clase
        class_doc = self.extract_docstring(cls)
        if class_doc:
            self.documents.append({
                'content': f"Clase {cls.__name__}: {class_doc}",
                'source': f"{cls.__module__}.{cls.__name__}",
                'type': 'class',
                'category': category
            })
            
        # Indexar métodos de la clase
        for name, method in inspect.getmembers(cls, inspect.isfunction):
            if name.startswith('_') and name != '__init__':
                continue
                
            # Obtener docstring del método
            method_doc = self.extract_docstring(method)
            if not method_doc:
                continue
                
            # Añadir método con su documentación
            method_content = self.extract_function_content(method)
            self.documents.append({
                'content': f"Método {cls.__name__}.{method.__name__}: {method_doc}\n\nCódigo:\n{method_content}",
                'source': f"{cls.__module__}.{cls.__name__}.{method.__name__}",
                'type': 'method',
                'category': category
            })
    
    def _add_general_knowledge(self):
        """
        Añade conocimiento general sobre criptografía al índice.
        """
        general_knowledge = [
            {
                'content': """La criptografía simétrica utiliza la misma clave para cifrar y descifrar.
                Algoritmos comunes incluyen AES, DES y 3DES. La principal ventaja es su velocidad,
                pero el problema es la distribución segura de claves.""",
                'source': 'general_knowledge',
                'type': 'concept',
                'category': 'Conceptos de Criptografía'
            },
            {
                'content': """La criptografía asimétrica utiliza un par de claves: pública y privada.
                La clave pública puede compartirse libremente, mientras que la privada debe mantenerse secreta.
                Algoritmos comunes incluyen RSA, DSA y ECC. Son más lentos que los simétricos pero resuelven
                el problema de distribución de claves.""",
                'source': 'general_knowledge',
                'type': 'concept',
                'category': 'Conceptos de Criptografía'
            },
            {
                'content': """Las funciones hash son algoritmos que convierten datos de cualquier tamaño
                en una cadena de longitud fija. Son de un solo sentido (no pueden revertirse) y se utilizan
                para verificar integridad de datos y almacenar contraseñas. Ejemplos incluyen MD5, SHA-1,
                SHA-256 y BLAKE2.""",
                'source': 'general_knowledge',
                'type': 'concept',
                'category': 'Conceptos de Criptografía'
            },
            {
                'content': """La criptografía híbrida combina las ventajas de los sistemas simétricos y asimétricos.
                Utiliza criptografía asimétrica para intercambiar una clave simétrica temporal, que luego se usa
                para cifrar los datos reales. Es el enfoque utilizado en protocolos como SSL/TLS.""",
                'source': 'general_knowledge',
                'type': 'concept',
                'category': 'Conceptos de Criptografía'
            },
            {
                'content': """Las firmas digitales proporcionan autenticidad e integridad a los mensajes.
                Funcionan mediante el cifrado de un hash del mensaje con la clave privada del remitente.
                Cualquiera con la clave pública correspondiente puede verificar que el mensaje no ha sido
                alterado y proviene del remitente correcto.""",
                'source': 'general_knowledge',
                'type': 'concept',
                'category': 'Conceptos de Criptografía'
            }
        ]
        
        self.documents.extend(general_knowledge)
    
    def save_content(self):
        """
        Guarda el contenido en disco.
        """
        # Guardar documentos
        with open(self.content_path, 'w', encoding='utf-8') as f:
            json.dump(self.documents, f, ensure_ascii=False, indent=2)
    
    def load_content(self):
        """
        Carga el contenido desde disco.
        """
        try:
            # Cargar documentos
            with open(self.content_path, 'r', encoding='utf-8') as f:
                self.documents = json.load(f)
                
            logger.info(f"Contenido cargado correctamente: {len(self.documents)} documentos.")
        except Exception as e:
            logger.error(f"Error al cargar el contenido: {str(e)}")
            # Reconstruir el índice si hay error
            self.build_index()
    
    def query(self, question: str, top_k: int = 3) -> List[Dict]:
        """
        Consulta la base de conocimiento con una pregunta usando la API de OpenAI.
        
        Args:
            question: Pregunta sobre criptografía
            top_k: Número máximo de resultados a devolver
            
        Returns:
            Lista de documentos relevantes
        """
        if not self.openai_api_key:
            logger.error("No se ha proporcionado una API key para OpenAI")
            return []
            
        try:
            # Usar OpenAI para encontrar documentos relevantes
            results = []
            
            # Método simple basado en palabras clave para simular búsqueda semántica
            keywords = self._extract_keywords(question.lower())
            
            for doc in self.documents:
                # Calcular una puntuación simple basada en coincidencias de palabras clave
                content = doc['content'].lower()
                score = sum(1 for keyword in keywords if keyword in content)
                
                if score > 0:
                    doc_copy = doc.copy()
                    doc_copy['score'] = score / len(keywords)
                    results.append(doc_copy)
            
            # Ordenar por puntuación
            results.sort(key=lambda x: x['score'], reverse=True)
            
            # Limitar a top_k resultados
            return results[:top_k]
                
        except Exception as e:
            logger.error(f"Error al consultar la API de OpenAI: {str(e)}")
            return []
    
    def _extract_keywords(self, text: str) -> List[str]:
        """
        Extrae palabras clave de una pregunta.
        
        Args:
            text: Texto del que extraer palabras clave
            
        Returns:
            Lista de palabras clave
        """
        # Eliminar palabras comunes
        stop_words = {'de', 'la', 'el', 'en', 'y', 'a', 'que', 'es', 'para', 'por', 'con', 'se', 'un', 'una'}
        
        # Extraer palabras clave (simplificado)
        words = re.findall(r'\b\w+\b', text.lower())
        keywords = [word for word in words if word not in stop_words and len(word) > 2]
        
        # Para preguntas específicas, añadir términos relacionados
        if 'simétric' in text:
            keywords.extend(['aes', 'des', 'clave', 'cbc', 'gcm'])
        elif 'asimétric' in text:
            keywords.extend(['rsa', 'ecc', 'pública', 'privada'])
        elif 'hash' in text:
            keywords.extend(['sha256', 'md5', 'integrity', 'sha512', 'blake2'])
        elif 'firma' in text or 'signature' in text:
            keywords.extend(['digital', 'pki', 'integridad', 'autenticidad'])
        elif 'híbrid' in text:
            keywords.extend(['rsa', 'aes', 'asimétrica', 'simétrica'])
        
        return keywords

    def _index_documentation_files(self):
        """
        Indexa archivos de documentación en Markdown y posiblemente PDF del directorio docs.
        """
        docs_path = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))) / "docs"
        
        if not docs_path.exists():
            logger.warning(f"El directorio de documentación {docs_path} no existe.")
            return
            
        logger.info(f"Indexando documentos de {docs_path}")
        
        # Indexar archivos Markdown
        for md_file in docs_path.glob("*.md"):
            try:
                # Leer contenido del archivo
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Convertir Markdown a texto plano 
                # (eliminamos las etiquetas HTML pero mantenemos la estructura)
                html_content = markdown.markdown(content)
                text_content = re.sub(r'<[^>]+>', '', html_content)
                
                # Obtener título del documento (primera línea con # o nombre del archivo)
                title = md_file.stem.replace('_', ' ')
                match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
                if match:
                    title = match.group(1)
                    
                # Generar metadatos para la documentación
                doc_name = md_file.stem
                source = f"docs.{doc_name}"
                
                # Determinar categoría basada en el nombre del archivo
                category = "Documentación General"
                if "caos" in doc_name.lower() or "v3" in doc_name.lower() or "v4" in doc_name.lower():
                    category = "Documentación CAOS"
                elif "informe" in doc_name.lower() or "tecnico" in doc_name.lower():
                    category = "Informes Técnicos"
                elif "presentacion" in doc_name.lower():
                    category = "Presentaciones"
                
                # Añadir al índice
                self.documents.append({
                    'content': f"Documento {title}:\n\n{text_content}",
                    'source': source,
                    'type': 'documentation',
                    'category': category
                })
                
                logger.info(f"Documento indexado: {md_file.name}")
                
            except Exception as e:
                logger.error(f"Error al indexar el documento {md_file}: {str(e)}")
        
        # TODO: En una implementación futura, podríamos añadir soporte para indexar PDFs
        # utilizando una biblioteca como PyPDF2 o pdfminer.six

class CryptoRAG:
    """
    Sistema RAG para responder preguntas sobre criptografía utilizando
    la base de conocimiento y la API de OpenAI.
    """
    def __init__(self):
        """Inicializa el sistema RAG."""
        # Recargar variables de entorno para asegurar que tenemos los valores más recientes
        load_dotenv()
        
        # Inicializar la base de conocimiento
        self.kb = CryptoKnowledgeBase()
        
        # Obtener la clave API más reciente
        self.openai_api_key = os.getenv("OPENAI_APIKEY")
        
        # Verificar si tenemos una clave API válida
        if not self.openai_api_key:
            logger.error("No se encontró la clave API de OpenAI. Las consultas al LLM no funcionarán.")
        else:
            # Solo mostrar los primeros caracteres por seguridad
            logger.info(f"CryptoRAG inicializado con clave API que comienza con {self.openai_api_key[:4]}...")
        
    def answer_question(self, question: str) -> Dict:
        """
        Responde a una pregunta sobre criptografía.
        
        Args:
            question: Pregunta del usuario
            
        Returns:
            Diccionario con la respuesta y el contexto
        """
        # Obtener documentos relevantes
        relevant_docs = self.kb.query(question, top_k=3)
        
        # Crear un contexto para el LLM
        context = "\n\n".join([f"Fuente: {doc['source']} ({doc['type']})\n{doc['content']}" 
                              for doc in relevant_docs])
        
        # Generar respuesta con OpenAI si tenemos la clave
        answer = self._generate_answer_with_openai(question, context) if self.openai_api_key else None
        
        # La respuesta contiene el contexto para que el LLM pueda generar una respuesta
        response = {
            'question': question,
            'context': context,
            'sources': [{'source': doc['source'], 'type': doc['type'], 'category': doc['category']} 
                        for doc in relevant_docs]
        }
        
        # Añadir la respuesta generada si existe
        if answer:
            response['answer'] = answer
            
        return response
    
    def _generate_answer_with_openai(self, question: str, context: str) -> str:
        """
        Genera una respuesta utilizando la API de OpenAI.
        
        Args:
            question: Pregunta del usuario
            context: Contexto relevante para la respuesta
            
        Returns:
            Respuesta generada por OpenAI
        """
        try:
            # Verificar que la clave API está disponible
            if not self.openai_api_key:
                logger.error("No se encontró la clave API de OpenAI en las variables de entorno")
                return "Error: No se ha configurado la clave API de OpenAI. Por favor, configura la variable de entorno OPENAI_APIKEY."
                
            # Imprimir primeros caracteres de la clave para depuración
            # (No mostrar la clave completa por seguridad)
            api_key_start = self.openai_api_key[:4] if self.openai_api_key else "None"
            logger.info(f"Utilizando clave API que comienza con: {api_key_start}...")
            
            # Configurar parámetros para la API de OpenAI
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.openai_api_key}"
            }
            
            # Preparar el prompt
            prompt = f"Eres un asistente experto en criptografía y seguridad informática. " \
                    f"Responde a la siguiente pregunta basándote en el contexto proporcionado. " \
                    f"Si la información no está en el contexto, utiliza tu conocimiento general " \
                    f"pero indica que es tu conocimiento y no de la base de datos.\n\n" \
                    f"Pregunta: {question}\n\n" \
                    f"Contexto:\n{context}\n\n" \
                    f"Respuesta:"
            
            # Preparar la solicitud
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "system", "content": "Eres un asistente experto en criptografía que proporciona información concisa y técnicamente correcta."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 500
            }
            
            # Registrar que estamos enviando la solicitud
            logger.info(f"Enviando solicitud a la API de OpenAI para la pregunta: {question[:50]}...")
            
            # Realizar la solicitud a la API de OpenAI
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            # Verificar el código de estado y registrar respuesta para depuración
            logger.info(f"Código de estado de la respuesta: {response.status_code}")
            
            # Si hubo un error, registrarlo detalladamente
            if response.status_code != 200:
                error_info = response.json() if response.text else "No se pudo obtener información del error"
                logger.error(f"Error en la respuesta de OpenAI: {error_info}")
                return f"Error al comunicarse con OpenAI (Código {response.status_code}). Por favor, verifica que tu clave API es válida y está activa."
            
            response.raise_for_status()
            
            # Extraer la respuesta
            response_data = response.json()
            generated_text = response_data['choices'][0]['message']['content'].strip()
            
            return generated_text
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error de conexión con la API de OpenAI: {str(e)}")
            return "Error de conexión con la API de OpenAI. Por favor, verifica tu conexión a internet y que la API esté disponible."
        except KeyError as e:
            logger.error(f"Error en la estructura de respuesta de OpenAI: {str(e)}")
            return "Error en el formato de respuesta de OpenAI. La estructura de la respuesta no es la esperada."
        except Exception as e:
            logger.error(f"Error al generar respuesta con OpenAI: {str(e)}", exc_info=True)
            return f"Lo siento, ha ocurrido un error al generar la respuesta: {str(e)}"

# Instancia del sistema RAG disponible globalmente
crypto_rag = CryptoRAG()

def answer_crypto_question(question: str) -> Dict:
    """
    Función de utilidad para responder preguntas de criptografía.
    
    Args:
        question: Pregunta del usuario
        
    Returns:
        Respuesta con contexto y fuentes
    """
    return crypto_rag.answer_question(question)

def rebuild_knowledge_base():
    """Reconstruye la base de conocimiento."""
    global crypto_rag
    crypto_rag = CryptoRAG()
    crypto_rag.kb.build_index()
    return {"status": "success", "message": "Base de conocimiento reconstruida correctamente."}

def reload_api_key():
    """
    Recarga la clave API de OpenAI.
    Útil cuando se ha actualizado el archivo .env
    """
    global crypto_rag
    # Recargar variables de entorno
    load_dotenv()
    # Crear una nueva instancia del RAG para que tome la nueva clave
    crypto_rag = CryptoRAG()
    api_key = os.getenv("OPENAI_APIKEY")
    if api_key:
        return {"status": "success", "message": f"Clave API recargada correctamente (comienza con {api_key[:4]}...)."}
    else:
        return {"status": "error", "message": "No se encontró la clave API de OpenAI después de la recarga."} 