import os
import logging
from typing import Optional
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import Chroma
from langchain.chains import RetrievalQA
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate

# Configurar logger
logger = logging.getLogger(__name__)

def get_rag_response(query: str) -> str:
    """
    Obtiene una respuesta usando RAG (Retrieval Augmented Generation).
    
    Args:
        query: La pregunta del usuario
        
    Returns:
        str: La respuesta generada
    """
    try:
        # Verificar que la clave API está configurada
        if not os.getenv('OPENAI_API_KEY'):
            raise ValueError("OPENAI_API_KEY no está configurada")
        
        # Inicializar el modelo de embeddings
        embeddings = OpenAIEmbeddings()
        
        # Cargar la base de datos vectorial
        persist_directory = os.getenv('CHROMA_PERSIST_DIRECTORY', './data/chroma')
        vectordb = Chroma(persist_directory=persist_directory, 
                         embedding_function=embeddings)
        
        # Configurar el prompt
        prompt_template = """Eres un asistente experto en criptografía. 
        Usa el siguiente contexto para responder la pregunta. 
        Si no sabes la respuesta, di que no lo sabes.
        
        Contexto: {context}
        
        Pregunta: {question}
        
        Respuesta:"""
        
        PROMPT = PromptTemplate(
            template=prompt_template, 
            input_variables=["context", "question"]
        )
        
        # Configurar el modelo de chat
        llm = ChatOpenAI(temperature=0, model_name="gpt-3.5-turbo")
        
        # Crear la cadena de QA
        qa_chain = RetrievalQA.from_chain_type(
            llm=llm,
            chain_type="stuff",
            retriever=vectordb.as_retriever(),
            return_source_documents=True,
            chain_type_kwargs={"prompt": PROMPT}
        )
        
        # Obtener la respuesta
        result = qa_chain({"query": query})
        
        return result["result"]
        
    except Exception as e:
        logger.error(f"Error en RAG: {str(e)}")
        return "Lo siento, hubo un error al procesar tu pregunta. Por favor, intenta de nuevo." 