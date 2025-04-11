FROM python:3.9-slim

WORKDIR /app

# Instalar dependencias del sistema para cryptography y otras bibliotecas
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copiar los archivos de requisitos
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Asegurarse de que las dependencias específicas para RAG estén instaladas
RUN pip install --no-cache-dir requests python-dotenv markdown

# Crear directorios necesarios
RUN mkdir -p /app/src/web/templates /app/src/web/static /app/benchmark_results /app/src/rag /app/docs

# Copiar el código fuente completo
COPY . /app/

# Asegurar que el directorio docs existe y se ha copiado
RUN echo "Verificando carpeta docs" && \
    if [ -d "/app/docs" ]; then \
        echo "Carpeta docs encontrada. Contenido:"; \
        ls -la /app/docs; \
    else \
        echo "ERROR: Carpeta docs no encontrada"; \
        exit 1; \
    fi

# Configurar el PYTHONPATH para incluir src y app
ENV PYTHONPATH="${PYTHONPATH}:/app:/app/src"

# Verificar que todas las dependencias están instaladas
RUN python -c "import requests; import dotenv; import markdown; print('Dependencias para RAG verificadas correctamente')"

# Exponer el puerto
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD ["python", "src/main.py"] 