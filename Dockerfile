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
RUN pip install --no-cache-dir requests python-dotenv

# Crear directorios necesarios
RUN mkdir -p /app/src/web/templates /app/src/web/static /app/benchmark_results /app/src/rag

# Copiar el código fuente
COPY . .

# Verificar que todos los módulos estén disponibles
RUN python -c "import requests; import dotenv; print('Dependencias para RAG verificadas correctamente')"

# Exponer el puerto
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD ["python", "src/main.py"] 