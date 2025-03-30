# Criptolab - Laboratorio de Criptografía

Una aplicación web interactiva para probar y comparar diferentes algoritmos de encriptación, funciones hash y firmas digitales.

## Características

- **Encriptación Simétrica**: AES con modos CBC y GCM
- **Encriptación Asimétrica**: RSA
- **Encriptación Híbrida**: RSA + AES
- **Encriptación Personalizada**: Algoritmos CAOS v3 y v4
- **Funciones Hash**: MD5, SHA-1, SHA-256, SHA-512
- **Firmas Digitales**: RSA + SHA-256
- **Benchmark**: Comparativa de rendimiento entre algoritmos

## Requisitos

- Python 3.8 o superior
- Las dependencias listadas en `requirements.txt`

## Instalación

1. Clona este repositorio:
   ```
   git clone <url-del-repositorio>
   cd encriptacion-project
   ```

2. Crea un entorno virtual (opcional pero recomendado):
   ```
   python -m venv venv
   ```

3. Activa el entorno virtual:
   - Windows:
     ```
     venv\Scripts\activate
     ```
   - Linux/macOS:
     ```
     source venv/bin/activate
     ```

4. Instala las dependencias:
   ```
   pip install -r requirements.txt
   ```

## Ejecución

1. Navega a la carpeta `src`:
   ```
   cd src
   ```

2. Ejecuta la aplicación Flask:
   ```
   python app.py
   ```

3. Abre tu navegador y accede a:
   ```
   http://127.0.0.1:5000
   ```

## Uso

1. Desde la página principal, selecciona el tipo de criptografía que deseas probar.
2. Cada sección te permite probar diferentes algoritmos con tus propios datos.
3. La sección de benchmark permite comparar el rendimiento de los diferentes algoritmos con diferentes tamaños de datos.

## Notas de Seguridad

- Esta aplicación es para fines educativos.
- Los algoritmos personalizados (CAOS) son solo para demostración y no deben usarse en entornos de producción.
- Para aplicaciones reales, siempre usa algoritmos criptográficos estándar y bibliotecas bien auditadas.

## Tecnologías Utilizadas

- **Backend**: Flask, Python
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Criptografía**: pycryptodome, cryptography
- **Visualización**: matplotlib 