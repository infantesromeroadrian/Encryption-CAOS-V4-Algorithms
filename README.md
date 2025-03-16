# Sistema de Mensajería Segura con Encriptación Híbrida

Este proyecto implementa un sistema de mensajería segura que utiliza encriptación híbrida (RSA + AES) para garantizar la confidencialidad, integridad y autenticidad de los mensajes.

## Descripción del Proyecto

Este sistema de mensajería segura combina diferentes técnicas criptográficas para proporcionar una comunicación segura entre usuarios:

1. **Encriptación híbrida**: Utiliza RSA (asimétrica) para el intercambio seguro de claves y AES (simétrica) para cifrar el contenido de los mensajes, aprovechando las ventajas de ambos sistemas.

2. **Firmas digitales**: Cada mensaje es firmado digitalmente por el remitente, lo que garantiza su autenticidad e integridad.

3. **Almacenamiento seguro de contraseñas**: Las contraseñas de los usuarios se almacenan utilizando bcrypt, un algoritmo de hash seguro.

4. **Protección de claves privadas**: Las claves privadas RSA de los usuarios se cifran con una clave derivada de su contraseña, asegurando que solo el propietario pueda utilizarlas.

5. **Autenticación basada en tokens**: Se utiliza JWT (JSON Web Tokens) para la autenticación de usuarios.

## Características

- **Autenticación segura**: Basada en tokens JWT con contraseñas hasheadas usando bcrypt.
- **Encriptación híbrida**: Combinación de encriptación asimétrica (RSA) y simétrica (AES).
- **Firmas digitales**: Verificación de la integridad y autenticidad de los mensajes.
- **Mensajes con caducidad**: Posibilidad de establecer un tiempo de vida para los mensajes.
- **Comunicación segura**: Soporte para TLS/SSL con generación automática de certificados autofirmados para desarrollo.
- **Interfaz de usuario intuitiva**: Frontend desarrollado con HTML, CSS y JavaScript puro.

## Componentes del Sistema

El proyecto está dividido en dos componentes principales:

1. **Backend (API)**: Implementado con FastAPI, proporciona los endpoints para la autenticación, gestión de usuarios y mensajes cifrados.

2. **Frontend**: Interfaz de usuario implementada con HTML, CSS y JavaScript puro.

## Estructura del proyecto

### Backend (API)

- `api/app/main.py`: Punto de entrada de la API FastAPI, configuración de CORS y rutas.
- `api/app/core/`: Configuración de la aplicación y base de datos.
  - `config.py`: Configuración de la aplicación (variables de entorno, configuración de JWT, etc.).
  - `database.py`: Configuración de la base de datos SQLAlchemy.
- `api/app/models/`: Modelos de datos (usuarios, mensajes).
  - `user.py`: Modelo de usuario con campos para claves RSA.
  - `message.py`: Modelo de mensaje con campos para contenido cifrado, clave AES cifrada, IV y firma.
- `api/app/routers/`: Endpoints de la API.
  - `auth.py`: Endpoints para registro e inicio de sesión.
  - `users.py`: Endpoints para gestión de usuarios.
  - `messages.py`: Endpoints para envío, recepción y descifrado de mensajes.
- `api/app/schemas/`: Esquemas de validación de datos.
  - `user.py`: Esquemas Pydantic para validación de datos de usuario.
  - `message.py`: Esquemas para mensajes (creación, respuesta, etc.).
  - `token.py`: Esquema para tokens de autenticación.
- `api/app/security/`: Implementación de funciones de seguridad.
  - `crypto.py`: Implementación de funciones criptográficas (RSA, AES, firmas, etc.).
  - `deps.py`: Dependencias para autenticación en FastAPI.
  - `password.py`: Funciones para hash y verificación de contraseñas.
  - `token.py`: Funciones para creación y verificación de tokens JWT.
- `api/run.py`: Script para ejecutar la API.

### Frontend

- `frontend/index.html`: Página principal de la aplicación.
- `frontend/css/styles.css`: Estilos CSS de la aplicación.
- `frontend/js/`: Scripts JavaScript para la lógica del cliente.
  - `api.js`: Cliente para comunicación con la API.
  - `auth.js`: Gestión de autenticación en el cliente.
  - `messages.js`: Funciones para gestión de mensajes.
  - `app.js`: Lógica principal de la aplicación.
- `frontend/server.py`: Servidor simple para servir el frontend.

### Ejemplos y Utilidades de Criptografía

- `src/symmetric_encryption.py`: Ejemplos de encriptación simétrica (AES).
- `src/asymmetric_encryption.py`: Ejemplos de encriptación asimétrica (RSA).
- `src/hybrid_encryption.py`: Ejemplos de encriptación híbrida (RSA + AES).
- `src/digital_signatures.py`: Ejemplos de firmas digitales.
- `src/password_hashing.py`: Ejemplos de hash de contraseñas.
- `src/hash_functions.py`: Ejemplos de funciones hash.

## Flujo de Funcionamiento

### Registro de Usuario
1. El usuario proporciona nombre de usuario, email y contraseña.
2. El sistema genera un par de claves RSA para el usuario.
3. La clave privada se cifra con una clave derivada de la contraseña del usuario.
4. La contraseña se hashea con bcrypt.
5. Se almacenan el nombre de usuario, email, contraseña hasheada, clave pública y clave privada cifrada.

### Envío de Mensajes
1. El remitente selecciona un destinatario y escribe un mensaje.
2. El sistema genera una clave AES aleatoria.
3. El mensaje se cifra con la clave AES.
4. La clave AES se cifra con la clave pública RSA del destinatario.
5. El remitente proporciona su contraseña para descifrar su clave privada RSA.
6. El mensaje se firma digitalmente con la clave privada del remitente.
7. Se almacenan el mensaje cifrado, la clave AES cifrada, el IV y la firma digital.

### Recepción de Mensajes
1. El destinatario ve una lista de mensajes recibidos.
2. Al seleccionar un mensaje, proporciona su contraseña para descifrar su clave privada RSA.
3. Con su clave privada, descifra la clave AES.
4. Con la clave AES, descifra el contenido del mensaje.
5. Se verifica la firma digital con la clave pública del remitente.
6. Si la firma es válida, se muestra el mensaje descifrado.

## Endpoints principales de la API

### Autenticación

- `POST /api/v1/auth/register`: Registrar un nuevo usuario.
- `POST /api/v1/auth/login`: Iniciar sesión y obtener un token JWT.

### Usuarios

- `GET /api/v1/users/me`: Obtener información del usuario actual.
- `PUT /api/v1/users/me`: Actualizar información del usuario actual.
- `GET /api/v1/users`: Obtener la lista de usuarios.
- `GET /api/v1/users/{user_id}`: Obtener información de un usuario específico.

### Mensajes

- `POST /api/v1/messages`: Crear un nuevo mensaje cifrado.
- `GET /api/v1/messages/sent`: Obtener los mensajes enviados por el usuario actual.
- `GET /api/v1/messages/received`: Obtener los mensajes recibidos por el usuario actual.
- `GET /api/v1/messages/{message_id}`: Obtener y descifrar un mensaje específico.

## Requisitos

- Python 3.8+
- Las dependencias listadas en `requirements.txt`
- Docker y Docker Compose (para la ejecución con contenedores)

## Instalación y Ejecución

### Método 1: Ejecución directa

1. Clonar el repositorio:
```bash
git clone <url-del-repositorio>
cd <directorio-del-repositorio>
```

2. Crear un entorno virtual e instalar las dependencias:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Ejecutar el backend (API):
```bash
cd api
python run.py
```

4. En otra terminal, ejecutar el frontend:
```bash
cd frontend
python server.py
```

### Método 2: Ejecución con Docker

1. Clonar el repositorio:
```bash
git clone <url-del-repositorio>
cd <directorio-del-repositorio>
```

2. Construir y ejecutar los contenedores con Docker Compose:
```bash
docker-compose up -d
```

3. Para detener los contenedores:
```bash
docker-compose down
```

## Uso de Docker

El proyecto está configurado para ejecutarse fácilmente con Docker, lo que permite una instalación y ejecución sencilla en cualquier sistema operativo que soporte Docker.

### Archivos de configuración Docker

- `docker-compose.yml`: Define los servicios, redes y volúmenes para la aplicación.
- `api/Dockerfile`: Instrucciones para construir la imagen del backend.
- `frontend/Dockerfile`: Instrucciones para construir la imagen del frontend.
- `.dockerignore`: Lista de archivos y directorios que se excluyen al construir las imágenes.

### Comandos Docker útiles

#### Iniciar la aplicación
```bash
docker-compose up -d
```
Este comando inicia los contenedores en segundo plano (`-d` significa "detached mode").

#### Detener la aplicación
```bash
docker-compose down
```
Este comando detiene y elimina los contenedores, redes y volúmenes definidos en `docker-compose.yml`.

#### Reconstruir los contenedores después de cambios en el código
```bash
docker-compose up --build -d
```
Usa este comando cuando hayas modificado el código y necesites que los cambios se reflejen en los contenedores.

#### Ver los logs de los contenedores
```bash
# Ver logs del backend
docker logs mensajeria-backend

# Ver logs del frontend
docker logs mensajeria-frontend

# Ver logs en tiempo real (seguimiento)
docker logs -f mensajeria-backend
```

#### Verificar el estado de los contenedores
```bash
docker ps
```
Muestra los contenedores en ejecución, sus puertos y estado.

#### Ejecutar comandos dentro de un contenedor
```bash
docker exec -it mensajeria-backend bash
```
Este comando te da acceso a una terminal dentro del contenedor del backend.

### Acceso a la aplicación con Docker

- Frontend: `http://localhost:8080`
- API: `http://localhost:8000`
- Documentación de la API: `http://localhost:8000/docs`

## Uso

1. Accede al frontend en `http://localhost:8080`.
2. Regístrate como nuevo usuario o inicia sesión si ya tienes una cuenta.
3. Envía mensajes cifrados a otros usuarios.
4. Lee y descifra los mensajes recibidos.

## Seguridad

Este sistema implementa varias capas de seguridad:

1. **Autenticación**: Basada en tokens JWT con tiempo de expiración.
2. **Almacenamiento de contraseñas**: Utilizando bcrypt para el hash de contraseñas.
3. **Encriptación de mensajes**: Utilizando encriptación híbrida (RSA + AES).
4. **Firmas digitales**: Para garantizar la integridad y autenticidad de los mensajes.
5. **TLS/SSL**: Para la comunicación segura entre cliente y servidor.

## Notas de desarrollo

- Los certificados SSL/TLS generados automáticamente son autofirmados y solo deben usarse en entornos de desarrollo.
- En un entorno de producción, se recomienda utilizar certificados emitidos por una autoridad de certificación confiable.
- Este proyecto es una demostración educativa y puede requerir ajustes adicionales para su uso en producción.

## Recursos Adicionales

- [Documentación de FastAPI](https://fastapi.tiangolo.com/)
- [Documentación de PyCryptodome](https://pycryptodome.readthedocs.io/)
- [Documentación de SQLAlchemy](https://docs.sqlalchemy.org/)
- [Documentación de JWT](https://jwt.io/)
- [Documentación de Docker](https://docs.docker.com/)
- [Documentación de Docker Compose](https://docs.docker.com/compose/) 