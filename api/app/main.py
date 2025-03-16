import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import ssl

from app.core.config import settings
from app.core.database import engine, Base
from app.routers import auth, users, messages

# Crear las tablas en la base de datos
Base.metadata.create_all(bind=engine)

# Crear la aplicación FastAPI
app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permitir todas las origenes en desarrollo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir los routers
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(users.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(messages.router, prefix=f"{settings.API_V1_STR}/messages", tags=["messages"])


@app.get("/")
def root():
    return {"message": "Bienvenido a la API de mensajería segura"}


if __name__ == "__main__":
    # Configurar SSL/TLS si se especifican los archivos de certificado y clave
    if settings.SSL_CERTFILE and settings.SSL_KEYFILE:
        # Crear el directorio de certificados si no existe
        os.makedirs("./certs", exist_ok=True)
        
        # Verificar si los archivos de certificado y clave existen
        if not os.path.exists(settings.SSL_CERTFILE) or not os.path.exists(settings.SSL_KEYFILE):
            # Generar un certificado autofirmado para desarrollo
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime
            
            # Generar una clave privada RSA
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Crear un certificado autofirmado
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Messaging API"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Guardar la clave privada
            with open(settings.SSL_KEYFILE, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            
            # Guardar el certificado
            with open(settings.SSL_CERTFILE, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            print(f"Certificado autofirmado generado en {settings.SSL_CERTFILE}")
            print(f"Clave privada generada en {settings.SSL_KEYFILE}")
        
        # Configurar SSL
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(settings.SSL_CERTFILE, settings.SSL_KEYFILE)
        
        # Iniciar el servidor con SSL
        uvicorn.run(
            "app.main:app",
            host="0.0.0.0",
            port=8000,
            ssl_keyfile=settings.SSL_KEYFILE,
            ssl_certfile=settings.SSL_CERTFILE,
        )
    else:
        # Iniciar el servidor sin SSL
        uvicorn.run("app.main:app", host="0.0.0.0", port=8000) 