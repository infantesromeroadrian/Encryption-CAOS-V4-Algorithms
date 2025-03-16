from typing import Optional
from pydantic import BaseModel
from datetime import datetime


# Esquema base para mensaje
class MessageBase(BaseModel):
    recipient_id: int


# Esquema para crear un mensaje
class MessageCreate(MessageBase):
    content: str  # Contenido sin cifrar (se cifrará en el servidor)
    expires_in_hours: Optional[int] = None  # Tiempo de caducidad en horas (opcional)
    password: str  # Contraseña del usuario para descifrar su clave privada


# Esquema para mensaje cifrado (para almacenamiento)
class MessageCrypto(BaseModel):
    encrypted_content: str
    encrypted_aes_key: str
    iv: str
    signature: str


# Esquema para respuesta de mensaje
class Message(BaseModel):
    id: int
    sender_id: int
    recipient_id: int
    is_read: bool
    created_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Esquema para mensaje con contenido descifrado
class MessageWithContent(Message):
    content: str  # Contenido descifrado 