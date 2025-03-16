from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"))
    
    # Contenido del mensaje cifrado con AES
    encrypted_content = Column(Text)
    
    # Clave AES cifrada con la clave pública del destinatario
    encrypted_aes_key = Column(Text)
    
    # Vector de inicialización para AES
    iv = Column(String)
    
    # Firma digital del mensaje (para verificar la integridad y autenticidad)
    signature = Column(Text)
    
    # Metadatos
    is_read = Column(Boolean, default=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Para mensajes con caducidad
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relaciones
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages") 