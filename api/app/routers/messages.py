from typing import Any, List
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.message import Message
from app.schemas.message import MessageCreate, Message as MessageSchema, MessageWithContent
from app.security.deps import get_current_active_user
from app.security.crypto import hybrid_encrypt, hybrid_decrypt, sign_message, verify_signature, decrypt_private_key

router = APIRouter()


@router.post("/", response_model=MessageSchema)
def create_message(
    *,
    db: Session = Depends(get_db),
    message_in: MessageCreate,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Crea un nuevo mensaje cifrado.
    """
    # Verificar que el destinatario existe
    recipient = db.query(User).filter(User.id == message_in.recipient_id).first()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Destinatario no encontrado",
        )
    
    # Verificar que el destinatario está activo
    if not recipient.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El destinatario no está activo",
        )
    
    # Cifrar el mensaje con la clave pública del destinatario
    encrypted_data = hybrid_encrypt(message_in.content, recipient.public_key)
    
    # Descifrar la clave privada del remitente con la contraseña proporcionada
    try:
        private_key = decrypt_private_key(current_user.encrypted_private_key, message_in.password)
        
        # Firmar el mensaje con la clave privada del remitente
        signature = sign_message(message_in.content, private_key)
        
        # Calcular la fecha de caducidad si se especifica
        expires_at = None
        if message_in.expires_in_hours:
            expires_at = datetime.utcnow() + timedelta(hours=message_in.expires_in_hours)
        
        # Crear el mensaje
        message = Message(
            sender_id=current_user.id,
            recipient_id=message_in.recipient_id,
            encrypted_content=encrypted_data["encrypted_content"],
            encrypted_aes_key=encrypted_data["encrypted_aes_key"],
            iv=encrypted_data["iv"],
            signature=signature,
            expires_at=expires_at,
        )
        
        # Guardar el mensaje en la base de datos
        db.add(message)
        db.commit()
        db.refresh(message)
        
        return message
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al procesar el mensaje: {str(e)}",
        )


@router.get("/sent", response_model=List[MessageSchema])
def read_sent_messages(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Obtiene los mensajes enviados por el usuario actual.
    """
    messages = (
        db.query(Message)
        .filter(Message.sender_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return messages


@router.get("/received", response_model=List[MessageSchema])
def read_received_messages(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Obtiene los mensajes recibidos por el usuario actual.
    """
    # Filtrar mensajes caducados
    current_time = datetime.utcnow()
    messages = (
        db.query(Message)
        .filter(Message.recipient_id == current_user.id)
        .filter((Message.expires_at.is_(None)) | (Message.expires_at > current_time))
        .offset(skip)
        .limit(limit)
        .all()
    )
    return messages


@router.get("/{message_id}", response_model=MessageWithContent)
def read_message(
    *,
    db: Session = Depends(get_db),
    message_id: int,
    password: str,  # En una implementación real, esto se manejaría de forma más segura
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Obtiene un mensaje por su ID y lo descifra.
    """
    # Buscar el mensaje
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mensaje no encontrado",
        )
    
    # Verificar que el usuario actual es el remitente o el destinatario
    if message.sender_id != current_user.id and message.recipient_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para ver este mensaje",
        )
    
    # Verificar que el mensaje no ha caducado
    if message.expires_at and message.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El mensaje ha caducado",
        )
    
    # Si el usuario actual es el destinatario, marcar el mensaje como leído
    if message.recipient_id == current_user.id and not message.is_read:
        message.is_read = True
        db.add(message)
        db.commit()
        db.refresh(message)
    
    # Descifrar el mensaje
    try:
        # Descifrar la clave privada del usuario con su contraseña
        private_key = decrypt_private_key(current_user.encrypted_private_key, password)
        
        # Descifrar el mensaje
        decrypted_content = hybrid_decrypt(
            message.encrypted_content,
            message.encrypted_aes_key,
            message.iv,
            private_key,
        )
        
        # Obtener la clave pública del remitente
        sender = db.query(User).filter(User.id == message.sender_id).first()
        
        # Verificar la firma del mensaje
        is_valid = verify_signature(decrypted_content, message.signature, sender.public_key)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La firma del mensaje no es válida",
            )
        
        # Devolver el mensaje con el contenido descifrado
        return {
            "id": message.id,
            "sender_id": message.sender_id,
            "recipient_id": message.recipient_id,
            "is_read": message.is_read,
            "created_at": message.created_at,
            "expires_at": message.expires_at,
            "content": decrypted_content,
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al descifrar el mensaje: {str(e)}",
        ) 