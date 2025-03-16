from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


# Esquema base para usuario
class UserBase(BaseModel):
    username: str
    email: EmailStr
    is_active: Optional[bool] = True


# Esquema para crear un usuario
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


# Esquema para actualizar un usuario
class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None


# Esquema para respuesta de usuario
class User(UserBase):
    id: int
    public_key: str
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Esquema para información de usuario con token
class UserWithToken(User):
    access_token: str
    token_type: str = "bearer" 