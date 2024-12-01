#Libraries
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
#On File
from database import Base


def generate_uuid():
    """
    Genera un UUID único para usar como identificador del grupo.
    Este UUID será parte de la URL personalizada para cada grupo.
    """
    return str(uuid.uuid4())

class User(Base):
    """
    Modelo para los usuarios del sistema (administradores y anfitriones).
    Este modelo maneja la autenticación y los permisos del sistema.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Group(Base):
    """
    Modelo para los grupos de invitados.
    Cada grupo tiene un identificador único que se usa en la URL personalizada.
    """
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    uuid = Column(String(36), unique=True, index=True, default=generate_uuid)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relaciones
    guests = relationship("Guest", back_populates="group", cascade="all, delete-orphan")
    messages = relationship("Message", back_populates="group", cascade="all, delete-orphan")

class Guest(Base):
    """
    Modelo para los invitados individuales.
    Cada invitado pertenece a un grupo y puede confirmar su asistencia.
    """
    __tablename__ = "guests"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), nullable=True)
    phone = Column(String(20), nullable=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    has_confirmed = Column(Boolean, default=False)
    is_attending = Column(Boolean, default=False)
    confirmation_date = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relaciones
    group = relationship("Group", back_populates="guests")
    message_signatures = relationship("MessageSignature", back_populates="guest")

class Message(Base):
    """
    Modelo para los mensajes de los invitados.
    Cada mensaje está asociado a un grupo y puede ser firmado por varios invitados.
    """
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relaciones
    group = relationship("Group", back_populates="messages")
    signatures = relationship("MessageSignature", back_populates="message", cascade="all, delete-orphan")

class MessageSignature(Base):
    """
    Modelo para las firmas de los mensajes.
    Permite que múltiples invitados firmen un mismo mensaje.
    """
    __tablename__ = "message_signatures"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("messages.id"), nullable=False)
    guest_id = Column(Integer, ForeignKey("guests.id"), nullable=False)
    signed_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relaciones
    message = relationship("Message", back_populates="signatures")
    guest = relationship("Guest", back_populates="message_signatures")