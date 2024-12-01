#Libraries
from fastapi import FastAPI, Depends, HTTPException, Request, Path, status, APIRouter
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Annotated, List, Union
from starlette import status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
from weasyprint import HTML, CSS
from io import BytesIO
import base64
from pathlib import Path as PathLib
from passlib.context import CryptContext 
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
#On File
import models
from models import User, Group, Guest, Message, MessageSignature
from database import engine, SessionLocal

from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')

print(SECRET_KEY)

router = APIRouter()


templates = Jinja2Templates(directory="templates")
models.Base.metadata.create_all(bind=engine)

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class CreateUserRequest(BaseModel):
    """
    Modelo para validar los datos de los usuarios.
    """
    username: str
    email: str
    password: str
    admin: bool


class GuestRequest(BaseModel):
    """
    Modelo para validar los datos de cada invitado.
    """
    name: str = Field(min_length=2, max_length=100)
    email: Union[str, None] = None
    phone: Union[str, None] = None


class GroupRequest(BaseModel):
    """
    Modelo para validar los datos del grupo completo.
    Incluye el nombre del grupo y la lista de invitados.
    """
    name: str = Field(min_length=2, max_length=100)
    guests: List[GuestRequest]


class GuestConfirmation(BaseModel):
    """
    Modelo para validar la confirmación de asistencia de un invitado.
    """
    guest_id: int = Field(gt=0, description="ID del invitado que confirma")
    is_attending: bool = Field(description="Indica si el invitado asistirá")


class GroupConfirmation(BaseModel):
    """
    Modelo para validar las confirmaciones de todo el grupo.
    """
    confirmations: List[GuestConfirmation]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


def authenticate_user(username:str, password:str, db):
    user = db.query(User).filter(User.username == username).first()

    if not user:
        return False
    
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return True


@router.post("/auth", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency,create_user_request:CreateUserRequest):
    create_user_model = User(
        username=create_user_request.username,email=create_user_request.email,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        is_admin=create_user_request.admin,
        is_active=True
    )

    db.add(create_user_model)
    db.commit()


@router.post("/token")
async def login_for_access_token(form_data:Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    
    if not user:
        return 'Failed Authentication'
    return 'Successful Authentication'



@router.get("/auth/groups", status_code=status.HTTP_200_OK)
async def read_all_groups(db:db_dependency):
    return db.query(Group).all()


@router.get("/auth/groups/{group_id}", status_code=status.HTTP_200_OK)
async def read_group(db: db_dependency, group_id: int=Path(gt=0), ):
    """
    Endpoint para obtener un grupo específico por su ID junto con sus invitados asociados.
    
    Args:
        group_id (int): ID del grupo a consultar
        db (Session): Sesión de base de datos proporcionada por la dependencia
    
    Returns:
        dict: Información del grupo y sus invitados
    
    Raises:
        HTTPException: Si el grupo no existe, retorna un error 404
    """
    # Consultamos el grupo específico incluyendo la relación con invitados
    group = db.query(Group).filter(Group.id == group_id).first()
    
    # Si no encontramos el grupo, lanzamos una excepción
    if group is None:
        raise HTTPException(
            status_code=404,
            detail=f"No se encontró el grupo con id {group_id}"
        )
    
    # Creamos un diccionario con la información del grupo
    return {
        "id": group.id,
        "name": group.name,
        "uuid": group.uuid,
        "created_at": group.created_at,
        "updated_at": group.updated_at,
        "guests": [
            {
                "id": guest.id,
                "name": guest.name,
                "email": guest.email,
                "phone": guest.phone,
                "has_confirmed": guest.has_confirmed,
                "is_attending": guest.is_attending,
                "confirmation_date": guest.confirmation_date
            }
            for guest in group.guests
        ]
    }


@router.post("/auth/group", status_code=status.HTTP_201_CREATED)
async def create_group(group_request: GroupRequest, db:db_dependency):
    """
    Endpoint para crear un nuevo grupo con sus invitados.
    
    Args:
        group_request.(GroupRequest): Datos del grupo y sus invitados
        db (Session): Sesión de base de datos
        
    Returns:
        dict: Información del grupo creado y sus invitados
        
    Raises:
        HTTPException: Si hay errores en la creación del grupo o los invitados
    """
    try:
        # Creamos el grupo
        new_group = Group(
            name=group_request.name
            # El UUID se generará automáticamente por el default en el modelo
        )
        db.add(new_group)
        db.flush()  # Esto nos permite obtener el ID del grupo sin hacer commit
        
        # Creamos los invitados asociados al grupo
        guests = []
        for guest_data in group_request.guests:
            new_guest = Guest(
                name=guest_data.name,
                email=guest_data.email,
                phone=guest_data.phone,
                group_id=new_group.id  # Asociamos el invitado al grupo
            )
            guests.append(new_guest)
            db.add(new_guest)
        
        # Guardamos todos los cambios en la base de datos
        db.commit()
        
        # Preparamos la respuesta
        return {
            "message": "Grupo creado exitosamente",
            "group": {
                "id": new_group.id,
                "name": new_group.name,
                "uuid": new_group.uuid,
                "guests": [
                    {
                        "id": guest.id,
                        "name": guest.name,
                        "email": guest.email,
                        "phone": guest.phone
                    }
                    for guest in guests
                ]
            }
        }
        
    except Exception as e:
        # Si algo sale mal, hacemos rollback y lanzamos una excepción
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al crear el grupo: {str(e)}"
        )