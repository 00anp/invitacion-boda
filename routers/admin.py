#Libraries
from fastapi import Depends, HTTPException, Request, Path, status, APIRouter, Query, Cookie, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, select
from typing import Annotated, List, Union, Optional, Dict
from starlette import status
from starlette.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext 
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
import pandas as pd
import re
from io import BytesIO
import base64
from pathlib import Path as PathLib
from PIL import Image, ImageDraw, ImageFont
import os

#On File
import models
from models import User, Group, Guest, Message, MessageSignature
from database import engine, SessionLocal
from .auth import get_current_user
from config import get_settings

settings = get_settings()

router = APIRouter(
    prefix='/admin',
    tags=['admin']
)

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

bcrypt_context = CryptContext(
    schemes=['bcrypt'], 
    deprecated='auto'
)
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

templates = Jinja2Templates(directory="templates")
models.Base.metadata.create_all(bind=engine)


class CreateUserRequest(BaseModel):
    """
    Modelo para validar los datos de los usuarios.
    """
    username: str
    email: str
    password: str
    is_admin: bool


class Token(BaseModel):
    access_token: str
    token_type: str


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
user_dependency = Annotated[dict, Depends(get_current_user)]

def authenticate_user(username: str, password: str, db):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user

def create_access_token(username: str, user_id: int, is_admin: bool, expires_delta: timedelta):
    
    encode = {'sub': username, 'id': user_id, 'is_admin': is_admin}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        is_admin: bool = payload.get('is_admin')

        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.')
        return { 'username': username, 'id': user_id,'is_admin': is_admin }
    
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.')

def sanitize_phone(phone: str) -> str:
    """Sanitiza números de teléfono para mantener solo dígitos y formato consistente."""
    if pd.isna(phone):
        return None
    # Eliminar todo excepto dígitos
    digits = re.sub(r'\D', '', str(phone))
    if not digits:
        return None
    return digits

def sanitize_email(email: str) -> str:
    """Sanitiza y valida direcciones de email."""
    if pd.isna(email):
        return None
    email = str(email).strip().lower()
    # Patrón básico de validación de email
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return email
    return None

def sanitize_name(name: str) -> str:
    """Sanitiza nombres eliminando caracteres especiales y espacios extra."""
    if pd.isna(name):
        return None
    # Eliminar espacios extras y caracteres especiales
    name = ' '.join(str(name).strip().split())
    return name if name else None

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency,create_user_request:CreateUserRequest):
    create_user_model = User(
        username=create_user_request.username,email=create_user_request.email,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        is_admin=create_user_request.is_admin,
        is_active=True
    )

    db.add(create_user_model)
    db.commit()


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data:Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency):

    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.')
    token = create_access_token(user.username, user.id, user.is_admin, timedelta(minutes=20))

    return {'access_token': token, 'token_type': 'bearer'}


@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Renderiza el dashboard administrativo con estadísticas ampliadas y lista de invitados.
    """
    try:
        # Verificar token
        if not access_token:
            return RedirectResponse(url="/auth/login", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            current_user = {
                'username': payload.get('sub'),
                'id': payload.get('id'),
                'is_admin': payload.get('is_admin')
            }
            
        except JWTError as e:
            print(f"Error de JWT: {str(e)}")  # Añadido para debugging
            return RedirectResponse(url="/auth/login", status_code=302)

        # Consultas mejoradas para estadísticas
        total_guests = db.query(func.count(Guest.id)).scalar()
        
        confirmed_guests = db.query(func.count(Guest.id))\
            .filter(Guest.has_confirmed == True).scalar()
        pending_guests = total_guests - confirmed_guests

        attending_guests = db.query(func.count(Guest.id))\
            .filter(Guest.has_confirmed == True)\
            .filter(Guest.is_attending == True).scalar()
            
        not_attending_guests = db.query(func.count(Guest.id))\
            .filter(Guest.has_confirmed == True)\
            .filter(Guest.is_attending == False).scalar()

        guests = db.query(Guest)\
            .options(joinedload(Guest.group))\
            .order_by(Guest.id.asc())\
            .all()

        guests_data = []
        for guest in guests:
            guest_data = {
                'id': guest.id,
                'name': guest.name,
                'has_confirmed': guest.has_confirmed,
                'is_attending': guest.is_attending,
                'group': {
                    'id': guest.group.id if guest.group else None,
                    'name': guest.group.name if guest.group else None,
                    'uuid': guest.group.uuid if guest.group else None
                } if guest.group else None
            }
            guests_data.append(guest_data)

        stats = {
            "total_guests": total_guests,
            "confirmed_guests": confirmed_guests,
            "pending_guests": pending_guests,
            "attending_guests": attending_guests,
            "not_attending_guests": not_attending_guests
        }

        try:
            return templates.TemplateResponse(
                "admin/dashboard.html",
                {
                    "request": request,
                    "user": current_user,
                    "guests": guests_data,
                    "stats": stats
                }
            )
        except Exception as template_error:
            print(f"Error de template: {str(template_error)}")  # Añadido para debugging
            raise HTTPException(
                status_code=500,
                detail=f"Error rendering template: {str(template_error)}"
            )

    except Exception as e:
        print(f"Error general: {str(e)}")  # Añadido para debugging
        raise HTTPException(
            status_code=500,
            detail=f"Error loading dashboard: {str(e)}"
        )
    

@router.get("/messages", response_class=HTMLResponse)
async def admin_messages(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Vista administrativa de mensajes
    """
    try:
        # Verificar token
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            current_user = {
                'username': payload.get('sub'),
                'id': payload.get('id'),
                'is_admin': payload.get('is_admin')
            }
        
        except JWTError as e:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        messages_query = (
            db.query(Message)
            .options(
                joinedload(Message.group),
                joinedload(Message.signatures)
                .joinedload(MessageSignature.guest)
            )
        )
            
        if not current_user['is_admin']:
            user = db.query(User).filter(User.id == current_user['id']).first()
            if not user:
                raise HTTPException(status_code=404, detail="Usuario no encontrado")
            
            messages = messages_query.order_by(Message.created_at.desc()).all()
        else:
            messages = messages_query.order_by(Message.created_at.desc()).all()

        return templates.TemplateResponse(
            "admin/messages.html",
            {
                "request": request,
                "user": current_user,
                "messages": messages,
                "is_admin": current_user['is_admin']
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error loading messages: {str(e)}"
        )


@router.get("/users", response_class=HTMLResponse)
async def list_users(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Vista principal de gestión de usuarios.
    Solo para usuario admin.
    """
    try:
        # Verificar token y que sea administrador
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            current_user = {
                'username': payload.get('sub'),
                'id': payload.get('id'),
                'is_admin': payload.get('is_admin')
            }
            
            if not current_user['is_admin']:
                raise HTTPException(
                    status_code=403,
                    detail="Acceso denegado - Se requieren privilegios de administrador"
                )
            
        except JWTError as e:
            return RedirectResponse(url="/auth/token", status_code=302)

        # Obtener lista de usuarios
        users = db.query(User).all()
        
        return templates.TemplateResponse(
            "admin/users.html",
            {
                "request": request,
                "user": current_user,
                "users": users
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error interno del servidor: {str(e)}"
        )


@router.post("/users/create", response_class=HTMLResponse)
async def create_user(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Endpoint para crear nuevos usuarios.
    Verifica que el creador sea administrador y encripta la contraseña.
    """
    try:
        # Verificar token y permisos de administrador
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get('is_admin'):
            raise HTTPException(status_code=403, detail="Acceso denegado")

        # Obtener datos del formulario
        form = await request.form()
        username = form.get("username")
        email = form.get("email")
        password = form.get("password")
        is_admin = form.get("is_admin") == "on"

        # Validar que el usuario no exista
        existing_user = db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            return templates.TemplateResponse(
                "users.html",
                {
                    "request": request,
                    "error": "El usuario o email ya existe",
                    "users": db.query(User).all()
                },
                status_code=400
            )

        # Crear nuevo usuario
        new_user = User(
            username=username,
            email=email,
            hashed_password=bcrypt_context.hash(password),
            is_admin=is_admin,
            is_active=True
        )
        db.add(new_user)
        db.commit()

        return RedirectResponse(
            url="/admin/users",
            status_code=302
        )

    except Exception as e:
        return templates.TemplateResponse(
            "admin/users.html",
            {
                "request": request,
                "error": f"Error creando usuario: {str(e)}",
                "users": db.query(User).all()
            },
            status_code=500
        )


@router.post("/users/{user_id}/deactivate", response_class=HTMLResponse)
async def deactivate_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Desactiva un usuario existente.
    Solo administradores pueden desactivar usuarios.
    """
    try:
        # Verificar token y permisos
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get('is_admin'):
            raise HTTPException(status_code=403, detail="Acceso denegado")

        # Encontrar y desactivar usuario
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        user.is_active = False
        db.commit()

        return RedirectResponse(
            url="/admin/users",
            status_code=302
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error desactivando usuario: {str(e)}"
        )


@router.post("/users/{user_id}/activate", response_class=HTMLResponse)
async def activate_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Activa un usuario desactivado.
    Solo administradores pueden activar usuarios.
    """
    try:
        # Verificar token y permisos
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get('is_admin'):
            raise HTTPException(status_code=403, detail="Acceso denegado")

        # Encontrar y activar usuario
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        user.is_active = True
        db.commit()

        return RedirectResponse(
            url="/admin/users",
            status_code=302
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error activando usuario: {str(e)}"
        )


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
async def edit_user_form(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Muestra el formulario de edición de usuario.
    """
    try:
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            current_user = {
                'username': payload.get('sub'),
                'id': payload.get('id'),
                'is_admin': payload.get('is_admin')
            }
            
            if not current_user['is_admin']:
                raise HTTPException(
                    status_code=403,
                    detail="Acceso denegado - Se requieren privilegios de administrador"
                )
            
        except JWTError as e:
            return RedirectResponse(url="/auth/token", status_code=302)

        edit_user = db.query(User).filter(User.id == user_id).first()
        if not edit_user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        return templates.TemplateResponse(
            "admin/edit_user.html",
            {
                "request": request,
                "user": current_user,  # Usuario actual para el menú
                "edit_user": edit_user  # Usuario que se está editando
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error interno del servidor: {str(e)}"
        )


@router.post("/users/{user_id}/edit", response_class=HTMLResponse)
async def update_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Procesa la actualización de un usuario existente.
    """
    try:
        # Verificar token y permisos
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        current_user = {
            'username': payload.get('sub'),
            'id': payload.get('id'),
            'is_admin': payload.get('is_admin')
        }
        
        if not current_user['is_admin']:
            raise HTTPException(status_code=403, detail="Acceso denegado")

        # Obtener datos del formulario
        form = await request.form()
        username = form.get("username")
        email = form.get("email")
        password = form.get("password")
        is_admin = form.get("is_admin") == "on"

        # Validar usuario existente
        existing_user = db.query(User).filter(
            User.id != user_id,  # Excluir el usuario actual
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            return templates.TemplateResponse(
                "admin/edit_user.html",
                {
                    "request": request,
                    "user": current_user,
                    "edit_user": db.query(User).get(user_id),
                    "error": "El usuario o email ya existe"
                },
                status_code=400
            )

        # Actualizar usuario
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        user.username = username
        user.email = email
        if password:
            user.hashed_password = bcrypt_context.hash(password)
        user.is_admin = is_admin

        db.commit()

        return RedirectResponse(
            url="/admin/users",
            status_code=302
        )

    except Exception as e:
        return templates.TemplateResponse(
            "admin/edit_user.html",
            {
                "request": request,
                "user": current_user,
                "edit_user": db.query(User).get(user_id),
                "error": f"Error actualizando usuario: {str(e)}"
            },
            status_code=500
        )


@router.get("/guests", response_class=HTMLResponse)
async def list_guests(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Vista principal de gestión de invitados.
    Usuarios no admin solo pueden exportar.
    """
    try:
        # Verificar token
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            current_user = {
                'username': payload.get('sub'),
                'id': payload.get('id'),
                'is_admin': payload.get('is_admin')
            }
        
        except JWTError as e:
            return RedirectResponse(url="/auth/token", status_code=302)

        # Obtener lista de invitados con sus grupos
        guests = db.query(Guest).join(Guest.group).all()
        
        return templates.TemplateResponse(
            "admin/guests.html",
            {
                "request": request,
                "user": current_user,
                "guests": guests,
                "is_admin": current_user['is_admin']
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error interno del servidor: {str(e)}"
        )


@router.post("/guests/import")
async def import_guests(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Importa invitados desde un archivo Excel.
    El archivo debe tener las columnas: Grupo, Nombre, Email, Teléfono
    """
    try:
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            if not payload.get('is_admin'):
                raise HTTPException(
                    status_code=403,
                    detail="Se requieren privilegios de administrador"
                )
            
        except JWTError as e:
            return RedirectResponse(url="/auth/token", status_code=302)

        # Validar el archivo
        if not file:
            raise HTTPException(
                status_code=400,
                detail="No se proporcionó ningún archivo"
            )

        # Validar el tipo de archivo
        if not file.filename.endswith(('.xlsx', '.xls')):
            return templates.TemplateResponse(
                "admin/guests.html",
                {
                    "request": request,
                    "error": "El archivo debe ser un Excel (.xlsx o .xls)",
                    "guests": db.query(Guest).join(Guest.group).all()
                }
            )

        # Leer el archivo Excel
        try:
            contents = await file.read()
            df = pd.read_excel(BytesIO(contents))
        except Exception as e:
            return templates.TemplateResponse(
                "admin/guests.html",
                {
                    "request": request,
                    "error": f"Error leyendo el archivo Excel: {str(e)}",
                    "guests": db.query(Guest).join(Guest.group).all()
                }
            )

        # Verificar columnas requeridas
        required_columns = ['Grupo', 'Nombre']
        if not all(col in df.columns for col in required_columns):
            return templates.TemplateResponse(
                "admin/guests.html",
                {
                    "request": request,
                    "error": "El archivo debe contener las columnas: Grupo, Nombre",
                    "guests": db.query(Guest).join(Guest.group).all()
                }
            )

        groups_cache: Dict[str, Group] = {}
        added_guests = 0
        errors = []

        for index, row in df.iterrows():
            try:
                group_name = sanitize_name(row['Grupo'])
                guest_name = sanitize_name(row['Nombre'])
                
                if not group_name or not guest_name:
                    errors.append(f"Fila {index + 2}: Nombre de grupo o invitado inválido")
                    continue

                # Obtener o crear el grupo
                if group_name not in groups_cache:
                    group = db.query(Group).filter(Group.name == group_name).first()
                    if not group:
                        group = Group(name=group_name)
                        db.add(group)
                        db.flush()
                    groups_cache[group_name] = group
                
                group = groups_cache[group_name]

                # Crear el invitado
                guest = Guest(
                    name=guest_name,
                    email=sanitize_email(row.get('Email', None)),
                    phone=sanitize_phone(row.get('Teléfono', None)),
                    group_id=group.id
                )
                
                db.add(guest)
                added_guests += 1
                
            except Exception as e:
                errors.append(f"Error en fila {index + 2}: {str(e)}")

        if errors:
            db.rollback()
            return templates.TemplateResponse(
                "admin/guests.html",
                {
                    "request": request,
                    "error": "Errores durante la importación",
                    "error_details": errors,
                    "guests": db.query(Guest).join(Guest.group).all()
                }
            )

        db.commit()
        return RedirectResponse(
            url="/admin/guests",
            status_code=302
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        return templates.TemplateResponse(
            "admin/guests.html",
            {
                "request": request,
                "error": f"Error procesando el archivo: {str(e)}",
                "guests": db.query(Guest).join(Guest.group).all()
            }
        )


@router.get("/guests/export")
async def export_guests(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Exporta la lista de invitados a un archivo Excel.
    """
    try:
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            if not payload.get('is_admin'):
                raise HTTPException(
                    status_code=403,
                    detail="Se requieren privilegios de administrador"
                )
            
        except JWTError as e:
            return RedirectResponse(url="/auth/token", status_code=302)

        # Consultar todos los invitados con sus grupos
        guests = db.query(Guest).join(Guest.group).all()

        # Crear DataFrame
        data = []
        for guest in guests:
            data.append({
                'Grupo': guest.group.name,
                'Nombre': guest.name,
                'Email': guest.email or '',
                'Teléfono': guest.phone or '',
                'Estado': 'Confirmado' if guest.has_confirmed else 'Pendiente',
                'Asistencia': 'Asistirá' if guest.is_attending else 'No asistirá' if guest.has_confirmed else 'Sin confirmar',
                'Link de Invitación': f'https://mariana-y-josue.com/{guest.group.uuid}'
            })

        df = pd.DataFrame(data)

        # Crear archivo Excel en memoria
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Invitados')

        output.seek(0)

        # Generar nombre de archivo con timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"invitados_{timestamp}.xlsx"

        # Retornar archivo para descarga
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"'
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generando el archivo Excel: {str(e)}"
        )
    

@router.get("/group/{group_id:int}", response_class=HTMLResponse)
async def view_group_details(
    request: Request,
    group_id: int = Path(..., gt=0),
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Vista detallada de un grupo específico.
    """
    try:
        # Verificar token
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            current_user = {
                'username': payload.get('sub'),
                'id': payload.get('id'),
                'is_admin': payload.get('is_admin')
            }
            
        except JWTError:
            return RedirectResponse(url="/auth/token", status_code=302)

        # Obtener grupo - consulta simplificada
        group = db.query(Group).filter(Group.id == group_id).first()

        if not group:
            raise HTTPException(status_code=404, detail="Grupo no encontrado")
            
        # Obtener invitados por separado
        guests = db.query(Guest).filter(Guest.group_id == group.id).all()
        
        # Datos básicos
        group_data = {
            'id': group.id,
            'name': group.name,
            'uuid': group.uuid,
            'guests': [{
                'id': guest.id,
                'name': guest.name,
                'has_confirmed': guest.has_confirmed,
                'is_attending': guest.is_attending
            } for guest in guests]
        }

        # Verificar confirmados
        has_confirmed_attendees = any(
            guest.has_confirmed and guest.is_attending 
            for guest in guests
        )

        # Template según rol
        template_name = "admin/group_detail_admin.html" if current_user['is_admin'] else "admin/group_detail_readonly.html"

        return templates.TemplateResponse(
            template_name,
            {
                "request": request,
                "user": current_user,
                "group": group_data,
                "has_confirmed_attendees": has_confirmed_attendees
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error interno del servidor: {str(e)}"
        )
    

@router.post("/group/{group_id}/guest/{guest_id}/edit", response_class=HTMLResponse)
async def edit_guest(
    request: Request,
    group_id: int,
    guest_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Procesa la edición de un invitado específico.
    """
    try:
        # Verificar token y permisos de admin
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if not payload.get('is_admin'):
            raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador")

        # Obtener datos del formulario
        form = await request.form()
        name = form.get("name")
        email = form.get("email")
        phone = form.get("phone")
        status = form.get("status")

        # Validar que el invitado existe y pertenece al grupo
        guest = db.query(Guest).filter(
            Guest.id == guest_id,
            Guest.group_id == group_id
        ).first()

        if not guest:
            raise HTTPException(status_code=404, detail="Invitado no encontrado")

        # Actualizar datos básicos
        if name:
            guest.name = name
        if email:
            guest.email = email
        if phone:
            guest.phone = phone

        # Actualizar estado de confirmación
        if status:
            if status == "attending":
                guest.has_confirmed = True
                guest.is_attending = True
            elif status == "not_attending":
                guest.has_confirmed = True
                guest.is_attending = False
            else:  # pending
                guest.has_confirmed = False
                guest.is_attending = False

        db.commit()
        return RedirectResponse(
            url=f"/admin/group/{group_id}",
            status_code=302
        )

    except Exception as e:
        return templates.TemplateResponse(
            "admin/error.html",
            {
                "request": request,
                "error": f"Error editando invitado: {str(e)}"
            },
            status_code=500
        )


@router.post("/group/{group_id}/guest/add", response_class=HTMLResponse)
async def add_guest(
    request: Request,
    group_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Agrega un nuevo invitado al grupo.
    """
    try:
        # Verificar token y permisos
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if not payload.get('is_admin'):
            raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador")

        # Obtener datos del formulario
        form = await request.form()
        name = form.get("name")
        email = form.get("email")
        phone = form.get("phone")

        # Validar grupo
        group = db.query(Group).filter(Group.id == group_id).first()

        if not group:
            raise HTTPException(status_code=404, detail="Grupo no encontrado")

        # Crear nuevo invitado
        new_guest = Guest(
            name=name,
            email=email,
            phone=phone,
            group_id=group_id
        )
        db.add(new_guest)
        db.commit()

        return RedirectResponse(
            url=f"/admin/group/{group_id}",
            status_code=302
        )

    except Exception as e:
        return templates.TemplateResponse(
            "admin/error.html",
            {
                "request": request,
                "error": f"Error agregando invitado: {str(e)}"
            },
            status_code=500
        )


@router.post("/group/{group_id}/guest/{guest_id}/delete", response_class=HTMLResponse)
async def delete_guest(
    request: Request,
    group_id: int,
    guest_id: int,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Elimina un invitado del grupo.
    """
    try:
        # Verificar token y permisos
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if not payload.get('is_admin'):
            raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador")

        # Validar y eliminar invitado
        guest = db.query(Guest).filter(
            Guest.id == guest_id,
            Guest.group_id == group_id
        ).first()

        if not guest:
            raise HTTPException(status_code=404, detail="Invitado no encontrado")

        db.delete(guest)
        db.commit()

        return RedirectResponse(
            url=f"/admin/group/{group_id}",
            status_code=302
        )

    except Exception as e:
        return templates.TemplateResponse(
            "admin/error.html",
            {
                "request": request,
                "error": f"Error eliminando invitado: {str(e)}"
            },
            status_code=500
        )
    

@router.get("/profile/edit", response_class=HTMLResponse)
async def edit_profile_form(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Muestra el formulario de edición del perfil del usuario actual.
    """
    try:
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        current_user = {
            'username': payload.get('sub'),
            'id': payload.get('id'),
            'is_admin': payload.get('is_admin')
        }
        
        # Obtener los datos completos del usuario
        user = db.query(User).filter(User.id == current_user['id']).first()

        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        return templates.TemplateResponse(
            "admin/profile_edit.html",
            {
                "request": request,
                "user": current_user,
                "edit_user": user
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error interno del servidor: {str(e)}"
        )

@router.post("/profile/edit", response_class=HTMLResponse)
async def update_profile(
    request: Request,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    """
    Procesa la actualización del perfil del usuario actual.
    """
    try:
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        current_user = {
            'username': payload.get('sub'),
            'id': payload.get('id'),
            'is_admin': payload.get('is_admin')
        }

        # Obtener datos del formulario
        form = await request.form()
        username = form.get("username")
        email = form.get("email")
        password = form.get("password")

        # Validar usuario existente (excluyendo el usuario actual)
        existing_user = db.query(User).filter(
            User.id != current_user['id'],
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            return templates.TemplateResponse(
                "admin/profile_edit.html",
                {
                    "request": request,
                    "user": current_user,
                    "edit_user": db.query(User).get(current_user['id']),
                    "error": "El usuario o email ya existe"
                },
                status_code=400
            )

        # Actualizar usuario
        user = db.query(User).filter(User.id == current_user['id']).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        user.username = username
        user.email = email
        if password:
            user.hashed_password = bcrypt_context.hash(password)

        db.commit()

        return RedirectResponse(
            url="/admin/dashboard",
            status_code=302
        )

    except Exception as e:
        return templates.TemplateResponse(
            "admin/profile_edit.html",
            {
                "request": request,
                "user": current_user,
                "edit_user": db.query(User).get(current_user['id']),
                "error": f"Error actualizando perfil: {str(e)}"
            },
            status_code=500
        )


@router.get("/ticket/{group_uuid}/jpg", response_class=StreamingResponse)
async def admin_generate_ticket_jpg(
    request: Request,
    group_uuid: str,
    db: Session = Depends(get_db),
    access_token: Optional[str] = Cookie(None)
):
    try:
        # Verificar token
        if not access_token:
            return RedirectResponse(url="/auth/token", status_code=302)
        
        try:
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
        except JWTError as e:
            return RedirectResponse(url="/auth/token", status_code=302)

        # Obtener el grupo y sus invitados confirmados
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo no encontrado")

        confirmed_guests = [g for g in group.guests if g.has_confirmed and g.is_attending]
        invitados_str = str(len(confirmed_guests))

        # Crear imagen
        width = 1170
        height = 2532
        image = Image.new('RGB', (width, height), '#e6e6e6')
        draw = ImageDraw.Draw(image)
        safe_top_margin = 180 

        # Cargar fuentes
        base_dir = PathLib(__file__).resolve().parent.parent
        font_path = base_dir / "static" / "fonts"
        try:
            title_font = ImageFont.truetype(str(font_path / "PlayfairDisplay-Bold.ttf"), 100)
            regular_font = ImageFont.truetype(str(font_path / "Lato-Regular.ttf"), 60)
            bold_font = ImageFont.truetype(str(font_path / "Lato-Bold.ttf"), 60)
            small_font = ImageFont.truetype(str(font_path / "Lato-Regular.ttf"), 40)
        except:
            # Fallback a fuente por defecto
            title_font = ImageFont.load_default()
            regular_font = ImageFont.load_default()
            bold_font = ImageFont.load_default()
            small_font = ImageFont.load_default()

        # Dibujar título
        draw.text((width//2, safe_top_margin + 80), "Mariana & Josué", font=title_font, fill='#000000', anchor='mm')

        # Cargar y redimensionar imagen
        try:
            img_path = base_dir / "static" / "images" / "ticket.webp"
            featured_img = Image.open(str(img_path))
            img_height = 800
            img_width = width // 2 - 60
            featured_img = featured_img.resize((img_width, img_height), Image.LANCZOS)
            image.paste(featured_img, (30, safe_top_margin + 200))
        except Exception as e:
            raise e

        # Información principal (lado derecho)
        right_x = width // 2 + 30
        y_offset = safe_top_margin + 200

        # Sección de información
        info_items = [
            ("Recepción", "", bold_font),
            ("Lugar:", "Jardín La Concordia", bold_font),
            ("Fecha:", "5 de abril de 2025", bold_font),
            ("Hora:", "2:30 pm", bold_font),
            ("# de Invitados:", invitados_str, bold_font)
        ]

        for label, value, font in info_items:
            draw.text((right_x, y_offset), label, font=font, fill='#000000')
            if value:
                draw.text((right_x, y_offset + 70), value, font=regular_font, fill='#000000')
                y_offset += 140
            else:
                y_offset += 80

        # Lista de invitados
        y_offset = safe_top_margin + 1100
        draw.text((width//2, y_offset), "Invitados confirmados:", font=bold_font, fill='#000000', anchor='mm')
        y_offset += 100

        for guest in confirmed_guests:
            text = f"{guest.name}"
            text_width = draw.textlength(text, font=regular_font)
            draw.text((width//2 - text_width//2, y_offset), text, font=regular_font, fill='#000000')
            y_offset += 70

        # Footer
        footer_text = "Este boleto confirma su asistencia a nuestra boda."
        draw.text((width//2, height - 150), footer_text, font=small_font, fill='#666666', anchor='mm')
        draw.text((width//2, height - 80), f"Ticket ID: {group.uuid}", font=small_font, fill='#666666', anchor='mm')

        # Convertir a bytes
        img_byte_array = BytesIO()
        image = image.resize((390, 844), Image.LANCZOS)
        image.save(img_byte_array, format='JPEG', quality=95)
        img_byte_array.seek(0)

        return StreamingResponse(
            img_byte_array,
            media_type="image/jpeg",
            headers={
                "Content-Disposition": f'attachment; filename="ticket_{group_uuid}.jpg"'
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generando el ticket: {str(e)}"
        )