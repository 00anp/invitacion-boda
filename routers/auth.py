#Libraries
from fastapi import Depends, HTTPException, Request, status, APIRouter, Cookie,  BackgroundTasks, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Annotated, List, Union, Optional
from starlette import status
from starlette.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext 
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt
import secrets
#On File
import models
from models import User
from database import engine, SessionLocal
from utils.email_config import send_magic_link
from utils.input_validation import InputValidation
from config import get_settings

settings = get_settings()

router = APIRouter(
    prefix='/auth',
    tags=['auth']
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


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),  # Cambiamos aquí también
    access_token: Optional[str] = Cookie(None)
):
    try:
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No se encontró token de autenticación"
            )
            
        # Remover el prefijo 'Bearer ' si existe
        token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Token inválido'
            )
            
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        is_admin: bool = payload.get('is_admin')

        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Could not validate user.'
            )
            
        return {
            'username': username,
            'id': user_id,
            'is_admin': is_admin
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate user.'
        )


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Renderiza la página de login"""
    return templates.TemplateResponse("login.html", {"request": request})

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


@router.post("/token", response_class=HTMLResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    next_url: str = None
):
    try:
        # Validar username
        username_validation = InputValidation.sanitize_and_validate_input('username', form_data.username)
        if not username_validation['is_valid']:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": username_validation['error_message'],
                    "next": next_url
                },
                status_code=401
            )
        
        # Validar password
        password_validation = InputValidation.sanitize_and_validate_input('password', form_data.password)
        if not password_validation['is_valid']:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": password_validation['error_message'],
                    "next": next_url
                },
                status_code=401
            )
        
        # Usar las versiones sanitizadas para autenticación
        user = authenticate_user(
            username_validation['sanitized_content'], 
            password_validation['sanitized_content'], 
            db
        )
        
        if not user:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Usuario o contraseña incorrectos",
                    "next": next_url
                },
                status_code=401
            )
            
        token = create_access_token(
            user.username,
            user.id,
            user.is_admin,
            timedelta(minutes=20)
        )
        
        # Creamos la respuesta
        response = RedirectResponse(
            url=next_url if next_url else "/admin/dashboard",
            status_code=303
        )
        
        # Configuramos la cookie correctamente
        response.set_cookie(
            key="access_token",
            value=f"Bearer {token}",
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=1200  # 20 minutos
        )
        
        return response
        
    except Exception as e:
        # Log del error para debugging
        print(f"Error en login: {str(e)}")
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Error en el proceso de login",
                "next": next_url
            },
            status_code=500
        )
    

@router.get("/logout")
async def logout():
    """
    Cierra la sesión del usuario de forma segura.
    
    Este endpoint:
    1. Crea una respuesta de redirección a la página de login
    2. Elimina la cookie de acceso_token estableciendo su valor a una cadena vacía
    3. Establece la fecha de expiración en el pasado para invalidar inmediatamente
    4. Usa los mismos parámetros de seguridad que al crear la cookie
    """
    try:
        # Crear respuesta de redirección
        response = RedirectResponse(
            url="/auth/login",
            status_code=status.HTTP_302_FOUND
        )

        # Eliminar la cookie de manera segura
        response.delete_cookie(
            key="access_token",
            # Asegurar que la cookie se elimine completamente
            path="/",
            secure=True,  # Solo enviar por HTTPS
            httponly=True,  # No accesible por JavaScript
            samesite="lax"  # Protección contra CSRF
        )
        
        return response

    except Exception as e:
        # Aún así intentamos redirigir al login
        return RedirectResponse(
            url="/auth/login",
            status_code=status.HTTP_302_FOUND
        )



@router.post("/forgot-password")
async def forgot_password(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    """Endpoint para solicitar recuperación de contraseña"""
    try:
        # Validar formato del email
        email_validation = InputValidation.sanitize_and_validate_input('email', email)
        if not email_validation['is_valid']:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Formato de correo electrónico inválido"
                }
            )
        
        # Usar el email sanitizado para la búsqueda
        sanitized_email = email_validation['sanitized_content']
        user = db.query(User).filter(User.email == sanitized_email).first()
        
        # Mantener mensaje genérico por seguridad
        if not user:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "success": "Si el correo existe, recibirás instrucciones para recuperar tu contraseña"
                }
            )
        
        # Generar token único
        reset_token = secrets.token_urlsafe(32)
        
        # Guardar token en la base de datos con try/except
        try:
            user.reset_token = reset_token
            user.reset_token_expires = datetime.now(timezone.utc) + timedelta(minutes=15)
            db.commit()
        except Exception as e:
            print(f"Error al guardar token: {str(e)}")
            db.rollback()
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "error": "Error al procesar la solicitud. Por favor, intenta más tarde."
                }
            )
        
        # Enviar email en segundo plano
        try:
            background_tasks.add_task(send_magic_link, sanitized_email, reset_token)
        except Exception as e:
            print(f"Error al enviar email: {str(e)}")
            # No informamos al usuario del error específico por seguridad
        
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "success": "Si el correo existe, recibirás instrucciones para recuperar tu contraseña"
            }
        )
        
    except Exception as e:
        print(f"Error en forgot_password: {str(e)}")
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Error al procesar la solicitud. Por favor, intenta más tarde."
            }
        )

@router.get("/reset-password/{token}")
async def reset_password_form(
    request: Request,
    token: str,
    db: Session = Depends(get_db)
):
    """Muestra el formulario para establecer nueva contraseña"""
    user = db.query(User).filter(
        User.reset_token == token,
        User.reset_token_expires > datetime.now(timezone.utc)
    ).first()
    
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "El enlace ha expirado o no es válido"
            }
        )
    
    return templates.TemplateResponse(
        "reset_password.html",
        {
            "request": request,
            "token": token
        }
    )

@router.post("/reset-password/{token}")
async def reset_password(
    request: Request,
    token: str,
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Procesa el cambio de contraseña"""
    if password != confirm_password:
        return templates.TemplateResponse(
            "reset_password.html",
            {
                "request": request,
                "token": token,
                "error": "Las contraseñas no coinciden"
            }
        )
    
    user = db.query(User).filter(
        User.reset_token == token,
        User.reset_token_expires > datetime.now(timezone.utc)
    ).first()
    
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "El enlace ha expirado o no es válido"
            }
        )
    
    # Actualizar contraseña
    user.hashed_password = bcrypt_context.hash(password)
    user.reset_token = None
    user.reset_token_expires = None
    db.commit()
    
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "success": "Contraseña actualizada exitosamente"
        }
    )