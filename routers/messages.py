#Libraries
from fastapi import APIRouter, Depends, HTTPException, Request, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func
from database import SessionLocal
from typing import Optional, Annotated
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer

#On File
from models import Message, MessageSignature
from config import get_settings

settings = get_settings()

# Configuración del router - Cambiamos el prefijo para que coincida con la estructura
router = APIRouter(
    prefix='/admin',
    tags=['admin']
)

# Constantes y configuración
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')
templates = Jinja2Templates(directory="templates")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@router.get("/messages", response_class=HTMLResponse)
async def view_messages(
    request: Request,
    db: db_dependency,
    access_token: Optional[str] = Cookie(None)
):
    """
    Vista de mensajes que incluye todos los mensajes 
    con sus firmantes y detalles del grupo.
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
            
            # Verificar si el usuario es administrador
            if not current_user['is_admin']:
                raise HTTPException(
                    status_code=403,
                    detail="Access forbidden - Admin privileges required"
                )
            
        except JWTError as e:
            return RedirectResponse(url="/auth/token", status_code=302)

        # Consulta optimizada para obtener todos los mensajes con sus relaciones
        messages = (
            db.query(Message)
            .options(
                joinedload(Message.group),
                joinedload(Message.signatures)
                .joinedload(MessageSignature.guest)
            )
            .order_by(Message.created_at.desc())
            .all()
        )

        # Estadísticas de mensajes
        total_messages = len(messages)
        messages_by_date = (
            db.query(
                func.date(Message.created_at).label('date'),
                func.count(Message.id).label('count')
            )
            .group_by(func.date(Message.created_at))
            .order_by(func.date(Message.created_at).desc())
            .all()
        )

        return templates.TemplateResponse(
            "messages.html",  # Asegúrate de que este template exista
            {
                "request": request,
                "user": current_user,
                "messages": messages,
                "stats": {
                    "total_messages": total_messages,
                    "messages_by_date": messages_by_date
                }
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error loading messages: {str(e)}"
        )