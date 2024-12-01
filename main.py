#Libraries
from fastapi import FastAPI, Depends, HTTPException, Request, Path, status
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
#On File
import models
from models import User, Group, Guest, Message, MessageSignature
from database import engine, SessionLocal
from routers import auth, confirmations

class MethodOverrideMiddleware(BaseHTTPMiddleware):
    """
    Middleware que permite sobrescribir el método HTTP usando el parámetro _method
    o el header X-HTTP-Method-Override.
    """
    async def dispatch(self, request, call_next):
        # Verificamos si hay un método override en la query string
        method = request.query_params.get("_method", "").upper()
        
        # Si no está en query params, buscamos en headers
        if not method:
            method = request.headers.get("X-HTTP-Method-Override", "").upper()
        
        # Si encontramos un método válido y la petición es POST, actualizamos
        if method in ["PUT", "DELETE", "PATCH"] and request.method == "POST":
            request._method = method
            
        return await call_next(request)


app = FastAPI()
templates = Jinja2Templates(directory="templates")
models.Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(confirmations.router)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
app.add_middleware(MethodOverrideMiddleware)


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


@app.get("/", response_class=HTMLResponse)
async def welcome_message(request: Request):
    """
    Endpoint que renderiza la página de bienvenida usando el template.
    Los datos se pasan directamente al template sin necesidad de una API separada.
    """
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "¡Bienvenidos a nuestra boda!",
            "message": "Estamos muy emocionados de compartir este momento tan especial con ustedes.",
            "submessage": "En este sitio podrán confirmar su asistencia y dejarnos sus mensajes de buenos deseos."
        }
    )


@app.get("/{group_uuid}", response_class=HTMLResponse)
async def group_welcome(
    request: Request,
    group_uuid: str,
    db: db_dependency
):
    """
    Endpoint que muestra la página de bienvenida específica para un grupo.
    Incluye el formulario de confirmación de asistencia para cada invitado.
    """
    # Obtenemos el grupo y sus invitados
    group = db.query(Group).filter(Group.uuid == group_uuid).first()
    
    # Verificamos si todos los invitados han confirmado
    all_confirmed = False
    if group:
        all_confirmed = all(guest.has_confirmed for guest in group.guests)
    
    # Renderizamos el template con todos los datos necesarios
    return templates.TemplateResponse(
        "group.html",
        {
            "request": request,
            "group": group,
            "all_confirmed": all_confirmed
        }
    )
