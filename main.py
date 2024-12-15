# Libraries
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import Annotated
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path as PathLib
from jose import JWTError, jwt 
from dotenv import load_dotenv
import os
# On File - Importamos todos los routers necesarios
import models
from models import Group
from database import engine, SessionLocal
from routers import (
    auth,
    confirmations,
    admin
)

load_dotenv()

BASE_DIR = PathLib(__file__).resolve().parent
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')

# Inicialización de la aplicación
app = FastAPI()
# Configuración de archivos estáticos 
app.mount(
    "/static", 
    StaticFiles(
        directory=str(BASE_DIR / "static"),
        # Añadimos configuración HTML5 para manejo de rutas
        html=True,
        check_dir=True
    ), 
    name="static"
)
# Configuración de templates después de los estáticos
templates = Jinja2Templates(directory="templates")
# Configuración de la base de datos
models.Base.metadata.create_all(bind=engine)

class MethodOverrideMiddleware(BaseHTTPMiddleware):
    """
    Middleware que permite sobrescribir el método HTTP usando el parámetro _method
    o el header X-HTTP-Method-Override.
    """
    async def dispatch(self, request, call_next):
        method = request.query_params.get("_method", "").upper()
        
        if not method:
            method = request.headers.get("X-HTTP-Method-Override", "").upper()
        
        if method in ["PUT", "DELETE", "PATCH"] and request.method == "POST":
            request._method = method
            
        return await call_next(request)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Rutas que no requieren autenticación
        public_paths = ['/', '/auth/token', '/auth/logout', '/static']
        
        # Verificar si la ruta actual es pública
        if any(request.url.path.startswith(path) for path in public_paths):
            response = await call_next(request)
            return response

        # Para rutas protegidas, verificar el token
        access_token = request.cookies.get('access_token')
        
        if not access_token:
            # Redirigir al login y establecer la URL de retorno
            return RedirectResponse(
                url=f"/auth/token?next={request.url.path}",
                status_code=302
            )

        try:
            # Limpiar el token
            token = access_token.replace("Bearer ", "") if access_token.startswith("Bearer ") else access_token
            
            # Verificar el token
            payload = jwt.decode(
                token, 
                SECRET_KEY, 
                algorithms=[ALGORITHM]
            )
            
            # Si llegamos aquí, el token es válido
            response = await call_next(request)
            return response

        except JWTError:
            return RedirectResponse(
                url="/auth/token",
                status_code=302
            )
        except Exception as e:
            return RedirectResponse(
                url="/auth/token",
                status_code=302
            )

# Middleware
app.add_middleware(MethodOverrideMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=True
)
app.add_middleware(AuthMiddleware)
# Routers
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(confirmations.router)



# Dependencia de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]


async def render_invitation(
    request: Request,
    db: Session,
    group_uuid: str | None = None
):
    """
    Función auxiliar que maneja la lógica de renderizado para ambas rutas
    """
    context = {
        "request": request,
        "group": None,
        "all_confirmed": False,
        "group_uuid": None
    }

    if group_uuid:
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        if group:
            # Serializamos los invitados
            serialized_guests = [
                {
                    "id": guest.id,
                    "name": guest.name,
                    "has_confirmed": guest.has_confirmed,
                    "is_attending": guest.is_attending
                }
                for guest in group.guests
            ]
            
            context.update({
                "group": {
                    "id": group.id,
                    "name": group.name,
                    "uuid": group.uuid,
                    "guests": serialized_guests
                },
                "group_uuid": group.uuid,
                "all_confirmed": all(guest.has_confirmed for guest in group.guests)
            })

    return templates.TemplateResponse("index.html", context)


# Rutas principales
@app.get("/", response_class=HTMLResponse)
async def welcome_message(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Ruta para la vista general de la invitación
    """
    return await render_invitation(request, db)


@app.get("/{group_uuid}", response_class=HTMLResponse, name="grupo")
async def group_welcome(
    request: Request,
    group_uuid: str,
    db: Session = Depends(get_db)
):
    """
    Ruta para la vista personalizada con grupo específico
    """
    return await render_invitation(request, db, group_uuid)

