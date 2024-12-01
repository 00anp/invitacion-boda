#Libraries
from fastapi import Depends, HTTPException, Request, Path, status, APIRouter
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
from models import User, Group, Guest, Message, MessageSignature
from database import engine, SessionLocal


router = APIRouter()
templates = Jinja2Templates(directory="templates")



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


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


@router.get("/confirmation/{group_uuid}", response_class=HTMLResponse)
async def show_confirmation(
    request: Request,
    db: db_dependency,
    group_uuid: str = Path(...)
):
    """
    Muestra la página de confirmación con el ticket y la opción de descarga PDF.
    Este endpoint se llama después de crear un mensaje exitosamente.
    """
    try:
        # Obtenemos el grupo y sus invitados
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo no encontrado")

        # Filtramos solo los invitados que confirmaron asistencia
        confirmed_guests = [
            guest for guest in group.guests 
            if guest.has_confirmed and guest.is_attending
        ]

        # Obtenemos el último mensaje del grupo (el que acabamos de crear)
        last_message = (
            db.query(Message)
            .filter(Message.group_id == group.id)
            .order_by(Message.created_at.desc())
            .first()
        )

        return templates.TemplateResponse(
            "ticket_confirmation.html",
            {
                "request": request,
                "group": group,
                "confirmed_guests": confirmed_guests,
                "message": last_message,
                # Agregamos datos adicionales para el ticket
                "event_date": "5 de Abril, 2025",
                "event_time": "16:00 hrs",
                "event_location": "Lugar del evento"
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error mostrando la confirmación: {str(e)}"
        )


@router.get("/confirmation/{group_uuid}/pdf")
async def generate_ticket_pdf(
    request: Request,
    db: db_dependency,
    group_uuid: str = Path(...)
):
    try:
        # Obtenemos el grupo y sus invitados confirmados
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo no encontrado")

        confirmed_guests = [g for g in group.guests if g.has_confirmed and g.is_attending]

        # Leemos la imagen y la convertimos a base64
        image_path = PathLib("static/images/background.jpg")  # Asegúrate de que la imagen esté en esta ruta
        with open(image_path, "rb") as image_file:
            encoded_image = base64.b64encode(image_file.read()).decode()

        # Generamos el HTML con el template
        html_content = templates.TemplateResponse(
            "ticket_template.html",
            {
                "request": request,
                "group": group,
                "confirmed_guests": confirmed_guests,
                "background_image": encoded_image
            }
        )

        # Convertimos el HTML a PDF
        html = HTML(string=html_content.body.decode())
        pdf_file = BytesIO()
        html.write_pdf(pdf_file)
        pdf_file.seek(0)

        return StreamingResponse(
            pdf_file,
            media_type="routerlication/pdf",
            headers={
                'Content-Disposition': f'attachment; filename="confirmacion_boda_{group_uuid}.pdf"'
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando el PDF: {str(e)}")


@router.post("/confirm/{group_uuid}", response_class=HTMLResponse)
async def confirm_attendance(
    request: Request,
    db: db_dependency,
    group_uuid: str = Path(...)
):
    """
    Endpoint para procesar las confirmaciones de asistencia.
    Recibe los datos del formulario vía POST y actualiza la base de datos.
    
    Args:
        request: El objeto Request de FastAPI
        db: Dependencia de la base de datos
        group_uuid: UUID del grupo que está confirmando asistencia
    """
    try:
        # Obtenemos el grupo
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        if not group:
            return templates.TemplateResponse(
                "confirmation_response.html",
                {
                    "request": request,
                    "success": False,
                    "error_message": "Grupo no encontrado",
                    "group_uuid": group_uuid
                }
            )

        # Procesamos el formulario
        form = await request.form()
        updates_made = False
        updated_guests = []
        current_time = datetime.now()

        # Actualizamos cada invitado
        for guest in group.guests:
            attendance_key = f"attendance_{guest.id}"
            
            if attendance_key in form:
                is_attending = form[attendance_key].lower() == 'true'
                guest.has_confirmed = True
                guest.is_attending = is_attending
                guest.confirmation_date = current_time
                updates_made = True
                updated_guests.routerend(guest)

        if updates_made:
            try:
                db.commit()
                # En lugar de redireccionar, mostramos la página de confirmación
                return templates.TemplateResponse(
                    "confirmation_success.html",
                    {
                        "request": request,
                        "updated_guests": updated_guests,
                        "group_uuid": group_uuid
                    }
                )
            except Exception as e:
                db.rollback()
                return templates.TemplateResponse(
                    "confirmation_response.html",
                    {
                        "request": request,
                        "success": False,
                        "error_message": f"Error al guardar en la base de datos: {str(e)}",
                        "group_uuid": group_uuid
                    }
                )
        else:
            return templates.TemplateResponse(
                "confirmation_response.html",
                {
                    "request": request,
                    "no_updates": True,
                    "group_uuid": group_uuid
                }
            )

    except Exception as e:
        if db is not None:
            db.rollback()
        return templates.TemplateResponse(
            "confirmation_response.html",
            {
                "request": request,
                "success": False,
                "error_message": str(e),
                "group_uuid": group_uuid
            }
        )
    

@router.post("/message/{group_uuid}", response_class=HTMLResponse)
async def create_message(
    request: Request,
    db: db_dependency,
    group_uuid: str = Path(...)
):
    """
    Endpoint para crear un nuevo mensaje y sus firmas asociadas.
    """
    try:
        # Obtenemos el grupo
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo no encontrado")

        # Obtenemos los datos del formulario
        form = await request.form()
        message_content = form.get("message")
        signer_ids = form.getlist("signers")

        # Creamos el mensaje
        new_message = Message(
            group_id=group.id,
            content=message_content
        )
        db.add(new_message)
        db.flush()  # Para obtener el ID del mensaje

        # Creamos las firmas
        for signer_id in signer_ids:
            signature = MessageSignature(
                message_id=new_message.id,
                guest_id=int(signer_id)
            )
            db.add(signature)

        db.commit()

        # Redirigimos a la página del grupo con un mensaje de éxito
        return RedirectResponse(
            url=f"/confirmation/{group_uuid}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    except Exception as e:
        db.rollback()
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_message": f"Error al guardar el mensaje: {str(e)}",
                "group_uuid": group_uuid
            }
        )