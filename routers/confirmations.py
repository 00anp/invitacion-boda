#Libraries
from fastapi import Depends, HTTPException, Request, Path, status, APIRouter
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Annotated, List, Union
from starlette.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel, Field
from datetime import datetime
from weasyprint import HTML, CSS
from io import BytesIO
import base64
from pathlib import Path as PathLib
from PIL import Image, ImageDraw, ImageFont
import os
import re
#On File
from models import User, Group, Guest, Message, MessageSignature
from database import engine, SessionLocal
from utils.input_validation import InputValidation


router = APIRouter(
    prefix='/htmx',
    tags=['confirmations']
)
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
   

@router.get("/confirm/{group_uuid}", response_class=HTMLResponse)
async def start_confirmation(
    request: Request,
    group_uuid: str,
    db: Session = Depends(get_db)
):
    """
    Inicia el proceso de confirmación mostrando el estado inicial.
    """
    try:
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        
        if not group:
            return templates.TemplateResponse(
                "confirmation/steps/error.html",
                {
                    "request": request,
                    "error": "Grupo no encontrado"
                }
            )
        
        # Verificar si ya confirmaron
        all_confirmed = all(guest.has_confirmed for guest in group.guests)
        
        if all_confirmed:
            # Retornar vista de confirmación exitosa
            return templates.TemplateResponse(
                "confirmation/steps/confirmed.html",  # Nuevo template
                {
                    "request": request,
                    "group": group,
                    "confirmed_guests": [guest for guest in group.guests if guest.is_attending]
                }
            )
        
        # Si no han confirmado, mostrar paso inicial
        return templates.TemplateResponse(
            "confirmation/steps/step_0.html",
            {
                "request": request,
                "group": group
            }
        )
    except Exception as e:
        return templates.TemplateResponse(
            "confirmation/steps/error.html",
            {
                "request": request,
                "error": f"Error inesperado: {str(e)}"
            }
        )

@router.get("/confirm/{group_uuid}/start", response_class=HTMLResponse)
async def advance_to_step_one(
    request: Request,
    group_uuid: str,
    db: Session = Depends(get_db)
):
    """
    Avanza al primer paso del proceso de confirmación.
    """
    try:
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        
        if not group:
            return templates.TemplateResponse(
                "confirmation/steps/error.html",
                {
                    "request": request,
                    "error": "Grupo no encontrado"
                }
            )

        # Serializar los datos necesarios
        guests_data = [
            {
                "id": guest.id,
                "name": guest.name,
                "has_confirmed": guest.has_confirmed,
                "is_attending": guest.is_attending
            }
            for guest in group.guests
        ]

        group_data = {
            "id": group.id,
            "name": group.name,
            "uuid": group.uuid,
            "guests": guests_data
        }

        # Cargar step_1
        return templates.TemplateResponse(
            "confirmation/steps/step_1.html",
            {
                "request": request,
                "group": group_data,
                "all_confirmed": False
            }
        )
    except Exception as e:
        return templates.TemplateResponse(
            "confirmation/steps/error.html",
            {
                "request": request,
                "error": f"Error inesperado: {str(e)}"
            }
        )

@router.post("/confirm/{group_uuid}/step/1", response_class=HTMLResponse)
async def process_step_one(
    request: Request,
    group_uuid: str,
    db: Session = Depends(get_db)
):
    """
    Procesa la selección de invitados y muestra el formulario de confirmación.
    """
    try:
        form = await request.form()
        selected_guests_ids = form.getlist("selected_guests")
        
        if not selected_guests_ids:
            return templates.TemplateResponse(
                "confirmation/steps/error.html",
                {
                    "request": request,
                    "error": "Por favor, selecciona al menos un invitado"
                }
            )

        # Obtener el grupo y los invitados seleccionados
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        selected_guests = db.query(Guest).filter(
            Guest.id.in_(selected_guests_ids)
        ).all()

        # Preparar los datos de manera segura
        guests_data = [
            {
                "id": guest.id,
                "name": guest.name,
                "has_confirmed": guest.has_confirmed,
                "is_attending": guest.is_attending
            }
            for guest in selected_guests
        ]

        group_data = {
            "id": group.id,
            "name": group.name,
            "uuid": group.uuid
        }

        return templates.TemplateResponse(
            "confirmation/steps/step_2.html",
            {
                "request": request,
                "group": group_data,
                "selected_guests": guests_data
            }
        )
        
    except Exception as e:
        print(f"Error procesando paso 1: {str(e)}")
        return templates.TemplateResponse(
            "confirmation/steps/error.html",
            {
                "request": request,
                "error": f"Error procesando la selección: {str(e)}"
            }
        )
    

@router.post("/confirm/{group_uuid}/step/2", response_class=HTMLResponse)
async def process_step_two(
    request: Request,
    group_uuid: str,
    db: Session = Depends(get_db)
):
    """
    Procesa las confirmaciones y pasa al paso del mensaje.
    Ahora guarda todas las confirmaciones sin filtrar por asistencia.
    """
    try:
        form = await request.form()
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        
        # Guardamos todas las confirmaciones en la sesión
        confirmed_guests = []
        for field, value in form.items():
            if field.startswith('attendance_'):
                guest_id = int(field.split('_')[1])
                is_attending = value.lower() == 'true'
                request.session[f"attendance_{guest_id}"] = is_attending
                # Obtenemos el invitado
                guest = db.query(Guest).get(guest_id)
                if guest:
                    confirmed_guests.append({
                        "id": guest.id,
                        "name": guest.name,
                        "is_attending": is_attending
                    })

        return templates.TemplateResponse(
            "confirmation/steps/step_3.html",
            {
                "request": request,
                "group": {
                    "id": group.id,
                    "name": group.name,
                    "uuid": group.uuid
                },
                "confirmed_guests": confirmed_guests
            }
        )
        
    except Exception as e:
        return templates.TemplateResponse(
            "confirmation/steps/error.html",
            {
                "request": request,
                "error": f"Error procesando las confirmaciones: {str(e)}"
            }
        )

@router.post("/confirm/{group_uuid}/step/3", response_class=HTMLResponse)
async def process_final_step(
    request: Request,
    group_uuid: str,
    db: Session = Depends(get_db)
):
    try:
        form = await request.form()
        message_content = form.get("message", "").strip()
        signer_ids = form.getlist("signers")
        
        # Validar UUID del grupo
        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', group_uuid):
            return templates.TemplateResponse(
                "confirmation/steps/error.html",
                {
                    "request": request,
                    "error": "Identificador de grupo inválido"
                }
            )
        
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        if not group:
            return templates.TemplateResponse(
                "confirmation/steps/error.html",
                {
                    "request": request,
                    "error": "Grupo no encontrado"
                }
            )

        # Actualizar el estado de confirmación de los invitados
        current_time = datetime.now()
        confirmed_guests = []
        has_attending_guests = False
        message_to_save = None
        
        try:
            # Obtener todos los invitados del grupo y actualizar su estado
            guests = db.query(Guest).filter(Guest.group_id == group.id).all()
            valid_guest_ids = {str(guest.id) for guest in guests}
            
            for guest in guests:
                attendance_key = f"attendance_{guest.id}"
                if attendance_key in request.session:
                    is_attending = request.session[attendance_key]
                    guest.has_confirmed = True
                    guest.is_attending = is_attending
                    guest.confirmation_date = current_time
                    if is_attending:
                        has_attending_guests = True
                    confirmed_guests.append({
                        "id": guest.id,
                        "name": guest.name,
                        "is_attending": is_attending
                    })

            # Validar el mensaje si existe
            if message_content:
                message_validation = InputValidation.sanitize_and_validate_input('message', message_content)
                if not message_validation['is_valid']:
                    return templates.TemplateResponse(
                        "confirmation/steps/error.html",
                        {
                            "request": request,
                            "error": message_validation['error_message']
                        }
                    )
                message_to_save = message_validation['sanitized_content']
                
                # Validar IDs de firmantes
                invalid_signers = [signer_id for signer_id in signer_ids 
                                 if signer_id not in valid_guest_ids]
                if invalid_signers:
                    return templates.TemplateResponse(
                        "confirmation/steps/error.html",
                        {
                            "request": request,
                            "error": "Firmantes inválidos detectados"
                        }
                    )

                # Guardar mensaje sanitizado
                new_message = Message(
                    group_id=group.id,
                    content=message_to_save
                )
                db.add(new_message)
                db.flush()

                # Guardar firmas validadas
                for signer_id in signer_ids:
                    signature = MessageSignature(
                        message_id=new_message.id,
                        guest_id=int(signer_id)
                    )
                    db.add(signature)

            # Guardar todos los cambios
            db.commit()

        except Exception as e:
            db.rollback()
            print(f"Error en proceso de confirmación: {str(e)}")
            return templates.TemplateResponse(
                "confirmation/steps/error.html",
                {
                    "request": request,
                    "error": "Error al procesar la confirmación. Por favor, intenta nuevamente."
                }
            )

        return templates.TemplateResponse(
            "confirmation/success.html",
            {
                "request": request,
                "group": {
                    "id": group.id,
                    "name": group.name,
                    "uuid": group.uuid
                },
                "confirmed_guests": confirmed_guests,
                "has_attending_guests": has_attending_guests,
                "message": message_to_save if message_to_save else None,
                "success": True
            }
        )

    except Exception as e:
        print(f"Error general en process_final_step: {str(e)}")
        return templates.TemplateResponse(
            "confirmation/steps/error.html",
            {
                "request": request,
                "error": "Error procesando la confirmación. Por favor, intenta nuevamente.",
                "group_uuid": group_uuid
            }
        )
   

@router.get("/ticket/{group_uuid}/jpg", response_class=StreamingResponse)
async def generate_ticket_jpg(
    group_uuid: str,
    db: Session = Depends(get_db)
):
    try:
        # Obtener el grupo y sus invitados confirmados
        group = db.query(Group).filter(Group.uuid == group_uuid).first()
        if not group:
            raise HTTPException(status_code=404, detail="Grupo no encontrado")

        confirmed_guests = [g for g in group.guests if g.has_confirmed and g.is_attending]
        invitados_str = str(len(confirmed_guests))

        # Crear imagen
        width = 1170  # 390px * 3 para mejor calidad
        height = 2532  # 844px * 3
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
        draw.text((width//2,safe_top_margin + 80), "Mariana & Josué", font=title_font, fill='#000000', anchor='mm')

        # Cargar y redimensionar imagen destacada
        try:
            img_path = base_dir / "static" / "images" / "ticket.webp"
            featured_img = Image.open(str(img_path))
            img_height = 800
            img_width = width // 2 - 60
            featured_img = featured_img.resize((img_width, img_height), Image.LANCZOS)
            image.paste(featured_img, (30, safe_top_margin + 200))
        except Exception as e:
            print(f"Error cargando imagen: {e}")

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
        
        # Lista de invitados (centrada debajo de las columnas)
        y_offset = safe_top_margin + 1100  
        draw.text((width//2, y_offset), "Invitados confirmados:", font=bold_font, fill='#000000', anchor='mm')
        y_offset += 100

        # Centrar lista de invitados
        for guest in confirmed_guests:
            text = f"{guest.name}"
            # Obtener ancho del texto para centrarlo
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