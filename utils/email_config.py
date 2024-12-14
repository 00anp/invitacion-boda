from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr
from typing import List
import os
from dotenv import load_dotenv

load_dotenv()

class EmailConfig:
    """
    Configuración para el servicio de email usando Gmail SMTP
    """
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_FROM = os.getenv('MAIL_FROM')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_STARTTLS = os.getenv('MAIL_STARTTLS', 'True').lower() == 'true'
    MAIL_SSL_TLS = os.getenv('MAIL_SSL_TLS', 'False').lower() == 'true'
    USE_CREDENTIALS = os.getenv('USE_CREDENTIALS', 'True').lower() == 'true'

conf = ConnectionConfig(
    MAIL_USERNAME=EmailConfig.MAIL_USERNAME,
    MAIL_PASSWORD=EmailConfig.MAIL_PASSWORD,
    MAIL_FROM=EmailConfig.MAIL_FROM,
    MAIL_PORT=EmailConfig.MAIL_PORT,
    MAIL_SERVER=EmailConfig.MAIL_SERVER,
    MAIL_STARTTLS=EmailConfig.MAIL_STARTTLS,
    MAIL_SSL_TLS=EmailConfig.MAIL_SSL_TLS,
    USE_CREDENTIALS=EmailConfig.USE_CREDENTIALS
)

async def send_email_async(subject: str, email_to: List[EmailStr], body: str):
    message = MessageSchema(
        subject=subject,
        recipients=email_to,
        body=body,
        subtype="html"
    )
    
    fm = FastMail(conf)
    await fm.send_message(message)


async def send_magic_link(email: str, token: str):
    """Envía el magic link al correo especificado"""
    base_url = os.getenv('BASE_URL', 'http://localhost:8000')
    reset_url = f"{base_url}/auth/reset-password/{token}"
    body = f"""
    <html>
        <body>
            <h2>Recuperación de Contraseña</h2>
            <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
            <p><a href="{reset_url}">Restablecer Contraseña</a></p>
            <p>Este enlace expirará en 15 minutos.</p>
            <p>Si no solicitaste este cambio, ignora este correo.</p>
        </body>
    </html>
    """
    await send_email_async(
        subject="Recuperación de Contraseña",
        email_to=[email],
        body=body
    )