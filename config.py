# config.py
from dotenv import load_dotenv
import os
from typing import Dict, Any
from functools import lru_cache

# Cargamos las variables de entorno al iniciar
load_dotenv()

class Settings:
    """
    Clase central de configuración que gestiona todas las variables de entorno
    y configuraciones del proyecto.
    """
    
    # Configuración de Base de Datos
    DATABASE_URL: str = os.getenv('DATABASE_URL')
    
    # Configuración de Seguridad
    SECRET_KEY: str = os.getenv('SECRET_KEY')
    ALGORITHM: str = os.getenv('ALGORITHM', 'HS256')
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '20'))
    
    # Configuración de Email
    MAIL_USERNAME: str = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD: str = os.getenv('MAIL_PASSWORD')
    MAIL_FROM: str = os.getenv('MAIL_FROM')
    MAIL_PORT: int = int(os.getenv('MAIL_PORT', '587'))
    MAIL_SERVER: str = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_STARTTLS: bool = os.getenv('MAIL_STARTTLS', 'True').lower() == 'true'
    MAIL_SSL_TLS: bool = os.getenv('MAIL_SSL_TLS', 'False').lower() == 'true'
    USE_CREDENTIALS: bool = os.getenv('USE_CREDENTIALS', 'True').lower() == 'true'
    
    # Configuración de la Aplicación
    BASE_URL: str = os.getenv('BASE_URL', 'http://localhost:8000')
    
    def validate_settings(self) -> Dict[str, Any]:
        """
        Valida que todas las variables críticas estén configuradas.
        Retorna un diccionario con el estado de las configuraciones.
        """
        required_settings = {
            'DATABASE_URL': self.DATABASE_URL,
            'SECRET_KEY': self.SECRET_KEY,
            'MAIL_USERNAME': self.MAIL_USERNAME,
            'MAIL_PASSWORD': self.MAIL_PASSWORD,
        }
        
        missing_settings = [key for key, value in required_settings.items() if not value]
        
        if missing_settings:
            raise ValueError(
                f"Faltan las siguientes configuraciones requeridas: {', '.join(missing_settings)}"
            )
            
        return required_settings

@lru_cache()
def get_settings() -> Settings:
    """
    Retorna una instancia única de Settings utilizando caché para mejorar el rendimiento.
    La decoración lru_cache asegura que solo se cree una instancia.
    """
    settings = Settings()
    settings.validate_settings()
    return settings