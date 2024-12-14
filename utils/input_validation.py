import re
import bleach
from typing import Tuple, Dict, Any
from bleach.sanitizer import ALLOWED_TAGS, ALLOWED_ATTRIBUTES

class InputValidation:
    """Clase para manejar validación y sanitización de inputs"""
    
    # Constantes para validación
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 72
    MIN_USERNAME_LENGTH = 3
    MAX_USERNAME_LENGTH = 50
    MAX_MESSAGE_LENGTH = 2000
    MAX_EMAIL_LENGTH = 255
    
    # Patrones de regex
    PATTERNS = {
        'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        'username': r'^[a-zA-Z0-9_-]+$',
        'password': r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$',
    }
    
    # Patrones maliciosos
    MALICIOUS_PATTERNS = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'onerror=',
        r'onclick=',
        r'onload=',
        r'onmouseover=',
        r'onfocus=',
        r'onblur=',
        r'alert\(',
        r'eval\(',
        r'document\.cookie',
        r'window\.location',
        r'fetch\(',
        r'XMLHttpRequest',
        r'\b(union|select|insert|update|delete|drop)\b',
    ]

    @classmethod
    def sanitize_html(cls, content: str) -> str:
        """Sanitiza contenido HTML"""
        return bleach.clean(
            content,
            tags=[],  # No permitir ningún tag HTML
            attributes={},
            strip=True
        )

    @classmethod
    def check_malicious_content(cls, content: str) -> Tuple[bool, str]:
        """Verifica contenido malicioso en el input"""
        for pattern in cls.MALICIOUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return False, "Contenido no permitido detectado"
        return True, ""

    @classmethod
    def validate_email(cls, email: str) -> Tuple[bool, str]:
        """Valida formato de email"""
        if not email or len(email) > cls.MAX_EMAIL_LENGTH:
            return False, "Email inválido o demasiado largo"
        
        if not re.match(cls.PATTERNS['email'], email):
            return False, "Formato de email inválido"
            
        return True, ""

    @classmethod
    def validate_password(cls, password: str) -> Tuple[bool, str]:
        """Valida contraseña"""
        if not cls.MIN_PASSWORD_LENGTH <= len(password) <= cls.MAX_PASSWORD_LENGTH:
            return False, f"La contraseña debe tener entre {cls.MIN_PASSWORD_LENGTH} y {cls.MAX_PASSWORD_LENGTH} caracteres"
            
        if not re.match(cls.PATTERNS['password'], password):
            return False, "La contraseña debe contener al menos una letra y un número"
            
        return True, ""

    @classmethod
    def validate_username(cls, username: str) -> Tuple[bool, str]:
        """Valida nombre de usuario"""
        if not cls.MIN_USERNAME_LENGTH <= len(username) <= cls.MAX_USERNAME_LENGTH:
            return False, f"El usuario debe tener entre {cls.MIN_USERNAME_LENGTH} y {cls.MAX_USERNAME_LENGTH} caracteres"
            
        if not re.match(cls.PATTERNS['username'], username):
            return False, "El usuario solo puede contener letras, números, guiones y guiones bajos"
            
        return True, ""

    @classmethod
    def validate_message(cls, message: str) -> Tuple[bool, str]:
        """Valida mensaje de usuario"""
        if not message:
            return False, "El mensaje no puede estar vacío"
            
        if len(message) > cls.MAX_MESSAGE_LENGTH:
            return False, f"El mensaje no puede exceder {cls.MAX_MESSAGE_LENGTH} caracteres"
        
        # Verificar contenido malicioso
        is_safe, error = cls.check_malicious_content(message)
        if not is_safe:
            return False, error
            
        return True, ""

    @classmethod
    def sanitize_and_validate_input(cls, input_type: str, content: str) -> Dict[str, Any]:
        """Método principal para sanitizar y validar cualquier input"""
        result = {
            'is_valid': False,
            'sanitized_content': '',
            'error_message': ''
        }
        
        # Primero sanitizamos
        sanitized_content = cls.sanitize_html(content)
        result['sanitized_content'] = sanitized_content
        
        # Luego validamos según el tipo
        if input_type == 'email':
            result['is_valid'], result['error_message'] = cls.validate_email(sanitized_content)
        elif input_type == 'password':
            result['is_valid'], result['error_message'] = cls.validate_password(sanitized_content)
        elif input_type == 'username':
            result['is_valid'], result['error_message'] = cls.validate_username(sanitized_content)
        elif input_type == 'message':
            result['is_valid'], result['error_message'] = cls.validate_message(sanitized_content)
        else:
            result['error_message'] = "Tipo de input no válido"
            
        return result