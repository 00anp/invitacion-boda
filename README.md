# Invitación de Boda - Aplicación Web

## Descripción
Aplicación web para gestionar invitaciones y confirmaciones de asistencia a una boda.

## Características
- Sistema de autenticación
- Panel administrativo
- Gestión de invitados
- Confirmaciones de asistencia
- Generación de tickets personalizados

## Tecnologías
- FastAPI
- SQLAlchemy
- MySQL
- HTMX

## Configuración
1. Crear archivo .env
2. Instalar dependencias: `pip install -r requirements.txt`
3. Ejecutar migraciones: `alembic upgrade head`
4. Iniciar servidor: `uvicorn main:app --reload`

## Estructura del Proyecto
- /routers: Endpoints de la API
- /templates: Plantillas HTML
- /static: Archivos estáticos
- /models: Modelos de base de datos
- /utils: Utilidades y configuraciones