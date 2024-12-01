#Libraries
from database import SessionLocal, engine
from sqlalchemy.orm import Session
from datetime import datetime
#On File
import models
from models import Group, Guest, Message, MessageSignature

# Creamos las tablas en la base de datos
models.Base.metadata.create_all(bind=engine)

def seed_database():
    """
    Función para poblar la base de datos con datos de prueba
    """
    # Creamos una sesión de la base de datos
    db = SessionLocal()
    
    try:
        # Creamos algunos grupos de prueba
        grupo_familia = Group(
            name="Familia Pérez"
        )
        grupo_amigos = Group(
            name="Amigos del Trabajo"
        )
        grupo_5 = Group(
            name="Grupo 3"
        )


        # Agregamos los grupos a la sesión
        db.add(grupo_familia)
        db.add(grupo_amigos)
        db.add(grupo_5)
        db.commit()
        
        # Refrescamos los objetos para obtener sus IDs
        db.refresh(grupo_familia)
        db.refresh(grupo_amigos)
        db.refresh(grupo_5)
        
        # Creamos invitados para el grupo familiar
        invitados_familia = [
            Guest(
                name="Juan Pérez",
                email="juan@example.com",
                phone="123456789",
                group_id=grupo_familia.id,
                has_confirmed=True,
                is_attending=True,
                confirmation_date=datetime.now()
            ),
            Guest(
                name="María Pérez",
                email="maria@example.com",
                phone="987654321",
                group_id=grupo_familia.id,
                has_confirmed=True,
                is_attending=True,
                confirmation_date=datetime.now()
            )
        ]
        
        # Creamos invitados para el grupo de amigos
        invitados_amigos = [
            Guest(
                name="Carlos López",
                email="carlos@example.com",
                phone="555666777",
                group_id=grupo_amigos.id,
                has_confirmed=True,
                is_attending=False,
                confirmation_date=datetime.now()
            ),
            Guest(
                name="Ana García",
                email="ana@example.com",
                phone="999888777",
                group_id=grupo_amigos.id,
                has_confirmed=True,
                is_attending=False,
                confirmation_date=datetime.now()
            )
        ]

        invitados_grupo_5 = [
            Guest(
                name="Citlali",
                email="test@example.com",
                phone="555666777",
                group_id=grupo_5.id,
                has_confirmed=True,
                is_attending=True,
                confirmation_date=datetime.now()
            ),
            Guest(
                name="Eloisa",
                email="test@example.com",
                phone="555666777",
                group_id=grupo_5.id,
                has_confirmed=True,
                is_attending=True,
                confirmation_date=datetime.now()
            ),
            Guest(
                name="Antonia",
                email="test@example.com",
                phone="555666777",
                group_id=grupo_5.id,
                has_confirmed=True,
                is_attending=True,
                confirmation_date=datetime.now()
            ),
            Guest(
                name="Luisa",
                email="test@example.com",
                phone="555666777",
                group_id=grupo_5.id,
                has_confirmed=True,
                is_attending=True,
                confirmation_date=datetime.now()
            ),
            Guest(
                name="Citlali",
                email="test@example.com",
                phone="555666777",
                group_id=grupo_5.id,
                has_confirmed=True,
                is_attending=True,
                confirmation_date=datetime.now()
            )
        ]
        
        # Agregamos todos los invitados a la sesión
        for invitado in invitados_familia + invitados_amigos + invitados_grupo_5:
            db.add(invitado)
        
        # Guardamos los cambios
        db.commit()
        
        # Creamos algunos mensajes de prueba
        mensaje_familia = Message(
            group_id=grupo_familia.id,
            content="¡Felicidades a los novios! Les deseamos lo mejor en esta nueva etapa."
        )

        mensaje_grupo_5 = Message(
            group_id=grupo_5.id,
            content="Felicidades a los novios."
        )
        
        db.add(mensaje_familia)
        db.add(mensaje_grupo_5)
        db.commit()
        db.refresh(mensaje_familia)
        db.refresh(mensaje_grupo_5)
        
        # Creamos firmas para el mensaje
        for invitado in invitados_familia:
            firma = MessageSignature(
                message_id=mensaje_familia.id,
                guest_id=invitado.id
            )
            db.add(firma)

        for invitado in invitados_grupo_5:
            firma = MessageSignature(
                message_id=mensaje_grupo_5.id,
                guest_id = invitado.id
            )
            db.add(firma)
        
        # Guardamos todos los cambios
        db.commit()
        
        print("¡Base de datos poblada exitosamente!")
        
    except Exception as e:
        print(f"Error al poblar la base de datos: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()