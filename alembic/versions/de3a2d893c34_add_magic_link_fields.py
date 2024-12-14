"""add_magic_link_fields

Revision ID: de3a2d893c34
Revises: 
Create Date: 2024-12-12 13:21:09.998197

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'de3a2d893c34'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('reset_token', sa.String(length=100), nullable=True))
    op.add_column('users', sa.Column('reset_token_expires', sa.DateTime(timezone=True), nullable=True))

def downgrade() -> None:
    pass
