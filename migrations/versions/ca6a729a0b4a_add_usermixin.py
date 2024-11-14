"""Add UserMixin

Revision ID: ca6a729a0b4a
Revises: d35493cac8ae
Create Date: 2024-11-14 20:03:01.637528

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ca6a729a0b4a'
down_revision = 'd35493cac8ae'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('date_added', sa.DateTime(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('date_added')

    # ### end Alembic commands ###
