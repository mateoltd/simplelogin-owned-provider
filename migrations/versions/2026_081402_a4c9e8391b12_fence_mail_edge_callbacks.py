"""fence mail-edge callback claims

Revision ID: a4c9e8391b12
Revises: 7d19f0d34a11
"""

from alembic import op
import sqlalchemy as sa


revision = "a4c9e8391b12"
down_revision = "7d19f0d34a11"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("mail_edge_callback_receipt") as batch_op:
        batch_op.add_column(
            sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False)
        )
        batch_op.add_column(
            sa.Column("fence", sa.BigInteger(), server_default="0", nullable=False)
        )
        batch_op.add_column(sa.Column("claimed_until", sa.DateTime(timezone=True)))
        batch_op.add_column(
            sa.Column("business_started_at", sa.DateTime(timezone=True))
        )
        batch_op.create_check_constraint(
            "ck_mail_edge_callback_attempt_count", "attempt_count >= 0"
        )
        batch_op.create_check_constraint("ck_mail_edge_callback_fence", "fence >= 0")
        batch_op.create_index(
            "ix_mail_edge_callback_claimed_until", ["claimed_until"], unique=False
        )
    op.execute(
        sa.text(
            "UPDATE mail_edge_callback_receipt "
            "SET business_started_at = CURRENT_TIMESTAMP "
            "WHERE status = 'processing'"
        )
    )


def downgrade():
    with op.batch_alter_table("mail_edge_callback_receipt") as batch_op:
        batch_op.drop_index("ix_mail_edge_callback_claimed_until")
        batch_op.drop_constraint("ck_mail_edge_callback_fence", type_="check")
        batch_op.drop_constraint("ck_mail_edge_callback_attempt_count", type_="check")
        batch_op.drop_column("claimed_until")
        batch_op.drop_column("business_started_at")
        batch_op.drop_column("fence")
        batch_op.drop_column("attempt_count")
