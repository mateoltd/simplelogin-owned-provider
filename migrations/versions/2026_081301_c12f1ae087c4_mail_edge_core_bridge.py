"""Add provider-neutral mail-edge core bridge persistence.

Revision ID: c12f1ae087c4
Revises: 4a9f8c2e1b3d
Create Date: 2026-08-13 06:30:00.000000

"""

from alembic import op
import sqlalchemy as sa
import sqlalchemy_utils


revision = "c12f1ae087c4"
down_revision = "4a9f8c2e1b3d"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mail_ingress_receipt",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "created_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=False
        ),
        sa.Column(
            "updated_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=True
        ),
        sa.Column("ingress_id", sa.String(length=128), nullable=False),
        sa.Column("message_digest", sa.String(length=64), nullable=False),
        sa.Column("state", sa.Integer(), server_default="0", nullable=False),
        sa.Column("lease_token", sa.String(length=64), nullable=True),
        sa.Column(
            "lease_expires_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=True
        ),
        sa.Column("smtp_status", sa.String(length=512), nullable=True),
        sa.Column("attempt_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "completed_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=True
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ingress_id"),
    )
    op.create_index(
        "ix_mail_ingress_receipt_state_lease",
        "mail_ingress_receipt",
        ["state", "lease_expires_at"],
        unique=False,
    )

    op.create_table(
        "transport_message_id_matching",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "created_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=False
        ),
        sa.Column(
            "updated_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=True
        ),
        sa.Column("edge_delivery_id", sa.String(length=128), nullable=False),
        sa.Column("provider_message_id", sa.String(length=512), nullable=True),
        sa.Column("provider_visible_message_id", sa.String(length=1024), nullable=True),
        sa.Column("submitted_message_id", sa.String(length=1024), nullable=False),
        sa.Column("original_message_id", sa.String(length=1024), nullable=False),
        sa.Column("original_envelope_from", sa.String(length=512), nullable=False),
        sa.Column("recipient", sa.String(length=512), nullable=False),
        sa.Column("email_log_id", sa.Integer(), nullable=True),
        sa.Column("transactional_email_id", sa.Integer(), nullable=True),
        sa.Column(
            "hard_bounce_applied_at",
            sqlalchemy_utils.types.arrow.ArrowType(),
            nullable=True,
        ),
        sa.Column(
            "complaint_applied_at",
            sqlalchemy_utils.types.arrow.ArrowType(),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["email_log_id"], ["email_log.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["transactional_email_id"],
            ["transactional_email.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("edge_delivery_id"),
        sa.UniqueConstraint("provider_message_id"),
        sa.UniqueConstraint("provider_visible_message_id"),
    )
    op.create_index(
        op.f("ix_transport_message_id_matching_email_log_id"),
        "transport_message_id_matching",
        ["email_log_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_transport_message_id_matching_transactional_email_id"),
        "transport_message_id_matching",
        ["transactional_email_id"],
        unique=False,
    )

    op.create_table(
        "mail_feedback_receipt",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "created_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=False
        ),
        sa.Column(
            "updated_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=True
        ),
        sa.Column("provider_event_id", sa.String(length=256), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("edge_delivery_id", sa.String(length=128), nullable=True),
        sa.Column("provider_message_id", sa.String(length=512), nullable=True),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("recipient", sa.String(length=512), nullable=False),
        sa.Column("smtp_status", sa.String(length=512), nullable=True),
        sa.Column("diagnostic", sa.String(length=2048), nullable=True),
        sa.Column(
            "occurred_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=False
        ),
        sa.Column("state", sa.Integer(), server_default="0", nullable=False),
        sa.Column("transport_matching_id", sa.Integer(), nullable=True),
        sa.Column(
            "applied_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=True
        ),
        sa.Column("rejection_reason", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(
            ["transport_matching_id"],
            ["transport_message_id_matching.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider_event_id"),
    )
    op.create_index(
        op.f("ix_mail_feedback_receipt_edge_delivery_id"),
        "mail_feedback_receipt",
        ["edge_delivery_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_mail_feedback_receipt_provider_message_id"),
        "mail_feedback_receipt",
        ["provider_message_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_mail_feedback_receipt_transport_matching_id"),
        "mail_feedback_receipt",
        ["transport_matching_id"],
        unique=False,
    )

    op.create_table(
        "mail_edge_replay_nonce",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "created_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=False
        ),
        sa.Column(
            "updated_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=True
        ),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column(
            "expires_at", sqlalchemy_utils.types.arrow.ArrowType(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_id", "nonce", name="uq_mail_edge_replay_key_nonce"),
    )
    op.create_index(
        op.f("ix_mail_edge_replay_nonce_expires_at"),
        "mail_edge_replay_nonce",
        ["expires_at"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        op.f("ix_mail_edge_replay_nonce_expires_at"),
        table_name="mail_edge_replay_nonce",
    )
    op.drop_table("mail_edge_replay_nonce")
    op.drop_index(
        op.f("ix_mail_feedback_receipt_transport_matching_id"),
        table_name="mail_feedback_receipt",
    )
    op.drop_index(
        op.f("ix_mail_feedback_receipt_provider_message_id"),
        table_name="mail_feedback_receipt",
    )
    op.drop_index(
        op.f("ix_mail_feedback_receipt_edge_delivery_id"),
        table_name="mail_feedback_receipt",
    )
    op.drop_table("mail_feedback_receipt")
    op.drop_index(
        op.f("ix_transport_message_id_matching_transactional_email_id"),
        table_name="transport_message_id_matching",
    )
    op.drop_index(
        op.f("ix_transport_message_id_matching_email_log_id"),
        table_name="transport_message_id_matching",
    )
    op.drop_table("transport_message_id_matching")
    op.drop_index(
        "ix_mail_ingress_receipt_state_lease",
        table_name="mail_ingress_receipt",
    )
    op.drop_table("mail_ingress_receipt")
