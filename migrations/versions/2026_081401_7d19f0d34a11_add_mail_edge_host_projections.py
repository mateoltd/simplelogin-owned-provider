"""add provider-neutral mail-edge host projections

Revision ID: 7d19f0d34a11
Revises: 4a9f8c2e1b3d
"""

from alembic import op
import sqlalchemy as sa


revision = "7d19f0d34a11"
down_revision = "4a9f8c2e1b3d"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mail_edge_replay_nonce",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("nonce_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_id", "nonce_digest", name="uq_mail_edge_replay_nonce"),
    )
    op.create_index(
        "ix_mail_edge_replay_nonce_expires_at", "mail_edge_replay_nonce", ["expires_at"]
    )
    op.create_table(
        "mail_edge_callback_receipt",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("operation", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=128), nullable=False),
        sa.Column("body_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="processing", nullable=False
        ),
        sa.Column("acknowledgement", sa.JSON(), nullable=True),
        sa.CheckConstraint(
            "status IN ('processing', 'completed')",
            name="ck_mail_edge_callback_receipt_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "operation", "subject_id", name="uq_mail_edge_callback_receipt"
        ),
    )
    op.create_index(
        "ix_mail_edge_callback_tenant_operation",
        "mail_edge_callback_receipt",
        ["tenant_id", "operation"],
    )
    op.create_table(
        "mail_edge_outbound_projection",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("intent_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("alias_id", sa.Integer(), nullable=False),
        sa.Column("contact_id", sa.Integer(), nullable=True),
        sa.Column("mailbox_id", sa.Integer(), nullable=True),
        sa.Column("email_log_id", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("version", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("feedback_kind", sa.String(length=32), nullable=True),
        sa.Column("quarantined", sa.Boolean(), server_default="0", nullable=False),
        sa.CheckConstraint(
            "state IN ('accepted', 'ready', 'dispatching', 'retry_wait', "
            "'provider_accepted', 'failed_not_sent', 'quarantined_unknown', "
            "'canceled')",
            name="ck_mail_edge_outbound_projection_state",
        ),
        sa.CheckConstraint(
            "version >= 0", name="ck_mail_edge_outbound_projection_version"
        ),
        sa.ForeignKeyConstraint(["alias_id"], ["alias.id"], ondelete="cascade"),
        sa.ForeignKeyConstraint(["contact_id"], ["contact.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["email_log_id"], ["email_log.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["mailbox_id"], ["mailbox.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="cascade"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "intent_id", name="uq_mail_edge_outbound_intent"
        ),
    )
    op.create_index(
        "ix_mail_edge_outbound_user_id_id",
        "mail_edge_outbound_projection",
        ["user_id", "id"],
    )
    op.create_index(
        "ix_mail_edge_outbound_alias_id_id",
        "mail_edge_outbound_projection",
        ["alias_id", "id"],
    )
    op.create_table(
        "mail_edge_route_binding_projection",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("domain_a_label", sa.String(length=253), nullable=False),
        sa.Column("direction", sa.String(length=8), nullable=False),
        sa.Column("binding_id", sa.String(length=36), nullable=False),
        sa.Column("binding_version", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.CheckConstraint(
            "direction IN ('inbound', 'outbound')",
            name="ck_mail_edge_route_binding_direction",
        ),
        sa.CheckConstraint(
            "state IN ('active', 'draining', 'retired')",
            name="ck_mail_edge_route_binding_state",
        ),
        sa.CheckConstraint(
            "binding_version > 0", name="ck_mail_edge_route_binding_version"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "domain_a_label",
            "direction",
            "binding_id",
            "binding_version",
            name="uq_mail_edge_route_binding_generation",
        ),
    )
    op.create_index(
        "ix_mail_edge_route_binding_active_lookup",
        "mail_edge_route_binding_projection",
        ["tenant_id", "domain_a_label", "direction", "state", "binding_version"],
    )
    op.create_index(
        "uq_mail_edge_route_binding_one_active",
        "mail_edge_route_binding_projection",
        ["tenant_id", "domain_a_label", "direction"],
        unique=True,
        postgresql_where=sa.text("state = 'active'"),
    )


def downgrade():
    op.drop_table("mail_edge_route_binding_projection")
    op.drop_table("mail_edge_outbound_projection")
    op.drop_table("mail_edge_callback_receipt")
    op.drop_table("mail_edge_replay_nonce")
