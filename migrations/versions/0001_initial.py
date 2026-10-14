"""initial schema: users, checks, reputation_entities, labels

Revision ID: 0001
Revises:
Create Date: 2026-10-15
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("user_hash", sa.String(64), primary_key=True),
        sa.Column("language", sa.String(16), nullable=False, server_default="hinglish"),
        sa.Column("consent_at", sa.DateTime(timezone=True)),
        sa.Column("checks_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "checks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_hash", sa.String(64), nullable=False, index=True),
        sa.Column("input_type", sa.String(16), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False, index=True),
        sa.Column("verdict", sa.String(16), nullable=False, index=True),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column(
            "reason_codes", postgresql.ARRAY(sa.String(32)), nullable=False, server_default="{}"
        ),
        sa.Column("domains", postgresql.ARRAY(sa.String(253)), nullable=False, server_default="{}"),
        sa.Column("language", sa.String(16), nullable=False),
        sa.Column("latency_ms", sa.Integer, nullable=False),
        sa.Column("from_cache", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("llm_used", sa.String(32), nullable=False, server_default="template"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True
        ),
    )
    op.create_table(
        "reputation_entities",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("entity_type", sa.String(16), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("prefix5", sa.String(5), nullable=False),
        sa.Column("value", sa.Text),
        sa.Column("verdict", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column("sources", postgresql.ARRAY(sa.String(32)), nullable=False, server_default="{}"),
        sa.Column("report_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("entity_type", "sha256", name="uq_rep_type_hash"),
    )
    op.create_index("ix_rep_type_prefix", "reputation_entities", ["entity_type", "prefix5"])
    op.create_table(
        "labels",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "check_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("checks.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("analyst", sa.String(64), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("note", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("labels")
    op.drop_index("ix_rep_type_prefix", table_name="reputation_entities")
    op.drop_table("reputation_entities")
    op.drop_table("checks")
    op.drop_table("users")
