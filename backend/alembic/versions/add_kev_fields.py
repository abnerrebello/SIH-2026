"""add CISA KEV fields

Revision ID: add_kev_fields
Revises: d9a76d15b758
Create Date: 2026-08-28
"""

from alembic import op
import sqlalchemy as sa


revision = "add_kev_fields"
down_revision = "d9a76d15b758"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "kev_status",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    op.add_column(
        "vulnerabilities",
        sa.Column(
            "kev_date_added",
            sa.DateTime(),
            nullable=True,
        ),
    )

    op.alter_column(
        "vulnerabilities",
        "kev_status",
        server_default=None,
    )


def downgrade() -> None:
    op.drop_column(
        "vulnerabilities",
        "kev_date_added",
    )

    op.drop_column(
        "vulnerabilities",
        "kev_status",
    )
