from alembic import op
import sqlalchemy as sa


revision = "add_users_auth"
down_revision = "add_kev_fields"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
        ),
        sa.Column(
            "full_name",
            sa.String(150),
            nullable=False,
        ),
        sa.Column(
            "email",
            sa.String(320),
            nullable=False,
        ),
        sa.Column(
            "password_hash",
            sa.String(255),
            nullable=False,
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_login_at",
            sa.DateTime(),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_users_email",
        "users",
        ["email"],
        unique=True,
    )


def downgrade():
    op.drop_index(
        "ix_users_email",
        table_name="users",
    )

    op.drop_table("users")