"""scope security data by user account

Revision ID: 20260906_account_data_isolation
Revises: add_users_auth
Create Date: 2026-09-06
"""

from alembic import op
import sqlalchemy as sa


revision = "20260906_account_data_isolation"
down_revision = "add_users_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add nullable ownership columns first so existing environments can be
    # assigned to the account that last logged in during the migration.
    op.add_column(
        "assets",
        sa.Column("user_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("user_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("user_id", sa.Integer(), nullable=True),
    )
    op.add_column(
        "asset_relationships",
        sa.Column("user_id", sa.Integer(), nullable=True),
    )

    op.create_foreign_key(
        "fk_assets_user_id_users",
        "assets",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_vulnerabilities_user_id_users",
        "vulnerabilities",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_asset_vulnerabilities_user_id_users",
        "asset_vulnerabilities",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_asset_relationships_user_id_users",
        "asset_relationships",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # Existing security data predates authentication. Assign it to the most
    # recently logged-in active account, which is the account that has been
    # using the existing shared environment.
    op.execute(
        sa.text(
            """
            DO $$
            DECLARE owner_id integer;
            BEGIN
                SELECT id INTO owner_id
                FROM users
                WHERE is_active = TRUE
                ORDER BY last_login_at DESC NULLS LAST, id DESC
                LIMIT 1;

                IF owner_id IS NULL THEN
                    RAISE EXCEPTION 'Cannot scope existing security data: no active user exists.';
                END IF;

                UPDATE assets
                SET user_id = owner_id
                WHERE user_id IS NULL;

                UPDATE vulnerabilities
                SET user_id = owner_id
                WHERE user_id IS NULL;

                UPDATE asset_vulnerabilities av
                SET user_id = a.user_id
                FROM assets a
                WHERE av.asset_id = a.id
                  AND av.user_id IS NULL;

                UPDATE asset_relationships ar
                SET user_id = a.user_id
                FROM assets a
                WHERE ar.source_asset_id = a.id
                  AND ar.user_id IS NULL;
            END $$;
            """
        )
    )

    op.alter_column("assets", "user_id", nullable=False)
    op.alter_column("vulnerabilities", "user_id", nullable=False)
    op.alter_column("asset_vulnerabilities", "user_id", nullable=False)
    op.alter_column("asset_relationships", "user_id", nullable=False)

    # Replace global uniqueness with per-account uniqueness.
    op.execute(
        sa.text(
            """
            DO $$
            DECLARE r record;
            BEGIN
                FOR r IN
                    SELECT c.conname
                    FROM pg_constraint c
                    JOIN pg_class t ON t.oid = c.conrelid
                    WHERE c.contype = 'u'
                      AND t.relname = 'assets'
                      AND pg_get_constraintdef(c.oid) = 'UNIQUE (name)'
                LOOP
                    EXECUTE format('ALTER TABLE assets DROP CONSTRAINT %I', r.conname);
                END LOOP;

                FOR r IN
                    SELECT c.conname
                    FROM pg_constraint c
                    JOIN pg_class t ON t.oid = c.conrelid
                    WHERE c.contype = 'u'
                      AND t.relname = 'vulnerabilities'
                      AND pg_get_constraintdef(c.oid) = 'UNIQUE (cve_id)'
                LOOP
                    EXECUTE format('ALTER TABLE vulnerabilities DROP CONSTRAINT %I', r.conname);
                END LOOP;
            END $$;
            """
        )
    )

    op.create_unique_constraint(
        "uq_assets_user_name",
        "assets",
        ["user_id", "name"],
    )
    op.create_unique_constraint(
        "uq_vulnerabilities_user_cve",
        "vulnerabilities",
        ["user_id", "cve_id"],
    )

    op.create_index(
        "ix_assets_user_id",
        "assets",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_vulnerabilities_user_id",
        "vulnerabilities",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_vulnerabilities_user_id",
        "asset_vulnerabilities",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_asset_relationships_user_id",
        "asset_relationships",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_asset_relationships_user_id", table_name="asset_relationships")
    op.drop_index("ix_asset_vulnerabilities_user_id", table_name="asset_vulnerabilities")
    op.drop_index("ix_vulnerabilities_user_id", table_name="vulnerabilities")
    op.drop_index("ix_assets_user_id", table_name="assets")

    op.drop_constraint("uq_vulnerabilities_user_cve", "vulnerabilities", type_="unique")
    op.drop_constraint("uq_assets_user_name", "assets", type_="unique")

    op.create_unique_constraint("uq_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])
    op.create_unique_constraint("uq_assets_name", "assets", ["name"])

    op.drop_constraint("fk_asset_relationships_user_id_users", "asset_relationships", type_="foreignkey")
    op.drop_constraint("fk_asset_vulnerabilities_user_id_users", "asset_vulnerabilities", type_="foreignkey")
    op.drop_constraint("fk_vulnerabilities_user_id_users", "vulnerabilities", type_="foreignkey")
    op.drop_constraint("fk_assets_user_id_users", "assets", type_="foreignkey")

    op.drop_column("asset_relationships", "user_id")
    op.drop_column("asset_vulnerabilities", "user_id")
    op.drop_column("vulnerabilities", "user_id")
    op.drop_column("assets", "user_id")
