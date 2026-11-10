from __future__ import annotations

import asyncio
from pathlib import Path

import asyncpg

from app.core.config import get_settings

MIGRATION_LOCK_ID = 8_428_601


async def migrate(database_url: str) -> list[str]:
    connection = await asyncpg.connect(database_url)
    applied: list[str] = []
    try:
        await connection.execute("SELECT pg_advisory_lock($1)", MIGRATION_LOCK_ID)
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version text PRIMARY KEY,
                applied_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        known = {
            row["version"]
            for row in await connection.fetch("SELECT version FROM schema_migrations")
        }
        directory = Path(__file__).with_name("migrations")
        for path in sorted(directory.glob("*.sql")):
            if path.name in known:
                continue
            async with connection.transaction():
                await connection.execute(path.read_text(encoding="utf-8"))
                await connection.execute(
                    "INSERT INTO schema_migrations(version) VALUES($1)", path.name
                )
            applied.append(path.name)
    finally:
        try:
            await connection.execute("SELECT pg_advisory_unlock($1)", MIGRATION_LOCK_ID)
        finally:
            await connection.close()
    return applied


async def main() -> None:
    settings = get_settings()
    if not settings.database_url:
        raise RuntimeError("DATABASE_URL is required to run migrations")
    applied = await migrate(settings.database_url)
    print(f"Applied {len(applied)} migration(s): {', '.join(applied) or 'none'}")


if __name__ == "__main__":
    asyncio.run(main())
