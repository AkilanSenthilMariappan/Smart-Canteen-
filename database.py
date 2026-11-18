
import os
from pathlib import Path
from urllib.parse import urlparse, unquote

import pg8000


def load_database_env():
    env_file = Path(__file__).with_name(".env")

    if env_file.exists():
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            os.environ.setdefault(
                key.strip(),
                value.strip().strip('"').strip("'")
            )


def get_connection():
    load_database_env()

    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured.")

    parsed = urlparse(database_url)

    if not parsed.hostname or not parsed.username or not parsed.password:
        raise RuntimeError("DATABASE_URL is incomplete.")

    return pg8000.connect(
        user=unquote(parsed.username),
        password=unquote(parsed.password),
        host=parsed.hostname,
        port=parsed.port or 5432,
        database=unquote(parsed.path.lstrip("/")),
        ssl_context=True
    )
