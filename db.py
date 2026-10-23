"""Хранение мастер-пароля и записей в SQLite."""

import sqlite3
from contextlib import contextmanager
from typing import Iterator, List, Optional

from paths import app_dir


def database_path():
    return app_dir() / "password.db"


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database_path())
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    """Создать password.db и таблицы, если их ещё нет."""
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                login TEXT NOT NULL,
                password TEXT NOT NULL
            )
            """
        )


def get_master_hash() -> Optional[str]:
    with connect() as connection:
        row = connection.execute(
            "SELECT password_hash FROM master WHERE id = 1"
        ).fetchone()
    if row is None:
        return None
    return str(row["password_hash"])


def set_master_hash(password_hash: str) -> None:
    with connect() as connection:
        connection.execute(
            """
            INSERT INTO master (id, password_hash)
            VALUES (1, ?)
            ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash
            """,
            (password_hash,),
        )


def add_entry(name: str, login: str, encrypted_password: str) -> None:
    with connect() as connection:
        connection.execute(
            "INSERT INTO entries (name, login, password) VALUES (?, ?, ?)",
            (name, login, encrypted_password),
        )


def get_entry(name: str) -> Optional[dict]:
    with connect() as connection:
        row = connection.execute(
            "SELECT name, login, password FROM entries WHERE name = ?",
            (name,),
        ).fetchone()
    if row is None:
        return None
    return {"name": row["name"], "login": row["login"], "password": row["password"]}


def list_entries() -> List[dict]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT name, login FROM entries ORDER BY name"
        ).fetchall()
    return [{"name": row["name"], "login": row["login"]} for row in rows]


def delete_entry(name: str) -> bool:
    """Удалить запись по названию. Вернуть True, если строка была."""
    with connect() as connection:
        cursor = connection.execute("DELETE FROM entries WHERE name = ?", (name,))
        return cursor.rowcount > 0
