import hashlib
import hmac
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt_hex, digest_hex = password_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return hmac.compare_digest(actual, expected)


class AuthRepository:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    PRIMARY KEY (user_id, role_id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (role_id) REFERENCES roles(id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)")
            conn.commit()

    def ensure_default_user(self, username: str, password: str, role: str):
        if not username or not password or not role:
            return
        existing = self.get_user_by_username(username)
        if existing:
            return
        self.create_user(username=username, password=password, roles=[role])

    def create_user(self, username: str, password: str, roles: List[str]) -> int:
        created_at = datetime.now(timezone.utc).isoformat()
        password_hash = hash_password(password)
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO users (username, password_hash, is_active, created_at)
                    VALUES (?, ?, 1, ?)
                    """,
                    (username, password_hash, created_at),
                )
                user_id = cursor.lastrowid
                self._assign_roles(conn=conn, user_id=user_id, roles=roles)
                conn.commit()
                return user_id

    def _assign_roles(self, conn, user_id: int, roles: List[str]):
        for role_name in sorted({r.strip().lower() for r in roles if r and r.strip()}):
            conn.execute("INSERT OR IGNORE INTO roles (name) VALUES (?)", (role_name,))
            role_row = conn.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
            conn.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                (user_id, role_row["id"]),
            )

    def get_user_by_username(self, username: str):
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, username, password_hash, is_active, created_at
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: int):
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, username, password_hash, is_active, created_at
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_user_roles(self, user_id: int) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT r.name
                FROM roles r
                INNER JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = ?
                ORDER BY r.name ASC
                """,
                (user_id,),
            ).fetchall()
        return [r["name"] for r in rows]
