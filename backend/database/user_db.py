import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

import bcrypt
import httpx

from backend.core.config import SUPABASE_URL, SUPABASE_KEY

logger = logging.getLogger('ats_resume_scorer')

_DB_DIR = Path(__file__).resolve().parents[2] / 'data'
_DB_PATH = _DB_DIR / 'users.db'


def _get_connection() -> sqlite3.Connection:
    _DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _get_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    finally:
        conn.close()


init_db()


def normalize_email(email: str) -> str:
    """Normalize email: trim leading/trailing whitespace and convert to lowercase."""
    if not email:
        return ""
    return email.strip().lower()


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as exc:
        logger.warning(f"Bcrypt verification failed with error: {exc}")
        return False


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    clean_email = normalize_email(email)
    if not clean_email:
        return None
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = ?", (clean_email,))
        row = cur.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    if not user_id:
        return None
    conn = _get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, password_hash, created_at, updated_at FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()


def sync_supabase_admin_user(email: str, password: str) -> Optional[str]:
    """Sync user creation to Supabase auth with auto email confirmation."""
    clean_email = normalize_email(email)
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }
    
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{SUPABASE_URL.rstrip('/')}/auth/v1/admin/users",
                headers=headers,
                json={
                    "email": clean_email,
                    "password": password,
                    "email_confirm": True,
                    "user_metadata": {"email_verified": True},
                },
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                logger.info(f"User synced to Supabase Admin Auth: {clean_email} -> {data.get('id')}")
                return data.get("id")
            elif resp.status_code == 422 or "already" in resp.text.lower():
                # User already exists in Supabase, let's find user and update password
                list_resp = client.get(f"{SUPABASE_URL.rstrip('/')}/auth/v1/admin/users", headers=headers)
                if list_resp.status_code == 200:
                    for u in list_resp.json().get("users", []):
                        if normalize_email(u.get("email")) == clean_email:
                            uid = u.get("id")
                            # Update password and confirm email
                            client.put(
                                f"{SUPABASE_URL.rstrip('/')}/auth/v1/admin/users/{uid}",
                                headers=headers,
                                json={"password": password, "email_confirm": True},
                            )
                            logger.info(f"Updated existing Supabase user password: {clean_email} -> {uid}")
                            return uid
    except Exception as exc:
        logger.warning(f"Supabase admin user sync failed (non-fatal): {exc}")
    return None


def create_user(email: str, password: str, custom_id: Optional[str] = None) -> Dict[str, Any]:
    """Create a new user with bcrypt password hash in database."""
    clean_email = normalize_email(email)
    if not clean_email:
        raise ValueError("Email cannot be empty")
    if not password:
        raise ValueError("Password cannot be empty")

    existing = get_user_by_email(clean_email)
    if existing:
        raise ValueError("An account with this email already exists")

    # Sync with Supabase admin to obtain Supabase UUID if available
    sb_id = sync_supabase_admin_user(clean_email, password)
    user_id = custom_id or sb_id or str(uuid.uuid4())
    pw_hash = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, clean_email, pw_hash, now, now),
            )
    finally:
        conn.close()

    return {
        "id": user_id,
        "email": clean_email,
        "created_at": now,
        "updated_at": now,
    }


def update_password(email: str, new_password: str) -> bool:
    clean_email = normalize_email(email)
    pw_hash = hash_password(new_password)
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_connection()
    try:
        with conn:
            cur = conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE email = ?",
                (pw_hash, now, clean_email),
            )
            updated = cur.rowcount > 0
    finally:
        conn.close()

    if updated:
        sync_supabase_admin_user(clean_email, new_password)
    return updated
