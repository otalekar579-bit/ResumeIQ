import os
import logging
from pathlib import Path
from typing import Any, Dict
import streamlit as st
from supabase import Client, create_client

logger = logging.getLogger('ats_resume_scorer')


try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[2] / '.env')
except ImportError:
    pass


def _secret(key: str, section: str = 'supabase') -> str:
    """Read from env first, then fall back to st.secrets[section][key]."""
    val = os.getenv(key, '')
    if val:
        return val
    try:
        return st.secrets[section][key]
    except (KeyError, FileNotFoundError, AttributeError):
        return ''


SUPABASE_URL = _secret('SUPABASE_URL')
SUPABASE_ANON_KEY = _secret('SUPABASE_ANON_KEY') or _secret('SUPABASE_PUBLISHABLE_KEY')

OAUTH_REDIRECT_URL = (
    os.getenv('AUTH_REDIRECT_URL')
    or _secret('redirect_uri', 'google_oauth')
    or 'http://localhost:8501'
)


def _missing_config() -> str | None:
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return 'Supabase is not configured — set SUPABASE_URL and SUPABASE_ANON_KEY in .env or .streamlit/secrets.toml'
    return None


@st.cache_resource
def get_client() -> Client | None:
    """Cached singleton — preserves PKCE state across Streamlit reruns."""
    if _missing_config():
        return None
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


def _session_dict(session, user) -> Dict[str, Any]:
    return {
        'access_token':  session.access_token,
        'refresh_token': session.refresh_token,
        'user_id':       user.id,
        'email':         user.email,
    }


import uuid
import time
import jwt

LOCAL_JWT_SECRET = "ats-local-secret-key-default-2026"


def create_local_session(identifier: str) -> Dict[str, Any]:
    clean_id = (identifier or "user").strip()
    user_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, clean_id.lower()))
    display_email = clean_id if "@" in clean_id else f"{clean_id}@local.user"
    payload = {
        "sub": user_uuid,
        "email": display_email,
        "aud": "authenticated",
        "exp": int(time.time()) + 86400 * 30,
    }
    token = jwt.encode(payload, LOCAL_JWT_SECRET, algorithm="HS256")
    return {
        "access_token": token,
        "refresh_token": token,
        "user_id": user_uuid,
        "email": clean_id,
    }


def sign_in_with_password(email: str, password: str) -> Dict[str, Any]:
    identifier = (email or "").strip().lower()
    if not identifier:
        return {'error': 'Please enter your email'}
    if not password:
        return {'error': 'Please enter your password'}

    # 1. Try Backend Auth API first (uses bcrypt, normalized email, Supabase sync)
    try:
        from frontend.services.api_client import auth_login
        res = auth_login(identifier, password)
        if "access_token" in res:
            return {
                "access_token": res["access_token"],
                "refresh_token": res["access_token"],
                "user_id": res["user"]["id"],
                "email": res["user"]["email"],
            }
        elif "error" in res:
            return {"error": res["error"]}
    except Exception as exc:
        logger.info(f"Backend auth login request failed: {exc}. Trying Supabase directly.")

    # 2. Try Supabase directly as fallback if configured
    if '@' in identifier and not _missing_config():
        try:
            resp = get_client().auth.sign_in_with_password(
                {'email': identifier, 'password': password}
            )
            if resp.session and resp.user:
                return _session_dict(resp.session, resp.user)
        except Exception as exc:
            return {'error': _humanize(exc)}

    return {'error': 'Incorrect password or account not found'}


def sign_up_with_password(email: str, password: str) -> Dict[str, Any]:
    identifier = (email or "").strip().lower()
    if not identifier:
        return {'error': 'Please enter your email'}
    if not password:
        return {'error': 'Please enter a password'}
    if len(password) < 6:
        return {'error': 'Password must be at least 6 characters'}

    # 1. Try Backend Auth API first (creates bcrypt hash + auto-confirmed Supabase user)
    try:
        from frontend.services.api_client import auth_register
        res = auth_register(identifier, password)
        if "access_token" in res:
            return {
                "access_token": res["access_token"],
                "refresh_token": res["access_token"],
                "user_id": res["user"]["id"],
                "email": res["user"]["email"],
            }
        elif "error" in res:
            return {"error": res["error"]}
    except Exception as exc:
        logger.info(f"Backend auth register request failed: {exc}. Trying Supabase directly.")

    # 2. Try Supabase directly as fallback
    if '@' in identifier and not _missing_config():
        try:
            resp = get_client().auth.sign_up({'email': identifier, 'password': password})
            if resp.session and resp.user:
                return _session_dict(resp.session, resp.user)
            elif resp.user:
                return {'error': 'Please check your email to confirm your account before logging in.'}
        except Exception as exc:
            return {'error': _humanize(exc)}

    return {'error': 'Registration failed. Please try again.'}



def google_oauth_url() -> Dict[str, Any]:
    err = _missing_config()
    if err:
        return {'error': err}
    try:
        resp = get_client().auth.sign_in_with_oauth({
            'provider': 'google',
            'options': {'redirect_to': OAUTH_REDIRECT_URL},
        })
        return {'url': resp.url}
    except Exception as exc:
        logger.warning(f'oauth url generation failed: {exc}')
        return {'error': _humanize(exc)}


def exchange_code_for_session(auth_code: str) -> Dict[str, Any]:
    """Called once after the OAuth provider redirects back with `?code=...`."""
    err = _missing_config()
    if err:
        return {'error': err}
    client = get_client()
    try:
        storage_key = f'{client.auth._storage_key}-code-verifier'
        code_verifier = client.auth._storage.get_item(storage_key) or ''
        resp = client.auth.exchange_code_for_session({
            'auth_code': auth_code,
            'code_verifier': code_verifier,
            'redirect_to': OAUTH_REDIRECT_URL,
        })
        if not resp.session or not resp.user:
            return {'error': 'OAuth exchange returned no session'}
        return _session_dict(resp.session, resp.user)
    except Exception as exc:
        logger.warning(f'exchange_code_for_session failed: {exc}')
        return {'error': _humanize(exc)}


def sign_out() -> None:
    if _missing_config():
        return
    try:
        get_client().auth.sign_out()
    except Exception as exc:
        logger.warning(f'sign_out failed: {exc}')


def _humanize(exc: Exception) -> str:
    msg = str(exc)
    # supabase errors arrive as "<status>: {json blob}" — surface the human bit
    if 'invalid_grant' in msg.lower() or 'invalid login' in msg.lower():
        return 'Wrong email or password'
    if 'user already registered' in msg.lower() or 'already been registered' in msg.lower():
        return 'An account with this email already exists — try signing in'
    if 'password should be at least' in msg.lower():
        return 'Password too short (Supabase default is 6 characters)'
    return msg
