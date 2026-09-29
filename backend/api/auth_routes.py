import logging
from typing import Any, Dict
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.api.auth import create_access_token, get_current_user_payload
from backend.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from backend.database.user_db import (
    create_user,
    get_user_by_email,
    get_user_by_id,
    normalize_email,
    verify_password,
    hash_password,
)

logger = logging.getLogger('ats_resume_scorer')

auth_router = APIRouter(prefix='/api/v1/auth', tags=['Authentication'])


class AuthCredentials(BaseModel):
    email: str
    password: str


class AuthUserResponse(BaseModel):
    id: str
    email: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: AuthUserResponse


@auth_router.post('/register', response_model=AuthResponse)
async def register(creds: AuthCredentials):
    clean_email = normalize_email(creds.email)
    if not clean_email or "@" not in clean_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid email address.",
        )
    if not creds.password or len(creds.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters long.",
        )

    existing = get_user_by_email(clean_email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists. Please log in.",
        )

    try:
        new_user = create_user(clean_email, creds.password)
    except Exception as exc:
        logger.error(f"Failed to create user {clean_email}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {exc}",
        )

    token = create_access_token(new_user["id"], clean_email)
    return AuthResponse(
        access_token=token,
        token_type="bearer",
        user=AuthUserResponse(id=new_user["id"], email=clean_email),
    )


@auth_router.post('/login', response_model=AuthResponse)
async def login(creds: AuthCredentials):
    clean_email = normalize_email(creds.email)
    if not clean_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide an email address.",
        )
    if not creds.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please enter your password.",
        )

    user = get_user_by_email(clean_email)

    # 1. If user exists in local database, verify password with bcrypt
    if user:
        is_valid = verify_password(creds.password, user["password_hash"])
        if not is_valid:
            # Check if Supabase has an updated password
            sb_valid = False
            sb_token = None
            if SUPABASE_URL and SUPABASE_ANON_KEY:
                try:
                    from supabase import create_client
                    sb = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
                    resp = sb.auth.sign_in_with_password({"email": clean_email, "password": creds.password})
                    if resp.session and resp.user:
                        sb_valid = True
                        sb_token = resp.session.access_token
                except Exception:
                    pass

            if not sb_valid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password",
                )

        token = create_access_token(user["id"], clean_email)
        return AuthResponse(
            access_token=token,
            token_type="bearer",
            user=AuthUserResponse(id=user["id"], email=clean_email),
        )

    # 2. If user is not yet in local database, check Supabase
    if SUPABASE_URL and SUPABASE_ANON_KEY:
        try:
            from supabase import create_client
            sb = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
            resp = sb.auth.sign_in_with_password({"email": clean_email, "password": creds.password})
            if resp.session and resp.user:
                # Sync into local DB
                new_user = create_user(clean_email, creds.password, custom_id=resp.user.id)
                return AuthResponse(
                    access_token=resp.session.access_token,
                    token_type="bearer",
                    user=AuthUserResponse(id=resp.user.id, email=clean_email),
                )
        except Exception as exc:
            err_msg = str(exc).lower()
            if "invalid login credentials" in err_msg or "invalid grant" in err_msg:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password",
                )
            logger.info(f"Supabase auth error for {clean_email}: {exc}")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect password or user does not exist",
    )


@auth_router.get('/me', response_model=AuthUserResponse)
async def get_me(payload: dict = Depends(get_current_user_payload)):
    user_id = payload.get("sub")
    email = payload.get("email") or ""
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    return AuthUserResponse(id=user_id, email=email)


@auth_router.post('/logout')
async def logout():
    return {"message": "Successfully logged out"}
