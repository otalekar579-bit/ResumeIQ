import os
from typing import Any, Dict, List

import requests
import streamlit as st


DEFAULT_BACKEND_URL = "http://localhost:8000"


def _backend_url() -> str:
    env_url = os.getenv("BACKEND_URL")
    if env_url:
        return env_url.rstrip("/")
    try:
        return st.secrets["backend"]["url"].rstrip("/")
    except (KeyError, FileNotFoundError, AttributeError):
        return DEFAULT_BACKEND_URL


def _auth_headers(access_token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def auth_register(email: str, password: str) -> Dict[str, Any]:
    url = f"{_backend_url()}/api/v1/auth/register"
    response = requests.post(url, json={"email": email, "password": password}, timeout=15)
    if response.status_code != 200:
        try:
            detail = response.json().get("detail", response.text)
        except Exception:
            detail = response.text
        return {"error": detail}
    return response.json()


def auth_login(email: str, password: str) -> Dict[str, Any]:
    url = f"{_backend_url()}/api/v1/auth/login"
    response = requests.post(url, json={"email": email, "password": password}, timeout=15)
    if response.status_code != 200:
        try:
            detail = response.json().get("detail", response.text)
        except Exception:
            detail = response.text
        return {"error": detail}
    return response.json()


def auth_me(access_token: str) -> Dict[str, Any]:
    url = f"{_backend_url()}/api/v1/auth/me"
    response = requests.get(url, headers=_auth_headers(access_token), timeout=10)
    response.raise_for_status()
    return response.json()


def auth_logout() -> Dict[str, Any]:
    url = f"{_backend_url()}/api/v1/auth/logout"
    try:
        response = requests.post(url, timeout=5)
        return response.json()
    except Exception:
        return {"message": "Logged out"}


def health_check() -> Dict[str, Any]:
    response = requests.get(f"{_backend_url()}/api/v1/health", timeout=10)
    response.raise_for_status()
    return response.json()



def analyze_resume(
    resume_file,
    access_token: str,
    job_description: str = "",
) -> Dict[str, Any]:
    files = {
        "resume": (resume_file.name, resume_file.getvalue(), resume_file.type),
    }
    data = {"job_description": job_description}
    response = requests.post(
        f"{_backend_url()}/api/v1/analyze-resume",
        files=files,
        data=data,
        headers=_auth_headers(access_token),
        timeout=180,
    )
    response.raise_for_status()
    return response.json()


def get_history(access_token: str) -> List[Dict[str, Any]]:
    response = requests.get(
        f"{_backend_url()}/api/v1/history",
        headers=_auth_headers(access_token),
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def delete_history_entry(analysis_id: str, access_token: str) -> None:
    response = requests.delete(
        f"{_backend_url()}/api/v1/history/{analysis_id}",
        headers=_auth_headers(access_token),
        timeout=30,
    )
    response.raise_for_status()


def generate_pdf(analysis_data: Dict[str, Any], access_token: str) -> bytes:
    response = requests.post(
        f"{_backend_url()}/api/v1/generate-pdf",
        json=analysis_data,
        headers=_auth_headers(access_token),
        timeout=60,
    )
    response.raise_for_status()
    return response.content


def get_history_pdf(analysis_id: str, access_token: str) -> bytes:
    response = requests.get(
        f"{_backend_url()}/api/v1/history/{analysis_id}/pdf",
        headers=_auth_headers(access_token),
        timeout=60,
    )
    response.raise_for_status()
    return response.content
