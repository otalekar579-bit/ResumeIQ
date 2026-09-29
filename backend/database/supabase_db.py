import logging
import httpx
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict

logger = logging.getLogger('ats_resume_scorer')

from backend.core.config import SUPABASE_URL, SUPABASE_KEY

def _get_headers():
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

from pathlib import Path
import uuid

_LOCAL_HISTORY_PATH = Path(__file__).resolve().parents[2] / 'data' / 'local_history.json'


def _load_local_history() -> List[Dict]:
    try:
        if _LOCAL_HISTORY_PATH.exists():
            with open(_LOCAL_HISTORY_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as exc:
        logger.warning(f"Failed to read local history: {exc}")
    return []


def _save_local_history(items: List[Dict]) -> None:
    try:
        _LOCAL_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_LOCAL_HISTORY_PATH, 'w', encoding='utf-8') as f:
            json.dump(items, f, indent=2)
    except Exception as exc:
        logger.error(f"Failed to write local history: {exc}")


async def save_analysis(user_id: str, filename: str, analysis_result: Dict) -> Optional[str]:
    def _json_default(o):
        if hasattr(o, 'model_dump'):
            return o.model_dump()
        return str(o)
    serializable_result = json.loads(json.dumps(analysis_result, default=_json_default))

    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "filename": filename,
        "ats_score": serializable_result.get("ats_score", 0),
        "keyword_match": serializable_result.get("keyword_match", 0),
        "missing_keywords": serializable_result.get("missing_keywords", []),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "analysis_result": serializable_result,
    }

    # 1. Try saving to Supabase if configured
    headers = _get_headers()
    if headers and SUPABASE_URL:
        url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/analyses"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, headers=headers, json=doc)
                if response.status_code in (200, 201):
                    data = response.json()
                    if data and len(data) > 0:
                        inserted_id = str(data[0].get("id"))
                        logger.info(f"Saved analysis to Supabase: {inserted_id}")
                        return inserted_id
        except Exception as exc:
            logger.info(f"Supabase save skipped ({exc}); saving locally.")

    # 2. Local fallback save
    items = _load_local_history()
    items.insert(0, doc)
    _save_local_history(items)
    logger.info(f"Saved analysis locally for user {user_id}: {doc['id']}")
    return doc["id"]


async def get_user_history(user_id: str) -> List[Dict]:
    headers = _get_headers()
    if headers and SUPABASE_URL:
        url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/analyses"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url, 
                    headers=headers, 
                    params={
                        "user_id": f"eq.{user_id}",
                        "order": "created_at.desc"
                    }
                )
                if response.status_code == 200:
                    docs = response.json()
                    if docs:
                        results = []
                        for doc in docs:
                            results.append({
                                "id": str(doc.get("id")),
                                "filename": doc.get("filename", "resume"),
                                "resume_name": doc.get("filename", "resume"),
                                "job_title": "Software Engineer",
                                "ats_score": doc.get("ats_score", 0),
                                "keyword_match": doc.get("keyword_match", 0),
                                "missing_keywords": doc.get("missing_keywords", []),
                                "date": doc.get("created_at", ""),
                                "created_at": doc.get("created_at", ""),
                                "analysis_result": doc.get("analysis_result", {}),
                            })
                        return results
        except Exception as exc:
            logger.info(f"Supabase history query skipped ({exc}); reading local history.")

    # Fallback: Read local history for this user
    local_items = _load_local_history()
    user_items = [d for d in local_items if d.get("user_id") == user_id]
    results = []
    for doc in user_items:
        results.append({
            "id": str(doc.get("id")),
            "filename": doc.get("filename", "resume"),
            "resume_name": doc.get("filename", "resume"),
            "job_title": "Software Engineer",
            "ats_score": doc.get("ats_score", 0),
            "keyword_match": doc.get("keyword_match", 0),
            "missing_keywords": doc.get("missing_keywords", []),
            "date": doc.get("created_at", ""),
            "created_at": doc.get("created_at", ""),
            "analysis_result": doc.get("analysis_result", {}),
        })
    return results


async def delete_analysis(analysis_id: str, user_id: str) -> bool:
    headers = _get_headers()
    if headers and SUPABASE_URL:
        url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/analyses"
        try:
            async with httpx.AsyncClient() as client:
                await client.delete(
                    url, 
                    headers=headers, 
                    params={
                        "id": f"eq.{analysis_id}",
                        "user_id": f"eq.{user_id}"
                    }
                )
        except Exception:
            pass

    # Also delete locally if present
    items = _load_local_history()
    new_items = [d for d in items if not (str(d.get("id")) == str(analysis_id) and d.get("user_id") == user_id)]
    _save_local_history(new_items)
    return True
