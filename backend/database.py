"""TriageOne — SQLite database for history & cache."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from backend.config import settings

DB_PATH = Path(settings.database_path)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS triage_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                risk_score REAL,
                verdict TEXT,
                provider_results TEXT,
                details TEXT,
                queried_at REAL NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_triage_ioc ON triage_history(ioc_value);
            CREATE INDEX IF NOT EXISTS idx_triage_time ON triage_history(queried_at DESC);

            CREATE TABLE IF NOT EXISTS advisory_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                link TEXT,
                severity TEXT,
                sectors TEXT,
                countries TEXT,
                published_at REAL,
                fetched_at REAL NOT NULL,
                raw_data TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_advisory_time ON advisory_cache(published_at DESC);
        """)


def save_triage_result(ioc_value, ioc_type, risk_score, verdict, provider_results, details=None) -> int:
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO triage_history
               (ioc_value, ioc_type, risk_score, verdict, provider_results, details, queried_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ioc_value, ioc_type, risk_score, verdict,
             json.dumps(provider_results), json.dumps(details or {}), time.time()),
        )
        return cur.lastrowid


def get_triage_history(limit=100, offset=0):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM triage_history ORDER BY queried_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def get_history_stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM triage_history").fetchone()[0]
        by_verdict = conn.execute(
            "SELECT verdict, COUNT(*) as cnt FROM triage_history GROUP BY verdict"
        ).fetchall()
        by_type = conn.execute(
            "SELECT ioc_type, COUNT(*) as cnt FROM triage_history GROUP BY ioc_type"
        ).fetchall()
    return {
        "total": total,
        "by_verdict": {r["verdict"]: r["cnt"] for r in by_verdict},
        "by_type": {r["ioc_type"]: r["cnt"] for r in by_type},
    }


def save_advisories(advisories):
    saved = 0
    with get_db() as conn:
        for adv in advisories:
            try:
                conn.execute(
                    """INSERT INTO advisory_cache
                       (source, title, description, link, severity, sectors, countries, published_at, fetched_at, raw_data)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (adv.get("source", ""), adv.get("title", ""), adv.get("description", ""),
                     adv.get("link", ""), adv.get("severity", "medium"),
                     json.dumps(adv.get("sectors", [])), json.dumps(adv.get("countries", [])),
                     adv.get("published_at", time.time()), time.time(),
                     json.dumps(adv.get("raw", {}))),
                )
                saved += 1
            except Exception:
                continue
    return saved


def get_cached_advisories(limit=200):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM advisory_cache ORDER BY published_at DESC LIMIT ?", (limit,)
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["sectors"] = json.loads(d.get("sectors") or "[]")
        d["countries"] = json.loads(d.get("countries") or "[]")
        results.append(d)
    return results


init_db()
