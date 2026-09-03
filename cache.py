import json
import os
import random
import sqlite3
import threading
import time
from typing import Any

DEFAULT_DB = os.path.join(os.path.dirname(__file__), "safebrowsing_cache.db")


class SafeBrowsingCache:
    """Persistent SQLite cache for Safe Browsing results."""

    def __init__(self, db_path: str = DEFAULT_DB, prune_chance: float = 0.15):
        self.db_path = db_path
        self._init_db()
        if random.random() < prune_chance:
            threading.Thread(target=self._prune_stale, daemon=True).start()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS url_cache (
                    cache_key TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    flagged INTEGER NOT NULL,
                    threats TEXT NOT NULL,
                    cached_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cache_expires "
                "ON url_cache(expires_at)"
            )
            conn.commit()

    def _prune_stale(self):
        now = int(time.time())
        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                conn.execute(
                    "DELETE FROM url_cache WHERE expires_at <= ?", (now,)
                )
                conn.commit()
        except sqlite3.OperationalError:
            pass

    def get(self, cache_key: str) -> dict[str, Any] | None:
        now = int(time.time())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT flagged, threats FROM url_cache "
                "WHERE cache_key = ? AND expires_at > ?",
                (cache_key, now)
            )
            row = cursor.fetchone()
            if row:
                return {
                    "flagged": bool(row[0]),
                    "threats": json.loads(row[1]),
                    "from_cache": True
                }
        return None

    def set(
        self,
        cache_key: str,
        original_url: str,
        flagged: bool,
        threats: list,
        ttl_seconds: int = 900,
    ):
        now = int(time.time())
        expires_at = now + ttl_seconds
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO url_cache (
                    cache_key, url, flagged, threats, cached_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                cache_key, original_url, int(flagged), json.dumps(threats),
                now,
                expires_at,
            ))
            conn.commit()
