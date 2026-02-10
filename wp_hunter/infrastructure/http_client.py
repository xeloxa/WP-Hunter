"""
HTTP Client Infrastructure
"""

import requests
from requests.adapters import HTTPAdapter
from typing import Optional
import threading

from wp_hunter.config import MAX_POOL_SIZE

_session_lock = threading.Lock()
_session: Optional[requests.Session] = None


def get_session(pool_size: int = 100) -> requests.Session:
    """
    Get or create the global requests session with optimized pooling.

    Thread-safe implementation with connection pool size limit.
    """
    global _session
    with _session_lock:
        if _session is None:
            # Apply security limit to pool size
            safe_pool_size = min(pool_size, MAX_POOL_SIZE)
            _session = requests.Session()
            adapter = HTTPAdapter(
                pool_connections=safe_pool_size,
                pool_maxsize=safe_pool_size,
                max_retries=3,
            )
            _session.mount("https://", adapter)
            _session.mount("http://", adapter)
        return _session


def close_session():
    """Close the global session (thread-safe)."""
    global _session
    with _session_lock:
        if _session:
            _session.close()
            _session = None
