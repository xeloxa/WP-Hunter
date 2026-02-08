"""
WP-Hunter Database Models

SQLite database schema and connection handling.
"""

import sqlite3
import os
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

# Default database location
DEFAULT_DB_PATH = Path.home() / ".wp-hunter" / "wp_hunter.db"


def ensure_db_dir():
    """Ensure the database directory exists."""
    DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_db_path() -> Path:
    """Get the database path, respecting environment variable if set."""
    env_path = os.environ.get("WP_HUNTER_DB")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB_PATH


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize the database with required tables."""
    if db_path is None:
        ensure_db_dir()
        db_path = get_db_path()
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Create scan_sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            config_json TEXT,
            total_found INTEGER DEFAULT 0,
            high_risk_count INTEGER DEFAULT 0,
            error_message TEXT
        )
    """)
    
    # Create scan_results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            slug TEXT NOT NULL,
            name TEXT,
            version TEXT,
            score INTEGER DEFAULT 0,
            installations INTEGER DEFAULT 0,
            days_since_update INTEGER DEFAULT 0,
            tested_wp_version TEXT,
            author_trusted INTEGER DEFAULT 0,
            is_risky_category INTEGER DEFAULT 0,
            is_user_facing INTEGER DEFAULT 0,
            risk_tags TEXT,
            security_flags TEXT,
            feature_flags TEXT,
            download_link TEXT,
            code_analysis_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
        )
    """)
    
    # Create index for faster lookups
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_results_session 
        ON scan_results(session_id)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_results_score 
        ON scan_results(score DESC)
    """)
    
    conn.commit()
    conn.close()


@contextmanager
def get_db(db_path: Optional[Path] = None):
    """Get a database connection as a context manager."""
    if db_path is None:
        db_path = get_db_path()
    
    # Initialize if needed
    if not db_path.exists():
        init_db(db_path)
    
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
