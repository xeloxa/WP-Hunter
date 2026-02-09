"""
WP-Hunter Database Repository

CRUD operations for scan sessions and results.
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from wp_hunter.database.models import get_db, init_db
from wp_hunter.models import ScanSession, ScanConfig, PluginResult, ScanStatus


class ScanRepository:
    """Repository for scan session and result operations."""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path
        init_db(db_path)
        
        # Migration: Add is_duplicate column if missing
        try:
            with get_db(self.db_path) as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT is_duplicate FROM scan_results LIMIT 1")
                except Exception:
                    cursor.execute("ALTER TABLE scan_results ADD COLUMN is_duplicate INTEGER DEFAULT 0")
                    conn.commit()
            
            # Migration: Add link columns if missing
            with get_db(self.db_path) as conn:
                cursor = conn.cursor()
                link_columns = ["cve_search_link", "wpscan_link", "patchstack_link", "wordfence_link", "google_dork_link", "trac_link"]
                for col in link_columns:
                    try:
                        cursor.execute(f"SELECT {col} FROM scan_results LIMIT 1")
                    except Exception:
                        cursor.execute(f"ALTER TABLE scan_results ADD COLUMN {col} TEXT")
                        conn.commit()

            # Migration: Add missing columns to favorite_plugins
            with get_db(self.db_path) as conn:
                cursor = conn.cursor()
                fav_cols = {
                    "author_trusted": "INTEGER DEFAULT 0",
                    "is_risky_category": "INTEGER DEFAULT 0",
                    "is_user_facing": "INTEGER DEFAULT 0",
                    "risk_tags": "TEXT",
                    "security_flags": "TEXT",
                    "feature_flags": "TEXT",
                    "code_analysis_json": "TEXT"
                }
                for col, type_def in fav_cols.items():
                    try:
                        cursor.execute(f"SELECT {col} FROM favorite_plugins LIMIT 1")
                    except Exception:
                        try:
                            cursor.execute(f"ALTER TABLE favorite_plugins ADD COLUMN {col} {type_def}")
                            conn.commit()
                        except Exception: pass

        except Exception as e:
            print(f"Database migration warning: {e}")
    
    def create_session(self, config: ScanConfig) -> int:
        """Create a new scan session and return its ID."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_sessions (config_json, status)
                VALUES (?, ?)
            """, (json.dumps(config.to_dict()), ScanStatus.PENDING.value))
            conn.commit()
            return cursor.lastrowid
    
    def update_session_status(
        self, 
        session_id: int, 
        status: ScanStatus,
        total_found: Optional[int] = None,
        high_risk_count: Optional[int] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Update session status and statistics."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            
            updates = ["status = ?"]
            params = [status.value]
            
            if total_found is not None:
                updates.append("total_found = ?")
                params.append(total_found)
            
            if high_risk_count is not None:
                updates.append("high_risk_count = ?")
                params.append(high_risk_count)
            
            if error_message is not None:
                updates.append("error_message = ?")
                params.append(error_message)
            
            params.append(session_id)
            
            cursor.execute(f"""
                UPDATE scan_sessions 
                SET {', '.join(updates)}
                WHERE id = ?
            """, params)
            conn.commit()
    
    def save_result(self, session_id: int, result: PluginResult) -> int:
        """Save a scan result for a session."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check for duplicates in OTHER sessions
            cursor.execute("""
                SELECT 1 FROM scan_results 
                WHERE slug = ? AND session_id != ? 
                LIMIT 1
            """, (result.slug, session_id))
            
            if cursor.fetchone():
                result.is_duplicate = True
            
            code_analysis_json = None
            if result.code_analysis:
                code_analysis_json = json.dumps({
                    "dangerous_functions": result.code_analysis.dangerous_functions,
                    "ajax_endpoints": result.code_analysis.ajax_endpoints,
                    "file_operations": result.code_analysis.file_operations,
                    "sql_queries": result.code_analysis.sql_queries,
                    "nonce_usage": result.code_analysis.nonce_usage,
                    "sanitization_issues": result.code_analysis.sanitization_issues,
                })
            
            cursor.execute("""
                INSERT INTO scan_results (
                    session_id, slug, name, version, score, installations,
                    days_since_update, tested_wp_version, author_trusted,
                    is_risky_category, is_user_facing, is_duplicate, risk_tags, security_flags,
                    feature_flags, download_link, cve_search_link, wpscan_link, patchstack_link, wordfence_link, google_dork_link, trac_link, code_analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                result.slug,
                result.name,
                result.version,
                result.score,
                result.installations,
                result.days_since_update,
                result.tested_wp_version,
                1 if result.author_trusted else 0,
                1 if result.is_risky_category else 0,
                1 if result.is_user_facing else 0,
                1 if result.is_duplicate else 0,
                ','.join(result.risk_tags),
                ','.join(result.security_flags),
                ','.join(result.feature_flags),
                result.download_link,
                result.cve_search_link,
                result.wpscan_link,
                result.patchstack_link,
                result.wordfence_link,
                result.google_dork_link,
                result.trac_link,
                code_analysis_json
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_session(self, session_id: int) -> Optional[Dict[str, Any]]:
        """Get a scan session by ID."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scan_sessions WHERE id = ?
            """, (session_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            return {
                "id": row["id"],
                "created_at": row["created_at"],
                "status": row["status"],
                "config": json.loads(row["config_json"]) if row["config_json"] else None,
                "total_found": row["total_found"],
                "high_risk_count": row["high_risk_count"],
                "error_message": row["error_message"],
            }
    
    def get_all_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get all scan sessions, most recent first."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scan_sessions 
                ORDER BY created_at DESC 
                LIMIT ?
            """, (limit,))
            
            sessions = []
            for row in cursor.fetchall():
                sessions.append({
                    "id": row["id"],
                    "created_at": row["created_at"],
                    "status": row["status"],
                    "config": json.loads(row["config_json"]) if row["config_json"] else None,
                    "total_found": row["total_found"],
                    "high_risk_count": row["high_risk_count"],
                    "error_message": row["error_message"],
                })
            
            return sessions
    
    # SQL Injection Prevention: Whitelisted column mappings
    _VALID_SORT_COLUMNS = {
        "score": "score",
        "installations": "installations",
        "days_since_update": "days_since_update",
        "name": "name",
        "slug": "slug"
    }
    _VALID_SORT_ORDERS = {"ASC", "DESC"}

    def get_session_results(
        self,
        session_id: int,
        sort_by: str = "score",
        sort_order: str = "desc",
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get results for a scan session."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()

            # SQL Injection Prevention: Use whitelisted column mapping
            safe_sort_column = self._VALID_SORT_COLUMNS.get(sort_by, "score")
            safe_sort_order = "DESC" if sort_order.upper() in self._VALID_SORT_ORDERS and sort_order.upper() == "DESC" else "ASC"

            # Build query using safe, validated values only
            query = f"""
                SELECT * FROM scan_results
                WHERE session_id = ?
                ORDER BY {safe_sort_column} {safe_sort_order}
                LIMIT ?
            """
            cursor.execute(query, (session_id, limit))
            
            results = []
            for row in cursor.fetchall():
                result = {
                    "id": row["id"],
                    "slug": row["slug"],
                    "name": row["name"],
                    "version": row["version"],
                    "score": row["score"],
                    "installations": row["installations"],
                    "days_since_update": row["days_since_update"],
                    "tested_wp_version": row["tested_wp_version"],
                    "author_trusted": bool(row["author_trusted"]),
                    "is_risky_category": bool(row["is_risky_category"]),
                    "is_user_facing": bool(row["is_user_facing"]),
                    "is_duplicate": bool(row["is_duplicate"]) if "is_duplicate" in row.keys() else False,
                    "risk_tags": row["risk_tags"].split(',') if row["risk_tags"] else [],
                    "security_flags": row["security_flags"].split(',') if row["security_flags"] else [],
                    "feature_flags": row["feature_flags"].split(',') if row["feature_flags"] else [],
                    "download_link": row["download_link"],
                    "cve_search_link": row["cve_search_link"],
                    "wpscan_link": row["wpscan_link"],
                    "patchstack_link": row["patchstack_link"],
                    "wordfence_link": row["wordfence_link"],
                    "google_dork_link": row["google_dork_link"],
                    "trac_link": row["trac_link"],
                }
                
                if row["code_analysis_json"]:
                    result["code_analysis"] = json.loads(row["code_analysis_json"])
                
                results.append(result)
            
            return results
    
    def delete_session(self, session_id: int) -> bool:
        """Delete a scan session and its results."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Delete results first (foreign key)
            cursor.execute("DELETE FROM scan_results WHERE session_id = ?", (session_id,))
            
            # Delete session
            cursor.execute("DELETE FROM scan_sessions WHERE id = ?", (session_id,))
            
            conn.commit()
            return cursor.rowcount > 0

    def get_latest_session_by_config(self, config_dict: Dict[str, Any], exclude_id: int) -> Optional[int]:
        """Find the most recent completed session with identical configuration."""
        config_str = json.dumps(config_dict, sort_keys=True)
        
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, config_json FROM scan_sessions 
                WHERE status = 'completed' AND id != ?
                ORDER BY id DESC LIMIT 20
            """, (exclude_id,))
            
            for row in cursor.fetchall():
                try:
                    row_config = json.loads(row["config_json"])
                    if json.dumps(row_config, sort_keys=True) == config_str:
                        return row["id"]
                except Exception:
                    continue
        return None

    def get_result_slugs(self, session_id: int) -> List[str]:
        """Get list of slugs for a session."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT slug FROM scan_results WHERE session_id = ?", (session_id,))
            return [row["slug"] for row in cursor.fetchall()]

    def touch_session(self, session_id: int) -> None:
        """Update session timestamp to now."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE scan_sessions SET created_at = CURRENT_TIMESTAMP WHERE id = ?", (session_id,))
            conn.commit()

    def add_favorite(self, result_dict: Dict[str, Any]) -> bool:
        """Add a plugin to favorites."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Handle list fields for storage
            r_tags = ','.join(result_dict.get('risk_tags', [])) if isinstance(result_dict.get('risk_tags'), list) else result_dict.get('risk_tags', '')
            s_flags = ','.join(result_dict.get('security_flags', [])) if isinstance(result_dict.get('security_flags'), list) else result_dict.get('security_flags', '')
            f_flags = ','.join(result_dict.get('feature_flags', [])) if isinstance(result_dict.get('feature_flags'), list) else result_dict.get('feature_flags', '')
            
            # Handle code analysis
            ca_json = None
            if result_dict.get('code_analysis'):
                ca_json = json.dumps(result_dict.get('code_analysis'))
            
            try:
                cursor.execute("""
                    INSERT INTO favorite_plugins (
                        slug, name, version, score, installations, days_since_update,
                        tested_wp_version, download_link, cve_search_link, wpscan_link,
                        patchstack_link, wordfence_link, google_dork_link, trac_link,
                        author_trusted, is_risky_category, is_user_facing,
                        risk_tags, security_flags, feature_flags, code_analysis_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result_dict.get('slug'), result_dict.get('name'), result_dict.get('version'), result_dict.get('score'),
                    result_dict.get('installations'), result_dict.get('days_since_update'), result_dict.get('tested_wp_version'),
                    result_dict.get('download_link'), result_dict.get('cve_search_link'), result_dict.get('wpscan_link'),
                    result_dict.get('patchstack_link'), result_dict.get('wordfence_link'), result_dict.get('google_dork_link'),
                    result_dict.get('trac_link'),
                    1 if result_dict.get('author_trusted') else 0,
                    1 if result_dict.get('is_risky_category') else 0,
                    1 if result_dict.get('is_user_facing') else 0,
                    r_tags, s_flags, f_flags, ca_json
                ))
                conn.commit()
                return True
            except Exception as e:
                print(f"Error adding favorite: {e}")
                return False

    def remove_favorite(self, slug: str) -> bool:
        """Remove a plugin from favorites."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM favorite_plugins WHERE slug = ?", (slug,))
            conn.commit()
            return cursor.rowcount > 0

    def get_favorites(self) -> List[Dict[str, Any]]:
        """Get all favorite plugins."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM favorite_plugins ORDER BY created_at DESC")
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                # Parse bools
                d['author_trusted'] = bool(d.get('author_trusted', 0))
                d['is_risky_category'] = bool(d.get('is_risky_category', 0))
                d['is_user_facing'] = bool(d.get('is_user_facing', 0))
                
                # Parse lists
                d['risk_tags'] = d['risk_tags'].split(',') if d.get('risk_tags') else []
                d['security_flags'] = d['security_flags'].split(',') if d.get('security_flags') else []
                d['feature_flags'] = d['feature_flags'].split(',') if d.get('feature_flags') else []
                
                # Parse JSON
                if d.get('code_analysis_json'):
                    d['code_analysis'] = json.loads(d['code_analysis_json'])
                
                results.append(d)
            return results
    
    def is_favorite(self, slug: str) -> bool:
        """Check if a plugin is favorited."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM favorite_plugins WHERE slug = ?", (slug,))
            return cursor.fetchone() is not None
