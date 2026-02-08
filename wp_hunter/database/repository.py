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
                    is_risky_category, is_user_facing, risk_tags, security_flags,
                    feature_flags, download_link, code_analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ','.join(result.risk_tags),
                ','.join(result.security_flags),
                ','.join(result.feature_flags),
                result.download_link,
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
            
            # Validate sort column
            valid_columns = {"score", "installations", "days_since_update", "name", "slug"}
            if sort_by not in valid_columns:
                sort_by = "score"
            
            order = "DESC" if sort_order.lower() == "desc" else "ASC"
            
            cursor.execute(f"""
                SELECT * FROM scan_results 
                WHERE session_id = ?
                ORDER BY {sort_by} {order}
                LIMIT ?
            """, (session_id, limit))
            
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
                    "risk_tags": row["risk_tags"].split(',') if row["risk_tags"] else [],
                    "security_flags": row["security_flags"].split(',') if row["security_flags"] else [],
                    "feature_flags": row["feature_flags"].split(',') if row["feature_flags"] else [],
                    "download_link": row["download_link"],
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
