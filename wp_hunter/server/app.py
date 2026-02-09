"""
WP-Hunter FastAPI Application

REST API and WebSocket endpoints for the web dashboard.
"""

import asyncio
import json
import re
import subprocess
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from wp_hunter.models import ScanConfig, ScanStatus, PluginResult
from wp_hunter.database.repository import ScanRepository
from wp_hunter.scanners.plugin_scanner import PluginScanner
from wp_hunter.scanners.theme_scanner import ThemeScanner
from wp_hunter.scanners.semgrep_scanner import SemgrepScanner, SEMGREP_REGISTRY_RULESETS, SEMGREP_COMMUNITY_SOURCES
from wp_hunter.downloaders.plugin_downloader import PluginDownloader


# Pydantic models for API
class ScanRequest(BaseModel):
    pages: int = 5
    limit: int = 0
    min_installs: int = 1000
    max_installs: int = 0
    sort: str = "updated"
    smart: bool = False
    abandoned: bool = False
    user_facing: bool = False
    themes: bool = False
    min_days: int = 0
    max_days: int = 0
    deep_analysis: bool = False
    download: int = 0
    auto_download_risky: int = 0
    output: Optional[str] = None
    format: str = "json"


class DownloadRequest(BaseModel):
    slug: str
    download_url: str


class SemgrepRuleRequest(BaseModel):
    id: str
    pattern: str
    message: str
    severity: str = "WARNING"
    languages: List[str] = ["php"]


# Connection manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, session_id: int):
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
        self.active_connections[session_id].append(websocket)
    
    def disconnect(self, websocket: WebSocket, session_id: int):
        if session_id in self.active_connections:
            if websocket in self.active_connections[session_id]:
                self.active_connections[session_id].remove(websocket)
    
    async def send_to_session(self, session_id: int, message: dict):
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass


manager = ConnectionManager()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    app = FastAPI(
        title="WP-Hunter Dashboard",
        description="WordPress Plugin & Theme Security Scanner",
        version="2.0.0"
    )
    
    # Repository instance
    repo = ScanRepository()
    
    # Track active scans
    active_scans: Dict[int, PluginScanner] = {}
    
    # Static files directory
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    assets_dir = static_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
    
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Serve the main dashboard."""
        index_path = static_dir / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        return HTMLResponse("<h1>WP-Hunter Dashboard</h1><p>Static files not found.</p>")
    
    @app.get("/api/config")
    async def get_default_config():
        """Get default scan configuration."""
        config = ScanConfig()
        return config.to_dict()
    
    @app.get("/api/scans")
    async def list_scans(limit: int = 50):
        """List all scan sessions."""
        sessions = repo.get_all_sessions(limit)
        return {"sessions": sessions}
    
    @app.post("/api/scans")
    async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
        """Create and start a new scan."""
        # Convert request to ScanConfig
        config = ScanConfig(
            pages=request.pages,
            limit=request.limit,
            min_installs=request.min_installs,
            max_installs=request.max_installs,
            sort=request.sort,
            smart=request.smart,
            abandoned=request.abandoned,
            user_facing=request.user_facing,
            themes=request.themes,
            min_days=request.min_days,
            max_days=request.max_days,
            deep_analysis=request.deep_analysis,
            download=request.download,
            auto_download_risky=request.auto_download_risky,
            output=request.output,
            format=request.format
        )
        
        # Create session in database
        session_id = repo.create_session(config)
        
        # Start scan in background
        background_tasks.add_task(run_scan_task, session_id, config, repo)
        
        return {
            "session_id": session_id,
            "status": "started",
            "websocket_url": f"/ws/scans/{session_id}"
        }
    
    @app.get("/api/scans/{session_id}")
    async def get_scan(session_id: int):
        """Get scan session details."""
        session = repo.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Scan session not found")
        return session
    
    @app.get("/api/scans/{session_id}/results")
    async def get_scan_results(
        session_id: int,
        sort_by: str = "score",
        sort_order: str = "desc",
        limit: int = 100
    ):
        """Get results for a scan session."""
        session = repo.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Scan session not found")
        
        results = repo.get_session_results(session_id, sort_by, sort_order, limit)
        return {
            "session_id": session_id,
            "total": len(results),
            "results": results
        }
    
    @app.delete("/api/scans/{session_id}")
    async def delete_scan(session_id: int):
        """Delete a scan session."""
        # Stop if running
        if session_id in active_scans:
            active_scans[session_id].stop()
            del active_scans[session_id]
        
        success = repo.delete_session(session_id)
        if not success:
            raise HTTPException(status_code=404, detail="Scan session not found")
        
        return {"status": "deleted"}
    
    @app.post("/api/scans/{session_id}/stop")
    async def stop_scan(session_id: int):
        """Stop a running scan."""
        if session_id not in active_scans:
            raise HTTPException(status_code=404, detail="No active scan found")
        
        active_scans[session_id].stop()
        repo.update_session_status(session_id, ScanStatus.CANCELLED)
        del active_scans[session_id]
        
        return {"status": "stopped"}
    
    @app.post("/api/plugins/download")
    async def download_plugin(request: DownloadRequest):
        """Download a plugin."""
        downloader = PluginDownloader()
        result = downloader.download_and_extract(request.download_url, request.slug, verbose=False)
        
        if result:
            return {
                "status": "success",
                "slug": request.slug,
                "path": str(result)
            }
        else:
            raise HTTPException(status_code=500, detail="Download failed")
    
    @app.get("/api/plugins/downloaded")
    async def list_downloaded_plugins():
        """List downloaded plugins."""
        downloader = PluginDownloader()
        plugins = downloader.get_downloaded_plugins()
        return {"plugins": plugins}
    
    @app.websocket("/ws/scans/{session_id}")
    async def websocket_endpoint(websocket: WebSocket, session_id: int):
        """WebSocket endpoint for real-time scan updates."""
        await manager.connect(websocket, session_id)
        try:
            while True:
                # Keep connection alive, receive any client messages
                data = await websocket.receive_text()
                # Could handle client commands here if needed
        except WebSocketDisconnect:
            manager.disconnect(websocket, session_id)
    
    @app.get("/api/favorites")
    async def list_favorites():
        return {"favorites": repo.get_favorites()}

    @app.post("/api/favorites")
    async def add_favorite(plugin: dict):
        success = repo.add_favorite(plugin)
        return {"success": success}

    @app.delete("/api/favorites/{slug}")
    async def remove_favorite(slug: str):
        success = repo.remove_favorite(slug)
        return {"success": success}

    # ==========================================
    # SEMGREP RULES API
    # ==========================================

    # Path to custom rules file
    custom_rules_path = Path(__file__).parent.parent / "semgrep_results" / "custom_rules.yaml"
    # Path to disabled configuration file
    disabled_config_path = Path(__file__).parent.parent / "semgrep_results" / "disabled_config.json"

    def get_disabled_config() -> Dict[str, List[str]]:
        """Load disabled rules and rulesets configuration."""
        default_config = {"rules": [], "rulesets": []}
        if disabled_config_path.exists():
            try:
                with open(disabled_config_path, 'r') as f:
                    config = json.load(f)
                    return {
                        "rules": config.get("rules", []),
                        "rulesets": config.get("rulesets", [])
                    }
            except Exception:
                pass
        return default_config

    def save_disabled_config(config: Dict[str, List[str]]):
        """Save disabled configuration."""
        disabled_config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(disabled_config_path, 'w') as f:
            json.dump(config, f)

    @app.get("/api/semgrep/rules")
    async def get_semgrep_rules():
        """Get Semgrep configuration (rulesets and custom rules)."""
        # Check if Semgrep is installed
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            installed = result.returncode == 0
        except Exception:
            installed = False

        disabled_config = get_disabled_config()
        disabled_rules = set(disabled_config["rules"])
        disabled_rulesets = set(disabled_config["rulesets"])

        # 1. Prepare Rulesets List
        rulesets = []
        for key, info in SEMGREP_REGISTRY_RULESETS.items():
            rulesets.append({
                "id": key,
                "name": info.get("description", key), # Use description as name
                "url": info.get("url", "#"),
                "enabled": key not in disabled_rulesets,
                "description": info.get("description", "")
            })

        # 2. Load Custom Rules
        custom_rules = []
        if custom_rules_path.exists():
            try:
                with open(custom_rules_path, 'r') as f:
                    custom_yaml = yaml.safe_load(f)
                    if custom_yaml and 'rules' in custom_yaml:
                        for rule in custom_yaml['rules']:
                            rule_id = rule.get('id', 'unknown')
                            pattern = rule.get('pattern', '')
                            if not pattern and 'patterns' in rule:
                                patterns = rule['patterns']
                                if patterns:
                                    pattern = str(patterns[0]) if isinstance(patterns[0], str) else patterns[0].get('pattern', 'Complex')

                            custom_rules.append({
                                "id": rule_id,
                                "message": rule.get('message', ''),
                                "severity": rule.get('severity', 'WARNING'),
                                "pattern": pattern,
                                "is_custom": True,
                                "enabled": rule_id not in disabled_rules
                            })
            except Exception as e:
                print(f"Error loading custom rules: {e}")

        return {
            "installed": installed,
            "rulesets": rulesets,
            "custom_rules": custom_rules,
            "community_sources": SEMGREP_COMMUNITY_SOURCES
        }

    @app.post("/api/semgrep/rules")
    async def add_semgrep_rule(rule: SemgrepRuleRequest):
        """Add a custom Semgrep rule."""
        # Validate rule ID (alphanumeric, hyphens, underscores only)
        if not re.match(r'^[a-zA-Z0-9_-]+$', rule.id):
            raise HTTPException(status_code=400, detail="Invalid rule ID format")

        # Ensure directory exists
        custom_rules_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing custom rules or create new
        existing_rules = {"rules": []}
        if custom_rules_path.exists():
            try:
                with open(custom_rules_path, 'r') as f:
                    existing_rules = yaml.safe_load(f) or {"rules": []}
            except Exception:
                existing_rules = {"rules": []}

        # Check for duplicate ID
        for existing in existing_rules.get('rules', []):
            if existing.get('id') == rule.id:
                raise HTTPException(status_code=400, detail=f"Rule with ID '{rule.id}' already exists")

        # Add new rule
        new_rule = {
            "id": rule.id,
            "pattern": rule.pattern,
            "message": rule.message,
            "languages": rule.languages,
            "severity": rule.severity
        }
        existing_rules['rules'].append(new_rule)

        # Save to file
        try:
            with open(custom_rules_path, 'w') as f:
                yaml.dump(existing_rules, f, default_flow_style=False, sort_keys=False)
            return {"success": True, "rule_id": rule.id}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save rule: {str(e)}")

    @app.delete("/api/semgrep/rules/{rule_id}")
    async def delete_semgrep_rule(rule_id: str):
        """Delete a custom Semgrep rule."""
        if not custom_rules_path.exists():
            raise HTTPException(status_code=404, detail="No custom rules file found")

        try:
            with open(custom_rules_path, 'r') as f:
                rules_data = yaml.safe_load(f) or {"rules": []}

            # Find and remove the rule
            original_count = len(rules_data.get('rules', []))
            rules_data['rules'] = [r for r in rules_data.get('rules', []) if r.get('id') != rule_id]

            if len(rules_data['rules']) == original_count:
                raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

            # Save updated rules
            with open(custom_rules_path, 'w') as f:
                yaml.dump(rules_data, f, default_flow_style=False, sort_keys=False)

            return {"success": True, "deleted": rule_id}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete rule: {str(e)}")

    @app.post("/api/semgrep/rules/{rule_id}/toggle")
    async def toggle_custom_rule(rule_id: str):
        """Enable or disable a custom Semgrep rule."""
        config = get_disabled_config()

        if rule_id in config["rules"]:
            # Enable
            config["rules"].remove(rule_id)
            save_disabled_config(config)
            return {"success": True, "rule_id": rule_id, "enabled": True}
        else:
            # Disable
            config["rules"].append(rule_id)
            save_disabled_config(config)
            return {"success": True, "rule_id": rule_id, "enabled": False}

    @app.post("/api/semgrep/rulesets/{ruleset_id}/toggle")
    async def toggle_ruleset(ruleset_id: str):
        """Enable or disable a Semgrep ruleset."""
        if ruleset_id not in SEMGREP_REGISTRY_RULESETS:
             raise HTTPException(status_code=404, detail=f"Ruleset '{ruleset_id}' not found")

        config = get_disabled_config()

        if ruleset_id in config["rulesets"]:
            # Enable
            config["rulesets"].remove(ruleset_id)
            save_disabled_config(config)
            return {"success": True, "ruleset_id": ruleset_id, "enabled": True}
        else:
            # Disable
            config["rulesets"].append(ruleset_id)
            save_disabled_config(config)
            return {"success": True, "ruleset_id": ruleset_id, "enabled": False}

    async def run_scan_task(session_id: int, config: ScanConfig, repo: ScanRepository):
        """Background task to run a scan."""
        try:
            repo.update_session_status(session_id, ScanStatus.RUNNING)
            
            # Send start message
            await manager.send_to_session(session_id, {
                "type": "start",
                "session_id": session_id
            })
            
            found_count = 0
            high_risk_count = 0
            
            async def on_result(result: PluginResult):
                nonlocal found_count, high_risk_count
                found_count += 1
                if result.score >= 50:
                    high_risk_count += 1
                
                # Save to database
                repo.save_result(session_id, result)
                
                # Send via WebSocket
                await manager.send_to_session(session_id, {
                    "type": "result",
                    "data": result.to_dict(),
                    "found_count": found_count
                })
            
            async def on_progress(current: int, total: int):
                await manager.send_to_session(session_id, {
                    "type": "progress",
                    "current": current,
                    "total": total,
                    "percent": int((current / total) * 100)
                })
            
            # Create scanner
            scanner = PluginScanner(config)
            active_scans[session_id] = scanner
            
            # Run scan in thread pool to not block
            loop = asyncio.get_event_loop()
            
            def sync_on_result(result: PluginResult):
                nonlocal found_count, high_risk_count
                found_count += 1
                if result.score >= 50:
                    high_risk_count += 1
                repo.save_result(session_id, result)
                # Schedule WebSocket send
                asyncio.run_coroutine_threadsafe(
                    manager.send_to_session(session_id, {
                        "type": "result",
                        "data": result.to_dict(),
                        "found_count": found_count
                    }),
                    loop
                )
            
            def sync_on_progress(current: int, total: int):
                asyncio.run_coroutine_threadsafe(
                    manager.send_to_session(session_id, {
                        "type": "progress",
                        "current": current,
                        "total": total,
                        "percent": int((current / total) * 100)
                    }),
                    loop
                )
            
            scanner.on_result = sync_on_result
            scanner.on_progress = sync_on_progress
            
            # Run in thread
            await loop.run_in_executor(None, scanner.scan)
            
            # Update final status
            repo.update_session_status(
                session_id, 
                ScanStatus.COMPLETED,
                total_found=found_count,
                high_risk_count=high_risk_count
            )
            
            # Check for identical previous scan
            prev_session_id = repo.get_latest_session_by_config(config.to_dict(), session_id)
            if prev_session_id:
                current_slugs = set(repo.get_result_slugs(session_id))
                prev_slugs = set(repo.get_result_slugs(prev_session_id))
                
                if current_slugs == prev_slugs:
                    # Identical results and config. Merge.
                    repo.delete_session(session_id)
                    repo.touch_session(prev_session_id)
                    
                    await manager.send_to_session(session_id, {
                        "type": "deduplicated",
                        "original_session_id": prev_session_id,
                        "message": "Results identical to previous scan. Merged."
                    })
                    return
            
            # Send completion message
            await manager.send_to_session(session_id, {
                "type": "complete",
                "session_id": session_id,
                "total_found": found_count,
                "high_risk_count": high_risk_count
            })
            
        except Exception as e:
            repo.update_session_status(
                session_id,
                ScanStatus.FAILED,
                error_message=str(e)
            )
            await manager.send_to_session(session_id, {
                "type": "error",
                "message": str(e)
            })
        finally:
            if session_id in active_scans:
                del active_scans[session_id]
    
    return app
