"""
WP-Hunter FastAPI Application

REST API and WebSocket endpoints for the web dashboard.
"""

import asyncio
import json
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from wp_hunter.models import ScanConfig, ScanStatus, PluginResult
from wp_hunter.database.repository import ScanRepository
from wp_hunter.scanners.plugin_scanner import PluginScanner
from wp_hunter.scanners.theme_scanner import ThemeScanner
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
