"""
WebSocket Connection Manager
"""

import asyncio
from typing import Dict, List
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, session_id: int):
        await websocket.accept()
        async with self.lock:
            if session_id not in self.active_connections:
                self.active_connections[session_id] = []
            self.active_connections[session_id].append(websocket)

    async def disconnect(self, websocket: WebSocket, session_id: int):
        async with self.lock:
            if session_id in self.active_connections:
                if websocket in self.active_connections[session_id]:
                    self.active_connections[session_id].remove(websocket)
                if not self.active_connections[session_id]:
                    del self.active_connections[session_id]

    async def send_to_session(self, session_id: int, message: dict):
        # Create a copy of connections to iterate over safely without holding lock during send
        connections_to_send = []
        async with self.lock:
            if session_id in self.active_connections:
                connections_to_send = list(self.active_connections[session_id])

        for connection in connections_to_send:
            try:
                await connection.send_json(message)
            except Exception:
                # If sending fails, we might want to cleanup, but for now just ignore
                pass


manager = ConnectionManager()
