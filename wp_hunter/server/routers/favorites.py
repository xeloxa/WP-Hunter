"""
Favorites Router
"""

from fastapi import APIRouter
from wp_hunter.database.repository import ScanRepository

router = APIRouter(prefix="/api/favorites", tags=["favorites"])
repo = ScanRepository()


@router.get("")
async def list_favorites():
    return {"favorites": repo.get_favorites()}


@router.post("")
async def add_favorite(plugin: dict):
    success = repo.add_favorite(plugin)
    return {"success": success}


@router.delete("/{slug}")
async def remove_favorite(slug: str):
    success = repo.remove_favorite(slug)
    return {"success": success}
