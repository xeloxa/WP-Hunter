"""
Config Router
"""

from fastapi import APIRouter
from wp_hunter.models import ScanConfig

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("")
async def get_default_config():
    """Get default scan configuration."""
    config = ScanConfig()
    return config.to_dict()
