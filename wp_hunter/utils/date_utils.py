"""
Date Utilities
"""

from datetime import datetime
from typing import Optional


def calculate_days_ago(date_str: Optional[str]) -> int:
    """Calculates number of days since the given date string."""
    if not date_str:
        return 9999
    try:
        date_obj = datetime.strptime(date_str.split(" ")[0], "%Y-%m-%d")
        delta = datetime.now() - date_obj
        return delta.days
    except ValueError:
        return 9999
