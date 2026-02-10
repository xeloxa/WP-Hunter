"""
Rate Limiter Configuration

Centralized rate limiting to avoid circular imports.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Security: Rate limiting setup - defined here to avoid circular imports
limiter = Limiter(key_func=get_remote_address)
