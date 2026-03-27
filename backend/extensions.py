import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Use Redis in production (set RATELIMIT_STORAGE_URI=redis://localhost:6379/0)
# Falls back to in-memory storage for development
_storage_uri = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

# Initialize Limiter with key function (remote address)
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_storage_uri,
    default_limits=["200 per day", "50 per hour"],
)
