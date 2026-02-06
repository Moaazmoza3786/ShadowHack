from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Limiter with key function (remote address)
# default_limits can be set here or in config
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://", # Use Redis in production
    default_limits=["200 per day", "50 per hour"]
)
