"""
ShadowHack - Local Development Runner
======================================
Forces SQLite (local file) before python-dotenv can load the remote
DATABASE_URL from .env, so the server runs fully offline without needing
a Supabase / PostgreSQL connection.

Usage:
    python run_dev.py
"""

import os
import sys

# ── Force SQLite BEFORE dotenv or any Flask code runs ────────────────────────
# Setting DATABASE_URL to an empty string here means load_dotenv() (called
# inside main.py) will NOT override it (override=False is the default).
os.environ["DATABASE_URL"] = ""

# Ensure development mode so CORS is wide open and debug is on
os.environ.setdefault("FLASK_ENV", "development")
os.environ.setdefault("FLASK_DEBUG", "true")
os.environ.setdefault("PLATFORM_ACCESS_CODE", "shadowhackmz.mrx")
os.environ.setdefault("RATELIMIT_STORAGE_URI", "memory://")
os.environ.setdefault("SQL_DEBUG", "false")

# ── Now import the application factory (dotenv runs inside) ──────────────────
from main import create_app, init_database, socketio  # noqa: E402

# ── Boot ─────────────────────────────────────────────────────────────────────
app = create_app()
init_database(app)

port = int(os.environ.get("PORT", 5000))
debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"

print("")
print("╔══════════════════════════════════════════════════╗")
print("║        SHADOWHACK  —  LOCAL DEV SERVER           ║")
print("╠══════════════════════════════════════════════════╣")
print(f"║  API  :  http://localhost:{port:<23}║")
print("║  DB   :  SQLite  (backend/studyhub.db)           ║")
print("║  Mode :  development  (CORS open)                ║")
print("╚══════════════════════════════════════════════════╝")
print("")

socketio.run(
    app,
    host="0.0.0.0",
    port=port,
    debug=debug,
    use_reloader=False,  # reloader conflicts with gevent
    log_output=True,
)
