import sqlite3
import os

db_path = 'backend/debug.db'
schema_path = 'backend/database-schema.sql'

if os.path.exists(db_path):
    os.remove(db_path)

conn = sqlite3.connect(db_path)
with open(schema_path, 'r', encoding='utf-8') as f:
    schema = f.read()

# Split by semicolon but be careful with triggers/etc if any
# Actually just try executing the whole thing but catch specific sqlite3 errors
try:
    conn.executescript(schema)
    print("SUCCESS: Schema executed perfectly.")
except sqlite3.Error as e:
    print(f"FAILED: {e}")
finally:
    conn.close()
