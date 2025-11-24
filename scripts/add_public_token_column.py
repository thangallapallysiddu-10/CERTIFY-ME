# scripts/add_public_token_column.py
import sqlite3, os, secrets

DB = os.path.join(os.path.dirname(__file__), "..", "certifyme.db")
DB = os.path.abspath(DB)

conn = sqlite3.connect(DB)
cur = conn.cursor()

cols = [r[1] for r in cur.execute("PRAGMA table_info(certificates)").fetchall()]
print("Existing columns:", cols)
if "public_token" not in cols:
    print("Adding column public_token")
    cur.execute("ALTER TABLE certificates ADD COLUMN public_token TEXT")
    conn.commit()
else:
    print("public_token already present")

conn.close()
print("Done.")
