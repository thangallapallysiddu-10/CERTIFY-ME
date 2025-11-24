# scripts/backfill_public_tokens.py
import sqlite3, os, secrets

BASE = os.path.dirname(os.path.dirname(__file__))
DB = os.path.join(BASE, "certifyme.db")

conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

rows = cur.execute("SELECT id, public_token FROM certificates").fetchall()
print("Found", len(rows), "certs")

count = 0
for r in rows:
    if r["public_token"]:
        continue
    token = secrets.token_urlsafe(24)  # ~32 chars, URL-safe
    cur.execute("UPDATE certificates SET public_token = ? WHERE id = ?", (token, r["id"]))
    count += 1

conn.commit()
conn.close()
print("Backfilled", count, "tokens")
