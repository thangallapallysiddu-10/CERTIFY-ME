# scripts/add_qr_code_column.py
# Run this ONCE to add the qr_code column to the existing certificates table.
# Usage: python scripts/add_qr_code_column.py

import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "certifyme.db")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Check if column already exists
cur.execute("PRAGMA table_info(certificates)")
columns = [row[1] for row in cur.fetchall()]

if "qr_code" not in columns:
    cur.execute("ALTER TABLE certificates ADD COLUMN qr_code TEXT")
    conn.commit()
    print("[OK] Added 'qr_code' column to certificates table.")
else:
    print("[INFO] Column 'qr_code' already exists. Nothing to do.")

conn.close()
