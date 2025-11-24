# seed_admin.py
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("certifyme.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
""")

pw = generate_password_hash("adminpass123")

try:
    cur.execute("INSERT INTO admins (name,email,password_hash) VALUES (?,?,?)",
                ("Super Admin", "admin@example.com", pw))
    conn.commit()
    print("✅ Seeded admin: admin@example.com / adminpass123")
except Exception as e:
    print("⚠️ Already exists or error:", e)

conn.close()
