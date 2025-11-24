# seed_student.py
import sqlite3, os
from werkzeug.security import generate_password_hash

DB = os.path.join(os.path.dirname(__file__), "certifyme.db")
conn = sqlite3.connect(DB)
cur = conn.cursor()

pw = generate_password_hash("studentpass123")
try:
    cur.execute("INSERT INTO students (name, email, password_hash) VALUES (?, ?, ?)",
                ("Demo Student", "student@example.com", pw))
    conn.commit()
    print("Inserted test student: student@example.com / studentpass123")
except sqlite3.IntegrityError:
    print("Student already exists or email duplicate.")
finally:
    conn.close()
