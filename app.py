# app.py
import os
import sqlite3
import hashlib
import hmac
import base64
import string
import random
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, render_template, redirect, url_for,
    flash, session, jsonify, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash

# PIL for image thumbnails
from PIL import Image, ImageDraw

# ----------------- CONFIG -----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "certifyme.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_DIR = os.path.join(STATIC_DIR, "uploads")
QRCODE_DIR = os.path.join(STATIC_DIR, "qrcodes")
THUMB_DIR = os.path.join(UPLOAD_DIR, "thumbs")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QRCODE_DIR, exist_ok=True)
os.makedirs(THUMB_DIR, exist_ok=True)

HMAC_SECRET = os.environ.get("CERTIFYME_HMAC_SECRET", "dev-hmac-secret").encode("utf-8")
FLASK_SECRET = os.environ.get("CERTIFYME_FLASK_SECRET", "dev-flask-secret")
BASE_URL = os.environ.get("CERTIFYME_BASE_URL", "http://127.0.0.1:5000")

ALLOWED_EXT = {"pdf", "png", "jpg", "jpeg"}

app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["QRCODE_FOLDER"] = QRCODE_DIR
app.config["THUMB_FOLDER"] = THUMB_DIR

# ----------------- DB HELPERS -----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        student_name TEXT NOT NULL,
        description TEXT,
        filename TEXT NOT NULL,
        verification_code TEXT UNIQUE NOT NULL,
        file_hash TEXT,
        signature TEXT,
        file_signature TEXT,
        uploaded_by INTEGER,
        uploaded_by_name TEXT,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        uploader_ip TEXT,
        student_email TEXT,
        thumbnail TEXT,
        public_token TEXT
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS teachers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        roll_no TEXT DEFAULT '',
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        certificate_id INTEGER,
        action TEXT NOT NULL,
        actor TEXT,
        ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    db.commit()
    db.close()

init_db()

def insert_audit(certificate_id, action, actor, ip):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (certificate_id, action, actor, ip) VALUES (?, ?, ?, ?)",
        (certificate_id, action, actor, ip)
    )
    db.commit()
    db.close()

def get_platform_stats():
    """Basic stats for the home page."""
    db = get_db()
    stats = {}
    stats["total_certs"] = db.execute(
        "SELECT COUNT(*) AS c FROM certificates"
    ).fetchone()["c"]
    stats["total_teachers"] = db.execute(
        "SELECT COUNT(*) AS c FROM teachers"
    ).fetchone()["c"]
    stats["total_students"] = db.execute(
        "SELECT COUNT(*) AS c FROM students"
    ).fetchone()["c"]

    today_str = datetime.now().strftime("%Y-%m-%d 00:00:00")
    stats["verifications_today"] = db.execute(
        "SELECT COUNT(*) AS c FROM audit_logs WHERE action = 'verify' AND created_at >= ?",
        (today_str,)
    ).fetchone()["c"]

    # You don't have an institutes table, so treat teachers as institutes for now
    stats["total_institutes"] = stats["total_teachers"]

    db.close()
    return stats

# ----------------- SECURITY HELPERS -----------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def sign_hash(hex_hash):
    mac = hmac.new(HMAC_SECRET, hex_hash.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("utf-8").rstrip("=")

def verify_signature(hex_hash, signature):
    if not signature:
        return False
    try:
        expected = sign_hash(hex_hash)
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False

def gen_verification_code(length=8):
    # Codes like: CFM-9A72KQ4G
    chars = string.ascii_uppercase + string.digits
    code = ''.join(random.choice(chars) for _ in range(length))
    return f"CFM-{code}"

def make_qr(code, filename_prefix):
    try:
        import qrcode
    except Exception:
        return None
    try:
        url = f"{BASE_URL}/verify?code={code}"
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        fname = f"{filename_prefix}_qr.png"
        path = os.path.join(QRCODE_DIR, fname)
        img.save(path)
        return fname
    except Exception:
        return None

def create_thumbnail(save_path, ts):
    try:
        ext = save_path.rsplit(".", 1)[1].lower()
        thumb_name = f"{ts}_thumb.png"
        thumb_path = os.path.join(THUMB_DIR, thumb_name)
        if ext in ("png", "jpg", "jpeg"):
            img = Image.open(save_path).convert("RGB")
            img.thumbnail((1200, 1200), Image.LANCZOS)
            draw = ImageDraw.Draw(img)
            try:
                draw.text((10, img.height - 30), "View Only", fill=(200, 200, 200))
            except Exception:
                pass
            img.save(thumb_path, "PNG", optimize=True)
            return thumb_name
        # skip PDFs here
        return None
    except Exception as e:
        print("Thumb error:", e)
        return None

# ----------------- AUTH HELPERS -----------------
def teacher_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "teacher_id" not in session:
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("admin_login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

# ----------------- ROUTES -----------------
# Landing at /
@app.route("/")
def root_page():
    # If you have a separate how_it_works.html, use it,
    # otherwise you can redirect to index() instead.
    return render_template("how_it_works.html")

# Home (index) page (Deepgram-style hero)
@app.route("/home")
def index():
    stats = get_platform_stats()
    return render_template("index.html", stats=stats)

@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")

# -------- Teacher register/login --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not (name and email and password):
            flash("All fields required", "danger")
            return redirect(request.url)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO teachers (name,email,password_hash) VALUES (?,?,?)",
                (name, email, generate_password_hash(password))
            )
            db.commit()
            flash("Teacher registered. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already registered as teacher.", "danger")
        finally:
            db.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT id,name,email,password_hash FROM teachers WHERE lower(email)=?",
            (email,)
        ).fetchone()
        db.close()

        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["teacher_id"] = row["id"]
            session["teacher_name"] = row["name"]
            session["teacher_email"] = row["email"]
            session["user_id"] = row["id"]
            session["role"] = "teacher"

            insert_audit(None, "teacher_login", row["email"], request.remote_addr or "unknown")
            flash("Logged in.", "success")
            return redirect(url_for("teacher_dashboard"))

        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    user = session.get("teacher_name") or session.get("admin_name") or session.get("student_name")
    session.clear()
    flash("Logged out.", "info")
    if user:
        insert_audit(None, "logout", user, request.remote_addr or "unknown")
    return redirect(url_for("index"))

# -------- Student auth --------
@app.route("/student/register", methods=["GET", "POST"])
def student_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        roll_no = request.form.get("roll_no", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not (name and email and password):
            flash("All fields required", "danger")
            return redirect(request.url)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO students (name,roll_no,email,password_hash) VALUES (?,?,?,?)",
                (name, roll_no, email, generate_password_hash(password))
            )
            db.commit()
            flash("Student registered. Please login.", "success")
            return redirect(url_for("student_login"))
        except sqlite3.IntegrityError:
            flash("Email already registered.", "danger")
        finally:
            db.close()
    return render_template("student_register.html")

@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT id,name,email,password_hash FROM students WHERE lower(email)=?",
            (email,)
        ).fetchone()
        db.close()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["student_id"] = row["id"]
            session["student_name"] = row["name"]
            session["student_email"] = row["email"]
            session["user_id"] = row["id"]
            session["role"] = "student"

            insert_audit(None, "student_login", row["email"], request.remote_addr or "unknown")
            flash("Student logged in.", "success")
            return redirect(url_for("student_dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("student_login.html")

@app.route("/student/logout")
def student_logout():
    user = session.get("student_email") or session.get("student_name")
    session.clear()
    flash("Student logged out.", "info")
    if user:
        insert_audit(None, "student_logout", user, request.remote_addr or "unknown")
    return redirect(url_for("index"))

# -------- Admin auth --------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT id,name,password_hash,email FROM admins WHERE lower(email)=?",
            (email,)
        ).fetchone()
        db.close()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["admin_id"] = row["id"]
            session["admin_name"] = row["name"]
            session["user_id"] = row["id"]
            session["role"] = "admin"

            insert_audit(None, "admin_login", row["email"], request.remote_addr or "unknown")
            flash("Admin logged in.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials", "danger")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    user = session.get("admin_name")
    session.clear()
    flash("Admin logged out.", "info")
    if user:
        insert_audit(None, "admin_logout", user, request.remote_addr or "unknown")
    return redirect(url_for("index"))

# -------- Upload route (teacher only) --------
@app.route("/upload", methods=["GET", "POST"])
@teacher_required
def upload():
    db = get_db()
    teacher_row = db.execute(
        "SELECT id,name,email FROM teachers WHERE id = ?",
        (session.get("teacher_id"),)
    ).fetchone()
    if request.method == "POST":
        student_name = request.form.get("student_name", "").strip()
        student_email = request.form.get("student_email", "").strip().lower()
        description = request.form.get("description", "").strip()
        file = request.files.get("file")
        if not student_name or not student_email:
            flash("Student name & email required (use autosuggest)", "danger")
            db.close()
            return redirect(request.url)
        if not file or file.filename == "":
            flash("File required", "danger")
            db.close()
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash("File type not allowed (pdf/jpg/png/jpeg)", "danger")
            db.close()
            return redirect(request.url)

        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        safe_filename = f"{ts}_{file.filename}"
        save_path = os.path.join(UPLOAD_DIR, safe_filename)
        file.save(save_path)

        file_hash = compute_sha256(save_path)
        signature = sign_hash(file_hash)
        code = gen_verification_code()

        # find student id if exists by email
        student_id = None
        srow = db.execute(
            "SELECT id FROM students WHERE lower(email)=?",
            (student_email,)
        ).fetchone()
        if srow:
            student_id = srow["id"]

        # create thumbnail if possible (images only)
        thumb_name = create_thumbnail(save_path, ts)

        # generate public token
        public_token = secrets.token_urlsafe(24)

        try:
            db.execute("""
                INSERT INTO certificates (student_id, student_name, student_email, description,
                                          filename, verification_code, file_hash, file_signature,
                                          uploaded_by, uploaded_by_name, uploader_ip, thumbnail, public_token)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                student_id,
                student_name,
                student_email,
                description,
                safe_filename,
                code,
                file_hash,
                signature,
                teacher_row["id"],
                teacher_row["name"],
                request.remote_addr or "unknown",
                thumb_name,
                public_token
            ))
            db.commit()
            cert_row = db.execute(
                "SELECT id FROM certificates WHERE verification_code = ?",
                (code,)
            ).fetchone()
            cert_id = cert_row["id"] if cert_row else None
            insert_audit(cert_id, "upload", teacher_row["email"], request.remote_addr or "unknown")
            qr_file = make_qr(code, ts)
            flash(f"Uploaded. Verification code: {code}", "success")
            db.close()
            return render_template("upload.html", code=code, qr=qr_file, filename=safe_filename)
        except Exception as e:
            flash("Failed to save certificate: " + str(e), "danger")
            db.close()
            return redirect(request.url)
    db.close()
    return render_template("upload.html")

# -------- Verify (public form + result in same template) --------
@app.route("/verify", methods=["GET", "POST"])
def verify_certificate():
    # Support old param name "verification_code" and new "query", plus ?code=
    query = (
        request.args.get("code")
        or request.form.get("query")
        or request.form.get("verification_code")
    )

    if not query:
        return render_template("verify.html", result=None)

    code = query.strip().upper()
    db = get_db()
    cert = db.execute(
        "SELECT * FROM certificates WHERE verification_code = ?",
        (code,)
    ).fetchone()
    db.close()

    if not cert:
        result = {
            "valid": False,
            "certificate_id": code,
            "student_name": None,
            "course": None,
        }
        return render_template("verify.html", result=result)

    file_path = os.path.join(UPLOAD_DIR, cert["filename"]) if cert["filename"] else None
    file_exists = file_path and os.path.exists(file_path)
    stored_hash = cert["file_hash"] or ""
    stored_sig = cert["file_signature"] or cert["signature"] or ""

    hash_ok = False
    sig_ok = False
    tampered = True

    if file_exists and stored_hash:
        current_hash = compute_sha256(file_path)
        hash_ok = (current_hash == stored_hash)
        sig_ok = verify_signature(current_hash, stored_sig) if stored_sig else False
        tampered = not (hash_ok and sig_ok)
    else:
        tampered = True

    insert_audit(
        cert["id"],
        "verify",
        request.remote_addr or "public",
        request.remote_addr or "unknown",
    )

    valid = not tampered

    result = {
        "valid": valid,
        "student_name": cert["student_name"],
        "course": cert["description"] or "Certificate",
        "certificate_id": cert["verification_code"],
        "issued_at": cert["uploaded_at"],
        "teacher_name": cert["uploaded_by_name"] or "Issuer",
        "institute_name": "CertifyMe Partner",
        "score": None,
        "tampered": tampered,
        "hash_ok": hash_ok,
        "sig_ok": sig_ok,
    }

    return render_template("verify.html", result=result)

# -------- API for student autosuggest --------
@app.route("/api/student-search")
def api_student_search():
    q = request.args.get("q", "").strip().lower()
    if not q:
        return jsonify([])
    db = get_db()
    rows = db.execute(
        "SELECT email, name FROM students WHERE lower(email) LIKE ? OR lower(name) LIKE ? LIMIT 10",
        (f"%{q}%", f"%{q}%")
    ).fetchall()
    db.close()
    results = [{"email": r["email"], "name": r["name"]} for r in rows]
    return jsonify(results)

# -------- Student dashboard --------
@app.route("/student/dashboard")
def student_dashboard():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student = db.execute(
        "SELECT * FROM students WHERE id = ?",
        (session["student_id"],)
    ).fetchone()
    if not student:
        db.close()
        flash("Student record not found", "danger")
        return redirect(url_for("student_login"))
    certs = db.execute("""
        SELECT * FROM certificates
        WHERE student_id = ? OR lower(student_email) = ?
        ORDER BY uploaded_at DESC
    """, (student["id"], student["email"].lower())).fetchall()
    db.close()
    return render_template("student_dashboard.html", certs=certs)

@app.route("/student/certificate/<int:cert_id>")
def student_certificate_view(cert_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    cert = db.execute(
        "SELECT * FROM certificates WHERE id = ?",
        (cert_id,)
    ).fetchone()
    student = db.execute(
        "SELECT * FROM students WHERE id = ?",
        (session["student_id"],)
    ).fetchone()
    db.close()
    if not cert:
        flash("Certificate not found", "danger")
        return redirect(url_for("student_dashboard"))
    if cert["student_email"] and cert["student_email"].lower() != student["email"].lower() and cert["student_id"] != student["id"]:
        flash("Access denied", "danger")
        return redirect(url_for("student_dashboard"))
    insert_audit(cert_id, "student_view", student["email"], request.remote_addr or "unknown")
    return render_template("student_certificate_view.html", cert=cert)

# -------- File serving --------
@app.route("/thumbs/<path:filename>")
def serve_thumb(filename):
    return send_from_directory(THUMB_DIR, filename, as_attachment=False)

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# -------- Teacher dashboard --------
@app.route("/teacher/dashboard")
@teacher_required
def teacher_dashboard():
    db = get_db()
    uploads = db.execute(
        "SELECT * FROM certificates WHERE uploaded_by = ? ORDER BY uploaded_at DESC",
        (session.get("teacher_id"),)
    ).fetchall()
    db.close()
    return render_template("teacher_dashboard.html", uploads=uploads)

# -------- Admin dashboard --------
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()
    audits = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
    uploads = db.execute("""
        SELECT c.*, t.name as uploaded_by_name
        FROM certificates c
        LEFT JOIN teachers t ON t.id = c.uploaded_by
        ORDER BY c.uploaded_at DESC LIMIT 200
    """).fetchall()
    teachers = db.execute(
        "SELECT id, name, email, created_at FROM teachers ORDER BY id DESC LIMIT 200"
    ).fetchall()
    students = db.execute(
        "SELECT id, name, email, created_at FROM students ORDER BY id DESC LIMIT 200"
    ).fetchall()
    db.close()
    insert_audit(
        None,
        "admin_view_dashboard",
        session.get("admin_name") or "admin",
        request.remote_addr or "unknown"
    )
    return render_template("admin_dashboard.html", audits=audits, uploads=uploads, teachers=teachers, students=students)

# -------- Public certificate view --------
@app.route("/public/<token>")
def public_view(token):
    token = token.strip()
    db = get_db()
    cert = db.execute(
        "SELECT * FROM certificates WHERE public_token = ?",
        (token,)
    ).fetchone()
    db.close()
    if not cert:
        return render_template("public_not_found.html", token=token), 404

    file_path = os.path.join(UPLOAD_DIR, cert["filename"]) if cert["filename"] else None
    file_exists = file_path and os.path.exists(file_path)
    stored_hash = cert["file_hash"] or ""
    stored_sig = cert["file_signature"] or cert["signature"] or ""

    hash_ok = False
    sig_ok = False
    tampered = True
    if file_exists and stored_hash:
        current_hash = compute_sha256(file_path)
        hash_ok = (current_hash == stored_hash)
        sig_ok = verify_signature(current_hash, stored_sig) if stored_sig else False
        tampered = not (hash_ok and sig_ok)
    else:
        tampered = True

    insert_audit(cert["id"], "public_view", request.remote_addr or "public", request.remote_addr or "unknown")

    return render_template("public_view.html", cert=cert, tampered=tampered, hash_ok=hash_ok, sig_ok=sig_ok)

# -------- Dev seed routes --------
@app.route("/_seed_admin")
def _seed_admin():
    db = get_db()
    try:
        pw = generate_password_hash("adminpass123")
        db.execute(
            "INSERT INTO admins (name, email, password_hash) VALUES (?, ?, ?)",
            ("Super Admin", "admin@example.com", pw)
        )
        db.commit()
        msg = "Admin seeded: admin@example.com / adminpass123"
    except sqlite3.IntegrityError:
        msg = "Admin already exists"
    db.close()
    return msg

@app.route("/_seed_teacher")
def _seed_teacher():
    db = get_db()
    try:
        pw = generate_password_hash("teacherpass123")
        db.execute(
            "INSERT INTO teachers (name, email, password_hash) VALUES (?, ?, ?)",
            ("Demo Teacher", "teacher@example.com", pw)
        )
        db.commit()
        msg = "Teacher seeded: teacher@example.com / teacherpass123"
    except sqlite3.IntegrityError:
        msg = "Teacher already exists"
    db.close()
    return msg

@app.route("/_seed_student")
def _seed_student():
    db = get_db()
    try:
        pw = generate_password_hash("studentpass123")
        db.execute(
            "INSERT INTO students (name, roll_no, email, password_hash) VALUES (?, ?, ?, ?)",
            ("Demo Student", "ROLL000", "student@example.com", pw)
        )
        db.commit()
        msg = "Student seeded: student@example.com / studentpass123"
    except sqlite3.IntegrityError:
        msg = "Student already exists"
    db.close()
    return msg

if __name__ == "__main__":
    print("CertifyMe starting. Upload folder:", UPLOAD_DIR)
    app.run(debug=True, port=5000)
