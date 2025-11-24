# CertifyMe – Secure Digital Certificate Management System  

> **Designed & Developed by Team HACKVOK**

CertifyMe is a secure, role-based digital certificate management system built with **Flask** and **SQLite**.  
It enables institutions and teachers to **issue digital certificates**, verify authenticity using **SHA-256 + HMAC tamper detection**, and allows students to **securely preview certificates in view-only mode** with **public share links** for resumes and job applications.

---

## 🔐 Core Features

### 🎓 Role-Based Portals
#### **Admin Portal**
- View audit logs  
- Monitor uploaded certificates, users, and activity  

#### **Teacher Portal**
- Register & login  
- Upload certificates (PDF / PNG / JPG)  
- Assign certificates to students  
- Auto-generate unique verification codes  

#### **Student Portal**
- Register & login  
- View certificates securely  
- Non-downloadable certificate preview (canvas-based)  
- Copy a **public share URL** for job applications  

---

## 🛡 Security & Verification
- **SHA-256 hashing** for every uploaded certificate  
- **HMAC signature** using a server-side secret  
- **Tamper detection** during verification  
- **QR code support** (backend integrated)  
- View-only protected canvas preview:
  - Right-click disabled  
  - F12, Ctrl+S, Ctrl+U, Ctrl+P blocked  
  - Full-page watermark for screenshot deterrence  

---

## 🏗 Tech Stack

### **Backend**
- Python 3.x  
- Flask  
- SQLite  
- SHA-256 + HMAC security  

### **Frontend**
- HTML5 / Jinja2  
- Bootstrap 5  
- Custom CSS  
- JavaScript (Clipboard API, security controls)

### **Optional Libraries**
- Pillow (PIL) – image handling  
- PyMuPDF / pdf2image – PDF → image thumbnails  
- qrcode – QR code generation  

---

## 📂 Project Structure (Simplified)

```bash
certifyme/
├── app.py                 # Main Flask application
├── requirements.txt       # Dependencies
├── certifyme.db           # Auto-created SQLite DB
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── student_login.html
│   ├── student_register.html
│   ├── teacher_dashboard.html
│   ├── student_dashboard.html
│   ├── upload.html
│   ├── verify.html
│   ├── result.html
│   └── admin_dashboard.html
│
└── static/
    ├── uploads/
    │   └── thumbs/
    ├── qrcodes/
    └── css/js/images
