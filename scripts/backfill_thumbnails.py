import sqlite3, os
from PIL import Image, ImageDraw

DB = "certifyme.db"
UPLOAD = "static/uploads"
THUMBS = "static/uploads/thumbs"

os.makedirs(THUMBS, exist_ok=True)

def create_thumb(filepath, thumbpath):
    ext = filepath.rsplit(".", 1)[1].lower()

    # Only thumbnails for images
    if ext in ("png", "jpg", "jpeg"):
        try:
            img = Image.open(filepath).convert("RGB")
            img.thumbnail((1200, 1200))
            d = ImageDraw.Draw(img)
            d.text((10, img.height - 40), "View Only", fill=(200, 200, 200))
            img.save(thumbpath)
            return True
        except:
            return False

    # PDFs → skip
    return False


conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

rows = cur.execute("SELECT id, filename FROM certificates").fetchall()

for r in rows:
    file_path = os.path.join(UPLOAD, r["filename"])
    thumb_name = f"{r['filename']}_thumb.png"
    thumb_path = os.path.join(THUMBS, thumb_name)

    if not os.path.exists(file_path):
        print("Missing:", file_path)
        continue

    print("Processing:", r["filename"])

    if create_thumb(file_path, thumb_path):
        cur.execute("UPDATE certificates SET thumbnail=? WHERE id=?", (thumb_name, r["id"]))
        conn.commit()
    else:
        print("Skipped (not image):", r["filename"])

conn.close()
print("Done.")
