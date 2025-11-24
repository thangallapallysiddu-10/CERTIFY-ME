# scripts/backfill_pdf_thumbs_pymupdf.py
import os, sqlite3, traceback

try:
    import fitz  # PyMuPDF
except Exception as e:
    raise SystemExit("PyMuPDF not installed. Run: pip install pymupdf") from e

from PIL import Image, ImageDraw

BASE = os.path.dirname(os.path.dirname(__file__))
DB = os.path.join(BASE, "certifyme.db")
UPLOAD = os.path.join(BASE, "static", "uploads")
THUMBS = os.path.join(UPLOAD, "thumbs")
os.makedirs(THUMBS, exist_ok=True)

def make_thumb_for_image(src_path, out_path):
    img = Image.open(src_path).convert("RGB")
    img.thumbnail((1600,1600), Image.LANCZOS)
    draw = ImageDraw.Draw(img)
    try:
        draw.text((10, img.height-40), "View Only", fill=(180,180,180))
    except Exception:
        pass
    img.save(out_path, "PNG", optimize=True)

def make_thumb_for_pdf(src_path, out_path):
    doc = fitz.open(src_path)
    page = doc.load_page(0)
    mat = fitz.Matrix(2, 2)   # scale for better resolution
    pix = page.get_pixmap(matrix=mat, alpha=False)
    pix.save(out_path)

def main():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rows = cur.execute("SELECT id, filename, thumbnail FROM certificates").fetchall()
    print("Found", len(rows), "certificate rows to check.")

    created = 0
    skipped = 0
    missing = 0

    for r in rows:
        cid = r["id"]
        fn = r["filename"]
        existing_thumb = r["thumbnail"]
        if not fn:
            print("id",cid,"has no filename. Skipping.")
            skipped += 1
            continue

        src = os.path.join(UPLOAD, fn)
        if not os.path.exists(src):
            print("Missing file on disk:", fn)
            missing += 1
            continue

        # prefer existing thumbnail
        if existing_thumb:
            # already has a thumbnail
            skipped += 1
            continue

        ext = fn.rsplit(".",1)[-1].lower()
        ts = fn.split("_")[0]
        outname = f"{ts}_thumb.png"
        outpath = os.path.join(THUMBS, outname)

        try:
            if ext in ("png","jpg","jpeg"):
                make_thumb_for_image(src, outpath)
            elif ext == "pdf":
                make_thumb_for_pdf(src, outpath)
            else:
                print("Unsupported ext, skipping:", fn)
                skipped += 1
                continue

            cur.execute("UPDATE certificates SET thumbnail = ? WHERE id = ?", (outname, cid))
            conn.commit()
            print("Created thumbnail for id", cid, "->", outname)
            created += 1

        except Exception as e:
            print("Thumbnail creation failed for", fn, ":", e)
            traceback.print_exc()
            skipped += 1

    conn.close()
    print("\nSummary: created =", created, "skipped =", skipped, "missing =", missing)

if __name__ == "__main__":
    main()
