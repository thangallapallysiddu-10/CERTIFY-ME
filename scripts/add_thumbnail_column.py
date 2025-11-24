# scripts/add_thumbnail_column.py
import sqlite3, os, sys

DB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "certifyme.db"))

def main():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cols = [r[1] for r in cur.execute("PRAGMA table_info(certificates)").fetchall()]
    print("Existing columns:", cols)

    if "thumbnail" not in cols:
        print("Adding column: thumbnail")
        cur.execute("ALTER TABLE certificates ADD COLUMN thumbnail TEXT")
        conn.commit()
        print("Added 'thumbnail'.")
    else:
        print("'thumbnail' already exists.")

    # if there is an accidentally-named column 'thumbnai', copy values
    if "thumbnai" in cols and "thumbnail" in cols:
        print("Copying values from 'thumbnai' -> 'thumbnail' where thumbnail is NULL")
        cur.execute("""
            UPDATE certificates
            SET thumbnail = thumbnai
            WHERE (thumbnail IS NULL OR trim(thumbnail) = '') AND (thumbnai IS NOT NULL AND trim(thumbnai) <> '')
        """)
        conn.commit()
        print("Copied values. Rows changed:", conn.total_changes)

    print("\nFinal schema:")
    for r in cur.execute("PRAGMA table_info(certificates)").fetchall():
        print(r)

    conn.close()
    print("\nDone.")

if __name__ == "__main__":
    main()
