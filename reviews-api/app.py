import os
import re
import hmac
import sqlite3
import secrets
from functools import wraps
from flask import Flask, request, jsonify, session

# -----------------------------
# Helpers: systemd credentials
# -----------------------------
def read_credential(name: str) -> str:
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not cred_dir:
        return ""
    path = os.path.join(cred_dir, name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""
    except Exception:
        return ""

def get_secret(env_name: str, cred_name: str) -> str:
    v = read_credential(cred_name)
    if v:
        return v
    return os.environ.get(env_name, "")

# -----------------------------
# Config
# -----------------------------
APP_DIR = os.path.dirname(__file__)
DB_PATH = os.environ.get("REVIEWS_DB", os.path.join(APP_DIR, "reviews.db"))

ADMIN_PASSWORD = get_secret("ADMIN_PASSWORD", "admin_password")
SECRET_KEY = get_secret("FLASK_SECRET_KEY", "flask_secret_key")

SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"

# Where images are stored on disk (served by nginx alias /assets/gallery/)
GALLERY_DIR = os.environ.get("GALLERY_DIR", "/var/lib/reviews-api/gallery")

CODE_RE = re.compile(r"^\d{3}$")

ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}

app = Flask(__name__)
app.secret_key = SECRET_KEY or "dev-change-me"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
)

# -----------------------------
# DB helpers
# -----------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def ensure_schema(conn: sqlite3.Connection):
    # existing codes table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS review_codes (
          code TEXT PRIMARY KEY,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          used_at TEXT,
          used_by_email TEXT,
          used_by_name TEXT
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_review_codes_used_at ON review_codes(used_at);")

    # NEW: gallery table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS gallery_images (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          filename TEXT NOT NULL UNIQUE,
          category TEXT NOT NULL,
          alt TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_gallery_images_category ON gallery_images(category);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_gallery_images_created_at ON gallery_images(created_at);")

def has_table(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?;",
        (table,),
    ).fetchone()
    return row is not None

def table_columns(conn: sqlite3.Connection, table: str):
    rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
    return [r["name"] for r in rows]

def now_sqlite(conn: sqlite3.Connection) -> str:
    return conn.execute("SELECT datetime('now');").fetchone()[0]

# -----------------------------
# Input parsing
# -----------------------------
def parse_incoming_review():
    if request.is_json:
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip()
        rating = data.get("rating")
        message = (data.get("message") or "").strip()
        code = (data.get("code") or "").strip()
    else:
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip()
        rating = request.form.get("rating")
        message = (request.form.get("message") or "").strip()
        code = (request.form.get("code") or "").strip()

    return name, email, rating, message, code

# -----------------------------
# Admin auth + small CSRF guard
# -----------------------------
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

def require_ajax_header():
    return request.headers.get("X-Requested-With") == "smr-admin"

def admin_write_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and not require_ajax_header():
            return jsonify({"ok": False, "error": "bad_request"}), 400
        return fn(*args, **kwargs)
    return wrapper

# -----------------------------
# Gallery helpers
# -----------------------------
def gallery_url_for(filename: str) -> str:
    # IMPORTANT: leading slash so it's always absolute from any page
    return f"/assets/gallery/{filename}"

def ensure_gallery_dir():
    os.makedirs(GALLERY_DIR, exist_ok=True)

def safe_ext(filename: str) -> str:
    _, ext = os.path.splitext(filename or "")
    return ext.lower()

def new_image_filename(ext: str) -> str:
    # token_urlsafe can include '-', '_' only; good for filenames
    token = secrets.token_urlsafe(16)
    return token + ext

# -----------------------------
# Public endpoints
# -----------------------------
@app.get("/health")
def health():
    conn = get_db()
    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})

@app.post("/submit-review")
def submit_review():
    name, email, rating, message, code = parse_incoming_review()

    if not name or not message or rating is None:
        return jsonify({"ok": False, "error": "name, rating, and message are required"}), 400

    if not CODE_RE.fullmatch(code or ""):
        return jsonify({"ok": False, "error": "invalid_code"}), 403

    try:
        rating_int = int(rating)
    except Exception:
        return jsonify({"ok": False, "error": "rating must be an integer"}), 400

    if rating_int < 1 or rating_int > 5:
        return jsonify({"ok": False, "error": "rating must be between 1 and 5"}), 400

    conn = get_db()
    try:
        ensure_schema(conn)
        if not has_table(conn, "reviews"):
            return jsonify({"ok": False, "error": "missing_reviews_table"}), 500

        conn.execute("BEGIN IMMEDIATE;")

        cur = conn.execute(
            """
            UPDATE review_codes
               SET used_at = datetime('now'),
                   used_by_email = ?,
                   used_by_name  = ?
             WHERE code = ?
               AND used_at IS NULL
            """,
            (email or None, name, code),
        )

        if cur.rowcount != 1:
            conn.execute("ROLLBACK;")
            return jsonify({"ok": False, "error": "invalid_code"}), 403

        cols = table_columns(conn, "reviews")
        insert_cols, values = [], []

        def add(col, val):
            insert_cols.append(col)
            values.append(val)

        if "name" in cols:
            add("name", name)
        if "email" in cols:
            add("email", (email or None))
        if "rating" in cols:
            add("rating", rating_int)
        if "message" in cols:
            add("message", message)
        if "created_at" in cols:
            add("created_at", now_sqlite(conn))

        if not insert_cols:
            conn.execute("ROLLBACK;")
            return jsonify({"ok": False, "error": "reviews_table_has_no_supported_columns"}), 500

        placeholders = ", ".join(["?"] * len(insert_cols))
        sql = f"INSERT INTO reviews ({', '.join(insert_cols)}) VALUES ({placeholders})"
        conn.execute(sql, tuple(values))

        conn.commit()
        return jsonify({"ok": True})

    except sqlite3.OperationalError as e:
        try:
            conn.execute("ROLLBACK;")
        except Exception:
            pass
        return jsonify({"ok": False, "error": "db_busy", "detail": str(e)}), 503
    except Exception as e:
        try:
            conn.execute("ROLLBACK;")
        except Exception:
            pass
        return jsonify({"ok": False, "error": "server_error", "detail": str(e)}), 500
    finally:
        conn.close()

@app.get("/reviews")
def list_reviews():
    limit = 50
    conn = get_db()
    try:
        if not has_table(conn, "reviews"):
            return jsonify({"reviews": []})

        cols = table_columns(conn, "reviews")
        select_cols = [c for c in ("name", "rating", "message", "created_at") if c in cols]
        if not select_cols:
            return jsonify({"reviews": []})

        if "id" in cols:
            order_clause = "ORDER BY id DESC"
        elif "created_at" in cols:
            order_clause = "ORDER BY created_at DESC"
        else:
            order_clause = ""

        sql = f"SELECT {', '.join(select_cols)} FROM reviews {order_clause} LIMIT ?"
        rows = conn.execute(sql, (limit,)).fetchall()

        out = []
        for r in rows:
            out.append({
                "name": r["name"] if "name" in r.keys() else "Happy Customer",
                "rating": r["rating"] if "rating" in r.keys() else 0,
                "message": r["message"] if "message" in r.keys() else "",
                "created_at": r["created_at"] if "created_at" in r.keys() else None,
            })
        return jsonify({"reviews": out})
    finally:
        conn.close()

# -----------------------------
# Public gallery data endpoint
# -----------------------------
@app.get("/gallery-data")
def gallery_data():
    conn = get_db()
    try:
        ensure_schema(conn)

        rows = conn.execute(
            """
            SELECT id, filename, category, alt, created_at
              FROM gallery_images
             ORDER BY category COLLATE NOCASE ASC, created_at DESC, id DESC
            """
        ).fetchall()

        # Group by category
        groups_map = {}
        for r in rows:
            cat = (r["category"] or "").strip() or "Uncategorized"
            groups_map.setdefault(cat, []).append({
                "id": r["id"],
                "filename": r["filename"],
                "category": cat,
                "alt": r["alt"] or "",
                "created_at": r["created_at"],
                "url": gallery_url_for(r["filename"]),  # <-- absolute path
            })

        # Keep stable ordering
        groups = [{"category": k, "images": groups_map[k]} for k in groups_map.keys()]

        return jsonify({"ok": True, "groups": groups})
    finally:
        conn.close()

# -----------------------------
# Admin API (NO HTML here)
# -----------------------------
@app.get("/api/admin/me")
def admin_me():
    return jsonify({"ok": True, "is_admin": bool(session.get("is_admin"))})

@app.post("/api/admin/login")
def api_admin_login():
    if not ADMIN_PASSWORD:
        return jsonify({"ok": False, "error": "admin_not_configured"}), 500

    if request.is_json:
        data = request.get_json(silent=True) or {}
        pw = (data.get("password") or "")
    else:
        pw = (request.form.get("password") or "")

    if not hmac.compare_digest(pw, ADMIN_PASSWORD):
        return jsonify({"ok": False, "error": "bad_password"}), 401

    session["is_admin"] = True
    return jsonify({"ok": True})

@app.post("/api/admin/logout")
@admin_write_required
def api_admin_logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/admin/codes")
@admin_required
def api_admin_codes():
    preview_limit = int(request.args.get("limit", "300"))
    preview_limit = max(50, min(preview_limit, 2000))

    conn = get_db()
    try:
        ensure_schema(conn)

        unused = conn.execute("SELECT COUNT(*) AS n FROM review_codes WHERE used_at IS NULL").fetchone()["n"]
        used = conn.execute("SELECT COUNT(*) AS n FROM review_codes WHERE used_at IS NOT NULL").fetchone()["n"]

        unused_rows = conn.execute(
            """
            SELECT code, created_at
              FROM review_codes
             WHERE used_at IS NULL
             ORDER BY created_at DESC, code
             LIMIT ?
            """,
            (preview_limit,),
        ).fetchall()

        used_rows = conn.execute(
            """
            SELECT code, created_at, used_at, used_by_name, used_by_email
              FROM review_codes
             WHERE used_at IS NOT NULL
             ORDER BY used_at DESC, code
             LIMIT ?
            """,
            (preview_limit,),
        ).fetchall()

        return jsonify({
            "ok": True,
            "counts": {"unused": unused, "used": used, "total": unused + used},
            "unused_codes": [{"code": r["code"], "created_at": r["created_at"]} for r in unused_rows],
            "used_codes": [{
                "code": r["code"],
                "created_at": r["created_at"],
                "used_at": r["used_at"],
                "used_by_name": r["used_by_name"],
                "used_by_email": r["used_by_email"],
            } for r in used_rows],
        })
    finally:
        conn.close()

@app.post("/api/admin/codes/add")
@admin_write_required
def api_admin_add_codes():
    if request.is_json:
        data = request.get_json(silent=True) or {}
        raw = (data.get("codes") or "")
    else:
        raw = (request.form.get("codes") or "")

    raw = raw.strip()
    if not raw:
        return jsonify({"ok": False, "error": "no_codes"}), 400

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    cleaned = []
    for c in lines:
        if not CODE_RE.fullmatch(c):
            return jsonify({"ok": False, "error": f"invalid_code_format:{c}"}), 400
        cleaned.append((c,))

    conn = get_db()
    try:
        ensure_schema(conn)
        conn.executemany("INSERT OR IGNORE INTO review_codes(code) VALUES (?)", cleaned)
        conn.commit()
        return jsonify({"ok": True, "submitted": len(cleaned)})
    finally:
        conn.close()

@app.post("/api/admin/codes/delete")
@admin_write_required
def api_admin_delete_code():
    if request.is_json:
        data = request.get_json(silent=True) or {}
        code = (data.get("code") or "").strip()
    else:
        code = (request.form.get("code") or "").strip()

    if not CODE_RE.fullmatch(code):
        return jsonify({"ok": False, "error": "invalid_code_format"}), 400

    conn = get_db()
    try:
        ensure_schema(conn)
        cur = conn.execute("DELETE FROM review_codes WHERE code = ?", (code,))
        conn.commit()
        return jsonify({"ok": True, "deleted": cur.rowcount})
    finally:
        conn.close()

@app.get("/api/admin/codes/unused.csv")
@admin_required
def api_admin_unused_csv():
    conn = get_db()
    try:
        ensure_schema(conn)
        rows = conn.execute(
            "SELECT code FROM review_codes WHERE used_at IS NULL ORDER BY code"
        ).fetchall()
        csv_data = "code\n" + "\n".join([r["code"] for r in rows]) + "\n"
    finally:
        conn.close()

    return app.response_class(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=unused_review_codes.csv"},
    )

# -----------------------------
# Admin Reviews API
# -----------------------------
@app.get("/api/admin/reviews")
@admin_required
def api_admin_reviews():
    try:
        limit = int(request.args.get("limit", "500"))
    except Exception:
        limit = 500
    limit = max(1, min(limit, 5000))

    conn = get_db()
    try:
        if not has_table(conn, "reviews"):
            return jsonify({"ok": True, "total": 0, "reviews": []})

        cols = table_columns(conn, "reviews")

        has_id = "id" in cols
        select_cols = ["id"] if has_id else ["rowid as id"]
        for c in ("created_at", "name", "email", "rating", "message"):
            if c in cols:
                select_cols.append(c)

        if has_id:
            order_clause = "ORDER BY id DESC"
        elif "created_at" in cols:
            order_clause = "ORDER BY created_at DESC"
        else:
            order_clause = "ORDER BY rowid DESC"

        sql = f"SELECT {', '.join(select_cols)} FROM reviews {order_clause} LIMIT ?"
        rows = conn.execute(sql, (limit,)).fetchall()

        out = []
        for r in rows:
            out.append({
                "id": r["id"],
                "created_at": r["created_at"] if "created_at" in r.keys() else None,
                "name": r["name"] if "name" in r.keys() else "",
                "email": r["email"] if "email" in r.keys() else "",
                "rating": r["rating"] if "rating" in r.keys() else 0,
                "message": r["message"] if "message" in r.keys() else "",
            })

        total = conn.execute("SELECT COUNT(*) AS n FROM reviews").fetchone()["n"]
        return jsonify({"ok": True, "total": total, "reviews": out})
    finally:
        conn.close()

@app.post("/api/admin/reviews/delete")
@admin_write_required
def api_admin_delete_review():
    if request.is_json:
        data = request.get_json(silent=True) or {}
        rid = str(data.get("id") or "").strip()
    else:
        rid = (request.form.get("id") or "").strip()

    if not rid.isdigit():
        return jsonify({"ok": False, "error": "bad_id"}), 400

    conn = get_db()
    try:
        if not has_table(conn, "reviews"):
            return jsonify({"ok": False, "error": "missing_reviews_table"}), 500

        cols = table_columns(conn, "reviews")
        if "id" in cols:
            cur = conn.execute("DELETE FROM reviews WHERE id = ?", (int(rid),))
        else:
            cur = conn.execute("DELETE FROM reviews WHERE rowid = ?", (int(rid),))

        conn.commit()

        if cur.rowcount != 1:
            return jsonify({"ok": False, "error": "not_found"}), 404

        return jsonify({"ok": True})
    finally:
        conn.close()

# -----------------------------
# Admin Gallery API (NEW)
# -----------------------------
@app.get("/api/admin/gallery")
@admin_required
def api_admin_gallery_list():
    conn = get_db()
    try:
        ensure_schema(conn)
        rows = conn.execute(
            """
            SELECT id, filename, category, alt, created_at
              FROM gallery_images
             ORDER BY created_at DESC, id DESC
            """
        ).fetchall()

        images = []
        for r in rows:
            images.append({
                "id": r["id"],
                "filename": r["filename"],
                "category": r["category"],
                "alt": r["alt"] or "",
                "created_at": r["created_at"],
                "url": gallery_url_for(r["filename"]),  # <-- absolute path
            })

        return jsonify({"ok": True, "images": images})
    finally:
        conn.close()

@app.post("/api/admin/gallery/upload")
@admin_write_required
def api_admin_gallery_upload():
    ensure_gallery_dir()

    # Must be multipart/form-data
    f = request.files.get("file")
    category = (request.form.get("category") or "").strip()
    alt = (request.form.get("alt") or "").strip()

    if not f:
        return jsonify({"ok": False, "error": "no_file"}), 400
    if not category:
        return jsonify({"ok": False, "error": "missing_category"}), 400

    ext = safe_ext(f.filename)
    if ext not in ALLOWED_IMAGE_EXTS:
        return jsonify({"ok": False, "error": "unsupported_file_type"}), 400

    filename = new_image_filename(ext)
    disk_path = os.path.join(GALLERY_DIR, filename)

    # Save file first
    try:
        f.save(disk_path)
    except Exception:
        return jsonify({"ok": False, "error": "save_failed"}), 500

    # Ensure readable by nginx (http). Usually fine if umask is sane; enforce:
    try:
        os.chmod(disk_path, 0o644)
    except Exception:
        pass

    conn = get_db()
    try:
        ensure_schema(conn)
        conn.execute(
            "INSERT INTO gallery_images(filename, category, alt) VALUES (?, ?, ?)",
            (filename, category, (alt or None)),
        )
        conn.commit()
    except Exception:
        # If DB insert fails, remove file to avoid orphans
        try:
            os.remove(disk_path)
        except Exception:
            pass
        return jsonify({"ok": False, "error": "db_insert_failed"}), 500
    finally:
        conn.close()

    return jsonify({"ok": True, "filename": filename, "url": gallery_url_for(filename)})

@app.post("/api/admin/gallery/delete")
@admin_write_required
def api_admin_gallery_delete():
    rid = (request.form.get("id") or "").strip()
    if not rid.isdigit():
        return jsonify({"ok": False, "error": "bad_id"}), 400

    conn = get_db()
    filename = None
    try:
        ensure_schema(conn)
        row = conn.execute("SELECT filename FROM gallery_images WHERE id = ?", (int(rid),)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "not_found"}), 404
        filename = row["filename"]

        cur = conn.execute("DELETE FROM gallery_images WHERE id = ?", (int(rid),))
        conn.commit()
        if cur.rowcount != 1:
            return jsonify({"ok": False, "error": "not_found"}), 404
    finally:
        conn.close()

    # Remove file from disk
    if filename:
        try:
            os.remove(os.path.join(GALLERY_DIR, filename))
        except FileNotFoundError:
            pass
        except Exception:
            # Don't fail the API if file deletion fails; DB is already updated
            pass

    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
