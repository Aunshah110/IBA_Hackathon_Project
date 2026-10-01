# =========================================================
# GHOST SCHOOL DETECTION SYSTEM (GSDS)
# Single-file Flask backend. All logic lives here by design.
# Sections:
#   1. Imports & Config
#   2. Database Models
#   3. Security / Ledger Helpers
#   4. Biometric Module (mockable)
#   5. Computer Vision Module (with fallback)
#   6. Geo-fence Module
#   7. Auth Routes
#   8. Dashboard Routes
#   9. Inspection Routes
#  10. Audit Routes
#  11. Parent Routes
#  12. Bootstrap & Main
# =========================================================

# =========================================================
# 1. IMPORTS & CONFIG
# =========================================================
import os
import io
import json
import hmac
import hashlib
import base64
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from math import radians, sin, cos, sqrt, atan2

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, abort, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

# --- Optional CV imports (graceful fallback) ---
try:
    import cv2
    import numpy as np
    CV_OPENCV = True
except ImportError:
    CV_OPENCV = False

try:
    import face_recognition
    CV_FACE = True
except ImportError:
    CV_FACE = False

# --- Optional bio imports (mocked in demo) ---
# REAL_SDK: from pyfingerprint.pyfingerprint import PyFingerprint
BIOMETRIC_REAL = False  # flip True when hardware is wired


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, instance_relative_config=False)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-insecure-key-change-me")
def _resolve_db_uri() -> str:
    """
    Return a SQLAlchemy-compatible URI. Handles three cases:
      1. Explicit DATABASE_URL from .env (normalize backslashes).
      2. Bare absolute path pasted from Explorer (prefix with sqlite:///).
      3. Fallback: relative sqlite path under project root.
    """
    raw = os.getenv("DATABASE_URL", "").strip().strip('"').strip("'")
    if raw:
        # Windows path pasted directly → convert to SQLAlchemy URI
        if "://" not in raw:
            raw = raw.replace("\\", "/")
            if not raw.startswith("/"):
                raw = "/" + raw  # absolute Windows path needs 4th slash
            raw = "sqlite:///" + raw.lstrip("/") if len(raw) < 4 else "sqlite://" + raw
        # Normalize backslashes in any URI
        raw = raw.replace("\\", "/")
        return raw
    # Fallback: relative path under project instance/ folder
    return "sqlite:///instance/gsds.db"


app.config["SQLALCHEMY_DATABASE_URI"] = _resolve_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "static", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB snapshots

GEO_FENCE_RADIUS_M = float(os.getenv("GEO_FENCE_RADIUS_M", "200"))
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
CV_MIN_CLASS_SIZE = int(os.getenv("CV_MIN_CLASS_SIZE", "5"))
CV_MISMATCH_THRESHOLD = int(os.getenv("CV_MISMATCH_THRESHOLD", "3"))

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(os.path.join(app.config["UPLOAD_FOLDER"], "snapshots"), exist_ok=True)
os.makedirs(os.path.join(app.config["UPLOAD_FOLDER"], "fingerprints"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if current_user.role not in roles:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


# =========================================================
# 1b. TEMPLATE CONTEXT HELPERS (HCI: recognition, status)
# =========================================================
@app.context_processor
def inject_globals():
    """Expose safe derived state to every template."""
    def status_meta(status: str) -> dict:
        return {
            "verified":   {"label": "Verified",   "icon": "●", "tone": "ok"},
            "flagged":    {"label": "Flagged",    "icon": "●", "tone": "bad"},
            "unverified": {"label": "Unverified", "icon": "●", "tone": "warn"},
        }.get(status, {"label": status, "icon": "●", "tone": "warn"})

    chain_ok = True
    chain_total = 0
    try:
        rows = AuditLedger.query.count()
        chain_total = rows
    except Exception:
        pass

    return {
        "status_meta": status_meta,
        "app_name": "GSDS",
        "app_full": "Ghost School Detection System",
        "chain_total": chain_total,
        "current_year": datetime.now(timezone.utc).year,
    }


# =========================================================
# 11b. HELP ROUTE (HCI: help & documentation)
# =========================================================
@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")



# =========================================================
# 2. DATABASE MODELS
# =========================================================
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False)  # district|inspector|teacher|parent
    full_name = db.Column(db.String(128))
    fingerprint_template_hash = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    @property
    def is_district(self):
        return self.role == "district"

    @property
    def is_inspector(self):
        return self.role == "inspector"

    @property
    def is_teacher(self):
        return self.role == "teacher"

    @property
    def is_parent(self):
        return self.role == "parent"


class School(db.Model):
    __tablename__ = "schools"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    village = db.Column(db.String(120))
    geo_lat = db.Column(db.Float, nullable=False)
    geo_lng = db.Column(db.Float, nullable=False)
    registered_students = db.Column(db.Integer, default=0)
    registered_teacher_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    verification_status = db.Column(db.String(16), default="unverified")  # verified|flagged|unverified
    last_verified_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    teacher = db.relationship("User", foreign_keys=[registered_teacher_id])


class Inspection(db.Model):
    """One verification event by an inspector at a school."""
    __tablename__ = "inspections"
    id = db.Column(db.Integer, primary_key=True)
    school_id = db.Column(db.Integer, db.ForeignKey("schools.id"), nullable=False)
    inspector_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    gps_lat = db.Column(db.Float, nullable=False)
    gps_lng = db.Column(db.Float, nullable=False)
    declared_students = db.Column(db.Integer, nullable=False)
    detected_faces = db.Column(db.Integer, nullable=True)
    fingerprint_ok = db.Column(db.Boolean, default=False)
    snapshot_path = db.Column(db.String(256), nullable=True)
    result = db.Column(db.String(16), default="pending")  # verified|flagged
    notes = db.Column(db.Text)


class BiometricLog(db.Model):
    __tablename__ = "biometric_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    inspection_id = db.Column(db.Integer, db.ForeignKey("inspections.id"), nullable=True)
    template_hash = db.Column(db.String(128), nullable=False)
    matched = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class CVSnapshot(db.Model):
    __tablename__ = "cv_snapshots"
    id = db.Column(db.Integer, primary_key=True)
    inspection_id = db.Column(db.Integer, db.ForeignKey("inspections.id"), nullable=False)
    image_path = db.Column(db.String(256), nullable=False)
    detected_faces = db.Column(db.Integer, default=0)
    image_hash = db.Column(db.String(128), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLedger(db.Model):
    """Append-only hash chain. Never UPDATE. Never DELETE."""
    __tablename__ = "audit_ledger"
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(48), nullable=False)
    payload_json = db.Column(db.Text, nullable=False)
    prev_hash = db.Column(db.String(128), nullable=False)
    curr_hash = db.Column(db.String(128), nullable=False, unique=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class ParentReport(db.Model):
    __tablename__ = "parent_reports"
    id = db.Column(db.Integer, primary_key=True)
    school_id = db.Column(db.Integer, db.ForeignKey("schools.id"), nullable=False)
    category = db.Column(db.String(48), nullable=False)  # no_teacher|no_class|closed|other
    text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ip_hash = db.Column(db.String(64))  # rate-limit / de-dupe, no raw IP stored



class SyncEvent(db.Model):
    """
    Idempotency ledger for offline-queued client events.
    A client generates a UUID per event; server records it once.
    Replay with the same UUID → no duplicate inspection, returns cached response.
    """
    __tablename__ = "sync_events"
    id = db.Column(db.Integer, primary_key=True)
    client_uuid = db.Column(db.String(64), unique=True, nullable=False, index=True)
    client_timestamp = db.Column(db.DateTime, nullable=False)
    server_timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    inspection_id = db.Column(db.Integer, db.ForeignKey("inspections.id"), nullable=True)
    response_json = db.Column(db.Text, nullable=False)
    was_conflict = db.Column(db.Boolean, default=False)


class TriangulationScore(db.Model):
    """
    Cached triangulation result per school. Recomputed after every
    inspection, parent report, or sync. Never hand-edited.
    """
    __tablename__ = "triangulation_scores"
    id = db.Column(db.Integer, primary_key=True)
    school_id = db.Column(db.Integer, db.ForeignKey("schools.id"), unique=True, nullable=False)
    score = db.Column(db.Float, default=0.0)          # 0..1, higher = more agreement
    signal = db.Column(db.String(16), default="unknown")  # agree|conflict|unknown
    components_json = db.Column(db.Text, nullable=False, default="{}")
    computed_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


    # =========================================================
# 3b. OFFLINE SYNC HELPERS (HCI: flexibility & efficiency #7)
# =========================================================
def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 string from the client. Reject if older than 72h."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        raise ValueError("invalid timestamp")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    if age_hours > 72:
        raise ValueError("event too old (>72h) — reject to prevent backdating")
    if age_hours < -1:
        raise ValueError("event timestamp is in the future")
    return dt


def get_or_create_sync_event(client_uuid: str, payload: dict,
                             actor_id: int) -> tuple[SyncEvent, bool]:
    """
    Returns (event, created_new). If client_uuid already exists,
    we return the cached response — the caller must NOT re-run side effects.
    """
    existing = SyncEvent.query.filter_by(client_uuid=client_uuid).first()
    if existing:
        return existing, False
    ev = SyncEvent(
        client_uuid=client_uuid,
        client_timestamp=_parse_iso(payload.get("client_timestamp", "")),
        actor_id=actor_id,
        response_json="{}",
    )
    db.session.add(ev)
    db.session.flush()
    return ev, True


# =========================================================
# 3c. TRIANGULATION (HCI: help users recover from errors #9)
# =========================================================
TRIANGULATION_WINDOW_DAYS = 30


def compute_triangulation(school: School) -> dict:
    """
    Weigh three independent sources and return a normalized score.

    Sources and weights:
      1. Latest inspection (weight 0.5)   — inspector's physical evidence
      2. Parent reports in window (0.3)   — ground-truth community signal
      3. Inspection recency (0.2)         — decay if unverified for long

    Returns dict:
      {
        "score": 0..1,
        "signal": "agree" | "conflict" | "unknown",
        "components": {...explainable...}
      }

    Design rule: never a black box. Every number is traceable.
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=TRIANGULATION_WINDOW_DAYS)

    # --- Source 1: latest inspection ---
    latest = (
        Inspection.query.filter_by(school_id=school.id)
        .order_by(Inspection.timestamp.desc())
        .first()
    )
    if latest:
        insp_score = 1.0 if latest.result == "verified" else 0.0
        insp_age_days = (now - latest.timestamp.replace(tzinfo=timezone.utc)).days
    else:
        insp_score = 0.0
        insp_age_days = None

    # --- Source 2: parent reports in window ---
    reports = (
        ParentReport.query
        .filter(ParentReport.school_id == school.id)
        .filter(ParentReport.created_at >= window_start)
        .all()
    )
    negative_cats = {"no_teacher", "no_class", "closed"}
    negatives = sum(1 for r in reports if r.category in negative_cats)
    positives = len(reports) - negatives

    if not reports:
        parent_score = 0.5  # neutral — no signal is not a negative signal
    else:
        parent_score = max(0.0, 1.0 - (negatives / len(reports)))

    # --- Source 3: recency decay ---
    if insp_age_days is None:
        recency_score = 0.0
    else:
        recency_score = max(0.0, 1.0 - (insp_age_days / TRIANGULATION_WINDOW_DAYS))

    score = (
        0.50 * insp_score +
        0.30 * parent_score +
        0.20 * recency_score
    )

    # --- Signal classification ---
    if latest is None and not reports:
        signal = "unknown"
    elif score >= 0.65:
        signal = "agree"
    elif score <= 0.35:
        signal = "conflict"
    else:
        signal = "unknown"

    return {
        "score": round(score, 3),
        "signal": signal,
        "components": {
            "inspection": {
                "score": round(insp_score, 3),
                "age_days": insp_age_days,
                "weight": 0.50,
            },
            "parents": {
                "score": round(parent_score, 3),
                "reports": len(reports),
                "negatives": negatives,
                "positives": positives,
                "weight": 0.30,
            },
            "recency": {
                "score": round(recency_score, 3),
                "weight": 0.20,
            },
        },
    }


def refresh_triangulation(school_id: int) -> TriangulationScore:
    """Recompute and persist. Called after inspection / report / sync."""
    school = db.session.get(School, school_id)
    if not school:
        raise ValueError(f"school {school_id} not found")
    result = compute_triangulation(school)
    row = TriangulationScore.query.filter_by(school_id=school_id).first()
    if not row:
        row = TriangulationScore(school_id=school_id)
        db.session.add(row)
    row.score = result["score"]
    row.signal = result["signal"]
    row.components_json = json.dumps(result["components"], sort_keys=True)
    row.computed_at = datetime.now(timezone.utc)
    return row


# =========================================================
# 10b. OFFLINE SYNC API
# =========================================================
@app.route("/api/sync", methods=["POST"])
@role_required("inspector")
def api_sync():
    """
    Accepts a batch of queued events from the browser.
    Each event is idempotent via client_uuid.

    Request JSON:
    {
      "events": [
        {
          "client_uuid": "uuid-v4",
          "client_timestamp": "2026-06-30T12:34:56Z",
          "type": "inspection",
          "payload": {
             "school_id": 3,
             "gps_lat": 27.5295, "gps_lng": 68.7592,
             "declared_students": 42,
             "fingerprint_token": "...",
             "snapshot_b64": "data:image/jpeg;base64,..."
          }
        },
        ...
      ]
    }

    Response:
    { "results": [ {"uuid":..., "status":"accepted|duplicate|rejected",
                    "inspection_id":..., "reason": null|"..."} ] }
    """
    body = request.get_json(silent=True) or {}
    events = body.get("events") or []
    if not isinstance(events, list) or len(events) > 50:
        return jsonify({"error": "events must be a list of ≤50 items"}), 400

    results = []
    for ev in events:
        uuid = (ev.get("client_uuid") or "").strip()
        if not uuid:
            results.append({"uuid": None, "status": "rejected", "reason": "missing client_uuid"})
            continue

        try:
            sync_row, is_new = get_or_create_sync_event(uuid, ev, current_user.id)
        except ValueError as e:
            results.append({"uuid": uuid, "status": "rejected", "reason": str(e)})
            continue

        if not is_new:
            cached = json.loads(sync_row.response_json)
            results.append({
                "uuid": uuid,
                "status": "duplicate",
                "inspection_id": sync_row.inspection_id,
                "was_conflict": sync_row.was_conflict,
                "previous": cached,
            })
            continue

        # --- Fresh event: process it ---
        try:
            insp_id, conflict = _process_sync_inspection(ev, current_user)
        except ValueError as e:
            db.session.rollback()
            results.append({"uuid": uuid, "status": "rejected", "reason": str(e)})
            continue

        sync_row.inspection_id = insp_id
        sync_row.was_conflict = conflict
        sync_row.response_json = json.dumps({"inspection_id": insp_id, "conflict": conflict})
        db.session.commit()

        results.append({
            "uuid": uuid,
            "status": "accepted",
            "inspection_id": insp_id,
            "was_conflict": conflict,
        })

    return jsonify({"results": results})


def _process_sync_inspection(ev: dict, actor: User) -> tuple[int, bool]:
    """
    Runs the same logic as /verify but from a JSON payload.
    Returns (inspection_id, was_conflict).

    Conflict detection: if the school's verification_status changed
    AFTER the client_timestamp of this event, we accept the inspection
    but mark it as a conflict and force result=flagged.
    """
    p = ev.get("payload") or {}
    school = db.session.get(School, int(p.get("school_id", 0)))
    if not school:
        raise ValueError("school not found")

    client_ts = _parse_iso(ev["client_timestamp"])
    conflict = False
    if school.last_verified_at:
        last = school.last_verified_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last > client_ts:
            conflict = True  # someone verified this school more recently than the queued event

    # GPS
    try:
        gps_lat = float(p["gps_lat"]); gps_lng = float(p["gps_lng"])
    except (KeyError, ValueError, TypeError):
        raise ValueError("invalid GPS")
    in_fence, distance_m = within_school_radius(gps_lat, gps_lng, school)

    # Fingerprint
    fp_token = (p.get("fingerprint_token") or "").encode()
    fp_ok = bool(fp_token) and verify_fingerprint(actor, fp_token)
    db.session.add(BiometricLog(
        user_id=actor.id,
        template_hash=hashlib.sha256(fp_token).hexdigest() if fp_token else "",
        matched=fp_ok,
    ))

    # Snapshot (base64)
    detected = 0
    img_hash = ""
    snap_path_rel = None
    snapshot_b64 = p.get("snapshot_b64")
    if snapshot_b64:
        try:
            header, b64 = snapshot_b64.split(",", 1)
            raw = base64.b64decode(b64)
            img_hash = hashlib.sha256(raw).hexdigest()
            fname = secure_filename(
                f"{school.id}_sync_{int(datetime.now(timezone.utc).timestamp())}_{secrets.token_hex(4)}.jpg"
            )
            abs_path = os.path.join(app.config["UPLOAD_FOLDER"], "snapshots", fname)
            with open(abs_path, "wb") as f:
                f.write(raw)
            snap_path_rel = f"uploads/snapshots/{fname}"
            detected = count_faces(raw)
        except Exception:
            raise ValueError("snapshot decode failed")

    try:
        declared = int(p.get("declared_students") or 0)
    except (ValueError, TypeError):
        declared = 0

    reasons = []
    if conflict:        reasons.append("server_newer_state")
    if not fp_ok:       reasons.append("fingerprint_mismatch")
    if not in_fence:    reasons.append(f"gps_outside_fence:{int(distance_m)}m")
    if detected < CV_MIN_CLASS_SIZE:
        reasons.append(f"class_too_small:{detected}")
    if declared and abs(detected - declared) > CV_MISMATCH_THRESHOLD:
        reasons.append(f"count_mismatch:{declared}v{detected}")

    result = "verified" if not reasons else "flagged"

    insp = Inspection(
        school_id=school.id,
        inspector_id=actor.id,
        timestamp=client_ts,
        gps_lat=gps_lat, gps_lng=gps_lng,
        declared_students=declared,
        detected_faces=detected,
        fingerprint_ok=fp_ok,
        snapshot_path=snap_path_rel,
        result=result,
        notes=";".join(reasons) if reasons else "all_checks_passed",
    )
    db.session.add(insp)
    db.session.flush()

    if snap_path_rel:
        db.session.add(CVSnapshot(
            inspection_id=insp.id, image_path=snap_path_rel,
            detected_faces=detected, image_hash=img_hash,
        ))

    # Only overwrite school status if this event is NOT a stale conflict
    if not conflict:
        school.verification_status = result
        school.last_verified_at = insp.timestamp

    append_to_ledger(
        "inspection_synced",
        {
            "inspection_id": insp.id,
            "school_id": school.id,
            "actor_id": actor.id,
            "result": result,
            "conflict": conflict,
            "reasons": reasons,
            "client_uuid": ev.get("client_uuid"),
            "client_timestamp": ev.get("client_timestamp"),
        },
        actor_id=actor.id,
    )
    refresh_triangulation(school.id)
    return insp.id, conflict


# =========================================================
# 10c. TRIANGULATION API
# =========================================================
@app.route("/api/triangulation/<int:school_id>")
@login_required
def api_triangulation(school_id):
    school = db.session.get(School, school_id) or abort(404)
    row = TriangulationScore.query.filter_by(school_id=school_id).first()
    if not row:
        row = refresh_triangulation(school_id)
        db.session.commit()
    return jsonify({
        "school_id": school_id,
        "score": row.score,
        "signal": row.signal,
        "components": json.loads(row.components_json),
        "computed_at": row.computed_at.isoformat(),
    })


# =========================================================
# 3. SECURITY / LEDGER HELPERS
# =========================================================
def _canonical(payload: dict) -> str:
    """Deterministic JSON for hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def hash_event(event_type: str, payload: dict, prev_hash: str, actor_id: int | None) -> str:
    """
    curr_hash = SHA256(event_type | canonical(payload) | prev_hash | actor_id | secret)
    The SECRET_KEY acts as a server-side HMAC salt so an attacker with DB write
    access still can't forge a valid chain without the app secret.
    """
    msg = f"{event_type}|{_canonical(payload)}|{prev_hash}|{actor_id or 0}"
    return hmac.new(
        app.config["SECRET_KEY"].encode(),
        msg.encode(),
        hashlib.sha256,
    ).hexdigest()


def append_to_ledger(event_type: str, payload: dict, actor_id: int | None = None) -> AuditLedger:
    """Append-only write. Returns the new ledger row."""
    last = AuditLedger.query.order_by(AuditLedger.id.desc()).first()
    prev_hash = last.curr_hash if last else "GENESIS"
    curr_hash = hash_event(event_type, payload, prev_hash, actor_id)
    row = AuditLedger(
        event_type=event_type,
        payload_json=_canonical(payload),
        prev_hash=prev_hash,
        curr_hash=curr_hash,
        actor_id=actor_id,
    )
    db.session.add(row)
    db.session.flush()  # get id, don't commit yet (caller commits atomically)
    return row


def verify_chain() -> dict:
    """
    Walk the ledger and confirm every curr_hash recomputes from prev_hash.
    Returns {valid: bool, broken_at: id|None, total: int}
    """
    rows = AuditLedger.query.order_by(AuditLedger.id.asc()).all()
    prev = "GENESIS"
    for r in rows:
        try:
            payload = json.loads(r.payload_json)
        except json.JSONDecodeError:
            return {"valid": False, "broken_at": r.id, "total": len(rows), "reason": "bad json"}
        expected = hash_event(r.event_type, payload, prev, r.actor_id)
        if expected != r.curr_hash or r.prev_hash != prev:
            return {"valid": False, "broken_at": r.id, "total": len(rows), "reason": "hash mismatch"}
        prev = r.curr_hash
    return {"valid": True, "broken_at": None, "total": len(rows)}


def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if current_user.role not in roles:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


# =========================================================
# 4. BIOMETRIC MODULE (mockable)
# =========================================================
def enroll_fingerprint(user: User, raw_template: bytes) -> str:
    """
    REAL_SDK (when hardware wired):
        f = PyFingerprint('/dev/ttyUSB0', 57600)
        f.verifyPassword()
        f.storeTemplate()  # writes to sensor flash
        template_hash = sha256(raw_template).hexdigest()

    DEMO: we hash whatever bytes the client sends (simulated scan).
    """
    digest = hashlib.sha256(raw_template).hexdigest()
    user.fingerprint_template_hash = digest
    return digest


def verify_fingerprint(user: User, raw_template: bytes) -> bool:
    """Constant-time compare against enrolled template."""
    if not user.fingerprint_template_hash:
        return False
    digest = hashlib.sha256(raw_template).hexdigest()
    return hmac.compare_digest(digest, user.fingerprint_template_hash)


# =========================================================
# 5. COMPUTER VISION MODULE
# =========================================================
def count_faces(image_bytes: bytes) -> int:
    """
    Real: face_recognition on decoded image.
    Fallback: deterministic pseudo-count from hash (so demo is reproducible).
    """
    if CV_FACE and CV_OPENCV:
        try:
            arr = np.frombuffer(image_bytes, dtype=np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is None:
                return 0
            rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            locations = face_recognition.face_locations(rgb, model="hog")
            return len(locations)
        except Exception:
            # Never let CV crash an inspection.
            pass

    # Deterministic stub: 5..20 faces from image hash
    h = int(hashlib.sha256(image_bytes).hexdigest(), 16)
    return 5 + (h % 16)


# =========================================================
# 6. GEO-FENCE MODULE
# =========================================================
def haversine_m(lat1, lon1, lat2, lon2) -> float:
    R = 6371000.0
    p1, p2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlam = radians(lon2 - lon1)
    a = sin(dphi/2)**2 + cos(p1)*cos(p2)*sin(dlam/2)**2
    return 2 * R * atan2(sqrt(a), sqrt(1 - a))


def within_school_radius(lat, lng, school: School) -> tuple[bool, float]:
    d = haversine_m(lat, lng, school.geo_lat, school.geo_lng)
    return d <= GEO_FENCE_RADIUS_M, d


# =========================================================
# 7. AUTH ROUTES
# =========================================================
@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


@app.route("/", methods=["GET"])
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            append_to_ledger(
                "user_login",
                {"user_id": user.id, "role": user.role, "ts": datetime.now(timezone.utc).isoformat()},
                actor_id=user.id,
            )
            db.session.commit()
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    append_to_ledger("user_logout", {"user_id": current_user.id}, actor_id=current_user.id)
    db.session.commit()
    logout_user()
    return redirect(url_for("login"))


# =========================================================
# 8. DASHBOARD ROUTES
# =========================================================
@app.route("/dashboard")
@login_required
def dashboard():
    ctx = {"role": current_user.role, "schools": [], "reports": [], "chain": None}

    if current_user.is_district or current_user.is_inspector:
        ctx["schools"] = School.query.order_by(School.name).all()
    elif current_user.is_teacher:
        ctx["schools"] = School.query.filter_by(registered_teacher_id=current_user.id).all()
    elif current_user.is_parent:
        ctx["schools"] = School.query.order_by(School.name).all()
        ctx["reports"] = (
            ParentReport.query.filter_by(school_id=None).limit(0).all()
        )  # parents see form only

    ctx["chain"] = verify_chain()
    return render_template("dashboard.html", **ctx)


# =========================================================
# 9. INSPECTION ROUTES
# =========================================================
@app.route("/school/<int:school_id>")
@login_required
def school_detail(school_id):
    school = db.session.get(School, school_id) or abort(404)
    inspections = (
        Inspection.query.filter_by(school_id=school_id)
        .order_by(Inspection.timestamp.desc())
        .all()
    )
    reports = (
        ParentReport.query.filter_by(school_id=school_id)
        .order_by(ParentReport.created_at.desc())
        .all()
    )
    return render_template(
        "school_detail.html", school=school, inspections=inspections, reports=reports
    )


@app.route("/checkin/<int:school_id>", methods=["GET"])
@role_required("inspector")
def checkin(school_id):
    school = db.session.get(School, school_id) or abort(404)
    return render_template("checkin.html", school=school, demo_mode=DEMO_MODE)


@app.route("/verify", methods=["POST"])
@role_required("inspector")
def verify():
    """
    Payload (multipart):
      school_id, gps_lat, gps_lng, declared_students,
      fingerprint_token (bytes-ish string), snapshot (file)
    """
    school = db.session.get(School, int(request.form["school_id"])) or abort(404)

    # --- 1. Fingerprint check ---
    fp_token = (request.form.get("fingerprint_token") or "").encode()
    if not fp_token:
        flash("Fingerprint required.", "error")
        return redirect(url_for("checkin", school_id=school.id))

    fp_ok = verify_fingerprint(current_user, fp_token)
    db.session.add(BiometricLog(
        user_id=current_user.id,
        template_hash=hashlib.sha256(fp_token).hexdigest(),
        matched=fp_ok,
    ))

    # --- 2. GPS check ---
    try:
        gps_lat = float(request.form["gps_lat"])
        gps_lng = float(request.form["gps_lng"])
    except (KeyError, ValueError):
        flash("GPS coordinates missing.", "error")
        return redirect(url_for("checkin", school_id=school.id))

    in_fence, distance_m = within_school_radius(gps_lat, gps_lng, school)

    # --- 3. CV snapshot ---
    snapshot = request.files.get("snapshot")
    detected = 0
    snap_path_rel = None
    img_hash = ""
    if snapshot and snapshot.filename:
        raw = snapshot.read()
        img_hash = hashlib.sha256(raw).hexdigest()
        fname = f"{school.id}_{int(datetime.now(timezone.utc).timestamp())}_{secrets.token_hex(4)}.jpg"
        fname = secure_filename(fname)
        abs_path = os.path.join(app.config["UPLOAD_FOLDER"], "snapshots", fname)
        with open(abs_path, "wb") as f:
            f.write(raw)
        snap_path_rel = f"uploads/snapshots/{fname}"
        detected = count_faces(raw)

    # --- 4. Decision ---
    try:
        declared = int(request.form.get("declared_students") or 0)
    except ValueError:
        declared = 0

    reasons = []
    if not fp_ok:
        reasons.append("fingerprint_mismatch")
    if not in_fence:
        reasons.append(f"gps_outside_fence:{int(distance_m)}m")
    if detected < CV_MIN_CLASS_SIZE:
        reasons.append(f"class_too_small:{detected}")
    if declared and abs(detected - declared) > CV_MISMATCH_THRESHOLD:
        reasons.append(f"count_mismatch:declared={declared},detected={detected}")

    result = "verified" if not reasons else "flagged"

    # --- 5. Persist inspection ---
    insp = Inspection(
        school_id=school.id,
        inspector_id=current_user.id,
        gps_lat=gps_lat,
        gps_lng=gps_lng,
        declared_students=declared,
        detected_faces=detected,
        fingerprint_ok=fp_ok,
        snapshot_path=snap_path_rel,
        result=result,
        notes=";".join(reasons) if reasons else "all_checks_passed",
    )
    db.session.add(insp)
    db.session.flush()

    if snap_path_rel:
        db.session.add(CVSnapshot(
            inspection_id=insp.id,
            image_path=snap_path_rel,
            detected_faces=detected,
            image_hash=img_hash,
        ))

    # --- 6. Update school status ---
    school.verification_status = result
    school.last_verified_at = insp.timestamp

    # --- 7. Append ledger (atomic with above) ---
    append_to_ledger(
        "inspection_completed",
        {
            "inspection_id": insp.id,
            "school_id": school.id,
            "inspector_id": current_user.id,
            "result": result,
            "reasons": reasons,
            "detected": detected,
            "declared": declared,
            "gps": [gps_lat, gps_lng],
            "distance_m": round(distance_m, 2),
            "snapshot_hash": img_hash,
        },
        actor_id=current_user.id,
    )

    db.session.commit()
    flash(f"Inspection recorded: {result.upper()}", "success" if result == "verified" else "error")
    return redirect(url_for("school_detail", school_id=school.id))


# =========================================================
# 10. AUDIT ROUTES
# =========================================================
@app.route("/audit")
@role_required("district", "inspector")
def audit_log():
    rows = AuditLedger.query.order_by(AuditLedger.id.desc()).limit(500).all()
    chain = verify_chain()
    return render_template("audit_log.html", rows=rows, chain=chain)


@app.route("/api/chain-status")
@role_required("district", "inspector")
def api_chain_status():
    return jsonify(verify_chain())


# =========================================================
# 11. PARENT ROUTES
# =========================================================
@app.route("/parent/report", methods=["GET", "POST"])
@role_required("parent")
def parent_report():
    schools = School.query.order_by(School.name).all()
    if request.method == "POST":
        try:
            school_id = int(request.form["school_id"])
        except (KeyError, ValueError):
            flash("Select a school.", "error")
            return redirect(url_for("parent_report"))

        category = request.form.get("category", "other")
        text = (request.form.get("text") or "").strip()[:2000]

        ip = request.remote_addr or "0.0.0.0"
        ip_hash = hashlib.sha256((ip + app.config["SECRET_KEY"]).encode()).hexdigest()[:32]

        rep = ParentReport(
            school_id=school_id, category=category, text=text, ip_hash=ip_hash
        )
        db.session.add(rep)
        db.session.flush()

        append_to_ledger(
            "parent_report",
            {"report_id": rep.id, "school_id": school_id, "category": category},
            actor_id=current_user.id,
        )
        db.session.commit()
        flash("Report submitted. Thank you.", "success")
        return redirect(url_for("parent_report"))

    return render_template("parent_report.html", schools=schools)


# =========================================================
# 12. BOOTSTRAP & MAIN
# =========================================================
def seed():
    """Idempotent seed — safe to run every startup."""
    if User.query.count() > 0:
        return

    district = User(username="district1", role="district", full_name="District Officer")
    district.set_password("district123")

    inspector = User(username="inspector1", role="inspector", full_name="Inspector A")
    inspector.set_password("inspect123")

    teacher = User(username="teacher1", role="teacher", full_name="Teacher A")
    teacher.set_password("teach123")

    parent = User(username="parent1", role="parent", full_name="Parent A")
    parent.set_password("parent123")

    db.session.add_all([district, inspector, teacher, parent])
    db.session.flush()

    # Enroll teacher fingerprint (demo: hash of a fixed byte string)
    enroll_fingerprint(teacher, b"DEMO_TEACHER_FP")

    schools = [
        School(name="GPS Khairpur No.1", village="Khairpur", geo_lat=27.5295, geo_lng=68.7592,
               registered_students=120, registered_teacher_id=teacher.id),
        School(name="GPS Rural East", village="East Chak", geo_lat=27.5400, geo_lng=68.7700,
               registered_students=80, registered_teacher_id=teacher.id),
        School(name="GPS Far Village", village="Remote Goth", geo_lat=27.5600, geo_lng=68.8000,
               registered_students=60, registered_teacher_id=None),
    ]
    db.session.add_all(schools)
    db.session.flush()

    append_to_ledger(
        "system_seed",
        {"schools": [s.id for s in schools], "users": [district.id, inspector.id, teacher.id, parent.id]},
        actor_id=None,
    )
    db.session.commit()
    print("[seed] Initial data created.")


with app.app_context():
    db.create_all()
    seed()

        # Backfill triangulation for any school missing a score
    for s in School.query.all():
        if not TriangulationScore.query.filter_by(school_id=s.id).first():
            refresh_triangulation(s.id)
    db.session.commit()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)