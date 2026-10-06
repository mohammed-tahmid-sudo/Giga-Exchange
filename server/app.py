from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Optional

import qrcode
import uvicorn
from argon2 import PasswordHasher
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
CLIENT_DIR = BASE_DIR / "client"
DB_PATH = Path(os.getenv("GIGA_DB_PATH", str(BASE_DIR / "giga_exchange.db")))

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "GIGA_CORS_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://localhost:5173",
    ).split(",")
    if origin.strip()
]

PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32)
QR_SECRET = os.getenv("GIGA_QR_SECRET", "giga-exchange-demo-secret-change-me")
SESSION_TTL_DAYS = int(os.getenv("GIGA_SESSION_TTL_DAYS", "7"))
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


def expires_at_from_now(days: int = SESSION_TTL_DAYS) -> str:
    return (now_utc() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_login_attempts(phone_number: str) -> None:
    records = LOGIN_ATTEMPTS.get(phone_number, deque())
    cutoff = time.time() - (15 * 60)
    while records and records[0] <= cutoff:
        records.popleft()


def check_login_rate_limit(phone_number: str) -> None:
    clean_login_attempts(phone_number)
    records = LOGIN_ATTEMPTS.get(phone_number, deque())
    if len(records) >= 5:
        raise HTTPException(
            status_code=429,
            detail={
                "success": False,
                "error": {
                    "code": "RATE_LIMITED",
                    "message": "Too many login attempts. Please wait a few minutes and try again.",
                },
            },
        )
    records.append(time.time())


def normalize_phone_number(value: str) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        raise ValueError("Phone number is required")
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]
    if not cleaned.isdigit() or len(cleaned) < 8 or len(cleaned) > 15:
        raise ValueError("Phone number must be 8-15 digits and may include a leading + sign")
    return f"+{cleaned}"


def validate_username(value: str) -> str:
    username = (value or "").strip()
    if not username:
        raise ValueError("Username is required")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,24}", username):
        raise ValueError("Username must be 3-24 characters and may include letters, numbers, underscores, dots, or hyphens")
    return username


def parse_amount_to_cents(raw_amount: Any) -> int:
    if raw_amount is None:
        raise ValueError("Amount is required")
    if isinstance(raw_amount, bool):
        raise ValueError("Amount must be a valid number")
    if isinstance(raw_amount, int):
        value = Decimal(raw_amount)
    elif isinstance(raw_amount, str):
        value = Decimal(raw_amount)
    elif isinstance(raw_amount, float):
        value = Decimal(str(raw_amount))
    elif isinstance(raw_amount, Decimal):
        value = raw_amount
    else:
        raise ValueError("Amount must be a number")

    try:
        quantized = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except InvalidOperation as exc:
        raise ValueError("Amount must be a valid number") from exc

    if not quantized.is_finite():
        raise ValueError("Amount must be a valid number")
    if quantized <= 0:
        raise ValueError("Amount must be greater than zero")
    return int((quantized * Decimal("100")).to_integral_value())


def cents_to_gex_text(cents: int) -> str:
    return f"{Decimal(cents) / Decimal('100'):.2f} GEX"


def db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_database(force_reset: bool = False) -> None:
    if force_reset and DB_PATH.exists():
        DB_PATH.unlink()
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                phone_number TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                balance_cents INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
                currency TEXT NOT NULL DEFAULT 'GEX',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender_wallet_id INTEGER NOT NULL,
                receiver_wallet_id INTEGER NOT NULL,
                sender_user_id INTEGER NOT NULL,
                receiver_user_id INTEGER NOT NULL,
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                currency TEXT NOT NULL DEFAULT 'GEX',
                status TEXT NOT NULL DEFAULT 'completed',
                description TEXT,
                created_at TEXT NOT NULL,
                idempotency_key TEXT,
                FOREIGN KEY(sender_wallet_id) REFERENCES wallets(id),
                FOREIGN KEY(receiver_wallet_id) REFERENCES wallets(id),
                FOREIGN KEY(sender_user_id) REFERENCES users(id),
                FOREIGN KEY(receiver_user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                user_agent TEXT,
                ip_address TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS idempotency_keys (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                operation TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


ensure_database()


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        PASSWORD_HASHER.verify(password_hash, password)
        return True
    except Exception:
        return False


def get_user_by_phone(phone_number: str) -> Optional[sqlite3.Row]:
    with db_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE phone_number = ?", (phone_number,)).fetchone()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with db_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_wallet_for_user(user_id: int) -> Optional[sqlite3.Row]:
    with db_connection() as conn:
        return conn.execute("SELECT * FROM wallets WHERE user_id = ?", (user_id,)).fetchone()


def get_user_public(user: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "phone_number": user["phone_number"],
        "created_at": user["created_at"],
    }


def get_wallet_public(wallet: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": wallet["id"],
        "user_id": wallet["user_id"],
        "balance_cents": wallet["balance_cents"],
        "currency": wallet["currency"],
        "created_at": wallet["created_at"],
        "updated_at": wallet["updated_at"],
    }


def add_audit_log(user_id: int, action: str, details: dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
    should_close = conn is None
    if conn is None:
        conn = db_connection()
    try:
        conn.execute(
            "INSERT INTO audit_log (id, user_id, action, details_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (f"AUD-{secrets.token_hex(8).upper()}", user_id, action, json.dumps(details, separators=(",", ":")), iso_now()),
        )
        if should_close:
            conn.commit()
    finally:
        if should_close:
            conn.close()


def generate_qr_payload_for_user_id(user_id: int) -> str:
    timestamp = int(time.time())
    payload = f"{user_id}:{timestamp}"
    signature = hmac.new(QR_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"gigaexchange://pay?user={user_id}&ts={timestamp}&sig={signature}"


def resolve_qr_payload(payload: str) -> int:
    if not payload or not payload.startswith("gigaexchange://pay?"):
        raise ValueError("QR payload is invalid")

    data = payload.split("?", 1)[1]
    params: dict[str, str] = {}
    for item in data.split("&"):
        if not item:
            continue
        if "=" in item:
            key, value = item.split("=", 1)
            params[key] = value

    user_id = params.get("user")
    ts = params.get("ts")
    sig = params.get("sig")
    if not user_id or not ts or not sig:
        raise ValueError("QR payload is missing required fields")

    expected = hmac.new(QR_SECRET.encode("utf-8"), f"{user_id}:{ts}".encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("QR payload signature is invalid")

    try:
        user_id_int = int(user_id)
    except ValueError as exc:
        raise ValueError("QR payload user id is invalid") from exc

    if not get_user_by_id(user_id_int):
        raise ValueError("QR payload references a non-existent user")
    return user_id_int


def get_session_for_token(token: str) -> Optional[sqlite3.Row]:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with db_connection() as conn:
        return conn.execute("SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?", (token_hash, iso_now())).fetchone()


def create_session_for_user(user_id: int, user_agent: Optional[str], ip_address: Optional[str]) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    session_id = f"SES-{secrets.token_hex(8).upper()}"
    conn = db_connection()
    try:
        conn.execute(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, user_agent, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, user_id, token_hash, expires_at_from_now(), iso_now(), user_agent, ip_address),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def delete_session_for_token(token: str) -> None:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = db_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.commit()
    finally:
        conn.close()


async def get_current_user(request: Request) -> sqlite3.Row:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"success": False, "error": {"code": "UNAUTHENTICATED", "message": "Authentication required"}})

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail={"success": False, "error": {"code": "UNAUTHENTICATED", "message": "Authentication required"}})

    session = get_session_for_token(token)
    if not session:
        raise HTTPException(status_code=401, detail={"success": False, "error": {"code": "INVALID_TOKEN", "message": "Session is expired or invalid"}})

    user = get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail={"success": False, "error": {"code": "USER_NOT_FOUND", "message": "Account no longer exists"}})
    return user


class RegisterRequest(BaseModel):
    phone_number: str
    username: str
    password: str
    confirm_password: str

    model_config = ConfigDict(extra="ignore")

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        return normalize_phone_number(value)

    @field_validator("username")
    @classmethod
    def validate_username_field(cls, value: str) -> str:
        return validate_username(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return value

    @field_validator("confirm_password")
    @classmethod
    def validate_confirm_password(cls, value: str, info: Any) -> str:
        password = info.data.get("password")
        if password and value != password:
            raise ValueError("Passwords do not match")
        return value


class LoginRequest(BaseModel):
    phone_number: str
    password: str

    model_config = ConfigDict(extra="ignore")

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        return normalize_phone_number(value)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    model_config = ConfigDict(extra="ignore")

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("New password must be at least 8 characters long")
        return value


class TransferRequest(BaseModel):
    recipient_identifier: str = Field(..., alias="recipient")
    amount: Any
    description: str = ""
    idempotency_key: Optional[str] = None

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    @field_validator("recipient_identifier")
    @classmethod
    def validate_recipient_identifier(cls, value: str) -> str:
        if value is None:
            raise ValueError("Recipient is required")
        text = str(value).strip()
        if not text:
            raise ValueError("Recipient is required")
        return text

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        if value is None:
            return ""
        return str(value).strip()[:200]


class QRResolveRequest(BaseModel):
    payload: str


def response_json(status_code: int, success: bool, message: str, **payload) -> JSONResponse:
    body = {"success": success, "message": message}
    for key, value in payload.items():
        body[key] = value
    return JSONResponse(status_code=status_code, content=body)


def resolve_recipient_by_identifier(user_id: int, identifier: str) -> sqlite3.Row:
    value = str(identifier).strip()
    if not value:
        raise ValueError("Recipient is required")

    conn = db_connection()
    try:
        if value.isdigit():
            candidate = conn.execute("SELECT * FROM users WHERE id = ?", (int(value),)).fetchone()
            if candidate is not None:
                if candidate["id"] == user_id:
                    raise ValueError("You cannot send money to yourself")
                return candidate

        if value.startswith("+") or value.replace("+", "").isdigit():
            candidate = conn.execute("SELECT * FROM users WHERE phone_number = ?", (normalize_phone_number(value),)).fetchone()
            if candidate is not None:
                if candidate["id"] == user_id:
                    raise ValueError("You cannot send money to yourself")
                return candidate

        candidate = conn.execute("SELECT * FROM users WHERE username = ?", (value,)).fetchone()
        if candidate is not None:
            if candidate["id"] == user_id:
                raise ValueError("You cannot send money to yourself")
            return candidate

        if value.isdigit():
            candidate = conn.execute("SELECT * FROM users WHERE id = ?", (int(value),)).fetchone()
            if candidate is not None:
                if candidate["id"] == user_id:
                    raise ValueError("You cannot send money to yourself")
                return candidate

        raise ValueError("Recipient not found")
    finally:
        conn.close()


def ensure_demo_accounts() -> None:
    with db_connection() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if user_count > 0:
            return
        now = iso_now()
        demo_password_hash = hash_password("Password123!")
        conn.execute(
            "INSERT INTO users (username, phone_number, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("demo", "+15550000001", demo_password_hash, now, now),
        )
        conn.execute(
            "INSERT INTO users (username, phone_number, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("merchant", "+15550000002", demo_password_hash, now, now),
        )
        conn.execute(
            "INSERT INTO wallets (user_id, balance_cents, currency, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (1, 100000, "GEX", now, now),
        )
        conn.execute(
            "INSERT INTO wallets (user_id, balance_cents, currency, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (2, 250000, "GEX", now, now),
        )
        conn.commit()


ensure_demo_accounts()


def execute_transfer(sender_user_id: int, recipient_identifier: str, amount_value: Any, description: str = "", idempotency_key: Optional[str] = None) -> dict[str, Any]:
    amount_cents = parse_amount_to_cents(amount_value)

    if not recipient_identifier or not str(recipient_identifier).strip():
        raise ValueError("Recipient is required")

    if not isinstance(sender_user_id, int):
        raise ValueError("Sender is invalid")

    recipient_user = resolve_recipient_by_identifier(sender_user_id, recipient_identifier)
    if recipient_user["id"] == sender_user_id:
        raise ValueError("You cannot send money to yourself")

    conn = db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")

        sender_wallet = conn.execute("SELECT * FROM wallets WHERE user_id = ?", (sender_user_id,)).fetchone()
        if sender_wallet is None:
            raise ValueError("Sender wallet not found")
        if sender_wallet["balance_cents"] < amount_cents:
            raise ValueError("Insufficient balance")

        receiver_wallet = conn.execute("SELECT * FROM wallets WHERE user_id = ?", (recipient_user["id"],)).fetchone()
        if receiver_wallet is None:
            raise ValueError("Recipient wallet not found")

        normalized_key = (idempotency_key or "").strip()
        if normalized_key:
            existing = conn.execute(
                "SELECT * FROM idempotency_keys WHERE id = ? AND user_id = ?",
                (normalized_key, sender_user_id),
            ).fetchone()
            if existing is not None:
                tx_data = json.loads(existing["response_json"])
                conn.commit()
                return tx_data

        tx_id = f"TXN-{secrets.token_hex(4).upper()}"
        sender_new_balance = sender_wallet["balance_cents"] - amount_cents
        receiver_new_balance = receiver_wallet["balance_cents"] + amount_cents

        conn.execute(
            "UPDATE wallets SET balance_cents = ?, updated_at = ? WHERE id = ?",
            (sender_new_balance, iso_now(), sender_wallet["id"]),
        )
        conn.execute(
            "UPDATE wallets SET balance_cents = ?, updated_at = ? WHERE id = ?",
            (receiver_new_balance, iso_now(), receiver_wallet["id"]),
        )
        conn.execute(
            "INSERT INTO transactions (id, sender_wallet_id, receiver_wallet_id, sender_user_id, receiver_user_id, amount_cents, currency, status, description, created_at, idempotency_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tx_id,
                sender_wallet["id"],
                receiver_wallet["id"],
                sender_user_id,
                recipient_user["id"],
                amount_cents,
                "GEX",
                "completed",
                description[:200] if description else "",
                iso_now(),
                normalized_key or None,
            ),
        )

        response_payload = {
            "success": True,
            "message": "Transfer completed",
            "transaction": {
                "id": tx_id,
                "sender_user_id": sender_user_id,
                "receiver_user_id": recipient_user["id"],
                "amount_cents": amount_cents,
                "amount_gex": f"{Decimal(amount_cents) / Decimal('100'):.2f}",
                "currency": "GEX",
                "status": "completed",
                "description": description[:200] if description else "",
                "created_at": iso_now(),
            },
        }

        if normalized_key:
            conn.execute(
                "INSERT INTO idempotency_keys (id, user_id, operation, response_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (normalized_key, sender_user_id, "transfer", json.dumps(response_payload, separators=(",", ":")), iso_now()),
            )

        add_audit_log(sender_user_id, "transfer_sent", {"recipient_user_id": recipient_user["id"], "amount_cents": amount_cents}, conn=conn)
        add_audit_log(recipient_user["id"], "transfer_received", {"sender_user_id": sender_user_id, "amount_cents": amount_cents}, conn=conn)
        conn.commit()
        return response_payload
    except ValueError:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


app = FastAPI(title="Giga Exchange API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 1024 * 1024:
        return JSONResponse(status_code=413, content={"success": False, "error": {"code": "PAYLOAD_TOO_LARGE", "message": "Request body is too large"}})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src 'self';"
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/")
def home() -> FileResponse:
    return FileResponse(CLIENT_DIR / "index.html")


app.mount("/client", StaticFiles(directory=str(CLIENT_DIR)), name="client")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "giga-exchange"}


@app.post("/api/auth/register")
def register_user(payload: RegisterRequest):
    phone_number = payload.phone_number
    username = payload.username

    conn = db_connection()
    try:
        existing_user = conn.execute(
            "SELECT id FROM users WHERE phone_number = ? OR username = ?",
            (phone_number, username),
        ).fetchone()
        if existing_user is not None:
            raise HTTPException(
                status_code=409,
                detail={"success": False, "error": {"code": "USER_EXISTS", "message": "A user with that phone number or username already exists"}},
            )

        now = iso_now()
        user_id = conn.execute(
            "INSERT INTO users (username, phone_number, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (username, phone_number, hash_password(payload.password), now, now),
        ).lastrowid
        conn.execute(
            "INSERT INTO wallets (user_id, balance_cents, currency, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, 0, "GEX", now, now),
        )
        conn.commit()

        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        wallet_row = conn.execute("SELECT * FROM wallets WHERE user_id = ?", (user_id,)).fetchone()
        add_audit_log(user_id, "registered", {"phone_number": phone_number, "username": username}, conn=conn)
        return response_json(
            status_code=201,
            success=True,
            message="Account created successfully",
            user=get_user_public(user_row),
            wallet=get_wallet_public(wallet_row),
        )
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        raise HTTPException(status_code=500, detail={"success": False, "error": {"code": "REGISTRATION_FAILED", "message": str(exc)}})
    finally:
        conn.close()


@app.post("/api/auth/login")
def login_user(payload: LoginRequest):
    phone_number = payload.phone_number
    check_login_rate_limit(phone_number)

    user = get_user_by_phone(phone_number)
    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=401,
            detail={"success": False, "error": {"code": "INVALID_CREDENTIALS", "message": "Invalid phone number or password"}},
        )

    LOGIN_ATTEMPTS[phone_number].clear()
    token = create_session_for_user(user["id"], "Unknown", "local")
    wallet = get_wallet_for_user(user["id"])
    return response_json(
        status_code=200,
        success=True,
        message="Login successful",
        token=token,
        expires_at=expires_at_from_now(),
        user=get_user_public(user),
        wallet=get_wallet_public(wallet),
    )


@app.post("/api/auth/logout")
def logout_user(request: Request, current_user: sqlite3.Row = Depends(get_current_user)):
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        delete_session_for_token(auth_header.split(" ", 1)[1].strip())
    return response_json(status_code=200, success=True, message="Logged out successfully")


@app.post("/api/auth/change-password")
def change_password(request: Request, payload: ChangePasswordRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    user = get_user_by_id(current_user["id"])
    if user is None:
        raise HTTPException(status_code=404, detail={"success": False, "error": {"code": "USER_NOT_FOUND", "message": "User not found"}})
    if not verify_password(payload.current_password, user["password_hash"]):
        raise HTTPException(status_code=401, detail={"success": False, "error": {"code": "INVALID_CURRENT_PASSWORD", "message": "Current password is incorrect"}})

    conn = db_connection()
    try:
        conn.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", (hash_password(payload.new_password), iso_now(), user["id"]))
        conn.commit()
        add_audit_log(user["id"], "password_changed", {"user_id": user["id"]}, conn=conn)
        return response_json(status_code=200, success=True, message="Password changed successfully")
    finally:
        conn.close()


@app.get("/api/users/me")
def get_my_profile(current_user: sqlite3.Row = Depends(get_current_user)):
    wallet = get_wallet_for_user(current_user["id"])
    return response_json(
        status_code=200,
        success=True,
        message="Profile loaded",
        user=get_user_public(current_user),
        wallet=get_wallet_public(wallet),
    )


@app.get("/api/users/{user_id}")
def get_user_by_path(user_id: int, current_user: sqlite3.Row = Depends(get_current_user)):
    if user_id != current_user["id"]:
        raise HTTPException(status_code=403, detail={"success": False, "error": {"code": "FORBIDDEN", "message": "You can only access your own account"}})
    wallet = get_wallet_for_user(user_id)
    return response_json(status_code=200, success=True, message="User found", user=get_user_public(current_user), wallet=get_wallet_public(wallet))


@app.get("/api/wallet")
def get_wallet(current_user: sqlite3.Row = Depends(get_current_user)):
    wallet = get_wallet_for_user(current_user["id"])
    if wallet is None:
        raise HTTPException(status_code=404, detail={"success": False, "error": {"code": "WALLET_NOT_FOUND", "message": "Wallet not found"}})
    return response_json(status_code=200, success=True, message="Wallet retrieved", data=get_wallet_public(wallet))


@app.get("/api/transactions")
def get_transactions(current_user: sqlite3.Row = Depends(get_current_user)):
    conn = db_connection()
    try:
        rows = conn.execute(
            """
            SELECT t.*, sw.user_id AS sender_user_id, rw.user_id AS receiver_user_id,
                   sender.username AS sender_username,
                   receiver.username AS receiver_username
            FROM transactions t
            INNER JOIN wallets sw ON sw.id = t.sender_wallet_id
            INNER JOIN wallets rw ON rw.id = t.receiver_wallet_id
            INNER JOIN users sender ON sender.id = sw.user_id
            INNER JOIN users receiver ON receiver.id = rw.user_id
            WHERE sw.user_id = ? OR rw.user_id = ?
            ORDER BY t.created_at DESC
            """,
            (current_user["id"], current_user["id"]),
        ).fetchall()

        transactions = []
        for row in rows:
            direction = "sent" if row["sender_user_id"] == current_user["id"] else "received"
            transactions.append(
                {
                    "id": row["id"],
                    "direction": direction,
                    "sender": {"id": row["sender_user_id"], "username": row["sender_username"]},
                    "receiver": {"id": row["receiver_user_id"], "username": row["receiver_username"]},
                    "amount_cents": row["amount_cents"],
                    "amount_gex": f"{Decimal(row['amount_cents']) / Decimal('100'):.2f}",
                    "currency": row["currency"],
                    "status": row["status"],
                    "description": row["description"],
                    "created_at": row["created_at"],
                }
            )
        return response_json(status_code=200, success=True, message="Transactions retrieved", data=transactions, count=len(transactions))
    finally:
        conn.close()


@app.post("/api/transactions/transfer")
def transfer_money(payload: TransferRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        body = execute_transfer(current_user["id"], payload.recipient_identifier, payload.amount, payload.description, payload.idempotency_key)
        return response_json(status_code=200, success=True, message=body["message"], transaction=body["transaction"])
    except ValueError as exc:
        message = str(exc)
        code = "INVALID_TRANSFER"
        status = 400
        if "Insufficient balance" in message:
            code = "INSUFFICIENT_FUNDS"
        elif "Recipient not found" in message:
            code = "RECIPIENT_NOT_FOUND"
        elif "You cannot send money to yourself" in message:
            code = "SELF_TRANSFER"
        elif "Amount must be greater than zero" in message or "Amount must be a valid number" in message:
            code = "INVALID_AMOUNT"
            status = 422
        raise HTTPException(status_code=status, detail={"success": False, "error": {"code": code, "message": message}})


@app.get("/api/qr/me")
def get_my_qr(current_user: sqlite3.Row = Depends(get_current_user)):
    payload = generate_qr_payload_for_user_id(current_user["id"])
    qr_image = qrcode.make(payload)
    buffered = io.BytesIO()
    qr_image.save(buffered, format="PNG")
    encoded = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return response_json(status_code=200, success=True, message="QR code generated", data={"payload": payload, "qr_data_url": f"data:image/png;base64,{encoded}"})


@app.post("/api/qr/resolve")
def resolve_qr(payload: QRResolveRequest):
    try:
        user_id = resolve_qr_payload(payload.payload)
        user = get_user_by_id(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail={"success": False, "error": {"code": "USER_NOT_FOUND", "message": "QR code targets an unknown user"}})
        return response_json(status_code=200, success=True, message="QR code resolved", user=get_user_public(user))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"success": False, "error": {"code": "INVALID_QR", "message": str(exc)}})


@app.post("/api/admin/demo-fund")
async def demo_fund(request: Request):
    token = os.getenv("GIGA_ADMIN_TOKEN")
    header = request.headers.get("X-Admin-Token")
    if os.getenv("GIGA_ENV", "development") == "production":
        raise HTTPException(status_code=403, detail={"success": False, "error": {"code": "FORBIDDEN", "message": "Demo funding is disabled in production"}})
    if not token or not header or header != token:
        raise HTTPException(status_code=401, detail={"success": False, "error": {"code": "UNAUTHORIZED", "message": "Admin token required"}})

    body = await request.json()
    username = body.get("username") if hasattr(body, "get") else None
    if username is None:
        raise HTTPException(status_code=400, detail={"success": False, "error": {"code": "BAD_REQUEST", "message": "username is required"}})

    amount_raw = body.get("amount", body.get("amount_cents", 100000)) if hasattr(body, "get") else 100000
    try:
        amount_cents = parse_amount_to_cents(amount_raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"success": False, "error": {"code": "INVALID_AMOUNT", "message": str(exc)}}) from exc

    conn = db_connection()
    try:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            raise HTTPException(status_code=404, detail={"success": False, "error": {"code": "USER_NOT_FOUND", "message": "User does not exist"}})
        conn.execute("UPDATE wallets SET balance_cents = balance_cents + ?, updated_at = ? WHERE user_id = ?", (amount_cents, iso_now(), user["id"]))
        conn.commit()
        wallet = conn.execute("SELECT * FROM wallets WHERE user_id = ?", (user["id"],)).fetchone()
        add_audit_log(user["id"], "admin_demo_fund", {"amount_cents": amount_cents, "admin_token_used": True}, conn=conn)
        return response_json(status_code=200, success=True, message="Demo funds added", wallet=get_wallet_public(wallet))
    finally:
        conn.close()


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"success": False, "error": {"code": "HTTP_ERROR", "message": str(exc.detail)}}
    return JSONResponse(status_code=exc.status_code, content=detail)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Giga Exchange API")
    parser.add_argument("--init-db", action="store_true", help="Create the SQLite database schema and seed demo data")
    parser.add_argument("--reset-db", action="store_true", help="Reset the database before creating the schema")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if args.reset_db:
        ensure_database(force_reset=True)
        ensure_demo_accounts()
        print("Database reset and initialized.")
        raise SystemExit(0)

    if args.init_db:
        ensure_database()
        ensure_demo_accounts()
        print("Database initialized.")
        raise SystemExit(0)

    uvicorn.run("server.app:app", host=args.host, port=args.port, reload=True)
