import hashlib
import os
import re
import secrets
import sqlite3
import sys
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, field_validator


DATABASE_PATH = os.environ.get(
    "WALLET_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wallet.db"),
)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
MIN_PASSWORD_LENGTH = 8
MAX_AMOUNT_PRECISION = 2

app = FastAPI(title="Science Fair Wallet API", version="1.0.0")


class RegisterRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Username cannot be empty")
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Username must be 3-20 characters and use only letters, numbers, or underscores")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < MIN_PASSWORD_LENGTH:
            raise ValueError("Password must be at least 8 characters long")
        return value


class LoginRequest(BaseModel):
    username: str
    password: str


class TransferRequest(BaseModel):
    receiver: str
    amount: Decimal

    model_config = ConfigDict(extra="ignore")

    @field_validator("receiver")
    @classmethod
    def validate_receiver(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Receiver username is required")
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Receiver username is invalid")
        return value

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, value: Decimal) -> Decimal:
        return validate_decimal_amount(value, allow_zero=False)


def now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def json_number(value: Any) -> Any:
    if isinstance(value, Decimal):
        as_float = float(value)
        if as_float.is_integer():
            return int(as_float)
        return round(as_float, MAX_AMOUNT_PRECISION)
    if isinstance(value, (int, float)):
        if float(value).is_integer():
            return int(value)
        return round(float(value), MAX_AMOUNT_PRECISION)
    return value


def validate_decimal_amount(value: Any, allow_zero: bool = False) -> Decimal:
    if value is None:
        raise ValueError("Amount is required")
    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("Amount must be a valid number")
    if not decimal_value.is_finite():
        raise ValueError("Amount must be a valid number")
    if decimal_value < 0:
        raise ValueError("Amount cannot be negative")
    if allow_zero:
        if decimal_value < 0:
            raise ValueError("Amount cannot be negative")
    else:
        if decimal_value <= 0:
            raise ValueError("Amount must be greater than zero")
    exponent = decimal_value.as_tuple().exponent
    if exponent < -MAX_AMOUNT_PRECISION:
        raise ValueError("Amount has too many decimal places")
    return decimal_value.quantize(Decimal("0.01"))


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_database(force_reset: bool = False) -> None:
    global DATABASE_PATH

    if force_reset and os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)

    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)

    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0 CHECK (balance >= 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                amount REAL NOT NULL CHECK (amount > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                previous_balance REAL NOT NULL,
                new_balance REAL NOT NULL,
                amount_changed REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


initialize_database()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt, digest_hex = password_hash.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    try:
        iterations_int = int(iterations)
    except ValueError:
        return False
    new_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations_int,
    )
    return new_digest.hex() == digest_hex


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return row
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return row
    finally:
        conn.close()


def get_user_public_profile(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "balance": json_number(row["balance"]),
    }


def login_user(username: str, password: str) -> str:
    user_row = get_user_by_username(username)
    if not user_row:
        raise ValueError("Invalid username or password")
    if not verify_password(password, user_row["password_hash"]):
        raise ValueError("Invalid username or password")

    token = secrets.token_urlsafe(32)
    conn = get_connection()
    try:
        conn.execute("INSERT INTO auth_tokens (token, user_id, created_at) VALUES (?, ?, ?)", (token, user_row["id"], now_iso()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.execute("UPDATE auth_tokens SET user_id = ?, created_at = ? WHERE token = ?", (user_row["id"], now_iso(), token))
        conn.commit()
    finally:
        conn.close()
    return token


def create_user(username: str, password: str) -> dict:
    normalized = username.strip()
    if not normalized:
        raise ValueError("Username cannot be empty")
    if not USERNAME_RE.fullmatch(normalized):
        raise ValueError("Username format is invalid")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("Password must be at least 8 characters long")

    conn = get_connection()
    try:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (normalized,)).fetchone()
        if existing:
            raise ValueError("Username already exists")
        password_hash = hash_password(password)
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, balance, created_at) VALUES (?, ?, 0, ?)",
            (normalized, password_hash, now_iso()),
        )
        conn.commit()
        user_id = cursor.lastrowid
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return get_user_public_profile(row)
    finally:
        conn.close()


def authenticate_user_from_token(token: str) -> sqlite3.Row:
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT u.*
            FROM auth_tokens a
            INNER JOIN users u ON u.id = a.user_id
            WHERE a.token = ?
            """,
            (token,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
        return row
    finally:
        conn.close()


def parse_bearer_token(header_value: Optional[str]) -> str:
    if header_value is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication token is required")
    parts = header_value.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication token is required")
    token = parts[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication token is required")
    return token


def get_current_user(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> sqlite3.Row:
    token = parse_bearer_token(authorization)
    user_row = authenticate_user_from_token(token)
    return user_row


def log_admin_action(user_id: int, username: str, action: str, previous_balance: Decimal, new_balance: Decimal, amount_changed: Decimal) -> None:
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO admin_audit_log (user_id, username, action, previous_balance, new_balance, amount_changed, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                username,
                action,
                float(previous_balance),
                float(new_balance),
                float(amount_changed),
                now_iso(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def admin_list_users() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT id, username, balance FROM users ORDER BY id ASC").fetchall()
        return [
            {"id": row["id"], "username": row["username"], "balance": json_number(row["balance"])}
            for row in rows
        ]
    finally:
        conn.close()


def admin_get_user(username: str) -> dict:
    user = get_user_by_username(username)
    if not user:
        raise ValueError("User not found")
    return {"id": user["id"], "username": user["username"], "balance": json_number(user["balance"]) }


def admin_get_balance(username: str) -> float:
    user = get_user_by_username(username)
    if not user:
        raise ValueError("User not found")
    return json_number(user["balance"])


def admin_set_balance(username: str, amount: Any) -> float:
    normalized_amount = validate_decimal_amount(amount, allow_zero=True)
    user = get_user_by_username(username)
    if not user:
        raise ValueError("User not found")
    if normalized_amount < 0:
        raise ValueError("Balance cannot be negative")

    previous_balance = Decimal(str(user["balance"]))
    new_balance = normalized_amount
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE users SET balance = ? WHERE username = ?", (float(new_balance), username))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    log_admin_action(user["id"], username, "SET_BALANCE", previous_balance, new_balance, new_balance - previous_balance)
    return json_number(new_balance)


def admin_add_balance(username: str, amount: Any) -> float:
    normalized_amount = validate_decimal_amount(amount, allow_zero=False)
    user = get_user_by_username(username)
    if not user:
        raise ValueError("User not found")

    previous_balance = Decimal(str(user["balance"]))
    new_balance = previous_balance + normalized_amount
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE users SET balance = ? WHERE username = ?", (float(new_balance), username))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    log_admin_action(user["id"], username, "ADD_BALANCE", previous_balance, new_balance, normalized_amount)
    return json_number(new_balance)


def admin_remove_balance(username: str, amount: Any) -> float:
    normalized_amount = validate_decimal_amount(amount, allow_zero=False)
    user = get_user_by_username(username)
    if not user:
        raise ValueError("User not found")

    previous_balance = Decimal(str(user["balance"]))
    if previous_balance < normalized_amount:
        raise ValueError("Removal amount exceeds current balance")
    new_balance = previous_balance - normalized_amount
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE users SET balance = ? WHERE username = ?", (float(new_balance), username))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    log_admin_action(user["id"], username, "REMOVE_BALANCE", previous_balance, new_balance, -normalized_amount)
    return json_number(new_balance)


def admin_get_transactions(username: str) -> list[dict]:
    user = get_user_by_username(username)
    if not user:
        raise ValueError("User not found")
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT t.id, s.username AS sender, r.username AS receiver, t.amount, t.created_at
            FROM transactions t
            INNER JOIN users s ON s.id = t.sender_id
            INNER JOIN users r ON r.id = t.receiver_id
            WHERE t.sender_id = ? OR t.receiver_id = ?
            ORDER BY t.id DESC
            """,
            (user["id"], user["id"]),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "sender": row["sender"],
                "receiver": row["receiver"],
                "amount": json_number(row["amount"]),
                "timestamp": row["created_at"],
            }
            for row in rows
        ]
    finally:
        conn.close()


def admin_get_audit_log(username: str) -> list[dict]:
    user = get_user_by_username(username)
    if not user:
        raise ValueError("User not found")
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM admin_audit_log WHERE user_id = ? ORDER BY id DESC",
            (user["id"],),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "user_id": row["user_id"],
                "username": row["username"],
                "action": row["action"],
                "previous_balance": json_number(row["previous_balance"]),
                "new_balance": json_number(row["new_balance"]),
                "amount_changed": json_number(row["amount_changed"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    finally:
        conn.close()


def execute_transfer(sender_id: int, receiver_username: str, amount: Any) -> dict:
    normalized_amount = validate_decimal_amount(amount, allow_zero=False)
    sender = get_user_by_id(sender_id)
    if not sender:
        raise ValueError("Sender not found")
    receiver = get_user_by_username(receiver_username)
    if not receiver:
        raise ValueError("Receiver not found")
    if sender["id"] == receiver["id"]:
        raise ValueError("Sender and receiver must be different users")

    sender_balance = Decimal(str(sender["balance"]))
    receiver_balance = Decimal(str(receiver["balance"]))
    if sender_balance < normalized_amount:
        raise ValueError("Insufficient funds")

    updated_sender_balance = sender_balance - normalized_amount
    updated_receiver_balance = receiver_balance + normalized_amount

    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        current_sender = conn.execute("SELECT balance FROM users WHERE id = ?", (sender_id,)).fetchone()
        if current_sender is None:
            raise ValueError("Sender not found")
        current_sender_balance = Decimal(str(current_sender["balance"]))
        if current_sender_balance < normalized_amount:
            raise ValueError("Insufficient funds")
        conn.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (float(updated_sender_balance), sender_id),
        )
        conn.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (float(updated_receiver_balance), receiver["id"]),
        )
        timestamp = now_iso()
        cursor = conn.execute(
            "INSERT INTO transactions (sender_id, receiver_id, amount, created_at) VALUES (?, ?, ?, ?)",
            (sender_id, receiver["id"], float(normalized_amount), timestamp),
        )
        conn.commit()
        transaction_id = cursor.lastrowid
        return {
            "id": transaction_id,
            "sender": sender["username"],
            "receiver": receiver["username"],
            "amount": json_number(normalized_amount),
            "timestamp": timestamp,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def record_transfer(sender_username: str, receiver_username: str, amount: Any) -> dict:
    sender = get_user_by_username(sender_username)
    if not sender:
        raise ValueError("Sender not found")
    receiver = get_user_by_username(receiver_username)
    if not receiver:
        raise ValueError("Receiver not found")
    if sender["id"] == receiver["id"]:
        raise ValueError("Sender and receiver must be different users")
    normalized_amount = validate_decimal_amount(amount, allow_zero=False)
    sender_balance = Decimal(str(sender["balance"]))
    if sender_balance < normalized_amount:
        raise ValueError("Insufficient funds")
    return execute_transfer(sender["id"], receiver_username, normalized_amount)


def get_user_transaction_history(user_id: int) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT t.id, s.username AS sender, r.username AS receiver, t.amount, t.created_at
            FROM transactions t
            INNER JOIN users s ON s.id = t.sender_id
            INNER JOIN users r ON r.id = t.receiver_id
            WHERE t.sender_id = ? OR t.receiver_id = ?
            ORDER BY t.id DESC
            """,
            (user_id, user_id),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "sender": row["sender"],
                "receiver": row["receiver"],
                "amount": json_number(row["amount"]),
                "timestamp": row["created_at"],
            }
            for row in rows
        ]
    finally:
        conn.close()


@app.post("/register")
def register(payload: RegisterRequest):
    try:
        profile = create_user(payload.username, payload.password)
        return profile
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/login")
def login(payload: LoginRequest):
    try:
        token = login_user(payload.username, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password") from exc
    return {"token": token}


@app.get("/me")
def get_me(current_user: sqlite3.Row = Depends(get_current_user)):
    return get_user_public_profile(current_user)


@app.get("/balance")
def get_balance(current_user: sqlite3.Row = Depends(get_current_user)):
    return {"balance": json_number(current_user["balance"])}


@app.post("/transfer")
def transfer(payload: TransferRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    try:
        result = execute_transfer(current_user["id"], payload.receiver, payload.amount)
        return result
    except ValueError as exc:
        detail = str(exc)
        if detail == "Receiver not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@app.get("/transactions")
def get_transactions(current_user: sqlite3.Row = Depends(get_current_user)):
    return get_user_transaction_history(current_user["id"])


def print_user_table(rows: list[dict]) -> None:
    if not rows:
        print("No users found.")
        return
    print("ID    Username    Balance")
    for row in rows:
        print(f"{row['id']:<5} {row['username']:<12} {row['balance']}")


def print_transaction_table(rows: list[dict]) -> None:
    if not rows:
        print("No transactions found.")
        return
    print("ID    Sender    Receiver    Amount    Time")
    for row in rows:
        print(f"{row['id']:<5} {row['sender']:<9} {row['receiver']:<11} {row['amount']:<8} {row['timestamp']}")


def admin_console() -> None:
    print("================================")
    print("       Wallet Admin Console")
    print("================================")
    print()
    print("Type 'help' for available commands.")

    while True:
        try:
            command = input("admin> ").strip()
        except EOFError:
            print()
            break
        if not command:
            continue
        parts = command.split()
        action = parts[0].lower()

        try:
            if action == "help":
                print("Available commands:")
                print("  help")
                print("  list_users")
                print("  user <username>")
                print("  balance <username>")
                print("  set_balance <username> <amount>")
                print("  add_balance <username> <amount>")
                print("  remove_balance <username> <amount>")
                print("  transactions <username>")
                print("  exit")
            elif action == "list_users":
                print_user_table(admin_list_users())
            elif action == "user":
                if len(parts) < 2:
                    raise ValueError("Usage: user <username>")
                user = admin_get_user(parts[1])
                print(f"ID: {user['id']}")
                print(f"Username: {user['username']}")
                print(f"Balance: {user['balance']}")
            elif action == "balance":
                if len(parts) < 2:
                    raise ValueError("Usage: balance <username>")
                print(admin_get_balance(parts[1]))
            elif action == "set_balance":
                if len(parts) < 3:
                    raise ValueError("Usage: set_balance <username> <amount>")
                print(admin_set_balance(parts[1], parts[2]))
            elif action == "add_balance":
                if len(parts) < 3:
                    raise ValueError("Usage: add_balance <username> <amount>")
                print(admin_add_balance(parts[1], parts[2]))
            elif action == "remove_balance":
                if len(parts) < 3:
                    raise ValueError("Usage: remove_balance <username> <amount>")
                print(admin_remove_balance(parts[1], parts[2]))
            elif action == "transactions":
                if len(parts) < 2:
                    raise ValueError("Usage: transactions <username>")
                print_transaction_table(admin_get_transactions(parts[1]))
            elif action == "exit":
                break
            else:
                print("Unknown command. Type 'help' for available commands.")
        except ValueError as exc:
            print(f"Error: {exc}")
        except Exception as exc:  # pragma: no cover - local console block
            print(f"Error: {exc}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "admin":
        admin_console()
    else:
        uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
