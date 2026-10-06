import json

import pytest
from fastapi.testclient import TestClient

from server.app import app, ensure_database, ensure_demo_accounts


@pytest.fixture(scope="session", autouse=True)
def reset_db():
    ensure_database(force_reset=True)
    ensure_demo_accounts()


client = TestClient(app)


def test_register_and_login():
    payload = {
        "phone_number": "+15550009999",
        "username": "alice",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["success"] is True
    assert data["user"]["username"] == "alice"

    login = client.post("/api/auth/login", json={"phone_number": "+15550009999", "password": "Password123!"})
    assert login.status_code == 200, login.text
    assert "token" in login.json()


def test_duplicate_phone_rejected():
    payload = {
        "phone_number": "+15550009999",
        "username": "alice2",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 409


def test_invalid_password_rejected():
    login = client.post("/api/auth/login", json={"phone_number": "+15550009999", "password": "WrongPass!"})
    assert login.status_code == 401


def test_unauthorized_access():
    res = client.get("/api/wallet")
    assert res.status_code == 401


def test_wallet_created_on_register():
    res = client.post(
        "/api/auth/register",
        json={"phone_number": "+15550008888", "username": "bob", "password": "Password123!", "confirm_password": "Password123!"},
    )
    assert res.status_code == 201
    wallet = res.json()["wallet"]
    assert wallet["currency"] == "GEX"
    assert wallet["balance_cents"] == 0


def test_successful_transfer():
    demo_login = client.post("/api/auth/login", json={"phone_number": "+15550000001", "password": "Password123!"})
    token = demo_login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post(
        "/api/auth/register",
        json={"phone_number": "+15550007777", "username": "charlie", "password": "Password123!", "confirm_password": "Password123!"},
    )
    transfer = client.post(
        "/api/transactions/transfer",
        headers=headers,
        json={"recipient": "charlie", "amount": "10.00", "description": "Groceries"},
    )
    assert transfer.status_code == 200, transfer.text
    assert transfer.json()["transaction"]["amount_cents"] == 1000


def test_insufficient_balance_transfer():
    register = client.post(
        "/api/auth/register",
        json={"phone_number": "+15550006666", "username": "lowbal", "password": "Password123!", "confirm_password": "Password123!"},
    )
    assert register.status_code == 201
    login = client.post("/api/auth/login", json={"phone_number": "+15550006666", "password": "Password123!"})
    token = login.json()["token"]
    transfer = client.post(
        "/api/transactions/transfer",
        headers={"Authorization": f"Bearer {token}"},
        json={"recipient": "demo", "amount": "1000.00", "description": "Too much"},
    )
    assert transfer.status_code == 400
    assert transfer.json()["error"]["code"] == "INSUFFICIENT_FUNDS"


def test_invalid_amount_and_self_transfer():
    demo_login = client.post("/api/auth/login", json={"phone_number": "+15550000001", "password": "Password123!"})
    token = demo_login.json()["token"]
    bad_amt = client.post("/api/transactions/transfer", headers={"Authorization": f"Bearer {token}"}, json={"recipient": "merchant", "amount": "0.00"})
    assert bad_amt.status_code == 422
    self_xfer = client.post("/api/transactions/transfer", headers={"Authorization": f"Bearer {token}"}, json={"recipient": "demo", "amount": "1.00"})
    assert self_xfer.status_code == 400
    assert self_xfer.json()["error"]["code"] == "SELF_TRANSFER"


def test_transaction_history_access_control():
    demo_login = client.post("/api/auth/login", json={"phone_number": "+15550000001", "password": "Password123!"})
    token = demo_login.json()["token"]
    res = client.get("/api/transactions", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()["data"]
    assert len(data) >= 1


def test_qr_resolution_and_idempotency():
    demo_login = client.post("/api/auth/login", json={"phone_number": "+15550000001", "password": "Password123!"})
    token = demo_login.json()["token"]
    qr = client.get("/api/qr/me", headers={"Authorization": f"Bearer {token}"})
    payload = qr.json()["data"]["payload"]
    resolved = client.post("/api/qr/resolve", json={"payload": payload})
    assert resolved.status_code == 200

    transfer = client.post(
        "/api/transactions/transfer",
        headers={"Authorization": f"Bearer {token}"},
        json={"recipient": "merchant", "amount": "5.00", "description": "Repeat me", "idempotency_key": "idem-1"},
    )
    second = client.post(
        "/api/transactions/transfer",
        headers={"Authorization": f"Bearer {token}"},
        json={"recipient": "merchant", "amount": "5.00", "description": "Repeat me", "idempotency_key": "idem-1"},
    )
    assert transfer.status_code == 200
    assert second.status_code == 200
    assert second.json()["transaction"]["id"] == transfer.json()["transaction"]["id"]


def test_admin_demo_fund_updates_wallet():
    res = client.post(
        "/api/admin/demo-fund",
        headers={"X-Admin-Token": "change-me-admin-token"},
        json={"username": "demo", "amount": "25.00"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["wallet"]["balance_cents"] >= 100000
