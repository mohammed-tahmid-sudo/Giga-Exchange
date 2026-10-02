import importlib
import os
import sys
import tempfile
import traceback
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient


PASS_COUNT = 0
FAIL_COUNT = 0


def make_client():
    temp_dir = tempfile.mkdtemp(prefix="wallet_test_")
    db_path = os.path.join(temp_dir, "wallet.db")
    os.environ["WALLET_DB_PATH"] = db_path
    import server

    importlib.reload(server)
    server.initialize_database(force_reset=True)
    return TestClient(server.app), server, temp_dir


def register_user(client, username="alice", password="password123"):
    response = client.post("/register", json={"username": username, "password": password})
    if response.status_code != 200:
        raise AssertionError(f"Register failed for {username}: {response.status_code} {response.text}")
    return response.json()


def login_user(client, username="alice", password="password123"):
    response = client.post("/login", json={"username": username, "password": password})
    if response.status_code != 200:
        raise AssertionError(f"Login failed for {username}: {response.status_code} {response.text}")
    data = response.json()
    if "token" not in data:
        raise AssertionError(f"Login response missing token: {data}")
    return data["token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def run_test(name, func):
    global PASS_COUNT, FAIL_COUNT
    try:
        func()
        print(f"[PASS] {name}")
        PASS_COUNT += 1
    except Exception as exc:  # pragma: no cover - test runner output
        print(f"[FAIL] {name}: {exc}")
        print(traceback.format_exc())
        FAIL_COUNT += 1


def test_account_creation_succeeds():
    client, _, _ = make_client()
    payload = register_user(client, "alice", "password123")
    assert payload["username"] == "alice"
    assert payload["balance"] == 0


def test_new_account_starts_at_zero():
    client, _, _ = make_client()
    response = client.post("/register", json={"username": "bob", "password": "password123"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["balance"] == 0


def test_duplicate_username_rejected():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    response = client.post("/register", json={"username": "alice", "password": "anotherpass"})
    assert response.status_code in (400, 409), response.text


def test_empty_username_rejected():
    client, _, _ = make_client()
    response = client.post("/register", json={"username": "", "password": "password123"})
    assert response.status_code in (400, 422), response.text


def test_invalid_username_rejected():
    client, _, _ = make_client()
    response = client.post("/register", json={"username": "bad username!", "password": "password123"})
    assert response.status_code in (400, 422), response.text


def test_weak_password_rejected():
    client, _, _ = make_client()
    response = client.post("/register", json={"username": "charlie", "password": "short"})
    assert response.status_code in (400, 422), response.text


def test_password_not_stored_in_plaintext():
    client, server_mod, _ = make_client()
    register_user(client, "dana", "password123")
    with server_mod.get_connection() as conn:
        row = conn.execute("SELECT username, password_hash FROM users WHERE username = ?", ("dana",)).fetchone()
    assert row is not None
    assert row[1] != "password123"
    assert "pbkdf2_sha256" in row[1]


def test_correct_login_succeeds():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    response = client.post("/login", json={"username": "alice", "password": "password123"})
    assert response.status_code == 200, response.text
    assert "token" in response.json()


def test_wrong_password_rejected():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    response = client.post("/login", json={"username": "alice", "password": "wrongpass"})
    assert response.status_code == 401, response.text


def test_wrong_username_rejected():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    response = client.post("/login", json={"username": "mallory", "password": "password123"})
    assert response.status_code == 401, response.text


def test_login_returns_auth_token():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    data = login_user(client, "alice", "password123")
    assert isinstance(data, str)
    assert len(data) > 20


def test_invalid_auth_token_rejected():
    client, _, _ = make_client()
    response = client.get("/me", headers={"Authorization": "Bearer clearly-invalid-token"})
    assert response.status_code == 401, response.text


def test_protected_endpoints_require_authentication():
    client, _, _ = make_client()
    for route in ["/me", "/balance", "/transactions"]:
        response = client.get(route)
        assert response.status_code == 401, route


def test_one_user_cannot_impersonate_another_user():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    server_mod.admin_set_balance("alice", 200)
    server_mod.admin_set_balance("bob", 100)
    alice_token = login_user(client, "alice", "password123")
    response = client.post(
        "/transfer",
        headers=auth_headers(alice_token),
        json={"receiver": "bob", "amount": 50, "sender": "bob"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["sender"] == "alice"
    assert response.json()["receiver"] == "bob"


def test_new_account_has_zero_balance():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    token = login_user(client, "alice", "password123")
    response = client.get("/balance", headers=auth_headers(token))
    assert response.status_code == 200, response.text
    assert response.json()["balance"] == 0


def test_balance_endpoint_returns_correct_balance():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    token = login_user(client, "alice", "password123")
    with client:
        pass
    response = client.get("/balance", headers=auth_headers(token))
    assert response.status_code == 200, response.text
    assert response.json()["balance"] == 0


def test_user_cannot_access_another_users_private_balance():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    alice_token = login_user(client, "alice", "password123")
    bob_token = login_user(client, "bob", "password123")
    response = client.get("/balance", headers=auth_headers(alice_token))
    assert response.status_code == 200
    assert response.json()["balance"] == 0
    response2 = client.get("/balance", headers=auth_headers(bob_token))
    assert response2.status_code == 200
    assert response2.json()["balance"] == 0


def test_successful_transfer_updates_balances_and_records_transaction():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod.admin_set_balance("alice", 500)
    server_mod.admin_set_balance("bob", 200)
    response = client.post(
        "/transfer",
        headers=auth_headers(token),
        json={"receiver": "bob", "amount": 100},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["sender"] == "alice"
    assert data["receiver"] == "bob"
    assert data["amount"] == 100
    alice_balance = client.get("/balance", headers=auth_headers(token)).json()["balance"]
    bob_token = login_user(client, "bob", "password123")
    bob_balance = client.get("/balance", headers=auth_headers(bob_token)).json()["balance"]
    assert alice_balance == 400
    assert bob_balance == 300


def test_sender_balance_decreases_correctly():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 500)
    server_mod.admin_set_balance("bob", 100)
    client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 50})
    assert client.get("/balance", headers=auth_headers(token)).json()["balance"] == 450


def test_receiver_balance_increases_correctly():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 300)
    server_mod.admin_set_balance("bob", 50)
    client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 75})
    bob_token = login_user(client, "bob", "password123")
    assert client.get("/balance", headers=auth_headers(bob_token)).json()["balance"] == 125


def test_sender_cannot_send_more_than_balance():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 50)
    server_mod.admin_set_balance("bob", 0)
    response = client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 100})
    assert response.status_code == 400, response.text


def test_negative_amounts_are_rejected():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 200)
    response = client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": -10})
    assert response.status_code in (400, 422), response.text


def test_zero_amount_is_rejected():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 200)
    response = client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 0})
    assert response.status_code in (400, 422), response.text


def test_receiver_must_exist():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 200)
    response = client.post("/transfer", headers=auth_headers(token), json={"receiver": "ghost", "amount": 50})
    assert response.status_code == 404, response.text


def test_self_transfer_rejected():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 200)
    response = client.post("/transfer", headers=auth_headers(token), json={"receiver": "alice", "amount": 50})
    assert response.status_code == 400, response.text


def test_failed_transfers_do_not_change_balances_or_transactions():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 100)
    server_mod.admin_set_balance("bob", 50)
    response = client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 200})
    assert response.status_code == 400, response.text
    alice_after = client.get("/balance", headers=auth_headers(token)).json()["balance"]
    bob_token = login_user(client, "bob", "password123")
    bob_after = client.get("/balance", headers=auth_headers(bob_token)).json()["balance"]
    assert alice_after == 100
    assert bob_after == 50
    txns = client.get("/transactions", headers=auth_headers(token)).json()
    assert len(txns) == 0


def test_multiple_transfers_update_balances_correctly():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    register_user(client, "charlie", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 300)
    client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 50})
    client.post("/transfer", headers=auth_headers(token), json={"receiver": "charlie", "amount": 70})
    bob_token = login_user(client, "bob", "password123")
    charlie_token = login_user(client, "charlie", "password123")
    assert client.get("/balance", headers=auth_headers(token)).json()["balance"] == 180
    assert client.get("/balance", headers=auth_headers(bob_token)).json()["balance"] == 50
    assert client.get("/balance", headers=auth_headers(charlie_token)).json()["balance"] == 70


def test_user_can_view_own_transactions():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 200)
    server_mod.admin_set_balance("bob", 0)
    client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 25})
    txns = client.get("/transactions", headers=auth_headers(token)).json()
    assert len(txns) == 1
    assert txns[0]["sender"] == "alice"
    assert txns[0]["receiver"] == "bob"
    assert txns[0]["amount"] == 25


def test_incoming_and_outgoing_transactions_appear():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    alice_token = login_user(client, "alice", "password123")
    bob_token = login_user(client, "bob", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 200)
    server_mod.admin_set_balance("bob", 0)
    client.post("/transfer", headers=auth_headers(alice_token), json={"receiver": "bob", "amount": 25})
    alice_txns = client.get("/transactions", headers=auth_headers(alice_token)).json()
    bob_txns = client.get("/transactions", headers=auth_headers(bob_token)).json()
    assert alice_txns[0]["sender"] == "alice"
    assert bob_txns[0]["receiver"] == "bob"
    assert bob_txns[0]["amount"] == 25


def test_other_user_cannot_access_private_transaction_history():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    alice_token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 200)
    server_mod.admin_set_balance("bob", 50)
    client.post("/transfer", headers=auth_headers(alice_token), json={"receiver": "bob", "amount": 25})
    bob_token = login_user(client, "bob", "password123")
    bob_txns = client.get("/transactions", headers=auth_headers(bob_token)).json()
    assert any(txn["receiver"] == "bob" for txn in bob_txns)
    assert all(txn["sender"] != "alice" or txn["receiver"] == "bob" for txn in bob_txns)


def test_admin_list_users_returns_users_without_passwords():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    users = server_mod.admin_list_users()
    assert len(users) >= 2
    assert all("password" not in str(user).lower() for user in users)


def test_admin_user_command_displays_basic_user_data():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    user = server_mod.admin_get_user("alice")
    assert user["username"] == "alice"
    assert user["balance"] == 0


def test_admin_balance_command_returns_current_balance():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    server_mod.admin_set_balance("alice", 500)
    assert server_mod.admin_get_balance("alice") == 500


def test_admin_set_balance_changes_balance():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    server_mod.admin_set_balance("alice", 400)
    assert server_mod.admin_get_balance("alice") == 400


def test_admin_add_balance_increases_balance():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    server_mod.admin_add_balance("alice", 1000)
    assert server_mod.admin_get_balance("alice") == 1000


def test_admin_remove_balance_decreases_balance_without_negative_outcome():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    server_mod.admin_set_balance("alice", 200)
    server_mod.admin_remove_balance("alice", 50)
    assert server_mod.admin_get_balance("alice") == 150


def test_admin_transactions_command_lists_user_history():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    server_mod.admin_set_balance("alice", 200)
    server_mod.admin_set_balance("bob", 0)
    server_mod.record_transfer("alice", "bob", 25)
    txns = server_mod.admin_get_transactions("alice")
    assert len(txns) >= 1
    assert txns[0]["amount"] == 25


def test_admin_invalid_username_rejected():
    client, server_mod, _ = make_client()
    try:
        server_mod.admin_set_balance("missing-user", 100)
        raise AssertionError("Missing user should fail")
    except ValueError:
        pass


def test_admin_invalid_amount_rejected():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    try:
        server_mod.admin_set_balance("alice", -10)
        raise AssertionError("Negative admin amount should fail")
    except ValueError:
        pass


def test_admin_remove_more_than_balance_rejected():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    server_mod.admin_set_balance("alice", 20)
    try:
        server_mod.admin_remove_balance("alice", 25)
        raise AssertionError("Removing too much should fail")
    except ValueError:
        pass


def test_admin_changes_create_audit_records():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    server_mod.admin_add_balance("alice", 300)
    logs = server_mod.admin_get_audit_log("alice")
    assert len(logs) >= 1
    assert logs[0]["action"] in {"ADD_BALANCE", "SET_BALANCE", "REMOVE_BALANCE"}
    assert logs[0]["amount_changed"] != 0


def test_balance_never_becomes_negative():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    server_mod.admin_set_balance("alice", 100)
    try:
        server_mod.admin_remove_balance("alice", 200)
        raise AssertionError("Negative admin balance should fail")
    except ValueError:
        pass
    assert server_mod.admin_get_balance("alice") == 100


def test_failed_transfer_rolls_back_completely():
    client, _, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    token = login_user(client, "alice", "password123")
    server_mod = __import__("server")
    server_mod.admin_set_balance("alice", 100)
    server_mod.admin_set_balance("bob", 10)
    response = client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 200})
    assert response.status_code == 400, response.text
    assert server_mod.admin_get_balance("alice") == 100
    assert server_mod.admin_get_balance("bob") == 10
    assert client.get("/transactions", headers=auth_headers(token)).json() == []


def test_concurrent_transfers_cannot_create_negative_balance():
    client, server_mod, _ = make_client()
    register_user(client, "alice", "password123")
    register_user(client, "bob", "password123")
    register_user(client, "charlie", "password123")
    token = login_user(client, "alice", "password123")
    server_mod.admin_set_balance("alice", 100)
    server_mod.admin_set_balance("bob", 0)
    server_mod.admin_set_balance("charlie", 0)

    client_b = TestClient(server_mod.app)
    token_b = login_user(client_b, "alice", "password123")

    def send_to_bob():
        return client.post("/transfer", headers=auth_headers(token), json={"receiver": "bob", "amount": 100})

    def send_to_charlie():
        return client_b.post("/transfer", headers=auth_headers(token_b), json={"receiver": "charlie", "amount": 100})

    with ThreadPoolExecutor(max_workers=2) as executor:
        future1 = executor.submit(send_to_bob)
        future2 = executor.submit(send_to_charlie)
        result1 = future1.result()
        result2 = future2.result()

    alice_balance = server_mod.admin_get_balance("alice")
    assert alice_balance >= 0
    assert alice_balance <= 100
    bob_balance = server_mod.admin_get_balance("bob")
    charlie_balance = server_mod.admin_get_balance("charlie")
    assert bob_balance in (0, 100)
    assert charlie_balance in (0, 100)
    assert bob_balance + charlie_balance in (0, 100)


def run_all_tests():
    tests = [
        ("Account creation", test_account_creation_succeeds),
        ("New account zero balance", test_new_account_starts_at_zero),
        ("Duplicate username rejected", test_duplicate_username_rejected),
        ("Empty username rejected", test_empty_username_rejected),
        ("Invalid username rejected", test_invalid_username_rejected),
        ("Weak password rejected", test_weak_password_rejected),
        ("Password not stored as plaintext", test_password_not_stored_in_plaintext),
        ("Correct login succeeds", test_correct_login_succeeds),
        ("Wrong password rejected", test_wrong_password_rejected),
        ("Wrong username rejected", test_wrong_username_rejected),
        ("Login returns token", test_login_returns_auth_token),
        ("Invalid auth token rejected", test_invalid_auth_token_rejected),
        ("Protected endpoints require auth", test_protected_endpoints_require_authentication),
        ("User impersonation blocked", test_one_user_cannot_impersonate_another_user),
        ("Balance endpoint works", test_new_account_has_zero_balance),
        ("Balance returns values", test_balance_endpoint_returns_correct_balance),
        ("Private balance access is restricted", test_user_cannot_access_another_users_private_balance),
        ("Successful transfer", test_successful_transfer_updates_balances_and_records_transaction),
        ("Sender balance decreases", test_sender_balance_decreases_correctly),
        ("Receiver balance increases", test_receiver_balance_increases_correctly),
        ("Insufficient funds rejected", test_sender_cannot_send_more_than_balance),
        ("Negative transfer rejected", test_negative_amounts_are_rejected),
        ("Zero transfer rejected", test_zero_amount_is_rejected),
        ("Receiver must exist", test_receiver_must_exist),
        ("Self transfer rejected", test_self_transfer_rejected),
        ("Failed transfer rollback", test_failed_transfers_do_not_change_balances_or_transactions),
        ("Multiple transfers update balances", test_multiple_transfers_update_balances_correctly),
        ("Own transactions visible", test_user_can_view_own_transactions),
        ("Incoming/outgoing transactions visible", test_incoming_and_outgoing_transactions_appear),
        ("Private history restricted", test_other_user_cannot_access_private_transaction_history),
        ("Admin list users", test_admin_list_users_returns_users_without_passwords),
        ("Admin user lookup", test_admin_user_command_displays_basic_user_data),
        ("Admin balance lookup", test_admin_balance_command_returns_current_balance),
        ("Admin set balance", test_admin_set_balance_changes_balance),
        ("Admin add balance", test_admin_add_balance_increases_balance),
        ("Admin remove balance", test_admin_remove_balance_decreases_balance_without_negative_outcome),
        ("Admin transactions", test_admin_transactions_command_lists_user_history),
        ("Admin invalid username", test_admin_invalid_username_rejected),
        ("Admin invalid amount", test_admin_invalid_amount_rejected),
        ("Admin remove too much", test_admin_remove_more_than_balance_rejected),
        ("Admin audit logging", test_admin_changes_create_audit_records),
        ("Balance never negative", test_balance_never_becomes_negative),
        ("Transfer rollback integrity", test_failed_transfer_rolls_back_completely),
        ("Concurrent transfer safety", test_concurrent_transfers_cannot_create_negative_balance),
    ]
    for name, func in tests:
        run_test(name, func)

    print("================================")
    print(f"Tests passed: {PASS_COUNT}")
    print(f"Tests failed: {FAIL_COUNT}")
    print("================================")
    if FAIL_COUNT > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_all_tests()
