from server.app import ensure_database, ensure_demo_accounts

if __name__ == "__main__":
    ensure_database()
    ensure_demo_accounts()
    print("Database initialized successfully.")
