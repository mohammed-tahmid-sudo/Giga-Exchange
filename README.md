# Giga Exchange

Giga Exchange is a prototype digital-wallet payment app built with FastAPI, SQLite, and vanilla HTML/CSS/JavaScript.

## Features

- Account registration and login
- Password hashing with Argon2id
- Session-based authentication
- Wallet balance and transaction history
- P2P transfers with input validation and atomic database updates
- QR-based payment flows with signed payloads
- Demo-funding endpoint gated by environment-controlled admin token
- Responsive frontend for desktop and mobile use

## Quick start

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Copy environment file:
   ```bash
   cp .env.example .env
   ```
3. Initialize the database and demo seed:
   ```bash
   python -m server.app --init-db
   ```
4. Start the API server:
   ```bash
   uvicorn server.app:app --reload --host 0.0.0.0 --port 8000
   ```
5. Open http://localhost:8000 in the browser.

## Demo accounts

The database bootstrap creates demo accounts when the database is empty:

- demo / Password123! (balance: 1000.00 GEX)
- merchant / Password123! (balance: 2500.00 GEX)

## Admin funding panel

The app includes a built-in admin modal for demo funding. Open the Admin button in the top bar, enter the configured `GIGA_ADMIN_TOKEN`, choose a username, and enter an amount to credit that user. This route is intentionally gated and disabled in production mode.

## Environment variables

See `.env.example` for defaults.

## Testing

```bash
pytest -q
```
