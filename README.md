# SessionShield — Session Replay Demonstration

## Overview

An educational Flask application that demonstrates one controlled replay scenario: a test session ID is presented without its separate proof credential. The backend rejects that request, revokes the test session, and records a security event. This demonstrates that specific scenario; it does not prevent or detect every form of session hijacking.

## Features

- Argon2id password hashing.
- Cryptographically random session IDs paired with HMAC-SHA256 proof tokens.
- Database-backed SQLite session storage and session expiration. Test sessions are marked separately from ordinary sessions and cannot be selected by the demo replay flow.
- Detection and logging of replay attempts that lack a valid proof token.
- Atomic session revocation and rejection of further requests using a revoked session.
- Two-client browser demo: Laptop A creates and uses a test session, then explicitly copies its test ID to Laptop B. Laptop B triggers a real HTTP request to the protected backend endpoint with the ID only.
- Security event logs contain fingerprints, not session IDs, proof tokens, or passwords.

## Local setup

1. Install Python 3.11 or later.
2. From the project directory, create and activate a virtual environment:

   ```bash
   python -m venv .venv
   # Windows PowerShell
   .venv\Scripts\Activate.ps1
   # macOS/Linux
   source .venv/bin/activate
   ```

3. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the application:

   ```bash
   python run.py
   ```

   To use a different port, run `python run.py --port 5001`.

5. Open [http://127.0.0.1:5000/demo](http://127.0.0.1:5000/demo). The local demo account is `alice` with password `Demo@1234`; enter the password in the masked form field. It is not embedded in the frontend or printed by the server.

## Two-laptop demonstration

Both laptops must open the same deployed application URL.

1. On Laptop A, open `/demo`, enter the demo password, select **Create Legitimate Session**, and then **Access Protected Resource**. Confirm that the backend returns `ACCESS_GRANTED`.
2. Copy the displayed **test session ID** using the copy button. This identifier is intentionally shared only for the test session created for this demo; do not copy a production session ID or either browser cookie.
3. On Laptop B, open `/demo`, paste that ID into **Test session ID handoff**, and select **Execute Replay Attack**. The app submits the ID to the backend’s dedicated demo route; the backend simulator makes a real request to `/api/protected-resource` with `sid` only and without `sproof`.
4. On Laptop B, confirm the backend-reported detection/revocation, then run **Confirm Detection Status** and **Verify Post-Revocation Rejection**. These stages report success only when the persisted backend event and session state and the actual HTTP responses confirm it.
5. Optionally, return to Laptop A and select **Access Protected Resource** again; the existing browser credentials should now be rejected because that test session was revoked.

Only demo sessions created through Stage 1 are eligible for the demo replay and reset routes. Ordinary `/api/login` sessions are not eligible. Reset operates on the one supplied test session ID and does not revoke all sessions belonging to the account.

## Render deployment requirements

The current storage implementation is SQLite. For the two-laptop demonstration, configure the Render web service as a **single instance** and attach a persistent disk mounted at `/var/data`. Set:

- `DATABASE_PATH=/var/data/session_hijack_demo.db`
- `SESSION_PROOF_KEY` to a stable, private random value shared by all workers and retained across restarts
- `SECRET_KEY` to a stable, private random value
- `SESSION_COOKIE_SECURE=true` when serving the demo over HTTPS

Render supplies `PORT`; the server-side simulator uses that local port to send its HTTP request back to the same backend instance. Do not log or include secret values in screenshots. The existing repository does not include Render infrastructure configuration, so the disk, single-instance setting, and environment variables must be configured in the Render dashboard.

Do not scale this SQLite deployment across multiple Render instances. A local SQLite file is not shared between instances, and Render persistent disks are attached to a single instance. Horizontal scaling requires migrating this application's persistence to a shared database (for example, PostgreSQL) before enabling multiple instances.
