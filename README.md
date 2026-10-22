# Session Hijacking Detection & Prevention System

## Overview

An educational Flask application that demonstrates a controlled session replay scenario and a defense against an attacker who has obtained only a session ID. The app detects a missing proof credential, rejects the request, revokes the session, and records the security event. The demo simulator sends requests only to localhost; this prototype is not intended for production use.

## Features

- Argon2id password hashing.
- Cryptographically random session IDs paired with HMAC-SHA256 proof tokens.
- Server-side SQLite session storage and session expiration.
- Detection and logging of replay attempts that lack a valid proof token.
- Atomic session revocation and rejection of further requests using a revoked session.
- Browser-based guided demo with a localhost-only replay simulator.

## Steps to Run

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

5. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser. Visit `/demo` to run the guided demonstration. The demo account is `alice` with password `Demo@1234`.
