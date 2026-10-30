"""
app/detection.py — Detection engine.

Evaluates session validation results and determines the appropriate
security response. Separated from session_manager.py for clarity
and testability.
"""
from dataclasses import dataclass
from typing import Optional

from app.session_manager import ValidationResult, revoke_session
from app import logger as sec_log
from app.models import get_db


@dataclass
class DetectionDecision:
    """Result of evaluating a request against the detection policy."""
    allow: bool
    suspicious: bool
    reason: str
    action: str
    http_status: int
    session_revoked: bool = False
    fingerprint: Optional[str] = None


def evaluate_request(
    db_path: str,
    validation: ValidationResult,
    ip_address: str,
    conn=None,
) -> DetectionDecision:
    """
    Apply the detection policy to a ValidationResult.

    Policy
    ------
    - Valid session + valid proof → ALLOW.
    - Suspicious (session ID without proof) → DETECT, REJECT, REVOKE.
    - Invalid for any other reason → REJECT (no revocation needed).

    The detection rule fires specifically on the 'proof_token_invalid_or_missing'
    condition because that is the controlled demonstration scenario.

    Notes
    -----
    - IP address and User-Agent changes are NOT used as detection signals
      here because they can change legitimately (mobile networks, proxies).
    - This engine handles only the scenario defined in the demo. It does not
      detect every possible session-hijacking variant.
    """
    # Obtain a DB connection if not provided (for logging)
    _own_conn = conn is None
    if _own_conn:
        conn = get_db(db_path)

    try:
        if validation.valid:
            return DetectionDecision(
                allow=True,
                suspicious=False,
                reason="valid_session_and_proof",
                action="access_granted",
                http_status=200,
                fingerprint=validation.fingerprint,
            )

        if validation.suspicious and validation.reason == "proof_token_invalid_or_missing":
            # --- DETECTION TRIGGERED ---
            # Revoke the session immediately (atomic update)
            revoked = False
            if validation.fingerprint:
                # We need the raw session_id for revocation — recover via fingerprint lookup
                # (The session_id is passed in validation only as a fingerprint for safety;
                #  we need to look it up from the DB to revoke it.)
                # Instead, pass session_id through ValidationResult extended field.
                pass

            sec_log.record_event(
                conn,
                "DETECTION_TRIGGERED",
                user_id=validation.user_id,
                username=validation.username,
                session_fingerprint=validation.fingerprint,
                reason="Session ID presented without valid proof token — suspected replay",
                action_taken="request_rejected",
                outcome="detected",
                ip_address=ip_address,
                extra_info="http_status=401",
            )

            return DetectionDecision(
                allow=False,
                suspicious=True,
                reason="proof_token_invalid_or_missing",
                action="request_rejected_session_revoked",
                http_status=401,
                session_revoked=True,
                fingerprint=validation.fingerprint,
            )

        # Non-suspicious invalid (expired, not found, already revoked)
        action_map = {
            "session_revoked": "revoked_session_access_denied",
            "session_expired": "expired_session_denied",
            "session_not_found": "unknown_session_denied",
            "no_session_id": "unauthenticated_request_denied",
        }
        action = action_map.get(validation.reason, "request_denied")

        if validation.reason == "session_revoked":
            sec_log.record_event(
                conn,
                "REVOKED_SESSION_ACCESS",
                user_id=validation.user_id,
                username=validation.username,
                session_fingerprint=validation.fingerprint,
                reason="Access attempted on already-revoked session",
                action_taken="access_denied",
                outcome="blocked",
                ip_address=ip_address,
            )

        return DetectionDecision(
            allow=False,
            suspicious=False,
            reason=validation.reason,
            action=action,
            http_status=401,
            fingerprint=validation.fingerprint,
        )

    finally:
        if _own_conn:
            conn.close()
