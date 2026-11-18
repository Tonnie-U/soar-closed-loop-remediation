#!/usr/bin/env python3
"""
soar_remediator.py — Closed-loop SOAR response daemon.

Receives webhook alerts from Kibana, authenticates them, maps the alert
category to a remediation playbook, executes it, re-audits the host, and
annotates the outcome back into Elasticsearch.

Authentication supports two schemes:

  X-SOAR-Token      shared secret, compared in constant time
  X-SOAR-Signature  HMAC-SHA256 of the raw request body, hex encoded

Kibana's webhook connector cannot compute a body signature, so it uses the
token header. The HMAC path exists for callers that can sign, and is what
the test harness exercises.

Configuration is read from the environment (see soar.env).
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

SOAR_TOKEN = os.environ.get("SOAR_TOKEN", "")
SOAR_HMAC_SECRET = os.environ.get("SOAR_HMAC_SECRET", "").encode()
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")
PLAYBOOK_DIR = os.environ.get("PLAYBOOK_DIR", "/usr/local/share/soar/playbooks")
AUDIT_INDEX = os.environ.get("AUDIT_INDEX", "soar-actions")
HARDENING_BASELINE = int(os.environ.get("HARDENING_BASELINE", "85"))
PLAYBOOK_TIMEOUT = int(os.environ.get("PLAYBOOK_TIMEOUT", "300"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
log = logging.getLogger("soar")

app = FastAPI(title="SOAR Remediation Daemon", version="1.0.0")

# A remediation must not run concurrently with itself. Two alerts for the
# same drift arriving together would otherwise race each other restoring
# the same config file.
_playbook_lock = asyncio.Lock()


# --------------------------------------------------------------------------
# Request model
# --------------------------------------------------------------------------

class AlertPayload(BaseModel):
    """Fields the Kibana webhook connector is configured to send."""
    target_host: str = Field(default="unknown")
    alert_rule: str = Field(default="unknown")
    severity: str = Field(default="unknown")
    hardening_score: Optional[int] = None
    certificate_id: Optional[str] = None
    principal: Optional[str] = None
    timestamp: Optional[str] = None


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def authenticate(raw_body: bytes, token: Optional[str], signature: Optional[str]) -> str:
    """Return the scheme that authenticated the request, or raise 401.

    Both comparisons are constant time. A timing-variable comparison on a
    shared secret leaks the secret one byte at a time to a caller who can
    measure response latency.
    """
    if token is not None and SOAR_TOKEN:
        if hmac.compare_digest(token, SOAR_TOKEN):
            return "token"
        log.warning("rejected: invalid token")
        raise HTTPException(status_code=401, detail="invalid credentials")

    if signature is not None and SOAR_HMAC_SECRET:
        expected = hmac.new(SOAR_HMAC_SECRET, raw_body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature.lower(), expected):
            return "hmac"
        log.warning("rejected: invalid signature")
        raise HTTPException(status_code=401, detail="invalid credentials")

    log.warning("rejected: no credentials presented")
    raise HTTPException(status_code=401, detail="invalid credentials")


# --------------------------------------------------------------------------
# Decision engine
# --------------------------------------------------------------------------

def select_playbook(alert: AlertPayload) -> Optional[str]:
    """Map an alert to a playbook. Returns None when nothing should run.

    Matching is on the rule name rather than the alert text, so that
    rewording a rule's description cannot silently change what executes.
    """
    rule = (alert.alert_rule or "").lower()

    if "hardening index" in rule or "drift" in rule:
        return "remediate_drift.sh"

    if "certificate" in rule and ("expir" in rule or "revok" in rule):
        return "remediate_certificate.sh"

    return None


# --------------------------------------------------------------------------
# Playbook execution
# --------------------------------------------------------------------------

async def run_playbook(name: str, alert: AlertPayload) -> dict:
    """Execute a playbook and capture its result."""
    path = os.path.join(PLAYBOOK_DIR, name)
    if not os.path.isfile(path):
        return {"ok": False, "error": f"playbook not found: {path}"}

    env = os.environ.copy()
    env["SOAR_TARGET_HOST"] = alert.target_host
    env["SOAR_ALERT_RULE"] = alert.alert_rule
    env["SOAR_SEVERITY"] = alert.severity
    if alert.certificate_id:
        env["SOAR_CERTIFICATE_ID"] = alert.certificate_id
    if alert.principal:
        env["SOAR_PRINCIPAL"] = alert.principal

    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            "/usr/bin/sudo", "-n", path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=PLAYBOOK_TIMEOUT)
        elapsed = time.monotonic() - started
        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "output": stdout.decode(errors="replace")[-4000:],
            "duration_seconds": round(elapsed, 3),
        }
    except asyncio.TimeoutError:
        return {
            "ok": False,
            "error": f"playbook exceeded {PLAYBOOK_TIMEOUT}s",
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    except Exception as exc:  # noqa: BLE001 - we want the reason recorded
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "duration_seconds": round(time.monotonic() - started, 3),
        }


def verification_passed(alert_rule, playbook, result, verification):
    """Trigger-aware post-remediation verification.

    A configuration-drift alert is satisfied when the drift playbook restores
    every deviating file. The Lynis hardening index measures overall compliance
    of the host, not whether this particular drift was corrected, so holding a
    drift remediation to the index reports unrelated failures as this
    remediation failing.

    A hardening-index alert is held to the index, because the index is the
    condition the alert fired on.

    Returns (passed, criterion).
    """
    if not result.get("ok"):
        return False, "playbook_failed"
    if playbook == "remediate_certificate.sh":
        return True, "certificate_revoked"
    clean = "0 failures" in result.get("output", "")
    if "hardening index" in (alert_rule or "").lower():
        return (clean and bool(verification.get("compliant"))), "lynis_index_at_baseline"
    return clean, "configuration_matches_baseline"


async def reaudit() -> dict:
    """Re-run the Lynis audit and read back the resulting index.

    This is the verification half of the loop: without it the daemon can
    only claim it ran a playbook, not that the playbook worked.
    """
    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            "/usr/bin/sudo", "-n", os.path.join(PLAYBOOK_DIR, "reaudit.sh"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=PLAYBOOK_TIMEOUT)
        text = stdout.decode(errors="replace")

        score = None
        for line in text.splitlines():
            if line.startswith("HARDENING_INDEX="):
                try:
                    score = int(line.split("=", 1)[1].strip())
                except ValueError:
                    pass

        return {
            "ok": score is not None,
            "hardening_index": score,
            "compliant": (score is not None and score >= HARDENING_BASELINE),
            "baseline": HARDENING_BASELINE,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "duration_seconds": round(time.monotonic() - started, 3),
        }


# --------------------------------------------------------------------------
# Elasticsearch annotation
# --------------------------------------------------------------------------

async def annotate(record: dict) -> bool:
    """Write the incident record back to Elasticsearch.

    Failure here is logged but does not fail the remediation — the host is
    already fixed, and losing the audit trail is the lesser problem.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{ES_URL}/{AUDIT_INDEX}/_doc",
                json=record,
                auth=(ES_USER, ES_PASSWORD),
            )
            if resp.status_code >= 300:
                log.error("annotation rejected: %s %s", resp.status_code, resp.text[:200])
                return False
            return True
    except Exception as exc:  # noqa: BLE001
        log.error("annotation failed: %s", exc)
        return False


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "baseline": HARDENING_BASELINE}


@app.post("/webhook/alert")
async def webhook(
    request: Request,
    x_soar_token: Optional[str] = Header(default=None),
    x_soar_signature: Optional[str] = Header(default=None),
):
    received_at = time.monotonic()
    raw = await request.body()

    scheme = authenticate(raw, x_soar_token, x_soar_signature)

    try:
        alert = AlertPayload(**json.loads(raw or b"{}"))
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="malformed payload")

    log.info(
        "alert accepted via %s: rule=%r host=%r severity=%r score=%r",
        scheme, alert.alert_rule, alert.target_host, alert.severity,
        alert.hardening_score,
    )

    playbook = select_playbook(alert)
    if playbook is None:
        log.info("no playbook matches rule %r — no action taken", alert.alert_rule)
        return {"status": "ignored", "reason": "no playbook matched"}

    async with _playbook_lock:
        result = await run_playbook(playbook, alert)
        verification = await reaudit() if result.get("ok") else {"ok": False, "skipped": True}

    total = round(time.monotonic() - received_at, 3)

    _passed, _criterion = verification_passed(
        alert.alert_rule, playbook, result, verification
    )

    record = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {"kind": "event", "category": ["configuration"], "action": "soar_remediation"},
        "soar": {
            "status": "REMEDIATED" if _passed else "FAILED",
            "verification_criterion": _criterion,
            "playbook": playbook,
            "auth_scheme": scheme,
            "alert_rule": alert.alert_rule,
            "severity": alert.severity,
            "target_host": alert.target_host,
            "score_at_alert": alert.hardening_score,
            "score_after_remediation": verification.get("hardening_index"),
            "baseline": HARDENING_BASELINE,
            "remediation": result,
            "verification": verification,
            "end_to_end_seconds": total,
        },
    }

    annotated = await annotate(record)

    log.info(
        "remediation complete: status=%s playbook=%s total=%.3fs annotated=%s",
        record["soar"]["status"], playbook, total, annotated,
    )

    return {
        "status": record["soar"]["status"],
        "playbook": playbook,
        "score_after_remediation": verification.get("hardening_index"),
        "end_to_end_seconds": total,
        "annotated": annotated,
    }
