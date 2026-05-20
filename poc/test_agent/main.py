"""
Mock cluster agent for the SCP poc stack.

Mirrors the wire contract of cmd/scp-agent: registers with the panel on
startup, accepts events at POST /api/v1/events, and posts a fake
Callback back to the panel after a short delay so the end-to-end flow
can be exercised without a real Kubernetes cluster.
"""

import logging
import os
import random
import sys
import threading
import time

import requests
from flask import Flask, request

EVENTS_PATH = "/api/v1/events"
HEALTH_PATH = "/api/v1/healthz"
AGENT_REGISTER_PATH = "/api/v1/agents/register"
CALLBACK_PATH = "/api/v1/callbacks"
AUTH_HEADER = "Authorization"
AUTH_SCHEME = "Bearer "

REGISTER_MAX_ATTEMPTS = 6
REGISTER_RETRY_SECONDS = 10
HTTP_TIMEOUT_SECONDS = 5


def _env(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        print(f"missing required env: {name}", file=sys.stderr)
        sys.exit(2)
    return v


CLUSTER = _env("SCP_CLUSTER", required=True)
EXTERNAL_URL = _env("SCP_URL", required=True)
TOKEN = _env("SCP_TOKEN", required=True)
PANEL_URL = _env("SCP_PANEL_URL", required=True)
PANEL_TOKEN = _env("SCP_PANEL_TOKEN", required=True)
LISTEN_HOST = _env("SCP_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(_env("SCP_LISTEN_PORT", "8081"))
SYNC_DELAY_MS = int(_env("SCP_SYNC_DELAY_MS", "500"))
FAIL_RATE = float(_env("SCP_FAIL_RATE", "0.0"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("agent")

app = Flask(__name__)


def _authorized() -> bool:
    return request.headers.get(AUTH_HEADER, "") == AUTH_SCHEME + TOKEN


@app.get(HEALTH_PATH)
def healthcheck() -> tuple[str, int]:
    return "ok\n", 200


@app.post(EVENTS_PATH)
def events() -> tuple[str, int]:
    if not _authorized():
        return "unauthorized", 401
    ev = request.get_json(silent=True) or {}
    log.info(
        "event received request_id=%s op=%s path=%s/%s version=%s",
        ev.get("request_id"),
        ev.get("operation"),
        ev.get("mount"),
        ev.get("path"),
        ev.get("version"),
    )
    threading.Thread(target=_send_callback, args=(ev,), daemon=True).start()
    return "", 202


def _send_callback(ev: dict) -> None:
    started = time.time()
    time.sleep(SYNC_DELAY_MS / 1000.0)
    synced = random.random() >= FAIL_RATE
    body = {
        "request_id": ev.get("request_id", ""),
        "cluster": CLUSTER,
        "synced": synced,
        "matched": 1,
        "patched": 1 if synced else 0,
        "elapsed_ms": int((time.time() - started) * 1000),
    }
    headers = {
        AUTH_HEADER: AUTH_SCHEME + PANEL_TOKEN,
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(
            PANEL_URL + CALLBACK_PATH,
            json=body,
            headers=headers,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        if resp.status_code >= 300:
            log.warning(
                "callback rejected request_id=%s status=%d body=%s",
                body["request_id"],
                resp.status_code,
                resp.text[:200],
            )
        else:
            log.info(
                "callback sent request_id=%s synced=%s",
                body["request_id"],
                synced,
            )
    except requests.RequestException as e:
        log.warning("callback failed request_id=%s err=%s", body["request_id"], e)


def _register_with_panel() -> None:
    body = {"cluster": CLUSTER, "url": EXTERNAL_URL, "token": TOKEN}
    headers = {
        AUTH_HEADER: AUTH_SCHEME + PANEL_TOKEN,
        "Content-Type": "application/json",
    }
    for attempt in range(1, REGISTER_MAX_ATTEMPTS + 1):
        try:
            resp = requests.post(
                PANEL_URL + AGENT_REGISTER_PATH,
                json=body,
                headers=headers,
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            if resp.status_code < 300:
                log.info("registered with panel panel_url=%s", PANEL_URL)
                return
            log.warning(
                "register rejected status=%d body=%s attempt=%d",
                resp.status_code,
                resp.text[:200],
                attempt,
            )
        except requests.RequestException as e:
            log.warning("register failed err=%s attempt=%d", e, attempt)
        time.sleep(REGISTER_RETRY_SECONDS)
    log.error("could not register with panel after %d attempts", REGISTER_MAX_ATTEMPTS)


if __name__ == "__main__":
    log.info(
        "mock-agent starting cluster=%s url=%s panel=%s listen=%s:%d",
        CLUSTER,
        EXTERNAL_URL,
        PANEL_URL,
        LISTEN_HOST,
        LISTEN_PORT,
    )
    threading.Thread(target=_register_with_panel, daemon=True).start()
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)