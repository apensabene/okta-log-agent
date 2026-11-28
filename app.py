r"""
OASIS web front end (FastAPI): the same tools and prompt as oasis.py, behind Okta sign-in.
Each chat keeps its own conversation, and every tool call is audited with the signed-in user.

Setup:  pip install -r requirements.txt
Env:    everything oasis.py needs, plus an Okta OIDC Web app for tester sign-in:
        OAUTH_OKTA_DOMAIN=your-org.okta.com          (no https://)
        OAUTH_OKTA_CLIENT_ID=0oa...
        OAUTH_OKTA_CLIENT_SECRET=...
        OAUTH_OKTA_AUTHORIZATION_SERVER_ID=false     (org authorization server; omit to use "default")
        APP_SESSION_SECRET=...                         (strong random secret for session signing)
        APP_BASE_URL=https://your-app.example.com    (public URL; taken from Render automatically)
        Sign-in redirect URI on the Okta app: <public URL>/auth/callback
Run:    uvicorn app:app --host 127.0.0.1 --port 8000
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import anthropic
import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

import oasis

_ALLOWED_USER_STATUSES = {"ACTIVE", "PASSWORD_EXPIRED", "RECOVERY"}
_MAX_HISTORY_MESSAGES = 60
_MAX_SESSIONS = 500
_SESSION_TTL_SECONDS = 8 * 60 * 60

client = anthropic.AsyncAnthropic()

# session_id -> {"user": str, "messages": list[dict[str, Any]], "last_seen": float}
_CONVERSATIONS: dict[str, dict[str, Any]] = {}


def _base_url(request: Request) -> str:
    render_url = os.environ.get("RENDER_EXTERNAL_URL", "").strip()
    if render_url:
        return render_url.rstrip("/")
    configured = os.environ.get("APP_BASE_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    return str(request.base_url).rstrip("/")


def _auth_server_path() -> str:
    domain = os.environ.get("OAUTH_OKTA_DOMAIN", "").strip().removeprefix("https://").removeprefix("http://")
    if not domain:
        raise RuntimeError("Missing OAUTH_OKTA_DOMAIN")
    auth_server_id = os.environ.get("OAUTH_OKTA_AUTHORIZATION_SERVER_ID", "default").strip()
    if auth_server_id.lower() in {"", "false", "org"}:
        return f"https://{domain}/oauth2/v1"
    return f"https://{domain}/oauth2/{quote(auth_server_id, safe='')}/v1"


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _prune_sessions() -> None:
    now = time.monotonic()
    expired = [
        sid for sid, data in _CONVERSATIONS.items()
        if now - data["last_seen"] > _SESSION_TTL_SECONDS
    ]
    for sid in expired:
        _CONVERSATIONS.pop(sid, None)
    while len(_CONVERSATIONS) > _MAX_SESSIONS:
        oldest_sid = min(_CONVERSATIONS, key=lambda k: _CONVERSATIONS[k]["last_seen"])
        _CONVERSATIONS.pop(oldest_sid, None)


def _get_or_create_conv(request: Request, user: str) -> dict[str, Any]:
    _prune_sessions()
    conv_id = request.session.get("conv_id")
    record = _CONVERSATIONS.get(conv_id) if conv_id else None
    if record is None or record["user"] != user:
        conv_id = str(uuid.uuid4())
        request.session["conv_id"] = conv_id
        record = {"user": user, "messages": [], "last_seen": time.monotonic()}
        _CONVERSATIONS[conv_id] = record
    else:
        record["last_seen"] = time.monotonic()
    return record


def _still_authorized(identifier: str) -> bool:
    """Re-check against Okta that the user is enabled and still assigned to the OIDC sign-in app.
    Fails closed: any error or unexpected response denies access."""
    app_id = os.environ.get("OAUTH_OKTA_CLIENT_ID")
    if not identifier or not app_id:
        return False
    try:
        r = requests.get(
            f"{oasis.ORG}/api/v1/users/{quote(identifier, safe='')}",
            headers=oasis._headers(),
            timeout=15,
        )
        if r.status_code != 200:
            return False
        u = r.json()
        if u.get("status") not in _ALLOWED_USER_STATUSES or not u.get("id"):
            return False
        r = requests.get(
            f"{oasis.ORG}/api/v1/apps/{quote(app_id, safe='')}/users/{quote(u['id'], safe='')}",
            headers=oasis._headers(),
            timeout=15,
        )
        if r.status_code != 200:
            return False
        return r.json().get("status") != "INACTIVE"
    except Exception:
        return False


def _exchange_code_for_email(code: str, code_verifier: str, redirect_uri: str) -> str | None:
    client_id = os.environ.get("OAUTH_OKTA_CLIENT_ID", "").strip()
    client_secret = os.environ.get("OAUTH_OKTA_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        return None
    token_url = f"{_auth_server_path()}/token"
    userinfo_url = f"{_auth_server_path()}/userinfo"
    try:
        token_resp = requests.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "code_verifier": code_verifier,
            },
            headers={"Accept": "application/json"},
            timeout=15,
        )
        if token_resp.status_code != 200:
            return None
        access_token = token_resp.json().get("access_token")
        if not access_token:
            return None
        ui_resp = requests.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout=15,
        )
        if ui_resp.status_code != 200:
            return None
        info = ui_resp.json()
        return info.get("email") or info.get("preferred_username") or info.get("sub")
    except Exception:
        return None


async def ask(messages: list[dict[str, Any]], question: str, user: str) -> tuple[str, list[dict[str, Any]]]:
    """Run one question to completion and return (answer, tool_events). Mirrors oasis.ask."""
    messages.append({"role": "user", "content": question})
    tool_events: list[dict[str, Any]] = []

    for _ in range(8):  # hard loop cap
        resp = await client.messages.create(
            model=oasis.MODEL,
            max_tokens=2000,
            system=oasis.SYSTEM,
            tools=oasis.TOOLS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            answer = "".join(b.text for b in resp.content if b.type == "text")
            return answer, tool_events

        results: list[dict[str, Any]] = []
        for b in resp.content:
            if b.type == "tool_use":
                oasis.audit(b.name, b.input, user)
                # The host's disk is not persistent, so the audit trail also goes to the service logs.
                print(
                    f"[audit] {json.dumps({'user': user, 'tool': b.name, 'args': b.input})}",
                    file=sys.stderr,
                    flush=True,
                )
                try:
                    out = await asyncio.to_thread(oasis.TOOL_FUNCS[b.name], **b.input)
                    status = f"Okta error: {out['error']}" if isinstance(out, dict) and out.get("error") else "done"
                except Exception as ex:
                    out = {"error": str(ex)}
                    status = f"Okta error: {out['error']}"
                tool_events.append({"tool": b.name, "status": status})
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": b.id,
                        "content": json.dumps(out),
                    }
                )
        messages.append({"role": "user", "content": results})

    return "Stopped: too many tool calls.", tool_events


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=16000)


session_secret = (
    os.environ.get("APP_SESSION_SECRET")
    or os.environ.get("CHAINLIT_AUTH_SECRET")
    or secrets.token_urlsafe(32)
)
is_production = bool(os.environ.get("RENDER_EXTERNAL_URL") or os.environ.get("APP_BASE_URL", "").startswith("https://"))

app = FastAPI(title="OASIS")
app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    same_site="lax",
    https_only=is_production,
)


@app.get("/auth/login")
async def login(request: Request):
    client_id = os.environ.get("OAUTH_OKTA_CLIENT_ID", "").strip()
    if not client_id:
        raise HTTPException(status_code=500, detail="OAUTH_OKTA_CLIENT_ID is not configured")
    state = secrets.token_urlsafe(24)
    code_verifier = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    request.session["code_verifier"] = code_verifier

    redirect_uri = f"{_base_url(request)}/auth/callback"
    params = {
        "client_id": client_id,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": _code_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    return RedirectResponse(url=f"{_auth_server_path()}/authorize?{urlencode(params)}")


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    if error or not code or not state:
        raise HTTPException(status_code=400, detail="Okta sign-in failed or was cancelled")
    expected_state = request.session.pop("oauth_state", None)
    code_verifier = request.session.pop("code_verifier", None)
    if not expected_state or not code_verifier or state != expected_state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    redirect_uri = f"{_base_url(request)}/auth/callback"
    identifier = await asyncio.to_thread(_exchange_code_for_email, code, code_verifier, redirect_uri)
    authorized = bool(identifier) and await asyncio.to_thread(_still_authorized, identifier)
    if not authorized:
        raise HTTPException(status_code=403, detail="Access denied: your account is not authorized")

    request.session["user"] = identifier
    return RedirectResponse(url="/")


@app.post("/auth/logout")
async def logout(request: Request):
    conv_id = request.session.pop("conv_id", None)
    if conv_id:
        _CONVERSATIONS.pop(conv_id, None)
    request.session.pop("user", None)
    return {"status": "logged_out"}


@app.get("/")
async def index(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/auth/login")
    if not await asyncio.to_thread(_still_authorized, user):
        request.session.clear()
        return HTMLResponse(
            "<h3>Access denied: your account is no longer authorized to use this application.</h3>",
            status_code=403,
        )
    static_ui = Path(__file__).parent / "static" / "index.html"
    if static_ui.exists():
        return FileResponse(static_ui)
    return HTMLResponse(_FALLBACK_HTML)


@app.post("/api/chat")
async def chat(req: ChatRequest, request: Request):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"detail": "Authentication required"}, status_code=401)

    # Re-validate on every message even when a session cookie already exists.
    if not await asyncio.to_thread(_still_authorized, user):
        request.session.clear()
        return JSONResponse(
            {"detail": "Access denied: your account is no longer authorized to use this application."},
            status_code=403,
        )

    conv = _get_or_create_conv(request, user)
    messages = conv["messages"]
    checkpoint = len(messages)

    try:
        answer, tool_events = await ask(messages, req.message, user)
        if len(messages) > _MAX_HISTORY_MESSAGES:
            del messages[: len(messages) - _MAX_HISTORY_MESSAGES]
        return {"user": user, "reply": answer, "tools": tool_events}
    except asyncio.CancelledError:
        del messages[checkpoint:]
        raise
    except Exception as ex:
        del messages[checkpoint:]
        raise HTTPException(status_code=500, detail=f"Error: {ex}") from ex


_FALLBACK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>OASIS</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 840px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #f8fafc; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
    #log { border: 1px solid #334155; border-radius: 8px; padding: 1rem; height: 65vh; overflow-y: auto; background: #1e293b; white-space: pre-wrap; }
    .msg { margin-bottom: 1rem; line-height: 1.5; }
    .user { color: #38bdf8; font-weight: 600; }
    .meta { color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.25rem; }
    form { display: flex; gap: 0.5rem; margin-top: 1rem; }
    input { flex: 1; padding: 0.75rem; border-radius: 6px; border: 1px solid #475569; background: #1e293b; color: #f8fafc; }
    button { padding: 0.75rem 1.25rem; border-radius: 6px; border: none; background: #2563eb; color: #fff; font-weight: 600; cursor: pointer; }
    button.secondary { background: #334155; }
    button:disabled { opacity: 0.5; }
  </style>
</head>
<body>
  <header>
    <h2>OASIS</h2>
    <button id="logout-btn" class="secondary" type="button">Sign out</button>
  </header>
  <div id="log"></div>
  <form id="chat-form">
    <input id="msg-input" type="text" placeholder="Ask OASIS about Okta logs or users..." autocomplete="off" required />
    <button id="send-btn" type="submit">Send</button>
  </form>
  <script>
    const log = document.getElementById("log");
    const form = document.getElementById("chat-form");
    const input = document.getElementById("msg-input");
    const sendBtn = document.getElementById("send-btn");
    const logoutBtn = document.getElementById("logout-btn");

    function appendLine(cls, text) {
      const el = document.createElement("div");
      el.className = cls;
      el.textContent = text;
      log.appendChild(el);
      log.scrollTop = log.scrollHeight;
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const text = input.value.trim();
      if (!text) return;
      appendLine("msg user", "You: " + text);
      input.value = "";
      sendBtn.disabled = true;
      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: text })
        });
        if (res.status === 401) {
          window.location.href = "/auth/login";
          return;
        }
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Request failed");
        if (data.tools && data.tools.length) {
          appendLine("meta", "Tools: " + data.tools.map(t => `${t.tool} (${t.status})`).join(", "));
        }
        appendLine("msg", "OASIS: " + data.reply);
      } catch (err) {
        appendLine("msg", "Error: " + err.message);
      } finally {
        sendBtn.disabled = false;
        input.focus();
      }
    });

    logoutBtn.addEventListener("click", async () => {
      await fetch("/auth/logout", { method: "POST" });
      window.location.href = "/auth/login";
    });
  </script>
</body>
</html>
"""