"""
OASIS (Okta Access Security Intelligence System): read-only Okta IAM troubleshooting agent (v2).
Tools: search_logs (paginated + summarized), get_user_status, get_user_authenticators,
       find_apps, get_user_apps, get_app_assignments.

Setup:  pip install anthropic requests "pyjwt[crypto]"
Auth:   OAuth 2.0 client credentials against the Okta org authorization server, using an
        API Services app (OIDC app type) with private_key_jwt client authentication.
Env:    OKTA_ORG_URL=https://your-org.okta.com
        OKTA_CLIENT_ID=0oa...                            (client ID of the API Services app)
        OKTA_PRIVATE_KEY_FILE=/path/to/private_key.pem   (private key, PEM or JWK; public half registered on the app)
        OKTA_KEY_ID=...                                  (optional kid; needed if the app has more than one key)
        OKTA_SCOPES=okta.logs.read okta.users.read okta.apps.read   (optional, space-separated; default below)
        ANTHROPIC_API_KEY=...
        ANTHROPIC_MODEL=claude-sonnet-5-5                (optional override)
Run:    python oasis.py                 (interactive prompt; "new" resets, "exit" quits)
        python oasis.py "why is jdoe@example.com failing to sign in today?"   (one question, then exit)
Test tenant / lab data only until your org approves this.
"""
import os, sys, json, time, uuid, collections, datetime as dt
import requests
import jwt
import anthropic

_missing = [v for v in ("OKTA_ORG_URL", "OKTA_CLIENT_ID", "OKTA_PRIVATE_KEY_FILE") if not os.environ.get(v)]
if _missing:
    sys.exit(f"Missing environment variable(s): {', '.join(_missing)}. See the setup notes at the top of this file.")

ORG = os.environ["OKTA_ORG_URL"].rstrip("/")
CLIENT_ID = os.environ["OKTA_CLIENT_ID"]
TOKEN_URL = f"{ORG}/oauth2/v1/token"  # org authorization server (the only one that issues okta.* scopes)
# Least privilege: logs for search_logs, users for get_user_status and the /users/{id}/factors listing,
# apps for the app assignment tools.
SCOPES = os.environ.get("OKTA_SCOPES", "okta.logs.read okta.users.read okta.apps.read")
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")

PAGE_SIZE = 100        # events per API page (Okta max 1000)
MAX_PAGES = 10         # hard cap on pages fetched per query
MAX_EVENTS = 1000      # hard cap on total events pulled per query
SAMPLE_SIZE = 40       # events actually shown to the model (rest are summarized)
MAX_ASSIGNEES = 1000   # hard cap on app users/groups fetched per app
ASSIGNEE_SAMPLE = 200  # assigned users actually shown to the model (rest are counted)


# ---------- auth ----------
_token = {"value": None, "expires_at": 0}


def _private_key():
    with open(os.environ["OKTA_PRIVATE_KEY_FILE"], encoding="utf-8") as f:
        raw = f.read().strip()
    return jwt.algorithms.RSAAlgorithm.from_jwk(raw) if raw.startswith("{") else raw


def _access_token():
    """Client-credentials token, authenticated with a signed JWT assertion. Cached until near expiry."""
    if _token["value"] and time.time() < _token["expires_at"] - 60:
        return _token["value"]
    now = int(time.time())
    kid = os.environ.get("OKTA_KEY_ID")
    assertion = jwt.encode(
        {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": TOKEN_URL,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        },
        _private_key(),
        algorithm="RS256",
        headers={"kid": kid} if kid else None,
    )
    r = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "scope": SCOPES,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        },
        headers={"Accept": "application/json"},
        timeout=30,
    )
    if not r.ok:
        raise RuntimeError(f"Okta token request failed ({r.status_code}): {r.text}")
    body = r.json()
    _token["value"] = body["access_token"]
    _token["expires_at"] = time.time() + int(body.get("expires_in", 3600))
    return _token["value"]


def _headers():
    return {"Authorization": f"Bearer {_access_token()}", "Accept": "application/json"}


# ---------- helpers ----------
def _q(s):
    return str(s).replace('"', "").replace("\\", "")


def _slim(e):
    return {
        "time": e.get("published"),
        "event": e.get("eventType"),
        "result": (e.get("outcome") or {}).get("result"),
        "reason": (e.get("outcome") or {}).get("reason"),
        "user": (e.get("actor") or {}).get("alternateId"),
        "app": next((t.get("displayName") for t in e.get("target") or [] if t.get("type") == "AppInstance"), None),
        "ip": (e.get("client") or {}).get("ipAddress"),
        "geo": ((e.get("client") or {}).get("geographicalContext") or {}).get("country"),
        "device": ((e.get("client") or {}).get("userAgent") or {}).get("rawUserAgent"),
        "credential": (e.get("authenticationContext") or {}).get("credentialType"),
        "message": e.get("displayMessage"),
    }


def _top(counter, n=8):
    return [{"value": k, "count": v} for k, v in counter.most_common(n) if k is not None]


def _get_all(url, params=None, cap=MAX_ASSIGNEES):
    """Follow Link: rel="next" pagination up to cap items. Returns (items, truncated)."""
    items, truncated = [], False
    while url:
        r = requests.get(url, headers=_headers(), params=params, timeout=30)
        r.raise_for_status()
        items.extend(r.json())
        params = None
        url = (r.links.get("next") or {}).get("url")
        if url and len(items) >= cap:
            truncated = True
            break
    return items[:cap], truncated


def _slim_app(a):
    return {
        "id": a.get("id"),
        "label": a.get("label"),
        "integration": a.get("name"),
        "status": a.get("status"),
        "signOnMode": a.get("signOnMode"),
    }


def _resolve_app(app):
    """App ID or label -> slim app dict, or an error dict listing candidates when ambiguous."""
    app = str(app).strip()
    if app.startswith("0oa") and " " not in app:
        r = requests.get(f"{ORG}/api/v1/apps/{_q(app)}", headers=_headers(), timeout=30)
        if r.status_code == 404:
            return {"error": "App not found"}
        r.raise_for_status()
        return _slim_app(r.json())
    r = requests.get(f"{ORG}/api/v1/apps", headers=_headers(), params={"q": app, "limit": 50}, timeout=30)
    r.raise_for_status()
    matches = [_slim_app(a) for a in r.json()]
    exact = [a for a in matches if (a["label"] or "").lower() == app.lower()]
    if len(exact) == 1:
        return exact[0]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        return {"error": f"No app matches '{app}'. Try find_apps with a shorter name."}
    return {"error": "Multiple apps match. Ask which one, then retry with its id.", "candidates": matches}


# ---------- tools ----------
def search_logs(user=None, event_type=None, outcome=None, hours_back=24, keyword=None):
    """Paginated System Log search. Returns totals + breakdowns + a sample of recent events."""
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=min(int(hours_back), 168))).strftime("%Y-%m-%dT%H:%M:%SZ")
    clauses = []
    if user:
        clauses.append(f'actor.alternateId eq "{_q(user)}"')
    if event_type:
        clauses.append(f'eventType eq "{_q(event_type)}"')
    if outcome in ("SUCCESS", "FAILURE", "SKIPPED", "ALLOW", "DENY", "CHALLENGE", "UNKNOWN"):
        clauses.append(f'outcome.result eq "{outcome}"')
    params = {"since": since, "limit": PAGE_SIZE, "sortOrder": "DESCENDING"}
    if clauses:
        params["filter"] = " and ".join(clauses)
    if keyword:
        params["q"] = keyword

    events, pages, url, truncated = [], 0, f"{ORG}/api/v1/logs", False
    while url:
        r = requests.get(url, headers=_headers(), params=params if pages == 0 else None, timeout=30)
        if r.status_code == 429:
            return {"error": "Okta rate limit hit (429). Narrow the query or retry later.", "events_fetched": len(events)}
        r.raise_for_status()
        events.extend(_slim(e) for e in r.json())
        pages += 1
        url = (r.links.get("next") or {}).get("url")  # Okta uses Link: rel="next"
        if url and (pages >= MAX_PAGES or len(events) >= MAX_EVENTS):
            truncated = True
            break
    events = events[:MAX_EVENTS]

    return {
        "total_events": len(events),
        "pages_fetched": pages,
        "truncated": truncated,
        "note": "Truncated: more events exist. Narrow user/event_type/outcome/hours_back." if truncated else None,
        "breakdown": {
            "by_event": _top(collections.Counter(e["event"] for e in events)),
            "by_result": _top(collections.Counter(e["result"] for e in events)),
            "by_reason": _top(collections.Counter(e["reason"] for e in events)),
            "by_user": _top(collections.Counter(e["user"] for e in events)),
            "by_ip": _top(collections.Counter(e["ip"] for e in events)),
            "by_country": _top(collections.Counter(e["geo"] for e in events)),
            "by_app": _top(collections.Counter(e["app"] for e in events)),
        },
        "first_event_time": events[-1]["time"] if events else None,
        "last_event_time": events[0]["time"] if events else None,
        "sample_most_recent": events[:SAMPLE_SIZE],
    }


def get_user_status(user):
    """Account state only: no profile PII beyond login."""
    r = requests.get(f"{ORG}/api/v1/users/{_q(user)}", headers=_headers(), timeout=30)
    if r.status_code == 404:
        return {"error": "User not found"}
    r.raise_for_status()
    u = r.json()
    return {
        "id": u.get("id"),
        "login": (u.get("profile") or {}).get("login"),
        "status": u.get("status"),  # ACTIVE, LOCKED_OUT, SUSPENDED, PASSWORD_EXPIRED, DEPROVISIONED, ...
        "created": u.get("created"),
        "activated": u.get("activated"),
        "statusChanged": u.get("statusChanged"),
    }