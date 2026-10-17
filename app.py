"""PQConnect backend: serves the site and the prediction API on LinuxONE.

Merged from the team's original app.py. Its endpoints still work (/api/ping, /api/payload-512k,
/api/estimate-telemetry, /api/predict) and the new frontend's endpoints are added.

Model features (the team's names, used everywhere):
    prev_auth_delay, recent_avg_auth_delay, recent_mac_retry_indicator,
    recent_phy_drop_indicator, recent_observed_throughput, recent_phy_tx_duration

What the browser can and cannot measure:
    measured / approximated: round trips to this server and a timed download
    not measurable from a browser: MAC retries, PHY drops, PHY Tx duration.
    Those use typical values from models/feature_defaults.json (dataset medians, see README)
    and are labelled "Assumed" everywhere. Nothing is invented from thresholds.

Files the server reads from models/ (all optional):
    latency_model.joblib   sklearn-style estimator with .predict(DataFrame) -> delay in ms
    feature_map.json       maps this server's column / algorithm names to the training ones
    feature_defaults.json  typical values for the inputs a browser cannot measure
    configs.json           [[ee_alg, ca_alg], ...] pairs present in the dataset
    model_info.json        {"model", "trained_rows", "metrics": {...}} shown in the UI
Without latency_model.joblib the server answers with mock predictions, flagged as mock.

Security: sign-in with scrypt-hashed passwords (manage_users.py), HttpOnly/Secure/SameSite=Strict
session cookie with 30 min idle timeout, CSRF token on every POST, sign-in lockout, strict CSP,
server-side validation of every input, HTTPS only unless PQCONNECT_DEV_HTTP=1. No debug mode.

Run:  PQCONNECT_DEV_HTTP=1 python app.py          (local, plain HTTP)
      python app.py                              (HTTPS, needs instance/tls/cert.pem + key.pem)
Env:  PQCONNECT_HOST (default 127.0.0.1), PQCONNECT_PORT (default 5000), PQCONNECT_MOCK=0 to refuse mock
"""
import csv
import io
import json
import logging
import math
import os
import platform
import secrets
import socket
import sys
import time
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, session
from flask.sessions import SecureCookieSessionInterface
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
INSTANCE = ROOT / "instance"
MODELS = ROOT / "models"
INSTANCE.mkdir(exist_ok=True)

DEV_HTTP = os.environ.get("PQCONNECT_DEV_HTTP") == "1"
ALLOW_MOCK = os.environ.get("PQCONNECT_MOCK", "1") != "0"


def _secret_key():
    env = os.environ.get("PQCONNECT_SECRET_KEY")
    if env:
        return env
    p = INSTANCE / "secret_key"
    if not p.exists():
        p.write_text(secrets.token_hex(32))
        p.chmod(0o600)
    return p.read_text().strip()


def _json(name, default):
    p = MODELS / name
    return json.loads(p.read_text()) if p.exists() else default


app = Flask(__name__)  # templates/ and static/ next to this file

# Probe responses must be as small as possible: on a slow link every extra byte of header shows up
# as fake latency. So probes don't refresh the session cookie and get only minimal headers.
PROBE_PATHS = {"/api/probe/ping", "/api/ping", "/api/probe/download", "/api/payload-512k"}


class _ProbeAwareSessions(SecureCookieSessionInterface):
    def should_set_cookie(self, app, sess):
        if request.path in PROBE_PATHS and not sess.modified:
            return False
        return super().should_set_cookie(app, sess)


app.session_interface = _ProbeAwareSessions()
app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_NAME="pqc_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=not DEV_HTTP,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

audit = logging.getLogger("pqconnect.audit")
_h = logging.FileHandler(INSTANCE / "audit.log")
_h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
audit.addHandler(_h)
audit.setLevel(logging.INFO)

HOST = {"arch": platform.machine(), "hostname": socket.gethostname()}

# ---------------------------------------------------------------- algorithms (FIPS 204/205 sizes in bytes)
SLH_SIG = {"128s": 7856, "128f": 17088, "192s": 16224, "192f": 35664, "256s": 29792, "256f": 49856}
ALGS = [
    {"name": "ML-DSA-44", "family": "ML-DSA", "category": 2, "pk": 1312, "sig": 2420},
    {"name": "ML-DSA-65", "family": "ML-DSA", "category": 3, "pk": 1952, "sig": 3309},
    {"name": "ML-DSA-87", "family": "ML-DSA", "category": 5, "pk": 2592, "sig": 4627},
]
for _hash in ("SHA2", "SHAKE"):
    for _lvl, _cat in ((128, 1), (192, 3), (256, 5)):
        for _v in ("s", "f"):
            ALGS.append({"name": f"SLH-DSA-{_hash}-{_lvl}{_v}", "family": f"SLH-DSA ({_hash})", "category": _cat,
                         "pk": _lvl // 4, "sig": SLH_SIG[f"{_lvl}{_v}"]})
ALG_BY_NAME = {a["name"]: a for a in ALGS}


def _load_configs():
    pairs = _json("configs.json", None)
    if pairs is None:
        return [(e["name"], c["name"]) for e in ALGS for c in ALGS], False
    good = [(ee, ca) for ee, ca in pairs if ee in ALG_BY_NAME and ca in ALG_BY_NAME]
    if len(good) != len(pairs):
        print(f"WARNING: {len(pairs) - len(good)} pairs in configs.json use names other than 'ML-DSA-65' / "
              f"'SLH-DSA-SHA2-192f' style and were skipped. Map them in feature_map.json.", file=sys.stderr)
    return good, True


CONFIGS, CONFIGS_FROM_DATA = _load_configs()

# ---------------------------------------------------------------- telemetry features (the team's names)
TELEMETRY_SPEC = {
    "prev_auth_delay":            {"label": "Previous auth delay (ms)",       "min": 0, "max": 600000, "step": 1},
    "recent_avg_auth_delay":      {"label": "Recent average auth delay (ms)", "min": 0, "max": 600000, "step": 1},
    "recent_mac_retry_indicator": {"label": "MAC retry indicator",            "min": 0, "max": 1000,   "step": 0.1},
    "recent_phy_drop_indicator":  {"label": "PHY drop indicator",             "min": 0, "max": 1000,   "step": 0.01},
    "recent_observed_throughput": {"label": "Observed throughput (Mbps)",     "min": 0, "max": 100000, "step": 0.1},
    "recent_phy_tx_duration":     {"label": "PHY Tx duration (ms)",           "min": 0, "max": 100000, "step": 0.1},
}
LATENCY_KEYS = ["prev_auth_delay", "recent_avg_auth_delay"]   # scaled in "busier network" scenarios
BANDWIDTH_KEYS = ["recent_observed_throughput"]

# Typical values for what a browser cannot see. Placeholder = the middle band of the old estimator,
# until train.py writes dataset medians to models/feature_defaults.json.
_PLACEHOLDER_DEFAULTS = {"prev_auth_delay": 300, "recent_avg_auth_delay": 300, "recent_mac_retry_indicator": 0.8,
                         "recent_phy_drop_indicator": 0.08, "recent_observed_throughput": 15, "recent_phy_tx_duration": 3.5}
_file_defaults = _json("feature_defaults.json", None)
FEATURE_DEFAULTS = {**_PLACEHOLDER_DEFAULTS, **(_file_defaults or {})}
DEFAULTS_FROM_DATA = _file_defaults is not None
DEFAULT_NOTE = "Typical value from the training data" if DEFAULTS_FROM_DATA else "Placeholder typical value (no feature_defaults.json yet)"

# Example networks, only for the API's legacy callers; the UI no longer uses them.
PRESETS = {
    "good":     {**FEATURE_DEFAULTS, "prev_auth_delay": 120, "recent_avg_auth_delay": 125, "recent_observed_throughput": 40},
    "moderate": dict(FEATURE_DEFAULTS),
    "poor":     {**FEATURE_DEFAULTS, "prev_auth_delay": 900, "recent_avg_auth_delay": 850, "recent_observed_throughput": 4},
}


def clean_telemetry(d):
    if not isinstance(d, dict):
        raise ValueError("telemetry must be an object")
    out = {}
    for key, spec in TELEMETRY_SPEC.items():
        try:
            v = float(d.get(key))
        except (TypeError, ValueError):
            raise ValueError(f"{spec['label']}: enter a number")
        if not math.isfinite(v) or v < spec["min"] or v > spec["max"]:
            raise ValueError(f"{spec['label']}: must be between {spec['min']} and {spec['max']}")
        out[key] = v
    return out


def _num(v, lo=0.0, hi=1e7):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) and lo <= v <= hi else None


def estimate_telemetry(body):
    """Turn what the browser measured into the 6 model inputs, with the source of each value.

    Accepts the new fields (pings_ms, download_mbps, hint, typical) and the old ones (latency, throughput).
    """
    pings = [p for p in (_num(x, 0, 60000) for x in (body.get("pings_ms") or [])[:50]) if p is not None]
    latency = _num(body.get("latency"), 0, 60000)
    dl = _num(body.get("download_mbps"), 1e-6, 100000)       # a zero rate is a failed test, not a measurement
    if dl is None:
        dl = _num(body.get("throughput"), 1e-6, 100000)
    dl_bytes = _num(body.get("download_bytes"), 1, 1e10)
    timing = body.get("timing") if body.get("timing") in ("resource", "wallclock") else None
    how = {"resource": " (browser Resource Timing)", "wallclock": " (JavaScript clock)"}.get(timing, "")
    hint = body.get("hint") if isinstance(body.get("hint"), dict) else {}
    hint_rtt, hint_dl = _num(hint.get("rtt"), 1e-6, 60000), _num(hint.get("downlink"), 1e-6, 100000)
    typical = bool(body.get("typical"))

    rows = {}

    def put(key, value, source, note):
        spec = TELEMETRY_SPEC[key]
        rows[key] = {"key": key, "label": spec["label"], "value": round(min(spec["max"], max(spec["min"], value)), 4),
                     "source": source, "note": note}

    if pings and not typical:
        put("prev_auth_delay", pings[-1], "Approximated", f"Last request round trip to the server{how}")
        last5 = pings[-5:]
        put("recent_avg_auth_delay", sum(last5) / len(last5), "Approximated", f"Mean of the last {len(last5)} round trips{how}")
    elif latency is not None and not typical:
        put("prev_auth_delay", latency, "Approximated", "Average request round trip to the server")
        put("recent_avg_auth_delay", latency, "Approximated", "Average request round trip to the server")
    elif hint_rtt and not typical:
        put("prev_auth_delay", hint_rtt, "Browser estimate", "Round trip reported by the browser")
        put("recent_avg_auth_delay", hint_rtt, "Browser estimate", "Round trip reported by the browser")
    else:
        put("prev_auth_delay", FEATURE_DEFAULTS["prev_auth_delay"], "Assumed", DEFAULT_NOTE)
        put("recent_avg_auth_delay", FEATURE_DEFAULTS["recent_avg_auth_delay"], "Assumed", DEFAULT_NOTE)

    if dl is not None and not typical:
        put("recent_observed_throughput", dl, "Measured",
            "Timed download from the server" + (f", {int(dl_bytes):,} bytes" if dl_bytes else "")
            + {"resource": ", first to last byte (browser Resource Timing)", "wallclock": " (JavaScript clock, includes one round trip)"}.get(body.get("download_timing"), ""))
    elif hint_dl and not typical:
        put("recent_observed_throughput", hint_dl, "Browser estimate", "Bandwidth reported by the browser")
    else:
        put("recent_observed_throughput", FEATURE_DEFAULTS["recent_observed_throughput"], "Assumed", DEFAULT_NOTE)

    put("recent_mac_retry_indicator", FEATURE_DEFAULTS["recent_mac_retry_indicator"], "Assumed", "Browsers cannot see Wi-Fi MAC retries. " + DEFAULT_NOTE)
    put("recent_phy_drop_indicator", FEATURE_DEFAULTS["recent_phy_drop_indicator"], "Assumed", "Browsers cannot see PHY frame drops. " + DEFAULT_NOTE)
    put("recent_phy_tx_duration", FEATURE_DEFAULTS["recent_phy_tx_duration"], "Assumed", "Browsers cannot see PHY transmit time. " + DEFAULT_NOTE)

    ordered = [rows[k] for k in TELEMETRY_SPEC]
    return {r["key"]: r["value"] for r in ordered}, ordered


# ---------------------------------------------------------------- model
FEATURE_MAP = _json("feature_map.json", {})      # {"columns": {our: theirs}, "algorithms": {our: theirs}}
COL_MAP = FEATURE_MAP.get("columns", {})
ALG_MAP = FEATURE_MAP.get("algorithms", {})
_model, _model_checked, _model_error = None, False, None


def get_model():
    global _model, _model_checked, _model_error
    if not _model_checked:
        _model_checked = True
        p = MODELS / "latency_model.joblib"
        if p.exists():
            try:
                import joblib
                _model = joblib.load(p)
            except Exception as e:  # report instead of crashing the site
                _model_error = f"latency_model.joblib failed to load: {e}"
                print("ERROR:", _model_error, file=sys.stderr)
    return _model


class ModelUnavailable(Exception):
    pass


class ModelMismatch(Exception):
    pass


def model_frame(telemetry, pairs):
    """The one place that must match train.py. Builds the DataFrame the model was fitted on."""
    import pandas as pd
    rows = [{**telemetry, "ee_alg": ALG_MAP.get(ee, ee), "ca_alg": ALG_MAP.get(ca, ca)} for ee, ca in pairs]
    frame = pd.DataFrame(rows).rename(columns=COL_MAP)
    expected = getattr(get_model(), "feature_names_in_", None)
    if expected is not None:
        missing = [c for c in expected if c not in frame.columns]
        if missing:
            raise ModelMismatch("The model expects columns this server does not build: " + ", ".join(missing)
                                + ". Map them in models/feature_map.json under \"columns\".")
        frame = frame[list(expected)]
    return frame


def mock_predict(t, ee, ca):
    """Placeholder formula so the site works before the model exists. Never quote these numbers."""
    size = ee["sig"] + ee["pk"] + 2 * ca["sig"] + ca["pk"] + 600
    tput = max(t["recent_observed_throughput"], 0.5)
    loss = 1 + 0.5 * t["recent_mac_retry_indicator"] + 2 * t["recent_phy_drop_indicator"]
    tx = size * 8 / (tput * 1000) * loss
    base = 0.6 * t["prev_auth_delay"] + 0.4 * t["recent_avg_auth_delay"]
    return 0.35 * base + 6 * tx + 2 * math.ceil(size / 1400) * loss


def predict(telemetry, pairs):
    model = get_model()
    if model is not None:
        return [float(x) for x in model.predict(model_frame(telemetry, pairs))], False
    if ALLOW_MOCK:
        return [mock_predict(telemetry, ALG_BY_NAME[ee], ALG_BY_NAME[ca]) for ee, ca in pairs], True
    raise ModelUnavailable(_model_error or "The prediction model is not loaded on the server yet.")


def model_info():
    info = _json("model_info.json", {})
    info["loaded"] = get_model() is not None
    if _model_error:
        info["error"] = _model_error
    return info


def score(telemetry, min_cat, target, allowed, pairs=None):
    pairs = [(ee, ca) for ee, ca in (pairs or CONFIGS) if ee in allowed and ca in allowed]
    if not pairs:
        raise ValueError("No known certificate chain uses only the allowed algorithms.")
    preds, mock = predict(telemetry, pairs)
    results = []
    for (ee, ca), ms in zip(pairs, preds):
        ce, cc = ALG_BY_NAME[ee]["category"], ALG_BY_NAME[ca]["category"]
        chain = min(ce, cc)
        results.append({"ee_alg": ee, "ca_alg": ca, "ee_category": ce, "ca_category": cc, "chain_category": chain,
                        "eligible": chain >= min_cat, "predicted_ms": round(ms, 2), "meets_target": ms <= target})
    eligible = sorted((r for r in results if r["eligible"]), key=lambda r: r["predicted_ms"])
    return results, (eligible[0] if eligible else None), mock


# ---------------------------------------------------------------- auth
USERS_FILE = INSTANCE / "users.json"
DUMMY_HASH = generate_password_hash(secrets.token_hex(16))
FAILED = {}
LOCK_WINDOW, LOCK_LIMIT = 300, 5


def load_users():
    return json.loads(USERS_FILE.read_text()) if USERS_FILE.exists() else {}


def locked_out(ip):
    now = time.time()
    FAILED[ip] = [t for t in FAILED.get(ip, []) if now - t < LOCK_WINDOW]
    return len(FAILED[ip]) >= LOCK_LIMIT


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if "user" not in session:
            return jsonify(error="Sign in to continue."), 401
        return fn(*a, **kw)
    return wrapper


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent, real = request.headers.get("X-CSRF-Token", ""), session.get("csrf", "")
        if not real or not secrets.compare_digest(sent, real):
            if "user" not in session and request.path != "/api/login":
                return jsonify(error="Sign in to continue."), 401
            return jsonify(error="Your session token is out of date. Reload the page."), 403


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    if request.path in PROBE_PATHS:  # not documents: CSP and friends do nothing here but add bytes
        resp.headers["Cache-Control"] = "no-store"
        return resp
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'; object-src 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not DEV_HTTP:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/session")
def get_session():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return jsonify(authenticated="user" in session, user=session.get("user"), csrf=session["csrf"])


@app.post("/api/login")
def login():
    ip = request.remote_addr or "?"
    if locked_out(ip):
        audit.info("login_locked ip=%s", ip)
        return jsonify(error="Too many failed sign-ins. Try again in 5 minutes."), 429
    body = request.get_json(silent=True) or {}
    username, password = str(body.get("username", ""))[:64], str(body.get("password", ""))[:256]
    stored = load_users().get(username)
    if not (check_password_hash(stored or DUMMY_HASH, password) and stored is not None):
        FAILED.setdefault(ip, []).append(time.time())
        audit.info("login_failed user=%r ip=%s", username, ip)
        return jsonify(error="Wrong username or password."), 401
    FAILED.pop(ip, None)
    session.clear()
    session.permanent = True
    session["user"] = username
    session["csrf"] = secrets.token_urlsafe(32)
    audit.info("login_ok user=%r ip=%s", username, ip)
    return jsonify(user=username, csrf=session["csrf"])


@app.post("/api/logout")
def logout():
    audit.info("logout user=%r", session.get("user"))
    session.clear()
    return jsonify(ok=True)


# ---------------------------------------------------------------- pages and metadata
@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/meta")
@login_required
def meta():
    return jsonify(
        user=session["user"],
        algorithms=[{k: a[k] for k in ("name", "family", "category", "pk", "sig")} for a in ALGS],
        telemetry_fields=[{"key": k, **v} for k, v in TELEMETRY_SPEC.items()],
        latency_keys=LATENCY_KEYS, bandwidth_keys=BANDWIDTH_KEYS,
        unmeasured_defaults=FEATURE_DEFAULTS, defaults_from_data=DEFAULTS_FROM_DATA,
        presets=PRESETS,
        model=model_info(),
        mock=get_model() is None and ALLOW_MOCK,
        configs_from_data=CONFIGS_FROM_DATA, n_configs=len(CONFIGS),
        host=HOST,
    )


# ---------------------------------------------------------------- network probes
PROBE_MAX_BYTES = 8 * 1024 * 1024
_PROBE_BLOB = os.urandom(PROBE_MAX_BYTES)  # random so nothing in the path can compress it


@app.get("/api/probe/ping")
@app.get("/api/ping")                     # original endpoint, kept
@login_required
def probe_ping():
    if request.path == "/api/ping":           # original endpoint keeps its JSON body
        return jsonify(status="ok")
    return Response(status=204)               # new probe: empty, so only the round trip is timed


@app.get("/api/probe/download")
@login_required
def probe_download():
    try:
        n = int(request.args.get("bytes", 262144))
    except ValueError:
        return jsonify(error="bytes must be a whole number"), 400
    n = max(1024, min(n, PROBE_MAX_BYTES))
    return Response(_PROBE_BLOB[:n], mimetype="application/octet-stream",
                    headers={"Content-Length": str(n), "Cache-Control": "no-store", "Content-Encoding": "identity"})


@app.get("/api/payload-512k")             # original endpoint, kept
@login_required
def payload_512k():
    return Response(_PROBE_BLOB[:512 * 1024], mimetype="application/octet-stream",
                    headers={"Cache-Control": "no-store", "Content-Encoding": "identity"})


@app.post("/api/estimate-telemetry")
@login_required
def estimate_telemetry_route():
    flat, rows = estimate_telemetry(request.get_json(silent=True) or {})
    return jsonify({**flat, "inputs": rows, "defaults_from_data": DEFAULTS_FROM_DATA})


# ---------------------------------------------------------------- prediction
def _policy(body):
    min_cat = int(body.get("min_category", 3))
    if min_cat not in (1, 2, 3, 5):
        raise ValueError("Minimum category must be 1, 2, 3 or 5.")
    target = float(body.get("target_ms", 500))
    if not math.isfinite(target) or not 1 <= target <= 600000:
        raise ValueError("Delay target must be between 1 and 600000 ms.")
    allowed = body.get("allowed_algs", [a["name"] for a in ALGS])
    if not isinstance(allowed, list) or not allowed or len(allowed) > len(ALGS) or any(a not in ALG_BY_NAME for a in allowed):
        raise ValueError("Allowed algorithms must be a non-empty list of known algorithm names.")
    return min_cat, target, set(allowed)


@app.post("/api/recommend")
@login_required
def recommend():
    body = request.get_json(silent=True) or {}
    try:
        telemetry = clean_telemetry(body.get("telemetry"))
        min_cat, target, allowed = _policy(body)
        results, rec, mock = score(telemetry, min_cat, target, allowed)
    except (TypeError, ValueError) as e:
        return jsonify(error=str(e)), 400
    except ModelMismatch as e:
        return jsonify(error=str(e)), 500
    except ModelUnavailable as e:
        return jsonify(error=str(e)), 503
    audit.info("analysis user=%r min_cat=%d target=%s n=%d rec=%s mock=%s", session["user"], min_cat, target,
               len(results), f"{rec['ee_alg']}/{rec['ca_alg']}" if rec else None, mock)
    return jsonify(results=results, recommended=rec, mock=mock, host=HOST, min_category=min_cat, target_ms=target)


@app.post("/api/predict")                 # original endpoint and response shape, now backed by the real scorer
@login_required
def predict_legacy():
    body = request.get_json(silent=True) or {}
    try:
        telemetry = clean_telemetry(body.get("telemetry"))
        min_cat, target, allowed = _policy(body)
        same_alg = [(a["name"], a["name"]) for a in ALGS]
        results, rec, mock = score(telemetry, min_cat, target, allowed, pairs=[p for p in same_alg if p in CONFIGS])
    except (TypeError, ValueError) as e:
        return jsonify(error=str(e)), 400
    except (ModelMismatch, ModelUnavailable) as e:
        return jsonify(error=str(e)), 503
    rows = sorted((r for r in results if r["eligible"]), key=lambda r: r["predicted_ms"])
    return jsonify(predictions=[{"algorithm": r["ee_alg"], "predicted_ms": round(r["predicted_ms"], 1),
                                 "status": "PASS" if r["meets_target"] else "WARNING"} for r in rows],
                   recommended=rec["ee_alg"] if rec else None, mock=mock)


@app.get("/api/health")
def health():
    """Unauthenticated liveness check for whoever runs the box. Reveals no data."""
    return jsonify(status="ok", model_loaded=get_model() is not None)


if __name__ == "__main__":
    host = os.environ.get("PQCONNECT_HOST", "127.0.0.1")
    port = int(os.environ.get("PQCONNECT_PORT", "5000"))
    if not load_users():
        print("No accounts yet. Create one with: python manage_users.py add <username>", file=sys.stderr)
    if get_model() is None:
        print("No models/latency_model.joblib: serving MOCK predictions (flagged in the UI)." if ALLOW_MOCK
              else "No model and PQCONNECT_MOCK=0: /api/recommend will return 503.", file=sys.stderr)
    if DEV_HTTP:
        print("DEV MODE: plain HTTP, cookies not marked Secure. Do not expose this.", file=sys.stderr)
        app.run(host=host, port=port, debug=False)
    else:
        cert, key = INSTANCE / "tls" / "cert.pem", INSTANCE / "tls" / "key.pem"
        if not (cert.exists() and key.exists()):
            sys.exit("No TLS certificate. Create one with:\n"
                     "  mkdir -p instance/tls && openssl req -x509 -newkey rsa:3072 -nodes -days 7 "
                     "-keyout instance/tls/key.pem -out instance/tls/cert.pem -subj /CN=pqconnect\n"
                     "or run with PQCONNECT_DEV_HTTP=1 for local testing.")
        app.run(host=host, port=port, ssl_context=(str(cert), str(key)), debug=False)
