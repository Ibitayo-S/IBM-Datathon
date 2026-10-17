"""One server for the dashboard, network probes and real model inference."""
import argparse
from functools import wraps
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import time
from urllib.parse import urlsplit

os.environ.setdefault('OMP_NUM_THREADS', '4')
os.environ.setdefault('OPENBLAS_NUM_THREADS', '4')

from flask import Flask, Response, jsonify, request, send_file, session
from werkzeug.security import check_password_hash, generate_password_hash
from model_service import ModelService, ModelUnavailable, PROFILES, SCOPE, category

ROOT = Path(__file__).resolve().parent
PROBE_MAX_BYTES = 8 * 1024 * 1024
PROBE_PATHS = {'/api/probe/ping', '/api/ping', '/api/probe/download', '/api/payload-512k'}


def create_app(config=None):
    supplied = config or {}
    instance = Path(supplied.get('INSTANCE_PATH', ROOT / 'instance'))
    instance.mkdir(parents=True, exist_ok=True)
    app = Flask(__name__, static_folder=None, instance_path=str(instance.resolve()))
    demo = os.environ.get('PQCONNECT_DEMO') == '1'
    dev_http = os.environ.get('PQCONNECT_DEV_HTTP') == '1'
    app.config.update(PQCONNECT_DEMO=demo, DEV_HTTP=dev_http,
                      SESSION_COOKIE_NAME='pqc_session', SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SECURE=not (demo or dev_http), SESSION_COOKIE_SAMESITE='Strict',
                      PERMANENT_SESSION_LIFETIME=1800, MAX_CONTENT_LENGTH=256 * 1024,
                      INSTANCE_PATH=str(instance), MODEL_DIR=ROOT / 'pqconnect/artifacts')
    app.config.update(supplied)
    if app.config['PQCONNECT_DEMO']:
        app.config['SESSION_COOKIE_SECURE'] = False
    if not app.config.get('SECRET_KEY'):
        key = os.environ.get('PQCONNECT_SECRET_KEY')
        if not key:
            secret_file = instance / 'secret_key'
            if not secret_file.exists():
                secret_file.write_text(secrets.token_hex(32), encoding='utf-8')
                secret_file.chmod(0o600)
            key = secret_file.read_text(encoding='utf-8').strip()
        app.config['SECRET_KEY'] = key
    service = ModelService(app.config['MODEL_DIR'])
    app.extensions['model_service'] = service
    failed = {}
    dummy = generate_password_hash(secrets.token_hex(16))
    probe_blob = os.urandom(PROBE_MAX_BYTES)

    def users():
        path = instance / 'users.json'
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}

    def body():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise ValueError('Send a JSON object.')
        return value

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if 'user' not in session:
                return jsonify(error='Sign in to continue.'), 401
            return fn(*args, **kwargs)
        return wrapped

    @app.before_request
    def protect():
        if app.config['PQCONNECT_DEMO'] or app.config['DEV_HTTP']:
            if request.remote_addr not in ('127.0.0.1', '::1') or urlsplit(request.host_url).hostname not in ('localhost', '127.0.0.1', '::1'):
                return jsonify(error='Local mode is available only on localhost.'), 403
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            sent, real = request.headers.get('X-CSRF-Token', ''), session.get('csrf', '')
            if not real or not sent.isascii() or not secrets.compare_digest(sent, real):
                return jsonify(error='Reload the page to refresh your session token.'), 403

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        if request.path not in PROBE_PATHS:
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'; object-src 'none'")
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['Referrer-Policy'] = 'no-referrer'
            response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        if not app.config['PQCONNECT_DEMO'] and not app.config['DEV_HTTP']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(ModelUnavailable)
    def unavailable(error):
        return jsonify(error=str(error), model_loaded=False), 503

    @app.errorhandler(413)
    def too_large(error):
        return jsonify(error='Request exceeds the 256 KiB limit.'), 413

    @app.get('/')
    def index():
        return send_file(ROOT / 'index.html')

    @app.get('/static/<name>')
    def static_asset(name):
        if name not in ('app.js', 'style.css', 'jspdf.umd.min.js'):
            return jsonify(error='Not found.'), 404
        return send_file(ROOT / name)

    @app.get('/api/session')
    def get_session():
        if app.config['PQCONNECT_DEMO']:
            session['user'] = 'Local demo'
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        return jsonify(authenticated='user' in session, user=session.get('user'),
                       csrf=session['csrf'], demo=app.config['PQCONNECT_DEMO'])

    @app.post('/api/login')
    def login():
        ip = request.remote_addr or '?'
        now = time.time()
        failed[ip] = [t for t in failed.get(ip, []) if now - t < 300]
        if len(failed[ip]) >= 5:
            return jsonify(error='Too many failed sign-ins. Try again in five minutes.'), 429
        data = body()
        username, password = data.get('username'), data.get('password')
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 or len(password) > 256:
            raise ValueError('Enter a valid username and password.')
        stored = users().get(username)
        if not (check_password_hash(stored or dummy, password) and stored is not None):
            failed[ip].append(now)
            return jsonify(error='Wrong username or password.'), 401
        failed.pop(ip, None)
        session.clear()
        session.permanent = True
        session['user'], session['csrf'] = username, secrets.token_urlsafe(32)
        return jsonify(user=username, csrf=session['csrf'])

    @app.post('/api/logout')
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get('/api/health')
    def health():
        loaded = service.model is not None
        return jsonify(status='ok' if loaded else 'unavailable', model_loaded=loaded), 200 if loaded else 503

    @app.get('/api/meta')
    @login_required
    def meta():
        service.require()
        return jsonify(user=session['user'], demo=app.config['PQCONNECT_DEMO'],
                       host={'arch': platform.machine(), 'hostname': socket.gethostname()},
                       model=service.info(), algorithms=[{'name': a, 'category': category(a),
                            'family': 'ML-DSA' if a.startswith('ML-DSA') else 'SLH-DSA'} for a in service.algorithms()],
                       configurations=list(service.catalog.values()),
                       default_configuration='ML-DSA-65_signed-by_ML-DSA-65',
                       profiles=PROFILES, baseline=service.baseline, scope=SCOPE)

    @app.get('/api/probe/ping')
    @app.get('/api/ping')
    @login_required
    def ping():
        return jsonify(status='ok') if request.path == '/api/ping' else Response(status=204)

    @app.get('/api/probe/download')
    @app.get('/api/payload-512k')
    @login_required
    def download():
        try:
            size = int(request.args.get('bytes', 512 * 1024))
        except (ValueError, TypeError):
            raise ValueError('bytes must be a whole number.')
        if not 1024 <= size <= PROBE_MAX_BYTES:
            raise ValueError(f'bytes must be between 1024 and {PROBE_MAX_BYTES}.')
        return Response(probe_blob[:size], mimetype='application/octet-stream',
                        headers={'Content-Length': str(size), 'Content-Encoding': 'identity'})

    @app.post('/api/analyze')
    @app.post('/api/recommend')
    @login_required
    def analyze():
        data = body()
        if 'telemetry' in data:
            raise ValueError('Flat browser telemetry cannot drive this model. Use a recorded profile or /api/predict with five authentic exchange records.')
        return jsonify(service.analyze(data))

    @app.post('/api/predict')
    @login_required
    def predict():
        return jsonify(service.predict(body()))

    @app.post('/api/estimate-telemetry')
    @login_required
    def estimate_telemetry():
        return jsonify(error='Browser probes cannot estimate authentication history or MAC/PHY indicators. Use /api/analyze for recorded telemetry or /api/predict for collected exchange history.'), 422

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true', help='Localhost-only dashboard without account setup')
    parser.add_argument('--http', action='store_true', help='Local HTTP with authentication')
    parser.add_argument('--host', default=os.environ.get('PQCONNECT_HOST', '127.0.0.1'))
    parser.add_argument('--port', type=int, default=int(os.environ.get('PQCONNECT_PORT', '5000')))
    args = parser.parse_args()
    demo = args.demo or os.environ.get('PQCONNECT_DEMO') == '1'
    plain = demo or args.http or os.environ.get('PQCONNECT_DEV_HTTP') == '1'
    if plain and args.host not in ('127.0.0.1', 'localhost', '::1'):
        parser.error('HTTP/demo mode binds to localhost only. Use authenticated HTTPS for a shared host.')
    app = create_app({'PQCONNECT_DEMO': demo, 'DEV_HTTP': plain, 'SESSION_COOKIE_SECURE': not plain})
    if app.extensions['model_service'].model is None:
        parser.exit(1, 'Model assets are unavailable. Restore pqconnect/artifacts; no mock predictions will be served.\n')
    print(f'PQConnect: {"http" if plain else "https"}://{args.host}:{args.port}', flush=True)
    if plain:
        from waitress import serve
        serve(app, host=args.host, port=args.port, threads=4)
    else:
        cert, key = ROOT / 'instance/tls/cert.pem', ROOT / 'instance/tls/key.pem'
        if not cert.exists() or not key.exists():
            parser.exit(1, 'Provide instance/tls/cert.pem and key.pem, or run python app.py --demo locally.\n')
        app.run(host=args.host, port=args.port, ssl_context=(str(cert), str(key)), debug=False)


if __name__ == '__main__':
    main()
