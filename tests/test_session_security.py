import os
import subprocess
import pytest
from app import app, users

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        yield client

# ==============================================================================
# C1. SECRET_KEY Tests
# ==============================================================================

def test_production_secret_key_missing_fails_startup():
    """Verify that in production mode, a missing SECRET_KEY halts startup with RuntimeError."""
    cmd = [
        "python", "-c",
        "import os; os.environ['FLASK_ENV'] = 'production'; os.environ.pop('TESTING', None); os.environ.pop('SECRET_KEY', None); import app"
    ]
    env = os.environ.copy()
    env.pop('SECRET_KEY', None)
    env['FLASK_ENV'] = 'production'
    env.pop('TESTING', None)

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode != 0
    assert "FATAL SECURITY ERROR" in res.stderr

def test_production_secret_key_default_fails_startup():
    """Verify that in production mode, the old default key halts startup with RuntimeError."""
    cmd = [
        "python", "-c",
        "import os; os.environ['FLASK_ENV'] = 'production'; os.environ.pop('TESTING', None); os.environ['SECRET_KEY'] = 'dev_secret_key_change_me'; import app"
    ]
    env = os.environ.copy()
    env['FLASK_ENV'] = 'production'
    env['SECRET_KEY'] = 'dev_secret_key_change_me'
    env.pop('TESTING', None)

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode != 0
    assert "FATAL SECURITY ERROR" in res.stderr

def test_production_secret_key_too_short_fails_startup():
    """Verify that in production mode, a secret key with < 32 characters is rejected."""
    cmd = [
        "python", "-c",
        "import os; os.environ['FLASK_ENV'] = 'production'; os.environ.pop('TESTING', None); os.environ['SECRET_KEY'] = 'short_secret_key_123'; import app"
    ]
    env = os.environ.copy()
    env['FLASK_ENV'] = 'production'
    env['SECRET_KEY'] = 'short_secret_key_123'
    env.pop('TESTING', None)

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode != 0
    assert "at least 32 characters" in res.stderr

def test_production_secret_key_valid_succeeds_startup():
    """Verify that in production mode, a valid strong secret starts successfully."""
    strong_key = "a_very_secure_and_random_production_secret_key_with_high_entropy_32+"
    cmd = [
        "python", "-c",
        f"import os; os.environ['FLASK_ENV'] = 'production'; os.environ.pop('TESTING', None); os.environ['SECRET_KEY'] = '{strong_key}'; import app; print('STARTUP_OK')"
    ]
    env = os.environ.copy()
    env['FLASK_ENV'] = 'production'
    env['SECRET_KEY'] = strong_key
    env.pop('TESTING', None)

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode == 0
    assert "STARTUP_OK" in res.stdout

def test_development_fallback_secret():
    """Verify that development/test mode allows startup with explicit testing fallback."""
    cmd = [
        "python", "-c",
        "import os; os.environ['FLASK_ENV'] = 'development'; os.environ.pop('SECRET_KEY', None); import app; print('DEV_OK')"
    ]
    env = os.environ.copy()
    env['FLASK_ENV'] = 'development'
    env.pop('SECRET_KEY', None)

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode == 0
    assert "DEV_OK" in res.stdout

# ==============================================================================
# C2. Cookie Security Tests
# ==============================================================================

def test_session_cookie_attributes_configuration():
    """Verify session cookie configuration flags in app.config."""
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert "PERMANENT_SESSION_LIFETIME" in app.config

def test_session_cookie_headers_on_response(client):
    """Verify that Set-Cookie header contains HttpOnly and SameSite=Lax."""
    res = client.get('/login')
    cookie_headers = res.headers.getlist('Set-Cookie')
    if cookie_headers:
        session_cookie = [c for c in cookie_headers if c.startswith('session=')]
        if session_cookie:
            c_val = session_cookie[0]
            assert "HttpOnly" in c_val
            assert "SameSite=Lax" in c_val

# ==============================================================================
# C3 & C4. Authentication, Session Fixation & Revocation Tests
# ==============================================================================

def test_anonymous_access_protected_endpoint(client):
    """Unauthenticated users cannot access protected routes."""
    res = client.get('/dashboard', follow_redirects=False)
    assert res.status_code == 302
    assert '/login' in res.headers['Location']

def test_authenticated_session_lifecycle(client):
    """Verify session establishment, authorization, and logout clearing."""
    # 1. Establish valid session
    with client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    # 2. Access protected route
    res = client.get('/dashboard')
    assert res.status_code == 200

    # 3. Logout (POST required)
    res_logout = client.post('/logout', follow_redirects=False)
    assert res_logout.status_code == 302

    # 4. Access protected route after logout -> rejected
    res_after = client.get('/dashboard', follow_redirects=False)
    assert res_after.status_code == 302
    assert '/login' in res_after.headers['Location']

def test_session_revocation_on_token_version_mismatch(client):
    """Verify that an outdated session (e.g. after password reset) is revoked."""
    # Find or use an existing test user
    user = users.find_one({'username': 'alice_dev'})
    if not user:
        pytest.skip("Test user alice_dev not found in database")

    current_ver = user.get('token_version', 1)
    
    # Establish session with current version
    with client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = current_ver

    # Access allowed
    res1 = client.get('/dashboard')
    assert res1.status_code == 200

    # Simulate token version mismatch (session revocation)
    with client.session_transaction() as sess:
        sess['token_version'] = current_ver + 999

    # Access revoked and redirected
    res2 = client.get('/dashboard', follow_redirects=False)
    assert res2.status_code == 302
    assert '/login' in res2.headers['Location']

def test_session_cleared_if_user_deleted(client):
    """Verify that if user in session does not exist in DB, session is cleared."""
    with client.session_transaction() as sess:
        sess['user'] = 'non_existent_ghost_user_999'
        sess['token_version'] = 1

    res = client.get('/dashboard', follow_redirects=False)
    assert res.status_code == 302
    assert '/login' in res.headers['Location']
