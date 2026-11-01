import os
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, users, password_reset_tokens, get_reset_token, verify_reset_token, hash_password

@pytest.fixture
def auth_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app.test_client()

@pytest.fixture
def test_user():
    """Ensure a clean, isolated test user exists."""
    username = "pass_audit_user"
    email = "pass_audit_user@example.com"
    users.delete_many({"$or": [{"username": username}, {"email": email}]})
    password_reset_tokens.delete_many({})

    raw_pass = "SecurePass123!"
    user_id = users.insert_one({
        "username": username,
        "email": email,
        "password": hash_password(raw_pass),
        "token_version": 1,
        "bio": "Test bio",
        "avatar_url": "https://example.com/avatar.png",
        "joined_at": datetime.now(timezone.utc),
        "last_visit": datetime.now(timezone.utc)
    }).inserted_id

    yield {"_id": user_id, "username": username, "email": email, "raw_pass": raw_pass}

    users.delete_many({"$or": [{"username": username}, {"email": email}]})
    password_reset_tokens.delete_many({"user_id": str(user_id)})


# ---------------------------------------------------------------------------
# 1. Password Storage & Hashing
# ---------------------------------------------------------------------------

def test_registration_stores_scrypt_hash_not_plaintext(auth_client):
    """Registration creates user with scrypt hash and never plaintext."""
    uname = "reg_test_user_44"
    uemail = "reg_test_user_44@example.com"
    raw_pass = "MySecretPass2026!"

    users.delete_many({"$or": [{"username": uname}, {"email": uemail}]})

    resp = auth_client.post('/register', data={
        'username': uname,
        'email': uemail,
        'password': raw_pass
    }, follow_redirects=False)
    assert resp.status_code == 302

    created = users.find_one({'username': uname})
    assert created is not None
    assert created['password'] != raw_pass
    assert created['password'].startswith('scrypt:')
    assert check_password_hash(created['password'], raw_pass) is True
    assert created.get('token_version') == 1

    users.delete_many({"$or": [{"username": uname}, {"email": uemail}]})

def test_stored_hash_verifies_original_password():
    """Stored hash verifies the original password."""
    raw = "SuperSecret#2026"
    h = hash_password(raw)
    assert h.startswith("scrypt:")
    assert check_password_hash(h, raw) is True

def test_incorrect_password_rejected():
    """Incorrect password fails verification."""
    h = hash_password("CorrectPassword123")
    assert check_password_hash(h, "WrongPassword321") is False

def test_empty_password_rejected_at_validation(auth_client):
    """Empty password fails registration validation."""
    resp = auth_client.post('/register', data={
        'username': 'empty_pass_user',
        'email': 'empty_pass@example.com',
        'password': ''
    })
    assert resp.status_code == 200
    assert b"This field is required" in resp.data

def test_short_password_rejected_at_validation(auth_client):
    """Password shorter than 8 characters fails validation."""
    resp = auth_client.post('/register', data={
        'username': 'short_pass_user',
        'email': 'short_pass@example.com',
        'password': 'short'
    })
    assert resp.status_code == 200
    assert b"Password must be between 8 and 128 characters" in resp.data

def test_missing_or_malformed_stored_hash_fails_safely(auth_client):
    """Malformed or None password hash in DB fails login safely without crashing."""
    malformed_user = "malformed_hash_user"
    users.delete_many({"username": malformed_user})
    users.insert_one({
        "username": malformed_user,
        "email": "malformed@example.com",
        "password": "invalid$hash$string",
        "token_version": 1
    })

    resp = auth_client.post('/login', data={
        'username': malformed_user,
        'password': 'SomePassword123'
    })
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data

    users.delete_many({"username": malformed_user})


# ---------------------------------------------------------------------------
# 2. Login & Credential Verification
# ---------------------------------------------------------------------------

def test_login_success_with_correct_credentials(auth_client, test_user):
    """Correct credentials authenticate and redirect to index."""
    resp = auth_client.post('/login', data={
        'username': test_user['username'],
        'password': test_user['raw_pass']
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'] == '/'

def test_login_failure_with_wrong_password(auth_client, test_user):
    """Wrong password fails authentication with generic message."""
    resp = auth_client.post('/login', data={
        'username': test_user['username'],
        'password': 'WrongPassword123'
    })
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data

def test_login_failure_for_nonexistent_user(auth_client):
    """Unknown username returns identical generic failure message."""
    resp = auth_client.post('/login', data={
        'username': 'completely_nonexistent_user_99999',
        'password': 'Password123!'
    })
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data

def test_password_hash_never_exposed_in_html(auth_client, test_user):
    """Password hash is never leaked in profile or settings views."""
    with auth_client.session_transaction() as sess:
        sess['user'] = test_user['username']
        sess['token_version'] = 1

    profile_resp = auth_client.get(f"/profile/{test_user['username']}")
    assert profile_resp.status_code == 200
    assert b"scrypt:" not in profile_resp.data

    settings_resp = auth_client.get("/settings/profile")
    assert settings_resp.status_code == 200
    assert b"scrypt:" not in settings_resp.data

def test_seamless_hash_upgrade_from_pbkdf2_to_scrypt(auth_client):
    """Users with legacy pbkdf2 hashes are upgraded to scrypt upon successful login."""
    legacy_user = "legacy_pbkdf2_user"
    legacy_pass = "LegacyPassword123!"
    users.delete_many({"username": legacy_user})

    # Insert user with legacy pbkdf2 hash
    legacy_hash = generate_password_hash(legacy_pass, method="pbkdf2:sha256:260000")
    users.insert_one({
        "username": legacy_user,
        "email": "legacy@example.com",
        "password": legacy_hash,
        "token_version": 1
    })

    # Verify initial hash is not scrypt
    doc = users.find_one({"username": legacy_user})
    assert doc['password'].startswith("pbkdf2:")

    # Log in
    resp = auth_client.post('/login', data={
        'username': legacy_user,
        'password': legacy_pass
    }, follow_redirects=False)
    assert resp.status_code == 302

    # Verify hash has been automatically upgraded to scrypt
    updated_doc = users.find_one({"username": legacy_user})
    assert updated_doc['password'].startswith("scrypt:")
    assert check_password_hash(updated_doc['password'], legacy_pass) is True

    users.delete_many({"username": legacy_user})


# ---------------------------------------------------------------------------
# 3. Password Reset Tokens & Expiry
# ---------------------------------------------------------------------------

def test_reset_token_generation_stores_sha256_hash_and_returns_raw(test_user):
    """get_reset_token inserts SHA-256 hashed token and returns high-entropy raw string."""
    raw_token = get_reset_token(test_user['_id'])
    assert isinstance(raw_token, str)
    assert len(raw_token) >= 32

    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    doc = password_reset_tokens.find_one({'token_hash': token_hash})
    assert doc is not None
    assert doc['user_id'] == str(test_user['_id'])
    assert doc['used'] is False
    exp = doc['expires_at']
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    assert exp > datetime.now(timezone.utc)

def test_verify_valid_token_succeeds(test_user):
    """verify_reset_token successfully returns the user document for valid unexpired token."""
    raw_token = get_reset_token(test_user['_id'])
    user = verify_reset_token(raw_token)
    assert user is not None
    assert user['_id'] == test_user['_id']

def test_verify_expired_token_rejected(test_user):
    """Expired token returns None."""
    raw_token = get_reset_token(test_user['_id'])
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

    # Artificially expire the token in MongoDB
    past_time = datetime.now(timezone.utc) - timedelta(seconds=10)
    password_reset_tokens.update_one({'token_hash': token_hash}, {'$set': {'expires_at': past_time}})

    user = verify_reset_token(raw_token)
    assert user is None

def test_verify_tampered_or_invalid_token_rejected():
    """Tampered or invalid token returns None."""
    assert verify_reset_token("invalid_random_string_12345") is None
    assert verify_reset_token("") is None
    assert verify_reset_token(None) is None


# ---------------------------------------------------------------------------
# 4. Single-Use Tokens & Password Reset Execution
# ---------------------------------------------------------------------------

def test_single_use_token_consumed_upon_successful_reset(auth_client, test_user):
    """Resetting password consumes token so it cannot be reused."""
    raw_token = get_reset_token(test_user['_id'])
    new_pass = "BrandNewPassword2026!"

    # Execute password reset
    resp = auth_client.post(f'/reset_password/{raw_token}', data={
        'password': new_pass,
        'confirm_password': new_pass
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'] == '/login'

    # Verify user can log in with new password
    updated_user = users.find_one({'_id': test_user['_id']})
    assert check_password_hash(updated_user['password'], new_pass) is True

    # Replay attack: attempt to use the same token again
    replay_resp = auth_client.post(f'/reset_password/{raw_token}', data={
        'password': 'AnotherPassword2026!',
        'confirm_password': 'AnotherPassword2026!'
    }, follow_redirects=False)
    assert replay_resp.status_code == 302
    assert replay_resp.headers['Location'] == '/reset_password'

    # Verify password was NOT changed by the replay
    final_user = users.find_one({'_id': test_user['_id']})
    assert check_password_hash(final_user['password'], new_pass) is True

def test_mismatched_password_confirmation_fails(auth_client, test_user):
    """Mismatched password confirmation fails EqualTo validation."""
    raw_token = get_reset_token(test_user['_id'])
    resp = auth_client.post(f'/reset_password/{raw_token}', data={
        'password': 'NewPassword123!',
        'confirm_password': 'DifferentPassword123!'
    })
    assert resp.status_code == 200
    assert b"Passwords must match" in resp.data

    # Token should not be consumed if validation fails
    assert verify_reset_token(raw_token) is not None


# ---------------------------------------------------------------------------
# 5. Account Enumeration & Email Reset Dispatch
# ---------------------------------------------------------------------------

def test_reset_request_returns_same_response_for_nonexistent_email(auth_client):
    """Password reset request returns identical generic message for unknown email."""
    resp = auth_client.post('/reset_password', data={
        'email': 'nonexistent_account_xyz@example.com'
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'] == '/login'

    # Inspect redirected page flash message
    login_page = auth_client.get('/login')
    assert b"An email has been sent with instructions to reset your password" in login_page.data

def test_reset_email_dispatches_with_trusted_app_url(auth_client, test_user, monkeypatch):
    """Reset URL is bound to trusted APP_URL / BASE_URL environment variable."""
    sent_emails = []

    def mock_send(app_ctx, to_email, subject, body):
        sent_emails.append({'to': to_email, 'subject': subject, 'body': body})

    monkeypatch.setattr("app.send_async_email", mock_send)
    monkeypatch.setenv("APP_URL", "https://flaskblog.security.io")

    resp = auth_client.post('/reset_password', data={
        'email': test_user['email']
    }, follow_redirects=False)
    assert resp.status_code == 302

    assert len(sent_emails) == 1
    assert "https://flaskblog.security.io/reset_password/" in sent_emails[0]['body']


# ---------------------------------------------------------------------------
# 6. Session Invalidation on Password Reset
# ---------------------------------------------------------------------------

def test_password_reset_increments_token_version_and_invalidates_old_sessions(auth_client, test_user):
    """Password reset increments token_version so active sessions are rejected."""
    # 1. Establish session
    with auth_client.session_transaction() as sess:
        sess['user'] = test_user['username']
        sess['token_version'] = 1

    # Access protected route
    res1 = auth_client.get('/dashboard')
    assert res1.status_code == 200

    # 2. Reset password out of band (e.g. from another browser or email link)
    raw_token = get_reset_token(test_user['_id'])
    reset_client = app.test_client()
    new_pass = "ResetPassword999!"
    reset_resp = reset_client.post(f'/reset_password/{raw_token}', data={
        'password': new_pass,
        'confirm_password': new_pass
    }, follow_redirects=False)
    assert reset_resp.status_code == 302

    # 3. Check user's token_version in DB
    updated = users.find_one({'_id': test_user['_id']})
    assert updated['token_version'] == 2

    # 4. Old session in auth_client attempts to access protected route -> redirected to /login
    res2 = auth_client.get('/dashboard', follow_redirects=False)
    assert res2.status_code == 302
    assert '/login' in res2.headers['Location']
