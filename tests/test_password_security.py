import os
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, users, password_reset_tokens, get_reset_token, verify_reset_token, hash_password, limiter

@pytest.fixture
def auth_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    limiter.reset()
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

def test_reset_url_valid_https_app_url(auth_client, test_user, monkeypatch):
    """1. Valid HTTPS APP_URL generates the correct reset link."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://flaskblog.security.io")
    monkeypatch.delenv("BASE_URL", raising=False)

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 1
    assert "https://flaskblog.security.io/reset_password/" in sent_emails[0]

def test_reset_url_valid_base_url_when_app_url_absent(auth_client, test_user, monkeypatch):
    """2. Valid BASE_URL works when APP_URL is absent."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.delenv("APP_URL", raising=False)
    monkeypatch.setenv("BASE_URL", "https://base.flaskblog.io")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 1
    assert "https://base.flaskblog.io/reset_password/" in sent_emails[0]

def test_reset_url_production_without_origin_fails_closed(auth_client, test_user, monkeypatch):
    """3. Production with neither variable configured fails closed (no email dispatched)."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.delenv("APP_URL", raising=False)
    monkeypatch.delenv("BASE_URL", raising=False)

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    # Generic public response is preserved
    assert resp.status_code == 302
    # But email sending fails closed; no poisoned or unvalidated link is sent
    assert len(sent_emails) == 0

def test_reset_url_forged_host_header_cannot_influence_link(auth_client, test_user, monkeypatch):
    """4. A forged Host header cannot influence the generated reset link."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://flaskblog.security.io")

    resp = auth_client.post('/reset_password', 
        data={'email': test_user['email']},
        headers={'Host': 'attacker-evil-host.com'},
        follow_redirects=False
    )
    assert resp.status_code == 302
    assert len(sent_emails) == 1
    assert "attacker-evil-host.com" not in sent_emails[0]
    assert "https://flaskblog.security.io/reset_password/" in sent_emails[0]

def test_reset_url_forged_x_forwarded_host_cannot_influence_link(auth_client, test_user, monkeypatch):
    """5. A forged X-Forwarded-Host header cannot influence the generated reset link."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://flaskblog.security.io")

    resp = auth_client.post('/reset_password', 
        data={'email': test_user['email']},
        headers={'X-Forwarded-Host': 'spoofed-domain.com'},
        follow_redirects=False
    )
    assert resp.status_code == 302
    assert len(sent_emails) == 1
    assert "spoofed-domain.com" not in sent_emails[0]
    assert "https://flaskblog.security.io/reset_password/" in sent_emails[0]

def test_reset_url_http_scheme_rejected_in_production(auth_client, test_user, monkeypatch):
    """6. HTTP production URLs are rejected."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("APP_URL", "http://insecure-http-url.com")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    # Fails closed, no email sent
    assert len(sent_emails) == 0

def test_reset_url_embedded_credentials_rejected(auth_client, test_user, monkeypatch):
    """7. URLs containing credentials are rejected."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://user:password@flaskblog.io")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 0

def test_reset_url_query_strings_or_fragments_rejected(auth_client, test_user, monkeypatch):
    """8. URLs containing query strings or fragments are rejected."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    
    # Query string test
    monkeypatch.setenv("APP_URL", "https://flaskblog.io/path?query=1")
    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 0

    # Fragment test
    monkeypatch.setenv("APP_URL", "https://flaskblog.io/path#fragment")
    resp2 = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp2.status_code == 302
    assert len(sent_emails) == 0

def test_reset_url_malformed_unsupported_scheme_rejected(auth_client, test_user, monkeypatch):
    """9. Malformed or unsupported URLs are rejected."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "ftp://flaskblog.io")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 0

def test_reset_url_development_behavior_functional(auth_client, test_user, monkeypatch):
    """10. Existing development behavior remains functional when unconfigured."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("APP_URL", raising=False)
    monkeypatch.delenv("BASE_URL", raising=False)

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 1
    assert "/reset_password/" in sent_emails[0]

def test_reset_url_render_production_overrides_test_flag(auth_client, test_user, monkeypatch):
    """11. Production validation cannot be bypassed by test-related environment flags."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("APP_URL", "http://insecure-on-render.com")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    # Insecure HTTP on Render must fail closed despite TESTING=true
    assert len(sent_emails) == 0

def test_reset_url_non_integer_port_rejected(auth_client, test_user, monkeypatch):
    """12. Origins with non-integer ports (e.g. :abc) are rejected and fail closed."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://example.com:abc")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 0

def test_reset_url_out_of_range_port_rejected(auth_client, test_user, monkeypatch):
    """13. Origins with out-of-range ports (e.g. :70000) are rejected and fail closed."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://example.com:70000")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 0

def test_reset_url_port_zero_rejected(auth_client, test_user, monkeypatch):
    """14. Port 0 is explicitly rejected and fails closed."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://example.com:0")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 0

def test_reset_url_valid_https_port_accepted(auth_client, test_user, monkeypatch):
    """15. A valid HTTPS port is accepted and included in reset link."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://example.com:8443")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 1
    assert "https://example.com:8443/reset_password/" in sent_emails[0]

def test_reset_url_valid_ipv4_with_port_preserved(auth_client, test_user, monkeypatch):
    """16. A valid IPv4 origin with a port is accepted and preserved in development."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("APP_URL", "http://127.0.0.1:5000")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 1
    assert "http://127.0.0.1:5000/reset_password/" in sent_emails[0]

def test_reset_url_valid_bracketed_ipv6_preserved(auth_client, test_user, monkeypatch):
    """17. A valid bracketed IPv6 origin (with port) is preserved."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("APP_URL", "https://[::1]:8443")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 1
    assert "https://[::1]:8443/reset_password/" in sent_emails[0]

def test_reset_url_invalid_production_port_fails_closed(auth_client, test_user, monkeypatch):
    """18. Invalid production port configuration strictly fails closed and sends no email."""
    sent_emails = []
    monkeypatch.setattr("app.send_async_email", lambda app_ctx, to, subj, body: sent_emails.append(body))
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("APP_URL", "https://prod.flaskblog.io:badport")

    resp = auth_client.post('/reset_password', data={'email': test_user['email']}, follow_redirects=False)
    assert resp.status_code == 302
    assert len(sent_emails) == 0


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


# ---------------------------------------------------------------------------
# 7. Sibling Token Invalidation & Lifecycle (F-02)
# ---------------------------------------------------------------------------

def test_sibling_tokens_invalidated_after_successful_reset(auth_client, test_user):
    """When a reset succeeds, all outstanding sibling tokens for the user are invalidated."""
    token1 = get_reset_token(test_user['_id'])
    token2 = get_reset_token(test_user['_id'])
    token3 = get_reset_token(test_user['_id'])

    # All three tokens exist and verify
    assert verify_reset_token(token1) is not None
    assert verify_reset_token(token2) is not None
    assert verify_reset_token(token3) is not None

    # Reset password using token1
    new_pass = "BrandNewSecret123!"
    resp = auth_client.post(f'/reset_password/{token1}', data={
        'password': new_pass,
        'confirm_password': new_pass
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'] == '/login'

    # Token1 cannot be reused
    assert verify_reset_token(token1) is None
    reuse_resp = auth_client.post(f'/reset_password/{token1}', data={
        'password': "AnotherPassword999!",
        'confirm_password': "AnotherPassword999!"
    }, follow_redirects=False)
    assert reuse_resp.status_code == 302
    assert reuse_resp.headers['Location'] == '/reset_password'

    # Sibling tokens (token2 and token3) are now invalidated
    assert verify_reset_token(token2) is None
    assert verify_reset_token(token3) is None

    # Attempting to reset with sibling token2 fails
    resp2 = auth_client.post(f'/reset_password/{token2}', data={
        'password': "AnotherPassword999!",
        'confirm_password': "AnotherPassword999!"
    }, follow_redirects=False)
    assert resp2.status_code == 302
    assert resp2.headers['Location'] == '/reset_password'

    # Verify audit trail: sibling tokens marked used=True with reason
    t2_doc = password_reset_tokens.find_one({'token_hash': hashlib.sha256(token2.encode('utf-8')).hexdigest()})
    assert t2_doc['used'] is True
    assert t2_doc['invalidated_reason'] == 'sibling_reset'

def test_sibling_invalidation_does_not_affect_other_users(auth_client, test_user):
    """Invalidating sibling tokens for user A does not affect tokens for user B."""
    # Create user B
    user_b_id = users.insert_one({
        "username": "sibling_other_user",
        "email": "sibling_other_user@example.com",
        "password": hash_password("PasswordUserB123!"),
        "token_version": 1
    }).inserted_id

    try:
        user_a_token1 = get_reset_token(test_user['_id'])
        user_a_token2 = get_reset_token(test_user['_id'])
        user_b_token = get_reset_token(user_b_id)

        # Reset using user A's token1
        new_pass_a = "UserANewPassword123!"
        resp = auth_client.post(f'/reset_password/{user_a_token1}', data={
            'password': new_pass_a,
            'confirm_password': new_pass_a
        }, follow_redirects=False)
        assert resp.status_code == 302

        # User A's sibling token2 is invalidated
        assert verify_reset_token(user_a_token2) is None

        # User B's token remains completely valid and usable
        assert verify_reset_token(user_b_token) is not None
        new_pass_b = "UserBNewPassword999!"
        resp_b = auth_client.post(f'/reset_password/{user_b_token}', data={
            'password': new_pass_b,
            'confirm_password': new_pass_b
        }, follow_redirects=False)
        assert resp_b.status_code == 302
        assert resp_b.headers['Location'] == '/login'

        # User B can now log in with new password
        user_b_updated = users.find_one({'_id': user_b_id})
        assert check_password_hash(user_b_updated['password'], new_pass_b)
    finally:
        users.delete_one({'_id': user_b_id})
        password_reset_tokens.delete_many({'user_id': str(user_b_id)})

def test_expired_sibling_token_remains_unusable(auth_client, test_user):
    """An expired token remains unusable before and after sibling reset."""
    raw_token = get_reset_token(test_user['_id'])
    # Manually expire the token
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    past_time = datetime.now(timezone.utc) - timedelta(hours=2)
    password_reset_tokens.update_one({'token_hash': token_hash}, {'$set': {'expires_at': past_time}})

    assert verify_reset_token(raw_token) is None
    resp = auth_client.post(f'/reset_password/{raw_token}', data={
        'password': 'SomeNewPassword123!',
        'confirm_password': 'SomeNewPassword123!'
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'] == '/reset_password'

def test_invalid_token_does_not_change_password(auth_client, test_user):
    """Non-existent token cannot reset password."""
    resp = auth_client.post('/reset_password/non_existent_token_string_123', data={
        'password': 'SomeNewPassword123!',
        'confirm_password': 'SomeNewPassword123!'
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'] == '/reset_password'

    # Verify password unchanged
    curr_user = users.find_one({'_id': test_user['_id']})
    assert check_password_hash(curr_user['password'], test_user['raw_pass'])

def test_mismatched_password_confirmation_does_not_consume_token(auth_client, test_user):
    """Form validation error (mismatched password) does not consume the token."""
    token = get_reset_token(test_user['_id'])
    resp = auth_client.post(f'/reset_password/{token}', data={
        'password': 'ValidPassword123!',
        'confirm_password': 'MismatchedPassword123!'
    }, follow_redirects=False)
    assert resp.status_code == 200 # Re-renders form

    # Token must still be valid and unconsumed
    token_doc = password_reset_tokens.find_one({'token_hash': hashlib.sha256(token.encode('utf-8')).hexdigest()})
    assert token_doc['used'] is False
    assert verify_reset_token(token) is not None

def test_failed_password_validation_does_not_consume_token(auth_client, test_user):
    """Form validation error (too short password) does not consume token."""
    token = get_reset_token(test_user['_id'])
    resp = auth_client.post(f'/reset_password/{token}', data={
        'password': 'short',
        'confirm_password': 'short'
    }, follow_redirects=False)
    assert resp.status_code == 200

    token_doc = password_reset_tokens.find_one({'token_hash': hashlib.sha256(token.encode('utf-8')).hexdigest()})
    assert token_doc['used'] is False
    assert verify_reset_token(token) is not None

def test_password_update_failure_reverts_token_consumption(auth_client, test_user, monkeypatch):
    """If database fails during password update, token consumption is reverted so user is not locked out."""
    token = get_reset_token(test_user['_id'])

    def fail_update(*args, **kwargs):
        raise RuntimeError("Simulated database write error during password update")

    monkeypatch.setattr(users, "update_one", fail_update)

    resp = auth_client.post(f'/reset_password/{token}', data={
        'password': 'NewPassword123!',
        'confirm_password': 'NewPassword123!'
    }, follow_redirects=False)

    # User redirected back to reset_token page to retry
    assert resp.status_code == 302
    assert f'/reset_password/{token}' in resp.headers['Location']

    # Token must NOT be permanently marked used
    token_doc = password_reset_tokens.find_one({'token_hash': hashlib.sha256(token.encode('utf-8')).hexdigest()})
    assert token_doc['used'] is False
