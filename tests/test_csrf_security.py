import re
import pytest
from app import app, posts, activities
from bson.objectid import ObjectId
from unittest.mock import MagicMock

@pytest.fixture
def csrf_client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = True
    return app.test_client()

def extract_csrf_token(html_text):
    """Helper to extract csrf_token from meta tag or hidden input."""
    # Look in meta tag
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html_text)
    if match:
        return match.group(1)
    # Look in form input
    match = re.search(r'name="csrf_token" value="([^"]+)"', html_text)
    if match:
        return match.group(1)
    return None

def test_missing_csrf_token_on_form_post_rejected(csrf_client):
    """POST request without csrf_token fails with HTTP 400 and renders CSRF error template."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    resp = csrf_client.post('/post/new', data={
        'title': 'Test Title',
        'content': 'Test Content',
        'intent': 'inform',
        'freshness': 'current'
    })
    assert resp.status_code == 400
    assert b"Request Security Check Failed" in resp.data
    assert b"CSRF validation failure" in resp.data

def test_invalid_csrf_token_rejected(csrf_client):
    """POST request with invalid csrf_token fails with HTTP 400."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    resp = csrf_client.post('/post/new', data={
        'title': 'Test Title',
        'content': 'Test Content',
        'intent': 'inform',
        'freshness': 'current',
        'csrf_token': 'completely_invalid_csrf_token'
    })
    assert resp.status_code == 400
    assert b"Request Security Check Failed" in resp.data

def test_valid_csrf_token_in_form_accepted(csrf_client, monkeypatch):
    """POST request with a valid csrf_token passes CSRF validation without writing to production."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    # First perform GET to extract CSRF token from page
    get_res = csrf_client.get('/post/new')
    assert get_res.status_code == 200
    token = extract_csrf_token(get_res.get_data(as_text=True))
    assert token is not None

    # Mock persistence in CSRF tests to prevent accidental database writes
    mock_post_id = ObjectId()
    mock_insert_post = MagicMock(return_value=MagicMock(inserted_id=mock_post_id))
    mock_insert_activity = MagicMock()
    monkeypatch.setattr(posts, "insert_one", mock_insert_post)
    monkeypatch.setattr(activities, "insert_one", mock_insert_activity)

    resp = csrf_client.post('/post/new', data={
        'title': 'Valid CSRF Story',
        'content': 'Story content that meets the minimum length requirements.',
        'intent': 'inform',
        'freshness': 'current',
        'submit': 'Publish',
        'csrf_token': token
    }, follow_redirects=False)
    # Valid post redirects to post detail (302), not 400
    assert resp.status_code == 302
    assert mock_insert_post.called
    assert mock_insert_activity.called

def test_ajax_post_without_csrf_rejected_with_json_error(csrf_client):
    """AJAX POST without CSRF token returns 400 JSON error."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    dummy_id = str(ObjectId())
    resp = csrf_client.post(
        f'/api/bookmark/{dummy_id}',
        headers={'X-Requested-With': 'XMLHttpRequest'}
    )
    assert resp.status_code == 400
    assert resp.is_json
    data = resp.get_json()
    assert 'error' in data
    assert 'CSRF' in data['error']

def test_ajax_post_with_x_csrf_token_header_accepted(csrf_client):
    """AJAX POST with valid X-CSRFToken header passes CSRF verification."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    get_res = csrf_client.get('/')
    token = extract_csrf_token(get_res.get_data(as_text=True))
    assert token is not None

    dummy_id = str(ObjectId())
    resp = csrf_client.post(
        f'/api/bookmark/{dummy_id}',
        headers={
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRFToken': token
        }
    )
    # CSRF validation passed: endpoint executes (returns 404 or 200, but not 400)
    assert resp.status_code in [200, 404]

def test_ai_routes_require_csrf(csrf_client):
    """AI endpoints (/ai/research, /ai/improve-draft, /ai/summarize) reject POST without CSRF."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    # /ai/research
    resp_res = csrf_client.post(
        '/ai/research',
        json={'topic': 'test', 'draft': 'test'},
        headers={'Content-Type': 'application/json'}
    )
    assert resp_res.status_code == 400
    assert resp_res.is_json

    # /ai/improve-draft
    resp_imp = csrf_client.post(
        '/ai/improve-draft',
        json={'draft': 'draft test'},
        headers={'Content-Type': 'application/json'}
    )
    assert resp_imp.status_code == 400
    assert resp_imp.is_json

    # /ai/summarize/<id>
    dummy_id = str(ObjectId())
    resp_sum = csrf_client.post(
        f'/ai/summarize/{dummy_id}',
        headers={'Content-Type': 'application/json'}
    )
    assert resp_sum.status_code == 400
    assert resp_sum.is_json

def test_logout_get_method_rejected(csrf_client):
    """GET /logout must be rejected with 405 Method Not Allowed and not clear session."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    resp = csrf_client.get('/logout')
    assert resp.status_code == 405

    # Verify session is NOT cleared
    with csrf_client.session_transaction() as sess:
        assert sess.get('user') == 'alice_dev'

def test_logout_post_without_csrf_rejected(csrf_client):
    """POST /logout without CSRF token returns 400 and preserves session."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    resp = csrf_client.post('/logout')
    assert resp.status_code == 400

    with csrf_client.session_transaction() as sess:
        assert sess.get('user') == 'alice_dev'

def test_logout_post_with_csrf_succeeds(csrf_client):
    """POST /logout with valid CSRF token clears session and redirects to index."""
    with csrf_client.session_transaction() as sess:
        sess['user'] = 'alice_dev'
        sess['token_version'] = 1

    # Establish session and obtain token
    get_res = csrf_client.get('/dashboard')
    token = extract_csrf_token(get_res.get_data(as_text=True))
    assert token is not None

    resp = csrf_client.post('/logout', data={'csrf_token': token}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers['Location'] == '/'

    # Verify session is cleared
    with csrf_client.session_transaction() as sess:
        assert 'user' not in sess

def test_templates_include_csrf_token(csrf_client):
    """Rendered templates include CSRF meta tag and form tokens."""
    resp = csrf_client.get('/')
    assert resp.status_code == 200
    assert b'meta name="csrf-token"' in resp.data

    login_resp = csrf_client.get('/login')
    assert login_resp.status_code == 200
    assert b'name="csrf_token"' in login_resp.data
