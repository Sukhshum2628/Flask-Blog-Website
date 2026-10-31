import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        yield client

def test_health_check(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert response.data == b"OK"

def test_ping(client):
    response = client.get('/ping')
    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}

def test_index_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'FlaskBlog' in response.data

def test_login_get(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Sign In' in response.data or b'Welcome back' in response.data

def test_register_get(client):
    response = client.get('/register')
    assert response.status_code == 200
    assert b'Join FlaskBlog' in response.data

def test_reset_password_get(client):
    response = client.get('/reset_password')
    assert response.status_code == 200
    assert b'Reset Password' in response.data

def test_unauthenticated_protected_routes(client):
    protected_urls = [
        '/dashboard',
        '/settings',
        '/settings/profile',
        '/settings/account',
        '/reading-list',
        '/post/new',
    ]
    for url in protected_urls:
        res = client.get(url, follow_redirects=False)
        assert res.status_code in (302, 401), f"Expected redirect/unauthorized for {url}, got {res.status_code}"

def test_search_suggestions_empty(client):
    res = client.get('/search/suggestions?q=a')
    assert res.status_code == 200
    assert res.get_json() == {'results': []}

def test_security_headers_present(client):
    res = client.get('/')
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
    assert res.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert 'Strict-Transport-Security' in res.headers
    assert 'Content-Security-Policy' in res.headers
