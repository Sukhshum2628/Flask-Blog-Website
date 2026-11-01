import pytest
import os
import uuid
from datetime import datetime, timezone
from bson.objectid import ObjectId

# Ensure testing environment
os.environ["TESTING"] = "true"
import app as flask_app
from app import app, users, posts, mongo, comments

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def setup_test_users():
    """Ensure two distinct test users exist in the test database."""
    users.update_one(
        {"username": "user_alice"},
        {"$set": {
            "username": "user_alice",
            "email": "alice@security.test",
            "password": "hashed_alice_password",
            "token_version": 1,
            "bookmarks": [],
            "bio": "Alice bio",
            "avatar_url": ""
        }},
        upsert=True
    )
    users.update_one(
        {"username": "user_bob"},
        {"$set": {
            "username": "user_bob",
            "email": "bob@security.test",
            "password": "hashed_bob_password",
            "token_version": 1,
            "bookmarks": [],
            "bio": "Bob bio",
            "avatar_url": ""
        }},
        upsert=True
    )
    yield
    # Cleanup any test jobs and posts created by tests
    mongo.db.jobs.delete_many({"username": {"$in": ["user_alice", "user_bob"]}})
    posts.delete_many({"author": {"$in": ["user_alice", "user_bob"]}})

# ==============================================================================
# 1. Anonymous Access Denied to Protected Resources
# ==============================================================================

def test_anonymous_access_denied_to_protected_routes(client):
    """Anonymous visitors must be redirected to /login or receive 401 on APIs."""
    # HTML routes -> 302 redirect to /login
    protected_html = ['/dashboard', '/settings', '/settings/profile', '/settings/account', '/reading-list', '/post/new']
    for route in protected_html:
        res = client.get(route, follow_redirects=False)
        assert res.status_code == 302
        assert '/login' in res.headers['Location']

    # JSON API routes -> 401 Unauthorized
    api_routes = [
        ('/api/bookmark/654321654321654321654321', 'post'),
        ('/ai/research', 'post'),
        ('/api/job/test-job-uuid-1234', 'get')
    ]
    for url, method in api_routes:
        if method == 'post':
            res = client.post(url, json={})
        else:
            res = client.get(url)
        assert res.status_code == 401

# ==============================================================================
# 2 & 3. Resource Ownership: User A Can Access Own Resources, Not User B's
# ==============================================================================

def test_user_a_can_access_own_resources(client):
    """User Alice can view her own dashboard, settings and draft."""
    draft_id = posts.insert_one({
        'title': 'Alice Secret Draft',
        'content': '<p>Top secret draft by Alice</p>',
        'author': 'user_alice',
        'is_draft': True,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    with client.session_transaction() as sess:
        sess['user'] = 'user_alice'
        sess['token_version'] = 1

    # Alice views her own draft -> 200 OK
    res = client.get(f'/post/{draft_id}')
    assert res.status_code == 200
    assert b'Alice Secret Draft' in res.data

def test_user_b_cannot_read_user_a_private_draft(client):
    """User Bob must be rejected with 403 when trying to view User Alice's draft."""
    draft_id = posts.insert_one({
        'title': 'Alice Secret Draft 2',
        'content': '<p>Confidential thoughts</p>',
        'author': 'user_alice',
        'is_draft': True,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    with client.session_transaction() as sess:
        sess['user'] = 'user_bob'
        sess['token_version'] = 1

    # Bob attempts to view Alice's draft -> 403 Forbidden
    res = client.get(f'/post/{draft_id}')
    assert res.status_code == 403

def test_anonymous_cannot_read_private_draft(client):
    """Anonymous visitors must be rejected with 403 when trying to access drafts directly."""
    draft_id = posts.insert_one({
        'title': 'Alice Secret Draft 3',
        'content': '<p>Confidential thoughts</p>',
        'author': 'user_alice',
        'is_draft': True,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    res = client.get(f'/post/{draft_id}')
    assert res.status_code == 403

# ==============================================================================
# 4 & 5. Post Editing & Deletion IDOR Protection
# ==============================================================================

def test_user_b_cannot_edit_user_a_post(client):
    """User Bob cannot edit User Alice's post."""
    post_id = posts.insert_one({
        'title': 'Alice Published Post',
        'content': '<p>Alice thoughts</p>',
        'author': 'user_alice',
        'is_draft': False,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    with client.session_transaction() as sess:
        sess['user'] = 'user_bob'
        sess['token_version'] = 1

    # GET edit form -> 403
    res_get = client.get(f'/post/{post_id}/edit')
    assert res_get.status_code == 403

    # POST edit -> 403
    res_post = client.post(f'/post/{post_id}/edit', data={
        'title': 'Hacked by Bob',
        'content': '<p>Defaced</p>',
        'intent': 'inform',
        'freshness': 'current'
    })
    assert res_post.status_code == 403

    # Verify post remains unchanged in DB
    unchanged = posts.find_one({'_id': post_id})
    assert unchanged['title'] == 'Alice Published Post'

def test_user_b_cannot_delete_user_a_post(client):
    """User Bob cannot delete User Alice's post."""
    post_id = posts.insert_one({
        'title': 'Alice Indelible Post',
        'content': '<p>Alice valuable content</p>',
        'author': 'user_alice',
        'is_draft': False,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    with client.session_transaction() as sess:
        sess['user'] = 'user_bob'
        sess['token_version'] = 1

    res = client.post(f'/post/{post_id}/delete')
    assert res.status_code == 403

    # Verify post still exists in DB
    still_there = posts.find_one({'_id': post_id})
    assert still_there is not None

def test_user_a_can_delete_own_post(client):
    """User Alice can delete her own post."""
    post_id = posts.insert_one({
        'title': 'Alice Delete Me',
        'content': '<p>Bye</p>',
        'author': 'user_alice',
        'is_draft': False,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    with client.session_transaction() as sess:
        sess['user'] = 'user_alice'
        sess['token_version'] = 1

    res = client.post(f'/post/{post_id}/delete')
    assert res.status_code == 302
    assert posts.find_one({'_id': post_id}) is None

# ==============================================================================
# 6 & 7. Comment Pinning & Bookmarks IDOR Protection
# ==============================================================================

def test_non_author_cannot_pin_comment(client):
    """Only the author of the post can pin comments on it."""
    post_id = posts.insert_one({
        'title': 'Alice Post for Comments',
        'content': '<p>Comments test</p>',
        'author': 'user_alice',
        'is_draft': False,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    comment_id = comments.insert_one({
        'post_id': post_id,
        'author': 'user_bob',
        'content': 'Bob comment',
        'is_pinned': False,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    # Bob attempts to pin his comment on Alice's post -> 403
    with client.session_transaction() as sess:
        sess['user'] = 'user_bob'
        sess['token_version'] = 1

    res_bob = client.post(f'/comment/{comment_id}/pin')
    assert res_bob.status_code == 403

    # Alice pins the comment on her post -> 302 success
    with client.session_transaction() as sess:
        sess['user'] = 'user_alice'
        sess['token_version'] = 1

    res_alice = client.post(f'/comment/{comment_id}/pin')
    assert res_alice.status_code == 302
    pinned = comments.find_one({'_id': comment_id})
    assert pinned.get('is_pinned') is True

def test_bookmark_isolation(client):
    """Toggling bookmark affects only the authenticated user's account."""
    fake_post_id = str(ObjectId())

    with client.session_transaction() as sess:
        sess['user'] = 'user_alice'
        sess['token_version'] = 1

    res = client.post(f'/api/bookmark/{fake_post_id}')
    assert res.status_code == 200
    assert res.get_json()['status'] == 'added'

    alice_doc = users.find_one({'username': 'user_alice'})
    bob_doc = users.find_one({'username': 'user_bob'})
    assert fake_post_id in alice_doc.get('bookmarks', [])
    assert fake_post_id not in bob_doc.get('bookmarks', [])

# ==============================================================================
# 8, 9 & 10. Background Job Ownership & Legacy Job Protection
# ==============================================================================

def test_user_a_can_create_and_retrieve_own_job(client):
    """User Alice can create an AI research job and retrieve its status."""
    with client.session_transaction() as sess:
        sess['user'] = 'user_alice'
        sess['token_version'] = 1

    # In test mode, create a job record directly or call route
    alice_doc = users.find_one({'username': 'user_alice'})
    job_uuid = str(uuid.uuid4())
    mongo.db.jobs.insert_one({
        'job_id': job_uuid,
        'user_id': alice_doc['_id'],
        'username': 'user_alice',
        'status': 'completed',
        'result': {'ammunition': [{'fact': 'Important fact', 'source': 'https://example.com'}]},
        'created_at': datetime.now(timezone.utc)
    })

    # Alice retrieves her job -> 200 OK
    res = client.get(f'/api/job/{job_uuid}')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'completed'
    assert 'ammunition' in data['result']

def test_user_b_cannot_retrieve_user_a_job(client):
    """User Bob must be rejected with 403 Forbidden when requesting Alice's job."""
    alice_doc = users.find_one({'username': 'user_alice'})
    job_uuid = str(uuid.uuid4())
    mongo.db.jobs.insert_one({
        'job_id': job_uuid,
        'user_id': alice_doc['_id'],
        'username': 'user_alice',
        'status': 'completed',
        'result': {'ammunition': [{'fact': 'Confidential research'}]},
        'created_at': datetime.now(timezone.utc)
    })

    with client.session_transaction() as sess:
        sess['user'] = 'user_bob'
        sess['token_version'] = 1

    res = client.get(f'/api/job/{job_uuid}')
    assert res.status_code == 403
    assert res.get_json()['error'] == 'Forbidden'

def test_legacy_ownerless_job_rejected(client):
    """Legacy jobs lacking user ownership metadata must be rejected with 403."""
    job_uuid = str(uuid.uuid4())
    mongo.db.jobs.insert_one({
        'job_id': job_uuid,
        # Intentionally omitting user_id and username
        'status': 'completed',
        'result': {'secret': 'legacy data'},
        'created_at': datetime.now(timezone.utc)
    })

    with client.session_transaction() as sess:
        sess['user'] = 'user_alice'
        sess['token_version'] = 1

    res = client.get(f'/api/job/{job_uuid}')
    assert res.status_code == 403
    assert res.get_json()['error'] == 'Forbidden'

# ==============================================================================
# 11 & 12. Invalid IDs & Mass-Assignment / Privilege Escalation Protection
# ==============================================================================

def test_invalid_object_id_handling(client):
    """Malformed or invalid ObjectIDs must return 400 or 404 cleanly, never 500."""
    with client.session_transaction() as sess:
        sess['user'] = 'user_alice'
        sess['token_version'] = 1

    bad_id = "not-a-valid-24-char-hex-oid!!!"
    
    # View post -> 404
    assert client.get(f'/post/{bad_id}').status_code == 404
    # Edit post -> 404
    assert client.get(f'/post/{bad_id}/edit').status_code == 404
    # Delete post -> 404
    assert client.post(f'/post/{bad_id}/delete').status_code == 404
    # Bookmark API -> 400
    assert client.post(f'/api/bookmark/{bad_id}').status_code == 400
    # Save progress -> 400
    assert client.post(f'/api/save_progress/{bad_id}', json={'progress': 50}).status_code == 400

def test_cannot_escalate_privilege_or_hijack_role_via_profile_update(client):
    """Profile settings updates only write whitelisted bio and avatar_url."""
    with client.session_transaction() as sess:
        sess['user'] = 'user_alice'
        sess['token_version'] = 1

    # Attempt to inject role, is_admin, and username into profile update
    res = client.post('/settings/profile', data={
        'bio': 'New updated bio',
        'avatar_url': 'https://example.com/avatar.png',
        'role': 'superadmin',
        'is_admin': True,
        'username': 'hacked_admin'
    }, follow_redirects=False)

    assert res.status_code == 302
    alice_doc = users.find_one({'username': 'user_alice'})
    assert alice_doc.get('bio') == 'New updated bio'
    assert 'role' not in alice_doc or alice_doc['role'] != 'superadmin'
    assert 'is_admin' not in alice_doc or alice_doc['is_admin'] != True
    assert alice_doc['username'] == 'user_alice'

# ==============================================================================
# 13. Public Resources Remain Accessible
# ==============================================================================

def test_public_resources_remain_accessible(client):
    """Public feeds, published articles, and author profiles remain accessible to all."""
    pub_id = posts.insert_one({
        'title': 'Public Community Story',
        'content': '<p>Welcome to FlaskBlog</p>',
        'author': 'user_alice',
        'is_draft': False,
        'created_at': datetime.now(timezone.utc)
    }).inserted_id

    # Anonymous access
    assert client.get('/').status_code == 200
    assert client.get(f'/post/{pub_id}').status_code == 200
    assert client.get('/profile/user_alice').status_code == 200
    assert client.get('/search?q=Community').status_code == 200
