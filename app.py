import os
import math
import re
import threading
from datetime import datetime, timezone, timedelta
import secrets
from flask import Flask, render_template, request, redirect, session, url_for, flash, abort, jsonify, make_response, g
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Optional, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from bson.objectid import ObjectId
import bleach
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Environment & Secret Key Management
import sys
FLASK_ENV = os.environ.get("FLASK_ENV", "development" if os.path.exists(".env") else "production")
IS_TESTING = os.environ.get("TESTING", "").lower() in ("true", "1") or ("pytest" in sys.modules) or ("test" in sys.argv[0].lower())
IS_PRODUCTION = (os.environ.get("FLASK_ENV") == "production") or (os.environ.get("RENDER") == "true")
if IS_TESTING:
    IS_PRODUCTION = False

raw_secret = os.environ.get("SECRET_KEY")

if IS_PRODUCTION:
    if not raw_secret or not raw_secret.strip() or raw_secret == "dev_secret_key_change_me":
        raise RuntimeError(
            "FATAL SECURITY ERROR: A secure, non-default SECRET_KEY environment variable "
            "must be configured in production. Application startup aborted."
        )
    if len(raw_secret.strip()) < 32:
        raise RuntimeError(
            "FATAL SECURITY ERROR: SECRET_KEY must contain at least 32 characters of entropy in production."
        )
    app.secret_key = raw_secret.strip()
else:
    # Explicit development / testing fallback
    app.secret_key = raw_secret.strip() if (raw_secret and raw_secret.strip()) else "dev_explicit_insecure_local_testing_key_32chars"

app.config["SECRET_KEY"] = app.secret_key
app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb://localhost:27017/blogDB")

# Session Cookie Hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "true" if IS_PRODUCTION else "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

from flask_wtf.csrf import CSRFProtect, CSRFError

# Global CSRF protection for all browser state-changing requests (forms and AJAX).
csrf = CSRFProtect(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.is_json or request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'CSRF Error', 'message': e.description}), 400
    return render_template('csrf_error.html', reason=e.description), 400

mongo = PyMongo(app)
users = mongo.db.users
posts = mongo.db.posts
comments = mongo.db.comments
activities = mongo.db.activities
reading_sessions = mongo.db.reading_sessions
reading_history = mongo.db.reading_history
password_reset_tokens = mongo.db.password_reset_tokens

# NOTE: the active inject_user context processor is defined further below
# (it also injects recent_activities + site_pulse). A second, simpler copy used
# to live here and was silently overridden by the later one.

@app.before_request
def set_csp_nonce():
    # Fresh per-request nonce so inline <script> blocks can be whitelisted
    # without allowing arbitrary injected script ('unsafe-inline').
    g.csp_nonce = secrets.token_urlsafe(16)

@app.before_request
def validate_session_state():
    # Ensure active session corresponds to a valid user and revocation token version
    if 'user' in session:
        user = users.find_one({'username': session['user']})
        if not user:
            session.clear()
            g.current_user = None
            return
        
        expected_version = user.get('token_version', 1)
        if session.get('token_version') != expected_version:
            session.clear()
            g.current_user = None
            return
            
        g.current_user = user
    else:
        g.current_user = None

@app.context_processor
def inject_csp_nonce():
    return dict(csp_nonce=getattr(g, 'csp_nonce', ''))

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    nonce = getattr(g, 'csp_nonce', '')
    # script-src: nonce-based, no 'unsafe-inline'/'unsafe-eval'. Inline scripts
    # must carry nonce="{{ csp_nonce }}". style-src keeps 'unsafe-inline' because
    # inline style="" attributes (used throughout) cannot take a nonce.
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https:; "
        f"script-src 'self' https: 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline' https:; "
        "img-src 'self' data: https:; "
        "font-src 'self' https: data:;"
    )
    return response

@app.route('/robots.txt')
def robots_txt():
    lines = [
        "User-agent: *",
        "Allow: /",
        "Disallow: /dashboard",
        "Disallow: /settings",
        "Disallow: /reset_password",
        "Disallow: /api/",
        "Disallow: /ai/",
        f"Sitemap: {url_for('sitemap', _external=True)}",
    ]
    resp = make_response("\n".join(lines))
    resp.headers["Content-Type"] = "text/plain"
    return resp

@app.route('/sitemap.xml')
def sitemap():
    pages = []
    # Static pages
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and len(rule.arguments) == 0:
            pages.append([url_for(rule.endpoint, _external=True), datetime.now().date()])

    # Dynamic posts
    for post in posts.find({'is_draft': {'$ne': True}}):
        pages.append([url_for('view_post', post_id=str(post['_id']), _external=True), post.get('updated_at', post.get('created_at', datetime.now())).date()])

    xml_sitemap = render_template('sitemap.xml', pages=pages)
    response = make_response(xml_sitemap)
    response.headers["Content-Type"] = "application/xml"
    return response

# Rate Limiter for Render Free Tier protection
limiter = Limiter(
    get_remote_address,
    app=app,
    # No global default: read pages (homepage, posts, search) must stay
    # unlimited so users sharing one IP (NAT/corporate/mobile) aren't locked
    # out. Limits are applied per-route below only to auth, write, and AI
    # endpoints, which are the abuse/cost-sensitive ones.
    default_limits=[],
    storage_uri="memory://",
)
from services import ai_service
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import uuid

# Background executor for slow AI tasks (throttled for Free Tier)
executor = ThreadPoolExecutor(max_workers=2)
# In-memory or MongoDB persistent job status
jobs = {} 

def send_digest_email(user_email, username, last_visit):
    with app.app_context():
        # 1. Find new posts since last visit
        new_posts = list(posts.find({'created_at': {'$gt': last_visit}}).limit(5))
        
        # 2. Find new interactions on user's own posts
        user_posts = [p['_id'] for p in posts.find({'author': username}, {'_id': 1})]
        new_comments = comments.count_documents({
            'post_id': {'$in': user_posts},
            'created_at': {'$gt': last_visit}
        })
        
        if not new_posts and new_comments == 0:
            return # Nothing new to report

        body = f"Hi {username}!\n\n"
        if new_comments > 0:
            body += f"You have {new_comments} new responses to your stories.\n\n"
            
        if new_posts:
            body += "Check out what's new on FlaskBlog:\n"
            for p in new_posts:
                body += f"- {p['title']} by {p['author']}\n"
        
        body += f"\nSee everything at: {url_for('index', _external=True)}"
        
        # Use Brevo API
        send_email_brevo(user_email, "While you were away...", body)

from flask_compress import Compress
from flask_caching import Cache

compress = Compress(app)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 60})

import requests

# Mail Configuration (Removed SMTP, using Resend API)
# We don't need app.config['MAIL_SERVER'] etc anymore.

# Helper for Brevo API (formerly Sendinblue)
def send_email_brevo(to_email, subject, body):
    api_key = os.environ.get("BREVO_API_KEY")
    sender_email = os.environ.get("MAIL_USER") # Must be the email you verified in Brevo
    
    if not api_key:
        print("ERROR: BREVO_API_KEY not found.", flush=True)
        return False
    if not sender_email:
        print("ERROR: MAIL_USER not found (needed for Sender).", flush=True)
        return False

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }
    
    payload = {
        "sender": {"name": "Flask Blog", "email": sender_email},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": f"<p>{body.replace(chr(10), '<br>')}</p>" # Convert newlines to HTML breaks
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code in [200, 201, 202]:
            print(f"SUCCESS: Email sent to {to_email} via Brevo.", flush=True)
            return True
        else:
            print(f"ERROR: Brevo API failed. Status: {response.status_code}, Body: {response.text}", flush=True)
            return False
    except Exception as e:
        print(f"ERROR: Exception while sending email via Brevo: {e}", flush=True)
        return False

def send_async_email(app, to_email, subject, body):
    with app.app_context():
        send_email_brevo(to_email, subject, body)

def hash_password(password):
    """Hash a password using modern scrypt algorithm with salt."""
    return generate_password_hash(password, method='scrypt')

def get_trusted_reset_url(token):
    """Generate password reset URL bound to trusted host to mitigate Host header poisoning."""
    app_url = os.environ.get('APP_URL') or os.environ.get('BASE_URL')
    if app_url:
        return f"{app_url.rstrip('/')}{url_for('reset_token', token=token)}"
    return url_for('reset_token', token=token, _external=True)

def send_reset_email(user):
    print(f"Attempting to send reset email to: {user['email']}", flush=True)
    token = get_reset_token(user['_id'])
    reset_url = get_trusted_reset_url(token)
    
    subject = 'Password Reset Request'
    body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    # Send in background thread
    threading.Thread(target=send_async_email, args=(app, user['email'], subject, body)).start()

@app.route('/test_email')
def test_email():
    # Production guard: Never expose or invoke test email in production or when not explicitly permitted
    # Render deployments set RENDER=true or FLASK_ENV=production.
    is_prod = (os.environ.get('FLASK_ENV') == 'production') or (os.environ.get('RENDER') == 'true')
    allow_test_endpoint = os.environ.get('ENABLE_TEST_EMAIL_ENDPOINT', '').lower() in ('true', '1')
    
    if is_prod or not allow_test_endpoint:
        abort(404)
        
    key = os.environ.get('BREVO_API_KEY')
    if not key:
        return "Error: BREVO_API_KEY not set.", 500
        
    target_email = os.environ.get('MAIL_USER') 
    if not target_email:
        return "Error: MAIL_USER env var not set.", 500

    if send_email_brevo(target_email, "Brevo API Test", "If you read this, the Brevo integration is working!"):
        return "Email test successfully dispatched. Check logs for details.", 200
    else:
        return "Failed to send test email. Check logs for details.", 500

# Global Cache for Trending Posts
TRENDING_CACHE = {
    'data': [],
    'last_updated': datetime.min.replace(tzinfo=timezone.utc)
}

def get_trending_posts():
    global TRENDING_CACHE
    now = datetime.now(timezone.utc)
    
    # Refresh cache if older than 1 hour (3600 seconds)
    if (now - TRENDING_CACHE['last_updated']).total_seconds() > 3600:
        # Fetch all posts but EXCLUDE the heavy fields (full HTML body + cached
        # AI summary). Trending only needs counts + card metadata, so pulling
        # every article body into memory was a needless memory spike on free tier.
        trending_fields = {'content': 0, 'summary_cache': 0}
        all_posts = list(posts.find({'is_draft': {'$ne': True}}, trending_fields))
        
        scored_posts = []
        for p in all_posts:
            views = p.get('views', 0)
            likes = len(p.get('likes', []))
            # Fallback to counting if comment_count field missing (migration)
            comments_count = p.get('comment_count', 0)
            
            # Weighted Score: Views(1) + Likes(2) + Comments(3)
            score = views + (likes * 2) + (comments_count * 3)
            p['score'] = score
            scored_posts.append(p)
            
        # Sort by score desc, take top 4
        scored_posts.sort(key=lambda x: x['score'], reverse=True)
        TRENDING_CACHE['data'] = scored_posts[:4]
        TRENDING_CACHE['last_updated'] = now
        
    return TRENDING_CACHE['data']

@app.route('/health')
def health_check():
    return "OK", 200

@app.route('/ping')
def ping():
    return {'status': 'ok'}, 200

@app.route('/api/save_progress/<post_id>', methods=['POST'])
def save_progress(post_id):
    if not g.get('current_user') or 'user' not in session:
        return {'status': 'ignored'}, 200
    
    obj_id = get_valid_object_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid post ID'}), 400
    
    data = request.get_json() or {}
    progress = data.get('progress', 0)
    
    reading_history.update_one(
        {'user': session['user'], 'post_id': obj_id},
        {'$set': {'progress': progress, 'updated_at': datetime.now(timezone.utc)}},
        upsert=True
    )
    return {'status': 'saved'}, 200

# Ensure indexes
try:
    users.create_index("username", unique=True)
    users.create_index("email", unique=True, sparse=True) # Email index
    posts.create_index("author")
    posts.create_index([("title", "text"), ("content", "text"), ("tags", "text")]) # Text search
    comments.create_index("post_id")
    # TTL Index: Activities expire after 48 hours
    activities.create_index("timestamp", expireAfterSeconds=172800)
    # TTL Index: Reading sessions expire after 5 minutes
    reading_sessions.create_index("timestamp", expireAfterSeconds=300)
except Exception as e:
    print(f"Index creation warning: {e}")

# Helper to log activity
def log_activity(user, action, target_id=None, target_title=None):
    activities.insert_one({
        'user': user,
        'action': action,
        'target_id': target_id,
        'target_title': target_title,
        'timestamp': datetime.now(timezone.utc)
    })

@app.template_filter('time_ago')
def time_ago_filter(dt):
    if not dt:
        return ""
    # Ensure dt is timezone-aware
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    now = datetime.now(timezone.utc)
    diff = now - dt
    
    seconds = diff.total_seconds()
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    elif seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    else:
        return f"{int(seconds // 86400)}d ago"

from functools import wraps
from bson.errors import InvalidId

def get_valid_object_id(oid_str):
    try:
        return ObjectId(oid_str)
    except (InvalidId, TypeError, ValueError):
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.get('current_user') or 'user' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helpers
def get_reading_time(text):
    word_count = len(re.findall(r'\w+', text))
    reading_time_min = math.ceil(word_count / 200) # Avg reading speed 200 wpm
    return reading_time_min

def get_post_read_time(post):
    """Read time for a post, preferring the value stored at write time.

    New/edited posts persist 'read_time', so list pages no longer need to run
    bleach over every article body on every request (a hot-path CPU cost). Only
    legacy docs without the field fall back to computing it on the fly.
    """
    stored = post.get('read_time')
    if stored:
        return stored
    clean_text = bleach.clean(post.get('content', ''), tags=[], strip=True)
    return get_reading_time(clean_text)

def sanitize_html(content):
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'h1', 'h2', 'h3', 'br', 'ul', 'ol', 'li', 'blockquote', 'img']
    allowed_attrs = {
        'a': ['href', 'title', 'target'],
        'img': ['src', 'alt', 'width', 'height']
    }
    return bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)

def get_reset_token(user_id, expires_sec=1800):
    """Generate a cryptographically secure, single-use, hashed password reset token."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=expires_sec)
    
    password_reset_tokens.insert_one({
        'user_id': str(user_id),
        'token_hash': token_hash,
        'created_at': now,
        'expires_at': expires_at,
        'used': False
    })
    return raw_token

def verify_reset_token(token, expires_sec=1800):
    """Verify that a password reset token is valid, unexpired, and unused."""
    if not token or not isinstance(token, str):
        return None
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now = datetime.now(timezone.utc)
    
    token_doc = password_reset_tokens.find_one({
        'token_hash': token_hash,
        'used': False
    })
    if not token_doc:
        return None
        
    expires_at = token_doc.get('expires_at')
    if not expires_at:
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
        
    if now > expires_at:
        return None
        
    user_oid = get_valid_object_id(token_doc.get('user_id'))
    if not user_oid:
        return None
    return users.find_one({'_id': user_oid})

def _get_navbar_activity():
    """Recent-activity feed + site pulse for the navbar, cached ~30s.

    This runs on EVERY request via the context processor; without caching it
    fired two more DB queries per request (even on health checks/static), which
    crushes throughput under concurrency. The feed only needs to be near-real-time.
    """
    cached = cache.get('navbar_activity')
    if cached is not None:
        return cached
    recent_activities = list(activities.find().sort("timestamp", -1).limit(5))
    site_pulse = recent_activities[0]['timestamp'] if recent_activities else None
    result = {'recent_activities': recent_activities, 'site_pulse': site_pulse}
    cache.set('navbar_activity', result, timeout=30)
    return result

# Context Processor for User Info in Navbar
@app.context_processor
def inject_user():
    current_user = getattr(g, 'current_user', None)
    if current_user is None and 'user' in session:
        current_user = users.find_one({'username': session['user']})

    activity = _get_navbar_activity()
    return dict(current_user=current_user,
                recent_activities=activity['recent_activities'],
                site_pulse=activity['site_pulse'])

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128, message='Password must be between 8 and 128 characters.')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=128)])
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128, message='Password must be between 8 and 128 characters.')])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        Length(max=128),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Reset Password')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    subtitle = StringField('Subtitle', validators=[Optional(), Length(max=200)])
    series_name = StringField('Series Name (Optional)', validators=[Optional(), Length(max=100)])
    cover_url = StringField('Cover Image URL', validators=[Optional()])
    tags = StringField('Tags (comma separated)', validators=[Optional()])
    
    # New Meta-Data Fields
    intent = SelectField('Writing Intent', choices=[
        ('inform', 'Inform (Teach something)'),
        ('reflect', 'Reflect (Share personal experience)'),
        ('document', 'Document (Record history/process)'),
        ('argue', 'Argue (Persuade opinion)')
    ], validators=[DataRequired()])
    
    freshness = SelectField('Content Freshness', choices=[
        ('current', 'Current (Relevant now)'),
        ('evergreen', 'Evergreen (Always relevant)'),
        ('aging', 'Aging (Might be outdated soon)')
    ], validators=[DataRequired()], default='current')

    why_wrote = TextAreaField('Why I Wrote This (Optional)', validators=[Optional(), Length(max=300)])
    summary = TextAreaField('Reading Summary (Author Curated)', validators=[Optional(), Length(max=500)])
    
    content = TextAreaField('Content', validators=[DataRequired()]) # HTML content
    submit = SubmitField('Publish')
    save_draft = SubmitField('Save Draft')

class SettingsAccountForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    # Password change fields could be here
    submit = SubmitField('Update Account')

class SettingsProfileForm(FlaskForm):
    bio = TextAreaField('Bio', validators=[Optional(), Length(max=300)])
    avatar_url = StringField('Avatar URL', validators=[Optional()])
    submit = SubmitField('Update Profile')

class CommentForm(FlaskForm):
    content = TextAreaField('Response', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Respond')

class ProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    bio = TextAreaField('Bio', validators=[Optional(), Length(max=300)])
    avatar_url = StringField('Avatar URL', validators=[Optional()])
    submit = SubmitField('Save Profile')

# Routes

def get_recommended_posts(user_id=None):
    # 1. If user is logged in, find their top tags from reading history/likes
    # For now, simplistic approach: Random sample of popular posts (excluding current trending to avoid dupe if possible)
    # In a real app, aggregation pipeline on user's activities would be best.
    pipeline = [
        {'$match': {'is_draft': {'$ne': True}}},
        {'$sample': {'size': 5}}
    ]
    return list(posts.aggregate(pipeline))

@app.route('/search/suggestions')
def search_suggestions():
    query = request.args.get('q', '')
    if not query or len(query) < 2:
        return {'results': []}
    
    # Regex search for title or tags
    # Limit to 5 results
    regex = re.compile(query, re.IGNORECASE)
    results = posts.find({
        '$or': [
            {'title': regex},
            {'tags': regex}
        ],
        'is_draft': {'$ne': True}
    }, {'title': 1, '_id': 1}).limit(5)
    
    suggestions = [{'title': p['title'], 'id': str(p['_id'])} for p in results]
    return {'results': suggestions}

@app.route('/')
@cache.cached(timeout=30, query_string=True,
              unless=lambda: 'user' in session)
def index():
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (TypeError, ValueError):
        page = 1
    tab = request.args.get('tab', 'latest')
    per_page = 5
    
    trending_posts = get_trending_posts()
    recommended_posts = []

    query = {'is_draft': {'$ne': True}}

    if tab == 'trending':
        # Re-use trending logic but paginated? 
        # For simplicity, let's just use the cached trending data as the "list"
        # Or sorting by views/likes via DB query for pagination support
        all_posts_cursor = posts.find(query).sort("views", -1).skip((page - 1) * per_page).limit(per_page)
        
    elif tab == 'recommended':
        # Recommended doesn't paginate well with random sampling, so we'll just fetch one batch
        if 'user' in session:
            # Complex recommendation logic could go here
            pass
        all_posts_cursor = get_recommended_posts() # Returns list, not cursor
        # Mock pagination behavior
        all_posts_cursor = all_posts_cursor # It's a list
        
    else: # latest
        all_posts_cursor = posts.find(query).sort("created_at", -1).skip((page - 1) * per_page).limit(per_page)

    # Handle list vs cursor
    if isinstance(all_posts_cursor, list):
        all_posts = all_posts_cursor
        total_posts = len(all_posts) # Approximate for recommended
    else:
        all_posts = list(all_posts_cursor)
        total_posts = posts.count_documents(query)
    
    for post in all_posts:
        post['read_time'] = get_post_read_time(post)

    # Fetch author avatars for the feed
    authors_list = list(set(p['author'] for p in all_posts))
    author_avatars = {u['username']: u.get('avatar_url') for u in users.find({'username': {'$in': authors_list}}, {'username': 1, 'avatar_url': 1})}
        
    total_pages = math.ceil(total_posts / per_page)
    
    return render_template('index.html', posts=all_posts, page=page, total_pages=total_pages, trending_posts=trending_posts, current_tab=tab, author_avatars=author_avatars)

@app.route('/search')
def search():
    query = request.args.get('q')
    if query:
        # Simple regex search if text index fails or for partial matches, 
        # but Mongo text search is better. Let's use text index.
        results_cursor = posts.find({"$text": {"$search": query}})
        results = list(results_cursor)
    else:
        results = []
    
    for post in results:
        post['read_time'] = get_post_read_time(post)

    # Fetch author avatars for search results
    authors_list = list(set(p['author'] for p in results))
    author_avatars = {u['username']: u.get('avatar_url') for u in users.find({'username': {'$in': authors_list}}, {'username': 1, 'avatar_url': 1})}
    trending_posts = get_trending_posts()

    return render_template('index.html', posts=results, search_query=query, trending_posts=trending_posts, author_avatars=author_avatars, current_tab='search')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = users.find_one({'username': form.username.data})
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        # Check email too
        existing_email = users.find_one({'email': form.email.data})
        if existing_email:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        
        hash_pwd = hash_password(form.password.data)
        users.insert_one({
            'username': form.username.data,
            'email': form.email.data,
            'password': hash_pwd,
            'token_version': 1,
            'bio': "New writer.",
            'avatar_url': f"https://ui-avatars.com/api/?name={form.username.data}&background=random",
            'joined_at': datetime.now(timezone.utc),
            'last_visit': datetime.now(timezone.utc)
        })
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute", methods=["POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Accept either username or email as the login identifier. Email is
        # matched case-insensitively (emails are not case-sensitive).
        identifier = (form.username.data or '').strip()
        email_regex = re.compile('^' + re.escape(identifier) + '$', re.IGNORECASE)
        user = users.find_one({
            '$or': [
                {'username': identifier},
                {'email': email_regex}
            ]
        })
        # Constant-time mitigation against timing attacks for nonexistent users
        dummy_hash = 'scrypt:32768:8:1$dummy$dummyhashforaccountenumerationmitigation1234567890'
        password_valid = False
        if user and user.get('password'):
            try:
                password_valid = check_password_hash(user['password'], form.password.data)
            except Exception:
                password_valid = False
        else:
            try:
                check_password_hash(dummy_hash, form.password.data)
            except Exception:
                pass

        if user and password_valid:
            # Seamlessly upgrade legacy/weaker hashes (e.g. pbkdf2) to scrypt on successful login
            stored_pwd = user.get('password', '')
            if not stored_pwd.startswith('scrypt:'):
                try:
                    new_hash = hash_password(form.password.data)
                    users.update_one({'_id': user['_id']}, {'$set': {'password': new_hash}})
                except Exception as ex:
                    print(f"Warning: Failed to upgrade password hash for user {user['username']}: {ex}", flush=True)

            # Regenerate / clear previous session state to prevent session fixation
            session.clear()
            token_version = user.get('token_version', 1)
            session['user'] = user['username']
            session['token_version'] = token_version
            
            # Check for digest trigger
            last_visit = user.get('last_visit')
            now = datetime.now(timezone.utc)
            
            if last_visit:
                # If last visit was > 3 days ago and user has email
                if (now - last_visit.replace(tzinfo=timezone.utc if last_visit.tzinfo is None else last_visit.tzinfo)).total_seconds() > 259200:
                    if user.get('email'):
                        threading.Thread(target=send_digest_email, 
                                       args=(user['email'], user['username'], last_visit)).start()
            
            # Update last visit
            users.update_one({'_id': user['_id']}, {'$set': {'last_visit': now}})
            
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("5 per hour", methods=["POST"])
def reset_request():
    if 'user' in session:
        return redirect(url_for('index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = users.find_one({'email': form.email.data})
        if user:
            send_reset_email(user)
        flash('An email has been sent with instructions to reset your password. (Please check your Spam/Junk folder if you do not see it)', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=["POST"])
def reset_token(token):
    if 'user' in session:
        return redirect(url_for('index'))
    user_doc = verify_reset_token(token)
    if user_doc is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now = datetime.now(timezone.utc)
        # Atomic token consumption to guarantee single-use and prevent race conditions
        consumed = password_reset_tokens.find_one_and_update(
            {
                'token_hash': token_hash,
                'used': False,
                'expires_at': {'$gt': now}
            },
            {
                '$set': {'used': True, 'consumed_at': now}
            }
        )
        if not consumed:
            flash('That is an invalid or expired token', 'warning')
            return redirect(url_for('reset_request'))

        hash_pwd = hash_password(form.password.data)
        # Atomically update password and increment token_version to invalidate all existing sessions
        users.update_one(
            {'_id': user_doc['_id']},
            {
                '$set': {'password': hash_pwd},
                '$inc': {'token_version': 1}
            }
        )
        session.clear()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/post/new', methods=['GET', 'POST'])
@limiter.limit("30 per hour", methods=["POST"])
@login_required
def new_post():
    
    form = PostForm()
    if form.validate_on_submit():
        # Clean HTML content
        clean_content = sanitize_html(form.content.data)
        tags_list = [tag.strip() for tag in form.tags.data.split(',')] if form.tags.data else []

        is_draft = form.save_draft.data # True if 'Save Draft' was clicked
        # Precompute read time once at write time (avoids per-request bleach on feeds)
        read_time = get_reading_time(bleach.clean(clean_content, tags=[], strip=True))

        post_id = posts.insert_one({
            'title': form.title.data,
            'subtitle': form.subtitle.data,
            'series_name': form.series_name.data,
            'intent': form.intent.data,
            'freshness': form.freshness.data,
            'why_wrote': form.why_wrote.data,
            'summary': form.summary.data,
            'content': clean_content,
            'read_time': read_time,
            'cover_url': form.cover_url.data,
            'author': session['user'],
            'tags': tags_list,
            'created_at': datetime.now(timezone.utc),
            'likes': [],
            'is_draft': is_draft,
            'revision_count': 1
        }).inserted_id
        
        if not is_draft:
            log_activity(session['user'], "published a new story", post_id, form.title.data)
            flash('Published!', 'success')
        else:
            flash('Draft saved.', 'info')
            
        return redirect(url_for('view_post', post_id=post_id))
    
    return render_template('post_form.html', form=form, legend="Write a Story")

@app.route('/post/<post_id>', methods=['GET', 'POST'])
@cache.cached(timeout=60, unless=lambda: 'user' in session or request.method == 'POST')
def view_post(post_id):
    obj_id = get_valid_object_id(post_id)
    if not obj_id:
        abort(404)
        
    post = posts.find_one({'_id': obj_id})
    if not post:
        abort(404)

    # Draft access control: only author can view drafts
    if post.get('is_draft'):
        if not g.get('current_user') or 'user' not in session or session['user'] != post['author']:
            abort(403)

    # Increment View Count (Lightweight Analytics)
    posts.update_one({'_id': obj_id}, {'$inc': {'views': 1}})
    
    # Get Author details
    author = users.find_one({'username': post['author']})
    
    # Access Control for Drafts (enforced at route entry)
    
    # Comments - sorted by pinned first, then new
    post_comments = list(comments.find({'post_id': ObjectId(post_id)}).sort([("is_pinned", -1), ("created_at", -1)]))
    
    # Comment Form
    form = CommentForm()
    if 'user' in session and form.validate_on_submit():
        comments.insert_one({
            'post_id': ObjectId(post_id),
            'author': session['user'],
            'content': form.content.data,
            'created_at': datetime.now(timezone.utc),
            'is_pinned': False
        })
        # Increment comment count for trending logic
        posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'comment_count': 1}})
        
        log_activity(session['user'], "responded to", post_id, post['title'])
        flash('Response added.', 'success')
        return redirect(url_for('view_post', post_id=post_id))

    read_time = get_post_read_time(post)

    is_author = 'user' in session and session['user'] == post['author']
    
    # Process Reactions
    reactions = post.get('reactions', {})
    # Backfill legacy likes if needed (optional, or just ignore legacy)
    legacy_likes = post.get('likes', [])
    if legacy_likes and not reactions:
        reactions = {u: 'like' for u in legacy_likes}
    
    user_reaction = reactions.get(session['user']) if 'user' in session else None
    reaction_counts = {}
    for r in reactions.values():
        reaction_counts[r] = reaction_counts.get(r, 0) + 1

    # Check if bookmarked
    is_bookmarked = False
    server_progress = 0
    if 'user' in session:
        user = users.find_one({'username': session['user']})
        if user:
            saved = user.get('bookmarks', [])
            is_bookmarked = post_id in saved

            # Get reading progress
            hist = reading_history.find_one({'user': session['user'], 'post_id': ObjectId(post_id)})
            if hist:
                server_progress = hist.get('progress', 0)
        else:
            # Session exists but user not found in DB (e.g. after DB reset)
            # Effectively treat as logged out for this request, or could clear session.
            pass
    
    # Track Reading Session
    # Use session ID or username to avoid counting same user twice
    session_id = session.get('user', request.remote_addr)
    reading_sessions.update_one(
        {'post_id': ObjectId(post_id), 'session_id': session_id},
        {'$set': {'timestamp': datetime.now(timezone.utc)}},
        upsert=True
    )
    
    # Count active readers (last 2 minutes)
    two_mins_ago = datetime.now(timezone.utc) - timedelta(minutes=2)
    active_readers = reading_sessions.count_documents({
        'post_id': ObjectId(post_id),
        'timestamp': {'$gt': two_mins_ago}
    })

    # Series Navigation
    series_prev = None
    series_next = None
    if post.get('series_name'):
        # Find prev: same series, created before this one, sort desc
        series_prev = posts.find_one({
            'series_name': post['series_name'],
            'created_at': {'$lt': post['created_at']}
        }, sort=[('created_at', -1)])
        
        # Find next: same series, created after this one, sort asc
        series_next = posts.find_one({
            'series_name': post['series_name'],
            'created_at': {'$gt': post['created_at']}
        }, sort=[('created_at', 1)])

    # Related Posts
    # Only the fields get_related_posts actually scores/renders - avoid pulling
    # 50 full article bodies into memory on every post view.
    related_fields = {'title': 1, 'tags': 1, 'author': 1, 'cover_url': 1,
                      'subtitle': 1, 'created_at': 1}
    all_other_posts = list(posts.find(
        {'is_draft': {'$ne': True}, '_id': {'$ne': ObjectId(post_id)}},
        related_fields
    ).limit(50))
    related_posts = ai_service.get_related_posts(post, all_other_posts)

    return render_template('post_detail.html', post=post, author=author, comments=post_comments, form=form, read_time=read_time, is_author=is_author, user_reaction=user_reaction, reaction_counts=reaction_counts, is_bookmarked=is_bookmarked, active_readers=active_readers, series_prev=series_prev, series_next=series_next, server_progress=server_progress, related_posts=related_posts)

@app.route('/post/<post_id>/bookmark', methods=['POST'])
@login_required
def bookmark_post(post_id):
    obj_id = get_valid_object_id(post_id)
    if not obj_id:
        abort(404)
        
    user = g.get('current_user') or users.find_one({'username': session['user']})
    saved = user.get('bookmarks', [])
    
    if post_id in saved:
        users.update_one({'username': session['user']}, {'$pull': {'bookmarks': post_id}})
        flash('Removed from reading list.', 'info')
    else:
        users.update_one({'username': session['user']}, {'$addToSet': {'bookmarks': post_id}})
        flash('Added to reading list.', 'success')
        
    return redirect(url_for('view_post', post_id=post_id))

# AI Routes
@app.route('/ai/summarize/<post_id>', methods=['POST'])
@limiter.limit("30 per hour")
def ai_summarize(post_id):
    try:
        obj_id = get_valid_object_id(post_id)
        if not obj_id:
            return jsonify({'error': 'Invalid post ID'}), 400
            
        post = posts.find_one({'_id': obj_id})
        if not post:
            return jsonify({'error': 'Post not found'}), 404
            
        # Do not allow AI summarization of someone else's draft
        if post.get('is_draft'):
            if not g.get('current_user') or 'user' not in session or session['user'] != post['author']:
                return jsonify({'error': 'Unauthorized'}), 403
            
        # 1. Check Cache
        if 'summary_cache' in post:
            cache_data = post['summary_cache']
            # Only use cache if it was generated after the last update and is not an error/fallback
            updated_at = post.get('updated_at', post.get('created_at'))
            if (cache_data.get('generated_at') and 
                cache_data['generated_at'] >= updated_at and 
                not cache_data.get('error') and 
                not cache_data.get('is_fallback')):
                return jsonify(cache_data)

        # 2. Extract Full Text with BeautifulSoup
        soup = BeautifulSoup(post.get('content', ''), 'html.parser')
        # Preserve paragraph breaks
        for p in soup.find_all('p'):
            p.append('\n\n')
        full_text = soup.get_text().strip()

        # 3. Call AI
        result = ai_service.summarize_text(full_text)
        
        # 4. Save to Cache only if it's a genuine AI summary (not error or temporary fallback)
        if isinstance(result, dict) and 'summary' in result:
            if not result.get('error') and not result.get('is_fallback'):
                result['generated_at'] = datetime.now(timezone.utc)
                posts.update_one({'_id': ObjectId(post_id)}, {'$set': {'summary_cache': result}})
            return jsonify(result)
        else:
            return jsonify({"summary": ["Failed to extract summary."], "insight": ""}), 500
            
    except Exception as e:
        print(f"AI SUMMARIZE ERROR: {e}", flush=True)
        return jsonify({"summary": ["An error occurred."], "insight": ""}), 500

@app.route('/ai/ask/<post_id>', methods=['POST'])
@csrf.exempt
def ai_ask(post_id):
    # This route is now a fallback for non-streaming clients or 
    # could be deprecated in favor of /api/chat/stream
    return jsonify({"error": "Please use the streaming endpoint /api/chat/stream/<post_id>"}), 400

@app.route('/api/chat/stream/<post_id>')
@limiter.limit("60 per hour")
def ai_chat_stream(post_id):
    question = request.args.get('question')
    if not question:
        return "data: [ERROR] Question required\n\n", 400
    
    obj_id = get_valid_object_id(post_id)
    if not obj_id:
        return "data: [ERROR] Invalid post ID\n\n", 400
        
    post = posts.find_one({'_id': obj_id})
    if not post:
        return "data: [ERROR] Post not found\n\n", 404
        
    if post.get('is_draft'):
        if not g.get('current_user') or 'user' not in session or session['user'] != post['author']:
            return "data: [ERROR] Unauthorized\n\n", 403

    soup = BeautifulSoup(post.get('content', ''), 'html.parser')
    clean_text = soup.get_text()

    from flask import Response
    return Response(ai_service.stream_answer(clean_text, question), mimetype='text/event-stream')

@app.route('/ai/research', methods=['POST'])
@limiter.limit("20 per hour")
@login_required
def ai_research():
    data = request.get_json() or {}
    topic = data.get('topic')
    draft = data.get('draft', '')
    
    if not topic:
        return {'error': 'Topic required'}, 400
    
    user_doc = g.get('current_user')
    user_id = user_doc['_id'] if user_doc else None
    username = session.get('user')
    
    job_id = str(uuid.uuid4())
    # TTL Index in MongoDB handles cleanup
    mongo.db.jobs.insert_one({
        'job_id': job_id,
        'user_id': user_id,
        'username': username,
        'status': 'pending',
        'created_at': datetime.now(timezone.utc)
    })

    def run_job(j_id, t, d):
        try:
            res = ai_service.research_topic(t, d)
            mongo.db.jobs.update_one({'job_id': j_id}, {
                '$set': {'status': 'completed', 'result': res}
            })
        except Exception as e:
            mongo.db.jobs.update_one({'job_id': j_id}, {
                '$set': {'status': 'failed', 'error': str(e)}
            })

    executor.submit(run_job, job_id, topic, draft)
    return jsonify({'job_id': job_id})

@app.route('/api/job/<job_id>')
@login_required
def get_job_status(job_id):
    user_doc = g.get('current_user')
    user_id = user_doc['_id'] if user_doc else None
    username = session.get('user')
    
    # Query with strict ownership verification
    job = mongo.db.jobs.find_one({'job_id': job_id})
    if not job:
        return jsonify({'error': 'Job not found'}), 404
        
    # Legacy jobs without owner metadata are rejected to prevent unauthorized exposure
    job_owner_id = job.get('user_id')
    job_username = job.get('username')
    
    is_owner = False
    if job_owner_id is not None and user_id is not None and job_owner_id == user_id:
        is_owner = True
    elif job_username is not None and username is not None and job_username == username:
        is_owner = True
        
    if not is_owner:
        return jsonify({'error': 'Forbidden', 'message': 'You do not have access to this job'}), 403
        
    return jsonify({
        'status': job['status'],
        'result': job.get('result'),
        'error': job.get('error')
    })

@app.route('/ai/improve-draft', methods=['POST'])
@limiter.limit("30 per hour")
def ai_improve_draft():
    if 'user' not in session:
        return {'error': 'Unauthorized'}, 401
    
    try:
        data = request.get_json()
        draft = data.get('draft')
        if not draft:
            return {'error': 'Draft is required'}, 400
            
        result = ai_service.improve_draft(draft)
        # Return original for diffing
        result['original'] = draft
        return jsonify(result)
    except Exception as e:
        print(f"AI IMPROVE ERROR: {e}", flush=True)
        return jsonify({'error': str(e)}), 500

@app.route('/post/<post_id>/edit', methods=['GET', 'POST'])
@limiter.limit("60 per hour", methods=["POST"])
@login_required
def edit_post(post_id):
    obj_id = get_valid_object_id(post_id)
    if not obj_id:
        abort(404)
        
    post = posts.find_one({'_id': obj_id})
    if not post:
        abort(404)
    if post['author'] != session['user']:
        abort(403)
        
    form = PostForm()
    if form.validate_on_submit():
        clean_content = sanitize_html(form.content.data)
        tags_list = [tag.strip() for tag in form.tags.data.split(',')] if form.tags.data else []
        
        is_draft = form.save_draft.data
        was_draft = post.get('is_draft', False)
        # Recompute read time on edit so the stored value stays accurate.
        read_time = get_reading_time(bleach.clean(clean_content, tags=[], strip=True))

        posts.update_one({'_id': ObjectId(post_id)}, {'$set': {
            'title': form.title.data,
            'subtitle': form.subtitle.data,
            'series_name': form.series_name.data,
            'intent': form.intent.data,
            'freshness': form.freshness.data,
            'why_wrote': form.why_wrote.data,
            'summary': form.summary.data,
            'content': clean_content,
            'read_time': read_time,
            'cover_url': form.cover_url.data,
            'tags': tags_list,
            'is_draft': is_draft,
            # Don't update created_at, maybe add updated_at
            'updated_at': datetime.now(timezone.utc)
        }, '$inc': {'revision_count': 1}})
        
        if was_draft and not is_draft:
             log_activity(session['user'], "published a new story", post_id, form.title.data)
             flash('Story published!', 'success')
        elif is_draft:
             flash('Draft saved.', 'info')
        else:
             flash('Story updated.', 'success')
             
        return redirect(url_for('view_post', post_id=post_id))
    
    elif request.method == 'GET':
        form.title.data = post.get('title')
        form.subtitle.data = post.get('subtitle')
        form.series_name.data = post.get('series_name')
        form.intent.data = post.get('intent', 'inform')
        form.freshness.data = post.get('freshness', 'current')
        form.why_wrote.data = post.get('why_wrote', '')
        form.summary.data = post.get('summary', '')
        form.cover_url.data = post.get('cover_url')
        form.content.data = post.get('content')
        form.tags.data = ", ".join(post.get('tags', []))
        
    return render_template('post_form.html', form=form, legend="Edit Story")

@app.route('/post/<post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    obj_id = get_valid_object_id(post_id)
    if not obj_id:
        abort(404)
        
    post = posts.find_one({'_id': obj_id})
    if not post:
        abort(404)
        
    if post['author'] != session['user']:
        abort(403)
        
    posts.delete_one({'_id': obj_id})
    comments.delete_many({'post_id': obj_id})
    flash('Story deleted.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/post/<post_id>/react/<reaction_type>', methods=['POST'])
@limiter.limit("60 per minute")
@login_required
def react_post(post_id, reaction_type):
    obj_id = get_valid_object_id(post_id)
    if not obj_id:
        abort(404)
        
    allowed_reactions = ['like', 'love', 'insightful', 'funny']
    if reaction_type not in allowed_reactions:
        flash('Invalid reaction.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))

    post = posts.find_one({'_id': ObjectId(post_id)})
    if post:
        # Structure: reactions = { 'username': 'type', ... }
        current_reactions = post.get('reactions', {})
        
        # Toggle logic: if clicking same reaction, remove it. If different, update it.
        if session['user'] in current_reactions and current_reactions[session['user']] == reaction_type:
            del current_reactions[session['user']]
        else:
            current_reactions[session['user']] = reaction_type
            log_activity(session['user'], f"reacted with {reaction_type} to", post_id, post['title'])
            
        posts.update_one({'_id': ObjectId(post_id)}, {'$set': {'reactions': current_reactions}})
            
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/comment/<comment_id>/pin', methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def pin_comment(comment_id):
    c_obj_id = get_valid_object_id(comment_id)
    if not c_obj_id:
        abort(404)
        
    comment = comments.find_one({'_id': c_obj_id})
    if not comment:
        abort(404)
        
    post = posts.find_one({'_id': comment['post_id']})
    if not post:
        abort(404)
        
    if post['author'] != session['user']:
        abort(403) # Only post author can pin
        
    new_state = not comment.get('is_pinned', False)
    comments.update_one({'_id': c_obj_id}, {'$set': {'is_pinned': new_state}})
    
    return redirect(url_for('view_post', post_id=post['_id']))

@app.route('/dashboard')
@login_required
def dashboard():
        
    section = request.args.get('section', 'stories')
    
    # Draft Nudge Logic
    draft_count = posts.count_documents({'author': session['user'], 'is_draft': True})
    
    if section == 'saved':
        user = users.find_one({'username': session['user']})
        saved_ids = user.get('bookmarks', [])
        # Fetch posts that are in the saved list
        user_posts = list(posts.find({'_id': {'$in': [ObjectId(bid) for bid in saved_ids]}}).sort("created_at", -1))
    elif section == 'drafts':
        user_posts = list(posts.find({'author': session['user'], 'is_draft': True}).sort("updated_at", -1))
    else:
        # Default: Published stories
        user_posts = list(posts.find({'author': session['user'], 'is_draft': {'$ne': True}}).sort("created_at", -1))
        
    return render_template('dashboard.html', posts=user_posts, section=section, draft_count=draft_count)

@app.route('/profile/<username>')
def profile(username):
    user = users.find_one({'username': username})
    if not user:
        abort(404)
        
    user_posts_cursor = posts.find({'author': username, 'is_draft': {'$ne': True}}).sort("created_at", -1)
    user_posts = list(user_posts_cursor)
    
    # Calculate stats
    total_likes = sum(len([r for r in p.get('reactions', {}).values() if r == 'like']) for p in user_posts)
    total_stories = len(user_posts)
    
    for post in user_posts:
        post['read_time'] = get_post_read_time(post)
    
    # Fetch recent activities
    user_activities = list(activities.find({'user': username}).sort("timestamp", -1).limit(10))
    
    return render_template('profile.html', user=user, posts=user_posts, activities=user_activities, total_likes=total_likes, total_stories=total_stories)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings_hub.html')

@app.route('/settings/profile', methods=['GET', 'POST'])
@login_required
def settings_profile():
    user = g.get('current_user') or users.find_one({'username': session['user']})
    form = SettingsProfileForm()
    
    if form.validate_on_submit():
        # Whitelisted fields only - prevents mass assignment / privilege escalation
        users.update_one({'username': session['user']}, {'$set': {
            'bio': form.bio.data,
            'avatar_url': form.avatar_url.data
        }})
        flash('Profile updated.', 'success')
        return redirect(url_for('profile', username=session['user']))
    
    elif request.method == 'GET':
        form.bio.data = user.get('bio', '')
        form.avatar_url.data = user.get('avatar_url', '')
        
    return render_template('settings_profile.html', form=form, user=user)

@app.route('/settings/account', methods=['GET', 'POST'])
@login_required
def settings_account():
    user = g.get('current_user') or users.find_one({'username': session['user']})
    form = SettingsAccountForm()
    
    if form.validate_on_submit():
        users.update_one({'username': session['user']}, {'$set': {
            'email': form.email.data
        }})
        flash('Account settings updated.', 'success')
        return redirect(url_for('settings'))
    
    elif request.method == 'GET':
        form.email.data = user.get('email', '')
        
    return render_template('settings_account.html', form=form)

@app.route('/api/bookmark/<post_id>', methods=['POST'])
@limiter.limit("10 per minute")
@login_required
def toggle_bookmark(post_id):
    obj_id = get_valid_object_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid post ID'}), 400
        
    user = g.get('current_user') or users.find_one({'username': session['user']})
    bookmarks = user.get('bookmarks', [])
    
    if post_id in bookmarks:
        users.update_one({'username': session['user']}, {'$pull': {'bookmarks': post_id}})
        return jsonify({'status': 'removed'})
    else:
        users.update_one({'username': session['user']}, {'$addToSet': {'bookmarks': post_id}})
        return jsonify({'status': 'added'})

@app.route('/reading-list')
@login_required
def reading_list():
    user = g.get('current_user') or users.find_one({'username': session['user']})
    bookmark_ids = user.get('bookmarks', [])
    
    bookmarked_posts = []
    if bookmark_ids:
        obj_ids = [get_valid_object_id(bid) for bid in bookmark_ids if get_valid_object_id(bid)]
        bookmarked_posts = list(posts.find({'_id': {'$in': obj_ids}, 'is_draft': {'$ne': True}}))
        
        for post in bookmarked_posts:
            post['read_time'] = get_post_read_time(post)
            
    return render_template('reading_list.html', posts=bookmarked_posts)

if __name__ == '__main__':
    app.run(debug=True)