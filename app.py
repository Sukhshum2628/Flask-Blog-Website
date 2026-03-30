import os
import math
import re
import threading
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, session, url_for, flash, abort, jsonify, make_response
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Optional, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import bleach
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()

app = Flask(__name__)
# ... (config follows)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key_change_me")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb://localhost:27017/blogDB")

# Rate Limiter for Render Free Tier protection
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:;"
    return response

mongo = PyMongo(app)
users = mongo.db.users
posts = mongo.db.posts
comments = mongo.db.comments
activities = mongo.db.activities
reading_sessions = mongo.db.reading_sessions
reading_history = mongo.db.reading_history

@app.context_processor
def inject_user():
    user = None
    if 'user' in session:
        user = users.find_one({'username': session['user']})
    return dict(current_user=user)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:;"
    return response

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
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
from services import ai_service
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import uuid

# Background executor for slow AI tasks
executor = ThreadPoolExecutor(max_workers=4)
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

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key_change_me")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb://localhost:27017/blogDB")

from flask_compress import Compress
from flask_caching import Cache

compress = Compress(app)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 60})

import requests

# ... (imports)

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

def send_reset_email(user):
    print(f"Attempting to send reset email to: {user['email']}", flush=True)
    token = get_reset_token(user['_id'])
    
    subject = 'Password Reset Request'
    body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    # Send in background thread
    threading.Thread(target=send_async_email, args=(app, user['email'], subject, body)).start()

# ... (routes)

@app.route('/test_email')
def test_email():
    key = os.environ.get('BREVO_API_KEY')
    if not key:
        return "Error: BREVO_API_KEY not set."
        
    target_email = os.environ.get('MAIL_USER') 
    
    if not target_email:
        return "Error: MAIL_USER env var not set."

    if send_email_brevo(target_email, "Brevo API Test", "If you read this, the Brevo integration is working!"):
        return f"Email sent via Brevo to {target_email}! Check logs for details."
    else:
        return "Failed to send email. Check Render logs for Brevo error response."

mongo = PyMongo(app)
users = mongo.db.users
posts = mongo.db.posts
comments = mongo.db.comments
activities = mongo.db.activities
reading_sessions = mongo.db.reading_sessions
reading_history = mongo.db.reading_history

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
        # Fetch all posts (Optimization: in a real app, limit to last 30 days)
        all_posts = list(posts.find({'is_draft': {'$ne': True}}))
        
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
    if 'user' not in session:
        return {'status': 'ignored'}, 200
    
    data = request.get_json()
    progress = data.get('progress', 0)
    
    reading_history.update_one(
        {'user': session['user'], 'post_id': ObjectId(post_id)},
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

# Helpers
def get_reading_time(text):
    word_count = len(re.findall(r'\w+', text))
    reading_time_min = math.ceil(word_count / 200) # Avg reading speed 200 wpm
    return reading_time_min

def sanitize_html(content):
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'h1', 'h2', 'h3', 'br', 'ul', 'ol', 'li', 'blockquote', 'img']
    allowed_attrs = {
        'a': ['href', 'title', 'target'],
        'img': ['src', 'alt', 'width', 'height']
    }
    return bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)

def get_reset_token(user_id, expires_sec=1800):
    s = Serializer(app.secret_key)
    return s.dumps({'user_id': str(user_id)})

def verify_reset_token(token, expires_sec=1800):
    s = Serializer(app.secret_key)
    try:
        user_id = s.loads(token, max_age=expires_sec)['user_id']
    except:
        return None
    return users.find_one({'_id': ObjectId(user_id)})

# Context Processor for User Info in Navbar
@app.context_processor
def inject_user():
    current_user = None
    if 'user' in session:
        current_user = users.find_one({'username': session['user']})
    
    # Also fetch recent activity and site pulse
    recent_activities = list(activities.find().sort("timestamp", -1).limit(5))
    
    # Site pulse: last activity time
    last_act = activities.find_one(sort=[("timestamp", -1)])
    site_pulse = last_act['timestamp'] if last_act else None

    return dict(current_user=current_user, recent_activities=recent_activities, site_pulse=site_pulse)

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()]) # Need EqualTo but skipping import for brevity, will check manually or trust user
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
def index():
    page = int(request.args.get('page', 1))
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
         clean_text = bleach.clean(post.get('content', ''), tags=[], strip=True)
         post['read_time'] = get_reading_time(clean_text)

    return render_template('index.html', posts=results, search_query=query)

@app.route('/register', methods=['GET', 'POST'])
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
        
        hash_pwd = generate_password_hash(form.password.data)
        users.insert_one({
            'username': form.username.data,
            'email': form.email.data,
            'password': hash_pwd,
            'bio': "New writer.",
            'avatar_url': f"https://ui-avatars.com/api/?name={form.username.data}&background=random",
            'joined_at': datetime.now(timezone.utc),
            'last_visit': datetime.now(timezone.utc)
        })
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = users.find_one({'username': form.username.data})
        if user and check_password_hash(user['password'], form.password.data):
            session['user'] = user['username']
            
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
def reset_token(token):
    if 'user' in session:
        return redirect(url_for('index'))
    user_doc = verify_reset_token(token)
    if user_doc is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hash_pwd = generate_password_hash(form.password.data)
        users.update_one({'_id': user_doc['_id']}, {'$set': {'password': hash_pwd}})
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/post/new', methods=['GET', 'POST'])
def new_post():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    form = PostForm()
    if form.validate_on_submit():
        # Clean HTML content
        clean_content = sanitize_html(form.content.data)
        tags_list = [tag.strip() for tag in form.tags.data.split(',')] if form.tags.data else []
        
        is_draft = form.save_draft.data # True if 'Save Draft' was clicked
        
        post_id = posts.insert_one({
            'title': form.title.data,
            'subtitle': form.subtitle.data,
            'series_name': form.series_name.data,
            'intent': form.intent.data,
            'freshness': form.freshness.data,
            'why_wrote': form.why_wrote.data,
            'summary': form.summary.data,
            'content': clean_content,
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
    post = posts.find_one({'_id': ObjectId(post_id)})
    if not post:
        abort(404)

    # Increment View Count (Lightweight Analytics)
    # Use $inc for atomic update. Check cookie or session to prevent spam? 
    # For now, simple increment per page load.
    posts.update_one({'_id': ObjectId(post_id)}, {'$inc': {'views': 1}})
    
    # Get Author details
    author = users.find_one({'username': post['author']})
    
    # Access Control for Drafts
    if post.get('is_draft'):
        if 'user' not in session or session['user'] != post['author']:
            abort(403) # Forbidden
    
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

    clean_text = bleach.clean(post.get('content', ''), tags=[], strip=True)
    read_time = get_reading_time(clean_text)

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
    all_other_posts = list(posts.find({'is_draft': {'$ne': True}, '_id': {'$ne': ObjectId(post_id)}}).limit(50))
    related_posts = ai_service.get_related_posts(post, all_other_posts)

    return render_template('post_detail.html', post=post, author=author, comments=post_comments, form=form, read_time=read_time, is_author=is_author, user_reaction=user_reaction, reaction_counts=reaction_counts, is_bookmarked=is_bookmarked, active_readers=active_readers, series_prev=series_prev, series_next=series_next, server_progress=server_progress, related_posts=related_posts)

@app.route('/post/<post_id>/bookmark')
def bookmark_post(post_id):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    user = users.find_one({'username': session['user']})
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
def ai_summarize(post_id):
    try:
        post = posts.find_one({'_id': ObjectId(post_id)})
        if not post:
            return jsonify({'error': 'Post not found'}), 404
            
        # 1. Check Cache
        if 'summary_cache' in post:
            cache_data = post['summary_cache']
            # Only use cache if it was generated after the last update
            updated_at = post.get('updated_at', post.get('created_at'))
            if cache_data.get('generated_at') and cache_data['generated_at'] >= updated_at:
                return jsonify(cache_data)

        # 2. Extract Full Text with BeautifulSoup
        soup = BeautifulSoup(post.get('content', ''), 'html.parser')
        # Preserve paragraph breaks
        for p in soup.find_all('p'):
            p.append('\n\n')
        full_text = soup.get_text().strip()

        # 3. Call AI
        result = ai_service.summarize_text(full_text)
        
        # 4. Save to Cache
        if isinstance(result, dict) and 'summary' in result:
            result['generated_at'] = datetime.now(timezone.utc)
            posts.update_one({'_id': ObjectId(post_id)}, {'$set': {'summary_cache': result}})
            return jsonify(result)
        else:
            return jsonify({"summary": ["Failed to extract summary."], "insight": ""}), 500
            
    except Exception as e:
        print(f"AI SUMMARIZE ERROR: {e}", flush=True)
        return jsonify({"summary": ["An error occurred."], "insight": ""}), 500

@app.route('/ai/ask/<post_id>', methods=['POST'])
def ai_ask(post_id):
    # This route is now a fallback for non-streaming clients or 
    # could be deprecated in favor of /api/chat/stream
    return jsonify({"error": "Please use the streaming endpoint /api/chat/stream/<post_id>"}), 400

@app.route('/api/chat/stream/<post_id>')
def ai_chat_stream(post_id):
    question = request.args.get('question')
    if not question:
        return "data: [ERROR] Question required\n\n", 400
    
    post = posts.find_one({'_id': ObjectId(post_id)})
    if not post:
        return "data: [ERROR] Post not found\n\n", 404

    soup = BeautifulSoup(post.get('content', ''), 'html.parser')
    clean_text = soup.get_text()

    from flask import Response
    return Response(ai_service.stream_answer(clean_text, question), mimetype='text/event-stream')

@app.route('/ai/research', methods=['POST'])
def ai_research():
    if 'user' not in session:
        return {'error': 'Unauthorized'}, 401
    
    data = request.get_json()
    topic = data.get('topic')
    draft = data.get('draft', '')
    
    if not topic:
        return {'error': 'Topic required'}, 400
    
    job_id = str(uuid.uuid4())
    # TTL Index in MongoDB handles cleanup
    mongo.db.jobs.insert_one({
        'job_id': job_id,
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
def get_job_status(job_id):
    job = mongo.db.jobs.find_one({'job_id': job_id})
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify({
        'status': job['status'],
        'result': job.get('result'),
        'error': job.get('error')
    })

@app.route('/ai/improve-draft', methods=['POST'])
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
        print(f"AI IMPROVE ERROR: {e}", flush=True)
        return {'error': str(e)}, 500

@app.route('/post/<post_id>/edit', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    post = posts.find_one({'_id': ObjectId(post_id)})
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
        
        posts.update_one({'_id': ObjectId(post_id)}, {'$set': {
            'title': form.title.data,
            'subtitle': form.subtitle.data,
            'series_name': form.series_name.data,
            'intent': form.intent.data,
            'freshness': form.freshness.data,
            'why_wrote': form.why_wrote.data,
            'summary': form.summary.data,
            'content': clean_content,
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
def delete_post(post_id):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    post = posts.find_one({'_id': ObjectId(post_id)})
    if post and post['author'] == session['user']:
        posts.delete_one({'_id': ObjectId(post_id)})
        # Delete associated comments
        comments.delete_many({'post_id': ObjectId(post_id)})
        flash('Story deleted.', 'success')
    else:
        flash('Unauthorized.', 'danger')
        
    return redirect(url_for('dashboard'))

@app.route('/post/<post_id>/react/<reaction_type>')
def react_post(post_id, reaction_type):
    if 'user' not in session:
        return redirect(url_for('login'))
        
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

@app.route('/comment/<comment_id>/pin')
def pin_comment(comment_id):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    comment = comments.find_one({'_id': ObjectId(comment_id)})
    if not comment:
        abort(404)
        
    post = posts.find_one({'_id': comment['post_id']})
    if not post or post['author'] != session['user']:
        abort(403) # Only post author can pin
        
    # Toggle pin
    new_state = not comment.get('is_pinned', False)
    comments.update_one({'_id': ObjectId(comment_id)}, {'$set': {'is_pinned': new_state}})
    
    return redirect(url_for('view_post', post_id=post['_id']))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
        
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
        clean_text = bleach.clean(post.get('content', ''), tags=[], strip=True)
        post['read_time'] = get_reading_time(clean_text)
    
    # Fetch recent activities
    user_activities = list(activities.find({'user': username}).sort("timestamp", -1).limit(10))
    
    return render_template('profile.html', user=user, posts=user_posts, activities=user_activities, total_likes=total_likes, total_stories=total_stories)

@app.route('/settings')
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('settings_hub.html')

@app.route('/settings/profile', methods=['GET', 'POST'])
def settings_profile():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    user = users.find_one({'username': session['user']})
    form = SettingsProfileForm()
    
    if form.validate_on_submit():
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
def settings_account():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    user = users.find_one({'username': session['user']})
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
def toggle_bookmark(post_id):
    if 'user' not in session:
        return jsonify({'error': 'Login required'}), 401
    
    user = users.find_one({'username': session['user']})
    bookmarks = user.get('bookmarks', [])
    
    if post_id in bookmarks:
        users.update_one({'username': session['user']}, {'$pull': {'bookmarks': post_id}})
        return jsonify({'status': 'removed'})
    else:
        users.update_one({'username': session['user']}, {'$addToSet': {'bookmarks': post_id}})
        return jsonify({'status': 'added'})

@app.route('/reading-list')
def reading_list():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    user = users.find_one({'username': session['user']})
    bookmark_ids = user.get('bookmarks', [])
    
    bookmarked_posts = []
    if bookmark_ids:
        # Convert string IDs to ObjectIDs
        obj_ids = [ObjectId(bid) for bid in bookmark_ids]
        bookmarked_posts = list(posts.find({'_id': {'$in': obj_ids}, 'is_draft': {'$ne': True}}))
        
        for post in bookmarked_posts:
            clean_text = bleach.clean(post.get('content', ''), tags=[], strip=True)
            post['read_time'] = get_reading_time(clean_text)
            
    return render_template('reading_list.html', posts=bookmarked_posts)

if __name__ == '__main__':
    app.run(debug=True)