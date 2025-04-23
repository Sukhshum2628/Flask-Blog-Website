from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from wtforms import ValidationError

app = Flask(__name__)
app.secret_key = "e47513b236d74f8f9dd1a7293fbb16ce"

app.config["MONGO_URI"] = "mongodb://localhost:27017/blogDB"
mongo = PyMongo(app)
users = mongo.db.users
posts = mongo.db.posts

# Index creation (one-time or on startup)
users.create_index("username", unique=True)
posts.create_index("author")

# Flask-WTF Forms 
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])

# Routes 
@app.route('/')
def index():
    all_posts = posts.find()
    return render_template('index.html', posts=all_posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = users.find_one({'username': form.username.data})
        if existing_user:
            flash('Username already exists. Try a different one.', 'danger')
            return redirect('/register')
        hash_pwd = generate_password_hash(form.password.data)
        users.insert_one({'username': form.username.data, 'password': hash_pwd})
        flash('Registration successful. Please log in.', 'success')
        return redirect('/login')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = users.find_one({'username': form.username.data})
        if user and check_password_hash(user['password'], form.password.data):
            session['user'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect('/dashboard')
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'info')
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('You must be logged in to view the dashboard.', 'warning')
        return redirect('/login')
    user_posts = posts.find({'author': session['user']})
    return render_template('dashboard.html', posts=user_posts)

@app.route('/post', methods=['GET', 'POST'])
def post():
    if 'user' not in session:
        flash('Login to create a post.', 'warning')
        return redirect('/login')
    form = PostForm()
    if form.validate_on_submit():
        posts.insert_one({
            'title': form.title.data,
            'content': form.content.data,
            'author': session['user']
        })
        flash('Post created successfully.', 'success')
        return redirect('/dashboard')
    return render_template('post_form.html', form=form)

@app.route('/delete/<post_id>')
def delete_post(post_id):
    if 'user' not in session:
        flash('Login to delete posts.', 'warning')
        return redirect('/login')
    post = posts.find_one({'_id': ObjectId(post_id)})
    if post and post['author'] == session['user']:
        posts.delete_one({'_id': ObjectId(post_id)})
        flash('Post deleted successfully.', 'success')
    else:
        flash('Unauthorized action or post not found.', 'danger')
    return redirect('/dashboard')

if __name__ == '__main__':
    app.run(debug=True)
