import sqlite3
import os
from datetime import datetime, timedelta, timezone
import random
import string
import json
import uuid # Import uuid for generating unique IDs
import base64 # Needed for base64 decoding camera/voice note data
import re # Needed for process_mentions_and_links

# Removed: import google.generativeai as genai
import firebase_admin
from firebase_admin import credentials, firestore, initialize_app # initialize_app is needed if credentials path exists

from flask import Flask, render_template, Blueprint, request, redirect, url_for, g, flash, session, abort, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash # Corrected: Removed extra 'werk'
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_moment import Moment
from functools import wraps # For admin_required decorator

import config # Your configuration file

app = Flask(__name__)

# Use environment variable for SECRET_KEY or fall back to config.py
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', config.SECRET_KEY)

# Database path
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'family_tree.db')

# Upload folders configuration
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads') # General upload folder
app.config['PROFILE_PHOTOS_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_photos')
app.config['POSTS_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'posts')
app.config['REEL_MEDIA_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'reel_media')
app.config['STORY_MEDIA_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'story_media')
app.config['VOICE_NOTES_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'voice_notes')
app.config['CHAT_MEDIA_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'chat_media')
app.config['CHAT_BACKGROUND_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'chat_backgrounds')

# Ensure upload directories exist
for folder in [
    app.config['PROFILE_PHOTOS_FOLDER'],
    app.config['POSTS_FOLDER'],
    app.config['REEL_MEDIA_FOLDER'],
    app.config['STORY_MEDIA_FOLDER'],
    app.config['VOICE_NOTES_FOLDER'],
    app.config['CHAT_MEDIA_FOLDER'],
    app.config['CHAT_BACKGROUND_FOLDER']
]:
    os.makedirs(folder, exist_ok=True)


# Allowed extensions for uploads
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv'}
ALLOWED_AUDIO_EXTENSIONS = {'mp3', 'wav', 'ogg'}

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login page if user is not authenticated

# Initialize Flask-Moment for date/time formatting
moment = Moment(app) # Use Moment object

# --- Firebase Admin SDK Initialization ---
# Only initialize if firebase_admin_key.json exists and is valid.
# No active Firestore/Storage operations are implemented in user-facing routes as per user's request.
db_firestore = None # Initialize to None by default
if config.FIREBASE_ADMIN_CREDENTIALS_PATH and os.path.exists(config.FIREBASE_ADMIN_CREDENTIALS_PATH):
    try:
        # Check if Firebase app is already initialized to prevent re-initialization
        if not firebase_admin._apps:
            cred = credentials.Certificate(config.FIREBASE_ADMIN_CREDENTIALS_PATH)
            firebase_admin.initialize_app(cred, {
                'projectId': config.FIREBASE_CLIENT_CONFIG['projectId'],
                'storageBucket': config.FIREBASE_CLIENT_CONFIG['storageBucket']
            })
            # db_firestore = firestore.client() # Firestore client not actively used for data ops
            app.logger.info("Firebase Admin SDK initialized successfully.")
        else:
            app.logger.info("Firebase Admin SDK already initialized.")
    except Exception as e:
        app.logger.error(f"Failed to initialize Firebase Admin SDK: {e}")
else:
    app.logger.warning("Firebase Admin SDK credentials file not found or path not configured. Firebase Admin SDK not initialized.")

# Removed: Gemini API Setup (as per user's explicit request to ignore AI)


# --- Database Helper Functions ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row # Return rows as dict-like objects
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- Helper Function for Unique Keys ---
def generate_unique_key():
    """Generates a 4-character unique key (2 letters, 2 numbers)."""
    letters = random.choices(string.ascii_uppercase, k=2)
    numbers = random.choices(string.digits, k=2)
    key_chars = letters + numbers
    random.shuffle(key_chars)
    return "".join(key_chars)


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.executescript(f.read())
        
        # --- Create Admin User if not exists ---
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (config.ADMIN_USERNAME,))
        admin_exists = cursor.fetchone()

        if not admin_exists:
            # Generate a unique key for the admin
            admin_unique_key = generate_unique_key() # Reusing the helper for consistency
            
            # Hash the admin password from config.py
            hashed_admin_password = generate_password_hash(config.ADMIN_PASSWORD_RAW) # Corrected to config.ADMIN_PASSWORD_RAW

            cursor.execute(
                """
                INSERT INTO users (username, originalName, password_hash, unique_key, is_admin)
                VALUES (?, ?, ?, ?, ?)
                """,
                (config.ADMIN_USERNAME, "SociaFam Admin", hashed_admin_password, admin_unique_key, 1) # is_admin = 1
            )
            admin_user_id = cursor.lastrowid
            
            # Also create a member profile for the admin
            db.execute(
                """
                INSERT INTO members (user_id, fullName, gender)
                VALUES (?, ?, ?)
                """,
                (admin_user_id, "SociaFam Admin", "Prefer not to say") # Default gender for admin
            )
            app.logger.info(f"Admin user '{config.ADMIN_USERNAME}' created with unique key '{admin_unique_key}'.")
        else:
            app.logger.info(f"Admin user '{config.ADMIN_USERNAME}' already exists.")

        db.commit() # Commit all changes after script and admin creation
    app.logger.info("Database initialized/updated from schema.sql.")

# Register close_db with the app context
app.teardown_appcontext(close_db)

# Run init_db once when the app starts if tables don't exist
with app.app_context():
    db = get_db()
    cursor = db.cursor()
    # Check for a critical table like 'users'
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    if not cursor.fetchone():
        init_db()
    else: # If tables exist, still ensure admin is present, useful for existing databases
        # This handles cases where a database exists but the admin user might have been manually deleted
        # or wasn't created in previous versions.
        cursor.execute("SELECT id FROM users WHERE username = ?", (config.ADMIN_USERNAME,))
        if not cursor.fetchone():
            init_db() # Call init_db to create admin even if tables exist
    db.close()


# --- User Model for Flask-Login ---
class User(UserMixin):
    def __init__(self, id, username, password_hash, is_admin=0, theme_preference='light', chat_background_image_path=None, unique_key=None, password_reset_pending=0, reset_request_timestamp=None, last_login_at=None, last_seen_at=None, original_name=None, email=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = bool(is_admin) # Convert to boolean
        self.theme_preference = theme_preference
        self.chat_background_image_path = chat_background_image_path
        self.unique_key = unique_key
        self.password_reset_pending = bool(password_reset_pending)
        self.reset_request_timestamp = reset_request_timestamp
        self.last_login_at = last_login_at
        self.last_seen_at = last_seen_at
        self.original_name = original_name
        self.email = email # Allow email to be stored for login

    def get_id(self):
        return str(self.id)

    def get_member_profile(self):
        db = get_db()
        member_profile = db.execute('SELECT * FROM members WHERE user_id = ?', (self.id,)).fetchone()
        return member_profile

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_data = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user_data:
        # Fetch member details to get email if available
        member_data = db.execute('SELECT email FROM members WHERE user_id = ?', (user_id,)).fetchone()
        email = member_data['email'] if member_data else None
        return User(
            id=user_data['id'],
            username=user_data['username'],
            password_hash=user_data['password_hash'],
            is_admin=user_data['is_admin'],
            theme_preference=user_data['theme_preference'],
            chat_background_image_path=user_data['chat_background_image_path'],
            unique_key=user_data['unique_key'],
            password_reset_pending=user_data['password_reset_pending'],
            reset_request_timestamp=user_data['reset_request_timestamp'],
            last_login_at=user_data['last_login_at'],
            last_seen_at=user_data['last_seen_at'],
            original_name=user_data['originalName'],
            email=email
        )
    return None

# --- Decorator for Admin-Only Access ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have administrative privileges to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions for File Uploads ---
def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_uploaded_file(file, upload_folder):
    if file and allowed_file(file.filename, ALLOWED_IMAGE_EXTENSIONS.union(ALLOWED_VIDEO_EXTENSIONS).union(ALLOWED_AUDIO_EXTENSIONS)):
        filename = secure_filename(file.filename)
        unique_filename = str(uuid.uuid4()) + '_' + filename
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        # Store relative path for database, correctly structured
        relative_path = os.path.join('static', 'uploads', os.path.basename(upload_folder), unique_filename)
        return relative_path.replace("\\", "/") # Ensure forward slashes for URLs
    return None


def get_member_profile_pic(user_id):
    db = get_db()
    member = db.execute("SELECT profilePhoto FROM members WHERE user_id = ?", (user_id,)).fetchone()
    if member and member['profilePhoto']:
        # Ensure the path is relative to 'static/' as expected by url_for
        # The stored path should already be like 'static/uploads/profile_photos/...'
        if member['profilePhoto'].startswith('static/'):
            # Only take the part after 'static/' for url_for's filename
            return url_for('static', filename=member['profilePhoto'][len('static/'):])
        # Fallback if path doesn't start with static/, though it should if saved by save_uploaded_file
        return url_for('static', filename=member['profilePhoto'])
    return url_for('static', filename='img/default_profile.png')

def get_member_from_user_id(user_id):
    db = get_db()
    member = db.execute('SELECT * FROM members WHERE user_id = ?', (user_id,)).fetchone()
    return member

def get_user_from_member_id(member_id):
    db = get_db()
    user_id_row = db.execute('SELECT user_id FROM members WHERE id = ?', (member_id,)).fetchone()
    if user_id_row:
        return load_user(user_id_row['user_id'])
    return None

def process_mentions_and_links(text):
    """
    Processes text to:
    1. Replace @username with clickable links to user profiles.
    2. Convert URLs to clickable links.
    """
    db = get_db()
    
    # 1. Process mentions
    # Find all mentions like @username
    def replace_mention(match):
        username = match.group(1)
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            return f'<a href="{url_for("profile", username=username)}">@{username}</a>'
        return match.group(0) # If username not found, keep original text
    
    processed_text = re.sub(r'@([a-zA-Z0-9_]+)', replace_mention, text)

    # 2. Process URLs
    # Regular expression to find URLs
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    def replace_url(match):
        url = match.group(0)
        # Prepend http:// if missing (for www. links)
        if not url.startswith('http'):
            url = 'http://' + url
        return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a>'
    
    processed_text = re.sub(url_pattern, replace_url, processed_text)
    
    return processed_text

# Add these helper functions to app.py (place them after other helpers like process_mentions_and_links)

def get_relationship_status(current_id, other_id):
    db = get_db()
    friendship = db.execute(
        """
        SELECT status, user1_id FROM friendships
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        """,
        (current_id, other_id, other_id, current_id)
    ).fetchone()
    if friendship:
        if friendship['status'] == 'accepted':
            return 'friend'
        elif friendship['status'] == 'pending':
            if friendship['user1_id'] == current_id:
                return 'pending_sent'
            else:
                return 'pending_received'
        else:
            return 'none'  # Treat declined as none for UI purposes
    return 'none'

def is_blocked(blocker_id, blocked_id):
    db = get_db()
    blocked = db.execute(
        "SELECT id FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
        (blocker_id, blocked_id)
    ).fetchone()
    return bool(blocked)

def get_mutual_friends_count(user1_id, user2_id):
    db = get_db()
    query = """
        SELECT COUNT(*) FROM (
            SELECT CASE WHEN user1_id = ? THEN user2_id ELSE user1_id END AS friend_id
            FROM friendships WHERE (user1_id = ? OR user2_id = ?) AND status = 'accepted'
            INTERSECT
            SELECT CASE WHEN user1_id = ? THEN user2_id ELSE user1_id END AS friend_id
            FROM friendships WHERE (user1_id = ? OR user2_id = ?) AND status = 'accepted'
        )
    """
    count = db.execute(query, (user1_id, user1_id, user1_id, user2_id, user2_id, user2_id)).fetchone()[0]
    return count

# --- Global Context Processor for Navbar Icons ---
@app.context_processor
def inject_navbar_data():
    if current_user.is_authenticated:
        # Determine if current user has a member profile (for profile photo in navbar)
        profile_photo_path = get_member_profile_pic(current_user.id)

        # Check for unread notifications
        db = get_db()
        unread_notifications = db.execute(
            "SELECT COUNT(*) FROM notifications WHERE receiver_id = ? AND is_read = 0",
            (current_user.id,)
        ).fetchone()[0]

        # Check for unread messages (assuming chat_room_members has unread status)
        unread_messages_count = db.execute(
            """
            SELECT COUNT(DISTINCT crm.chat_room_id)
            FROM chat_room_members crm
            JOIN chat_messages cm ON crm.chat_room_id = cm.chat_room_id
            WHERE crm.user_id = ? AND cm.sender_id != ? AND cm.timestamp > crm.last_read_message_timestamp
            """,
            (current_user.id, current_user.id)
        ).fetchone()[0]

        return {
            'navbar_profile_photo': profile_photo_path,
            'has_unread_notifications': unread_notifications > 0,
            'has_unread_messages': unread_messages_count > 0,
            'is_admin_user': current_user.is_admin
        }
    return {
        'navbar_profile_photo': url_for('static', filename='img/default_profile.png'),
        'has_unread_notifications': False,
        'has_unread_messages': False,
        'is_admin_user': False
    }


# --- System Notification & Messaging Functions ---
def send_system_notification(receiver_id, message, link=None, type='system_message'):
    db = get_db()
    try:
        db.execute(
            "INSERT INTO notifications (receiver_id, type, message, timestamp, link, is_read) VALUES (?, ?, ?, ?, ?, ?)",
            (receiver_id, type, message, datetime.now(timezone.utc), link, 0)
        )
        db.commit()
        app.logger.info(f"System notification sent to user {receiver_id}: {message}")
    except Exception as e:
        app.logger.error(f"Error sending system notification to {receiver_id}: {e}")

def get_admin_user_id():
    db = get_db()
    admin_user = db.execute("SELECT id FROM users WHERE username = ?", (config.ADMIN_USERNAME,)).fetchone()
    if admin_user:
        return admin_user['id']
    return None

# --- ROUTES ---

@app.route('/')
@app.route('/home')
@login_required
def home():
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    # Removed dummy post data here as it will be fetched by AJAX
    return render_template('index.html', current_year=current_year)


# --- API Route to Get Posts ---
@app.route('/api/get_posts')
@login_required
def api_get_posts():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    offset = (page - 1) * per_page

    posts_query = """
        SELECT
            p.id,
            p.user_id,
            p.description,
            p.media_path,
            p.media_type,
            p.timestamp,
            p.likes_count,
            p.comments_count,
            u.username,
            u.originalName,
            m.profilePhoto AS author_profile_pic
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE (
            p.visibility = 'public'
            OR
            (p.visibility = 'friends' AND EXISTS (
                SELECT 1 FROM friendships
                WHERE ((user1_id = ? AND user2_id = p.user_id) OR (user1_id = p.user_id AND user2_id = ?))
                AND status = 'accepted'
            ))
            OR
            (p.visibility = 'private' AND p.user_id = ?)
        )
        ORDER BY p.timestamp DESC
        LIMIT ? OFFSET ?
    """
    
    # Execute the query to get posts for the current page
    posts_data = db.execute(posts_query, (current_user.id, current_user.id, current_user.id, per_page, offset)).fetchall()

    posts_list = []
    for post in posts_data:
        post_dict = dict(post)
        post_dict['profile_pic'] = get_member_profile_pic(post_dict['user_id'])
        # Ensure timestamp is ISO format for moment.js
        if post_dict['timestamp']:
            post_dict['timestamp'] = datetime.fromisoformat(post_dict['timestamp']).isoformat()
        posts_list.append(post_dict)

    # Check if there are more posts for the next page
    has_more_query = """
        SELECT COUNT(*)
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE (
            p.visibility = 'public'
            OR
            (p.visibility = 'friends' AND EXISTS (
                SELECT 1 FROM friendships
                WHERE ((user1_id = ? AND user2_id = p.user_id) OR (user1_id = p.user_id AND user2_id = ?))
                AND status = 'accepted'
            ))
            OR
            (p.visibility = 'private' AND p.user_id = ?)
        )
    """
    total_posts = db.execute(has_more_query, (current_user.id, current_user.id, current_user.id)).fetchone()[0]
    has_more = (offset + per_page) < total_posts

    return jsonify({
        'posts': posts_list,
        'has_more': has_more
    })


# --- Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    form_data = request.form.to_dict() # Capture form data for re-populating on error
    if request.method == 'POST':
        username = request.form['username'].strip()
        original_name = request.form['originalName'].strip()
        gender = request.form['gender']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        db = get_db()
        # Check if username already exists
        existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            return render_template('register.html', form_data=form_data)

        # Prevent registration with admin credentials
        if username == config.ADMIN_USERNAME:
            flash('This username is reserved. Please choose a different one.', 'danger')
            return render_template('register.html', form_data=form_data)

        # Password validation
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', form_data=form_data)
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html', form_data=form_data)
        # Check for numbers, alphabets, and special characters
        if not (any(char.isdigit() for char in password) and
                any(char.isalpha() for char in password) and
                any(not char.isalnum() for char in password)):
            flash('Password must include at least one number, one letter, and one special character.', 'danger')
            return render_template('register.html', form_data=form_data)

        hashed_password = generate_password_hash(password)
        unique_key = generate_unique_key() # Generate unique key

        try:
            cursor = db.execute(
                'INSERT INTO users (username, originalName, password_hash, unique_key) VALUES (?, ?, ?, ?)',
                (username, original_name, hashed_password, unique_key)
            )
            user_id = cursor.lastrowid

            # Create an associated member profile automatically
            db.execute(
                'INSERT INTO members (user_id, fullName, gender) VALUES (?, ?, ?)',
                (user_id, original_name, gender)
            )
            db.commit()

            flash(f'Account created successfully for {username}! Your unique key for password recovery is: <strong>{unique_key}</strong>. Please save it.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('An unexpected error occurred (e.g., unique key collision). Please try again.', 'danger')
            db.rollback()
            return render_template('register.html', form_data=form_data)
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
            db.rollback()
            return render_template('register.html', form_data=form_data)

    return render_template('register.html', form_data=None)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    username_or_email = request.form.get('username')
    password = request.form.get('password')
    admin_login_checkbox = request.form.get('admin_login_checkbox')

    if request.method == 'POST':
        if not username_or_email or not password:
            flash('Please enter both username/email and password.', 'danger')
            return render_template('login.html', username=username_or_email)

        db = get_db()
        user_data = None

        # Try to find user by username
        user_data = db.execute('SELECT * FROM users WHERE username = ?', (username_or_email,)).fetchone()

        # If not found by username, try to find by email in members table
        if not user_data:
            member_with_email = db.execute('SELECT user_id FROM members WHERE email = ?', (username_or_email,)).fetchone()
            if member_with_email:
                user_data = db.execute('SELECT * FROM users WHERE id = ?', (member_with_email['user_id'],)).fetchone()

        if user_data:
            user = load_user(user_data['id'])
            if user and check_password_hash(user.password_hash, password):
                # Check admin login flag
                if admin_login_checkbox and not user.is_admin:
                    flash('You checked "Login as Admin" but you do not have admin privileges.', 'danger')
                    return render_template('login.html', username=username_or_email)
                if not admin_login_checkbox and user.is_admin:
                    flash('Please check "Login as Admin" to log in with this account.', 'danger')
                    return render_template('login.html', username=username_or_email)

                # Update last login and last seen timestamps
                now_utc = datetime.now(timezone.utc)
                db.execute('UPDATE users SET last_login_at = ?, last_seen_at = ? WHERE id = ?', (now_utc, now_utc, user.id))
                db.commit()

                login_user(user)
                flash('Logged in successfully!', 'success')
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('home'))
            else:
                flash('Invalid username/email or password.', 'danger')
        else:
            flash('Invalid username/email or password.', 'danger')

    return render_template('login.html', username=username_or_email)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/forgot_password', methods=['GET', 'POST']) # Updated to handle POST
def forgot_password():
    current_year = datetime.now(timezone.utc).year
    form_data = request.form.to_dict() # Capture form data for repopulation

    if request.method == 'POST':
        username = request.form.get('username')
        unique_key = request.form.get('unique_key')

        if not username or not unique_key:
            flash('Username and unique key are required.', 'danger')
            return render_template('forgot_password.html', current_year=current_year, form_data=form_data)

        db = get_db()
        user_data = db.execute('SELECT id, unique_key FROM users WHERE username = ?', (username,)).fetchone()

        if user_data and user_data['unique_key'] == unique_key:
            # Set a session variable to indicate password reset is pending for this user
            session['password_reset_user_id'] = user_data['id']
            flash('Unique key verified. You can now set a new password.', 'success')
            return redirect(url_for('set_new_password', unique_id=user_data['id']))
        else:
            flash('Invalid username or unique key.', 'danger')
            return render_template('forgot_password.html', current_year=current_year, form_data=form_data)

    return render_template('forgot_password.html', current_year=current_year, form_data=None) # GET request


@app.route('/set_new_password/<int:unique_id>', methods=['GET', 'POST'])
def set_new_password(unique_id):
    # Ensure this request is linked to a verified forgot password flow
    if 'password_reset_user_id' not in session or session['password_reset_user_id'] != unique_id:
        flash('Unauthorized access to password reset. Please use the "Forgot Password" link.', 'danger')
        return redirect(url_for('login'))

    db = get_db()
    user_data = db.execute('SELECT username, originalName FROM users WHERE id = ?', (unique_id,)).fetchone()
    if not user_data:
        flash('User not found.', 'danger')
        session.pop('password_reset_user_id', None) # Clear session
        return redirect(url_for('login'))

    username = user_data['username']
    current_year = datetime.now(timezone.utc).year # Pass current year

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('New password and confirmation do not match.', 'danger')
            return render_template('set_new_password.html', username=username, unique_id=unique_id, current_year=current_year)

        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            return render_template('set_new_password.html', username=username, unique_id=unique_id, current_year=current_year)
        if not (any(char.isdigit() for char in new_password) and
                any(char.isalpha() for char in new_password) and
                any(not char.isalnum() for char in new_password)):
            flash('New password must include at least one number, one letter, and one special character.', 'danger')
            return render_template('set_new_password.html', username=username, unique_id=unique_id, current_year=current_year)

        hashed_password = generate_password_hash(new_password)
        db.execute('UPDATE users SET password_hash = ?, password_reset_pending = 0, reset_request_timestamp = NULL WHERE id = ?', (hashed_password, unique_id))
        db.commit()

        session.pop('password_reset_user_id', None) # Clear session after successful reset
        flash('Your password has been changed successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('set_new_password.html', username=username, unique_id=unique_id, current_year=current_year)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html', current_year=current_year)

        if new_password != confirm_new_password:
            flash('New password and confirmation do not match.', 'danger')
            return render_template('change_password.html', current_year=current_year)

        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            return render_template('change_password.html', current_year=current_year)
        if not (any(char.isdigit() for char in new_password) and
                any(char.isalpha() for char in new_password) and
                any(not char.isalnum() for char in new_password)):
            flash('New password must include at least one number, one letter, and one special character.', 'danger')
            return render_template('change_password.html', current_year=current_year)

        db = get_db()
        hashed_password = generate_password_hash(new_password)
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_password, current_user.id))
        db.commit()
        flash('Your password has been changed successfully!', 'success')
        return redirect(url_for('my_profile')) # Redirect to profile or settings

    return render_template('change_password.html', current_year=current_year)


# --- Member & Profile Management ---

@app.route('/my_profile')
@login_required
def my_profile():
    db = get_db()
    member = current_user.get_member_profile()
    
    if not member:
        flash("Please complete your personal details first.", 'info')
        return redirect(url_for('edit_my_details'))

    # Prepare current_user_profile for the template
    current_user_profile = {
        'id': current_user.id,
        'username': current_user.username,
        'real_name': member['fullName'] or current_user.original_name,
        'profile_pic': get_member_profile_pic(current_user.id),
        'bio': member['bio'],
        'dob': member['dateOfBirth'],
        'gender': member['gender'],
        'pronouns': member['pronouns'], # Assuming 'pronouns' column exists or add it
        'work_info': member['workInfo'], # Assuming 'workInfo' column exists or add it
        'university': member['university'], # Assuming 'university' column exists or add it
        'secondary': member['secondary'], # Assuming 'secondary' column exists or add it
        'location': member['location'], # Assuming 'location' column exists or add it
        'phone': member['contact'],
        'email': member['email'],
        'social_link': member['socialLink'], # Assuming 'socialLink' column exists or add it
        'website_link': member['websiteLink'], # Assuming 'websiteLink' column exists or add it
        'relationship_status': member['maritalStatus'],
        'spouse_fiancee_name': member['maritalStatus'] in ['Married', 'Engaged'] and (member['spouseNames'] or member['girlfriendNames']) or None,
        'personal_relationship_description': member['personalRelationshipDescription'], # Added this line for the new field
        
        # Placeholder counts - Replace with actual database queries
        'friends_count': 0, 
        'followers_count': 0,
        'following_count': 0,
        'likes_count': 0,
        'posts_count': 0,

        # Determine if any additional info exists for the template
        'has_any_additional_info': any([
            member['dateOfBirth'], member['gender'], member['pronouns'], member['workInfo'],
            member['university'], member['secondary'], member['location'],
            member['contact'], member['email'], member['socialLink'], member['websiteLink'],
            member['maritalStatus'], member['spouseNames'], member['girlfriendNames'],
            member['personalRelationshipDescription'] # Added for consistency
        ])
    }
    
    # Fetch user details associated with the member (e.g., unique_key)
    user_details = db.execute("SELECT unique_key FROM users WHERE id = ?", (current_user.id,)).fetchone()

    # Placeholder for different content types on profile
    my_posts = []
    my_locked_posts = []
    my_saved_items = []
    my_reposts = []
    my_liked_items = []
    my_reels = []

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template(
        'my_profile.html',
        member=member, # Still pass the raw member data for backward compatibility or direct use if needed
        current_user_profile=current_user_profile, # The comprehensive profile dict
        unique_key=user_details['unique_key'] if user_details else None, # Duplicated for clarity, can be removed if profile dict is used
        current_year=current_year,
        my_posts=my_posts,
        my_locked_posts=my_locked_posts,
        my_saved_items=my_saved_items,
        my_reposts=my_reposts,
        my_liked_items=my_liked_items,
        my_reels=my_reels
    )


@app.route('/edit_my_details', methods=['GET', 'POST'])
@login_required
def edit_my_details():
    db = get_db()
    member = current_user.get_member_profile()
    
    # Prepare current_user_profile for the template, especially for profile_pic
    current_user_profile = {
        'profile_pic': get_member_profile_pic(current_user.id),
        'real_name': member['fullName'] if member else current_user.original_name,
        # Default empty strings for fields that might be None in the database,
        # so Jinja doesn't throw errors when accessing them
        'bio': member['bio'] if member else '',
        'dob': member['dateOfBirth'] if member else '',
        'gender': member['gender'] if member else '',
        'pronouns': member['pronouns'] if member else '',
        'work_info': member['workInfo'] if member else '',
        'university': member['university'] if member else '',
        'secondary': member['secondary'] if member else '',
        'location': member['location'] if member else '',
        'phone': member['contact'] if member else '',
        'email': member['email'] if member else '',
        'social_link': member['socialLink'] if member else '',
        'website_link': member['websiteLink'] if member else '',
        'relationship_status': member['maritalStatus'] if member else '',
        'spouse_fiancee_name': member['maritalStatus'] in ['Married', 'Engaged'] and (member['spouseNames'] or member['girlfriendNames']) or (member['maritalStatus'] == 'Dating' and member['girlfriendNames']) or '',
        'personal_relationship_description': member['personalRelationshipDescription'] if member else '', # Added
    }

    form_data = {}

    if member:
        form_data = dict(member) # Pre-populate form with existing data
        # Ensure date format is YYYY-MM-DD for HTML input
        # The database stores it as 'YYYY-MM-DD' directly from HTML input type="date"
        # So, we just need to ensure it's a string. No complex parsing/reformatting is needed for display.
        if form_data.get('dateOfBirth'):
            form_data['dateOfBirth'] = str(form_data['dateOfBirth']) # Ensure it's a string, already YYYY-MM-DD
            
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    if request.method == 'POST':
        fullName = request.form['fullName'].strip()
        dateOfBirth = request.form['dateOfBirth']
        gender = request.form['gender']
        contact = request.form['contact'].strip()
        email = request.form['email'].strip()
        bio = request.form['bio'].strip()
        personalRelationshipDescription = request.form['personalRelationshipDescription'].strip()
        maritalStatus = request.form['maritalStatus']
        spouseNames = request.form.get('spouseNames', '').strip()
        girlfriendNames = request.form.get('girlfriendNames', '').strip() # For Engaged
        
        # New fields from schema for edit_my_details
        pronouns = request.form.get('pronouns', '').strip()
        workInfo = request.form.get('workInfo', '').strip()
        university = request.form.get('university', '').strip()
        secondary = request.form.get('secondary', '').strip()
        location = request.form.get('location', '').strip()
        socialLink = request.form.get('socialLink', '').strip()
        websiteLink = request.form.get('websiteLink', '').strip()


        profile_photo_file = request.files.get('profilePhotoFile') # Changed to profilePhotoFile for clarity in HTML
        profilePhoto_path = member['profilePhoto'] if member else None

        if profile_photo_file and profile_photo_file.filename != '':
            profilePhoto_path = save_uploaded_file(profile_photo_file, app.config['PROFILE_PHOTOS_FOLDER'])
            if not profilePhoto_path:
                flash('Invalid profile photo file type.', 'danger')
                form_data = request.form.to_dict()
                return render_template('edit_my_details.html', form_data=form_data, member=member, current_user_profile=current_user_profile, current_year=current_year)

        try:
            if member:
                db.execute(
                    """
                    UPDATE members SET fullName=?, dateOfBirth=?, gender=?, contact=?, email=?, bio=?,
                    personalRelationshipDescription=?, maritalStatus=?, spouseNames=?, girlfriendNames=?, profilePhoto=?,
                    pronouns=?, workInfo=?, university=?, secondary=?, location=?, socialLink=?, websiteLink=?
                    WHERE user_id=?
                    """,
                    (fullName, dateOfBirth, gender, contact, email, bio,
                     personalRelationshipDescription, maritalStatus, spouseNames, girlfriendNames, profilePhoto_path,
                     pronouns, workInfo, university, secondary, location, socialLink, websiteLink,
                     current_user.id)
                )
                flash('Your details have been updated successfully!', 'success')
            else:
                db.execute(
                    """
                    INSERT INTO members (user_id, fullName, dateOfBirth, gender, contact, email, bio,
                    personalRelationshipDescription, maritalStatus, spouseNames, girlfriendNames, profilePhoto,
                    pronouns, workInfo, university, secondary, location, socialLink, websiteLink)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (current_user.id, fullName, dateOfBirth, gender, contact, email, bio,
                     personalRelationshipDescription, maritalStatus, spouseNames, girlfriendNames, profilePhoto_path,
                     pronouns, workInfo, university, secondary, location, socialLink, websiteLink)
                )
                flash('Your personal details have been added successfully!', 'success')
            db.commit()
            return redirect(url_for('my_profile'))
        except Exception as e:
            flash(f'An error occurred while saving your details: {e}', 'danger')
            db.rollback()
            form_data = request.form.to_dict()
            return render_template('edit_my_details.html', form_data=form_data, member=member, current_user_profile=current_user_profile, current_year=current_year)

    return render_template('edit_my_details.html', form_data=form_data, member=member, current_user_profile=current_user_profile, current_year=current_year)


@app.route('/profile/<username>')
@login_required
def profile(username):
    db = get_db()
    # Get user details for the requested profile
    profile_user = db.execute('SELECT id, username, originalName, is_admin FROM users WHERE username = ?', (username,)).fetchone()
    if not profile_user:
        flash("User not found.", "danger")
        return redirect(url_for('home')) # Redirect to home if user not found

    # Get member details for the requested profile
    member = db.execute('SELECT * FROM members WHERE user_id = ?', (profile_user['id'],)).fetchone()
    if not member:
        flash("This user has not completed their personal profile yet.", 'info')
        # Provide minimal info or redirect
        return render_template('profile.html', profile_user=profile_user, member=None, is_friend=False, is_pending_request=False, is_blocked=False, current_user_is_admin=current_user.is_admin)

    # Check friendship status
    is_friend = False
    is_pending_request = False # True if request sent by current_user to profile_user
    is_received_request = False # True if request sent by profile_user to current_user

    friendship = db.execute(
        "SELECT * FROM friendships WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)",
        (current_user.id, profile_user['id'], profile_user['id'], current_user.id)
    ).fetchone()

    if friendship:
        if friendship['status'] == 'accepted':
            is_friend = True
        elif friendship['status'] == 'pending':
            if friendship['user1_id'] == current_user.id:
                is_pending_request = True # Current user sent request
            else:
                is_received_request = True # Profile user sent request to current user

    # Check if current user has blocked this profile user
    is_blocked = db.execute(
        "SELECT 1 FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
        (current_user.id, profile_user['id'])
    ).fetchone() is not None

    # No 'temp_video' or 'story-viewer.html' or 'statuses' table on the list
    temp_video = None

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template(
        'profile.html',
        profile_user=profile_user,
        member=member,
        is_friend=is_friend,
        is_pending_request=is_pending_request,
        is_received_request=is_received_request,
        is_blocked=is_blocked,
        temp_video=temp_video, # Will be None
        current_user_is_admin=current_user.is_admin,
        current_year=current_year
    )

# Removed: @app.route('/list_members') and associated function
# as 'members_list.html' is not on the user's list.
# Functionality to view members can be integrated into 'friends.html' or search results.


# Removed: @app.route('/add_member', methods=['GET', 'POST']) and associated function
# as 'add-member.html' is not on the user's list and not in sociafam.doc.


# --- Friendship Routes (API endpoints for AJAX) ---

@app.route('/api/send_friend_request/<int:receiver_id>', methods=['POST'])
@login_required
def api_send_friend_request(receiver_id):
    db = get_db()
    # Check if request already exists or they are already friends
    existing_friendship = db.execute(
        """
        SELECT * FROM friendships
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        """,
        (current_user.id, receiver_id, receiver_id, current_user.id)
    ).fetchone()

    if existing_friendship:
        if existing_friendship['status'] == 'accepted':
            return jsonify({'success': False, 'message': 'You are already friends.'})
        elif existing_friendship['status'] == 'pending':
            return jsonify({'success': False, 'message': 'Friend request already sent or received.'})

    try:
        db.execute(
            "INSERT INTO friendships (user1_id, user2_id, status) VALUES (?, ?, 'pending')",
            (current_user.id, receiver_id)
        )
        db.commit()
        # Send notification to the receiver
        receiver_user = load_user(receiver_id)
        if receiver_user:
            message = f'<strong>{current_user.original_name}</strong> (@{current_user.username}) sent you a friend request!'
            send_system_notification(
                receiver_id,
                message,
                link=url_for('friends'),
                type='friend_request'
            )
        return jsonify({'success': True, 'message': 'Friend request sent!'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error sending friend request: {e}")
        return jsonify({'success': False, 'message': 'Failed to send friend request.'})


@app.route('/api/accept_friend_request/<int:request_id>', methods=['POST'])
@login_required
def api_accept_friend_request(request_id):
    db = get_db()
    friendship = db.execute(
        "SELECT * FROM friendships WHERE id = ? AND user2_id = ? AND status = 'pending'",
        (request_id, current_user.id)
    ).fetchone()

    if not friendship:
        return jsonify({'success': False, 'message': 'Friend request not found or not pending.'})

    try:
        db.execute(
            "UPDATE friendships SET status = 'accepted' WHERE id = ?",
            (request_id,)
        )
        db.commit()
        # Send notification to the sender
        sender_user = load_user(friendship['user1_id'])
        if sender_user:
            message = f'<strong>{current_user.original_name}</strong> (@{current_user.username}) accepted your friend request!'
            send_system_notification(
                friendship['user1_id'],
                message,
                link=url_for('profile', username=current_user.username),
                type='friend_accepted'
            )
        return jsonify({'success': True, 'message': 'Friend request accepted!'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error accepting friend request: {e}")
        return jsonify({'success': False, 'message': 'Failed to accept friend request.'})


@app.route('/api/decline_friend_request/<int:request_id>', methods=['POST'])
@login_required
def api_decline_friend_request(request_id):
    db = get_db()
    friendship = db.execute(
        "SELECT * FROM friendships WHERE id = ? AND user2_id = ? AND status = 'pending'",
        (request_id, current_user.id)
    ).fetchone()

    if not friendship:
        return jsonify({'success': False, 'message': 'Friend request not found or not pending.'})

    try:
        db.execute("DELETE FROM friendships WHERE id = ?", (request_id,))
        db.commit()
        flash('Friend request declined.', 'info') # Flash message for the user who declined
        return jsonify({'success': True, 'message': 'Friend request declined.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error declining friend request: {e}")
        return jsonify({'success': False, 'message': 'Failed to decline friend request.'})


@app.route('/api/unfriend/<int:friend_id>', methods=['POST'])
@login_required
def api_unfriend(friend_id):
    db = get_db()
    friendship = db.execute(
        """
        SELECT * FROM friendships
        WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
        AND status = 'accepted'
        """,
        (current_user.id, friend_id, friend_id, current_user.id)
    ).fetchone()

    if not friendship:
        return jsonify({'success': False, 'message': 'Not friends with this user.'})

    try:
        db.execute("DELETE FROM friendships WHERE id = ?", (friendship['id'],))
        db.commit()
        flash('User unfriended.', 'info')
        return jsonify({'success': True, 'message': 'User unfriended.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error unfriending user: {e}")
        return jsonify({'success': False, 'message': 'Failed to unfriend user.'})


# Update the friends route in app.py
@app.route('/friends')
@login_required
def friends():
    db = get_db()

    # Fetch all accepted friends (mutual)
    all_friends_raw = db.execute(
        """
        SELECT u.id, m.fullName AS realName, u.username, m.profilePhoto
        FROM friendships f
        JOIN users u ON (f.user1_id = u.id OR f.user2_id = u.id)
        JOIN members m ON m.user_id = u.id
        WHERE (f.user1_id = ? OR f.user2_id = ?) AND f.status = 'accepted' AND u.id != ?
            AND u.id NOT IN (SELECT blocked_id FROM blocked_users WHERE blocker_id = ?)
        """,
        (current_user.id, current_user.id, current_user.id, current_user.id)
    ).fetchall()

    all_friends = []
    for friend in all_friends_raw:
        mutual_count = get_mutual_friends_count(current_user.id, friend['id'])
        all_friends.append(dict(friend, mutual_count=mutual_count, profilePhoto=get_member_profile_pic(friend['id'])))

    # Fetch following: users I sent request to and accepted
    following_raw = db.execute(
        """
        SELECT u.id, m.fullName AS realName, u.username, m.profilePhoto
        FROM friendships f
        JOIN users u ON f.user2_id = u.id
        JOIN members m ON m.user_id = u.id
        WHERE f.user1_id = ? AND f.status = 'accepted'
            AND u.id NOT IN (SELECT blocked_id FROM blocked_users WHERE blocker_id = ?)
        """,
        (current_user.id, current_user.id)
    ).fetchall()

    following = []
    for user in following_raw:
        mutual_count = get_mutual_friends_count(current_user.id, user['id'])
        following.append(dict(user, mutual_count=mutual_count, profilePhoto=get_member_profile_pic(user['id'])))

    # Fetch followers: users who sent request to me and accepted
    followers_raw = db.execute(
        """
        SELECT u.id, m.fullName AS realName, u.username, m.profilePhoto
        FROM friendships f
        JOIN users u ON f.user1_id = u.id
        JOIN members m ON m.user_id = u.id
        WHERE f.user2_id = ? AND f.status = 'accepted'
            AND u.id NOT IN (SELECT blocked_id FROM blocked_users WHERE blocker_id = ?)
        """,
        (current_user.id, current_user.id)
    ).fetchall()

    followers = []
    for user in followers_raw:
        mutual_count = get_mutual_friends_count(current_user.id, user['id'])
        followers.append(dict(user, mutual_count=mutual_count, profilePhoto=get_member_profile_pic(user['id'])))

    # Fetch friend requests: pending requests sent to me
    friend_requests_raw = db.execute(
        """
        SELECT f.id AS friendship_id, u.id AS sender_id, m.fullName AS sender_realName, u.username AS sender_username, m.profilePhoto
        FROM friendships f
        JOIN users u ON f.user1_id = u.id
        JOIN members m ON m.user_id = u.id
        WHERE f.user2_id = ? AND f.status = 'pending'
            AND u.id NOT IN (SELECT blocked_id FROM blocked_users WHERE blocker_id = ?)
        """,
        (current_user.id, current_user.id)
    ).fetchall()

    friend_requests = []
    for request in friend_requests_raw:
        mutual_count = get_mutual_friends_count(current_user.id, request['sender_id'])
        friend_requests.append(dict(request, mutual_count=mutual_count, profilePhoto=get_member_profile_pic(request['sender_id'])))

    # Fetch suggested users: friends of friends, with mutual count
    suggested_users_raw = db.execute(
        """
        SELECT u.id, m.fullName AS realName, u.username, m.profilePhoto, COUNT(DISTINCT my_friend.id) AS mutual_count
        FROM users u
        JOIN members m ON m.user_id = u.id
        JOIN friendships f1 ON (f1.user1_id = ? OR f1.user2_id = ?) AND f1.status = 'accepted'
        JOIN users my_friend ON my_friend.id = CASE WHEN f1.user1_id = ? THEN f1.user2_id ELSE f1.user1_id END
        JOIN friendships f2 ON (f2.user1_id = my_friend.id OR f2.user2_id = my_friend.id) AND f2.status = 'accepted'
        WHERE u.id = CASE WHEN f2.user1_id = my_friend.id THEN f2.user2_id ELSE f2.user1_id END
            AND u.id != ?
            AND u.id NOT IN (
                SELECT CASE WHEN f.user1_id = ? THEN f.user2_id ELSE f.user1_id END
                FROM friendships f
                WHERE (f.user1_id = ? OR f.user2_id = ?) AND f.status IN ('accepted', 'pending')
            )
            AND u.id NOT IN (SELECT blocked_id FROM blocked_users WHERE blocker_id = ?)
        GROUP BY u.id
        HAVING mutual_count > 0
        ORDER BY mutual_count DESC
        LIMIT 10
        """,
        (current_user.id, current_user.id, current_user.id, current_user.id, current_user.id, current_user.id, current_user.id, current_user.id)
    ).fetchall()

    suggested_users = [dict(user, profilePhoto=get_member_profile_pic(user['id'])) for user in suggested_users_raw]

    return render_template(
        'friends.html',
        all_friends=all_friends,
        following=following,
        followers=followers,
        friend_requests=friend_requests,
        suggested_users=suggested_users
    )

# Add this new API route to app.py for search
@app.route('/api/search_users')
@login_required
def api_search_users():
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify([])

    db = get_db()
    users_raw = db.execute(
        """
        SELECT u.id, m.fullName AS realName, u.username, m.profilePhoto,
        CASE WHEN LOWER(m.fullName) LIKE ? THEN 0 ELSE 1 END AS sort_order
        FROM users u
        JOIN members m ON m.user_id = u.id
        WHERE (LOWER(m.fullName) LIKE ? OR LOWER(u.username) LIKE ?) AND u.id != ?
            AND u.id NOT IN (SELECT blocked_id FROM blocked_users WHERE blocker_id = ?)
        ORDER BY sort_order, LOWER(m.fullName), LOWER(u.username)
        """,
        (query + '%', query + '%', query + '%', current_user.id, current_user.id)
    ).fetchall()

    users = []
    for user in users_raw:
        mutual_count = get_mutual_friends_count(current_user.id, user['id'])
        status = get_relationship_status(current_user.id, user['id'])
        users.append({
            'id': user['id'],
            'realName': user['realName'],
            'username': user['username'],
            'profilePhoto': get_member_profile_pic(user['id']),
            'mutual_count': mutual_count,
            'status': status
        })

    return jsonify(users)

# --- Messaging & Chat Rooms ---

@app.route('/inbox')
@login_required
def inbox():
    db = get_db()

    # Fetch conversations (chat rooms the user is a member of)
    # Get latest message for each chat room
    conversations_data = db.execute(
        """
        SELECT
            cr.id AS chat_room_id,
            cr.is_group,
            MAX(cm.timestamp) AS latest_message_timestamp,
            (SELECT content FROM chat_messages WHERE chat_room_id = cr.id ORDER BY timestamp DESC LIMIT 1) AS latest_message_content,
            (SELECT sender_id FROM chat_messages WHERE chat_room_id = cr.id ORDER BY timestamp DESC LIMIT 1) AS latest_message_sender_id,
            (SELECT COUNT(*) FROM chat_messages WHERE chat_room_id = cr.id AND sender_id != ? AND timestamp > crm.last_read_message_timestamp) AS unread_count,
            u_other.id AS other_user_id,
            u_other.username AS other_username,
            u_other.originalName AS other_original_name,
            m_other.profilePhoto AS other_profile_photo
        FROM chat_rooms cr
        JOIN chat_room_members crm ON cr.id = crm.chat_room_id
        LEFT JOIN chat_messages cm ON cr.id = cm.chat_room_id
        LEFT JOIN chat_room_members crm_other ON cr.id = crm_other.chat_room_id AND crm_other.user_id != ? AND cr.is_group = 0
        LEFT JOIN users u_other ON crm_other.user_id = u_other.id
        LEFT JOIN members m_other ON u_other.id = m_other.user_id
        WHERE crm.user_id = ?
        GROUP BY cr.id
        ORDER BY latest_message_timestamp DESC
        """,
        (current_user.id, current_user.id, current_user.id)
    ).fetchall()

    conversations = []
    for conv in conversations_data:
        conv_dict = dict(conv)
        conv_dict['is_unread'] = conv_dict['unread_count'] > 0
        conv_dict['latest_message_snippet'] = (conv_dict['latest_message_content'][:50] + '...') if conv_dict['latest_message_content'] and len(conv_dict['latest_message_content']) > 50 else (conv_dict['latest_message_content'] or "No messages yet.")

        # If it's a 1-on-1 chat, populate other_user details
        if not conv_dict['is_group']:
            conv_dict['other_user'] = {
                'id': conv_dict['other_user_id'],
                'username': conv_dict['other_username'],
                'originalName': conv_dict['other_original_name'],
                'profilePhoto': get_member_profile_pic(conv_dict['other_user_id'])
            }
        else:
            # For groups, you might want to show group name or a generic group icon
            group_details = db.execute("SELECT name, profilePhoto FROM groups WHERE chat_room_id = ?", (conv_dict['chat_room_id'],)).fetchone()
            if group_details:
                conv_dict['other_user'] = { # Reusing structure for display
                    'id': conv_dict['chat_room_id'],
                    'username': group_details['name'], # Display group name as "username" for simplicity
                    'originalName': group_details['name'],
                    'profilePhoto': group_details['profilePhoto'] or url_for('static', filename='img/default_group.png')
                }
            else:
                 conv_dict['other_user'] = {
                    'id': conv_dict['chat_room_id'],
                    'username': "Group Chat",
                    'originalName': "Group Chat",
                    'profilePhoto': url_for('static', filename='img/default_group.png')
                }

        conversations.append(conv_dict)


    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('inbox.html', conversations=conversations, current_year=current_year)


@app.route('/message_member', methods=['GET', 'POST'])
@login_required
def message_member():
    db = get_db()
    # Fetch all users who are not the current user and are not blocked by current user
    # Also exclude users blocked by them to prevent one-sided chat initiation
    available_users = db.execute(
        """
        SELECT u.id, u.username, u.originalName, m.profilePhoto
        FROM users u
        LEFT JOIN members m ON u.id = m.user_id
        WHERE u.id != ?
          AND u.id NOT IN (SELECT blocked_id FROM blocked_users WHERE blocker_id = ?)
          AND u.id NOT IN (SELECT blocker_id FROM blocked_users WHERE blocked_id = ?)
        ORDER BY u.originalName
        """,
        (current_user.id, current_user.id, current_user.id)
    ).fetchall()

    users_with_pics = []
    for user in available_users:
        user_dict = dict(user)
        user_dict['profilePhoto'] = get_member_profile_pic(user_dict['id'])
        users_with_pics.append(user_dict)

    if request.method == 'POST':
        receiver_user_id = request.form['receiver_user_id']
        # This route is now primarily for displaying the list.
        # Starting a chat will redirect to view_chat
        return redirect(url_for('view_chat', chat_room_id=receiver_user_id)) # Redirect to start/view conversation

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('message_member.html', available_users=users_with_pics, current_year=current_year)


@app.route('/view_chat/<int:chat_room_id>', methods=['GET', 'POST'])
@login_required
def view_chat(chat_room_id):
    db = get_db()

    # Verify current user is a member of this chat room
    is_member = db.execute(
        "SELECT 1 FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?",
        (chat_room_id, current_user.id)
    ).fetchone()
    
    # If not a member, check if it's a new 1-on-1 chat being initiated
    if not is_member:
        # Assume chat_room_id here might be a target user_id if initiating a new chat
        # Try to find an existing 1-on-1 chat with this user_id
        target_user_id = chat_room_id # Temporarily assume chat_room_id is user_id
        existing_chat_room = db.execute(
            """
            SELECT cr.id FROM chat_rooms cr
            JOIN chat_room_members crm1 ON cr.id = crm1.chat_room_id AND crm1.user_id = ?
            JOIN chat_room_members crm2 ON cr.id = crm2.chat_room_id AND crm2.user_id = ?
            WHERE cr.is_group = 0
            """,
            (current_user.id, target_user_id)
        ).fetchone()

        if existing_chat_room:
            chat_room_id = existing_chat_room['id']
            is_member = True # Now we are a member of an existing chat
        else:
            # Create a new 1-on-1 chat room
            try:
                cursor = db.execute("INSERT INTO chat_rooms (is_group, created_by) VALUES (?, ?)", (0, current_user.id))
                new_chat_room_id = cursor.lastrowid
                db.execute("INSERT INTO chat_room_members (chat_room_id, user_id) VALUES (?, ?)", (new_chat_room_id, current_user.id))
                db.execute("INSERT INTO chat_room_members (chat_room_id, user_id) VALUES (?, ?)", (new_chat_room_id, target_user_id))
                db.commit()
                flash('New conversation started!', 'success')
                return redirect(url_for('view_chat', chat_room_id=new_chat_room_id))
            except Exception as e:
                flash(f'Error starting new conversation: {e}', 'danger')
                db.rollback()
                return redirect(url_for('inbox')) # Fallback to inbox

    if not is_member: # Should not happen if logic above is correct
        flash('You are not a member of this chat room.', 'danger')
        return redirect(url_for('inbox'))

    chat_room = db.execute("SELECT * FROM chat_rooms WHERE id = ?", (chat_room_id,)).fetchone()
    if not chat_room:
        flash("Chat room not found.", "danger")
        return redirect(url_for('inbox'))

    other_user = None
    if not chat_room['is_group']:
        # For 1-on-1 chat, find the other user
        other_member_id = db.execute(
            "SELECT user_id FROM chat_room_members WHERE chat_room_id = ? AND user_id != ?",
            (chat_room_id, current_user.id)
        ).fetchone()
        if other_member_id:
            other_user = load_user(other_member_id['user_id'])
            if other_user:
                other_user_member = get_member_from_user_id(other_user.id)
                other_user.profile_pic = get_member_profile_pic(other_user.id)
                other_user.real_name = other_user_member['fullName'] if other_user_member else other_user.username
    else:
        # For group chat, redirect to view_group_chat
        return redirect(url_for('view_group_chat', group_chat_room_id=chat_room_id))


    # Fetch messages
    messages = db.execute(
        """
        SELECT cm.*, u.username, m.profilePhoto
        FROM chat_messages cm
        JOIN users u ON cm.sender_id = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE cm.chat_room_id = ?
        ORDER BY cm.timestamp
        """,
        (chat_room_id,)
    ).fetchall()

    # Mark messages as read for current user
    db.execute(
        "UPDATE chat_room_members SET last_read_message_timestamp = ? WHERE chat_room_id = ? AND user_id = ?",
        (datetime.now(timezone.utc), chat_room_id, current_user.id)
    )
    db.commit()

    # Get chat background image for current user
    chat_background_image_path = current_user.chat_background_image_path or url_for('static', filename='img/default_chat_background.jpg')

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template(
        'view_chat.html', # Changed to view_chat.html
        chat_room_id=chat_room_id,
        other_user=other_user,
        chat_messages=messages,
        current_user_id=current_user.id,
        chat_background_image_path=chat_background_image_path,
        current_year=current_year
    )


@app.route('/view_group_chat/<int:group_chat_room_id>')
@login_required
def view_group_chat(group_chat_room_id):
    db = get_db()

    # Verify current user is a member of this chat room
    is_member = db.execute(
        "SELECT 1 FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?",
        (group_chat_room_id, current_user.id)
    ).fetchone()
    if not is_member:
        flash('You are not a member of this group chat.', 'danger')
        return redirect(url_for('inbox'))

    group_chat_room = db.execute("SELECT * FROM chat_rooms WHERE id = ? AND is_group = 1", (group_chat_room_id,)).fetchone()
    if not group_chat_room:
        flash("Group chat not found.", "danger")
        return redirect(url_for('inbox'))

    group_details = db.execute("SELECT * FROM groups WHERE chat_room_id = ?", (group_chat_room_id,)).fetchone()
    if not group_details:
        flash("Group details not found.", "danger")
        return redirect(url_for('inbox'))

    # Fetch messages
    messages = db.execute(
        """
        SELECT cm.*, u.username, m.profilePhoto
        FROM chat_messages cm
        JOIN users u ON cm.sender_id = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE cm.chat_room_id = ?
        ORDER BY cm.timestamp
        """,
        (group_chat_room_id,)
    ).fetchall()

    # Mark messages as read for current user in this group chat
    db.execute(
        "UPDATE chat_room_members SET last_read_message_timestamp = ? WHERE chat_room_id = ? AND user_id = ?",
        (datetime.now(timezone.utc), group_chat_room_id, current_user.id)
    )
    db.commit()

    # Get chat background image for current user
    chat_background_image_path = current_user.chat_background_image_path or url_for('static', filename='img/default_chat_background.jpg')

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template(
        'view_group_chat.html',
        chat_room_id=group_chat_room_id,
        group=group_details,
        chat_messages=messages,
        current_user_id=current_user.id,
        chat_background_image_path=chat_background_image_path,
        current_year=current_year
    )


@app.route('/api/send_chat_message/<int:chat_room_id>', methods=['POST'])
@login_required
def api_send_chat_message(chat_room_id):
    db = get_db()

    # Verify user is member of chat room
    is_member = db.execute(
        "SELECT 1 FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?",
        (chat_room_id, current_user.id)
    ).fetchone()
    if not is_member:
        return jsonify({'success': False, 'message': 'You are not a member of this chat room.'}), 403

    content = request.form.get('content')
    media_file = request.files.get('media_file')
    media_path = None
    media_type = None

    if media_file and media_file.filename != '':
        media_path = save_uploaded_file(media_file, app.config['CHAT_MEDIA_FOLDER'])
        if media_path:
            if media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
                media_type = 'image'
            elif media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS:
                media_type = 'video'
            elif media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_AUDIO_EXTENSIONS:
                media_type = 'audio'
        else:
            return jsonify({'success': False, 'message': 'Invalid media file type.'}), 400

    if not content and not media_path:
        return jsonify({'success': False, 'message': 'Message cannot be empty.'}), 400

    try:
        cursor = db.execute(
            "INSERT INTO chat_messages (chat_room_id, sender_id, content, timestamp, media_path, media_type) VALUES (?, ?, ?, ?, ?, ?)",
            (chat_room_id, current_user.id, content, datetime.now(timezone.utc), media_path, media_type)
        )
        message_id = cursor.lastrowid
        db.commit()

        # Fetch the newly created message to return
        new_message = db.execute(
            "SELECT cm.*, u.username, m.profilePhoto FROM chat_messages cm JOIN users u ON cm.sender_id = u.id LEFT JOIN members m ON u.id = m.user_id WHERE cm.id = ?",
            (message_id,)
        ).fetchone()

        # Send notifications to other chat room members (excluding sender)
        other_members = db.execute(
            "SELECT user_id FROM chat_room_members WHERE chat_room_id = ? AND user_id != ?",
            (chat_room_id, current_user.id)
        ).fetchall()
        for member in other_members:
            # Construct a snippet of the message for notification
            notif_content = content if content else f"sent a {media_type}"
            message_text = f"<strong>{current_user.original_name}</strong> sent a message in your chat: {notif_content[:50]}"
            send_system_notification(
                member['user_id'],
                message_text,
                link=url_for('view_chat', chat_room_id=chat_room_id),
                type='message_received'
            )

        return jsonify({'success': True, 'message': dict(new_message)})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error sending chat message: {e}")
        return jsonify({'success': False, 'message': 'Failed to send message.'}), 500


@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    db = get_db()
    # Fetch friends for adding to the group
    friends_data = db.execute(
        """
        SELECT u.id, u.username, u.originalName, m.profilePhoto
        FROM friendships f
        JOIN users u ON CASE WHEN f.user1_id = ? THEN f.user2_id ELSE f.user1_id END = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE (f.user1_id = ? OR f.user2_id = ?) AND f.status = 'accepted'
        ORDER BY u.originalName
        """,
        (current_user.id, current_user.id, current_user.id)
    ).fetchall()

    friends_with_pics = []
    for friend in friends_data:
        friend_dict = dict(friend)
        friend_dict['profilePhoto'] = get_member_profile_pic(friend_dict['id'])
        friends_with_pics.append(friend_dict)

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    if request.method == 'POST':
        group_name = request.form['groupName'].strip()
        description = request.form.get('description', '').strip()
        selected_friends_ids_str = request.form.getlist('selectedFriends')
        selected_friends_ids = [int(fid) for fid in selected_friends_ids_str if fid.isdigit()]

        group_profile_pic_file = request.files.get('groupProfilePhoto')
        profile_photo_path = None

        if group_profile_pic_file and group_profile_pic_file.filename != '':
            profile_photo_path = save_uploaded_file(group_profile_pic_file, app.config['PROFILE_PHOTOS_FOLDER'])
            if not profile_photo_path:
                flash('Invalid group profile photo file type.', 'danger')
                return render_template('create_group.html', friends=friends_with_pics, form_data=request.form.to_dict(), current_year=current_year)

        if not group_name:
            flash('Group name is required.', 'danger')
            return render_template('create_group.html', friends=friends_with_pics, form_data=request.form.to_dict(), current_year=current_year)

        if not selected_friends_ids:
            flash('Please select at least one friend to add to the group.', 'danger')
            return render_template('create_group.html', friends=friends_with_pics, form_data=request.form.to_dict(), current_year=current_year)

        try:
            # Create chat room for the group
            cursor = db.execute(
                "INSERT INTO chat_rooms (is_group, created_by) VALUES (?, ?)",
                (1, current_user.id)
            )
            chat_room_id = cursor.lastrowid

            # Create group entry
            cursor = db.execute(
                "INSERT INTO groups (name, description, profilePhoto, created_by, chat_room_id) VALUES (?, ?, ?, ?, ?)",
                (group_name, description, profile_photo_path, current_user.id, chat_room_id)
            )
            group_id = cursor.lastrowid

            # Add current user as member and admin of the chat room
            db.execute(
                "INSERT INTO chat_room_members (chat_room_id, user_id, is_admin) VALUES (?, ?, ?)",
                (chat_room_id, current_user.id, 1) # Creator is admin
            )

            # Add selected friends to chat room members
            for friend_id in selected_friends_ids:
                db.execute(
                    "INSERT INTO chat_room_members (chat_room_id, user_id, is_admin) VALUES (?, ?, ?)",
                    (chat_room_id, friend_id, 0) # Friends are regular members
                )
                # Send notification to invited friends
                friend_user = load_user(friend_id)
                if friend_user:
                    message = f'<strong>{current_user.original_name}</strong> invited you to the group chat: <strong>{group_name}</strong>!'
                    send_system_notification(
                        friend_id,
                        message,
                        link=url_for('view_group_profile', group_id=group_id),
                        type='group_invite'
                    )

            db.commit()
            flash(f'Group "{group_name}" created successfully!', 'success')
            return redirect(url_for('view_group_profile', group_id=group_id))
        except Exception as e:
            flash(f'An error occurred while creating the group: {e}', 'danger')
            db.rollback()
            return render_template('create_group.html', friends=friends_with_pics, form_data=request.form.to_dict(), current_year=current_year)

    return render_template('create_group.html', friends=friends_with_pics, form_data=None, current_year=current_year)


@app.route('/view_group_profile/<int:group_id>')
@login_required
def view_group_profile(group_id):
    db = get_db()
    group = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not group:
        flash("Group not found.", "danger")
        return redirect(url_for('inbox')) # Redirect to inbox if group not found

    is_admin_view = request.args.get('admin_view', 'false').lower() == 'true'

    # Check if current_user is a member (unless in admin_view mode)
    is_member = db.execute(
        "SELECT 1 FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?",
        (group['chat_room_id'], current_user.id)
    ).fetchone() is not None

    if not is_member and not (current_user.is_admin and is_admin_view):
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('inbox')) # Or a more appropriate page

    group_members_data = db.execute(
        """
        SELECT u.id, u.username, u.originalName, m.profilePhoto, crm.is_admin as is_group_admin
        FROM chat_room_members crm
        JOIN users u ON crm.user_id = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE crm.chat_room_id = ?
        ORDER BY u.originalName
        """,
        (group['chat_room_id'],)
    ).fetchall()

    group_members = []
    for member in group_members_data:
        member_dict = dict(member)
        member_dict['profilePhoto'] = get_member_profile_pic(member_dict['id'])
        group_members.append(member_dict)

    # Check if current user is admin of *this specific group*
    current_user_is_group_admin = db.execute(
        "SELECT is_admin FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?",
        (group['chat_room_id'], current_user.id)
    ).fetchone()
    current_user_is_group_admin = current_user_is_group_admin['is_admin'] if current_user_is_group_admin else 0

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template(
        'view_group_profile.html',
        group=group,
        group_members=group_members,
        is_member=is_member,
        current_user_is_group_admin=current_user_is_group_admin,
        admin_view=is_admin_view, # Pass this flag to template
        current_year=current_year
    )


@app.route('/api/join_group/<int:group_id>', methods=['POST'])
@login_required
def api_join_group(group_id):
    db = get_db()
    group = db.execute("SELECT chat_room_id, name FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not group:
        return jsonify({'success': False, 'message': 'Group not found.'}), 404

    chat_room_id = group['chat_room_id']

    is_member = db.execute(
        "SELECT 1 FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?",
        (chat_room_id, current_user.id)
    ).fetchone()
    if is_member:
        return jsonify({'success': False, 'message': 'You are already a member of this group.'}), 400

    try:
        db.execute(
            "INSERT INTO chat_room_members (chat_room_id, user_id, is_admin) VALUES (?, ?, 0)",
            (chat_room_id, current_user.id)
        )
        db.commit()
        flash(f'You have successfully joined "{group["name"]}"!', 'success')
        return jsonify({'success': True, 'message': 'Successfully joined group.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error joining group: {e}")
        return jsonify({'success': False, 'message': 'Failed to join group.'}), 500


@app.route('/api/leave_group/<int:group_id>', methods=['POST'])
@login_required
def api_leave_group(group_id):
    db = get_db()
    group = db.execute("SELECT chat_room_id, name FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not group:
        return jsonify({'success': False, 'message': 'Group not found.'}), 404

    chat_room_id = group['chat_room_id']

    is_member = db.execute(
        "SELECT 1 FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?",
        (chat_room_id, current_user.id)
    ).fetchone()
    if not is_member:
        return jsonify({'success': False, 'message': 'You are not a member of this group.'}), 400

    try:
        db.execute(
            "DELETE FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?",
            (chat_room_id, current_user.id)
        )
        db.commit()
        flash(f'You have successfully left "{group["name"]}".', 'info')
        return jsonify({'success': True, 'message': 'Successfully left group.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error leaving group: {e}")
        return jsonify({'success': False, 'message': 'Failed to leave group.'}), 500


# --- Content Creation Routes ---

@app.route('/add_to')
@login_required
def add_to():
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('add_to.html', current_year=current_year)

# Create Post
@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year

    if request.method == 'POST':
        db = get_db()
        cursor = db.cursor()

        post_content = request.form.get('description') # Renamed from post_content to description to match schema
        visibility = request.form.get('visibility')
        media_path = None
        media_type = None

        # Ensure the posts upload directory exists
        posts_folder = app.config['POSTS_FOLDER']
        if not os.path.exists(posts_folder):
            os.makedirs(posts_folder)

        if 'mediaFile' in request.files: # Changed from media_file to mediaFile to match HTML form
            file = request.files['mediaFile']
            if file and file.filename != '':
                # Using the save_uploaded_file helper for consistency
                media_path = save_uploaded_file(file, app.config['POSTS_FOLDER'])
                if media_path:
                    # Determine media_type based on file extension
                    file_extension = file.filename.rsplit('.', 1)[1].lower()
                    if file_extension in ALLOWED_IMAGE_EXTENSIONS:
                        media_type = 'image'
                    elif file_extension in ALLOWED_VIDEO_EXTENSIONS:
                        media_type = 'video'
                    # No else for audio, as posts typically don't directly embed audio for main media
                else:
                    flash('Invalid media file type.', 'danger')
                    return render_template('create_post.html', title='Create Post', current_year=current_year)
            
        if not post_content and not media_path:
            flash('Post cannot be empty. Please add text or media.', 'danger')
            return render_template('create_post.html', title='Create Post', current_year=current_year)


        try:
            # Insert the post into the database
            cursor.execute("INSERT INTO posts (user_id, description, media_path, media_type, visibility) VALUES (?, ?, ?, ?, ?)",
                           (current_user.id, post_content, media_path, media_type, visibility))
            db.commit()
            flash('Post uploaded successfully!', 'success')
            
            # Redirect to the home page after success
            return redirect(url_for('home'))

        except sqlite3.IntegrityError as e:
            db.rollback()
            app.logger.error(f"Integrity Error while posting: {e}")
            flash('Database error. Post could not be created.', 'danger')
            return render_template('create_post.html', title='Create Post', current_year=current_year)
        except Exception as e:
            db.rollback()
            app.logger.error(f"Error creating post: {e}")
            flash('Failed to create post.', 'danger')
            return render_template('create_post.html', title='Create Post', current_year=current_year)

    return render_template('create_post.html', title='Create Post', current_year=current_year)


@app.route('/create_reel', methods=['GET', 'POST']) # Changed URL path to avoid conflict
@login_required
def create_reel():
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    if request.method == 'POST':
        description = request.form.get('description', '').strip()
        # Visibility is fixed to public for reels as per requirements
        visibility = 'public'
        media_file = request.files.get('mediaFile')
        audio_file = request.files.get('audioFile') # For photo reels

        media_path = None
        media_type = None
        audio_path = None

        if media_file and media_file.filename != '':
            media_path = save_uploaded_file(media_file, app.config['REEL_MEDIA_FOLDER'])
            if media_path:
                if media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
                    media_type = 'image'
                elif media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS:
                    media_type = 'video'
            else:
                flash('Invalid media file type for reel.', 'danger')
                return render_template('create_reel.html', form_data=request.form.to_dict(), current_year=current_year)
        else:
            flash('Reel requires a photo or video.', 'danger')
            return render_template('create_reel.html', form_data=request.form.to_dict(), current_year=current_year)

        # If it's an image reel, handle optional audio
        if media_type == 'image' and audio_file and audio_file.filename != '':
            audio_path = save_uploaded_file(audio_file, app.config['VOICE_NOTES_FOLDER']) # Reusing folder
            if not audio_path:
                flash('Invalid audio file type for reel.', 'danger')
                return render_template('create_reel.html', form_data=request.form.to_dict(), current_year=current_year)

        db = get_db()
        try:
            db.execute(
                """
                INSERT INTO reels (user_id, description, media_path, media_type, audio_path, visibility, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (current_user.id, description, media_path, media_type, audio_path, visibility, datetime.now(timezone.utc))
            )
            db.commit()
            flash('Reel created successfully!', 'success')
            return redirect(url_for('home')) # Redirect to reels feed
        except Exception as e:
            flash(f'An error occurred while creating your reel: {e}', 'danger')
            db.rollback()
            return render_template('create_reel.html', form_data=request.form.to_dict(), current_year=current_year)

    return render_template('create_reel.html', current_year=current_year)


@app.route('/reels') # This is now exclusively for viewing reels
@login_required
def reels():
    db = get_db()
    
    all_reels_data = db.execute(
        """
        SELECT r.*, u.username, m.profilePhoto AS owner_profile_pic, u.originalName AS owner_original_name
        FROM reels r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE r.visibility = 'public' OR (r.visibility = 'friends' AND EXISTS (
            SELECT 1 FROM friendships WHERE ((user1_id = ? AND user2_id = r.user_id) OR (user1_id = r.user_id AND user2_id = ?)) AND status = 'accepted'
        ))
        ORDER BY r.timestamp DESC
        """,
        (current_user.id, current_user.id)
    ).fetchall()

    reels_to_display = []
    for reel_item in all_reels_data:
        reel_dict = dict(reel_item)
        reel_dict['owner_profile_pic'] = get_member_profile_pic(reel_dict['user_id'])
        
        # Determine if current_user is following the reel's poster
        is_following_poster = False
        if current_user.id != reel_dict['user_id']: # Cannot follow yourself
            friendship_status = db.execute(
                """
                SELECT status FROM friendships
                WHERE (user1_id = ? AND user2_id = ?)
                """,
                (current_user.id, reel_dict['user_id'])
            ).fetchone()
            if friendship_status and friendship_status['status'] == 'accepted':
                is_following_poster = True
        
        reel_dict['is_following_poster'] = is_following_poster
        reels_to_display.append(reel_dict)

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('reels.html', reels=reels_to_display, current_year=current_year)


@app.route('/create_story', methods=['GET', 'POST'])
@login_required
def create_story():
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    if request.method == 'POST':
        description = request.form.get('description', '').strip()
        # Visibility is fixed to friends for stories
        visibility = 'friends'

        media_path = None
        media_type = None # 'image', 'video', 'audio' (for voice note)
        background_audio_path = None # For photos with separate audio

        # Prioritize camera captures, then uploaded files, then voice notes
        camera_captured_data = request.form.get('cameraCapturedData')
        camera_captured_media_type = request.form.get('cameraCapturedMediaType')
        voice_note_data = request.form.get('voiceNoteData')
        media_file = request.files.get('mediaFile') # Uploaded file
        audio_file = request.files.get('audioFile') # Background audio for photo story

        # 1. Handle camera captured data (photo or video)
        if camera_captured_data:
            header, encoded = camera_captured_data.split(",", 1)
            decoded_data = base64.b64decode(encoded)
            file_extension = 'png' if 'image' in camera_captured_media_type else 'webm'
            unique_filename = f"{uuid.uuid4()}.{file_extension}"
            file_path = os.path.join(app.config['STORY_MEDIA_FOLDER'], unique_filename)
            full_path_for_db = os.path.join('static', 'uploads', os.path.basename(app.config['STORY_MEDIA_FOLDER']), unique_filename)

            with open(file_path, 'wb') as f:
                f.write(decoded_data)
            media_path = full_path_for_db
            media_type = 'image' if 'image' in camera_captured_media_type else 'video'

        # 2. Handle uploaded media file (if no camera data)
        elif media_file and media_file.filename != '':
            media_path = save_uploaded_file(media_file, app.config['STORY_MEDIA_FOLDER'])
            if media_path:
                if media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
                    media_type = 'image'
                elif media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS:
                    media_type = 'video'
            else:
                flash('Invalid uploaded media file type for story.', 'danger')
                return render_template('create_story.html', form_data=request.form.to_dict(), current_year=current_year)

        # 3. Handle voice note (if no other media)
        elif voice_note_data:
            # Voice note data is also base64 (or data URL from frontend)
            header, encoded = voice_note_data.split(",", 1)
            decoded_data = base64.b64decode(encoded)
            unique_filename = f"{uuid.uuid4()}.webm" # Assuming webm format
            file_path = os.path.join(app.config['VOICE_NOTES_FOLDER'], unique_filename)
            full_path_for_db = os.path.join('static', 'uploads', os.path.basename(app.config['VOICE_NOTES_FOLDER']), unique_filename)

            with open(file_path, 'wb') as f:
                f.write(decoded_data)
            media_path = full_path_for_db
            media_type = 'audio'
        else:
            flash('Story requires a photo, video, or voice note.', 'danger')
            return render_template('create_story.html', form_data=request.form.to_dict(), current_year=current_year)

        # Handle background audio if main media is an image
        if media_type == 'image' and audio_file and audio_file.filename != '':
            background_audio_path = save_uploaded_file(audio_file, app.config['VOICE_NOTES_FOLDER'])
            if not background_audio_path:
                flash('Invalid background audio file type for story.', 'danger')
                return render_template('create_story.html', form_data=request.form.to_dict(), current_year=current_year)


        db = get_db()
        try:
            # Stories expire in 24 hours
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
            db.execute(
                """
                INSERT INTO stories (user_id, description, media_path, media_type, background_audio_path, visibility, timestamp, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (current_user.id, description, media_path, media_type, background_audio_path, visibility, datetime.now(timezone.utc), expires_at)
            )
            db.commit()
            flash('Story created successfully! It will expire in 24 hours.', 'success')
            return redirect(url_for('home')) # Redirect to home/stories feed
        except Exception as e:
            flash(f'An error occurred while creating your story: {e}', 'danger')
            app.logger.error(f"Error creating story: {e}")
            db.rollback()
            return render_template('create_story.html', form_data=request.form.to_dict(), current_year=current_year)

    return render_template('create_story.html', current_year=current_year)

# --- Search Route ---
@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('q', '').strip()
    db = get_db()
    
    search_results = []
    if query:
        # Search users
        users = db.execute(
            """
            SELECT u.id, u.username, u.originalName, m.profilePhoto
            FROM users u
            LEFT JOIN members m ON u.id = m.user_id
            WHERE u.username LIKE ? OR u.originalName LIKE ?
            ORDER BY u.originalName
            """,
            (f'%{query}%', f'%{query}%')
        ).fetchall()
        for user in users:
            user_dict = dict(user)
            user_dict['profilePhoto'] = get_member_profile_pic(user_dict['id'])
            search_results.append({'type': 'user', 'data': user_dict})
        
        # Search groups
        groups = db.execute(
            """
            SELECT g.id, g.name, g.description, g.profilePhoto
            FROM groups g
            WHERE g.name LIKE ? OR g.description LIKE ?
            ORDER BY g.name
            """,
            (f'%{query}%', f'%{query}%')
        ).fetchall()
        for group in groups:
            group_dict = dict(group)
            group_dict['profilePhoto'] = group_dict['profilePhoto'] or url_for('static', filename='img/default_group.png')
            search_results.append({'type': 'group', 'data': group_dict})

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('search.html', query=query, search_results=search_results, current_year=current_year)


# --- Dashboard & Static Pages ---
# 'dashboard.html' is not on the user's list. Redirect to my_profile as the closest personal overview.
@app.route('/dashboard')
@login_required
def dashboard_redirect():
    flash('Dashboard is not available. Redirecting to your profile.', 'info')
    return redirect(url_for('my_profile'))


# Removed: @app.route('/status_feed') and associated function
# as 'status_feed.html' is not on the user's list.
# Any status functionality will be integrated directly into 'my_profile.html' where relevant.


# Removed: @app.route('/upload_status_video', methods=['POST']) and associated function
# as status_feed is removed and this was for temporary videos which can be handled by stories.

# Removed: @app.route('/admin_delete_user_status/<int:member_id>', methods=['POST'])
# as status_feed and individual statuses are not explicitly rendered via a template.


# Removed: @app.route('/success') and associated function
# as 'success.html' is not on the user's list.
# All successes will use flash messages and redirect.


# --- Games ---
# Removed: All game-related routes and functions as per user's explicit request.


# --- Notifications ---
@app.route('/notifications')
@login_required
def notifications():
    db = get_db()
    user_notifications = db.execute(
        "SELECT * FROM notifications WHERE receiver_id = ? ORDER BY timestamp DESC",
        (current_user.id,)
    ).fetchall()

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('notifications.html', notifications=user_notifications, current_year=current_year)

@app.route('/api/notifications/mark_all_read', methods=['POST'])
@login_required
def api_mark_all_notifications_read():
    db = get_db()
    try:
        db.execute("UPDATE notifications SET is_read = 1 WHERE receiver_id = ?", (current_user.id,))
        db.commit()
        return jsonify({'success': True, 'message': 'All notifications marked as read.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error marking all notifications as read: {e}")
        return jsonify({'success': False, 'message': 'Failed to mark all notifications as read.'}), 500

@app.route('/api/notifications/mark_read/<int:notification_id>', methods=['POST'])
@login_required
def api_mark_single_notification_read(notification_id):
    db = get_db()
    try:
        db.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND receiver_id = ?", (notification_id, current_user.id))
        db.commit()
        return jsonify({'success': True, 'message': 'Notification marked as read.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error marking single notification as read: {e}")
        return jsonify({'success': False, 'message': 'Failed to mark notification as read.'}), 500


# --- Menu & Settings ---
@app.route('/menu')
@login_required
def menu():
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('menu.html', current_year=current_year)

@app.route('/account_status')
@login_required
def account_status():
    db = get_db()
    # Fetch warnings for the current user
    warnings = db.execute(
        "SELECT * FROM warnings WHERE user_id = ? AND status = 'active' ORDER BY timestamp DESC",
        (current_user.id,)
    ).fetchall()

    # Removed 'strikes' as it's not explicitly in the schema or document.
    strikes = [] # Placeholder if not implemented yet

    # Check for active bans
    user_data = db.execute("SELECT ban_status, ban_ends_at, ban_reason FROM users WHERE id = ?", (current_user.id,)).fetchone()
    
    temporary_ban = None
    permanent_ban = None
    if user_data and user_data['ban_status'] == 'temporary' and user_data['ban_ends_at'] and datetime.fromisoformat(user_data['ban_ends_at']) > datetime.now(timezone.utc):
        temporary_ban = {'ends_at': user_data['ban_ends_at'], 'reason': user_data['ban_reason']}
    elif user_data and user_data['ban_status'] == 'permanent':
        permanent_ban = {'reason': user_data['ban_reason']}

    # Determine overall account health
    is_good = not (temporary_ban or permanent_ban or len(warnings) > 0 or len(strikes) > 0)

    account_health = {'is_good': is_good}
    account_status_details = {
        'warnings': warnings,
        'strikes': strikes,
        'temporary_ban': temporary_ban,
        'permanent_ban': permanent_ban,
        # Removed 'created_at' and 'last_policy_review' as they were not essential for account status logic
    }
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('account_status.html', account_health=account_health, account_status=account_status_details, current_year=current_year)


@app.route('/support_inbox')
@login_required
def support_inbox():
    db = get_db()
    admin_user_id = get_admin_user_id()
    if not admin_user_id:
        flash('Support system not fully configured (admin user not found).', 'danger')
        return redirect(url_for('menu'))

    # Find or create a 1-on-1 chat room between current_user and admin_user
    chat_room_id_row = db.execute(
        """
        SELECT cr.id
        FROM chat_rooms cr
        JOIN chat_room_members crm1 ON cr.id = crm1.chat_room_id
        JOIN chat_room_members crm2 ON cr.id = crm2.chat_room_id
        WHERE crm1.user_id = ? AND crm2.user_id = ? AND cr.is_group = 0
        """,
        (current_user.id, admin_user_id)
    ).fetchone()

    if not chat_room_id_row:
        # Create a new chat room for support
        cursor = db.execute("INSERT INTO chat_rooms (is_group, created_by) VALUES (?, ?)", (0, current_user.id))
        chat_room_id = cursor.lastrowid
        db.execute("INSERT INTO chat_room_members (chat_room_id, user_id) VALUES (?, ?)", (chat_room_id, current_user.id))
        db.execute("INSERT INTO chat_room_members (chat_room_id, user_id) VALUES (?, ?)", (chat_room_id, admin_user_id))
        db.commit()
        flash('A new support ticket has been opened.', 'info')
    else:
        chat_room_id = chat_room_id_row['id']

    # Fetch messages for this support chat
    messages = db.execute(
        """
        SELECT cm.*, u.username, m.profilePhoto
        FROM chat_messages cm
        JOIN users u ON cm.sender_id = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE cm.chat_room_id = ?
        ORDER BY cm.timestamp
        """,
        (chat_room_id,)
    ).fetchall()

    # Mark messages as read for current user
    db.execute(
        "UPDATE chat_room_members SET last_read_message_timestamp = ? WHERE chat_room_id = ? AND user_id = ?",
        (datetime.now(timezone.utc), chat_room_id, current_user.id)
    )
    db.commit()

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('support_inbox.html', messages=messages, current_user_id=current_user.id, support_chat_id=chat_room_id, current_year=current_year)


@app.route('/api/support/send_message/<int:chat_id>', methods=['POST'])
@login_required
def api_send_support_message_user(chat_id):
    db = get_db()
    admin_user_id = get_admin_user_id()
    if not admin_user_id:
        return jsonify({'success': False, 'message': 'Support system not configured.'}), 500

    # Ensure this chat is indeed a 1-on-1 chat between current_user and admin
    is_valid_support_chat = db.execute(
        """
        SELECT COUNT(*)
        FROM chat_room_members crm1
        JOIN chat_room_members crm2 ON crm1.chat_room_id = crm2.chat_room_id
        WHERE crm1.chat_room_id = ? AND crm1.user_id = ? AND crm2.user_id = ?
        """,
        (chat_id, current_user.id, admin_user_id)
    ).fetchone()[0] == 2

    if not is_valid_support_chat:
        return jsonify({'success': False, 'message': 'Invalid support chat ID.'}), 403

    content = request.json.get('content')
    if not content:
        return jsonify({'success': False, 'message': 'Message content cannot be empty.'}), 400

    try:
        cursor = db.execute(
            "INSERT INTO chat_messages (chat_room_id, sender_id, content, timestamp, is_ai_message) VALUES (?, ?, ?, ?, ?)",
            (chat_id, current_user.id, content, datetime.now(timezone.utc), 0) # This message is from user, not AI
        )
        message_id = cursor.lastrowid
        db.commit()

        new_message = db.execute(
            "SELECT id, sender_id, content, timestamp FROM chat_messages WHERE id = ?", (message_id,)
        ).fetchone()

        # Send notification to admin user
        admin_user = load_user(admin_user_id)
        if admin_user:
            message_text = f"<strong>{current_user.original_name}</strong> sent a new support message: {content[:50]}"
            send_system_notification(
                admin_user_id,
                message_text,
                link=url_for('admin_support_chat', chat_id=chat_id),
                type='message_received'
            )

        return jsonify({'success': True, 'message': dict(new_message)})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error sending support message (user side): {e}")
        return jsonify({'success': False, 'message': 'Failed to send message.'}), 500


@app.route('/terms_and_policies')
def terms_and_policies():
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('terms_and_policies.html', current_year=current_year)


@app.route('/settings')
@login_required
def settings():
    db = get_db()
    # Fetch user settings, or default values if not found
    user_settings = db.execute("SELECT language, theme_preference, profile_locking, posts_visibility, allow_post_sharing, allow_post_comments, reels_visibility, allow_reel_sharing, allow_reel_comments, notify_friend_requests, notify_friend_acceptance, notify_post_likes, notify_new_messages, notify_group_invites, notify_comments, notify_tags FROM users WHERE id = ?", (current_user.id,)).fetchone()

    if not user_settings:
        # Default settings if none found
        user_settings = {
            'language': 'en',
            'theme': 'light',
            'profile_locking': False,
            'posts_visibility': 'public',
            'allow_post_sharing': True,
            'allow_post_comments': True,
            'reels_visibility': 'public',
            'allow_reel_sharing': True,
            'allow_reel_comments': True,
            'notify_friend_requests': True,
            'notify_friend_acceptance': True,
            'notify_post_likes': True,
            'notify_new_messages': True,
            'notify_group_invites': True,
            'notify_comments': True,
            'notify_tags': True,
        }
    else:
        # Convert 0/1 to False/True for boolean fields
        user_settings_dict = dict(user_settings)
        user_settings_dict['theme'] = user_settings_dict['theme_preference'] # Map theme_preference to 'theme'
        boolean_fields = [
            'profile_locking', 'allow_post_sharing', 'allow_post_comments',
            'allow_reel_sharing', 'allow_reel_comments', 'notify_friend_requests',
            'notify_friend_acceptance', 'notify_post_likes', 'notify_new_messages',
            'notify_group_invites', 'notify_comments', 'notify_tags'
        ]
        for field in boolean_fields:
            if field in user_settings_dict:
                user_settings_dict[field] = bool(user_settings_dict[field])
        user_settings = user_settings_dict


    # Pass user's current chat background for display if any
    current_chat_background = current_user.chat_background_image_path
    
    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template(
        'settings.html',
        user_settings=user_settings,
        current_chat_background=current_chat_background,
        current_year=current_year
    )


@app.route('/blocked_users')
@login_required
def blocked_users():
    db = get_db()
    blocked_list = db.execute(
        """
        SELECT bu.blocked_id, u.username, u.originalName, m.profilePhoto
        FROM blocked_users bu
        JOIN users u ON bu.blocked_id = u.id
        LEFT JOIN members m ON u.id = m.user_id
        WHERE bu.blocker_id = ?
        ORDER BY u.originalName
        """,
        (current_user.id,)
    ).fetchall()

    display_blocked_users = []
    for user in blocked_list:
        user_dict = dict(user)
        user_dict['profile_pic'] = get_member_profile_pic(user_dict['blocked_id'])
        user_dict['id'] = user_dict['blocked_id'] # Map blocked_id to id for convenience in template
        display_blocked_users.append(user_dict)

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template('blocked_users.html', blocked_users=display_blocked_users, current_year=current_year)


@app.route('/api/block_user/<int:user_id_to_block>', methods=['POST'])
@login_required
def api_block_user(user_id_to_block):
    db = get_db()
    if current_user.id == user_id_to_block:
        return jsonify({'success': False, 'message': 'You cannot block yourself.'}), 400

    # Check if already blocked
    already_blocked = db.execute(
        "SELECT 1 FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
        (current_user.id, user_id_to_block)
    ).fetchone()

    if already_blocked:
        return jsonify({'success': False, 'message': 'User is already blocked.'}), 400

    try:
        db.execute(
            "INSERT INTO blocked_users (blocker_id, blocked_id, timestamp) VALUES (?, ?, ?)",
            (current_user.id, user_id_to_block, datetime.now(timezone.utc))
        )
        db.commit()
        # Also remove friendship if they were friends
        db.execute(
            """
            DELETE FROM friendships
            WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
            """,
            (current_user.id, user_id_to_block, user_id_to_block, current_user.id)
        )
        db.commit()
        return jsonify({'success': True, 'message': 'User blocked successfully.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error blocking user: {e}")
        return jsonify({'success': False, 'message': 'Failed to block user.'}), 500


@app.route('/api/unblock_user/<int:user_id_to_unblock>', methods=['POST'])
@login_required
def api_unblock_user(user_id_to_unblock):
    db = get_db()
    try:
        db.execute(
            "DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
            (current_user.id, user_id_to_unblock)
        )
        db.commit()
        return jsonify({'success': True, 'message': 'User unblocked successfully.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error unblocking user: {e}")
        return jsonify({'success': False, 'message': 'Failed to unblock user.'}), 500


# --- Admin Dashboard Routes ---

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    db = get_db()

    # --- Overview Counts ---
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    group_count = db.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
    post_count = db.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    reel_count = db.execute("SELECT COUNT(*) FROM reels").fetchone()[0]
    story_count = db.execute("SELECT COUNT(*) FROM stories").fetchone()[0]
    pending_reports_count = db.execute("SELECT COUNT(*) FROM reports WHERE status = 'pending'").fetchone()[0]
    active_warnings_count = db.execute("SELECT COUNT(*) FROM warnings WHERE status = 'active'").fetchone()[0]
    active_bans_count = db.execute("SELECT COUNT(*) FROM users WHERE ban_status != 'none'").fetchone()[0]
    
    counts = {
        'user_count': user_count,
        'group_count': group_count,
        'post_count': post_count,
        'reel_count': reel_count,
        'story_count': story_count,
        'pending_reports_count': pending_reports_count,
        'active_warnings_count': active_warnings_count,
        'active_bans_count': active_bans_count
    }

    # --- All Users for Management ---
    all_users_data = db.execute(
        """
        SELECT u.id, u.username, u.originalName AS real_name, m.profilePhoto,
               u.ban_status AS is_banned_status,
               (SELECT COUNT(*) FROM warnings WHERE user_id = u.id AND status = 'active') AS warnings_count
        FROM users u
        LEFT JOIN members m ON u.id = m.user_id
        ORDER BY u.username
        """
    ).fetchall()
    all_users = []
    for user_data in all_users_data:
        user_dict = dict(user_data)
        user_dict['profile_pic'] = get_member_profile_pic(user_dict['id'])
        user_dict['is_banned'] = user_dict['is_banned_status'] != 'none'
        all_users.append(user_dict)


    # --- All Groups for Management ---
    all_groups_data = db.execute(
        """
        SELECT g.id, g.name, g.profilePhoto,
               (SELECT COUNT(*) FROM chat_room_members WHERE chat_room_id = g.chat_room_id) AS member_count,
               g.ban_status AS is_banned_status,
               (SELECT COUNT(*) FROM reports WHERE reported_item_type = 'group' AND reported_item_id = g.id AND status = 'pending') AS reports_count
        FROM groups g
        ORDER BY g.name
        """
    ).fetchall()
    all_groups = []
    for group_data in all_groups_data:
        group_dict = dict(group_data)
        group_dict['profile_pic'] = group_dict['profilePhoto'] or url_for('static', filename='img/default_group.png')
        group_dict['is_banned'] = group_dict['is_banned_status'] != 'none'
        all_groups.append(group_dict)

    # --- Pending Reports ---
    pending_reports_data = db.execute(
        """
        SELECT r.*,
               u_reporter.username AS reported_by_username,
               u_item.username AS reported_item_username,
               g_item.name AS reported_item_name
        FROM reports r
        LEFT JOIN users u_reporter ON r.reported_by_user_id = u_reporter.id
        LEFT JOIN users u_item ON (r.reported_item_type = 'user' AND r.reported_item_id = u_item.id)
        LEFT JOIN groups g_item ON (r.reported_item_type = 'group' AND r.reported_item_id = g_item.id)
        WHERE r.status = 'pending'
        ORDER BY r.timestamp DESC
        """
    ).fetchall()
    pending_reports = [dict(rep) for rep in pending_reports_data]


    # --- Support Chats Overview ---
    admin_user_id = get_admin_user_id()
    support_chats_overview_data = []
    if admin_user_id:
        support_chats_overview_data = db.execute(
            """
            SELECT
                cr.id AS chat_id,
                u_other.id AS user_id,
                u_other.username AS user_username,
                u_other.originalName AS user_real_name,
                m_other.profilePhoto AS user_profile_pic,
                (SELECT content FROM chat_messages WHERE chat_room_id = cr.id ORDER BY timestamp DESC LIMIT 1) AS last_message_content,
                (SELECT COUNT(*) FROM chat_messages cm JOIN chat_room_members crm ON cm.chat_room_id = crm.chat_room_id WHERE crm.chat_room_id = cr.id AND cm.sender_id != ? AND cm.timestamp > crm.last_read_message_timestamp AND crm.user_id = ?) AS unread_admin_messages_count
            FROM chat_rooms cr
            JOIN chat_room_members crm_admin ON cr.id = crm_admin.chat_room_id AND crm_admin.user_id = ?
            JOIN chat_room_members crm_user ON cr.id = crm_user.chat_room_id AND crm_user.user_id != ?
            JOIN users u_other ON crm_user.user_id = u_other.id
            LEFT JOIN members m_other ON u_other.id = m_other.user_id
            WHERE cr.is_group = 0
            ORDER BY (SELECT MAX(timestamp) FROM chat_messages WHERE chat_room_id = cr.id) DESC
            """,
            (admin_user_id, admin_user_id, admin_user_id, admin_user_id) # The subquery needs the admin_user_id for sender_id != ? and crm.user_id = ?
        ).fetchall()

    support_chats_overview = []
    for chat in support_chats_overview_data:
        chat_dict = dict(chat)
        chat_dict['user_profile_pic'] = get_member_profile_pic(chat_dict['user_id'])
        chat_dict['last_message_snippet'] = (chat_dict['last_message_content'][:50] + '...') if chat_dict['last_message_content'] and len(chat_dict['last_message_content']) > 50 else (chat_dict['last_message_content'] or "No messages yet.")
        support_chats_overview.append(chat_dict)

    # Pass the current year to the template
    current_year = datetime.now(timezone.utc).year
    return render_template(
        'admin_dashboard.html',
        counts=counts,
        all_users=all_users,
        all_groups=all_groups,
        pending_reports=pending_reports,
        support_chats_overview=support_chats_overview,
        current_year=current_year
    )


@app.route('/api/admin/send_support_message/<int:chat_id>', methods=['POST'])
@admin_required
def api_admin_send_support_message(chat_id):
    db = get_db()
    admin_user_id = get_admin_user_id()
    if not admin_user_id:
        return jsonify({'success': False, 'message': 'Admin user not found.'}), 500

    # Ensure this chat is a 1-on-1 chat between current admin and a user
    chat_room_members = db.execute(
        "SELECT user_id FROM chat_room_members WHERE chat_room_id = ?", (chat_id,)
    ).fetchall()
    
    other_user_id = None
    for member in chat_room_members:
        if member['user_id'] != admin_user_id:
            other_user_id = member['user_id']
            break

    if not other_user_id: # Or if len(chat_room_members) != 2
        return jsonify({'success': False, 'message': 'Invalid support chat ID or missing user.'}), 403

    content = request.json.get('content')
    if not content:
        return jsonify({'success': False, 'message': 'Message content cannot be empty.'}), 400

    try:
        cursor = db.execute(
            "INSERT INTO chat_messages (chat_room_id, sender_id, content, timestamp, is_ai_message) VALUES (?, ?, ?, ?, ?)",
            (chat_id, admin_user_id, content, datetime.now(timezone.utc), 0) # Admin is not AI
        )
        message_id = cursor.lastrowid
        db.commit()

        new_message = db.execute(
            "SELECT id, sender_id, content, timestamp FROM chat_messages WHERE id = ?", (message_id,)
        ).fetchone()

        # Send notification to the user in the support chat
        user_for_chat_obj = load_user(other_user_id)
        if user_for_chat_obj:
            message_text = f"Admin sent a response to your support ticket: {content[:50]}"
            send_system_notification(
                other_user_id,
                message_text,
                link=url_for('support_inbox'),
                type='message_received' # Re-using type, could be 'admin_response'
            )

        return jsonify({'success': True, 'message': dict(new_message)})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error sending support message (admin side): {e}")
        return jsonify({'success': False, 'message': 'Failed to send message.'}), 500


@app.route('/api/admin/warn_user/<int:user_id>', methods=['POST'])
@admin_required
def api_admin_warn_user(user_id):
    db = get_db()
    title = request.json.get('title')
    description = request.json.get('description')

    if not title or not description:
        return jsonify({'success': False, 'message': 'Title and description are required for a warning.'}), 400

    try:
        db.execute(
            "INSERT INTO warnings (user_id, title, description, timestamp, status) VALUES (?, ?, ?, ?, 'active')",
            (user_id, title, description, datetime.now(timezone.utc))
        )
        db.commit()
        # Send system notification to the warned user
        warned_user = load_user(user_id)
        if warned_user:
            notification_message = f'You have received a warning: <strong>{title}</strong>. Reason: {description}'
            send_system_notification(
                user_id,
                notification_message,
                link=url_for('account_status'),
                type='warning'
            )
        return jsonify({'success': True, 'message': 'User warned successfully.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error warning user: {e}")
        return jsonify({'success': False, 'message': 'Failed to warn user.'}), 500


@app.route('/api/admin/ban_user/<int:user_id>', methods=['POST'])
@admin_required
def api_admin_ban_user(user_id):
    db = get_db()
    reason = request.json.get('reason')
    duration = request.json.get('duration') # 'temporary' or 'permanent'
    days = request.json.get('days') # Only for temporary ban

    if not reason:
        return jsonify({'success': False, 'message': 'Reason for ban is required.'}), 400

    ban_ends_at = None
    if duration == 'temporary':
        if not days or not isinstance(days, int) or days < 1:
            return jsonify({'success': False, 'message': 'Valid number of days is required for temporary ban.'}), 400
        ban_ends_at = datetime.now(timezone.utc) + timedelta(days=days)
        ban_status = 'temporary'
    elif duration == 'permanent':
        ban_status = 'permanent'
    else:
        return jsonify({'success': False, 'message': 'Invalid ban duration.'}), 400

    try:
        db.execute(
            "UPDATE users SET ban_status = ?, ban_reason = ?, ban_starts_at = ?, ban_ends_at = ? WHERE id = ?",
            (ban_status, reason, datetime.now(timezone.utc), ban_ends_at, user_id)
        )
        db.commit()
        # Send system notification to the banned user
        banned_user = load_user(user_id)
        if banned_user:
            notification_message = f'Your account has been {ban_status}ly banned. Reason: {reason}.'
            if ban_ends_at:
                notification_message += f' Ban ends: {ban_ends_at.strftime("%Y-%m-%d %H:%M UTC")}'
            send_system_notification(
                user_id,
                notification_message,
                link=url_for('account_status'),
                type='danger' # Or 'ban_notification'
            )
        return jsonify({'success': True, 'message': 'User banned successfully.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error banning user: {e}")
        return jsonify({'success': False, 'message': 'Failed to ban user.'}), 500


@app.route('/api/admin/unban_user/<int:user_id>', methods=['POST'])
@admin_required
def api_admin_unban_user(user_id):
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET ban_status = 'none', ban_reason = NULL, ban_starts_at = NULL, ban_ends_at = NULL WHERE id = ?",
            (user_id,)
        )
        db.commit()
        # Send system notification to the unbanned user
        unbanned_user = load_user(user_id)
        if unbanned_user:
            notification_message = 'Your account ban has been lifted. You can now access all features.'
            send_system_notification(
                user_id,
                notification_message,
                link=url_for('home'),
                type='info' # Or 'unban_notification'
            )
        return jsonify({'success': True, 'message': 'User unbanned successfully.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error unblocking user: {e}")
        return jsonify({'success': False, 'message': 'Failed to unblock user.'}), 500


@app.route('/api/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def api_admin_delete_user(user_id):
    db = get_db()
    # Prevent admin from deleting themselves
    if user_id == current_user.id:
        return jsonify({'success': False, 'message': 'You cannot delete your own admin account through this interface.'}), 403

    try:
        # Cascade deletes should handle most related data if defined in schema.sql
        # Otherwise, explicit deletes would be needed for:
        # members, friendships, chat_room_members, chat_messages (if sender_id),
        # posts, reels, stories, reports (reporter or reported), warnings, blocked_users
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        # No notification to a deleted user
        return jsonify({'success': True, 'message': 'User account and all associated data deleted permanently.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'success': False, 'message': 'Failed to delete user.'}), 500


@app.route('/api/admin/ban_group/<int:group_id>', methods=['POST'])
@admin_required
def api_admin_ban_group(group_id):
    db = get_db()
    # For simplicity, assuming permanent ban and generic reason for groups from admin_dashboard
    reason = request.json.get('reason', 'Violation of community guidelines.')
    duration = request.json.get('duration', 'permanent')

    ban_ends_at = None
    ban_status = duration
    if duration == 'temporary':
        days = request.json.get('days', 7)
        if not isinstance(days, int) or days < 1:
             return jsonify({'success': False, 'message': 'Valid number of days is required for temporary ban.'}), 400
        ban_ends_at = datetime.now(timezone.utc) + timedelta(days=days)

    try:
        db.execute(
            "UPDATE groups SET ban_status = ?, ban_reason = ?, ban_starts_at = ?, ban_ends_at = ? WHERE id = ?",
            (ban_status, reason, datetime.now(timezone.utc), ban_ends_at, group_id)
        )
        db.commit()
        # Notify group members (optional but good practice)
        group = db.execute("SELECT name, chat_room_id FROM groups WHERE id = ?", (group_id,)).fetchone()
        if group:
            members = db.execute("SELECT user_id FROM chat_room_members WHERE chat_room_id = ?", (group['chat_room_id'],)).fetchall()
            for member in members:
                message = f'The group "<strong>{group["name"]}</strong>" has been {ban_status}ly banned. Reason: {reason}.'
                send_system_notification(
                    member['user_id'],
                    message,
                    link=url_for('home'),
                    type='danger'
                )
        return jsonify({'success': True, 'message': 'Group banned successfully.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error banning group: {e}")
        return jsonify({'success': False, 'message': 'Failed to ban group.'}), 500


@app.route('/api/admin/unban_group/<int:group_id>', methods=['POST'])
@admin_required
def api_admin_unban_group(group_id):
    db = get_db()
    try:
        db.execute(
            "UPDATE groups SET ban_status = 'none', ban_reason = NULL, ban_starts_at = NULL, ban_ends_at = NULL WHERE id = ?",
            (group_id,)
        )
        db.commit()
        # Notify group members
        group = db.execute("SELECT name, chat_room_id FROM groups WHERE id = ?", (group_id,)).fetchone()
        if group:
            members = db.execute("SELECT user_id FROM chat_room_members WHERE chat_room_id = ?", (group['chat_room_id'],)).fetchall()
            for member in members:
                message = f'The ban on group "<strong>{group["name"]}</strong>" has been lifted. You can now access it.'
                send_system_notification(
                    member['user_id'],
                    message,
                    link=url_for('view_group_profile', group_id=group_id),
                    type='info'
                )
        return jsonify({'success': True, 'message': 'Group unbanned successfully.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error unbanning group: {e}")
        return jsonify({'success': False, 'message': 'Failed to unban group.'}), 500


@app.route('/api/admin/delete_group/<int:group_id>', methods=['POST'])
@admin_required
def api_admin_delete_group(group_id):
    db = get_db()
    try:
        # Fetch group chat_room_id for cascade deletion
        group_chat_room_id = db.execute("SELECT chat_room_id FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not group_chat_room_id:
            return jsonify({'success': False, 'message': 'Group not found.'}), 404

        # Delete from groups table (cascade will handle chat_room_members and chat_messages)
        db.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        # Also delete the chat_room itself
        db.execute("DELETE FROM chat_rooms WHERE id = ?", (group_chat_room_id['chat_room_id'],))
        db.commit()
        # No notification needed as group is gone
        return jsonify({'success': True, 'message': 'Group and all associated data deleted permanently.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error deleting group {group_id}: {e}")
        return jsonify({'success': False, 'message': 'Failed to delete group.'}), 500


@app.route('/api/admin/handle_report/<int:report_id>/<action>', methods=['POST'])
@admin_required
def api_admin_handle_report(report_id, action):
    db = get_db()
    report = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not report:
        return jsonify({'success': False, 'message': 'Report not found.'}), 404

    reported_item_id = report['reported_item_id']
    reported_item_type = report['reported_item_type']
    # reported_by_user_id = report['reported_by_user_id'] # Not directly used here
    report_reason = report['reason']

    try:
        if action == 'warn':
            # This would typically open a modal to customize the warning
            # For direct action, we issue a generic warning
            if reported_item_type == 'user':
                db.execute(
                    "INSERT INTO warnings (user_id, title, description, timestamp, status) VALUES (?, ?, ?, ?, 'active')",
                    (reported_item_id, 'Reported Content Violation', f'User reported for: {report_reason}', datetime.now(timezone.utc))
                )
                # Notify reported user
                send_system_notification(
                    reported_item_id,
                    f'You received a warning due to a report: {report_reason[:50]}...',
                    link=url_for('account_status'),
                    type='warning'
                )
            # You could add similar logic for groups/posts/reels/stories
            db.execute("UPDATE reports SET status = 'handled', admin_notes = ? WHERE id = ?", ('Warned user/item.', report_id))
            db.commit()
            return jsonify({'success': True, 'message': 'Report handled: item warned.'})

        elif action == 'ban':
            # This would typically open a modal to customize the ban
            # For direct action, we issue a permanent ban
            if reported_item_type == 'user':
                db.execute(
                    "UPDATE users SET ban_status = 'permanent', ban_reason = ?, ban_starts_at = ? WHERE id = ?",
                    (f'Banned due to report: {report_reason}', datetime.now(timezone.utc), reported_item_id)
                )
                # Notify reported user
                send_system_notification(
                    reported_item_id,
                    f'Your account has been permanently banned due to a report: {report_reason[:50]}...',
                    link=url_for('account_status'),
                    type='danger'
                )
            elif reported_item_type == 'group':
                 db.execute(
                    "UPDATE groups SET ban_status = 'permanent', ban_reason = ?, ban_starts_at = ? WHERE id = ?",
                    (f'Banned due to report: {report_reason}', datetime.now(timezone.utc), reported_item_id)
                )
                 # Notify group members
                 group = db.execute("SELECT name, chat_room_id FROM groups WHERE id = ?", (reported_item_id,)).fetchone()
                 if group:
                    members = db.execute("SELECT user_id FROM chat_room_members WHERE chat_room_id = ?", (group['chat_room_id'],)).fetchall()
                    for member in members:
                        message = f'The group "<strong>{group["name"]}</strong>" has been permanently banned due to a report.'
                        send_system_notification(member['user_id'], message, link=url_for('home'), type='danger')
            # Other content types (post, reel, story) would be deleted rather than banned
            db.execute("UPDATE reports SET status = 'handled', admin_notes = ? WHERE id = ?", ('Banned user/item.', report_id))
            db.commit()
            return jsonify({'success': True, 'message': 'Report handled: item banned.'})

        elif action == 'ignore':
            db.execute("UPDATE reports SET status = 'ignored', admin_notes = ? WHERE id = ?", ('No action taken.', report_id))
            db.commit()
            return jsonify({'success': True, 'message': 'Report ignored.'})

        else:
            return jsonify({'success': False, 'message': 'Invalid action for report handling.'}), 400

    except Exception as e:
        db.rollback()
        app.logger.error(f"Error handling report {report_id} with action {action}: {e}")
        return jsonify({'success': False, 'message': 'Failed to handle report.'}), 500


@app.route('/api/admin/broadcast_message', methods=['POST'])
@admin_required
def api_admin_broadcast_message():
    db = get_db()
    message_content = request.json.get('message')

    if not message_content:
        return jsonify({'success': False, 'message': 'Broadcast message cannot be empty.'}), 400

    try:
        all_users = db.execute("SELECT id FROM users WHERE is_admin = 0").fetchall() # Exclude admin users
        for user in all_users:
            send_system_notification(
                user['id'],
                f'<strong>SociaFam Update:</strong> {message_content}',
                link=url_for('notifications'),
                type='system_message'
            )
        db.commit() # Commit all notifications
        return jsonify({'success': True, 'message': 'Broadcast message sent to all users.'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error broadcasting message: {e}")
        return jsonify({'success': False, 'message': 'Failed to send broadcast message.'}), 500


@app.route('/api/admin/post_sociafam_story', methods=['POST'])
@admin_required
def api_admin_post_sociafam_story():
    db = get_db()
    media_file = request.files.get('mediaFile')
    description = request.form.get('description', '').strip()

    if not media_file or media_file.filename == '':
        return jsonify({'success': False, 'message': 'Media file is required for SociaFam Story.'}), 400

    media_path = save_uploaded_file(media_file, app.config['STORY_MEDIA_FOLDER'])
    if not media_path:
        return jsonify({'success': False, 'message': 'Invalid media file type for SociaFam Story.'}), 400

    media_type = None
    if media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
        media_type = 'image'
    elif media_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS:
        media_type = 'video'
    else:
        # Should be caught by save_uploaded_file, but as a fallback
        return jsonify({'success': False, 'message': 'Unsupported media type.'}), 400

    try:
        # Use a special 'admin' user_id or a fixed placeholder for SociaFam stories
        # Assuming admin's own user_id for simplicity, but a distinct 'SociaFam' user could be created.
        admin_user = db.execute("SELECT id FROM users WHERE username = ?", (config.ADMIN_USERNAME,)).fetchone()
        if not admin_user:
            return jsonify({'success': False, 'message': 'Admin user for story posting not found.'}), 500

        # Stories expire in 24 hours
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        db.execute(
            """
            INSERT INTO stories (user_id, description, media_path, media_type, visibility, timestamp, expires_at, is_sociafam_story)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (admin_user['id'], description, media_path, media_type, 'public', datetime.now(timezone.utc), expires_at, 1)
        )
        db.commit()
        # Optionally notify all users of new SociaFam story
        return jsonify({'success': True, 'message': 'SociaFam Story posted successfully!'})
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error posting SociaFam Story: {e}")
        return jsonify({'success': False, 'message': 'Failed to post SociaFam Story.'}), 500


# --- Catch-all for undefined routes ---
# Redirect to home page with a flash message if an unlisted or non-existent page is accessed.
@app.errorhandler(404)
def page_not_found(e):
    flash('The page you requested could not be found.', 'danger')
    return redirect(url_for('home'))

@app.errorhandler(403)
def forbidden(e):
    flash('You do not have permission to access this resource.', 'danger')
    return redirect(url_for('home'))


# Run the app
if __name__ == '__main__':
    # Initialize the database if it doesn't exist
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if not cursor.fetchone():
            init_db()
        else: # If tables exist, still ensure admin is present, useful for existing databases
            # This handles cases where a database exists but the admin user might have been manually deleted
            # or wasn't created in previous versions.
            cursor.execute("SELECT id FROM users WHERE username = ?", (config.ADMIN_USERNAME,))
            if not cursor.fetchone():
                init_db() # Call init_db to create admin even if tables exist
    db.close()
    app.run(debug=True) # Set debug=False in production
