import sqlite3
import os
from datetime import datetime, timedelta, timezone
import random
import string

from flask import Flask, render_template, request, redirect, url_for, g, flash, session, abort, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_moment import Moment

app = Flask(__name__)
# IMPORTANT: Change this secret key in production!
app.config['SECRET_KEY'] = 'your_super_secret_key_change_this_in_production'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'img', 'profile_photos')
app.config['UPLOAD_VIDEO_FOLDER'] = os.path.join('static', 'videos', 'status_videos')
app.config['UPLOAD_CHAT_PHOTO_FOLDER'] = os.path.join('static', 'chat_media', 'photos')
app.config['UPLOAD_CHAT_VIDEO_FOLDER'] = os.path.join('static', 'chat_media', 'videos')
app.config['UPLOAD_CHAT_BACKGROUND_FOLDER'] = os.path.join('static', 'img', 'chat_backgrounds')

app.config['ADMIN_USERNAME'] = 'Henry'  # Admin username
app.config['ADMIN_PASS'] = 'Dec@2003'  # Admin password (CHANGE THIS IN PRODUCTION!)

# Ensure the upload folders exist
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_VIDEO_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_CHAT_PHOTO_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_CHAT_VIDEO_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_CHAT_BACKGROUND_FOLDER']), exist_ok=True)


# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

moment = Moment(app)

@app.context_processor
def inject_global_vars():
    return {
        'now': datetime.utcnow(),
    }

class User(UserMixin):
    def __init__(self, id, username, originalName, password_hash, is_admin=False, theme_preference='light', chat_background_image_path=None, unique_key=None, password_reset_pending=0, reset_request_timestamp=None):
        self.id = id
        self.username = username
        self.originalName = originalName
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.theme_preference = theme_preference
        self.chat_background_image_path = chat_background_image_path
        self.unique_key = unique_key
        self.password_reset_pending = password_reset_pending
        self.reset_request_timestamp = reset_request_timestamp

    @staticmethod
    def get(user_id):
        db = get_db()
        user_data = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_data:
            is_admin_status = (user_data['username'] == app.config['ADMIN_USERNAME'])

            theme_preference = user_data['theme_preference'] if 'theme_preference' in user_data.keys() else 'light'
            chat_background_image_path = user_data['chat_background_image_path'] if 'chat_background_image_path' in user_data.keys() else None
            unique_key = user_data['unique_key'] if 'unique_key' in user_data.keys() else None
            password_reset_pending = user_data['password_reset_pending'] if 'password_reset_pending' in user_data.keys() else 0
            reset_request_timestamp = user_data['reset_request_timestamp'] if 'reset_request_timestamp' in user_data.keys() else None

            return User(user_data['id'], user_data['username'], user_data['originalName'],
                        user_data['password_hash'],
                        is_admin_status, theme_preference,
                        chat_background_image_path,
                        unique_key,
                        password_reset_pending,
                        reset_request_timestamp)
        if user_id == 0 and app.config['ADMIN_USERNAME'] == 'Henry':
            return User(0, app.config['ADMIN_USERNAME'], 'Admin User', generate_password_hash(app.config['ADMIN_PASS']), is_admin=True, theme_preference='dark', chat_background_image_path=None, unique_key='ADM0', password_reset_pending=0, reset_request_timestamp=None)
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

# --- Database Configuration ---
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'family_tree.db')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'webm'}
ALLOWED_CHAT_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_CHAT_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'webm'}
ALLOWED_BACKGROUND_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


# --- Database Functions ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql'), 'r') as f:
            db.executescript(f.read())
        db.commit()
    print("Database initialized.")

# Helper to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_video_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS

def allowed_chat_image_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_CHAT_IMAGE_EXTENSIONS

def allowed_chat_video_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_CHAT_VIDEO_EXTENSIONS

def allowed_background_image_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_BACKGROUND_IMAGE_EXTENSIONS

def generate_unique_key():
    nums = ''.join(random.choices(string.digits, k=2))
    chars = ''.join(random.choices(string.ascii_uppercase, k=2))
    return f"{nums}{chars}"

def calculate_age(dob):
    if not dob:
        return None
    try:
        if isinstance(dob, datetime):
            birth_date = dob.date()
        elif isinstance(dob, str):
            if dob.strip() == '':
                return None
            birth_date = datetime.strptime(dob, '%Y-%m-%d').date()
        else:
            return None

        today = datetime.now().date()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        return age
    except ValueError:
        return None
    except Exception as e:
        print(f"Error calculating age for DOB {dob}: {e}")
        return None

def get_current_user_member_profile():
    if current_user.is_authenticated:
        db = get_db()
        member = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()
        return member
    return None

def get_unread_messages_count():
    if current_user.is_authenticated:
        db = get_db()
        count = db.execute('SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0', (current_user.id,)).fetchone()[0]
        return count
    return 0

def cleanup_expired_videos():
    db = get_db()
    now = datetime.utcnow()
    expiration_threshold = now - timedelta(hours=12)

    expired_videos = db.execute('SELECT id, file_path FROM temporary_videos WHERE upload_timestamp < ?', (expiration_threshold,)).fetchall()

    for video in expired_videos:
        video_path = os.path.join(app.root_path, video['file_path'])
        if os.path.exists(video_path):
            try:
                os.remove(video_path)
                print(f"Deleted expired video file: {video_path}")
            except OSError as e:
                print(f"Error deleting video file {video_path}: {e}")
        else:
            print(f"Expired video file not found on disk, removing DB entry: {video_path}")

        db.execute('DELETE FROM temporary_videos WHERE id = ?', (video['id'],))
        db.commit()
        print(f"Removed expired video DB entry for ID: {video['id']}")

def cleanup_expired_chat_media():
    db = get_db()
    now = datetime.utcnow()
    expiration_threshold = now - timedelta(days=5)

    expired_media = db.execute('SELECT id, file_path FROM chat_media WHERE upload_timestamp < ?', (expiration_threshold,)).fetchall()

    for media in expired_media:
        media_path = os.path.join(app.root_path, media['file_path'])
        if os.path.exists(media_path):
            try:
                os.remove(media_path)
                print(f"Deleted expired chat media file: {media_path}")
            except OSError as e:
                print(f"Error deleting chat media file {media_path}: {e}")
        else:
            print(f"Expired chat media file not found on disk, removing DB entry: {media_path}")

        db.execute('DELETE FROM chat_media WHERE id = ?', (media['id'],))
        db.commit()
        print(f"Removed expired chat media DB entry for ID: {media['id']}")


# --- Routes ---

@app.route('/')
def root_redirect():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('home'))

@app.before_request
def before_request_hook():
    db = get_db() # Assuming get_db() is available globally

    # These lines are reconstructed from the visible parts of your screenshot
    g.user_member = get_current_user_member_profile() # This function is defined elsewhere
    g.unread_messages_count = get_unread_messages_count() # This function is defined elsewhere
    cleanup_expired_videos() # This function is defined elsewhere
    cleanup_expired_chat_media() # This function is defined elsewhere

    if current_user.is_authenticated:
        # These lines are reconstructed from the visible parts of your screenshot
        g.user_theme = current_user.theme_preference
        g.user_chat_background = current_user.chat_background_image_path # This was the problematic line
        g.user_unique_key = current_user.unique_key
    else:
        # These lines are reconstructed from the visible parts of your screenshot
        g.user_theme = request.cookies.get('theme', 'light')
        g.user_chat_background = None
        g.user_unique_key = None

@app.route('/home')
@login_required
def home():
    background_image = url_for('static', filename='img/Nyangabackground.jpg')
    return render_template('index.html',
                           background_image=background_image,
                           member=g.user_member,
                           unread_messages_count=g.unread_messages_count)

# --- User Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    form_data = {}

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin_attempt = request.form.get('admin_login_checkbox')

        db = get_db()

        if is_admin_attempt:
            if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASS']:
                admin_user = User(0, app.config['ADMIN_USERNAME'], 'Admin User', generate_password_hash(app.config['ADMIN_PASS']), is_admin=True, theme_preference='dark', chat_background_image_path=None, unique_key='ADM0', password_reset_pending=0, reset_request_timestamp=None)
                login_user(admin_user)
                flash('Logged in as Admin successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid admin username or password.', 'danger')
                return render_template('login.html', username=username)

        user_data = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user_data:
            user = User.get(user_data['id'])

            if user.password_reset_pending == 1:
                session['reset_username'] = user.username
                flash('Your password reset has been initiated by an administrator. Please set a new password.', 'info')
                return redirect(url_for('set_new_password'))

            if user.reset_request_timestamp and user.password_reset_pending == 0:
                time_since_request = datetime.utcnow() - user.reset_request_timestamp
                if time_since_request <= timedelta(minutes=1):
                    db.execute('UPDATE users SET password_reset_pending = 1, reset_request_timestamp = NULL WHERE id = ?', (user.id,))
                    db.commit()
                    session['reset_username'] = user.username
                    flash('Your password reset has been automatically initiated. Please set a new password.', 'info')
                    return redirect(url_for('set_new_password'))
                else:
                    db.execute('UPDATE users SET reset_request_timestamp = NULL WHERE id = ?', (user.id,))
                    db.commit()
                    flash('Your password reset request has expired. Please submit a new request if needed.', 'warning')

            if check_password_hash(user_data['password_hash'], password):
                member_profile = db.execute('SELECT has_login_access FROM members WHERE user_id = ?', (user.id,)).fetchone()
                if member_profile and member_profile['has_login_access'] == 0:
                    flash('Your account is not yet enabled for login. Please contact an administrator.', 'danger')
                    return render_template('login.html', username=username)

                login_user(user)

                member_exists = db.execute('SELECT id FROM members WHERE user_id = ?', (user.id,)).fetchone()
                if not member_exists:
                    flash('Welcome! Please add your personal details to complete your family profile.', 'info')
                    return redirect(url_for('add_my_details'))
                else:
                    flash('Logged in successfully.', 'success')
                    return redirect(url_for('home'))
            else:
                flash('Invalid username or password.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    form_data = {}

    if request.method == 'POST':
        username = request.form['username']
        original_name = request.form['originalName']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        form_data = {
            'username': username,
            'originalName': original_name,
        }

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', form_data=form_data)

        hashed_password = generate_password_hash(password)
        db = get_db()

        unique_key = generate_unique_key()

        try:
            db.execute(
                'INSERT INTO users (username, originalName, password_hash, theme_preference, chat_background_image_path, unique_key, password_reset_pending, reset_request_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (username, original_name, hashed_password, 'light', None, unique_key, 0, None)
            )
            db.commit()
            flash(f'Registration successful! Your unique key is: <strong>{unique_key}</strong>. Please keep it safe for password recovery.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', form_data=form_data)
        except Exception as e:
            flash(f'An error occurred during registration: {e}', 'danger')
            return render_template('register.html', form_data=form_data)

    return render_template('register.html', form_data=form_data)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        unique_key = request.form.get('unique_key', '').upper()

        db = get_db()
        user_data = db.execute('SELECT id, username, unique_key FROM users WHERE username = ?', (username,)).fetchone()

        if not user_data:
            return jsonify({'success': False, 'message': 'Username not found.'})
        if user_data['unique_key'] != unique_key:
            return jsonify({'success': False, 'message': 'Incorrect unique key.'})

        admin_user = User.get(0)
        if not admin_user:
            return jsonify({'success': False, 'message': 'Admin account not found. Cannot process password reset request.'})

        message_body = f"Password reset request for user: {username}. Unique Key provided: {unique_key}. Please verify this key and initiate a password reset for this user from the Manage Users page if correct."
        try:
            db.execute(
                'INSERT INTO messages (sender_id, receiver_id, body, timestamp, is_read, is_admin_message) VALUES (?, ?, ?, ?, ?, ?)',
                (user_data['id'], admin_user.id, message_body, datetime.utcnow(), 0, 0)
            )
            db.execute('UPDATE users SET reset_request_timestamp = ?, password_reset_pending = 0 WHERE id = ?',
                       (datetime.utcnow(), user_data['id']))
            db.commit()
            return jsonify({'success': True, 'message': 'Your password reset request has been sent to the administrator. You will be redirected to set a new password in 2 minutes if the admin does not act sooner.'})
        except sqlite3.Error as e:
            return jsonify({'success': False, 'message': f"Error sending request: {e}"})
        except Exception as e:
            return jsonify({'success': False, 'message': f"An unexpected error occurred: {e}"})

    flash('Please use the "Forgot Password?" link on the login page to request a reset.', 'info')
    return redirect(url_for('login'))



# In app.py, ensure you have these imports at the top of your file:
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash # <--- Make sure these are imported
# from .db import get_db # Or wherever your get_db function is defined
# from .models import User # Make sure your User model is imported

# ... (your existing Flask app setup and other routes) ...

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    Allows a logged-in user to change their password.
    Requires current password verification.
    """
    db = get_db() # Get your SQLite database connection

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # Fetch the user's current password hash from the database
        # Assuming your User table has 'password_hash' column
        user_data = db.execute('SELECT password_hash FROM users WHERE id = ?', (current_user.id,)).fetchone()

        if not user_data:
            flash('User not found.', 'danger')
            return redirect(url_for('settings'))

        stored_password_hash = user_data['password_hash']

        # 1. Verify current password
        if not check_password_hash(stored_password_hash, current_password):
            flash('Incorrect current password.', 'danger')
            return render_template('change_password.html') # Re-render form with error

        # 2. Validate new password
        if not new_password or len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            return render_template('change_password.html')

        if new_password != confirm_new_password:
            flash('New password and confirmation do not match.', 'danger')
            return render_template('change_password.html')

        # 3. Hash and update new password
        hashed_new_password = generate_password_hash(new_password)
        try:
            db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_new_password, current_user.id))
            db.commit()
            flash('Your password has been changed successfully!', 'success')
            return redirect(url_for('settings')) # Redirect back to settings page
        except Exception as e:
            flash(f'An error occurred while changing password: {e}', 'danger')
            return render_template('change_password.html')

    # For GET request, simply render the form
    return render_template('change_password.html')

@app.route('/set-new-password', methods=['GET', 'POST'])
def set_new_password():
    if not session.get('reset_username'):
        flash('No pending password reset request found. Please try again.', 'danger')
        return redirect(url_for('login'))
    username = session['reset_username']
    db = get_db()
    user_data = db.execute('SELECT id, password_reset_pending FROM users WHERE username = ?', (username,)).fetchone()
    if not user_data or user_data['password_reset_pending'] != 1:
        flash('No pending password reset request for this user. Please try again.', 'danger')
        session.pop('reset_username', None)
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if not new_password or not confirm_password:
            flash('New password and confirm password fields are required.', 'danger')
            return render_template('set_new_password.html', username=username)
        elif new_password != confirm_password:
            flash('New password and confirmation do not match.', 'danger')
            return render_template('set_new_password.html', username=username)
        try:
            hashed_password = generate_password_hash(new_password)
            db.execute('UPDATE users SET password_hash = ?, password_reset_pending = 0, reset_request_timestamp = NULL WHERE id = ?', (hashed_password, user_data['id']))
            db.commit()
            session.pop('reset_username', None)
            flash('Your password has been reset successfully! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'Database error setting new password: {e}', 'danger')
            return render_template('set_new_password.html', username=username)
    return render_template('set_new_password.html', username=username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/settings')
@login_required
def settings():
    db = get_db()
    user_member_profile = db.execute('SELECT profilePhoto FROM members WHERE user_id = ?', (current_user.id,)).fetchone()
    profile_photo_path = user_member_profile['profilePhoto'] if user_member_profile else None
    current_chat_background = current_user.chat_background_image_path
    return render_template('settings.html', profile_photo_path=profile_photo_path, current_chat_background=current_chat_background)

# Renamed from video_moments_page to status_feed
@app.route('/status')
@login_required
def status_feed():
    db = get_db()
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    print(f"DEBUG: Current UTC time: {now}")
    active_statuses_raw = db.execute('''
        SELECT tv.file_path, tv.upload_timestamp, m.fullName, m.profilePhoto, m.id AS member_id, m.user_id AS uploader_user_id
        FROM temporary_videos tv
        JOIN members m ON tv.member_id = m.id
        ORDER BY tv.upload_timestamp DESC
    ''').fetchall()
    statuses_for_template = []
    if not active_statuses_raw:
        print("DEBUG: No raw statuses found in temporary_videos table.")
    for status_raw in active_statuses_raw:
        print(f"DEBUG: Processing status for {status_raw['fullName']} (Member ID: {status_raw['member_id']})")
        print(f"DEBUG: Raw upload_timestamp: {status_raw['upload_timestamp']}")
        try:
            # The upload_timestamp is already a datetime object due to detect_types=sqlite3.PARSE_DECLTYPES
            upload_time_dt = status_raw['upload_timestamp']
            # Ensure it's timezone-aware for consistent comparison with 'now'
            if upload_time_dt.tzinfo is None:
                upload_time_dt = upload_time_dt.replace(tzinfo=timezone.utc)
            expires_at_dt = upload_time_dt + timedelta(hours=12)
            is_active = (now < expires_at_dt)
            print(f"DEBUG: Parsed (or directly used) upload_time_dt: {upload_time_dt}")
            print(f"DEBUG: Expires at: {expires_at_dt}")
            print(f"DEBUG: Is active: {is_active}")
            if is_active:
                statuses_for_template.append({
                    'file_path': status_raw['file_path'],
                    'upload_time': upload_time_dt,
                    'expires_at': expires_at_dt,
                    'fullName': status_raw['fullName'],
                    'profilePhoto': status_raw['profilePhoto'],
                    'member_id': status_raw['member_id'],
                    'uploader_user_id': status_raw['uploader_user_id']
                })
            else:
                print(f"DEBUG: Status for {status_raw['fullName']} is NOT active (expired).")
        except Exception as e:
            # Catch all exceptions during processing
            print(f"ERROR: Failed to process status for {status_raw['fullName']} (Member ID: {status_raw['member_id']}). Error: {e}")
            continue
    print(f"DEBUG: Total active statuses for template: {len(statuses_for_template)}")
    return render_template('status_feed.html', statuses=statuses_for_template)


@app.route('/photo-gallery')
@login_required
def photo_gallery_page():
    return render_template('photo-gallery.html')


@app.route('/add-my-details', methods=['GET', 'POST'])
@login_required
def add_my_details():
    db = get_db()
    member_exists = db.execute('SELECT id FROM members WHERE user_id = ?', (current_user.id,)).fetchone()
    if member_exists:
        flash('You have already added your personal details. You can edit them through your member profile.', 'info')
        return redirect(url_for('my_profile'))

    form_data = {} # Initialize form_data

    if request.method == 'POST':
        full_name = request.form['fullName']
        gender = request.form['gender']
        date_of_birth = request.form.get('dateOfBirth')
        marital_status = request.form.get('maritalStatus')
        spouse_names = request.form.get('spouseNames')
        children_names = request.form.get('childrenNames')
        whereabouts = request.form.get('whereabouts')
        contact = request.form.get('contact')
        bio = request.form.get('bio')
        school_name = request.form.get('schoolName')
        can_message = 1 if request.form.get('can_message') else 0
        personal_relationship_description = request.form.get('personalRelationshipDescription')

        profile_photo_path = None
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(os.path.join(app.root_path, profile_photo_path))

        try:
            db.execute(
                'INSERT INTO members (user_id, fullName, gender, whereabouts, contact, bio, profilePhoto, dateOfBirth, maritalStatus, spouseNames, childrenNames, needs_details_update, schoolName, has_login_access, can_message, personalRelationshipDescription) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (current_user.id, full_name, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, 0, school_name, 1, can_message, personal_relationship_description)
            )
            db.commit()
            flash('Your details have been added successfully!', 'success')
            return redirect(url_for('my_profile'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')

    return render_template('add_my_details.html', form_data=form_data)


@app.route('/my-profile')
@login_required
def my_profile():
    db = get_db()
    member = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()

    if member is None:
        flash('Please add your personal details to complete your family profile.', 'info')
        return redirect(url_for('add_my_details'))

    # Determine if 'Manage Users' link should be visible (admin or related roles)
    can_manage_users = current_user.is_admin

    # Get members linked to the current user's profile based on fullName and dob (simple link for demonstration)
    # In a real app, this would be based on explicit family links
    linked_members = []
    if member:
        linked_members = db.execute('''
            SELECT id, fullName, gender, dateOfBirth, profilePhoto
            FROM members
            WHERE id != ?
            AND (
                fullName LIKE ? OR
                (gender = ? AND dateOfBirth = ?)
            )
        ''', (member['id'], f"%{member['fullName'].split()[0]}%", member['gender'], member['dateOfBirth'])).fetchall()


    return render_template('my_profile.html',
                           member=member,
                           calculate_age=calculate_age,
                           can_manage_users=can_manage_users,
                           linked_members=linked_members)


@app.route('/edit-my-details', methods=['GET', 'POST'])
@login_required
def edit_my_details():
    db = get_db()
    member = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()

    if member is None:
        flash('No personal details found. Please add your details first.', 'warning')
        return redirect(url_for('add_my_details'))

    if request.method == 'POST':
        full_name = request.form['fullName']
        gender = request.form['gender']
        date_of_birth = request.form.get('dateOfBirth')
        marital_status = request.form.get('maritalStatus')
        spouse_names = request.form.get('spouseNames')
        children_names = request.form.get('childrenNames')
        whereabouts = request.form.get('whereabouts')
        contact = request.form.get('contact')
        bio = request.form.get('bio')
        school_name = request.form.get('schoolName')
        can_message = 1 if request.form.get('can_message') else 0
        personal_relationship_description = request.form.get('personalRelationshipDescription')


        profile_photo_path = member['profilePhoto'] # Keep existing path if no new file uploaded
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                # Delete old photo if it exists and is not the default
                if profile_photo_path and profile_photo_path != url_for('static', filename='img/default_profile.png'):
                    old_path = os.path.join(app.root_path, profile_photo_path)
                    if os.path.exists(old_path):
                        os.remove(old_path)

                filename = secure_filename(file.filename)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(os.path.join(app.root_path, profile_photo_path))

        try:
            db.execute(
                'UPDATE members SET fullName = ?, gender = ?, whereabouts = ?, contact = ?, bio = ?, profilePhoto = ?, dateOfBirth = ?, maritalStatus = ?, spouseNames = ?, childrenNames = ?, needs_details_update = ?, schoolName = ?, can_message = ?, personalRelationshipDescription = ? WHERE user_id = ?',
                (full_name, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, 0, school_name, can_message, personal_relationship_description, current_user.id)
            )
            db.commit()
            flash('Your details have been updated successfully!', 'success')
            return redirect(url_for('my_profile'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')

    return render_template('edit_my_details.html', member=member)


@app.route('/delete-profile-photo', methods=['POST'])
@login_required
def delete_profile_photo():
    db = get_db()
    member = db.execute('SELECT id, profilePhoto FROM members WHERE user_id = ?', (current_user.id,)).fetchone()

    if member and member['profilePhoto']:
        try:
            old_path = os.path.join(app.root_path, member['profilePhoto'])
            if os.path.exists(old_path):
                os.remove(old_path)
            db.execute('UPDATE members SET profilePhoto = NULL WHERE id = ?', (member['id'],))
            db.commit()
            flash('Profile photo deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting photo: {e}', 'danger')
    else:
        flash('No profile photo to delete.', 'info')

    return redirect(url_for('edit_my_details'))


@app.route('/admin/manage-users')
@login_required
def admin_manage_users():
    if not current_user.is_admin:
        abort(403)  # Forbidden

    db = get_db()
    # Fetch all users with their associated member profiles
    users = db.execute('''
        SELECT
            u.id AS user_id,
            u.username,
            u.originalName,
            u.relationshipToRaphael,
            u.unique_key,
            u.password_reset_pending,
            u.reset_request_timestamp,
            m.id AS member_id,
            m.fullName,
            m.profilePhoto,
            m.has_login_access,
            m.needs_details_update
        FROM users u
        LEFT JOIN members m ON u.id = m.user_id
        WHERE u.username != ?
        ORDER BY u.username
    ''', (app.config['ADMIN_USERNAME'],)).fetchall()

    members_without_users = db.execute('''
        SELECT id AS member_id, fullName, profilePhoto, needs_details_update
        FROM members
        WHERE user_id IS NULL
        ORDER BY fullName
    ''').fetchall()

    users_for_template = []
    for user in users:
        reset_request_time = user['reset_request_timestamp']
        time_since_request = None
        if reset_request_time:
            time_since_request = datetime.utcnow() - reset_request_time
            if time_since_request.total_seconds() > 120: # 2 minutes
                db.execute('UPDATE users SET reset_request_timestamp = NULL WHERE id = ?', (user['user_id'],))
                db.commit()
                reset_request_time = None # Clear it for this session if expired

        users_for_template.append({
            'user_id': user['user_id'],
            'username': user['username'],
            'originalName': user['originalName'],
            'relationshipToRaphael': user['relationshipToRaphael'],
            'unique_key': user['unique_key'],
            'password_reset_pending': user['password_reset_pending'],
            'reset_request_timestamp': reset_request_time,
            'member_id': user['member_id'],
            'fullName': user['fullName'],
            'profilePhoto': user['profilePhoto'],
            'has_login_access': user['has_login_access'],
            'needs_details_update': user['needs_details_update']
        })


    return render_template('admin_manage_users.html', users=users_for_template, members_without_users=members_without_users)


@app.route('/admin/toggle-login-access/<int:user_id>', methods=['POST'])
@login_required
def admin_toggle_login_access(user_id):
    if not current_user.is_admin:
        abort(403)

    db = get_db()
    member = db.execute('SELECT id, has_login_access FROM members WHERE user_id = ?', (user_id,)).fetchone()
    if member:
        new_status = 1 if member['has_login_access'] == 0 else 0
        db.execute('UPDATE members SET has_login_access = ? WHERE id = ?', (new_status, member['id']))
        db.commit()
        flash(f"Login access {'enabled' if new_status == 1 else 'disabled'} for user.", 'success')
    else:
        flash("Member profile not found for this user.", 'danger')
    return redirect(url_for('admin_manage_users'))

@app.route('/admin/initiate-password-reset/<int:user_id>', methods=['POST'])
@login_required
def admin_initiate_password_reset(user_id):
    if not current_user.is_admin:
        abort(403)

    db = get_db()
    user = db.execute('SELECT id, username FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        try:
            db.execute('UPDATE users SET password_reset_pending = 1, reset_request_timestamp = NULL WHERE id = ?', (user_id,))
            db.commit()
            flash(f"Password reset initiated for {user['username']}. They will be prompted to set a new password on next login.", 'success')
        except sqlite3.Error as e:
            flash(f"Database error initiating password reset: {e}", 'danger')
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')
    else:
        flash("User not found.", 'danger')
    return redirect(url_for('admin_manage_users'))


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    if user_id == current_user.id:
        flash("You cannot delete your own admin account.", 'danger')
        return redirect(url_for('admin_manage_users'))

    db = get_db()
    try:
        # First, delete associated member profile if it exists
        member = db.execute('SELECT id, profilePhoto FROM members WHERE user_id = ?', (user_id,)).fetchone()
        if member:
            # Delete profile photo if it exists and is not the default
            if member['profilePhoto'] and member['profilePhoto'] != url_for('static', filename='img/default_profile.png'):
                old_path = os.path.join(app.root_path, member['profilePhoto'])
                if os.path.exists(old_path):
                    os.remove(old_path)
            db.execute('DELETE FROM members WHERE id = ?', (member['id'],))

        # Then delete the user
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        flash('User and associated member profile (if any) deleted successfully.', 'success')
    except sqlite3.Error as e:
        flash(f"Database error deleting user: {e}", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('admin_manage_users'))


@app.route('/admin/link-user-to-member/<int:user_id>/<int:member_id>', methods=['POST'])
@login_required
def admin_link_user_to_member(user_id, member_id):
    if not current_user.is_admin:
        abort(403)

    db = get_db()
    try:
        # Check if member is already linked
        existing_member = db.execute('SELECT user_id FROM members WHERE id = ?', (member_id,)).fetchone()
        if existing_member and existing_member['user_id'] is not None:
            flash(f"Member ID {member_id} is already linked to a user. Unlink it first if you wish to re-link.", 'danger')
            return redirect(url_for('admin_manage_users'))

        # Link the member to the user
        db.execute('UPDATE members SET user_id = ?, has_login_access = 1, needs_details_update = 0 WHERE id = ?', (user_id, member_id))
        
        # Get member's full name to update user's originalName
        member_full_name = db.execute('SELECT fullName FROM members WHERE id = ?', (member_id,)).fetchone()
        if member_full_name:
            db.execute('UPDATE users SET originalName = ? WHERE id = ?', (member_full_name['fullName'], user_id))

        db.commit()
        flash(f"User ID {user_id} successfully linked to Member ID {member_id}.", 'success')
    except sqlite3.Error as e:
        flash(f"Database error linking user to member: {e}", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')
    return redirect(url_for('admin_manage_users'))


@app.route('/admin/unlink-user-from-member/<int:user_id>/<int:member_id>', methods=['POST'])
@login_required
def admin_unlink_user_from_member(user_id, member_id):
    if not current_user.is_admin:
        abort(403)

    db = get_db()
    try:
        # Unlink the member from the user
        db.execute('UPDATE members SET user_id = NULL, has_login_access = 0 WHERE id = ? AND user_id = ?', (member_id, user_id))
        
        # Optionally, clear originalName for the user or set it to a default
        db.execute('UPDATE users SET originalName = NULL WHERE id = ?', (user_id,))
        
        db.commit()
        flash(f"User ID {user_id} successfully unlinked from Member ID {member_id}.", 'success')
    except sqlite3.Error as e:
        flash(f"Database error unlinking user from member: {e}", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')
    return redirect(url_for('admin_manage_users'))

@app.route('/admin/add-member', methods=['GET', 'POST'])
@login_required
def admin_add_member():
    if not current_user.is_admin:
        abort(403)

    if request.method == 'POST':
        full_name = request.form['fullName']
        gender = request.form['gender']
        date_of_birth = request.form.get('dateOfBirth')
        marital_status = request.form.get('maritalStatus')
        spouse_names = request.form.get('spouseNames')
        children_names = request.form.get('childrenNames')
        whereabouts = request.form.get('whereabouts')
        contact = request.form.get('contact')
        bio = request.form.get('bio')
        school_name = request.form.get('schoolName')
        has_login_access = 1 if request.form.get('has_login_access') else 0
        can_message = 1 if request.form.get('can_message') else 0
        personal_relationship_description = request.form.get('personalRelationshipDescription')


        profile_photo_path = None
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(os.path.join(app.root_path, profile_photo_path))

        db = get_db()
        try:
            db.execute(
                'INSERT INTO members (fullName, gender, whereabouts, contact, bio, profilePhoto, dateOfBirth, maritalStatus, spouseNames, childrenNames, needs_details_update, schoolName, has_login_access, can_message, personalRelationshipDescription) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (full_name, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, 0, school_name, has_login_access, can_message, personal_relationship_description)
            )
            db.commit()
            flash('Member added successfully!', 'success')
            return redirect(url_for('admin_manage_users'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')

    return render_template('admin_add_member.html')


@app.route('/admin/edit-member/<int:member_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_member(member_id):
    if not current_user.is_admin:
        abort(403)

    db = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()

    if member is None:
        flash('Member not found.', 'danger')
        return redirect(url_for('admin_manage_users'))

    if request.method == 'POST':
        full_name = request.form['fullName']
        gender = request.form['gender']
        date_of_birth = request.form.get('dateOfBirth')
        marital_status = request.form.get('maritalStatus')
        spouse_names = request.form.get('spouseNames')
        children_names = request.form.get('childrenNames')
        whereabouts = request.form.get('whereabouts')
        contact = request.form.get('contact')
        bio = request.form.get('bio')
        school_name = request.form.get('schoolName')
        can_message = 1 if request.form.get('can_message') else 0
        personal_relationship_description = request.form.get('personalRelationshipDescription')

        profile_photo_path = member['profilePhoto']
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                if profile_photo_path and profile_photo_path != url_for('static', filename='img/default_profile.png'):
                    old_path = os.path.join(app.root_path, profile_photo_path)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                filename = secure_filename(file.filename)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(os.path.join(app.root_path, profile_photo_path))

        try:
            db.execute(
                'UPDATE members SET fullName = ?, gender = ?, whereabouts = ?, contact = ?, bio = ?, profilePhoto = ?, dateOfBirth = ?, maritalStatus = ?, spouseNames = ?, childrenNames = ?, needs_details_update = ?, schoolName = ?, can_message = ?, personalRelationshipDescription = ? WHERE id = ?',
                (full_name, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, 0, school_name, can_message, personal_relationship_description, member_id)
            )
            db.commit()

            flash('Member details updated successfully!', 'success')
            return redirect(url_for('member_detail', member_id=member_id))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')

    return render_template('admin_edit_member.html', member=member)


@app.route('/admin/delete-member/<int:member_id>', methods=['POST'])
@login_required
def admin_delete_member(member_id):
    if not current_user.is_admin:
        abort(403)

    db = get_db()
    try:
        member = db.execute('SELECT id, profilePhoto, user_id FROM members WHERE id = ?', (member_id,)).fetchone()
        if member:
            # If the member is linked to a user, unlink them first
            if member['user_id']:
                db.execute('UPDATE users SET originalName = NULL WHERE id = ?', (member['user_id'],))
            
            # Delete profile photo if it exists and is not the default
            if member['profilePhoto'] and member['profilePhoto'] != url_for('static', filename='img/default_profile.png'):
                old_path = os.path.join(app.root_path, member['profilePhoto'])
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            db.execute('DELETE FROM members WHERE id = ?', (member_id,))
            db.commit()
            flash('Member deleted successfully!', 'success')
        else:
            flash('Member not found.', 'danger')
    except sqlite3.Error as e:
        flash(f"Database error deleting member: {e}", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('admin_manage_users'))

@app.route('/member/<int:member_id>')
@login_required
def member_detail(member_id):
    db = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member:
        flash('Member not found.', 'danger')
        return redirect(url_for('home'))

    return render_template('member_detail.html', member=member, calculate_age=calculate_age)


@app.route('/chat')
@login_required
def chat():
    db = get_db()
    users_with_members = db.execute('''
        SELECT u.id AS user_id, u.username, m.fullName, m.profilePhoto, m.can_message
        FROM users u
        JOIN members m ON u.id = m.user_id
        WHERE u.id != ? AND m.can_message = 1
        ORDER BY m.fullName
    ''', (current_user.id,)).fetchall()

    return render_template('chat.html', users=users_with_members)

@app.route('/get_messages/<int:receiver_id>', methods=['GET'])
@login_required
def get_messages(receiver_id):
    db = get_db()
    messages = db.execute('''
        SELECT * FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp
    ''', (current_user.id, receiver_id, receiver_id, current_user.id)).fetchall()

    # Mark messages as read
    db.execute('UPDATE messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0', (current_user.id, receiver_id))
    db.commit()

    messages_list = []
    for msg in messages:
        messages_list.append({
            'sender_id': msg['sender_id'],
            'receiver_id': msg['receiver_id'],
            'body': msg['body'],
            'timestamp': msg['timestamp'].isoformat(),
            'is_read': msg['is_read'],
            'is_image': bool(msg['is_image']),
            'is_video': bool(msg['is_video']),
            'file_path': msg['file_path']
        })
    return jsonify(messages_list)


@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.form.get('receiver_id')
    message_body = request.form.get('message_body')

    if not receiver_id:
        return jsonify({'success': False, 'message': 'Receiver ID is required.'}), 400
    
    receiver_id = int(receiver_id)

    db = get_db()
    receiver_can_message = db.execute('SELECT m.can_message FROM members m JOIN users u ON m.user_id = u.id WHERE u.id = ?', (receiver_id,)).fetchone()
    if not receiver_can_message or receiver_can_message['can_message'] == 0:
        return jsonify({'success': False, 'message': 'This user cannot receive messages.'}), 403


    is_image = 0
    is_video = 0
    file_path = None

    if 'media_file' in request.files:
        file = request.files['media_file']
        if file.filename != '':
            filename = secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()

            if allowed_chat_image_file(filename):
                is_image = 1
                upload_folder = app.config['UPLOAD_CHAT_PHOTO_FOLDER']
            elif allowed_chat_video_file(filename):
                is_video = 1
                upload_folder = app.config['UPLOAD_CHAT_VIDEO_FOLDER']
            else:
                return jsonify({'success': False, 'message': 'Unsupported file type.'}), 400

            file_path = os.path.join(upload_folder, filename)
            file.save(os.path.join(app.root_path, file_path))
            message_body = message_body if message_body else "" # Ensure message_body is not None

    if not message_body and not file_path:
        return jsonify({'success': False, 'message': 'Message body or media file is required.'}), 400

    try:
        db.execute(
            'INSERT INTO messages (sender_id, receiver_id, body, timestamp, is_read, is_image, is_video, file_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (current_user.id, receiver_id, message_body, datetime.utcnow(), 0, is_image, is_video, file_path)
        )
        db.commit()
        return jsonify({'success': True, 'message': 'Message sent.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/upload-status-video', methods=['POST'])
@login_required
def upload_status_video():
    if 'status_video' not in request.files:
        flash('No video part', 'danger')
        return redirect(url_for('status_feed'))

    file = request.files['status_video']
    if file.filename == '':
        flash('No selected video', 'danger')
        return redirect(url_for('status_feed'))

    if file and allowed_video_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_VIDEO_FOLDER'], filename)
        
        try:
            full_upload_path = os.path.join(app.root_path, file_path)
            file.save(full_upload_path)
            
            db = get_db()
            member_profile = get_current_user_member_profile()
            if not member_profile:
                flash('Please add your member profile details before uploading a status video.', 'warning')
                return redirect(url_for('add_my_details'))

            db.execute(
                'INSERT INTO temporary_videos (member_id, file_path, upload_timestamp) VALUES (?, ?, ?)',
                (member_profile['id'], file_path, datetime.utcnow())
            )
            db.commit()
            flash('Status video uploaded successfully!', 'success')
        except Exception as e:
            flash(f'Error uploading video: {e}', 'danger')
    else:
        flash('Allowed video types are mp4, mov, avi, webm.', 'danger')

    return redirect(url_for('status_feed'))

@app.route('/delete-status-video/<int:video_id>', methods=['POST'])
@login_required
def delete_status_video(video_id):
    db = get_db()
    video = db.execute('SELECT file_path, member_id FROM temporary_videos WHERE id = ?', (video_id,)).fetchone()

    if video:
        member_profile = get_current_user_member_profile()
        if member_profile and video['member_id'] == member_profile['id'] or current_user.is_admin:
            try:
                os.remove(os.path.join(app.root_path, video['file_path']))
                db.execute('DELETE FROM temporary_videos WHERE id = ?', (video_id,))
                db.commit()
                flash('Status video deleted successfully.', 'success')
            except OSError as e:
                flash(f'Error deleting video file: {e}', 'danger')
            except Exception as e:
                flash(f'An unexpected error occurred: {e}', 'danger')
        else:
            flash('You are not authorized to delete this video.', 'danger')
            abort(403)
    else:
        flash('Video not found.', 'danger')

    return redirect(url_for('status_feed'))

@app.route('/update_theme', methods=['POST'])
@login_required
def update_theme():
    theme = request.form.get('theme')
    if theme in ['light', 'dark']:
        db = get_db()
        try:
            db.execute('UPDATE users SET theme_preference = ? WHERE id = ?', (theme, current_user.id))
            db.commit()
            flash('Theme updated successfully!', 'success')
        except Exception as e:
            flash(f'Error updating theme: {e}', 'danger')
    else:
        flash('Invalid theme selected.', 'danger')
    return redirect(url_for('settings'))

@app.route('/upload_chat_background', methods=['POST'])
@login_required
def upload_chat_background():
    if 'chat_background_image' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('settings'))

    file = request.files['chat_background_image']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('settings'))

    if file and allowed_background_image_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_CHAT_BACKGROUND_FOLDER'], filename)

        # Delete old background if it exists and is not a default/system one
        # You might want a more robust check to ensure you're not deleting shared defaults
        if current_user.chat_background_image_path and \
           not current_user.chat_background_image_path.startswith('static/img/chat_backgrounds/default_'): # Assuming default backgrounds start with 'default_'
            old_path = os.path.join(app.root_path, current_user.chat_background_image_path)
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except OSError as e:
                    print(f"Error deleting old chat background: {e}")

        try:
            full_upload_path = os.path.join(app.root_path, file_path)
            file.save(full_upload_path)
            
            db = get_db()
            db.execute('UPDATE users SET chat_background_image_path = ? WHERE id = ?', (file_path, current_user.id))
            db.commit()
            flash('Chat background uploaded successfully!', 'success')
        except Exception as e:
            flash(f'Error uploading chat background: {e}', 'danger')
    else:
        flash('Allowed image types are png, jpg, jpeg, gif for chat background.', 'danger')

    return redirect(url_for('settings'))

@app.route('/remove_chat_background', methods=['POST'])
@login_required
def remove_chat_background():
    db = get_db()
    if current_user.chat_background_image_path:
        try:
            # Prevent deletion of default/system backgrounds if applicable
            if not current_user.chat_background_image_path.startswith('static/img/chat_backgrounds/default_'):
                old_path = os.path.join(app.root_path, current_user.chat_background_image_path)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            db.execute('UPDATE users SET chat_background_image_path = NULL WHERE id = ?', (current_user.id,))
            db.commit()
            flash('Chat background removed successfully!', 'success')
        except Exception as e:
            flash(f'Error removing chat background: {e}', 'danger')
    else:
        flash('No custom chat background to remove.', 'info')
    
    return redirect(url_for('settings'))

if __name__ == '__main__':
    # You might want to run init_db() only once or conditionally
    # For development, you can uncomment it to re-initialize DB on each...
    app.run(debug=True)
