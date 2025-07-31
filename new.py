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
    def __init__(self, id, username, originalName, password_hash, relationshipToRaphael, is_admin=False, theme_preference='light', chat_background_image_path=None, unique_key=None, password_reset_pending=0, reset_request_timestamp=None):
        self.id = id
        self.username = username
        self.originalName = originalName
        self.password_hash = password_hash
        self.relationshipToRaphael = relationshipToRaphael
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
                        user_data['password_hash'], user_data['relationshipToRaphael'],
                        is_admin_status, theme_preference,
                        chat_background_image_path,
                        unique_key,
                        password_reset_pending,
                        reset_request_timestamp)
        if user_id == 0 and app.config['ADMIN_USERNAME'] == 'Henry':
            return User(0, app.config['ADMIN_USERNAME'], 'Admin User', generate_password_hash(app.config['ADMIN_PASS']), 'Administrator', is_admin=True, theme_preference='dark', chat_background_image_path=None, unique_key='ADM0', password_reset_pending=0, reset_request_timestamp=None)
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

def get_child_association(parent_association):
    parent_association_lower = parent_association.lower()
    if 'son of Raphael Nyanga' in parent_association_lower or 'daughter of Raphael Nyanga' in parent_association_lower:
        return 'Grandchild of Raphael Nyanga'
    elif 'grandchild of Raphael Nyanga' in parent_association_lower:
        return 'Great-grandchild of Raphael Nyanga'
    elif 'great-grandchild of Raphael Nyanga' in parent_association_lower:
        return 'Great-great-grandchild of Raphael Nyanga'
    return 'Descendant of Raphael Nyanga'


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
                admin_user = User(0, app.config['ADMIN_USERNAME'], 'Admin User', generate_password_hash(app.config['ADMIN_PASS']), 'Administrator', is_admin=True, theme_preference='dark', chat_background_image_path=None, unique_key='ADM0', password_reset_pending=0, reset_request_timestamp=None)
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
        relationship_to_raphael = request.form['relationshipToRaphael']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        form_data = {
            'username': username,
            'originalName': original_name,
            'relationshipToRaphael': relationship_to_raphael
        }

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', form_data=form_data)

        hashed_password = generate_password_hash(password)
        db = get_db()

        unique_key = generate_unique_key()

        try:
            db.execute(
                'INSERT INTO users (username, originalName, relationshipToRaphael, password_hash, theme_preference, chat_background_image_path, unique_key, password_reset_pending, reset_request_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (username, original_name, relationship_to_raphael, hashed_password, 'light', None, unique_key, 0, None)
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
            db.execute('UPDATE users SET password_hash = ?, password_reset_pending = 0, reset_request_timestamp = NULL WHERE id = ?',
                       (hashed_password, user_data['id']))
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

    return render_template('settings.html',
                           profile_photo_path=profile_photo_path,
                           current_chat_background=current_chat_background)

# Renamed from video_moments_page to status_feed
@app.route('/status')
@login_required
def status_feed():
    db = get_db()
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    print(f"DEBUG: Current UTC time: {now}")

    active_statuses_raw = db.execute('''
        SELECT
            tv.file_path,
            tv.upload_timestamp,
            m.fullName,
            m.profilePhoto,
            m.id AS member_id,
            m.user_id AS uploader_user_id
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

        except Exception as e: # Catch all exceptions during processing
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
        flash('You have already added your personal details. You can edit them from your member profile.', 'info')
        return redirect(url_for('my_profile'))

    if request.method == 'POST':
        full_name = request.form['fullName']
        gender = request.form['gender']
        whereabouts = request.form['whereabouts']
        contact = request.form['contact']
        bio = request.form['bio']
        date_of_birth = request.form.get('dateOfBirth')
        marital_status = request.form.get('maritalStatus')
        spouse_names = request.form.get('spouseNames', '')
        girlfriend_names = request.form.get('girlfriendNames', '')
        children_names = request.form.get('childrenNames', '')
        school_name = request.form.get('schoolName', '')
        personal_relationship_description = request.form.get('personalRelationshipDescription', '')

        if marital_status == 'Engaged' and girlfriend_names:
            spouse_names = girlfriend_names

        if contact and not all(c.strip() == '' or c.strip().isdigit() or c.strip().replace('+', '').isdigit() or c.strip().count('@') == 1 for c in contact.split(',')):
            flash('Contact information should be valid phone numbers (digits, +, -, (, )) or emails, separated by commas.', 'danger')
            form_data = request.form.to_dict()
            if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                form_data['profilePhoto'] = ''
            return render_template('add_my_details.html', user=current_user, form_data=form_data)

        association = current_user.relationshipToRaphael

        if not full_name or not gender:
            flash('Full Name and Gender are required.', 'danger')
            form_data = request.form.to_dict()
            if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                form_data['profilePhoto'] = ''
            return render_template('add_my_details.html', user=current_user, form_data=form_data)

        profile_photo_path = ''
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_save_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
                file.save(file_save_path)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')

        try:
            is_raphael_descendant = 1 if association.lower() in ['son of raphael nyanga', 'daughter of raphael nyanga', 'grandchild of raphael nyanga', 'great-grandchild of raphael nyanga'] else 0
            cursor = db.execute(
 'INSERT INTO members (fullName, association, gender, whereabouts, contact, bio, profilePhoto, dateOfBirth, maritalStatus, spouseNames, childrenNames, isRaphaelDescendant, user_id, needs_details_update, added_by_user_id, schoolName, has_login_access, can_message, personalRelationshipDescription) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (full_name, association, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, is_raphael_descendant, current_user.id, 0, current_user.id, school_name, 1, 1, personal_relationship_description)
            )
            db.commit()
            new_member_id = cursor.lastrowid

            flash('Your personal details have been added successfully!', 'success')
            return redirect(url_for('my_profile'))
        except sqlite3.IntegrityError:
            flash('A member profile already exists for this user. Please edit it instead.', 'danger')
            return redirect(url_for('my_profile'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
            form_data = request.form.to_dict()
            if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                form_data['profilePhoto'] = ''
            return render_template('add_my_details.html', user=current_user, form_data=form_data)

    form_data = {
        'fullName': current_user.originalName,
        'association': current_user.relationshipToRaphael,
        'maritalStatus': 'Single',
        'personalRelationshipDescription': ''
    }
    return render_template('add_my_details.html', user=current_user, form_data=form_data)


@app.route('/my-profile')
@login_required
def my_profile():
    db = get_db()
    member = g.user_member

    if not member:
        flash('Please add your personal details to create your family profile.', 'info')
        return redirect(url_for('add_my_details'))

    age = calculate_age(member['dateOfBirth'])

    temp_video = db.execute('SELECT * FROM temporary_videos WHERE member_id = ? ORDER BY upload_timestamp DESC LIMIT 1', (member['id'],)).fetchone()
    if temp_video:
        try:
            upload_time = temp_video['upload_timestamp']
            if isinstance(upload_time, str):
                upload_time = datetime.strptime(upload_time, '%Y-%m-%d %H:%M:%S.%f')
            elif not isinstance(upload_time, datetime):
                upload_time = None
        except (ValueError, TypeError):
            upload_time = None

        if upload_time and datetime.utcnow() - upload_time > timedelta(hours=12):
           temp_video = None

    return render_template('my_profile.html', member=member, age=age, temp_video=temp_video)


@app.route('/add-member', methods=['GET', 'POST'])
@login_required
def add_member_form():
    if not current_user.is_admin:
        flash('You do not have permission to add new members.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        full_name = request.form['fullName']
        association = request.form['association']
        gender = request.form['gender']
        whereabouts = request.form['whereabouts']
        contact = request.form['contact']
        bio = request.form['bio']
        date_of_birth = request.form.get('dateOfBirth')
        marital_status = request.form.get('maritalStatus')
        spouse_names = request.form.get('spouseNames', '')
        girlfriend_names = request.form.get('girlfriendNames', '')
        children_names = request.form.get('childrenNames', '')
        school_name = request.form.get('schoolName', '')
        personal_relationship_description = request.form.get('personalRelationshipDescription', '')

        if marital_status == 'Engaged' and girlfriend_names:
            spouse_names = girlfriend_names

        if contact:
            contacts_list = [c.strip() for c in contact.split(',') if c.strip()]
            for c in contacts_list:
                if '@' in c:
                    if not (c.count('@') == 1 and '.' in c.split('@')[1]):
                        flash('Invalid email format in contact information.', 'danger')
                        form_data = request.form.to_dict()
                        if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                            form_data['profilePhoto'] = ''
                        return render_template('add-member.html', form_data=form_data)
                else:
                    if not (c.replace('+', '').replace('-', '').replace('(', '').replace(')', '').replace(' ', '').isdigit()):
                        flash('Invalid phone number format in contact information.', 'danger')
                        form_data = request.form.to_dict()
                        if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                            form_data['profilePhoto'] = ''
                        return render_template('add-member.html', form_data=form_data)

        if not full_name or not association or not gender:
            flash('Full Name, Association, and Gender are required.', 'danger')
            form_data = request.form.to_dict()
            if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                form_data['profilePhoto'] = ''
            return render_template('add-member.html', form_data=form_data)

        profile_photo_path = ''
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{member['id']}_{datetime.utcnow().timestamp()}_{file.filename}") # Error: member not defined here
                file_save_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
                file.save(file_save_path)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')

        db = get_db()
        try:
            is_raphael_descendant = 1 if association.lower() in ['son of raphael nyanga', 'daughter of raphael nyanga', 'grandchild of raphael nyanga', 'great-grandchild of raphael nyanga'] else 0

            cursor = db.execute(
                'INSERT INTO members (fullName, association, gender, whereabouts, contact, bio, profilePhoto, dateOfBirth, maritalStatus, spouseNames, childrenNames, isRaphaelDescendant, user_id, needs_details_update, added_by_user_id, schoolName, has_login_access, can_message, personalRelationshipDescription) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (full_name, association, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, is_raphael_descendant, None, 0, current_user.id, school_name, 0, 0, personal_relationship_description)
            )
            db.commit()
            new_member_id = cursor.lastrowid

            flash('Family member details added successfully!', 'success')
            return redirect(url_for('member_added_success'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
            form_data = request.form.to_dict()
            if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                form_data['profilePhoto'] = ''
            return render_template('add-member.html', form_data=form_data)

    return render_template('add-member.html', form_data={})

@app.route('/member-added-success')
@login_required
def member_added_success():
    return render_template('success.html', message="Family member details added successfully!")

# In your app.py, locate and replace your existing list_members() route with this:

@app.route('/members')
@login_required
def list_members():
    db = get_db()

    # --- UPDATED QUERY ---
    # LEFT JOIN with 'users' table to get the 'username'
    # The WHERE clause `m.user_id IS NULL OR m.user_id != ?` correctly filters out the current user's profile
    # and includes unlinked members.
    members_data = db.execute('''
        SELECT
            m.*,
            u.username AS linked_username, -- Alias the username from users table
            tv.file_path AS temp_video_path,
            tv.upload_timestamp AS temp_video_upload_time
        FROM members m
        LEFT JOIN users u ON m.user_id = u.id
        LEFT JOIN temporary_videos tv ON m.id = tv.member_id
        WHERE m.user_id IS NULL OR m.user_id != ?
        ORDER BY m.fullName ASC
    ''', (current_user.id,)).fetchall()

    members_for_template = []
    now = datetime.utcnow()
    for member in members_data:
        member_dict = dict(member)
        # Add the fetched 'linked_username' to the dictionary as 'username'
        member_dict['username'] = member_dict['linked_username'] if member_dict['linked_username'] else ''

        # Existing video status logic (from your original code)
        upload_time = None
        if member_dict['temp_video_upload_time']:
            try:
                upload_time = member_dict['temp_video_upload_time']
                if isinstance(upload_time, str):
                    upload_time = datetime.strptime(upload_time, '%Y-%m-%d %H:%M:%S.%f')
                elif not isinstance(upload_time, datetime):
                    upload_time = None
            except (ValueError, TypeError):
                upload_time = None

        if upload_time and now - upload_time <= timedelta(hours=12):
            member_dict['has_active_video'] = True
        else:
            member_dict['has_active_video'] = False
        # End existing video status logic

        members_for_template.append(member_dict)

    # Render members_list.html with the prepared members data
    return render_template('members_list.html', members=members_for_template)


# In app.py, ensure you have these imports at the top of your file:
# from flask import render_template, redirect, url_for, flash, request, jsonify, g
# from flask_login import login_user, logout_user, login_required, current_user
# from datetime import datetime, timedelta # Needed for datetime/timedelta
# from .db import get_db # Or wherever your get_db function is defined

# ... (your existing Flask app setup and other routes) ...

# This is the route you specifically asked to rename/adapt.
# In your app.py, locate and replace your existing message_member() route with this:

@app.route('/message-member') # Route URL
@login_required
def message_member(): # Function name
    db = get_db()

    # --- UPDATED QUERY ---
    # LEFT JOIN with 'users' table to get the 'username'
    # Filter:
    # 1. Member must be linked to a user (m.user_id IS NOT NULL)
    # 2. Member must not be the current logged-in user (m.user_id != ?)
    # 3. Member must have messaging capability enabled (m.can_message = 1)
    members_data = db.execute('''
        SELECT
        m.*,
            u.username AS linked_username, -- Alias the username from users table
            tv.file_path AS temp_video_path,
            tv.upload_timestamp AS temp_video_upload_time
        FROM members m
        LEFT JOIN users u ON m.user_id = u.id
        LEFT JOIN temporary_videos tv ON m.id = tv.member_id
        WHERE m.user_id IS NOT NULL AND m.user_id != ? AND m.can_message = 1
        ORDER BY m.fullName ASC
    ''', (current_user.id,)).fetchall()

    members_for_template = []
    now = datetime.utcnow()
    for member in members_data:
        member_dict = dict(member)
        # Add the fetched 'linked_username' to the dictionary as 'username'
        member_dict['username'] = member_dict['linked_username'] if member_dict['linked_username'] else ''

        # Existing video status logic (from your original code)
        upload_time = None
        if member_dict['temp_video_upload_time']:
            try:
                upload_time = member_dict['temp_video_upload_time']
                if isinstance(upload_time, str):
                    upload_time = datetime.strptime(upload_time, '%Y-%m-%d %H:%M:%S.%f')
                elif not isinstance(upload_time, datetime):
                    upload_time = None
            except (ValueError, TypeError):
                upload_time = None

        if upload_time and now - upload_time <= timedelta(hours=12):
            member_dict['has_active_video'] = True
        else:
            member_dict['has_active_video'] = False
        # End existing video status logic

        members_for_template.append(member_dict)

    # Render message_member.html with the prepared members data
    return render_template('message_member.html', members=members_for_template)




# --- MODIFIED ROUTE: member_detail (This is the correct and only one now) ---
@app.route('/members/<int:member_id>')
@login_required
def member_detail(member_id):
    db = get_db()

    # Check if the requested member_id is the current user's own member_id
    if g.user_member and member_id == g.user_member['id']:
        return redirect(url_for('my_profile')) # Redirect to my_profile if it's their own

    member = db.execute(
        'SELECT * FROM members WHERE id = ?', (member_id,)
    ).fetchone()

    if member is None:
        flash('Member not found.', 'danger')
        return redirect(url_for('home'))

    # Determine if the logged-in user can message this member
    can_message_member = False
    if g.user_member and member['user_id'] and member['can_message'] == 1:
        # Check if the target member has login access and can message
        # And if the current user also has messaging access (implicitly through their login)
        can_message_member = True

    age = calculate_age(member['dateOfBirth'])

    # --- Start: Video Status Data Processing for Template (for other users to view) ---
    temp_video_data_for_template = None
    temp_video_raw = db.execute('SELECT * FROM temporary_videos WHERE member_id = ? ORDER BY upload_timestamp DESC LIMIT 1', (member_id,)).fetchone()

    if temp_video_raw:
        try:
            # Ensure upload_timestamp is a datetime object for calculations
            upload_time_str = temp_video_raw['upload_timestamp']
            # Convert to datetime object, assuming it's stored as string with microseconds
            upload_time_dt = datetime.strptime(upload_time_str, '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)

            expires_at_dt = upload_time_dt + timedelta(hours=12)
            is_active_status = (datetime.now(timezone.utc) < expires_at_dt)

            # Assign temp_video_data_for_template regardless of active status
            temp_video_data_for_template = {
                'file_path': temp_video_raw['file_path'],
                'upload_time': upload_time_dt, # Pass as datetime object
                'expires_at': expires_at_dt,  # Pass as datetime object
                'is_active': is_active_status # True or False
            }

        except (ValueError, TypeError, Exception) as e:
            print(f"Error processing temporary video for member {member_id} in member_detail: {e}")
            # If there's an error in processing, treat it as no active video
            temp_video_data_for_template = None
    # --- End: Video Status Data Processing for Template ---

    return render_template(
        'member_detail.html',
        member=member,
        age=age,
        can_message_member=can_message_member,
        temp_video=temp_video_data_for_template # Pass the processed video data
    )

# --- NEW ROUTE: Admin Show User Status ---
@app.route('/admin/show-user-status/<int:member_id>', methods=['GET'])
@login_required
def admin_show_user_status(member_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    db = get_db()
    temp_video = db.execute('SELECT file_path, upload_timestamp FROM temporary_videos WHERE member_id = ? ORDER BY upload_timestamp DESC LIMIT 1', (member_id,)).fetchone()

    if temp_video:
        try:
            upload_time = temp_video['upload_timestamp']
            if isinstance(upload_time, str):
                upload_time = datetime.strptime(upload_time, '%Y-%m-%d %H:%M:%S.%f')
            elif not isinstance(upload_time, datetime):
                upload_time = None
        except (ValueError, TypeError):
            upload_time = None

        if upload_time and datetime.utcnow() - upload_time <= timedelta(hours=12):
            status_message = "This is the current active video status for the user."
        elif upload_time:
            status_message = "This video status has expired (older than 12 hours)."
        else:
            status_message = "Could not determine video upload time."

        return render_template('admin_view_status.html',
                               video_url=url_for('static', filename=temp_video['file_path']),
                               status_message=status_message,
                               member_id=member_id)
    else:
        flash('No video status found for this user.', 'info')
        return redirect(url_for('member_detail', member_id=member_id))


# --- NEW ROUTE: Admin Delete User Status ---
# --- NEW ROUTE: Admin Delete User Status ---
@app.route('/admin/delete-user-status/<int:member_id>', methods=['POST'])
@login_required
def admin_delete_user_status(member_id):
    db = get_db()

    # Get the member profile associated with the video
    member_profile = db.execute('SELECT user_id FROM members WHERE id = ?', (member_id,)).fetchone()

    if not member_profile:
        flash('Member profile not found.', 'danger')
        return redirect(url_for('home')) # Or list_members

    # Check authorization: Must be admin OR the owner of the profile
    if not (current_user.is_admin or (member_profile['user_id'] and current_user.id == member_profile['user_id'])):
        flash('You do not have permission to delete this status.', 'danger')
        # Redirect to the profile if unauthorized, otherwise to admin panel if admin
        if current_user.is_admin:
            return redirect(url_for('admin_manage_users'))
        else:
            return redirect(url_for('my_profile'))


    temp_video = db.execute('SELECT id, file_path FROM temporary_videos WHERE member_id = ? ORDER BY upload_timestamp DESC LIMIT 1', (member_id,)).fetchone()

    if temp_video:
        video_path = os.path.join(app.root_path, temp_video['file_path'])

        if os.path.exists(video_path):
            try:
                os.remove(video_path)
                print(f"Deleted temporary video file: {video_path}")
            except OSError as e:
                flash(f"Error deleting video file from disk: {e}", 'danger')
                print(f"Error deleting video file {video_path}: {e}")
        else:
            print(f"Video file not found on disk, removing DB entry: {video_path}")

        db.execute('DELETE FROM temporary_videos WHERE id = ?', (temp_video['id'],))
        db.commit()
        flash('Video status deleted successfully.', 'success')
    else:
        flash('No video status found for this member to delete.', 'info')

    # Redirect based on who deleted it
    if current_user.is_admin:
        return redirect(url_for('member_detail', member_id=member_id)) # Redirect back to the member's detail page
    else:
        return redirect(url_for('my_profile')) # Redirect to their own profile

# --- Messaging Routes ---
@app.route('/inbox')
@login_required
def inbox():
    db = get_db()

    # Get all distinct users current_user has messaged or been messaged by,
    # combining messages and chat_media to find all participants.
    # Also, get the latest timestamp for each conversation to order them.
    conversations_raw = db.execute('''
        WITH CombinedActivity AS (
            SELECT
                CASE
                    WHEN sender_id = ? THEN receiver_id
                    ELSE sender_id
                END AS other_user_id,
                timestamp AS activity_timestamp
            FROM messages
            WHERE sender_id = ? OR receiver_id = ?
            UNION ALL
            SELECT
                CASE
                    WHEN sender_id = ? THEN receiver_id
                    ELSE sender_id
                END AS other_user_id,
                upload_timestamp AS activity_timestamp
            FROM chat_media
            WHERE sender_id = ? OR receiver_id = ?
        )
        SELECT
            other_user_id,
            MAX(activity_timestamp) AS last_activity_timestamp
        FROM CombinedActivity
        WHERE other_user_id != ? -- Exclude current user from being their own "other_user"
        GROUP BY other_user_id
        ORDER BY last_activity_timestamp DESC
    ''', (current_user.id, current_user.id, current_user.id,
          current_user.id, current_user.id, current_user.id,
          current_user.id)).fetchall()

    inbox_conversations = []
    for conv_summary in conversations_raw:
        other_user_id = conv_summary['other_user_id']

        other_user_data = db.execute('SELECT id, username, originalName FROM users WHERE id = ?', (other_user_id,)).fetchone()
        if not other_user_data:
            continue # Skip if user not found (e.g., deleted account)

        # Get the very latest message (text) for the snippet
        latest_message = db.execute(
            '''
            SELECT
                body AS content,
                timestamp,
                sender_id,
                is_read,
                is_admin_message,
                'message' AS content_type
            FROM messages
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ORDER BY timestamp DESC
            LIMIT 1
            ''', (current_user.id, other_user_id, other_user_id, current_user.id)
        ).fetchone()

        # Get the very latest media for the snippet
        latest_media = db.execute(
            '''
            SELECT
                file_path AS content,
                upload_timestamp AS timestamp,
                sender_id,
                1 AS is_read, -- Media is considered read for inbox view
                0 AS is_admin_message,
                'media' AS content_type
            FROM chat_media
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ORDER BY upload_timestamp DESC
            LIMIT 1
            ''', (current_user.id, other_user_id, other_user_id, current_user.id)
        ).fetchone()

        latest_item = None
        if latest_message and latest_media:
            # Compare timestamps to find the absolute latest
            # Ensure timestamps are datetime objects for comparison
            msg_ts = latest_message['timestamp']
            media_ts = latest_media['timestamp']

            if isinstance(msg_ts, str):
                try: msg_ts = datetime.strptime(msg_ts, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError: msg_ts = datetime.strptime(msg_ts, '%Y-%m-%d %H:%M:%S')
            if isinstance(media_ts, str):
                try: media_ts = datetime.strptime(media_ts, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError: media_ts = datetime.strptime(media_ts, '%Y-%m-%d %H:%M:%S')

            if msg_ts > media_ts:
                latest_item = latest_message
            else:
                latest_item = latest_media
        elif latest_message:
            latest_item = latest_message
        elif latest_media:
            latest_item = latest_media

        latest_snippet = "No messages yet."
        is_unread = False

        if latest_item:
            if latest_item['content_type'] == 'message':
                full_content = latest_item['content']
                if full_content:
                    latest_snippet = full_content.split('\n')[0] # First line
                    if len(latest_snippet) > 50:
                        latest_snippet = latest_snippet[:47] + '...'
                else:
                    latest_snippet = "(Empty message)"
            elif latest_item['content_type'] == 'media':
                latest_snippet = f"[{latest_item['content_type'].capitalize()}]" # e.g., "[Media]"

            # Prepend "You: " if current user sent it
            if latest_item['sender_id'] == current_user.id:
                latest_snippet = f"You: {latest_snippet}"
            elif latest_item['is_admin_message'] == 1:
                latest_snippet = f"System: {latest_snippet}"

            # Check unread status (only if current user is receiver and it's not read)
            unread_count_for_this_conv = db.execute('''
                SELECT COUNT(*) FROM messages
                WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
            ''', (other_user_id, current_user.id)).fetchone()[0]

            if unread_count_for_this_conv > 0:
                is_unread = True


        inbox_conversations.append({
            'other_user': other_user_data,
            'latest_message_snippet': latest_snippet,
            'timestamp': conv_summary['last_activity_timestamp'],
            'is_unread': is_unread
        })

    return render_template('inbox.html', conversations=inbox_conversations)

@app.route('/messages/<int:other_user_id>', methods=['GET', 'POST'])
@login_required
def messages_with(other_user_id):
    db = get_db()
    other_user = db.execute('SELECT id, username FROM users WHERE id = ?', (other_user_id,)).fetchone()

    if not other_user:
        flash('User not found.', 'danger')
        return redirect(url_for('inbox'))

    other_member_profile = db.execute('SELECT can_message FROM members WHERE user_id = ?', (other_user_id,)).fetchone()
    if not other_member_profile or other_member_profile['can_message'] == 0:
        flash(f"Messaging is not enabled for {other_user['username']}.", 'danger')
        return redirect(url_for('inbox'))

    conversation_messages = db.execute('''
        SELECT m.*, u.username AS sender_username, m.is_admin_message
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp ASC
    ''', (current_user.id, other_user_id, other_user_id, current_user.id)).fetchall()

    chat_media = db.execute('''
        SELECT cm.*, u.username AS sender_username
        FROM chat_media cm
        JOIN users u ON cm.sender_id = u.id
        WHERE (cm.sender_id = ? AND cm.receiver_id = ?) OR (cm.sender_id = ? AND cm.receiver_id = ?)
        ORDER BY cm.upload_timestamp ASC
    ''', (current_user.id, other_user_id, other_user_id, current_user.id)).fetchall()

    combined_feed = []
    for msg in conversation_messages:
        msg_dict = dict(msg)
        msg_dict['type'] = 'message'
        combined_feed.append(msg_dict)
    for media in chat_media:
        media_dict = dict(media)
        media_dict['type'] = 'media'
        combined_feed.append(media_dict)

    combined_feed.sort(key=lambda x: x['timestamp'] if x['type'] == 'message' else x['upload_timestamp'])


    db.execute('UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0',
               (other_user_id, current_user.id))
    db.commit()
    g.unread_messages_count = get_unread_messages_count()

    if request.method == 'POST':
        body = request.form['message_body'].strip()
        if not body:
            flash('Message body cannot be empty.', 'danger')
        else:
            try:
                is_admin_message = 1 if current_user.is_admin else 0

                db.execute(
                    'INSERT INTO messages (sender_id, receiver_id, body, timestamp, is_read, is_admin_message) VALUES (?, ?, ?, ?, ?, ?)',
                    (current_user.id, other_user_id, body, datetime.utcnow(), 0, is_admin_message)
                )
                db.commit()
            except sqlite3.Error as e:
                flash(f"Error sending message: {e}", 'danger')
        return redirect(url_for('messages_with', other_user_id=other_user_id))

    current_user_chat_background = current_user.chat_background_image_path

    return render_template('view_conversation.html',
                           other_user=other_user,
                           combined_feed=combined_feed,
                           current_user_chat_background=current_user_chat_background)


# In your app.py, locate and replace your existing search_members() route with this:

@app.route('/search-members', methods=['GET'])
@login_required
def search_members():
    search_query = request.args.get('q', '').strip() # Renamed 'query' to 'search_query' to avoid conflict
    db = get_db()

    results = [] # Initialize results list

    if search_query:
        # Use a wildcard for LIKE operator for partial matches
        search_pattern = '%' + search_query + '%'

        # --- UPDATED QUERY ---
        # LEFT JOIN with 'users' table to get the 'username'
        # Search in both fullName and username (case-insensitive)
        # Exclude the current user's profile
        members_data = db.execute('''
            SELECT
                m.id,
                m.fullName,
                m.profilePhoto,
                m.association,
                m.user_id,
                u.username AS linked_username
            FROM members m
            LEFT JOIN users u ON m.user_id = u.id
            WHERE
                (LOWER(m.fullName) LIKE LOWER(?) OR LOWER(u.username) LIKE LOWER(?))
                AND (m.user_id IS NULL OR m.user_id != ?)
            LIMIT 10
        ''', (search_pattern, search_pattern, current_user.id if current_user.is_authenticated else -1)).fetchall()

        for member in members_data:
            profile_photo_url = url_for('static', filename=member['profilePhoto']) if member['profilePhoto'] else url_for('static', filename='img/default_profile.png')

            results.append({
                'id': member['id'],
                'fullName': member['fullName'],
                'username': member['linked_username'] if member['linked_username'] else '', # Add username
                'profilePhoto': profile_photo_url,
                'association': member['association'],
                'isLinkedUser': True if member['user_id'] else False
            })
    return jsonify(results)


@app.route('/upload-status-video', methods=['POST']) # Removed GET method, only POST for AJAX
@login_required
def upload_status_video():
    db = get_db()
    member = g.user_member

    if not member:
        # This case should ideally be handled client-side by disabling the button
        # if no member profile exists, but keeping for robustness.
        return jsonify({'success': False, 'message': 'Please complete your profile details first.'}), 400

    if 'video_file' not in request.files:
        return jsonify({'success': False, 'message': 'No video file part.'}), 400

    file = request.files['video_file']

    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected video file.'}), 400

    if file and allowed_video_file(file.filename):
        filename = secure_filename(f"{member['id']}_{datetime.utcnow().timestamp()}_{file.filename}")
        file_save_path = os.path.join(app.root_path, app.config['UPLOAD_VIDEO_FOLDER'], filename)

        try:
            existing_video = db.execute('SELECT id, file_path FROM temporary_videos WHERE member_id = ?', (member['id'],)).fetchone()
            if existing_video:
                old_video_path = os.path.join(app.root_path, existing_video['file_path'])
                if os.path.exists(old_video_path):
                    os.remove(old_video_path)
                    print(f"Removed old temporary video: {old_video_path}")
                db.execute('DELETE FROM temporary_videos WHERE id = ?', (existing_video['id'],))
                db.commit()

            file.save(file_save_path)
            video_db_path = os.path.join(app.config['UPLOAD_VIDEO_FOLDER'], filename).replace('\\', '/')

            db.execute(
                'INSERT INTO temporary_videos (member_id, file_path, upload_timestamp) VALUES (?, ?, ?)',
                (member['id'], video_db_path, datetime.utcnow())
            )
            db.commit()
            return jsonify({'success': True, 'message': 'Status video uploaded successfully! It will be available for 12 hours.'}), 200
        except sqlite3.Error as e:
            return jsonify({'success': False, 'message': f"Database error saving video: {e}"}), 500
        except Exception as e:
            return jsonify({'success': False, 'message': f"An unexpected error occurred during video upload: {e}"}), 500
    else:
        return jsonify({'success': False, 'message': 'Invalid video file type. Allowed types: mp4, mov, avi, webm.'}), 400

# NOTE: The GET method handling is removed as the form is now inline via modal.
# If you ever need a dedicated upload page again, you'd re-add a GET handler here.

@app.route('/get-member-status-video/<int:member_id>', methods=['GET'])
@login_required
def get_member_status_video(member_id):
    db = get_db()
    member_video = db.execute('SELECT * FROM temporary_videos WHERE member_id = ? ORDER BY upload_timestamp DESC LIMIT 1', (member_id,)).fetchone()

    if member_video:
        if datetime.utcnow() - member_video['upload_timestamp'] <= timedelta(hours=12):
            return jsonify({
                'video_url': url_for('static', filename=member_video['file_path']),
                'upload_time': member_video['upload_timestamp'].isoformat(),
                'expires_at': (member_video['upload_timestamp'] + timedelta(hours=12)).isoformat()
            })
    return jsonify({'video_url': None, 'message': 'No active status video found.'})

@app.route('/update-theme-preference', methods=['POST'])
@login_required
def update_theme_preference():
    theme = request.json.get('theme')
    if theme not in ['light', 'dark']:
        return jsonify({'success': False, 'message': 'Invalid theme preference'}), 400

    db = get_db()
    try:
        db.execute('UPDATE users SET theme_preference = ? WHERE id = ?', (theme, current_user.id))
        db.commit()
        current_user.theme_preference = theme

        response = jsonify({'success': True, 'message': 'Theme preference updated.'})
        response.set_cookie('theme_preference', theme, max_age=30*24*60*60)
        return response
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {e}'}), 500

@app.route('/upload_chat_media/<int:receiver_user_id>', methods=['POST'])
@login_required
def upload_chat_media(receiver_user_id):
    db = get_db()
    receiver = db.execute('SELECT id, username FROM users WHERE id = ?', (receiver_user_id,)).fetchone()

    if not receiver:
        return jsonify({'success': False, 'message': 'Recipient user not found.'}), 404

    if 'media_file' not in request.files:
        return jsonify({'success': False, 'message': 'No media file part.'}), 400

    file = request.files['media_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected media file.'}), 400

    media_type = 'unknown'
    file_path_prefix = ''
    if allowed_chat_image_file(file.filename):
        media_type = 'image'
        file_path_prefix = app.config['UPLOAD_CHAT_PHOTO_FOLDER']
    elif allowed_chat_video_file(file.filename):
        media_type = 'video'
        file_path_prefix = app.config['UPLOAD_CHAT_VIDEO_FOLDER']
    else:
        return jsonify({'success': False, 'message': 'Invalid file type. Only images (png, jpg, jpeg, gif) and videos (mp4, mov, avi, webm) are allowed.'}), 400

    filename = secure_filename(f"{current_user.id}_{receiver_user_id}_{datetime.utcnow().timestamp()}_{file.filename}")
    file_save_path = os.path.join(app.root_path, file_path_prefix, filename)

    try:
        file.save(file_save_path)
        db_file_path = os.path.join(file_path_prefix, filename).replace('\\', '/')

        db.execute(
            'INSERT INTO chat_media (sender_id, receiver_id, file_path, media_type, upload_timestamp) VALUES (?, ?, ?, ?, ?)',
            (current_user.id, receiver_user_id, db_file_path, datetime.utcnow())
        )
        db.commit()

        media_message_body = f"[{media_type.capitalize()} sent]"
        is_admin_message = 1 if current_user.is_admin else 0

        db.execute(
            'INSERT INTO messages (sender_id, receiver_id, body, timestamp, is_read, is_admin_message) VALUES (?, ?, ?, ?, ?, ?)',
            (current_user.id, receiver_user_id, media_message_body, datetime.utcnow(), 0, is_admin_message)
        )
        db.commit()

        return jsonify({'success': True, 'message': 'Media uploaded successfully!', 'file_path': db_file_path, 'media_type': media_type}), 200
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {e}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred: {e}'}), 500

@app.route('/download_chat_media/<path:filename>')
@login_required
def download_chat_media(filename):
    if 'chat_media/photos' in filename:
        directory = os.path.join(app.root_path, app.config['UPLOAD_CHAT_PHOTO_FOLDER'])
        actual_filename = os.path.basename(filename)
    elif 'chat_media/videos' in filename:
        directory = os.path.join(app.root_path, app.config['UPLOAD_CHAT_VIDEO_FOLDER'])
        actual_filename = os.path.basename(filename)
    else:
        abort(404)

    db = get_db()
    media_record = db.execute(
        'SELECT id FROM chat_media WHERE file_path = ? AND (sender_id = ? OR receiver_id = ?)',
        (os.path.join(os.path.basename(directory), actual_filename).replace('\\', '/'), current_user.id, current_user.id)
    ).fetchone()

    if not media_record:
        flash('You do not have permission to download this file.', 'danger')
        abort(403)

    try:
        return send_from_directory(directory, actual_filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)

@app.route('/update_chat_background', methods=['POST'])
@login_required
def update_chat_background():
    db = get_db()
    action = request.form.get('action')

    current_background_path = current_user.chat_background_image_path
    new_background_path = None
    message = "Chat background updated successfully!"
    success = True

    try:
        if action == 'upload':
            if 'background_file' not in request.files:
                flash('No file part for background upload.', 'danger')
                return redirect(url_for('settings'))

            file = request.files['background_file']
            if file.filename == '':
                flash('No selected file for background.', 'danger')
                return redirect(url_for('settings'))

            if file and allowed_background_image_file(file.filename):
                filename = secure_filename(f"{current_user.id}_chat_bg_{datetime.utcnow().timestamp()}_{file.filename}")
                file_save_path = os.path.join(app.root_path, app.config['UPLOAD_CHAT_BACKGROUND_FOLDER'], filename)

                file.save(file_save_path)
                new_background_path = os.path.join(app.config['UPLOAD_CHAT_BACKGROUND_FOLDER'], filename).replace('\\', '/')
                message = "Custom chat background uploaded and set!"
            else:
                flash('Invalid file type for background image. Allowed types: png, jpg, jpeg, gif.', 'danger')
                return redirect(url_for('settings'))

        elif action == 'use_profile_photo':
            user_member_profile = db.execute('SELECT profilePhoto FROM members WHERE user_id = ?', (current_user.id,)).fetchone()
            if user_member_profile and user_member_profile['profilePhoto']:
                new_background_path = user_member_profile['profilePhoto']
                message = "Profile photo set as chat background!"
            else:
                flash('You do not have a profile photo to use as background.', 'danger')
                return redirect(url_for('settings'))

        elif action == 'clear':
            new_background_path = None
            message = "Chat background cleared successfully!"
        else:
            flash('Invalid action for chat background.', 'danger')
            return redirect(url_for('settings'))

        if current_background_path and current_background_path != new_background_path and \
           app.config['UPLOAD_CHAT_BACKGROUND_FOLDER'] in current_background_path:
            old_background_full_path = os.path.join(app.root_path, current_background_path)
            if os.path.exists(old_background_full_path):
                try:
                    os.remove(old_background_full_path)
                    print(f"Deleted old chat background file: {old_background_full_path}")
                except OSError as e:
                    print(f"Error deleting old chat background file {old_background_full_path}: {e}")

        db.execute('UPDATE users SET chat_background_image_path = ? WHERE id = ?', (new_background_path, current_user.id))
        db.commit()
        current_user.chat_background_image_path = new_background_path

        flash(message, 'success')
    except sqlite3.Error as e:
        flash(f"Database error updating chat background: {e}", 'danger')
        success = False
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')
        success = False

    return redirect(url_for('settings'))

@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
def admin_manage_users():
    if not current_user.is_admin:
        flash('You do not have administrative access.', 'danger')
        return redirect(url_for('home'))

    db = get_db()

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id') # This is for delete_user, toggle_admin, etc.
        member_id = request.form.get('member_id') # This is for link_member_to_user, toggle_login_access, etc.

        if action == 'toggle_admin':
            target_user = User.get(user_id)
            if target_user and target_user.id != current_user.id: # Prevent admin from de-admining themselves
                new_admin_status = not target_user.is_admin
                db.execute('UPDATE users SET is_admin = ? WHERE id = ?', (1 if new_admin_status else 0, user_id))
                db.commit()
                flash(f"Admin status for {target_user.username} {'enabled' if new_admin_status else 'disabled'}.", 'success')
            else:
                flash('Cannot change admin status for this user or yourself.', 'danger')

        elif action == 'reset_password':
            target_user_id = request.form.get('user_id')
            new_password = request.form.get(f'new_password_{target_user_id}') # Dynamic name from modal
            confirm_password = request.form.get(f'confirm_password_{target_user_id}') # Dynamic name from modal

            if not new_password or not confirm_password or new_password != confirm_password:
                flash('New passwords do not match or are empty.', 'danger')
            else:
                hashed_password = generate_password_hash(new_password)
                db.execute('UPDATE users SET password_hash = ?, password_reset_pending = 0, reset_request_timestamp = NULL WHERE id = ?', (hashed_password, target_user_id))
                db.commit()
                flash(f'Password for user ID {target_user_id} has been reset.', 'success')

        elif action == 'initiate_password_reset':
            target_user_id = request.form.get('user_id')
            db.execute('UPDATE users SET password_reset_pending = 1, reset_request_timestamp = NULL WHERE id = ?', (target_user_id,))
            db.commit()
            flash(f'Password reset initiated for user ID {target_user_id}. They will be prompted to set a new password on next login.', 'info')

        # --- ADDED: Delete User Action ---
        elif action == 'delete_user':
            user_id_to_delete = request.form.get('user_id') # Use a distinct variable name
            if not user_id_to_delete:
                flash("User ID not provided for deleting user.", 'danger')
                return redirect(url_for('admin_manage_users'))

            try:
                user_to_delete_data = db.execute('SELECT id, username FROM users WHERE id = ?', (user_id_to_delete,)).fetchone()
                if not user_to_delete_data:
                    flash(f"User with ID {user_id_to_delete} not found.", 'danger')
                    return redirect(url_for('admin_manage_users'))

                if user_to_delete_data['username'] == app.config['ADMIN_USERNAME']:
                    flash("Cannot delete the super admin account.", 'danger')
                    return redirect(url_for('admin_manage_users'))

                # Delete associated data first to maintain referential integrity
                db.execute('DELETE FROM members WHERE user_id = ?', (user_id_to_delete,))
                db.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', (user_id_to_delete, user_id_to_delete))
                db.execute('DELETE FROM chat_media WHERE sender_id = ? OR receiver_id = ?', (user_id_to_delete, user_id_to_delete))
                # If temporary_videos has a user_id, add:
                # db.execute('DELETE FROM temporary_videos WHERE user_id = ?', (user_id_to_delete,))

                # Finally, delete the user
                db.execute('DELETE FROM users WHERE id = ?', (user_id_to_delete,))
                db.commit()
                flash(f"User '{user_to_delete_data['username']}' and all associated data deleted successfully.", 'success')
            except sqlite3.Error as e:
                db.rollback()
                flash(f"Database error deleting user: {e}", 'danger')
            except Exception as e:
                flash(f"An unexpected error occurred deleting user: {e}", 'danger')

            return redirect(url_for('admin_manage_users'))
        # --- END ADDED: Delete User Action ---

        elif action == 'link_member_to_user':
            new_username = request.form.get('new_username')
            new_password = request.form.get('new_password')
            member_id_to_link = request.form.get('member_id')

            if not new_username or not new_password or not member_id_to_link:
                flash('Missing data for linking user.', 'danger')
            else:
                existing_user = db.execute('SELECT id FROM users WHERE username = ?', (new_username,)).fetchone()
                if existing_user:
                    flash('Username already exists. Please choose a different one.', 'danger')
                else:
                    try:
                        member_to_link = db.execute('SELECT fullName, association FROM members WHERE id = ?', (member_id_to_link,)).fetchone()
                        if not member_to_link:
                            flash('Member not found for linking.', 'danger')
                        else:
                            hashed_password = generate_password_hash(new_password)
                            cursor = db.execute(
                                # FIX: Removed chat_background_image_path from INSERT query
                                'INSERT INTO users (username, originalName, relationshipToRaphael, password, theme_preference, unique_key, password_reset_pending, reset_request_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                                (new_username, member_to_link['fullName'], member_to_link['association'], hashed_password, 'light', generate_unique_key(), 0, None)
                            )
                            new_user_id = cursor.lastrowid
                            db.execute('UPDATE members SET user_id = ?, has_login_access = 1, can_message = 1 WHERE id = ?', (new_user_id, member_id_to_link))
                            db.commit()
                            flash(f'User {new_username} created and linked to {member_to_link["fullName"]}. Login access enabled.', 'success')
                    except sqlite3.IntegrityError:
                        flash('Username already exists or database error.', 'danger')
                    except Exception as e:
                        flash(f'An error occurred during linking: {e}', 'danger')

        elif action == 'toggle_login_access':
            member_id_toggle = request.form.get('member_id')
            member_data = db.execute('SELECT user_id, has_login_access FROM members WHERE id = ?', (member_id_toggle,)).fetchone()
            if member_data and member_data['user_id']:
                new_access_status = not member_data['has_login_access']
                db.execute('UPDATE members SET has_login_access = ? WHERE id = ?', (1 if new_access_status else 0, member_id_toggle))
                db.commit()
                flash(f"Login access for member ID {member_id_toggle} {'enabled' if new_access_status else 'disabled'}.", 'success')
            else:
                flash('Cannot toggle login access for unlinked member or member not found.', 'danger')

        elif action == 'toggle_messaging_capability':
            member_id_toggle = request.form.get('member_id')
            member_data = db.execute('SELECT user_id, can_message FROM members WHERE id = ?', (member_id_toggle,)).fetchone()
            if member_data and member_data['user_id']:
                new_message_status = not member_data['can_message']
                db.execute('UPDATE members SET can_message = ? WHERE id = ?', (1 if new_message_status else 0, member_id_toggle))
                db.commit()
                flash(f"Messaging for member ID {member_id_toggle} {'enabled' if new_message_status else 'disabled'}.", 'success')
            else:
                flash('Cannot toggle messaging for unlinked member or member not found.', 'danger')

        return redirect(url_for('admin_manage_users'))

    # Reload data after any POST request
    users = db.execute('SELECT id, username, originalName, relationshipToRaphael, is_admin, unique_key, password_reset_pending, reset_request_timestamp FROM users ORDER BY username ASC').fetchall()

    members_with_status = db.execute('''
        SELECT m.*, u.username AS linked_username
        FROM members m
        LEFT JOIN users u ON m.user_id = u.id
        ORDER BY m.fullName ASC
    ''').fetchall()

    return render_template('admin_manage_users.html', users=users, members_with_status=members_with_status)

@app.route('/delete_member/<int:member_id>', methods=['POST'])
@login_required
def delete_member(member_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete members.', 'danger')
        return redirect(url_for('home'))

    db = get_db()
    member_to_delete = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()

    if not member_to_delete:
        flash('Member not found.', 'danger')
        return redirect(url_for('list_members'))

    try:
        # Delete associated profile photo if exists
        if member_to_delete['profilePhoto']:
            photo_path = os.path.join(app.root_path, member_to_delete['profilePhoto'])
            if os.path.exists(photo_path):
                os.remove(photo_path)
                print(f"Deleted profile photo: {photo_path}")

        # If member is linked to a user, delete the user account and all their messages/media
        if member_to_delete['user_id']:
            user_id_to_delete = member_to_delete['user_id']
            if user_id_to_delete == current_user.id:
                flash('You cannot delete your own user account through this interface.', 'danger')
                return redirect(url_for('admin_manage_users'))

            # Delete user's chat media
            user_chat_media = db.execute('SELECT file_path FROM chat_media WHERE sender_id = ? OR receiver_id = ?', (user_id_to_delete, user_id_to_delete)).fetchall()
            for media in user_chat_media:
                media_file_path = os.path.join(app.root_path, media['file_path'])
                if os.path.exists(media_file_path):
                    os.remove(media_file_path)
                    print(f"Deleted chat media: {media_file_path}")
            db.execute('DELETE FROM chat_media WHERE sender_id = ? OR receiver_id = ?', (user_id_to_delete, user_id_to_delete))

            # Delete user's messages
            db.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', (user_id_to_delete, user_id_to_delete))

            # Delete user's temporary videos
            user_temp_videos = db.execute('SELECT file_path FROM temporary_videos WHERE member_id = ?', (member_id,)).fetchall()
            for video in user_temp_videos:
                video_file_path = os.path.join(app.root_path, video['file_path'])
                if os.path.exists(video_file_path):
                    os.remove(video_file_path)
                    print(f"Deleted temporary video: {video_file_path}")
            db.execute('DELETE FROM temporary_videos WHERE member_id = ?', (member_id,))

            # Delete the user account itself
            db.execute('DELETE FROM users WHERE id = ?', (user_id_to_delete,))
            flash(f"User account and all associated data for {member_to_delete['fullName']} deleted.", 'success')

        # Finally, delete the member profile
        db.execute('DELETE FROM members WHERE id = ?', (member_id,))
        db.commit()
        flash(f"Member profile for {member_to_delete['fullName']} deleted successfully.", 'success')

    except sqlite3.Error as e:
        flash(f"Database error deleting member: {e}", 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('admin_manage_users'))


@app.route('/edit-member/<int:member_id>', methods=['GET', 'POST'])
@login_required
def edit_member(member_id):
    db = get_db()
    member = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()

    if not member:
        flash('Member not found.', 'danger')
        return redirect(url_for('list_members'))

    # Check if current user is admin OR the user linked to this member OR the user who added this member
    if not (current_user.is_admin or (member['user_id'] is not None and current_user.id == member['user_id']) or (member['added_by_user_id'] is not None and current_user.id == member['added_by_user_id'])):
        flash('You do not have permission to edit this member.', 'danger')
        return redirect(url_for('member_detail', member_id=member_id))

    if request.method == 'POST':
        full_name = request.form['fullName']
        gender = request.form['gender']
        whereabouts = request.form['whereabouts']
        contact = request.form['contact']
        bio = request.form['bio']
        date_of_birth = request.form.get('dateOfBirth')
        marital_status = request.form.get('maritalStatus')
        spouse_names = request.form.get('spouseNames', '')
        girlfriend_names = request.form.get('girlfriendNames', '')
        children_names = request.form.get('childrenNames', '')
        school_name = request.form.get('schoolName', '')
        personal_relationship_description = request.form.get('personalRelationshipDescription', '')
        can_message = 1 if request.form.get('can_message') else 0

        if marital_status == 'Engaged' and girlfriend_names:
            spouse_names = girlfriend_names

        if contact:
            contacts_list = [c.strip() for c in contact.split(',') if c.strip()]
            for c in contacts_list:
                if '@' in c:
                    if not (c.count('@') == 1 and '.' in c.split('@')[1]):
                        flash('Invalid email format in contact information.', 'danger')
                        return render_template('edit_member.html', member=member)
                else:
                    if not (c.replace('+', '').replace('-', '').replace('(', '').replace(')', '').replace(' ', '').isdigit()):
                        flash('Invalid phone number format in contact information.', 'danger')
                        return render_template('edit_member.html', member=member)

        if not full_name or not gender:
            flash('Full Name and Gender are required.', 'danger')
            return render_template('edit_member.html', member=member)

        profile_photo_path = member['profilePhoto'] # Keep existing photo by default
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                # Delete old photo if it exists and is different
                if profile_photo_path and os.path.exists(os.path.join(app.root_path, profile_photo_path)):
                    try:
                        os.remove(os.path.join(app.root_path, profile_photo_path))
                        print(f"Removed old profile photo: {profile_photo_path}")
                    except OSError as e:
                        print(f"Error deleting old profile photo {profile_photo_path}: {e}")

                filename = secure_filename(f"{member['id']}_{datetime.utcnow().timestamp()}_{file.filename}")
                file_save_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
                file.save(file_save_path)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')

        association = request.form['association'] # Get association from form

        try:
            is_raphael_descendant = 1 if association.lower() in ['son of raphael nyanga', 'daughter of raphael nyanga', 'grandchild of raphael nyanga', 'great-grandchild of raphael nyanga'] else 0

            db.execute(
                'UPDATE members SET fullName = ?, association = ?, gender = ?, whereabouts = ?, contact = ?, bio = ?, profilePhoto = ?, dateOfBirth = ?, maritalStatus = ?, spouseNames = ?, childrenNames = ?, isRaphaelDescendant = ?, needs_details_update = ?, schoolName = ?, can_message = ?, personalRelationshipDescription = ? WHERE id = ?',
                (full_name, association, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, is_raphael_descendant, 0, school_name, can_message, personal_relationship_description, member_id)
            )
            db.commit()

            # If the member is linked to a user, update the user's originalName and relationshipToRaphael
            if member['user_id']:
                db.execute('UPDATE users SET originalName = ?, relationshipToRaphael = ? WHERE id = ?',
                           (full_name, association, member['user_id']))
                db.commit()

            flash('Member details updated successfully!', 'success')
            return redirect(url_for('member_detail', member_id=member_id))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')

    return render_template('edit_member.html', member=member)

if __name__ == '__main__':
    # You might want to run init_db() only once or conditionally
    # For development, you can uncomment it to re-initialize DB on each run
    #init_db()
    app.run(debug=True)