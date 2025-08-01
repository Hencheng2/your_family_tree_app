import sqlite3
import os
from datetime import datetime, timedelta, timezone
import random
import string
import json
import google.generativeai as genai
import firebase_admin
from firebase_admin import credentials, initialize_app, firestore


from flask import Flask, render_template, request, redirect, url_for, g, flash, session, abort, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_moment import Moment

import config

app = Flask(__name__)
# Use environment variable for SECRET_KEY or fall back to config.py
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', config.SECRET_KEY)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'family_tree.db')

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'img', 'profile_photos')
app.config['UPLOAD_VIDEO_FOLDER'] = os.path.join('static', 'videos', 'status_videos')
app.config['UPLOAD_CHAT_PHOTO_FOLDER'] = os.path.join('static', 'chat_media', 'photos')
app.config['UPLOAD_CHAT_VIDEO_FOLDER'] = os.path.join('static', 'chat_media', 'videos')
app.config['UPLOAD_CHAT_BACKGROUND_FOLDER'] = os.path.join('static', 'img', 'chat_backgrounds')

app.config['ADMIN_USERNAME'] = config.ADMIN_USERNAME
app.config['ADMIN_PASS'] = config.ADMIN_PASS

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'webm'}
ALLOWED_CHAT_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_CHAT_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'webm'}
ALLOWED_BACKGROUND_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_VIDEO_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_CHAT_PHOTO_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_CHAT_VIDEO_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_CHAT_BACKGROUND_FOLDER']), exist_ok=True)


# --- SQLite3 Database Functions ---
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
        # The schema.sql content is embedded here for clarity and to ensure consistency.
        # If you modify schema.sql as a separate file, you MUST ensure this embedded string matches.
        schema_sql_content = """
            -- schema.sql

            -- Drop existing tables (order matters due to foreign keys)
            DROP TABLE IF EXISTS chat_messages;
            DROP TABLE IF EXISTS chat_room_members;
            DROP TABLE IF EXISTS chat_rooms;
            DROP TABLE IF EXISTS messages;
            DROP TABLE IF EXISTS statuses;
            DROP TABLE IF EXISTS members;
            DROP TABLE IF EXISTS users;

            -- Create users table
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                originalName TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                theme_preference TEXT DEFAULT 'light',
                chat_background_image_path TEXT,
                unique_key TEXT UNIQUE NOT NULL,
                password_reset_pending INTEGER DEFAULT 0,
                reset_request_timestamp TIMESTAMP,
                last_login_at TIMESTAMP,
                last_seen_at TIMESTAMP
            );

            -- Create members table
            CREATE TABLE members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullName TEXT NOT NULL,
                gender TEXT NOT NULL,
                dateOfBirth TEXT,
                maritalStatus TEXT,
                spouseNames TEXT,
                childrenNames TEXT,
                schoolName TEXT,
                whereabouts TEXT,
                contact TEXT,
                bio TEXT,
                personalRelationshipDescription TEXT,
                profilePhoto TEXT,
                user_id INTEGER UNIQUE,
                needs_details_update INTEGER DEFAULT 0,
                added_by_user_id INTEGER NOT NULL,
                can_message INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (added_by_user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            -- Create messages table (for private messages/admin notifications)
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL, -- RENAMED from receiver_id
                content TEXT NOT NULL,          -- RENAMED from body
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                is_admin_message INTEGER DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE -- RENAMED from receiver_id
            );

            -- Create statuses table (renamed from temporary_videos)
            CREATE TABLE statuses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_id INTEGER UNIQUE NOT NULL,
                file_path TEXT NOT NULL,
                upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_video INTEGER DEFAULT 0,
                uploader_user_id INTEGER NOT NULL,
                FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE,
                FOREIGN KEY (uploader_user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            -- NEW TABLES FOR CHAT ROOMS AND MESSAGES (including AI chat history)
            CREATE TABLE chat_rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_group_chat INTEGER DEFAULT 0
            );

            CREATE TABLE chat_room_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_room_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin INTEGER DEFAULT 0,
                FOREIGN KEY (chat_room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE (chat_room_id, user_id)
            );

            CREATE TABLE chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_room_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                content TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                media_path TEXT,
                media_type TEXT,
                is_ai_message INTEGER DEFAULT 0,
                FOREIGN KEY (chat_room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """
        db.executescript(schema_sql_content)
        db.commit()
        print("Database initialized.")

# --- Custom Model Classes ---
class User(UserMixin):
    def __init__(self, id, username, originalName, password_hash, is_admin=False, theme_preference='light', chat_background_image_path=None, unique_key=None, password_reset_pending=0, reset_request_timestamp=None, last_login_at=None, last_seen_at=None):
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
        self.last_login_at = last_login_at
        self.last_seen_at = last_seen_at

    def get_id(self):
        return str(self.id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
            last_login_at = user_data['last_login_at'] if 'last_login_at' in user_data.keys() else None
            last_seen_at = user_data['last_seen_at'] if 'last_seen_at' in user_data.keys() else None

            return User(user_data['id'], user_data['username'], user_data['originalName'],
                        user_data['password_hash'],
                        is_admin_status, theme_preference,
                        chat_background_image_path, unique_key,
                        password_reset_pending, reset_request_timestamp,
                        last_login_at, last_seen_at)
        if user_id == 0 and app.config['ADMIN_USERNAME'] == 'Henry':
            return User(0, app.config['ADMIN_USERNAME'], 'Admin User', generate_password_hash(config.ADMIN_PASS), is_admin=True, theme_preference='dark', chat_background_image_path=None, unique_key='ADM0', password_reset_pending=0, reset_request_timestamp=None, last_login_at=datetime.utcnow(), last_seen_at=datetime.utcnow())
        return None

class Member:
    def __init__(self, id, fullName, dateOfBirth, gender, maritalStatus, spouseNames, childrenNames, schoolName, whereabouts, contact, bio, personalRelationshipDescription, profilePhoto, user_id, can_message=1, added_by_user_id=None, needs_details_update=1):
        self.id = id
        self.fullName = fullName
        self.dateOfBirth = dateOfBirth
        self.gender = gender
        self.maritalStatus = maritalStatus
        self.spouseNames = spouseNames
        self.childrenNames = childrenNames
        self.schoolName = schoolName
        self.whereabouts = whereabouts
        self.contact = contact
        self.bio = bio
        self.personalRelationshipDescription = personalRelationshipDescription
        self.profilePhoto = profilePhoto
        self.user_id = user_id
        self.can_message = can_message
        self.added_by_user_id = added_by_user_id
        self.needs_details_update = needs_details_update

    @property
    def user(self):
        if self.user_id:
            return User.get(self.user_id)
        return None

class Status: # Represents an entry in the 'statuses' table
    def __init__(self, id, file_path, upload_time, is_video, member_id, uploader_user_id):
        self.id = id
        self.file_path = file_path
        self.upload_time = upload_time
        self.is_video = is_video
        self.member_id = member_id
        self.uploader_user_id = uploader_user_id

class Message: # Represents an entry in the 'messages' table (direct messages/admin notifications)
    def __init__(self, id, sender_id, recipient_id, content, timestamp, is_read, is_admin_message):
        self.id = id
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.content = content
        self.timestamp = timestamp
        self.is_read = is_read
        self.is_admin_message = is_admin_message

class ChatRoom:
    def __init__(self, id, name, created_at, is_group_chat):
        self.id = id
        self.name = name
        self.created_at = created_at
        self.is_group_chat = is_group_chat

class ChatRoomMember:
    def __init__(self, id, chat_room_id, user_id, joined_at, is_admin):
        self.id = id
        self.chat_room_id = chat_room_id
        self.user_id = user_id
        self.joined_at = joined_at
        self.is_admin = is_admin

class ChatMessage:
    def __init__(self, id, chat_room_id, sender_id, content, timestamp, media_path, media_type):
        self.id = id
        self.chat_room_id = chat_room_id
        self.sender_id = sender_id
        self.content = content
        self.timestamp = timestamp
        self.media_path = media_path
        self.media_type = media_type


# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    if user_id is None:
        return None
    try:
        return User.get(int(user_id))
    except (ValueError, TypeError):
        return None

# --- Flask-Moment Setup ---
moment = Moment(app)

# --- Firebase Admin SDK Initialization ---
firestore_db = None
try:
    if not firebase_admin._apps:
        cred_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), config.FIREBASE_ADMIN_CREDENTIALS_PATH)
        cred = credentials.Certificate(cred_path)
        initialize_app(cred)
    firestore_db = firestore.client()
    print("Firebase Admin SDK initialized successfully.")
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {e}. Please ensure '{config.FIREBASE_ADMIN_CREDENTIALS_PATH}' is in your project directory and is a valid JSON key file.")


# --- Gemini API Configuration ---
GEMINI_API_KEY = config.GEMINI_API_KEY
if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
    print("WARNING: GEMINI_API_KEY is not set in config.py or is still a placeholder. AI chat will not function.")
genai.configure(api_key=GEMINI_API_KEY)


# --- Helper functions ---
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
        member_data = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()
        if member_data:
            return Member(
                id=member_data['id'],
                fullName=member_data['fullName'],
                dateOfBirth=member_data['dateOfBirth'],
                gender=member_data['gender'],
                maritalStatus=member_data['maritalStatus'],
                spouseNames=member_data['spouseNames'],
                childrenNames=member_data['childrenNames'],
                schoolName=member_data['schoolName'],
                whereabouts=member_data['whereabouts'],
                contact=member_data['contact'],
                bio=member_data['bio'],
                personalRelationshipDescription=member_data['personalRelationshipDescription'],
                profilePhoto=member_data['profilePhoto'],
                user_id=member_data['user_id'],
                can_message=member_data['can_message'],
                added_by_user_id=member_data['added_by_user_id'],
                needs_details_update=member_data['needs_details_update']
            )
    return None

def get_unread_messages_count():
    if current_user.is_authenticated:
        try:
            db = get_db()
            # Use 'recipient_id' and 'is_read' from the 'messages' table
            count_messages = db.execute('SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND is_read = 0', (current_user.id,)).fetchone()[0]
            return count_messages
        except sqlite3.OperationalError:
            print("Skipping unread message count due to missing 'messages' table.")
            return 0
        except Exception as e:
            print(f"Error getting unread messages count: {e}")
            return 0
    return 0

def cleanup_expired_videos():
    db = get_db()
    now = datetime.utcnow()
    expiration_threshold = now - timedelta(hours=12)

    try:
        # Use 'statuses' table and 'upload_time' column
        expired_videos = db.execute('SELECT id, file_path FROM statuses WHERE upload_time < ?', (expiration_threshold,)).fetchall()

        for video in expired_videos:
            video_path = os.path.join(app.root_path, video['file_path'])
            if os.path.exists(video_path):
                try:
                    os.remove(video_path)
                    print(f"Deleted expired status file: {video_path}")
                except OSError as e:
                    print(f"Error deleting status file {video_path}: {e}")
            else:
                print(f"Expired status file not found on disk, removing DB entry: {video['id']}")

            db.execute('DELETE FROM statuses WHERE id = ?', (video['id'],))
            db.commit()
            print(f"Removed expired status DB entry for ID: {video['id']}")
    except sqlite3.OperationalError as e:
        print(f"Skipping cleanup_expired_videos due to missing table: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during cleanup_expired_videos: {e}")


def cleanup_expired_chat_media():
    db = get_db()
    now = datetime.utcnow()
    expiration_threshold = now - timedelta(days=5)

    try:
        # Use 'chat_messages' table and 'media_path', 'timestamp' columns
        expired_media_messages = db.execute('SELECT id, media_path FROM chat_messages WHERE media_path IS NOT NULL AND timestamp < ?', (expiration_threshold,)).fetchall()

        for media_msg in expired_media_messages:
            media_path = os.path.join(app.root_path, media_msg['media_path'])
            if os.path.exists(media_path):
                try:
                    os.remove(media_path)
                    print(f"Deleted expired chat media file: {media_path}")
                except OSError as e:
                    print(f"Error deleting chat media file {media_path}: {e}")
            else:
                print(f"Expired chat media file not found on disk, removing DB entry for message ID: {media_msg['id']}")
    except sqlite3.OperationalError as e:
        print(f"Skipping cleanup_expired_chat_media due to missing table: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during cleanup_expired_chat_media: {e}")


def create_ai_user_and_member():
    db_conn = get_db()
    ai_username = "AdminAI"
    ai_original_name = "Admin AI"
    ai_unique_key = "AI001"
    ai_gender = "Other"

    ai_user_data = db_conn.execute('SELECT id FROM users WHERE username = ?', (ai_username,)).fetchone()

    if not ai_user_data:
        ai_password_hash = generate_password_hash(config.AI_USER_PASSWORD)
        db_conn.execute(
            'INSERT INTO users (username, password_hash, originalName, is_admin, unique_key) VALUES (?, ?, ?, ?, ?)',
            (ai_username, ai_password_hash, ai_original_name, 0, ai_unique_key)
        )
        db_conn.commit()
        ai_user_id = db_conn.execute('SELECT id FROM users WHERE username = ?', (ai_username,)).fetchone()[0]
        print(f"Created new AI user with ID: {ai_user_id}")
    else:
        ai_user_id = ai_user_data[0]
        print(f"AI user already exists with ID: {ai_user_id}")

    ai_member_data = db_conn.execute('SELECT id FROM members WHERE user_id = ?', (ai_user_id,)).fetchone()
    if not ai_member_data:
        db_conn.execute(
            'INSERT INTO members (fullName, user_id, can_message, gender, added_by_user_id, profilePhoto) VALUES (?, ?, ?, ?, ?, ?)',
            (ai_original_name, ai_user_id, 1, ai_gender, ai_user_id, os.path.join(app.config['UPLOAD_FOLDER'], 'ai_icon.png').replace('\\', '/'))
        )
        db_conn.commit()
        print(f"Created member profile for AI user {ai_user_id}.")
    else:
        current_ai_photo = db_conn.execute('SELECT profilePhoto FROM members WHERE user_id = ?', (ai_user_id,)).fetchone()
        expected_ai_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'ai_icon.png').replace('\\', '/')
        if not current_ai_photo or current_ai_photo['profilePhoto'] != expected_ai_photo_path:
            db_conn.execute('UPDATE members SET profilePhoto = ? WHERE user_id = ?', (expected_ai_photo_path, ai_user_id))
            db_conn.commit()
            print(f"Updated AI member profile photo for AI user {ai_user_id}.")


# --- Run AI user creation and DB initialization on app startup ---
with app.app_context():
    db_file_exists = os.path.exists(DATABASE)
    db_conn = get_db() # Get a connection

    if not db_file_exists:
        print("Database file not found, initializing fresh DB...")
        init_db() # This will create the DB and all tables
        print("Database initialized.")
    else:
        try:
            # Attempt to access a table/column that would be missing if schema is old
            db_conn.execute("SELECT id FROM statuses LIMIT 1")
            db_conn.execute("SELECT recipient_id, content FROM messages LIMIT 1")
            print("Database file exists and schema appears up-to-date.")
        except sqlite3.OperationalError as e:
            print(f"WARNING: Database schema might be outdated or incomplete ({e}).")
            print("To apply the latest schema, please delete 'family_tree.db' manually from your PythonAnywhere 'Files' tab and then reload your web application.")
            print("Note: This will delete all existing data.")
        except Exception as e:
            print(f"An unexpected error occurred during database schema check: {e}")

    # Ensure AI user is created/updated after DB is confirmed to be initialized
    create_ai_user_and_member()

# --- Global context processor ---
@app.context_processor
def inject_global_template_vars():
    client_firebase_config = config.FIREBASE_CLIENT_CONFIG
    initial_auth_token = getattr(g, 'initial_auth_token', '')

    unread_messages_count = 0
    if current_user.is_authenticated:
        try:
            db = get_db()
            unread_count_data = db.execute(
                'SELECT COUNT(id) FROM messages WHERE recipient_id = ? AND is_read = 0',
                (current_user.id,)
            ).fetchone()
            unread_messages_count = unread_count_data[0] if unread_count_data else 0
        except sqlite3.OperationalError:
            print("Skipping unread message count due to missing 'messages' table during context processing.")
            unread_messages_count = 0
        except Exception as e:
            print(f"Error getting unread messages count: {e}")
            unread_messages_count = 0


    return {
        'now': datetime.utcnow(),
        'config': app.config,
        'firebase_config_json': json.dumps(client_firebase_config),
        'initial_auth_token': initial_auth_token,
        'current_user': current_user,
        'unread_messages_count': unread_messages_count,
        'canvas_app_id': config.CANVAS_APP_ID
    }

# --- Before Request Hook ---
@app.before_request
def before_request_hook():
    db = get_db()

    g.user_member = get_current_user_member_profile()
    g.unread_messages_count = get_unread_messages_count()
    cleanup_expired_videos()
    cleanup_expired_chat_media()

    if current_user.is_authenticated:
        db.execute('UPDATE users SET last_seen_at = ? WHERE id = ?', (datetime.utcnow(), current_user.id))
        db.commit()

        g.user_theme = current_user.theme_preference
        g.user_chat_background = current_user.chat_background_image_path
        g.user_unique_key = current_user.unique_key
    else:
        g.user_theme = request.cookies.get('theme', 'light')
        g.user_chat_background = None
        g.user_unique_key = None

# --- API Route for AI Chat (from v17) ---
@app.route('/api/send_ai_message', methods=['POST'])
@login_required
def send_ai_message():
    if not firestore_db:
        print("Firestore DB not initialized, cannot send AI message.")
        return jsonify({'error': 'AI service not available. Firestore not initialized.'}), 500

    data = request.get_json()
    user_message = data.get('message')
    human_user_id = data.get('humanUserId')

    if not user_message or not human_user_id:
        return jsonify({'error': 'Message or human user ID missing.'}), 400

    db_conn = get_db()
    ai_user_data = db_conn.execute('SELECT id FROM users WHERE username = ?', ('AdminAI',)).fetchone()
    if not ai_user_data:
        print("AdminAI user not found in SQLite DB.")
        return jsonify({'error': 'AI user not configured.'}), 500

    ai_user_id = str(ai_user_data[0])
    human_user_id_str = str(human_user_id)
    chat_collection_path = f'artifacts/{config.CANVAS_APP_ID}/users/{human_user_id_str}/conversations/{ai_user_id}/messages'

    try:
        firestore_db.collection(chat_collection_path).add({
            'senderId': human_user_id_str,
            'message': user_message,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'isAI': False
        })

        history = []
        messages_ref = firestore_db.collection(chat_collection_path).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(5)
        docs = messages_ref.get()
        for doc in docs:
            msg = doc.to_dict()
            role = "model" if msg.get('isAI') else "user"
            history.append({"role": role, "parts": [{"text": msg.get('message', '')}]})
        history.reverse()

        model = genai.GenerativeModel('gemini-pro')
        gemini_response = model.generate_content(history)
        ai_response_text = gemini_response.text

        firestore_db.collection(chat_collection_path).add({
            'senderId': ai_user_id,
            'message': ai_response_text,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'isAI': True
        })
        return jsonify({'success': True, 'response': ai_response_text})
    except Exception as e:
        print(f"Error communicating with AI or Firestore: {e}")
        return jsonify({'error': f'Failed to get AI response: {e}'}), 500

# --- ROUTES ---
@app.route('/')
def root_redirect():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('home'))

@app.route('/get-ai-user-id') # From v17
@login_required
def get_ai_user_id():
    db = get_db()
    ai_user_data = db.execute('SELECT id FROM users WHERE username = ?', ('AdminAI',)).fetchone()
    if ai_user_data:
        return jsonify({'ai_user_id': ai_user_data['id']})
    return jsonify({'ai_user_id': None}), 404

@app.route('/home')
@login_required
def home():
    background_image = url_for('static', filename='img/Nyangabackground.jpg')
    return render_template('index.html', background_image=background_image, member=g.user_member, unread_messages_count=g.unread_messages_count)

# --- User Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))

    form_data = {} # Initialize form_data for all cases

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin_attempt = request.form.get('admin_login_checkbox')
        db = get_db()

        if is_admin_attempt:
            if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASS']:
                admin_user = User(0, app.config['ADMIN_USERNAME'], 'Admin User', generate_password_hash(app.config['ADMIN_PASS']), is_admin=True, theme_preference='dark', chat_background_image_path=None, unique_key='ADM0', password_reset_pending=0, reset_request_timestamp=None, last_login_at=datetime.utcnow(), last_seen_at=datetime.utcnow())
                login_user(admin_user)
                flash('Logged in as administrator!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid admin credentials.', 'danger')
        else:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user['password_hash'], password):
                # Check for password reset pending
                if user['password_reset_pending']:
                    flash('Your password reset is pending. Please complete the reset process.', 'warning')
                    return redirect(url_for('reset_password', unique_key=user['unique_key']))

                user_obj = User.get(user['id']) # Use the User.get static method
                login_user(user_obj)
                db.execute('UPDATE users SET last_login_at = ?, last_seen_at = ? WHERE id = ?',
                           (datetime.utcnow(), datetime.utcnow(), user['id']))
                db.commit()
                flash('Logged in successfully.', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password. Please check your credentials.', 'danger')

        form_data = request.form.to_dict() # Retain form data on failed login
    return render_template('login.html', form_data=form_data)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already registered and logged in.', 'info')
        return redirect(url_for('home'))

    form_data = {}
    if request.method == 'POST':
        username = request.form['username'].strip()
        original_name = request.form['originalName'].strip()
        gender = request.form['gender']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        form_data = request.form.to_dict() # Store submitted data

        db = get_db()
        # Check if username already exists
        existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', form_data=form_data)

        # Password validation
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', form_data=form_data)
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html', form_data=form_data)

        # Generate unique key for the new user
        unique_key = generate_unique_key()
        while db.execute('SELECT id FROM users WHERE unique_key = ?', (unique_key,)).fetchone():
            unique_key = generate_unique_key()

        hashed_password = generate_password_hash(password)

        try:
            db.execute(
                'INSERT INTO users (username, originalName, password_hash, unique_key) VALUES (?, ?, ?, ?)',
                (username, original_name, hashed_password, unique_key)
            )
            db.commit()

            user_id = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()[0]

            # Create a corresponding member profile for the new user
            db.execute(
                'INSERT INTO members (fullName, gender, user_id, added_by_user_id, needs_details_update) VALUES (?, ?, ?, ?, ?)',
                (original_name, gender, user_id, user_id, 1) # Set needs_details_update to 1 for new users
            )
            db.commit()

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'An error occurred during registration: {e}', 'danger')
            return render_template('register.html', form_data=form_data)
    return render_template('register.html', form_data=form_data)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- User Profile Management ---
@app.route('/my_profile', methods=['GET', 'POST'])
@login_required
def my_profile():
    db = get_db()
    member_profile = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()
    user_data = db.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()

    if not member_profile:
        flash("Your member profile is missing. Please contact an administrator.", "danger")
        return redirect(url_for('home'))

    form_data = {
        'fullName': member_profile['fullName'],
        'dateOfBirth': member_profile['dateOfBirth'],
        'gender': member_profile['gender'],
        'maritalStatus': member_profile['maritalStatus'],
        'spouseNames': member_profile['spouseNames'],
        'childrenNames': member_profile['childrenNames'],
        'schoolName': member_profile['schoolName'],
        'whereabouts': member_profile['whereabouts'],
        'contact': member_profile['contact'],
        'bio': member_profile['bio'],
        'personalRelationshipDescription': member_profile['personalRelationshipDescription'],
        'profilePhoto': member_profile['profilePhoto'],
        'username': user_data['username'],
        'originalName': user_data['originalName']
    }

    if request.method == 'POST':
        new_username = request.form['username'].strip()
        new_original_name = request.form['originalName'].strip()
        new_full_name = request.form['fullName'].strip()
        new_date_of_birth = request.form['dateOfBirth'].strip()
        new_gender = request.form['gender']
        new_marital_status = request.form['maritalStatus'].strip()
        new_spouse_names = request.form['spouseNames'].strip()
        new_children_names = request.form['childrenNames'].strip()
        new_school_name = request.form['schoolName'].strip()
        new_whereabouts = request.form['whereabouts'].strip()
        new_contact = request.form['contact'].strip()
        new_bio = request.form['bio'].strip()
        new_personal_relationship_description = request.form['personalRelationshipDescription'].strip()

        # Update form_data to reflect submitted values for re-rendering if needed
        form_data.update(request.form.to_dict())

        # Validate new username
        if new_username != current_user.username:
            existing_user = db.execute('SELECT id FROM users WHERE username = ?', (new_username,)).fetchone()
            if existing_user:
                flash('Username already taken. Please choose another.', 'danger')
                return render_template('my_profile.html', form_data=form_data)

        # Handle profile photo upload
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{current_user.id}_{file.filename}")
                file_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(file_path)
                    profile_photo_db_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')
                    db.execute('UPDATE members SET profilePhoto = ? WHERE user_id = ?',
                               (profile_photo_db_path, current_user.id))
                    db.commit()
                    form_data['profilePhoto'] = profile_photo_db_path # Update form_data for display
                    flash('Profile photo updated successfully!', 'success')
                except Exception as e:
                    flash(f"Error uploading profile photo: {e}", 'danger')
            elif file and not allowed_file(file.filename):
                flash('Invalid file type for profile photo. Allowed types: png, jpg, jpeg, gif.', 'danger')

        try:
            # Update user details
            db.execute(
                'UPDATE users SET username = ?, originalName = ? WHERE id = ?',
                (new_username, new_original_name, current_user.id)
            )

            # Update member details
            db.execute(
                '''UPDATE members SET fullName = ?, dateOfBirth = ?, gender = ?,
                   maritalStatus = ?, spouseNames = ?, childrenNames = ?,
                   schoolName = ?, whereabouts = ?, contact = ?, bio = ?,
                   personalRelationshipDescription = ?, needs_details_update = 0
                   WHERE user_id = ?''',
                (new_full_name, new_date_of_birth, new_gender, new_marital_status,
                 new_spouse_names, new_children_names, new_school_name, new_whereabouts,
                 new_contact, new_bio, new_personal_relationship_description, current_user.id)
            )
            db.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('my_profile'))
        except sqlite3.Error as e:
            flash(f'An error occurred during profile update: {e}', 'danger')
            db.rollback() # Rollback changes in case of error

    return render_template('my_profile.html', form_data=form_data)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form_data = {}
    if request.method == 'POST':
        current_password = request.form['currentPassword']
        new_password = request.form['newPassword']
        confirm_new_password = request.form['confirmNewPassword']

        # Verify current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            form_data = request.form.to_dict()
            return render_template('change_password.html', form_data=form_data)

        # Validate new password
        if new_password != confirm_new_password:
            flash('New password and confirmation do not match.', 'danger')
            form_data = request.form.to_dict()
            return render_template('change_password.html', form_data=form_data)

        if len(new_password) < 6:
            flash('New password must be at least 6 characters long.', 'danger')
            form_data = request.form.to_dict()
            return render_template('change_password.html', form_data=form_data)

        db = get_db()
        hashed_password = generate_password_hash(new_password)
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_password, current_user.id))
        db.commit()
        flash('Your password has been changed successfully!', 'success')
        return redirect(url_for('my_profile'))

    return render_template('change_password.html', form_data=form_data)


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


if __name__ == '__main__':
    # For development, initialize DB here. In production (PythonAnywhere), it's handled by WSGI.
    # with app.app_context():
    #     init_db()
    app.run(debug=True)
