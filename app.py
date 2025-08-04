import sqlite3
import os
from datetime import datetime, timedelta, timezone
import random
import string
import json
import google.generativeai as genai
import firebase_admin
from firebase_admin import credentials, initialize_app, firestore


from flask import Flask, render_template, Blueprint, request, redirect, url_for, g, flash, session, abort, jsonify, send_from_directory
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
                relationshipToRaphael TEXT NOT NULL,
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
                association TEXT NOT NULL,
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
                isRaphaelDescendant INTEGER DEFAULT 0,
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
    def __init__(self, id, username, originalName, password_hash, relationshipToRaphael, is_admin=False, theme_preference='light', chat_background_image_path=None, unique_key=None, password_reset_pending=0, reset_request_timestamp=None, last_login_at=None, last_seen_at=None):
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
                        user_data['password_hash'], user_data['relationshipToRaphael'],
                        is_admin_status, theme_preference,
                        chat_background_image_path, unique_key,
                        password_reset_pending, reset_request_timestamp,
                        last_login_at, last_seen_at)
        if user_id == 0 and app.config['ADMIN_USERNAME'] == 'Henry':
            return User(0, app.config['ADMIN_USERNAME'], 'Admin User', generate_password_hash(config.ADMIN_PASS), 'Administrator', is_admin=True, theme_preference='dark', chat_background_image_path=None, unique_key='ADM0', password_reset_pending=0, reset_request_timestamp=None, last_login_at=datetime.utcnow(), last_seen_at=datetime.utcnow())
        return None

class Member:
    def __init__(self, id, fullName, dateOfBirth, gender, association, maritalStatus, spouseNames, childrenNames, schoolName, whereabouts, contact, bio, personalRelationshipDescription, profilePhoto, user_id, can_message=1, added_by_user_id=None, needs_details_update=1, isRaphaelDescendant=0):
        self.id = id
        self.fullName = fullName
        self.dateOfBirth = dateOfBirth
        self.gender = gender
        self.association = association
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
        self.isRaphaelDescendant = isRaphaelDescendant

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
        member_data = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()
        if member_data:
            return Member(
                id=member_data['id'],
                fullName=member_data['fullName'],
                dateOfBirth=member_data['dateOfBirth'],
                gender=member_data['gender'],
                association=member_data['association'],
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
                needs_details_update=member_data['needs_details_update'],
                isRaphaelDescendant=member_data['isRaphaelDescendant'] if 'isRaphaelDescendant' in member_data.keys() else 0
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
            'INSERT INTO users (username, password_hash, originalName, relationshipToRaphael, is_admin, unique_key) VALUES (?, ?, ?, ?, ?, ?)',
            (ai_username, ai_password_hash, ai_original_name, 'AI Assistant', 0, ai_unique_key)
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
            'INSERT INTO members (fullName, association, user_id, can_message, gender, added_by_user_id, profilePhoto) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (ai_original_name, 'AI Assistant', ai_user_id, 1, ai_gender, ai_user_id, os.path.join(app.config['UPLOAD_FOLDER'], 'ai_icon.png').replace('\\', '/'))
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

    form_data = {} # Initialize form_data for all cases

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin_attempt = request.form.get('admin_login_checkbox')

        db = get_db()

        if is_admin_attempt:
            if username == app.config['ADMIN_USERNAME'] and password == app.config['ADMIN_PASS']:
                admin_user = User(0, app.config['ADMIN_USERNAME'], 'Admin User', generate_password_hash(app.config['ADMIN_PASS']), 'Administrator', is_admin=True, theme_preference='dark', chat_background_image_path=None, unique_key='ADM0', password_reset_pending=0, reset_request_timestamp=None, last_login_at=datetime.utcnow(), last_seen_at=datetime.utcnow())
                login_user(admin_user)
                flash('Logged in as Admin successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid admin username or password.', 'danger')
                form_data['username'] = username # Preserve username on failed attempt
                return render_template('login.html', form_data=form_data) # Pass form_data

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
                member_profile = db.execute('SELECT can_message FROM members WHERE user_id = ?', (user.id,)).fetchone()
                # Check for 'can_message' from the members table
                if not member_profile or member_profile['can_message'] == 0:
                    flash('Your account is not yet enabled for login. Please contact an administrator.', 'danger')
                    form_data['username'] = username # Preserve username
                    return render_template('login.html', form_data=form_data) # Pass form_data

                login_user(user)

                db.execute('UPDATE users SET last_login_at = ?, last_seen_at = ? WHERE id = ?', (datetime.utcnow(), datetime.utcnow(), user.id))
                db.commit()

                member_exists = db.execute('SELECT id FROM members WHERE user_id = ?', (user.id,)).fetchone()
                if not member_exists:
                    flash('Welcome! Please add your personal details to complete your family profile.', 'info')
                    return redirect(url_for('add_my_details'))
                else:
                    flash('Logged in successfully.', 'success')
                    return redirect(url_for('home'))
            else:
                flash('Invalid username or password.', 'danger')
                form_data['username'] = username # Preserve username
                return render_template('login.html', form_data=form_data) # Pass form_data
        else:
            flash('Invalid username or password.', 'danger')
            form_data['username'] = username # Preserve username
            return render_template('login.html', form_data=form_data) # Pass form_data

    return render_template('login.html', form_data=form_data)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form_data = {} # Initialize form_data for all cases

    if request.method == 'POST':
        username = request.form.get('username')
        original_name = request.form.get('originalName')
        gender = request.form.get('gender') # <--- NEW: Get gender from form
        relationship_to_raphael = request.form.get('relationshipToRaphael')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')

        form_data = { # Populate form_data with submitted values
            'username': username,
            'originalName': original_name,
            'gender': gender, # <--- NEW: Add gender to form_data
            'relationshipToRaphael': relationship_to_raphael
        }

        if not original_name or not gender: # <--- NEW: Validate gender
            flash('Full Name (Original Name) and Gender are required.', 'danger')
            return render_template('register.html', form_data=form_data)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', form_data=form_data)

        db = get_db()
        existing_user_data = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user_data:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', form_data=form_data)

        unique_key = generate_unique_key()
        password_hash = generate_password_hash(password)

        try:
            db.execute(
                'INSERT INTO users (username, originalName, relationshipToRaphael, password_hash, theme_preference, chat_background_image_path, unique_key, password_reset_pending, reset_request_timestamp, last_login_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (username, original_name, relationship_to_raphael, password_hash, 'light', None, unique_key, 0, None, datetime.utcnow(), datetime.utcnow())
            )
            db.commit()

            new_user_id = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()[0]

            total_users = db.execute('SELECT COUNT(id) FROM users').fetchone()[0]
            if total_users == 1: # First user registered becomes admin
                db.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (new_user_id,))
                db.commit()

            # Create a basic member profile for the new user, with can_message enabled
            # <--- NEW: Pass gender to members table insertion
            db.execute(
                'INSERT INTO members (fullName, association, gender, user_id, can_message, added_by_user_id, needs_details_update) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (original_name, relationship_to_raphael, gender, new_user_id, 1, new_user_id, 1) # needs_details_update = 1 to prompt user to fill more details
            )
            db.commit()

            flash(f'Registration successful! Your unique key is: <strong>{unique_key}</strong>. Please keep it safe for password recovery. You can now log in.', 'success')
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

@app.route('/forgot-password', methods=['GET', 'POST']) # Added GET method from new.py
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        unique_key = request.form.get('unique_key', '').upper()

        db = get_db()

        user_data = db.execute('SELECT id, username, unique_key FROM users WHERE LOWER(username) = LOWER(?)', (username,)).fetchone()

        if not user_data:
            return jsonify({'success': False, 'message': 'Username not found.'})
        if user_data['unique_key'] != unique_key:
            return jsonify({'success': False, 'message': 'Incorrect unique key.'})

        ai_user_data = db.execute('SELECT id FROM users WHERE username = ?', ('AdminAI',)).fetchone()
        if not ai_user_data:
            return jsonify({'success': False, 'message': 'Admin AI account not found. Cannot process password reset request.'})
        admin_ai_user_id = ai_user_data['id']

        message_body = f"Password reset request for user: {username}. Unique Key provided: {unique_key}. Please verify this key and initiate a password reset for this user from the Manage Users page if correct."
        try:
            # Using recipient_id and content as per v17 schema
            db.execute(
                'INSERT INTO messages (sender_id, recipient_id, content, timestamp, is_read, is_admin_message) VALUES (?, ?, ?, ?, ?, ?)',
                (user_data['id'], admin_ai_user_id, message_body, datetime.utcnow(), 0, 1)
            )
            db.execute('UPDATE users SET password_reset_pending = 1, reset_request_timestamp = ? WHERE id = ?',
                       (datetime.utcnow(), user_data['id']))
            db.commit()

            return jsonify({'success': True, 'message': 'Your password reset request has been sent to the administrator. You will be redirected to set a new password in 2 minutes if the admin does not act sooner.'})
        except sqlite3.Error as e:
            db.rollback()
            print(f"Database error during password reset request: {e}")
            return jsonify({'success': False, 'message': f"Database error during request: {e}"})
        except Exception as e:
            db.rollback()
            print(f"An unexpected error occurred during password reset request: {e}")
            return jsonify({'success': False, 'message': f"An unexpected error occurred: {e}"})

    # For GET request, display a message (from new.py)
    flash('Please use the "Forgot Password?" link on the login page to request a reset.', 'info')
    return redirect(url_for('login'))


@app.route('/my-profile')
@login_required
def my_profile():
    db = get_db()
    member_data = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()

    if not member_data:
        flash('Please add your personal details to create your family profile.', 'info')
        return redirect(url_for('add_my_details'))

    # Convert to Member object for consistency
    member_profile = Member(
        id=member_data['id'],
        fullName=member_data['fullName'],
        dateOfBirth=member_data['dateOfBirth'],
        gender=member_data['gender'],
        association=member_data['association'],
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
        needs_details_update=member_data['needs_details_update'],
        isRaphaelDescendant=member_data['isRaphaelDescendant'] if 'isRaphaelDescendant' in member_data.keys() else 0
    )

    age = calculate_age(member_profile.dateOfBirth)

    # Status video logic (adapted from new.py to use 'statuses' table)
    temp_video_data_for_template = None
    latest_status_data = db.execute('SELECT * FROM statuses WHERE member_id = ? ORDER BY upload_time DESC LIMIT 1', (member_profile.id,)).fetchone()
    if latest_status_data:
        try:
            upload_time_dt = latest_status_data['upload_time']
            if isinstance(upload_time_dt, str):
                upload_time_dt = datetime.strptime(upload_time_dt, '%Y-%m-%d %H:%M:%S.%f')

            expires_at_dt = upload_time_dt + timedelta(hours=12)
            is_active_status = (datetime.now(timezone.utc) < expires_at_dt)

            if is_active_status: # Only show if active
                temp_video_data_for_template = {
                    'file_path': latest_status_data['file_path'],
                    'upload_time': upload_time_dt,
                    'expires_at': expires_at_dt,
                    'is_active': is_active_status
                }
        except Exception as e:
            print(f"Error processing status for my_profile: {e}")
            temp_video_data_for_template = None

    return render_template('my_profile.html', member=member_profile, age=age, temp_video=temp_video_data_for_template)


@app.route('/edit-my-profile', methods=['GET', 'POST'])
@login_required
def edit_my_profile():
    db = get_db()
    member_data = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()
    if not member_data:
        flash("No member profile linked to your account. Please contact an admin.", "danger")
        return redirect(url_for('my_profile'))

    member = Member(
        id=member_data['id'],
        fullName=member_data['fullName'],
        dateOfBirth=member_data['dateOfBirth'],
        gender=member_data['gender'],
        association=member_data['association'],
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
        needs_details_update=member_data['needs_details_update'],
        isRaphaelDescendant=member_data['isRaphaelDescendant'] if 'isRaphaelDescendant' in member_data.keys() else 0
    )

    if not current_user.is_admin and (member.user_id is None or current_user.id != member.user_id):
        flash("You do not have permission to edit this profile.", "danger")
        return redirect(url_for('home'))

    # Initialize form_data with existing member data for GET request
    form_data = {
        'fullName': member.fullName,
        'dateOfBirth': str(member.dateOfBirth) if member.dateOfBirth else '',
        'gender': member.gender,
        'association': member.association,
        'maritalStatus': member.maritalStatus,
        'spouseNames': member.spouseNames,
        'childrenNames': member.childrenNames,
        'schoolName': member.schoolName,
        'whereabouts': member.whereabouts,
        'contact': member.contact,
        'bio': member.bio,
        'personalRelationshipDescription': member.personalRelationshipDescription,
        # profilePhoto is handled separately via member.profilePhoto
    }

    if request.method == 'POST':
        member.fullName = request.form.get('fullName')
        member.dateOfBirth = datetime.strptime(request.form.get('dateOfBirth'), '%Y-%m-%d').date() if request.form.get('dateOfBirth') else None
        member.gender = request.form.get('gender')
        member.association = request.form.get('association')
        member.maritalStatus = request.form.get('maritalStatus')
        member.spouseNames = request.form.get('spouseNames')
        member.childrenNames = request.form.get('childrenNames')
        member.schoolName = request.form.get('schoolName')
        member.whereabouts = request.form.get('whereabouts')
        member.contact = request.form.get('contact')
        member.bio = request.form.get('bio')
        member.personalRelationshipDescription = request.form.get('personalRelationshipDescription')

        profile_photo_file = request.files.get('profilePhoto')
        if profile_photo_file and profile_photo_file.filename != '':
            filename = secure_filename(profile_photo_file.filename)
            filepath = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
            profile_photo_file.save(filepath)
            member.profilePhoto = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')
        elif request.form.get('remove_profile_photo'):
            if member.profilePhoto and os.path.exists(os.path.join(app.root_path, member.profilePhoto)):
                os.remove(os.path.join(app.root_path, member.profilePhoto))
            member.profilePhoto = None

        needs_details_update = 0
        if not all([member.fullName, member.dateOfBirth, member.gender, member.association, member.maritalStatus,
                    member.whereabouts, member.contact, member.bio, member.personalRelationshipDescription]):
            needs_details_update = 1
            # Populate form_data with submitted values if validation fails
            form_data = request.form.to_dict() # Update form_data with current submission

        if needs_details_update == 1: # If validation failed, re-render with form_data
            flash('Please fill in all required fields.', 'danger')
            return render_template('edit_member.html', member=member, form_data=form_data)


        db.execute('''
            UPDATE members SET
                fullName = ?, dateOfBirth = ?, gender = ?, association = ?, maritalStatus = ?,
                spouseNames = ?, childrenNames = ?, schoolName = ?, whereabouts = ?, contact = ?,
                bio = ?, personalRelationshipDescription = ?, profilePhoto = ?, needs_details_update = ?
            WHERE id = ?
        ''', (
            member.fullName, member.dateOfBirth, member.gender, member.association, member.maritalStatus,
            member.spouseNames, member.childrenNames, member.schoolName, member.whereabouts, member.contact,
            member.bio, member.personalRelationshipDescription, member.profilePhoto, needs_details_update,
            member.id
        ))
        db.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('member_detail', member_id=member.id))

    return render_template('edit_member.html', member=member, form_data=form_data)


@app.route('/delete_member/<int:member_id>', methods=['POST'])
@login_required
def delete_member(member_id):
    if not current_user.is_admin:
        flash("You do not have administrative access to delete members.", "danger")
        return redirect(url_for('home'))

    db = get_db()
    member_data = db.execute('SELECT user_id, profilePhoto FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member_data:
        flash("Member not found.", "danger")
        return redirect(url_for('admin_manage_users'))

    linked_user_id = member_data['user_id']
    profile_photo_path = member_data['profilePhoto']

    try:
        # Delete associated status (from statuses table)
        db.execute('DELETE FROM statuses WHERE member_id = ?', (member_id,))

        if linked_user_id:
            # Delete user's messages (direct messages)
            db.execute('DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?', (linked_user_id, linked_user_id))
            # Delete user's chat room memberships and messages in chat_messages table
            db.execute('DELETE FROM chat_room_members WHERE user_id = ?', (linked_user_id,))
            db.execute('DELETE FROM chat_messages WHERE sender_id = ?', (linked_user_id,))

            db.execute('DELETE FROM users WHERE id = ?', (linked_user_id,))

        db.execute('DELETE FROM members WHERE id = ?', (member_id,))
        db.commit()

        if profile_photo_path and os.path.exists(os.path.join(app.root_path, profile_photo_path)):
            os.remove(os.path.join(app.root_path, profile_photo_path))

        flash(f"Member and associated data deleted successfully.", "success")

    except sqlite3.Error as e:
        flash(f"Database error deleting member: {e}", "danger")
    except Exception as e:
        flash(f"An unexpected error occurred deleting member: {e}", 'danger')

    return redirect(url_for('admin_manage_users'))


@app.route('/chat_rooms') # From v17
@login_required
def chat_rooms():
    db = get_db()
    user_memberships_data = db.execute('SELECT chat_room_id FROM chat_room_members WHERE user_id = ?', (current_user.id,)).fetchall()
    room_ids = [m['chat_room_id'] for m in user_memberships_data]

    chat_rooms_data = []
    if room_ids:
        placeholders = ','.join('?' * len(room_ids))
        chat_rooms_data = db.execute(f'''
            SELECT id, name, created_at, is_group_chat
            FROM chat_rooms
            WHERE id IN ({placeholders})
            ORDER BY name ASC
        ''', room_ids).fetchall()

    rooms_for_template = []
    for room_data in chat_rooms_data:
        room = ChatRoom(
            id=room_data['id'],
            name=room_data['name'],
            created_at=room_data['created_at'],
            is_group_chat=room_data['is_group_chat']
        )
        last_message_data = db.execute('SELECT content, timestamp FROM chat_messages WHERE chat_room_id = ? ORDER BY timestamp DESC LIMIT 1', (room.id,)).fetchone()
        last_message = None
        if last_message_data:
            last_message = Message(
                id=None,
                sender_id=None,
                recipient_id=None,
                content=last_message_data['content'],
                timestamp=last_message_data['timestamp'],
                is_read=None,
                is_admin_message=None
            )

        unread_count_data = db.execute('SELECT COUNT(id) FROM chat_messages WHERE chat_room_id = ? AND sender_id != ?', (room.id, current_user.id)).fetchone()
        unread_count = unread_count_data[0] if unread_count_data else 0

        rooms_for_template.append({
            'room': room,
            'last_message': last_message,
            'unread_count': unread_count
        })

    sorted_rooms = sorted(rooms_for_template, key=lambda x: x['last_message'].timestamp if x['last_message'] else datetime.min, reverse=True)


    return render_template('chat_rooms.html', chat_rooms=sorted_rooms)


@app.route('/create_chat_room', methods=['GET', 'POST']) # From v17
@login_required
def create_chat_room():
    db = get_db()

    form_data = {}

    if request.method == 'POST':
        room_name = request.form.get('room_name')
        member_ids = request.form.getlist('members')

        if not room_name:
            flash('Chat room name is required.', 'danger')
            form_data = request.form.to_dict()
            return render_template('create_chat_room.html', all_users=get_all_users_for_chat_creation(), form_data=form_data)

        existing_room_data = db.execute('SELECT id FROM chat_rooms WHERE name = ?', (room_name,)).fetchone()
        if existing_room_data:
            flash('A chat room with this name already exists.', 'danger')
            form_data = request.form.to_dict()
            return render_template('create_chat_room.html', all_users=get_all_users_for_chat_creation(), form_data=form_data)

        db.execute(
            'INSERT INTO chat_rooms (name, created_at, is_group_chat) VALUES (?, ?, ?)',
            (room_name, datetime.utcnow(), 1)
        )
        db.commit()
        new_room_id = db.execute('SELECT id FROM chat_rooms WHERE name = ?', (room_name,)).fetchone()[0]

        db.execute(
            'INSERT INTO chat_room_members (chat_room_id, user_id, joined_at, is_admin) VALUES (?, ?, ?, ?)',
            (new_room_id, current_user.id, datetime.utcnow(), 1)
        )

        for user_id_str in member_ids:
            user_id = int(user_id_str)
            existing_member = db.execute('SELECT id FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?', (new_room_id, user_id)).fetchone()
            if not existing_member:
                db.execute(
                    'INSERT INTO chat_room_members (chat_room_id, user_id, joined_at, is_admin) VALUES (?, ?, ?, ?)',
                    (new_room_id, user_id, datetime.utcnow(), 0)
                )
        db.commit()

        flash(f'Chat room "{room_name}" created successfully!', 'success')
        return redirect(url_for('chat_rooms'))

    def get_all_users_for_chat_creation():
        all_users_data = db.execute('SELECT id, username, originalName FROM users WHERE id != ? ORDER BY username ASC', (current_user.id,)).fetchall()
        users_list = []
        for u_data in all_users_data:
            users_list.append(User(
                id=u_data['id'],
                username=u_data['username'],
                originalName=u_data['originalName'],
                password_hash=None, relationshipToRaphael=None, is_admin=None, theme_preference=None, chat_background_image_path=None, unique_key=None, password_reset_pending=None, reset_request_timestamp=None, last_login_at=None, last_seen_at=None
            ))
        return users_list

    return render_template('create_chat_room.html', all_users=get_all_users_for_chat_creation(), form_data=form_data)


@app.route('/chat_room/<int:room_id>', methods=['GET', 'POST']) # From v17
@login_required
def chat_room(room_id):
    db = get_db()
    room_data = db.execute('SELECT id, name, is_group_chat FROM chat_rooms WHERE id = ?', (room_id,)).fetchone()
    if not room_data:
        flash("Chat room not found.", "danger")
        return redirect(url_for('chat_rooms'))

    room = ChatRoom(
        id=room_data['id'],
        name=room_data['name'],
        created_at=None, is_group_chat=room_data['is_group_chat']
    )

    is_member_data = db.execute('SELECT id FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?', (room.id, current_user.id)).fetchone()
    if not is_member_data:
        flash("You are not a member of this chat room.", "danger")
        return redirect(url_for('chat_rooms'))

    if request.method == 'POST':
        message_content = request.form.get('message_content')
        media_file = request.files.get('media_file')

        media_path = None
        media_type = None

        if media_file and media_file.filename != '':
            filename = secure_filename(media_file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()

            if file_extension in app.config['ALLOWED_CHAT_IMAGE_EXTENSIONS']:
                upload_folder = app.config['UPLOAD_CHAT_PHOTO_FOLDER']
                media_type = 'image'
            elif file_extension in app.config['ALLOWED_CHAT_VIDEO_EXTENSIONS']:
                upload_folder = app.config['UPLOAD_CHAT_VIDEO_FOLDER']
                media_type = 'video'
            else:
                flash('Unsupported media file type.', 'danger')
                return redirect(url_for('chat_room', room_id=room_id))

            filepath = os.path.join(app.root_path, upload_folder, filename)
            media_file.save(filepath)
            relative_filepath = os.path.join(upload_folder, filename).replace('\\', '/')
            media_path = relative_filepath

        if message_content or media_path:
            db.execute(
                'INSERT INTO chat_messages (chat_room_id, sender_id, content, timestamp, media_path, media_type) VALUES (?, ?, ?, ?, ?, ?)',
                (room.id, current_user.id, message_content, datetime.utcnow(), media_path, media_type)
            )
            db.commit()
            return redirect(url_for('chat_room', room_id=room.id))
        else:
            flash('Message content or media file is required.', 'danger')

    messages_data = db.execute('SELECT * FROM chat_messages WHERE chat_room_id = ? ORDER BY timestamp', (room.id,)).fetchall()
    messages = []
    for msg_data in messages_data:
        messages.append(ChatMessage(
            id=msg_data['id'],
            chat_room_id=msg_data['chat_room_id'],
            sender_id=msg_data['sender_id'],
            content=msg_data['content'],
            timestamp=msg_data['timestamp'],
            media_path=msg_data['media_path'],
            media_type=msg_data['media_type']
        ))

    room_members_data = db.execute('SELECT user_id FROM chat_room_members WHERE chat_room_id = ?', (room.id,)).fetchall()
    member_user_ids = [m['user_id'] for m in room_members_data]
    placeholders = ','.join('?' * len(member_user_ids)) if member_user_ids else 'NULL'
    users_in_room_data = db.execute(f'SELECT id, username, originalName FROM users WHERE id IN ({placeholders})', member_user_ids).fetchall()
    users_dict = {}
    for u_data in users_in_room_data:
        users_dict[u_data['id']] = User(
            id=u_data['id'],
            username=u_data['username'],
            originalName=u_data['originalName'],
            password_hash=None, relationshipToRaphael=None, is_admin=None, theme_preference=None, chat_background_image_path=None, unique_key=None, password_reset_pending=None, reset_request_timestamp=None, last_login_at=None, last_seen_at=None
        )
    return render_template('chat_room.html', room=room, messages=messages, users_dict=users_dict)


@app.route('/delete_chat_message/<int:message_id>', methods=['POST']) # From v17
@login_required
def delete_chat_message(message_id):
    db = get_db()
    message_data = db.execute('SELECT chat_room_id, sender_id, media_path FROM chat_messages WHERE id = ?', (message_id,)).fetchone()
    if not message_data:
        flash("Message not found.", "danger")
        return redirect(url_for('home'))

    room_id = message_data['chat_room_id']
    sender_id = message_data['sender_id']
    media_path = message_data['media_path']

    if sender_id != current_user.id and not current_user.is_admin:
        flash("You do not have permission to delete this message.", "danger")
        return redirect(url_for('chat_room', room_id=room_id))

    try:
        if media_path and os.path.exists(os.path.join(app.root_path, media_path)):
            os.remove(os.path.join(app.root_path, media_path))

        db.execute('DELETE FROM chat_messages WHERE id = ?', (message_id,))
        db.commit()
        flash('Message deleted.', 'success')
    except sqlite3.Error as e:
        flash(f'Database error deleting message: {e}', 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')

    return redirect(url_for('chat_room', room_id=room_id))


@app.route('/add_chat_room_member/<int:room_id>', methods=['GET', 'POST']) # From v17
@login_required
def add_chat_room_member(room_id):
    db = get_db()
    room_data = db.execute('SELECT id FROM chat_rooms WHERE id = ?', (room_id,)).fetchone()
    if not room_data:
        flash("Chat room not found.", "danger")
        return redirect(url_for('chat_rooms'))

    room = ChatRoom(id=room_data['id'], name=None, created_at=None, is_group_chat=None)

    is_room_admin_data = db.execute('SELECT is_admin FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?', (room.id, current_user.id)).fetchone()
    is_room_admin = is_room_admin_data['is_admin'] if is_room_admin_data else 0

    if not current_user.is_admin and not is_room_admin:
        flash("You do not have permission to add members to this chat room.", "danger")
        return redirect(url_for('chat_room', room_id=room_id))

    form_data = {}

    if request.method == 'POST':
        user_ids_to_add = request.form.getlist('user_ids')

        if not user_ids_to_add:
            flash('No members selected to add.', 'danger')
            form_data = request.form.to_dict()
            return render_template('add_chat_room_member.html', room=room, users_not_in_room=get_users_not_in_room(room.id), form_data=form_data)


        for user_id_str in user_ids_to_add:
            user_id = int(user_id_str)
            existing_member = db.execute('SELECT id FROM chat_room_members WHERE chat_room_id = ? AND user_id = ?', (room.id, user_id)).fetchone()
            if not existing_member:
                db.execute(
                    'INSERT INTO chat_room_members (chat_room_id, user_id, joined_at, is_admin) VALUES (?, ?, ?, ?)',
                    (room.id, user_id, datetime.utcnow(), 0)
                )
        db.commit()
        flash('Members added to chat room.', 'success')
        return redirect(url_for('chat_room', room_id=room.id))

    def get_users_not_in_room(room_id):
        current_member_ids_data = db.execute('SELECT user_id FROM chat_room_members WHERE chat_room_id = ?', (room_id,)).fetchall()
        current_member_ids = [m['user_id'] for m in current_member_ids_data]

        placeholders = ','.join('?' * len(current_member_ids)) if current_member_ids else 'NULL'
        all_users_not_in_room_data = db.execute(f'''
            SELECT id, username, originalName FROM users
            WHERE id NOT IN ({placeholders}) AND id != ?
            ORDER BY username ASC
        ''', current_member_ids + [current_user.id] if current_member_ids else [current_user.id]).fetchall()

        users_not_in_room = []
        for u_data in all_users_not_in_room_data:
            users_not_in_room.append(User(
                id=u_data['id'],
                username=u_data['username'],
                originalName=u_data['originalName'],
                password_hash=None, relationshipToRaphael=None, is_admin=None, theme_preference=None, chat_background_image_path=None, unique_key=None, password_reset_pending=None, reset_request_timestamp=None, last_login_at=None, last_seen_at=None
            ))
        return users_not_in_room

    return render_template('add_chat_room_member.html', room=room, users_not_in_room=get_users_not_in_room(room.id), form_data=form_data)


@app.route('/set_new_password', methods=['GET', 'POST'])
def set_new_password():
    if 'reset_username' not in session:
        flash('No pending password reset request. Please use the forgot password link.', 'warning')
        return redirect(url_for('login'))

    username = session['reset_username']
    db = get_db()
    user_data = db.execute('SELECT id, password_reset_pending FROM users WHERE username = ?', (username,)).fetchone()

    if not user_data or user_data['password_reset_pending'] == 0:
        flash('No pending password reset request for this user.', 'warning')
        session.pop('reset_username', None)
        return redirect(url_for('login'))

    form_data = {}

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password and confirm_password and new_password == confirm_password:
            hashed_password = generate_password_hash(new_password)
            db.execute('UPDATE users SET password_hash = ?, password_reset_pending = 0, reset_request_timestamp = NULL WHERE id = ?',
                       (hashed_password, user_data['id']))
            db.commit()
            session.pop('reset_username', None)
            flash('Your password has been reset successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match or are invalid.', 'danger')
            form_data = request.form.to_dict()
            return render_template('set_new_password.html', username=username, form_data=form_data)

    return render_template('set_new_password.html', username=username, form_data=form_data)


@app.route('/download_chat_media/<path:filename>')
@login_required
def download_chat_media(filename):
    # Determine the correct directory based on the filename path
    if 'chat_media/photos/' in filename:
        directory = os.path.join(app.root_path, app.config['UPLOAD_CHAT_PHOTO_FOLDER'])
    elif 'chat_media/videos/' in filename:
        directory = os.path.join(app.root_path, app.config['UPLOAD_CHAT_VIDEO_FOLDER'])
    else:
        # If the filename doesn't match expected chat media paths, it's an invalid request
        abort(404)

    # Extract just the basename from the full path provided in 'filename'
    actual_filename = os.path.basename(filename)

    db = get_db()
    # Check if the current user is either the sender or recipient of a message containing this media
    # This check now looks for the full path in the content, not just the basename
    media_record = db.execute('''
        SELECT id FROM messages
        WHERE content LIKE ?
        AND (sender_id = ? OR recipient_id = ?)
    ''', ('%' + filename + '%', current_user.id, current_user.id)).fetchone()

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

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']), filename)

@app.route('/videos/<path:filename>')
def uploaded_video(filename):
    return send_from_directory(os.path.join(app.root_path, app.config['UPLOAD_VIDEO_FOLDER']), filename)

@app.route('/chat_media/photos/<path:filename>')
def chat_photo(filename):
    return send_from_directory(os.path.join(app.root_path, app.config['UPLOAD_CHAT_PHOTO_FOLDER']), filename)

@app.route('/chat_media/videos/<path:filename>')
def chat_video(filename):
    return send_from_directory(os.path.join(app.root_path, app.config['UPLOAD_CHAT_VIDEO_FOLDER']), filename)

@app.route('/chat_backgrounds/<path:filename>')
def chat_background(filename):
    return send_from_directory(os.path.join(app.root_path, app.config['UPLOAD_CHAT_BACKGROUND_FOLDER']), filename)


@app.route('/members')
@login_required
def list_members():
    db = get_db()
    # Updated query from new.py, adapted to 'statuses' table
    members_data = db.execute('''
        SELECT
            m.*,
            u.username AS linked_username,
            s.file_path AS status_file_path,
            s.upload_time AS status_upload_time
        FROM members m
        LEFT JOIN users u ON m.user_id = u.id
        LEFT JOIN statuses s ON m.id = s.member_id
        WHERE m.user_id IS NULL OR m.user_id != ?
        ORDER BY m.fullName ASC
    ''', (current_user.id,)).fetchall()

    members_for_template = []
    now = datetime.utcnow()
    for member in members_data:
        member_dict = dict(member)
        member_dict['username'] = member_dict['linked_username'] if member_dict['linked_username'] else ''

        # Status logic
        upload_time_dt = None
        if member_dict['status_upload_time']:
            try:
                upload_time_dt = member_dict['status_upload_time']
                if isinstance(upload_time_dt, str):
                    upload_time_dt = datetime.strptime(upload_time_dt, '%Y-%m-%d %H:%M:%S.%f')
            except (ValueError, TypeError):
                upload_time_dt = None

        if upload_time_dt and now - upload_time_dt <= timedelta(hours=12):
            member_dict['has_active_video'] = True
        else:
            member_dict['has_active_video'] = False

        # Ensure profilePhoto path is correct for display
        if member_dict['profilePhoto']:
            member_dict['profilePhotoUrl'] = url_for('uploaded_file', filename=os.path.basename(member_dict['profilePhoto']))
        else:
            member_dict['profilePhotoUrl'] = url_for('static', filename='img/default_profile.png')

        # Handle AdminAI profile photo if it's the AI user
        if member_dict['username'] == 'AdminAI' and not member_dict['profilePhoto']:
            member_dict['profilePhotoUrl'] = url_for('static', filename='img/ai_icon.png')

        members_for_template.append(member_dict)

    return render_template('members_list.html', members=members_for_template)

@app.route('/members/detail/<int:member_id>') # Updated URL from new.py
@login_required
def member_detail(member_id):
    db = get_db()

    # Redirect to my_profile if it's the current user's own member_id
    if g.user_member and member_id == g.user_member.id:
        return redirect(url_for('my_profile'))

    member_data = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()

    if not member_data:
        flash("Member not found.", "danger")
        return redirect(url_for('list_members'))

    member_profile = Member(
        id=member_data['id'],
        fullName=member_data['fullName'],
        dateOfBirth=member_data['dateOfBirth'],
        gender=member_data['gender'],
        association=member_data['association'],
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
        needs_details_update=member_data['needs_details_update'],
        isRaphaelDescendant=member_data['isRaphaelDescendant'] if 'isRaphaelDescendant' in member_data.keys() else 0
    )

    # Determine if the logged-in user can message this member
    can_message_member = False
    if member_profile.user_id and member_profile.can_message == 1:
        can_message_member = True

    age = calculate_age(member_profile.dateOfBirth)

    # Status video logic (adapted from new.py to use 'statuses' table)
    temp_video_data_for_template = None
    latest_status_data = db.execute('SELECT * FROM statuses WHERE member_id = ? ORDER BY upload_time DESC LIMIT 1', (member_profile.id,)).fetchone()

    if latest_status_data:
        try:
            upload_time_dt = latest_status_data['upload_time']
            if isinstance(upload_time_dt, str):
                upload_time_dt = datetime.strptime(upload_time_dt, '%Y-%m-%d %H:%M:%S.%f')

            expires_at_dt = upload_time_dt + timedelta(hours=12)
            is_active_status = (datetime.now(timezone.utc) < expires_at_dt)

            if is_active_status: # Only show if active
                temp_video_data_for_template = {
                    'file_path': latest_status_data['file_path'],
                    'upload_time': upload_time_dt,
                    'expires_at': expires_at_dt,
                    'is_active': is_active_status
                }
        except Exception as e:
            print(f"Error processing status for member_detail: {e}")
            temp_video_data_for_template = None

    return render_template(
        'member_detail.html',
        member=member_profile,
        age=age,
        can_message_member=can_message_member,
        temp_video=temp_video_data_for_template
    )


@app.route('/status') # From new.py
@login_required
def status_feed():
    db = get_db()
    now = datetime.utcnow().replace(tzinfo=timezone.utc)

    active_statuses_raw = db.execute('''
        SELECT
            s.file_path,
            s.upload_time,
            m.fullName,
            m.profilePhoto,
            m.id AS member_id,
            s.uploader_user_id
        FROM statuses s
        JOIN members m ON s.member_id = m.id
        ORDER BY s.upload_time DESC
    ''').fetchall()

    statuses_for_template = []
    for status_raw in active_statuses_raw:
        try:
            upload_time_dt = status_raw['upload_time']
            if isinstance(upload_time_dt, str):
                upload_time_dt = datetime.strptime(upload_time_dt, '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
            elif upload_time_dt.tzinfo is None:
                upload_time_dt = upload_time_dt.replace(tzinfo=timezone.utc)

            expires_at_dt = upload_time_dt + timedelta(hours=12)
            is_active = (now < expires_at_dt)

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
        except Exception as e:
            print(f"ERROR: Failed to process status for {status_raw['fullName']} (Member ID: {status_raw['member_id']}). Error: {e}")
            continue

    return render_template('status_feed.html', statuses=statuses_for_template)


@app.route('/games')
@login_required
def games_hub(): # Renamed function for clarity
    return render_template('game_page.html')

@app.route('/play_game') # You can choose a more specific URL like '/play_my_awesome_game'
@login_required
def play_my_game():
    return render_template('game_page.html')


@app.route('/message-member')
@login_required
def message_member():
    db = get_db()

    # Get the ID of the AdminAI user
    ai_user_data = db.execute('SELECT id FROM users WHERE username = ?', ('AdminAI',)).fetchone()
    ai_user_id = ai_user_data['id'] if ai_user_data else -1 # Default to -1 if not found

    # Updated query to exclude current user AND AdminAI
    members_data = db.execute('''
        SELECT
        m.id, m.fullName, m.profilePhoto, m.user_id, u.username AS linked_username,
        s.file_path AS status_file_path, s.upload_time AS status_upload_time
        FROM members m
        LEFT JOIN users u ON m.user_id = u.id
        LEFT JOIN statuses s ON m.id = s.member_id
        WHERE m.user_id IS NOT NULL
          AND m.user_id != ?
          AND m.user_id != ? -- Exclude AdminAI user
          AND m.can_message = 1
        ORDER BY m.fullName ASC
    ''', (current_user.id, ai_user_id)).fetchall() # Pass both current_user.id and ai_user_id

    members_for_template = []
    now = datetime.utcnow()
    for member in members_data:
        member_dict = dict(member)
        member_dict['username'] = member_dict['linked_username'] if member_dict['linked_username'] else ''

        # Status logic
        upload_time_dt = None
        if member_dict['status_upload_time']:
            try:
                upload_time_dt = member_dict['status_upload_time']
                if isinstance(upload_time_dt, str):
                    upload_time_dt = datetime.strptime(upload_time_dt, '%Y-%m-%d %H:%M:%S.%f')
            except (ValueError, TypeError):
                upload_time_dt = None

        if upload_time_dt and now - upload_time_dt <= timedelta(hours=12):
            member_dict['has_active_video'] = True
        else:
            member_dict['has_active_video'] = False

        if member_dict['profilePhoto']:
            member_dict['profilePhotoUrl'] = url_for('uploaded_file', filename=os.path.basename(member_dict['profilePhoto']))
        else:
            member_dict['profilePhotoUrl'] = url_for('static', filename='img/default_profile.png')

        members_for_template.append(member_dict)

    return render_template('message_member.html', messageable_members=members_for_template, ai_user_id=ai_user_id)



@app.route('/add-my-details', methods=['GET', 'POST'])
@login_required
def add_my_details():
    db = get_db()
    member_data = db.execute('SELECT * FROM members WHERE user_id = ?', (current_user.id,)).fetchone()

    if member_data:
        flash("You already have a member profile. You can edit it from My Profile.", "info")
        return redirect(url_for('my_profile'))

    form_data = {}

    if request.method == 'POST':
        full_name = request.form.get('fullName')
        gender = request.form.get('gender')
        whereabouts = request.form.get('whereabouts')
        contact = request.form.get('contact')
        bio = request.form.get('bio')
        date_of_birth = request.form.get('dateOfBirth')
        marital_status = request.form.get('maritalStatus')
        spouse_names = request.form.get('spouseNames', '')
        # girlfriend_names removed, merged into spouse_names if marital_status is Engaged
        children_names = request.form.get('childrenNames', '')
        school_name = request.form.get('schoolName', '')
        personal_relationship_description = request.form.get('personalRelationshipDescription', '')

        if marital_status == 'Engaged' and request.form.get('girlfriendNames'): # Use girlfriendNames if exists
            spouse_names = request.form.get('girlfriendNames')

        if contact:
            contacts_list = [c.strip() for c in contact.split(',') if c.strip()]
            for c in contacts_list:
                if '@' in c:
                    if not (c.count('@') == 1 and '.' in c.split('@')[1]):
                        flash('Invalid email format in contact information.', 'danger')
                        form_data = request.form.to_dict()
                        if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                            form_data['profilePhoto'] = ''
                        return render_template('add_my_details.html', user=current_user, form_data=form_data)
                else:
                    if not (c.replace('+', '').replace('-', '').replace('(', '').replace(')', '').replace(' ', '').isdigit()):
                        flash('Invalid phone number format in contact information.', 'danger')
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

        profile_photo_path = None # Initialize to None instead of empty string
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                # Use current_user.id for filename to ensure uniqueness per user
                filename = secure_filename(f"{current_user.id}_profile_{datetime.utcnow().timestamp()}_{file.filename}")
                file_save_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
                file.save(file_save_path)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')

        try:
            is_raphael_descendant = 1 if association.lower() in ['son of raphael nyanga', 'daughter of raphael nyanga', 'grandchild of raphael nyanga', 'great-grandchild of raphael nyanga'] else 0

            # Use 'can_message' instead of 'has_login_access' as per v17 schema
            db.execute(
                'INSERT INTO members (fullName, association, gender, whereabouts, contact, bio, profilePhoto, dateOfBirth, maritalStatus, spouseNames, childrenNames, isRaphaelDescendant, user_id, needs_details_update, added_by_user_id, schoolName, can_message, personalRelationshipDescription) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (full_name, association, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, is_raphael_descendant, current_user.id, 0, current_user.id, school_name, 1, personal_relationship_description)
            )
            db.commit()

            # Update the user's originalName and relationshipToRaphael
            db.execute('UPDATE users SET originalName = ?, relationshipToRaphael = ? WHERE id = ?',
                       (full_name, association, current_user.id))
            db.commit()

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
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')
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


@app.route('/add-member', methods=['GET', 'POST'])
@login_required
def add_member_form():
    if not current_user.is_admin:
        flash('You do not have permission to add new members.', 'danger')
        return redirect(url_for('home'))

    form_data = {}

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
        # girlfriend_names removed, merged into spouse_names if marital_status is Engaged
        children_names = request.form.get('childrenNames', '')
        school_name = request.form.get('schoolName', '')
        personal_relationship_description = request.form.get('personalRelationshipDescription', '')
        can_message = 1 if request.form.get('can_message') else 0 # From new.py

        if marital_status == 'Engaged' and request.form.get('girlfriendNames'):
            spouse_names = request.form.get('girlfriendNames')

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

        profile_photo_path = None # Initialize to None
        if 'profilePhoto' in request.files:
            file = request.files['profilePhoto']
            if file and allowed_file(file.filename):
                # Use a generic unique filename for new members
                filename = secure_filename(f"new_member_{datetime.utcnow().timestamp()}_{file.filename}")
                file_save_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
                file.save(file_save_path)
                profile_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')

        db = get_db()
        try:
            is_raphael_descendant = 1 if association.lower() in ['son of raphael nyanga', 'daughter of raphael nyanga', 'grandchild of raphael nyanga', 'great-grandchild of raphael nyanga'] else 0

            # Use 'can_message' instead of 'has_login_access' as per v17 schema
            cursor = db.execute(
                'INSERT INTO members (fullName, association, gender, whereabouts, contact, bio, profilePhoto, dateOfBirth, maritalStatus, spouseNames, childrenNames, isRaphaelDescendant, user_id, needs_details_update, added_by_user_id, schoolName, can_message, personalRelationshipDescription) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (full_name, association, gender, whereabouts, contact, bio, profile_photo_path,
                 date_of_birth, marital_status, spouse_names, children_names, is_raphael_descendant, None, 0, current_user.id, school_name, can_message, personal_relationship_description)
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
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')
            form_data = request.form.to_dict()
            if 'profilePhoto' in request.files and request.files['profilePhoto'].filename:
                form_data['profilePhoto'] = ''
            return render_template('add-member.html', form_data=form_data)

    return render_template('add-member.html', form_data={})


@app.route('/member-added-success') # From new.py
@login_required
def member_added_success():
    return render_template('success.html', message="Family member details added successfully!")


@app.route('/admin/show-user-status/<int:member_id>', methods=['GET']) # New route from new.py
@login_required
def admin_show_user_status(member_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home')) # Changed from dashboard to home

    db = get_db()
    # Use 'statuses' table and 'upload_time' column
    status_data = db.execute('SELECT file_path, upload_time FROM statuses WHERE member_id = ? ORDER BY upload_time DESC LIMIT 1', (member_id,)).fetchone()
    member_name_data = db.execute('SELECT fullName FROM members WHERE id = ?', (member_id,)).fetchone()
    member_name = member_name_data['fullName'] if member_name_data else "Unknown Member"

    if status_data:
        try:
            upload_time_dt = status_data['upload_time']
            if isinstance(upload_time_dt, str):
                upload_time_dt = datetime.strptime(upload_time_dt, '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
            elif upload_time_dt.tzinfo is None:
                upload_time_dt = upload_time_dt.replace(tzinfo=timezone.utc)

            expires_at_dt = upload_time_dt + timedelta(hours=12)
            is_active = (datetime.now(timezone.utc) < expires_at_dt)

            status_message = ""
            if is_active:
                status_message = "This is the current active video status for the user."
            else:
                status_message = "This video status has expired (older than 12 hours)."

            return render_template('admin_view_status.html',
                                   video_url=url_for('uploaded_video', filename=os.path.basename(status_data['file_path'])),
                                   status_message=status_message,
                                   member_id=member_id,
                                   member_name=member_name,
                                   upload_time=upload_time_dt,
                                   expires_at=expires_at_dt)
        except Exception as e:
            print(f"Error processing status for admin_show_user_status: {e}")
            flash(f"Error loading status: {e}", 'danger')
            return redirect(url_for('member_detail', member_id=member_id))
    else:
        flash('No video status found for this user.', 'info')
        return redirect(url_for('member_detail', member_id=member_id))


@app.route('/admin/delete-user-status/<int:member_id>', methods=['POST']) # New route from new.py
@login_required
def admin_delete_user_status(member_id):
    db = get_db()

    member_profile = db.execute('SELECT user_id FROM members WHERE id = ?', (member_id,)).fetchone()

    if not member_profile:
        flash('Member profile not found.', 'danger')
        return redirect(url_for('home'))

    if not (current_user.is_admin or (member_profile['user_id'] and current_user.id == member_profile['user_id'])):
        flash('You do not have permission to delete this status.', 'danger')
        if current_user.is_admin:
            return redirect(url_for('admin_manage_users'))
        else:
            return redirect(url_for('my_profile'))

    # Use 'statuses' table
    status_data = db.execute('SELECT id, file_path FROM statuses WHERE member_id = ? ORDER BY upload_time DESC LIMIT 1', (member_id,)).fetchone()

    if status_data:
        file_path = os.path.join(app.root_path, status_data['file_path'])

        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Deleted status file: {file_path}")
            except OSError as e:
                flash(f"Error deleting file from disk: {e}", 'danger')
                print(f"Error deleting status file {file_path}: {e}")
        else:
            print(f"Status file not found on disk, removing DB entry: {file_path}")

        db.execute('DELETE FROM statuses WHERE id = ?', (status_data['id'],))
        db.commit()
        flash('Video status deleted successfully.', 'success')
    else:
        flash('No video status found for this member to delete.', 'info')

    if current_user.is_admin:
        return redirect(url_for('member_detail', member_id=member_id))
    else:
        return redirect(url_for('my_profile'))


# --- Messaging Routes (Adapted from new.py for direct messages) ---
@app.route('/inbox')
@login_required
def inbox():
    db = get_db()

    # Get the ID of the AdminAI user to pass to the template
    ai_user_data = db.execute('SELECT id FROM users WHERE username = ?', ('AdminAI',)).fetchone()
    ai_user_id = ai_user_data['id'] if ai_user_data else -1 # Default to -1 if not found

    # Get all distinct users current_user has messaged or been messaged by using the 'messages' table
    conversations_raw = db.execute('''
        WITH CombinedActivity AS (
            SELECT
                CASE
                    WHEN sender_id = ? THEN recipient_id
                    ELSE sender_id
                END AS other_user_id,
                timestamp AS activity_timestamp
            FROM messages
            WHERE sender_id = ? OR recipient_id = ?
        )
        SELECT
            other_user_id,
            MAX(activity_timestamp) AS last_activity_timestamp
        FROM CombinedActivity
        WHERE other_user_id != ?
        GROUP BY other_user_id
        ORDER BY last_activity_timestamp DESC
    ''', (current_user.id, current_user.id, current_user.id, current_user.id)).fetchall()

    inbox_conversations = []
    for conv_summary in conversations_raw:
        other_user_id = conv_summary['other_user_id']

        other_user_data = db.execute('SELECT id, username, originalName FROM users WHERE id = ?', (other_user_id,)).fetchone()
        if not other_user_data:
            continue

        # Get the very latest message (text or media indication) for the snippet
        latest_message = db.execute(
            '''
            SELECT
                content,
                timestamp,
                sender_id,
                is_read,
                is_admin_message
            FROM messages
            WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
            ORDER BY timestamp DESC
            LIMIT 1
            ''', (current_user.id, other_user_id, other_user_id, current_user.id)
        ).fetchone()

        latest_snippet = "No messages yet."
        is_unread = False

        if latest_message:
            full_content = latest_message['content']
            if full_content:
                latest_snippet = full_content.split('\n')[0]
                if len(latest_snippet) > 50:
                    latest_snippet = latest_snippet[:47] + '...'
            else:
                latest_snippet = "(Empty message)"

            if latest_message['sender_id'] == current_user.id:
                latest_snippet = f"You: {latest_snippet}"
            elif latest_message['is_admin_message'] == 1:
                latest_snippet = f"System: {latest_snippet}"

            # Check unread status (only if current user is recipient and it's not read)
            unread_count_for_this_conv = db.execute('''
                SELECT COUNT(*) FROM messages
                WHERE sender_id = ? AND recipient_id = ? AND is_read = 0
            ''', (other_user_id, current_user.id)).fetchone()[0]

            if unread_count_for_this_conv > 0:
                is_unread = True

        inbox_conversations.append({
            'other_user': other_user_data,
            'latest_message_snippet': latest_snippet,
            'timestamp': conv_summary['last_activity_timestamp'],
            'is_unread': is_unread
        })

    return render_template('inbox.html', conversations=inbox_conversations, ai_user_id=ai_user_id)


@app.route('/messages/<int:other_user_id>', methods=['GET', 'POST'])
@login_required
def messages_with(other_user_id):
    db = get_db()
    other_user = db.execute('SELECT id, username, originalName FROM users WHERE id = ?', (other_user_id,)).fetchone()

    if not other_user:
        flash('User not found.', 'danger')
        return redirect(url_for('inbox'))

    # Check if the other_user is the AdminAI. If so, redirect to the dedicated AI chat route.
    ai_user_data = db.execute('SELECT id FROM users WHERE username = ?', ('AdminAI',)).fetchone()
    if ai_user_data and other_user['id'] == ai_user_data['id']:
        return redirect(url_for('ai_chat_page')) # Redirect to the new AI chat route

    other_member_profile = db.execute('SELECT can_message FROM members WHERE user_id = ?', (other_user['id'],)).fetchone()
    if not other_member_profile or other_member_profile['can_message'] == 0:
        flash(f"Messaging is not enabled for {other_user['originalName']}.", 'danger')
        return redirect(url_for('inbox'))

    # Fetch messages from the 'messages' table
    conversation_messages = db.execute('''
        SELECT m.id, m.sender_id, m.recipient_id, m.content, m.timestamp, m.is_read, m.is_admin_message
        FROM messages m
        WHERE (m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.timestamp ASC
    ''', (current_user.id, other_user['id'], other_user['id'], current_user.id)).fetchall()

    # Process messages to include media details if applicable
    combined_feed = []
    for msg_data in conversation_messages:
        msg_dict = dict(msg_data)
        content = msg_dict['content']

        # Check for media content pattern: [Type: path]
        if content and (content.startswith('[Image:') or content.startswith('[Video:')):
            try:
                # Extract path from content string, e.g., "[Image: static/path/to/image.png]"
                # This assumes the format is always "[Type: full/path/to/file.ext]"
                parts = content.split(':', 1) # Split only on the first colon
                media_type_str = parts[0].strip('[').strip() # "Image" or "Video"
                file_path_full = parts[1].strip(']').strip() # "static/path/to/file.ext"

                msg_dict['type'] = 'media'
                msg_dict['media_type'] = media_type_str.lower()
                msg_dict['file_path'] = file_path_full
                msg_dict['content'] = '' # Clear original content for media messages to avoid double display

            except IndexError:
                # Fallback if parsing fails, treat as a regular message
                msg_dict['type'] = 'message'
                print(f"Warning: Failed to parse media content for message ID {msg_dict['id']}: {content}")
            except Exception as e:
                # Catch any other unexpected errors during parsing
                msg_dict['type'] = 'message'
                print(f"Error parsing media content for message ID {msg_dict['id']}: {e} - Content: {content}")
        else:
            msg_dict['type'] = 'message'

        combined_feed.append(msg_dict)

    combined_feed.sort(key=lambda x: x['timestamp']) # Sort by timestamp

    # Mark messages as read for the current user
    db.execute('UPDATE messages SET is_read = 1 WHERE sender_id = ? AND recipient_id = ? AND is_read = 0',
               (other_user['id'], current_user.id))
    db.commit()
    g.unread_messages_count = get_unread_messages_count() # Update global count

    if request.method == 'POST':
        message_body = request.form['message_body'].strip()
        if not message_body:
            flash('Message body cannot be empty.', 'danger')
        else:
            try:
                is_admin_message = 1 if current_user.is_admin else 0

                db.execute(
                    'INSERT INTO messages (sender_id, recipient_id, content, timestamp, is_read, is_admin_message) VALUES (?, ?, ?, ?, ?, ?)',
                    (current_user.id, other_user['id'], message_body, datetime.utcnow(), 0, is_admin_message)
                )
                db.commit()
            except sqlite3.Error as e:
                flash(f"Error sending message: {e}", 'danger')
        return redirect(url_for('messages_with', other_user_id=other_user['id']))

    current_user_chat_background = current_user.chat_background_image_path

    return render_template('view_conversation.html',
                           other_user=other_user,
                           combined_feed=combined_feed,
                           current_user_chat_background=current_user_chat_background)

@app.route('/ai-chat') # NEW DEDICATED AI CHAT ROUTE
@login_required
def ai_chat_page():
    db = get_db()
    ai_user_data = db.execute('SELECT id, username, originalName FROM users WHERE username = ?', ('AdminAI',)).fetchone()
    if not ai_user_data:
        flash('Admin AI user not found. AI chat is unavailable.', 'danger')
        return redirect(url_for('home'))

    ai_user = {
        'id': ai_user_data['id'],
        'username': ai_user_data['username'],
        'originalName': ai_user_data['originalName']
    }

    # For now, we're not fetching chat history from Firestore here.
    # The ai_chat.html will handle fetching and sending via AJAX/Firestore.
    return render_template('ai_chat.html', other_user=ai_user, current_user_chat_background=current_user.chat_background_image_path)


@app.route('/search-members', methods=['GET']) # From new.py
@login_required
def search_members():
    search_query = request.args.get('q', '').strip()
    db = get_db()

    results = []

    if search_query:
        search_pattern = '%' + search_query + '%'

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
            profile_photo_url = url_for('uploaded_file', filename=os.path.basename(member['profilePhoto'])) if member['profilePhoto'] else url_for('static', filename='img/default_profile.png')

            results.append({
                'id': member['id'],
                'fullName': member['fullName'],
                'username': member['linked_username'] if member['linked_username'] else '',
                'profilePhoto': profile_photo_url,
                'association': member['association'],
                'isLinkedUser': True if member['user_id'] else False
            })
    return jsonify(results)


@app.route('/upload-status-video', methods=['POST']) # From new.py
@login_required
def upload_status_video():
    db = get_db()
    member = g.user_member

    if not member:
        return jsonify({'success': False, 'message': 'Please complete your profile details first.'}), 400

    if 'video_file' not in request.files:
        return jsonify({'success': False, 'message': 'No video file part.'}), 400

    file = request.files['video_file']

    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected video file.'}), 400

    if file and allowed_video_file(file.filename):
        filename = secure_filename(f"{member.id}_status_{datetime.utcnow().timestamp()}_{file.filename}")
        file_save_path = os.path.join(app.root_path, app.config['UPLOAD_VIDEO_FOLDER'], filename)

        try:
            # Delete previous status for this member if it exists (from 'statuses' table)
            existing_status = db.execute('SELECT id, file_path FROM statuses WHERE member_id = ?', (member.id,)).fetchone()
            if existing_status:
                old_file_path = os.path.join(app.root_path, existing_status['file_path'])
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)
                    print(f"Removed old status video: {old_file_path}")
                db.execute('DELETE FROM statuses WHERE id = ?', (existing_status['id'],))
                db.commit()

            file.save(file_save_path)
            video_db_path = os.path.join(app.config['UPLOAD_VIDEO_FOLDER'], filename).replace('\\', '/')

            # Insert into 'statuses' table
            db.execute(
                'INSERT INTO statuses (member_id, file_path, upload_time, is_video, uploader_user_id) VALUES (?, ?, ?, ?, ?)',
                (member.id, video_db_path, datetime.utcnow(), 1, current_user.id)
            )
            db.commit()
            return jsonify({'success': True, 'message': 'Status video uploaded successfully! It will be available for 12 hours.'}), 200
        except sqlite3.Error as e:
            return jsonify({'success': False, 'message': f"Database error saving video: {e}"}), 500
        except Exception as e:
            return jsonify({'success': False, 'message': f"An unexpected error occurred during video upload: {e}"}), 500
    else:
        return jsonify({'success': False, 'message': 'Invalid video file type. Allowed types: mp4, mov, avi, webm.'}), 400


@app.route('/get-member-status-video/<int:member_id>', methods=['GET']) # From new.py
@login_required
def get_member_status_video(member_id):
    db = get_db()
    # Use 'statuses' table and 'upload_time' column
    member_status = db.execute('SELECT * FROM statuses WHERE member_id = ? ORDER BY upload_time DESC LIMIT 1', (member_id,)).fetchone()

    if member_status:
        upload_time_dt = member_status['upload_time']
        if isinstance(upload_time_dt, str):
            upload_time_dt = datetime.strptime(upload_time_dt, '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
        elif upload_time_dt.tzinfo is None:
            upload_time_dt = upload_time_dt.replace(tzinfo=timezone.utc)

        if datetime.utcnow().replace(tzinfo=timezone.utc) - upload_time_dt <= timedelta(hours=12):
            return jsonify({
                'video_url': url_for('uploaded_video', filename=os.path.basename(member_status['file_path'])),
                'upload_time': upload_time_dt.isoformat(),
                'expires_at': (upload_time_dt + timedelta(hours=12)).isoformat()
            })
    return jsonify({'video_url': None, 'message': 'No active status video found.'})

@app.route('/update-theme-preference', methods=['POST']) # From new.py
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


@app.route('/upload_chat_media/<int:recipient_user_id>', methods=['POST']) # From new.py, adapted to v17 schema
@login_required
def upload_chat_media(recipient_user_id):
    db = get_db()
    recipient = db.execute('SELECT id, username FROM users WHERE id = ?', (recipient_user_id,)).fetchone()

    if not recipient:
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

    filename = secure_filename(f"{current_user.id}_{recipient_user_id}_{datetime.utcnow().timestamp()}_{file.filename}")
    file_save_path = os.path.join(app.root_path, file_path_prefix, filename)

    try:
        file.save(file_save_path)
        db_file_path = os.path.join(file_path_prefix, filename).replace('\\', '/')

        # Insert into 'messages' table with content indicating media
        media_message_content = f"[{media_type.capitalize()}: {db_file_path}]" # Store path in content for retrieval
        is_admin_message = 1 if current_user.is_admin else 0

        db.execute(
            'INSERT INTO messages (sender_id, recipient_id, content, timestamp, is_read, is_admin_message) VALUES (?, ?, ?, ?, ?, ?)',
            (current_user.id, recipient_user_id, media_message_content, datetime.utcnow(), 0, is_admin_message)
        )
        db.commit()

        return jsonify({'success': True, 'message': 'Media uploaded successfully!', 'file_path': db_file_path, 'media_type': media_type}), 200
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': f'Database error: {e}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred: {e}'}), 500

@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
def admin_manage_users():
    if not current_user.is_admin:
        flash('You do not have administrative access.', 'danger')
        return redirect(url_for('home'))

    db = get_db()

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        member_id = request.form.get('member_id')

        if action == 'toggle_admin':
            target_user = User.get(user_id)
            if target_user and target_user.username != app.config['ADMIN_USERNAME']:
                new_admin_status = 1 if target_user.is_admin == 0 else 0
                db.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_admin_status, user_id))
                db.commit()
                flash(f"Admin status for {target_user.username} {'enabled' if new_admin_status else 'disabled'}.", 'success')
            else:
                flash('Cannot change admin status for this user or yourself.', 'danger')

        elif action == 'reset_password':
            target_user_id = request.form.get('user_id')
            new_password = request.form.get(f'new_password_{target_user_id}')
            confirm_password = request.form.get(f'confirm_password_{target_user_id}')

            if not new_password or not confirm_password or new_password != confirm_password:
                flash('New passwords do not match or are empty.', 'danger')
            else:
                hashed_password = generate_password_hash(new_password)
                db.execute('UPDATE users SET password_hash = ?, password_reset_pending = 0, reset_request_timestamp = NULL WHERE id = ?', (hashed_password, target_user_id))
                db.commit()
                flash(f'Password for user ID {target_user_id} has been reset.', 'success')

        elif action == 'initiate_password_reset':
            target_user_id = request.form.get('user_id')
            db.execute('UPDATE users SET password_reset_pending = 1, reset_request_timestamp = ? WHERE id = ?', (datetime.utcnow(), target_user_id))
            db.commit()
            flash(f'Password reset initiated for user ID {target_user_id}. They will be prompted to set a new password on next login.', 'info')

        elif action == 'delete_user': # From new.py
            user_id_to_delete = request.form.get('user_id')
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
                db.execute('DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?', (user_id_to_delete, user_id_to_delete)) # Adapted to recipient_id
                db.execute('DELETE FROM chat_messages WHERE sender_id = ?', (user_id_to_delete,)) # For group chat messages
                db.execute('DELETE FROM chat_room_members WHERE user_id = ?', (user_id_to_delete,)) # For group chat memberships
                db.execute('DELETE FROM statuses WHERE uploader_user_id = ?', (user_id_to_delete,)) # Adapted to statuses table

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

        elif action == 'link_member_to_user': # From new.py
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
                                'INSERT INTO users (username, originalName, relationshipToRaphael, password_hash, theme_preference, unique_key, password_reset_pending, reset_request_timestamp, last_login_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                                (new_username, member_to_link['fullName'], member_to_link['association'], hashed_password, 'light', generate_unique_key(), 0, None, datetime.utcnow(), datetime.utcnow())
                            )
                            new_user_id = cursor.lastrowid
                            # Use 'can_message' instead of 'has_login_access'
                            db.execute('UPDATE members SET user_id = ?, can_message = 1 WHERE id = ?', (new_user_id, member_id_to_link))
                            db.commit()
                            flash(f'User {new_username} created and linked to {member_to_link["fullName"]}. Login access enabled.', 'success')
                    except sqlite3.IntegrityError:
                        flash('Username already exists or database error.', 'danger')
                    except Exception as e:
                        flash(f'An error occurred during linking: {e}', 'danger')

        elif action == 'toggle_login_access': # From new.py, adapted to 'can_message'
            member_id_toggle = request.form.get('member_id')
            member_data = db.execute('SELECT user_id, can_message FROM members WHERE id = ?', (member_id_toggle,)).fetchone()
            if member_data and member_data['user_id']:
                new_access_status = not member_data['can_message'] # Toggle can_message for login access
                db.execute('UPDATE members SET can_message = ? WHERE id = ?', (1 if new_access_status else 0, member_id_toggle))
                db.commit()
                flash(f"Login access for member ID {member_id_toggle} {'enabled' if new_access_status else 'disabled'}.", 'success')
            else:
                flash('Cannot toggle login access for unlinked member or member not found.', 'danger')

        elif action == 'toggle_messaging_capability': # From new.py
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
    users_data = db.execute('SELECT id, username, originalName, relationshipToRaphael, is_admin, unique_key, password_reset_pending, reset_request_timestamp FROM users ORDER BY username ASC').fetchall()
    users_for_template = []
    for row in users_data:
        user_dict = dict(row)
        user_dict['is_admin'] = bool(user_dict['is_admin'])
        users_for_template.append(user_dict)

    # Get members with their linked user status for display
    members_with_status_data = db.execute('''
        SELECT m.id, m.fullName, m.profilePhoto, m.user_id, m.can_message,
               u.username AS linked_username
        FROM members m
        LEFT JOIN users u ON m.user_id = u.id
        ORDER BY m.fullName ASC
    ''').fetchall()

    members_with_status_for_template = []
    for row in members_with_status_data:
        member_dict = dict(row)
        member_dict['can_message'] = bool(member_dict['can_message'])
        members_with_status_for_template.append(member_dict)

    return render_template('admin_manage_users.html', users=users_for_template, members_with_status=members_with_status_for_template)


@app.route('/edit-member/<int:member_id>', methods=['GET', 'POST'])
@login_required
def edit_member(member_id):
    db = get_db()
    member_data = db.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    if not member_data:
        flash('Member not found.', 'danger')
        return redirect(url_for('list_members'))

    member = Member(
        id=member_data['id'],
        fullName=member_data['fullName'],
        dateOfBirth=member_data['dateOfBirth'],
        gender=member_data['gender'],
        association=member_data['association'],
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
        needs_details_update=member_data['needs_details_update'],
        isRaphaelDescendant=member_data['isRaphaelDescendant'] if 'isRaphaelDescendant' in member_data.keys() else 0
    )

    # Permission check: Admin, or the user linked to this member, or the user who added this member
    if not current_user.is_admin and \
       (member.user_id is None or current_user.id != member.user_id) and \
       (member.added_by_user_id is None or current_user.id != member.added_by_user_id):
        flash("You do not have permission to edit this profile.", "danger")
        return redirect(url_for('home'))

    form_data = {
        'fullName': member.fullName,
        'dateOfBirth': str(member.dateOfBirth) if member.dateOfBirth else '',
        'gender': member.gender,
        'association': member.association,
        'maritalStatus': member.maritalStatus,
        'spouseNames': member.spouseNames,
        'childrenNames': member.childrenNames,
        'schoolName': member.schoolName,
        'whereabouts': member.whereabouts,
        'contact': member.contact,
        'bio': member.bio,
        'personalRelationshipDescription': member.personalRelationshipDescription,
        'isRaphaelDescendant': '1' if member.isRaphaelDescendant else '0',
        'can_message': '1' if member.can_message else '0'
    }

    if request.method == 'POST':
        member.fullName = request.form.get('fullName')
        member.dateOfBirth = request.form.get('dateOfBirth')
        member.gender = request.form.get('gender')
        member.association = request.form.get('association')
        member.maritalStatus = request.form.get('maritalStatus')
        member.spouseNames = request.form.get('spouseNames')
        member.childrenNames = request.form.get('childrenNames')
        member.schoolName = request.form.get('schoolName')
        member.whereabouts = request.form.get('whereabouts')
        member.contact = request.form.get('contact')
        member.bio = request.form.get('bio')
        member.personalRelationshipDescription = request.form.get('personalRelationshipDescription')
        member.isRaphaelDescendant = request.form.get('isRaphaelDescendant') == '1'
        member.can_message = request.form.get('can_message') == '1'

        profile_photo_file = request.files.get('profilePhoto')
        if profile_photo_file and profile_photo_file.filename != '':
            if allowed_file(profile_photo_file.filename):
                filename = secure_filename(profile_photo_file.filename)
                filepath = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
                profile_photo_file.save(filepath)
                member.profilePhoto = os.path.join(app.config['UPLOAD_FOLDER'], filename).replace('\\', '/')
            else:
                flash('Invalid file type for profile photo. Allowed: png, jpg, jpeg, gif.', 'danger')
                form_data = request.form.to_dict()
                return render_template('edit_member.html', member=member, form_data=form_data)
        elif request.form.get('remove_profile_photo'):
            if member.profilePhoto and os.path.exists(os.path.join(app.root_path, member.profilePhoto)):
                os.remove(os.path.join(app.root_path, member.profilePhoto))
            member.profilePhoto = None

        needs_details_update = 0
        if not all([member.fullName, member.dateOfBirth, member.gender, member.association, member.maritalStatus,
                    member.whereabouts, member.contact, member.bio, member.personalRelationshipDescription]):
            needs_details_update = 1
            form_data = request.form.to_dict()
            flash('Please fill in all required fields.', 'danger')
            return render_template('edit_member.html', member=member, form_data=form_data)

        try:
            db.execute('''
                UPDATE members SET
                    fullName = ?, association = ?, gender = ?, dateOfBirth = ?, maritalStatus = ?,
                    spouseNames = ?, childrenNames = ?, schoolName = ?, whereabouts = ?, contact = ?,
                    bio = ?, personalRelationshipDescription = ?, profilePhoto = ?,
                    isRaphaelDescendant = ?, needs_details_update = ?, can_message = ?
                WHERE id = ?
            ''', (
                member.fullName, member.association, member.gender, member.dateOfBirth, member.maritalStatus,
                member.spouseNames, member.childrenNames, member.schoolName, member.whereabouts, member.contact,
                member.bio, member.personalRelationshipDescription, member.profilePhoto,
                member.isRaphaelDescendant, needs_details_update, member.can_message,
                member.id
            ))
            db.commit()

            # If the member is linked to a user, update the user's originalName and relationshipToRaphael
            if member.user_id:
                db.execute('UPDATE users SET originalName = ?, relationshipToRaphael = ? WHERE id = ?',
                           (member.fullName, member.association, member.user_id))
                db.commit()

            flash('Member details updated successfully!', 'success')
            return redirect(url_for('member_detail', member_id=member.id))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'danger')
            form_data = request.form.to_dict()
            return render_template('edit_member.html', member=member, form_data=form_data)
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')
            form_data = request.form.to_dict()
            return render_template('edit_member.html', member=member, form_data=form_data)

    return render_template('edit_member.html', member=member, form_data=form_data)


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form_data = {}
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            form_data = request.form.to_dict()
            return render_template('change_password.html', form_data=form_data)

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
    app.run(debug=True)
