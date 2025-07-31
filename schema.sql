-- schema.sql

-- Drop existing tables (order matters due to foreign keys)
DROP TABLE IF EXISTS chat_messages;
DROP TABLE IF EXISTS chat_room_members;
DROP TABLE IF EXISTS chat_rooms;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS statuses; -- Renamed from temporary_videos
DROP TABLE IF EXISTS members;
DROP TABLE IF EXISTS users;

-- Create users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    originalName TEXT NOT NULL,
    relationshipToRaphael TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0, -- 0 for regular user, 1 for admin
    theme_preference TEXT DEFAULT 'light',
    chat_background_image_path TEXT,
    unique_key TEXT UNIQUE NOT NULL, -- For password recovery
    password_reset_pending INTEGER DEFAULT 0, -- 1 if admin initiated reset, 0 otherwise
    reset_request_timestamp TIMESTAMP, -- Timestamp of user's reset request (for auto-initiation)
    last_login_at TIMESTAMP, -- NEW: Timestamp of last login
    last_seen_at TIMESTAMP -- NEW: Timestamp of last activity/seen
);

-- Create members table
CREATE TABLE members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullName TEXT NOT NULL,
    association TEXT NOT NULL,
    gender TEXT NOT NULL,
    dateOfBirth TEXT, -- YYYY-MM-DD format
    maritalStatus TEXT,
    spouseNames TEXT, -- comma-separated list of names
    childrenNames TEXT, -- comma-separated list of names
    schoolName TEXT,
    whereabouts TEXT,
    contact TEXT, -- comma-separated phone numbers/emails
    bio TEXT,
    personalRelationshipDescription TEXT,
    profilePhoto TEXT, -- path to photo file
    isRaphaelDescendant INTEGER DEFAULT 0, -- 1 if direct descendant, 0 otherwise
    user_id INTEGER UNIQUE, -- NULL if not linked to a user account, links to users.id
    needs_details_update INTEGER DEFAULT 0, -- 1 if admin needs to add more details (e.g., after initial user registration)
    added_by_user_id INTEGER NOT NULL, -- The user.id who initially added this member profile
    -- REMOVED: has_login_access (redundant with users.password_reset_pending)
    can_message INTEGER DEFAULT 0, -- 1 if linked user can send/receive messages, 0 otherwise (managed by admin)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL, -- If user deleted, set member.user_id to NULL
    FOREIGN KEY (added_by_user_id) REFERENCES users(id) ON DELETE CASCADE -- If user deleted, delete members they added
);

-- Create messages table (for private messages/admin notifications)
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL, -- Consistent with schema (was recipient_id in app.py)
    body TEXT NOT NULL, -- Consistent with schema (was content in app.py)
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER DEFAULT 0, -- 0 for unread, 1 for read
    is_admin_message INTEGER DEFAULT 0, -- 1 if message is from an admin (e.g., password reset notifications)
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create statuses table (renamed from temporary_videos)
CREATE TABLE statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER UNIQUE NOT NULL, -- Only one active status per member at a time
    file_path TEXT NOT NULL, -- path to video/image file
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Renamed from upload_timestamp to match app.py class
    is_video INTEGER DEFAULT 0, -- NEW: 1 if video, 0 if image
    uploader_user_id INTEGER NOT NULL, -- NEW: The user who uploaded this status
    FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE,
    FOREIGN KEY (uploader_user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- NEW TABLES FOR CHAT ROOMS AND MESSAGES (including AI chat history)
CREATE TABLE chat_rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL, -- Name of the chat room (e.g., "Family Chat", or "AI Chat")
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_group_chat INTEGER DEFAULT 0 -- 1 for group chat, 0 for direct/AI chat (can be simplified)
);

CREATE TABLE chat_room_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_room_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_admin INTEGER DEFAULT 0, -- 1 if user is admin of this specific chat room
    FOREIGN KEY (chat_room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (chat_room_id, user_id) -- Ensures a user can only be in a room once
);

CREATE TABLE chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_room_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    content TEXT, -- Message text (can be NULL if only media)
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    media_path TEXT, -- Path to media file (NULL if no media)
    media_type TEXT, -- 'image', 'video', 'audio' (NULL if no media)
    is_ai_message INTEGER DEFAULT 0, -- NEW: 1 if message is from AI, 0 otherwise
    FOREIGN KEY (chat_room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);
