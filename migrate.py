import sqlite3
import os

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'family_tree.db')

def migrate_db():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Add 'has_login_access' column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE members ADD COLUMN has_login_access INTEGER DEFAULT 0")
            print("Added 'has_login_access' column to members table.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("'has_login_access' column already exists.")
            else:
                print(f"Error adding 'has_login_access': {e}")

        # Add 'can_message' column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE members ADD COLUMN can_message INTEGER DEFAULT 0")
            print("Added 'can_message' column to members table.")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("'can_message' column already exists.")
            else:
                print(f"Error adding 'can_message': {e}")

        # Verify the schema (optional, but good for debugging)
        cursor.execute("PRAGMA table_info(members)")
        columns = [col[1] for col in cursor.fetchall()]
        print(f"Current columns in 'members' table: {columns}")

        conn.commit()
        print("Database migration attempt complete.")

    except sqlite3.Error as e:
        print(f"Database error during migration: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    migrate_db()