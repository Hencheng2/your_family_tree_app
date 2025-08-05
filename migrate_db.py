    import sqlite3
    import os

    # Define the path to your database file
    # This path must match the Mount Path you configure on Render
    DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'family_tree.db')

    def migrate_database():
        conn = None
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # --- Migration for game_invitations table ---
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='game_invitations';")
            if cursor.fetchone():
                print("Table 'game_invitations' already exists. No migration needed for it.")
            else:
                cursor.execute("""
                    CREATE TABLE game_invitations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_id INTEGER NOT NULL,
                        recipient_id INTEGER NOT NULL,
                        game_name TEXT NOT NULL,
                        status TEXT DEFAULT 'pending', -- 'pending', 'accepted', 'declined'
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                        FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                """)
                print("Table 'game_invitations' created successfully.")

            # --- Migration for messages table column rename (if needed) ---
            # This is a more complex ALTER TABLE, as SQLite doesn't directly support RENAME COLUMN.
            # It usually involves creating a new table, copying data, dropping old, renaming new.
            # For simplicity, we'll assume your app.py is already using 'recipient_id' and 'content'.
            # If you have existing data in 'messages' with 'receiver_id' and 'body'
            # and you need to access it with the new names, this part would be more involved.
            # For now, we'll just check if the columns exist and print a message.
            
            # Check for 'receiver_id' column
            cursor.execute("PRAGMA table_info(messages);")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]

            if 'receiver_id' in column_names and 'recipient_id' not in column_names:
                print("WARNING: 'messages' table still has 'receiver_id'. Manual migration might be needed if you have old data you wish to preserve and access with 'recipient_id'.")
            if 'body' in column_names and 'content' not in column_names:
                print("WARNING: 'messages' table still has 'body'. Manual migration might be needed if you have old data you wish to preserve and access with 'content'.")
            
            conn.commit()
            print("Database migration script finished.")

        except sqlite3.Error as e:
            print(f"Database error during migration: {e}")
            if conn:
                conn.rollback()
        finally:
            if conn:
                conn.close()

    if __name__ == '__main__':
        migrate_database()
    
