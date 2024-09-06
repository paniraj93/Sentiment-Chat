import sqlite3
import os

# Create a 'database' directory if it doesn't exist
if not os.path.exists('database'):
    os.makedirs('database')

# Connect to the SQLite database
conn = sqlite3.connect('database/chat_app.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    otp TEXT,
    otp_valid_until DATETIME
)
''')

# Create friendships table
cursor.execute('''
CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    friend_id INTEGER,
    status TEXT,
    relationship TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (friend_id) REFERENCES users (id)
)
''')

# Create sentiment_analysis table
cursor.execute('''
CREATE TABLE IF NOT EXISTS sentiment_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    negative_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'positive',
    FOREIGN KEY (user_id) REFERENCES users (id)
)
''')

# Create a function to generate chat tables
def create_chat_table(username1, username2):
    table_name = f"chat_{min(username1, username2)}_{max(username1, username2)}"
    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS {table_name} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        sentiment TEXT
    )
    ''')

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database and tables created successfully.")