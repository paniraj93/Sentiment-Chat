import os
import sqlite3
import random
import string
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import pickle
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import time

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL')
app.config['MAIL_PASSWORD'] = os.getenv('PASSWORD')
mail = Mail(app)

DATABASE = 'database/chat_app.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        
def execute_with_retry(cursor, query, params=None, max_attempts=5):
    for attempt in range(max_attempts):
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_attempts - 1:
                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
            else:
                raise

# Load the sentiment analysis model and tokenizer
model = load_model('sentiment_model.h5')
with open('tokenizer.pkl', 'rb') as file:
    tokenizer = pickle.load(file)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    msg = Message('OTP for Chat App', sender=os.getenv('EMAIL'), recipients=[email])
    msg.body = f'Your OTP is: {otp}'
    mail.send(msg)

def preprocess_text(text, max_length=100):
    sequence = tokenizer.texts_to_sequences([text])
    padded_sequence = pad_sequences(sequence, maxlen=max_length)
    return padded_sequence

def predict_sentiment(text):
    processed_text = preprocess_text(text)
    prediction = model.predict(processed_text)
    return 'positive' if prediction[0][0] > 0.5 else 'negative'

def create_chat_table(username1, username2):
    db = get_db()
    cursor = db.cursor()
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
    db.commit()
    


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('signup'))

        conn = get_db()
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            flash('Username or email already exists.')
            return redirect(url_for('signup'))

        # Generate and send OTP
        otp = generate_otp()
        otp_valid_until = datetime.now() + timedelta(minutes=10)
        send_otp_email(email, otp)

        # Store user data and OTP in the database
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, email, password, otp, otp_valid_until) VALUES (?, ?, ?, ?, ?)',
                       (username, email, hashed_password, otp, otp_valid_until))
        conn.commit()
        conn.close()

        flash('OTP sent to your email. Please verify to complete registration.')
        return redirect(url_for('verify_otp', email=email))

    return render_template('signup.html')

@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    if request.method == 'POST':
        entered_otp = request.form['otp']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? AND otp = ? AND otp_valid_until > ?',
                       (email, entered_otp, datetime.now()))
        user = cursor.fetchone()

        if user:
            # OTP verified, complete registration
            cursor.execute('UPDATE users SET otp = NULL, otp_valid_until = NULL WHERE email = ?', (email,))
            conn.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP or OTP expired.')

        conn.close()

    return render_template('verify_otp.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully.')
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password.')

        conn.close()

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            # Generate and send OTP
            otp = generate_otp()
            otp_valid_until = datetime.now() + timedelta(minutes=10)
            send_otp_email(email, otp)

            # Store OTP in the database
            cursor.execute('UPDATE users SET otp = ?, otp_valid_until = ? WHERE email = ?',
                           (otp, otp_valid_until, email))
            conn.commit()

            flash('OTP sent to your email. Please verify to reset password.')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Email not found.')

        conn.close()

    return render_template('forgot_password.html')

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if request.method == 'POST':
        entered_otp = request.form['otp']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password', email=email))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? AND otp = ? AND otp_valid_until > ?',
                       (email, entered_otp, datetime.now()))
        user = cursor.fetchone()

        if user:
            # OTP verified, reset password
            hashed_password = generate_password_hash(new_password)
            cursor.execute('UPDATE users SET password = ?, otp = NULL, otp_valid_until = NULL WHERE email = ?',
                           (hashed_password, email))
            conn.commit()
            flash('Password reset successful. Please log in with your new password.')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP or OTP expired.')

        conn.close()

    return render_template('reset_password.html', email=email)

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Initialize chat tables
    initialize_chat_tables()

    db = get_db()
    cursor = db.cursor()

    try:
        # Get user's friends
        cursor.execute('''
            SELECT u.username, f.relationship
            FROM friendships f
            JOIN users u ON f.friend_id = u.id
            WHERE f.user_id = ? AND f.status = 'accepted'
        ''', (session['user_id'],))
        friends = cursor.fetchall()

        return render_template('chat.html', username=session['username'], friends=friends)
    finally:
        cursor.close()
        # Note: We don't close the database connection here because it's handled by teardown_appcontext

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    sender = session['username']
    recipient = request.form['recipient']
    message = request.form['message']

    # Analyze sentiment
    sentiment = predict_sentiment(message)

    db = get_db()
    cursor = db.cursor()

    try:
        # Store the message
        table_name = f"chat_{min(sender, recipient)}_{max(sender, recipient)}"
        cursor.execute(f'''
            INSERT INTO {table_name} (sender, message, sentiment)
            VALUES (?, ?, ?)
        ''', (sender, message, sentiment))

        new_status = 'positive'

        # Update sentiment analysis
        if sentiment == 'negative':
            cursor.execute('''
                INSERT INTO sentiment_analysis (user_id, negative_count, status)
                VALUES (?, 1, 'positive')
                ON CONFLICT(user_id) DO UPDATE SET
                negative_count = negative_count + 1
                RETURNING negative_count
            ''', (session['user_id'],))
            
            result = cursor.fetchone()
            negative_count = result[0] if result else 1

            if negative_count > 7:
                new_status = 'suicidal'
            elif negative_count > 5:
                new_status = 'depressed'
            elif negative_count > 3:
                new_status = 'sad'
            else:
                new_status = 'positive'

            cursor.execute('''
                UPDATE sentiment_analysis
                SET status = ?
                WHERE user_id = ?
            ''', (new_status, session['user_id']))

            # Notify friends and family if status changed
            if new_status != 'positive':
                cursor.execute('''
                    SELECT u.email
                    FROM friendships f
                    JOIN users u ON f.friend_id = u.id
                    WHERE f.user_id = ? AND f.status = 'accepted' AND f.relationship IN ('friend', 'family')
                ''', (session['user_id'],))
                friends_family = cursor.fetchall()

                for contact in friends_family:
                    send_notification_email(contact[0], session['username'], new_status)

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error in send_message: {e}")
        return "An error occurred while sending the message", 500
    finally:
        cursor.close()

    return redirect(url_for('chat'))

@app.route('/get_messages/<friend>')
def get_messages(friend):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    create_chat_table(session['username'], friend)

    conn = get_db()
    cursor = conn.cursor()

    table_name = f"chat_{min(session['username'], friend)}_{max(session['username'], friend)}"
    cursor.execute(f'''
        SELECT * FROM {table_name}
        ORDER BY timestamp DESC
        LIMIT 50
    ''')
    messages = cursor.fetchall()

    conn.close()

    return render_template('messages.html', messages=messages)

def initialize_chat_tables():
    if 'user_id' not in session:
        return

    db = get_db()
    cursor = db.cursor()

    try:
        # Get all friends
        cursor.execute('''
            SELECT u.username
            FROM friendships f
            JOIN users u ON f.friend_id = u.id
            WHERE f.user_id = ? AND f.status = 'accepted'
        ''', (session['user_id'],))
        friends = cursor.fetchall()

        # Create chat tables for each friendship
        for friend in friends:
            create_chat_table(session['username'], friend['username'])
    finally:
        cursor.close()

@app.route('/friends', methods=['GET', 'POST'])
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        action = request.form['action']
        friend_username = request.form['friend_username']

        cursor.execute('SELECT id FROM users WHERE username = ?', (friend_username,))
        friend = cursor.fetchone()

        if friend:
            friend_id = friend['id']

            if action == 'send_request':
                relationship = request.form['relationship']
                cursor.execute('''
                    INSERT INTO friendships (user_id, friend_id, status, relationship)
                    VALUES (?, ?, 'pending', ?)
                ''', (session['user_id'], friend_id, relationship))

            elif action == 'accept_request':
                cursor.execute('''
                    UPDATE friendships
                    SET status = 'accepted'
                    WHERE user_id = ? AND friend_id = ?
                ''', (friend_id, session['user_id']))

                # Add reverse friendship
                cursor.execute('''
                    INSERT INTO friendships (user_id, friend_id, status, relationship)
                    SELECT ?, ?, 'accepted', relationship
                    FROM friendships
                    WHERE user_id = ? AND friend_id = ?
                ''', (session['user_id'], friend_id, friend_id, session['user_id']))

            elif action == 'reject_request':
                cursor.execute('''
                    DELETE FROM friendships
                    WHERE user_id = ? AND friend_id = ?
                ''', (friend_id, session['user_id']))

            conn.commit()
            flash('Friend request action completed successfully.')
        else:
            flash('User not found.')

    # Get friend requests
    cursor.execute('''
        SELECT u.username, f.relationship
        FROM friendships f
        JOIN users u ON f.user_id = u.id
        WHERE f.friend_id = ? AND f.status = 'pending'
    ''', (session['user_id'],))
    friend_requests = cursor.fetchall()

    # Get friends list
    cursor.execute('''
        SELECT u.username, f.relationship
        FROM friendships f
        JOIN users u ON f.friend_id = u.id
        WHERE f.user_id = ? AND f.status = 'accepted'
    ''', (session['user_id'],))
    friends = cursor.fetchall()

    conn.close()

    return render_template('friends.html', friend_requests=friend_requests, friends=friends)

def send_notification_email(email, username, status):
    subject = f"Concern about {username}'s emotional state"
    body = f"We've noticed that {username}'s recent messages indicate they might be feeling {status}. Please reach out to them if you can."
    msg = Message(subject, sender=os.getenv('EMAIL'), recipients=[email])
    msg.body = body
    mail.send(msg)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
