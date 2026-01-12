import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

DATABASE = 'users.db'

def init_db():
    """Initialize the database and create users table if it doesn't exist"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def create_user(first_name, last_name, email, username, password):
    """Create a new user account"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Hash the password
        password_hash = generate_password_hash(password)
        
        cursor.execute('''
            INSERT INTO users (first_name, last_name, email, username, password_hash)
            VALUES (?, ?, ?, ?, ?)
        ''', (first_name, last_name, email, username, password_hash))
        
        conn.commit()
        conn.close()
        return True, "User created successfully"
    except sqlite3.IntegrityError:
        return False, "Username or email already exists"
    except Exception as e:
        return False, f"Error creating user: {str(e)}"

def verify_user(username_or_email, password):
    """Verify user credentials using username or email and return user data"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if input is username or email
        cursor.execute('''
            SELECT id, first_name, last_name, email, username, password_hash 
            FROM users 
            WHERE username = ? OR email = ?
        ''', (username_or_email, username_or_email))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            password_hash = result[5]
            if check_password_hash(password_hash, password):
                full_name = result[1] if not result[2] else f"{result[1]} {result[2]}"
                return True, {
                    'id': result[0],
                    'first_name': result[1],
                    'last_name': result[2] or '',
                    'name': full_name,
                    'email': result[3],
                    'username': result[4]
                }
            else:
                return False, "Invalid password"
        else:
            return False, "User not found"
    except Exception as e:
        return False, f"Error verifying user: {str(e)}"

def get_user_by_email(email):
    """Get user information by email"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, first_name, last_name, email, username FROM users WHERE email = ?
        ''', (email,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            full_name = result[1] if not result[2] else f"{result[1]} {result[2]}"
            return {
                'id': result[0],
                'first_name': result[1],
                'last_name': result[2] or '',
                'name': full_name,
                'email': result[3],
                'username': result[4]
            }
        return None
    except Exception as e:
        print(f"Error getting user: {str(e)}")
        return None

# Initialize database on import
init_db()

def check_username_exists(username):
    """Check if username already exists in database"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        print(f"Error checking username: {str(e)}")
        return False

def check_email_exists(email):
    """Check if email already exists in database"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE email = ?', (email,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        print(f"Error checking email: {str(e)}")
        return False
