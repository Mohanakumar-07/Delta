from flask import Flask, render_template, request, redirect, jsonify, flash, session, url_for
from flask_cors import CORS
from functools import wraps
from main import listen, get_response, greet_st
from database import create_user, verify_user, get_user_by_email, check_username_exists, check_email_exists
import os
from datetime import timedelta, datetime
from dotenv import load_dotenv
import re
from collections import defaultdict
import time


load_dotenv()

app = Flask(__name__)

if not os.getenv('FLASK_SECRET_KEY'):
    import secrets
    print("WARNING: FLASK_SECRET_KEY not set. Using random key (sessions won't persist across restarts)")
    app.secret_key = secrets.token_hex(32)
else:
    app.secret_key = os.getenv('FLASK_SECRET_KEY')

# CORS Configuration - NEVER use '*' in production
FRONTEND_URL = os.getenv('FRONTEND_URL')
if not FRONTEND_URL:
    print("WARNING: FRONTEND_URL not set. CORS disabled for security. Set this in production!")
    FRONTEND_URL = 'http://localhost:5000'  # Safe default for development
CORS(app, 
     resources={r"/*": {"origins": FRONTEND_URL}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = os.getenv('COOKIE_SECURE', 'False') == 'True'  # True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'None' if os.getenv('COOKIE_SECURE', 'False') == 'True' else 'Lax'  # None for cross-origin


login_attempts = defaultdict(list)  
RATE_LIMIT_WINDOW = 300  
MAX_LOGIN_ATTEMPTS = 5  

def is_rate_limited(ip):
    """Check if IP has exceeded login attempts"""
    now = time.time()
    # Clean old attempts
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < RATE_LIMIT_WINDOW]
    return len(login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS

def record_login_attempt(ip):
    """Record a login attempt for rate limiting"""
    login_attempts[ip].append(time.time())

def clear_login_attempts(ip):
    """Clear login attempts after successful login"""
    login_attempts[ip] = []

# Login required decorator for page routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function  

# API login required decorator (returns JSON instead of redirect)
def api_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function  


@app.after_request
def add_security_headers(response):
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS filter
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/')
def landingpage():
    return render_template('landingpage.html')

@app.route('/main')
@login_required
def home():
    return render_template('delta.html')


@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == "POST":
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # Check rate limiting
        if is_rate_limited(client_ip):
            flash('Too many login attempts. Please try again in 5 minutes.', 'error')
            return render_template("login.html")
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        
        if username and password:
            record_login_attempt(client_ip)
            success, result = verify_user(username, password)
            if success:
                clear_login_attempts(client_ip)  # Clear on successful login
                user_data = result
                session['username'] = user_data['username']
                session['name'] = user_data['name']
                session['email'] = user_data['email']
                session['user_id'] = user_data['id']
                session['logged_in'] = True
                session.permanent = remember
                
                if remember:
                    app.permanent_session_lifetime = timedelta(days=30)
                
                return redirect(url_for('home'))
            else:
                # Generic error message to prevent username enumeration
                flash('Invalid credentials', 'error')
        else:
            flash('Please enter username/email and password', 'error')
    
    return render_template("login.html")


# API Login endpoint (for separate frontend)
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # Check rate limiting
    if is_rate_limited(client_ip):
        return jsonify({'success': False, 'error': 'Too many login attempts. Please try again in 5 minutes.'}), 429
    
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    remember = data.get('remember', False)
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400
    
    record_login_attempt(client_ip)
    success, result = verify_user(username, password)
    if success:
        clear_login_attempts(client_ip)  # Clear on successful login
        user_data = result
        session['username'] = user_data['username']
        session['name'] = user_data['name']
        session['email'] = user_data['email']
        session['user_id'] = user_data['id']
        session['logged_in'] = True
        session.permanent = remember
        
        if remember:
            app.permanent_session_lifetime = timedelta(days=30)
        
        # Return user data (excluding sensitive info)
        return jsonify({
            'success': True,
            'user': {
                'username': user_data['username'],
                'name': user_data['name'],
                'email': user_data['email']
            }
        })
    else:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not all([first_name, email, username, password, confirm_password]):
            flash('First name, email, username, and password are required', 'error')
        elif len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
        elif not all(c.isalnum() or c == '_' for c in username):
            flash('Username can only contain letters, numbers, and underscores', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
        else:
            success, message = create_user(first_name, last_name, email, username, password)
            if success:
                flash('Account created successfully! Please login.', 'success')
                return redirect(url_for('login'))
            else:
                flash(message, 'error')
    
    return render_template('signup.html')


# API Signup endpoint (for separate frontend)
@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()
    email = data.get('email', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    
    # Validation
    if not all([first_name, email, username, password, confirm_password]):
        return jsonify({'success': False, 'error': 'All required fields must be filled'}), 400
    
    if len(username) < 3:
        return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
    
    if not all(c.isalnum() or c == '_' for c in username):
        return jsonify({'success': False, 'error': 'Username can only contain letters, numbers, and underscores'}), 400
    
    if password != confirm_password:
        return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    
    success, message = create_user(first_name, last_name, email, username, password)
    if success:
        return jsonify({'success': True, 'message': 'Account created successfully'})
    else:
        return jsonify({'success': False, 'error': message}), 400

@app.route('/forgetpassword', methods=['GET', 'POST'])
def forgetpassword():
    if request.method == "POST":
        email = request.form.get('email')
        
        if email:
            user = get_user_by_email(email)
            if user:
                flash('Password reset link sent to your email (feature coming soon)', 'success')
            else:
                flash('Email not found', 'error')
        else:
            flash('Please enter your email', 'error')
    
    return render_template('forgetpass.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('landingpage'))


# API Logout endpoint
@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})


# API Check auth status
@app.route('/api/auth/check', methods=['GET'])
def api_check_auth():
    if session.get('logged_in'):
        return jsonify({
            'authenticated': True,
            'user': {
                'username': session.get('username'),
                'name': session.get('name'),
                'email': session.get('email')
            }
        })
    return jsonify({'authenticated': False})


# API Get user profile
@app.route('/api/user/profile', methods=['GET'])
@api_login_required
def api_user_profile():
    return jsonify({
        'success': True,
        'user': {
            'username': session.get('username'),
            'name': session.get('name'),
            'email': session.get('email')
        }
    })

@app.route("/update", methods=["POST"])
@api_login_required
def update():
    try:
        data = request.get_json()
        user_msg = data.get("message", "").strip().lower()

        if user_msg:
            assistant_reply = get_response(user_msg)
        else:
            assistant_reply = "Sorry, I didn’t catch that."

        return jsonify({
            "user": user_msg,
            "reply": assistant_reply
        })
    except Exception as e:
        # Log the actual error server-side, don't expose to client
        print(f"Error in /update: {str(e)}")
        return jsonify({
            "user": "",
            "reply": "Sorry, something went wrong. Please try again."
        }), 500

# API endpoint to check username availability
@app.route('/api/check-username', methods=['POST'])
def api_check_username():
    data = request.get_json()
    username = data.get('username', '').strip()
    
    if not username:
        return jsonify({'valid': False, 'message': 'Username is required'})
    
    if len(username) < 3:
        return jsonify({'valid': False, 'message': 'At least 3 characters required'})
    
    if not all(c.isalnum() or c == '_' for c in username):
        return jsonify({'valid': False, 'message': 'Only letters, numbers, and underscores'})
    
    if check_username_exists(username):
        return jsonify({'valid': False, 'message': 'Username already taken'})
    
    return jsonify({'valid': True, 'message': 'Username available'})

# API endpoint to check email availability
@app.route('/api/check-email', methods=['POST'])
def api_check_email():
    data = request.get_json()
    email = data.get('email', '').strip()
    
    if not email:
        return jsonify({'valid': False, 'message': 'Email is required'})
    
    # Basic email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return jsonify({'valid': False, 'message': 'Invalid email format'})
    
    if check_email_exists(email):
        return jsonify({'valid': False, 'message': 'Email already registered'})
    
    return jsonify({'valid': True, 'message': 'Email available'})

# API endpoint for password validation
@app.route('/api/validate-password', methods=['POST'])
def api_validate_password():
    data = request.get_json()
    password = data.get('password', '')
    confirm = data.get('confirm', '')
    
    errors = []
    
    if len(password) < 6:
        errors.append('At least 6 characters required')
    
    if confirm and password != confirm:
        errors.append('Passwords do not match')
    
    if errors:
        return jsonify({'valid': False, 'errors': errors})
    
    return jsonify({'valid': True, 'message': 'Password is valid'})

if __name__ == '__main__':
    # IMPORTANT: Set DEBUG=False in production environment variables
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))