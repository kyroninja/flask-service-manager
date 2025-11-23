from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Fix paths for running from api/ directory
basedir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.dirname(basedir)

# Database connection
def get_db_connection():
    conn = psycopg2.connect(os.environ.get('POSTGRES_URL'))
    return conn

# Initialize database tables
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Services table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            service_name VARCHAR(100) NOT NULL,
            cloud_provider VARCHAR(20) NOT NULL,
            access_key VARCHAR(255) NOT NULL,
            secret_key VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    cur.close()
    conn.close()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if user exists
        cur.execute('SELECT id FROM users WHERE username = %s', (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return render_template('register.html', error='Username already exists')
        
        # Create user
        hashed_password = generate_password_hash(password)
        cur.execute('INSERT INTO users (username, password) VALUES (%s, %s)',
                   (username, hashed_password))
        conn.commit()
        cur.close()
        conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/add-service', methods=['GET', 'POST'])
@login_required
def add_service():
    if request.method == 'POST':
        service_name = request.form['service_name']
        cloud_provider = request.form['cloud_provider']
        access_key = request.form['access_key']
        secret_key = request.form['secret_key']
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO services (user_id, service_name, cloud_provider, access_key, secret_key)
            VALUES (%s, %s, %s, %s, %s)
        ''', (session['user_id'], service_name, cloud_provider, access_key, secret_key))
        conn.commit()
        cur.close()
        conn.close()
        
        return redirect(url_for('dashboard'))
    
    return render_template('add_service.html')

@app.route('/view-claims')
@login_required
def view_claims():
    import os, requests
    from flask import session, render_template

    # Get claims endpoint from environment variable
    claims_endpoint = os.environ.get('CLAIMS_ENDPOINT_URL', '')
    
    claims_data = []
    error = None
    
    if claims_endpoint:
        try:
            # Call the updated claims endpoint
            response = requests.get(
                claims_endpoint,
                params={'user_id': session.get('user_id')},
                timeout=10
            )
            if response.status_code == 200:
                # The endpoint now returns a JSON array directly
                claims_data = response.json()
            else:
                error = f"Error fetching claims: {response.status_code} {response.text}"
        except Exception as e:
            error = f"Error fetching claims data: {str(e)}"
    else:
        error = "Claims endpoint not configured"
    
    return render_template(
        'view_claims.html', 
        claims_data=claims_data, 
        error=error
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# API Endpoints
@app.route('/api/services', methods=['GET'])
def api_get_services():
    """API endpoint to get all services (for your separate system)"""
    # You can add API key authentication here if needed
    api_key = request.headers.get('X-API-Key')
    expected_key = os.environ.get('API_KEY')
    
    if expected_key and api_key != expected_key:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('''
        SELECT s.id, s.service_name, s.cloud_provider, s.access_key, 
               s.secret_key, s.created_at, u.username
        FROM services s
        JOIN users u ON s.user_id = u.id
    ''')
    services = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(services)

@app.route('/api/services/user/<int:user_id>', methods=['GET'])
def api_get_user_services(user_id):
    """API endpoint to get services for a specific user"""
    api_key = request.headers.get('X-API-Key')
    expected_key = os.environ.get('API_KEY')
    
    if expected_key and api_key != expected_key:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('''
        SELECT id, service_name, cloud_provider, access_key, secret_key, created_at
        FROM services
        WHERE user_id = %s
    ''', (user_id,))
    services = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify(services)

# Initialize DB on first request
_db_initialized = False

@app.before_request
def before_first_request():
    global _db_initialized
    if not _db_initialized:
        try:
            init_db()
            _db_initialized = True
        except:
            pass

if __name__ == '__main__':
    app.run(debug=True)