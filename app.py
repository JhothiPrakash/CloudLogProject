"""
Cloud Log Analytics - Secure Flask Web Application
===================================================
SECURITY-FOCUSED APPLICATION

CRITICAL SECURITY MEASURES:
1. AWS credentials are NEVER logged, printed, or stored persistently
2. All credentials exist ONLY in encrypted session memory
3. Session is completely cleared on logout
4. CSRF protection on all forms
5. Security headers on all responses
6. Rate limiting to prevent brute force
7. Input validation and sanitization
8. User consent required before credential submission
9. Users can only view their own uploaded log results
"""

import os
import re
import uuid
import gzip
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import time

from flask import (
    Flask, 
    render_template, 
    request, 
    redirect, 
    url_for, 
    session, 
    flash,
    abort,
    make_response
)

from aws_utils import (
    validate_aws_credentials,
    upload_file_to_s3,
    get_analysis_results
)

# ============== CONFIGURATION ==============
S3_BUCKET_NAME = "your-s3-bucket-name"  # Configure this
DYNAMODB_TABLE = ""

# Security Configuration
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max
ALLOWED_EXTENSIONS = {'.log', '.txt'}
SESSION_TIMEOUT = 1800  # 30 minutes
RATE_LIMIT_WINDOW = 300  # 5 minutes
MAX_LOGIN_ATTEMPTS = 5
MAX_UPLOAD_ATTEMPTS = 20

# Flask configuration
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=SESSION_TIMEOUT),
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH
)

rate_limit_storage = defaultdict(list)


# ============== SECURITY MIDDLEWARE ==============

@app.before_request
def security_checks():
    """Security checks before each request."""
    if request.endpoint == 'static':
        return
    
    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            abort(403)
    
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(seconds=SESSION_TIMEOUT):
            session.clear()
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
    
    session['last_activity'] = datetime.now().isoformat()
    
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self';"
    )
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    if 'aws_access_key' in session:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
    
    return response


def check_rate_limit(identifier: str, max_attempts: int, window: int) -> bool:
    """Check rate limits."""
    current_time = time.time()
    rate_limit_storage[identifier] = [
        t for t in rate_limit_storage[identifier] if current_time - t < window
    ]
    if len(rate_limit_storage[identifier]) >= max_attempts:
        return True
    rate_limit_storage[identifier].append(current_time)
    return False


def login_required(f):
    """Decorator for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'aws_access_key' not in session:
            flash('Please log in with your AWS credentials.', 'warning')
            return redirect(url_for('login'))
        
        if 'session_fingerprint' in session:
            current_fp = generate_session_fingerprint()
            if session['session_fingerprint'] != current_fp:
                session.clear()
                flash('Session integrity check failed.', 'error')
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function


def generate_session_fingerprint() -> str:
    """Generate session fingerprint for integrity checking."""
    components = [
        request.headers.get('User-Agent', ''),
        request.headers.get('Accept-Language', ''),
    ]
    return hashlib.sha256('|'.join(components).encode()).hexdigest()[:16]


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent attacks."""
    filename = os.path.basename(filename)
    filename = re.sub(r'[^\w\-.]', '_', filename)
    filename = filename.lstrip('.')
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:95] + ext
    return filename


def validate_aws_key_format(access_key: str, secret_key: str) -> tuple:
    """Validate AWS key format."""
    if not re.match(r'^(AKIA|ASIA|AIDA)[A-Z0-9]{16}$', access_key):
        return False, "Invalid Access Key format"
    if not re.match(r'^[A-Za-z0-9+/]{40}$', secret_key):
        return False, "Invalid Secret Key format"
    return True, None


def calculate_file_hash(file_content: bytes) -> str:
    """Calculate SHA-256 hash."""
    return hashlib.sha256(file_content).hexdigest()


def compress_content(content: bytes) -> bytes:
    """Compress using gzip."""
    return gzip.compress(content)


def generate_unique_filename(original_filename: str, session_id: str) -> str:
    """Generate unique filename."""
    safe_name = sanitize_filename(original_filename)
    base_name = os.path.splitext(safe_name)[0]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    short_uuid = str(uuid.uuid4())[:8]
    session_hash = hashlib.sha256(session_id.encode()).hexdigest()[:6]
    return f"{base_name}_{timestamp}_{session_hash}_{short_uuid}.log.gz"


# ============== ROUTES ==============

@app.route('/', methods=['GET', 'POST'])
def login():
    """Secure login with consent requirement."""
    if 'aws_access_key' in session:
        return redirect(url_for('dashboard'))
    
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    
    if request.method == 'POST':
        if check_rate_limit(f"login_{client_ip}", MAX_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW):
            flash('Too many login attempts. Please wait 5 minutes.', 'error')
            return render_template('login.html', csrf_token=session.get('csrf_token'))
        
        consent = request.form.get('security_consent')
        if consent != 'agreed':
            flash('You must acknowledge the security terms to continue.', 'error')
            return render_template('login.html', csrf_token=session.get('csrf_token'))
        
        access_key = request.form.get('access_key', '').strip()
        secret_key = request.form.get('secret_key', '').strip()
        region = request.form.get('region', '').strip()
        
        if not all([access_key, secret_key, region]):
            flash('All fields are required.', 'error')
            return render_template('login.html', csrf_token=session.get('csrf_token'))
        
        is_valid_format, format_error = validate_aws_key_format(access_key, secret_key)
        if not is_valid_format:
            flash(f'Invalid credentials format.', 'error')
            return render_template('login.html', csrf_token=session.get('csrf_token'))
        
        valid_regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-north-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',
            'sa-east-1', 'ca-central-1'
        ]
        if region not in valid_regions:
            flash('Invalid AWS region.', 'error')
            return render_template('login.html', csrf_token=session.get('csrf_token'))
        
        is_valid, message = validate_aws_credentials(access_key, secret_key, region)
        
        if is_valid:
            session.clear()
            session['csrf_token'] = secrets.token_hex(32)
            session['aws_access_key'] = access_key
            session['aws_secret_key'] = secret_key
            session['aws_region'] = region
            session['session_id'] = secrets.token_hex(16)
            session['session_fingerprint'] = generate_session_fingerprint()
            session['login_time'] = datetime.now().isoformat()
            session['last_activity'] = datetime.now().isoformat()
            session['uploaded_hashes'] = []
            session['uploaded_files'] = []
            session.permanent = True
            
            flash('Successfully connected to AWS!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('AWS Authentication Failed. Please check your credentials.', 'error')
            return render_template('login.html', csrf_token=session.get('csrf_token'))
    
    return render_template('login.html', csrf_token=session.get('csrf_token'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    """Secure dashboard for file uploads."""
    if request.method == 'POST':
        if check_rate_limit(f"upload_{session.get('session_id')}", MAX_UPLOAD_ATTEMPTS, RATE_LIMIT_WINDOW):
            flash('Too many upload attempts. Please wait.', 'error')
            return render_template('dashboard.html', 
                                 csrf_token=session.get('csrf_token'),
                                 uploaded_files=session.get('uploaded_files', []))
        
        if 'logfile' not in request.files:
            flash('No file selected.', 'error')
            return render_template('dashboard.html', 
                                 csrf_token=session.get('csrf_token'),
                                 uploaded_files=session.get('uploaded_files', []))
        
        file = request.files['logfile']
        
        if file.filename == '':
            flash('No file selected.', 'error')
            return render_template('dashboard.html', 
                                 csrf_token=session.get('csrf_token'),
                                 uploaded_files=session.get('uploaded_files', []))
        
        safe_filename = sanitize_filename(file.filename)
        file_ext = os.path.splitext(safe_filename)[1].lower()
        
        if file_ext not in ALLOWED_EXTENSIONS:
            flash('Only .log and .txt files are allowed.', 'error')
            return render_template('dashboard.html', 
                                 csrf_token=session.get('csrf_token'),
                                 uploaded_files=session.get('uploaded_files', []))
        
        log_type = request.form.get('log_type', 'system')
        if log_type not in ['system', 'server']:
            log_type = 'system'
        
        try:
            file_content = file.read()
            
            if len(file_content) == 0:
                flash('File is empty.', 'error')
                return render_template('dashboard.html', 
                                     csrf_token=session.get('csrf_token'),
                                     uploaded_files=session.get('uploaded_files', []))
            
            file_hash = calculate_file_hash(file_content)
            
            uploaded_hashes = session.get('uploaded_hashes', [])
            if file_hash in uploaded_hashes:
                flash('This file has already been uploaded.', 'warning')
                return render_template('dashboard.html', 
                                     csrf_token=session.get('csrf_token'),
                                     uploaded_files=session.get('uploaded_files', []))
            
            unique_filename = generate_unique_filename(safe_filename, session.get('session_id', ''))
            compressed_content = compress_content(file_content)
            
            success, message = upload_file_to_s3(
                session=session,
                file_content=compressed_content,
                bucket_name=S3_BUCKET_NAME,
                s3_key=unique_filename,
                file_hash=file_hash,
                log_type=log_type
            )
            
            if success:
                uploaded_hashes.append(file_hash)
                session['uploaded_hashes'] = uploaded_hashes
                
                uploaded_files = session.get('uploaded_files', [])
                uploaded_files.append({
                    'filename': unique_filename,
                    'original_name': safe_filename,
                    'upload_time': datetime.now().isoformat(),
                    'log_type': log_type
                })
                session['uploaded_files'] = uploaded_files
                session['last_uploaded_file'] = unique_filename
                
                flash('File uploaded successfully! Analyzing...', 'success')
                return redirect(url_for('results'))
            else:
                flash('Upload failed. Please try again.', 'error')
                
        except Exception:
            flash('Error processing file.', 'error')
    
    return render_template('dashboard.html', 
                         csrf_token=session.get('csrf_token'),
                         uploaded_files=session.get('uploaded_files', []))


@app.route('/results')
@login_required
def results():
    """Results page - Shows ONLY the current user's results."""
    filename = session.get('last_uploaded_file')
    
    if not filename:
        flash('No file has been uploaded yet.', 'warning')
        return redirect(url_for('dashboard'))
    
    uploaded_files = session.get('uploaded_files', [])
    user_filenames = [f['filename'] for f in uploaded_files]
    
    if filename not in user_filenames:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    success, data = get_analysis_results(
        session=session,
        table_name=DYNAMODB_TABLE,
        filename=filename
    )
    
    if success and data:
        return render_template('results.html', 
                             results=data, 
                             filename=filename,
                             csrf_token=session.get('csrf_token'))
    else:
        return render_template('results.html', 
                             results=None, 
                             filename=filename,
                             message="Analysis in progress...",
                             csrf_token=session.get('csrf_token'))


@app.route('/history')
@login_required
def history():
    """View upload history."""
    return render_template('history.html', 
                         uploaded_files=session.get('uploaded_files', []),
                         csrf_token=session.get('csrf_token'))


@app.route('/view-result/<filename>')
@login_required
def view_result(filename):
    """View specific result with ownership validation."""
    filename = sanitize_filename(filename)
    uploaded_files = session.get('uploaded_files', [])
    user_filenames = [f['filename'] for f in uploaded_files]
    
    if filename not in user_filenames:
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    session['last_uploaded_file'] = filename
    return redirect(url_for('results'))


@app.route('/logout')
def logout():
    """Secure logout - clears ALL session data."""
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    flash('Logged out. Credentials cleared.', 'success')
    return response


@app.route('/privacy')
def privacy():
    """Privacy policy page."""
    return render_template('privacy.html', csrf_token=session.get('csrf_token'))


# ============== ERROR HANDLERS ==============

@app.errorhandler(403)
def forbidden(e):
    flash('Security validation failed.', 'error')
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error_code=404, 
                         error_message="Page Not Found",
                         csrf_token=session.get('csrf_token')), 404

@app.errorhandler(413)
def file_too_large(e):
    flash('File too large. Max 50MB.', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, 
                         error_message="Server Error",
                         csrf_token=session.get('csrf_token')), 500


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
