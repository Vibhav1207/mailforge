import os
import json
import time
import shutil
import secrets
import base64
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, Response, stream_with_context, jsonify, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

# ─── App Config ───────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static'),
    static_url_path='/static'
)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = os.path.join('/tmp', 'uploads')  # Vercel writable
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# MongoDB
MONGODB_URI = os.environ.get('MONGODB_URI', '').strip()
if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI environment variable is not set!")
client = MongoClient(MONGODB_URI)
db = client['emailsnder']

# ─── Security Headers ────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

# ─── Helpers ──────────────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' in session:
        user = db.users.find_one({'_id': ObjectId(session['user_id'])})
        return user
    return None

# ─── Auth Routes ──────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action', 'login')

        if action == 'register':
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm_password', '')

            if not name or not email or not password:
                flash('All fields are required.', 'danger')
                return redirect(url_for('login'))

            if password != confirm:
                flash('Passwords do not match.', 'danger')
                return redirect(url_for('login'))

            if len(password) < 6:
                flash('Password must be at least 6 characters.', 'danger')
                return redirect(url_for('login'))

            if db.users.find_one({'email': email}):
                flash('An account with this email already exists.', 'danger')
                return redirect(url_for('login'))

            user_id = db.users.insert_one({
                'name': name,
                'email': email,
                'password_hash': generate_password_hash(password),
                'created_at': datetime.now(timezone.utc)
            }).inserted_id

            session['user_id'] = str(user_id)
            session['user_name'] = name
            session['user_email'] = email
            flash(f'Welcome, {name}! Account created successfully.', 'success')
            return redirect(url_for('index'))

        else:  # login
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')

            user = db.users.find_one({'email': email})
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = str(user['_id'])
                session['user_name'] = user['name']
                session['user_email'] = user['email']
                flash(f'Welcome back, {user["name"]}!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid email or password.', 'danger')
                return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ─── Dashboard ────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    templates = list(db.templates.find({'user_id': session['user_id']}))
    user = get_current_user()
    return render_template('index.html', templates=templates, user=user)

# ─── Templates ────────────────────────────────────────────────
@app.route('/create_template', methods=['GET', 'POST'])
@login_required
def create_template():
    user = get_current_user()
    if request.method == 'POST':
        name = request.form['name']
        subject = request.form['subject']
        body = request.form['body']

        db.templates.insert_one({
            'name': name,
            'subject': subject,
            'body': body,
            'user_id': session['user_id'],
            'created_at': datetime.now(timezone.utc)
        })
        flash('Template created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('create_template.html', user=user)

@app.route('/edit_template/<template_id>', methods=['GET', 'POST'])
@login_required
def edit_template(template_id):
    user = get_current_user()
    try:
        template = db.templates.find_one({
            '_id': ObjectId(template_id),
            'user_id': session['user_id']
        })
    except Exception:
        flash('Invalid template.', 'danger')
        return redirect(url_for('index'))

    if not template:
        flash('Template not found.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        db.templates.update_one(
            {'_id': ObjectId(template_id), 'user_id': session['user_id']},
            {'$set': {
                'name': request.form['name'],
                'subject': request.form['subject'],
                'body': request.form['body']
            }}
        )
        flash('Template updated!', 'success')
        return redirect(url_for('index'))

    return render_template('create_template.html', template=template, user=user)

@app.route('/delete_template/<template_id>', methods=['POST'])
@login_required
def delete_template(template_id):
    try:
        db.templates.delete_one({
            '_id': ObjectId(template_id),
            'user_id': session['user_id']
        })
        flash('Template deleted.', 'success')
    except Exception:
        flash('Error deleting template.', 'danger')
    return redirect(url_for('index'))

@app.route('/api/template/<template_id>')
@login_required
def api_template(template_id):
    try:
        template = db.templates.find_one({
            '_id': ObjectId(template_id),
            'user_id': session['user_id']
        })
        if template:
            return jsonify({
                'subject': template['subject'],
                'body': template['body']
            })
    except Exception:
        pass
    return jsonify({'error': 'Not found'}), 404

# ─── Upload Images (stored in MongoDB) ───────────────────────
@app.route('/upload_folder', methods=['GET', 'POST'])
@login_required
def upload_folder():
    user = get_current_user()
    if request.method == 'POST':
        folder_name = request.form['folder_name']
        files = request.files.getlist('files')

        if not folder_name:
            flash('Folder name is required.', 'danger')
            return redirect(request.url)

        safe_name = secure_filename(folder_name)
        count = 0
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_data = file.read()
                # Store image in MongoDB
                db.images.update_one(
                    {
                        'user_id': session['user_id'],
                        'folder': safe_name,
                        'filename': filename
                    },
                    {'$set': {
                        'user_id': session['user_id'],
                        'folder': safe_name,
                        'filename': filename,
                        'data': base64.b64encode(file_data).decode('utf-8'),
                        'uploaded_at': datetime.now(timezone.utc)
                    }},
                    upsert=True
                )
                count += 1

        flash(f'Uploaded {count} images to "{folder_name}".', 'success')
        return redirect(url_for('index'))

    return render_template('upload_folder.html', user=user)

# ─── Send Email ───────────────────────────────────────────────
@app.route('/send_email', methods=['GET', 'POST'])
@login_required
def send_email():
    user = get_current_user()
    templates = list(db.templates.find({'user_id': session['user_id']}))

    # Get image folders from MongoDB
    image_folders = db.images.distinct('folder', {'user_id': session['user_id']})

    if request.method == 'POST':
        def generate():
            try:
                template_id = request.form['template_id']
                sender_email = request.form['sender_email']
                sender_password = request.form['sender_password']
                smtp_server = request.form.get('smtp_server', 'smtp.gmail.com')
                smtp_port = int(request.form.get('smtp_port', 587))

                file = request.files['file']
                if not file:
                    yield json.dumps({'type': 'error', 'message': 'No file uploaded'}) + '\n'
                    return

                if file.filename.endswith('.csv'):
                    df = pd.read_csv(file)
                elif file.filename.endswith(('.xls', '.xlsx')):
                    df = pd.read_excel(file)
                else:
                    yield json.dumps({'type': 'error', 'message': 'Invalid file format. Use CSV or Excel.'}) + '\n'
                    return

                # Find email column
                email_col = None
                for col in df.columns:
                    if col.lower() == 'email':
                        email_col = col
                        break
                if not email_col:
                    for col in df.columns:
                        if 'email' in col.lower():
                            email_col = col
                            break
                if not email_col:
                    yield json.dumps({'type': 'error', 'message': 'No "email" column found in file.'}) + '\n'
                    return

                # Find name column
                name_col = None
                for col in df.columns:
                    if col.lower() == 'name':
                        name_col = col
                        break
                if not name_col:
                    for col in df.columns:
                        if 'name' in col.lower():
                            name_col = col
                            break

                # Build image map from MongoDB
                image_map = {}
                selected_folder = request.form.get('image_folder')
                if selected_folder:
                    safe_folder = secure_filename(selected_folder)
                    folder_images = db.images.find({
                        'user_id': session['user_id'],
                        'folder': safe_folder
                    })
                    for img_doc in folder_images:
                        key = os.path.splitext(img_doc['filename'])[0].lower()
                        image_map[key] = {
                            'data': base64.b64decode(img_doc['data']),
                            'filename': img_doc['filename']
                        }

                # Manual bulk images (uploaded at send time — stored in /tmp)
                bulk_images = request.files.getlist('bulk_images')
                if bulk_images and bulk_images[0].filename != '':
                    for img in bulk_images:
                        if img and allowed_file(img.filename):
                            filename = secure_filename(img.filename)
                            img_data = img.read()
                            key = os.path.splitext(filename)[0].lower()
                            image_map[key] = {
                                'data': img_data,
                                'filename': filename
                            }

                # Default attachment
                default_image = None
                if 'default_image' in request.files:
                    default_file = request.files['default_image']
                    if default_file and allowed_file(default_file.filename):
                        filename = secure_filename(default_file.filename)
                        default_image = {
                            'data': default_file.read(),
                            'filename': filename
                        }

                # Get template (user-scoped)
                try:
                    template = db.templates.find_one({
                        '_id': ObjectId(template_id),
                        'user_id': session['user_id']
                    })
                except Exception:
                    template = None

                if not template:
                    yield json.dumps({'type': 'error', 'message': 'Template not found.'}) + '\n'
                    return

                total = len(df)
                yield json.dumps({'type': 'info', 'message': f'Starting send for {total} recipients...', 'total': total}) + '\n'

                # SMTP connect
                try:
                    server = smtplib.SMTP(smtp_server, smtp_port)
                    server.starttls()
                    server.login(sender_email, sender_password)
                except Exception as e:
                    yield json.dumps({'type': 'error', 'message': f'SMTP Login Failed: {str(e)}'}) + '\n'
                    return

                sent_count = 0
                failed_count = 0

                for index, row in df.iterrows():
                    if index > 0:
                        time.sleep(3)

                    recipient_email = row[email_col]
                    if pd.isna(recipient_email) or str(recipient_email).strip() == '':
                        continue

                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = str(recipient_email).strip()
                    msg['Subject'] = template['subject']

                    # Replace placeholders
                    body_content = template['body']
                    for col in df.columns:
                        placeholder = f"{{{{{col}}}}}"
                        if placeholder in body_content:
                            body_content = body_content.replace(placeholder, str(row[col]))

                    msg.attach(MIMEText(body_content, 'plain'))

                    # Attach image
                    attached_image = False
                    if name_col and image_map:
                        raw_name = str(row[name_col]).strip()
                        safe_name_key = secure_filename(raw_name).lower()
                        if safe_name_key in image_map:
                            img_info = image_map[safe_name_key]
                            image = MIMEImage(img_info['data'], name=img_info['filename'])
                            image.add_header('Content-Disposition', 'attachment', filename=img_info['filename'])
                            msg.attach(image)
                            attached_image = True

                    if not attached_image and default_image:
                        image = MIMEImage(default_image['data'], name=default_image['filename'])
                        image.add_header('Content-Disposition', 'attachment', filename=default_image['filename'])
                        msg.attach(image)

                    # Send
                    try:
                        server.send_message(msg)
                        db.logs.insert_one({
                            'user_id': session['user_id'],
                            'recipient_email': str(recipient_email).strip(),
                            'template_name': template['name'],
                            'status': 'Sent',
                            'timestamp': datetime.now(timezone.utc),
                            'error_message': None
                        })
                        sent_count += 1
                        yield json.dumps({
                            'type': 'success',
                            'message': f'Sent to {recipient_email}',
                            'sent': sent_count, 'failed': failed_count, 'total': total
                        }) + '\n'
                    except Exception as e:
                        error_str = str(e).lower()
                        if 'connect' in error_str or 'pipe' in error_str or 'server' in error_str:
                            yield json.dumps({'type': 'warning', 'message': 'Connection lost. Reconnecting...'}) + '\n'
                            try:
                                server = smtplib.SMTP(smtp_server, smtp_port)
                                server.starttls()
                                server.login(sender_email, sender_password)
                                server.send_message(msg)
                                db.logs.insert_one({
                                    'user_id': session['user_id'],
                                    'recipient_email': str(recipient_email).strip(),
                                    'template_name': template['name'],
                                    'status': 'Sent',
                                    'timestamp': datetime.now(timezone.utc),
                                    'error_message': None
                                })
                                sent_count += 1
                                yield json.dumps({
                                    'type': 'success',
                                    'message': f'Sent to {recipient_email} (retry)',
                                    'sent': sent_count, 'failed': failed_count, 'total': total
                                }) + '\n'
                            except Exception as retry_e:
                                db.logs.insert_one({
                                    'user_id': session['user_id'],
                                    'recipient_email': str(recipient_email).strip(),
                                    'template_name': template['name'],
                                    'status': 'Failed',
                                    'timestamp': datetime.now(timezone.utc),
                                    'error_message': str(retry_e)
                                })
                                failed_count += 1
                                yield json.dumps({
                                    'type': 'error',
                                    'message': f'Failed: {recipient_email} — {str(retry_e)}',
                                    'sent': sent_count, 'failed': failed_count, 'total': total
                                }) + '\n'
                        else:
                            db.logs.insert_one({
                                'user_id': session['user_id'],
                                'recipient_email': str(recipient_email).strip(),
                                'template_name': template['name'],
                                'status': 'Failed',
                                'timestamp': datetime.now(timezone.utc),
                                'error_message': str(e)
                            })
                            failed_count += 1
                            yield json.dumps({
                                'type': 'error',
                                'message': f'Failed: {recipient_email} — {str(e)}',
                                'sent': sent_count, 'failed': failed_count, 'total': total
                            }) + '\n'

                try:
                    server.quit()
                except Exception:
                    pass

                yield json.dumps({'type': 'done', 'sent': sent_count, 'failed': failed_count, 'total': total}) + '\n'

            except Exception as e:
                yield json.dumps({'type': 'error', 'message': f'Critical Error: {str(e)}'}) + '\n'

        return Response(stream_with_context(generate()), mimetype='application/json')

    return render_template('send_email.html', templates=templates, image_folders=image_folders, user=user)

# ─── Logs ─────────────────────────────────────────────────────
@app.route('/logs')
@login_required
def logs():
    user = get_current_user()
    user_logs = list(db.logs.find({'user_id': session['user_id']}).sort('timestamp', -1))
    return render_template('logs.html', logs=user_logs, user=user)

# ─── Guide ────────────────────────────────────────────────────
@app.route('/guide')
@login_required
def guide():
    user = get_current_user()
    return render_template('guide.html', user=user)

# ─── Block Sensitive Static Files ─────────────────────────────
@app.before_request
def block_sensitive_static():
    if request.path.startswith('/static/'):
        blocked = ('.py', '.pyc', '.env', '.git', '.db', '.sqlite')
        if any(request.path.endswith(ext) for ext in blocked):
            abort(404)

# ─── Run (local dev) ─────────────────────────────────────────
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=False, host='0.0.0.0', port=5000)
