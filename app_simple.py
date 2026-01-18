"""
Безопасная корпоративная система обмена файлами с MFA и ролевой моделью доступа
Упрощенная версия без отделов
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import secrets
from cryptography.fernet import Fernet
import bcrypt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_file_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Генерируем ключ для шифрования файлов
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    department = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    role = db.relationship('Role', backref='users')
    files = db.relationship('File', backref='owner', lazy=True)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    permissions = db.Column(db.Text)  # JSON строка с разрешениями
    
    def has_permission(self, permission):
        import json
        perms = json.loads(self.permissions or '[]')
        return permission in perms

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    encrypted = db.Column(db.Boolean, default=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    access_level = db.Column(db.String(20), default='private')  # private, department, public
    department = db.Column(db.String(100))
    
    # Связи для контроля доступа
    shared_with = db.relationship('FileAccess', backref='file', lazy=True)

class FileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    permission = db.Column(db.String(20), default='read')  # read, write, admin
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Декоратор для проверки ролей
def role_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.role.has_permission(permission):
                flash('У вас нет прав для выполнения этого действия', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Функция для логирования действий
def log_action(action, resource_type=None, resource_id=None, details=None):
    log = AuditLog(
        user_id=current_user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=details
    )
    db.session.add(log)
    db.session.commit()

# Шифрование и расшифровка файлов
def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        
        if not encrypted_data:
            raise ValueError("Файл пуст")
            
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return decrypted_data
    except Exception as e:
        print(f"Ошибка расшифровки файла {file_path}: {str(e)}")
        raise

# Маршруты
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if user.mfa_enabled:
                # Если включен MFA, перенаправляем на страницу ввода кода
                return redirect(url_for('mfa_verify', user_id=user.id))
            else:
                login_user(user)
                user.last_login = datetime.utcnow()
                db.session.commit()
                log_action('login')
                return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

@app.route('/mfa_verify/<int:user_id>', methods=['GET', 'POST'])
def mfa_verify(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        token = request.form['token']
        totp = pyotp.TOTP(user.mfa_secret)
        
        if totp.verify(token, valid_window=1):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_action('login_with_mfa')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный код MFA', 'error')
    
    return render_template('mfa_verify.html', user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Проверяем, что пользователь с таким именем не существует
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return render_template('register.html')
        
        # Создаем пользователя с ролью "user" по умолчанию
        user_role = Role.query.filter_by(name='user').first()
        if not user_role:
            user_role = Role(name='user', description='Обычный пользователь', permissions='["upload_files", "download_files"]')
            db.session.add(user_role)
            db.session.commit()
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role_id=user_role.id,
            department=request.form.get('department', '')
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация успешна! Теперь вы можете войти в систему.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Получаем файлы пользователя
    user_files = File.query.filter_by(owner_id=current_user.id).order_by(File.created_at.desc()).all()
    
    # Получаем файлы, к которым у пользователя есть доступ
    shared_files = File.query.join(FileAccess).filter(
        FileAccess.user_id == current_user.id,
        File.owner_id != current_user.id
    ).all()
    
    # Публичные файлы всех других пользователей
    public_files = File.query.filter(
        File.access_level == 'public',
        File.owner_id != current_user.id
    ).all()

    # Файлы отдела (если у пользователя есть отдел)
    department_files = []
    if current_user.department:
        department_files = File.query.filter(
            File.access_level == 'department',
            File.department == current_user.department,
            File.owner_id != current_user.id
        ).all()

    # Объединяем списки без дублей по id
    shared_map = {}
    for f in shared_files + public_files + department_files:
        shared_map[f.id] = f
    shared_files = list(shared_map.values())
    
    return render_template('dashboard.html', user_files=user_files, shared_files=shared_files)

@app.route('/upload', methods=['POST'])
@login_required
@role_required('upload_files')
def upload_file():
    if 'file' not in request.files:
        flash('Файл не выбран', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Файл не выбран', 'error')
        return redirect(url_for('dashboard'))
    
    if file:
        filename = secure_filename(file.filename)
        # Добавляем уникальный идентификатор к имени файла
        unique_filename = f"{secrets.token_hex(8)}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Сохраняем файл
        file.save(file_path)
        
        # Шифруем файл
        encrypt_file(file_path)
        
        # Сохраняем информацию о файле в базе данных
        access_level = request.form.get('access_level', 'private')
        department = request.form.get('department', '')
        
        new_file = File(
            filename=unique_filename,
            original_filename=filename,
            file_path=file_path,
            file_size=os.path.getsize(file_path),
            mime_type=file.content_type,
            owner_id=current_user.id,
            access_level=access_level,
            department=department if access_level == 'department' else None
        )
        
        db.session.add(new_file)
        db.session.commit()
        
        log_action('file_upload', 'file', new_file.id, f'Uploaded: {filename}, access={access_level}')
        flash('Файл успешно загружен', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        # Проверяем права доступа
        has_access = False
        
        # Владелец файла всегда имеет доступ
        if file.owner_id == current_user.id:
            has_access = True
        # Проверяем явно предоставленный доступ
        elif FileAccess.query.filter_by(file_id=file_id, user_id=current_user.id).first():
            has_access = True
        # Проверяем публичный доступ (public виден всем пользователям)
        elif file.access_level == 'public':
            has_access = True
        # Проверяем доступ на уровне отдела
        elif (file.access_level == 'department' and 
              file.department and 
              current_user.department and
              file.department == current_user.department):
            has_access = True
        
        if not has_access:
            flash('У вас нет прав для скачивания этого файла', 'error')
            return redirect(url_for('dashboard'))
        
        # Проверяем, что файл существует
        if not os.path.exists(file.file_path):
            flash('Файл не найден на сервере', 'error')
            return redirect(url_for('dashboard'))
        
        # Расшифровываем файл
        decrypted_data = decrypt_file(file.file_path)
        
        log_action('file_download', 'file', file_id, f'Downloaded: {file.original_filename}')
        
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=file.original_filename,
            mimetype=file.mime_type or 'application/octet-stream'
        )
        
    except FileNotFoundError:
        flash('Файл не найден на сервере', 'error')
        return redirect(url_for('dashboard'))
    except PermissionError:
        flash('Нет прав доступа к файлу', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"Ошибка при скачивании файла: {str(e)}")
        flash(f'Ошибка при скачивании файла: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/setup_mfa')
@login_required
def setup_mfa():
    if current_user.mfa_enabled:
        flash('MFA уже настроен', 'info')
        return redirect(url_for('dashboard'))
    
    # Генерируем секретный ключ для MFA
    secret = pyotp.random_base32()
    current_user.mfa_secret = secret
    db.session.commit()
    
    # Создаем QR код
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name="Secure File System"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    qr_code = base64.b64encode(img_buffer.getvalue()).decode()
    
    return render_template('setup_mfa.html', qr_code=qr_code, secret=secret)

@app.route('/enable_mfa', methods=['POST'])
@login_required
def enable_mfa():
    token = request.form['token']
    totp = pyotp.TOTP(current_user.mfa_secret)
    
    if totp.verify(token, valid_window=1):
        current_user.mfa_enabled = True
        db.session.commit()
        log_action('mfa_enabled')
        flash('MFA успешно включен', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Неверный код MFA', 'error')
        return redirect(url_for('setup_mfa'))

@app.route('/share_file/<int:file_id>', methods=['POST'])
@login_required
@role_required('share_files')
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Проверяем, что пользователь является владельцем файла
    if file.owner_id != current_user.id:
        flash('У вас нет прав для предоставления доступа к этому файлу', 'error')
        return redirect(url_for('dashboard'))
    
    username = request.form['username']
    permission = request.form['permission']
    
    # Находим пользователя
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Пользователь не найден', 'error')
        return redirect(url_for('dashboard'))
    
    # При публичном доступе шаринг не нужен
    if file.access_level == 'public':
        flash('Файл уже публичный и доступен всем пользователям', 'info')
        return redirect(url_for('dashboard'))

    # Проверяем, не предоставлен ли уже доступ
    existing_access = FileAccess.query.filter_by(
        file_id=file_id, 
        user_id=user.id
    ).first()
    
    if existing_access:
        flash('Доступ уже предоставлен этому пользователю', 'error')
        return redirect(url_for('dashboard'))
    
    # Создаем запись о доступе
    access = FileAccess(
        file_id=file_id,
        user_id=user.id,
        permission=permission,
        granted_by=current_user.id
    )
    
    db.session.add(access)
    db.session.commit()
    
    log_action('file_shared', 'file', file_id, f'Shared with {username} ({permission})')
    flash(f'Доступ к файлу предоставлен пользователю {username}', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/admin/delete_file/<int:file_id>', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_delete_file(file_id):
    """Удаление файла администратором из админ-панели"""
    file = File.query.get_or_404(file_id)

    try:
        # Удаляем записи о доступах к файлу
        FileAccess.query.filter_by(file_id=file.id).delete()
        db.session.flush()

        # Удаляем физический файл
        if os.path.exists(file.file_path):
            try:
                os.remove(file.file_path)
            except Exception as e:
                print(f"Не удалось удалить файл на диске: {e}")

        # Удаляем запись о файле
        file_info = f"{file.original_filename} (владелец: {file.owner.username})"
        db.session.delete(file)
        db.session.commit()

        log_action('admin_file_deleted', 'file', file_id, f'Admin deleted: {file_info}')
        flash(f'Файл "{file.original_filename}" удален', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Ошибка при удалении файла: {e}")
        flash('Ошибка при удалении файла', 'error')

    return redirect(url_for('admin_panel'))

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Полное удаление файла: права, запись в БД и физический файл"""
    file = File.query.get_or_404(file_id)

    # Только владелец или администратор может удалять файл
    if file.owner_id != current_user.id and not current_user.role.has_permission('admin_access'):
        flash('У вас нет прав для удаления этого файла', 'error')
        return redirect(url_for('dashboard'))

    try:
        # Удаляем записи о доступах к файлу
        FileAccess.query.filter_by(file_id=file.id).delete()
        db.session.flush()

        # Удаляем физический файл
        if os.path.exists(file.file_path):
            try:
                os.remove(file.file_path)
            except Exception as e:
                print(f"Не удалось удалить файл на диске: {e}")

        # Удаляем запись о файле
        db.session.delete(file)
        db.session.commit()

        log_action('file_deleted', 'file', file_id, f'Deleted: {file.original_filename}')
        flash('Файл удален', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Ошибка при удалении файла: {e}")
        flash('Ошибка при удалении файла', 'error')

    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    log_action('logout')
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
@role_required('admin_access')
def admin_panel():
    users = User.query.all()
    files = File.query.all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    # Подсчет статистики хранилища
    total_size = sum(file.file_size for file in files)  # Общий размер в байтах
    total_size_mb = total_size / (1024 * 1024)  # Конвертация в МБ
    total_size_gb = total_size / (1024 * 1024 * 1024)  # Конвертация в ГБ
    
    # Получение размера папки uploads
    uploads_path = app.config['UPLOAD_FOLDER']
    disk_usage = 0
    if os.path.exists(uploads_path):
        for dirpath, dirnames, filenames in os.walk(uploads_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    disk_usage += os.path.getsize(filepath)
    
    disk_usage_mb = disk_usage / (1024 * 1024)
    disk_usage_gb = disk_usage / (1024 * 1024 * 1024)
    
    # Получение информации о дисковом пространстве
    import shutil
    try:
        disk_stats = shutil.disk_usage(uploads_path)
        total_disk_space = disk_stats.total / (1024 * 1024 * 1024)  # В ГБ
        free_disk_space = disk_stats.free / (1024 * 1024 * 1024)  # В ГБ
        used_disk_space = disk_stats.used / (1024 * 1024 * 1024)  # В ГБ
        disk_usage_percent = (disk_stats.used / disk_stats.total) * 100
    except:
        total_disk_space = 0
        free_disk_space = 0
        used_disk_space = 0
        disk_usage_percent = 0
    
    # Статистика по типам файлов
    file_types = {}
    for file in files:
        mime_type = file.mime_type.split('/')[0] if file.mime_type else 'unknown'
        if mime_type not in file_types:
            file_types[mime_type] = {'count': 0, 'size': 0}
        file_types[mime_type]['count'] += 1
        file_types[mime_type]['size'] += file.file_size
    
    storage_stats = {
        'total_files': len(files),
        'total_size': total_size,
        'total_size_mb': round(total_size_mb, 2),
        'total_size_gb': round(total_size_gb, 3),
        'disk_usage': disk_usage,
        'disk_usage_mb': round(disk_usage_mb, 2),
        'disk_usage_gb': round(disk_usage_gb, 3),
        'total_disk_space': round(total_disk_space, 2),
        'free_disk_space': round(free_disk_space, 2),
        'used_disk_space': round(used_disk_space, 2),
        'disk_usage_percent': round(disk_usage_percent, 2),
        'file_types': file_types
    }
    
    return render_template('admin.html', users=users, files=files, 
                         audit_logs=audit_logs, storage_stats=storage_stats)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin_access')
def edit_user(user_id):
    """Редактирование профиля пользователя администратором"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Обновляем данные пользователя
        user.username = request.form['username']
        user.email = request.form['email']
        user.department = request.form.get('department', '')
        user.is_active = 'is_active' in request.form
        
        # Обновляем роль
        new_role_id = request.form.get('role_id')
        if new_role_id:
            user.role_id = int(new_role_id)
        
        # Обновляем пароль если указан
        new_password = request.form.get('password')
        if new_password:
            user.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        
        log_action('user_edited', 'user', user_id, f'Edited user: {user.username}')
        flash(f'Профиль пользователя {user.username} обновлен', 'success')
        return redirect(url_for('admin_panel'))
    
    # Получаем все роли для выбора
    roles = Role.query.all()
    return render_template('edit_user.html', user=user, roles=roles)

# Обработчик ошибок для больших файлов
@app.errorhandler(413)
def too_large(e):
    flash('Файл слишком большой. Максимальный размер: 100MB', 'error')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Создаем роли по умолчанию
        if not Role.query.first():
            roles = [
                Role(name='admin', description='Администратор системы', 
                     permissions='["admin_access", "upload_files", "download_files", "share_files", "manage_users"]'),
                Role(name='manager', description='Менеджер', 
                     permissions='["upload_files", "download_files", "share_files"]'),
                Role(name='user', description='Обычный пользователь', 
                     permissions='["upload_files", "download_files"]')
            ]
            for role in roles:
                db.session.add(role)
            db.session.commit()
            
            # Создаем администратора по умолчанию
            admin_role = Role.query.filter_by(name='admin').first()
            admin = User(
                username='admin',
                email='admin@company.com',
                password_hash=generate_password_hash('admin123'),
                role_id=admin_role.id
            )
            db.session.add(admin)
            db.session.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
