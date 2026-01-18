"""
Безопасная корпоративная система обмена файлами с MFA и ролевой моделью доступа
Упрощенная версия без отделов
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort, session as flask_session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import pyotp
import qrcode
import io
import base64
import json
import hashlib
from datetime import datetime, timedelta, timezone
import secrets
from cryptography.fernet import Fernet
import bcrypt
from functools import wraps
import requests
import logging
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger
import uuid
from config import Config

PERMISSIONS_CATALOG = [
    "admin_access",
    "manage_users",
    "manage_roles",
    "manage_departments",
    "manage_exchange_policies",
    "manage_force_mfa",
    "manage_department_users",
    "view_audit",
    "view_security_events",
    "upload_files",
    "download_files",
    "share_files",
]

PERMISSIONS_LABELS = {
    "admin_access": "Доступ к админ-панели",
    "manage_users": "Управление пользователями",
    "manage_roles": "Управление ролями и правами",
    "manage_departments": "Управление отделами",
    "manage_exchange_policies": "Политики обмена файлами",
    "manage_force_mfa": "Управление политикой MFA",
    "manage_department_users": "Управление пользователями отдела",
    "view_audit": "Просмотр журнала аудита",
    "view_security_events": "Просмотр событий безопасности",
    "upload_files": "Загрузка файлов",
    "download_files": "Скачивание файлов",
    "share_files": "Предоставление доступа к файлам",
}
app = Flask(__name__)
app.config.from_object(Config)
app.config['MAX_CONTENT_LENGTH'] = app.config.get('MAX_CONTENT_LENGTH', 300 * 1024 * 1024)


@app.template_filter('fromjson')
def fromjson_filter(value):
    """Преобразует JSON-строку в Python-объект внутри шаблонов."""
    if not value:
        return []
    try:
        return json.loads(value)
    except Exception:
        return []

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Функция для получения московского времени (UTC+3)
def moscow_now():
    """Возвращает текущее время в московском часовом поясе (UTC+3)"""
    return datetime.now(timezone(timedelta(hours=3)))
login_manager.login_view = 'login'

# Настройка файлового логирования с ротацией
def setup_logging():
    """Настройка структурированного логирования в файлы с ротацией"""
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    # Форматтер для JSON логов
    json_formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Основной лог файл (INFO и выше)
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(json_formatter)
    
    # Лог ошибок (ERROR и выше)
    error_handler = RotatingFileHandler(
        os.path.join(log_dir, 'error.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(json_formatter)
    
    # Лог безопасности (WARNING и выше)
    security_handler = RotatingFileHandler(
        os.path.join(log_dir, 'security.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=20
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(json_formatter)
    
    # Настройка root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)
    
    # Создаем отдельный logger для безопасности
    security_logger = logging.getLogger('security')
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    
    return security_logger

security_logger = setup_logging()

# Middleware для управления сессиями
@app.before_request
def update_session():
    """Обновляет активность сессии и проверяет валидность"""
    # Пропускаем статические файлы и страницы логина/регистрации
    if request.endpoint in ('static', 'login', 'register', 'index', 'about', 'help'):
        return None
    
    if current_user.is_authenticated:
        session_id = flask_session.get('session_id')
        if session_id:
            # Проверка валидности сессии
            try:
                user_session = UserSession.query.filter_by(
                    session_id=session_id,
                    user_id=current_user.id,
                    is_active=True
                ).first()
                
                if user_session:
                    # IP-based session validation (предупреждение, но не блокировка)
                    if user_session.ip_address != request.remote_addr:
                        security_logger.warning('IP address changed for session', extra={
                            'session_id': session_id,
                            'user_id': current_user.id,
                            'old_ip': user_session.ip_address,
                            'new_ip': request.remote_addr
                        })
                        # Можно добавить логику блокировки при смене IP
                    
                    # Обновление активности
                    update_session_activity(session_id)
                else:
                    # Сессия не найдена или неактивна - выход
                    security_logger.warning('Invalid session detected', extra={
                        'session_id': session_id,
                        'user_id': current_user.id,
                        'ip_address': request.remote_addr
                    })
                    logout_user()
                    flask_session.clear()
                    from flask import redirect, url_for
                    return redirect(url_for('login'))
            except Exception as e:
                logging.error(f"Ошибка проверки сессии: {e}", exc_info=True)
                # В случае ошибки не блокируем пользователя

# Загружаем мастер-ключ шифрования из конфигурации.
# Ключ должен быть установлен через переменную окружения ENCRYPTION_KEY (base64 urlsafe 32 байта)
ENCRYPTION_MASTER_KEY = app.config.get('ENCRYPTION_KEY')
if not ENCRYPTION_MASTER_KEY:
    raise RuntimeError("ENCRYPTION_KEY must be set in environment for persistent access to files")
cipher_suite = Fernet(ENCRYPTION_MASTER_KEY)


def column_exists(table_name, column_name):
    # SQLite PRAGMA не принимает плейсхолдеры, используем форматирование.
    result = db.session.execute(db.text(f"PRAGMA table_info({table_name})"))
    return any(row[1] == column_name for row in result)


def migrate_db():
    """Простейшая миграция для существующей SQLite БД"""
    with app.app_context():
        # Создаем новые таблицы если их нет
        db.create_all()

        # user table columns
        if not column_exists('user', 'department_id'):
            db.session.execute(db.text("ALTER TABLE user ADD COLUMN department_id INTEGER"))
        if not column_exists('user', 'managed_department_id'):
            db.session.execute(db.text("ALTER TABLE user ADD COLUMN managed_department_id INTEGER"))
        if not column_exists('user', 'status'):
            db.session.execute(db.text("ALTER TABLE user ADD COLUMN status VARCHAR(20) DEFAULT 'pending'"))
        if not column_exists('user', 'status_reason'):
            db.session.execute(db.text("ALTER TABLE user ADD COLUMN status_reason TEXT"))
        if not column_exists('user', 'is_enabled'):
            db.session.execute(db.text("ALTER TABLE user ADD COLUMN is_enabled BOOLEAN DEFAULT 1"))
        if not column_exists('user', 'force_mfa_override'):
            db.session.execute(db.text("ALTER TABLE user ADD COLUMN force_mfa_override BOOLEAN"))

        # file table columns
        if not column_exists('file', 'department_id'):
            db.session.execute(db.text("ALTER TABLE file ADD COLUMN department_id INTEGER"))
        if not column_exists('file', 'vt_status'):
            db.session.execute(db.text("ALTER TABLE file ADD COLUMN vt_status VARCHAR(20) DEFAULT 'unscanned'"))
        if not column_exists('file', 'vt_checked_at'):
            db.session.execute(db.text("ALTER TABLE file ADD COLUMN vt_checked_at DATETIME"))
        if not column_exists('file', 'vt_detection_count'):
            db.session.execute(db.text("ALTER TABLE file ADD COLUMN vt_detection_count INTEGER DEFAULT 0"))
        if not column_exists('file', 'vt_permalink'):
            db.session.execute(db.text("ALTER TABLE file ADD COLUMN vt_permalink VARCHAR(500)"))
        if not column_exists('file', 'encryption_key_id'):
            db.session.execute(db.text("ALTER TABLE file ADD COLUMN encryption_key_id INTEGER"))

        # login_attempt table columns
        try:
            if not column_exists('login_attempt', 'user_id'):
                db.session.execute(db.text("ALTER TABLE login_attempt ADD COLUMN user_id INTEGER"))
                db.session.commit()
        except Exception as e:
            # Если таблица не существует или ошибка, она будет создана через db.create_all()
            logging.warning(f"Не удалось добавить столбец user_id в login_attempt: {e}")
            db.session.rollback()

        # security_event table columns
        try:
            if not column_exists('security_event', 'severity'):
                db.session.execute(db.text("ALTER TABLE security_event ADD COLUMN severity VARCHAR(20) DEFAULT 'medium'"))
            if not column_exists('security_event', 'ip_address'):
                db.session.execute(db.text("ALTER TABLE security_event ADD COLUMN ip_address VARCHAR(45)"))
            if not column_exists('security_event', 'user_agent'):
                db.session.execute(db.text("ALTER TABLE security_event ADD COLUMN user_agent VARCHAR(500)"))
            if not column_exists('security_event', 'status'):
                db.session.execute(db.text("ALTER TABLE security_event ADD COLUMN status VARCHAR(20) DEFAULT 'new'"))
            if not column_exists('security_event', 'acknowledged_by'):
                db.session.execute(db.text("ALTER TABLE security_event ADD COLUMN acknowledged_by INTEGER"))
            if not column_exists('security_event', 'acknowledged_at'):
                db.session.execute(db.text("ALTER TABLE security_event ADD COLUMN acknowledged_at DATETIME"))
            if not column_exists('security_event', 'resolved_at'):
                db.session.execute(db.text("ALTER TABLE security_event ADD COLUMN resolved_at DATETIME"))
            db.session.commit()
        except Exception as e:
            logging.warning(f"Не удалось добавить столбцы в security_event: {e}")
            db.session.rollback()

        db.session.commit()

        # Проставляем значения по умолчанию для существующих записей
        db.session.execute(db.text("UPDATE user SET status='active' WHERE status IS NULL"))
        db.session.execute(db.text("UPDATE user SET is_enabled=1 WHERE is_enabled IS NULL"))
        db.session.execute(db.text("UPDATE file SET vt_status='unscanned' WHERE vt_status IS NULL"))
        # Гарантируем, что встроенный администратор активен
        db.session.execute(db.text("UPDATE user SET status='active' WHERE username='admin'"))
        db.session.commit()

# Модели базы данных
class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text)
    parent_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=moscow_now)
    parent = db.relationship('Department', remote_side=[id], backref='children')

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    force_mfa = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=moscow_now)
    updated_at = db.Column(db.DateTime, default=moscow_now, onupdate=moscow_now)

class VirusTotalCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sha256 = db.Column(db.String(64), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending')  # clean, malicious, pending, unknown
    detections = db.Column(db.Integer, default=0)
    permalink = db.Column(db.String(500))
    scanned_at = db.Column(db.DateTime)

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    sha256 = db.Column(db.String(64))
    filename = db.Column(db.String(255))
    event_type = db.Column(db.String(50))
    details = db.Column(db.Text)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    status = db.Column(db.String(20), default='new')  # new, acknowledged, resolved
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=moscow_now)
    
    user = db.relationship('User', foreign_keys=[user_id])
    acknowledged_by_user = db.relationship('User', foreign_keys=[acknowledged_by])

class ConfigChangeLog(db.Model):
    """Логирование изменений конфигурации системы"""
    id = db.Column(db.Integer, primary_key=True)
    changed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    change_type = db.Column(db.String(50), nullable=False)  # role, permission, department, settings, user
    resource_type = db.Column(db.String(50))  # role, user, department, settings
    resource_id = db.Column(db.Integer)
    resource_name = db.Column(db.String(255))
    field_name = db.Column(db.String(100))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=moscow_now)
    details = db.Column(db.Text)
    
    changed_by_user = db.relationship('User', foreign_keys=[changed_by])

class SecurityAlert(db.Model):
    """Настройки автоматических алертов"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    condition = db.Column(db.String(100))  # count_per_hour, count_per_day, etc.
    threshold = db.Column(db.Integer, default=5)
    enabled = db.Column(db.Boolean, default=True)
    notify_admins = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=moscow_now)
    last_triggered = db.Column(db.DateTime, nullable=True)

class SecurityIncident(db.Model):
    """Группировка связанных событий безопасности в инциденты"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), default='medium')
    status = db.Column(db.String(20), default='open')  # open, investigating, resolved, closed
    related_events = db.Column(db.Text)  # JSON массив ID событий
    ip_address = db.Column(db.String(45))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=moscow_now)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolution_notes = db.Column(db.Text)
    
    user = db.relationship('User', foreign_keys=[user_id])
    assigned_user = db.relationship('User', foreign_keys=[assigned_to])

class EncryptionKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scope = db.Column(db.String(20), default='file')
    ref_id = db.Column(db.Integer, nullable=False)
    encrypted_key = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=moscow_now)
    rotated_at = db.Column(db.DateTime)

class ExchangePolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    target_department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    action = db.Column(db.String(20), nullable=False)  # send/view
    allow = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=moscow_now)
    
    source_department = db.relationship('Department', foreign_keys=[source_department_id])
    target_department = db.relationship('Department', foreign_keys=[target_department_id])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    managed_department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, active, rejected, blocked
    status_reason = db.Column(db.Text)
    is_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=moscow_now)
    last_login = db.Column(db.DateTime)
    force_mfa_override = db.Column(db.Boolean, nullable=True)  # None - inherit
    
    role = db.relationship('Role', backref='users')
    department = db.relationship('Department', foreign_keys=[department_id])
    managed_department = db.relationship('Department', foreign_keys=[managed_department_id])
    files = db.relationship('File', backref='owner', lazy=True)

    @property
    def is_active(self):
        return self.status == 'active' and self.is_enabled

    def in_department(self, department_id):
        return self.department_id == department_id

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
    created_at = db.Column(db.DateTime, default=moscow_now)
    access_level = db.Column(db.String(20), default='private')  # private, department, public
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    vt_status = db.Column(db.String(20), default='unscanned')  # unscanned, pending, clean, malicious, failed, skipped
    vt_checked_at = db.Column(db.DateTime)
    vt_detection_count = db.Column(db.Integer, default=0)
    vt_permalink = db.Column(db.String(500))
    encryption_key_id = db.Column(db.Integer, db.ForeignKey('encryption_key.id'))
    
    # Связи для контроля доступа
    shared_with = db.relationship('FileAccess', backref='file', lazy=True)
    department = db.relationship('Department', foreign_keys=[department_id])
    encryption_key = db.relationship('EncryptionKey', foreign_keys=[encryption_key_id])

class FileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    permission = db.Column(db.String(20), default='read')  # read, write, admin
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=moscow_now)
    expires_at = db.Column(db.DateTime)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=moscow_now)
    details = db.Column(db.Text)
    
    user = db.relationship('User', foreign_keys=[user_id])

class LoginAttempt(db.Model):
    """Модель для отслеживания попыток входа"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=moscow_now)
    user_agent = db.Column(db.String(500))
    failure_reason = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    user = db.relationship('User', foreign_keys=[user_id])

class UserSession(db.Model):
    """Модель для отслеживания активных сессий пользователей"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=moscow_now)
    last_activity = db.Column(db.DateTime, default=moscow_now)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', foreign_keys=[user_id])

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
    try:
        # Проверяем, что пользователь аутентифицирован
        if not current_user.is_authenticated:
            return  # Не логируем действия неаутентифицированных пользователей
        
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

        # Файловое логирование
        logging.info('Action logged', extra={
            'action': action,
            'user_id': current_user.id,
            'username': current_user.username,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'ip_address': request.remote_addr,
            'details': details
        })
    except Exception as e:
        # Если ошибка при логировании, не падаем, просто выводим в консоль
        print(f"Ошибка логирования действия: {e}")
        logging.error(f"Ошибка логирования действия: {e}", exc_info=True)
        db.session.rollback()

# Функции для защиты от брутфорса
def check_login_attempts(ip_address, username=None):
    """Проверяет количество неудачных попыток входа за последние LOCKOUT_DURATION секунд"""
    try:
        lockout_time = moscow_now() - timedelta(seconds=app.config['LOCKOUT_DURATION'])
        
        # Используем raw SQL для избежания проблем с отсутствующими столбцами
        try:
            # Подсчет неудачных попыток по IP через raw SQL
            result = db.session.execute(
                db.text("""
                    SELECT COUNT(*) FROM login_attempt 
                    WHERE ip_address = :ip AND success = 0 AND timestamp > :lockout_time
                """),
                {'ip': ip_address, 'lockout_time': lockout_time}
            )
            ip_attempts = result.scalar() or 0
        except Exception as e:
            logging.warning(f"Ошибка подсчета попыток по IP: {e}")
            ip_attempts = 0
        
        # Подсчет неудачных попыток по username (если указан)
        user_attempts = 0
        if username:
            user = User.query.filter_by(username=username).first()
            if user:
                try:
                    # Проверяем наличие столбца user_id через raw SQL
                    result = db.session.execute(
                        db.text("""
                            SELECT COUNT(*) FROM login_attempt 
                            WHERE user_id = :user_id AND success = 0 AND timestamp > :lockout_time
                        """),
                        {'user_id': user.id, 'lockout_time': lockout_time}
                    )
                    user_attempts = result.scalar() or 0
                except Exception:
                    # Если столбца нет, используем только IP проверку
                    user_attempts = 0
        
        max_attempts = app.config['MAX_LOGIN_ATTEMPTS']
        return ip_attempts >= max_attempts or user_attempts >= max_attempts
    except Exception as e:
        # В случае ошибки возвращаем False, чтобы не блокировать вход
        logging.error(f"Ошибка проверки попыток входа: {e}", exc_info=True)
        return False

def record_login_attempt(username, ip_address, success, failure_reason=None, user_id=None):
    """Записывает попытку входа в базу данных"""
    try:
        attempt = LoginAttempt(
            username=username,
            ip_address=ip_address,
            success=success,
            user_agent=request.headers.get('User-Agent', ''),
            failure_reason=failure_reason,
            user_id=user_id
        )
        db.session.add(attempt)
        db.session.commit()
        
        # Логирование в файл
        if success:
            logging.info('Login successful', extra={
                'username': username,
                'ip_address': ip_address,
                'user_id': user_id
            })
        else:
            security_logger.warning('Login failed', extra={
                'username': username,
                'ip_address': ip_address,
                'failure_reason': failure_reason,
                'user_id': user_id
            })
    except Exception as e:
        logging.error(f"Ошибка записи попытки входа: {e}", exc_info=True)
        db.session.rollback()

def notify_admin_suspicious_activity(username, ip_address, reason):
    """Уведомляет администратора о подозрительной активности"""
    try:
        # Создаем событие безопасности для отображения в админ-панели
        event = log_security_event(
            user_id=None,
            sha256=None,
            filename=None,
            event_type='suspicious_login',
            details=f"Подозрительная активность: {reason}. Username: {username}, IP: {ip_address}",
            severity='high',
            ip_address=ip_address,
            user_agent=request.headers.get('User-Agent') if hasattr(request, 'headers') else None
        )
        
        # Уведомляем всех админов
        if event:
            admins = User.query.join(Role).filter(Role.permissions.contains('"admin_access"')).all()
            for admin in admins:
                admin_event = SecurityEvent(
                    user_id=admin.id,
                    event_type='admin_notification',
                    details=f"Подозрительная активность: {reason}. Username: {username}, IP: {ip_address}",
                    severity='high',
                    ip_address=ip_address,
                    status='new'
                )
                db.session.add(admin_event)
            db.session.commit()
        
        # Логирование в файл
        security_logger.warning('Suspicious activity detected', extra={
            'username': username,
            'ip_address': ip_address,
            'reason': reason
        })
    except Exception as e:
        logging.error(f"Ошибка уведомления администратора: {e}", exc_info=True)
        db.session.rollback()

def create_user_session(user, ip_address):
    """Создает новую сессию пользователя"""
    try:
        session_id = str(uuid.uuid4())
        flask_session['session_id'] = session_id
        
        user_session = UserSession(
            user_id=user.id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=request.headers.get('User-Agent', ''),
            last_activity=moscow_now()
        )
        db.session.add(user_session)
        db.session.commit()
        
        logging.info('User session created', extra={
            'user_id': user.id,
            'username': user.username,
            'session_id': session_id,
            'ip_address': ip_address
        })
        
        return session_id
    except Exception as e:
        logging.error(f"Ошибка создания сессии: {e}", exc_info=True)
        db.session.rollback()
        return None

def update_session_activity(session_id):
    """Обновляет время последней активности сессии"""
    try:
        if session_id:
            user_session = UserSession.query.filter_by(session_id=session_id, is_active=True).first()
            if user_session:
                user_session.last_activity = moscow_now()
                db.session.commit()
    except Exception as e:
        logging.error(f"Ошибка обновления активности сессии: {e}", exc_info=True)
        db.session.rollback()

def deactivate_session(session_id):
    """Деактивирует сессию"""
    try:
        if session_id:
            user_session = UserSession.query.filter_by(session_id=session_id).first()
            if user_session:
                user_session.is_active = False
                db.session.commit()
                logging.info('Session deactivated', extra={
                    'session_id': session_id,
                    'user_id': user_session.user_id
                })
    except Exception as e:
        logging.error(f"Ошибка деактивации сессии: {e}", exc_info=True)
        db.session.rollback()

# Работа с ключами и шифрованием
def generate_data_key():
    """Создает одноразовый ключ для файла"""
    return Fernet.generate_key()

def wrap_data_key(data_key: bytes) -> bytes:
    """Шифруем ключ файла мастер-ключом"""
    return cipher_suite.encrypt(data_key)

def unwrap_data_key(encrypted_key: bytes) -> bytes:
    return cipher_suite.decrypt(encrypted_key)

def encrypt_file_with_key(file_path, data_key):
    cipher = Fernet(data_key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(file_data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file_with_key(file_path, data_key):
    cipher = Fernet(data_key)
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        
        if not encrypted_data:
            raise ValueError("Файл пуст")
            
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data
    except Exception as e:
        print(f"Ошибка расшифровки файла {file_path}: {str(e)}")
        raise

def store_file_key(file_id, data_key):
    encrypted_key = wrap_data_key(data_key)
    key_record = EncryptionKey(scope='file', ref_id=file_id, encrypted_key=encrypted_key)
    db.session.add(key_record)
    db.session.flush()
    return key_record

def get_file_data_key(file_obj: File):
    if not file_obj.encryption_key:
        raise ValueError("Ключ шифрования для файла не найден")
    return unwrap_data_key(file_obj.encryption_key.encrypted_key)

def get_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(force_mfa=False)
        db.session.add(settings)
        db.session.commit()
    return settings

def get_or_create_department(name):
    if not name:
        return None
    dept = Department.query.filter_by(name=name).first()
    if not dept:
        dept = Department(name=name)
        db.session.add(dept)
        db.session.commit()
    return dept

def is_view_allowed(file_obj: File, user: User):
    # Если не указаны отделы, разрешаем
    if not file_obj.department_id or not user.department_id:
        return True
    if file_obj.department_id == user.department_id:
        return True
    rule = ExchangePolicy.query.filter_by(
        source_department_id=file_obj.department_id,
        target_department_id=user.department_id,
        action='view'
    ).first()
    # По умолчанию запрещаем при отсутствии явного правила
    return rule.allow if rule else False

def is_send_allowed(source_department_id, target_department_id):
    if not source_department_id or not target_department_id:
        return True
    if source_department_id == target_department_id:
        return True
    rule = ExchangePolicy.query.filter_by(
        source_department_id=source_department_id,
        target_department_id=target_department_id,
        action='send'
    ).first()
    return rule.allow if rule else False


def is_department_head(user: User) -> bool:
    """Проверяет, является ли пользователь руководителем отдела."""
    return bool(user.managed_department_id)

# Работа с VirusTotal
VT_API_KEY = os.environ.get('VT_API_KEY')
VT_TIMEOUT = 25

def log_security_event(user_id, sha256, filename, event_type, details, severity='medium', ip_address=None, user_agent=None):
    """Логирует событие безопасности с расширенной информацией"""
    try:
        event = SecurityEvent(
            user_id=user_id,
            sha256=sha256,
            filename=filename,
            event_type=event_type,
            details=details,
            severity=severity,
            ip_address=ip_address or request.remote_addr if hasattr(request, 'remote_addr') else None,
            user_agent=user_agent or request.headers.get('User-Agent') if hasattr(request, 'headers') else None,
            status='new'
        )
        db.session.add(event)
        db.session.commit()
        
        # Логирование в файл
        security_logger.warning('Security event logged', extra={
            'event_type': event_type,
            'severity': severity,
            'user_id': user_id,
            'ip_address': event.ip_address,
            'details': details
        })
        
        # Проверка алертов
        check_security_alerts(event)
        
        return event
    except Exception as e:
        logging.error(f"Ошибка логирования события безопасности: {e}", exc_info=True)
        db.session.rollback()
        return None

def log_config_change(change_type, resource_type, resource_id, resource_name, field_name, old_value, new_value, details=None):
    """Логирует изменение конфигурации системы"""
    try:
        if not current_user.is_authenticated:
            return
        
        change_log = ConfigChangeLog(
            changed_by=current_user.id,
            change_type=change_type,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            field_name=field_name,
            old_value=str(old_value) if old_value is not None else None,
            new_value=str(new_value) if new_value is not None else None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            details=details
        )
        db.session.add(change_log)
        db.session.commit()
        
        logging.info('Config change logged', extra={
            'change_type': change_type,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'field_name': field_name,
            'changed_by': current_user.id
        })
    except Exception as e:
        logging.error(f"Ошибка логирования изменения конфигурации: {e}", exc_info=True)
        db.session.rollback()

def check_security_alerts(event):
    """Проверяет события безопасности на соответствие правилам алертов"""
    try:
        alerts = SecurityAlert.query.filter_by(enabled=True).all()
        
        for alert in alerts:
            # Проверка типа события
            if alert.event_type and alert.event_type != event.event_type:
                continue
            
            # Проверка severity
            if alert.severity and alert.severity != event.severity:
                continue
            
            # Подсчет событий за период
            if alert.condition == 'count_per_hour':
                time_threshold = moscow_now() - timedelta(hours=1)
            elif alert.condition == 'count_per_day':
                time_threshold = moscow_now() - timedelta(days=1)
            else:
                time_threshold = moscow_now() - timedelta(hours=1)
            
            # Подсчет событий
            count = SecurityEvent.query.filter(
                SecurityEvent.event_type == event.event_type,
                SecurityEvent.severity == event.severity,
                SecurityEvent.created_at > time_threshold
            ).count()
            
            if count >= alert.threshold:
                # Триггерим алерт
                trigger_security_alert(alert, event, count)
                alert.last_triggered = moscow_now()
                db.session.commit()
    except Exception as e:
        logging.error(f"Ошибка проверки алертов: {e}", exc_info=True)

def trigger_security_alert(alert, event, count):
    """Триггерит алерт безопасности"""
    try:
        if alert.notify_admins:
            admins = User.query.join(Role).filter(Role.permissions.contains('"admin_access"')).all()
            
            for admin in admins:
                notification = SecurityEvent(
                    user_id=admin.id,
                    event_type='security_alert',
                    details=f"Алерт '{alert.name}' сработал: {count} событий типа '{event.event_type}' с severity '{event.severity}' за период",
                    severity='high',
                    ip_address=event.ip_address,
                    user_agent=event.user_agent,
                    status='new'
                )
                db.session.add(notification)
            
            db.session.commit()
            
            security_logger.warning('Security alert triggered', extra={
                'alert_name': alert.name,
                'event_type': event.event_type,
                'severity': event.severity,
                'count': count,
                'threshold': alert.threshold
            })
    except Exception as e:
        logging.error(f"Ошибка триггера алерта: {e}", exc_info=True)
        db.session.rollback()

def correlate_security_events():
    """Коррелирует события безопасности и создает инциденты"""
    try:
        # Находим группы связанных событий за последний час
        time_threshold = moscow_now() - timedelta(hours=1)
        
        # Группируем по IP и типу события
        events = SecurityEvent.query.filter(
            SecurityEvent.created_at > time_threshold,
            SecurityEvent.severity.in_(['high', 'critical']),
            SecurityEvent.status == 'new'
        ).all()
        
        # Группировка по IP
        ip_groups = {}
        for event in events:
            if event.ip_address:
                if event.ip_address not in ip_groups:
                    ip_groups[event.ip_address] = []
                ip_groups[event.ip_address].append(event)
        
        # Создаем инциденты для групп с 3+ событиями
        for ip, event_list in ip_groups.items():
            if len(event_list) >= 3:
                # Проверяем, нет ли уже открытого инцидента для этого IP
                existing_incident = SecurityIncident.query.filter_by(
                    ip_address=ip,
                    status='open'
                ).first()
                
                if not existing_incident:
                    # Определяем максимальную severity
                    max_severity = max([e.severity for e in event_list], 
                                     key=lambda x: ['low', 'medium', 'high', 'critical'].index(x))
                    
                    event_types = [e.event_type for e in event_list]
                    incident = SecurityIncident(
                        title=f"Подозрительная активность с IP {ip}",
                        description=f"Обнаружено {len(event_list)} событий безопасности за последний час",
                        severity=max_severity,
                        status='open',
                        related_events=json.dumps([e.id for e in event_list]),
                        ip_address=ip,
                        user_id=event_list[0].user_id
                    )
                    db.session.add(incident)
                    db.session.commit()
                    
                    security_logger.warning('Security incident created', extra={
                        'incident_id': incident.id,
                        'ip_address': ip,
                        'event_count': len(event_list),
                        'severity': max_severity
                    })
    except Exception as e:
        logging.error(f"Ошибка корреляции событий: {e}", exc_info=True)
        db.session.rollback()

def compute_sha256(file_path):
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()

def cache_vt_result(sha256, status, detections=0, permalink=None):
    cache = VirusTotalCache.query.filter_by(sha256=sha256).first()
    if not cache:
        cache = VirusTotalCache(sha256=sha256)
    cache.status = status
    cache.detections = detections or 0
    cache.permalink = permalink
    cache.scanned_at = moscow_now()
    db.session.add(cache)
    db.session.commit()
    return cache

def check_virustotal(file_path, original_filename, user_id):
    sha256 = compute_sha256(file_path)
    cache = VirusTotalCache.query.filter_by(sha256=sha256).first()
    if cache and cache.status in ['clean', 'malicious']:
        return cache, sha256

    if not VT_API_KEY:
        cache = cache_vt_result(sha256, 'skipped', 0, None)
        return cache, sha256

    headers = {"x-apikey": VT_API_KEY}
    meta = None
    resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=VT_TIMEOUT)
    if resp.status_code == 200:
        data = resp.json().get('data', {})
        attributes = data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        detections = stats.get('malicious', 0) + stats.get('suspicious', 0)
        status = 'malicious' if detections > 0 else 'clean'
        cache = cache_vt_result(sha256, status, detections, data.get('links', {}).get('self') or attributes.get('permalink'))
        return cache, sha256
    elif resp.status_code == 404:
        with open(file_path, "rb") as f:
            upload_resp = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files={"file": (original_filename, f)},
                timeout=VT_TIMEOUT
            )
        if upload_resp.status_code in [200, 202]:
            cache = cache_vt_result(sha256, 'pending', 0, None)
            return cache, sha256
        cache = cache_vt_result(sha256, 'failed', 0, None)
        return cache, sha256


def refresh_vt_for_file(file_obj: File):
    """Переопрашивает VirusTotal для конкретного файла, если статус не финальный."""
    if file_obj.vt_status in ['clean', 'malicious']:
        return
    if not VT_API_KEY:
        return
    vt_cache, sha256 = check_virustotal(file_obj.file_path, file_obj.original_filename, file_obj.owner_id)
    file_obj.vt_status = vt_cache.status
    file_obj.vt_checked_at = vt_cache.scanned_at
    file_obj.vt_detection_count = vt_cache.detections
    file_obj.vt_permalink = vt_cache.permalink
    db.session.commit()

# Маршруты
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/about')
def about():
    """Страница 'О нас'"""
    return render_template('about.html')

@app.route('/security')
def security():
    """Страница 'Безопасность'"""
    return render_template('security.html')

@app.route('/security/sessions/<session_id>/terminate', methods=['POST'])
@login_required
def terminate_session(session_id):
    """Завершает указанную сессию (для обычных пользователей)"""
    user_session = UserSession.query.filter_by(
        session_id=session_id,
        user_id=current_user.id
    ).first_or_404()
    
    deactivate_session(session_id)
    flash('Сессия успешно завершена', 'success')
    log_action('session_terminated', 'session', user_session.id, f'Session {session_id} terminated')
    return redirect(url_for('security'))

@app.route('/security/sessions/terminate_all', methods=['POST'])
@login_required
def terminate_all_sessions():
    """Завершает все сессии пользователя кроме текущей (для обычных пользователей)"""
    current_session_id = flask_session.get('session_id')
    
    active_sessions = UserSession.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).all()
    
    terminated_count = 0
    for session in active_sessions:
        if session.session_id != current_session_id:
            deactivate_session(session.session_id)
            terminated_count += 1
    
    flash(f'Завершено сессий: {terminated_count}', 'success')
    log_action('all_sessions_terminated', 'session', None, f'Terminated {terminated_count} sessions')
    return redirect(url_for('security'))

# Админские маршруты для управления сессиями пользователей
@app.route('/admin/users/<int:user_id>/sessions')
@login_required
@role_required('admin_access')
def admin_get_user_sessions(user_id):
    """Получает список сессий пользователя для админа"""
    user = User.query.get_or_404(user_id)
    
    sessions = UserSession.query.filter_by(user_id=user_id).order_by(UserSession.last_activity.desc()).all()
    
    sessions_data = []
    for session in sessions:
        sessions_data.append({
            'session_id': session.session_id,
            'ip_address': session.ip_address,
            'user_agent': session.user_agent,
            'created_at': session.created_at.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'is_active': session.is_active
        })
    
    return jsonify({
        'success': True,
        'sessions': sessions_data,
        'username': user.username
    })

@app.route('/admin/sessions/<session_id>/terminate', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_terminate_session(session_id):
    """Завершает сессию пользователя (для админа)"""
    user_session = UserSession.query.filter_by(session_id=session_id).first_or_404()
    user = User.query.get(user_session.user_id)
    
    deactivate_session(session_id)
    log_action('admin_session_terminated', 'session', user_session.id, 
               f'Admin terminated session {session_id} for user {user.username if user else "unknown"}')
    
    return jsonify({
        'success': True,
        'message': 'Сессия успешно завершена'
    })

@app.route('/admin/users/<int:user_id>/sessions/terminate_all', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_terminate_all_user_sessions(user_id):
    """Завершает все сессии пользователя (для админа)"""
    user = User.query.get_or_404(user_id)
    
    active_sessions = UserSession.query.filter_by(
        user_id=user_id,
        is_active=True
    ).all()
    
    terminated_count = 0
    for session in active_sessions:
        deactivate_session(session.session_id)
        terminated_count += 1
    
    log_action('admin_terminate_all_sessions', 'session', None, 
               f'Admin terminated all {terminated_count} sessions for user {user.username}')
    
    return jsonify({
        'success': True,
        'message': f'Завершено сессий: {terminated_count}',
        'terminated_count': terminated_count
    })

@app.route('/help')
def help():
    """Страница помощи и FAQ"""
    return render_template('help.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_address = request.remote_addr
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Проверка блокировки по IP или username
        if check_login_attempts(ip_address, username):
            record_login_attempt(username, ip_address, False, 'Account locked due to too many failed attempts')
            notify_admin_suspicious_activity(username, ip_address, f'Account locked after {app.config["MAX_LOGIN_ATTEMPTS"]} failed attempts')
            flash(f'Слишком много неудачных попыток входа. Попробуйте через {app.config["LOCKOUT_DURATION"] // 60} минут.', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        # Проверка пароля (унифицированное сообщение для защиты от timing attacks)
        password_valid = False
        if user:
            password_valid = check_password_hash(user.password_hash, password)
        
        if not user or not password_valid:
            record_login_attempt(username, ip_address, False, 'Invalid credentials', user.id if user else None)
            
            # Проверка, не превышен ли лимит после этой попытки
            if check_login_attempts(ip_address, username):
                notify_admin_suspicious_activity(username, ip_address, f'Multiple failed login attempts from IP {ip_address}')
            
            flash('Неверное имя пользователя или пароль', 'error')
            return render_template('login.html')

        if user.status == 'pending':
            record_login_attempt(username, ip_address, False, 'Account pending approval', user.id)
            flash('Учетная запись ожидает одобрения администратора', 'warning')
            return render_template('login.html')
        if user.status == 'rejected':
            record_login_attempt(username, ip_address, False, 'Account rejected', user.id)
            flash('Учетная запись отклонена администратором', 'error')
            return render_template('login.html')
        if not user.is_enabled:
            record_login_attempt(username, ip_address, False, 'Account disabled', user.id)
            flash('Учетная запись заблокирована', 'error')
            return render_template('login.html')

        settings = get_settings()
        if settings.force_mfa and not user.mfa_enabled:
            record_login_attempt(username, ip_address, False, 'MFA required but not configured', user.id)
            flash('Необходимо настроить MFA перед входом', 'warning')
            return redirect(url_for('mfa_verify', user_id=user.id))

        if user.mfa_enabled:
            # Если включен MFA, перенаправляем на страницу ввода кода
            # Попытка будет записана после успешной проверки MFA
            return redirect(url_for('mfa_verify', user_id=user.id))
        else:
            # Успешный вход
            login_user(user)
            user.last_login = moscow_now()
            db.session.commit()
            
            # Создание сессии
            create_user_session(user, ip_address)
            
            # Запись успешной попытки
            record_login_attempt(username, ip_address, True, None, user.id)
            log_action('login')
            
            return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/mfa_verify/<int:user_id>', methods=['GET', 'POST'])
def mfa_verify(user_id):
    user = User.query.get_or_404(user_id)
    ip_address = request.remote_addr
    
    if user.status != 'active' or not user.is_enabled:
        flash('Учетная запись не активна', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form['token']
        totp = pyotp.TOTP(user.mfa_secret)
        
        if totp.verify(token, valid_window=1):
            login_user(user)
            user.last_login = moscow_now()
            db.session.commit()
            
            # Создание сессии
            create_user_session(user, ip_address)
            
            # Запись успешной попытки входа
            record_login_attempt(user.username, ip_address, True, None, user.id)
            log_action('login_with_mfa')
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(user.username, ip_address, False, 'Invalid MFA token', user.id)
            flash('Неверный код MFA', 'error')
    
    return render_template('mfa_verify.html', user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        department_name = request.form.get('department', '').strip()
        
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
            status='pending',
            department_id=get_or_create_department(department_name).id if department_name else None
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация успешна! Учетная запись ожидает одобрения администратора.', 'success')
        return redirect(url_for('login'))
    
    departments = Department.query.order_by(Department.name).all()
    return render_template('register.html', departments=departments)

@app.route('/dashboard')
@login_required
def dashboard():
    # Мои файлы
    user_files = File.query.filter_by(owner_id=current_user.id).order_by(File.created_at.desc()).all()
    
    # Файлы, к которым есть доступ
    shared_files = File.query.join(FileAccess).filter(
        FileAccess.user_id == current_user.id,
        File.owner_id != current_user.id
    ).all()
    
    # Публичные файлы
    public_files = File.query.filter(
        File.access_level == 'public',
        File.owner_id != current_user.id
    ).all()

    # Файлы отдела
    department_files = []
    if current_user.department_id:
        department_files = File.query.filter(
            File.access_level == 'department',
            File.department_id == current_user.department_id,
            File.owner_id != current_user.id
        ).all()
    dept_file_count = len(department_files)

    # Объединяем списки без дублей по id
    shared_map = {}
    for f in shared_files + public_files + department_files:
        shared_map[f.id] = f
    shared_files = list(shared_map.values())
    
    # Доступы, выданные текущим пользователем
    shared_by_me_count = FileAccess.query.filter_by(granted_by=current_user.id).count()

    # Пользователи в отделе
    dept_user_count = 0
    if current_user.department_id:
        dept_user_count = User.query.filter_by(department_id=current_user.department_id).count()

    # Статистика по VirusTotal для файлов пользователя
    vt_stats = {'clean': 0, 'pending': 0, 'malicious': 0, 'other': 0}
    for f in user_files:
        status = f.vt_status or 'unscanned'
        if status == 'clean':
            vt_stats['clean'] += 1
        elif status == 'pending':
            vt_stats['pending'] += 1
        elif status == 'malicious':
            vt_stats['malicious'] += 1
        else:  # unscanned, failed, skipped, None
            vt_stats['other'] += 1

    # Последние действия пользователя
    recent_events = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    departments = Department.query.order_by(Department.name).all()
    return render_template(
        'dashboard.html',
        user_files=user_files,
        shared_files=shared_files,
        departments=departments,
        shared_by_me_count=shared_by_me_count,
        vt_stats=vt_stats,
        recent_events=recent_events,
        dept_file_count=dept_file_count,
        dept_user_count=dept_user_count,
    )

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
        
        # Проверяем VirusTotal
        vt_cache, sha256 = check_virustotal(file_path, filename, current_user.id)
        if vt_cache.status == 'malicious':
            log_security_event(current_user.id, sha256, filename, 'virus_detected', 
                             f"Detections: {vt_cache.detections}",
                             severity='critical',
                             ip_address=request.remote_addr,
                             user_agent=request.headers.get('User-Agent'))
            os.remove(file_path)
            flash('Файл заблокирован: обнаружено вредоносное содержимое (VirusTotal)', 'error')
            return redirect(url_for('dashboard'))
        
        # Сохраняем информацию о файле в базе данных
        access_level = request.form.get('access_level', 'private')
        department_name = request.form.get('department', '')
        department = get_or_create_department(department_name) if access_level == 'department' else None
        
        new_file = File(
            filename=unique_filename,
            original_filename=filename,
            file_path=file_path,
            file_size=os.path.getsize(file_path),
            mime_type=file.content_type,
            owner_id=current_user.id,
            access_level=access_level,
            department_id=department.id if department else None,
            vt_status=vt_cache.status,
            vt_checked_at=vt_cache.scanned_at,
            vt_detection_count=vt_cache.detections,
            vt_permalink=vt_cache.permalink
        )
        
        db.session.add(new_file)
        db.session.flush()

        # Генерируем и сохраняем ключ для файла
        data_key = generate_data_key()
        encrypt_file_with_key(file_path, data_key)
        key_record = store_file_key(new_file.id, data_key)
        new_file.encryption_key_id = key_record.id

        db.session.commit()
        
        log_action('file_upload', 'file', new_file.id, f'Uploaded: {filename}, access={access_level}, vt={vt_cache.status}')
        if vt_cache.status == 'pending':
            flash('Файл загружен и отправлен на проверку VirusTotal. Доступ будет открыт после завершения.', 'info')
        else:
            flash('Файл успешно загружен', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        # Проверяем права доступа
        has_access = False
        
        # Администратор имеет доступ ко всем файлам
        if current_user.role.has_permission('admin_access'):
            has_access = True
        # Владелец файла всегда имеет доступ
        elif file.owner_id == current_user.id:
            has_access = True
        # Проверяем явно предоставленный доступ
        elif FileAccess.query.filter_by(file_id=file_id, user_id=current_user.id).first():
            has_access = True
        # Проверяем публичный доступ (public виден всем пользователям)
        elif file.access_level == 'public':
            has_access = True
        # Проверяем доступ на уровне отдела
        elif (file.access_level == 'department' and 
              file.department_id and 
              current_user.department_id and
              file.department_id == current_user.department_id):
            has_access = True
        
        # Проверка политик просмотра между отделами (для администратора пропускаем)
        if has_access and not current_user.role.has_permission('admin_access') and not is_view_allowed(file, current_user):
            has_access = False
        
        if not has_access:
            flash('У вас нет прав для скачивания этого файла', 'error')
            return redirect(url_for('dashboard'))
        
        # Проверяем, что файл существует
        if not os.path.exists(file.file_path):
            flash('Файл не найден на сервере', 'error')
            return redirect(url_for('dashboard'))

        # Актуализируем статус VirusTotal при необходимости (без падения приложения при ошибке)
        if file.vt_status in ['pending', 'failed', 'skipped', 'unscanned', None]:
            try:
                refresh_vt_for_file(file)
            except Exception as e:
                print(f"Ошибка обновления статуса VirusTotal для файла {file.id}: {e}")

        # Проверка статуса VirusTotal после обновления:
        # - clean  -> скачивание разрешено
        # - pending/failed/skipped/unscanned/None -> временно блокируем скачивание
        # - malicious -> навсегда блокируем скачивание
        if file.vt_status in ['pending', 'failed', 'skipped', 'unscanned', None]:
            flash('Файл еще проходит или не смог пройти проверку VirusTotal. Скачивание временно запрещено.', 'warning')
            return redirect(url_for('dashboard'))
        if file.vt_status == 'malicious':
            log_security_event(current_user.id, None, file.original_filename, 'blocked_download', 
                             'VirusTotal malicious',
                             severity='high',
                             ip_address=request.remote_addr,
                             user_agent=request.headers.get('User-Agent'))
            flash('Доступ к файлу запрещен (VirusTotal)', 'error')
            return redirect(url_for('dashboard'))
        
        # Расшифровываем файл
        data_key = get_file_data_key(file)
        decrypted_data = decrypt_file_with_key(file.file_path, data_key)
        
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
    if user.status != 'active':
        flash('Пользователь не активирован', 'error')
        return redirect(url_for('dashboard'))

    if not is_send_allowed(current_user.department_id, user.department_id):
        flash('Политика обмена запрещает отправку файлов между отделами', 'error')
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
        file_info = f"{file.original_filename} (владелец: {file.owner.username if file.owner else 'Удален'})"
        db.session.delete(file)
        db.session.commit()

        log_action('admin_file_deleted', 'file', file_id, f'Admin deleted: {file_info}')
        flash(f'Файл "{file.original_filename}" удален', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Ошибка при удалении файла: {e}")
        flash('Ошибка при удалении файла', 'error')

    return redirect(url_for('admin_files'))


@app.route('/admin/users/<int:user_id>/approve', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_approve_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.status == 'active':
        flash('Пользователь уже активирован', 'info')
        return redirect(url_for('admin_users'))
    user.status = 'active'
    user.status_reason = None
    user.is_enabled = True
    db.session.commit()
    log_action('user_approved', 'user', user_id, f'Approved user {user.username}')
    flash(f'Пользователь {user.username} одобрен', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/reject', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_reject_user(user_id):
    user = User.query.get_or_404(user_id)
    reason = request.form.get('reason', '').strip()
    user.status = 'rejected'
    user.status_reason = reason or 'Отклонено администратором'
    user.is_enabled = False
    db.session.commit()
    log_action('user_rejected', 'user', user_id, f'Rejected user {user.username}. Reason: {user.status_reason}')
    flash(f'Пользователь {user.username} отклонен', 'warning')
    return redirect(url_for('admin_users'))


@app.route('/admin/departments', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_add_department():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    parent_id = request.form.get('parent_id')
    if not name:
        flash('Название отдела обязательно', 'error')
        return redirect(url_for('admin_panel'))
    parent = Department.query.get(parent_id) if parent_id else None
    dept = Department(name=name, description=description, parent_id=parent.id if parent else None)
    db.session.add(dept)
    db.session.commit()
    log_action('department_created', 'department', dept.id, f'Created department {name}')
    log_config_change('department', 'department', dept.id, name, 'created', None, name, f'Department {name} created')
    flash('Отдел создан', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/departments/<int:dept_id>/update', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_update_department(dept_id):
    dept = Department.query.get_or_404(dept_id)
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    parent_id = request.form.get('parent_id')
    if not name:
        flash('Название отдела обязательно', 'error')
        return redirect(url_for('admin_panel'))
    old_name = dept.name
    old_parent = dept.parent_id
    dept.name = name
    dept.description = description
    dept.parent_id = int(parent_id) if parent_id else None
    db.session.commit()
    log_action('department_updated', 'department', dept.id, f'Updated department {name}')
    if old_name != name:
        log_config_change('department', 'department', dept.id, name, 'name', old_name, name, f'Department renamed from {old_name} to {name}')
    if old_parent != dept.parent_id:
        log_config_change('department', 'department', dept.id, name, 'parent_id', old_parent, dept.parent_id, f'Department parent changed')
    flash('Отдел обновлен', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/departments/<int:dept_id>/delete', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_delete_department(dept_id):
    dept = Department.query.get_or_404(dept_id)
    dept_name = dept.name
    db.session.delete(dept)
    db.session.commit()
    log_action('department_deleted', 'department', dept.id, f'Deleted department {dept_name}')
    log_config_change('department', 'department', dept.id, dept_name, 'deleted', dept_name, None, f'Department {dept_name} deleted')
    flash('Отдел удален', 'success')
    return redirect(url_for('admin_panel'))


def permissions_to_json(perms_list):
    return json.dumps(perms_list or [])


def parse_permissions_from_form(form):
    perms = form.getlist('permissions')
    return permissions_to_json(perms)


@app.route('/admin/roles', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_add_role():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    if not name:
        flash('Название роли обязательно', 'error')
        return redirect(url_for('admin_panel'))
    perms_json = parse_permissions_from_form(request.form)
    role = Role(name=name, description=description, permissions=perms_json)
    db.session.add(role)
    db.session.commit()
    log_action('role_created', 'role', role.id, f'Created role {name}')
    log_config_change('role', 'role', role.id, name, 'permissions', None, perms_json, f'Role {name} created with permissions')
    flash('Роль создана', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/roles/<int:role_id>/update', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_update_role(role_id):
    role = Role.query.get_or_404(role_id)
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    if not name:
        flash('Название роли обязательно', 'error')
        return redirect(url_for('admin_panel'))
    old_permissions = role.permissions
    old_name = role.name
    role.name = name
    role.description = description
    new_permissions = parse_permissions_from_form(request.form)
    role.permissions = new_permissions
    db.session.commit()
    log_action('role_updated', 'role', role.id, f'Updated role {name}')
    log_config_change('role', 'role', role.id, name, 'permissions', old_permissions, new_permissions, f'Role {name} permissions updated')
    if old_name != name:
        log_config_change('role', 'role', role.id, name, 'name', old_name, name, f'Role renamed from {old_name} to {name}')
    flash('Роль обновлена', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/roles/<int:role_id>/delete', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    if role.name == 'admin':
        flash('Нельзя удалить роль администратора', 'error')
        return redirect(url_for('admin_panel'))
    role_name = role.name
    role_permissions = role.permissions
    db.session.delete(role)
    db.session.commit()
    log_action('role_deleted', 'role', role.id, f'Deleted role {role_name}')
    log_config_change('role', 'role', role.id, role_name, 'deleted', role_permissions, None, f'Role {role_name} deleted')
    flash('Роль удалена', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/policies', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_add_policy():
    source_id = request.form.get('source_department_id')
    target_id = request.form.get('target_department_id')
    action = request.form.get('action')
    allow = request.form.get('allow') == 'true'
    if not action:
        flash('Действие обязательно', 'error')
        return redirect(url_for('admin_panel'))
    policy = ExchangePolicy(
        source_department_id=int(source_id) if source_id else None,
        target_department_id=int(target_id) if target_id else None,
        action=action,
        allow=allow,
        created_by=current_user.id
    )
    db.session.add(policy)
    db.session.commit()
    log_action('policy_created', 'exchange_policy', policy.id, f'Policy {action} {source_id}->{target_id} allow={allow}')
    flash('Политика добавлена', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/policies/<int:policy_id>/delete', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_delete_policy(policy_id):
    policy = ExchangePolicy.query.get_or_404(policy_id)
    db.session.delete(policy)
    db.session.commit()
    log_action('policy_deleted', 'exchange_policy', policy.id, 'Policy deleted')
    flash('Политика удалена', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/settings/force_mfa', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_force_mfa():
    settings = get_settings()
    old_force_mfa = settings.force_mfa
    settings.force_mfa = 'force_mfa' in request.form
    db.session.commit()
    log_action('settings_updated', 'settings', settings.id, f'Force MFA: {settings.force_mfa}')
    log_config_change('settings', 'settings', settings.id, 'Settings', 'force_mfa', old_force_mfa, settings.force_mfa, f'Force MFA setting changed from {old_force_mfa} to {settings.force_mfa}')
    flash('Настройки обновлены', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/department/users')
@login_required
def department_users():
    """Панель руководителя отдела для управления пользователями своего отдела."""
    if not is_department_head(current_user):
        flash('Доступ разрешен только руководителям отделов', 'error')
        return redirect(url_for('dashboard'))
    dept = Department.query.get_or_404(current_user.managed_department_id)
    users = User.query.filter_by(department_id=dept.id).all()
    roles = Role.query.order_by(Role.name).all()
    return render_template('department_users.html', department=dept, users=users, roles=roles)


@app.route('/department/users/<int:user_id>/update', methods=['POST'])
@login_required
def department_update_user(user_id):
    if not is_department_head(current_user):
        flash('Доступ разрешен только руководителям отделов', 'error')
        return redirect(url_for('dashboard'))
    dept_id = current_user.managed_department_id
    user = User.query.get_or_404(user_id)
    if user.department_id != dept_id:
        flash('Можно управлять только пользователями своего отдела', 'error')
        return redirect(url_for('department_users'))
    if user.role.name == 'admin':
        flash('Нельзя изменять администратора', 'error')
        return redirect(url_for('department_users'))

    role_id = request.form.get('role_id')
    is_enabled = 'is_enabled' in request.form
    if role_id:
        role = Role.query.get(int(role_id))
        if role and role.name != 'admin':
            user.role_id = role.id
    user.is_enabled = is_enabled
    db.session.commit()
    log_action('dept_user_updated', 'user', user.id, f'Dept head updated user {user.username}')
    flash(f'Пользователь {user.username} обновлен', 'success')
    return redirect(url_for('department_users'))


@app.route('/department/users/<int:user_id>/reset_mfa', methods=['POST'])
@login_required
def department_reset_mfa(user_id):
    if not is_department_head(current_user):
        flash('Доступ разрешен только руководителям отделов', 'error')
        return redirect(url_for('dashboard'))
    dept_id = current_user.managed_department_id
    user = User.query.get_or_404(user_id)
    if user.department_id != dept_id:
        flash('Можно управлять только пользователями своего отдела', 'error')
        return redirect(url_for('department_users'))
    user.mfa_enabled = False
    user.mfa_secret = None
    db.session.commit()
    log_action('dept_user_mfa_reset', 'user', user.id, f'Dept head reset MFA for {user.username}')
    flash(f'MFA для пользователя {user.username} сброшена', 'success')
    return redirect(url_for('department_users'))

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
    # Деактивация сессии
    session_id = flask_session.get('session_id')
    if session_id:
        deactivate_session(session_id)
    
    log_action('logout')
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
@role_required('admin_access')
def admin_panel():
    try:
        # Получаем только необходимые данные для статистики
        users_count = User.query.count()
        users_mfa_count = User.query.filter_by(mfa_enabled=True).count()
        files_count = File.query.count()
        audit_logs_count = AuditLog.query.count()
        pending_users = User.query.filter_by(status='pending').all()
        departments = Department.query.order_by(Department.name).all()
        roles = Role.query.order_by(Role.name).all()
        exchange_policies = ExchangePolicy.query.all()
        security_events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(100).all()
        settings = get_settings()
        
        # Получаем файлы только для статистики хранилища
        files = File.query.all()
    except Exception as e:
        print(f"Ошибка при загрузке данных для админ панели: {e}")
        import traceback
        traceback.print_exc()
        # Пробрасываем ошибку дальше, чтобы увидеть полный traceback
        raise
        # Возвращаем минимальные данные для отображения страницы
        return render_template(
            'admin.html',
            users_count=0,
            users_mfa_count=0,
            files=[],
            files_count=0,
            audit_logs_count=0,
            pending_users=[],
            storage_stats={'total_files': 0, 'total_size_mb': 0, 'disk_usage_mb': 0, 'used_disk_space': 0, 'total_disk_space': 0, 'free_disk_space': 0, 'disk_usage_percent': 0, 'file_types': {}},
            departments=[],
            roles=[],
            exchange_policies=[],
            permissions_catalog=PERMISSIONS_CATALOG,
            permissions_labels=PERMISSIONS_LABELS,
            settings=get_settings(),
            security_events=[],
        )
    
    # Подсчет статистики хранилища
    total_size = sum(file.file_size or 0 for file in files)  # Общий размер в байтах
    total_size_mb = total_size / (1024 * 1024) if total_size > 0 else 0  # Конвертация в МБ
    total_size_gb = total_size / (1024 * 1024 * 1024) if total_size > 0 else 0  # Конвертация в ГБ
    
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
        disk_usage_percent = (disk_stats.used / disk_stats.total) * 100 if disk_stats.total > 0 else 0
    except Exception as e:
        print(f"Ошибка при получении статистики диска: {e}")
        total_disk_space = 0
        free_disk_space = 0
        used_disk_space = 0
        disk_usage_percent = 0
    
    # Статистика по типам файлов
    file_types = {}
    for file in files:
        try:
            mime_type = file.mime_type.split('/')[0] if file.mime_type else 'unknown'
            if mime_type not in file_types:
                file_types[mime_type] = {'count': 0, 'size': 0}
            file_types[mime_type]['count'] += 1
            file_types[mime_type]['size'] += file.file_size or 0
        except Exception as e:
            print(f"Ошибка при обработке файла {file.id}: {e}")
            continue
    
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
    
    return render_template(
        'admin.html',
        users_count=users_count,
        users_mfa_count=users_mfa_count,
        files_count=files_count,
        audit_logs_count=audit_logs_count,
        pending_users=pending_users,
        storage_stats=storage_stats,
        departments=departments,
        roles=roles,
        exchange_policies=exchange_policies,
        permissions_catalog=PERMISSIONS_CATALOG,
        permissions_labels=PERMISSIONS_LABELS,
        settings=settings,
        security_events=security_events,
    )

@app.route('/admin/files')
@login_required
@role_required('admin_access')
def admin_files():
    """Страница управления файлами"""
    try:
        files = File.query.order_by(File.created_at.desc()).all()
        
        # Подсчет статистики хранилища
        total_size = sum(file.file_size or 0 for file in files)
        total_size_mb = total_size / (1024 * 1024) if total_size > 0 else 0
        
        # Подсчет статистики
        public_count = sum(1 for file in files if file.access_level == 'public')
        private_count = sum(1 for file in files if file.access_level == 'private')
        department_count = sum(1 for file in files if file.access_level == 'department')
        
        stats = {
            'total': len(files),
            'public': public_count,
            'private': private_count,
            'department': department_count
        }
        
        storage_stats = {
            'total_files': len(files),
            'total_size': total_size,
            'total_size_mb': round(total_size_mb, 2),
        }
        
        return render_template('admin_files.html', files=files, storage_stats=storage_stats, stats=stats)
    except Exception as e:
        print(f"Ошибка при загрузке страницы файлов: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Ошибка при загрузке файлов: {str(e)}', 'error')
        return render_template('admin_files.html', files=[], storage_stats={'total_files': 0, 'total_size_mb': 0}, stats={'total': 0, 'public': 0, 'private': 0, 'department': 0})

@app.route('/admin/users')
@login_required
@role_required('admin_access')
def admin_users():
    """Страница управления пользователями"""
    users = User.query.order_by(User.created_at.desc()).all()
    pending_users = User.query.filter_by(status='pending').all()
    
    # Подсчет статистики
    total_count = len(users)
    active_count = sum(1 for user in users if user.status == 'active')
    pending_count = sum(1 for user in users if user.status == 'pending')
    mfa_count = sum(1 for user in users if user.mfa_enabled)
    
    # Подсчет активных сессий
    active_sessions_count = UserSession.query.filter_by(is_active=True).count()
    
    stats = {
        'total': total_count,
        'active': active_count,
        'pending': pending_count,
        'mfa': mfa_count,
        'active_sessions': active_sessions_count
    }
    
    return render_template('admin_users.html', users=users, pending_users=pending_users, stats=stats)

@app.route('/admin/audit')
@login_required
@role_required('admin_access')
def admin_audit():
    """Страница журнала аудита"""
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(500).all()
    
    # Подсчет статистики
    total_count = len(audit_logs)
    login_count = sum(1 for log in audit_logs if 'login' in log.action)
    upload_count = sum(1 for log in audit_logs if 'upload' in log.action)
    download_count = sum(1 for log in audit_logs if 'download' in log.action)
    
    stats = {
        'total': total_count,
        'login': login_count,
        'upload': upload_count,
        'download': download_count
    }
    
    return render_template('admin_audit.html', audit_logs=audit_logs, stats=stats)

@app.route('/admin/security/events')
@login_required
@role_required('admin_access')
def admin_security_events():
    """Страница фильтрации и поиска событий безопасности"""
    # Получаем параметры фильтрации
    event_type = request.args.get('event_type', '')
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    search = request.args.get('search', '')
    ip_address = request.args.get('ip_address', '')
    user_id = request.args.get('user_id', '')
    export_format = request.args.get('export', '')
    
    # Построение запроса
    query = SecurityEvent.query
    
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if status:
        query = query.filter(SecurityEvent.status == status)
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(SecurityEvent.created_at >= date_from_obj)
        except:
            pass
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(SecurityEvent.created_at < date_to_obj)
        except:
            pass
    if search:
        query = query.filter(SecurityEvent.details.contains(search))
    if ip_address:
        query = query.filter(SecurityEvent.ip_address.contains(ip_address))
    if user_id:
        query = query.filter(SecurityEvent.user_id == int(user_id))
    
    events = query.order_by(SecurityEvent.created_at.desc()).limit(1000).all()
    
    # Подсчет статистики
    stats = {
        'total': len(events),
        'critical': sum(1 for e in events if e.severity == 'critical'),
        'high': sum(1 for e in events if e.severity == 'high'),
        'new': sum(1 for e in events if e.status == 'new'),
        'resolved': sum(1 for e in events if e.status == 'resolved')
    }
    
    # Экспорт
    if export_format == 'csv':
        import csv
        from io import StringIO
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Время', 'Тип', 'Уровень', 'Пользователь', 'IP адрес', 'Статус', 'Детали'])
        for event in events:
            writer.writerow([
                event.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                event.event_type,
                event.severity or 'medium',
                event.user.username if event.user else '-',
                event.ip_address or '-',
                event.status or 'new',
                event.details or '-'
            ])
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename=security_events_{moscow_now().strftime("%Y%m%d_%H%M%S")}.csv'
        return response
    
    if export_format == 'json':
        events_data = []
        for event in events:
            events_data.append({
                'id': event.id,
                'created_at': event.created_at.isoformat(),
                'event_type': event.event_type,
                'severity': event.severity or 'medium',
                'status': event.status or 'new',
                'user': event.user.username if event.user else None,
                'ip_address': event.ip_address,
                'details': event.details
            })
        response = jsonify(events_data)
        response.headers['Content-Disposition'] = f'attachment; filename=security_events_{moscow_now().strftime("%Y%m%d_%H%M%S")}.json'
        return response
    
    # Получаем всех пользователей для фильтра
    all_users = User.query.order_by(User.username).all()
    
    return render_template('admin_security_events.html', 
                         events=events, 
                         stats=stats,
                         all_users=all_users)

@app.route('/admin/security/events/<int:event_id>/acknowledge', methods=['POST'])
@login_required
@role_required('admin_access')
def acknowledge_security_event(event_id):
    """Принимает событие безопасности"""
    try:
        event = SecurityEvent.query.get_or_404(event_id)
        event.status = 'acknowledged'
        event.acknowledged_by = current_user.id
        event.acknowledged_at = moscow_now()
        db.session.commit()
        
        log_action('security_event_acknowledged', 'security_event', event_id, f'Event {event.event_type} acknowledged')
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/security/events/<int:event_id>/resolve', methods=['POST'])
@login_required
@role_required('admin_access')
def resolve_security_event(event_id):
    """Решает событие безопасности"""
    try:
        event = SecurityEvent.query.get_or_404(event_id)
        event.status = 'resolved'
        event.resolved_at = moscow_now()
        db.session.commit()
        
        log_action('security_event_resolved', 'security_event', event_id, f'Event {event.event_type} resolved')
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/security/incidents')
@login_required
@role_required('admin_access')
def admin_security_incidents():
    """Страница инцидентов безопасности"""
    incidents = SecurityIncident.query.order_by(SecurityIncident.created_at.desc()).limit(100).all()
    
    return render_template('admin_security_incidents.html', incidents=incidents)

@app.route('/admin/security/alerts')
@login_required
@role_required('admin_access')
def admin_security_alerts():
    """Страница управления алертами безопасности"""
    alerts = SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).all()
    
    return render_template('admin_security_alerts.html', alerts=alerts)

@app.route('/admin/security/alerts', methods=['POST'])
@login_required
@role_required('admin_access')
def admin_create_alert():
    """Создание нового алерта"""
    name = request.form.get('name', '').strip()
    event_type = request.form.get('event_type', '').strip() or None
    severity = request.form.get('severity', '').strip() or None
    condition = request.form.get('condition', 'count_per_hour')
    threshold = int(request.form.get('threshold', 5))
    enabled = 'enabled' in request.form
    notify_admins = 'notify_admins' in request.form
    
    if not name:
        flash('Название алерта обязательно', 'error')
        return redirect(url_for('admin_security_alerts'))
    
    alert = SecurityAlert(
        name=name,
        event_type=event_type,
        severity=severity,
        condition=condition,
        threshold=threshold,
        enabled=enabled,
        notify_admins=notify_admins
    )
    db.session.add(alert)
    db.session.commit()
    
    log_config_change('alert', 'security_alert', alert.id, name, 'created', None, f'Alert: {name}', f'Security alert {name} created')
    flash('Алерт создан', 'success')
    return redirect(url_for('admin_security_alerts'))

@app.route('/admin/config/changes')
@login_required
@role_required('admin_access')
def admin_config_changes():
    """Страница истории изменений конфигурации"""
    changes = ConfigChangeLog.query.order_by(ConfigChangeLog.created_at.desc()).limit(500).all()
    
    return render_template('admin_config_changes.html', changes=changes)

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
        dept_name = request.form.get('department', '').strip()
        user.department_id = get_or_create_department(dept_name).id if dept_name else None
        user.is_enabled = 'is_enabled' in request.form
        new_status = request.form.get('status')
        if new_status:
            user.status = new_status
        user.status_reason = request.form.get('status_reason') or None
        managed_dept_id = request.form.get('managed_department_id')
        user.managed_department_id = int(managed_dept_id) if managed_dept_id else None
        
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
        return redirect(url_for('admin_users'))
    
    # Получаем все роли и отделы для выбора
    roles = Role.query.all()
    departments = Department.query.order_by(Department.name).all()
    return render_template('edit_user.html', user=user, roles=roles, departments=departments)

# Обработчик ошибок для больших файлов
@app.errorhandler(413)
def too_large(e):
    flash('Файл слишком большой. Максимальный размер: 100MB', 'error')
    return redirect(url_for('dashboard'))

# Обработчик ошибок для отладки
@app.errorhandler(500)
def internal_error(e):
    import traceback
    error_traceback = traceback.format_exc()
    print("=" * 50)
    print("ОШИБКА 500:")
    print(error_traceback)
    print("=" * 50)
    return f"<h1>Внутренняя ошибка сервера</h1><pre>{error_traceback}</pre>", 500

if __name__ == '__main__':
    with app.app_context():
        migrate_db()
        
        # Создаем роли по умолчанию
        if not Role.query.first():
            roles = [
                Role(name='admin', description='Администратор системы', 
                     permissions='[\"admin_access\", \"upload_files\", \"download_files\", \"share_files\", \"manage_users\"]'),
                Role(name='manager', description='Менеджер', 
                     permissions='[\"upload_files\", \"download_files\", \"share_files\"]'),
                Role(name='user', description='Обычный пользователь', 
                     permissions='[\"upload_files\", \"download_files\"]')
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
                role_id=admin_role.id,
                status='active'
            )
            db.session.add(admin)
            db.session.commit()
    
    # Запускаем корреляцию событий при старте
    with app.app_context():
        try:
            correlate_security_events()
        except Exception as e:
            logging.warning(f"Ошибка корреляции событий при старте: {e}")
    
    app.run(debug=False, host='0.0.0.0', port=5000)
