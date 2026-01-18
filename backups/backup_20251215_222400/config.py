"""
Конфигурация для безопасной системы обмена файлами
"""

import os
from dotenv import load_dotenv

load_dotenv('KEY.env')

class Config:
    """Базовая конфигурация"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///secure_file_system.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 100 * 1024 * 1024))  # 100MB
    
    # Настройки безопасности
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', 3600))  # 1 час
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION = int(os.environ.get('LOCKOUT_DURATION', 900))  # 15 минут
    
    # Настройки MFA
    MFA_ISSUER_NAME = os.environ.get('MFA_ISSUER_NAME', 'Secure File System')
    MFA_VALID_WINDOW = int(os.environ.get('MFA_VALID_WINDOW', 1))
    
    # Настройки аудита
    AUDIT_LOG_RETENTION_DAYS = int(os.environ.get('AUDIT_LOG_RETENTION_DAYS', 365))
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    
    # Настройки шифрования
    # ВАЖНО: ключ должен быть задан через переменную окружения ENCRYPTION_KEY или в KEY.env
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

class DevelopmentConfig(Config):
    """Конфигурация для разработки"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///secure_file_system_dev.db'

class ProductionConfig(Config):
    """Конфигурация для продакшена"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost/secure_file_system')
    
    # Дополнительные настройки безопасности для продакшена
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

class TestingConfig(Config):
    """Конфигурация для тестирования"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

