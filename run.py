#!/usr/bin/env python3
"""
Скрипт для запуска безопасной системы обмена файлами
"""

import os
import sys
from app import app, db
from config import config

def create_app(config_name=None):
    """Создание приложения с конфигурацией"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app.config.from_object(config[config_name])
    
    # Создаем папку для загрузок
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    return app

def init_db():
    """Инициализация базы данных"""
    with app.app_context():
        db.create_all()
        
        # Создаем роли по умолчанию
        from app import Role, User
        from werkzeug.security import generate_password_hash
        
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
            print("База данных инициализирована")
            print("Создан администратор: admin / admin123")

def main():
    """Главная функция"""
    print("Запуск безопасной системы обмена файлами")
    print("=" * 50)
    
    # Создаем приложение
    app = create_app()
    
    # Инициализируем базу данных
    init_db()
    
    # Получаем настройки
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"Сервер запущен на http://{host}:{port}")
    print(f"Режим отладки: {'Включен' if debug else 'Отключен'}")
    print("=" * 50)
    
    # Запускаем сервер
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()

