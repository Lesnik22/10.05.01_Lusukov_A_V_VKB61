"""
Скрипт для тестирования улучшений аудита безопасности
Создает тестовые данные и проверяет работоспособность всех функций
"""

import sys
import os
import json
from datetime import datetime, timedelta
import random

# Добавляем путь к приложению
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from app import (
    User, SecurityEvent, ConfigChangeLog, SecurityAlert, SecurityIncident,
    Role, Department,
    log_security_event, log_config_change, correlate_security_events,
    check_security_alerts
)

def print_header(text):
    """Красивый вывод заголовка"""
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def print_success(text):
    """Вывод успешного сообщения"""
    print(f"✓ {text}")

def print_error(text):
    """Вывод сообщения об ошибке"""
    print(f"✗ {text}")

def create_test_security_events():
    """Создание тестовых событий безопасности"""
    print_header("Создание тестовых событий безопасности")
    
    with app.app_context():
        # Получаем пользователей
        users = User.query.limit(5).all()
        if not users:
            print_error("Нет пользователей в системе. Создайте хотя бы одного пользователя.")
            return False
        
        # Типы событий и их severity
        event_types = [
            ('suspicious_login', 'high'),
            ('virus_detected', 'critical'),
            ('blocked_download', 'high'),
            ('security_alert', 'medium'),
            ('admin_notification', 'low'),
        ]
        
        # IP адреса для тестирования
        test_ips = [
            '192.168.1.100',
            '192.168.1.101',
            '10.0.0.50',
            '172.16.0.10',
        ]
        
        created_count = 0
        
        # Создаем события за последние 7 дней
        for day in range(7):
            date = datetime.utcnow() - timedelta(days=day)
            
            # Создаем несколько событий каждого типа
            for event_type, severity in event_types:
                for i in range(random.randint(1, 3)):
                    user = random.choice(users) if random.random() > 0.3 else None
                    ip = random.choice(test_ips)
                    
                    # Создаем событие напрямую через модель
                    event = SecurityEvent(
                        user_id=user.id if user else None,
                        event_type=event_type,
                        details=f"Тестовое событие {event_type} #{i+1} за {day} дней назад",
                        severity=severity,
                        ip_address=ip,
                        user_agent=f"Mozilla/5.0 (Test Browser) Day-{day}",
                        status=random.choice(['new', 'acknowledged', 'resolved']),
                        created_at=date - timedelta(hours=random.randint(0, 23))
                    )
                    db.session.add(event)
                    created_count += 1
        
        # Создаем группу событий с одного IP для тестирования корреляции
        suspicious_ip = '192.168.1.200'
        for i in range(5):
            event = SecurityEvent(
                user_id=None,
                event_type='suspicious_login',
                details=f"Множественные попытки входа с IP {suspicious_ip}",
                severity='high',
                ip_address=suspicious_ip,
                user_agent='Test Bot',
                status='new',
                created_at=datetime.utcnow() - timedelta(minutes=i*10)
            )
            db.session.add(event)
            created_count += 1
        
        try:
            db.session.commit()
            print_success(f"Создано {created_count} тестовых событий безопасности")
            return True
        except Exception as e:
            print_error(f"Ошибка при создании событий: {e}")
            db.session.rollback()
            return False

def create_test_alerts():
    """Создание тестовых алертов"""
    print_header("Создание тестовых алертов")
    
    with app.app_context():
        alerts_config = [
            {
                'name': 'Критические события вирусов',
                'event_type': 'virus_detected',
                'severity': 'critical',
                'condition': 'count_per_hour',
                'threshold': 1,
                'enabled': True,
                'notify_admins': True
            },
            {
                'name': 'Множественные подозрительные входы',
                'event_type': 'suspicious_login',
                'severity': 'high',
                'condition': 'count_per_hour',
                'threshold': 3,
                'enabled': True,
                'notify_admins': True
            },
            {
                'name': 'Высокий уровень событий',
                'event_type': None,
                'severity': 'high',
                'condition': 'count_per_day',
                'threshold': 10,
                'enabled': True,
                'notify_admins': False
            },
        ]
        
        created_count = 0
        
        for alert_config in alerts_config:
            # Проверяем, существует ли уже такой алерт
            existing = SecurityAlert.query.filter_by(name=alert_config['name']).first()
            if existing:
                print_success(f"Алерт '{alert_config['name']}' уже существует, пропускаем")
                continue
            
            alert = SecurityAlert(**alert_config)
            db.session.add(alert)
            created_count += 1
        
        try:
            db.session.commit()
            print_success(f"Создано {created_count} тестовых алертов")
            return True
        except Exception as e:
            print_error(f"Ошибка при создании алертов: {e}")
            db.session.rollback()
            return False

def create_test_config_changes():
    """Создание тестовых изменений конфигурации"""
    print_header("Создание тестовых изменений конфигурации")
    
    with app.app_context():
        # Получаем админа
        admin = User.query.join(Role).filter(Role.name == 'admin').first()
        if not admin:
            print_error("Администратор не найден")
            return False
        
        # Получаем роли и отделы
        roles = Role.query.limit(3).all()
        departments = Department.query.limit(2).all()
        
        if not roles:
            print_error("Нет ролей в системе")
            return False
        
        created_count = 0
        
        # Имитируем изменения ролей
        for role in roles[:2]:
            change = ConfigChangeLog(
                changed_by=admin.id,
                change_type='role',
                resource_type='role',
                resource_id=role.id,
                resource_name=role.name,
                field_name='permissions',
                old_value='["old_permission"]',
                new_value='["new_permission", "updated_permission"]',
                ip_address='192.168.1.1',
                user_agent='Test Admin Browser',
                details=f'Тестовое изменение прав роли {role.name}',
                created_at=datetime.utcnow() - timedelta(days=random.randint(1, 5))
            )
            db.session.add(change)
            created_count += 1
        
        # Имитируем изменения отделов
        if departments:
            for dept in departments[:1]:
                change = ConfigChangeLog(
                    changed_by=admin.id,
                    change_type='department',
                    resource_type='department',
                    resource_id=dept.id,
                    resource_name=dept.name,
                    field_name='name',
                    old_value=f'Old {dept.name}',
                    new_value=dept.name,
                    ip_address='192.168.1.1',
                    user_agent='Test Admin Browser',
                    details=f'Тестовое переименование отдела',
                    created_at=datetime.utcnow() - timedelta(days=random.randint(1, 3))
                )
                db.session.add(change)
                created_count += 1
        
        # Имитируем изменения настроек
        change = ConfigChangeLog(
            changed_by=admin.id,
            change_type='settings',
            resource_type='settings',
            resource_id=1,
            resource_name='Settings',
            field_name='force_mfa',
            old_value='False',
            new_value='True',
            ip_address='192.168.1.1',
            user_agent='Test Admin Browser',
            details='Тестовое изменение настройки принудительной MFA',
            created_at=datetime.utcnow() - timedelta(days=2)
        )
        db.session.add(change)
        created_count += 1
        
        try:
            db.session.commit()
            print_success(f"Создано {created_count} тестовых изменений конфигурации")
            return True
        except Exception as e:
            print_error(f"Ошибка при создании изменений конфигурации: {e}")
            db.session.rollback()
            return False

def test_correlation():
    """Тестирование корреляции событий"""
    print_header("Тестирование корреляции событий")
    
    with app.app_context():
        try:
            correlate_security_events()
            
            # Проверяем созданные инциденты
            incidents = SecurityIncident.query.all()
            print_success(f"Найдено {len(incidents)} инцидентов")
            
            for incident in incidents:
                print(f"  - Инцидент #{incident.id}: {incident.title}")
                print(f"    Severity: {incident.severity}, Status: {incident.status}")
                if incident.related_events:
                    event_ids = json.loads(incident.related_events)
                    print(f"    Связанных событий: {len(event_ids)}")
            
            return True
        except Exception as e:
            print_error(f"Ошибка при корреляции: {e}")
            import traceback
            traceback.print_exc()
            return False

def test_alerts():
    """Тестирование системы алертов"""
    print_header("Тестирование системы алертов")
    
    with app.app_context():
        alerts = SecurityAlert.query.filter_by(enabled=True).all()
        print_success(f"Найдено {len(alerts)} активных алертов")
        
        for alert in alerts:
            print(f"\n  Алерт: {alert.name}")
            print(f"    Тип события: {alert.event_type or 'Любой'}")
            print(f"    Severity: {alert.severity or 'Любой'}")
            print(f"    Условие: {alert.condition}")
            print(f"    Порог: {alert.threshold}")
            print(f"    Последний срабатывание: {alert.last_triggered.strftime('%Y-%m-%d %H:%M:%S') if alert.last_triggered else 'Никогда'}")
        
        return True

def show_statistics():
    """Вывод статистики"""
    print_header("Статистика системы аудита безопасности")
    
    with app.app_context():
        # Статистика событий
        total_events = SecurityEvent.query.count()
        critical_events = SecurityEvent.query.filter_by(severity='critical').count()
        high_events = SecurityEvent.query.filter_by(severity='high').count()
        new_events = SecurityEvent.query.filter_by(status='new').count()
        resolved_events = SecurityEvent.query.filter_by(status='resolved').count()
        
        print("\n📊 События безопасности:")
        print(f"  Всего событий: {total_events}")
        print(f"  Критических: {critical_events}")
        print(f"  Высокого уровня: {high_events}")
        print(f"  Новых: {new_events}")
        print(f"  Решенных: {resolved_events}")
        
        # Статистика инцидентов
        total_incidents = SecurityIncident.query.count()
        open_incidents = SecurityIncident.query.filter_by(status='open').count()
        
        print("\n🚨 Инциденты:")
        print(f"  Всего инцидентов: {total_incidents}")
        print(f"  Открытых: {open_incidents}")
        
        # Статистика алертов
        total_alerts = SecurityAlert.query.count()
        enabled_alerts = SecurityAlert.query.filter_by(enabled=True).count()
        
        print("\n🔔 Алерты:")
        print(f"  Всего алертов: {total_alerts}")
        print(f"  Включенных: {enabled_alerts}")
        
        # Статистика изменений конфигурации
        total_changes = ConfigChangeLog.query.count()
        role_changes = ConfigChangeLog.query.filter_by(change_type='role').count()
        dept_changes = ConfigChangeLog.query.filter_by(change_type='department').count()
        settings_changes = ConfigChangeLog.query.filter_by(change_type='settings').count()
        
        print("\n⚙️  Изменения конфигурации:")
        print(f"  Всего изменений: {total_changes}")
        print(f"  Изменений ролей: {role_changes}")
        print(f"  Изменений отделов: {dept_changes}")
        print(f"  Изменений настроек: {settings_changes}")
        
        # Топ IP адресов по событиям
        print("\n🌐 Топ IP адресов по событиям:")
        from sqlalchemy import func
        top_ips = db.session.query(
            SecurityEvent.ip_address,
            func.count(SecurityEvent.id).label('count')
        ).filter(
            SecurityEvent.ip_address.isnot(None)
        ).group_by(
            SecurityEvent.ip_address
        ).order_by(
            func.count(SecurityEvent.id).desc()
        ).limit(5).all()
        
        for ip, count in top_ips:
            print(f"  {ip}: {count} событий")

def cleanup_test_data():
    """Очистка тестовых данных (опционально)"""
    print_header("Очистка тестовых данных")
    
    response = input("Удалить все тестовые данные? (yes/no): ")
    if response.lower() != 'yes':
        print("Очистка отменена")
        return
    
    with app.app_context():
        try:
            # Удаляем тестовые события
            test_events = SecurityEvent.query.filter(
                SecurityEvent.details.like('%Тестовое событие%')
            ).all()
            for event in test_events:
                db.session.delete(event)
            
            # Удаляем тестовые алерты
            test_alerts = SecurityAlert.query.filter(
                SecurityAlert.name.in_(['Критические события вирусов', 'Множественные подозрительные входы', 'Высокий уровень событий'])
            ).all()
            for alert in test_alerts:
                db.session.delete(alert)
            
            # Удаляем тестовые изменения конфигурации
            test_changes = ConfigChangeLog.query.filter(
                ConfigChangeLog.details.like('%Тестовое%')
            ).all()
            for change in test_changes:
                db.session.delete(change)
            
            # Удаляем тестовые инциденты
            test_incidents = SecurityIncident.query.filter(
                SecurityIncident.title.like('%192.168.1.200%')
            ).all()
            for incident in test_incidents:
                db.session.delete(incident)
            
            db.session.commit()
            print_success("Тестовые данные удалены")
        except Exception as e:
            print_error(f"Ошибка при удалении: {e}")
            db.session.rollback()

def main():
    """Главная функция"""
    print("\n" + "="*60)
    print("  ТЕСТИРОВАНИЕ СИСТЕМЫ АУДИТА БЕЗОПАСНОСТИ")
    print("="*60)
    
    with app.app_context():
        # Проверяем подключение к БД
        try:
            db.session.execute(db.text("SELECT 1"))
            print_success("Подключение к базе данных установлено")
        except Exception as e:
            print_error(f"Ошибка подключения к БД: {e}")
            return
        
        # Меню
        print("\nВыберите действие:")
        print("1. Создать тестовые события безопасности")
        print("2. Создать тестовые алерты")
        print("3. Создать тестовые изменения конфигурации")
        print("4. Запустить корреляцию событий")
        print("5. Показать статистику")
        print("6. Выполнить все тесты")
        print("7. Очистить тестовые данные")
        print("0. Выход")
        
        choice = input("\nВаш выбор: ").strip()
        
        if choice == '1':
            create_test_security_events()
        elif choice == '2':
            create_test_alerts()
        elif choice == '3':
            create_test_config_changes()
        elif choice == '4':
            test_correlation()
        elif choice == '5':
            show_statistics()
        elif choice == '6':
            print("\n🚀 Запуск всех тестов...")
            create_test_security_events()
            create_test_alerts()
            create_test_config_changes()
            test_correlation()
            test_alerts()
            show_statistics()
            print("\n✅ Все тесты завершены!")
        elif choice == '7':
            cleanup_test_data()
        elif choice == '0':
            print("Выход...")
            return
        else:
            print("Неверный выбор")
            return
        
        print("\n" + "="*60)
        print("  Тестирование завершено")
        print("="*60 + "\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nПрервано пользователем")
    except Exception as e:
        print(f"\n\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()

