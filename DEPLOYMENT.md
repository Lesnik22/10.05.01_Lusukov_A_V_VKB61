# Развертывание на облачном сервере

## Варианты хостинга

### 1. Heroku (бесплатный уровень)
```bash
# Установка Heroku CLI
# Создание Procfile
echo "web: gunicorn app_simple:app" > Procfile

# Развертывание
heroku login
heroku create your-app-name
git push heroku main
```

### 2. PythonAnywhere (бесплатный)
- Зарегистрируйтесь на https://www.pythonanywhere.com/
- Загрузите файлы проекта
- Настройте WSGI приложение
- Получите URL: `your-username.pythonanywhere.com`

### 3. DigitalOcean / AWS / Azure
**Для продакшена:**
```bash
# На сервере Ubuntu
sudo apt update
sudo apt install python3 python3-pip nginx

# Установка зависимостей
pip3 install -r requirements.txt

# Настройка Gunicorn
pip3 install gunicorn

# Запуск
gunicorn -w 4 -b 0.0.0.0:5000 app_simple:app
```

### 4. Docker + любой хостинг
```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "app_simple.py"]
```

```bash
# Сборка и запуск
docker build -t secure-file-system .
docker run -p 5000:5000 secure-file-system
```

## Важно для продакшена!

### Обязательные настройки:
1. **Измените SECRET_KEY** в app_simple.py
2. **Используйте PostgreSQL** вместо SQLite
3. **Настройте HTTPS** (Let's Encrypt)
4. **Используйте WSGI сервер** (Gunicorn/uWSGI)
5. **Настройте Nginx** как reverse proxy
6. **Создайте резервные копии** БД
7. **Мониторинг и логирование**

### Конфигурация Nginx:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # SSL от Let's Encrypt
    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
}
```

### Переменные окружения:
```bash
export SECRET_KEY="super-secure-random-key-here"
export DATABASE_URL="postgresql://user:password@localhost/dbname"
export FLASK_ENV="production"
```



