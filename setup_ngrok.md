# Настройка Ngrok для удаленного доступа

## Что такое Ngrok?
Ngrok создает безопасный туннель к вашему локальному серверу и предоставляет публичный URL с HTTPS.

## Установка

### 1. Скачайте Ngrok
- Перейдите на https://ngrok.com/
- Зарегистрируйтесь (бесплатно)
- Скачайте для Windows
- Распакуйте в папку проекта

### 2. Подключите аккаунт
```bash
ngrok config add-authtoken YOUR_AUTH_TOKEN
```

### 3. Запустите туннель
```bash
# В новом терминале (при запущенном app_simple.py)
ngrok http 5000
```

## Результат
```
Session Status                online
Account                       your@email.com
Version                       3.0.0
Region                        United States (us)
Web Interface                 http://127.0.0.1:4040
Forwarding                    https://abc123.ngrok.io -> http://localhost:5000
```

## Использование
Теперь ваше приложение доступно по адресу:
- `https://abc123.ngrok.io`

## Преимущества
- ✅ Автоматический HTTPS
- ✅ Публичный URL
- ✅ Не требует настройки роутера
- ✅ Работает через любые файрволлы
- ✅ Веб-интерфейс для мониторинга запросов

## Недостатки
- ⚠️ URL меняется при каждом запуске (бесплатная версия)
- ⚠️ Ограничение на количество соединений
- ⚠️ Не для продакшена

## Альтернативы Ngrok
- **Localtunnel**: https://localtunnel.github.io/www/
- **Serveo**: https://serveo.net/
- **Cloudflare Tunnel**: https://www.cloudflare.com/products/tunnel/

