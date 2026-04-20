# Task

Task — backend-first мессенджер с поддержкой:
- Хранения сообщений в PostgreSQL.
- Авторизации JWT + refresh token rotation.
- Каналов и личных чатов (DM).
- Загрузки файлов.
- Push-уведомлений (серверная заглушка очереди отправки).
- E2E-ready модели сообщений (хранится `ciphertext` + `nonce`, сервер не расшифровывает).

## Быстрый локальный старт

### 1) Поднять PostgreSQL

```bash
docker run --name task-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=task -p 5432:5432 -d postgres:16
```

### 2) Запустить сервер

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL='postgresql+asyncpg://postgres:postgres@localhost:5432/task'
export JWT_SECRET='change-me'
uvicorn server:app --reload
```

Открыть: `http://127.0.0.1:8000`.

---

## Пошаговый деплой на хостинг (VPS + Docker + HTTPS)

Ниже инструкция для Ubuntu 22.04/24.04 VPS (Hetzner, DigitalOcean, Timeweb, Selectel и т.д.).

### Шаг 0. Что нужно заранее

- VPS с публичным IP.
- Домен, у которого A-запись указывает на IP сервера.
- Доступ по SSH.

### Шаг 1. Подключиться к серверу и поставить Docker

```bash
ssh root@YOUR_SERVER_IP
apt update && apt upgrade -y
apt install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sh
systemctl enable docker
systemctl start docker
```

Проверка:

```bash
docker --version
docker compose version
```

### Шаг 2. Склонировать проект

```bash
mkdir -p /opt/task && cd /opt/task
git clone <YOUR_REPO_URL> .
```

### Шаг 3. Создать `.env`

```bash
cat > .env <<'EOF'
POSTGRES_PASSWORD=super-strong-password
JWT_SECRET=super-long-random-secret
DOMAIN=task.example.com
EOF
```

> `DOMAIN` должен точно совпадать с доменным именем, которое смотрит на ваш VPS.

### Шаг 4. Проверить Caddy-конфиг

Файл уже есть в проекте: `deploy/Caddyfile`.
Он использует переменную `{$DOMAIN}` и автоматически поднимет HTTPS (Let's Encrypt).

### Шаг 5. Запустить контейнеры

```bash
docker compose pull
docker compose up -d --build
```

Проверить состояние:

```bash
docker compose ps
docker compose logs -f app
```

### Шаг 6. Открыть порты в firewall

Если используете UFW:

```bash
ufw allow 22
ufw allow 80
ufw allow 443
ufw enable
ufw status
```

### Шаг 7. Проверить доступность

- Откройте в браузере: `https://task.example.com`
- Должна открыться страница клиента `Task`.

API-проверка:

```bash
curl -i https://task.example.com/
```

### Шаг 8. Обновление приложения

```bash
cd /opt/task
git pull
docker compose up -d --build
```

### Шаг 9. Резервные копии (минимум)

Сделайте cron/скрипт дампа PostgreSQL:

```bash
docker compose exec -T db pg_dump -U task task > /opt/task/backup_$(date +%F).sql
```

Рекомендуется также бэкапить том `uploads_data`.

---

## Основные API

- `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`
- `POST /e2e/public-key`, `GET /e2e/public-keys`
- `POST /channels`, `POST /dm/{username}`, `GET /conversations`
- `GET /messages/{conversation_id}`
- `POST /files/upload`
- `POST /push/subscribe`, `POST /push/notify`
- `WS /ws/{conversation_id}?token=<access_jwt>`

## Замечания

- Для полноценного E2E клиент должен сам шифровать/расшифровывать payload.
- Для production нужны миграции (Alembic), rate limiting, anti-spam, реальные интеграции с APNS/FCM.
