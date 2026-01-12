#!/bin/bash

# Скрипт для деплоя в staging окружение
set -e

echo "🚀 Starting staging deployment..."

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция для логирования
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Проверка переменных окружения
check_env() {
    log "Checking environment variables..."
    
    if [ -z "$GITHUB_REPOSITORY" ]; then
        error "GITHUB_REPOSITORY environment variable is not set"
    fi
    
    if [ -z "$GITHUB_TOKEN" ]; then
        error "GITHUB_TOKEN environment variable is not set"
    fi
    
    log "Environment variables OK"
}

# Логин в GitHub Container Registry
login_registry() {
    log "Logging into GitHub Container Registry..."
    echo "$GITHUB_TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
    log "Successfully logged into registry"
}

# Подтягивание последнего образа
pull_image() {
    log "Pulling latest staging image..."
    docker pull "ghcr.io/${GITHUB_REPOSITORY}:latest" || error "Failed to pull image"
    log "Image pulled successfully"
}

# Создание .env файла для staging
create_env_file() {
    log "Creating staging environment file..."
    
    # Проверяем, существует ли .env.staging
    if [ ! -f ".env.staging" ]; then
        warn ".env.staging not found, creating from example..."
        if [ -f ".env.staging.example" ]; then
            cp .env.staging.example .env.staging
            warn "Please update .env.staging with actual values before running in production"
        else
            error ".env.staging.example not found"
        fi
    fi
    
    log "Environment file ready"
}

# Остановка старых контейнеров
stop_old_containers() {
    log "Stopping old staging containers..."
    docker-compose -f docker-compose.staging.yml down --remove-orphans || warn "No containers to stop"
    log "Old containers stopped"
}

# Запуск новых контейнеров
start_containers() {
    log "Starting staging containers..."
    
    # Экспортируем переменные для docker-compose
    export GITHUB_REPOSITORY
    
    docker-compose -f docker-compose.staging.yml up -d --remove-orphans
    
    if [ $? -eq 0 ]; then
        log "Containers started successfully"
    else
        error "Failed to start containers"
    fi
}

# Проверка здоровья приложения
health_check() {
    log "Performing health check..."
    
    # Ждем запуска приложения
    sleep 30
    
    # Проверяем доступность приложения
    for i in {1..10}; do
        if curl -f http://localhost:8081/health > /dev/null 2>&1; then
            log "Health check passed"
            return 0
        fi
        warn "Health check attempt $i failed, retrying in 10 seconds..."
        sleep 10
    done
    
    error "Health check failed after 10 attempts"
}

# Очистка старых образов
cleanup() {
    log "Cleaning up old images..."
    docker image prune -f || warn "Failed to cleanup images"
    log "Cleanup completed"
}

# Отправка уведомления (опционально)
send_notification() {
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        log "Sending deployment notification..."
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚀 Staging deployment completed successfully for ${GITHUB_REPOSITORY}\"}" \
            "$SLACK_WEBHOOK_URL" || warn "Failed to send notification"
    fi
}

# Основная функция
main() {
    log "Starting staging deployment for ${GITHUB_REPOSITORY:-unknown}"
    
    check_env
    login_registry
    pull_image
    create_env_file
    stop_old_containers
    start_containers
    health_check
    cleanup
    send_notification
    
    log "🎉 Staging deployment completed successfully!"
    log "Application is available at: http://localhost:8081"
    log "PgAdmin is available at: http://localhost:15433"
    log "Grafana is available at: http://localhost:3001"
}

# Обработка ошибок
trap 'error "Deployment failed"' ERR

# Запуск
main "$@"
