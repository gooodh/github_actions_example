#!/bin/bash

# Скрипт для локального тестирования staging деплоя
set -e

echo "🧪 Testing staging deployment locally..."

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

# Проверка Docker
check_docker() {
    log "Checking Docker..."
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
    fi
    
    if ! docker info &> /dev/null; then
        error "Docker is not running"
    fi
    
    log "Docker is ready"
}

# Сборка локального образа для тестирования
build_local_image() {
    log "Building local staging image..."
    
    # Используем тег latest для локального тестирования
    docker build -t "local/staging-test:latest" .
    
    if [ $? -eq 0 ]; then
        log "Local image built successfully"
    else
        error "Failed to build local image"
    fi
}

# Создание тестового .env файла
create_test_env() {
    log "Creating test environment file..."
    
    cat > .env.staging << EOF
# Test Staging Environment
ENVIRONMENT=staging
DATABASE_URL=postgresql://postgres:test_staging_password@db_postgres:5432/staging_db
POSTGRES_DB=staging_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=test_staging_password
SECRET_KEY=test_staging_secret_key_do_not_use_in_production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
LOG_LEVEL=DEBUG
CORS_ORIGINS=["http://localhost:3000", "http://localhost:8081"]
GRAFANA_PASSWORD=test_admin
PGADMIN_PASSWORD=test_pgadmin
EOF
    
    log "Test environment file created"
}

# Модификация docker-compose для локального тестирования
create_test_compose() {
    log "Creating test docker-compose file..."
    
    # Заменяем образ на локальный
    sed 's|ghcr.io/${GITHUB_REPOSITORY}:latest|local/staging-test:latest|g' \
        docker-compose.staging.yml > docker-compose.staging.test.yml
    
    log "Test docker-compose file created"
}

# Запуск тестового окружения
start_test_environment() {
    log "Starting test staging environment..."
    
    # Останавливаем старые контейнеры
    docker-compose -f docker-compose.staging.test.yml down --remove-orphans 2>/dev/null || true
    
    # Запускаем новые
    docker-compose -f docker-compose.staging.test.yml up -d
    
    if [ $? -eq 0 ]; then
        log "Test environment started successfully"
    else
        error "Failed to start test environment"
    fi
}

# Проверка здоровья
test_health() {
    log "Testing application health..."
    
    # Ждем запуска
    sleep 30
    
    for i in {1..10}; do
        if curl -f http://localhost:8081/health > /dev/null 2>&1; then
            log "✅ Health check passed"
            return 0
        fi
        warn "Health check attempt $i failed, retrying in 5 seconds..."
        sleep 5
    done
    
    error "❌ Health check failed"
}

# Тестирование основных эндпоинтов
test_endpoints() {
    log "Testing main endpoints..."
    
    # Тест корневого эндпоинта
    if curl -f http://localhost:8081/ > /dev/null 2>&1; then
        log "✅ Root endpoint OK"
    else
        warn "❌ Root endpoint failed"
    fi
    
    # Тест документации
    if curl -f http://localhost:8081/docs > /dev/null 2>&1; then
        log "✅ Documentation endpoint OK"
    else
        warn "❌ Documentation endpoint failed"
    fi
    
    # Тест метрик (если есть)
    if curl -f http://localhost:8081/metrics > /dev/null 2>&1; then
        log "✅ Metrics endpoint OK"
    else
        warn "❌ Metrics endpoint not available (this might be OK)"
    fi
}

# Показ логов
show_logs() {
    log "Showing application logs..."
    docker-compose -f docker-compose.staging.test.yml logs --tail=50 app
}

# Показ статуса сервисов
show_status() {
    log "Service status:"
    docker-compose -f docker-compose.staging.test.yml ps
    
    echo ""
    log "Available services:"
    echo "🌐 Application: http://localhost:8081"
    echo "🗄️  PgAdmin: http://localhost:15433 (admin@staging.pgadmin.com / test_pgadmin)"
    echo "📊 Grafana: http://localhost:3001 (admin / test_admin)"
    echo "🔍 Prometheus: http://localhost:9091"
}

# Очистка
cleanup() {
    log "Cleaning up test environment..."
    docker-compose -f docker-compose.staging.test.yml down --remove-orphans
    docker rmi local/staging-test:latest 2>/dev/null || true
    rm -f .env.staging docker-compose.staging.test.yml
    log "Cleanup completed"
}

# Основная функция
main() {
    case "${1:-test}" in
        "test")
            log "Running full staging test..."
            check_docker
            build_local_image
            create_test_env
            create_test_compose
            start_test_environment
            test_health
            test_endpoints
            show_status
            log "🎉 Staging test completed successfully!"
            ;;
        "logs")
            show_logs
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            cleanup
            ;;
        "stop")
            log "Stopping test environment..."
            docker-compose -f docker-compose.staging.test.yml down
            ;;
        *)
            echo "Usage: $0 {test|logs|status|cleanup|stop}"
            echo "  test    - Run full staging test (default)"
            echo "  logs    - Show application logs"
            echo "  status  - Show service status"
            echo "  cleanup - Clean up test environment"
            echo "  stop    - Stop test environment"
            exit 1
            ;;
    esac
}

# Обработка прерывания
trap cleanup EXIT

# Запуск
main "$@"
