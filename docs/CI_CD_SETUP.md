# Настройка CI/CD

## Обзор

Проект использует GitHub Actions для автоматизации процессов разработки, тестирования и деплоя.

## Структура CI/CD

```
.github/
├── workflows/
│   ├── ci.yml                 # Основной CI/CD pipeline
│   ├── code-quality.yml       # Проверка качества кода
│   ├── dependency-update.yml  # Обновление зависимостей
│   └── release.yml           # Создание релизов
├── ISSUE_TEMPLATE/           # Шаблоны для issues
├── PULL_REQUEST_TEMPLATE.md  # Шаблон для PR
└── dependabot.yml           # Настройки Dependabot
```

## Workflows

### 1. CI/CD Pipeline (`ci.yml`)

**Триггеры:**
- Push в ветки `main`, `develop`
- Pull Request в ветки `main`, `develop`
- Создание релиза

**Этапы:**
1. **Test** - Запуск тестов с PostgreSQL
2. **Security** - Сканирование безопасности
3. **Build** - Сборка Docker образа
4. **Deploy Staging** - Деплой в staging (ветка `develop`)
5. **Deploy Production** - Деплой в production (релизы)
6. **Performance Test** - Тесты производительности

### 2. Code Quality (`code-quality.yml`)

**Проверки:**
- Ruff (линтинг, форматирование, сортировка импортов, безопасность)
- MyPy (типизация)
- Radon (сложность кода)

### 3. Dependency Update (`dependency-update.yml`)

**Функции:**
- Автоматическое обновление зависимостей
- Запуск тестов с новыми версиями
- Создание PR с обновлениями

### 4. Release (`release.yml`)

**Функции:**
- Автоматическое создание релизов
- Генерация changelog
- Публикация Docker образов

## Настройка репозитория

### 1. Secrets

Добавьте в Settings → Secrets and variables → Actions:

```bash
# Автоматически доступны
GITHUB_TOKEN

# Для деплоя (при необходимости)
DEPLOY_HOST
DEPLOY_USER
DEPLOY_KEY
```

### 2. Environments

Создайте в Settings → Environments:

- **staging**
  - Deployment branches: `develop`
  - Environment secrets (если нужны)

- **production**
  - Deployment branches: `main`
  - Required reviewers (рекомендуется)
  - Environment secrets

### 3. Branch Protection

Настройте в Settings → Branches для `main` и `develop`:

- ✅ Require a pull request before merging
- ✅ Require status checks to pass before merging
  - ✅ Require branches to be up to date before merging
  - Status checks: `test`, `code-quality`
- ✅ Restrict pushes that create files larger than 100 MB

## Локальная разработка

### Установка pre-commit хуков

```bash
make pre-commit-install
```

### Запуск всех CI проверок локально

```bash
./scripts/ci-local.sh
```

### Отдельные команды

```bash
# Тесты
make ci-test

# Качество кода (линтинг + форматирование)
make ci-lint

# Безопасность
make ci-security

# Форматирование (исправляет ошибки автоматически)
make format

# Только проверка линтинга
ruff check app/ tests/

# Только форматирование
ruff format app/ tests/
```

## Docker

### Тестирование в Docker

```bash
# Запуск тестов в Docker
make docker-test

# Или напрямую
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

### Сборка образа

```bash
make docker-build
```

## Деплой

### Staging

Автоматически при push в `develop`:

```bash
git checkout develop
git push origin develop
```

### Production

Создание релиза:

```bash
# Создать тег
git tag v1.0.0
git push origin v1.0.0

# Или через GitHub UI
# Releases → Create a new release
```

## Мониторинг и отчеты

### Codecov

Покрытие кода автоматически отправляется в Codecov после каждого запуска тестов.

### Security

- Bandit сканирует код на уязвимости
- Safety проверяет зависимости
- Dependabot отслеживает обновления безопасности

### Performance

Тесты производительности запускаются при push в `main` и сохраняют результаты как артефакты.

## Troubleshooting

### Тесты падают в CI

1. Проверьте логи в GitHub Actions
2. Запустите локально: `make ci-test`
3. Проверьте переменные окружения в `.env.test`

### Проблемы с Docker

1. Проверьте Dockerfile
2. Убедитесь в корректности зависимостей
3. Проверьте логи сборки

### Проблемы с деплоем

1. Проверьте настройки environments
2. Убедитесь в наличии необходимых secrets
3. Проверьте права доступа

## Лучшие практики

### Commits

```bash
# Используйте conventional commits
feat: добавить новую функцию
fix: исправить баг
docs: обновить документацию
style: форматирование кода
refactor: рефакторинг
test: добавить тесты
chore: обновить зависимости
```

### Pull Requests

- Используйте шаблон PR
- Добавляйте описание изменений
- Связывайте с issues
- Проверяйте, что все CI проверки проходят

### Releases

- Используйте семантическое версионирование (SemVer)
- Добавляйте описание изменений
- Тестируйте перед релизом

## Расширение CI/CD

### Добавление новых проверок

1. Создайте новый job в `ci.yml`
2. Добавьте соответствующую команду в Makefile
3. Обновите документацию

### Интеграция с внешними сервисами

1. Добавьте необходимые secrets
2. Создайте новый workflow или расширьте существующий
3. Настройте уведомления (Slack, Discord, etc.)

### Кастомизация для проекта

1. Обновите переменные окружения
2. Настройте специфичные для проекта проверки
3. Адаптируйте процесс деплоя под вашу инфраструктуру