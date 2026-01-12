# Тесты для FastAPI приложения

Этот каталог содержит комплексные тесты для FastAPI приложения с аутентификацией.

## Структура тестов

```
tests/
├── __init__.py                 # Инициализация пакета тестов
├── conftest.py                # Конфигурация pytest и фикстуры
├── test_main.py               # Тесты основного приложения
├── test_auth.py               # Тесты аутентификации
├── test_schemas.py            # Тесты Pydantic схем
├── test_dao.py                # Тесты DAO классов
├── test_utils.py              # Тесты утилит
├── test_config.py             # Тесты конфигурации
├── test_exceptions.py         # Тесты исключений
├── test_integration.py        # Интеграционные тесты
├── test_performance.py        # Тесты производительности
├── requirements-test.txt      # Зависимости для тестов
└── README.md                  # Этот файл
```

## Типы тестов

### Unit тесты
- `test_schemas.py` - тестирование валидации данных
- `test_utils.py` - тестирование утилит (хеширование паролей, токены)
- `test_config.py` - тестирование конфигурации
- `test_exceptions.py` - тестирование пользовательских исключений

### Integration тесты
- `test_main.py` - тестирование основных эндпоинтов
- `test_auth.py` - тестирование роутеров аутентификации
- `test_dao.py` - тестирование работы с базой данных
- `test_integration.py` - полные сценарии использования

### Performance тесты
- `test_performance.py` - тесты производительности и нагрузки

## Установка зависимостей

```bash
# Установка основных зависимостей
uv sync
# Установка тестовых зависимостей
uv pip install -r tests/requirements-test.txt
```

## Запуск тестов

### Все тесты
```bash
pytest tests/ -v
```

### Только unit тесты
```bash
pytest tests/ -v -m "not integration and not slow"
```

### Только интеграционные тесты
```bash
pytest tests/test_integration.py -v
```

### Тесты с покрытием кода
```bash
pytest tests/ --cov=app --cov-report=term-missing --cov-report=html
```

### Тесты производительности
```bash
pytest tests/test_performance.py -v -m slow
```

### Параллельный запуск тестов
```bash
pytest tests/ -n auto
```

## Использование Makefile

Для удобства можно использовать команды из Makefile:

```bash
# Показать все доступные команды
make help

# Установить зависимости
make install

# Запустить все тесты
make test

# Запустить только unit тесты
make test-unit

# Запустить интеграционные тесты
make test-integration

# Запустить тесты с покрытием
make test-cov

# Запустить тесты с HTML отчетом
make test-html

# Очистить временные файлы
make clean
```

## Конфигурация тестов

### pytest.ini
Основная конфигурация pytest находится в файле `pytest.ini` в корне проекта.

### Фикстуры
Основные фикстуры определены в `conftest.py`:

- `db_session` - тестовая сессия базы данных
- `client` - HTTP клиент для тестирования API
- `test_user` - тестовый пользователь
- `test_admin_user` - тестовый администратор
- `test_role` - тестовая роль пользователя
- `user_data` - данные для регистрации пользователя

### Тестовая база данных
Тесты используют SQLite в памяти для изоляции и скорости выполнения.

## Маркеры тестов

- `@pytest.mark.asyncio` - асинхронные тесты
- `@pytest.mark.integration` - интеграционные тесты
- `@pytest.mark.slow` - медленные тесты (производительность)

## Отчеты

### HTML отчет
```bash
pytest tests/ --html=reports/report.html --self-contained-html
```

### Покрытие кода
```bash
pytest tests/ --cov=app --cov-report=html
```
Отчет будет доступен в `htmlcov/index.html`

## Лучшие практики

1. **Изоляция тестов** - каждый тест должен быть независимым
2. **Использование фикстур** - для подготовки тестовых данных
3. **Понятные имена** - тесты должны четко описывать что проверяется
4. **Проверка граничных случаев** - тестирование edge cases
5. **Мокирование внешних зависимостей** - для изоляции тестируемого кода

## Примеры запуска

```bash
# Запуск конкретного теста
pytest tests/test_auth.py::TestAuthRouter::test_register_user_success -v

# Запуск тестов с определенным маркером
pytest tests/ -m "not slow" -v

# Запуск тестов с выводом print statements
pytest tests/ -v -s

# Запуск тестов с остановкой на первой ошибке
pytest tests/ -v -x

# Запуск тестов с подробным выводом ошибок
pytest tests/ -v --tb=long
```

## Отладка тестов

Для отладки тестов можно использовать:

```python
import pytest

def test_something():
    # Точка останова для отладки
    pytest.set_trace()
    
    # Ваш тестовый код
    assert True
```

## CI/CD интеграция

Тесты готовы для интеграции с CI/CD системами. Пример для GitHub Actions:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.12
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r tests/requirements-test.txt
    - name: Run tests
      run: pytest tests/ --cov=app --cov-report=xml
    - name: Upload coverage
      uses: codecov/codecov-action@v1
```
