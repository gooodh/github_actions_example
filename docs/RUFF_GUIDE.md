# Руководство по Ruff

## Что такое Ruff?

Ruff - это современный, очень быстрый линтер и форматтер для Python, написанный на Rust. Он заменяет множество инструментов:

- **flake8** (линтинг)
- **black** (форматирование)
- **isort** (сортировка импортов)
- **bandit** (проверки безопасности)
- **pyupgrade** (обновление синтаксиса)
- **autoflake** (удаление неиспользуемых импортов)
- И многие другие!

## Основные команды

### Линтинг (проверка ошибок)
```bash
# Проверить код
ruff check app/ tests/

# Проверить и исправить автоматически исправимые ошибки
ruff check app/ tests/ --fix

# Показать различия без применения изменений
ruff check app/ tests/ --diff
```

### Форматирование
```bash
# Отформатировать код
ruff format app/ tests/

# Проверить форматирование без изменений
ruff format --check app/ tests/

# Показать различия
ruff format --diff app/ tests/
```

### Специфичные проверки
```bash
# Только проверки безопасности
ruff check app/ tests/ --select S

# Только проверки импортов
ruff check app/ tests/ --select I

# Исключить определенные правила
ruff check app/ tests/ --ignore E501,F401
```

## Конфигурация в pyproject.toml

```toml
[tool.ruff]
line-length = 88
target-version = "py312"

[tool.ruff.lint]
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "I",   # isort
    "B",   # flake8-bugbear
    "C4",  # flake8-comprehensions
    "UP",  # pyupgrade
    "S",   # bandit (security)
]

ignore = [
    "E501",  # line too long (handled by formatter)
    "S101",  # use of assert detected
]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101"]  # Allow assert in tests
"app/migration/versions/*" = ["ALL"]  # Ignore all rules for migration files

[tool.ruff.format]
quote-style = "double"
indent-style = "space"
```

## Основные правила

### Категории правил:
- **E, W** - pycodestyle (стиль кода)
- **F** - pyflakes (логические ошибки)
- **I** - isort (сортировка импортов)
- **B** - bugbear (потенциальные баги)
- **S** - bandit (безопасность)
- **UP** - pyupgrade (современный синтаксис)
- **C4** - comprehensions (оптимизация списков/словарей)
- **SIM** - simplify (упрощение кода)

### Примеры проверок:

**Безопасность (S):**
```python
# ❌ Плохо
password = "hardcoded_password"
exec(user_input)

# ✅ Хорошо
password = os.getenv("PASSWORD")
# Не используйте exec() с пользовательским вводом
```

**Современный синтаксис (UP):**
```python
# ❌ Старый синтаксис
from typing import List, Dict
def process_data(items: List[str]) -> Dict[str, int]:
    pass

# ✅ Современный синтаксис (Python 3.9+)
def process_data(items: list[str]) -> dict[str, int]:
    pass
```

**Оптимизация (C4):**
```python
# ❌ Неэффективно
result = []
for item in items:
    if condition(item):
        result.append(transform(item))

# ✅ Эффективно
result = [transform(item) for item in items if condition(item)]
```

## Интеграция с редакторами

### VS Code
Установите расширение "Ruff" и добавьте в settings.json:
```json
{
    "[python]": {
        "editor.defaultFormatter": "charliermarsh.ruff",
        "editor.codeActionsOnSave": {
            "source.organizeImports": true,
            "source.fixAll": true
        }
    }
}
```

### PyCharm
Настройте External Tools:
- Program: `ruff`
- Arguments: `check $FilePath$ --fix`
- Working directory: `$ProjectFileDir$`

## Миграция с других инструментов

### Замена flake8
```bash
# Было
flake8 app/ tests/ --max-line-length=88

# Стало
ruff check app/ tests/
```

### Замена black + isort
```bash
# Было
black app/ tests/
isort app/ tests/

# Стало
ruff format app/ tests/
ruff check app/ tests/ --select I --fix
```

### Замена bandit
```bash
# Было
bandit -r app/

# Стало
ruff check app/ --select S
```

## Производительность

Ruff работает в **10-100 раз быстрее** традиционных инструментов:

```bash
# Время выполнения на большом проекте:
# flake8 + black + isort: ~30 секунд
# ruff: ~0.3 секунды
```

## Полезные команды для разработки

```bash
# Проверить весь проект
make lint

# Исправить все автоматически исправимые ошибки
make format

# Запустить только быстрые проверки
ruff check app/ --select F,E9

# Показать статистику по правилам
ruff check app/ --statistics

# Проверить конкретный файл
ruff check app/main.py

# Игнорировать правило в конкретной строке
# ruff: noqa: E501
very_long_line = "This line is too long but we need it for some reason"

# Игнорировать правило в файле
# ruff: noqa: F401
import unused_module
```

## Исключение файлов и папок

### Исключение целых директорий
Добавьте пути в секцию `exclude`:
```toml
[tool.ruff]
exclude = [
    "migrations",
    "app/migration/versions",  # Файлы миграций Alembic
    "build",
    "dist",
]
```

### Исключение правил для конкретных файлов
Используйте `per-file-ignores`:
```toml
[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101"]  # Разрешить assert в тестах
"app/migration/versions/*" = ["ALL"]  # Игнорировать все правила для миграций
"__init__.py" = ["F401"]  # Разрешить неиспользуемые импорты
```

### Исключение правил в коде
```python
# Игнорировать правило в конкретной строке
password = "hardcoded"  # ruff: noqa: S105

# Игнорировать несколько правил
import unused_module  # ruff: noqa: F401, I001

# Игнорировать все правила в строке
some_complex_code()  # ruff: noqa

# Игнорировать правило в файле (в начале файла)
# ruff: noqa: F401
import lots_of_unused_modules
```

## Troubleshooting

### Конфликт с существующими инструментами
Если у вас уже настроены black/flake8/isort, удалите их конфигурации:
- `.flake8`
- `setup.cfg` (секции flake8/isort)
- `pyproject.toml` (секции tool.black, tool.isort)

### Слишком много ошибок
Начните с базовых правил и постепенно добавляйте:
```toml
[tool.ruff.lint]
select = ["E", "F"]  # Только основные ошибки
```

### Настройка для legacy кода
```toml
[tool.ruff.lint]
ignore = [
    "E501",  # line too long
    "F401",  # unused imports
    "F841",  # unused variables
]
```

Ruff значительно ускоряет разработку и делает код более качественным и безопасным!