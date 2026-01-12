# Makefile для управления тестами и разработкой

.PHONY: help install test test-unit test-integration test-cov test-html clean lint format

help:  ## Показать справку
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Установить зависимости
	pip install -r requirements.txt
	pip install -r tests/requirements-test.txt

test:  ## Запустить все тесты
	pytest tests/ -v

test-unit:  ## Запустить только unit тесты
	pytest tests/ -v -m "not integration"

test-integration:  ## Запустить только интеграционные тесты
	pytest tests/test_integration.py -v

test-cov:  ## Запустить тесты с покрытием кода
	pytest tests/ --cov=app --cov-report=term-missing --cov-report=html

test-html:  ## Запустить тесты с HTML отчетом
	pytest tests/ --html=reports/report.html --self-contained-html

test-parallel:  ## Запустить тесты параллельно
	pytest tests/ -n auto

test-watch:  ## Запустить тесты в режиме наблюдения (требует pytest-watch)
	ptw tests/ app/

clean:  ## Очистить временные файлы
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf reports
	rm -rf .coverage

lint:  ## Проверить код линтером
	ruff check app/ tests/
	ruff format --check app/ tests/

format:  ## Отформатировать код
	ruff check app/ tests/ --fix
	ruff format app/ tests/

run:  ## Запустить приложение
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run-prod:  ## Запустить приложение в продакшн режиме
	uvicorn app.main:app --host 0.0.0.0 --port 8000

docker-build:  ## Собрать Docker образ
	docker build -t fastapi-app .

docker-run:  ## Запустить приложение в Docker
	docker-compose up -d

docker-test:  ## Запустить тесты в Docker
	docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit

setup-dev:  ## Настроить среду разработки
	python -m venv .venv
	source .venv/bin/activate && pip install -r requirements.txt
	source .venv/bin/activate && pip install -r tests/requirements-test.txt

ci-install:  ## Установить зависимости для CI
	pip install -r requirements.txt
	pip install -r tests/requirements-test.txt
	pip install ruff mypy safety

ci-test:  ## Запустить тесты для CI
	pytest tests/ -v --cov=app --cov-report=xml --cov-report=term-missing

ci-lint:  ## Проверить код для CI
	ruff check app/ tests/ || true
	ruff format --check app/ tests/
	mypy app/ --ignore-missing-imports || true

ci-security:  ## Проверить безопасность для CI
	ruff check app/ tests/ --select S
	safety check

pre-commit-install:  ## Установить pre-commit хуки
	pip install pre-commit
	pre-commit install

pre-commit-run:  ## Запустить pre-commit на всех файлах
	pre-commit run --all-files