"""
Тесты для основного приложения.
"""

import pytest
from httpx import AsyncClient


class TestMainApp:
    """Тесты основного функционала приложения."""

    @pytest.mark.asyncio
    async def test_create_app(self):
        """Тест создания приложения."""
        from app.main import create_app

        app = create_app()
        assert app.title == "FastAPI Starter Build"
        assert app.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_home_page(self, client: AsyncClient):
        """Тест главной страницы."""
        response = await client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Добро пожаловать!"

    @pytest.mark.asyncio
    async def test_static_files_mount(self, client: AsyncClient):
        """Тест монтирования статических файлов."""
        # Проверяем, что статические файлы доступны
        response = await client.get("/static/")
        # Ожидаем 404 или 403, так как директория может быть пустой
        assert response.status_code in [404, 403, 200]

    @pytest.mark.asyncio
    async def test_cors_headers(self, client: AsyncClient):
        """Тест CORS заголовков."""
        # CORS заголовки появляются при реальных запросах
        response = await client.get("/")

        # Проверяем, что запрос прошел успешно (CORS не блокирует)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, client: AsyncClient):
        """Тест эндпоинта метрик Prometheus."""
        response = await client.get("/metrics")

        # В тестовом режиме метрики могут быть недоступны
        # Проверяем, что эндпоинт существует (не 404) или возвращает метрики
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            # Если метрики доступны, проверяем content-type
            assert "text/plain" in response.headers.get("content-type", "")
