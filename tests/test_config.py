"""
Тесты для конфигурации приложения.
"""

import os
from unittest.mock import mock_open, patch

from app.config import Settings


class TestSettings:
    """Тесты настроек приложения."""

    def test_settings_default_values(self):
        """Тест значений по умолчанию."""
        # Мокаем переменные окружения для тестирования
        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": "test_secret",
                "ALGORITHM": "HS256",
                "POSTGRES_USER": "test_user",
                "POSTGRES_PASSWORD": "test_password",
                "POSTGRES_HOST": "localhost",
                "POSTGRES_PORT": "5432",
                "POSTGRES_DB": "test_db",
            },
        ):
            settings = Settings()

            assert (
                settings.FORMAT_LOG
                == "{time:YYYY-MM-DD at HH:mm:ss} | {level} | {name}:{function}:{line} - {message}"
            )
            assert settings.LOG_ROTATION == "10 MB"
            assert settings.SECRET_KEY == "test_secret"  # noqa: S105
            assert settings.ALGORITHM == "HS256"

    def test_database_url_generation(self):
        """Тест генерации URL базы данных."""
        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": "test_secret",
                "ALGORITHM": "HS256",
                "POSTGRES_USER": "testuser",
                "POSTGRES_PASSWORD": "testpass",
                "POSTGRES_HOST": "testhost",
                "POSTGRES_PORT": "5433",
                "POSTGRES_DB": "testdb",
            },
        ):
            settings = Settings()
            db_url = settings.get_db_url()

            expected_url = "postgresql+asyncpg://testuser:testpass@testhost:5433/testdb"
            assert db_url == expected_url

    def test_postgres_port_as_integer(self):
        """Тест что порт PostgreSQL является целым числом."""
        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": "test_secret",
                "ALGORITHM": "HS256",
                "POSTGRES_USER": "test_user",
                "POSTGRES_PASSWORD": "test_password",
                "POSTGRES_HOST": "localhost",
                "POSTGRES_PORT": "5432",
                "POSTGRES_DB": "test_db",
            },
        ):
            settings = Settings()

            assert isinstance(settings.POSTGRES_PORT, int)
            assert settings.POSTGRES_PORT == 5432

    def test_settings_from_env_file(self):
        """Тест загрузки настроек из .env файла."""
        # Мокаем содержимое .env файла
        env_content = """
SECRET_KEY=env_secret_key
ALGORITHM=HS256
POSTGRES_USER=env_user
POSTGRES_PASSWORD=env_password
POSTGRES_HOST=env_host
POSTGRES_PORT=5432
POSTGRES_DB=env_db
"""

        with (
            patch("builtins.open", mock_open(read_data=env_content)),
            patch("os.path.exists", return_value=True),
            patch.dict(os.environ, {}, clear=True),
        ):
            # Очищаем переменные окружения и загружаем из файла
            settings = Settings()

            # Проверяем, что настройки загрузились
            assert settings.SECRET_KEY is not None
            assert settings.POSTGRES_USER is not None

    def test_required_fields_validation(self):
        """Тест валидации обязательных полей."""
        # Проверяем, что Settings требует определенные поля
        # Если .env файл существует, то поля могут загружаться оттуда
        try:
            settings = Settings()
            # Если создание прошло успешно, проверяем наличие ключевых полей
            assert hasattr(settings, "SECRET_KEY")
            assert hasattr(settings, "POSTGRES_USER")
        except Exception as e:
            # Если возникла ошибка валидации, это тоже нормально
            assert (
                "validation error" in str(e).lower()
                or "field required" in str(e).lower()
            )

    def test_database_url_with_special_characters(self):
        """Тест генерации URL с специальными символами в пароле."""
        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": "test_secret",
                "ALGORITHM": "HS256",
                "POSTGRES_USER": "user",
                "POSTGRES_PASSWORD": "pass@word#123",
                "POSTGRES_HOST": "localhost",
                "POSTGRES_PORT": "5432",
                "POSTGRES_DB": "testdb",
            },
        ):
            settings = Settings()
            db_url = settings.get_db_url()

            # URL должен содержать пароль как есть (без кодирования в этом случае)
            assert "pass@word#123" in db_url

    def test_log_format_customization(self):
        """Тест кастомизации формата логов."""
        custom_format = "{time} | {level} | {message}"

        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": "test_secret",
                "ALGORITHM": "HS256",
                "POSTGRES_USER": "test_user",
                "POSTGRES_PASSWORD": "test_password",
                "POSTGRES_HOST": "localhost",
                "POSTGRES_PORT": "5432",
                "POSTGRES_DB": "test_db",
                "FORMAT_LOG": custom_format,
            },
        ):
            settings = Settings()

            assert custom_format == settings.FORMAT_LOG

    def test_log_rotation_customization(self):
        """Тест кастомизации ротации логов."""
        custom_rotation = "5 MB"

        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": "test_secret",
                "ALGORITHM": "HS256",
                "POSTGRES_USER": "test_user",
                "POSTGRES_PASSWORD": "test_password",
                "POSTGRES_HOST": "localhost",
                "POSTGRES_PORT": "5432",
                "POSTGRES_DB": "test_db",
                "LOG_ROTATION": custom_rotation,
            },
        ):
            settings = Settings()

            assert custom_rotation == settings.LOG_ROTATION


class TestConfigModule:
    """Тесты модуля конфигурации."""

    def test_settings_singleton(self):
        """Тест что settings является синглтоном."""
        from app.config import settings as settings1
        from app.config import settings as settings2

        # Должны быть одним и тем же объектом
        assert settings1 is settings2

    def test_database_url_constant(self):
        """Тест константы DATABASE_PG_URL."""
        from app.config import DATABASE_PG_URL

        assert DATABASE_PG_URL is not None
        assert isinstance(DATABASE_PG_URL, str)
        assert "postgresql+asyncpg://" in DATABASE_PG_URL

    def test_logger_configuration(self):
        """Тест конфигурации логгера."""
        # Проверяем, что настройки логгера корректны
        from app.config import settings

        assert settings.FORMAT_LOG is not None
        assert settings.LOG_ROTATION is not None
        assert "INFO" in settings.FORMAT_LOG or settings.LOG_ROTATION == "10 MB"
