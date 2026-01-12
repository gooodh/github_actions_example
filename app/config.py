import os

from loguru import logger
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    FORMAT_LOG: str = (
        "{time:YYYY-MM-DD at HH:mm:ss} | {level} | {name}:{function}:{line} - {message}"
    )
    LOG_ROTATION: str = "10 MB"

    SECRET_KEY: str = "test-secret-key"  # noqa: S105
    ALGORITHM: str = "HS256"

    POSTGRES_USER: str = "test"
    POSTGRES_PASSWORD: str = "test"  # noqa: S105
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "test"

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    )

    def get_db_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


# Получаем параметры для загрузки переменных среды
settings = Settings()

# Инициализация логирования только если не в тестовом режиме
if "pytest" not in os.environ.get("_", "") and "PYTEST_CURRENT_TEST" not in os.environ:
    log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.log")
    logger.add(
        log_file_path,
        format=settings.FORMAT_LOG,
        level="INFO",
        rotation=settings.LOG_ROTATION,
    )

DATABASE_PG_URL = settings.get_db_url()
