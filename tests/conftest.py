"""
Конфигурация тестов для FastAPI приложения.
"""

import asyncio

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.auth.models import Role, User
from app.auth.utils import get_password_hash
from app.dao.database import Base
from app.dependencies.dao_dep import get_session_with_commit, get_session_without_commit
from app.main import create_app


# Тестовая база данных в памяти
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# Создание тестового движка
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    poolclass=StaticPool,
    connect_args={"check_same_thread": False},
    echo=False,
)

# Создание тестовой сессии
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest.fixture(scope="session")
def event_loop():
    """Создание event loop для всей сессии тестов."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """Создание тестовой сессии базы данных."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session
        await session.rollback()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client(db_session):
    """Создание тестового HTTP клиента."""
    app = create_app()

    # Переопределение зависимостей для использования тестовой БД
    app.dependency_overrides[get_session_with_commit] = lambda: db_session
    app.dependency_overrides[get_session_without_commit] = lambda: db_session

    # Используем новый API httpx для работы с ASGI приложениями
    try:
        # Для новых версий httpx (0.24+)
        from httpx import ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    except ImportError:
        # Для старых версий httpx
        async with AsyncClient(app=app, base_url="http://test") as ac:
            yield ac


@pytest_asyncio.fixture
async def test_role(db_session):
    """Создание тестовой роли."""
    role = Role(name="user")
    db_session.add(role)
    await db_session.commit()
    await db_session.refresh(role)
    return role


@pytest_asyncio.fixture
async def test_admin_role(db_session):
    """Создание тестовой роли администратора."""
    role = Role(name="admin")
    db_session.add(role)
    await db_session.commit()
    await db_session.refresh(role)
    return role


@pytest_asyncio.fixture
async def test_user(db_session, test_role):
    """Создание тестового пользователя."""
    user = User(
        phone_number="+1234567890",
        first_name="Тест",
        last_name="Пользователь",
        email="test@example.com",
        password=get_password_hash("testpassword"),
        role_id=test_role.id,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_admin_user(db_session, test_admin_role):
    """Создание тестового администратора."""
    admin = User(
        phone_number="+1234567891",
        first_name="Админ",
        last_name="Пользователь",
        email="admin@example.com",
        password=get_password_hash("adminpassword"),
        role_id=test_admin_role.id,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)
    return admin


@pytest.fixture
def user_data():
    """Тестовые данные пользователя для регистрации."""
    return {
        "phone_number": "+1234567892",
        "first_name": "Новый",
        "last_name": "Пользователь",
        "email": "newuser@example.com",
        "password": "newpassword",
        "confirm_password": "newpassword",
    }


@pytest.fixture
def invalid_user_data():
    """Невалидные данные пользователя."""
    return {
        "phone_number": "invalid_phone",
        "first_name": "A",  # Слишком короткое имя
        "last_name": "B",  # Слишком короткая фамилия
        "email": "invalid_email",
        "password": "123",  # Слишком короткий пароль
        "confirm_password": "456",  # Не совпадает с паролем
    }
