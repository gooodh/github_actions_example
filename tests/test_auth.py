"""
Тесты для модуля аутентификации.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dao import RoleDAO, UsersDAO
from app.auth.schemas import EmailModel


class TestAuthRouter:
    """Тесты роутера аутентификации."""

    @pytest.mark.asyncio
    async def test_register_user_success(
        self, client: AsyncClient, user_data, test_role
    ):
        """Тест успешной регистрации пользователя."""
        response = await client.post("/auth/register/", json=user_data)

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Вы успешно зарегистрированы!"

    @pytest.mark.asyncio
    async def test_register_user_already_exists(
        self, client: AsyncClient, user_data, test_user, test_role
    ):
        """Тест регистрации уже существующего пользователя."""
        # Используем email существующего пользователя
        user_data["email"] = test_user.email

        response = await client.post("/auth/register/", json=user_data)

        assert response.status_code == 409
        data = response.json()
        assert "уже существует" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_user_invalid_data(
        self, client: AsyncClient, invalid_user_data, test_role
    ):
        """Тест регистрации с невалидными данными."""
        response = await client.post("/auth/register/", json=invalid_user_data)

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient, test_user):
        """Тест успешной авторизации."""
        login_data = {"email": test_user.email, "password": "testpassword"}

        response = await client.post("/auth/login/", json=login_data)

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["message"] == "Авторизация успешна!"

        # Проверяем наличие cookies
        assert "user_access_token" in response.cookies
        assert "user_refresh_token" in response.cookies

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient, test_user):
        """Тест авторизации с неверным паролем."""
        login_data = {"email": test_user.email, "password": "wrongpassword"}

        response = await client.post("/auth/login/", json=login_data)

        assert (
            response.status_code == 400
        )  # IncorrectEmailOrPasswordException возвращает 400

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Тест авторизации несуществующего пользователя."""
        login_data = {"email": "nonexistent@example.com", "password": "password"}

        response = await client.post("/auth/login/", json=login_data)

        assert (
            response.status_code == 400
        )  # IncorrectEmailOrPasswordException возвращает 400

    @pytest.mark.asyncio
    async def test_logout(self, client: AsyncClient):
        """Тест выхода из системы."""
        response = await client.post("/auth/logout")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Пользователь успешно вышел из системы"

    @pytest.mark.asyncio
    async def test_get_me_unauthorized(self, client: AsyncClient):
        """Тест получения информации о пользователе без авторизации."""
        response = await client.get("/auth/me/")

        assert response.status_code == 400  # TokenNoFound возвращает 400

    @pytest.mark.asyncio
    async def test_get_all_users_unauthorized(self, client: AsyncClient):
        """Тест получения всех пользователей без авторизации."""
        response = await client.get("/auth/all_users/")

        assert response.status_code == 400  # TokenNoFound возвращает 400

    @pytest.mark.asyncio
    async def test_add_role_unauthorized(self, client: AsyncClient):
        """Тест добавления роли без авторизации."""
        role_data = {"name": "new_role"}
        response = await client.post("/auth/addroles", json=role_data)

        assert response.status_code == 400  # TokenNoFound возвращает 400


class TestAuthDAO:
    """Тесты DAO для аутентификации."""

    @pytest.mark.asyncio
    async def test_users_dao_find_by_email(self, db_session: AsyncSession, test_user):
        """Тест поиска пользователя по email."""
        users_dao = UsersDAO(db_session)

        user = await users_dao.find_one_or_none(
            filters=EmailModel(email=test_user.email)
        )

        assert user is not None
        assert user.email == test_user.email
        assert user.first_name == test_user.first_name

    @pytest.mark.asyncio
    async def test_users_dao_find_nonexistent(self, db_session: AsyncSession):
        """Тест поиска несуществующего пользователя."""
        users_dao = UsersDAO(db_session)

        user = await users_dao.find_one_or_none(
            filters=EmailModel(email="nonexistent@example.com")
        )

        assert user is None

    @pytest.mark.asyncio
    async def test_role_dao_create_role(self, db_session: AsyncSession):
        """Тест создания роли."""
        role_dao = RoleDAO(db_session)

        from app.auth.schemas import RoleAddModel

        role_data = RoleAddModel(name="test_role")

        new_role = await role_dao.add(values=role_data)
        await db_session.commit()

        assert new_role.name == "test_role"
        assert new_role.id is not None

    @pytest.mark.asyncio
    async def test_role_dao_find_all(
        self, db_session: AsyncSession, test_role, test_admin_role
    ):
        """Тест получения всех ролей."""
        role_dao = RoleDAO(db_session)

        roles = await role_dao.find_all()

        assert len(roles) >= 2
        role_names = [role.name for role in roles]
        assert "user" in role_names
        assert "admin" in role_names


class TestAuthModels:
    """Тесты моделей аутентификации."""

    def test_user_repr(self, test_user):
        """Тест строкового представления пользователя."""
        repr_str = repr(test_user)
        assert "User" in repr_str
        assert str(test_user.id) in repr_str

    def test_role_repr(self, test_role):
        """Тест строкового представления роли."""
        repr_str = repr(test_role)
        assert "Role" in repr_str
        assert test_role.name in repr_str
        assert str(test_role.id) in repr_str

    @pytest.mark.asyncio
    async def test_user_role_relationship(
        self, db_session: AsyncSession, test_user, test_role
    ):
        """Тест связи пользователя с ролью."""
        # Обновляем объект из БД для загрузки связей
        await db_session.refresh(test_user)

        assert test_user.role is not None
        assert test_user.role.name == test_role.name
        assert test_user.role_id == test_role.id
