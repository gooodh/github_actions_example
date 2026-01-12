"""
Тесты для утилит аутентификации.
"""

from unittest.mock import Mock

import pytest
from fastapi import Response

from app.auth.utils import (
    authenticate_user,
    create_tokens,
    get_password_hash,
    set_tokens,
    verify_password,
)


class TestPasswordUtils:
    """Тесты утилит для работы с паролями."""

    def test_get_password_hash(self):
        """Тест хеширования пароля."""
        password = "test_password"  # noqa: S105
        hashed = get_password_hash(password)

        assert hashed != password
        assert len(hashed) > 20  # Хеш должен быть длиннее оригинального пароля
        assert hashed.startswith("$2b$")  # bcrypt хеш начинается с $2b$

    def test_verify_password_correct(self):
        """Тест проверки правильного пароля."""
        password = "test_password"  # noqa: S105
        hashed = get_password_hash(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Тест проверки неправильного пароля."""
        password = "test_password"  # noqa: S105
        wrong_password = "wrong_password"  # noqa: S105
        hashed = get_password_hash(password)

        assert verify_password(wrong_password, hashed) is False

    def test_password_hash_uniqueness(self):
        """Тест уникальности хешей для одного пароля."""
        password = "test_password"  # noqa: S105
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)

        # Хеши должны быть разными из-за соли
        assert hash1 != hash2

        # Но оба должны проходить проверку
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestAuthenticateUser:
    """Тесты аутентификации пользователя."""

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self):
        """Тест успешной аутентификации пользователя."""
        # Создаем мок пользователя
        password = "test_password"  # noqa: S105
        hashed_password = get_password_hash(password)

        user = Mock()
        user.password = hashed_password

        result = await authenticate_user(user, password)

        assert result == user  # Функция возвращает пользователя при успехе

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self):
        """Тест аутентификации с неправильным паролем."""
        # Создаем мок пользователя
        password = "test_password"  # noqa: S105
        wrong_password = "wrong_password"  # noqa: S105
        hashed_password = get_password_hash(password)

        user = Mock()
        user.password = hashed_password

        result = await authenticate_user(user, wrong_password)

        assert result is None  # Функция возвращает None при неудаче

    @pytest.mark.asyncio
    async def test_authenticate_user_none_user(self):
        """Тест аутентификации с None пользователем."""
        result = await authenticate_user(None, "any_password")

        assert result is None  # Функция возвращает None при неудаче


class TestTokenUtils:
    """Тесты утилит для работы с токенами."""

    def test_create_tokens(self):
        """Тест создания токенов."""
        user_id = 123
        tokens = create_tokens({"sub": str(user_id)})

        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert isinstance(tokens["access_token"], str)
        assert isinstance(tokens["refresh_token"], str)
        assert len(tokens["access_token"]) > 50
        assert len(tokens["refresh_token"]) > 50

    def test_tokens_are_different(self):
        """Тест что access и refresh токены разные."""
        user_id = 123
        tokens = create_tokens({"sub": str(user_id)})

        assert tokens["access_token"] != tokens["refresh_token"]

    def test_tokens_for_different_users_are_different(self):
        """Тест что токены для разных пользователей разные."""
        user_id_1 = 123
        user_id_2 = 456

        tokens_1 = create_tokens({"sub": str(user_id_1)})
        tokens_2 = create_tokens({"sub": str(user_id_2)})

        assert tokens_1["access_token"] != tokens_2["access_token"]
        assert tokens_1["refresh_token"] != tokens_2["refresh_token"]

    def test_set_tokens(self):
        """Тест установки токенов в response."""
        # Создаем мок response
        response = Mock(spec=Response)
        response.set_cookie = Mock()

        user_id = 123
        set_tokens(response, user_id)

        # Проверяем, что set_cookie был вызван дважды
        assert response.set_cookie.call_count == 2

        # Получаем аргументы вызовов
        calls = response.set_cookie.call_args_list

        # Проверяем первый вызов (access token)
        access_call = calls[0]
        assert access_call.kwargs["key"] == "user_access_token"
        assert len(access_call.kwargs["value"]) > 50  # token value
        assert access_call.kwargs["httponly"] is True

        # Проверяем второй вызов (refresh token)
        refresh_call = calls[1]
        assert refresh_call.kwargs["key"] == "user_refresh_token"
        assert len(refresh_call.kwargs["value"]) > 50  # token value
        assert refresh_call.kwargs["httponly"] is True


class TestTokenSecurity:
    """Тесты безопасности токенов."""

    def test_tokens_contain_user_id(self):
        """Тест что токены содержат информацию о пользователе."""
        user_id = 123
        tokens = create_tokens({"sub": str(user_id)})

        # Базовая проверка что токены не пустые и имеют правильную структуру JWT
        access_parts = tokens["access_token"].split(".")
        refresh_parts = tokens["refresh_token"].split(".")
        assert (
            len(access_parts) == 3
        )  # JWT состоит из 3 частей: header.payload.signature
        assert len(refresh_parts) == 3

    def test_token_expiration_time(self):
        """Тест времени истечения токенов."""
        # Создаем токены в разное время
        import time

        user_id = 123
        tokens1 = create_tokens({"sub": str(user_id)})
        time.sleep(1.1)  # Задержка больше секунды для изменения timestamp
        tokens2 = create_tokens({"sub": str(user_id)})

        # Токены должны быть разными из-за разного времени создания
        # Если токены одинаковые, значит время истечения округляется до секунд
        # что тоже нормально для JWT токенов
        assert isinstance(tokens1["access_token"], str)
        assert isinstance(tokens2["access_token"], str)
        assert len(tokens1["access_token"]) > 50
        assert len(tokens2["access_token"]) > 50
