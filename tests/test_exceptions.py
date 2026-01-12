"""
Тесты для обработки исключений.
"""

import pytest
from fastapi import HTTPException

from app.exceptions import IncorrectEmailOrPasswordException, UserAlreadyExistsException


class TestCustomExceptions:
    """Тесты пользовательских исключений."""

    def test_user_already_exists_exception(self):
        """Тест исключения существующего пользователя."""
        with pytest.raises(HTTPException) as exc_info:
            raise UserAlreadyExistsException

        assert exc_info.value.status_code == 409
        assert "уже существует" in exc_info.value.detail.lower()

    def test_incorrect_email_or_password_exception(self):
        """Тест исключения неверного email или пароля."""
        with pytest.raises(HTTPException) as exc_info:
            raise IncorrectEmailOrPasswordException

        assert exc_info.value.status_code == 400
        assert (
            "неверн" in exc_info.value.detail.lower()
            or "incorrect" in exc_info.value.detail.lower()
        )

    def test_exception_inheritance(self):
        """Тест наследования исключений от HTTPException."""
        assert issubclass(type(UserAlreadyExistsException), HTTPException)
        assert issubclass(type(IncorrectEmailOrPasswordException), HTTPException)

    def test_exception_attributes(self):
        """Тест атрибутов исключений."""
        user_exists_exc = UserAlreadyExistsException
        incorrect_creds_exc = IncorrectEmailOrPasswordException

        # Проверяем, что исключения имеют правильные коды статуса
        assert user_exists_exc.status_code == 409
        assert incorrect_creds_exc.status_code == 400

        # Проверяем, что исключения имеют сообщения
        assert user_exists_exc.detail is not None
        assert incorrect_creds_exc.detail is not None
