"""
Тесты для схем Pydantic.
"""

import pytest
from pydantic import ValidationError

from app.auth.schemas import (
    EmailModel,
    RoleAddModel,
    SUserAuth,
    SUserInfo,
    SUserRegister,
    UserBase,
)


class TestUserSchemas:
    """Тесты схем пользователя."""

    def test_email_model_valid(self):
        """Тест валидного email."""
        email = EmailModel(email="test@example.com")
        assert email.email == "test@example.com"

    def test_email_model_invalid(self):
        """Тест невалидного email."""
        with pytest.raises(ValidationError):
            EmailModel(email="invalid_email")

    def test_user_base_valid_phone(self):
        """Тест валидного номера телефона."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+1234567890",
            "first_name": "Тест",
            "last_name": "Пользователь",
        }
        user = UserBase(**user_data)
        assert user.phone_number == "+1234567890"

    def test_user_base_invalid_phone_no_plus(self):
        """Тест номера телефона без плюса."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "1234567890",
            "first_name": "Тест",
            "last_name": "Пользователь",
        }
        with pytest.raises(ValidationError) as exc_info:
            UserBase(**user_data)

        assert "должен начинаться с" in str(exc_info.value)

    def test_user_base_invalid_phone_too_short(self):
        """Тест слишком короткого номера телефона."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+123",
            "first_name": "Тест",
            "last_name": "Пользователь",
        }
        with pytest.raises(ValidationError):
            UserBase(**user_data)

    def test_user_base_invalid_phone_too_long(self):
        """Тест слишком длинного номера телефона."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+1234567890123456",
            "first_name": "Тест",
            "last_name": "Пользователь",
        }
        with pytest.raises(ValidationError):
            UserBase(**user_data)

    def test_user_base_short_names(self):
        """Тест слишком коротких имени и фамилии."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+1234567890",
            "first_name": "A",  # Слишком короткое
            "last_name": "B",  # Слишком короткое
        }
        with pytest.raises(ValidationError):
            UserBase(**user_data)

    def test_user_register_valid(self):
        """Тест валидной регистрации пользователя."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+1234567890",
            "first_name": "Тест",
            "last_name": "Пользователь",
            "password": "password123",
            "confirm_password": "password123",
        }
        user = SUserRegister(**user_data)

        assert user.email == "test@example.com"
        assert user.first_name == "Тест"
        # Пароль должен быть захеширован
        assert user.password != "password123"  # noqa: S105
        assert len(user.password) > 20  # Хеш длиннее оригинального пароля

    def test_user_register_password_mismatch(self):
        """Тест несовпадения паролей при регистрации."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+1234567890",
            "first_name": "Тест",
            "last_name": "Пользователь",
            "password": "password123",
            "confirm_password": "different_password",
        }
        with pytest.raises(ValidationError) as exc_info:
            SUserRegister(**user_data)

        assert "не совпадают" in str(exc_info.value)

    def test_user_register_short_password(self):
        """Тест слишком короткого пароля."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+1234567890",
            "first_name": "Тест",
            "last_name": "Пользователь",
            "password": "123",
            "confirm_password": "123",
        }
        with pytest.raises(ValidationError):
            SUserRegister(**user_data)

    def test_user_auth_valid(self):
        """Тест валидной схемы авторизации."""
        auth_data = {"email": "test@example.com", "password": "password123"}
        auth = SUserAuth(**auth_data)

        assert auth.email == "test@example.com"
        assert auth.password == "password123"  # noqa: S105

    def test_role_add_model(self):
        """Тест схемы добавления роли."""
        role_data = {"name": "admin"}
        role = RoleAddModel(**role_data)

        assert role.name == "admin"

    def test_user_info_computed_fields(self):
        """Тест вычисляемых полей в SUserInfo."""

        # Создаем мок роли
        class MockRole:
            id = 1
            name = "admin"

        user_data = {
            "id": 1,
            "email": "test@example.com",
            "phone_number": "+1234567890",
            "first_name": "Тест",
            "last_name": "Пользователь",
            "role": MockRole(),
        }

        user_info = SUserInfo(**user_data)

        assert user_info.role_name == "admin"
        assert user_info.role_id == 1


class TestSchemaValidation:
    """Тесты валидации схем."""

    def test_phone_number_with_letters(self):
        """Тест номера телефона с буквами."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+123abc7890",
            "first_name": "Тест",
            "last_name": "Пользователь",
        }
        with pytest.raises(ValidationError):
            UserBase(**user_data)

    def test_phone_number_with_spaces(self):
        """Тест номера телефона с пробелами."""
        user_data = {
            "email": "test@example.com",
            "phone_number": "+123 456 7890",
            "first_name": "Тест",
            "last_name": "Пользователь",
        }
        with pytest.raises(ValidationError):
            UserBase(**user_data)

    def test_empty_required_fields(self):
        """Тест пустых обязательных полей."""
        with pytest.raises(ValidationError):
            UserBase(email="", phone_number="", first_name="", last_name="")

    def test_none_values(self):
        """Тест None значений."""
        with pytest.raises(ValidationError):
            UserBase(email=None, phone_number=None, first_name=None, last_name=None)
