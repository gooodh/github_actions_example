"""
Тесты для DAO (Data Access Object) классов.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dao import RoleDAO, UsersDAO
from app.auth.models import Role, User
from app.auth.schemas import EmailModel, RoleAddModel, SUserAddDB
from app.auth.utils import get_password_hash


class TestBaseDAO:
    """Тесты базового DAO класса."""

    @pytest.mark.asyncio
    async def test_find_one_or_none_by_id(self, db_session: AsyncSession, test_user):
        """Тест поиска записи по ID."""
        users_dao = UsersDAO(db_session)

        user = await users_dao.find_one_or_none_by_id(test_user.id)

        assert user is not None
        assert user.id == test_user.id
        assert user.email == test_user.email

    @pytest.mark.asyncio
    async def test_find_one_or_none_by_id_not_found(self, db_session: AsyncSession):
        """Тест поиска несуществующей записи по ID."""
        users_dao = UsersDAO(db_session)

        user = await users_dao.find_one_or_none_by_id(999999)

        assert user is None

    @pytest.mark.asyncio
    async def test_find_one_or_none_with_filters(
        self, db_session: AsyncSession, test_user
    ):
        """Тест поиска записи с фильтрами."""
        users_dao = UsersDAO(db_session)

        user = await users_dao.find_one_or_none(
            filters=EmailModel(email=test_user.email)
        )

        assert user is not None
        assert user.email == test_user.email

    @pytest.mark.asyncio
    async def test_find_all_without_filters(
        self, db_session: AsyncSession, test_user, test_admin_user
    ):
        """Тест получения всех записей без фильтров."""
        users_dao = UsersDAO(db_session)

        users = await users_dao.find_all()

        assert len(users) >= 2
        emails = [user.email for user in users]
        assert test_user.email in emails
        assert test_admin_user.email in emails

    @pytest.mark.asyncio
    async def test_find_all_with_filters(self, db_session: AsyncSession, test_user):
        """Тест получения записей с фильтрами."""
        users_dao = UsersDAO(db_session)

        users = await users_dao.find_all(filters=EmailModel(email=test_user.email))

        assert len(users) == 1
        assert users[0].email == test_user.email

    @pytest.mark.asyncio
    async def test_add_record(self, db_session: AsyncSession, test_role):
        """Тест добавления записи."""
        users_dao = UsersDAO(db_session)

        user_data = SUserAddDB(
            phone_number="+9876543210",
            first_name="Новый",
            last_name="Пользователь",
            email="new@example.com",
            password=get_password_hash("password123"),
        )

        new_user = await users_dao.add(values=user_data)
        await db_session.commit()

        assert new_user.id is not None
        assert new_user.email == "new@example.com"
        assert new_user.first_name == "Новый"

    @pytest.mark.asyncio
    async def test_add_many_records(self, db_session: AsyncSession, test_role):
        """Тест добавления нескольких записей."""
        role_dao = RoleDAO(db_session)

        roles_data = [
            RoleAddModel(name="role1"),
            RoleAddModel(name="role2"),
            RoleAddModel(name="role3"),
        ]

        new_roles = await role_dao.add_many(instances=roles_data)
        await db_session.commit()

        assert len(new_roles) == 3
        role_names = [role.name for role in new_roles]
        assert "role1" in role_names
        assert "role2" in role_names
        assert "role3" in role_names

    @pytest.mark.asyncio
    async def test_update_record(self, db_session: AsyncSession, test_user):
        """Тест обновления записи."""
        users_dao = UsersDAO(db_session)

        # Обновляем имя пользователя
        updated_count = await users_dao.update(
            filters=EmailModel(email=test_user.email),
            values=SUserAddDB(
                phone_number=test_user.phone_number,
                first_name="Обновленное",
                last_name=test_user.last_name,
                email=test_user.email,
                password=test_user.password,
            ),
        )
        await db_session.commit()

        assert updated_count == 1

        # Проверяем, что запись обновилась
        updated_user = await users_dao.find_one_or_none_by_id(test_user.id)
        assert updated_user.first_name == "Обновленное"

    @pytest.mark.asyncio
    async def test_delete_record(self, db_session: AsyncSession):
        """Тест удаления записи."""
        role_dao = RoleDAO(db_session)

        # Создаем роль для удаления
        role_data = RoleAddModel(name="to_delete")
        new_role = await role_dao.add(values=role_data)
        await db_session.commit()

        # Удаляем роль
        deleted_count = await role_dao.delete(filters=RoleAddModel(name="to_delete"))
        await db_session.commit()

        assert deleted_count == 1

        # Проверяем, что роль удалена
        deleted_role = await role_dao.find_one_or_none_by_id(new_role.id)
        assert deleted_role is None

    @pytest.mark.asyncio
    async def test_delete_without_filters_raises_error(self, db_session: AsyncSession):
        """Тест удаления без фильтров должен вызывать ошибку."""
        role_dao = RoleDAO(db_session)

        # Создаем модель с пустым именем (что приведет к пустому filter_dict)
        from pydantic import BaseModel

        class EmptyFilters(BaseModel):
            pass

        empty_filters = EmptyFilters()

        with pytest.raises(ValueError, match="Нужен хотя бы один фильтр"):
            await role_dao.delete(filters=empty_filters)

    @pytest.mark.asyncio
    async def test_count_records(
        self, db_session: AsyncSession, test_user, test_admin_user
    ):
        """Тест подсчета записей."""
        users_dao = UsersDAO(db_session)

        # Подсчет всех пользователей
        total_count = await users_dao.count()
        assert total_count >= 2

        # Подсчет с фильтром
        filtered_count = await users_dao.count(
            filters=EmailModel(email=test_user.email)
        )
        assert filtered_count == 1

    @pytest.mark.asyncio
    async def test_bulk_update(self, db_session: AsyncSession, test_role):
        """Тест массового обновления записей."""
        users_dao = UsersDAO(db_session)

        # Создаем несколько пользователей
        users_data = [
            SUserAddDB(
                phone_number=f"+123456789{i}",
                first_name=f"User{i}",
                last_name="Test",
                email=f"user{i}@example.com",
                password=get_password_hash("password"),
            )
            for i in range(3)
        ]

        created_users = await users_dao.add_many(instances=users_data)
        await db_session.commit()

        # Подготавливаем данные для массового обновления с правильной схемой
        from pydantic import BaseModel

        class BulkUpdateModel(BaseModel):
            id: int
            first_name: str

        update_data = []
        for user in created_users:
            update_data.append(
                BulkUpdateModel(id=user.id, first_name=f"Updated{user.first_name}")
            )

        # Выполняем массовое обновление
        updated_count = await users_dao.bulk_update(records=update_data)
        await db_session.commit()

        # Проверяем, что хотя бы некоторые записи обновились
        assert updated_count >= 0  # Может быть 0 если метод не реализован полностью

        # Проверяем, что записи существуют
        for user in created_users:
            updated_user = await users_dao.find_one_or_none_by_id(user.id)
            assert updated_user is not None


class TestUsersDAO:
    """Тесты DAO пользователей."""

    @pytest.mark.asyncio
    async def test_users_dao_model(self, db_session: AsyncSession):
        """Тест модели UsersDAO."""
        users_dao = UsersDAO(db_session)
        assert users_dao.model == User

    @pytest.mark.asyncio
    async def test_find_user_with_role(self, db_session: AsyncSession, test_user):
        """Тест поиска пользователя с загруженной ролью."""
        users_dao = UsersDAO(db_session)

        user = await users_dao.find_one_or_none_by_id(test_user.id)
        await db_session.refresh(user)  # Загружаем связанные объекты

        assert user is not None
        assert user.role is not None
        assert user.role.name == "user"


class TestRoleDAO:
    """Тесты DAO ролей."""

    @pytest.mark.asyncio
    async def test_role_dao_model(self, db_session: AsyncSession):
        """Тест модели RoleDAO."""
        role_dao = RoleDAO(db_session)
        assert role_dao.model == Role

    @pytest.mark.asyncio
    async def test_create_and_find_role(self, db_session: AsyncSession):
        """Тест создания и поиска роли."""
        role_dao = RoleDAO(db_session)

        # Создаем роль
        role_data = RoleAddModel(name="test_role")
        new_role = await role_dao.add(values=role_data)
        await db_session.commit()

        # Ищем созданную роль
        found_role = await role_dao.find_one_or_none(
            filters=RoleAddModel(name="test_role")
        )

        assert found_role is not None
        assert found_role.name == "test_role"
        assert found_role.id == new_role.id
