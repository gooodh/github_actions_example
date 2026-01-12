from fastapi import APIRouter, Depends, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dao import RoleDAO, UsersDAO
from app.auth.models import User
from app.auth.schemas import (
    EmailModel,
    PhoneModel,
    RoleAddModel,
    SUserAddDB,
    SUserAuth,
    SUserInfo,
    SUserRegister,
)
from app.auth.utils import authenticate_user, set_tokens
from app.dependencies.auth_dep import (
    check_refresh_token,
    get_current_admin_user,
    get_current_user,
)
from app.dependencies.dao_dep import get_session_with_commit, get_session_without_commit
from app.exceptions import IncorrectEmailOrPasswordException, UserAlreadyExistsException


router = APIRouter()


@router.post("/register/")
async def register_user(
    user_data: SUserRegister, session: AsyncSession = Depends(get_session_with_commit)
) -> dict:
    # Проверка существования пользователя по email
    user_dao = UsersDAO(session)

    existing_user = await user_dao.find_one_or_none(
        filters=EmailModel(email=user_data.email)
    )
    if existing_user:
        raise UserAlreadyExistsException

    # Проверка существования пользователя по номеру телефона
    existing_phone = await user_dao.find_one_or_none(
        filters=PhoneModel(phone_number=user_data.phone_number)
    )
    if existing_phone:
        raise UserAlreadyExistsException

    # Подготовка данных для добавления
    user_data_dict = user_data.model_dump()
    user_data_dict.pop("confirm_password", None)

    try:
        # Добавление пользователя
        await user_dao.add(values=SUserAddDB(**user_data_dict))
        return {"message": "Вы успешно зарегистрированы!"}
    except IntegrityError:
        # Обработка ошибок целостности базы данных (например, дублирование)
        raise UserAlreadyExistsException


@router.post("/login/")
async def auth_user(
    response: Response,
    user_data: SUserAuth,
    session: AsyncSession = Depends(get_session_without_commit),
) -> dict:
    users_dao = UsersDAO(session)
    user = await users_dao.find_one_or_none(filters=EmailModel(email=user_data.email))

    if not (user and await authenticate_user(user=user, password=user_data.password)):
        raise IncorrectEmailOrPasswordException
    set_tokens(response, user.id)
    return {"ok": True, "message": "Авторизация успешна!"}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("user_access_token")
    response.delete_cookie("user_refresh_token")
    return {"message": "Пользователь успешно вышел из системы"}


@router.get("/me/")
async def get_me(user_data: User = Depends(get_current_user)) -> SUserInfo:
    return SUserInfo.model_validate(user_data)


@router.get("/all_users/")
async def get_all_users(
    session: AsyncSession = Depends(get_session_with_commit),
    user_data: User = Depends(get_current_admin_user),
) -> list[SUserInfo]:
    return await UsersDAO(session).find_all()


@router.post("/refresh")
async def process_refresh_token(
    response: Response, user: User = Depends(check_refresh_token)
):
    set_tokens(response, user.id)
    return {"message": "Токены успешно обновлены"}


@router.post("/addroles")
async def addroles(
    role_data: RoleAddModel,
    session: AsyncSession = Depends(get_session_with_commit),
    current_admin: User = Depends(get_current_admin_user),
):
    role_dao = RoleDAO(session)
    role = await role_dao.find_one_or_none(filters=RoleAddModel(name=role_data.name))
    if role:
        raise UserAlreadyExistsException
    role_data_dict = role_data.model_dump()

    await role_dao.add(values=RoleAddModel(**role_data_dict))
    return {"message": "Роль успешно добавлена"}
