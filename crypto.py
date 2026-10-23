"""Шифрование паролей и генерация мастер-ключа."""

import hashlib
import secrets
import string

from cryptography.fernet import Fernet, InvalidToken

from paths import app_dir

UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*()-_=+"

MIN_PASSWORD_LENGTH = 1
MAX_PASSWORD_LENGTH = 64
DEFAULT_PASSWORD_LENGTH = 16


class CryptoError(Exception):
    """Ошибка ключа или расшифровки."""


def key_path():
    return app_dir() / ".key"


def ensure_key() -> bytes:
    """Вернуть ключ Fernet из .key. Если файла нет — создать его."""
    path = key_path()
    if path.exists():
        key = path.read_bytes().strip()
        try:
            Fernet(key)
        except ValueError as exc:
            raise CryptoError(
                "Файл .key повреждён. Удалите .key вместе с password.db, "
                "чтобы начать заново."
            ) from exc
        return key

    key = Fernet.generate_key()
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def encrypt_password(plain: str) -> str:
    """Зашифровать пароль и вернуть токен Fernet."""
    token = Fernet(ensure_key()).encrypt(plain.encode("utf-8"))
    return token.decode("ascii")


def decrypt_password(token: str) -> str:
    """Расшифровать токен Fernet. Без подходящего .key это невозможно."""
    try:
        plain = Fernet(ensure_key()).decrypt(token.encode("ascii"))
    except (InvalidToken, ValueError) as exc:
        raise CryptoError(
            "Не удалось расшифровать пароль. Файл .key не подходит к этой базе."
        ) from exc
    return plain.decode("utf-8")


def hash_master_password(password: str) -> str:
    """Хеш мастер-пароля SHA-256 в виде hex-строки."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_master_password(password: str, password_hash: str) -> bool:
    """Сравнить введённый мастер-пароль с сохранённым хешем."""
    actual = hash_master_password(password)
    return secrets.compare_digest(actual, password_hash)


def generate_password(
    length: int,
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_special: bool,
) -> str:
    """Собрать пароль из выбранных наборов символов."""
    if length < MIN_PASSWORD_LENGTH or length > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"Длина должна быть от {MIN_PASSWORD_LENGTH} до {MAX_PASSWORD_LENGTH}."
        )

    pools = []
    if use_upper:
        pools.append(UPPERCASE)
    if use_lower:
        pools.append(LOWERCASE)
    if use_digits:
        pools.append(DIGITS)
    if use_special:
        pools.append(SPECIAL)

    if not pools:
        raise ValueError("Выберите хотя бы один тип символов.")
    if length < len(pools):
        raise ValueError(
            "Длина меньше числа выбранных типов символов. "
            "Увеличьте длину или отключите лишний тип."
        )

    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(pools)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
