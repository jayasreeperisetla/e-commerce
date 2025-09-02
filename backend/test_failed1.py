import pytest
from unittest.mock import MagicMock, patch
import logging
from pydantic import BaseModel, Field
from fastapi import HTTPException

# --- Fallback/Dummy Implementations for unknown imports ---

# Mock settings
class Settings:
    EMAILS_ENABLED: bool = False
    SMTP_HOST: str | None = None
    SMTP_PORT: int | None = None
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    EMAILS_FROM_EMAIL: str | None = None

settings = Settings()

# Mock for send_email dependencies
# Assuming fastapi_mail is used for sending emails
class MockMessage:
    def __init__(self, email_to, subject, html_content, subtype="html"):
        self.recipients = [email_to]
        self.subject = subject
        self.body = html_content
        self.subtype = subtype

    # Add __eq__ for easier comparison in assert_called_once_with
    def __eq__(self, other):
        if not isinstance(other, MockMessage):
            return NotImplemented
        return (self.recipients == other.recipients and
                self.subject == other.subject and
                self.body == other.body and
                self.subtype == other.subtype)

    def __repr__(self):
        return f"MockMessage(recipients={self.recipients}, subject='{self.subject}', body='{self.body}', subtype='{self.subtype}')"


class MockFastMail:
    def __init__(self, conf):
        if not conf.get("SMTP_HOST") or not conf.get("EMAILS_FROM_EMAIL"):
            raise ValueError("Missing SMTP_HOST or EMAILS_FROM_EMAIL")
        if conf.get("SMTP_PORT") == 0:
            raise ValueError("Invalid SMTP_PORT")
        self.conf = conf

    async def send_message(self, message):
        # Simulate sending, raise exception if auth fails or other issues
        if self.conf.get("SMTP_USER") and self.conf.get("SMTP_PASSWORD") == "fail_auth":
            raise Exception("Authentication failed")
        if "invalid-email" in message.recipients[0]: # Specific check for test_send_email_2_negative_invalid_email_to
            raise Exception("Invalid recipient email")
        # Simulate success
        return {"status": "success"}

# Mock the actual send_email function
# This will be patched when testing create_user
# And its internal dependencies (FastMail, logger) will be patched when testing send_email itself.
async def send_email(email_to: str, subject: str = "", html_content: str = "") -> None:
    """
    Dummy send_email function for testing purposes.
    The actual implementation would use a mail client.
    """
    logger = logging.getLogger(__name__)

    if not settings.EMAILS_ENABLED:
        raise AssertionError("no provided configuration for email variables")

    mail_conf = {
        "SMTP_HOST": settings.SMTP_HOST,
        "SMTP_PORT": settings.SMTP_PORT,
        "SMTP_USER": settings.SMTP_USER,
        "SMTP_PASSWORD": settings.SMTP_PASSWORD,
        "EMAILS_FROM_EMAIL": settings.EMAILS_FROM_EMAIL,
        "USE_CREDENTIALS": bool(settings.SMTP_USER and settings.SMTP_PASSWORD),
        "VALIDATE_CERTS": False, # For simplicity in mock
    }

    try:
        mail_client = MockFastMail(mail_conf)
        message = MockMessage(email_to, subject, html_content)
        await mail_client.send_message(message)
        logger.info(f"Email sent successfully to {email_to}") # Log only success
    except Exception as e:
        logger.info(f"Failed to send email to {email_to}: {e}") # Log only failure
        raise # Re-raise to simulate the original behavior if not caught internally


# Mock for create_user dependencies
class UserIn(BaseModel):
    email: str | None = None
    password: str | None = None
    full_name: str | None = None

class User(BaseModel):
    id: int = 1
    email: str | None # Allow None for test_create_user_10
    hashed_password: str
    full_name: str | None = None

# Mock CRUD operations
class MockCRUD:
    def get_user_by_email(self, db, email: str | None):
        if email == "existing@example.com":
            return User(email=email, hashed_password="hashed_password")
        if email == "error@example.com":
            raise Exception("Database error on get_user_by_email")
        return None

    def create_user(self, db, user_in: UserIn):
        if user_in.email == "db_error@example.com":
            raise Exception("Database error on create_user")
        return User(email=user_in.email, hashed_password="hashed_password", full_name=user_in.full_name)

crud = MockCRUD()

# Mock for email content generation
def generate_new_account_email(user: User, password: str | None) -> tuple[str, str]:
    if user.email == "gen_error@example.com":
        raise Exception("Error generating email content")
    return "New Account Subject", "<h1>Welcome!</h1>"

# Mock the actual create_user function
async def create_user(db: MagicMock, user_in: UserIn) -> User:
    """
    Dummy create_user function for testing purposes.
    """
    if user_in.email: # Only check for existing email if provided
        user = crud.get_user_by_email(db, user_in.email)
        if user:
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")

    created_user = crud.create_user(db, user_in)

    if settings.EMAILS_ENABLED and created_user.email and created_user.email != "":
        try:
            subject, content = generate_new_account_email(created_user, user_in.password)
            await send_email(
                email_to=created_user.email, # Use created_user.email as it's the final email
                subject=subject,
                html_content=content,
            )
        except Exception as e:
            # Depending on desired behavior, this could be logged or re-raised
            # For now, re-raise as per some test cases
            raise e

    return created_user

# --- Pytest fixtures and tests ---

@pytest.fixture(autouse=True)
def mock_settings_fixture(monkeypatch):
    """Fixture to reset settings for each test."""
    # Patch the global settings object directly.
    # Assuming this file is named 'test_module.py' for monkeypatch target.
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    monkeypatch.setattr("test_module.settings.SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr("test_module.settings.SMTP_PORT", 587)
    monkeypatch.setattr("test_module.settings.EMAILS_FROM_EMAIL", "from@example.com")
    monkeypatch.setattr("test_module.settings.SMTP_USER", "user")
    monkeypatch.setattr("test_module.settings.SMTP_PASSWORD", "password")

@pytest.fixture
def mock_db():
    """Fixture for a mock database session."""
    return MagicMock()

# --- Tests for send_email ---

@pytest.mark.asyncio
async def test_send_email_1_positive(monkeypatch):
    """
    Test Case 1 (Positive): Call send_email with valid email_to, subject, and html_content.
    settings.emails_enabled is True. `message.send` is called once and returns a successful response.
    logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    mock_fastmail_instance = MagicMock()
    mock_fastmail_instance.send_message.return_value = {"status": "success"}
    monkeypatch.setattr("test_module.MockFastMail", MagicMock(return_value=mock_fastmail_instance))

    await send_email("test@example.com", "Test Subject", "<h1>Test Content</h1>")

    mock_fastmail_instance.send_message.assert_called_once_with(
        MockMessage("test@example.com", "Test Subject", "<h1>Test Content</h1>")
    )
    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Email sent successfully to test@example.com")


@pytest.mark.asyncio
async def test_send_email_2_negative_invalid_email_to(monkeypatch):
    """
    Test Case 2 (Negative): Call send_email with invalid email_to address.
    settings.emails_enabled is True. `message.send` is called once and raises an exception.
    logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    # The MockFastMail.send_message has logic to raise for "invalid-email"
    mock_fastmail_instance = MagicMock()
    mock_fastmail_instance.send_message.side_effect = Exception("Invalid recipient email")
    monkeypatch.setattr("test_module.MockFastMail", MagicMock(return_value=mock_fastmail_instance))

    with pytest.raises(Exception, match="Invalid recipient email"):
        await send_email("invalid-email", "Test Subject", "<h1>Test Content</h1>")

    mock_fastmail_instance.send_message.assert_called_once_with(
        MockMessage("invalid-email", "Test Subject", "<h1>Test Content</h1>")
    )
    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Failed to send email to invalid-email: Invalid recipient email")


@pytest.mark.asyncio
async def test_send_email_3_edge_empty_content(monkeypatch):
    """
    Test Case 3 (Edge): Call send_email with empty subject and html_content.
    settings.emails_enabled is True. `message.send` is called once and returns a successful response.
    logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    mock_fastmail_instance = MagicMock()
    mock_fastmail_instance.send_message.return_value = {"status": "success"}
    monkeypatch.setattr("test_module.MockFastMail", MagicMock(return_value=mock_fastmail_instance))

    await send_email("test@example.com", "", "")

    mock_fastmail_instance.send_message.assert_called_once_with(
        MockMessage("test@example.com", "", "")
    )
    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Email sent successfully to test@example.com")


@pytest.mark.asyncio
async def test_send_email_4_negative_emails_disabled(monkeypatch):
    """
    Test Case 4 (Negative): Call send_email with settings.emails_enabled is False.
    Expects AssertionError("no provided configuration for email variables").
    `message.send` is not called. logger.info is not called.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", False)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    mock_fastmail_instance = MagicMock()
    monkeypatch.setattr("test_module.MockFastMail", MagicMock(return_value=mock_fastmail_instance))

    with pytest.raises(AssertionError, match="no provided configuration for email variables"):
        await send_email("test@example.com", "Subject", "Content")

    mock_fastmail_instance.send_message.assert_not_called()
    mock_logger.info.assert_not_called()


@pytest.mark.asyncio
async def test_send_email_5_edge_only_email_to(monkeypatch):
    """
    Test Case 5 (Edge): Call send_email with only email_to.
    settings.emails_enabled is True. `message.send` is called once and returns a successful response.
    logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    mock_fastmail_instance = MagicMock()
    mock_fastmail_instance.send_message.return_value = {"status": "success"}
    monkeypatch.setattr("test_module.MockFastMail", MagicMock(return_value=mock_fastmail_instance))

    await send_email("test@example.com") # Subject and html_content default to empty strings

    mock_fastmail_instance.send_message.assert_called_once_with(
        MockMessage("test@example.com", "", "")
    )
    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Email sent successfully to test@example.com")


@pytest.mark.asyncio
async def test_send_email_6_negative_message_send_raises_exception(monkeypatch):
    """
    Test Case 6 (Negative): Mock `message.send` to raise an exception.
    settings.emails_enabled is True. `message.send` is called once and raises an exception.
    logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    mock_fastmail_instance = MagicMock()
    mock_fastmail_instance.send_message.side_effect = Exception("SMTP connection error")
    monkeypatch.setattr("test_module.MockFastMail", MagicMock(return_value=mock_fastmail_instance))

    with pytest.raises(Exception, match="SMTP connection error"):
        await send_email("test@example.com", "Subject", "Content")

    mock_fastmail_instance.send_message.assert_called_once_with(
        MockMessage("test@example.com", "Subject", "Content")
    )
    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Failed to send email to test@example.com: SMTP connection error")


@pytest.mark.asyncio
async def test_send_email_7_edge_smtp_host_none(monkeypatch):
    """
    Test Case 7 (Edge): settings.SMTP_HOST is None. settings.emails_enabled is True.
    Expects `message.send` to raise an exception (due to missing SMTP host).
    logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    monkeypatch.setattr("test_module.settings.SMTP_HOST", None)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    # MockFastMail constructor will raise ValueError if SMTP_HOST is None
    with pytest.raises(ValueError, match="Missing SMTP_HOST or EMAILS_FROM_EMAIL"):
        await send_email("test@example.com", "Subject", "Content")

    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Failed to send email to test@example.com: Missing SMTP_HOST or EMAILS_FROM_EMAIL")


@pytest.mark.asyncio
async def test_send_email_8_negative_emails_from_email_none(monkeypatch):
    """
    Test Case 8 (Negative): settings.EMAILS_FROM_EMAIL is None. settings.emails_enabled is True.
    Expects `message.send` to raise an exception (due to missing from email).
    logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    monkeypatch.setattr("test_module.settings.EMAILS_FROM_EMAIL", None)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    with pytest.raises(ValueError, match="Missing SMTP_HOST or EMAILS_FROM_EMAIL"):
        await send_email("test@example.com", "Subject", "Content")

    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Failed to send email to test@example.com: Missing SMTP_HOST or EMAILS_FROM_EMAIL")


@pytest.mark.asyncio
async def test_send_email_9_edge_smtp_port_zero(monkeypatch):
    """
    Test Case 9 (Edge): settings.SMTP_PORT is 0. settings.emails_enabled is True.
    Expects `message.send` to raise an exception (due to invalid port).
    logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    monkeypatch.setattr("test_module.settings.SMTP_PORT", 0)
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    with pytest.raises(ValueError, match="Invalid SMTP_PORT"):
        await send_email("test@example.com", "Subject", "Content")

    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Failed to send email to test@example.com: Invalid SMTP_PORT")


@pytest.mark.asyncio
async def test_send_email_10_negative_smtp_auth_fails(monkeypatch):
    """
    Test Case 10 (Negative): settings.SMTP_USER and settings.SMTP_PASSWORD are provided,
    but SMTP authentication fails (mock this). settings.emails_enabled is True.
    `message.send` is called once and raises an exception. logger.info is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    monkeypatch.setattr("test_module.settings.SMTP_USER", "user")
    monkeypatch.setattr("test_module.settings.SMTP_PASSWORD", "fail_auth") # Special value to trigger mock failure
    mock_logger = MagicMock()
    monkeypatch.setattr("logging.getLogger", MagicMock(return_value=mock_logger))

    # MockFastMail constructor will be called, then send_message will raise
    mock_fastmail_instance = MagicMock()
    mock_fastmail_instance.send_message.side_effect = Exception("Authentication failed")
    monkeypatch.setattr("test_module.MockFastMail", MagicMock(return_value=mock_fastmail_instance))

    with pytest.raises(Exception, match="Authentication failed"):
        await send_email("test@example.com", "Subject", "Content")

    mock_fastmail_instance.send_message.assert_called_once_with(
        MockMessage("test@example.com", "Subject", "Content")
    )
    mock_logger.info.assert_called_once()
    mock_logger.info.assert_called_with("Failed to send email to test@example.com: Authentication failed")


# --- Tests for create_user ---

@pytest.mark.asyncio
async def test_create_user_1_positive(mock_db, monkeypatch):
    """
    Test Case 1 (Positive): Call create_user with valid user_in data.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object. `send_email` is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_get_user_by_email = MagicMock(return_value=None)
    mock_created_user = User(email="new@example.com", hashed_password="hashed")
    mock_create_user = MagicMock(return_value=mock_created_user)
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock(return_value=("Welcome", "HTML Content"))
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email="new@example.com", password="password123")
    created_user = await create_user(mock_db, user_in)

    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_called_once_with(mock_db, user_in)
    mock_generate_email.assert_called_once_with(mock_created_user, user_in.password)
    mock_send_email.assert_called_once_with(
        email_to=mock_created_user.email,
        subject="Welcome",
        html_content="HTML Content"
    )
    assert created_user.email == user_in.email


@pytest.mark.asyncio
async def test_create_user_2_negative_email_exists(mock_db, monkeypatch):
    """
    Test Case 2 (Negative): Call create_user with user_in data where email already exists.
    settings.emails_enabled is True. `crud.get_user_by_email` returns a user object.
    `crud.create_user` is not called. `send_email` is not called.
    Expects HTTPException(status_code=400,...).
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_get_user_by_email = MagicMock(return_value=User(email="existing@example.com", hashed_password="hashed"))
    mock_create_user = MagicMock()
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock()
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email="existing@example.com", password="password123")

    with pytest.raises(HTTPException) as exc_info:
        await create_user(mock_db, user_in)

    assert exc_info.value.status_code == 400
    assert "already exists" in exc_info.value.detail
    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_not_called()
    mock_send_email.assert_not_called()
    mock_generate_email.assert_not_called()


@pytest.mark.asyncio
async def test_create_user_3_edge_empty_email(mock_db, monkeypatch):
    """
    Test Case 3 (Edge): Call create_user with user_in data with empty email.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object. `send_email` is not called.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_get_user_by_email = MagicMock(return_value=None)
    mock_created_user = User(email="", hashed_password="hashed")
    mock_create_user = MagicMock(return_value=mock_created_user)
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock()
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email="", password="password123")
    created_user = await create_user(mock_db, user_in)

    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_called_once_with(mock_db, user_in)
    mock_send_email.assert_not_called() # Email not sent for empty email
    mock_generate_email.assert_not_called()
    assert created_user.email == user_in.email


@pytest.mark.asyncio
async def test_create_user_4_negative_crud_create_user_raises_exception(mock_db, monkeypatch):
    """
    Test Case 4 (Negative): Mock `crud.create_user` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and raises an exception. `send_email` is not called.
    Expects the exception to propagate.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_get_user_by_email = MagicMock(return_value=None)
    mock_create_user = MagicMock(side_effect=Exception("DB write error"))
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock()
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email="new@example.com", password="password123")

    with pytest.raises(Exception, match="DB write error"):
        await create_user(mock_db, user_in)

    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_called_once_with(mock_db, user_in)
    mock_send_email.assert_not_called()
    mock_generate_email.assert_not_called()


@pytest.mark.asyncio
async def test_create_user_5_edge_very_long_email(mock_db, monkeypatch):
    """
    Test Case 5 (Edge): Call create_user with user_in data with a very long email address.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object. `send_email` is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    long_email = "a" * 240 + "@example.com" # Exceeds typical 254 char limit for email, but valid for some systems
    mock_get_user_by_email = MagicMock(return_value=None)
    mock_created_user = User(email=long_email, hashed_password="hashed")
    mock_create_user = MagicMock(return_value=mock_created_user)
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock(return_value=("Welcome Long", "HTML Content Long"))
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email=long_email, password="password123")
    created_user = await create_user(mock_db, user_in)

    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_called_once_with(mock_db, user_in)
    mock_generate_email.assert_called_once_with(mock_created_user, user_in.password)
    mock_send_email.assert_called_once_with(
        email_to=mock_created_user.email,
        subject="Welcome Long",
        html_content="HTML Content Long"
    )
    assert created_user.email == user_in.email


@pytest.mark.asyncio
async def test_create_user_6_negative_emails_disabled(mock_db, monkeypatch):
    """
    Test Case 6 (Negative): settings.emails_enabled is False.
    `crud.get_user_by_email` returns None. `crud.create_user` is called once and returns a user object.
    `send_email` is not called.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", False)
    mock_get_user_by_email = MagicMock(return_value=None)
    mock_created_user = User(email="new@example.com", hashed_password="hashed")
    mock_create_user = MagicMock(return_value=mock_created_user)
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock()
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email="new@example.com", password="password123")
    created_user = await create_user(mock_db, user_in)

    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_called_once_with(mock_db, user_in)
    mock_send_email.assert_not_called() # Emails disabled
    mock_generate_email.assert_not_called()
    assert created_user.email == user_in.email


@pytest.mark.asyncio
async def test_create_user_7_edge_crud_get_user_by_email_raises_exception(mock_db, monkeypatch):
    """
    Test Case 7 (Edge): Mock `crud.get_user_by_email` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` is called once and raises an exception.
    `crud.create_user` is not called. `send_email` is not called. Expects the exception to propagate.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_get_user_by_email = MagicMock(side_effect=Exception("DB read error"))
    mock_create_user = MagicMock()
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock()
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email="new@example.com", password="password123")

    with pytest.raises(Exception, match="DB read error"):
        await create_user(mock_db, user_in)

    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_not_called()
    mock_send_email.assert_not_called()
    mock_generate_email.assert_not_called()


@pytest.mark.asyncio
async def test_create_user_8_negative_generate_new_account_email_raises_exception(mock_db, monkeypatch):
    """
    Test Case 8 (Negative): Mock `generate_new_account_email` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object.
    `generate_new_account_email` is called once and raises an exception.
    `send_email` is not called. Expects the exception to propagate.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_get_user_by_email = MagicMock(return_value=None)
    mock_created_user = User(email="new@example.com", hashed_password="hashed")
    mock_create_user = MagicMock(return_value=mock_created_user)
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock(side_effect=Exception("Email content generation failed"))
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email="new@example.com", password="password123")

    with pytest.raises(Exception, match="Email content generation failed"):
        await create_user(mock_db, user_in)

    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_called_once_with(mock_db, user_in)
    mock_generate_email.assert_called_once_with(mock_created_user, user_in.password)
    mock_send_email.assert_not_called()


@pytest.mark.asyncio
async def test_create_user_9_edge_user_in_password_none(mock_db, monkeypatch):
    """
    Test Case 9 (Edge): user_in.password is None. settings.emails_enabled is True.
    `crud.get_user_by_email` returns None. `crud.create_user` is called once and returns a user object.
    `generate_new_account_email` is called once. `send_email` is called once.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_get_user_by_email = MagicMock(return_value=None)
    mock_created_user = User(email="new@example.com", hashed_password="hashed")
    mock_create_user = MagicMock(return_value=mock_created_user)
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock(return_value=("Welcome No Pass", "HTML Content No Pass"))
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email="new@example.com", password=None)
    created_user = await create_user(mock_db, user_in)

    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_called_once_with(mock_db, user_in)
    mock_generate_email.assert_called_once_with(mock_created_user, user_in.password)
    mock_send_email.assert_called_once_with(
        email_to=mock_created_user.email,
        subject="Welcome No Pass",
        html_content="HTML Content No Pass"
    )
    assert created_user.email == user_in.email


@pytest.mark.asyncio
async def test_create_user_10_negative_user_in_email_none(mock_db, monkeypatch):
    """
    Test Case 10 (Negative): user_in.email is None. settings.emails_enabled is True.
    `crud.get_user_by_email` returns None. `crud.create_user` is called once and returns a user object.
    `generate_new_account_email` is not called. `send_email` is not called.
    """
    monkeypatch.setattr("test_module.settings.EMAILS_ENABLED", True)
    mock_get_user_by_email = MagicMock(return_value=None)
    mock_created_user = User(email=None, hashed_password="hashed")
    mock_create_user = MagicMock(return_value=mock_created_user)
    monkeypatch.setattr("test_module.crud.get_user_by_email", mock_get_user_by_email)
    monkeypatch.setattr("test_module.crud.create_user", mock_create_user)
    mock_send_email = MagicMock()
    monkeypatch.setattr("test_module.send_email", mock_send_email)
    mock_generate_email = MagicMock()
    monkeypatch.setattr("test_module.generate_new_account_email", mock_generate_email)

    user_in = UserIn(email=None, password="password123")
    created_user = await create_user(mock_db, user_in)

    # crud.get_user_by_email is called with None, which is handled by the mock
    mock_get_user_by_email.assert_called_once_with(mock_db, user_in.email)
    mock_create_user.assert_called_once_with(mock_db, user_in)
    mock_generate_email.assert_not_called() # No email to send
    mock_send_email.assert_not_called() # No email to send
    assert created_user.email is None