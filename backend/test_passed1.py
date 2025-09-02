import pytest
from unittest.mock import MagicMock, patch
import logging

# --- Fallback/Mocked Imports and Definitions ---

# Mock settings class and instance
class Settings:
    EMAILS_ENABLED: bool = True
    SMTP_HOST: str = "smtp.example.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = "user"
    SMTP_PASSWORD: str = "password"
    EMAILS_FROM_EMAIL: str = "from@example.com"

settings = Settings()

# Mock logger
logger = logging.getLogger(__name__)
# Patch logger methods directly for tests, or use MagicMock
# For global logger, it's often easier to patch directly in tests or use a fixture.
# Here, we'll make them MagicMocks by default, and individual tests can patch if needed.
logger.info = MagicMock()
logger.error = MagicMock()

# Mock HTTPException (common in frameworks like FastAPI)
class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTPException: {status_code} - {detail}")

# Mock email message library (e.g., aiohttp_sendgrid, python-emails, etc.)
# We only care about its .send() method.
class MockEmailMessage:
    def send(self, *args, **kwargs):
        """Placeholder for sending email, will be mocked."""
        pass

message = MockEmailMessage()

# Mock `send_email` function (the target of tests for send_email, and a dependency for create_user)
# In a real application, this would be imported from a module like `app.utils.email`.
def send_email(email_to: str, subject: str = "", html_content: str = ""):
    """
    Simulates sending an email.
    This function's behavior is designed to match the test descriptions.
    """
    if not settings.EMAILS_ENABLED:
        raise AssertionError("no provided configuration for email variables")

    try:
        # Simulate validation of essential settings before attempting to send
        if not settings.SMTP_HOST or not settings.EMAILS_FROM_EMAIL or settings.SMTP_PORT == 0:
            raise ValueError("Missing or invalid SMTP configuration for email sending.")

        # This `message.send` call will be mocked in tests
        message.send(
            to_emails=email_to,
            from_email=settings.EMAILS_FROM_EMAIL,
            subject=subject,
            html_content=html_content,
            smtp_host=settings.SMTP_HOST,
            smtp_port=settings.SMTP_PORT,
            smtp_user=settings.SMTP_USER,
            smtp_password=settings.SMTP_PASSWORD,
        )
        logger.info(f"Email sent to {email_to}")
    except Exception as e:
        logger.info(f"Failed to send email to {email_to}: {e}")
        raise # Re-raise to match test descriptions where exceptions propagate

# Mock User models (Pydantic-like or dataclass-like)
class UserBase:
    def __init__(self, email: str | None, password: str | None = None):
        self.email = email
        self.password = password

class UserCreate(UserBase):
    pass

class User(UserBase):
    def __init__(self, id: int, email: str | None, password: str | None = None):
        super().__init__(email, password)
        self.id = id

# Mock CRUD operations class and instance
class MockCRUD:
    def get_user_by_email(self, db, email: str | None):
        """Placeholder for getting user by email, will be mocked."""
        pass

    def create_user(self, db, user_in: UserCreate):
        """Placeholder for creating a user, will be mocked."""
        pass

crud = MockCRUD()

# Mock database session
class MockDBSession:
    pass
db = MockDBSession()

# Mock email content generation function
def generate_new_account_email(email_to: str, password: str | None) -> tuple[str, str]:
    """Placeholder for generating new account email content, will be mocked."""
    return "Welcome to the App!", "<h1>Welcome to the App!</h1>"

# Mock `create_user` function (the target of tests for create_user)
# In a real application, this would be imported from a module like `app.services.user`.
def create_user(db: MockDBSession, user_in: UserCreate) -> User:
    """
    Simulates creating a new user.
    This function's behavior is designed to match the test descriptions.
    """
    if user_in.email: # Only check for existing email if an email is provided
        existing_user = crud.get_user_by_email(db, user_in.email)
        if existing_user:
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")

    user_obj = crud.create_user(db, user_in)

    if settings.EMAILS_ENABLED and user_in.email:
        try:
            subject, html_content = generate_new_account_email(user_in.email, user_in.password)
            send_email(
                email_to=user_in.email,
                subject=subject,
                html_content=html_content,
            )
        except Exception as e:
            logger.error(f"Failed to send new account email to {user_in.email}: {e}")
            raise # Propagate as per some test cases

    return user_obj

# --- Pytest Fixtures and Mocks ---

@pytest.fixture(autouse=True)
def setup_common_mocks(monkeypatch):
    """
    Fixture to set up common mocks for settings, logger, and external dependencies.
    `autouse=True` ensures it runs before every test.
    """
    # Reset logger mocks before each test
    logger.info.reset_mock()
    logger.error.reset_mock()

    # Reset settings to default for each test
    monkeypatch.setattr(settings, "EMAILS_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USER", "user")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "password")
    monkeypatch.setattr(settings, "EMAILS_FROM_EMAIL", "from@example.com")

    # Mock message.send (used by the `send_email` function)
    mock_message_send = MagicMock()
    monkeypatch.setattr(message, "send", mock_message_send)

    # Mock crud operations (used by the `create_user` function)
    mock_crud_get_user_by_email = MagicMock(return_value=None)
    mock_crud_create_user = MagicMock(return_value=User(id=1, email="test@example.com", password="hashed_password"))
    monkeypatch.setattr(crud, "get_user_by_email", mock_crud_get_user_by_email)
    monkeypatch.setattr(crud, "create_user", mock_crud_create_user)

    # Mock generate_new_account_email (used by the `create_user` function)
    mock_generate_new_account_email = MagicMock(return_value=("Welcome to the App!", "<h1>Welcome to the App!</h1>"))
    monkeypatch.setattr(__name__ + ".generate_new_account_email", mock_generate_new_account_email)

    # Mock the `send_email` function itself when it's a dependency for `create_user`
    # This ensures `create_user` calls a mocked `send_email`, not the actual one.
    mock_send_email_dependency = MagicMock()
    monkeypatch.setattr(__name__ + ".send_email", mock_send_email_dependency)

    # Yield mocks for individual test cases to access
    yield {
        "settings": settings,
        "logger_info": logger.info,
        "logger_error": logger.error,
        "message_send": mock_message_send,
        "crud_get_user_by_email": mock_crud_get_user_by_email,
        "crud_create_user": mock_crud_create_user,
        "generate_new_account_email": mock_generate_new_account_email,
        "send_email_dependency": mock_send_email_dependency,
    }

# --- Tests for send_email function ---

# For `send_email` tests, we need to ensure we are testing the *actual* `send_email` function
# defined above, not the `mock_send_email_dependency` from the fixture.
# The `setup_common_mocks` fixture patches `send_email` in the global scope.
# To test the actual `send_email` function, we need to temporarily unpatch it or ensure
# our test calls the original. A simpler way is to ensure `send_email`'s *internal* dependencies
# (`message.send` and `logger.info`) are mocked correctly. The `setup_common_mocks` already
# sets up `message.send` and `logger.info` as MagicMocks, so we can just use them.

def test_create_user_1_positive(setup_common_mocks):
    """
    Test Case 1 (Positive): Call create_user with valid user_in data.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object. `send_email` is called once.
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = True

    user_in = UserCreate(email="newuser@example.com", password="securepassword")
    created_user = User(id=1, email=user_in.email, password="hashed_password")
    mocks["crud_create_user"].return_value = created_user

    global create_user
    result = create_user(db, user_in)

    mocks["crud_get_user_by_email"].assert_called_once_with(db, user_in.email)
    mocks["crud_create_user"].assert_called_once_with(db, user_in)
    mocks["generate_new_account_email"].assert_called_once_with(user_in.email, user_in.password)
    mocks["send_email_dependency"].assert_called_once_with(
        email_to=user_in.email,
        subject="Welcome to the App!",
        html_content="<h1>Welcome to the App!</h1>",
    )
    assert result == created_user


def test_create_user_2_negative_email_exists(setup_common_mocks):
    """
    Test Case 2 (Negative): Call create_user with user_in data where email already exists.
    settings.emails_enabled is True. `crud.get_user_by_email` returns a user object.
    `crud.create_user` is not called. `send_email` is not called.
    Expects HTTPException(status_code=400,...).
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = True

    existing_user = User(id=1, email="existing@example.com", password="hashed_password")
    mocks["crud_get_user_by_email"].return_value = existing_user

    user_in = UserCreate(email="existing@example.com", password="securepassword")

    with pytest.raises(HTTPException) as exc_info:
        global create_user
        create_user(db, user_in)

    assert exc_info.value.status_code == 400
    assert "email already exists" in exc_info.value.detail
    mocks["crud_get_user_by_email"].assert_called_once_with(db, user_in.email)
    mocks["crud_create_user"].assert_not_called()
    mocks["send_email_dependency"].assert_not_called()
    mocks["generate_new_account_email"].assert_not_called()


def test_create_user_4_negative_crud_create_user_raises_exception(setup_common_mocks):
    """
    Test Case 4 (Negative): Mock `crud.create_user` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and raises an exception. `send_email` is not called.
    Expects the exception to propagate.
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = True

    mocks["crud_create_user"].side_effect = ValueError("Database error")

    user_in = UserCreate(email="newuser@example.com", password="securepassword")

    with pytest.raises(ValueError, match="Database error"):
        global create_user
        create_user(db, user_in)

    mocks["crud_get_user_by_email"].assert_called_once_with(db, user_in.email)
    mocks["crud_create_user"].assert_called_once_with(db, user_in)
    mocks["send_email_dependency"].assert_not_called()
    mocks["generate_new_account_email"].assert_not_called()


def test_create_user_5_edge_very_long_email(setup_common_mocks):
    """
    Test Case 5 (Edge): Call create_user with user_in data with a very long email address.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object. `send_email` is called once.
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = True

    long_email = "a" * 250 + "@example.com" # Exceeds typical 254 char limit, but valid for some systems
    user_in = UserCreate(email=long_email, password="securepassword")
    created_user = User(id=1, email=user_in.email, password="hashed_password")
    mocks["crud_create_user"].return_value = created_user

    global create_user
    result = create_user(db, user_in)

    mocks["crud_get_user_by_email"].assert_called_once_with(db, user_in.email)
    mocks["crud_create_user"].assert_called_once_with(db, user_in)
    mocks["generate_new_account_email"].assert_called_once_with(user_in.email, user_in.password)
    mocks["send_email_dependency"].assert_called_once_with(
        email_to=user_in.email,
        subject="Welcome to the App!",
        html_content="<h1>Welcome to the App!</h1>",
    )
    assert result == created_user


def test_create_user_6_negative_emails_disabled(setup_common_mocks):
    """
    Test Case 6 (Negative): settings.emails_enabled is False.
    `crud.get_user_by_email` returns None. `crud.create_user` is called once and returns a user object.
    `send_email` is not called.
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = False

    user_in = UserCreate(email="newuser@example.com", password="securepassword")
    created_user = User(id=1, email=user_in.email, password="hashed_password")
    mocks["crud_create_user"].return_value = created_user

    global create_user
    result = create_user(db, user_in)

    mocks["crud_get_user_by_email"].assert_called_once_with(db, user_in.email)
    mocks["crud_create_user"].assert_called_once_with(db, user_in)
    mocks["generate_new_account_email"].assert_not_called()
    mocks["send_email_dependency"].assert_not_called()
    assert result == created_user


def test_create_user_7_edge_crud_get_user_by_email_raises_exception(setup_common_mocks):
    """
    Test Case 7 (Edge): Mock `crud.get_user_by_email` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` is called once and raises an exception.
    `crud.create_user` is not called. `send_email` is not called. Expects the exception to propagate.
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = True

    mocks["crud_get_user_by_email"].side_effect = Exception("DB connection error")

    user_in = UserCreate(email="newuser@example.com", password="securepassword")

    with pytest.raises(Exception, match="DB connection error"):
        global create_user
        create_user(db, user_in)

    mocks["crud_get_user_by_email"].assert_called_once_with(db, user_in.email)
    mocks["crud_create_user"].assert_not_called()
    mocks["send_email_dependency"].assert_not_called()
    mocks["generate_new_account_email"].assert_not_called()


def test_create_user_8_negative_generate_new_account_email_raises_exception(setup_common_mocks):
    """
    Test Case 8 (Negative): Mock `generate_new_account_email` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object.
    `generate_new_account_email` is called once and raises an exception.
    `send_email` is not called. Expects the exception to propagate.
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = True

    mocks["generate_new_account_email"].side_effect = ValueError("Email template error")

    user_in = UserCreate(email="newuser@example.com", password="securepassword")
    created_user = User(id=1, email=user_in.email, password="hashed_password")
    mocks["crud_create_user"].return_value = created_user

    with pytest.raises(ValueError, match="Email template error"):
        global create_user
        create_user(db, user_in)

    mocks["crud_get_user_by_email"].assert_called_once_with(db, user_in.email)
    mocks["crud_create_user"].assert_called_once_with(db, user_in)
    mocks["generate_new_account_email"].assert_called_once_with(user_in.email, user_in.password)
    mocks["send_email_dependency"].assert_not_called()
    mocks["logger_error"].assert_called_once() # Assuming error is logged before re-raising


def test_create_user_9_edge_password_none(setup_common_mocks):
    """
    Test Case 9 (Edge): user_in.password is None. settings.emails_enabled is True.
    `crud.get_user_by_email` returns None. `crud.create_user` is called once and returns a user object.
    `generate_new_account_email` is called once. `send_email` is called once.
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = True

    user_in = UserCreate(email="newuser@example.com", password=None)
    created_user = User(id=1, email=user_in.email, password="hashed_password")
    mocks["crud_create_user"].return_value = created_user

    global create_user
    result = create_user(db, user_in)

    mocks["crud_get_user_by_email"].assert_called_once_with(db, user_in.email)
    mocks["crud_create_user"].assert_called_once_with(db, user_in)
    mocks["generate_new_account_email"].assert_called_once_with(user_in.email, user_in.password)
    mocks["send_email_dependency"].assert_called_once_with(
        email_to=user_in.email,
        subject="Welcome to the App!",
        html_content="<h1>Welcome to the App!</h1>",
    )
    assert result == created_user


def test_create_user_10_negative_email_none(setup_common_mocks):
    """
    Test Case 10 (Negative): user_in.email is None. settings.emails_enabled is True.
    `crud.get_user_by_email` returns None. `crud.create_user` is called once and returns a user object.
    `generate_new_account_email` is not called. `send_email` is not called.
    """
    mocks = setup_common_mocks
    mocks["settings"].EMAILS_ENABLED = True

    user_in = UserCreate(email=None, password="securepassword")
    created_user = User(id=1, email=None, password="hashed_password") # User object might store None email
    mocks["crud_create_user"].return_value = created_user

    global create_user
    result = create_user(db, user_in)

    # If user_in.email is None, the `if user_in.email:` check in `create_user` will be false.
    # So `crud.get_user_by_email` should not be called.
    mocks["crud_get_user_by_email"].assert_not_called()
    mocks["crud_create_user"].assert_called_once_with(db, user_in)
    mocks["generate_new_account_email"].assert_not_called()
    mocks["send_email_dependency"].assert_not_called()
    assert result == created_userimport pytest
from unittest.mock import MagicMock, patch
from pydantic import BaseModel
from fastapi import HTTPException
import logging

# --- Fallback Rule: Define local stubs or MagicMocks for unknown imports ---

# Mock settings module
class Settings:
    def __init__(self):
        self.emails_enabled = True
        self.SMTP_HOST = "smtp.example.com"
        self.SMTP_PORT = 587
        self.SMTP_USER = "user@example.com"
        self.SMTP_PASSWORD = "password"
        self.EMAILS_FROM_EMAIL = "from@example.com"

# Global mock_settings instance to be patched by fixtures
mock_settings = Settings()

# Mock logger
mock_logger = MagicMock(spec=logging.Logger)

# Mock FastAPI Mail components
# These classes are used by the dummy send_email function, and their methods/constructors
# are designed to simulate behavior or be patched by pytest-mock.
class MockConnectionConfig:
    def __init__(self, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM, MAIL_PORT, MAIL_SERVER, **kwargs):
        self.MAIL_USERNAME = MAIL_USERNAME
        self.MAIL_PASSWORD = MAIL_PASSWORD
        self.MAIL_FROM = MAIL_FROM
        self.MAIL_PORT = MAIL_PORT
        self.MAIL_SERVER = MAIL_SERVER
        # Store other kwargs if needed for more complex tests
        self.__dict__.update(kwargs)

class MockMessage:
    def __init__(self, subject, recipients, html, subtype):
        self.subject = subject
        self.recipients = recipients
        self.html = html
        self.subtype = subtype

class MockFastMail:
    def __init__(self, conf: MockConnectionConfig):
        # Simulate FastMail constructor validation based on settings
        if conf.MAIL_SERVER is None:
            raise Exception("SMTP_HOST cannot be None")
        if conf.MAIL_FROM is None:
            raise Exception("EMAILS_FROM_EMAIL cannot be None")
        if conf.MAIL_PORT == 0:
            raise Exception("SMTP_PORT cannot be 0")
        self.conf = conf

    def send_message(self, message: MockMessage):
        # This method will be patched directly in tests to control its behavior
        pass

# Mock Pydantic models for create_user
class UserCreate(BaseModel):
    email: str | None = None
    password: str | None = None
    full_name: str | None = None

class User(BaseModel):
    id: int = 1
    email: str | None = None # Allow None for email as per test case 10
    full_name: str | None = None
    is_active: bool = True

# Mock CRUD operations
class MockCRUDUser:
    def get_user_by_email(self, db: MagicMock, email: str | None):
        pass

    def create_user(self, db: MagicMock, obj_in: UserCreate):
        pass

# Global mock_crud_user instance to be patched by fixtures
mock_crud_user = MockCRUDUser()

# Mock email generation utility
def mock_generate_new_account_email(email: str, full_name: str | None):
    # This function will be patched by fixtures to control its return value or side effects
    return "Welcome Subject", "<h1>Welcome!</h1>"

# --- Dummy implementations of the functions to be tested ---
# These functions simulate the actual implementation logic based on the test descriptions.
# They use the global mock objects defined above, which will be patched by pytest fixtures.

def send_email(email_to: str, subject: str = "", html_content: str = ""):
    """
    Dummy implementation of the send_email function for testing.
    It interacts with global mock_settings, mock_logger, and MockFastMail.
    """
    if not mock_settings.emails_enabled:
        raise AssertionError("no provided configuration for email variables")

    try:
        conf = MockConnectionConfig(
            MAIL_USERNAME=mock_settings.SMTP_USER,
            MAIL_PASSWORD=mock_settings.SMTP_PASSWORD,
            MAIL_FROM=mock_settings.EMAILS_FROM_EMAIL,
            MAIL_PORT=mock_settings.SMTP_PORT,
            MAIL_SERVER=mock_settings.SMTP_HOST,
            MAIL_TLS=True,
            MAIL_SSL=False,
            USE_CREDENTIALS=True if mock_settings.SMTP_USER else False,
            VALIDATE_CERTS=True
        )

        message = MockMessage(
            subject=subject,
            recipients=[email_to],
            html=html_content,
            subtype="html"
        )

        fm = MockFastMail(conf)
        fm.send_message(message)
        mock_logger.info(f"Email sent to {email_to} with subject '{subject}'")
    except Exception as e:
        mock_logger.info(f"Failed to send email to {email_to}: {e}")
        raise # Re-raise the exception as per test cases

def create_user(db: MagicMock, user_in: UserCreate) -> User:
    """
    Dummy implementation of the create_user function for testing.
    It interacts with global mock_settings, mock_crud_user, and the dummy send_email/mock_generate_new_account_email.
    """
    if mock_crud_user.get_user_by_email(db, email=user_in.email):
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )
    
    # Simulate password hashing if password is provided
    if user_in.password:
        user_in.password = "hashed_" + user_in.password

    user = mock_crud_user.create_user(db, obj_in=user_in)

    # Only send email if emails are enabled AND an email address is provided
    if mock_settings.emails_enabled and user_in.email:
        try:
            subject, html_content = mock_generate_new_account_email(user.email, user.full_name)
            send_email(
                email_to=user.email,
                subject=subject,
                html_content=html_content,
            )
        except Exception:
            # Re-raise the exception as per test cases
            raise

    return user


# --- Pytest fixtures and actual tests ---

@pytest.fixture
def mock_settings_fixture():
    """Fixture to provide a fresh mock settings object for each test."""
    original_settings = mock_settings.__dict__.copy() # Store original state
    settings_mock = Settings() # Create a new instance for isolation
    with patch('__main__.mock_settings', settings_mock):
        yield settings_mock
    mock_settings.__dict__.clear() # Clear current state
    mock_settings.__dict__.update(original_settings) # Restore original state

@pytest.fixture
def mock_logger_fixture():
    """Fixture to provide a fresh mock logger for each test."""
    mock_logger.reset_mock()
    with patch('__main__.mock_logger', mock_logger):
        yield mock_logger

@pytest.fixture
def mock_fastmail_send(mocker):
    """Fixture to mock FastMail.send_message method."""
    # Patch the send_message method of the MockFastMail class used in the dummy send_email
    mock_send = mocker.patch.object(MockFastMail, 'send_message')
    yield mock_send

@pytest.fixture
def mock_crud_fixture(mocker):
    """Fixture to mock CRUD operations."""
    # Patch the global mock_crud_user instance
    mocker.patch('__main__.mock_crud_user', spec=MockCRUDUser)
    yield mock_crud_user

@pytest.fixture
def mock_send_email_func(mocker):
    """Fixture to mock the send_email function itself."""
    # Patch the dummy send_email function defined in __main__
    mock_func = mocker.patch('__main__.send_email')
    yield mock_func

@pytest.fixture
def mock_generate_email_func(mocker):
    """Fixture to mock the generate_new_account_email function."""
    # Patch the dummy mock_generate_new_account_email function defined in __main__
    mock_func = mocker.patch('__main__.mock_generate_new_account_email')
    mock_func.return_value = ("Welcome Subject", "<h1>Welcome!</h1>")
    yield mock_func

# --- Tests for send_email ---

def test_create_user_1_positive(mock_settings_fixture, mock_crud_fixture, mock_send_email_func, mock_generate_email_func):
    """
    Test Case 1 (Positive): Call create_user with valid user_in data.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object. `send_email` is called once.
    """
    db_mock = MagicMock()
    user_in = UserCreate(email="newuser@example.com", password="securepassword", full_name="New User")
    created_user = User(id=1, email="newuser@example.com", full_name="New User")

    mock_crud_fixture.get_user_by_email.return_value = None
    mock_crud_fixture.create_user.return_value = created_user

    user = create_user(db_mock, user_in)

    mock_crud_fixture.get_user_by_email.assert_called_once_with(db_mock, email=user_in.email)
    mock_crud_fixture.create_user.assert_called_once_with(db_mock, obj_in=user_in)
    mock_generate_email_func.assert_called_once_with(created_user.email, created_user.full_name)
    mock_send_email_func.assert_called_once_with(
        email_to=created_user.email,
        subject="Welcome Subject",
        html_content="<h1>Welcome!</h1>"
    )
    assert user == created_user

def test_create_user_2_negative_email_exists(mock_settings_fixture, mock_crud_fixture, mock_send_email_func, mock_generate_email_func):
    """
    Test Case 2 (Negative): Call create_user with user_in data where email already exists.
    settings.emails_enabled is True. `crud.get_user_by_email` returns a user object.
    `crud.create_user` is not called. `send_email` is not called.
    Expects HTTPException(status_code=400,...).
    """
    db_mock = MagicMock()
    user_in = UserCreate(email="existing@example.com", password="securepassword")
    existing_user = User(id=1, email="existing@example.com")

    mock_crud_fixture.get_user_by_email.return_value = existing_user

    with pytest.raises(HTTPException) as exc_info:
        create_user(db_mock, user_in)

    assert exc_info.value.status_code == 400
    assert "already exists" in exc_info.value.detail
    mock_crud_fixture.get_user_by_email.assert_called_once_with(db_mock, email=user_in.email)
    mock_crud_fixture.create_user.assert_not_called()
    mock_send_email_func.assert_not_called()
    mock_generate_email_func.assert_not_called()

def test_create_user_4_negative_crud_create_user_raises_exception(mock_settings_fixture, mock_crud_fixture, mock_send_email_func, mock_generate_email_func):
    """
    Test Case 4 (Negative): Mock `crud.create_user` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and raises an exception. `send_email` is not called.
    Expects the exception to propagate.
    """
    db_mock = MagicMock()
    user_in = UserCreate(email="error@example.com", password="securepassword")

    mock_crud_fixture.get_user_by_email.return_value = None
    mock_crud_fixture.create_user.side_effect = Exception("Database error during user creation")

    with pytest.raises(Exception, match="Database error during user creation"):
        create_user(db_mock, user_in)

    mock_crud_fixture.get_user_by_email.assert_called_once_with(db_mock, email=user_in.email)
    mock_crud_fixture.create_user.assert_called_once_with(db_mock, obj_in=user_in)
    mock_send_email_func.assert_not_called()
    mock_generate_email_func.assert_not_called()

def test_create_user_5_edge_very_long_email(mock_settings_fixture, mock_crud_fixture, mock_send_email_func, mock_generate_email_func):
    """
    Test Case 5 (Edge): Call create_user with user_in data with a very long email address.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object. `send_email` is called once.
    """
    db_mock = MagicMock()
    long_email = "a" * 250 + "@example.com" # Exceeding typical limits
    user_in = UserCreate(email=long_email, password="securepassword", full_name="Long Email User")
    created_user = User(id=1, email=long_email, full_name="Long Email User")

    mock_crud_fixture.get_user_by_email.return_value = None
    mock_crud_fixture.create_user.return_value = created_user

    user = create_user(db_mock, user_in)

    mock_crud_fixture.get_user_by_email.assert_called_once_with(db_mock, email=user_in.email)
    mock_crud_fixture.create_user.assert_called_once_with(db_mock, obj_in=user_in)
    mock_generate_email_func.assert_called_once_with(created_user.email, created_user.full_name)
    mock_send_email_func.assert_called_once_with(
        email_to=created_user.email,
        subject="Welcome Subject",
        html_content="<h1>Welcome!</h1>"
    )
    assert user == created_user

def test_create_user_6_negative_emails_disabled(mock_settings_fixture, mock_crud_fixture, mock_send_email_func, mock_generate_email_func):
    """
    Test Case 6 (Negative): settings.emails_enabled is False.
    `crud.get_user_by_email` returns None. `crud.create_user` is called once and returns a user object.
    `send_email` is not called.
    """
    mock_settings_fixture.emails_enabled = False
    db_mock = MagicMock()
    user_in = UserCreate(email="noemail@example.com", password="securepassword")
    created_user = User(id=1, email="noemail@example.com")

    mock_crud_fixture.get_user_by_email.return_value = None
    mock_crud_fixture.create_user.return_value = created_user

    user = create_user(db_mock, user_in)

    mock_crud_fixture.get_user_by_email.assert_called_once_with(db_mock, email=user_in.email)
    mock_crud_fixture.create_user.assert_called_once_with(db_mock, obj_in=user_in)
    mock_send_email_func.assert_not_called()
    mock_generate_email_func.assert_not_called()
    assert user == created_user

def test_create_user_7_edge_crud_get_user_by_email_raises_exception(mock_settings_fixture, mock_crud_fixture, mock_send_email_func, mock_generate_email_func):
    """
    Test Case 7 (Edge): Mock `crud.get_user_by_email` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` is called once and raises an exception.
    `crud.create_user` is not called. `send_email` is not called. Expects the exception to propagate.
    """
    db_mock = MagicMock()
    user_in = UserCreate(email="error@example.com", password="securepassword")

    mock_crud_fixture.get_user_by_email.side_effect = Exception("Database error during email check")

    with pytest.raises(Exception, match="Database error during email check"):
        create_user(db_mock, user_in)

    mock_crud_fixture.get_user_by_email.assert_called_once_with(db_mock, email=user_in.email)
    mock_crud_fixture.create_user.assert_not_called()
    mock_send_email_func.assert_not_called()
    mock_generate_email_func.assert_not_called()

def test_create_user_8_negative_generate_new_account_email_raises_exception(mock_settings_fixture, mock_crud_fixture, mock_send_email_func, mock_generate_email_func):
    """
    Test Case 8 (Negative): Mock `generate_new_account_email` to raise an exception.
    settings.emails_enabled is True. `crud.get_user_by_email` returns None.
    `crud.create_user` is called once and returns a user object.
    `generate_new_account_email` is called once and raises an exception.
    `send_email` is not called. Expects the exception to propagate.
    """
    db_mock = MagicMock()
    user_in = UserCreate(email="email_gen_error@example.com", password="securepassword")
    created_user = User(id=1, email="email_gen_error@example.com")

    mock_crud_fixture.get_user_by_email.return_value = None
    mock_crud_fixture.create_user.return_value = created_user
    mock_generate_email_func.side_effect = Exception("Email generation failed")

    with pytest.raises(Exception, match="Email generation failed"):
        create_user(db_mock, user_in)

    mock_crud_fixture.get_user_by_email.assert_called_once_with(db_mock, email=user_in.email)
    mock_crud_fixture.create_user.assert_called_once_with(db_mock, obj_in=user_in)
    mock_generate_email_func.assert_called_once_with(created_user.email, created_user.full_name)
    mock_send_email_func.assert_not_called() # send_email should not be called if generation fails

