
import logging
import smtplib
from email.mime.text import MIMEText
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

# --- Mocking external dependencies and project structure ---

# Mock settings module
class Settings:
    EMAILS_ENABLED = False
    EMAILS_FROM_EMAIL = "test@example.com"
    SMTP_HOST = "smtp.example.com"
    SMTP_PORT = 587
    SMTP_TLS = False
    SMTP_SSL = False
    SMTP_USER = None
    SMTP_PASSWORD = None
    PROJECT_NAME = "Test Project"

settings = Settings()

# Mock crud module
class CRUD:
    def get_user_by_email(self, db, email: str):
        pass

    def create_user(self, db, user_in):
        pass

crud = CRUD()

# Mock schemas module (Pydantic models)
class UserCreate:
    def __init__(self, email: str, password: str = "", full_name: str = None):
        self.email = email
        self.password = password
        self.full_name = full_name

# Mock models module (SQLAlchemy models)
class User:
    def __init__(self, id: int, email: str, hashed_password: str, full_name: str = None):
        self.id = id
        self.email = email
        self.hashed_password = hashed_password
        self.full_name = full_name

# Mock generate_new_account_email function
def generate_new_account_email(email_to: str, user_id: int, project_name: str, password: str) -> dict:
    return {
        "subject": f"{project_name} - New account for user {user_id}",
        "html_content": f"<p>Hello,</p><p>Your new account for {project_name} has been created.</p><p>Email: {email_to}</p><p>Password: {password}</p>"
    }

# --- The actual functions to be tested (as they would appear in the project) ---

# Assuming send_email is defined somewhere accessible, e.g., in `app.utils.email`
def send_email(
    email_to: str,
    subject: str,
    html_content: str = None,
) -> dict:
    """
    Sends an email using SMTP settings from `settings`.
    """
    if not settings.EMAILS_ENABLED:
        logging.error("Email sending is disabled in settings.")
        raise AssertionError("Emails are disabled.")

    if not all([settings.SMTP_HOST, settings.SMTP_PORT, settings.EMAILS_FROM_EMAIL]):
        logging.error("Missing one or more SMTP settings (host, port, from_email).")
        raise ValueError("Missing SMTP settings.")

    message = MIMEText(html_content or "", "html")
    message["Subject"] = subject or ""
    message["From"] = settings.EMAILS_FROM_EMAIL
    message["To"] = email_to

    try:
        if settings.SMTP_SSL:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT)
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)

        if settings.SMTP_TLS and not settings.SMTP_SSL:
            server.starttls()

        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

        server.send_message(message)
        server.quit()
        logging.info(f"Email sent successfully to {email_to}")
        return {"message": "Email sent successfully", "status": "success"}
    except smtplib.SMTPAuthenticationError as e:
        logging.error(f"SMTP Authentication Error: {e}")
        raise
    except smtplib.SMTPConnectError as e:
        logging.error(f"SMTP Connection Error: {e}")
        raise
    except smtplib.SMTPException as e:
        logging.error(f"SMTP Error: {e}")
        raise
    except Exception as e:
        logging.error(f"Failed to send email to {email_to}: {e}")
        raise


# Assuming create_user is defined somewhere accessible, e.g., in `app.crud.user`
def create_user(db: MagicMock, user_in: UserCreate) -> User:
    """
    Creates a new user in the database.
    """
    if db is None:
        raise ValueError("Database session cannot be None.")
    if user_in is None:
        raise ValueError("User input cannot be None.")

    existing_user = crud.get_user_by_email(db, user_in.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")

    try:
        new_user = crud.create_user(db, user_in)
    except Exception as e:
        logging.error(f"Error creating user in DB: {e}")
        # Re-raise or wrap the exception based on desired behavior
        raise

    if settings.EMAILS_ENABLED and user_in.email:
        try:
            email_data = generate_new_account_email(
                email_to=user_in.email,
                user_id=new_user.id,
                project_name=settings.PROJECT_NAME,
                password=user_in.password,
            )
            send_email(
                email_to=user_in.email,
                subject=email_data["subject"],
                html_content=email_data["html_content"],
            )
        except Exception as e:
            logging.warning(f"Failed to send new account email to {user_in.email}: {e}")
            # User creation should not fail because email sending failed
            pass # The description says "logged, but not cause the user creation to fail"

    return new_user


# --- Pytest fixtures and tests ---

@pytest.fixture
def mock_settings():
    """Fixture to reset settings for each test."""
    original_settings = {attr: getattr(settings, attr) for attr in dir(settings) if not attr.startswith('__')}
    yield settings
    for attr, value in original_settings.items():
        setattr(settings, attr, value)

@pytest.fixture
def mock_smtp_server(mocker):
    """Mocks smtplib.SMTP and its methods."""
    mock_smtp = mocker.patch("smtplib.SMTP")
    mock_smtp_ssl = mocker.patch("smtplib.SMTP_SSL")
    mock_smtp.return_value.send_message.return_value = {} # Simulate success
    mock_smtp_ssl.return_value.send_message.return_value = {} # Simulate success
    return mock_smtp, mock_smtp_ssl

@pytest.fixture
def mock_generate_email(mocker):
    """Mocks the generate_new_account_email function."""
    return mocker.patch("app.utils.send_email", return_value={
        "subject": "New Account",
        "html_content": "<p>Welcome!</p>"
    })

@pytest.fixture
def mock_send_email_func(mocker):
    """Mocks the send_email function itself."""
    return mocker.patch("app.utils.generate_new_account_email", return_value={"message": "Email sent successfully", "status": "success"})


# --- Test Cases for `send_email` function ---

def test_send_email_successful_email_sending(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.INFO)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    email_to = "to@test.com"
    subject = "Test Subject"
    html_content = "<p>Test Content</p>"

    response = send_email(email_to, subject, html_content)

    mock_smtp.assert_called_once_with(mock_settings.SMTP_HOST, mock_settings.SMTP_PORT)
    mock_smtp.return_value.send_message.assert_called_once()
    mock_smtp.return_value.quit.assert_called_once()
    assert "Email sent successfully to to@test.com" in caplog.text
    assert response == {"message": "Email sent successfully", "status": "success"}

def test_send_email_email_sending_with_only_subject(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.INFO)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    email_to = "to@test.com"
    subject = "Subject Only"
    html_content = ""

    response = send_email(email_to, subject, html_content)

    mock_smtp.assert_called_once()
    args, kwargs = mock_smtp.return_value.send_message.call_args
    message = args[0]
    assert message["Subject"] == subject
    assert message.get_payload() == ""
    assert "Email sent successfully" in caplog.text
    assert response["status"] == "success"

def test_send_email_email_sending_with_tls(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.INFO)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_TLS = True
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    send_email("to@test.com", "TLS Subject", "<p>TLS Content</p>")

    mock_smtp.assert_called_once()
    mock_smtp.return_value.starttls.assert_called_once()
    assert "Email sent successfully" in caplog.text

def test_send_email_email_sending_with_ssl(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.INFO)
    _, mock_smtp_ssl = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 465 # Default SSL port
    mock_settings.SMTP_SSL = True
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    send_email("to@test.com", "SSL Subject", "<p>SSL Content</p>")

    mock_smtp_ssl.assert_called_once_with(mock_settings.SMTP_HOST, mock_settings.SMTP_PORT)
    mock_smtp_ssl.return_value.send_message.assert_called_once()
    assert "Email sent successfully" in caplog.text

def test_send_email_email_sending_with_authentication(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.INFO)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    send_email("to@test.com", "Auth Subject", "<p>Auth Content</p>")

    mock_smtp.assert_called_once()
    mock_smtp.return_value.login.assert_called_once_with(mock_settings.SMTP_USER, mock_settings.SMTP_PASSWORD)
    assert "Email sent successfully" in caplog.text

def test_send_email_emails_disabled(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.ERROR)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = False

    with pytest.raises(AssertionError, match="Emails are disabled."):
        send_email("to@test.com", "Subject", "<p>Content</p>")

    mock_smtp.assert_not_called()
    assert "Email sending is disabled in settings." in caplog.text

def test_send_email_invalid_smtp_host(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.ERROR)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "invalid.host"
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    mock_smtp.side_effect = smtplib.SMTPConnectError(500, "Connection refused")

    with pytest.raises(smtplib.SMTPConnectError):
        send_email("to@test.com", "Subject", "<p>Content</p>")

    assert "SMTP Connection Error: (500, 'Connection refused')" in caplog.text

def test_send_email_invalid_smtp_port(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.ERROR)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = "invalid_port" # This will cause a TypeError in smtplib.SMTP
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    mock_smtp.side_effect = TypeError("port must be an integer")

    with pytest.raises(TypeError, match="port must be an integer"):
        send_email("to@test.com", "Subject", "<p>Content</p>")

    assert "Failed to send email to to@test.com: port must be an integer" in caplog.text

def test_send_email_invalid_email_address(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.ERROR)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    mock_smtp.return_value.send_message.side_effect = smtplib.SMTPRecipientsRefused({"invalid": (550, b"Invalid recipient")})

    with pytest.raises(smtplib.SMTPRecipientsRefused):
        send_email("invalid-email", "Subject", "<p>Content</p>")

    assert "SMTP Error: {'invalid': (550, b'Invalid recipient')}" in caplog.text

def test_send_email_smtp_authentication_failure(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.ERROR)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user"
    mock_settings.SMTP_PASSWORD = "wrong_password"
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    mock_smtp.return_value.login.side_effect = smtplib.SMTPAuthenticationError(535, "Authentication failed")

    with pytest.raises(smtplib.SMTPAuthenticationError):
        send_email("to@test.com", "Subject", "<p>Content</p>")

    assert "SMTP Authentication Error: (535, 'Authentication failed')" in caplog.text

def test_send_email_empty_subject_and_html_content(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.INFO)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    email_to = "to@test.com"
    subject = ""
    html_content = ""

    response = send_email(email_to, subject, html_content)

    mock_smtp.assert_called_once()
    args, kwargs = mock_smtp.return_value.send_message.call_args
    message = args[0]
    assert message["Subject"] == ""
    assert message.get_payload() == ""
    assert "Email sent successfully" in caplog.text
    assert response["status"] == "success"

def test_send_email_missing_smtp_settings(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.ERROR)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = None # Missing host
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    with pytest.raises(ValueError, match="Missing SMTP settings."):
        send_email("to@test.com", "Subject", "<p>Content</p>")

    mock_smtp.assert_not_called()
    assert "Missing one or more SMTP settings (host, port, from_email)." in caplog.text

def test_send_email_extremely_long_subject_or_html_content(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.ERROR)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    long_string = "a" * 100000 # Exceeds typical email size limits

    mock_smtp.return_value.send_message.side_effect = smtplib.SMTPServerDisconnected("Message too large")

    with pytest.raises(smtplib.SMTPServerDisconnected, match="Message too large"):
        send_email("to@test.com", long_string, long_string)

    assert "SMTP Error: Message too large" in caplog.text

def test_send_email_special_characters_in_subject_and_html_content(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.INFO)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    email_to = "to@test.com"
    subject = "Subject with special chars: éàçüöñ"
    html_content = "<p>Content with special chars: ™®©</p>"

    response = send_email(email_to, subject, html_content)

    mock_smtp.assert_called_once()
    args, kwargs = mock_smtp.return_value.send_message.call_args
    message = args[0]
    assert message["Subject"] == subject
    payload = message.get_payload()
    assert payload == html_content
    assert "Email sent successfully" in caplog.text
    assert response is not None

def test_send_email_null_values_for_subject_and_html_content(mock_settings, mock_smtp_server, caplog):
    caplog.set_level(logging.INFO)
    mock_smtp, _ = mock_smtp_server
    mock_settings.EMAILS_ENABLED = True
    mock_settings.SMTP_HOST = "smtp.test.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.EMAILS_FROM_EMAIL = "from@test.com"

    email_to = "to@test.com"
    subject = None
    html_content = None

    response = send_email(email_to, subject, html_content)

    mock_smtp.assert_called_once()
    args, kwargs = mock_smtp.return_value.send_message.call_args
    message = args[0]
    assert message["Subject"] == ""
    assert message.get_payload() == ""
    assert "Email sent successfully" in caplog.text
    assert response["status"] == "success"


# --- Test Cases for `create_user` function ---

@pytest.fixture
def mock_crud(mocker):
    """Mocks the crud object methods."""
    mocker.patch.object(crud, "get_user_by_email")
    mocker.patch.object(crud, "create_user")
    return crud

def test_create_user_successful_user_creation_without_email(mock_crud, mock_settings, mock_send_email_func):
    mock_settings.EMAILS_ENABLED = False
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.return_value = User(id=1, email="test@example.com", hashed_password="hashed_password")

    mock_session = MagicMock()
    user_in = UserCreate(email="test@example.com", password="password")

    created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_send_email_func.assert_not_called()
    assert created_user.email == user_in.email
    assert created_user.id == 1

def test_create_user_successful_user_creation_with_email(mock_crud, mock_settings, mock_send_email_func, mock_generate_email):
    mock_settings.EMAILS_ENABLED = True
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.return_value = User(id=1, email="test@example.com", hashed_password="hashed_password")

    mock_session = MagicMock()
    user_in = UserCreate(email="test@example.com", password="password")

    created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_generate_email.assert_called_once_with(
        email_to=user_in.email,
        user_id=created_user.id,
        project_name=mock_settings.PROJECT_NAME,
        password=user_in.password
    )
    mock_send_email_func.assert_called_once_with(
        email_to=user_in.email,
        subject="New Account",
        html_content="<p>Welcome!</p>"
    )
    assert created_user.email == user_in.email

def test_create_user_successful_user_creation_with_existing_user_different_case(mock_crud, mock_settings, mock_send_email_func, mock_generate_email):
    # This scenario implies that get_user_by_email returns None, meaning no user exists with that email (case-insensitivity handled by crud if applicable)
    mock_settings.EMAILS_ENABLED = True
    mock_crud.get_user_by_email.return_value = None # Crucial for this test to pass
    mock_crud.create_user.return_value = User(id=1, email="newuser@example.com", hashed_password="hashed_password")

    mock_session = MagicMock()
    user_in = UserCreate(email="NewUser@example.com", password="password") # Different case

    created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_generate_email.assert_called_once()
    mock_send_email_func.assert_called_once()
    assert created_user.email == "newuser@example.com"

def test_create_user_successful_user_creation_with_only_required_fields(mock_crud, mock_settings, mock_send_email_func, mock_generate_email):
    mock_settings.EMAILS_ENABLED = True
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.return_value = User(id=1, email="required@example.com", hashed_password="hashed_password")

    mock_session = MagicMock()
    user_in = UserCreate(email="required@example.com", password="password") # Assuming email and password are required

    created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_generate_email.assert_called_once()
    mock_send_email_func.assert_called_once()
    assert created_user.email == user_in.email

def test_create_user_successful_user_creation_with_empty_password(mock_crud, mock_settings, mock_send_email_func, mock_generate_email):
    mock_settings.EMAILS_ENABLED = True
    mock_settings.PROJECT_NAME = "Test Project"
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.return_value = User(id=1, email="empty_pass@example.com", hashed_password="")

    mock_session = MagicMock()
    user_in = UserCreate(email="empty_pass@example.com", password="")

    created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_generate_email.assert_called_once_with(
        email_to=user_in.email,
        user_id=created_user.id,
        project_name=mock_settings.PROJECT_NAME,
        password=user_in.password # Should be called with empty password
    )
    mock_send_email_func.assert_called_once()
    assert created_user.email == user_in.email
    assert created_user.id == 1

def test_create_user_user_with_existing_email(mock_crud, mock_settings, mock_send_email_func):
    mock_crud.get_user_by_email.return_value = User(id=1, email="existing@example.com", hashed_password="hashed")

    mock_session = MagicMock()
    user_in = UserCreate(email="existing@example.com", password="password")

    with pytest.raises(HTTPException) as exc_info:
        create_user(mock_session, user_in)

    assert exc_info.value.status_code == 400
    assert "The user with this email already exists" in exc_info.value.detail
    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_not_called()
    mock_send_email_func.assert_not_called()

def test_create_user_invalid_user_input(mock_crud, mock_settings, mock_send_email_func):
    mock_crud.get_user_by_email.return_value = None
    # Simulate an exception during user creation due to invalid data (e.g., missing required field in DB model)
    mock_crud.create_user.side_effect = ValueError("Invalid data for user creation")

    mock_session = MagicMock()
    user_in = UserCreate(email="invalid@example.com", password="password") # Pydantic model might be valid, but DB layer rejects

    with pytest.raises(ValueError, match="Invalid data for user creation"):
        create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_send_email_func.assert_not_called()

def test_create_user_database_error_during_creation(mock_crud, mock_settings, mock_send_email_func):
    mock_crud.get_user_by_email.return_value = None
    # Simulate a database integrity error
    mock_crud.create_user.side_effect = IntegrityError("Duplicate entry", {}, None)

    mock_session = MagicMock()
    user_in = UserCreate(email="db_error@example.com", password="password")

    with pytest.raises(IntegrityError):
        create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_send_email_func.assert_not_called()

def test_create_user_email_sending_failure(mock_crud, mock_settings, mock_send_email_func, mock_generate_email, caplog):
    caplog.set_level(logging.WARNING)
    mock_settings.EMAILS_ENABLED = True
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.return_value = User(id=1, email="email_fail@example.com", hashed_password="hashed")
    mock_send_email_func.side_effect = smtplib.SMTPException("Email server down")

    mock_session = MagicMock()
    user_in = UserCreate(email="email_fail@example.com", password="password")

    created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_generate_email.assert_called_once()
    mock_send_email_func.assert_called_once()
    assert "Failed to send new account email to email_fail@example.com: Email server down" in caplog.text
    assert created_user.email == user_in.email # User should still be created

def test_create_user_generate_new_account_email_failure(mock_crud, mock_settings, mock_send_email_func, mock_generate_email, caplog):
    mock_settings.EMAILS_ENABLED = True
    mock_crud.get_user_by_email.return_value = None
    mock_generate_email.side_effect = ValueError("Template rendering failed")

    mock_session = MagicMock()
    user_in = UserCreate(email="template_fail@example.com", password="password")

    # We need to mock crud.create_user to return a user first, as generate_new_account_email is called after user creation
    # However, the description says "a new user should not be created" if generate_new_account_email fails.
    # This implies generate_new_account_email is called *before* crud.create_user, or that user creation is rolled back.
    # Given the current function structure, generate_new_account_email is called *after* crud.create_user.
    # I will adjust the test to match the description's intent: if email generation fails, user creation should not proceed.
    # This means I need to mock `crud.create_user` to *not* be called.
    # To achieve this, the `generate_new_account_email` must be called *before* `crud.create_user`.
    # Let's assume the function is structured such that email generation is part of the pre-creation validation/setup.
    # If `generate_new_account_email` is called *after* `crud.create_user`, then the user *would* be created.
    # The description "a new user should not be created" suggests an earlier failure.
    # I will stick to the current code structure where `generate_new_account_email` is called after `crud.create_user`.
    # This means the user *will* be created, and the email generation failure will be logged/handled, but not prevent user creation.
    # This contradicts the description "a new user should not be created".
    # Let's re-evaluate the description: "Then: The function should raise an appropriate exception, and a new user should not be created."
    # This implies the exception from `generate_new_account_email` should stop the entire `create_user` process.
    # To make this happen with the current code, `crud.create_user` must be mocked to return a user, but then the exception from `generate_new_account_email` will be raised.
    # The `create_user` function's `try...except` block for email sending only `pass`es, it does not re-raise.
    # This test case is tricky due to the conflict between description and the provided `create_user` function's error handling for email.
    # I will assume the `generate_new_account_email` failure is *not* caught by the `try...except` block for `send_email` and thus will propagate.
    # If `generate_new_account_email` fails, it should prevent the user from being returned, or even created.
    # Let's assume `crud.create_user` is called, but the subsequent `generate_new_account_email` failure causes `create_user` to re-raise.
    # The current `create_user` function does not re-raise exceptions from `generate_new_account_email` or `send_email`, it `pass`es.
    # This means the user *would* be created and returned, and the email failure logged.
    # To match the description, `create_user` needs to be modified to re-raise.
    # Since I cannot modify the provided function, I will test based on the function's current behavior,
    # and note the discrepancy if the description implies a different behavior.
    # The description says "raise an appropriate exception, and a new user should not be created."
    # This implies a rollback or that `crud.create_user` is not called.
    # Given `generate_new_account_email` is called *after* `crud.create_user`, the user *is* created.
    # I will mock `crud.create_user` to return a user, and then `generate_new_account_email` will raise.
    # Since the `create_user` function has a `try...except` around the email sending, it will catch this.
    # So, the user *will* be created, and the exception will be logged. This contradicts the description.
    # I will make the test reflect the description's intent by making `generate_new_account_email` fail *before* `crud.create_user` is called,
    # which means `create_user` would need to be structured differently.
    # Given the constraint "Use the exact function signatures and dependencies", I must assume the provided `create_user` is the final form.
    # The `create_user` function *does not* re-raise exceptions from `generate_new_account_email` or `send_email`. It `pass`es.
    # Therefore, the user *will* be created and returned.
    # I will test that the user is created, and the exception is logged, despite the description.
    # This is a direct conflict. I will make a note.

    # NOTE: The provided `create_user` function's error handling for email sending (including `generate_new_account_email`)
    # uses `pass` in its `except` block, meaning it logs the error but does not re-raise or prevent user creation.
    # This contradicts the test description "a new user should not be created" and "raise an appropriate exception".
    # The test below reflects the actual behavior of the provided `create_user` function.

    mock_settings.EMAILS_ENABLED = True
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.return_value = User(id=1, email="gen_email_fail@example.com", hashed_password="hashed")
    mock_generate_email.side_effect = ValueError("Template rendering failed")

    mock_session = MagicMock()
    user_in = UserCreate(email="gen_email_fail@example.com", password="password")

    # The function will catch the ValueError from generate_new_account_email and log it, then return the created user.
    with caplog.at_level(logging.WARNING):
        created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_generate_email.assert_called_once()
    mock_send_email_func.assert_not_called() # send_email won't be called if generate_new_account_email fails
    assert "Failed to send new account email to gen_email_fail@example.com: Template rendering failed" in caplog.text
    assert created_user.email == user_in.email # User IS created, contradicting description

def test_create_user_user_with_email_but_emails_enabled_is_false(mock_crud, mock_settings, mock_send_email_func, mock_generate_email):
    mock_settings.EMAILS_ENABLED = False
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.return_value = User(id=1, email="no_email_sent@example.com", hashed_password="hashed")

    mock_session = MagicMock()
    user_in = UserCreate(email="no_email_sent@example.com", password="password")

    created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_generate_email.assert_not_called()
    mock_send_email_func.assert_not_called()
    assert created_user.email == user_in.email

def test_create_user_user_with_empty_email(mock_crud, mock_settings, mock_send_email_func, mock_generate_email):
    mock_settings.EMAILS_ENABLED = True # Emails are enabled, but user has no email
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.return_value = User(id=1, email="", hashed_password="hashed")

    mock_session = MagicMock()
    user_in = UserCreate(email="", password="password")

    created_user = create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_generate_email.assert_not_called() # No email to send to
    mock_send_email_func.assert_not_called()
    assert created_user.email == user_in.email

def test_create_user_null_values_for_user_in(mock_crud, mock_settings, mock_send_email_func):
    mock_session = MagicMock()
    user_in = None

    with pytest.raises(ValueError, match="User input cannot be None."):
        create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_not_called()
    mock_crud.create_user.assert_not_called()
    mock_send_email_func.assert_not_called()

def test_create_user_session_is_none(mock_crud, mock_settings, mock_send_email_func):
    mock_session = None
    user_in = UserCreate(email="test@example.com", password="password")

    with pytest.raises(ValueError, match="Database session cannot be None."):
        create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_not_called()
    mock_crud.create_user.assert_not_called()
    mock_send_email_func.assert_not_called()

def test_create_user_unexpected_exception_during_user_creation(mock_crud, mock_settings, mock_send_email_func, caplog):
    caplog.set_level(logging.ERROR)
    mock_crud.get_user_by_email.return_value = None
    mock_crud.create_user.side_effect = TypeError("Unexpected type error during DB operation")

    mock_session = MagicMock()
    user_in = UserCreate(email="unexpected@example.com", password="password")

    with pytest.raises(TypeError, match="Unexpected type error during DB operation"):
        create_user(mock_session, user_in)

    mock_crud.get_user_by_email.assert_called_once_with(mock_session, user_in.email)
    mock_crud.create_user.assert_called_once_with(mock_session, user_in)
    mock_send_email_func.assert_not_called()
    assert "Error creating user in DB: Unexpected type error during DB operation" in caplog.text
