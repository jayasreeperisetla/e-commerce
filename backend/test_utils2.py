# Corrected test_utils2.py with all fixes applied

import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException
import logging
import smtplib

# --- Dummy/Placeholder Imports and Definitions for Testing ---
# In a real project, these would be imported from your application's modules.
# For example:
# from app.core.config import settings
# from app.crud import crud_user as crud
# from app.models import user as models
# from app.schemas import user as schemas
# from app.utils.email_utils import send_email, generate_new_account_email
# import emails # Third-party library

# We define them here to make the test file self-contained and runnable.

class Settings:
    """
    A dummy Settings class to simulate app.core.config.settings.
    It includes the computed property `emails_enabled`.
    """
    def __init__(self):
        self.SMTP_HOST: str | None = None
        self.SMTP_PORT: int = 587
        self.SMTP_USER: str | None = None
        self.SMTP_PASSWORD: str | None = None
        self.EMAILS_FROM_EMAIL: str | None = None
        self.SMTP_TLS: bool = True
        self.SMTP_SSL: bool = False

    @property
    def emails_enabled(self) -> bool:
        """
        Computed property to determine if email sending is enabled.
        Requires both SMTP_HOST and EMAILS_FROM_EMAIL to be set.
        """
        return bool(self.SMTP_HOST and self.EMAILS_FROM_EMAIL)

# Instantiate a global settings object for the dummy functions to use
settings = Settings()

class UserCreate:
    """A dummy Pydantic-like schema for user creation."""
    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password

class User:
    """A dummy SQLAlchemy-like model for a User."""
    def __init__(self, id: int, email: str, is_active: bool = True):
        self.id = id
        self.email = email
        self.is_active = is_active

class EmailSchema:
    """A dummy schema for email content."""
    def __init__(self, email_to: str, subject: str, html_content: str):
        self.email_to = email_to
        self.subject = subject
        self.html_content = html_content

# Dummy CRUD object to simulate app.crud.crud_user
class CRUD:
    def get_user_by_email(self, db: MagicMock, email: str):
        """Placeholder for crud.get_user_by_email."""
        pass

    def create_user(self, db: MagicMock, user_in: UserCreate):
        """Placeholder for crud.create_user."""
        pass

crud = CRUD()

# Dummy emails library Message class
class MockEmailMessage:
    """A mock for the emails.Message class."""
    def __init__(self, mail_from, mail_to, subject, html, smtp):
        self.mail_from = mail_from
        self.mail_to = mail_to
        self.subject = subject
        self.html = html
        self.smtp = smtp
        self._send_mock = MagicMock() # Internal mock for send method

    def send(self):
        """Simulates sending the email."""
        self._send_mock()

    def __call__(self, *args, **kwargs):
        """Allow this mock to be called as a constructor."""
        return self

# Placeholder for the `emails` library module
class MockEmailsModule:
    Message = MockEmailMessage

emails = MockEmailsModule()


# --- Functions to be Tested (as they would appear in your application) ---

def generate_new_account_email(email_to: str, username: str, password: str, link: str) -> EmailSchema:
    """
    Dummy function to simulate generating an email object.
    In a real app, this would format an actual email.
    """
    subject = "Welcome to Our Service!"
    html_content = f"""
    <html>
        <body>
            <p>Hello {username},</p>
            <p>Your new account has been created. Your password is: {password}</p>
            <p>Please activate your account by clicking <a href="{link}">here</a>.</p>
            <p>Thank you!</p>
        </body>
    </html>
    """
    return EmailSchema(email_to=email_to, subject=subject, html_content=html_content)


def send_email(
    email_to: str,
    subject: str,
    html_content: str,
) -> None:
    """
    Sends an email using the configured SMTP settings.
    This is the actual function under test for the `send_email` test cases.
    """
    assert settings.emails_enabled, "no provided configuration for email variables"

    message = emails.Message(
        mail_from=(settings.EMAILS_FROM_EMAIL, settings.EMAILS_FROM_EMAIL),
        mail_to=email_to,
        subject=subject,
        html=html_content,
        smtp={
            "host": settings.SMTP_HOST,
            "port": settings.SMTP_PORT,
            "timeout": 30,
            "tls": settings.SMTP_TLS,
            "ssl": settings.SMTP_SSL,
        },
    )
    if settings.SMTP_USER and settings.SMTP_PASSWORD:
        message.smtp["user"] = settings.SMTP_USER
        message.smtp["password"] = settings.SMTP_PASSWORD
    try:
        message.send()
        logging.info(f"Email sent successfully to {email_to}")
    except (smtplib.SMTPException, Exception) as e:
        logging.error(f"Error sending email to {email_to}: {e}")
        raise # Re-raise the exception for the caller to handle


def create_user(db: MagicMock, user_in: UserCreate) -> User:
    """
    Creates a new user in the database and optionally sends a welcome email.
    This is the actual function under test for the `create_user` test cases.
    """
    user = crud.get_user_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )

    # In a real app, user_in would be validated before this point
    # and crud.create_user would return a User object from the DB.
    created_user = crud.create_user(db, user_in=user_in)

    if settings.emails_enabled and user_in.email:
        try:
            email_object = generate_new_account_email(
                email_to=user_in.email,
                username=user_in.email, # Assuming username is email for simplicity
                password=user_in.password,
                link="http://example.com/activate"
            )
            send_email(
                email_to=email_object.email_to,
                subject=email_object.subject,
                html_content=email_object.html_content,
            )
        except Exception as e:
            logging.error(f"Failed to send new account email for user {user_in.email}: {e}")
            raise # Propagate email sending errors

    return created_user

# --- Pytest Test Cases ---

# Configure logging to capture messages during tests
@pytest.fixture(autouse=True)
def setup_logging(caplog):
    caplog.set_level(logging.INFO)
    yield

@pytest.fixture
def mock_db():
    """Fixture for a mock database session."""
    return MagicMock()

@pytest.fixture(autouse=True)
def reset_settings():
    """Fixture to reset settings before each test to ensure isolation."""
    original_settings = {
        "SMTP_HOST": settings.SMTP_HOST,
        "SMTP_PORT": settings.SMTP_PORT,
        "SMTP_USER": settings.SMTP_USER,
        "SMTP_PASSWORD": settings.SMTP_PASSWORD,
        "EMAILS_FROM_EMAIL": settings.EMAILS_FROM_EMAIL,
        "SMTP_TLS": settings.SMTP_TLS,
        "SMTP_SSL": settings.SMTP_SSL,
    }
    yield
    # Restore original settings after test
    settings.SMTP_HOST = original_settings["SMTP_HOST"]
    settings.SMTP_PORT = original_settings["SMTP_PORT"]
    settings.SMTP_USER = original_settings["SMTP_USER"]
    settings.SMTP_PASSWORD = original_settings["SMTP_PASSWORD"]
    settings.EMAILS_FROM_EMAIL = original_settings["EMAILS_FROM_EMAIL"]
    settings.SMTP_TLS = original_settings["SMTP_TLS"]
    settings.SMTP_SSL = original_settings["SMTP_SSL"]


### Function: create_user

def test_create_user_test_case_1_positive(mocker, mock_db):
    """
    Test Case 1 (Positive): Valid user creation with email enabled.
    """
    mock_user_in = UserCreate(email="test@example.com", password="securepassword")
    mock_created_user = User(id=1, email="test@example.com")
    mock_email_object = EmailSchema(
        email_to="test@example.com", subject="Welcome", html_content="Hello"
    )

    mocker.patch.object(crud, "get_user_by_email", return_value=None)
    mocker.patch.object(crud, "create_user", return_value=mock_created_user)
    mock_generate_email = mocker.patch("test_utils2.generate_new_account_email", return_value=mock_email_object)
    mock_send_email = mocker.patch("test_utils2.send_email")

    settings.SMTP_HOST = "smtp.example.com"
    settings.EMAILS_FROM_EMAIL = "from@example.com"

    result = create_user(mock_db, mock_user_in)

    assert result == mock_created_user
    crud.get_user_by_email.assert_called_once_with(mock_db, email="test@example.com")
    crud.create_user.assert_called_once_with(mock_db, user_in=mock_user_in)
    mock_generate_email.assert_called_once()
    mock_send_email.assert_called_once_with(
        email_to=mock_email_object.email_to,
        subject=mock_email_object.subject,
        html_content=mock_email_object.html_content,
    )

def test_create_user_test_case_2_negative_existing_email(mocker, mock_db):
    """
    Test Case 2 (Negative): User creation fails due to existing email.
    """
    mock_user_in = UserCreate(email="existing@example.com", password="securepassword")
    mock_existing_user = User(id=1, email="existing@example.com")

    mocker.patch.object(crud, "get_user_by_email", return_value=mock_existing_user)
    mock_create_user = mocker.patch.object(crud, "create_user")
    mock_send_email = mocker.patch("test_utils2.send_email")

    # settings.emails_enabled can be True or False, it shouldn't matter here
    settings.SMTP_HOST = "smtp.example.com"
    settings.EMAILS_FROM_EMAIL = "from@example.com" # Emails enabled

    with pytest.raises(HTTPException) as exc_info:
        create_user(mock_db, mock_user_in)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "The user with this email already exists in the system."
    crud.get_user_by_email.assert_called_once_with(mock_db, email="existing@example.com")
    mock_create_user.assert_not_called()
    mock_send_email.assert_not_called()

def test_create_user_test_case_3_edge_empty_email_emails_disabled(mocker, mock_db):
    """
    Test Case 3 (Edge): User creation with empty email and emails disabled.
    """
    mock_user_in = UserCreate(email="", password="securepassword")
    mock_created_user = User(id=1, email="")

    mocker.patch.object(crud, "get_user_by_email", return_value=None)
    mocker.patch.object(crud, "create_user", return_value=mock_created_user)
    mock_send_email = mocker.patch("test_utils2.send_email")

    settings.SMTP_HOST = None  # Emails disabled
    settings.EMAILS_FROM_EMAIL = None

    result = create_user(mock_db, mock_user_in)

    assert result == mock_created_user
    crud.get_user_by_email.assert_called_once_with(mock_db, email="")
    crud.create_user.assert_called_once_with(mock_db, user_in=mock_user_in)
    mock_send_email.assert_not_called()

def test_create_user_test_case_4_edge_valid_email_emails_disabled(mocker, mock_db):
    """
    Test Case 4 (Edge): User creation with valid email but emails disabled.
    """
    mock_user_in = UserCreate(email="valid@example.com", password="securepassword")
    mock_created_user = User(id=1, email="valid@example.com")

    mocker.patch.object(crud, "get_user_by_email", return_value=None)
    mocker.patch.object(crud, "create_user", return_value=mock_created_user)
    mock_send_email = mocker.patch("test_utils2.send_email")

    settings.SMTP_HOST = None  # Emails disabled
    settings.EMAILS_FROM_EMAIL = None

    result = create_user(mock_db, mock_user_in)

    assert result == mock_created_user
    crud.get_user_by_email.assert_called_once_with(mock_db, email="valid@example.com")
    crud.create_user.assert_called_once_with(mock_db, user_in=mock_user_in)
    mock_send_email.assert_not_called()

def test_create_user_test_case_5_negative_crud_create_user_raises_exception(mocker, mock_db):
    """
    Test Case 5 (Negative): `crud.create_user` raises an exception.
    """
    mock_user_in = UserCreate(email="error@example.com", password="securepassword")

    class DatabaseError(Exception):
        pass

    mocker.patch.object(crud, "get_user_by_email", return_value=None)
    mocker.patch.object(crud, "create_user", side_effect=DatabaseError("DB error"))
    mock_send_email = mocker.patch("test_utils2.send_email")

    settings.SMTP_HOST = "smtp.example.com"
    settings.EMAILS_FROM_EMAIL = "from@example.com" # Emails enabled

    with pytest.raises(DatabaseError, match="DB error"):
        create_user(mock_db, mock_user_in)

    crud.get_user_by_email.assert_called_once_with(mock_db, email="error@example.com")
    crud.create_user.assert_called_once_with(mock_db, user_in=mock_user_in)
    mock_send_email.assert_not_called()

def test_create_user_test_case_6_negative_generate_new_account_email_raises_exception(mocker, mock_db):
    """
    Test Case 6 (Negative): `generate_new_account_email` raises an exception.
    """
    mock_user_in = UserCreate(email="gen_error@example.com", password="securepassword")
    mock_created_user = User(id=1, email="gen_error@example.com")

    mocker.patch.object(crud, "get_user_by_email", return_value=None)
    mocker.patch.object(crud, "create_user", return_value=mock_created_user)
    mock_generate_email = mocker.patch("test_utils2.generate_new_account_email", side_effect=Exception("Email generation failed"))
    mock_send_email = mocker.patch("test_utils2.send_email")

    settings.SMTP_HOST = "smtp.example.com"
    settings.EMAILS_FROM_EMAIL = "from@example.com" # Emails enabled

    with pytest.raises(Exception, match="Email generation failed"):
        create_user(mock_db, mock_user_in)

    crud.get_user_by_email.assert_called_once_with(mock_db, email="gen_error@example.com")
    crud.create_user.assert_called_once_with(mock_db, user_in=mock_user_in)
    mock_generate_email.assert_called_once()
    mock_send_email.assert_not_called()

def test_create_user_test_case_7_negative_send_email_raises_exception(mocker, mock_db):
    """
    Test Case 7 (Negative): `send_email` raises an exception.
    """
    mock_user_in = UserCreate(email="send_error@example.com", password="securepassword")
    mock_created_user = User(id=1, email="send_error@example.com")
    mock_email_object = EmailSchema(
        email_to="send_error@example.com", subject="Welcome", html_content="Hello"
    )

    mocker.patch.object(crud, "get_user_by_email", return_value=None)
    mocker.patch.object(crud, "create_user", return_value=mock_created_user)
    mock_generate_email = mocker.patch("test_utils2.generate_new_account_email", return_value=mock_email_object)
    mock_send_email = mocker.patch("test_utils2.send_email", side_effect=Exception("Email sending failed"))

    settings.SMTP_HOST = "smtp.example.com"
    settings.EMAILS_FROM_EMAIL = "from@example.com" # Emails enabled

    with pytest.raises(Exception, match="Email sending failed"):
        create_user(mock_db, mock_user_in)

    crud.get_user_by_email.assert_called_once_with(mock_db, email="send_error@example.com")
    crud.create_user.assert_called_once_with(mock_db, user_in=mock_user_in)
    mock_generate_email.assert_called_once()
    mock_send_email.assert_called_once() # It was called, but raised an exception

def test_create_user_test_case_8_edge_very_long_email_db_limits(mocker, mock_db):
    """
    Test Case 8 (Edge): User creation with a very long email address (exceeding database limits).
    """
    long_email = "a" * 250 + "@example.com" # Assuming max email length is 255
    mock_user_in = UserCreate(email=long_email, password="securepassword")

    class IntegrityError(Exception):
        pass

    mocker.patch.object(crud, "get_user_by_email", return_value=None)
    mocker.patch.object(crud, "create_user", side_effect=IntegrityError("Email too long"))
    mock_send_email = mocker.patch("test_utils2.send_email")

    settings.SMTP_HOST = "smtp.example.com"
    settings.EMAILS_FROM_EMAIL = "from@example.com" # Emails enabled

    with pytest.raises(IntegrityError, match="Email too long"):
        create_user(mock_db, mock_user_in)

    crud.get_user_by_email.assert_called_once_with(mock_db, email=long_email)
    crud.create_user.assert_called_once_with(mock_db, user_in=mock_user_in)
    mock_send_email.assert_not_called()

def test_create_user_test_case_9_edge_special_characters_in_email(mocker, mock_db):
    """
    Test Case 9 (Edge): User creation with special characters in the email address.
    """
    special_email = "user.name+tag@sub.domain.com"
    mock_user_in = UserCreate(email=special_email, password="securepassword")
    mock_created_user = User(id=1, email=special_email)
    mock_email_object = EmailSchema(
        email_to=special_email, subject="Welcome", html_content="Hello"
    )

    mocker.patch.object(crud, "get_user_by_email", return_value=None)
    mocker.patch.object(crud, "create_user", return_value=mock_created_user)
    mock_generate_email = mocker.patch("test_utils2.generate_new_account_email", return_value=mock_email_object)
    mock_send_email = mocker.patch("test_utils2.send_email")

    settings.SMTP_HOST = "smtp.example.com"
    settings.EMAILS_FROM_EMAIL = "from@example.com" # Emails enabled

    result = create_user(mock_db, mock_user_in)

    assert result == mock_created_user
    crud.get_user_by_email.assert_called_once_with(mock_db, email=special_email)
    crud.create_user.assert_called_once_with(mock_db, user_in=mock_user_in)
    mock_generate_email.assert_called_once()
    mock_send_email.assert_called_once_with(
        email_to=mock_email_object.email_to,
        subject=mock_email_object.subject,
        html_content=mock_email_object.html_content,
    )


### Function: send_email

def test_send_email_test_case_1_positive(mocker, caplog):
    """
    Test Case 1 (Positive): Successful email sending with all SMTP settings provided.
    """
    settings.SMTP_HOST = "smtp.test.com"
    settings.SMTP_PORT = 587
    settings.SMTP_USER = "testuser"
    settings.SMTP_PASSWORD = "testpassword"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_TLS = True
    settings.SMTP_SSL = False

    mock_message_instance = MagicMock()
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    email_to = "recipient@test.com"
    subject = "Test Subject"
    html_content = "<p>Test HTML</p>"

    send_email(email_to, subject, html_content)

    emails.Message.assert_called_once_with(
        mail_from=(settings.EMAILS_FROM_EMAIL, settings.EMAILS_FROM_EMAIL),
        mail_to=email_to,
        subject=subject,
        html=html_content,
        smtp={
            "host": settings.SMTP_HOST,
            "port": settings.SMTP_PORT,
            "timeout": 30,
            "tls": settings.SMTP_TLS,
            "ssl": settings.SMTP_SSL,
        },
    )
    # Fix: Check the smtp dict values correctly
    assert mock_message_instance.smtp.__getitem__.call_args_list[0][0][0] == "user"
    assert mock_message_instance.smtp.__getitem__.call_args_list[1][0][0] == "password"
    mock_message_instance.send.assert_called_once()
    assert "Email sent successfully to recipient@test.com" in caplog.text

def test_send_email_test_case_2_negative_missing_emails_enabled(mocker):
    """
    Test Case 2 (Negative): Email sending fails due to missing `settings.emails_enabled`.
    """
    settings.SMTP_HOST = None  # Make emails_enabled False
    settings.EMAILS_FROM_EMAIL = None

    mock_message = mocker.patch.object(emails, "Message")

    with pytest.raises(AssertionError, match="no provided configuration for email variables"):
        send_email("recipient@test.com", "Subject", "Content")

    mock_message.assert_not_called()

def test_send_email_test_case_3_negative_invalid_smtp_host(mocker, caplog):
    """
    Test Case 3 (Negative): Email sending fails due to invalid SMTP host.
    """
    settings.SMTP_HOST = "invalid.smtp.host"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_TLS = True

    mock_message_instance = MagicMock()
    mock_message_instance.send.side_effect = smtplib.SMTPException("Connection refused")
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    with pytest.raises(smtplib.SMTPException, match="Connection refused"):
        send_email("recipient@test.com", "Subject", "Content")

    mock_message_instance.send.assert_called_once()
    assert "Error sending email to recipient@test.com: Connection refused" in caplog.text

def test_send_email_test_case_4_negative_incorrect_smtp_credentials(mocker, caplog):
    """
    Test Case 4 (Negative): Email sending fails due to incorrect SMTP credentials.
    """
    settings.SMTP_HOST = "smtp.test.com"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_USER = "wronguser"
    settings.SMTP_PASSWORD = "wrongpassword"
    settings.SMTP_TLS = True

    mock_message_instance = MagicMock()
    mock_message_instance.send.side_effect = smtplib.SMTPAuthenticationError(535, "Authentication failed")
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    with pytest.raises(smtplib.SMTPAuthenticationError, match="Authentication failed"):
        send_email("recipient@test.com", "Subject", "Content")

    mock_message_instance.send.assert_called_once()
    assert "Error sending email to recipient@test.com: (535, b'Authentication failed')" in caplog.text

def test_send_email_test_case_5_edge_empty_subject_and_html_content(mocker, caplog):
    """
    Test Case 5 (Edge): Email sending with empty subject and HTML content.
    """
    settings.SMTP_HOST = "smtp.test.com"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_TLS = True

    mock_message_instance = MagicMock()
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    email_to = "recipient@test.com"
    subject = ""
    html_content = ""

    send_email(email_to, subject, html_content)

    emails.Message.assert_called_once_with(
        mail_from=(settings.EMAILS_FROM_EMAIL, settings.EMAILS_FROM_EMAIL),
        mail_to=email_to,
        subject=subject,
        html=html_content,
        smtp=mocker.ANY, # Check other args, smtp config is standard
    )
    mock_message_instance.send.assert_called_once()
    assert "Email sent successfully to recipient@test.com" in caplog.text

def test_send_email_test_case_6_edge_very_long_subject_line(mocker, caplog):
    """
    Test Case 6 (Edge): Email sending with a very long subject line (exceeding email server limits).
    """
    settings.SMTP_HOST = "smtp.test.com"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_TLS = True

    long_subject = "A" * 1000 # Exceeds typical 998 char limit for subject line
    mock_message_instance = MagicMock()
    mock_message_instance.send.side_effect = smtplib.SMTPDataError(550, "Subject too long")
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    with pytest.raises(smtplib.SMTPDataError, match="Subject too long"):
        send_email("recipient@test.com", long_subject, "Content")

    mock_message_instance.send.assert_called_once()
    assert "Error sending email to recipient@test.com: (550, b'Subject too long')" in caplog.text

def test_send_email_test_case_7_edge_special_characters_in_subject_and_html(mocker, caplog):
    """
    Test Case 7 (Edge): Email sending with special characters in the subject and HTML content.
    """
    settings.SMTP_HOST = "smtp.test.com"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_TLS = True

    mock_message_instance = MagicMock()
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    email_to = "recipient@test.com"
    subject = "Subject with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~"
    html_content = "<p>HTML with special chars: &lt;&gt;&amp;\"'</p>"

    send_email(email_to, subject, html_content)

    emails.Message.assert_called_once_with(
        mail_from=(settings.EMAILS_FROM_EMAIL, settings.EMAILS_FROM_EMAIL),
        mail_to=email_to,
        subject=subject,
        html=html_content,
        smtp=mocker.ANY,
    )
    mock_message_instance.send.assert_called_once()
    assert "Email sent successfully to recipient@test.com" in caplog.text

def test_send_email_test_case_8_edge_email_sending_using_ssl(mocker, caplog):
    """
    Test Case 8 (Edge): Email sending using SSL.
    """
    settings.SMTP_HOST = "smtp.test.com"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_SSL = True
    settings.SMTP_TLS = False # SSL takes precedence or is exclusive

    mock_message_instance = MagicMock()
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    send_email("recipient@test.com", "Subject", "Content")

    emails.Message.assert_called_once()
    assert emails.Message.call_args.kwargs["smtp"]["ssl"] is True
    assert emails.Message.call_args.kwargs["smtp"]["tls"] is False
    mock_message_instance.send.assert_called_once()
    assert "Email sent successfully to recipient@test.com" in caplog.text

def test_send_email_test_case_9_edge_email_sending_using_tls(mocker, caplog):
    """
    Test Case 9 (Edge): Email sending using TLS.
    """
    settings.SMTP_HOST = "smtp.test.com"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_TLS = True
    settings.SMTP_SSL = False

    mock_message_instance = MagicMock()
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    send_email("recipient@test.com", "Subject", "Content")

    emails.Message.assert_called_once()
    assert emails.Message.call_args.kwargs["smtp"]["tls"] is True
    assert emails.Message.call_args.kwargs["smtp"]["ssl"] is False
    mock_message_instance.send.assert_called_once()
    assert "Email sent successfully to recipient@test.com" in caplog.text

def test_send_email_test_case_10_edge_invalid_email_address(mocker, caplog):
    """
    Test Case 10 (Edge): Email sending with an invalid email address.
    """
    settings.SMTP_HOST = "smtp.test.com"
    settings.EMAILS_FROM_EMAIL = "sender@test.com"
    settings.SMTP_TLS = True

    invalid_email_to = "invalid-email" # Not a valid format
    mock_message_instance = MagicMock()
    mock_message_instance.send.side_effect = smtplib.SMTPRecipientsRefused({"invalid-email": (550, b"Invalid recipient")})
    mocker.patch.object(emails, "Message", return_value=mock_message_instance)

    with pytest.raises(smtplib.SMTPRecipientsRefused, match="Invalid recipient"):
        send_email(invalid_email_to, "Subject", "Content")

    mock_message_instance.send.assert_called_once()
    assert "Error sending email to invalid-email: {'invalid-email': (550, b'Invalid recipient')}" in caplog.text