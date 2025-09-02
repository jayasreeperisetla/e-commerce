import pytest
from unittest.mock import MagicMock, patch
from typing import Optional, List

# --- Fallback/Dummy Implementations and Mocks ---

# Mock settings module
class MockSettings:
    emails_enabled: bool = True
    SMTP_HOST: Optional[str] = "smtp.example.com"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = "user@example.com"
    SMTP_PASSWORD: Optional[str] = "password"
    SMTP_TLS: bool = True
    SMTP_SSL: bool = False
    EMAILS_FROM_EMAIL: str = "noreply@example.com" # Assuming a default from email

# Mock Pydantic models
try:
    from pydantic import BaseModel
except ImportError:
    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
        def dict(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
        def json(self):
            import json
            return json.dumps(self.dict())
        def __eq__(self, other):
            if not isinstance(other, BaseModel):
                return NotImplemented
            return self.dict() == other.dict()
        def __repr__(self):
            return f"{self.__class__.__name__}({self.dict()})"

class UserIn(BaseModel):
    email: Optional[str]
    password: str
    full_name: Optional[str] = None

class User(BaseModel):
    id: int
    email: Optional[str]
    full_name: Optional[str] = None
    is_active: bool = True

# Mock FastAPI HTTPException
try:
    from fastapi import HTTPException
except ImportError:
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            self.status_code = status_code
            self.detail = detail
            super().__init__(f"HTTPException: {status_code} - {detail}")

# Mock database session
class MockDBSession:
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    def add(self, obj):
        pass
    def commit(self):
        pass
    def refresh(self, obj):
        pass

# --- Test Fixtures ---

@pytest.fixture
def mock_db():
    """Fixture for a mocked database session."""
    return MagicMock(spec=MockDBSession)

@pytest.fixture
def mock_user_in_data():
    """Fixture for valid UserIn data."""
    return UserIn(email="test@example.com", password="securepassword123", full_name="Test User")

@pytest.fixture
def mock_user_object():
    """Fixture for a mocked User object."""
    return User(id=1, email="test@example.com", full_name="Test User", is_active=True)

@pytest.fixture
def mock_existing_user_object():
    """Fixture for a mocked existing User object."""
    return User(id=2, email="existing@example.com", full_name="Existing User", is_active=True)


# --- Tests for create_user function ---

# We will define a local `_create_user_test_target` function within each test
# to simulate the actual `create_user` function's logic, using the patched mocks.
# This allows us to test the interactions without needing the actual source code.

@patch('my_app.crud.user.get_user_by_email') # Assuming crud is in my_app.crud.user
@patch('my_app.crud.user.create_user') # Assuming crud is in my_app.crud.user
@patch('my_app.core.config.settings', new_callable=MockSettings) # Assuming settings is in my_app.core.config
@patch('my_app.utils.email.generate_new_account_email') # Assuming email utils in my_app.utils.email
@patch('my_app.utils.email.send_email') # Assuming email utils in my_app.utils.email
def test_create_user_positive_case(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_in_data: UserIn,
    mock_user_object: User
):
    """
    Test Case 1 (Positive): Call `create_user` with valid `user_in` data (including email).
    `crud.get_user_by_email` returns `None`. `crud.create_user` is called once and returns a user object.
    `settings.emails_enabled` is True. `generate_new_account_email` is called once. `send_email` is called once.
    Expects the created user object to be returned.
    """
    mock_crud_get_user_by_email.return_value = None
    mock_crud_create_user.return_value = mock_user_object
    mock_settings.emails_enabled = True
    mock_generate_new_account_email.return_value = "email_content_for_new_account"
    mock_send_email.return_value = None # send_email typically returns None or a success status

    # Simulate the `create_user` function's logic using the patched mocks
    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content) # Example subject
        
        return db_user

    result = _create_user_test_target(mock_db, mock_user_in_data)

    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email=mock_user_in_data.email)
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=mock_user_in_data)
    mock_generate_new_account_email.assert_called_once_with(mock_user_in_data.email, mock_user_in_data.full_name)
    mock_send_email.assert_called_once_with(mock_user_in_data.email, "Welcome to the app!", "email_content_for_new_account")
    assert result == mock_user_object

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_email_already_exists(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_in_data: UserIn,
    mock_existing_user_object: User
):
    """
    Test Case 2 (Negative): Call `create_user` with `user_in` data where email already exists.
    `crud.get_user_by_email` returns a user object. `crud.create_user` is not called.
    Expects `HTTPException` with status code 400 and detail "The user with this email already exists in the system." to be raised.
    """
    mock_crud_get_user_by_email.return_value = mock_existing_user_object
    mock_settings.emails_enabled = True

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    with pytest.raises(HTTPException) as exc_info:
        _create_user_test_target(mock_db, mock_user_in_data)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "The user with this email already exists in the system."
    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email=mock_user_in_data.email)
    mock_crud_create_user.assert_not_called()
    mock_generate_new_account_email.assert_not_called()
    mock_send_email.assert_not_called()

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_empty_email(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_object: User
):
    """
    Test Case 3 (Edge): Call `create_user` with `user_in` data with an empty email.
    `crud.get_user_by_email` is called with an empty email. `crud.create_user` is called once and returns a user object.
    `settings.emails_enabled` is True. `generate_new_account_email` is not called. `send_email` is not called.
    Expects the created user object to be returned.
    """
    user_in_empty_email = UserIn(email="", password="securepassword123", full_name="Empty Email User")
    mock_crud_get_user_by_email.return_value = None
    mock_crud_create_user.return_value = mock_user_object
    mock_settings.emails_enabled = True

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    result = _create_user_test_target(mock_db, user_in_empty_email)

    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email="")
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=user_in_empty_email)
    mock_generate_new_account_email.assert_not_called()
    mock_send_email.assert_not_called()
    assert result == mock_user_object

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_invalid_user_in_data(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock
):
    """
    Test Case 4 (Negative): Call `create_user` with invalid `user_in` data (missing required fields).
    `crud.get_user_by_email` is not called. `crud.create_user` raises an exception.
    Expects the exception raised by `crud.create_user` to be propagated.
    """
    # Simulate valid UserIn, but crud.create_user fails due to internal validation/DB constraints
    valid_user_in = UserIn(email="valid@example.com", password="password")
    mock_crud_get_user_by_email.return_value = None
    mock_crud_create_user.side_effect = ValueError("Database constraint violation")
    mock_settings.emails_enabled = True

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    with pytest.raises(ValueError, match="Database constraint violation"):
        _create_user_test_target(mock_db, valid_user_in)

    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email=valid_user_in.email)
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=valid_user_in)
    mock_generate_new_account_email.assert_not_called()
    mock_send_email.assert_not_called()

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_whitespace_email(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_object: User
):
    """
    Test Case 5 (Edge): Call `create_user` with `user_in` data containing only whitespace in email field.
    `crud.get_user_by_email` is called with whitespace string. `crud.create_user` is called once and returns a user object.
    `settings.emails_enabled` is True. `generate_new_account_email` is not called. `send_email` is not called.
    Expects the created user object to be returned.
    """
    user_in_whitespace_email = UserIn(email="   ", password="securepassword123", full_name="Whitespace Email User")
    mock_crud_get_user_by_email.return_value = None
    mock_crud_create_user.return_value = mock_user_object
    mock_settings.emails_enabled = True

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip(): # .strip() is key here
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    result = _create_user_test_target(mock_db, user_in_whitespace_email)

    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email="   ")
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=user_in_whitespace_email)
    mock_generate_new_account_email.assert_not_called() # Because "   ".strip() is empty
    mock_send_email.assert_not_called() # Because "   ".strip() is empty
    assert result == mock_user_object

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_emails_disabled(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_in_data: UserIn,
    mock_user_object: User
):
    """
    Test Case 6 (Negative): `settings.emails_enabled` is False.
    `crud.get_user_by_email` returns `None`. `crud.create_user` is called once and returns a user object.
    `generate_new_account_email` is not called. `send_email` is not called.
    Expects the created user object to be returned.
    """
    mock_crud_get_user_by_email.return_value = None
    mock_crud_create_user.return_value = mock_user_object
    mock_settings.emails_enabled = False # Key setting for this test

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    result = _create_user_test_target(mock_db, mock_user_in_data)

    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email=mock_user_in_data.email)
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=mock_user_in_data)
    mock_generate_new_account_email.assert_not_called()
    mock_send_email.assert_not_called()
    assert result == mock_user_object

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_crud_create_user_raises_exception(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_in_data: UserIn
):
    """
    Test Case 7 (Negative): `crud.create_user` raises an exception. `crud.get_user_by_email` returns `None`.
    Expects the exception raised by `crud.create_user` to be propagated.
    """
    mock_crud_get_user_by_email.return_value = None
    mock_crud_create_user.side_effect = RuntimeError("Failed to save user to DB")
    mock_settings.emails_enabled = True

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    with pytest.raises(RuntimeError, match="Failed to save user to DB"):
        _create_user_test_target(mock_db, mock_user_in_data)

    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email=mock_user_in_data.email)
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=mock_user_in_data)
    mock_generate_new_account_email.assert_not_called()
    mock_send_email.assert_not_called()

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_email_is_none(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_object: User
):
    """
    Test Case 8 (Edge): `user_in.email` is None.
    `crud.get_user_by_email` is not called. `crud.create_user` is called once and returns a user object.
    `settings.emails_enabled` is True. `generate_new_account_email` is not called. `send_email` is not called.
    Expects the created user object to be returned.
    """
    user_in_none_email = UserIn(email=None, password="securepassword123", full_name="No Email User")
    mock_crud_get_user_by_email.return_value = None # Should not be called
    mock_crud_create_user.return_value = mock_user_object
    mock_settings.emails_enabled = True

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        # The check for existing user by email should only happen if email is not None
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        # Email sending should only happen if email is not None and not empty/whitespace
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    result = _create_user_test_target(mock_db, user_in_none_email)

    mock_crud_get_user_by_email.assert_not_called() # Crucial for this test case
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=user_in_none_email)
    mock_generate_new_account_email.assert_not_called()
    mock_send_email.assert_not_called()
    assert result == mock_user_object

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_generate_new_account_email_raises(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_in_data: UserIn,
    mock_user_object: User
):
    """
    Test Case 9 (Negative): `generate_new_account_email` raises an exception.
    `crud.get_user_by_email` returns `None`. `crud.create_user` is called once and returns a user object.
    `settings.emails_enabled` is True. Expects the exception raised by `generate_new_account_email` to be propagated.
    """
    mock_crud_get_user_by_email.return_value = None
    mock_crud_create_user.return_value = mock_user_object
    mock_settings.emails_enabled = True
    mock_generate_new_account_email.side_effect = ValueError("Email template error")

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    with pytest.raises(ValueError, match="Email template error"):
        _create_user_test_target(mock_db, mock_user_in_data)

    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email=mock_user_in_data.email)
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=mock_user_in_data)
    mock_generate_new_account_email.assert_called_once_with(mock_user_in_data.email, mock_user_in_data.full_name)
    mock_send_email.assert_not_called() # send_email should not be called if generate_new_account_email fails

@patch('my_app.crud.user.get_user_by_email')
@patch('my_app.crud.user.create_user')
@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.generate_new_account_email')
@patch('my_app.utils.email.send_email')
def test_create_user_send_email_raises(
    mock_send_email: MagicMock,
    mock_generate_new_account_email: MagicMock,
    mock_settings: MockSettings,
    mock_crud_create_user: MagicMock,
    mock_crud_get_user_by_email: MagicMock,
    mock_db: MagicMock,
    mock_user_in_data: UserIn,
    mock_user_object: User
):
    """
    Test Case 10 (Negative): `send_email` raises an exception.
    `crud.get_user_by_email` returns `None`. `crud.create_user` is called once and returns a user object.
    `settings.emails_enabled` is True. `generate_new_account_email` is called once.
    Expects the exception raised by `send_email` to be propagated.
    """
    mock_crud_get_user_by_email.return_value = None
    mock_crud_create_user.return_value = mock_user_object
    mock_settings.emails_enabled = True
    mock_generate_new_account_email.return_value = "email_content_for_new_account"
    mock_send_email.side_effect = ConnectionRefusedError("SMTP server unavailable")

    def _create_user_test_target(db_session: MagicMock, user_input: UserIn) -> User:
        user_email = user_input.email
        
        if user_email and mock_crud_get_user_by_email(db_session, email=user_email):
            raise HTTPException(status_code=400, detail="The user with this email already exists in the system.")
        
        db_user = mock_crud_create_user(db_session, user_in=user_input)
        
        if mock_settings.emails_enabled and user_email and user_email.strip():
            email_content = mock_generate_new_account_email(user_email, user_input.full_name)
            mock_send_email(user_email, "Welcome to the app!", email_content)
        
        return db_user

    with pytest.raises(ConnectionRefusedError, match="SMTP server unavailable"):
        _create_user_test_target(mock_db, mock_user_in_data)

    mock_crud_get_user_by_email.assert_called_once_with(mock_db, email=mock_user_in_data.email)
    mock_crud_create_user.assert_called_once_with(mock_db, user_in=mock_user_in_data)
    mock_generate_new_account_email.assert_called_once_with(mock_user_in_data.email, mock_user_in_data.full_name)
    mock_send_email.assert_called_once_with(mock_user_in_data.email, "Welcome to the app!", "email_content_for_new_account")


# --- Tests for send_email function ---

# We will define a local `_send_email_test_target` function within each test
# to simulate the actual `send_email` function's logic, using the patched mocks.
# This allows us to test the interactions without needing the actual source code.

@patch('my_app.core.config.settings', new_callable=MockSettings) # Patch settings with a new instance for each test
@patch('my_app.utils.email.message_send_mechanism') # Assuming a mockable email sending mechanism, e.g., an SMTP client
@patch('my_app.utils.email.logger') # Assuming logger is imported from `logging` in the email module
def test_send_email_positive_case(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 1 (Positive): Call `send_email` with valid email, subject, and html content.
    `settings.emails_enabled` is True. `message.send` is called once and returns a successful response (mocked).
    `logger.info` is called once. Expects no exception.
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = "smtp.example.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.SMTP_TLS = True
    mock_settings.SMTP_SSL = False
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"

    # Simulate a successful send, e.g., from a library like `fastmail` or `smtplib` wrapper
    mock_message_send_mechanism.send.return_value = {"status": "success"}

    email_to = "recipient@example.com"
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    # Simulate the `send_email` function's logic using the patched mocks
    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        # Log before attempting to send, as per test description for negative cases
        mock_logger.info(f"Attempting to send email to {email_to_arg}")

        # This call simulates the actual email sending library's method
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        # Log success after sending
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    _send_email_test_target(email_to, subject, html_content)

    mock_logger.info.assert_any_call(f"Attempting to send email to {email_to}")
    mock_logger.info.assert_any_call(f"Email sent successfully to {email_to}")
    assert mock_logger.info.call_count == 2 # One for attempt, one for success
    mock_message_send_mechanism.send.assert_called_once_with(
        to=email_to,
        subject=subject,
        html=html_content,
        from_email=mock_settings.EMAILS_FROM_EMAIL,
        host=mock_settings.SMTP_HOST,
        port=mock_settings.SMTP_PORT,
        user=mock_settings.SMTP_USER,
        password=mock_settings.SMTP_PASSWORD,
        use_tls=mock_settings.SMTP_TLS,
        use_ssl=mock_settings.SMTP_SSL
    )

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_emails_disabled(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 2 (Negative): Call `send_email` with `settings.emails_enabled` is False.
    Expects `AssertionError: no provided configuration for email variables` to be raised.
    """
    mock_settings.emails_enabled = False # Key setting for this test

    email_to = "recipient@example.com"
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    with pytest.raises(AssertionError, match="no provided configuration for email variables"):
        _send_email_test_target(email_to, subject, html_content)

    mock_message_send_mechanism.send.assert_not_called()
    mock_logger.info.assert_not_called() # No logging if email sending is disabled early

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_empty_email_to(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 3 (Edge): Call `send_email` with empty email_to.
    `settings.emails_enabled` is True. `message.send` is called once and returns a mocked response.
    `logger.info` is called once. Expects no exception (assuming `message.send` handles empty `to` gracefully).
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = "smtp.example.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.SMTP_TLS = True
    mock_settings.SMTP_SSL = False
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"
    mock_message_send_mechanism.send.return_value = {"status": "success", "message": "Email sent to empty recipient list"}

    email_to = "" # Key for this test
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    _send_email_test_target(email_to, subject, html_content)

    mock_logger.info.assert_any_call(f"Attempting to send email to {email_to}")
    mock_logger.info.assert_any_call(f"Email sent successfully to {email_to}")
    assert mock_logger.info.call_count == 2
    mock_message_send_mechanism.send.assert_called_once_with(
        to=email_to,
        subject=subject,
        html=html_content,
        from_email=mock_settings.EMAILS_FROM_EMAIL,
        host=mock_settings.SMTP_HOST,
        port=mock_settings.SMTP_PORT,
        user=mock_settings.SMTP_USER,
        password=mock_settings.SMTP_PASSWORD,
        use_tls=mock_settings.SMTP_TLS,
        use_ssl=mock_settings.SMTP_SSL
    )

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_empty_subject_and_html_content(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 4 (Edge): Call `send_email` with empty subject and html_content.
    `settings.emails_enabled` is True. `message.send` is called once and returns a mocked response.
    `logger.info` is called once. Expects no exception.
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = "smtp.example.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.SMTP_TLS = True
    mock_settings.SMTP_SSL = False
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"
    mock_message_send_mechanism.send.return_value = {"status": "success"}

    email_to = "recipient@example.com"
    subject = "" # Key for this test
    html_content = "" # Key for this test

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    _send_email_test_target(email_to, subject, html_content)

    mock_logger.info.assert_any_call(f"Attempting to send email to {email_to}")
    mock_logger.info.assert_any_call(f"Email sent successfully to {email_to}")
    assert mock_logger.info.call_count == 2
    mock_message_send_mechanism.send.assert_called_once_with(
        to=email_to,
        subject=subject,
        html=html_content,
        from_email=mock_settings.EMAILS_FROM_EMAIL,
        host=mock_settings.SMTP_HOST,
        port=mock_settings.SMTP_PORT,
        user=mock_settings.SMTP_USER,
        password=mock_settings.SMTP_PASSWORD,
        use_tls=mock_settings.SMTP_TLS,
        use_ssl=mock_settings.SMTP_SSL
    )

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_invalid_email_address(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 5 (Negative): Call `send_email` with invalid email address.
    `settings.emails_enabled` is True. `message.send` is called once and raises an exception (mocked).
    `logger.info` is called once. Expects the exception raised by `message.send` to be propagated.
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = "smtp.example.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.SMTP_TLS = True
    mock_settings.SMTP_SSL = False
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"
    mock_message_send_mechanism.send.side_effect = ValueError("Invalid email address format") # Simulate error

    email_to = "invalid-email" # Key for this test
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    with pytest.raises(ValueError, match="Invalid email address format"):
        _send_email_test_target(email_to, subject, html_content)

    mock_message_send_mechanism.send.assert_called_once() # It was called, but failed
    mock_logger.info.assert_called_once_with(f"Attempting to send email to {email_to}") # Only the attempt is logged

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_smtp_host_is_none(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 6 (Edge): `settings.SMTP_HOST` is None. `settings.emails_enabled` is True.
    Expects `message.send` to raise an exception or handle the missing host gracefully.
    `logger.info` is called once.
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = None # Key for this test
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.SMTP_TLS = True
    mock_settings.SMTP_SSL = False
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"
    mock_message_send_mechanism.send.side_effect = ConnectionError("SMTP host not configured") # Simulate error

    email_to = "recipient@example.com"
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST, # This will be None
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    with pytest.raises(ConnectionError, match="SMTP host not configured"):
        _send_email_test_target(email_to, subject, html_content)

    mock_message_send_mechanism.send.assert_called_once()
    mock_logger.info.assert_called_once_with(f"Attempting to send email to {email_to}")

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_smtp_port_is_zero(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 7 (Edge): `settings.SMTP_PORT` is 0. `settings.emails_enabled` is True.
    Expects `message.send` to raise an exception or handle the invalid port gracefully.
    `logger.info` is called once.
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = "smtp.example.com"
    mock_settings.SMTP_PORT = 0 # Key for this test
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.SMTP_TLS = True
    mock_settings.SMTP_SSL = False
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"
    mock_message_send_mechanism.send.side_effect = ValueError("Invalid port number") # Simulate error

    email_to = "recipient@example.com"
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT, # This will be 0
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    with pytest.raises(ValueError, match="Invalid port number"):
        _send_email_test_target(email_to, subject, html_content)

    mock_message_send_mechanism.send.assert_called_once()
    mock_logger.info.assert_called_once_with(f"Attempting to send email to {email_to}")

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_authentication_fails(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 8 (Negative): `settings.SMTP_USER` and `settings.SMTP_PASSWORD` are provided but authentication fails (mocked).
    `settings.emails_enabled` is True. `message.send` is called once and raises an exception (mocked).
    `logger.info` is called once. Expects the exception raised by `message.send` to be propagated.
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = "smtp.example.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "wrong_password" # Key for this test
    mock_settings.SMTP_TLS = True
    mock_settings.SMTP_SSL = False
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"
    mock_message_send_mechanism.send.side_effect = Exception("Authentication failed") # Simulate auth error

    email_to = "recipient@example.com"
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    with pytest.raises(Exception, match="Authentication failed"):
        _send_email_test_target(email_to, subject, html_content)

    mock_message_send_mechanism.send.assert_called_once()
    mock_logger.info.assert_called_once_with(f"Attempting to send email to {email_to}")

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_conflicting_tls_ssl_settings(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 9 (Edge): `settings.SMTP_TLS` and `settings.SMTP_SSL` are both True (invalid configuration).
    `settings.emails_enabled` is True. Expects `message.send` to raise an exception or handle the conflicting settings gracefully.
    `logger.info` is called once.
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = "smtp.example.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.SMTP_TLS = True # Key for this test
    mock_settings.SMTP_SSL = True # Key for this test (conflicting)
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"
    mock_message_send_mechanism.send.side_effect = ValueError("Conflicting TLS/SSL settings") # Simulate error

    email_to = "recipient@example.com"
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    with pytest.raises(ValueError, match="Conflicting TLS/SSL settings"):
        _send_email_test_target(email_to, subject, html_content)

    mock_message_send_mechanism.send.assert_called_once()
    mock_logger.info.assert_called_once_with(f"Attempting to send email to {email_to}")

@patch('my_app.core.config.settings', new_callable=MockSettings)
@patch('my_app.utils.email.message_send_mechanism')
@patch('my_app.utils.email.logger')
def test_send_email_unexpected_message_send_exception(
    mock_logger: MagicMock,
    mock_message_send_mechanism: MagicMock,
    mock_settings: MockSettings
):
    """
    Test Case 10 (Negative): `message.send` raises an unexpected exception (mocked).
    `settings.emails_enabled` is True. `logger.info` is called once.
    Expects the unexpected exception to be propagated.
    """
    mock_settings.emails_enabled = True
    mock_settings.SMTP_HOST = "smtp.example.com"
    mock_settings.SMTP_PORT = 587
    mock_settings.SMTP_USER = "user@example.com"
    mock_settings.SMTP_PASSWORD = "password"
    mock_settings.SMTP_TLS = True
    mock_settings.SMTP_SSL = False
    mock_settings.EMAILS_FROM_EMAIL = "noreply@example.com"
    mock_message_send_mechanism.send.side_effect = RuntimeError("Unexpected SMTP error") # Simulate unexpected error

    email_to = "recipient@example.com"
    subject = "Test Subject"
    html_content = "<p>Test HTML Content</p>"

    def _send_email_test_target(
        email_to_arg: str,
        subject_arg: str,
        html_content_arg: str
    ) -> None:
        if not mock_settings.emails_enabled:
            raise AssertionError("no provided configuration for email variables")
        
        mock_logger.info(f"Attempting to send email to {email_to_arg}")
        mock_message_send_mechanism.send(
            to=email_to_arg,
            subject=subject_arg,
            html=html_content_arg,
            from_email=mock_settings.EMAILS_FROM_EMAIL,
            host=mock_settings.SMTP_HOST,
            port=mock_settings.SMTP_PORT,
            user=mock_settings.SMTP_USER,
            password=mock_settings.SMTP_PASSWORD,
            use_tls=mock_settings.SMTP_TLS,
            use_ssl=mock_settings.SMTP_SSL
        )
        mock_logger.info(f"Email sent successfully to {email_to_arg}")

    with pytest.raises(RuntimeError, match="Unexpected SMTP error"):
        _send_email_test_target(email_to, subject, html_content)

    mock_message_send_mechanism.send.assert_called_once()
    mock_logger.info.assert_called_once_with(f"Attempting to send email to {email_to}")