### Function: create_user
- **Test Case 1 (Positive):**  Valid user creation with email enabled.  Mocks `crud.get_user_by_email` to return `None` (user doesn't exist). Mocks `crud.create_user` to return a valid user object. Mocks `generate_new_account_email` to return a valid email object. Mocks `send_email` to simulate successful email sending.  `settings.emails_enabled` is `True`.  Asserts that `create_user` returns the created user object and that `send_email` is called once.

- **Test Case 2 (Negative):** User creation fails due to existing email. Mocks `crud.get_user_by_email` to return a user object (user already exists).  Mocks `crud.create_user` is not called. `settings.emails_enabled` can be True or False. Asserts that `create_user` raises `HTTPException(status_code=400, detail="The user with this email already exists in the system.")` and that `send_email` is not called.

- **Test Case 3 (Edge):** User creation with empty email and emails disabled.  Mocks `crud.get_user_by_email` to return `None`. Mocks `crud.create_user` to return a valid user object (with an empty email). `settings.emails_enabled` is `False`. Asserts that `create_user` returns the created user object and that `send_email` is not called.

- **Test Case 4 (Edge):** User creation with valid email but emails disabled. Mocks `crud.get_user_by_email` to return `None`. Mocks `crud.create_user` to return a valid user object. `settings.emails_enabled` is `False`. Asserts that `create_user` returns the created user object and that `send_email` is not called.

- **Test Case 5 (Negative):**  `crud.create_user` raises an exception. Mocks `crud.get_user_by_email` to return `None`. Mocks `crud.create_user` to raise a custom exception (e.g., `DatabaseError`). `settings.emails_enabled` can be True or False. Asserts that `create_user` propagates the exception.

- **Test Case 6 (Negative):** `generate_new_account_email` raises an exception. Mocks `crud.get_user_by_email` to return `None`. Mocks `crud.create_user` to return a valid user object. Mocks `generate_new_account_email` to raise an exception (e.g., `ValueError`). `settings.emails_enabled` is `True`. Asserts that `create_user` raises an exception.

- **Test Case 7 (Negative):**  `send_email` raises an exception. Mocks `crud.get_user_by_email` to return `None`. Mocks `crud.create_user` to return a valid user object. Mocks `generate_new_account_email` to return a valid email object. Mocks `send_email` to raise an exception (e.g., `SMTPException`). `settings.emails_enabled` is `True`. Asserts that `create_user` raises an exception.

- **Test Case 8 (Edge):** User creation with a very long email address (exceeding database limits). Mocks `crud.get_user_by_email` to return `None`. Mocks `crud.create_user` to raise an exception simulating a database constraint violation. `settings.emails_enabled` can be True or False. Asserts that `create_user` raises an exception.

- **Test Case 9 (Edge):** User creation with special characters in the email address. Mocks `crud.get_user_by_email` to return `None`. Mocks `crud.create_user` to return a valid user object (with a special character email). Mocks `generate_new_account_email` and `send_email` appropriately. `settings.emails_enabled` is `True`. Asserts that `create_user` returns the created user object and that `send_email` is called once.


### Function: send_email
- **Test Case 1 (Positive):** Successful email sending with all SMTP settings provided.  Mocks `emails.Message` to simulate successful message creation.  `settings.emails_enabled` is `True`.  Asserts that `send_email` completes without raising exceptions and that the logger info message contains "success".  The mock `message.send` should be called once.

- **Test Case 2 (Negative):** Email sending fails due to missing `settings.emails_enabled`. `settings.emails_enabled` is `False`. Asserts that `send_email` raises an `AssertionError` with the message "no provided configuration for email variables".

- **Test Case 3 (Negative):** Email sending fails due to invalid SMTP host.  `settings.SMTP_HOST` is set to an invalid hostname.  Mocks `emails.Message` and simulates a failure in `message.send`. `settings.emails_enabled` is `True`. Asserts that `send_email` raises an exception (e.g., `SMTPException`).  The mock `message.send` should be called once.

- **Test Case 4 (Negative):** Email sending fails due to incorrect SMTP credentials. `settings.SMTP_USER` or `settings.SMTP_PASSWORD` are incorrect.  Mocks `emails.Message` and simulates a failure in `message.send`. `settings.emails_enabled` is `True`. Asserts that `send_email` raises an exception (e.g., `SMTPAuthenticationError`). The mock `message.send` should be called once.

- **Test Case 5 (Edge):** Email sending with empty subject and HTML content. `settings.emails_enabled` is `True`. Asserts that `send_email` completes without raising exceptions. The mock `message.send` should be called once.

- **Test Case 6 (Edge):** Email sending with a very long subject line (exceeding email server limits). `settings.emails_enabled` is `True`. Mocks `emails.Message` and simulates a failure in `message.send`. Asserts that `send_email` raises an exception (e.g., `SMTPSenderRefused`). The mock `message.send` should be called once.

- **Test Case 7 (Edge):** Email sending with special characters in the subject and HTML content. `settings.emails_enabled` is `True`. Asserts that `send_email` completes without raising exceptions. The mock `message.send` should be called once.

- **Test Case 8 (Edge):** Email sending using SSL. `settings.SMTP_SSL` is `True`, `settings.SMTP_TLS` is `False`.  Mocks `emails.Message` and simulates successful message creation. `settings.emails_enabled` is `True`. Asserts that `send_email` completes without raising exceptions. The mock `message.send` should be called once.

- **Test Case 9 (Edge):** Email sending using TLS. `settings.SMTP_TLS` is `True`, `settings.SMTP_SSL` is `False`.  Mocks `emails.Message` and simulates successful message creation. `settings.emails_enabled` is `True`. Asserts that `send_email` completes without raising exceptions. The mock `message.send` should be called once.

- **Test Case 10 (Edge):** Email sending with an invalid email address.  `email_to` is an invalid email address. Mocks `emails.Message` and simulates a failure in `message.send`. `settings.emails_enabled` is `True`. Asserts that `send_email` raises an exception (e.g., `SMTPRecipientsRefused`). The mock `message.send` should be called once.