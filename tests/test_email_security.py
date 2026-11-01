import pytest
import os
from unittest.mock import patch
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        yield client

def test_production_request_to_test_email_returns_404(client, monkeypatch):
    """In production (RENDER=true or FLASK_ENV=production), /test_email must return 404."""
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("ENABLE_TEST_EMAIL_ENDPOINT", "true")  # Even if mistakenly enabled

    with patch("app.send_email_brevo") as mock_send:
        res = client.get("/test_email")
        assert res.status_code == 404
        mock_send.assert_not_called()

def test_production_without_enable_flag_returns_404(client, monkeypatch):
    """By default in production without any flags, /test_email must return 404."""
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("ENABLE_TEST_EMAIL_ENDPOINT", raising=False)

    with patch("app.send_email_brevo") as mock_send:
        res = client.get("/test_email")
        assert res.status_code == 404
        mock_send.assert_not_called()

def test_development_without_explicit_enable_flag_returns_404(client, monkeypatch):
    """In development without ENABLE_TEST_EMAIL_ENDPOINT=true, /test_email returns 404."""
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("ENABLE_TEST_EMAIL_ENDPOINT", raising=False)

    with patch("app.send_email_brevo") as mock_send:
        res = client.get("/test_email")
        assert res.status_code == 404
        mock_send.assert_not_called()

def test_test_email_dispatches_when_explicitly_enabled_in_non_prod(client, monkeypatch):
    """When non-production AND ENABLE_TEST_EMAIL_ENDPOINT=true, test email executes safely with mock."""
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("ENABLE_TEST_EMAIL_ENDPOINT", "true")
    monkeypatch.setenv("BREVO_API_KEY", "mock_brevo_key_12345")
    monkeypatch.setenv("MAIL_USER", "admin@blogtest.com")

    with patch("app.send_email_brevo", return_value=True) as mock_send:
        res = client.get("/test_email")
        assert res.status_code == 200
        assert b"Email test successfully dispatched" in res.data
        mock_send.assert_called_once_with(
            "admin@blogtest.com",
            "Brevo API Test",
            "If you read this, the Brevo integration is working!"
        )

def test_missing_configuration_does_not_call_brevo(client, monkeypatch):
    """If BREVO_API_KEY or MAIL_USER is missing in non-prod enabled mode, Brevo is not called."""
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("ENABLE_TEST_EMAIL_ENDPOINT", "true")
    monkeypatch.delenv("BREVO_API_KEY", raising=False)
    monkeypatch.delenv("MAIL_USER", raising=False)

    with patch("app.send_email_brevo") as mock_send:
        res = client.get("/test_email")
        assert res.status_code == 500
        mock_send.assert_not_called()

def test_render_production_overrides_test_environment_flags(client, monkeypatch):
    """Render production status (RENDER=true) cannot be bypassed by TESTING or ENABLE flags."""
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("ENABLE_TEST_EMAIL_ENDPOINT", "1")

    with patch("app.send_email_brevo") as mock_send:
        res = client.get("/test_email")
        assert res.status_code == 404
        mock_send.assert_not_called()
