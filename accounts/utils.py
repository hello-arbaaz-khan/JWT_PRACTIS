"""
accounts/utils.py
-----------------
Helper utilities for:
  - Purpose-scoped token generation & verification
  - Sending transactional emails
"""

import logging

from django.conf import settings
from django.core import signing
from django.core.mail import send_mail

logger = logging.getLogger("accounts")

TOKEN_PURPOSE_EMAIL_VERIFY = "email-verify"
TOKEN_PURPOSE_PASSWORD_RESET = "password-reset"


def _token_max_age(purpose: str) -> int:
    if purpose == TOKEN_PURPOSE_EMAIL_VERIFY:
        return settings.EMAIL_VERIFICATION_TIMEOUT
    if purpose == TOKEN_PURPOSE_PASSWORD_RESET:
        return settings.PASSWORD_RESET_TIMEOUT
    raise ValueError(f"Unsupported token purpose: {purpose}")


def generate_token(user, purpose: str) -> str:
    """Return a signed token scoped to one auth purpose."""
    _token_max_age(purpose)
    payload = {
        "uid": user.pk,
        "password": user.password,
        "is_email_verified": user.is_email_verified,
    }
    return signing.dumps(payload, salt=purpose)


def verify_token(raw_token: str, purpose: str):
    """
    Decode and validate a purpose-scoped token produced by ``generate_token()``.

    Returns the matching ``CustomUser`` on success, or ``None`` if invalid,
    expired, reused after a state change, or used for the wrong purpose.
    """
    from accounts.models import CustomUser  # avoid circular import

    try:
        payload = signing.loads(
            raw_token,
            salt=purpose,
            max_age=_token_max_age(purpose),
        )
        user = CustomUser.objects.get(pk=payload["uid"])

        if user.password == payload["password"]:
            if purpose == TOKEN_PURPOSE_EMAIL_VERIFY and user.is_email_verified:
                return None
            return user
    except Exception as exc:
        logger.warning("Token verification failed [purpose=%s]: %s", purpose, exc)

    return None


def send_verification_email(user) -> None:
    """Send an account-verification email to the given user."""
    token = generate_token(user, TOKEN_PURPOSE_EMAIL_VERIFY)
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    message = "\n\n".join([
        f"Hi {user.first_name or user.user_name},",
        "Please verify your email address by clicking the link below:",
        verify_url,
        "This link will expire in 24 hours.",
        "If you did not create an account, please ignore this email.",
    ])

    send_mail(
        subject="Verify Your Email Address",
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    logger.info("Verification email sent -> %s", user.email)


def send_password_reset_email(user) -> None:
    """Send a password-reset link to the given user."""
    token = generate_token(user, TOKEN_PURPOSE_PASSWORD_RESET)
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    message = "\n\n".join([
        f"Hi {user.first_name or user.user_name},",
        "We received a request to reset the password for your account.",
        "Click the link below to set a new password:",
        reset_url,
        "This link will expire in 1 hour.",
        "If you did not request a password reset, please ignore this email.",
    ])

    send_mail(
        subject="Reset Your Password",
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    logger.info("Password reset email sent -> %s", user.email)
