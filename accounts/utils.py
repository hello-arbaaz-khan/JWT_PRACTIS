"""
accounts/utils.py
-----------------
Helper utilities for:
  - Secure token generation & verification (email verify, password reset)
  - Sending transactional emails
"""

import logging

from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

logger = logging.getLogger("accounts")

# Reuse Django's built-in HMAC-based token generator
_token_generator = PasswordResetTokenGenerator()


def generate_token(user) -> str:
    """Return a URL-safe token string encoding the user PK + HMAC signature."""
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = _token_generator.make_token(user)
    return f"{uid}-{token}"


def verify_token(raw_token: str, purpose: str = None):
    """
    Decode and validate a token produced by ``generate_token()``.

    Returns the matching ``CustomUser`` on success, or ``None`` if
    invalid / expired.  Django's ``PasswordResetTokenGenerator`` expires
    tokens via ``settings.PASSWORD_RESET_TIMEOUT``.
    """
    from accounts.models import CustomUser  # avoid circular import

    try:
        uid_b64, token = raw_token.split("-", 1)
        uid = force_str(urlsafe_base64_decode(uid_b64))
        user = CustomUser.objects.get(pk=uid)

        if _token_generator.check_token(user, token):
            return user
    except Exception as exc:
        logger.warning("Token verification failed [purpose=%s]: %s", purpose, exc)

    return None


def send_verification_email(user) -> None:
    """Send an account-verification email to the given user."""
    token = generate_token(user)
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"

    send_mail(
        subject="Verify Your Email Address",
        message=(
            f"Hi {user.first_name or user.user_name},\n\n"
            f"Please verify your email address by clicking the link below:\n\n"
            f"{verify_url}\n\n"
            f"This link will expire in 24 hours.\n\n"
            f"If you did not create an account, please ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    logger.info("Verification email sent -> %s", user.email)


def send_password_reset_email(user) -> None:
    """Send a password-reset link to the given user."""
    token = generate_token(user)
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"

    send_mail(
        subject="Reset Your Password",
        message=(
            f"Hi {user.first_name or user.user_name},\n\n"
            f"We received a request to reset the password for your account.\n\n"
            f"Click the link below to set a new password:\n\n"
            f"{reset_url}\n\n"
            f"This link will expire in 1 hour.\n\n"
            f"If you did not request a password reset, please ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    logger.info("Password reset email sent -> %s", user.email)
