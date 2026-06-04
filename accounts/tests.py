import re

from django.core import mail
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.throttling import AnonRateThrottle
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import CustomUser
from accounts.utils import (
    TOKEN_PURPOSE_EMAIL_VERIFY,
    TOKEN_PURPOSE_PASSWORD_RESET,
    generate_token,
    verify_token,
)


TEST_REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "1000/min",
        "user": "1000/day",
    },
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    FRONTEND_URL="http://frontend.test",
    REST_FRAMEWORK=TEST_REST_FRAMEWORK,
)
class AuthAPITestCase(APITestCase):
    password = "StrongPass1!"

    def setUp(self):
        cache.clear()
        mail.outbox = []

    def create_user(self, **overrides):
        data = {
            "email": "user@example.com",
            "user_name": "user",
            "first_name": "Test",
            "last_name": "User",
            "password": self.password,
            "is_active": True,
            "is_email_verified": True,
        }
        data.update(overrides)
        password = data.pop("password")
        return CustomUser.objects.create_user(password=password, **data)

    def login(self, email="user@example.com", password=None):
        return self.client.post(
            reverse("login"),
            {"email": email, "password": password or self.password},
            format="json",
        )

    def extract_token_from_email(self, body):
        match = re.search(r"token=([^\s]+)", body)
        self.assertIsNotNone(match, body)
        return match.group(1)

    def test_registration_creates_inactive_unverified_user_and_sends_email(self):
        response = self.client.post(
            reverse("register"),
            {
                "email": "New@Example.com",
                "user_name": "new_user",
                "first_name": "New",
                "last_name": "User",
                "password": self.password,
                "confirm_password": self.password,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = CustomUser.objects.get(email="new@example.com")
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_email_verified)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("verify-email", mail.outbox[0].body)

    def test_registration_rejects_weak_password_and_duplicate_email(self):
        self.create_user(email="dupe@example.com", user_name="dupe")

        weak = self.client.post(
            reverse("register"),
            {
                "email": "weak@example.com",
                "user_name": "weak",
                "first_name": "Weak",
                "last_name": "User",
                "password": "password",
                "confirm_password": "password",
            },
            format="json",
        )
        self.assertEqual(weak.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", weak.data)

        duplicate = self.client.post(
            reverse("register"),
            {
                "email": "DUPE@example.com",
                "user_name": "other",
                "first_name": "Other",
                "last_name": "User",
                "password": self.password,
                "confirm_password": self.password,
            },
            format="json",
        )
        self.assertEqual(duplicate.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", duplicate.data)

    def test_login_success_returns_tokens_and_records_ip(self):
        self.create_user()

        response = self.login()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data["data"])
        self.assertIn("refresh", response.data["data"])
        user = CustomUser.objects.get(email="user@example.com")
        self.assertEqual(user.failed_login_count, 0)
        self.assertIsNotNone(user.last_login_ip)

    def test_login_rejects_invalid_unverified_and_inactive_users(self):
        self.create_user()
        invalid = self.login(password="WrongPass1!")
        self.assertEqual(invalid.status_code, status.HTTP_401_UNAUTHORIZED)

        unverified = self.create_user(
            email="unverified@example.com",
            user_name="unverified",
            is_active=False,
            is_email_verified=False,
        )
        response = self.login(email=unverified.email)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("verify", response.data["detail"].lower())

        inactive = self.create_user(
            email="inactive@example.com",
            user_name="inactive",
            is_active=False,
            is_email_verified=True,
        )
        response = self.login(email=inactive.email)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("deactivated", response.data["detail"].lower())

    def test_account_locks_after_repeated_failed_logins(self):
        user = self.create_user()

        for _ in range(5):
            response = self.login(password="WrongPass1!")
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        user.refresh_from_db()
        self.assertEqual(user.failed_login_count, 5)
        self.assertIsNotNone(user.account_locked_until)

        locked = self.login()
        self.assertEqual(locked.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("locked", locked.data["detail"].lower())

    def test_token_refresh_and_logout_blacklists_refresh_token(self):
        self.create_user()
        login_response = self.login()
        refresh = login_response.data["data"]["refresh"]
        access = login_response.data["data"]["access"]

        refresh_response = self.client.post(
            reverse("token_refresh"), {"refresh": refresh}, format="json"
        )
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertIn("access", refresh_response.data)
        logout_refresh = refresh_response.data.get("refresh", refresh)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        logout = self.client.post(reverse("logout"), {"refresh": logout_refresh}, format="json")
        self.assertEqual(logout.status_code, status.HTTP_205_RESET_CONTENT)
        self.assertEqual(BlacklistedToken.objects.count(), 2)

    def test_email_verify_activates_account_and_resend_is_generic(self):
        user = self.create_user(
            email="verify@example.com",
            user_name="verify",
            is_active=False,
            is_email_verified=False,
        )
        token = generate_token(user, TOKEN_PURPOSE_EMAIL_VERIFY)

        response = self.client.post(reverse("email_verify"), {"token": token}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_email_verified)

        resend_existing = self.client.post(
            reverse("email_resend"), {"email": user.email}, format="json"
        )
        resend_missing = self.client.post(
            reverse("email_resend"), {"email": "missing@example.com"}, format="json"
        )
        self.assertEqual(resend_existing.status_code, status.HTTP_200_OK)
        self.assertEqual(resend_missing.status_code, status.HTTP_200_OK)
        self.assertEqual(resend_existing.data, resend_missing.data)

    def test_password_forgot_reset_and_change(self):
        user = self.create_user()

        forgot = self.client.post(
            reverse("password_forgot"), {"email": user.email}, format="json"
        )
        self.assertEqual(forgot.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        token = self.extract_token_from_email(mail.outbox[0].body)

        reset = self.client.post(
            reverse("password_reset"),
            {
                "token": token,
                "new_password": "NewStrong1!",
                "confirm_new_password": "NewStrong1!",
            },
            format="json",
        )
        self.assertEqual(reset.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertTrue(user.check_password("NewStrong1!"))

        login_response = self.login(password="NewStrong1!")
        access = login_response.data["data"]["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        change = self.client.post(
            reverse("password_change"),
            {
                "old_password": "NewStrong1!",
                "new_password": "NewestStrong1!",
                "confirm_new_password": "NewestStrong1!",
            },
            format="json",
        )
        self.assertEqual(change.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertTrue(user.check_password("NewestStrong1!"))

    def test_profile_get_patch_and_upload_validation(self):
        user = self.create_user()
        refresh = RefreshToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        profile = self.client.get(reverse("profile"))
        self.assertEqual(profile.status_code, status.HTTP_200_OK)
        self.assertEqual(profile.data["email"], user.email)

        patch = self.client.patch(
            reverse("profile"), {"first_name": "Updated"}, format="json"
        )
        self.assertEqual(patch.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertEqual(user.first_name, "Updated")

        invalid_file = SimpleUploadedFile(
            "profile.txt", b"not-an-image", content_type="text/plain"
        )
        upload = self.client.patch(
            reverse("profile"), {"profile_image": invalid_file}, format="multipart"
        )
        self.assertEqual(upload.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("profile_image", upload.data)

    def test_purpose_scoped_tokens_cannot_be_reused_for_other_flows(self):
        user = self.create_user(
            email="token@example.com",
            user_name="token",
            is_active=False,
            is_email_verified=False,
        )
        verify_token_value = generate_token(user, TOKEN_PURPOSE_EMAIL_VERIFY)
        reset_token_value = generate_token(user, TOKEN_PURPOSE_PASSWORD_RESET)

        self.assertIsNone(verify_token(verify_token_value, TOKEN_PURPOSE_PASSWORD_RESET))
        self.assertIsNone(verify_token(reset_token_value, TOKEN_PURPOSE_EMAIL_VERIFY))
        self.assertEqual(verify_token(verify_token_value, TOKEN_PURPOSE_EMAIL_VERIFY), user)

    def test_anonymous_rate_limit_applies_to_login(self):
        cache.clear()
        self.create_user()
        original_rates = AnonRateThrottle.THROTTLE_RATES
        AnonRateThrottle.THROTTLE_RATES = {**original_rates, "anon": "2/min"}

        try:
            for _ in range(2):
                response = self.login(password="WrongPass1!")
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

            throttled = self.login(password="WrongPass1!")
            self.assertEqual(throttled.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        finally:
            AnonRateThrottle.THROTTLE_RATES = original_rates
