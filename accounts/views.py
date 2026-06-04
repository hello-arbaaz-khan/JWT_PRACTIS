
import logging
from datetime import timedelta

from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework import status
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import CustomUser
from accounts.serializers import (
    ForgotPasswordSerializer,
    PasswordChangeSerializer,
    ResetPasswordSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserRegistrationSerializer,
)
from accounts.utils import (
    send_password_reset_email,
    send_verification_email,
    verify_token,
)

logger = logging.getLogger("accounts")


# ── Helper ──────────────────────────────────────────────────────────────────

def _get_client_ip(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


# ── Register ────────────────────────────────────────────────────────────────

class RegisterView(APIView):
    """POST /api/v1/auth/register/ — create account, send verification email."""
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            try:
                send_verification_email(user)
            except Exception as exc:
                logger.error("Failed to send verification email to %s: %s", user.email, exc)

            logger.info("New registration: %s | IP: %s", user.email, _get_client_ip(request))
            return Response(
                {"message": "Registration successful. Please check your email to verify your account."},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ── Login ───────────────────────────────────────────────────────────────────

class LoginView(APIView):
    """
    POST /api/v1/auth/login/
    Returns JWT tokens. Enforces email verification and account lockout.
    """
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    LOCKOUT_THRESHOLD = 5
    LOCKOUT_MINUTES = 15

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"].lower().strip()
        password = serializer.validated_data["password"]
        ip = _get_client_ip(request)

        # Fetch user
        try:
            user_obj = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            logger.warning("Login for unknown email: %s | IP: %s", email, ip)
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        # Account lockout check
        if user_obj.account_locked_until and user_obj.account_locked_until > timezone.now():
            mins = int((user_obj.account_locked_until - timezone.now()).total_seconds() / 60)
            return Response(
                {"detail": f"Account locked due to multiple failed attempts. Try again in {mins} minute(s)."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Authenticate
        user = authenticate(request, username=email, password=password)

        if user is None:
            user_obj.failed_login_count += 1
            if user_obj.failed_login_count >= self.LOCKOUT_THRESHOLD:
                user_obj.account_locked_until = timezone.now() + timedelta(minutes=self.LOCKOUT_MINUTES)
                logger.warning("Account locked: %s | IP: %s", email, ip)
            user_obj.save(update_fields=["failed_login_count", "account_locked_until"])
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        # Email verification gate
        if not user.is_email_verified:
            return Response(
                {"detail": "Please verify your email address before logging in."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Active check
        if not user.is_active:
            return Response({"detail": "This account has been deactivated."}, status=status.HTTP_403_FORBIDDEN)

        # Success — reset counters, record IP
        user.failed_login_count = 0
        user.account_locked_until = None
        user.last_login_ip = ip
        user.save(update_fields=["failed_login_count", "account_locked_until", "last_login_ip"])

        refresh = RefreshToken.for_user(user)
        logger.info("Login OK: %s | IP: %s", email, ip)

        return Response(
            {
                "message": "Login successful.",
                "data": {
                    "id": user.id,
                    "email": user.email,
                    "user_name": user.user_name,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "full_name": user.full_name,
                    "is_email_verified": user.is_email_verified,
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                },
            },
            status=status.HTTP_200_OK,
        )


# ── Logout ──────────────────────────────────────────────────────────────────

class LogoutView(APIView):
    """POST /api/v1/auth/logout/ — blacklist the refresh token."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info("Logout: %s", request.user.email)
            return Response({"message": "Logged out successfully."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response({"detail": "Invalid or already expired token."}, status=status.HTTP_400_BAD_REQUEST)


# ── Email Verification ─────────────────────────────────────────────────────

class VerifyEmailView(APIView):
    """POST /api/v1/auth/email/verify/ — verify the token and activate the account."""
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get("token", "").strip()
        if not token:
            return Response({"detail": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = verify_token(token, purpose="email-verify")
        if not user:
            return Response({"detail": "The verification link is invalid or has expired."}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_email_verified:
            return Response({"detail": "Email is already verified."}, status=status.HTTP_200_OK)

        user.is_email_verified = True
        user.is_active = True
        user.save(update_fields=["is_email_verified", "is_active"])

        logger.info("Email verified: %s", user.email)
        return Response({"message": "Email verified successfully. You can now log in."}, status=status.HTTP_200_OK)


class ResendVerifyEmailView(APIView):
    """POST /api/v1/auth/email/resend/ — resend verification email."""
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        email = request.data.get("email", "").lower().strip()
        if not email:
            return Response({"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Generic message to prevent user-enumeration
        msg = "If this email is registered and unverified, a new verification link has been sent."

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"message": msg}, status=status.HTTP_200_OK)

        if user.is_email_verified:
            return Response({"detail": "This email is already verified."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            send_verification_email(user)
        except Exception as exc:
            logger.error("Resend verify email failed for %s: %s", email, exc)
            return Response({"detail": "Failed to send email. Try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": msg}, status=status.HTTP_200_OK)


# ── Password: Forgot / Reset / Change ──────────────────────────────────────

class ForgotPasswordView(APIView):
    """
    POST /api/v1/auth/password/forgot/
    Always returns 200 to prevent user-enumeration.
    """
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"].lower().strip()
        try:
            user = CustomUser.objects.get(email=email)
            send_password_reset_email(user)
            logger.info("Password reset email sent: %s", email)
        except CustomUser.DoesNotExist:
            pass  # Intentionally silent — prevents enumeration

        return Response(
            {"message": "If an account with this email exists, a password reset link has been sent."},
            status=status.HTTP_200_OK,
        )


class ResetPasswordView(APIView):
    """POST /api/v1/auth/password/reset/ — set new password via emailed token."""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = verify_token(serializer.validated_data["token"], purpose="password-reset")
        if not user:
            return Response({"detail": "The reset link is invalid or has expired."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data["new_password"])
        user.save(update_fields=["password"])
        logger.info("Password reset completed: %s", user.email)

        return Response(
            {"message": "Password reset successful. You can now log in with your new password."},
            status=status.HTTP_200_OK,
        )


class PasswordChangeView(APIView):
    """POST /api/v1/auth/password/change/ — change password while logged in."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        if not user.check_password(serializer.validated_data["old_password"]):
            return Response({"detail": "Current password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data["new_password"])
        user.save(update_fields=["password"])
        logger.info("Password changed: %s", user.email)

        return Response(
            {"message": "Password changed successfully. Please log in again with your new password."},
            status=status.HTTP_200_OK,
        )


# ── Profile ─────────────────────────────────────────────────────────────────

class ProfileView(APIView):
    """
    GET   /api/v1/auth/profile/ — return authenticated user's profile.
    PATCH /api/v1/auth/profile/ — partially update profile fields.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, MultiPartParser]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
