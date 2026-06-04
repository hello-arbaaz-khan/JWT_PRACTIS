"""
accounts/serializers.py
-----------------------
Industry-level serializers with:
  - Strong password validation (uppercase + digit + special char)
  - Confirm-password matching on registration
  - Case-insensitive email / username uniqueness
  - Serializers for: register, login, profile, change/forgot/reset password
"""

import re

from rest_framework import serializers

from accounts.models import CustomUser


# ── Shared validator ────────────────────────────────────────────────────────

def validate_strong_password(value: str) -> str:
    """Enforce uppercase, digit, and special-character requirements."""
    if not re.search(r"[A-Z]", value):
        raise serializers.ValidationError(
            "Password must contain at least one uppercase letter."
        )
    if not re.search(r"[0-9]", value):
        raise serializers.ValidationError(
            "Password must contain at least one digit."
        )
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~\"\\]", value):
        raise serializers.ValidationError(
            "Password must contain at least one special character."
        )
    return value


# ── Registration ────────────────────────────────────────────────────────────

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        validators=[validate_strong_password],
        style={"input_type": "password"},
    )
    confirm_password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    class Meta:
        model = CustomUser
        fields = [
            "email", "user_name", "first_name",
            "last_name", "password", "confirm_password",
        ]

    def validate_email(self, value: str) -> str:
        value = value.lower().strip()
        if CustomUser.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                "An account with this email already exists."
            )
        return value

    def validate_user_name(self, value: str) -> str:
        if CustomUser.objects.filter(user_name__iexact=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )
        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        return CustomUser.objects.create_user(**validated_data)


# ── Login ───────────────────────────────────────────────────────────────────

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )


# ── Profile ─────────────────────────────────────────────────────────────────

class UserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.ReadOnlyField()

    MAX_PROFILE_IMAGE_SIZE = 2 * 1024 * 1024
    ALLOWED_PROFILE_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}

    class Meta:
        model = CustomUser
        fields = [
            "id", "email", "user_name", "first_name", "last_name",
            "full_name", "profile_image", "is_email_verified", "date_joined",
        ]
        read_only_fields = [
            "id", "email", "is_email_verified", "date_joined", "full_name",
        ]

    def validate_profile_image(self, value):
        if value.size > self.MAX_PROFILE_IMAGE_SIZE:
            raise serializers.ValidationError("Profile image must be 2MB or smaller.")

        content_type = getattr(value, "content_type", None)
        if content_type not in self.ALLOWED_PROFILE_IMAGE_TYPES:
            raise serializers.ValidationError(
                "Profile image must be a JPEG, PNG, or WEBP file."
            )

        return value


# ── Password management ────────────────────────────────────────────────────

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )
    new_password = serializers.CharField(
        write_only=True, min_length=8,
        validators=[validate_strong_password],
        style={"input_type": "password"},
    )
    confirm_new_password = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )

    def validate(self, data):
        if data["new_password"] != data["confirm_new_password"]:
            raise serializers.ValidationError(
                {"confirm_new_password": "Passwords do not match."}
            )
        return data


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(
        write_only=True, min_length=8,
        validators=[validate_strong_password],
        style={"input_type": "password"},
    )
    confirm_new_password = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )

    def validate(self, data):
        if data["new_password"] != data["confirm_new_password"]:
            raise serializers.ValidationError(
                {"confirm_new_password": "Passwords do not match."}
            )
        return data
