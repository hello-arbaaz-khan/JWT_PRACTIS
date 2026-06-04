"""
accounts/urls.py
----------------
All auth routes — prefixed with /api/v1/auth/ by root urls.py.
"""

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from accounts.views import (
    ForgotPasswordView,
    LoginView,
    LogoutView,
    PasswordChangeView,
    ProfileView,
    RegisterView,
    ResendVerifyEmailView,
    ResetPasswordView,
    VerifyEmailView,
)

urlpatterns = [
    # Authentication
    path("register/",        RegisterView.as_view(),          name="register"),
    path("login/",           LoginView.as_view(),             name="login"),
    path("logout/",          LogoutView.as_view(),            name="logout"),
    path("token/refresh/",   TokenRefreshView.as_view(),      name="token_refresh"),

    # Email Verification
    path("email/verify/",    VerifyEmailView.as_view(),       name="email_verify"),
    path("email/resend/",    ResendVerifyEmailView.as_view(), name="email_resend"),

    # Password Management
    path("password/forgot/", ForgotPasswordView.as_view(),    name="password_forgot"),
    path("password/reset/",  ResetPasswordView.as_view(),     name="password_reset"),
    path("password/change/", PasswordChangeView.as_view(),    name="password_change"),

    # Profile
    path("profile/",         ProfileView.as_view(),           name="profile"),
]
