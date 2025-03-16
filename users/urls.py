from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from .views import (
    ChangePasswordView,
    PasswordResetEmailView,
    PasswordResetView,
    Profile,
    RegisterView,
)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path(
        "login/", TokenObtainPairView.as_view(), name="token_obtain_pair"
    ),
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path(
        "send_reset/", PasswordResetEmailView.as_view(), name="send_reset"
    ),
    path("change/", ChangePasswordView.as_view(), name="change_password"),
    path(
        "reset_password/<uid>/<token>/",
        PasswordResetView.as_view(),
        name="reset",
    ),
    path("profile/", Profile.as_view(), name="profile"),
]
