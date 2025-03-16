from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from .models import User


class CustomUserCreationForm(UserCreationForm):

    class Meta:
        model = User
        fields = ("email", "first_name", "last_name", "DoB")


class CustomUserChangeForm(UserChangeForm):

    class Meta:
        model = User
        fields = (
            "email",
            "DoB",
        )
