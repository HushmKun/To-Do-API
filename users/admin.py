from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .forms import CustomUserChangeForm, CustomUserCreationForm
from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = User
    list_display = (
        "user_full_name",
        "email",
        "is_staff",
        "is_active",
    )
    list_filter = (
        "is_staff",
        "is_active",
    )
    fieldsets = (
        ("User Data", {"fields": ("email", "password", "DoB")}),
        (
            "Permissions",
            {"fields": ("is_staff", "is_active")},
        ),  # , "groups", "user_permissions")}),
    )
    add_fieldsets = (
        (
            "Personal Data",
            {
                "classes": ("wide",),
                "fields": (
                    "first_name",
                    "last_name",
                    "DoB",
                ),
            },
        ),
        (
            "User Data",
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "is_staff",
                    "is_active",
                    # , "groups", "user_permissions"
                ),
            },
        ),
    )
    search_fields = ("email",)
    ordering = ("email",)

    def user_full_name(self, obj):
        return obj.first_name + " " + obj.last_name
