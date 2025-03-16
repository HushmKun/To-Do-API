from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

User = get_user_model()

from rest_framework import serializers

from .models import ToDo


class ToDoSerializer(serializers.ModelSerializer):
    user = serializers.HiddenField(
        default=serializers.CurrentUserDefault()
    )

    class Meta:
        model = ToDo
        fields = [
            "id",
            "title",
            "user",
            "desc",
            "status",
            "created_at",
            "url",
        ]
        read_only_fields = ["created_at", "url", "user", "id"]
        extra_kwargs = {
            "title": {
                "min_length": 3,
                "max_length": 50,
                "error_messages": {
                    "min_length": _("Title must be at least 3 characters"),
                    "max_length": _("Title cannot exceed 50 characters"),
                },
            },
            "status": {
                "choices": ["todo", "in_progress", "done"],
                "default": "todo",
            },
        }

    # Add URL field for get_absolute_url
    url = serializers.HyperlinkedIdentityField(
        view_name="todo_detail", lookup_field="pk"
    )

    def validate(self, attr):
        """Cross-field validation example"""
        if len(attr.get("desc", "")) > 256:
            raise serializers.ValidationError(
                {
                    "Description": _(
                        "Description cannot exceed 256 characters"
                    )
                }
            )
        return attr
