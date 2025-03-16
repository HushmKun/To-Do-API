from django.contrib import admin

from .models import ToDo

# Register your models here.


@admin.register(ToDo)
class ToDoAdmin(admin.ModelAdmin):
    list_display = ["title", "full_name", "status"]
    list_filter = ["status"]
    ordering = ["created_at"]

    def full_name(self, obj):
        return obj.user.first_name + " " + obj.user.last_name
