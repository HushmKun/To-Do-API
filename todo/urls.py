from django.urls import path

from .views import ToDosView, ToDoView

urlpatterns = [
    path("", ToDoView.as_view(), name="todo"),
    path("<pk>/", ToDosView.as_view(), name="todo_detail"),
]
