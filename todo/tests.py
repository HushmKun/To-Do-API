from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.test import APITestCase

from .models import ToDo

User = get_user_model()

# * Models Tests


class ToDoModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            password="Testpassword123",
            first_name="Test",
            last_name="User",
        )
        self.todo = ToDo.objects.create(
            title="Test ToDo",
            user=self.user,
            desc="Test Description",
        )

    def test_todo_creation(self):
        self.assertEqual(self.todo.title, "Test ToDo")
        self.assertEqual(self.todo.user, self.user)
        self.assertEqual(self.todo.desc, "Test Description")
        self.assertEqual(self.todo.status, "todo")
        self.assertIsInstance(self.todo.created_at, timezone.datetime)

    def test_todo_status_choices(self):
        expected_choices = [
            ("todo", _("Todo")),
            ("in_progress", _("In Progress")),
            ("done", _("Done")),
        ]
        self.assertEqual(ToDo.STATUS_CHOICES, expected_choices)

    def test_todo_string_representation(self):
        self.assertEqual(str(self.todo), "Test ToDo")

    def test_todo_verbose_name(self):
        self.assertEqual(ToDo._meta.verbose_name, _("ToDo"))

    def test_todo_verbose_name_plural(self):
        self.assertEqual(ToDo._meta.verbose_name_plural, _("ToDos"))

    def test_todo_get_absolute_url(self):
        expected_url = reverse("todo_detail", kwargs={"pk": self.todo.pk})
        self.assertEqual(self.todo.get_absolute_url(), expected_url)

    def test_todo_status_can_be_changed(self):
        self.todo.status = "in_progress"
        self.todo.save()
        updated_todo = ToDo.objects.get(pk=self.todo.pk)
        self.assertEqual(updated_todo.status, "in_progress")

    def test_todo_related_user_deletion(self):
        self.user.delete()
        self.assertEqual(ToDo.objects.count(), 0)


class ToDoViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            password="Testpassword123",
            first_name="Test",
            last_name="User",
        )
        self.client.force_authenticate(user=self.user)
        self.list_create_url = reverse("todo")  # Adjust name if needed

        # Create some ToDos for testing
        self.todo1 = ToDo.objects.create(
            title="ToDo 1", user=self.user, desc="Description 1"
        )
        self.todo2 = ToDo.objects.create(
            title="ToDo 2",
            user=self.user,
            desc="Description 2",
            status="done",
        )

    def test_get_todos(self):
        response = self.client.get(self.list_create_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            len(response.data["results"]), 2
        )  # Check for pagination
        self.assertEqual(response.data["results"][0]["title"], "ToDo 1")
        self.assertEqual(response.data["results"][1]["title"], "ToDo 2")

    def test_get_todos_filtered_by_status(self):
        url = self.list_create_url + "?status=done"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["title"], "ToDo 2")

    def test_get_todos_searched_by_title(self):
        url = self.list_create_url + "?search=ToDo 1"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["results"]), 1)
        self.assertEqual(response.data["results"][0]["title"], "ToDo 1")

    def test_create_todo(self):
        data = {
            "title": "New ToDo",
            "desc": "New Description",
            "status": "todo",
        }
        response = self.client.post(
            self.list_create_url, data, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(ToDo.objects.count(), 3)
        self.assertEqual(ToDo.objects.last().title, "New ToDo")

    def test_create_todo_invalid_data(self):
        data = {"desc": "New Description"}  # Missing title
        response = self.client.post(
            self.list_create_url, data, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_todos_unauthenticated(self):
        self.client.logout()
        response = self.client.get(self.list_create_url)
        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_todo_ordering(self):
        url = self.list_create_url + "?ordering=title"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["results"][0]["title"], "ToDo 1"
        )  # Alphabetical Ordering


class ToDosViewTests(APITestCase):  # Detail, Update, Delete
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            password="Testpassword123",
            first_name="Test",
            last_name="User",
        )
        self.client.force_authenticate(user=self.user)
        self.todo = ToDo.objects.create(
            title="Test ToDo", user=self.user, desc="Test Description"
        )
        self.detail_url = reverse(
            "todo_detail", kwargs={"pk": self.todo.pk}
        )  # Adjust name if needed

    def test_get_todo_detail(self):
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["title"], "Test ToDo")

    def test_update_todo(self):
        data = {"title": "Updated ToDo", "desc": "Updated Description"}
        response = self.client.put(self.detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["title"], "Updated ToDo")
        self.todo.refresh_from_db()
        self.assertEqual(self.todo.title, "Updated ToDo")

    def test_delete_todo(self):
        response = self.client.delete(self.detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(ToDo.objects.count(), 0)

    def test_get_todo_detail_not_found(self):
        url = reverse("todo_detail", kwargs={"pk": 999})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_get_todo_detail_unauthenticated(self):
        self.client.logout()
        response = self.client.get(self.detail_url)
        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_update_todo_unauthenticated(self):
        self.client.logout()
        data = {"title": "Updated ToDo"}
        response = self.client.put(self.detail_url, data, format="json")
        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_delete_todo_unauthenticated(self):
        self.client.logout()
        response = self.client.delete(self.detail_url)
        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_get_todo_detail_different_user(self):
        other_user = User.objects.create_user(
            email="other@example.com", password="Anotherpassword123"
        )
        self.client.force_authenticate(user=other_user)
        response = self.client.get(self.detail_url)
        print(f">>>{response.json()}")
        self.assertEqual(
            response.status_code, status.HTTP_404_NOT_FOUND
        )  # Verify a different user can't access another user's todo
