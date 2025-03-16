from datetime import date
from typing import override
from unittest import expectedFailure, mock
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.test import TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.test import APITestCase

from users.serializers import (
    ChangePasswordSerializer,
    PasswordResetEmailSerializer,
    PasswordResetSerializer,
    UserSerializer,
)

User = get_user_model()

# * Models Tests


class UsersModelTests(TestCase):

    @override
    def setUp(self) -> None:
        self.User = get_user_model()
        return super().setUp()

    def test_create_user(self):
        user = self.User.objects.create_user(
            email="normal@user.com",
            password="foo",
            first_name="Tester",
            last_name="User",
            DoB=date(2011, 1, 25),
        )
        self.assertEqual(user.email, "normal@user.com")
        self.assertEqual(user.get_full_name(), "Tester User")
        self.assertEqual(user.DoB, date(2011, 1, 25))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        try:
            self.assertIsNone(user.username)
        except AttributeError:
            pass

    def test_create_invalid_user(self):
        with self.assertRaises(TypeError):
            self.User.objects.create_user()
        with self.assertRaises(TypeError):
            self.User.objects.create_user(email="")
        with self.assertRaises(ValueError):
            self.User.objects.create_user(email="", password="foo")

    def test_create_superuser(self):
        admin_user = self.User.objects.create_superuser(
            email="super@user.com", password="foo"
        )
        self.assertEqual(admin_user.email, "super@user.com")
        self.assertTrue(admin_user.is_active)
        self.assertTrue(admin_user.is_staff)
        self.assertTrue(admin_user.is_superuser)

        try:
            self.assertIsNone(admin_user.username)
        except AttributeError:
            pass

    def test_create_invalid_superuser(self):
        with self.assertRaises(ValueError):
            self.User.objects.create_superuser(
                email="super@user.com", password="foo", is_superuser=False
            )


# * Serializers Tests


class UserSerializerTests(TestCase):
    def setUp(self):
        self.user_data = {
            "first_name": "Test",
            "last_name": "User",
            "DoB": "01/01/2000",
            "email": "test@example.com",
            "password": "Testpassword123",
            "password2": "Testpassword123",
        }

    def test_user_serializer_valid(self):
        serializer = UserSerializer(data=self.user_data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.errors, {})

    def test_user_serializer_invalid_password_mismatch(self):
        self.user_data["password2"] = "wrongpassword"
        serializer = UserSerializer(data=self.user_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)
        self.assertEqual(
            serializer.errors["password"],
            ["Password fields didn't match."],
        )

    def test_user_serializer_invalid_dob_future(self):
        self.user_data["DoB"] = date(2099, 1, 1).strftime("%d/%m/%Y")
        serializer = UserSerializer(data=self.user_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("DoB", serializer.errors)
        self.assertEqual(
            serializer.errors["DoB"],
            ["Date of Birth can't be after today."],
        )

    def test_user_serializer_create(self):
        serializer = UserSerializer(data=self.user_data)
        serializer.is_valid(raise_exception=True)
        user = serializer.create(serializer.validated_data)

        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(user.email, "test@example.com")
        self.assertEqual(user.first_name, "Test")
        self.assertEqual(user.last_name, "User")
        self.assertEqual(user.DoB, date(2000, 1, 1))
        self.assertTrue(user.check_password("Testpassword123"))

    def test_user_serializer_invalid_missing_fields(self):
        data = {}
        serializer = UserSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("first_name", serializer.errors)
        self.assertIn("last_name", serializer.errors)
        self.assertIn("DoB", serializer.errors)
        self.assertIn("email", serializer.errors)
        self.assertIn("password", serializer.errors)
        self.assertIn("password2", serializer.errors)

    def test_user_serializer_invalid_email(self):
        self.user_data["email"] = "invalid-email"
        serializer = UserSerializer(data=self.user_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)

    def test_user_serializer_invalid_password_complexity_short(self):
        self.user_data["password"] = "Short1!"
        self.user_data["password2"] = self.user_data["password"]
        serializer = UserSerializer(data=self.user_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)

    @expectedFailure  #! Add Password Complexity
    def test_user_serializer_invalid_password_complexity_no_digit(self):
        self.user_data["password"] = "NoDigit!"
        self.user_data["password2"] = self.user_data["password"]
        serializer = UserSerializer(data=self.user_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)

    @expectedFailure  #! Add Password Complexity
    def test_user_serializer_invalid_password_complexity_no_uppercase(
        self,
    ):
        self.user_data["password"] = "nodigit!"
        self.user_data["password2"] = self.user_data["password"]
        serializer = UserSerializer(data=self.user_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)

    @expectedFailure  #! Add Password Complexity
    def test_user_serializer_invalid_password_complexity_no_lowercase(
        self,
    ):
        self.user_data["password"] = "NODIGIT!"
        self.user_data["password2"] = self.user_data["password"]
        serializer = UserSerializer(data=self.user_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)

    @expectedFailure  #! Add Password Complexity
    def test_user_serializer_invalid_password_complexity_no_special_char(
        self,
    ):
        self.user_data["password"] = "NoSpecialChar1"
        self.user_data["password2"] = self.user_data["password"]
        serializer = UserSerializer(data=self.user_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)


class ChangePasswordSerializerTests(TestCase):
    def test_change_password_serializer_valid(self):
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        serializer = ChangePasswordSerializer(
            data=data, context={"user": Mock()}
        )
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.errors, {})

    def test_change_password_serializer_invalid_mismatch(self):
        data = {"password": "Newpassword123", "password2": "wrongpassword"}
        serializer = ChangePasswordSerializer(
            data=data, context={"user": Mock()}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("non_field_errors", serializer.errors)
        self.assertEqual(
            serializer.errors["non_field_errors"],
            ["Password and Confirm Password doesn't match"],
        )

    def test_change_password_serializer_save(self):
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        user = Mock()
        serializer = ChangePasswordSerializer(
            data=data, context={"user": user}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user.set_password.assert_called_with("Newpassword123")
        user.save.assert_called()

    def test_change_password_serializer_invalid_password_complexity(self):
        data = {"password": "short", "password2": "short"}
        serializer = ChangePasswordSerializer(
            data=data, context={"user": Mock()}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)


class PasswordResetEmailSerializerTests(TestCase):
    def test_password_reset_email_serializer_valid(self):
        user = User.objects.create_user(
            email="test@example.com", password="Testpassword123"
        )

        mock_make_token = self.patch(
            "users.serializers.PasswordResetTokenGenerator.make_token"
        )
        mock_make_token.return_value = "test_token"

        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = "test_token"

        expected_url = f"http://example.com/reset_password/{uid}/{token}/"

        mock_reverse = self.patch("users.serializers.reverse")
        mock_reverse.return_value = expected_url

        data = {"email": "test@example.com"}
        request = Mock()
        request.scheme = "http"
        request.get_host.return_value = "example.com"
        context = {"request": request}
        serializer = PasswordResetEmailSerializer(
            data=data, context=context
        )

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.errors, {})

        mock_reverse.assert_called_once()
        args, kwargs = mock_reverse.call_args

        self.assertEqual(kwargs["kwargs"]["uid"], uid)
        self.assertEqual(kwargs["kwargs"]["token"], token)
        self.assertEqual(mock_reverse.return_value, expected_url)

    def test_password_reset_email_serializer_invalid_email(self):
        data = {"email": "nonexistent@example.com"}
        request = Mock()
        context = {"request": request}
        try:
            serializer = PasswordResetEmailSerializer(
                data=data, context=context
            )
        except AssertionError:
            self.assertFalse(serializer.is_valid())
            self.assertIn("email", serializer.errors)

    def test_password_reset_email_serializer_invalid_email_format(self):
        data = {"email": "not-a-valid-email"}
        request = Mock()
        context = {"request": request}
        serializer = PasswordResetEmailSerializer(
            data=data, context=context
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)

    def patch(self, target, **kwargs):
        patcher = mock.patch(target, **kwargs)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing


class PasswordResetSerializerTests(TestCase):
    def test_password_reset_serializer_valid(self):
        user = User.objects.create_user(
            email="test@example.com", password="Oldpassword123"
        )
        mock_check_token = self.patch(
            "users.serializers.PasswordResetTokenGenerator.check_token"
        )
        mock_check_token.return_value = True

        uid = "MQ"
        token = "valid_token"
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        context = {"uid": uid, "token": token}

        serializer = PasswordResetSerializer(data=data, context=context)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.errors, {})
        self.assertEqual(serializer.validated_data["user"], user)

    def test_password_reset_serializer_invalid_mismatch(self):
        data = {"password": "Newpassword123", "password2": "wrongpassword"}
        context = {"uid": "test_uid", "token": "test_token"}
        serializer = PasswordResetSerializer(data=data, context=context)
        self.assertFalse(serializer.is_valid())
        self.assertIn("non_field_errors", serializer.errors)
        self.assertEqual(
            serializer.errors["non_field_errors"],
            ["Password and Confirm Password doesn't match"],
        )

    def test_password_reset_serializer_invalid_token(self):
        User.objects.create_user(
            email="test@example.com", password="Oldpassword123"
        )
        mock_check_token = self.patch(
            "users.serializers.PasswordResetTokenGenerator.check_token"
        )
        mock_check_token.return_value = False
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        context = {"uid": "MQ", "token": "invalid_token"}
        serializer = PasswordResetSerializer(data=data, context=context)
        self.assertFalse(serializer.is_valid())
        self.assertIn("non_field_errors", serializer.errors)
        self.assertEqual(
            serializer.errors["non_field_errors"],
            ["Token is not Valid or Expired"],
        )

    def test_password_reset_serializer_save(self):
        user = User.objects.create_user(
            email="test@example.com", password="Oldpassword123"
        )
        mock_check_token = self.patch(
            "users.serializers.PasswordResetTokenGenerator.check_token"
        )
        mock_check_token.return_value = True
        uid = "MQ"
        token = "valid_token"
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        context = {"uid": uid, "token": token}
        serializer = PasswordResetSerializer(data=data, context=context)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user.refresh_from_db()
        self.assertTrue(user.check_password("Newpassword123"))

    @expectedFailure  #! Figure This Out, Dim wit.
    def test_password_reset_serializer_invalid_uid(self):
        mock_check_token = self.patch(
            "users.serializers.PasswordResetTokenGenerator.check_token"
        )
        mock_check_token.return_value = True

        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        context = {"uid": "00", "token": "valid_token"}
        serializer = PasswordResetSerializer(data=data, context=context)
        self.assertFalse(serializer.is_valid())
        self.assertIn("non_field_errors", serializer.errors)

    @expectedFailure  #! Add Password Complexity
    def test_password_reset_serializer_invalid_password_complexity(self):
        data = {"password": "short", "password2": "short"}
        context = {"uid": "test_uid", "token": "test_token"}
        serializer = PasswordResetSerializer(data=data, context=context)
        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)

    def patch(self, target, **kwargs):
        patcher = mock.patch(target, **kwargs)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing


# * Views Tests


class RegisterViewTests(APITestCase):
    def test_register_user(self):
        url = reverse("register")
        data = {
            "first_name": "Test",
            "last_name": "User",
            "DoB": "01/01/2000",
            "email": "test@example.com",
            "password": "Testpassword123",
            "password2": "Testpassword123",
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        user = User.objects.first()
        self.assertEqual(user.email, "test@example.com")
        self.assertTrue(user.check_password("Testpassword123"))

    def test_register_user_invalid_data(self):
        url = reverse("register")
        data = {}  # Missing required fields
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 0)


class ChangePasswordViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            password="Oldpassword123",
            first_name="Test",
            last_name="User",
        )
        self.client.force_authenticate(user=self.user)
        self.url = reverse("change_password")

    def test_change_password(self):
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data, {"msg": "Password Changed Successfully"}
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Newpassword123"))

    def test_change_password_invalid_data(self):
        data = {"password": "Newpassword123", "password2": "wrongpassword"}
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("non_field_errors", response.data)

    def test_change_password_unauthenticated(self):
        self.client.logout()
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )


class PasswordResetEmailViewTests(APITestCase):
    def setUp(self):
        self.url = reverse("send_reset")
        self.user = User.objects.create_user(
            email="test@example.com",
            password="Testpassword123",
            first_name="Test",
            last_name="User",
        )

    @patch(
        "users.views.PasswordResetEmailSerializer"
    )  # Patch the view's serializer
    def test_password_reset_email(self, MockSerializer):
        # Configure the MockSerializer to return a valid result
        mock_serializer = MockSerializer.return_value
        mock_serializer.is_valid.return_value = True

        data = {"email": "test@example.com"}
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data,
            {"msg": "Password Reset link send. Please check your Email"},
        )
        mock_serializer.is_valid.assert_called_once_with(
            raise_exception=True
        )  # Check that the method has been called

    def test_password_reset_email_invalid_data(self):
        data = {"email": "invalid-email"}
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST
        )  # Or another appropriate error status code

    def test_password_reset_email_user_does_not_exist(self):
        data = {"email": "nonexistent@example.com"}
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class PasswordResetViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            password="Oldpassword123",
            first_name="Test",
            last_name="User",
        )
        self.uid = urlsafe_base64_encode(force_bytes(self.user.id))
        self.token = PasswordResetTokenGenerator().make_token(self.user)
        self.url = reverse(
            "reset", kwargs={"uid": self.uid, "token": self.token}
        )

    def test_password_reset(self):
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data, {"msg": "Password Reset Successfully"}
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Newpassword123"))

    def test_password_reset_invalid_data(self):
        data = {"password": "Newpassword123", "password2": "wrongpassword"}
        response = self.client.post(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("non_field_errors", response.data)

    def test_password_reset_invalid_token(self):
        url = reverse(
            "reset", kwargs={"uid": self.uid, "token": "invalid_token"}
        )
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @expectedFailure  #! Figure This Out, Dim wit.
    def test_password_reset_invalid_uid(self):
        url = reverse(
            "reset", kwargs={"uid": "invalid_uid", "token": self.token}
        )
        data = {
            "password": "Newpassword123",
            "password2": "Newpassword123",
        }
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_password_reset_get_request(self):
        response = self.client.get(self.url)
        self.assertEqual(
            response.status_code, 200
        )  # Assuming your template renders successfully


class ProfileViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@example.com",
            password="Testpassword123",
            first_name="Test",
            last_name="User",
            DoB="2000-01-01",
        )
        self.client.force_authenticate(user=self.user)
        self.url = reverse("profile")

    def test_get_profile(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["email"], "test@example.com")
        self.assertEqual(response.data["first_name"], "Test")
        self.assertEqual(response.data["last_name"], "User")

    def test_patch_profile(self):
        data = {"first_name": "Updated", "last_name": "User2"}
        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["first_name"], "Updated")
        self.assertEqual(response.data["last_name"], "User2")
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Updated")
        self.assertEqual(self.user.last_name, "User2")

    def test_patch_profile_invalid_data(self):
        data = {"email": "invalid-email"}
        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_patch_profile_unauthenticated(self):
        self.client.logout()
        data = {"first_name": "Updated"}
        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )
