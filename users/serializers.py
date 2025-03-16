from datetime import date

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, smart_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import serializers
from rest_framework.exceptions import NotFound
from rest_framework.generics import get_object_or_404
from rest_framework.reverse import reverse
from rest_framework.validators import UniqueValidator

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
    )

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)
    DoB = serializers.DateField(
        format="%d/%m/%Y", input_formats=["%d/%m/%Y"]
    )

    class Meta:
        model = User
        fields = (
            "id",
            "first_name",
            "last_name",
            "DoB",
            "email",
            "password",
            "password2",
        )
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name": {"required": True},
            "DoB": {"required": True},
        }

    def validate(self, attrs):
        if ("password" in attrs) or ("password2" in attrs):
            if attrs["password"] != attrs["password2"]:
                raise serializers.ValidationError(
                    {"password": "Password fields didn't match."}
                )

        if ("DoB" in attrs) and (attrs["DoB"] > date.today()):
            raise serializers.ValidationError(
                {"DoB": "Date of Birth can't be after today."}
            )

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data["email"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            DoB=validated_data["DoB"],
        )

        user.set_password(validated_data["password"])
        user.save()

        return user


class ChangePasswordSerializer(serializers.Serializer):

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )

    class Meta:
        fields = ["password", "password2"]

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password doesn't match"
            )
        return attrs

    def save(self, **kwargs):
        user = self.context["user"]

        user.set_password(self.validated_data["password"])
        user.save()
        return user


class PasswordResetEmailSerializer(serializers.Serializer):

    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        email = attrs.get("email")

        user = User.objects.filter(email=email).first()

        if user is None:
            raise NotFound(
                {"email": "No user matches this email."}, code=404
            )
        uid = urlsafe_base64_encode(force_bytes(user.id))

        # print("Encoded UID", uid)
        token = PasswordResetTokenGenerator().make_token(user)

        # print("Password Reset Token", token)
        link = reverse(
            "reset",
            kwargs={"uid": uid, "token": token},
            request=self.context["request"],
        )

        # print("Password Reset Link", link)
        return attrs


class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )

    class Meta:
        fields = ["password", "password2"]

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        uid = self.context.get("uid")
        token = self.context.get("token")

        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password doesn't match"
            )

        id = smart_str(urlsafe_base64_decode(uid))
        user = get_object_or_404(User, pk=id)

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError(
                "Token is not Valid or Expired"
            )

        attrs["user"] = user
        return attrs

    def save(self):

        user = self.validated_data["user"]

        user.set_password(self.validated_data["password"])
        user.save()

        return user
