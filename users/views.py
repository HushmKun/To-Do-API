from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView, Response

from .models import User
from .serializers import (
    ChangePasswordSerializer,
    PasswordResetEmailSerializer,
    PasswordResetSerializer,
    UserSerializer,
)

# Create your views here.


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = UserSerializer


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(
            data=request.data, context={"user": request.user}
        )
        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer.save()
        return Response(
            {"msg": "Password Changed Successfully"},
            status=status.HTTP_200_OK,
        )


class PasswordResetEmailView(APIView):
    def post(self, request, format=None):
        serializer = PasswordResetEmailSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            {"msg": "Password Reset link send. Please check your Email"},
            status=status.HTTP_200_OK,
        )


class PasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = PasswordResetSerializer(
            data=request.data,
            context={"uid": uid, "token": token, "request": request},
        )
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save()
        return Response(
            {"msg": "Password Reset Successfully"},
            status=status.HTTP_200_OK,
        )

    def get(self, request, uid, token):

        return render(request, "users/reset_password.html")


class Profile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        user = self.request.user
        request.data.pop("password", None)
        serializer = UserSerializer(
            user,
            data=request.data,
            partial=True,
        )
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save()
        return Response(serializer.data)
