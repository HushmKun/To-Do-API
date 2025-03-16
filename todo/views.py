from typing import override

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework.generics import (
    ListCreateAPIView,
    RetrieveUpdateDestroyAPIView,
)
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import Response

from .models import ToDo
from .serializers import ToDoSerializer


# Create your views here.
class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class ToDoView(ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ToDoSerializer
    pagination_class = StandardResultsSetPagination
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["status"]
    search_fields = ["title"]
    ordering_fields = ["title", "created_at"]
    ordering = ["created_at"]

    @override
    def get_queryset(self, *args, **kwargs):
        queryset = ToDo.objects.filter(user=self.request.user)
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @override
    def perform_create(self, serializer):
        return super().perform_create(serializer)


class ToDosView(RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ToDoSerializer
    queryset = ToDo.objects.all()

    @override
    def get_queryset(self):
        data = super().get_queryset()

        return data.filter(user=self.request.user)
