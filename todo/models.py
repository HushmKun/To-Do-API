from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

# Create your models here.


class ToDo(models.Model):

    STATUS_CHOICES = [
        ("todo", _("Todo")),
        ("in_progress", _("In Progress")),
        ("done", _("Done")),
    ]

    title = models.CharField(_("Title"), max_length=50)
    user = models.ForeignKey(
        "users.user", verbose_name=_("User"), on_delete=models.CASCADE
    )
    desc = models.CharField(_("Description"), max_length=256)
    status = models.CharField(
        _("Status"), max_length=50, choices=STATUS_CHOICES, default="todo"
    )
    created_at = models.DateTimeField(
        _("Date of creation"), auto_now=False, auto_now_add=True
    )

    class Meta:
        verbose_name = _("ToDo")
        verbose_name_plural = _("ToDos")

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse("todo_detail", kwargs={"pk": self.pk})
