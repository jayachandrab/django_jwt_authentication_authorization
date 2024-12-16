from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User
from django.db import models

class RegisteredUser(models.Model):
    name = models.CharField(max_length=100)
    emailid = models.CharField(max_length=100)
    phoneNum = models.CharField(blank=True, null=True, max_length = 20)
    password = models.CharField(max_length=30)

    def get_absolute_url(self):
        return reverse('userdetail', kwargs={'pk': self.pk})




class Role(models.TextChoices):
    ADMIN = 'admin', 'Admin'
    MANAGER = 'manager', 'Manager'
    ASSISTANT = 'assistant', 'Assistant'

# Adding the role field to the existing User model
User.add_to_class('role', models.CharField(max_length=10, choices=Role.choices, default=Role.ASSISTANT))
